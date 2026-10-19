//! Verified object fills (`PLAN.md` §3.6-§3.9, §7): reserve, stream into a
//! private spool temporary with incremental hashing, require exact size and
//! digest, then commit. Nothing is observable before the commit.
//!
//! [`upstream`] holds the origin client, [`flight`] the single-flight registry.

pub mod flight;
pub mod upstream;

use std::time::Duration;

use ferrum_apt::digest::ObjectIdentity;
use ferrum_apt::path::RepositoryPath;
use ferrum_storage::s3::{S3Error, S3Store};
use ferrum_storage::{Spool, SpoolError, SpoolWriter, VerifiedObject};
use futures_util::StreamExt;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub use self::flight::{FillRegistry, JoinOutcome};
pub use self::upstream::{SourceError, SourceResponse, UpstreamClient};
use crate::config::Limits;

/// Terminal failure of a fill. Cloneable so a watch channel can replay it.
#[derive(Debug, Clone, Error)]
pub enum FillError {
    /// No spool capacity or no fill slot within the admission wait.
    #[error("fill admission refused")]
    Admission,
    /// Persistent S3 allowance exhausted or unreconciled; never bypassed via origin.
    #[error("S3 transfer allowance unavailable")]
    Budget,
    /// Confirmed origin absence.
    #[error("object absent at the origin")]
    NotFound,
    /// Origin refused the request.
    #[error("origin refused the request")]
    Forbidden,
    /// S3 authorization opens a persistent circuit; never origin fallback.
    #[error("S3 authorization circuit open")]
    BackendForbidden,
    /// Size or digest mismatch before verification; never retried.
    #[error("object failed verification: {0}")]
    Corrupt(String),
    /// Transient origin failure after all permitted attempts.
    #[error("transient origin failure: {0}")]
    Transient(String),
    /// The producer deadline or the origin timeouts expired.
    #[error("fill timed out")]
    Timeout,
    /// An unclassified origin status.
    #[error("unexpected origin response: {0}")]
    Unexpected(String),
    /// Local failure (spool I/O, producer panic, closed channel).
    #[error("internal fill failure: {0}")]
    Internal(String),
    /// The gateway is shutting down.
    #[error("gateway shutting down")]
    Shutdown,
}

impl FillError {
    /// Bounded label for `ferrum_fills_total{outcome=...}`.
    pub fn metrics_label(&self) -> &'static str {
        match self {
            FillError::Admission => "admission",
            FillError::Budget => "s3_budget",
            FillError::NotFound => "not_found",
            FillError::Corrupt(_) => "corrupt",
            FillError::Transient(_) => "transient",
            FillError::Timeout => "timeout",
            FillError::BackendForbidden => "s3_forbidden",
            FillError::Forbidden
            | FillError::Unexpected(_)
            | FillError::Internal(_)
            | FillError::Shutdown => "internal",
        }
    }

    /// Whether the failure may be retried from offset zero within one fill.
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(self, FillError::Transient(_) | FillError::Timeout)
    }
}

impl From<SourceError> for FillError {
    fn from(error: SourceError) -> Self {
        match error {
            SourceError::NotFound => FillError::NotFound,
            SourceError::Forbidden => FillError::Forbidden,
            SourceError::Transient(detail) | SourceError::Io(detail) => {
                FillError::Transient(detail)
            }
            SourceError::Timeout => FillError::Timeout,
            SourceError::Corrupt(detail) => FillError::Corrupt(detail),
            SourceError::Unexpected(status) => FillError::Unexpected(format!("status {status}")),
        }
    }
}

impl From<SpoolError> for FillError {
    fn from(error: SpoolError) -> Self {
        match error {
            SpoolError::CapacityExhausted { .. }
            | SpoolError::ObjectTooLarge { .. }
            | SpoolError::AdmissionClosed => FillError::Admission,
            SpoolError::Mismatch { .. } | SpoolError::Overflow { .. } => {
                FillError::Corrupt(error.to_string())
            }
            other => FillError::Internal(other.to_string()),
        }
    }
}

impl From<S3Error> for FillError {
    fn from(error: S3Error) -> Self {
        match error {
            S3Error::NotFound => Self::NotFound,
            S3Error::Forbidden => Self::BackendForbidden,
            S3Error::Corrupt => Self::Corrupt("S3 object quarantined".into()),
            S3Error::Timeout => Self::Timeout,
            S3Error::Throttled | S3Error::Unavailable => Self::Transient(error.to_string()),
            S3Error::Cancelled => Self::Shutdown,
            S3Error::Budget | S3Error::AdmissionRefused => Self::Budget,
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<ferrum_storage::capture::CaptureError> for FillError {
    fn from(error: ferrum_storage::capture::CaptureError) -> Self {
        use ferrum_storage::capture::CaptureError;
        match error {
            CaptureError::Admission => Self::Admission,
            CaptureError::Proof => Self::Corrupt("capture proof conflict".to_owned()),
            CaptureError::Spool(error) => error.into(),
            CaptureError::S3(error) => error.into(),
            CaptureError::Budget(_) => Self::Budget,
            other => Self::Internal(other.to_string()),
        }
    }
}

/// Production package source selection. Only authenticated index authority can
/// enter this path; a new upstream capture reserves durable outbox capacity
/// before the first source body, whereas receipted rehydration does not.
pub(crate) async fn fill_authorized_package(
    client: &UpstreamClient,
    store: &S3Store,
    capture: &ferrum_storage::capture::CaptureManager,
    proof: &ferrum_storage::capture::VerifiedCaptureProof,
    spool: &Spool,
    limits: &Limits,
    cancel: &CancellationToken,
) -> Result<VerifiedObject, FillError> {
    let identity = proof.identity();
    let deadline = tokio::time::Instant::now() + limits.producer_deadline;
    if capture.is_durable(identity)? {
        return capture
            .rehydrate(identity, deadline, cancel)
            .await
            .map_err(Into::into);
    }
    let reservation = spool.reserve(identity.size)?;
    let mut writer = spool.begin_write(reservation, identity).await?;
    let mut capture_reservation = None;
    let from_s3 = match attempt_s3(store, &mut writer, identity, deadline).await {
        Ok(()) => true,
        Err(error) => {
            if matches!(error, FillError::Corrupt(_)) {
                store.quarantine(identity)?;
            }
            if !matches!(
                error,
                FillError::NotFound
                    | FillError::Transient(_)
                    | FillError::Timeout
                    | FillError::BackendForbidden
            ) {
                writer.abort().await;
                return Err(error);
            }
            // The persistent capture gate also funds future verification and
            // receipt writes; no origin fallback can bypass it.
            capture_reservation =
                Some(capture.reserve(proof, ferrum_apt::release::UnixTime::now().as_secs())?);
            writer.reset().await?;
            let mut attempt = 1;
            loop {
                match attempt_once(client, &mut writer, identity, proof.path()).await {
                    Ok(()) => break,
                    Err(error) if error.is_retryable() && attempt < limits.source_attempts => {
                        writer.reset().await?;
                        tokio::time::sleep(retry_backoff()).await;
                        attempt += 1;
                    }
                    Err(error) => {
                        writer.abort().await;
                        return Err(error);
                    }
                }
            }
            false
        }
    };
    let object = match writer.commit().await {
        Ok(object) => object,
        Err(error) => {
            if from_s3
                && matches!(
                    error,
                    SpoolError::Mismatch { .. } | SpoolError::Overflow { .. }
                )
            {
                store.quarantine(identity)?;
            }
            return Err(error.into());
        }
    };
    if from_s3 {
        capture
            .capture_verified_hit(proof, deadline, cancel)
            .await?;
    }
    drop(capture_reservation);
    Ok(object)
}

/// Fetches `path` from the origin and installs it as `identity`.
///
/// Reserves the signed size, then makes up to `limits.source_attempts` attempts.
/// Each attempt streams the body into the writer, reading at most the signed
/// size plus one overflow-detection byte; a clean EOF at the signed size commits
/// (digest mismatch is [`FillError::Corrupt`] and never retried). Transient
/// failures, timeouts and truncated bodies reset the writer to zero and retry
/// after a 250-750 ms jittered pause. The caller bounds the whole call by the
/// producer deadline.
///
/// # Errors
/// [`FillError`]; on error nothing is installed and the reservation is released.
///
/// # Cancellation
/// Dropping the future drops the writer, which removes the temporary.
pub async fn fill_object(
    client: &UpstreamClient,
    spool: &Spool,
    identity: ObjectIdentity,
    path: &RepositoryPath,
    limits: &Limits,
) -> Result<VerifiedObject, FillError> {
    fill_package_object(client, None, spool, identity, path, limits).await
}

/// Package-only source selection; metadata callers use `fill_object` and remain origin-only.
pub async fn fill_package_object(
    client: &UpstreamClient,
    s3: Option<&S3Store>,
    spool: &Spool,
    identity: ObjectIdentity,
    path: &RepositoryPath,
    limits: &Limits,
) -> Result<VerifiedObject, FillError> {
    let reservation = spool.reserve(identity.size)?;
    let mut writer = spool.begin_write(reservation, identity).await?;
    let deadline = tokio::time::Instant::now() + limits.producer_deadline;
    let mut use_s3 = s3.is_some();
    let mut attempt = 1u32;
    loop {
        let result = if use_s3 {
            match s3 {
                Some(store) => attempt_s3(store, &mut writer, identity, deadline).await,
                None => Err(FillError::Internal("missing selected S3 source".into())),
            }
        } else {
            attempt_once(client, &mut writer, identity, path).await
        };
        match result {
            Ok(()) => {
                let result = writer.commit().await.map_err(FillError::from);
                if use_s3
                    && matches!(result, Err(FillError::Corrupt(_)))
                    && let Some(store) = s3
                {
                    store.quarantine(identity).map_err(FillError::from)?;
                }
                return result;
            }
            Err(FillError::NotFound) if use_s3 => {
                use_s3 = false;
                attempt = 1;
                writer.reset().await?;
            }
            Err(error) if error.is_retryable() && attempt < limits.source_attempts => {
                writer.reset().await?;
                tokio::time::sleep(retry_backoff()).await;
                attempt = attempt.saturating_add(1);
            }
            Err(error) => {
                if use_s3
                    && matches!(error, FillError::Corrupt(_))
                    && let Some(store) = s3
                {
                    store.quarantine(identity).map_err(FillError::from)?;
                }
                writer.abort().await;
                return Err(error);
            }
        }
    }
}

/// Streams one source attempt into `writer`; `Ok` means exactly `identity.size`
/// bytes arrived followed by EOF.
async fn attempt_once(
    client: &UpstreamClient,
    writer: &mut SpoolWriter,
    identity: ObjectIdentity,
    path: &RepositoryPath,
) -> Result<(), FillError> {
    let response = client.get(path, Some(identity.size)).await?;
    stream_into_writer(
        response
            .into_stream()
            .map(|chunk| chunk.map_err(FillError::from)),
        writer,
        identity,
    )
    .await
}

async fn attempt_s3(
    store: &S3Store,
    writer: &mut SpoolWriter,
    identity: ObjectIdentity,
    deadline: tokio::time::Instant,
) -> Result<(), FillError> {
    let response = store
        .get(identity, deadline, CancellationToken::new())
        .await?;
    let result = stream_into_writer(
        response
            .into_stream()
            .map(|chunk| chunk.map_err(FillError::from)),
        writer,
        identity,
    )
    .await;
    if result.is_err() && store.is_quarantined(identity) {
        return Err(FillError::Corrupt("S3 object quarantined".into()));
    }
    result
}

async fn stream_into_writer(
    mut body: impl futures_util::Stream<Item = Result<bytes::Bytes, FillError>> + Unpin,
    writer: &mut SpoolWriter,
    identity: ObjectIdentity,
) -> Result<(), FillError> {
    while let Some(chunk) = body.next().await {
        let mut chunk = chunk?;
        let remaining = identity.size.saturating_sub(writer.written());
        // The HTTP transport may have buffered more; inspect at most the signed
        // remainder plus the one byte needed to prove overflow.
        let bound = usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX);
        chunk.truncate(bound);
        if chunk.len() as u64 > remaining {
            return Err(FillError::Corrupt(format!(
                "source sent more than the signed {} bytes",
                identity.size
            )));
        }
        writer.write(chunk).await?;
    }
    if writer.written() != identity.size {
        return Err(FillError::Transient(format!(
            "body truncated at {} of {} bytes",
            writer.written(),
            identity.size
        )));
    }
    Ok(())
}

fn retry_backoff() -> Duration {
    Duration::from_millis(rand::random_range(250..=750))
}
