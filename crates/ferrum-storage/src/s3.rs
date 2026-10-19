//! Concrete locked S3 adapter with explicit private and production admission profiles.
mod production;
pub use production::{
    ControlCondition, ControlObject, OperationIdentity, S3Config, S3Store, VerifiedUpload,
};
mod config;
mod journal;
#[doc(hidden)]
#[cfg(any(test, feature = "test-harness"))]
pub mod testing;
mod wire;

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_types::byte_stream::Length;
use bytes::Bytes;
use ferrum_apt::digest::ObjectIdentity;
use futures_util::{Stream, StreamExt};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::VerifiedObject;
pub use config::PrivateS3Config;
pub use journal::{ObjectRecord, ReplacementIntent, TransferStatus};

const CONTROL: u64 = 64 * 1024;
const PROTOCOL_BUFFER: u64 = 256 * 1024;
const SINGLE_PUT_LIMIT: u64 = 64 * 1024 * 1024;
const CHUNK: usize = 256 * 1024;
pub(crate) fn production_now() -> Result<i64, S3Error> {
    production::now()
}

type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, S3Error>> + Send>>;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum S3Error {
    #[error("S3 object not found")]
    NotFound,
    #[error("S3 authorization forbidden; backend circuit open")]
    Forbidden,
    #[error("S3 throttled")]
    Throttled,
    #[error("S3 deadline or idle timeout")]
    Timeout,
    #[error("S3 unavailable")]
    Unavailable,
    #[error("S3 object failed authenticated verification; quarantined")]
    Corrupt,
    #[error("S3 conditional mutation conflict")]
    Conflict,
    #[error("S3 operation unsupported in private fixture")]
    Unsupported,
    #[error("request outside private S3 boundary")]
    Boundary,
    #[error("explicit protected credential file or proxy policy rejected")]
    Credentials,
    #[error("private test transfer allowance exhausted")]
    Budget,
    #[error("S3 admission refused before dispatch")]
    AdmissionRefused,
    #[error("private transfer journal: {0}")]
    Journal(String),
    #[error("S3 operation cancelled")]
    Cancelled,
    #[error("invalid sentinel unexpectedly succeeded")]
    UnexpectedSuccess,
}

pub struct S3Response {
    pub content_length: u64,
    pub etag: Option<String>,
    pub version_id: Option<String>,
    stream: BodyStream,
}

impl S3Response {
    pub fn into_stream(self) -> BodyStream {
        self.stream
    }
}

#[derive(Debug)]
pub struct S3ObjectMeta {
    pub content_length: u64,
    pub etag: Option<String>,
    pub version_id: Option<String>,
}

pub(super) struct PrivateStore {
    client: aws_sdk_s3::Client,
    wire: wire::Wire,
    config: Arc<PrivateS3Config>,
    journal: journal::SharedJournal,
    // Fourteen data operations leave two of the sixteen slots for HEAD/cleanup.
    operations: Arc<Semaphore>,
    data: Arc<Semaphore>,
    uploads: Arc<Semaphore>,
}

impl PrivateStore {
    /// Explicit fresh initialization only. Existing or partially initialized paths fail closed.
    pub fn initialize_private_journal(config: &PrivateS3Config) -> Result<(), S3Error> {
        journal::Journal::initialize(config)
    }

    /// Reopens existing known usage. Never initializes, resets or refunds reservations.
    pub fn open_private(config: PrivateS3Config) -> Result<Self, S3Error> {
        config.validate()?;
        let journal = journal::Journal::reopen(&config)?;
        let config = Arc::new(config);
        let wire = wire::Wire::new(config.clone(), journal.clone());
        let client = config::client(&config, wire.clone())?;
        Ok(Self {
            client,
            wire,
            config,
            journal,
            operations: Arc::new(Semaphore::new(16)),
            data: Arc::new(Semaphore::new(14)),
            uploads: Arc::new(Semaphore::new(2)),
        })
    }

    pub fn status(&self) -> Result<TransferStatus, S3Error> {
        Ok(journal::lock(&self.journal)?.status())
    }

    pub fn circuit_open(&self) -> bool {
        journal::lock(&self.journal).map_or(true, |journal| journal.is_forbidden())
    }

    pub fn allowance_blocked(&self) -> bool {
        journal::lock(&self.journal).map_or(true, |journal| journal.has_overrun())
    }

    pub fn is_quarantined(&self, identity: ObjectIdentity) -> bool {
        let key = format!(
            "{}v1/objects/sha256/{}",
            self.config.package_prefix, identity.sha256
        );
        journal::lock(&self.journal).map_or(true, |journal| {
            journal.object(&key).is_ok_and(|record| record.quarantined)
        })
    }

    fn key(&self, identity: ObjectIdentity) -> Result<String, S3Error> {
        if identity.size >= SINGLE_PUT_LIMIT {
            return Err(S3Error::Unsupported);
        }
        let key = format!(
            "{}v1/objects/sha256/{}",
            self.config.package_prefix, identity.sha256
        );
        self.config.validate_key(&key)?;
        journal::lock(&self.journal)?.authorize(&key, identity)?;
        Ok(key)
    }

    fn check(&self, key: &str) -> Result<(), S3Error> {
        let journal = journal::lock(&self.journal)?;
        if journal.is_forbidden() {
            return Err(S3Error::Forbidden);
        }
        if journal.object(key)?.quarantined {
            return Err(S3Error::Corrupt);
        }
        if journal.has_overrun() {
            return Err(S3Error::Budget);
        }
        Ok(())
    }

    pub fn quarantine(&self, identity: ObjectIdentity) -> Result<(), S3Error> {
        let key = self.key(identity)?;
        journal::lock(&self.journal)?.quarantine(&key)?;
        tracing::error!(sha256 = %identity.sha256, "private S3 object quarantined; no fallback or overwrite");
        Ok(())
    }

    async fn slot(
        &self,
        control: bool,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(OwnedSemaphorePermit, Option<OwnedSemaphorePermit>), S3Error> {
        bounded(deadline, cancel, async {
            let data = if control {
                None
            } else {
                Some(
                    self.data
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| S3Error::Cancelled)?,
                )
            };
            let total = self
                .operations
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| S3Error::Cancelled)?;
            Ok((total, data))
        })
        .await
    }

    fn failure<E: ProvideErrorMetadata>(
        &self,
        key: &str,
        error: SdkError<E>,
        head: bool,
    ) -> S3Error {
        if let Ok(journal) = journal::lock(&self.journal) {
            if journal.is_forbidden() {
                return S3Error::Forbidden;
            }
            if journal.object(key).is_ok_and(|record| record.quarantined) {
                return S3Error::Corrupt;
            }
            if journal.has_overrun() {
                return S3Error::Budget;
            }
        }
        classify_sdk(error, head)
    }

    /// Direct GET, with no preceding HEAD. Dropping the returned stream cancels this attempt.
    pub async fn get(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<S3Response, S3Error> {
        let key = self.key(identity)?;
        self.check(&key)?;
        let slots = self.slot(false, deadline, &cancel).await?;
        let output = bounded(deadline, &cancel, async {
            self.client
                .get_object()
                .bucket(config::BUCKET)
                .key(&key)
                .send()
                .await
                .map_err(|error| self.failure(&key, error, false))
        })
        .await?;
        let length = output
            .content_length()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(S3Error::Corrupt)?;
        if length != identity.size {
            self.quarantine(identity)?;
            return Err(S3Error::Corrupt);
        }
        let etag = output.e_tag().map(str::to_owned);
        let version_id = output.version_id().map(str::to_owned);
        let state = (output.body, Bytes::new(), slots, cancel, false);
        let stream = futures_util::stream::unfold(
            state,
            move |(mut body, mut pending, slots, cancel, finished)| async move {
                if finished {
                    return None;
                }
                if !pending.is_empty() {
                    let chunk = pending.split_to(pending.len().min(CHUNK));
                    return Some((Ok(chunk), (body, pending, slots, cancel, false)));
                }
                let next = bounded(
                    deadline.min(Instant::now() + Duration::from_secs(30)),
                    &cancel,
                    async {
                        body.next()
                            .await
                            .transpose()
                            .map_err(|_| S3Error::Unavailable)
                    },
                )
                .await;
                match next {
                    Ok(Some(mut bytes)) => {
                        let chunk = bytes.split_to(bytes.len().min(CHUNK));
                        Some((Ok(chunk), (body, bytes, slots, cancel, false)))
                    }
                    Ok(None) => None,
                    Err(error) => Some((Err(error), (body, pending, slots, cancel, true))),
                }
            },
        );
        Ok(S3Response {
            content_length: length,
            etag,
            version_id,
            stream: Box::pin(stream),
        })
    }

    /// Descriptor-only probe; validates size and never fills or promotes residency.
    pub async fn head(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<S3ObjectMeta, S3Error> {
        let key = self.key(identity)?;
        self.check(&key)?;
        let _slots = self.slot(true, deadline, &cancel).await?;
        let output = bounded(deadline, &cancel, async {
            self.client
                .head_object()
                .bucket(config::BUCKET)
                .key(&key)
                .send()
                .await
                .map_err(|error| self.failure(&key, error, true))
        })
        .await?;
        let length = output
            .content_length()
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(S3Error::Corrupt)?;
        if length != identity.size {
            self.quarantine(identity)?;
            return Err(S3Error::Corrupt);
        }
        Ok(S3ObjectMeta {
            content_length: length,
            etag: output.e_tag().map(str::to_owned),
            version_id: output.version_id().map(str::to_owned),
        })
    }

    /// Create-only file-backed PUT from the spool's verified, leased file.
    /// Ownership intent is durable before mutation; a collision is never overwritten.
    pub async fn put_file(
        &self,
        object: &VerifiedObject,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<String, S3Error> {
        let identity = object.identity();
        let key = self.key(identity)?;
        self.check(&key)?;
        journal::lock(&self.journal)?.intent(&key)?;
        let _upload = bounded(deadline, &cancel, async {
            self.uploads
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| S3Error::Cancelled)
        })
        .await?;
        let _slots = self.slot(false, deadline, &cancel).await?;
        let body = ByteStream::read_from()
            .path(object.path())
            .length(Length::Exact(identity.size))
            .buffer_size(CHUNK)
            .build()
            .await
            .map_err(|_| S3Error::Unavailable)?;
        let output = bounded(deadline, &cancel, async {
            self.client
                .put_object()
                .bucket(config::BUCKET)
                .key(&key)
                .if_none_match("*")
                .metadata("ferrum-b05-run", self.config.marker())
                .content_length(identity.size as i64)
                .body(body)
                .send()
                .await
                .map_err(|error| self.failure(&key, error, false))
        })
        .await?;
        if output.version_id().is_some_and(|version| version != "null") {
            return Err(S3Error::Unsupported);
        }
        let etag = output.e_tag().ok_or(S3Error::Corrupt)?.to_owned();
        journal::lock(&self.journal)?.owned(&key, etag.clone())?;
        Ok(etag)
    }

    /// Explicit private-fixture negative operation. Corrupts only one recorded owned key
    /// conditionally, at the same length, using the verified lease as input. This API
    /// accepts only PrivateS3Config namespaces; it is not a production writer path.
    pub async fn corrupt_private_fixture(
        &self,
        object: &VerifiedObject,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<(), S3Error> {
        let identity = object.identity();
        if identity.size == 0 {
            return Err(S3Error::Unsupported);
        }
        let key = self.key(identity)?;
        self.check(&key)?;
        // A same-length changed first byte followed by replayable file tail; no package Vec.
        let mut stream = object
            .stream_range(0, 0)
            .map_err(|_| S3Error::Unavailable)?;
        let first = stream
            .next()
            .await
            .ok_or(S3Error::Corrupt)?
            .map_err(|_| S3Error::Unavailable)?;
        let first = first.first().copied().ok_or(S3Error::Corrupt)? ^ 1;
        let tail = if identity.size > 1 {
            Some(
                object
                    .stream_range(1, identity.size - 1)
                    .map_err(|_| S3Error::Unavailable)?,
            )
        } else {
            None
        };
        let body = wire::fixture_body(first, tail, identity.size);
        let _upload = bounded(deadline, &cancel, async {
            self.uploads
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| S3Error::Cancelled)
        })
        .await?;
        let _slots = self.slot(false, deadline, &cancel).await?;
        let token = format!("{:032x}", rand::random::<u128>());
        let etag = journal::lock(&self.journal)?.replace_intent(&key, token.clone())?;
        let output = bounded(deadline, &cancel, async {
            self.client
                .put_object()
                .bucket(config::BUCKET)
                .key(&key)
                .if_match(etag)
                .metadata("ferrum-b05-run", self.config.marker())
                .metadata("ferrum-b05-mutation", token)
                .content_length(identity.size as i64)
                .body(body)
                .send()
                .await
                .map_err(|error| self.failure(&key, error, false))
        })
        .await?;
        if output.version_id().is_some_and(|version| version != "null") {
            return Err(S3Error::Unsupported);
        }
        let etag = output.e_tag().ok_or(S3Error::Corrupt)?.to_owned();
        journal::lock(&self.journal)?.owned(&key, etag)?;
        Ok(())
    }

    /// Deliberately invalid non-secret sentinel, never prints or alters the real credentials.
    pub async fn probe_forbidden_private(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<(), S3Error> {
        let key = self.key(identity)?;
        let _slots = self.slot(false, deadline, &cancel).await?;
        let invalid = aws_sdk_s3::Client::from_conf(
            self.client
                .config()
                .to_builder()
                .identity_cache(aws_sdk_s3::config::IdentityCache::no_cache())
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "FERRUMINTENTIONALLYINVALID",
                    "ferrum-intentionally-invalid-sentinel-not-a-secret",
                    None,
                    None,
                    "private-negative-sentinel",
                ))
                .http_client(self.wire.for_forbidden_probe())
                .build(),
        );
        match bounded(deadline, &cancel, async {
            invalid
                .get_object()
                .bucket(config::BUCKET)
                .key(&key)
                .send()
                .await
                .map_err(|error| classify_sdk(error, false))
        })
        .await
        {
            Err(S3Error::Forbidden) => {
                tracing::error!(
                    "private S3 sentinel received Forbidden; persistent backend circuit open"
                );
                Ok(())
            }
            Err(error) => Err(error),
            Ok(_) => Err(S3Error::UnexpectedSuccess),
        }
    }

    /// Cleanup only recorded intents; reconcile marker + ETag and delete conditionally.
    /// No bucket LIST, prefix sweep, version deletion or foreign-object deletion exists.
    pub async fn cleanup_private(
        &self,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<(), S3Error> {
        let records = self.status()?.objects;
        let client = aws_sdk_s3::Client::from_conf(
            self.client
                .config()
                .to_builder()
                .http_client(self.wire.for_cleanup())
                .build(),
        );
        for (key, record) in records {
            if !record.mutation_intent || record.deleted {
                continue;
            }
            let _slots = self.slot(true, deadline, &cancel).await?;
            let output = bounded(deadline, &cancel, async {
                client
                    .head_object()
                    .bucket(config::BUCKET)
                    .key(&key)
                    .send()
                    .await
                    .map_err(|error| classify_sdk(error, true))
            })
            .await;
            let output = match output {
                Err(S3Error::NotFound) => {
                    journal::lock(&self.journal)?.deleted(&key)?;
                    continue;
                }
                other => other?,
            };
            if output.version_id().is_some_and(|version| version != "null")
                || output
                    .metadata()
                    .and_then(|metadata| metadata.get("ferrum-b05-run"))
                    .map(String::as_str)
                    != Some(self.config.marker())
            {
                return Err(S3Error::Boundary);
            }
            let etag = output.e_tag().ok_or(S3Error::Corrupt)?.to_owned();
            if record
                .etag
                .as_deref()
                .is_some_and(|recorded| recorded != etag)
            {
                let mutation = output
                    .metadata()
                    .and_then(|metadata| metadata.get("ferrum-b05-mutation"))
                    .map(String::as_str);
                if !record.replacement.as_ref().is_some_and(|intent| {
                    mutation == Some(intent.token.as_str())
                        && record.etag.as_deref() == Some(intent.prior_etag.as_str())
                }) {
                    return Err(S3Error::Conflict);
                }
            }
            journal::lock(&self.journal)?.owned(&key, etag.clone())?;
            bounded(deadline, &cancel, async {
                client
                    .delete_object()
                    .bucket(config::BUCKET)
                    .key(&key)
                    .if_match(etag)
                    .send()
                    .await
                    .map_err(|error| classify_sdk(error, false))
            })
            .await?;
            journal::lock(&self.journal)?.deleted(&key)?;
        }
        Ok(())
    }
}

async fn bounded<T>(
    deadline: Instant,
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, S3Error>>,
) -> Result<T, S3Error> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(S3Error::Cancelled),
        result = tokio::time::timeout_at(deadline, future) => result.map_err(|_| S3Error::Timeout)?,
    }
}

fn classify_sdk<E: ProvideErrorMetadata>(error: SdkError<E>, head: bool) -> S3Error {
    if let SdkError::DispatchFailure(failure) = &error {
        let mut source = failure
            .as_connector_error()
            .map(|error| error as &(dyn std::error::Error + 'static));
        while let Some(cause) = source {
            if let Some(error) = cause.downcast_ref::<S3Error>() {
                return error.clone();
            }
            source = cause.source();
        }
    }
    let status = error
        .raw_response()
        .map(|response| response.status().as_u16());
    let code = error.as_service_error().and_then(|error| error.code());
    let timeout = matches!(&error, SdkError::TimeoutError(_))
        || matches!(&error, SdkError::DispatchFailure(error) if error.is_timeout());
    classify(status, code, timeout, head)
}

fn classify(status: Option<u16>, code: Option<&str>, timeout: bool, head: bool) -> S3Error {
    match (status, code) {
        (Some(404), Some("NoSuchKey" | "NotFound")) => S3Error::NotFound,
        (Some(404), None) if head => S3Error::NotFound,
        (Some(403), _) => S3Error::Forbidden,
        (Some(409 | 412), _) => S3Error::Conflict,
        (Some(429), _) | (_, Some("SlowDown" | "Throttling")) => S3Error::Throttled,
        (Some(501), _) | (_, Some("NotImplemented" | "UnsupportedOperation")) => {
            S3Error::Unsupported
        }
        _ if timeout => S3Error::Timeout,
        _ => S3Error::Unavailable,
    }
}
