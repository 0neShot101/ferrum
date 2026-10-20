//! Sibling-prefix publication intents. The selected shared-key profile is NONISOLATED.
//! CAS validators coordinate writers; only signed artifacts establish content trust.
mod publication;
pub use publication::{PackageDescriptor, PackageScope};
mod metadata;
mod selection;
use crate::catalog::CatalogError;
use crate::{
    Spool,
    s3::{ControlCondition, OperationIdentity, S3Error, S3Store},
};
use ferrum_apt::digest::Sha256Digest;
pub use metadata::{MetadataDescriptor, MetadataHash};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub const CHECKPOINT_LIMIT: u64 = 16 * 1024;
pub const MANIFEST_LIMIT: u64 = 1024 * 1024;
/// Shared bound for configured, retained and reconciled suite identities.
pub const MAX_SUITES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct SuiteKey {
    repository: String,
    suite: String,
}
impl SuiteKey {
    pub fn new(repository: &str, suite: &str) -> Result<Self, CheckpointError> {
        fn valid(value: &str) -> bool {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }
        if !valid(repository) || !valid(suite) {
            return Err(CheckpointError::Invalid);
        }
        Ok(Self {
            repository: repository.into(),
            suite: suite.into(),
        })
    }
    pub fn repository(&self) -> &str {
        &self.repository
    }
    pub fn suite(&self) -> &str {
        &self.suite
    }
    /// Unsigned Pacman databases have transport freshness, not a signed revision
    /// order. The local checkpoint sequence records observations, not rollback
    /// resistance against a malicious or replaying origin.
    pub fn uses_transport_candidate_metadata(&self) -> bool {
        matches!(
            self.repository.as_str(),
            "archlinux" | "chaotic-aur" | "cachyos" | "archlinuxcn" | "endeavouros"
        )
    }
    pub(crate) fn suffix(&self) -> String {
        format!("v1/checkpoints/{}/{}.json", self.repository, self.suite)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryProfile {
    SharedNonisolated,
    ProviderIsolated,
}
impl RecoveryProfile {
    pub fn validate(self) -> Result<(), CheckpointError> {
        // No effective-policy/administrative-bypass denial evidence has been qualified.
        if self != Self::SharedNonisolated {
            return Err(CheckpointError::IsolationUnqualified);
        }
        Ok(())
    }
    pub fn disclosure(self) -> &'static str {
        "NONISOLATED: ordinary VM-local-loss recovery only while checkpoint/artifacts remain intact and trusted; no shared-key compromise or bucket-loss protection"
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationIntent {
    pub schema_version: u32,
    pub repository: String,
    pub suite: String,
    pub sequence: u64,
    pub generation_id: String,
    pub manifest_sha256: String,
    pub release_content_sha256: String,
    pub release_date: i64,
}
impl PublicationIntent {
    pub fn key(&self) -> Result<SuiteKey, CheckpointError> {
        SuiteKey::new(&self.repository, &self.suite)
    }
    pub fn validate(&self) -> Result<(), CheckpointError> {
        self.key()?;
        if self.schema_version != 1 || self.sequence == 0 || self.sequence > i64::MAX as u64 {
            return Err(CheckpointError::Invalid);
        }
        for digest in [
            &self.generation_id,
            &self.manifest_sha256,
            &self.release_content_sha256,
        ] {
            canonical_digest(digest)?;
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<String, CheckpointError> {
        self.validate()?;
        Ok(serde_json::to_string(self)?)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() as u64 > CHECKPOINT_LIMIT {
            return Err(CheckpointError::Invalid);
        }
        let intent: Self = serde_json::from_slice(bytes)?;
        intent.validate()?;
        Ok(intent)
    }
}
pub(crate) fn canonical_digest(text: &str) -> Result<Sha256Digest, CheckpointError> {
    let digest = Sha256Digest::from_hex(text).map_err(|_| CheckpointError::Invalid)?;
    if digest.to_hex() != text {
        return Err(CheckpointError::Invalid);
    }
    Ok(digest)
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("invalid checkpoint, identity or manifest")]
    Invalid,
    #[error("provider-isolated profile lacks actual denial/effective-policy evidence")]
    IsolationUnqualified,
    #[error("lost-state suite has no trusted checkpoint floor")]
    UntrustedFloor,
    #[error("checkpoint floor or pending intent conflicts; affected suite is closed")]
    Conflict,
    #[error("authenticated generation closure missing or invalid")]
    Proof,
    #[error("operator bootstrap requires an explicit durable rollback-reset audit")]
    BootstrapAudit,
    #[error(transparent)]
    Transport(#[from] S3Error),
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error(transparent)]
    Spool(#[from] crate::SpoolError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Signature(#[from] ferrum_apt::signature::SignatureError),
    #[error(transparent)]
    Release(#[from] ferrum_apt::release::ReleaseError),
    #[error("current authenticated origin confirmation failed")]
    Origin,
}

/// Explicit operator judgement, not an assertion that hashes can detect replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorTrust {
    IntactTrusted,
    MissingOrSuspectedCompromise,
}

pub struct CheckpointPublisher {
    pub(crate) spool: Spool,
    pub(crate) store: Arc<S3Store>,
    profile: RecoveryProfile,
    pub(crate) proofs:
        std::sync::Mutex<std::collections::HashMap<String, Arc<publication::CachedProof>>>,
}
impl CheckpointPublisher {
    pub fn new(
        spool: Spool,
        store: Arc<S3Store>,
        profile: RecoveryProfile,
    ) -> Result<Self, CheckpointError> {
        profile.validate()?;
        spool.durable_catalog()?;
        if !spool.same_owner(store.ledger()?.spool()) {
            return Err(CheckpointError::Proof);
        }
        Ok(Self {
            spool,
            store,
            profile,
            proofs: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }
    pub fn profile(&self) -> RecoveryProfile {
        self.profile
    }
    /// Reads the exact suite key. Neither LIST order nor an old local backup is a floor.
    pub async fn read_floor(
        &self,
        key: &SuiteKey,
        trust: FloorTrust,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(PublicationIntent, String), CheckpointError> {
        if trust != FloorTrust::IntactTrusted {
            return Err(CheckpointError::UntrustedFloor);
        }
        let object = self
            .store
            .control_get(
                OperationIdentity::Checkpoint,
                &key.suffix(),
                CHECKPOINT_LIMIT,
                deadline,
                cancel,
            )
            .await?;
        let intent = PublicationIntent::decode(&object.bytes)?;
        if intent.key()? != *key || object.etag.is_empty() {
            return Err(CheckpointError::UntrustedFloor);
        }
        Ok((intent, object.etag))
    }
    /// A private authenticated token is constructed only by the shared recovery verifier.
    /// Durable closure readback and current-origin confirmation precede this call.
    pub async fn publish(
        &self,
        generation: &crate::recovery::VerifiedGeneration,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<PublicationIntent, CheckpointError> {
        generation.ensure_current(&self.store)?;
        self.spool
            .check_publication_capacity(generation.manifest())?;
        let key = generation.key();
        let catalog = self.spool.durable_catalog()?;
        let state = catalog.checkpoint_state(key.clone())?;
        if state.pending.is_some() || (state.blocked && !state.recovery_ready) {
            return Err(CheckpointError::Conflict);
        }
        let previous = state.floor.as_ref();
        let (remote, etag) = match self
            .read_floor(key, FloorTrust::IntactTrusted, deadline, cancel)
            .await
        {
            Ok((intent, etag)) => (Some(intent), Some(etag)),
            Err(CheckpointError::Transport(S3Error::NotFound))
                if previous.is_none() && state.bootstrap_authorized =>
            {
                (None, None)
            }
            Err(
                error @ (CheckpointError::Transport(S3Error::NotFound | S3Error::Corrupt)
                | CheckpointError::UntrustedFloor
                | CheckpointError::Invalid
                | CheckpointError::Json(_)),
            ) => {
                catalog_update(&self.spool, |catalog| catalog.checkpoint_block(key.clone()))?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if remote.as_ref() != previous {
            catalog_update(&self.spool, |catalog| catalog.checkpoint_block(key.clone()))?;
            return Err(CheckpointError::Conflict);
        }
        let sequence = previous.map_or(Ok(1), |intent| {
            intent
                .sequence
                .checked_add(1)
                .ok_or(CheckpointError::Invalid)
        })?;
        let intent = generation.intent(sequence);
        catalog_update(&self.spool, |catalog| {
            catalog.checkpoint_prepare(intent.clone())
        })?;
        let condition = etag.map_or(ControlCondition::Create, ControlCondition::Match);
        let encoded = intent.encode()?;
        let put = self
            .store
            .control_put(
                OperationIdentity::Checkpoint,
                &key.suffix(),
                encoded.as_bytes(),
                condition,
                deadline,
                cancel,
            )
            .await;
        // Even Conflict/timeout may be our committed write with its ACK lost. Exact
        // direct readback is the only reconciliation, never unconditional overwrite.
        match self
            .read_floor(key, FloorTrust::IntactTrusted, deadline, cancel)
            .await
        {
            Ok((actual, _)) if actual == intent && matches!(&put, Err(S3Error::Unsupported)) => {
                catalog_update(&self.spool, |catalog| catalog.checkpoint_block(key.clone()))?;
                Err(S3Error::Unsupported.into())
            }
            Ok((actual, _)) if actual == intent => {
                catalog_update(&self.spool, |catalog| {
                    catalog.checkpoint_accept(intent.clone())
                })?;
                Ok(intent)
            }
            Ok((actual, _))
                if Some(&actual) == previous
                    && matches!(
                        &put,
                        Err(S3Error::Forbidden
                            | S3Error::Boundary
                            | S3Error::Credentials
                            | S3Error::Conflict
                            | S3Error::AdmissionRefused)
                    ) =>
            {
                catalog_update(&self.spool, |catalog| {
                    catalog.checkpoint_cancel_unwritten(
                        key.clone(),
                        previous.cloned(),
                        state.blocked,
                        state.recovery_ready,
                    )
                })?;
                Err(put.err().ok_or(CheckpointError::Conflict)?.into())
            }
            Ok(_) => {
                catalog_update(&self.spool, |catalog| catalog.checkpoint_block(key.clone()))?;
                Err(CheckpointError::Conflict)
            }
            Err(error)
                if matches!(
                    &put,
                    Err(S3Error::Forbidden
                        | S3Error::Boundary
                        | S3Error::Credentials
                        | S3Error::AdmissionRefused)
                ) && matches!(
                    &error,
                    CheckpointError::Transport(
                        S3Error::Forbidden
                            | S3Error::Timeout
                            | S3Error::Unavailable
                            | S3Error::Throttled
                            | S3Error::AdmissionRefused
                            | S3Error::Budget
                            | S3Error::Cancelled
                    )
                ) =>
            {
                // These outcomes definitively reject the mutation; an auth circuit
                // may prevent readback, but there is no accepted intent to resolve.
                catalog_update(&self.spool, |catalog| {
                    catalog.checkpoint_cancel_unwritten(
                        key.clone(),
                        previous.cloned(),
                        state.blocked,
                        state.recovery_ready,
                    )
                })?;
                Err(error)
            }
            Err(error) => {
                let _ = put;
                Err(error)
            }
        }
    }
    /// Local activation is a separate short transaction after accepted readback.
    /// The caller must publish its in-process handle only after this succeeds.
    pub fn activate(
        &self,
        generation: &crate::recovery::VerifiedGeneration,
        intent: &PublicationIntent,
    ) -> Result<(), CheckpointError> {
        generation.ensure_current(&self.store)?;
        if generation.intent(intent.sequence) != *intent {
            return Err(CheckpointError::Proof);
        }
        self.spool
            .activate_publication(crate::catalog::publication::Activation {
                intent: intent.clone(),
                manifest: generation.manifest().clone(),
                valid_until: generation
                    .release()
                    .valid_until
                    .map(|until| until.as_secs()),
                now: ferrum_apt::release::UnixTime::now().as_secs(),
                confirmed_at: Some(generation.confirmed_at()),
                metadata: generation.proof.metadata_records()?,
            })?;
        self.cache_proof(generation.proof.clone())?;
        Ok(())
    }
    pub fn state(&self, key: &SuiteKey) -> Result<SuiteState, CheckpointError> {
        Ok(self
            .spool
            .durable_catalog()?
            .checkpoint_state(key.clone())?)
    }

    /// Reads durable suite state without blocking the async request executor.
    /// A full reader queue fails immediately; cancellation does not cancel admitted SQL.
    pub async fn state_async(&self, key: &SuiteKey) -> Result<SuiteState, CheckpointError> {
        Ok(self
            .spool
            .durable_catalog()?
            .checkpoint_state_async(key.clone())
            .await?)
    }

    /// Reads the active generation only when durable publication permits serving.
    /// Callers must separately enforce clock, view freshness, and retention checks.
    pub async fn available_generation(
        &self,
        key: &SuiteKey,
    ) -> Result<Option<String>, CheckpointError> {
        Ok(self
            .spool
            .durable_catalog()?
            .checkpoint_available_generation(key.clone())
            .await?)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SuiteState {
    pub observed_date: Option<i64>,
    pub observed_content: Option<String>,
    pub floor: Option<PublicationIntent>,
    pub active: Option<PublicationIntent>,
    pub pending: Option<PublicationIntent>,
    pub blocked: bool,
    pub bootstrap_authorized: bool,
    /// Historical floor artifacts are complete locally, but mutable service is
    /// still closed until current-origin confirmation or a newer CAS publication.
    pub recovery_ready: bool,
    pub candidate_generation: Option<String>,
    pub observed_at: Option<i64>,
    pub confirmed_at: Option<i64>,
    pub successor_seen_at: Option<i64>,
    pub last_error: Option<String>,
    pub next_check_at: Option<i64>,
}

impl CheckpointPublisher {
    /// Begins lost-state/pending-intent recovery. Unlike a normal availability
    /// probe this closes only the selected suite before consulting the remote floor.
    pub async fn recovery_floor(
        &self,
        key: &SuiteKey,
        trust: FloorTrust,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(PublicationIntent, String), CheckpointError> {
        catalog_update(&self.spool, |catalog| catalog.checkpoint_block(key.clone()))?;
        self.read_floor(key, trust, deadline, cancel).await
    }
}

pub(crate) fn catalog_update<T>(
    spool: &Spool,
    operation: impl FnOnce(&crate::catalog::Catalog) -> Result<T, CatalogError>,
) -> Result<T, CheckpointError> {
    let _admission = spool.catalog_admission(2 * 1024 * 1024)?;
    Ok(operation(spool.durable_catalog()?)?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    fn profiles_never_infer_isolation() {
        assert!(RecoveryProfile::ProviderIsolated.validate().is_err());
    }
    #[test]
    fn suite_keys_cannot_alias_prefixes() {
        assert!(SuiteKey::new("ubuntu", "../noble").is_err());
        assert_ne!(
            SuiteKey::new("ubuntu", "noble").unwrap(),
            SuiteKey::new("ubuntu", "noble-updates").unwrap()
        );
    }
}
