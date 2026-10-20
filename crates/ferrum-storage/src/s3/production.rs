use super::{
    CHUNK, CONTROL, PrivateS3Config, PrivateStore, S3Error, S3ObjectMeta, S3Response,
    SINGLE_PUT_LIMIT, TransferStatus, bounded, classify_sdk, config,
};
use crate::budget::{BudgetClass, BudgetLedger};
use crate::{Spool, SpoolError, VerifiedObject};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest, Sha256Hasher};
use futures_util::StreamExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
pub(super) mod body;
mod circuit;
pub(super) mod dns;
mod maintenance;
mod metered;
mod multipart;
mod qualification;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transfer_tests;
mod uploads;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationIdentity {
    Object,
    Checkpoint,
    OfflineMaintenance,
    PrivateQualificationCleanup,
}
#[derive(Clone, Debug)]
pub enum ControlCondition {
    Create,
    Match(String),
}
pub struct ControlObject {
    pub bytes: Vec<u8>,
    pub etag: String,
}
/// A failure before a remote transfer has both reached EOF and committed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error(transparent)]
    S3(#[from] S3Error),
    #[error(transparent)]
    Spool(#[from] SpoolError),
}

/// Single-use evidence from this store's exact object GET and verified commit.
/// Local residency, HEAD and upload acknowledgments cannot construct it.
pub struct VerifiedFetch {
    identity: ObjectIdentity,
    operation: OperationIdentity,
    store: Arc<Semaphore>,
    owner: Spool,
}

impl VerifiedFetch {
    pub(crate) fn consume(
        self,
        store: &S3Store,
        spool: &Spool,
        identity: ObjectIdentity,
    ) -> Result<(), S3Error> {
        let production = store.production()?;
        if self.identity != identity
            || self.operation != OperationIdentity::Object
            || !Arc::ptr_eq(&self.store, &production.operations)
            || !spool.same_owner(&self.owner)
        {
            return Err(S3Error::Boundary);
        }

        production.check(&production.object_key(identity))
    }
}

/// Full object bytes were read back and hashed by this adapter. Construction is
/// private; neither a PUT ACK, HEAD nor metadata can manufacture this result.
pub struct VerifiedUpload {
    identity: ObjectIdentity,
    etag: String,
    key: String,
    _owner: Spool,
}
impl VerifiedUpload {
    pub fn identity(&self) -> ObjectIdentity {
        self.identity
    }
    pub fn etag(&self) -> &str {
        &self.etag
    }
    pub fn key(&self) -> &str {
        &self.key
    }
}
enum UploadOutcome {
    Acknowledged { etag: String, key: String },
    ReadBack(VerifiedUpload),
}
impl UploadOutcome {
    fn etag(self) -> String {
        match self {
            Self::Acknowledged { etag, .. } => etag,
            Self::ReadBack(verified) => verified.etag,
        }
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawS3Config {
    provider: Option<String>,
    account_id: Option<String>,
    endpoint: Option<String>,
    region: Option<String>,
    bucket: String,
    #[serde(default = "default_package_prefix")]
    package_prefix: String,
    #[serde(default = "default_checkpoint_prefix")]
    checkpoint_prefix: String,
    credentials_file: PathBuf,
    #[serde(default = "default_shared_nonisolated")]
    shared_nonisolated: bool,
}

fn default_package_prefix() -> String {
    config::DEFAULT_PACKAGE_PREFIX.into()
}

fn default_checkpoint_prefix() -> String {
    config::DEFAULT_CHECKPOINT_PREFIX.into()
}

fn default_shared_nonisolated() -> bool {
    true
}

impl From<RawS3Config> for S3Config {
    fn from(raw: RawS3Config) -> Self {
        let (endpoint, region) = config::resolve_provider_fields(
            raw.provider.as_deref(),
            raw.account_id.as_deref(),
            raw.endpoint,
            raw.region,
        );
        Self {
            endpoint,
            region,
            bucket: raw.bucket,
            package_prefix: raw.package_prefix,
            checkpoint_prefix: raw.checkpoint_prefix,
            credentials_file: raw.credentials_file,
            shared_nonisolated: raw.shared_nonisolated,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(from = "RawS3Config")]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub package_prefix: String,
    pub checkpoint_prefix: String,
    pub credentials_file: PathBuf,
    /// This initial supported profile is deliberately NONISOLATED.
    pub shared_nonisolated: bool,
}
impl S3Config {
    pub fn validate(&self) -> Result<(), S3Error> {
        let _ = config::valid_endpoint_and_host(&self.endpoint)?;
        if !config::valid_region(&self.region)
            || !config::valid_bucket(&self.bucket)
            || !config::valid_prefix(&self.package_prefix)
            || !config::valid_prefix(&self.checkpoint_prefix)
            || config::prefixes_overlap(&self.package_prefix, &self.checkpoint_prefix)
            || !self.shared_nonisolated
            || !self.credentials_file.is_absolute()
        {
            return Err(S3Error::Boundary);
        }
        config::no_symlink_ancestors(&self.credentials_file)?;
        Ok(())
    }
    /// Non-secret durable destination, with URL normalization and the effective
    /// qualification namespaces rather than an unscoped parent prefix.
    pub fn provider_identity(
        &self,
        qualification_run: Option<&str>,
    ) -> Result<crate::budget::ProviderIdentity, S3Error> {
        self.validate()?;
        let endpoint = url::Url::parse(&self.endpoint).map_err(|_| S3Error::Boundary)?;
        let (package_prefix, checkpoint_prefix) = match qualification_run {
            None => (self.package_prefix.clone(), self.checkpoint_prefix.clone()),
            Some(run) if crate::budget::provider::valid_run(run) => (
                format!("{}_ferrum-b07/{run}/", self.package_prefix),
                format!("{}_ferrum-b07/{run}/", self.checkpoint_prefix),
            ),
            Some(_) => return Err(S3Error::Boundary),
        };
        Ok(crate::budget::ProviderIdentity {
            endpoint: endpoint.to_string(),
            bucket: self.bucket.clone(),
            region: self.region.clone(),
            package_prefix,
            checkpoint_prefix,
        })
    }
}

/// One concrete SDK adapter. Private qualification retains its original journal
/// and operation boundary; production identities share one ledger and slot owner.
pub struct S3Store {
    pub(super) mode: Mode,
}
pub(super) enum Mode {
    Private(PrivateStore),
    Production(Production),
}
pub(super) struct Production {
    client: aws_sdk_s3::Client,
    transport: metered::Metered,
    config: RuntimeConfig,
    operations: Arc<Semaphore>,
    pub(super) data: Arc<Semaphore>,
    uploads: Arc<Semaphore>,
    circuit: Arc<Mutex<Circuit>>,
    key_locks: Mutex<std::collections::HashMap<String, std::sync::Weak<Semaphore>>>,
}
struct RuntimeConfig {
    bucket: String,
    package_prefix: Box<str>,
    checkpoint_prefix: Box<str>,
}
impl From<S3Config> for RuntimeConfig {
    fn from(config: S3Config) -> Self {
        Self {
            bucket: config.bucket,
            package_prefix: config.package_prefix.into_boxed_str(),
            checkpoint_prefix: config.checkpoint_prefix.into_boxed_str(),
        }
    }
}
#[derive(Clone, Copy)]
enum GetMode {
    Package,
    PackageReadback,
    Control,
}
impl GetMode {
    fn reconciliation(class: BudgetClass) -> Self {
        match class {
            BudgetClass::Control => Self::Control,
            BudgetClass::Package => Self::PackageReadback,
        }
    }
}
#[derive(Default)]
struct Circuit {
    forbidden: bool,
    transient: u8,
    until: Option<Instant>,
    probe: bool,
}
pub(super) fn now() -> Result<i64, S3Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_secs()).ok())
        .ok_or(S3Error::Budget)
}
fn database(error: impl std::fmt::Display) -> S3Error {
    S3Error::Journal(error.to_string())
}
impl S3Store {
    pub fn open(config: S3Config, ledger: BudgetLedger) -> Result<Self, S3Error> {
        let identity = config.provider_identity(None)?;
        if ledger.qualification_bound().map_err(database)? {
            return Err(S3Error::Boundary);
        }
        ledger.bind_provider(&identity).map_err(database)?;
        Self::open_scoped(config, ledger)
    }
    /// Same adapter, constrained to correlated disposable owned namespaces.
    pub fn open_qualification(
        mut config: S3Config,
        ledger: BudgetLedger,
        run_id: &str,
    ) -> Result<Self, S3Error> {
        let identity = config.provider_identity(Some(run_id))?;
        ledger.bind_provider(&identity).map_err(database)?;
        ledger
            .bind_qualification(run_id)
            .map_err(|_| S3Error::AdmissionRefused)?;
        config.package_prefix = identity.package_prefix;
        config.checkpoint_prefix = identity.checkpoint_prefix;
        Self::open_scoped(config, ledger)
    }
    fn open_scoped(config: S3Config, ledger: BudgetLedger) -> Result<Self, S3Error> {
        let transport = metered::Metered::new(ledger.clone(), &config)?;
        let client = config::client_for_credentials(
            &config.credentials_file,
            &config.endpoint,
            &config.region,
            &config.bucket,
            &config.package_prefix,
            transport.clone(),
        )?;
        let forbidden = ledger
            .spool()
            .durable_catalog()
            .map_err(database)?
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT forbidden FROM remote_health WHERE id=1",
                    [],
                    |row| row.get(0),
                )?)
            })
            .map_err(database)?;
        Ok(Self {
            mode: Mode::Production(Production {
                client,
                transport,
                config: config.into(),
                operations: Arc::new(Semaphore::new(16)),
                data: Arc::new(Semaphore::new(14)),
                uploads: Arc::new(Semaphore::new(2)),
                circuit: Arc::new(Mutex::new(Circuit {
                    forbidden,
                    ..Circuit::default()
                })),
                key_locks: Mutex::new(std::collections::HashMap::new()),
            }),
        })
    }
    #[cfg(any(test, feature = "test-harness"))]
    pub(super) fn scripted(
        config: S3Config,
        ledger: BudgetLedger,
        inner: aws_smithy_runtime_api::client::http::SharedHttpClient,
    ) -> Result<Self, S3Error> {
        let identity = Self::scripted_provider(&config, &ledger)?;
        let mut config = config;
        config.package_prefix = identity.package_prefix;
        config.checkpoint_prefix = identity.checkpoint_prefix;
        let forbidden = ledger
            .spool()
            .durable_catalog()
            .map_err(database)?
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT forbidden FROM remote_health WHERE id=1",
                    [],
                    |row| row.get(0),
                )?)
            })
            .map_err(database)?;
        let transport = metered::Metered::scripted(ledger.clone(), inner, &config)?;
        let sdk = aws_sdk_s3::Config::builder()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::v2026_01_12())
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .endpoint_url(&config.endpoint)
            .force_path_style(true)
            .disable_multi_region_access_points(true)
            .disable_s3_express_session_auth(true)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "TESTACCESS",
                "not-a-real-secret",
                None,
                None,
                "scripted-production",
            ))
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .response_checksum_validation(
                aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
            )
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .http_client(transport.clone())
            .build();
        Ok(Self {
            mode: Mode::Production(Production {
                client: aws_sdk_s3::Client::from_conf(sdk),
                transport,
                config: config.into(),
                operations: Arc::new(Semaphore::new(16)),
                data: Arc::new(Semaphore::new(14)),
                uploads: Arc::new(Semaphore::new(2)),
                circuit: Arc::new(Mutex::new(Circuit {
                    forbidden,
                    ..Circuit::default()
                })),
                key_locks: Mutex::new(std::collections::HashMap::new()),
            }),
        })
    }
    #[cfg(any(test, feature = "test-harness"))]
    pub(super) fn scripted_provider(
        config: &S3Config,
        ledger: &BudgetLedger,
    ) -> Result<crate::budget::ProviderIdentity, S3Error> {
        let run = match ledger.qualification_run().map_err(database)? {
            None => None,
            Some(Some(run)) => Some(run),
            Some(None) => return Err(S3Error::Boundary),
        };
        let identity = config.provider_identity(run.as_deref())?;
        ledger.bind_provider(&identity).map_err(database)?;
        Ok(identity)
    }
    pub fn initialize_private_journal(config: &PrivateS3Config) -> Result<(), S3Error> {
        PrivateStore::initialize_private_journal(config)
    }
    pub fn open_private(config: PrivateS3Config) -> Result<Self, S3Error> {
        Ok(Self {
            mode: Mode::Private(PrivateStore::open_private(config)?),
        })
    }
    pub fn status(&self) -> Result<TransferStatus, S3Error> {
        match &self.mode {
            Mode::Private(store) => store.status(),
            Mode::Production(_) => Err(S3Error::Unsupported),
        }
    }
    pub fn circuit_open(&self) -> bool {
        match &self.mode {
            Mode::Private(store) => store.circuit_open(),
            Mode::Production(store) => store.circuit.lock().map_or(true, |c| {
                c.forbidden || c.until.is_some_and(|until| Instant::now() < until)
            }),
        }
    }
    pub fn allowance_blocked(&self) -> bool {
        match &self.mode {
            Mode::Private(store) => store.allowance_blocked(),
            Mode::Production(store) => store
                .transport
                .ledger
                .usage()
                .map_or(true, |usage| !usage.certain),
        }
    }
    pub fn is_quarantined(&self, identity: ObjectIdentity) -> bool {
        match &self.mode {
            Mode::Private(store) => store.is_quarantined(identity),
            Mode::Production(store) => store
                .quarantined(&store.object_key(identity))
                .unwrap_or(true),
        }
    }
    pub fn quarantine(&self, identity: ObjectIdentity) -> Result<(), S3Error> {
        match &self.mode {
            Mode::Private(store) => store.quarantine(identity),
            Mode::Production(store) => store.quarantine(&store.object_key(identity)),
        }
    }
    pub async fn get(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<S3Response, S3Error> {
        match &self.mode {
            Mode::Private(store) => store.get(identity, deadline, cancel).await,
            Mode::Production(store) => {
                store
                    .get(
                        OperationIdentity::Object,
                        &store.object_key(identity),
                        identity.size,
                        false,
                        deadline,
                        &cancel,
                    )
                    .await
            }
        }
    }
    /// Downloads and commits one exact object, retaining non-replayable remote
    /// verification evidence for immediate capture. Dropping the future removes
    /// its temporary; queued filesystem work retains its reservation and lease.
    /// The deadline and token bound filesystem waits as well as HTTP. A commit
    /// already dispatched may finish locally, but timeout grants no capability.
    pub async fn fetch_verified(
        &self,
        spool: &Spool,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<(VerifiedObject, VerifiedFetch), FetchError> {
        let store = self.production()?;
        if !spool.same_owner(store.transport.ledger.spool()) {
            return Err(S3Error::Boundary.into());
        }

        if cancel.is_cancelled() {
            return Err(S3Error::Cancelled.into());
        }
        if Instant::now() >= deadline {
            return Err(S3Error::Timeout.into());
        }

        let transfer = async {
            let reservation = spool.reserve(identity.size)?;
            let response = self.get(identity, deadline, cancel.clone()).await?;
            let mut writer = spool.begin_write(reservation, identity).await?;
            let mut body = response.into_stream();
            while let Some(bytes) = body.next().await {
                if let Err(error) = writer.write(bytes?).await {
                    if matches!(
                        error,
                        SpoolError::Mismatch { .. } | SpoolError::Overflow { .. }
                    ) {
                        self.quarantine(identity)?;
                        return Err(S3Error::Corrupt.into());
                    }
                    return Err(error.into());
                }
            }

            match writer.commit().await {
                Ok(object) => Ok::<_, FetchError>(object),
                Err(error) => {
                    if matches!(
                        error,
                        SpoolError::Mismatch { .. } | SpoolError::Overflow { .. }
                    ) {
                        self.quarantine(identity)?;
                        return Err(S3Error::Corrupt.into());
                    }
                    Err(error.into())
                }
            }
        };
        // Keep typed spool failures inside the S3 deadline boundary. Dropping
        // the transfer retains reservations in any detached filesystem work.
        let object = bounded(deadline, &cancel, async { Ok(transfer.await) }).await??;
        if cancel.is_cancelled() {
            return Err(S3Error::Cancelled.into());
        }
        if Instant::now() >= deadline {
            return Err(S3Error::Timeout.into());
        }

        Ok((
            object,
            VerifiedFetch {
                identity,
                operation: OperationIdentity::Object,
                store: Arc::clone(&store.operations),
                owner: spool.clone(),
            },
        ))
    }

    pub async fn head(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<S3ObjectMeta, S3Error> {
        match &self.mode {
            Mode::Private(store) => store.head(identity, deadline, cancel).await,
            Mode::Production(store) => {
                let key = store.object_key(identity);
                store.check(&key)?;
                let _slots = store.slot(true, deadline, &cancel).await?;
                let client = store.client(
                    OperationIdentity::Object,
                    &key,
                    CONTROL,
                    BudgetClass::Control,
                )?;
                let result = bounded(deadline, &cancel, async {
                    client
                        .head_object()
                        .bucket(&store.config.bucket)
                        .key(&key)
                        .send()
                        .await
                        .map_err(|e| classify_sdk(e, true))
                })
                .await;
                store.outcome(&result)?;
                let output = result?;
                let length = output
                    .content_length()
                    .and_then(|n| u64::try_from(n).ok())
                    .ok_or(S3Error::Corrupt)?;
                if length != identity.size {
                    store.quarantine(&key)?;
                    return Err(S3Error::Corrupt);
                }
                Ok(S3ObjectMeta {
                    content_length: length,
                    etag: output.e_tag().map(str::to_owned),
                    version_id: output.version_id().map(str::to_owned),
                })
            }
        }
    }
    pub async fn put_file(
        &self,
        object: &VerifiedObject,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<String, S3Error> {
        match &self.mode {
            Mode::Private(store) => store.put_file(object, deadline, cancel).await,
            Mode::Production(store) => store
                .put_verified(object, deadline, &cancel)
                .await
                .map(UploadOutcome::etag),
        }
    }
    /// Production capture's single shared upload/readback operation. A multipart
    /// or ambiguous-ACK readback is reused rather than downloading twice.
    pub async fn put_file_verified(
        &self,
        object: &VerifiedObject,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<VerifiedUpload, S3Error> {
        let store = self.production()?;
        let identity = object.identity();
        match store.put_verified(object, deadline, &cancel).await? {
            UploadOutcome::ReadBack(verified) => Ok(verified),
            UploadOutcome::Acknowledged { etag, key } => {
                self.verify_seed(identity, deadline, cancel).await?;
                Ok(VerifiedUpload {
                    identity,
                    etag,
                    key,
                    _owner: store.transport.ledger.spool().clone(),
                })
            }
        }
    }
    pub async fn verify_seed(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<(), S3Error> {
        let response = match &self.mode {
            Mode::Private(store) => store.get(identity, deadline, cancel.clone()).await?,
            Mode::Production(store) => {
                store
                    .get_metered(
                        OperationIdentity::Object,
                        &store.object_key(identity),
                        identity.size,
                        GetMode::PackageReadback,
                        deadline,
                        &cancel,
                    )
                    .await?
            }
        };
        let mut body = response.into_stream();
        let mut size = 0u64;
        let mut hash = Sha256Hasher::new();
        while let Some(bytes) = body.next().await {
            let bytes = bytes?;
            size = size
                .checked_add(bytes.len() as u64)
                .ok_or(S3Error::Corrupt)?;
            if size > identity.size {
                self.quarantine(identity)?;
                return Err(S3Error::Corrupt);
            }
            hash.update(&bytes);
        }
        if size != identity.size || hash.finalize() != identity.sha256 {
            self.quarantine(identity)?;
            return Err(S3Error::Corrupt);
        }
        Ok(())
    }
    pub async fn corrupt_private_fixture(
        &self,
        object: &VerifiedObject,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<(), S3Error> {
        match &self.mode {
            Mode::Private(store) => {
                store
                    .corrupt_private_fixture(object, deadline, cancel)
                    .await
            }
            _ => Err(S3Error::Boundary),
        }
    }
    pub async fn probe_forbidden_private(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<(), S3Error> {
        match &self.mode {
            Mode::Private(store) => {
                store
                    .probe_forbidden_private(identity, deadline, cancel)
                    .await
            }
            _ => Err(S3Error::Boundary),
        }
    }
    pub async fn cleanup_private(
        &self,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<(), S3Error> {
        match &self.mode {
            Mode::Private(store) => store.cleanup_private(deadline, cancel).await,
            _ => Err(S3Error::Boundary),
        }
    }
    fn production(&self) -> Result<&Production, S3Error> {
        match &self.mode {
            Mode::Production(store) => Ok(store),
            _ => Err(S3Error::Boundary),
        }
    }
    pub async fn control_get(
        &self,
        identity: OperationIdentity,
        suffix: &str,
        maximum: u64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<ControlObject, S3Error> {
        if maximum > 1024 * 1024 || maximum == 0 {
            return Err(S3Error::Boundary);
        }
        let store = self.production()?;
        let key = store.key(identity, suffix)?;
        let response = store
            .get(identity, &key, maximum, true, deadline, cancel)
            .await?;
        let etag = response.etag.clone().ok_or(S3Error::Corrupt)?;
        let mut stream = response.into_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > maximum as usize {
                return Err(S3Error::Corrupt);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(ControlObject { bytes, etag })
    }
    pub async fn control_get_stream(
        &self,
        identity: OperationIdentity,
        suffix: &str,
        expected: ObjectIdentity,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<S3Response, S3Error> {
        let store = self.production()?;
        let key = store.key(identity, suffix)?;
        store
            .get(identity, &key, expected.size, true, deadline, cancel)
            .await
    }
    pub async fn control_put(
        &self,
        identity: OperationIdentity,
        suffix: &str,
        bytes: &[u8],
        condition: ControlCondition,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), S3Error> {
        if bytes.len() > 1024 * 1024 {
            return Err(S3Error::Boundary);
        }
        let store = self.production()?;
        let key = store.key(identity, suffix)?;
        store.check(&key)?;
        store
            .transport
            .ledger
            .reserve_storage(&key, bytes.len() as u64, BudgetClass::Control)
            .map_err(|_| S3Error::AdmissionRefused)?;
        let _slots = store.slot(true, deadline, cancel).await?;
        let client = store.client(identity, &key, CONTROL, BudgetClass::Control)?;
        let marker = store.mutation_marker(&key, matches!(&condition, ControlCondition::Create))?;
        let request = client
            .put_object()
            .bucket(&store.config.bucket)
            .key(&key)
            .metadata("ferrum-owner", marker)
            .content_length(bytes.len() as i64)
            .body(ByteStream::from(bytes.to_owned()));
        let request = match condition {
            ControlCondition::Create => request.if_none_match("*"),
            ControlCondition::Match(token) => {
                if token.is_empty() {
                    return Err(S3Error::Boundary);
                }
                request.if_match(token)
            }
        };
        let result = bounded(deadline, cancel, async {
            request.send().await.map_err(|e| classify_sdk(e, false))
        })
        .await;
        store.outcome(&result)?;
        if let Ok(output) = &result {
            store.mutation_accepted(&key, output.e_tag())?;
        }
        if result
            .as_ref()
            .is_ok_and(|out| out.version_id().is_some_and(|v| v != "null"))
        {
            return Err(S3Error::Unsupported);
        }
        result.map(|_| ())
    }
    /// Uploads a resident object from this store's spool. The exact path and
    /// identity must still name a verified object; SDK reads own its lease.
    pub async fn control_put_file(
        &self,
        suffix: &str,
        path: &Path,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), S3Error> {
        let store = self.production()?;
        let object = store
            .transport
            .ledger
            .spool()
            .lookup(identity)
            .filter(|object| object.path() == path)
            .ok_or(S3Error::Boundary)?;
        let key = store.key(OperationIdentity::Object, suffix)?;
        let _key = store.key_slot(&key, deadline, cancel).await?;
        store.check(&key)?;
        store
            .transport
            .ledger
            .reserve_storage(&key, identity.size, BudgetClass::Control)
            .map_err(|_| S3Error::Budget)?;
        if identity.size > SINGLE_PUT_LIMIT {
            let _upload = bounded(deadline, cancel, async {
                store
                    .uploads
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| S3Error::Cancelled)
            })
            .await?;
            store
                .multipart(&object, &key, BudgetClass::Control, deadline, cancel)
                .await?;
            return Ok(());
        }
        let marker = store.mutation_marker(&key, true)?;
        let result = {
            let _slots = store.slot(true, deadline, cancel).await?;
            let client = store.client(
                OperationIdentity::Object,
                &key,
                CONTROL,
                BudgetClass::Control,
            )?;
            let body = body::object_body(&object, 0, identity.size)?;
            bounded(deadline, cancel, async {
                client
                    .put_object()
                    .bucket(&store.config.bucket)
                    .key(&key)
                    .if_none_match("*")
                    .metadata("ferrum-owner", marker)
                    .content_length(identity.size as i64)
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| classify_sdk(e, false))
            })
            .await
        };
        store.outcome(&result)?;
        if let Ok(output) = &result {
            store.mutation_accepted(&key, output.e_tag())?;
        }
        if let Err(error) = result
            && !matches!(
                error,
                S3Error::Conflict | S3Error::Timeout | S3Error::Unavailable
            )
        {
            return Err(error);
        }
        let response = store
            .get(
                OperationIdentity::Object,
                &key,
                identity.size,
                true,
                deadline,
                cancel,
            )
            .await?;
        if let Err(error) = verify_response(response, identity).await {
            if error == S3Error::Corrupt {
                store.quarantine(&key)?;
            }
            return Err(error);
        }
        Ok(())
    }
    pub(crate) async fn capture_proof_slot(
        &self,
        suffix: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, S3Error> {
        let store = self.production()?;
        let key = store.key(OperationIdentity::Object, suffix)?;
        store.key_slot(&key, deadline, cancel).await
    }
    pub(crate) fn try_capture_path_slot(
        &self,
        repository: &str,
        path: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, S3Error> {
        self.production()?
            .key_gate(&format!(
                "capture-path:{repository}:{}",
                Sha256Digest::of(path.as_bytes())
            ))?
            .try_acquire_owned()
            .map_err(|_| S3Error::AdmissionRefused)
    }
    pub(crate) async fn capture_path_slot(
        &self,
        repository: &str,
        path: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, S3Error> {
        self.production()?
            .key_slot(
                &format!(
                    "capture-path:{repository}:{}",
                    Sha256Digest::of(path.as_bytes())
                ),
                deadline,
                cancel,
            )
            .await
    }
    pub(crate) async fn reconciliation_slot(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, S3Error> {
        self.production()?
            .key_slot("capture-reconciliation", deadline, cancel)
            .await
    }
    pub(crate) fn quarantine_control(&self, suffix: &str) -> Result<(), S3Error> {
        let store = self.production()?;
        store.quarantine(&store.key(OperationIdentity::Object, suffix)?)
    }
    pub(crate) fn ledger(&self) -> Result<&BudgetLedger, S3Error> {
        Ok(&self.production()?.transport.ledger)
    }
    pub fn package_key(&self, suffix: &str) -> Result<String, S3Error> {
        self.production()?.key(OperationIdentity::Object, suffix)
    }
    pub(crate) fn package_prefix(&self) -> Result<&str, S3Error> {
        Ok(&self.production()?.config.package_prefix)
    }
}
impl Production {
    fn key_gate(&self, key: &str) -> Result<Arc<Semaphore>, S3Error> {
        let mut locks = self.key_locks.lock().map_err(|_| S3Error::Unavailable)?;
        locks.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = locks.get(key).and_then(std::sync::Weak::upgrade) {
            Ok(gate)
        } else {
            if locks.len() >= 32 {
                return Err(S3Error::AdmissionRefused);
            }
            let gate = Arc::new(Semaphore::new(1));
            locks.insert(key.to_owned(), Arc::downgrade(&gate));
            Ok(gate)
        }
    }
    async fn key_slot(
        &self,
        key: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, S3Error> {
        let gate = self.key_gate(key)?;
        bounded(
            deadline.min(Instant::now() + Duration::from_secs(2)),
            cancel,
            async { gate.acquire_owned().await.map_err(|_| S3Error::Cancelled) },
        )
        .await
    }
    fn object_key(&self, identity: ObjectIdentity) -> String {
        format!(
            "{}v1/objects/sha256/{}",
            self.config.package_prefix, identity.sha256
        )
    }
    fn key(&self, identity: OperationIdentity, suffix: &str) -> Result<String, S3Error> {
        if identity == OperationIdentity::PrivateQualificationCleanup {
            return Err(S3Error::Boundary);
        }
        validate_suffix(identity, suffix)?;
        Ok(format!(
            "{}{}",
            if identity == OperationIdentity::Checkpoint {
                &self.config.checkpoint_prefix
            } else {
                &self.config.package_prefix
            },
            suffix
        ))
    }
    fn client(
        &self,
        identity: OperationIdentity,
        key: &str,
        maximum: u64,
        class: BudgetClass,
    ) -> Result<aws_sdk_s3::Client, S3Error> {
        self.client_metered(identity, key, maximum, class, false)
    }
    fn client_metered(
        &self,
        identity: OperationIdentity,
        key: &str,
        maximum: u64,
        class: BudgetClass,
        readback: bool,
    ) -> Result<aws_sdk_s3::Client, S3Error> {
        let wire = self
            .transport
            .scoped(identity, key.to_owned(), maximum, class)
            .with_readback(readback)
            .with_circuit(
                if identity == OperationIdentity::PrivateQualificationCleanup {
                    None
                } else {
                    Some(self.circuit.clone())
                },
            );
        Ok(aws_sdk_s3::Client::from_conf(
            self.client.config().to_builder().http_client(wire).build(),
        ))
    }
    fn quarantined(&self, key: &str) -> Result<bool, S3Error> {
        let key = key.to_owned();
        self.transport
            .ledger
            .spool()
            .durable_catalog()
            .map_err(database)?
            .read(move |connection| {
                Ok(connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM remote_quarantine WHERE key=?1)",
                    [key],
                    |row| row.get(0),
                )?)
            })
            .map_err(database)
    }
    fn quarantine(&self, key: &str) -> Result<(), S3Error> {
        quarantine_key(&self.transport.ledger, key)
    }
    fn check(&self, key: &str) -> Result<(), S3Error> {
        if self.quarantined(key)? {
            return Err(S3Error::Corrupt);
        }
        let circuit = self.circuit.lock().map_err(|_| S3Error::Unavailable)?;
        if circuit.forbidden {
            return Err(S3Error::Forbidden);
        }
        if let Some(until) = circuit.until
            && (Instant::now() < until || circuit.probe)
        {
            return Err(S3Error::Unavailable);
        }
        Ok(())
    }
    fn outcome<T>(&self, result: &Result<T, S3Error>) -> Result<(), S3Error> {
        let mut circuit = self.circuit.lock().map_err(|_| S3Error::Unavailable)?;
        match result {
            Err(S3Error::Forbidden) => {
                circuit.forbidden = true;
                self.transport
                    .ledger
                    .spool()
                    .catalog_write(|connection| {
                        connection
                            .execute("UPDATE remote_health SET forbidden=1 WHERE id=1", [])?;
                        Ok(())
                    })
                    .map_err(database)?;
            }
            Err(S3Error::Timeout | S3Error::Throttled | S3Error::Unavailable) => {
                circuit.transient = circuit.transient.saturating_add(1);
                if circuit.transient >= 5 {
                    circuit.until = Some(Instant::now() + Duration::from_secs(30));
                }
            }
            Ok(_) | Err(S3Error::NotFound | S3Error::Conflict) => {
                circuit.transient = 0;
                circuit.until = None;
            }
            _ => {}
        }
        Ok(())
    }
    async fn slot(
        &self,
        control: bool,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<
        (
            tokio::sync::OwnedSemaphorePermit,
            Option<tokio::sync::OwnedSemaphorePermit>,
        ),
        S3Error,
    > {
        bounded(
            deadline.min(Instant::now() + Duration::from_secs(2)),
            cancel,
            async {
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
            },
        )
        .await
    }
    async fn get(
        &self,
        identity: OperationIdentity,
        key: &str,
        maximum: u64,
        control: bool,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<S3Response, S3Error> {
        let mode = if control {
            GetMode::Control
        } else {
            GetMode::Package
        };
        self.get_metered(identity, key, maximum, mode, deadline, cancel)
            .await
    }
    async fn get_metered(
        &self,
        identity: OperationIdentity,
        key: &str,
        maximum: u64,
        mode: GetMode,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<S3Response, S3Error> {
        let control = matches!(mode, GetMode::Control);
        let readback = matches!(mode, GetMode::PackageReadback);
        self.check(key)?;
        let slots = self.slot(control, deadline, cancel).await?;
        let client = self.client_metered(
            identity,
            key,
            maximum,
            if control {
                BudgetClass::Control
            } else {
                BudgetClass::Package
            },
            readback,
        )?;
        let result = bounded(deadline, cancel, async {
            client
                .get_object()
                .bucket(&self.config.bucket)
                .key(key)
                .send()
                .await
                .map_err(|e| classify_sdk(e, false))
        })
        .await;
        if result.is_err() {
            self.outcome(&result)?;
        }
        let output = result?;
        let length = match output.content_length().and_then(|n| u64::try_from(n).ok()) {
            Some(length) => length,
            None => {
                self.quarantine(key)?;
                return Err(S3Error::Corrupt);
            }
        };
        if length > maximum || (!control && length != maximum) {
            self.quarantine(key)?;
            return Err(S3Error::Corrupt);
        }
        let etag = output.e_tag().map(str::to_owned);
        let version_id = output.version_id().map(str::to_owned);
        if version_id.as_deref().is_some_and(|v| v != "null") {
            return Err(S3Error::Unsupported);
        }
        let cancel = cancel.clone();
        let state = (
            output.body,
            Bytes::new(),
            slots,
            cancel,
            0u64,
            false,
            self.transport.ledger.clone(),
            key.to_owned(),
        );
        let stream = futures_util::stream::unfold(
            state,
            move |(mut body, mut pending, slots, cancel, mut consumed, finished, ledger, key)| async move {
                if finished {
                    return None;
                }
                if !pending.is_empty() {
                    let chunk = pending.split_to(pending.len().min(CHUNK));
                    return Some((
                        Ok(chunk),
                        (body, pending, slots, cancel, consumed, false, ledger, key),
                    ));
                }
                let next = bounded(
                    deadline.min(Instant::now() + Duration::from_secs(30)),
                    &cancel,
                    async { body.next().await.transpose().map_err(classify_body_error) },
                )
                .await;
                match next {
                    Ok(Some(mut bytes)) => {
                        consumed = consumed.saturating_add(bytes.len() as u64);
                        if consumed > maximum {
                            let _ = quarantine_key(&ledger, &key);
                            return Some((
                                Err(S3Error::Corrupt),
                                (
                                    body,
                                    Bytes::new(),
                                    slots,
                                    cancel,
                                    consumed,
                                    true,
                                    ledger,
                                    key,
                                ),
                            ));
                        }
                        let chunk = bytes.split_to(bytes.len().min(CHUNK));
                        Some((
                            Ok(chunk),
                            (body, bytes, slots, cancel, consumed, false, ledger, key),
                        ))
                    }
                    Ok(None) if consumed == length => None,
                    Ok(None) => {
                        let _ = quarantine_key(&ledger, &key);
                        Some((
                            Err(S3Error::Corrupt),
                            (body, pending, slots, cancel, consumed, true, ledger, key),
                        ))
                    }
                    Err(error) => {
                        if error == S3Error::Corrupt {
                            let _ = quarantine_key(&ledger, &key);
                        }
                        Some((
                            Err(error),
                            (body, pending, slots, cancel, consumed, true, ledger, key),
                        ))
                    }
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
    async fn put_verified(
        &self,
        object: &VerifiedObject,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<UploadOutcome, S3Error> {
        let identity = object.identity();
        if identity.size > 8 * 1024 * 1024 * 1024 {
            return Err(S3Error::Boundary);
        }
        let key = self.object_key(identity);
        self.check(&key)?;
        let _key = self.key_slot(&key, deadline, cancel).await?;
        self.transport
            .ledger
            .reserve_storage(&key, identity.size, BudgetClass::Package)
            .map_err(|_| S3Error::Budget)?;
        let _upload = bounded(
            deadline.min(Instant::now() + Duration::from_secs(2)),
            cancel,
            async {
                self.uploads
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| S3Error::Cancelled)
            },
        )
        .await?;
        if identity.size > SINGLE_PUT_LIMIT {
            return self
                .multipart(object, &key, BudgetClass::Package, deadline, cancel)
                .await
                .map(|etag| {
                    UploadOutcome::ReadBack(VerifiedUpload {
                        identity,
                        etag,
                        key,
                        _owner: self.transport.ledger.spool().clone(),
                    })
                });
        }
        let _slots = self.slot(false, deadline, cancel).await?;
        let client = self.client(
            OperationIdentity::Object,
            &key,
            CONTROL,
            BudgetClass::Package,
        )?;
        let body = body::object_body(object, 0, identity.size)?;
        let marker = self.mutation_marker(&key, true)?;
        let result = bounded(deadline, cancel, async {
            client
                .put_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .if_none_match("*")
                .metadata("ferrum-owner", marker)
                .content_length(identity.size as i64)
                .body(body)
                .send()
                .await
                .map_err(|e| classify_sdk(e, false))
        })
        .await;
        self.outcome(&result)?;
        if let Ok(output) = &result {
            self.mutation_accepted(&key, output.e_tag())?;
        }
        match result {
            Ok(output) => {
                if output.version_id().is_some_and(|v| v != "null") {
                    return Err(S3Error::Unsupported);
                }
                let etag = output.e_tag().ok_or(S3Error::Corrupt)?.to_owned();
                Ok(UploadOutcome::Acknowledged { etag, key })
            }
            Err(S3Error::Conflict | S3Error::Timeout | S3Error::Unavailable) => {
                drop(_slots);
                let response = self
                    .get_metered(
                        OperationIdentity::Object,
                        &key,
                        identity.size,
                        GetMode::PackageReadback,
                        deadline,
                        cancel,
                    )
                    .await?;
                let etag = response.etag.clone().ok_or(S3Error::Corrupt)?;
                if let Err(error) = verify_response(response, identity).await {
                    if error == S3Error::Corrupt {
                        self.quarantine(&key)?;
                    }
                    return Err(error);
                }
                Ok(UploadOutcome::ReadBack(VerifiedUpload {
                    identity,
                    etag,
                    key,
                    _owner: self.transport.ledger.spool().clone(),
                }))
            }
            Err(error) => Err(error),
        }
    }
}
async fn verify_response(response: S3Response, identity: ObjectIdentity) -> Result<(), S3Error> {
    let mut stream = response.into_stream();
    let mut size = 0u64;
    let mut hash = Sha256Hasher::new();
    while let Some(bytes) = stream.next().await {
        let bytes = bytes?;
        size = size
            .checked_add(bytes.len() as u64)
            .ok_or(S3Error::Corrupt)?;
        if size > identity.size {
            return Err(S3Error::Corrupt);
        }
        hash.update(&bytes);
    }
    if size != identity.size || hash.finalize() != identity.sha256 {
        return Err(S3Error::Corrupt);
    }
    Ok(())
}
fn validate_suffix(identity: OperationIdentity, suffix: &str) -> Result<(), S3Error> {
    if suffix.len() > 8192
        || suffix.contains(['%', '?', '#', '\\'])
        || suffix.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
    {
        return Err(S3Error::Boundary);
    }
    let mut split = suffix.split('/');
    let parts: [Option<&str>; 7] = std::array::from_fn(|_| split.next());
    let hex = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let allowed = match (identity, parts) {
        (
            OperationIdentity::PrivateQualificationCleanup,
            [
                Some("v1"),
                Some("checkpoints"),
                Some(_),
                Some(file),
                None,
                None,
                None,
            ],
        ) => file.ends_with(".json"),
        (
            OperationIdentity::Checkpoint,
            [
                Some("v1"),
                Some("checkpoints"),
                Some(_),
                Some(file),
                None,
                None,
                None,
            ],
        ) => file.ends_with(".json"),
        (OperationIdentity::Checkpoint, _) => false,
        (
            _,
            [
                Some("v1"),
                Some("objects"),
                Some("sha256"),
                Some(digest),
                None,
                None,
                None,
            ],
        ) => hex(digest),
        (
            _,
            [
                Some("v1"),
                Some("generations"),
                Some(_),
                Some(_),
                Some(generation),
                Some("manifest.json"),
                None,
            ],
        ) => hex(generation),
        (
            _,
            [
                Some("v1"),
                Some("captures"),
                Some(_),
                Some(path),
                Some(file),
                None,
                None,
            ],
        ) => hex(path) && file.strip_suffix(".json").is_some_and(hex),
        (
            _,
            [
                Some("v1"),
                Some("backups"),
                Some(hour),
                Some(file),
                None,
                None,
                None,
            ],
        ) => {
            hour.bytes().all(|b| b.is_ascii_digit())
                && (file
                    .strip_suffix(".sqlite")
                    .or_else(|| file.strip_suffix(".json")))
                .is_some_and(hex)
        }
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(S3Error::Boundary)
    }
}

fn namespace_suffix<'a>(
    identity: OperationIdentity,
    key: &'a str,
    package_prefix: &str,
    checkpoint_prefix: &str,
) -> Result<&'a str, S3Error> {
    let base_package = package_prefix
        .split_once("_ferrum-b07/")
        .map_or(package_prefix, |(base, _)| base);
    let base_checkpoint = checkpoint_prefix
        .split_once("_ferrum-b07/")
        .map_or(checkpoint_prefix, |(base, _)| base);
    let checkpoints = identity == OperationIdentity::Checkpoint
        || (identity == OperationIdentity::PrivateQualificationCleanup
            && key.starts_with(base_checkpoint));
    let suffix = key
        .strip_prefix(if checkpoints {
            base_checkpoint
        } else {
            base_package
        })
        .ok_or(S3Error::Boundary)?;
    if identity == OperationIdentity::PrivateQualificationCleanup
        && !suffix.starts_with("_ferrum-b07/")
    {
        return Err(S3Error::Boundary);
    }
    if let Some(rest) = suffix.strip_prefix("_ferrum-b07/") {
        let (run, suffix) = rest.split_once('/').ok_or(S3Error::Boundary)?;
        if run.len() != 32
            || !run
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(S3Error::Boundary);
        }
        return Ok(suffix);
    }
    Ok(suffix)
}
fn quarantine_key(ledger: &BudgetLedger, key: &str) -> Result<(), S3Error> {
    if let Err(error) = ledger.spool().quarantine_remote_key(key) {
        ledger.spool().close_capture_admission();
        tracing::error!(%error,"remote corruption quarantine could not persist; owner admission closed");
        return Err(S3Error::Corrupt);
    }
    Ok(())
}
fn classify_body_error(error: impl std::error::Error + 'static) -> S3Error {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(error) = cause {
        if let Some(error) = error.downcast_ref::<S3Error>() {
            return error.clone();
        }
        cause = error.source();
    }
    S3Error::Unavailable
}
