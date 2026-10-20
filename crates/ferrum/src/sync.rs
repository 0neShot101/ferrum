//! Suite synchronizer: the fixture subset of `PLAN.md` §6.
//!
//! Every candidate generation is authenticated end to end (InRelease signature,
//! detached Release signature, identity, dates, index hashes, package catalog)
//! and staged into the spool before it is published atomically. A rejected
//! candidate never replaces the active view.

mod catalog;
pub mod publication;
pub mod scheduler;
pub mod view;

pub use catalog::Catalog;
pub use publication::{DurableSynchronizer, SyncTrigger};

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrum_apt::digest::{ObjectIdentity, Sha256Digest, Sha256Hasher, Sha512Digest, Sha512Hasher};
use ferrum_apt::index::{IndexError, PackageRecord, parse_packages};
use ferrum_apt::path::RepositoryPath;
use ferrum_apt::release::{ParseLimits, Release, ReleaseError, UnixTime};
use ferrum_apt::signature::{SignatureError, SignatureVerifier};
use ferrum_storage::{Reservation, Spool, SpoolError, VerifiedObject};
use futures_util::StreamExt;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use self::view::ViewParts;
pub use self::view::{ActiveView, ByHashKey, CacheClass, HashAlgorithm, Resolution};
use crate::admin::jobs::JobRegistry;
use crate::config::{ARCHITECTURE, COMPONENT, Config, MAX_METADATA_BYTES, SUITE};
use crate::fetch::{FillError, SourceError, UpstreamClient, fill_object};
use crate::health::Metrics;

/// Tolerated clock skew for a Release `Date` in the future.
const MAX_FUTURE_DATE: Duration = Duration::from_secs(600);
/// Chunk size when installing in-memory metadata bytes through the spool writer.
const INSTALL_CHUNK: usize = 256 * 1024;
/// Longest `last_error` retained for health.
const MAX_LAST_ERROR: usize = 256;

/// Why a candidate generation was not published.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("{path}: {source}")]
    Source {
        path: &'static str,
        #[source]
        source: SourceError,
    },
    #[error("{path}: signature verification failed: {source}")]
    Signature {
        path: &'static str,
        #[source]
        source: SignatureError,
    },
    #[error("{path}: release parse failed: {source}")]
    Release {
        path: &'static str,
        #[source]
        source: ReleaseError,
    },
    #[error("identity check failed: {0}")]
    Identity(String),
    #[error("candidate Date is older than the active generation (rollback)")]
    Rollback,
    #[error("candidate has the active Date with different content (conflict)")]
    Conflict,
    #[error("Release and InRelease disagree: {0}")]
    ReleaseMismatch(&'static str),
    #[error("required index {0} is not listed in the Release")]
    MissingEntry(String),
    #[error("index {path}: {source}")]
    Fill {
        path: String,
        #[source]
        source: FillError,
    },
    #[error("index {0}: SHA512 does not match the Release")]
    Sha512Mismatch(String),
    #[error("Packages index rejected: {0}")]
    Index(#[from] IndexError),
    #[error("Packages index quarantined: {0}")]
    Quarantine(String),
    #[error("{path}: exceeds {MAX_METADATA_BYTES} bytes")]
    TooLarge { path: &'static str },
    #[error("spool: {0}")]
    Spool(#[from] SpoolError),
    #[error("scratch I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("publication authority: {0}")]
    Publication(#[from] ferrum_storage::checkpoint::CheckpointError),
}

impl SyncError {
    /// Whether the candidate was rejected by the trust chain (as opposed to an
    /// operational error such as the origin being down).
    pub fn is_rejection(&self) -> bool {
        match self {
            SyncError::Source { source, .. } => matches!(source, SourceError::Corrupt(_)),
            SyncError::Fill { source, .. } => {
                matches!(source, FillError::Corrupt(_) | FillError::NotFound)
            }
            SyncError::Spool(_) | SyncError::Io(_) => false,
            SyncError::Publication(error) => matches!(
                error,
                ferrum_storage::checkpoint::CheckpointError::Invalid
                    | ferrum_storage::checkpoint::CheckpointError::Proof
                    | ferrum_storage::checkpoint::CheckpointError::Signature(_)
                    | ferrum_storage::checkpoint::CheckpointError::Release(_)
            ),
            _ => true,
        }
    }

    /// Bounded summary (classification and path only) for health reporting.
    pub fn summary(&self) -> String {
        let text = match self {
            SyncError::Source { path, source } => format!("source {path}: {}", class_of(source)),
            SyncError::Signature { path, .. } => format!("signature rejected: {path}"),
            SyncError::Release { path, .. } => format!("release parse rejected: {path}"),
            SyncError::Identity(reason) => format!("identity rejected: {reason}"),
            SyncError::Rollback => "rollback rejected".to_owned(),
            SyncError::Conflict => "conflict rejected".to_owned(),
            SyncError::ReleaseMismatch(field) => format!("Release/InRelease mismatch: {field}"),
            SyncError::MissingEntry(path) => format!("missing index: {path}"),
            SyncError::Fill { path, source } => {
                format!("index fill {}: {path}", source.metrics_label())
            }
            SyncError::Sha512Mismatch(path) => format!("sha512 mismatch: {path}"),
            SyncError::Index(_) => "Packages index rejected".to_owned(),
            SyncError::Quarantine(path) => format!("quarantined: {path}"),
            SyncError::TooLarge { path } => format!("too large: {path}"),
            SyncError::Spool(_) => "spool error".to_owned(),
            SyncError::Io(_) => "scratch I/O error".to_owned(),
            SyncError::Publication(_) => "publication blocked".to_owned(),
        };
        truncate(text, MAX_LAST_ERROR)
    }
}

fn class_of(error: &SourceError) -> &'static str {
    match error {
        SourceError::NotFound => "not found",
        SourceError::Forbidden => "forbidden",
        SourceError::Transient(_) => "transient",
        SourceError::Timeout => "timeout",
        SourceError::Corrupt(_) => "corrupt",
        SourceError::Unexpected(_) => "unexpected status",
        SourceError::Io(_) => "transfer failed",
    }
}

fn truncate(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// Result of one successful authentication pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// A new generation was published.
    Published,
    /// The active generation was reconfirmed (same InRelease bytes).
    Renewed,
}

/// Authenticates the fixture suite and publishes complete generations.
pub struct Synchronizer {
    config: Arc<Config>,
    verifier: SignatureVerifier,
    spool: Spool,
    client: Arc<UpstreamClient>,
    catalog: Arc<Catalog>,
    metrics: Arc<Metrics>,
    scratch: Arc<ScratchSpace>,
    cpu_jobs: Arc<Semaphore>,
    limits: ParseLimits,
    trust: ferrum_storage::recovery::TrustPolicy,
    key: ferrum_storage::checkpoint::SuiteKey,
    trigger: SyncTrigger,
    observed: Mutex<Option<(UnixTime, Sha256Digest)>>,
    jobs: Option<Arc<JobRegistry>>,
}

/// Verified descriptors of the three mutable suite files.
struct SuiteFiles {
    inrelease: Vec<u8>,
    release: Vec<u8>,
    release_gpg: Vec<u8>,
    parsed: Release,
}

/// Scratch files share the exclusive process owner and byte budget of the spool.
/// Verifier supervisors retain this owner until their child has been reaped.
struct ScratchSpace {
    path: PathBuf,
    reservations: Vec<Reservation>,
}

impl ScratchSpace {
    fn open(config: &Config, spool: &Spool) -> Result<Self, SyncError> {
        let path = config.scratch_dir();
        if path.try_exists()? {
            if !std::fs::symlink_metadata(&path)?.is_dir()
                || std::fs::read(path.join(".ferrum-fixture-scratch"))?
                    != b"Ferrum fixture scratch\n"
            {
                return Err(SyncError::Identity("unowned scratch directory".to_owned()));
            }
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !entry.file_type()?.is_file()
                    || !(matches!(
                        name.as_ref(),
                        ".ferrum-fixture-scratch" | "InRelease" | "Release" | "Release.gpg"
                    ) || (name.starts_with("sqv-") && name.ends_with(".provisional")))
                {
                    return Err(SyncError::Identity("unexpected scratch entry".to_owned()));
                }
            }
            std::fs::remove_dir_all(&path)?;
        }
        std::fs::create_dir(&path)?;
        std::fs::write(
            path.join(".ferrum-fixture-scratch"),
            b"Ferrum fixture scratch\n",
        )?;
        let mut reservations = Vec::with_capacity(4);
        for _ in 0..4 {
            reservations.push(spool.reserve(MAX_METADATA_BYTES)?);
        }
        Ok(Self { path, reservations })
    }
}

impl Drop for ScratchSpace {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            tracing::error!(%error, "scratch cleanup failed; preserving byte reservations");
            std::mem::forget(std::mem::take(&mut self.reservations));
        }
    }
}

impl Synchronizer {
    /// Wipes and recreates the scratch directory, then returns the synchronizer.
    ///
    /// # Errors
    /// Scratch directory I/O.
    pub async fn new(
        config: Arc<Config>,
        verifier: SignatureVerifier,
        spool: Spool,
        client: Arc<UpstreamClient>,
        catalog: Arc<Catalog>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, SyncError> {
        let scratch = Arc::new(ScratchSpace::open(&config, &spool)?);
        let trust = ferrum_storage::recovery::TrustPolicy::LoopbackFixture {
            keyring: config.fixture.keyring.clone(),
        };
        let key = ferrum_storage::checkpoint::SuiteKey::new("fixture", SUITE)?;
        let trigger = SyncTrigger::new(vec![key.clone()]);
        Ok(Self {
            config,
            verifier,
            spool,
            client,
            catalog,
            metrics,
            scratch,
            cpu_jobs: ferrum_apt::signature::cpu_gate(),
            limits: ParseLimits::default(),
            trust,
            key,
            trigger,
            observed: Mutex::new(None),
            jobs: None,
        })
    }

    pub fn with_job_registry(mut self, jobs: Arc<JobRegistry>) -> Self {
        self.jobs = Some(jobs);
        self
    }

    async fn job_phase(
        &self,
        phase: &str,
        generation: Option<String>,
        completed: Option<u64>,
        total: Option<u64>,
        path: Option<String>,
    ) {
        if let Some(jobs) = &self.jobs {
            jobs.phase_changed(&self.key, phase, generation, completed, total, path)
                .await;
        }
    }

    pub fn trigger_handle(&self) -> SyncTrigger {
        self.trigger.clone()
    }

    /// Runs the first authentication, then repeats every `sync_interval` with
    /// ±10 % jitter until `cancel` fires. Failures are logged and recorded; the
    /// loop never exits on its own.
    pub async fn run(self, cancel: CancellationToken) {
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => return,
                _ = self.authenticate_and_record() => {}
            }
            let interval = jittered(self.config.limits.sync_interval);
            tokio::select! {
                () = cancel.cancelled() => return,
                () = self.trigger.notified() => {
                    let _ = self.trigger.take_pending();
                }
                () = tokio::time::sleep(interval) => {}
            }
        }
    }

    /// One pass with logging, metrics and health bookkeeping.
    pub async fn authenticate_and_record(&self) -> Result<SyncOutcome, SyncError> {
        if let Some(jobs) = &self.jobs {
            jobs.pass_started(&self.key, "observing").await;
        }
        let result = self.authenticate_once().await;
        match &result {
            Ok(SyncOutcome::Published) => {
                self.metrics.record_sync("published");
                self.catalog.set_last_error(None);
                let generation = self.catalog.load().map(|view| view.generation_id.to_hex());
                tracing::info!(
                    outcome = "published",
                    generation = generation.as_deref().unwrap_or("-"),
                    "sync published a new generation"
                );
            }
            Ok(SyncOutcome::Renewed) => {
                self.metrics.record_sync("renewed");
                self.catalog.set_last_error(None);
                tracing::info!(outcome = "renewed", "sync renewed the active generation");
            }
            Err(error) => {
                let summary = error.summary();
                let outcome = if error.is_rejection() {
                    "rejected"
                } else {
                    "error"
                };
                self.metrics.record_sync(outcome);
                self.catalog.set_last_error(Some(summary.clone()));
                let detail = truncate(error.to_string(), 512);
                if error.is_rejection() {
                    tracing::warn!(
                        outcome,
                        summary = %summary,
                        detail = %detail,
                        "sync rejected the candidate generation: verification failed; active view unchanged"
                    );
                } else {
                    tracing::warn!(
                        outcome,
                        summary = %summary,
                        detail = %detail,
                        "sync could not reach a verified candidate; active view unchanged"
                    );
                }
            }
        }
        if let Some(jobs) = &self.jobs {
            let generation = self.catalog.load().map(|view| view.generation_id.to_hex());
            let (outcome, error) = match &result {
                Ok(SyncOutcome::Published) => ("published", None),
                Ok(SyncOutcome::Renewed) => ("renewed", None),
                Err(error) => (
                    if error.is_rejection() {
                        "rejected"
                    } else {
                        "failed"
                    },
                    Some(error.summary()),
                ),
            };
            if jobs
                .pass_completed(
                    &self.key,
                    outcome,
                    if result.is_ok() { generation } else { None },
                    error,
                )
                .await
            {
                let _ = self
                    .trigger
                    .trigger(Some(self.key.repository()), Some(self.key.suite()));
            }
        }
        result
    }

    /// Authenticates the suite once (`PLAN.md` §6 fixture subset, steps 1-7).
    ///
    /// # Errors
    /// [`SyncError`]; the active view is never replaced on error.
    pub async fn authenticate_once(&self) -> Result<SyncOutcome, SyncError> {
        match tokio::time::timeout(
            self.config.limits.producer_deadline,
            self.authenticate_inner(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(SyncError::Source {
                path: "metadata authentication",
                source: SourceError::Timeout,
            }),
        }
    }

    async fn authenticate_inner(&self) -> Result<SyncOutcome, SyncError> {
        if Arc::strong_count(&self.scratch) != 1 {
            return Err(SyncError::Identity(
                "previous verifier is still being reaped".to_owned(),
            ));
        }
        if !self.catalog.clock_valid() {
            return Err(SyncError::Identity(
                "wall clock rolled backwards".to_owned(),
            ));
        }
        let inrelease_path = self.scratch.path.join("InRelease");
        let inrelease =
            download_bounded(&self.client, "dists/ferrum-test/InRelease", &inrelease_path).await?;
        self.job_phase(
            "verifying_metadata",
            None,
            None,
            None,
            Some("InRelease".into()),
        )
        .await;
        let authenticated = self
            .verifier
            .verify_cleartext_owned(
                &self.config.fixture.keyring,
                &inrelease_path,
                &self.scratch.path,
                MAX_METADATA_BYTES,
                Arc::clone(&self.scratch),
            )
            .await
            .map_err(|source| SyncError::Signature {
                path: "InRelease",
                source,
            })?;
        let candidate =
            Release::parse(&authenticated, &self.limits).map_err(|source| SyncError::Release {
                path: "InRelease",
                source,
            })?;
        check_identity(&candidate, &self.trust, &self.key)?;
        let generation_id = Sha256Digest::of(&inrelease);
        self.job_phase(
            "verifying_metadata",
            Some(generation_id.to_hex()),
            None,
            Some(6),
            Some("Release.gpg".into()),
        )
        .await;
        {
            let mut observed = self
                .observed
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some((date, digest)) = *observed {
                if candidate.date < date {
                    return Err(SyncError::Rollback);
                }
                if candidate.date == date && candidate.content_sha256() != digest {
                    return Err(SyncError::Conflict);
                }
            }
            *observed = Some((candidate.date, candidate.content_sha256()));
        }
        let active = self.catalog.load();
        if let Some(active) = active.as_deref() {
            if !self.catalog.clock_valid() {
                return Err(SyncError::Identity(
                    "wall clock rolled backwards".to_owned(),
                ));
            }
            if active.generation_id == generation_id {
                self.catalog
                    .publish(active.renewed(Instant::now(), UnixTime::now()));
                return Ok(SyncOutcome::Renewed);
            }
            if candidate.date < active.release_date {
                return Err(SyncError::Rollback);
            }
            if candidate.date == active.release_date
                && candidate.content_sha256() != active.content_sha256
            {
                return Err(SyncError::Conflict);
            }
        }

        let suite = self.verify_detached_release(inrelease, candidate).await?;
        self.job_phase(
            "staging",
            Some(generation_id.to_hex()),
            Some(0),
            Some(6),
            None,
        )
        .await;
        let (metadata_indexes, by_hash) = self.stage_indexes(&suite.parsed).await?;
        let packages_object = metadata_indexes
            .iter()
            .find(|(path, _)| path.as_str() == "dists/ferrum-test/main/binary-amd64/Packages")
            .map(|(_, object)| object.clone())
            .ok_or_else(|| SyncError::MissingEntry("main/binary-amd64/Packages".to_owned()))?;
        let packages = parse_catalog(
            &packages_object,
            Arc::clone(&self.cpu_jobs),
            self.config.limits.max_object_bytes,
        )
        .await?;

        let mut metadata: HashMap<RepositoryPath, (VerifiedObject, CacheClass)> = HashMap::new();
        for (name, bytes) in [
            ("InRelease", &suite.inrelease),
            ("Release", &suite.release),
            ("Release.gpg", &suite.release_gpg),
        ] {
            let object = install_bytes(&self.spool, bytes).await?;
            let path = suite_path(name)?;
            metadata.insert(path, (object, CacheClass::Mutable));
            self.job_phase(
                "staging",
                Some(generation_id.to_hex()),
                Some(metadata.len() as u64 + 3),
                Some(6),
                Some(name.into()),
            )
            .await;
        }
        for (path, object) in metadata_indexes {
            metadata.insert(path, (object, CacheClass::Canonical));
        }

        let reconfirmed =
            download_bounded(&self.client, "dists/ferrum-test/InRelease", &inrelease_path).await?;
        if Sha256Digest::of(&reconfirmed) != generation_id || !self.catalog.clock_valid() {
            return Err(SyncError::Identity(
                "candidate changed before publication".to_owned(),
            ));
        }
        check_identity(&suite.parsed, &self.trust, &self.key)?;
        let mut view = ActiveView::from_parts(ViewParts {
            generation_id,
            release_date: suite.parsed.date,
            content_sha256: suite.parsed.content_sha256(),
            valid_until: suite.parsed.valid_until,
            confirmed_at: Instant::now(),
            confirmed_at_unix: UnixTime::now(),
            lease: self.config.limits.active_lease,
            metadata,
            by_hash,
            packages,
        });
        if let Some(previous) = active.as_deref() {
            view.retain_from(previous).map_err(|path| {
                SyncError::Quarantine(format!("conflicting retained path {path}"))
            })?;
        }
        tracing::info!(
            generation = %generation_id,
            packages = view.package_count(),
            "candidate generation verified"
        );
        self.job_phase(
            "publishing",
            Some(generation_id.to_hex()),
            Some(6),
            Some(6),
            None,
        )
        .await;
        self.catalog.publish(view);
        Ok(SyncOutcome::Published)
    }

    /// Step 3: detached `Release` + `Release.gpg` must verify and agree with the
    /// InRelease parse.
    async fn verify_detached_release(
        &self,
        inrelease: Vec<u8>,
        candidate: Release,
    ) -> Result<SuiteFiles, SyncError> {
        let release_path = self.scratch.path.join("Release");
        let signature_path = self.scratch.path.join("Release.gpg");
        let release =
            download_bounded(&self.client, "dists/ferrum-test/Release", &release_path).await?;
        let release_gpg = download_bounded(
            &self.client,
            "dists/ferrum-test/Release.gpg",
            &signature_path,
        )
        .await?;
        self.verifier
            .verify_detached_owned(
                &self.config.fixture.keyring,
                &release_path,
                &signature_path,
                Arc::clone(&self.scratch),
            )
            .await
            .map_err(|source| SyncError::Signature {
                path: "Release.gpg",
                source,
            })?;
        let detached =
            Release::parse(&release, &self.limits).map_err(|source| SyncError::Release {
                path: "Release",
                source,
            })?;
        compare_releases(&candidate, &detached)?;
        Ok(SuiteFiles {
            inrelease,
            release,
            release_gpg,
            parsed: candidate,
        })
    }

    /// Step 4: the selected closure (three index entries) staged through the
    /// shared fill path, by-hash first, canonical path on confirmed absence.
    async fn stage_indexes(
        &self,
        release: &Release,
    ) -> Result<
        (
            Vec<(RepositoryPath, VerifiedObject)>,
            HashMap<ByHashKey, VerifiedObject>,
        ),
        SyncError,
    > {
        let directory = format!("{COMPONENT}/binary-{ARCHITECTURE}");
        for entry in release.entries() {
            if !matches!(
                entry.path.as_str().strip_prefix(&directory),
                Some("/Packages" | "/Packages.gz" | "/Release")
            ) {
                return Err(SyncError::Identity(format!(
                    "unsupported fixture target {}",
                    entry.path
                )));
            }
        }
        let mut staged = Vec::with_capacity(3);
        let mut by_hash = HashMap::with_capacity(6);
        for name in ["Packages", "Packages.gz", "Release"] {
            let relative = RepositoryPath::parse_decoded(&format!("{directory}/{name}"))
                .map_err(|error| SyncError::Identity(format!("index path {name}: {error}")))?;
            let entry = release
                .entry(&relative)
                .ok_or_else(|| SyncError::MissingEntry(relative.as_str().to_owned()))?;
            let sha256 = entry
                .sha256
                .ok_or_else(|| SyncError::MissingEntry(format!("{relative} (no SHA256 entry)")))?;
            let identity = ObjectIdentity {
                sha256,
                size: entry.size,
            };
            let canonical = suite_path(relative.as_str())?;
            self.job_phase(
                "staging",
                None,
                Some(staged.len() as u64),
                Some(6),
                Some(canonical.as_str().into()),
            )
            .await;
            let object = self.stage_one(identity, &canonical, &directory).await?;
            if let Some(expected) = entry.sha512 {
                if hash_sha512(&object, Arc::clone(&self.cpu_jobs)).await? != expected {
                    return Err(SyncError::Sha512Mismatch(relative.as_str().to_owned()));
                }
                by_hash.insert(
                    ByHashKey {
                        directory: directory.clone(),
                        algorithm: HashAlgorithm::Sha512,
                        hex: expected.to_hex(),
                    },
                    object.clone(),
                );
            }
            by_hash.insert(
                ByHashKey {
                    directory: directory.clone(),
                    algorithm: HashAlgorithm::Sha256,
                    hex: sha256.to_hex(),
                },
                object.clone(),
            );
            staged.push((canonical, object));
            self.job_phase("staging", None, Some(staged.len() as u64), Some(6), None)
                .await;
        }
        let plain = staged
            .iter()
            .find(|(path, _)| path.as_str().ends_with("/Packages"))
            .map(|(_, object)| object.identity())
            .ok_or_else(|| SyncError::MissingEntry("Packages".to_owned()))?;
        let compressed = staged
            .iter()
            .find(|(path, _)| path.as_str().ends_with("/Packages.gz"))
            .map(|(_, object)| object.clone())
            .ok_or_else(|| SyncError::MissingEntry("Packages.gz".to_owned()))?;
        verify_gzip(compressed, plain, Arc::clone(&self.cpu_jobs)).await?;
        Ok((staged, by_hash))
    }

    async fn stage_one(
        &self,
        identity: ObjectIdentity,
        canonical: &RepositoryPath,
        directory: &str,
    ) -> Result<VerifiedObject, SyncError> {
        if let Some(object) = self.spool.lookup(identity) {
            return Ok(object);
        }
        let by_hash_path = suite_path(&format!(
            "{directory}/by-hash/SHA256/{}",
            identity.sha256.to_hex()
        ))?;
        match self.fill_bounded(identity, &by_hash_path).await {
            Err(SyncError::Fill {
                source: FillError::NotFound,
                ..
            }) => {
                tracing::info!(path = %canonical, "by-hash alias absent; filling the canonical path");
                self.fill_bounded(identity, canonical).await
            }
            other => other,
        }
    }

    async fn fill_bounded(
        &self,
        identity: ObjectIdentity,
        path: &RepositoryPath,
    ) -> Result<VerifiedObject, SyncError> {
        let fill = fill_object(
            &self.client,
            &self.spool,
            identity,
            path,
            &self.config.limits,
        );
        let source = match tokio::time::timeout(self.config.limits.producer_deadline, fill).await {
            Ok(Ok(object)) => return Ok(object),
            Ok(Err(source)) => source,
            Err(_elapsed) => FillError::Timeout,
        };
        Err(SyncError::Fill {
            path: path.as_str().to_owned(),
            source,
        })
    }
}

/// Step 2: fixed fixture identity and date sanity.
fn check_identity(
    release: &Release,
    trust: &ferrum_storage::recovery::TrustPolicy,
    key: &ferrum_storage::checkpoint::SuiteKey,
) -> Result<(), SyncError> {
    trust.identity(key, release)?;
    let reject = |reason: String| Err(SyncError::Identity(reason));
    let now = UnixTime::now();
    let skew = i64::try_from(MAX_FUTURE_DATE.as_secs()).unwrap_or(i64::MAX);
    if release.date.as_secs() > now.as_secs().saturating_add(skew) {
        return reject("Date is in the future".to_owned());
    }
    if let Some(valid_until) = release.valid_until
        && valid_until <= now
    {
        return reject("Valid-Until has passed".to_owned());
    }
    Ok(())
}

fn compare_releases(inrelease: &Release, release: &Release) -> Result<(), SyncError> {
    let mismatch = |field| Err(SyncError::ReleaseMismatch(field));
    if inrelease.origin != release.origin {
        return mismatch("Origin");
    }
    if inrelease.suite != release.suite {
        return mismatch("Suite");
    }
    if inrelease.codename != release.codename {
        return mismatch("Codename");
    }
    if inrelease.date != release.date {
        return mismatch("Date");
    }
    if inrelease.valid_until != release.valid_until {
        return mismatch("Valid-Until");
    }
    if inrelease.architectures != release.architectures {
        return mismatch("Architectures");
    }
    if inrelease.components != release.components {
        return mismatch("Components");
    }
    if inrelease.acquire_by_hash != release.acquire_by_hash {
        return mismatch("Acquire-By-Hash");
    }
    if inrelease.entries() != release.entries() {
        return mismatch("hash tables");
    }
    if inrelease.label != release.label
        || inrelease.version != release.version
        || inrelease.no_support_for_architecture_all != release.no_support_for_architecture_all
    {
        return mismatch("release attributes");
    }
    Ok(())
}

/// Step 5: the authenticated package catalog (amd64/all records under `pool/`).
async fn parse_catalog(
    packages: &VerifiedObject,
    cpu_jobs: Arc<Semaphore>,
    max_object_bytes: u64,
) -> Result<HashMap<RepositoryPath, ObjectIdentity>, SyncError> {
    let permit = cpu_jobs
        .acquire_owned()
        .await
        .map_err(|_| SyncError::Identity("CPU gate closed".to_owned()))?;
    let object = packages.clone();
    let cancel = CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut catalog: HashMap<RepositoryPath, ObjectIdentity> = HashMap::new();
        let mut sink = |record: PackageRecord| -> Result<(), IndexError> {
            if cancel.is_cancelled() {
                return Err(IndexError::Sink("publication cancelled".to_owned()));
            }
            if record.architecture != ARCHITECTURE && record.architecture != "all" {
                return Ok(());
            }
            if record.filename.segments().next() != Some("pool") {
                return Err(IndexError::Sink(format!(
                    "Filename {} is outside pool/",
                    record.filename
                )));
            }
            if record.size > max_object_bytes {
                return Err(IndexError::Sink(format!(
                    "package {} exceeds object ceiling",
                    record.filename
                )));
            }
            let identity = ObjectIdentity {
                sha256: record.sha256,
                size: record.size,
            };
            match catalog.get(&record.filename) {
                Some(existing) if *existing != identity => Err(IndexError::Sink(format!(
                    "quarantine: Filename {} listed with two identities",
                    record.filename
                ))),
                _ => {
                    catalog.insert(record.filename, identity);
                    Ok(())
                }
            }
        };
        let file = std::fs::File::open(object.path())?;
        parse_packages(BufReader::new(file), &ParseLimits::default(), &mut sink).map_err(
            |error| match error {
                IndexError::Sink(reason) => SyncError::Quarantine(reason),
                other => SyncError::Index(other),
            },
        )?;
        Ok(catalog)
    })
    .await
    .map_err(|error| SyncError::Io(std::io::Error::other(error)))?
}

async fn hash_sha512(
    object: &VerifiedObject,
    cpu_jobs: Arc<Semaphore>,
) -> Result<Sha512Digest, SyncError> {
    let permit = cpu_jobs
        .acquire_owned()
        .await
        .map_err(|_| SyncError::Identity("CPU gate closed".to_owned()))?;
    let object = object.clone();
    let cancel = CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut file = std::fs::File::open(object.path())?;
        let mut buffer = [0; 64 * 1024];
        let mut hasher = Sha512Hasher::new();
        loop {
            if cancel.is_cancelled() {
                return Err(SyncError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "publication cancelled",
                )));
            }
            let length = file.read(&mut buffer)?;
            if length == 0 {
                return Ok(hasher.finalize());
            }
            hasher.update(&buffer[..length]);
        }
    })
    .await
    .map_err(|error| SyncError::Io(std::io::Error::other(error)))?
}

async fn verify_gzip(
    compressed: VerifiedObject,
    expected: ObjectIdentity,
    cpu_jobs: Arc<Semaphore>,
) -> Result<(), SyncError> {
    let permit = cpu_jobs
        .acquire_owned()
        .await
        .map_err(|_| SyncError::Identity("CPU gate closed".to_owned()))?;
    let cancel = CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let file = std::fs::File::open(compressed.path())?;
        let mut decoder = flate2::read::MultiGzDecoder::new(BufReader::new(file))
            .take(expected.size.saturating_add(1));
        let mut buffer = [0; 64 * 1024];
        let mut hash = Sha256Hasher::new();
        let mut size = 0u64;
        loop {
            if cancel.is_cancelled() {
                return Err(SyncError::Identity("decode cancelled".to_owned()));
            }
            let length = decoder.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            size += length as u64;
            hash.update(&buffer[..length]);
        }
        if size != expected.size || hash.finalize() != expected.sha256 {
            return Err(SyncError::Quarantine(
                "Packages.gz does not expand to signed Packages".to_owned(),
            ));
        }
        Ok(())
    })
    .await
    .map_err(|error| SyncError::Io(std::io::Error::other(error)))?
}

/// Streams `path` (relative to the origin base) into `destination`, refusing
/// bodies above [`MAX_METADATA_BYTES`], and returns the bytes.
async fn download_bounded(
    client: &UpstreamClient,
    path: &'static str,
    destination: &Path,
) -> Result<Vec<u8>, SyncError> {
    let repository_path = RepositoryPath::parse_decoded(path)
        .map_err(|error| SyncError::Identity(format!("constant path {path}: {error}")))?;
    let source = |source| SyncError::Source { path, source };
    let response = client.get(&repository_path, None).await.map_err(source)?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_METADATA_BYTES)
    {
        return Err(SyncError::TooLarge { path });
    }
    let mut file = tokio::fs::File::create(destination).await?;
    let mut bytes = Vec::new();
    let mut body = response.into_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(source)?;
        let next = u64::try_from(bytes.len())
            .ok()
            .and_then(|length| length.checked_add(u64::try_from(chunk.len()).ok()?))
            .ok_or(SyncError::TooLarge { path })?;
        if next > MAX_METADATA_BYTES {
            return Err(SyncError::TooLarge { path });
        }
        file.write_all(&chunk).await?;
        bytes.extend_from_slice(&chunk);
    }
    file.flush().await?;
    file.sync_data().await?;
    Ok(bytes)
}

/// Step 6: installs exact bytes as a spool object (identity from the bytes).
async fn install_bytes(spool: &Spool, bytes: &[u8]) -> Result<VerifiedObject, SyncError> {
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(bytes),
        size: u64::try_from(bytes.len()).map_err(|_| SyncError::Identity("length".to_owned()))?,
    };
    if let Some(object) = spool.lookup(identity) {
        return Ok(object);
    }
    let reservation = spool.reserve(identity.size)?;
    let mut writer = spool.begin_write(reservation, identity).await?;
    for chunk in bytes.chunks(INSTALL_CHUNK) {
        if let Err(error) = writer.write(bytes::Bytes::copy_from_slice(chunk)).await {
            writer.abort().await;
            return Err(error.into());
        }
    }
    Ok(writer.commit().await?)
}

fn suite_path(relative: &str) -> Result<RepositoryPath, SyncError> {
    RepositoryPath::parse_decoded(&format!("dists/{SUITE}/{relative}"))
        .map_err(|error| SyncError::Identity(format!("suite path {relative}: {error}")))
}

fn jittered(interval: Duration) -> Duration {
    interval.mul_f64(rand::random_range(0.9..=1.1))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn gzip_must_expand_to_the_exact_signed_uncompressed_identity() {
        let root = tempfile::tempdir().expect("spool parent");
        let spool = Spool::open_exclusive_fixture(ferrum_storage::SpoolConfig {
            root: root.path().join("spool"),
            managed_ceiling: 1024 * 1024,
            max_object_size: 1024 * 1024,
            io_workers: 2,
            read_chunk: 4096,
        })
        .expect("spool");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"authentic index").expect("gzip input");
        let compressed = encoder.finish().expect("gzip bytes");
        let object = install_bytes(&spool, &compressed)
            .await
            .expect("installed compressed index");
        let expected = ObjectIdentity {
            sha256: Sha256Digest::of(b"authentic index"),
            size: 15,
        };
        verify_gzip(object.clone(), expected, Arc::new(Semaphore::new(2)))
            .await
            .expect("matching sibling");
        let different = ObjectIdentity {
            sha256: Sha256Digest::of(b"different index"),
            size: 15,
        };
        assert!(
            verify_gzip(object.clone(), different, Arc::new(Semaphore::new(2)))
                .await
                .is_err()
        );
        let shorter = ObjectIdentity {
            sha256: expected.sha256,
            size: 2,
        };
        assert!(
            verify_gzip(object, shorter, Arc::new(Semaphore::new(2)))
                .await
                .is_err()
        );
    }
}
