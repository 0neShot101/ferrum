//! Durable publication orchestration. Storage remains the sole activation,
//! package-index and checkpoint authority; this actor only stages authenticated
//! candidates and publishes a process handle after its transaction succeeds.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferrum_apt::digest::{ObjectIdentity, Sha256Digest, Sha512Digest, Sha512Hasher};
use ferrum_apt::path::RepositoryPath;
use ferrum_apt::release::{Release, UnixTime};
use ferrum_apt::signature::SignatureVerifier;
use ferrum_storage::checkpoint::{CheckpointError, CheckpointPublisher, FloorTrust, SuiteKey};
use ferrum_storage::disk::ReservationClass;
use ferrum_storage::recovery::{
    AuthenticatedObservation, DerivedArtifact, GenerationManifest, ManifestArtifact,
    OriginVerifier, PublicationVerification,
};
use ferrum_storage::{Spool, VerifiedObject};
use futures_util::StreamExt;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "test-harness")]
use super::SyncOutcome;
use super::scheduler::FairRounds;
use super::{ActiveView, Catalog, SyncError};
use crate::config::{Config, MAX_METADATA_BYTES, SuiteConfig};
use crate::fetch::{FillError, UpstreamClient};
use crate::health::Metrics;

struct SuiteRuntime {
    configuration: SuiteConfig,
    client: Arc<UpstreamClient>,
    origin: Arc<OriginVerifier>,
}

struct Shared {
    config: Arc<Config>,
    verifier: SignatureVerifier,
    spool: Spool,
    publisher: Arc<CheckpointPublisher>,
    catalog: Arc<Catalog>,
    metrics: Arc<Metrics>,
    suites: Vec<SuiteRuntime>,
}

struct Work {
    path: String,
    expected: Option<ObjectIdentity>,
    sha512: Option<Sha512Digest>,
}

struct Candidate {
    generation: Sha256Digest,
    release: Release,
    artifacts: Vec<(String, VerifiedObject)>,
    derived: Vec<DerivedArtifact>,
    work: VecDeque<Work>,
    detached_verified: bool,
}

struct Slot {
    saved: Option<(VerifiedObject, String)>,
    candidate: Option<Candidate>,
    // Superseded references survive until the current bounded object boundary.
    retiring: Option<Candidate>,
    observing: bool,
    bulk_active: bool,
    recovered: bool,
    publishing: Option<Sha256Digest>,
    next_check: Instant,
}

impl Slot {
    fn new() -> Self {
        Self {
            saved: None,
            candidate: None,
            retiring: None,
            observing: false,
            bulk_active: false,
            recovered: false,
            publishing: None,
            next_check: Instant::now(),
        }
    }
}

enum Event {
    Recovered(usize, Result<(), SyncError>),
    Observed(
        usize,
        Result<(AuthenticatedObservation, Option<String>), SyncError>,
    ),
    Staged(
        usize,
        Sha256Digest,
        String,
        Result<VerifiedObject, SyncError>,
    ),
    Detached(usize, Sha256Digest, Result<(), SyncError>),
    Finished(usize, Result<ActiveView, SyncError>),
}

/// Independent suite states, two observation jobs, two bulk jobs, and at most
/// one bulk operation per suite. No actor lock survives any I/O await.
pub struct DurableSynchronizer {
    shared: Arc<Shared>,
    slots: Vec<Slot>,
}

impl DurableSynchronizer {
    pub async fn new(
        config: Arc<Config>,
        verifier: SignatureVerifier,
        spool: Spool,
        publisher: Arc<CheckpointPublisher>,
        catalog: Arc<Catalog>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, SyncError> {
        let configurations = config
            .suites()
            .map_err(|error| SyncError::Identity(error.to_string()))?;
        catalog.configure_package_signatures(&verifier, &configurations)?;
        let mut suites: Vec<SuiteRuntime> = Vec::with_capacity(configurations.len());
        for configuration in configurations {
            let client = if let Some(existing) = suites
                .iter()
                .find(|suite| suite.configuration.origin == configuration.origin)
            {
                existing.client.clone()
            } else {
                Arc::new(
                    UpstreamClient::new(configuration.origin.clone(), &config.limits).map_err(
                        |source| SyncError::Source {
                            path: "origin client",
                            source,
                        },
                    )?,
                )
            };
            let origin = origin_verifier(&configuration)?;
            suites.push(SuiteRuntime {
                configuration,
                client,
                origin: Arc::new(origin),
            });
        }
        let keys: Vec<_> = suites
            .iter()
            .map(|suite| suite.configuration.key.clone())
            .collect();
        FairRounds::new(&keys)?;
        let slots = (0..suites.len()).map(|_| Slot::new()).collect();
        Ok(Self {
            shared: Arc::new(Shared {
                config,
                verifier,
                spool,
                publisher,
                catalog,
                metrics,
                suites,
            }),
            slots,
        })
    }

    pub async fn run(mut self, cancel: CancellationToken) {
        let keys: Vec<_> = self
            .shared
            .suites
            .iter()
            .map(|suite| suite.configuration.key.clone())
            .collect();
        let mut observations = match FairRounds::new(&keys) {
            Ok(rounds) => rounds,
            Err(error) => {
                tracing::error!(%error, "invalid suite scheduler");
                return;
            }
        };
        let mut rounds = match FairRounds::new(&keys) {
            Ok(rounds) => rounds,
            Err(error) => {
                tracing::error!(%error, "invalid suite scheduler");
                return;
            }
        };
        let mut jobs = JoinSet::new();
        loop {
            if cancel.is_cancelled() {
                break;
            }
            let mut observation_count = self.slots.iter().filter(|slot| slot.observing).count();
            let mut bootstrapping_active = self
                .slots
                .iter()
                .enumerate()
                .filter(|(idx, s)| {
                    (s.observing || s.candidate.is_some() || s.publishing.is_some())
                        && self
                            .shared
                            .publisher
                            .state(&keys[*idx])
                            .is_ok_and(|st| st.bootstrap_authorized && st.floor.is_none())
                })
                .count();
            for _ in 0..observations.suite_count() {
                if observation_count == 2 {
                    break;
                }
                let (_, index) = observations.next_opportunity();
                let is_bootstrapping = self
                    .shared
                    .publisher
                    .state(&keys[index])
                    .is_ok_and(|st| st.bootstrap_authorized && st.floor.is_none());
                let slot = &mut self.slots[index];
                if !slot.recovered
                    || slot.observing
                    || slot.next_check > Instant::now()
                    || (is_bootstrapping && bootstrapping_active >= 2)
                {
                    continue;
                }
                slot.observing = true;
                observation_count += 1;
                if is_bootstrapping {
                    bootstrapping_active += 1;
                }
                let shared = self.shared.clone();
                let token = cancel.child_token();
                let interval = super::jittered(self.shared.config.limits.sync_interval);
                slot.next_check = Instant::now() + interval;
                let next = UnixTime::now()
                    .as_secs()
                    .saturating_add(interval.as_secs() as i64);
                let saved = slot.saved.clone();
                if let Err(error) = self.shared.publisher.set_next_check(&keys[index], next) {
                    self.record_failure(index, &SyncError::Publication(error));
                }
                jobs.spawn(async move {
                    Event::Observed(index, observe(&shared, index, saved.as_ref(), &token).await)
                });
            }
            let mut bulk_count = self.slots.iter().filter(|slot| slot.bulk_active).count();
            for _ in 0..rounds.suite_count() {
                if bulk_count == 2 {
                    break;
                }
                let (_, index) = rounds.next_opportunity();
                let slot = &mut self.slots[index];
                if slot.bulk_active {
                    continue;
                }
                if !slot.recovered {
                    if slot.next_check > Instant::now() {
                        continue;
                    }
                    slot.bulk_active = true;
                    bulk_count += 1;
                    let shared = self.shared.clone();
                    let token = cancel.child_token();
                    jobs.spawn(async move {
                        Event::Recovered(index, recover(&shared, index, &token).await)
                    });
                    continue;
                }
                let Some(candidate) = slot.candidate.as_mut() else {
                    continue;
                };
                let shared = self.shared.clone();
                let token = cancel.child_token();
                slot.bulk_active = true;
                bulk_count += 1;
                if !candidate.detached_verified && candidate.artifacts.len() >= 3 {
                    let generation = candidate.generation;
                    let expected = candidate.release.content_sha256();
                    let pair = detached_pair(candidate);
                    jobs.spawn(async move {
                        Event::Detached(
                            index,
                            generation,
                            verify_detached(&shared, index, pair, expected, &token).await,
                        )
                    });
                } else if let Some(work) = candidate.work.pop_front() {
                    let generation = candidate.generation;
                    jobs.spawn(async move {
                        let path = work.path.clone();
                        let result = stage(&shared, index, work, &token).await;
                        Event::Staged(index, generation, path, result)
                    });
                } else if let Some(candidate) = slot.candidate.take() {
                    slot.publishing = Some(candidate.generation);
                    jobs.spawn(async move {
                        Event::Finished(index, finish(&shared, index, candidate, &token).await)
                    });
                }
            }
            tokio::select! {
                () = cancel.cancelled() => break,
                event = jobs.join_next(), if !jobs.is_empty() => {
                    match event {
                        Some(Ok(event)) => self.apply(event),
                        Some(Err(error)) => {
                            tracing::error!(%error, "publication worker failed; stopping scheduler");
                            cancel.cancel();
                        }
                        None => {}
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
        // Cancellation propagates to network/decoder owners. An acknowledged
        // checkpoint intent is activated synchronously even during shutdown.
        cancel.cancel();
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok(event) => self.apply(event),
                Err(error) => tracing::error!(%error, "publication shutdown worker failed"),
            }
        }
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Recovered(index, result) => {
                self.slots[index].bulk_active = false;
                match result {
                    Ok(()) => self.slots[index].recovered = true,
                    Err(error) => {
                        // Missing floors permit authenticated observations only;
                        // operational recovery errors retry with bounded backoff.
                        self.slots[index].recovered = matches!(
                            error,
                            SyncError::Publication(CheckpointError::UntrustedFloor)
                        );
                        self.slots[index].next_check =
                            Instant::now() + self.shared.config.limits.sync_interval;
                        self.record_failure(index, &error);
                    }
                }
            }
            Event::Observed(index, result) => {
                self.slots[index].observing = false;
                match result {
                    Ok((observation, validator)) => {
                        if let Some(validator) = validator {
                            self.slots[index].saved =
                                Some((observation.inrelease().clone(), validator));
                        } else {
                            self.slots[index].saved = None;
                        }
                        if let Err(error) = self.accept_observation(index, observation) {
                            self.record_failure(index, &error);
                        }
                    }
                    Err(error) => self.record_failure(index, &error),
                }
            }
            Event::Staged(index, generation, path, result) => {
                self.slots[index].bulk_active = false;
                self.slots[index].retiring = None;
                let current = self.slots[index]
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.generation == generation);
                if current {
                    match result {
                        Ok(object) => {
                            if let Some(candidate) = self.slots[index].candidate.as_mut() {
                                candidate.artifacts.push((path, object));
                            }
                        }
                        Err(error) => {
                            self.slots[index].candidate = None;
                            self.record_failure(index, &error);
                        }
                    }
                }
            }
            Event::Detached(index, generation, result) => {
                self.slots[index].bulk_active = false;
                self.slots[index].retiring = None;
                if self.slots[index]
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| candidate.generation == generation)
                {
                    match result {
                        Ok(()) => {
                            if let Some(candidate) = self.slots[index].candidate.as_mut() {
                                candidate.detached_verified = true;
                            }
                        }
                        Err(error) => {
                            self.slots[index].candidate = None;
                            self.record_failure(index, &error);
                        }
                    }
                }
            }
            Event::Finished(index, result) => {
                self.slots[index].bulk_active = false;
                self.slots[index].publishing = None;
                self.slots[index].retiring = None;
                match result {
                    Ok(view) => {
                        let key = &self.shared.suites[index].configuration.key;
                        match self.shared.catalog.publish_suite(key, view) {
                            Ok(()) => self.shared.metrics.record_sync("published"),
                            Err(error) => {
                                self.record_failure(index, &SyncError::Publication(error))
                            }
                        }
                    }
                    Err(error) => {
                        if self
                            .shared
                            .publisher
                            .state(&self.shared.suites[index].configuration.key)
                            .is_ok_and(|state| state.pending.is_some())
                        {
                            self.slots[index].candidate = None;
                            self.slots[index].recovered = false;
                        }
                        self.record_failure(index, &error);
                    }
                }
            }
        }
    }

    fn accept_observation(
        &mut self,
        index: usize,
        observation: AuthenticatedObservation,
    ) -> Result<(), SyncError> {
        let key = &self.shared.suites[index].configuration.key;
        let state = self.shared.publisher.state(key)?;
        if let Some(active) = self.shared.catalog.load_suite(key)
            && active.content_sha256 == observation.release().content_sha256()
            && active.generation_id == observation.inrelease().sha256()
            && state.successor_seen_at.is_none()
            && state.confirmed_at == Some(observation.observed_at())
        {
            let observed = observation.observed_at();
            let age = UnixTime::now()
                .as_secs()
                .checked_sub(observed)
                .filter(|age| *age >= 0)
                .ok_or(CheckpointError::Proof)? as u64;
            let confirmed_monotonic = Instant::now()
                .checked_sub(Duration::from_secs(age))
                .ok_or(CheckpointError::Proof)?;
            self.shared.catalog.publish_suite(
                key,
                active.renewed(confirmed_monotonic, UnixTime::from_secs(observed)),
            )?;
            self.shared.metrics.record_sync("renewed");
            return Ok(());
        }
        if state.pending.is_some() {
            return Err(CheckpointError::Conflict.into());
        }
        if state.floor.is_none() && !state.bootstrap_authorized {
            return Err(CheckpointError::UntrustedFloor.into());
        }
        let generation = observation.inrelease().sha256();
        if self.slots[index].publishing == Some(generation) {
            return Ok(());
        }
        if self.slots[index]
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.generation == generation)
        {
            return Ok(());
        }
        let mut candidate = candidate(&self.shared.suites[index].configuration, observation)?;
        if state
            .floor
            .as_ref()
            .is_some_and(|floor| floor.generation_id == generation.to_hex())
        {
            candidate.work.retain(|work| work.expected.is_none());
        }
        let old = self.slots[index].candidate.replace(candidate);
        if self.slots[index].bulk_active && self.slots[index].retiring.is_none() {
            self.slots[index].retiring = old;
        }
        Ok(())
    }

    fn record_failure(&self, index: usize, error: &SyncError) {
        let key = &self.shared.suites[index].configuration.key;
        let interval = self.shared.config.limits.sync_interval.as_secs() as i64;
        let next = UnixTime::now().as_secs().saturating_add(interval);
        let class = failure_class(error);
        if let Err(persistence) = self.shared.publisher.record_error(key, class, next) {
            tracing::error!(repository = key.repository(), suite = key.suite(), %persistence,
                "cannot persist suite failure");
        }
        self.shared.metrics.record_sync(if error.is_rejection() {
            "rejected"
        } else {
            "error"
        });
        tracing::warn!(repository = key.repository(), suite = key.suite(), class,
            error = %error, "suite candidate remains unpublished");
    }

    /// Authenticates one exact origin representation without staging/promoting it.
    /// The saved validator/object tuple is the same one used by the live actor.
    #[cfg(feature = "test-harness")]
    pub async fn observe_once(
        &mut self,
        key: &SuiteKey,
        cancel: &CancellationToken,
    ) -> Result<(), SyncError> {
        let index = self
            .shared
            .suites
            .iter()
            .position(|suite| &suite.configuration.key == key)
            .ok_or_else(|| SyncError::Identity("unconfigured test suite".into()))?;
        let (observation, validator) = observe(
            &self.shared,
            index,
            self.slots[index].saved.as_ref(),
            cancel,
        )
        .await?;
        self.slots[index].saved =
            validator.map(|validator| (observation.inrelease().clone(), validator));
        self.accept_observation(index, observation)
    }

    /// Deterministic private qualification seam: the same observation, per-object
    /// staging and durable finalization functions as the live actor, with no timer.
    #[cfg(feature = "test-harness")]
    pub async fn synchronize_once(
        &mut self,
        key: &SuiteKey,
        cancel: &CancellationToken,
    ) -> Result<SyncOutcome, SyncError> {
        let index = self
            .shared
            .suites
            .iter()
            .position(|suite| &suite.configuration.key == key)
            .ok_or_else(|| SyncError::Identity("unconfigured test suite".into()))?;
        if !self.slots[index].recovered {
            recover(&self.shared, index, cancel).await?;
            self.slots[index].recovered = true;
        }
        let observation = observe(
            &self.shared,
            index,
            self.slots[index].saved.as_ref(),
            cancel,
        )
        .await?;
        let (observation, validator) = observation;
        self.slots[index].saved =
            validator.map(|validator| (observation.inrelease().clone(), validator));
        self.accept_observation(index, observation)?;
        let Some(mut candidate) = self.slots[index].candidate.take() else {
            return Ok(SyncOutcome::Renewed);
        };
        stage_candidate(&self.shared, index, &mut candidate, cancel).await?;
        let view = finish(&self.shared, index, candidate, cancel).await?;
        self.shared.catalog.publish_suite(key, view)?;
        self.shared.metrics.record_sync("published");
        Ok(SyncOutcome::Published)
    }

    /// Deterministic private qualification bootstrap: stages the complete
    /// authenticated suite closure with streaming downloads, persists the
    /// generation closure to the durable store, records the explicit
    /// [`ferrum_storage::recovery::BootstrapAudit`] and activates the initial
    /// checkpoint floor.
    #[cfg(feature = "test-harness")]
    pub async fn bootstrap_once(
        &mut self,
        key: &SuiteKey,
        audit: ferrum_storage::recovery::BootstrapAudit,
        cancel: &CancellationToken,
    ) -> Result<SyncOutcome, SyncError> {
        let index = self
            .shared
            .suites
            .iter()
            .position(|suite| &suite.configuration.key == key)
            .ok_or_else(|| SyncError::Identity("unconfigured test suite".into()))?;
        if !self.shared.catalog.clock_valid() {
            return Err(CheckpointError::Origin.into());
        }
        let (observation, validator) = observe(
            &self.shared,
            index,
            self.slots[index].saved.as_ref(),
            cancel,
        )
        .await?;
        self.slots[index].saved =
            validator.map(|validator| (observation.inrelease().clone(), validator));
        let mut candidate = candidate(&self.shared.suites[index].configuration, observation)?;
        stage_candidate(&self.shared, index, &mut candidate, cancel).await?;
        let suite = &self.shared.suites[index];
        let manifest = manifest_from_candidate(&suite.configuration.key, &mut candidate)?;
        let persist_deadline =
            tokio::time::Instant::now() + self.shared.config.limits.producer_deadline;
        let staged_proof = tokio::select! {
            () = cancel.cancelled() => return Err(CheckpointError::Origin.into()),
            result = tokio::time::timeout_at(persist_deadline,
                ferrum_storage::recovery::verify_historical_proof(&self.shared.spool, &manifest,
                    &suite.configuration.policy, &self.shared.verifier)) =>
                result.map_err(|_| SyncError::Publication(CheckpointError::Proof))??,
        };
        self.shared
            .publisher
            .persist_generation(staged_proof.manifest(), persist_deadline, cancel)
            .await?;
        let bootstrap_deadline =
            tokio::time::Instant::now() + self.shared.config.limits.producer_deadline;
        let verification = PublicationVerification {
            policy: &suite.configuration.policy,
            verifier: &self.shared.verifier,
            origin: &suite.origin,
        };
        let (generation, _) = self
            .shared
            .publisher
            .bootstrap_current(&manifest, &verification, audit, bootstrap_deadline, cancel)
            .await?;
        if !self.shared.catalog.clock_valid() {
            return Err(CheckpointError::Origin.into());
        }
        let view = ActiveView::from_generation(
            &generation.proof(),
            generation.confirmed_at(),
            self.shared.config.limits.active_lease,
        )?;
        self.shared.catalog.publish_suite(key, view)?;
        self.slots[index].recovered = true;
        let interval = super::jittered(self.shared.config.limits.sync_interval);
        self.slots[index].next_check = Instant::now() + interval;
        let next = UnixTime::now()
            .as_secs()
            .saturating_add(interval.as_secs() as i64);
        let _ = self.shared.publisher.set_next_check(key, next);
        self.shared.metrics.record_sync("published");
        Ok(SyncOutcome::Published)
    }
}

fn failure_class(error: &SyncError) -> &'static str {
    match error {
        SyncError::Publication(CheckpointError::Signature(_)) | SyncError::Signature { .. } => {
            "signature"
        }
        SyncError::Publication(CheckpointError::Conflict) => "checkpoint_conflict",
        SyncError::Publication(CheckpointError::UntrustedFloor) => "untrusted_floor",
        SyncError::Publication(CheckpointError::Proof) => "proof",
        SyncError::Spool(_) | SyncError::Publication(CheckpointError::Spool(_)) => "storage",
        SyncError::Source { .. }
        | SyncError::Fill { .. }
        | SyncError::Publication(CheckpointError::Origin) => "origin",
        _ => "publication",
    }
}

fn origin_verifier(configuration: &SuiteConfig) -> Result<OriginVerifier, SyncError> {
    if configuration.origin.scheme() == "https" {
        return Ok(OriginVerifier::new()?);
    }
    if configuration.key.repository() == "fixture"
        && configuration.key.suite() == crate::config::SUITE
        && configuration.origin.as_str() == crate::config::ORIGIN_BASE_URL
        && matches!(
            configuration.policy,
            ferrum_storage::recovery::TrustPolicy::LoopbackFixture { .. }
        )
    {
        return Ok(OriginVerifier::new()?);
    }
    #[cfg(feature = "test-harness")]
    {
        let mut base = configuration.origin.clone();
        let suffix = format!("{}/", configuration.key.repository());
        let prefix = base
            .path()
            .strip_suffix(&suffix)
            .ok_or_else(|| SyncError::Identity("test origin repository prefix".into()))?
            .to_owned();
        base.set_path(&prefix);
        Ok(OriginVerifier::loopback_for_tests(base.as_str())?)
    }
    #[cfg(not(feature = "test-harness"))]
    Err(CheckpointError::Origin.into())
}

async fn recover(
    shared: &Shared,
    index: usize,
    cancel: &CancellationToken,
) -> Result<(), SyncError> {
    if !shared.catalog.clock_valid() {
        return Err(CheckpointError::Origin.into());
    }
    let suite = &shared.suites[index].configuration;
    if shared.publisher.state(&suite.key)?.bootstrap_authorized {
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + shared.config.limits.producer_deadline;
    // Local suite state may be absent after operator ledger reconciliation.
    // Only storage's authenticated intact off-VM floor can restore it; absence
    // or distrust there remains an error, never permission to bootstrap.
    shared
        .publisher
        .recover_floor_artifacts(
            &suite.key,
            FloorTrust::IntactTrusted,
            &suite.policy,
            &shared.verifier,
            deadline,
            cancel,
        )
        .await?;
    shared
        .publisher
        .restore_retained(
            &suite.key,
            &suite.policy,
            &shared.verifier,
            deadline,
            cancel,
        )
        .await?;
    Ok(())
}

async fn observe(
    shared: &Shared,
    index: usize,
    saved: Option<&(VerifiedObject, String)>,
    cancel: &CancellationToken,
) -> Result<(AuthenticatedObservation, Option<String>), SyncError> {
    if !shared.catalog.clock_valid() {
        return Err(CheckpointError::Origin.into());
    }
    let suite = &shared.suites[index];
    tokio::select! {
        () = cancel.cancelled() => Err(CheckpointError::Origin.into()),
        result = tokio::time::timeout(Duration::from_secs(60), suite.origin.observe_conditional(
            &shared.spool, &suite.configuration.key, &suite.configuration.policy,
            &shared.verifier, saved.map(|(object, validator)| (object, validator.as_str())),
            UnixTime::now().as_secs())) => {
                result.map_err(|_| SyncError::Publication(CheckpointError::Origin))?
                    .map_err(SyncError::from)
            }
    }
}

fn candidate(
    configuration: &SuiteConfig,
    observation: AuthenticatedObservation,
) -> Result<Candidate, SyncError> {
    let release = observation.release().clone();
    if configuration.policy.is_pacman() || configuration.policy.is_rpm() {
        let Some((metadata, entries)) = release.entries().split_first() else {
            return Err(SyncError::MissingEntry(
                "repository metadata closure".into(),
            ));
        };
        let artifacts = vec![(
            metadata.path.as_str().to_owned(),
            observation.inrelease().clone(),
        )];
        let mut work = VecDeque::with_capacity(entries.len());
        for entry in entries {
            work.push_back(Work {
                path: entry.path.as_str().to_owned(),
                expected: Some(ObjectIdentity {
                    sha256: entry.sha256.ok_or_else(|| {
                        SyncError::MissingEntry(format!("{}: SHA256", entry.path))
                    })?,
                    size: entry.size,
                }),
                sha512: None,
            });
        }
        return Ok(Candidate {
            generation: observation.inrelease().sha256(),
            release,
            artifacts,
            derived: Vec::new(),
            work,
            detached_verified: false,
        });
    }
    let (selected, _) = ferrum_apt::selection::select_for_architectures(
        &release,
        configuration.policy.components_for_suite(&release.codename),
        matches!(
            configuration.policy,
            ferrum_storage::recovery::TrustPolicy::Ubuntu { .. }
                | ferrum_storage::recovery::TrustPolicy::UbuntuPorts { .. }
        ),
        configuration.policy.architectures(),
    )
    .map_err(|error| SyncError::Identity(error.to_string()))?;
    let mut work = VecDeque::with_capacity(selected.len() + 2);
    for path in ["Release", "Release.gpg"] {
        work.push_back(Work {
            path: path.into(),
            expected: None,
            sha512: None,
        });
    }
    let mut derived = Vec::new();
    for target in selected {
        if let Some(source_path) = target.derived_from {
            derived.push(DerivedArtifact {
                path: target.path,
                source_path,
            });
        } else if target.pinned {
            let path = RepositoryPath::parse_decoded(&target.path)
                .map_err(|error| SyncError::Identity(error.to_string()))?;
            let entry = release
                .entry(&path)
                .ok_or_else(|| SyncError::MissingEntry(target.path.clone()))?;
            work.push_back(Work {
                path: target.path,
                expected: Some(ObjectIdentity {
                    sha256: entry
                        .sha256
                        .ok_or_else(|| SyncError::MissingEntry(format!("{path}: SHA256")))?,
                    size: entry.size,
                }),
                sha512: entry.sha512,
            });
        }
    }
    Ok(Candidate {
        generation: observation.inrelease().sha256(),
        release,
        artifacts: vec![("InRelease".into(), observation.inrelease().clone())],
        derived,
        work,
        detached_verified: false,
    })
}

fn detached_pair(candidate: &Candidate) -> Result<(VerifiedObject, VerifiedObject), SyncError> {
    if let Some((path, metadata)) = candidate.artifacts.first()
        && path.ends_with("/repodata/repomd.xml")
    {
        let signature = candidate
            .artifacts
            .get(1)
            .ok_or_else(|| SyncError::MissingEntry("repomd.xml.asc".into()))?;
        return Ok((metadata.clone(), signature.1.clone()));
    }
    if candidate
        .artifacts
        .first()
        .is_some_and(|(path, _)| path.ends_with(".db"))
    {
        let package = candidate
            .artifacts
            .get(1)
            .ok_or_else(|| SyncError::MissingEntry("Pacman canary package".into()))?;
        let signature = candidate
            .artifacts
            .get(2)
            .ok_or_else(|| SyncError::MissingEntry("Pacman canary signature".into()))?;
        return Ok((package.1.clone(), signature.1.clone()));
    }
    let find = |name: &str| {
        candidate
            .artifacts
            .iter()
            .find(|(path, _)| path == name)
            .map(|(_, object)| object.clone())
            .ok_or_else(|| SyncError::MissingEntry(name.into()))
    };
    Ok((find("Release")?, find("Release.gpg")?))
}

async fn verify_detached(
    shared: &Shared,
    index: usize,
    pair: Result<(VerifiedObject, VerifiedObject), SyncError>,
    expected: Sha256Digest,
    cancel: &CancellationToken,
) -> Result<(), SyncError> {
    let (release, signature) = pair?;
    let policy = &shared.suites[index].configuration.policy;
    let is_pacman = policy.is_pacman();
    let is_rpm = policy.is_rpm();
    let operation = async {
        let scratch = shared
            .spool
            .reserve_class(MAX_METADATA_BYTES, ReservationClass::Metadata)?;
        shared
            .verifier
            .verify_detached_owned(
                policy.keyring(),
                release.path(),
                signature.path(),
                (scratch, release.clone(), signature.clone()),
            )
            .await
            .map_err(|source| SyncError::Signature {
                path: if is_pacman {
                    "Pacman canary signature"
                } else if is_rpm {
                    "repomd.xml.asc"
                } else {
                    "Release.gpg"
                },
                source,
            })?;
        if is_pacman || is_rpm {
            return Ok(());
        }
        let bytes = release.read_bounded(MAX_METADATA_BYTES as usize).await?;
        let permit = ferrum_apt::signature::cpu_gate()
            .acquire_owned()
            .await
            .map_err(|_| SyncError::Identity("CPU gate closed".into()))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if Sha256Digest::of(&bytes) != expected
                && bytes
                    .strip_suffix(b"\n")
                    .is_none_or(|bytes| Sha256Digest::of(bytes) != expected)
            {
                return Err(SyncError::ReleaseMismatch("authenticated content"));
            }
            Ok(())
        })
        .await
        .map_err(|error| SyncError::Io(std::io::Error::other(error)))?
    };
    tokio::select! {
        () = cancel.cancelled() => Err(CheckpointError::Origin.into()),
        result = tokio::time::timeout(shared.config.limits.producer_deadline, operation) =>
            result.map_err(|_| SyncError::Publication(CheckpointError::Origin))?,
    }
}

async fn stage(
    shared: &Shared,
    index: usize,
    work: Work,
    cancel: &CancellationToken,
) -> Result<VerifiedObject, SyncError> {
    let operation = stage_inner(shared, index, work);
    tokio::select! {
        () = cancel.cancelled() => Err(CheckpointError::Origin.into()),
        result = tokio::time::timeout(shared.config.limits.producer_deadline, operation) =>
            result.map_err(|_| SyncError::Publication(CheckpointError::Origin))?,
    }
}

async fn stage_inner(
    shared: &Shared,
    index: usize,
    work: Work,
) -> Result<VerifiedObject, SyncError> {
    let suite = &shared.suites[index];
    if let Some(identity) = work.expected {
        if let Some(object) = shared.spool.lookup(identity) {
            return Ok(object);
        }
        let canonical = suite_path(&suite.configuration.key, &work.path)?;
        if suite.configuration.policy.is_pacman() || suite.configuration.policy.is_rpm() {
            return download_known(shared, &suite.client, &canonical, identity, work.sha512).await;
        }
        let directory = work
            .path
            .rsplit_once('/')
            .map_or("", |(directory, _)| directory);
        let alias = if directory.is_empty() {
            format!("by-hash/SHA256/{}", identity.sha256)
        } else {
            format!("{directory}/by-hash/SHA256/{}", identity.sha256)
        };
        let alias = suite_path(&suite.configuration.key, &alias)?;
        match download_known(shared, &suite.client, &alias, identity, work.sha512).await {
            Err(SyncError::Fill {
                source: FillError::NotFound,
                ..
            }) => download_known(shared, &suite.client, &canonical, identity, work.sha512).await,
            result => result,
        }
    } else {
        let path = suite_path(&suite.configuration.key, &work.path)?;
        let scratch = shared
            .spool
            .reserve_class(MAX_METADATA_BYTES, ReservationClass::Metadata)?;
        let response = suite
            .client
            .get(&path, None)
            .await
            .map_err(|source| SyncError::Source {
                path: "detached metadata",
                source,
            })?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_METADATA_BYTES)
        {
            return Err(SyncError::TooLarge {
                path: "detached metadata",
            });
        }
        let mut bytes = Vec::with_capacity(response.content_length().unwrap_or(4096) as usize);
        let mut stream = response.into_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|source| SyncError::Source {
                path: "detached metadata",
                source,
            })?;
            if (bytes.len() as u64).saturating_add(chunk.len() as u64) > MAX_METADATA_BYTES {
                return Err(SyncError::TooLarge {
                    path: "detached metadata",
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        drop(scratch);
        install_metadata(&shared.spool, bytes).await
    }
}

async fn install_metadata(spool: &Spool, bytes: Vec<u8>) -> Result<VerifiedObject, SyncError> {
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(&bytes),
        size: bytes.len() as u64,
    };
    if let Some(object) = spool.lookup(identity) {
        return Ok(object);
    }
    let reservation = spool.reserve_class(identity.size, ReservationClass::Metadata)?;
    let mut writer = spool.begin_write(reservation, identity).await?;
    writer.write(bytes.into()).await?;
    Ok(writer.commit().await?)
}

async fn download_known(
    shared: &Shared,
    client: &UpstreamClient,
    path: &RepositoryPath,
    identity: ObjectIdentity,
    expected_sha512: Option<Sha512Digest>,
) -> Result<VerifiedObject, SyncError> {
    let reservation = shared
        .spool
        .reserve_class(identity.size, ReservationClass::Metadata)?;
    let mut writer = shared.spool.begin_write(reservation, identity).await?;
    let attempts = shared.config.limits.source_attempts;
    for attempt in 0..attempts {
        let result = async {
            let response = client
                .get(path, Some(identity.size))
                .await
                .map_err(FillError::from)?;
            let mut stream = response.into_stream();
            let mut sha512 = Sha512Hasher::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(FillError::from)?;
                if expected_sha512.is_some() {
                    sha512.update(&chunk);
                }
                writer.write(chunk).await.map_err(FillError::from)?;
            }
            if expected_sha512.is_some_and(|expected| sha512.finalize() != expected) {
                return Err(FillError::Corrupt("metadata SHA512 mismatch".into()));
            }
            Ok::<(), FillError>(())
        }
        .await;
        match result {
            Ok(()) => return Ok(writer.commit().await?),
            Err(error) if error.is_retryable() && attempt + 1 < attempts => {
                writer.reset().await?;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(source) => {
                return Err(SyncError::Fill {
                    path: path.as_str().into(),
                    source,
                });
            }
        }
    }
    Err(SyncError::Fill {
        path: path.as_str().into(),
        source: FillError::Timeout,
    })
}

fn suite_path(key: &SuiteKey, path: &str) -> Result<RepositoryPath, SyncError> {
    if matches!(key.repository(), "almalinux" | "rockylinux") {
        return RepositoryPath::parse_decoded(path)
            .map_err(|error| SyncError::Identity(error.to_string()));
    }
    let public = if key.repository() == "cachyos" {
        format!(
            "x86_64/{}/{}",
            key.suite(),
            path.strip_prefix("x86_64/").unwrap_or(path)
        )
    } else if matches!(
        key.repository(),
        "archlinux" | "chaotic-aur" | "archlinuxcn" | "endeavouros"
    ) {
        format!("{}/{path}", key.suite())
    } else {
        format!("dists/{}/{path}", key.suite())
    };
    RepositoryPath::parse_decoded(&public).map_err(|error| SyncError::Identity(error.to_string()))
}

async fn finish(
    shared: &Shared,
    index: usize,
    mut candidate: Candidate,
    cancel: &CancellationToken,
) -> Result<ActiveView, SyncError> {
    if !shared.catalog.clock_valid() {
        return Err(CheckpointError::Origin.into());
    }
    if !candidate.detached_verified {
        return Err(CheckpointError::Proof.into());
    }
    let suite = &shared.suites[index];
    let deadline = tokio::time::Instant::now() + shared.config.limits.producer_deadline;
    let state = shared.publisher.state(&suite.configuration.key)?;
    if state
        .floor
        .as_ref()
        .is_some_and(|floor| floor.generation_id == candidate.generation.to_hex())
    {
        // A trusted generation's manifest is immutable, including artifact order
        // and reconstruction choices. Recover its exact original bytes rather
        // than rewriting that key from a newly assembled equivalent candidate.
        let verification = PublicationVerification {
            policy: &suite.configuration.policy,
            verifier: &shared.verifier,
            origin: &suite.origin,
        };
        let generation = shared
            .publisher
            .recover_suite(
                &suite.configuration.key,
                FloorTrust::IntactTrusted,
                &verification,
                deadline,
                cancel,
            )
            .await?;
        return Ok(ActiveView::from_generation(
            &generation.proof(),
            generation.confirmed_at(),
            shared.config.limits.active_lease,
        )?);
    }
    let manifest = manifest_from_candidate(&suite.configuration.key, &mut candidate)?;
    // Authenticate every local compressed/derived byte and stream all Packages
    // indexes before any candidate artifact becomes a remote publication input.
    let staged_proof = tokio::select! {
        () = cancel.cancelled() => return Err(CheckpointError::Origin.into()),
        result = tokio::time::timeout_at(deadline,
            ferrum_storage::recovery::verify_historical_proof(&shared.spool, &manifest,
                &suite.configuration.policy, &shared.verifier)) =>
            result.map_err(|_| SyncError::Publication(CheckpointError::Proof))??,
    };
    // Artifact+manifest PUT and mandatory exact readback precede origin
    // reconfirmation; no network await holds the local activation owner lock.
    shared
        .publisher
        .persist_generation(staged_proof.manifest(), deadline, cancel)
        .await?;
    let verification = PublicationVerification {
        policy: &suite.configuration.policy,
        verifier: &shared.verifier,
        origin: &suite.origin,
    };
    let generation = shared
        .publisher
        .verify_durable_generation(&manifest, &verification, deadline, cancel)
        .await?;
    if !shared.catalog.clock_valid() {
        return Err(CheckpointError::Origin.into());
    }
    if state.bootstrap_authorized {
        shared
            .publisher
            .complete_authorized_bootstrap(&generation, deadline, cancel)
            .await?;
    } else {
        let intent = shared
            .publisher
            .publish(&generation, deadline, cancel)
            .await?;
        // Never abandon a read-back durable intent, including on shutdown or
        // supersession. This synchronous storage-owned transaction is the cutover.
        shared.publisher.activate(&generation, &intent)?;
    }
    Ok(ActiveView::from_generation(
        &generation.proof(),
        generation.confirmed_at(),
        shared.config.limits.active_lease,
    )?)
}

#[cfg(feature = "test-harness")]
async fn stage_candidate(
    shared: &Shared,
    index: usize,
    candidate: &mut Candidate,
    cancel: &CancellationToken,
) -> Result<(), SyncError> {
    while let Some(work) = candidate.work.pop_front() {
        if work.expected.is_some() && !candidate.detached_verified && candidate.artifacts.len() >= 3
        {
            verify_detached(
                shared,
                index,
                detached_pair(candidate),
                candidate.release.content_sha256(),
                cancel,
            )
            .await?;
            candidate.detached_verified = true;
        }
        let path = work.path.clone();
        let object = stage(shared, index, work, cancel).await?;
        candidate.artifacts.push((path, object));
    }
    if !candidate.detached_verified {
        verify_detached(
            shared,
            index,
            detached_pair(candidate),
            candidate.release.content_sha256(),
            cancel,
        )
        .await?;
        candidate.detached_verified = true;
    }
    Ok(())
}

fn manifest_from_candidate(
    key: &SuiteKey,
    candidate: &mut Candidate,
) -> Result<GenerationManifest, SyncError> {
    let manifest = GenerationManifest {
        schema_version: 1,
        repository: key.repository().into(),
        suite: key.suite().into(),
        generation_id: candidate.generation.to_hex(),
        release_content_sha256: candidate.release.content_sha256().to_hex(),
        release_date: candidate.release.date.as_secs(),
        artifacts: candidate
            .artifacts
            .iter()
            .map(|(path, object)| ManifestArtifact {
                path: path.clone(),
                sha256: object.sha256().to_hex(),
                size: object.size(),
            })
            .collect(),
        derived: std::mem::take(&mut candidate.derived),
    };
    manifest.validate()?;
    Ok(manifest)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn suite_paths_use_repository_layout() {
        for (repository, suite, relative, expected) in [
            (
                "archlinux",
                "core",
                "os/x86_64/core.db",
                "core/os/x86_64/core.db",
            ),
            (
                "chaotic-aur",
                "chaotic-aur",
                "x86_64/chaotic-aur.db",
                "chaotic-aur/x86_64/chaotic-aur.db",
            ),
            (
                "archlinux",
                "extra",
                "os/x86_64/package.pkg.tar.zst.sig",
                "extra/os/x86_64/package.pkg.tar.zst.sig",
            ),
            (
                "cachyos",
                "cachyos-v3",
                "x86_64/cachyos-v3.db",
                "x86_64/cachyos-v3/cachyos-v3.db",
            ),
            (
                "archlinuxcn",
                "archlinuxcn",
                "x86_64/archlinuxcn.db",
                "archlinuxcn/x86_64/archlinuxcn.db",
            ),
            (
                "endeavouros",
                "endeavouros",
                "x86_64/endeavouros.db",
                "endeavouros/x86_64/endeavouros.db",
            ),
            (
                "almalinux",
                "9-baseos-aarch64",
                "9/BaseOS/aarch64/os/repodata/repomd.xml",
                "9/BaseOS/aarch64/os/repodata/repomd.xml",
            ),
            (
                "rockylinux",
                "10-appstream-x86-64",
                "10/AppStream/x86_64/os/repodata/repomd.xml.asc",
                "10/AppStream/x86_64/os/repodata/repomd.xml.asc",
            ),
            ("debian", "trixie", "Release", "dists/trixie/Release"),
        ] {
            let key = SuiteKey::new(repository, suite).expect("suite key");
            assert_eq!(suite_path(&key, relative).expect("path").as_str(), expected);
        }
    }
}
