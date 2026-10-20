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

use super::scheduler::FairRounds;
use super::{ActiveView, Catalog, SyncError, SyncOutcome};
use crate::admin::jobs::JobRegistry;
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

/// Handle used by the admin listener and CLI trigger to request an immediate
/// synchronization of all mirrors, one repository mirror, or one suite.
#[derive(Clone)]
pub struct SyncTrigger {
    keys: Arc<Vec<SuiteKey>>,
    pending: Arc<std::sync::Mutex<std::collections::BTreeSet<usize>>>,
    notify: Arc<tokio::sync::Notify>,
}

impl SyncTrigger {
    pub fn new(keys: Vec<SuiteKey>) -> Self {
        Self {
            keys: Arc::new(keys),
            pending: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new())),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn matches(key: &SuiteKey, repository: Option<&str>, suite: Option<&str>) -> bool {
        match (repository, suite) {
            (None, None) | (Some("all"), None) => true,
            (Some(repo), None) => key.repository() == repo,
            (Some(repo), Some(suite)) => key.repository() == repo && key.suite() == suite,
            (None, Some(_)) => false,
        }
    }

    /// Resolve configured targets without waking the actor. Durable admission
    /// must commit before the matching targets are actually triggered.
    pub fn matching(&self, repository: Option<&str>, suite: Option<&str>) -> Option<Vec<SuiteKey>> {
        let matched: Vec<_> = self
            .keys
            .iter()
            .filter(|key| Self::matches(key, repository, suite))
            .cloned()
            .collect();
        if matched.is_empty() {
            None
        } else {
            Some(matched)
        }
    }

    pub fn trigger(&self, repository: Option<&str>, suite: Option<&str>) -> Option<Vec<SuiteKey>> {
        let matched = self.matching(repository, suite)?;
        if let Ok(mut pending) = self.pending.lock() {
            for (index, key) in self.keys.iter().enumerate() {
                if Self::matches(key, repository, suite) {
                    pending.insert(index);
                }
            }
        }
        self.notify.notify_one();
        Some(matched)
    }

    pub(crate) fn take_pending(&self) -> Vec<usize> {
        self.pending
            .lock()
            .map(|mut pending| std::mem::take(&mut *pending).into_iter().collect())
            .unwrap_or_default()
    }

    pub(crate) async fn notified(&self) {
        self.notify.notified().await;
    }
}

/// Independent suite states, two observation jobs, two bulk jobs, and at most
/// one bulk operation per suite. No actor lock survives any I/O await.
pub struct DurableSynchronizer {
    shared: Arc<Shared>,
    slots: Vec<Slot>,
    trigger: SyncTrigger,
    jobs: Option<Arc<JobRegistry>>,
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
        if !keys.is_empty() {
            FairRounds::new(&keys)?;
        }
        let slots = (0..suites.len()).map(|_| Slot::new()).collect();
        let trigger = SyncTrigger::new(keys);
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
            trigger,
            jobs: None,
        })
    }

    pub fn with_job_registry(mut self, jobs: Arc<JobRegistry>) -> Self {
        self.jobs = Some(jobs);
        self
    }

    async fn job_phase(&self, index: usize, phase: &str, path: Option<String>) {
        if let Some(jobs) = &self.jobs {
            let slot = &self.slots[index];
            let (generation, completed, total) = match &slot.candidate {
                Some(candidate) => (
                    Some(candidate.generation.to_hex()),
                    Some(candidate.artifacts.len() as u64),
                    Some((candidate.artifacts.len() + candidate.work.len()) as u64),
                ),
                None => (
                    slot.publishing.map(|generation| generation.to_hex()),
                    None,
                    None,
                ),
            };
            jobs.phase_changed(
                &self.shared.suites[index].configuration.key,
                phase,
                generation,
                completed,
                total,
                path,
            )
            .await;
        }
    }

    async fn job_completed(
        &self,
        index: usize,
        outcome: &str,
        generation: Option<String>,
        error: Option<String>,
    ) {
        if let Some(jobs) = &self.jobs {
            let key = &self.shared.suites[index].configuration.key;
            if jobs.pass_completed(key, outcome, generation, error).await {
                let _ = self
                    .trigger
                    .trigger(Some(key.repository()), Some(key.suite()));
            }
        }
    }

    pub fn trigger_handle(&self) -> SyncTrigger {
        self.trigger.clone()
    }

    pub async fn run(mut self, cancel: CancellationToken) {
        let keys: Vec<_> = self
            .shared
            .suites
            .iter()
            .map(|suite| suite.configuration.key.clone())
            .collect();
        if keys.is_empty() {
            cancel.cancelled().await;
            return;
        }
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
            for index in self.trigger.take_pending() {
                if let Some(slot) = self.slots.get_mut(index) {
                    slot.next_check = Instant::now();
                    let _ = self
                        .shared
                        .publisher
                        .set_next_check(&keys[index], UnixTime::now().as_secs());
                }
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
                if let Some(jobs) = &self.jobs {
                    jobs.pass_started(&keys[index], "observing").await;
                }
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
                    self.record_failure(index, &SyncError::Publication(error))
                        .await;
                }
                jobs.spawn(async move {
                    Event::Observed(index, observe(&shared, index, saved.as_ref(), &token).await)
                });
            }
            let mut recovery_count = self
                .slots
                .iter()
                .filter(|slot| slot.bulk_active && !slot.recovered)
                .count();
            for _ in 0..rounds.suite_count() {
                if recovery_count >= 8 {
                    break;
                }
                let (_, index) = rounds.next_opportunity();
                let slot = &mut self.slots[index];
                if slot.recovered || slot.bulk_active || slot.next_check > Instant::now() {
                    continue;
                }
                slot.bulk_active = true;
                recovery_count += 1;
                if let Some(jobs) = &self.jobs {
                    jobs.pass_started(&keys[index], "recovering").await;
                }
                let shared = self.shared.clone();
                let token = cancel.child_token();
                jobs.spawn(async move {
                    Event::Recovered(index, recover(&shared, index, &token).await)
                });
            }
            let mut bulk_count = self
                .slots
                .iter()
                .filter(|slot| slot.bulk_active && slot.recovered)
                .count();
            for _ in 0..rounds.suite_count() {
                if bulk_count == 2 {
                    break;
                }
                let (_, index) = rounds.next_opportunity();
                let slot = &mut self.slots[index];
                if slot.bulk_active || !slot.recovered {
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
                    if let Some(registry) = &self.jobs {
                        registry
                            .phase_changed(
                                &keys[index],
                                "verifying_metadata",
                                Some(generation.to_hex()),
                                Some(candidate.artifacts.len() as u64),
                                Some((candidate.artifacts.len() + candidate.work.len()) as u64),
                                Some("Release.gpg".into()),
                            )
                            .await;
                    }
                    jobs.spawn(async move {
                        Event::Detached(
                            index,
                            generation,
                            verify_detached(&shared, index, pair, expected, &token).await,
                        )
                    });
                } else if let Some(work) = candidate.work.pop_front() {
                    let generation = candidate.generation;
                    if let Some(registry) = &self.jobs {
                        registry
                            .phase_changed(
                                &keys[index],
                                "staging",
                                Some(generation.to_hex()),
                                Some(candidate.artifacts.len() as u64),
                                Some((candidate.artifacts.len() + candidate.work.len() + 1) as u64),
                                Some(work.path.clone()),
                            )
                            .await;
                    }
                    jobs.spawn(async move {
                        let path = work.path.clone();
                        let result = stage(&shared, index, work, &token).await;
                        Event::Staged(index, generation, path, result)
                    });
                } else if let Some(candidate) = slot.candidate.take() {
                    slot.publishing = Some(candidate.generation);
                    if let Some(registry) = &self.jobs {
                        registry
                            .phase_changed(
                                &keys[index],
                                "publishing",
                                Some(candidate.generation.to_hex()),
                                Some(candidate.artifacts.len() as u64),
                                Some(candidate.artifacts.len() as u64),
                                None,
                            )
                            .await;
                    }
                    jobs.spawn(async move {
                        Event::Finished(index, finish(&shared, index, candidate, &token).await)
                    });
                }
            }
            tokio::select! {
                () = cancel.cancelled() => break,
                () = self.trigger.notified() => {}
                event = jobs.join_next(), if !jobs.is_empty() => {
                    match event {
                        Some(Ok(event)) => self.apply(event).await,
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
                Ok(event) => self.apply(event).await,
                Err(error) => tracing::error!(%error, "publication shutdown worker failed"),
            }
        }
    }

    async fn apply(&mut self, event: Event) {
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
                        self.record_failure(index, &error).await;
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
                        if let Err(error) = self.accept_observation(index, observation).await {
                            self.record_failure(index, &error).await;
                        }
                    }
                    Err(error) => self.record_failure(index, &error).await,
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
                            self.job_phase(index, "staging", None).await;
                        }
                        Err(error) => {
                            self.slots[index].candidate = None;
                            self.record_failure(index, &error).await;
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
                            self.job_phase(index, "staging", None).await;
                        }
                        Err(error) => {
                            self.slots[index].candidate = None;
                            self.record_failure(index, &error).await;
                        }
                    }
                }
            }
            Event::Finished(index, result) => {
                self.slots[index].bulk_active = false;
                let finished_generation = self.slots[index]
                    .publishing
                    .map(|generation| generation.to_hex());
                self.slots[index].publishing = None;
                self.slots[index].retiring = None;
                match result {
                    Ok(view) => {
                        let key = &self.shared.suites[index].configuration.key;
                        let generation = view.generation_id.to_hex();
                        match self.shared.catalog.publish_suite(key, view) {
                            Ok(()) => {
                                self.shared.metrics.record_sync("published");
                                self.job_completed(index, "published", Some(generation), None)
                                    .await;
                            }
                            Err(error) => {
                                self.record_generation_failure(
                                    index,
                                    &SyncError::Publication(error),
                                    Some(generation),
                                )
                                .await
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
                        self.record_generation_failure(index, &error, finished_generation)
                            .await;
                    }
                }
            }
        }
    }

    async fn accept_observation(
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
            self.job_completed(index, "renewed", Some(active.generation_id.to_hex()), None)
                .await;
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
        self.job_phase(index, "staging", None).await;
        Ok(())
    }

    async fn record_failure(&self, index: usize, error: &SyncError) {
        self.record_generation_failure(index, error, None).await;
    }

    async fn record_generation_failure(
        &self,
        index: usize,
        error: &SyncError,
        generation: Option<String>,
    ) {
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
        self.job_completed(
            index,
            if error.is_rejection() {
                "rejected"
            } else {
                "failed"
            },
            generation,
            Some(error.summary()),
        )
        .await;
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
        if let Some(jobs) = &self.jobs {
            jobs.pass_started(key, "observing").await;
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
        self.accept_observation(index, observation).await
    }

    /// Deterministic single-suite synchronization pass: runs the same
    /// recovery, observation, per-object staging and durable finalization
    /// functions as the live actor, with no timer.
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
        let result = self.synchronize_index(index, cancel).await;
        match &result {
            Ok(outcome) => {
                let generation = self
                    .shared
                    .catalog
                    .load_suite(key)
                    .map(|view| view.generation_id.to_hex());
                self.job_completed(
                    index,
                    if *outcome == SyncOutcome::Published {
                        "published"
                    } else {
                        "renewed"
                    },
                    generation,
                    None,
                )
                .await;
            }
            Err(error) => self.record_failure(index, error).await,
        }
        result
    }

    async fn synchronize_index(
        &mut self,
        index: usize,
        cancel: &CancellationToken,
    ) -> Result<SyncOutcome, SyncError> {
        let key = self.shared.suites[index].configuration.key.clone();
        if !self.slots[index].recovered {
            if let Some(jobs) = &self.jobs {
                jobs.pass_started(&key, "recovering").await;
            }
            recover(&self.shared, index, cancel).await?;
            self.slots[index].recovered = true;
        }
        if let Some(jobs) = &self.jobs {
            jobs.pass_started(&key, "observing").await;
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
        self.accept_observation(index, observation).await?;
        let Some(mut candidate) = self.slots[index].candidate.take() else {
            return Ok(SyncOutcome::Renewed);
        };
        stage_candidate(
            &self.shared,
            index,
            &mut candidate,
            cancel,
            self.jobs.as_deref(),
        )
        .await?;
        if let Some(jobs) = &self.jobs {
            jobs.phase_changed(
                &key,
                "publishing",
                Some(candidate.generation.to_hex()),
                Some(candidate.artifacts.len() as u64),
                Some(candidate.artifacts.len() as u64),
                None,
            )
            .await;
        }
        let view = finish(&self.shared, index, candidate, cancel).await?;
        self.shared.catalog.publish_suite(&key, view)?;
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
        stage_candidate(
            &self.shared,
            index,
            &mut candidate,
            cancel,
            self.jobs.as_deref(),
        )
        .await?;
        stage_pdiffs(&self.shared, index, &mut candidate, cancel).await?;
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
            // OriginVerifier already authenticated the RPM metadata signature or
            // Pacman canary pair. Staging still checks every closure identity;
            // a canary never grants package or database-wide authenticity.
            detached_verified: true,
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
                path: "Release.gpg",
                source,
            })?;
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
        if ferrum_apt::pdiff::is_patch_path(&work.path) {
            return download_known(shared, &suite.client, &canonical, identity, work.sha512).await;
        }
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
        let architecture =
            ferrum_apt::pacman::cachyos_suite_arch(key.suite()).ok_or(CheckpointError::Invalid)?;
        let relative = path
            .strip_prefix(architecture)
            .and_then(|tail| tail.strip_prefix('/'))
            .ok_or(CheckpointError::Invalid)?;
        format!("{architecture}/{}/{relative}", key.suite())
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
        let deadline = tokio::time::Instant::now() + shared.config.limits.producer_deadline;
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
    stage_pdiffs(shared, index, &mut candidate, cancel).await?;
    // Optional history acquisition has its own deadline. A timeout there must
    // not consume the proof/persistence window for the mandatory full indexes.
    let deadline = tokio::time::Instant::now() + shared.config.limits.producer_deadline;
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

/// PDiff is optional: never publish a partial chain or prevent a valid full-index
/// generation from advancing because origin history rotated during acquisition.
async fn stage_pdiffs(
    shared: &Shared,
    index: usize,
    candidate: &mut Candidate,
    cancel: &CancellationToken,
) -> Result<(), SyncError> {
    let policy = &shared.suites[index].configuration.policy;
    if policy.is_pacman() || policy.is_rpm() {
        return Ok(());
    }
    let (selected, _) = ferrum_apt::selection::select_for_architectures(
        &candidate.release,
        policy.components_for_suite(&candidate.release.codename),
        matches!(
            policy,
            ferrum_storage::recovery::TrustPolicy::Ubuntu { .. }
                | ferrum_storage::recovery::TrustPolicy::UbuntuPorts { .. }
        ),
        policy.architectures(),
    )
    .map_err(|error| SyncError::Identity(error.to_string()))?;
    let roots = ferrum_apt::selection::pdiffs(&candidate.release, &selected);
    let deadline = tokio::time::Instant::now() + shared.config.limits.producer_deadline;
    let mut budget = ferrum_apt::pdiff::MAX_SUITE_BYTES;
    for root in roots {
        let result = tokio::select! {
            () = cancel.cancelled() => return Err(CheckpointError::Origin.into()),
            result = tokio::time::timeout_at(deadline,
                stage_pdiff(shared, index, &candidate.release, root, &mut budget, cancel)) => result,
        };
        match result {
            Ok(Ok(artifacts)) if candidate.artifacts.len() + artifacts.len() <= 8192 => {
                candidate.artifacts.extend(artifacts);
            }
            Ok(Ok(_)) => break,
            Ok(Err(error)) => {
                if cancel.is_cancelled() {
                    return Err(CheckpointError::Origin.into());
                }
                tracing::warn!(path = %root.path, %error, "PDiff unavailable; serving full index");
            }
            Err(_) => break,
        }
    }
    Ok(())
}

async fn stage_pdiff(
    shared: &Shared,
    index: usize,
    release: &Release,
    root: &ferrum_apt::release::ReleaseEntry,
    budget: &mut u64,
    cancel: &CancellationToken,
) -> Result<Vec<(String, VerifiedObject)>, SyncError> {
    let expected = ObjectIdentity {
        sha256: root.sha256.ok_or(CheckpointError::Proof)?,
        size: root.size,
    };
    *budget = budget
        .checked_sub(expected.size)
        .ok_or(CheckpointError::Proof)?;
    let object = stage(
        shared,
        index,
        Work {
            path: root.path.as_str().to_owned(),
            expected: Some(expected),
            sha512: root.sha512,
        },
        cancel,
    )
    .await?;
    let bytes = object
        .read_bounded(ferrum_apt::pdiff::MAX_INDEX_BYTES)
        .await?;
    if Sha256Digest::of(&bytes) != expected.sha256 {
        return Err(CheckpointError::Proof.into());
    }
    let base = root
        .path
        .as_str()
        .strip_suffix(".diff/Index")
        .ok_or(CheckpointError::Proof)?;
    let path = RepositoryPath::parse_decoded(base).map_err(|_| CheckpointError::Proof)?;
    let full = release.entry(&path).ok_or(CheckpointError::Proof)?;
    let pdiff = ferrum_apt::pdiff::Index::parse(
        &bytes,
        ObjectIdentity {
            sha256: full.sha256.ok_or(CheckpointError::Proof)?,
            size: full.size,
        },
    )
    .map_err(|_| CheckpointError::Proof)?;
    let mut size = 0u64;
    for patch in &pdiff.patches {
        size = size
            .checked_add(patch.download.size)
            .and_then(|size| size.checked_add(patch.expanded.size))
            .ok_or(CheckpointError::Proof)?;
    }
    // Debit before downloads, including failed or timed-out closures, so origin
    // rotation cannot repeatedly consume the suite's optional transfer budget.
    *budget = budget.checked_sub(size).ok_or(CheckpointError::Proof)?;
    let mut artifacts = Vec::with_capacity(pdiff.patches.len() + 1);
    artifacts.push((root.path.as_str().to_owned(), object));
    for patch in &pdiff.patches {
        let path = format!("{base}.diff/{}.gz", patch.name);
        let parsed = RepositoryPath::parse_decoded(&path).map_err(|_| CheckpointError::Proof)?;
        if let Some(entry) = release.entry(&parsed)
            && (entry.sha256 != Some(patch.download.sha256) || entry.size != patch.download.size)
        {
            return Err(CheckpointError::Proof.into());
        }
        let object = stage(
            shared,
            index,
            Work {
                path: path.clone(),
                expected: Some(patch.download),
                sha512: None,
            },
            cancel,
        )
        .await?;
        ferrum_storage::recovery::verify_pdiff_patch(&shared.spool, &object, patch).await?;
        artifacts.push((path, object));
    }
    Ok(artifacts)
}

async fn stage_candidate(
    shared: &Shared,
    index: usize,
    candidate: &mut Candidate,
    cancel: &CancellationToken,
    jobs: Option<&JobRegistry>,
) -> Result<(), SyncError> {
    let key = &shared.suites[index].configuration.key;
    let total = (candidate.artifacts.len() + candidate.work.len()) as u64;
    while let Some(work) = candidate.work.pop_front() {
        if work.expected.is_some() && !candidate.detached_verified && candidate.artifacts.len() >= 3
        {
            if let Some(jobs) = jobs {
                jobs.phase_changed(
                    key,
                    "verifying_metadata",
                    Some(candidate.generation.to_hex()),
                    Some(candidate.artifacts.len() as u64),
                    Some(total),
                    Some("Release.gpg".into()),
                )
                .await;
            }
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
        if let Some(jobs) = jobs {
            jobs.phase_changed(
                key,
                "staging",
                Some(candidate.generation.to_hex()),
                Some(candidate.artifacts.len() as u64),
                Some(total),
                Some(path.clone()),
            )
            .await;
        }
        let object = stage(shared, index, work, cancel).await?;
        candidate.artifacts.push((path, object));
        if let Some(jobs) = jobs {
            jobs.phase_changed(
                key,
                "staging",
                Some(candidate.generation.to_hex()),
                Some(candidate.artifacts.len() as u64),
                Some(total),
                None,
            )
            .await;
        }
    }
    if !candidate.detached_verified {
        if let Some(jobs) = jobs {
            jobs.phase_changed(
                key,
                "verifying_metadata",
                Some(candidate.generation.to_hex()),
                Some(candidate.artifacts.len() as u64),
                Some(total),
                Some("Release.gpg".into()),
            )
            .await;
        }
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
                "x86_64_v3/cachyos-v3.db",
                "x86_64_v3/cachyos-v3/cachyos-v3.db",
            ),
            (
                "cachyos",
                "cachyos-v4",
                "x86_64_v4/cachyos-v4.db",
                "x86_64_v4/cachyos-v4/cachyos-v4.db",
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
            if repository == "cachyos" {
                let (requested_suite, request_tail) =
                    ferrum_apt::pacman::split_cachyos_suite_path(expected)
                        .expect("public request maps back to configured suite");
                assert_eq!(requested_suite, suite);
                let architecture =
                    ferrum_apt::pacman::cachyos_suite_arch(suite).expect("fixed architecture");
                assert_eq!(format!("{architecture}/{request_tail}"), relative);
            }
        }
    }

    #[test]
    fn cachyos_metadata_requests_reject_wrong_architecture_roots() {
        for suite in ["cachyos-v3", "cachyos-v4"] {
            let key = SuiteKey::new("cachyos", suite).expect("suite key");
            assert!(suite_path(&key, &format!("x86_64/{suite}.db")).is_err());
        }
    }
}
