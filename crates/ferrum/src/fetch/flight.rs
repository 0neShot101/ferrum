//! Single-flight fill registry (`PLAN.md` §3.6-§3.9, §7).
//!
//! One live fill per `(SHA-256, size)` per process. The producer is an
//! independently spawned task: the first request creates the flight but never
//! owns it, so reader timeouts and disconnects never cancel the fill. Waiters
//! observe only `Filling`, `Verified` or `Failed` through a watch channel; a
//! closed channel is `Failed`, never perpetual `Filling`. The terminal state is
//! published before the registry entry is removed, and failures enter a bounded
//! backoff map so followers see the recorded class instead of starting a
//! duplicate fill.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ferrum_apt::digest::ObjectIdentity;
use ferrum_apt::path::RepositoryPath;
use ferrum_storage::capture::{CaptureManager, VerifiedCaptureProof};
use ferrum_storage::s3::S3Store;
use ferrum_storage::{Spool, VerifiedObject};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::{FillError, UpstreamClient, fill_package_object};
use crate::config::Limits;
use crate::health::Metrics;
use crate::sync::view::DerivedDescriptor;

enum FillWork {
    Fixture(RepositoryPath),
    Package {
        path: RepositoryPath,
        client: Arc<UpstreamClient>,
        capture: Arc<CaptureManager>,
        proof: Arc<VerifiedCaptureProof>,
    },
    Derived(DerivedDescriptor),
}

impl FillWork {
    fn requires_signature(&self) -> bool {
        matches!(self, Self::Package { proof, .. } if proof.requires_package_signature())
    }
    fn label(&self) -> &str {
        match self {
            Self::Fixture(path) | Self::Package { path, .. } => path.as_str(),
            Self::Derived(descriptor) => &descriptor.source_path,
        }
    }
}

/// Observable state of one flight.
#[derive(Debug, Clone)]
pub enum FlightState {
    Filling,
    Verified(VerifiedObject, usize),
    Failed(FillError),
}

/// What a waiter receives from [`FillRegistry::join`].
#[derive(Debug)]
pub enum JoinOutcome {
    Verified(VerifiedObject),
    Failed(FillError),
    /// The waiter timeout expired; the producer continues untouched.
    Timeout,
    /// More than `waiters_per_object` requests already wait for this object.
    TooManyWaiters,
}

struct Flight {
    sender: watch::Sender<FlightState>,
    waiters: Arc<AtomicUsize>,
    foreground: Arc<AtomicBool>,
    cancelling: bool,
}

struct FailureEntry {
    error: FillError,
    expires_at: Instant,
}

/// Private-fixture source-to-verified-spool timing, excluding HTTP body delivery
/// and admission queueing. Available only to the explicit benchmark harness.
#[cfg(feature = "test-harness")]
#[derive(Clone, Debug)]
pub struct CompletedFill {
    pub identity: ObjectIdentity,
    pub started_at: Instant,
    pub verified_at: Instant,
    pub elapsed: std::time::Duration,
}

struct RegistryInner {
    spool: Spool,
    client: Arc<UpstreamClient>,
    s3: Option<Arc<S3Store>>,
    limits: Limits,
    fill_slots: Arc<Semaphore>,
    background_slots: Arc<Semaphore>,
    flights: Mutex<HashMap<ObjectIdentity, Flight>>,
    failures: Mutex<HashMap<ObjectIdentity, FailureEntry>>,
    cancel: CancellationToken,
    supervisors: Mutex<JoinSet<()>>,
    metrics: Arc<Metrics>,
    #[cfg(feature = "test-harness")]
    completed: Mutex<std::collections::VecDeque<CompletedFill>>,
}

/// Shared handle to the registry; clones observe the same flights.
#[derive(Clone)]
pub struct FillRegistry {
    inner: Arc<RegistryInner>,
}

/// Decrements the per-object and global waiter counts when a waiter leaves.
struct WaiterGuard {
    flight_waiters: Arc<AtomicUsize>,
    metrics: Arc<Metrics>,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.flight_waiters.fetch_sub(1, Ordering::AcqRel);
        self.metrics.waiter_left();
    }
}

enum Joined {
    Verified(VerifiedObject),
    Replayed(FillError),
    TooManyWaiters,
    Paused,
    Wait(watch::Receiver<FlightState>, WaiterGuard),
    Cancelling(watch::Receiver<FlightState>, WaiterGuard, FillWork),
}

impl FillRegistry {
    /// Creates a registry whose producers stop when `cancel` is cancelled.
    pub fn new(
        spool: Spool,
        client: Arc<UpstreamClient>,
        s3: Option<Arc<S3Store>>,
        limits: Limits,
        cancel: CancellationToken,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                spool,
                client,
                s3,
                fill_slots: Arc::new(Semaphore::new(limits.concurrent_fills.max(1))),
                background_slots: Arc::new(Semaphore::new(
                    limits.concurrent_fills.saturating_sub(1),
                )),
                limits,
                flights: Mutex::new(HashMap::new()),
                failures: Mutex::new(HashMap::new()),
                cancel,
                supervisors: Mutex::new(JoinSet::new()),
                metrics,
                #[cfg(feature = "test-harness")]
                completed: Mutex::new(std::collections::VecDeque::new()),
            }),
        }
    }

    /// A background fill never queues ahead of foreground admission and leaves
    /// at least one producer slot reserved for foreground requests. Cancellation
    /// stops a background-only producer, but never a flight joined by a client.
    /// `None` means no work was admitted: pause before retrying admission.
    pub(crate) async fn join_background(
        &self,
        identity: ObjectIdentity,
        path: &RepositoryPath,
        client: Arc<UpstreamClient>,
        capture: Arc<CaptureManager>,
        proof: Arc<VerifiedCaptureProof>,
        (deadline, cancel): (tokio::time::Instant, CancellationToken),
    ) -> Option<JoinOutcome> {
        if identity != proof.identity() || path != proof.path() {
            return Some(JoinOutcome::Failed(FillError::Corrupt(
                "package descriptor conflict".to_owned(),
            )));
        }

        let joined = self.join_or_start(
            identity,
            FillWork::Package {
                path: path.clone(),
                client,
                capture,
                proof,
            },
            Some((deadline, cancel.clone())),
        );
        if matches!(joined, Joined::Paused | Joined::Cancelling(..)) {
            return None;
        }
        Some(self.wait(joined, Some((deadline, cancel))).await)
    }

    /// Returns the verified object for `identity`, joining or creating a fill of
    /// `path` when it is not installed.
    ///
    /// Waits at most `waiter_timeout`; a timeout detaches only this waiter.
    pub async fn join(&self, identity: ObjectIdentity, path: &RepositoryPath) -> JoinOutcome {
        self.join_work(identity, FillWork::Fixture(path.clone()))
            .await
    }

    pub async fn join_authorized(
        &self,
        identity: ObjectIdentity,
        path: &RepositoryPath,
        client: Arc<UpstreamClient>,
        capture: Arc<CaptureManager>,
        proof: Arc<VerifiedCaptureProof>,
    ) -> JoinOutcome {
        if identity != proof.identity() || path != proof.path() {
            return JoinOutcome::Failed(FillError::Corrupt(
                "package descriptor conflict".to_owned(),
            ));
        }
        self.join_work(
            identity,
            FillWork::Package {
                path: path.clone(),
                client,
                capture,
                proof,
            },
        )
        .await
    }

    pub async fn join_derived(&self, descriptor: &DerivedDescriptor) -> JoinOutcome {
        self.join_work(descriptor.identity, FillWork::Derived(descriptor.clone()))
            .await
    }

    async fn join_work(&self, identity: ObjectIdentity, mut work: FillWork) -> JoinOutcome {
        let deadline = tokio::time::Instant::now() + self.inner.limits.waiter_timeout;
        loop {
            if tokio::time::Instant::now() >= deadline {
                self.inner.metrics.record_waiter_timeout();
                return JoinOutcome::Timeout;
            }
            let joined = self.join_or_start(identity, work, None);
            let Joined::Cancelling(receiver, guard, pending) = joined else {
                return self
                    .wait(joined, Some((deadline, self.inner.cancel.clone())))
                    .await;
            };
            let outcome = self
                .wait(
                    Joined::Wait(receiver, guard),
                    Some((deadline, self.inner.cancel.clone())),
                )
                .await;
            if matches!(outcome, JoinOutcome::Failed(FillError::Shutdown))
                && !self.inner.cancel.is_cancelled()
            {
                work = pending;
                continue;
            }
            return outcome;
        }
    }

    async fn wait(
        &self,
        joined: Joined,
        background: Option<(tokio::time::Instant, CancellationToken)>,
    ) -> JoinOutcome {
        let (mut receiver, _guard) = match joined {
            Joined::Verified(object) => {
                let _ = crate::server::REQUEST_SOURCE.try_with(|slot| slot.set(0));
                return JoinOutcome::Verified(object);
            }
            Joined::Replayed(error) => return JoinOutcome::Failed(error),
            Joined::TooManyWaiters => return JoinOutcome::TooManyWaiters,
            Joined::Paused => return JoinOutcome::Failed(FillError::Admission),
            Joined::Wait(receiver, guard) => (receiver, guard),
            Joined::Cancelling(receiver, guard, _) => (receiver, guard),
        };
        let terminal = receiver.wait_for(|state| !matches!(state, FlightState::Filling));
        let result = if let Some((deadline, cancel)) = background {
            tokio::select! {
                biased;
                () = cancel.cancelled() => return JoinOutcome::Failed(FillError::Shutdown),
                result = tokio::time::timeout_at(deadline, terminal) => result,
            }
        } else {
            tokio::time::timeout(self.inner.limits.waiter_timeout, terminal).await
        };
        match result {
            Ok(Ok(state)) => match &*state {
                FlightState::Verified(object, source) => {
                    let _ = crate::server::REQUEST_SOURCE
                        .try_with(|slot| slot.set(if *source < 3 { source + 2 } else { 0 }));
                    JoinOutcome::Verified(object.clone())
                }
                FlightState::Failed(error) => JoinOutcome::Failed(error.clone()),
                FlightState::Filling => JoinOutcome::Failed(FillError::Internal(
                    "flight ended while filling".to_owned(),
                )),
            },
            Ok(Err(_closed)) => {
                JoinOutcome::Failed(FillError::Internal("flight channel closed".to_owned()))
            }
            Err(_elapsed) => {
                self.inner.metrics.record_waiter_timeout();
                JoinOutcome::Timeout
            }
        }
    }

    /// Synchronous part of `join`: lookup, backoff replay, or flight join/create.
    /// The flights lock is never held across an await.
    fn join_or_start(
        &self,
        identity: ObjectIdentity,
        work: FillWork,
        background: Option<(tokio::time::Instant, CancellationToken)>,
    ) -> Joined {
        let authenticated_hit = !work.requires_signature();
        if self.inner.cancel.is_cancelled() {
            return Joined::Replayed(FillError::Shutdown);
        }
        if authenticated_hit && let Some(object) = self.inner.spool.lookup(identity) {
            return Joined::Verified(object);
        }
        let mut flights = lock_unpoisoned(&self.inner.flights);
        // A producer may have committed and removed its flight since the first
        // lookup. Recheck while creation/removal is serialized.
        if authenticated_hit && let Some(object) = self.inner.spool.lookup(identity) {
            return Joined::Verified(object);
        }
        if let Some(flight) = flights.get(&identity) {
            if flight.cancelling {
                return match self.attach(flight) {
                    Joined::Wait(receiver, guard) => Joined::Cancelling(receiver, guard, work),
                    joined => joined,
                };
            }
            let joined = self.attach(flight);
            if background.is_none() && matches!(joined, Joined::Wait(_, _)) {
                flight.foreground.store(true, Ordering::Release);
            }
            return joined;
        }
        if let Some(error) = self.replayed_failure(identity) {
            return Joined::Replayed(error);
        }
        let permits = if background.is_some() {
            let Ok(background) = Arc::clone(&self.inner.background_slots).try_acquire_owned()
            else {
                return Joined::Paused;
            };
            let Ok(fill) = Arc::clone(&self.inner.fill_slots).try_acquire_owned() else {
                return Joined::Paused;
            };
            Some((background, fill))
        } else {
            None
        };
        let foreground = Arc::new(AtomicBool::new(background.is_none()));
        let (sender, _) = watch::channel(FlightState::Filling);
        let flight = Flight {
            sender,
            waiters: Arc::new(AtomicUsize::new(0)),
            foreground: Arc::clone(&foreground),
            cancelling: false,
        };
        let joined = self.attach(&flight);
        let producer_sender = flight.sender.clone();
        flights.insert(identity, flight);
        drop(flights);
        self.spawn_supervised(
            identity,
            work,
            producer_sender,
            permits,
            background,
            foreground,
        );
        joined
    }

    fn attach(&self, flight: &Flight) -> Joined {
        let waiters = flight
            .waiters
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if waiters > self.inner.limits.waiters_per_object {
            flight.waiters.fetch_sub(1, Ordering::AcqRel);
            return Joined::TooManyWaiters;
        }
        self.inner.metrics.waiter_joined();
        Joined::Wait(
            flight.sender.subscribe(),
            WaiterGuard {
                flight_waiters: Arc::clone(&flight.waiters),
                metrics: Arc::clone(&self.inner.metrics),
            },
        )
    }

    pub fn replayed_failure(&self, identity: ObjectIdentity) -> Option<FillError> {
        let mut failures = lock_unpoisoned(&self.inner.failures);
        let now = Instant::now();
        match failures.get(&identity) {
            Some(entry) if entry.expires_at > now => Some(entry.error.clone()),
            Some(_) => {
                failures.remove(&identity);
                None
            }
            None => None,
        }
    }

    fn record_failure(&self, identity: ObjectIdentity, error: &FillError) {
        let mut failures = lock_unpoisoned(&self.inner.failures);
        let now = Instant::now();
        failures.retain(|_, entry| entry.expires_at > now);
        let capacity = self.inner.limits.failure_map_entries.max(1);
        if failures.len() >= capacity
            && let Some(oldest) = failures
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| *key)
        {
            failures.remove(&oldest);
        }
        failures.insert(
            identity,
            FailureEntry {
                error: error.clone(),
                expires_at: now + self.inner.limits.failure_backoff,
            },
        );
    }

    /// Spawns the producer and its supervisor. The supervisor publishes the
    /// terminal state (converting panic, abort and shutdown into failures),
    /// records backoff, and only then removes the registry entry.
    fn spawn_supervised(
        &self,
        identity: ObjectIdentity,
        work: FillWork,
        sender: watch::Sender<FlightState>,
        permits: Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>,
        background: Option<(tokio::time::Instant, CancellationToken)>,
        foreground: Arc<AtomicBool>,
    ) {
        let mut supervisors = lock_unpoisoned(&self.inner.supervisors);
        if self.inner.cancel.is_cancelled() {
            sender.send_replace(FlightState::Failed(FillError::Shutdown));
            lock_unpoisoned(&self.inner.flights).remove(&identity);
            return;
        }
        while supervisors.try_join_next().is_some() {}
        let path = work.label().to_owned();
        let started = Instant::now();
        let derived = matches!(&work, FillWork::Derived(_));
        let (background_permit, fill_permit) = match permits {
            Some((background, fill)) => (Some(background), Some(fill)),
            None => (None, None),
        };
        let inner = Arc::clone(&self.inner);
        let producer = tokio::spawn(super::PRODUCER_SOURCE.scope(
            std::cell::Cell::new(if derived { 2 } else { usize::MAX }),
            async move {
                let _background_permit = background_permit;
                let result = match tokio::time::timeout(
                    inner.limits.producer_deadline,
                    produce(Arc::clone(&inner), identity, work, fill_permit),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(FillError::Timeout),
                };
                let source = if derived {
                    2
                } else {
                    super::PRODUCER_SOURCE.with(std::cell::Cell::get)
                };
                result.map(|object| (object, source))
            },
        ));
        let registry = self.clone();
        supervisors.spawn(async move {
            registry
                .supervise(
                    identity,
                    sender,
                    producer,
                    background,
                    foreground,
                    (path, started),
                )
                .await;
        });
    }

    async fn supervise(
        &self,
        identity: ObjectIdentity,
        sender: watch::Sender<FlightState>,
        mut producer: tokio::task::JoinHandle<Result<(VerifiedObject, usize), FillError>>,
        background: Option<(tokio::time::Instant, CancellationToken)>,
        foreground: Arc<AtomicBool>,
        context: (String, Instant),
    ) {
        let inner = &self.inner;
        let (path, started) = context;
        let background_stop = async {
            if let Some((deadline, cancel)) = background {
                tokio::select! {
                    () = cancel.cancelled() => {}
                    () = tokio::time::sleep_until(deadline) => {}
                }
                return;
            }
            std::future::pending::<()>().await;
        };
        let outcome = tokio::select! {
            () = background_stop => {
                // Promotion and cancellation are serialized. Keep the
                // identity occupied until the producer has dropped every
                // reservation; new foreground callers wait, then retry.
                let aborted = {
                    let mut flights = lock_unpoisoned(&inner.flights);
                    if foreground.load(Ordering::Acquire) {
                        false
                    } else {
                        if let Some(flight) = flights.get_mut(&identity) {
                            flight.cancelling = true;
                        }
                        producer.abort();
                        true
                    }
                };
                if aborted {
                    let _ = (&mut producer).await;
                    Err(FillError::Shutdown)
                } else {
                    tokio::select! {
                        () = inner.cancel.cancelled() => {
                            producer.abort();
                            let _ = (&mut producer).await;
                            Err(FillError::Shutdown)
                        }
                        joined = &mut producer => match joined {
                            Ok(result) => result,
                            Err(error) => Err(FillError::Internal(error.to_string())),
                        },
                    }
                }
            }
            () = inner.cancel.cancelled() => {
                producer.abort();
                let _ = (&mut producer).await;
                Err(FillError::Shutdown)
            }
            joined = &mut producer => match joined {
                Ok(result) => result,
                Err(join_error) if join_error.is_cancelled() => Err(FillError::Shutdown),
                Err(join_error) => Err(FillError::Internal(format!("producer failed: {join_error}"))),
            },
        };
        inner.metrics.record_fill_duration(started.elapsed());
        let state = match &outcome {
            Ok((object, source)) => {
                tracing::info!(path = %path, size = object.size(), outcome = "verified", "fill finished");
                inner.metrics.record_fill("verified");
                inner.metrics.record_producer(*source);
                FlightState::Verified(object.clone(), *source)
            }
            Err(error) => {
                tracing::warn!(path = %path, outcome = error.metrics_label(), error = %error, "fill failed");
                inner.metrics.record_fill(error.metrics_label());
                if !matches!(error, FillError::Shutdown) {
                    self.record_failure(identity, error);
                }
                FlightState::Failed(error.clone())
            }
        };
        let mut flights = lock_unpoisoned(&inner.flights);
        sender.send_replace(state);
        if flights
            .get(&identity)
            .is_some_and(|flight| Arc::ptr_eq(&flight.foreground, &foreground))
        {
            flights.remove(&identity);
        }
    }

    /// Cancels every producer; waiters wake with [`FillError::Shutdown`].
    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        let mut supervisors = {
            let mut tasks = lock_unpoisoned(&self.inner.supervisors);
            std::mem::take(&mut *tasks)
        };
        while let Some(result) = supervisors.join_next().await {
            if let Err(error) = result {
                tracing::error!(%error, "fill supervisor failed during shutdown");
            }
        }
    }

    /// Last 1,024 successful private-fixture producers, not client TTFB/body
    /// timings. Warm hits and durable capture/receipt work do not add samples.
    #[cfg(feature = "test-harness")]
    pub fn completed_fills(&self) -> Vec<CompletedFill> {
        lock_unpoisoned(&self.inner.completed)
            .iter()
            .cloned()
            .collect()
    }

    /// Live flights (for tests and health).
    pub fn active_flights(&self) -> usize {
        lock_unpoisoned(&self.inner.flights).len()
    }

    pub fn available_fill_slots(&self) -> usize {
        self.inner.fill_slots.available_permits()
    }
    pub fn max_fill_slots(&self) -> usize {
        self.inner.limits.concurrent_fills.max(1)
    }
}

/// The independently owned producer: fill slot admission, then the bounded fill.
async fn produce(
    inner: Arc<RegistryInner>,
    identity: ObjectIdentity,
    work: FillWork,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<VerifiedObject, FillError> {
    let _slot = match permit {
        Some(permit) => permit,
        None => {
            let admission = tokio::time::timeout(
                inner.limits.admission_wait,
                Arc::clone(&inner.fill_slots).acquire_owned(),
            );
            match admission.await {
                Ok(Ok(permit)) => permit,
                Ok(Err(_closed)) => return Err(FillError::Shutdown),
                Err(_elapsed) => return Err(FillError::Admission),
            }
        }
    };
    match work {
        FillWork::Fixture(path) => {
            #[cfg(feature = "test-harness")]
            let started_at = Instant::now();
            let result = fill_package_object(
                &inner.client,
                inner.s3.as_deref(),
                &inner.spool,
                identity,
                &path,
                &inner.limits,
            )
            .await;
            #[cfg(feature = "test-harness")]
            if result.is_ok() {
                let verified_at = Instant::now();
                let mut samples = lock_unpoisoned(&inner.completed);
                if samples.len() == 1024 {
                    samples.pop_front();
                }
                samples.push_back(CompletedFill {
                    identity,
                    started_at,
                    verified_at,
                    elapsed: verified_at.duration_since(started_at),
                });
            }
            result
        }
        FillWork::Package {
            client,
            capture,
            proof,
            ..
        } => {
            let store = inner
                .s3
                .as_deref()
                .ok_or_else(|| FillError::Internal("durable package store missing".to_owned()))?;
            super::fill_authorized_package(
                &client,
                store,
                &capture,
                &proof,
                &inner.spool,
                &inner.limits,
                &inner.cancel,
            )
            .await
        }
        FillWork::Derived(descriptor) => ferrum_storage::recovery::materialize_derived(
            &inner.spool,
            descriptor.source,
            &descriptor.source_path,
            descriptor.identity,
            inner.cancel.clone(),
        )
        .await
        .map_err(|error| match error {
            ferrum_storage::checkpoint::CheckpointError::Spool(error) => error.into(),
            ferrum_storage::checkpoint::CheckpointError::Proof => {
                FillError::Corrupt("derived representation failed verification".to_owned())
            }
            other => FillError::Internal(other.to_string()),
        }),
    }
}

/// The maps hold plain handles and timestamps; a panicking holder leaves them
/// consistent, so the guard is recovered instead of propagating the poison.
fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod prewarm_tests {
    use super::*;
    use ferrum_apt::digest::Sha256Digest;
    use ferrum_storage::SpoolConfig;
    use std::time::Duration;

    fn make_registry(root: &std::path::Path, fills: usize, base: url::Url) -> FillRegistry {
        let spool = Spool::open_exclusive_fixture(SpoolConfig {
            root: root.join("spool"),
            managed_ceiling: 1024 * 1024,
            max_object_size: 128 * 1024,
            io_workers: 1,
            read_chunk: 4096,
        })
        .expect("test spool");
        let limits = Limits {
            concurrent_fills: fills,
            producer_deadline: Duration::from_secs(10),
            waiter_timeout: Duration::from_secs(10),
            ..Limits::default()
        };
        let client = Arc::new(UpstreamClient::new(base, &limits).expect("test client"));
        FillRegistry::new(
            spool,
            client,
            None,
            limits,
            CancellationToken::new(),
            Arc::new(Metrics::default()),
        )
    }

    fn fixture_work(bytes: &[u8]) -> (ObjectIdentity, FillWork) {
        (
            ObjectIdentity {
                sha256: Sha256Digest::of(bytes),
                size: bytes.len() as u64,
            },
            FillWork::Fixture(RepositoryPath::parse_decoded("pool/package.deb").expect("path")),
        )
    }

    #[tokio::test]
    async fn background_admission_reserves_foreground_capacity_without_queueing() {
        let root = tempfile::tempdir().expect("test root");
        let registry = make_registry(
            root.path(),
            2,
            "http://127.0.0.1:9/fixture/".parse().expect("base"),
        );
        let (identity, work) = fixture_work(b"first");
        let joined = registry.join_or_start(
            identity,
            work,
            Some((
                tokio::time::Instant::now() + Duration::from_secs(10),
                CancellationToken::new(),
            )),
        );
        assert!(matches!(joined, Joined::Wait(_, _)));
        assert_eq!(registry.available_fill_slots(), 1);
        let (identity, work) = fixture_work(b"second");
        let denied = registry.join_or_start(
            identity,
            work,
            Some((
                tokio::time::Instant::now() + Duration::from_secs(10),
                CancellationToken::new(),
            )),
        );
        assert!(matches!(denied, Joined::Paused));
        assert!(
            Arc::clone(&registry.inner.fill_slots)
                .try_acquire_owned()
                .is_ok()
        );
        assert_eq!(registry.active_flights(), 1);
        registry.shutdown().await;
    }

    #[tokio::test]
    async fn single_fill_slot_disables_background_producers() {
        let root = tempfile::tempdir().expect("test root");
        let registry = make_registry(
            root.path(),
            1,
            "http://127.0.0.1:9/fixture/".parse().expect("base"),
        );
        let (identity, work) = fixture_work(b"one");
        let denied = registry.join_or_start(
            identity,
            work,
            Some((
                tokio::time::Instant::now() + Duration::from_secs(10),
                CancellationToken::new(),
            )),
        );
        assert!(matches!(denied, Joined::Paused));
        assert_eq!(registry.active_flights(), 0);
        assert_eq!(registry.available_fill_slots(), 1);
        registry.shutdown().await;
    }

    #[tokio::test]
    async fn cancellation_stops_background_only_but_preserves_foreground_transfers() {
        let root = tempfile::tempdir().expect("test root");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let count = Arc::new(AtomicUsize::new(0));
        let route = axum::Router::new().fallback({
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            let count = Arc::clone(&count);
            move || {
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    started.notify_one();
                    release.notified().await;
                    "shared package"
                }
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, route).await.expect("test origin");
        });
        let registry = make_registry(
            root.path(),
            2,
            format!("http://{address}/fixture/").parse().expect("base"),
        );
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let (identity, work) = fixture_work(b"shared package");
        let background = registry.join_or_start(identity, work, Some((deadline, cancel.clone())));
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .expect("background origin request");
        let (_, work) = fixture_work(b"shared package");
        let foreground = registry.join_or_start(identity, work, None);
        cancel.cancel();
        assert!(matches!(
            registry.wait(background, Some((deadline, cancel))).await,
            JoinOutcome::Failed(FillError::Shutdown)
        ));
        release.notify_one();
        assert!(matches!(
            registry.wait(foreground, None).await,
            JoinOutcome::Verified(_)
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(registry.inner.spool.lookup(identity).is_some());
        registry.shutdown().await;

        let second_root = tempfile::tempdir().expect("second test root");
        let second = make_registry(
            second_root.path(),
            2,
            format!("http://{address}/fixture/").parse().expect("base"),
        );
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let (identity, work) = fixture_work(b"shared package");
        let background = second.join_or_start(identity, work, Some((deadline, cancel.clone())));
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .expect("second background origin request");
        cancel.cancel();
        assert!(matches!(
            second.wait(background, Some((deadline, cancel))).await,
            JoinOutcome::Failed(FillError::Shutdown)
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            while second.active_flights() != 0 || second.available_fill_slots() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background-only cancellation drains producer");
        assert_eq!(second.available_fill_slots(), 2);
        assert!(second.inner.spool.lookup(identity).is_none());
        second.shutdown().await;

        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelling_identity_stays_reserved_until_producer_ownership_is_dropped() {
        struct DropGate {
            entered: Arc<tokio::sync::Notify>,
            release: std::sync::mpsc::Receiver<()>,
            _reservations: Vec<ferrum_storage::disk::Reservation>,
            _fill: OwnedSemaphorePermit,
            _background: OwnedSemaphorePermit,
        }

        impl Drop for DropGate {
            fn drop(&mut self) {
                self.entered.notify_one();
                self.release
                    .recv_timeout(Duration::from_secs(10))
                    .expect("release producer ownership");
            }
        }

        let root = tempfile::tempdir().expect("test root");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let count = Arc::new(AtomicUsize::new(0));
        let route = axum::Router::new().fallback({
            let count = Arc::clone(&count);
            move || {
                count.fetch_add(1, Ordering::SeqCst);
                async { "replacement package" }
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, route).await.expect("test origin");
        });
        let registry = make_registry(
            root.path(),
            2,
            format!("http://{address}/fixture/").parse().expect("base"),
        );
        let (identity, work) = fixture_work(b"replacement package");
        let path = match work {
            FillWork::Fixture(path) => path,
            _ => unreachable!("fixture work"),
        };
        let foreground = Arc::new(AtomicBool::new(false));
        let (sender, _) = watch::channel(FlightState::Filling);
        lock_unpoisoned(&registry.inner.flights).insert(
            identity,
            Flight {
                sender: sender.clone(),
                waiters: Arc::new(AtomicUsize::new(0)),
                foreground: Arc::clone(&foreground),
                cancelling: false,
            },
        );

        // Fill the real spool allowance so a premature replacement would fail
        // reservation admission and poison this identity's failure backoff.
        let reservations = (0..8)
            .map(|_| {
                registry
                    .inner
                    .spool
                    .reserve(128 * 1024)
                    .expect("owned reservation")
            })
            .collect();
        let entered = Arc::new(tokio::sync::Notify::new());
        let started = Arc::new(tokio::sync::Notify::new());
        let (release, released) = std::sync::mpsc::channel();
        let gate = DropGate {
            entered: Arc::clone(&entered),
            release: released,
            _reservations: reservations,
            _fill: Arc::clone(&registry.inner.fill_slots)
                .try_acquire_owned()
                .expect("producer slot"),
            _background: Arc::clone(&registry.inner.background_slots)
                .try_acquire_owned()
                .expect("background slot"),
        };
        let producer = tokio::spawn({
            let started = Arc::clone(&started);
            async move {
                let _gate = gate;
                started.notify_one();
                std::future::pending::<Result<(VerifiedObject, usize), FillError>>().await
            }
        });
        started.notified().await;
        let cancel = CancellationToken::new();
        let supervisor = tokio::spawn({
            let registry = registry.clone();
            let cancel = cancel.clone();
            async move {
                registry
                    .supervise(
                        identity,
                        sender,
                        producer,
                        Some((
                            tokio::time::Instant::now() + Duration::from_secs(10),
                            cancel,
                        )),
                        foreground,
                        ("pool/package.deb".into(), Instant::now()),
                    )
                    .await;
            }
        });
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("producer stopped inside ownership drop");

        let first = tokio::spawn({
            let registry = registry.clone();
            let path = path.clone();
            async move { registry.join(identity, &path).await }
        });
        let second = tokio::spawn({
            let registry = registry.clone();
            async move { registry.join(identity, &path).await }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while registry.inner.metrics.fill_waiters() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("foreground waiters attached to cancelling identity");
        assert_eq!(registry.active_flights(), 1);
        assert_eq!(registry.inner.spool.accounting().reserved, 1024 * 1024);
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(registry.replayed_failure(identity).is_none());
        assert!(!first.is_finished() && !second.is_finished());

        release.send(()).expect("release real spool reservations");
        supervisor
            .await
            .expect("cancelled producer fully terminated");
        assert!(matches!(
            first.await.expect("first foreground"),
            JoinOutcome::Verified(_)
        ));
        assert!(matches!(
            second.await.expect("second foreground"),
            JoinOutcome::Verified(_)
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(registry.replayed_failure(identity).is_none());
        assert_eq!(registry.inner.spool.accounting().reserved, 0);
        registry.shutdown().await;
        server.abort();
        let _ = server.await;
    }
}
