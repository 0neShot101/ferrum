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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ferrum_apt::digest::ObjectIdentity;
use ferrum_apt::path::RepositoryPath;
use ferrum_storage::capture::{CaptureManager, VerifiedCaptureProof};
use ferrum_storage::s3::S3Store;
use ferrum_storage::{Spool, VerifiedObject};
use tokio::sync::{Semaphore, watch};
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
    Verified(VerifiedObject),
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
    Wait(watch::Receiver<FlightState>, WaiterGuard),
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

    async fn join_work(&self, identity: ObjectIdentity, work: FillWork) -> JoinOutcome {
        let (mut receiver, _guard) = match self.join_or_start(identity, work) {
            Joined::Verified(object) => return JoinOutcome::Verified(object),
            Joined::Replayed(error) => return JoinOutcome::Failed(error),
            Joined::TooManyWaiters => return JoinOutcome::TooManyWaiters,
            Joined::Wait(receiver, guard) => (receiver, guard),
        };
        let terminal = receiver.wait_for(|state| !matches!(state, FlightState::Filling));
        match tokio::time::timeout(self.inner.limits.waiter_timeout, terminal).await {
            Ok(Ok(state)) => match &*state {
                FlightState::Verified(object) => JoinOutcome::Verified(object.clone()),
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
    fn join_or_start(&self, identity: ObjectIdentity, work: FillWork) -> Joined {
        if self.inner.cancel.is_cancelled() {
            return Joined::Replayed(FillError::Shutdown);
        }
        if let Some(object) = self.inner.spool.lookup(identity) {
            return Joined::Verified(object);
        }
        let mut flights = lock_unpoisoned(&self.inner.flights);
        // A producer may have committed and removed its flight since the first
        // lookup. Recheck while creation/removal is serialized.
        if let Some(object) = self.inner.spool.lookup(identity) {
            return Joined::Verified(object);
        }
        if let Some(flight) = flights.get(&identity) {
            return self.attach(flight);
        }
        if let Some(error) = self.replayed_failure(identity) {
            return Joined::Replayed(error);
        }
        let (sender, _) = watch::channel(FlightState::Filling);
        let flight = Flight {
            sender,
            waiters: Arc::new(AtomicUsize::new(0)),
        };
        let joined = self.attach(&flight);
        let producer_sender = flight.sender.clone();
        flights.insert(identity, flight);
        drop(flights);
        self.spawn_supervised(identity, work, producer_sender);
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
    ) {
        let mut supervisors = lock_unpoisoned(&self.inner.supervisors);
        if self.inner.cancel.is_cancelled() {
            sender.send_replace(FlightState::Failed(FillError::Shutdown));
            lock_unpoisoned(&self.inner.flights).remove(&identity);
            return;
        }
        while supervisors.try_join_next().is_some() {}
        let path = work.label().to_owned();
        let registry = self.clone();
        let inner = Arc::clone(&self.inner);
        let mut producer = tokio::spawn(async move {
            match tokio::time::timeout(
                inner.limits.producer_deadline,
                produce(Arc::clone(&inner), identity, work),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(FillError::Timeout),
            }
        });
        let inner = Arc::clone(&self.inner);
        supervisors.spawn(async move {
            let outcome = tokio::select! {
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
            let state = match &outcome {
                Ok(object) => {
                    tracing::info!(path = %path, size = object.size(), outcome = "verified", "fill finished");
                    inner.metrics.record_fill("verified");
                    FlightState::Verified(object.clone())
                }
                Err(error) => {
                    tracing::warn!(path = %path, outcome = error.metrics_label(), error = %error, "fill failed");
                    inner.metrics.record_fill(error.metrics_label());
                    registry.record_failure(identity, error);
                    FlightState::Failed(error.clone())
                }
            };
            sender.send_replace(state);
            lock_unpoisoned(&inner.flights).remove(&identity);
        });
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
}

/// The independently owned producer: fill slot admission, then the bounded fill.
async fn produce(
    inner: Arc<RegistryInner>,
    identity: ObjectIdentity,
    work: FillWork,
) -> Result<VerifiedObject, FillError> {
    let admission = tokio::time::timeout(
        inner.limits.admission_wait,
        Arc::clone(&inner.fill_slots).acquire_owned(),
    );
    let _slot = match admission.await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_closed)) => return Err(FillError::Shutdown),
        Err(_elapsed) => return Err(FillError::Admission),
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
