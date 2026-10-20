//! Shared bounded telemetry: 720 five-second samples and seven days of minute
//! rollups in the independent admin database. Busy persistence is shed; missing
//! minutes and boot/counter resets are graph gaps, never zero-rate observations.
//! Histograms count requests (TTFB) and terminal producer flights (fill duration),
//! including failed flights; source counters count successfully verified producers.
//! Quantiles are merged bucket upper-bound estimates, not averaged percentiles.
//! Measurements describe server work, not client ACK or whole-host utilization.
//! Sampling and persistence never run on the public request path.
use super::{
    model::{Permission, StoreError},
    routes::{authenticate, store_error},
    store::{actor, audit},
};
use crate::health::{CACHE_SOURCES, HealthState, LATENCY_BUCKETS_NANOS, Metrics};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
};
use futures_util::stream;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_util::sync::CancellationToken;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}
fn now() -> i64 {
    ferrum_apt::release::UnixTime::now().as_secs()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub condition_id: String,
    pub severity: String,
    pub message: String,
    pub active: bool,
    pub first_seen_at: i64,
    pub changed_at: i64,
}
impl Alert {
    fn new(condition_id: String, severity: &str, message: String) -> Self {
        Self {
            condition_id,
            severity: severity.into(),
            message,
            active: true,
            first_seen_at: now(),
            changed_at: now(),
        }
    }
}
#[derive(Default)]
struct AlertTracker {
    retained: BTreeMap<String, Alert>,
    pending: BTreeMap<String, u8>,
}
impl AlertTracker {
    fn update(&mut self, alerts: Vec<Alert>) -> Vec<Alert> {
        let live: BTreeMap<_, _> = alerts
            .into_iter()
            .map(|alert| (alert.condition_id.clone(), alert))
            .collect();
        self.pending.retain(|id, _| live.contains_key(id));
        for (id, mut alert) in live.iter().map(|(id, alert)| (id.clone(), alert.clone())) {
            let count = self.pending.entry(id.clone()).or_default();
            *count = count.saturating_add(1);
            if alert.severity == "warning" && *count < 2 {
                continue;
            }
            if let Some(previous) = self.retained.get(&id) {
                alert.first_seen_at = previous.first_seen_at;
                if previous.active && previous.severity == alert.severity {
                    alert.changed_at = previous.changed_at;
                }
            }
            self.retained.insert(id, alert);
        }
        for (id, alert) in &mut self.retained {
            if alert.active && !live.contains_key(id) {
                alert.active = false;
                alert.changed_at = now();
            }
        }
        while self.retained.len() > 256 {
            let oldest = self
                .retained
                .iter()
                .filter(|(_, alert)| !alert.active)
                .min_by_key(|(_, alert)| alert.changed_at)
                .map(|(id, _)| id.clone());
            let Some(oldest) = oldest else { break };
            self.retained.remove(&oldest);
        }
        self.retained.values().cloned().collect()
    }
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Admission {
    pub available_request_slots: Option<usize>,
    pub available_body_slots: Option<usize>,
    pub available_fill_slots: Option<usize>,
    pub max_fill_slots: Option<usize>,
    pub active_flights: Option<usize>,
    pub fill_waiters: String,
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetrySample {
    pub boot_id: String,
    pub sample_at: i64,
    pub resolution_seconds: u32,
    pub gap: bool,
    pub requests: String,
    pub response_bytes: String,
    pub requests_per_second: Option<f64>,
    pub bytes_per_second: Option<f64>,
    pub cache_sources: BTreeMap<String, String>,
    pub latency_buckets: [String; 8],
    pub fill_duration_buckets: [String; 8],
    pub latency_p95_seconds: Option<f64>,
    pub fill_p95_seconds: Option<f64>,
    pub rss_bytes: Option<String>,
    pub cpu_core_equivalents: Option<f64>,
    pub process_measurement_note: String,
    pub installed_bytes: Option<String>,
    pub filesystem_available_bytes: Option<String>,
    pub outbox_entries: Option<String>,
    pub circuit_open: Option<bool>,
    pub remote_storage_bytes: Option<String>,
    pub remote_download_bytes: Option<String>,
    pub remote_reserved_download_bytes: Option<String>,
    pub remote_ledger_period: Option<i64>,
    pub remote_usage_certain: Option<bool>,
    pub repository_traffic: Option<Vec<RepositoryTraffic>>,
    pub producer_sources: BTreeMap<String, String>,
    pub admission: Admission,
    pub alerts: Vec<Alert>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryTraffic {
    pub repository: String,
    pub successful_requests: String,
    pub error_requests: String,
    pub response_bytes: String,
}
#[derive(Clone)]
struct Counters {
    requests: u64,
    bytes: u64,
    cache: [u64; 5],
    latency: [u64; 8],
    fills: [u64; 8],
    producers: [u64; 3],
    repo_requests: [[u64; 2]; 25],
    repo_bytes: [u64; 25],
}
impl Counters {
    fn read(metrics: &Metrics) -> Self {
        let load = |value: &std::sync::atomic::AtomicU64| value.load(Ordering::Relaxed);
        Self {
            requests: metrics
                .requests
                .iter()
                .flatten()
                .map(load)
                .fold(0, u64::saturating_add),
            bytes: metrics
                .response_bytes
                .iter()
                .map(load)
                .fold(0, u64::saturating_add),
            cache: std::array::from_fn(|i| load(&metrics.cache_sources[i])),
            latency: std::array::from_fn(|i| {
                metrics
                    .request_ttfb_buckets
                    .iter()
                    .map(|class| load(&class[i]))
                    .fold(0, u64::saturating_add)
            }),
            fills: std::array::from_fn(|i| load(&metrics.fill_duration_buckets[i])),
            producers: std::array::from_fn(|i| load(&metrics.producer_sources[i])),
            repo_requests: std::array::from_fn(|i| {
                std::array::from_fn(|j| load(&metrics.repo_requests[i][j]))
            }),
            repo_bytes: std::array::from_fn(|i| load(&metrics.repo_bytes[i])),
        }
    }
    fn delta(&self, previous: &Self) -> Option<Self> {
        let mut repo_requests = [[0; 2]; 25];
        for (i, row) in repo_requests.iter_mut().enumerate() {
            *row = subtract(self.repo_requests[i], previous.repo_requests[i])?;
        }
        Some(Self {
            requests: self.requests.checked_sub(previous.requests)?,
            bytes: self.bytes.checked_sub(previous.bytes)?,
            cache: subtract(self.cache, previous.cache)?,
            latency: subtract(self.latency, previous.latency)?,
            fills: subtract(self.fills, previous.fills)?,
            producers: subtract(self.producers, previous.producers)?,
            repo_requests,
            repo_bytes: subtract(self.repo_bytes, previous.repo_bytes)?,
        })
    }
}
fn subtract<const N: usize>(current: [u64; N], previous: [u64; N]) -> Option<[u64; N]> {
    let mut delta = [0; N];
    for i in 0..N {
        delta[i] = current[i].checked_sub(previous[i])?;
    }
    Some(delta)
}
/// Upper bucket bound, not an interpolated or averaged percentile. +Inf is unknown.
pub fn quantile(buckets: &[u64; 8], percentile: f64) -> Option<f64> {
    let total = buckets.iter().copied().fold(0u64, u64::saturating_add);
    if total == 0 {
        return None;
    }
    let rank = (total as f64 * percentile).ceil().max(1.0) as u64;
    let mut count = 0u64;
    for (i, value) in buckets.iter().enumerate() {
        count = count.saturating_add(*value);
        if count >= rank {
            return (i < 7).then_some(LATENCY_BUCKETS_NANOS[i] as f64 / 1e9);
        }
    }
    None
}

pub struct TelemetryHub {
    pub boot_id: String,
    ring: Mutex<VecDeque<TelemetrySample>>,
    latest: watch::Sender<Option<TelemetrySample>>,
    connections: Arc<Semaphore>,
    sessions: Mutex<BTreeMap<String, usize>>,
}
impl Default for TelemetryHub {
    fn default() -> Self {
        Self::new()
    }
}
impl TelemetryHub {
    pub fn new() -> Self {
        let (latest, _) = watch::channel(None);
        let token = super::password::random_token();
        Self {
            boot_id: token.chars().take(32).collect(),
            ring: Mutex::new(VecDeque::with_capacity(720)),
            latest,
            connections: Arc::new(Semaphore::new(16)),
            sessions: Mutex::new(BTreeMap::new()),
        }
    }
    pub fn snapshot(&self) -> Option<TelemetrySample> {
        self.latest.borrow().clone().map(|mut sample| {
            if now().saturating_sub(sample.sample_at) > 10 {
                let mut alert = Alert::new(
                    "telemetry.stale".into(),
                    "warning",
                    "Telemetry sampling is stale; current rates are unavailable.".into(),
                );
                alert.first_seen_at = sample.sample_at.saturating_add(10);
                alert.changed_at = alert.first_seen_at;
                sample.alerts.push(alert);
                sample.requests_per_second = None;
                sample.bytes_per_second = None;
            }
            sample
        })
    }
    fn publish(&self, sample: TelemetrySample) {
        let mut ring = lock(&self.ring);
        if ring.len() == 720 {
            ring.pop_front();
        }
        ring.push_back(sample.clone());
        drop(ring);
        self.latest.send_replace(Some(sample));
    }
    fn connect(self: &Arc<Self>, session: String) -> Result<ConnectionGuard, StoreError> {
        let permit = self
            .connections
            .clone()
            .try_acquire_owned()
            .map_err(|_| StoreError::Busy)?;
        let mut sessions = lock(&self.sessions);
        let count = sessions.entry(session.clone()).or_default();
        if *count >= 2 {
            return Err(StoreError::Busy);
        }
        *count += 1;
        Ok(ConnectionGuard {
            hub: self.clone(),
            session,
            _permit: permit,
        })
    }
}
struct ConnectionGuard {
    hub: Arc<TelemetryHub>,
    session: String,
    _permit: OwnedSemaphorePermit,
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut sessions = lock(&self.hub.sessions);
        if let Some(count) = sessions.get_mut(&self.session) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                sessions.remove(&self.session);
            }
        }
    }
}

#[derive(Default)]
struct Process {
    ticks: Option<u64>,
    sampled: Option<Instant>,
}
impl Process {
    fn sample(&mut self) -> (Option<String>, Option<f64>) {
        #[cfg(target_os = "linux")]
        {
            let rss = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find_map(|line| {
                            line.strip_prefix("VmRSS:").and_then(|value| {
                                value.split_whitespace().next()?.parse::<u64>().ok()
                            })
                        })
                        .and_then(|value| value.checked_mul(1024))
                });
            let ticks = std::fs::read_to_string("/proc/self/stat")
                .ok()
                .and_then(|text| {
                    let (_, tail) = text.rsplit_once(')')?;
                    let fields: Vec<_> = tail.split_whitespace().collect();
                    fields
                        .get(11)?
                        .parse::<u64>()
                        .ok()?
                        .checked_add(fields.get(12)?.parse::<u64>().ok()?)
                });
            let at = Instant::now();
            // Linux exposes proc CPU times in USER_HZ (100 on supported x86-64).
            let cpu = ticks.zip(self.ticks).zip(self.sampled).and_then(
                |((current, previous), before)| {
                    current
                        .checked_sub(previous)
                        .map(|delta| delta as f64 / 100.0 / at.duration_since(before).as_secs_f64())
                },
            );
            self.ticks = ticks;
            self.sampled = Some(at);
            (
                rss.map(|value| value.to_string()),
                cpu.filter(|value| value.is_finite()),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            (None, None)
        }
    }
}
fn evaluate_alerts(
    state: &HealthState,
    suites: Vec<crate::health::SuiteHealth>,
    installed: Option<u64>,
    ceiling: Option<u64>,
    admission_open: Option<bool>,
    outbox: Option<u64>,
    circuit: Option<bool>,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let mut add = |id: String, severity: &str, message: String| {
        alerts.push(Alert::new(id, severity, message))
    };
    if !state.catalog.clock_valid() {
        add(
            "clock.invalid".into(),
            "critical",
            "Gateway clock is not trusted.".into(),
        );
    }
    if circuit == Some(true) {
        add(
            "remote.circuit".into(),
            "critical",
            "Recorded remote circuit is open.".into(),
        );
    }
    if admission_open == Some(false) {
        add(
            "storage.admission".into(),
            "critical",
            "Local storage admission is closed.".into(),
        );
    }
    if let Some((used, limit)) = installed.zip(ceiling).filter(|(_, limit)| *limit > 0) {
        let ratio = used as f64 / limit as f64;
        if ratio >= 0.8 {
            add(
                "storage.pressure".into(),
                if ratio >= 0.95 { "critical" } else { "warning" },
                "Local managed storage is above its pressure threshold.".into(),
            );
        }
    }
    if outbox.is_some_and(|value| value >= 1000) {
        add(
            "capture.backlog".into(),
            "warning",
            "Capture outbox has at least 1000 entries.".into(),
        );
    }
    if state
        .capture
        .as_ref()
        .is_some_and(|capture| capture.coverage_ready().ok() == Some(false))
    {
        add(
            "capture.coverage".into(),
            "critical",
            "Captured package coverage is not ready.".into(),
        );
    }
    for suite in suites.into_iter().take(128) {
        if suite.alert_state != "ok" {
            add(
                format!("mirror.{}.{}", suite.repository, suite.suite),
                if suite.alert_state == "page" {
                    "critical"
                } else {
                    "warning"
                },
                "Mirror health requires operator attention.".into(),
            );
        }
    }
    alerts
}

/// Spawn once from app lifecycle and supervise this handle alongside gateway tasks.
pub fn spawn_sampler(
    state: Arc<HealthState>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(5));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous: Option<(Counters, Instant)> = None;
        let mut process = Process::default();
        let mut minute_samples = Vec::with_capacity(12);
        let mut minute = now().div_euclid(60);
        let mut previous_rejections = 0u64;
        let mut rejection_streak = 0u8;
        let mut alert_tracker = AlertTracker::default();
        loop {
            tokio::select! { () = cancel.cancelled() => break, _ = timer.tick() => {} }
            let suites =
                crate::health::suite_health(&state.catalog, state.catalog.clock_valid()).await;
            let state_for_read = state.clone();
            let mut next_process = std::mem::take(&mut process);
            let sampled = tokio::task::spawn_blocking(move || {
                let usage = state_for_read.spool.usage().ok();
                let outbox = state_for_read
                    .capture
                    .as_ref()
                    .and_then(|capture| capture.usage().ok())
                    .map(|usage| usage.entries);
                let circuit = state_for_read.s3.as_ref().map(|store| store.circuit_open());
                let budget =
                    ferrum_storage::budget::BudgetLedger::inspect_detailed(&state_for_read.spool)
                        .ok();
                let alerts = evaluate_alerts(
                    &state_for_read,
                    suites,
                    usage.as_ref().map(|u| u.managed_bytes),
                    usage.as_ref().map(|u| u.objects.ceiling),
                    usage.as_ref().map(|u| u.admission_open),
                    outbox,
                    circuit,
                );
                let (rss, cpu) = next_process.sample();
                (
                    usage,
                    outbox,
                    circuit,
                    budget,
                    alerts,
                    rss,
                    cpu,
                    next_process,
                )
            })
            .await;
            let Ok((usage, outbox, circuit, budget, mut alerts, rss, cpu, updated_process)) =
                sampled
            else {
                continue;
            };
            process = updated_process;
            let counters = Counters::read(&state.metrics);
            let at = Instant::now();
            let delta = previous.as_ref().and_then(|(before, instant)| {
                (at.duration_since(*instant) <= Duration::from_secs(10))
                    .then(|| counters.delta(before))
                    .flatten()
            });
            let elapsed = previous
                .as_ref()
                .map(|(_, instant)| at.duration_since(*instant).as_secs_f64());
            let rejected = state.metrics.fills[4].load(Ordering::Relaxed);
            rejection_streak = if rejected > previous_rejections {
                rejection_streak.saturating_add(1)
            } else {
                0
            };
            previous_rejections = rejected;
            if rejection_streak >= 3 {
                alerts.push(Alert::new(
                    "admission.repeated_rejection".into(),
                    "warning",
                    "Fill admission rejected producers in three consecutive samples.".into(),
                ));
            }
            if let (Some(budget), Some(config)) = (budget.as_ref(), state.config.durable()) {
                for (id, used, limit) in [
                    (
                        "remote.storage_pressure",
                        budget.storage,
                        config.budget.storage,
                    ),
                    (
                        "remote.download_pressure",
                        budget.download.saturating_add(budget.reserved_download),
                        config.budget.monthly_download,
                    ),
                ] {
                    if limit > 0 && used as f64 / limit as f64 >= 0.8 {
                        alerts.push(Alert::new(
                            id.into(),
                            if used as f64 / limit as f64 >= 0.95 {
                                "critical"
                            } else {
                                "warning"
                            },
                            "Recorded remote allowance is above its pressure threshold.".into(),
                        ));
                    }
                }
                if !budget.certain {
                    alerts.push(Alert::new(
                        "remote.uncertain".into(),
                        "critical",
                        "Remote allowance certainty requires operator reconciliation.".into(),
                    ));
                }
            }
            let alerts = alert_tracker.update(alerts);
            let sample = TelemetrySample {
                boot_id: state.telemetry.boot_id.clone(), sample_at: now(), resolution_seconds: 5, gap: delta.is_none(),
                repository_traffic: delta.as_ref().map(|delta| (0..25).map(|i| RepositoryTraffic {
                    repository: crate::config::Repository::ALL.get(i).map_or("fixture", |repo| repo.name()).into(),
                    successful_requests: delta.repo_requests[i][0].to_string(),
                    error_requests: delta.repo_requests[i][1].to_string(),
                    response_bytes: delta.repo_bytes[i].to_string(),
                }).collect()),
                producer_sources: crate::health::PRODUCER_SOURCES.iter().enumerate().map(|(i, source)| (source.to_string(), delta.as_ref().map_or(0, |d| d.producers[i]).to_string())).collect(),
                requests: delta.as_ref().map_or(0, |d| d.requests).to_string(), response_bytes: delta.as_ref().map_or(0, |d| d.bytes).to_string(),
                requests_per_second: delta.as_ref().zip(elapsed).map(|(d, seconds)| d.requests as f64 / seconds), bytes_per_second: delta.as_ref().zip(elapsed).map(|(d, seconds)| d.bytes as f64 / seconds),
                cache_sources: CACHE_SOURCES.iter().enumerate().map(|(i, source)| (source.to_string(), delta.as_ref().map_or(0, |d| d.cache[i]).to_string())).collect(),
                latency_buckets: std::array::from_fn(|i| delta.as_ref().map_or(0, |d| d.latency[i]).to_string()), fill_duration_buckets: std::array::from_fn(|i| delta.as_ref().map_or(0, |d| d.fills[i]).to_string()),
                latency_p95_seconds: delta.as_ref().and_then(|d| quantile(&d.latency, 0.95)), fill_p95_seconds: delta.as_ref().and_then(|d| quantile(&d.fills, 0.95)),
                rss_bytes: rss, cpu_core_equivalents: cpu, process_measurement_note: "Process RSS and CPU core equivalents; Linux proc USER_HZ=100 on x86-64. Unavailable measurements are null; not host utilization.".into(),
                installed_bytes: usage.as_ref().map(|u| u.objects.installed.to_string()), filesystem_available_bytes: usage.as_ref().map(|u| u.filesystem_available.to_string()), outbox_entries: outbox.map(|n| n.to_string()), circuit_open: circuit,
                remote_storage_bytes: budget.as_ref().map(|b| b.storage.to_string()), remote_download_bytes: budget.as_ref().map(|b| b.download.to_string()), remote_reserved_download_bytes: budget.as_ref().map(|b| b.reserved_download.to_string()), remote_ledger_period: budget.as_ref().map(|b| b.period), remote_usage_certain: budget.as_ref().map(|b| b.certain),
                admission: Admission { available_request_slots: state.request_slots.as_ref().map(|s| s.available_permits()), available_body_slots: state.active_bodies.as_ref().map(|s| s.available_permits()), available_fill_slots: state.fills.as_ref().map(|s| s.available_fill_slots()), max_fill_slots: state.fills.as_ref().map(|s| s.max_fill_slots()), active_flights: state.fills.as_ref().map(|s| s.active_flights()), fill_waiters: state.metrics.fill_waiters().to_string() }, alerts,
            };
            previous = Some((counters, at));
            let new_minute = sample.sample_at.div_euclid(60);
            if new_minute != minute {
                if let Some(rollup) = rollup(&minute_samples)
                    && let Ok(body) = serde_json::to_vec(&rollup)
                {
                    let boot = rollup.boot_id;
                    let result = state.admin.write(move |tx| { tx.execute("INSERT OR REPLACE INTO metric_rollups(minute,boot_id,body) VALUES(?1,?2,?3)", rusqlite::params![minute, boot, body])?; Ok(()) }).await;
                    if result.is_err() {
                        tracing::debug!("telemetry rollup shed: administration store unavailable");
                    }
                }
                minute_samples.clear();
                minute = new_minute;
            }
            if minute_samples.len() < 12 {
                minute_samples.push(sample.clone());
            }
            state.telemetry.publish(sample);
        }
    })
}
fn rollup(samples: &[TelemetrySample]) -> Option<TelemetrySample> {
    let mut merged = samples.last()?.clone();
    merged.resolution_seconds = 60;
    // Mirror histories remain in the hour ring; global rollups do not duplicate
    // alert text or per-mirror rows for seven days.
    merged.repository_traffic = None;
    merged.alerts.clear();
    merged.process_measurement_note.clear();
    merged.gap =
        samples.len() != 12 || samples.iter().any(|s| s.gap || s.boot_id != merged.boot_id);
    let sum = |read: fn(&TelemetrySample) -> &String| {
        samples
            .iter()
            .filter_map(|s| read(s).parse::<u64>().ok())
            .fold(0u64, u64::saturating_add)
    };
    merged.requests = sum(|s| &s.requests).to_string();
    merged.response_bytes = sum(|s| &s.response_bytes).to_string();
    let mut latency = [0u64; 8];
    let mut fills = [0u64; 8];
    for sample in samples {
        for i in 0..8 {
            latency[i] = latency[i].saturating_add(sample.latency_buckets[i].parse().unwrap_or(0));
            fills[i] =
                fills[i].saturating_add(sample.fill_duration_buckets[i].parse().unwrap_or(0));
        }
    }
    merged.latency_buckets = latency.map(|n| n.to_string());
    merged.fill_duration_buckets = fills.map(|n| n.to_string());
    merged.latency_p95_seconds = quantile(&latency, 0.95);
    merged.fill_p95_seconds = quantile(&fills, 0.95);
    for key in CACHE_SOURCES {
        let total = samples
            .iter()
            .filter_map(|s| s.cache_sources.get(key)?.parse::<u64>().ok())
            .fold(0u64, u64::saturating_add);
        merged.cache_sources.insert(key.into(), total.to_string());
    }
    for key in crate::health::PRODUCER_SOURCES {
        let total = samples
            .iter()
            .filter_map(|s| s.producer_sources.get(key)?.parse::<u64>().ok())
            .fold(0u64, u64::saturating_add);
        merged
            .producer_sources
            .insert(key.into(), total.to_string());
    }
    merged.requests_per_second =
        (!merged.gap).then(|| merged.requests.parse::<u64>().unwrap_or(0) as f64 / 60.0);
    merged.bytes_per_second =
        (!merged.gap).then(|| merged.response_bytes.parse::<u64>().unwrap_or(0) as f64 / 60.0);
    Some(merged)
}

pub async fn get_events(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let guard = match state.telemetry.connect(if auth.machine {
        "machine:local-control".into()
    } else {
        auth.session_id
    }) {
        Ok(guard) => guard,
        Err(error) => return store_error(error),
    };
    let receiver = state.telemetry.latest.subscribe();
    let events =
        stream::unfold(
            (state, headers, receiver, guard, true),
            |(state, headers, mut receiver, guard, first)| async move {
                if !first {
                    loop {
                        let changed =
                            tokio::time::timeout(Duration::from_secs(5), receiver.changed()).await;
                        if authenticate(&state, &headers, false, Some(Permission::ViewStatus))
                            .await
                            .is_err()
                        {
                            return None;
                        }
                        match changed {
                            Ok(Ok(())) => break,
                            Ok(Err(_)) => return None,
                            Err(_) => {
                                if state.telemetry.snapshot().is_none_or(|sample| {
                                    now().saturating_sub(sample.sample_at) > 10
                                }) {
                                    let event =
                                        Event::default().event("stale").data("{\"stale\":true}");
                                    return Some((
                                        Ok::<_, Infallible>(event),
                                        (state, headers, receiver, guard, false),
                                    ));
                                }
                            }
                        }
                    }
                } else if authenticate(&state, &headers, false, Some(Permission::ViewStatus))
                    .await
                    .is_err()
                {
                    return None;
                }
                let sample = receiver.borrow_and_update().clone();
                let event = match sample {
                    Some(sample) => Event::default().event("telemetry").json_data(sample).ok()?,
                    None => Event::default().event("waiting").data("{}"),
                };
                Some((
                    Ok::<_, Infallible>(event),
                    (state, headers, receiver, guard, false),
                ))
            },
        );
    Sse::new(events)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}
fn parse_range(uri: &Uri) -> Result<String, StoreError> {
    let Some(raw) = uri.query() else {
        return Ok("15m".into());
    };
    let mut range = None;
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        if k == "range" && range.is_none() {
            range = Some(v.into_owned());
        } else {
            return Err(StoreError::Invalid);
        }
    }
    Ok(range.unwrap_or_else(|| "15m".into()))
}
pub async fn get_metrics_history(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await
    {
        return response;
    }
    let range = match parse_range(&uri) {
        Ok(r) => r,
        Err(e) => return store_error(e),
    };
    let (seconds, resolution) = match range.as_str() {
        "15m" => (900, 5),
        "1h" => (3600, 5),
        "24h" => (86400, 60),
        "7d" => (604800, 60),
        _ => return store_error(StoreError::Invalid),
    };
    let cutoff = now() - seconds;
    let result = if resolution == 5 {
        Ok(lock(&state.telemetry.ring)
            .iter()
            .filter(|s| s.sample_at >= cutoff)
            .cloned()
            .collect::<Vec<_>>())
    } else {
        state
            .admin
            .read(move |c| {
                let mut statement = c.prepare(
                    "SELECT body FROM metric_rollups WHERE minute>=?1 ORDER BY minute LIMIT 10080",
                )?;
                let rows =
                    statement.query_map([cutoff.div_euclid(60)], |r| r.get::<_, Vec<u8>>(0))?;
                let mut samples = Vec::new();
                for row in rows {
                    samples.push(
                        serde_json::from_slice::<TelemetrySample>(&row?)
                            .map_err(|_| StoreError::Unavailable)?,
                    );
                }
                Ok(samples)
            })
            .await
    };
    match result {
        Ok(mut samples) => {
            mark_gaps(&mut samples);
            let sampled_at = state.telemetry.snapshot().map(|sample| sample.sample_at);
            Json(serde_json::json!({
                "samples": samples, "resolutionSeconds": resolution,
                "sampleAt": sampled_at, "requestedAt": now(),
                "stale": sampled_at.is_none_or(|at| now().saturating_sub(at) > 10),
                "range": range
            }))
            .into_response()
        }
        Err(error) => store_error(error),
    }
}
fn mark_gaps(samples: &mut [TelemetrySample]) {
    for i in 1..samples.len() {
        let elapsed = samples[i]
            .sample_at
            .saturating_sub(samples[i - 1].sample_at);
        let expected = i64::from(samples[i].resolution_seconds);
        if samples[i].boot_id != samples[i - 1].boot_id
            || elapsed <= 0
            || elapsed > expected + expected / 2
        {
            samples[i].gap = true;
        }
    }
}
pub async fn get_alerts(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await
    {
        return response;
    }
    let acknowledgments = state.admin.read(|c| { let mut statement = c.prepare("SELECT condition_id,actor,note,created_at FROM alert_acknowledgments ORDER BY created_at DESC LIMIT 100")?; let rows = statement.query_map([], |r| Ok(serde_json::json!({"conditionId":r.get::<_,String>(0)?,"actor":r.get::<_,String>(1)?,"note":r.get::<_,String>(2)?,"createdAt":r.get::<_,i64>(3)?})))?; Ok(rows.collect::<Result<Vec<_>, _>>()?) }).await;
    match acknowledgments { Ok(acknowledgments) => Json(serde_json::json!({"alerts":state.telemetry.snapshot().map(|s| s.alerts),"acknowledgments":acknowledgments,"sampleAt":now()})).into_response(), Err(error) => store_error(error) }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeRequest {
    note: String,
}
pub async fn post_acknowledge_alert(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AcknowledgeRequest>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::AcknowledgeAlerts)).await
    {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if request.note.trim().is_empty()
        || request.note.len() > 1024
        || id.len() > 256
        || !state
            .telemetry
            .snapshot()
            .is_some_and(|s| s.alerts.iter().any(|a| a.condition_id == id))
    {
        return store_error(StoreError::Invalid);
    }
    let result = state
        .admin
        .write(move |tx| {
            let user = actor(tx, &auth, Some(Permission::AcknowledgeAlerts))?;
            persist_acknowledgment(tx, &id, &user.id, &request.note, now())
        })
        .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => store_error(error),
    }
}
fn persist_acknowledgment(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    user: &str,
    note: &str,
    time: i64,
) -> Result<(), StoreError> {
    tx.execute("INSERT OR REPLACE INTO alert_acknowledgments(condition_id,actor,note,created_at) VALUES(?1,?2,?3,?4)", rusqlite::params![id, user, note, time])?;
    tx.execute("DELETE FROM alert_acknowledgments WHERE rowid IN (SELECT rowid FROM alert_acknowledgments ORDER BY created_at DESC LIMIT -1 OFFSET 1000)", [])?;
    audit(tx, user, "alert.acknowledge", id, "acknowledged", note)
}
pub async fn get_activity(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let audit = if auth.user.permissions.contains(&Permission::ViewAudit) {
        match state.admin.list_audit(auth, None, 100).await {
            Ok(events) => Some(events),
            Err(error) => return store_error(error),
        }
    } else {
        None
    };
    let jobs = state.admin.read(|c| { let mut statement = c.prepare("SELECT id,state,created_at FROM operation_requests ORDER BY created_at DESC,id DESC LIMIT 100")?; let rows = statement.query_map([], |r| Ok(serde_json::json!({"id":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"createdAt":r.get::<_,i64>(2)?})))?; Ok(rows.collect::<Result<Vec<_>,_>>()?) }).await;
    match jobs {
        Ok(jobs) => {
            Json(serde_json::json!({"auditEvents":audit,"operations":jobs,"sampleAt":now()}))
                .into_response()
        }
        Err(error) => store_error(error),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn warning_transitions_debounce_and_resolution_is_retained() {
        let mut tracker = AlertTracker::default();
        let warning = || Alert::new("storage.pressure".into(), "warning", "Pressure".into());
        assert!(tracker.update(vec![warning()]).is_empty());
        assert!(tracker.update(vec![warning()])[0].active);
        assert!(!tracker.update(Vec::new())[0].active);
    }
    #[test]
    fn rollups_merge_histograms_instead_of_percentiles() {
        let mut samples: Vec<_> = (0..12)
            .map(|i| TelemetrySample {
                boot_id: "boot".into(),
                sample_at: i * 5,
                resolution_seconds: 5,
                latency_buckets: ["0", "0", "0", "0", "0", "0", "0", "0"].map(String::from),
                fill_duration_buckets: ["0", "0", "0", "0", "0", "0", "0", "0"].map(String::from),
                ..Default::default()
            })
            .collect();
        samples[0].latency_buckets[0] = "1000".into();
        samples[1].latency_buckets[6] = "1".into();
        let merged = rollup(&samples).unwrap();
        assert_eq!(merged.latency_p95_seconds, Some(0.001));
        assert_eq!(merged.latency_buckets[6], "1");
        assert!(!merged.gap);
        let mut minutes = [
            TelemetrySample {
                boot_id: "boot".into(),
                sample_at: 60,
                resolution_seconds: 60,
                ..Default::default()
            },
            TelemetrySample {
                boot_id: "boot".into(),
                sample_at: 180,
                resolution_seconds: 60,
                ..Default::default()
            },
        ];
        mark_gaps(&mut minutes);
        assert!(minutes[1].gap);
    }
    #[test]
    fn counter_resets_are_gaps() {
        let metrics = Metrics::default();
        let before = Counters::read(&metrics);
        assert!(before.delta(&before).is_some());
        metrics.record_cache_source(0);
        let newer = Counters::read(&metrics);
        assert!(before.delta(&newer).is_none());
    }
    #[test]
    fn boot_changes_and_missing_ticks_create_gaps() {
        let first = TelemetrySample {
            boot_id: "first".into(),
            sample_at: 100,
            resolution_seconds: 5,
            ..Default::default()
        };
        let second = TelemetrySample {
            boot_id: "second".into(),
            sample_at: 105,
            resolution_seconds: 5,
            ..Default::default()
        };
        let third = TelemetrySample {
            boot_id: "second".into(),
            sample_at: 125,
            resolution_seconds: 5,
            ..Default::default()
        };
        let mut samples = [first, second, third];
        mark_gaps(&mut samples);
        assert!(samples[1].gap);
        assert!(samples[2].gap);
        assert!(rollup(&samples).unwrap().gap);
    }
    #[test]
    fn quantiles_do_not_fabricate_infinite_latency() {
        assert_eq!(quantile(&[0; 8], 0.95), None);
        assert_eq!(quantile(&[0, 0, 0, 0, 0, 0, 0, 100], 0.95), None);
        assert_eq!(quantile(&[0, 0, 100, 0, 0, 0, 0, 0], 0.95), Some(0.025));
    }
    #[test]
    fn connection_caps_release_on_drop() {
        let hub = Arc::new(TelemetryHub::new());
        let first = hub.connect("same".into()).unwrap();
        let second = hub.connect("same".into()).unwrap();
        assert!(hub.connect("same".into()).is_err());
        let others: Vec<_> = (0..14)
            .map(|i| hub.connect(i.to_string()).unwrap())
            .collect();
        assert!(hub.connect("overflow".into()).is_err());
        drop(first);
        assert!(hub.connect("same".into()).is_ok());
        drop(second);
        drop(others);
        assert_eq!(hub.connections.available_permits(), 16);
    }
    #[test]
    fn acknowledgment_is_durable_and_does_not_clear_condition() {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE alert_acknowledgments(condition_id TEXT,actor TEXT,note TEXT,created_at INTEGER,PRIMARY KEY(condition_id,created_at,actor)); CREATE TABLE audit_events(id INTEGER PRIMARY KEY,actor TEXT,action TEXT,target TEXT,outcome TEXT,reason TEXT,created_at INTEGER);").unwrap();
        let tx = c.transaction().unwrap();
        persist_acknowledgment(&tx, "storage.pressure", "operator", "Investigating", 123).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            c.query_row(
                "SELECT note FROM alert_acknowledgments WHERE condition_id='storage.pressure'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "Investigating"
        );
        assert_eq!(
            c.query_row("SELECT count(*) FROM audit_events", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
