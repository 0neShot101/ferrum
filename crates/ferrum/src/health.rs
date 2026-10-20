//! Admin listener: liveness, readiness and bounded Prometheus metrics.
//!
//! Labels are fixed enumerations; no path, digest or client address ever
//! becomes a label.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::sync::Catalog;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ferrum_apt::release::UnixTime;
use ferrum_storage::Spool;
use ferrum_storage::budget::BudgetLedger;
use serde::Serialize;

/// Request class of `ferrum_requests_total`.
#[derive(Debug, Clone, Copy)]
pub enum RequestClass {
    Metadata,
    ByHash,
    Package,
    Other,
}

pub(crate) const REQUEST_CLASSES: [&str; 4] = ["metadata", "by_hash", "package", "other"];
pub(crate) const REQUEST_OUTCOMES: [&str; 4] = ["2xx", "3xx", "4xx", "5xx"];
pub(crate) const FILL_OUTCOMES: [&str; 9] = [
    "verified",
    "corrupt",
    "not_found",
    "transient",
    "admission",
    "timeout",
    "s3_forbidden",
    "s3_budget",
    "internal",
];
pub(crate) const SYNC_OUTCOMES: [&str; 4] = ["published", "renewed", "rejected", "error"];
pub(crate) const CACHE_SOURCES: [&str; 5] = [
    "local_hit",
    "conditional_304",
    "s3_rehydrated",
    "origin_fill",
    "derived_expanded",
];
pub(crate) const PRODUCER_SOURCES: [&str; 3] = ["s3", "origin", "derived"];
pub(crate) const LATENCY_BUCKETS_NANOS: [u64; 8] = [
    1_000_000,
    5_000_000,
    25_000_000,
    100_000_000,
    500_000_000,
    2_000_000_000,
    10_000_000_000,
    u64::MAX,
];
const SUITE_ERROR_CLASSES: [&str; 7] = [
    "signature",
    "checkpoint_conflict",
    "untrusted_floor",
    "proof",
    "storage",
    "origin",
    "publication",
];

/// Plain atomics; every label combination is a fixed slot.
#[derive(Debug, Default)]
pub struct Metrics {
    pub(crate) cache_sources: [AtomicU64; 5],
    pub(crate) producer_sources: [AtomicU64; 3],
    pub(crate) repo_requests: [[AtomicU64; 2]; 25],
    pub(crate) repo_bytes: [AtomicU64; 25],
    pub(crate) request_ttfb_buckets: [[AtomicU64; 8]; 4],
    pub(crate) fill_duration_buckets: [AtomicU64; 8],
    pub(crate) requests: [[AtomicU64; 4]; 4],
    pub(crate) request_ttfb_nanos: [AtomicU64; 4],
    pub(crate) response_bytes: [AtomicU64; 4],
    pub(crate) body_duration_nanos: [AtomicU64; 4],
    pub(crate) body_transfers: [AtomicU64; 2],
    pub(crate) fills: [AtomicU64; 9],
    pub(crate) fill_waiters: AtomicU64,
    pub(crate) waiter_timeouts: AtomicU64,
    pub(crate) sync: [AtomicU64; 4],
}

fn class_slot(class: RequestClass) -> usize {
    match class {
        RequestClass::Metadata => 0,
        RequestClass::ByHash => 1,
        RequestClass::Package => 2,
        RequestClass::Other => 3,
    }
}

impl Metrics {
    pub fn record_cache_source(&self, source: usize) {
        if let Some(counter) = self.cache_sources.get(source) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn record_producer(&self, source: usize) {
        if let Some(counter) = self.producer_sources.get(source) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn record_fill_duration(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let bucket = LATENCY_BUCKETS_NANOS
            .iter()
            .position(|bound| nanos <= *bound)
            .unwrap_or(7);
        self.fill_duration_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_repository_request(&self, repository: usize, status: StatusCode) {
        if let Some(counters) = self.repo_requests.get(repository) {
            counters[usize::from(status.is_server_error() || status.is_client_error())]
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn record_repository_bytes(&self, repository: usize, bytes: u64) {
        if let Some(counter) = self.repo_bytes.get(repository) {
            counter.fetch_add(bytes, Ordering::Relaxed);
        }
    }
    pub fn record_request(&self, class: RequestClass, status: StatusCode) {
        self.record_request_timed(class, status, Duration::ZERO);
    }

    pub fn record_request_timed(&self, class: RequestClass, status: StatusCode, ttfb: Duration) {
        let outcome = match status.as_u16() {
            200..=299 => 0,
            300..=399 => 1,
            400..=499 => 2,
            _ => 3,
        };
        let slot = class_slot(class);
        self.requests[slot][outcome].fetch_add(1, Ordering::Relaxed);
        let nanos = u64::try_from(ttfb.as_nanos()).unwrap_or(u64::MAX);
        self.request_ttfb_nanos[slot].fetch_add(nanos, Ordering::Relaxed);
        let bucket = LATENCY_BUCKETS_NANOS
            .iter()
            .position(|bound| nanos <= *bound)
            .unwrap_or(7);
        self.request_ttfb_buckets[slot][bucket].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_body_bytes(&self, class: RequestClass, bytes: u64) {
        self.response_bytes[class_slot(class)].fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_body_transfer(&self, completed: bool, class: RequestClass, duration: Duration) {
        let index = usize::from(!completed);
        self.body_transfers[index].fetch_add(1, Ordering::Relaxed);
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        self.body_duration_nanos[class_slot(class)].fetch_add(nanos, Ordering::Relaxed);
    }

    /// `label` must be one of the bounded fill outcomes; unknown labels count as
    /// `internal`.
    pub fn record_fill(&self, label: &str) {
        let index = FILL_OUTCOMES
            .iter()
            .position(|known| *known == label)
            .unwrap_or(FILL_OUTCOMES.len() - 1);
        self.fills[index].fetch_add(1, Ordering::Relaxed);
    }

    /// `label` must be one of the bounded sync outcomes; unknown labels count as
    /// `error`.
    pub fn record_sync(&self, label: &str) {
        let index = SYNC_OUTCOMES
            .iter()
            .position(|known| *known == label)
            .unwrap_or(SYNC_OUTCOMES.len() - 1);
        self.sync[index].fetch_add(1, Ordering::Relaxed);
    }

    pub fn waiter_joined(&self) {
        self.fill_waiters.fetch_add(1, Ordering::Relaxed);
    }

    pub fn waiter_left(&self) {
        self.fill_waiters.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_waiter_timeout(&self) {
        self.waiter_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fill_waiters(&self) -> u64 {
        self.fill_waiters.load(Ordering::Relaxed)
    }
}

/// State behind the admin routes.
pub struct HealthState {
    pub catalog: Arc<Catalog>,
    pub metrics: Arc<Metrics>,
    pub spool: Spool,
    pub capture: Option<Arc<ferrum_storage::capture::CaptureManager>>,
    pub sync_trigger: Option<crate::sync::SyncTrigger>,
    pub admin: Arc<crate::admin::AdminStore>,
    pub admin_http: Arc<crate::admin::AdminHttpState>,
    pub verifier_version: String,
    pub jobs: Arc<crate::admin::jobs::JobRegistry>,
    pub telemetry: Arc<crate::admin::telemetry::TelemetryHub>,
    pub config: Arc<crate::config::Config>,
    pub publisher: Option<Arc<ferrum_storage::checkpoint::CheckpointPublisher>>,
    pub s3: Option<Arc<ferrum_storage::s3::S3Store>>,
    pub fills: Option<crate::fetch::FillRegistry>,
    pub request_slots: Option<Arc<tokio::sync::Semaphore>>,
    pub active_bodies: Option<Arc<tokio::sync::Semaphore>>,
    pub prewarm: Option<Arc<crate::prewarm::Prewarm>>,
}

#[derive(Serialize)]
struct Readiness {
    ready: bool,
}

#[derive(Serialize, Clone)]
pub(crate) struct SuiteHealth {
    pub(crate) repository: String,
    pub(crate) suite: String,
    pub(crate) ready: bool,
    pub(crate) generation_id: Option<String>,
    pub(crate) lease_deadline: Option<i64>,
    pub(crate) lease_remaining_seconds: Option<i64>,
    pub(crate) observed_age_seconds: Option<i64>,
    pub(crate) confirmed_age_seconds: Option<i64>,
    pub(crate) publication_lag_seconds: Option<i64>,
    pub(crate) checkpoint_sequence: Option<u64>,
    pub(crate) checkpoint_status: &'static str,
    pub(crate) alert_state: &'static str,
    pub(crate) last_error: Option<String>,
}

fn classify_suite_alert(
    ready: bool,
    lease_remaining_seconds: Option<i64>,
    observed_age_seconds: Option<i64>,
    publication_lag_seconds: Option<i64>,
    last_error: Option<&str>,
) -> &'static str {
    let page_error = matches!(
        last_error,
        Some("signature" | "checkpoint_conflict" | "untrusted_floor" | "proof" | "storage")
    );
    if !ready
        || page_error
        || lease_remaining_seconds.is_some_and(|remaining| remaining <= 3600)
        || observed_age_seconds.is_some_and(|age| age >= 1800)
        || publication_lag_seconds.is_some_and(|lag| lag >= 1800)
    {
        "page"
    } else if last_error.is_some()
        || observed_age_seconds.is_some_and(|age| age >= 600)
        || publication_lag_seconds.is_some_and(|lag| lag >= 600)
    {
        "warn"
    } else {
        "ok"
    }
}

pub(crate) async fn suite_health(catalog: &Catalog, clock_valid: bool) -> Vec<SuiteHealth> {
    let wall = UnixTime::now();
    let now = Instant::now();
    let keys = catalog.keys();
    let mut health = Vec::with_capacity(keys.len());

    for key in keys {
        let view = catalog.load_suite(&key);
        let persisted = match catalog.publisher() {
            Some(publisher) => publisher.state_async(&key).await.ok(),
            None => None,
        };
        let ready = clock_valid
            && view.as_ref().is_some_and(|view| {
                view.is_fresh(now, wall)
                    && (catalog.publisher().is_none()
                        || persisted.as_ref().is_some_and(|state| {
                            !state.blocked
                                && state.pending.is_none()
                                && state.active.as_ref().is_some_and(|active| {
                                    active.generation_id == view.generation_id.to_hex()
                                })
                        }))
            });
        let checkpoint_status = match &persisted {
            None => "unavailable",
            Some(state) if state.blocked => "blocked",
            Some(state) if state.pending.is_some() => "pending",
            Some(state) if state.active.is_some() => "active",
            Some(_) => "missing",
        };

        let age = |time: i64| wall.as_secs().saturating_sub(time).max(0);
        let lease_deadline = view.as_ref().map(|view| {
            let lease = i64::try_from(view.lease.as_secs()).unwrap_or(i64::MAX);
            let deadline = view.confirmed_at_unix.as_secs().saturating_add(lease);
            view.valid_until
                .map_or(deadline, |until| deadline.min(until.as_secs()))
        });
        let lease_remaining_seconds =
            lease_deadline.map(|deadline| deadline.saturating_sub(wall.as_secs()).max(0));
        let observed_age_seconds = persisted
            .as_ref()
            .and_then(|state| state.observed_at)
            .map(age);
        let confirmed_age_seconds = persisted
            .as_ref()
            .and_then(|state| state.confirmed_at)
            .map(age);
        let publication_lag_seconds = persisted
            .as_ref()
            .and_then(|state| state.successor_seen_at)
            .map(age);
        let last_error: Option<String> = persisted
            .as_ref()
            .and_then(|state| state.last_error.as_ref())
            .map(|error| error.chars().take(256).collect());
        let alert_state = classify_suite_alert(
            ready,
            lease_remaining_seconds,
            observed_age_seconds,
            publication_lag_seconds,
            last_error.as_deref(),
        );

        health.push(SuiteHealth {
            repository: key.repository().to_owned(),
            suite: key.suite().to_owned(),
            ready,
            generation_id: view.as_ref().map(|view| view.generation_id.to_hex()),
            lease_deadline,
            lease_remaining_seconds,
            observed_age_seconds,
            confirmed_age_seconds,
            publication_lag_seconds,
            checkpoint_sequence: persisted
                .as_ref()
                .and_then(|state| state.floor.as_ref())
                .map(|floor| floor.sequence),
            checkpoint_status,
            alert_state,
            last_error,
        });
    }

    health
}

/// Loopback administration listener. Probes are minimal; detailed routes require authentication.
pub fn router(state: Arc<HealthState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/livez", get(healthz))
        .route("/readyz", get(readyz))
        .route("/readyz/{repository}/{suite}", get(suite_readyz))
        .route("/metrics", get(metrics))
        .merge(crate::admin::routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::admin::security_boundary,
        ))
        .with_state(state)
}

async fn healthz() -> Response {
    (StatusCode::OK, "ok").into_response()
}

async fn readyz(State(state): State<Arc<HealthState>>) -> Response {
    let view = state.catalog.load();
    let clock_valid = state.catalog.clock_valid();
    let suites = suite_health(&state.catalog, clock_valid).await;
    let ready = if state.catalog.is_fixture() {
        view.as_ref()
            .is_some_and(|view| clock_valid && view.is_fresh(Instant::now(), UnixTime::now()))
    } else {
        clock_valid && suites.iter().all(|suite| suite.ready)
    };
    // Metadata can publish before startup capture reconciliation completes.
    // Do not advertise aggregate readiness while cold package admission is closed.
    let ready = ready
        && state
            .capture
            .as_ref()
            .is_none_or(|capture| capture.coverage_ready().unwrap_or(false));
    let body = Readiness { ready };
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

async fn suite_readyz(State(state): State<Arc<HealthState>>, uri: Uri) -> Response {
    let mut parts = uri.path().trim_matches('/').split('/');
    let (Some("readyz"), Some(repository), Some(suite), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let clock_valid = state.catalog.clock_valid();
    let Some(mut health) = suite_health(&state.catalog, clock_valid)
        .await
        .into_iter()
        .find(|item| item.repository == repository && item.suite == suite)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let capture_ready = state
        .capture
        .as_ref()
        .is_none_or(|capture| capture.coverage_ready().unwrap_or(false));
    health.ready = health.ready && capture_ready;
    let status = if health.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(Readiness {
            ready: health.ready,
        }),
    )
        .into_response()
}

async fn metrics(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    if let Err(response) = crate::admin::authorize_metrics(&state, &headers).await {
        return response;
    }
    let text = render_metrics(&state).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        text,
    )
        .into_response()
}

async fn render_metrics(state: &HealthState) -> String {
    let metrics = &state.metrics;
    let mut text = String::with_capacity(2048);
    for (slot, source) in CACHE_SOURCES.iter().enumerate() {
        let _ = writeln!(
            text,
            "ferrum_cache_sources_total{{source=\"{source}\"}} {}",
            metrics.cache_sources[slot].load(Ordering::Relaxed)
        );
    }
    for (slot, source) in PRODUCER_SOURCES.iter().enumerate() {
        let _ = writeln!(
            text,
            "ferrum_producer_sources_total{{source=\"{source}\"}} {}",
            metrics.producer_sources[slot].load(Ordering::Relaxed)
        );
    }
    for repository in 0..25 {
        let name = crate::config::Repository::ALL
            .get(repository)
            .map_or("fixture", |item| item.name());
        for (outcome, label) in ["ok", "error"].iter().enumerate() {
            let _ = writeln!(
                text,
                "ferrum_repository_requests_total{{repository=\"{name}\",outcome=\"{label}\"}} {}",
                metrics.repo_requests[repository][outcome].load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            text,
            "ferrum_repository_bytes_total{{repository=\"{name}\"}} {}",
            metrics.repo_bytes[repository].load(Ordering::Relaxed)
        );
    }
    for (class, label) in REQUEST_CLASSES.iter().enumerate() {
        let mut cumulative = 0u64;
        for (bucket, boundary) in ["0.001", "0.005", "0.025", "0.1", "0.5", "2", "10", "+Inf"]
            .iter()
            .enumerate()
        {
            cumulative = cumulative.saturating_add(
                metrics.request_ttfb_buckets[class][bucket].load(Ordering::Relaxed),
            );
            let _ = writeln!(
                text,
                "ferrum_request_ttfb_seconds_bucket{{class=\"{label}\",le=\"{boundary}\"}} {cumulative}"
            );
        }
    }
    let mut cumulative = 0u64;
    for (bucket, boundary) in ["0.001", "0.005", "0.025", "0.1", "0.5", "2", "10", "+Inf"]
        .iter()
        .enumerate()
    {
        cumulative = cumulative
            .saturating_add(metrics.fill_duration_buckets[bucket].load(Ordering::Relaxed));
        let _ = writeln!(
            text,
            "ferrum_fill_duration_seconds_bucket{{le=\"{boundary}\"}} {cumulative}"
        );
    }
    let _ = writeln!(text, "# TYPE ferrum_requests_total counter");
    for (class_index, class) in REQUEST_CLASSES.iter().enumerate() {
        for (outcome_index, outcome) in REQUEST_OUTCOMES.iter().enumerate() {
            let value = metrics.requests[class_index][outcome_index].load(Ordering::Relaxed);
            let _ = writeln!(
                text,
                "ferrum_requests_total{{class=\"{class}\",outcome=\"{outcome}\"}} {value}"
            );
        }
    }
    let _ = writeln!(text, "# TYPE ferrum_request_ttfb_nanos_total counter");
    for (class_index, class) in REQUEST_CLASSES.iter().enumerate() {
        let value = metrics.request_ttfb_nanos[class_index].load(Ordering::Relaxed);
        let _ = writeln!(
            text,
            "ferrum_request_ttfb_nanos_total{{class=\"{class}\"}} {value}"
        );
    }
    let _ = writeln!(text, "# TYPE ferrum_response_bytes_total counter");
    for (class_index, class) in REQUEST_CLASSES.iter().enumerate() {
        let value = metrics.response_bytes[class_index].load(Ordering::Relaxed);
        let _ = writeln!(
            text,
            "ferrum_response_bytes_total{{class=\"{class}\"}} {value}"
        );
    }
    let _ = writeln!(text, "# TYPE ferrum_body_duration_nanos_total counter");
    for (class_index, class) in REQUEST_CLASSES.iter().enumerate() {
        let value = metrics.body_duration_nanos[class_index].load(Ordering::Relaxed);
        let _ = writeln!(
            text,
            "ferrum_body_duration_nanos_total{{class=\"{class}\"}} {value}"
        );
    }
    let _ = writeln!(text, "# TYPE ferrum_body_transfers_total counter");
    for (index, outcome) in ["completed", "aborted"].iter().enumerate() {
        let value = metrics.body_transfers[index].load(Ordering::Relaxed);
        let _ = writeln!(
            text,
            "ferrum_body_transfers_total{{outcome=\"{outcome}\"}} {value}"
        );
    }
    let _ = writeln!(text, "# TYPE ferrum_fills_total counter");
    for (index, outcome) in FILL_OUTCOMES.iter().enumerate() {
        let value = metrics.fills[index].load(Ordering::Relaxed);
        let _ = writeln!(text, "ferrum_fills_total{{outcome=\"{outcome}\"}} {value}");
    }
    let _ = writeln!(text, "# TYPE ferrum_fill_waiters gauge");
    let _ = writeln!(text, "ferrum_fill_waiters {}", metrics.fill_waiters());
    let _ = writeln!(text, "# TYPE ferrum_waiter_timeouts_total counter");
    let _ = writeln!(
        text,
        "ferrum_waiter_timeouts_total {}",
        metrics.waiter_timeouts.load(Ordering::Relaxed)
    );
    let accounting = state.spool.accounting();
    let _ = writeln!(text, "# TYPE ferrum_spool_bytes gauge");
    let _ = writeln!(
        text,
        "ferrum_spool_bytes{{state=\"reserved\"}} {}",
        accounting.reserved
    );
    let _ = writeln!(
        text,
        "ferrum_spool_bytes{{state=\"installed\"}} {}",
        accounting.installed
    );
    if let Ok(usage) = state.spool.usage() {
        let _ = writeln!(
            text,
            "ferrum_spool_catalog_bytes {}\nferrum_spool_managed_bytes {}\nferrum_spool_available_bytes {}\nferrum_spool_admission_open {}",
            usage.catalog_bytes,
            usage.managed_bytes,
            usage.filesystem_available,
            u8::from(usage.admission_open)
        );
    }
    if let Some(capture) = &state.capture {
        if let Ok(outbox) = capture.usage() {
            let _ = writeln!(
                text,
                "ferrum_capture_outbox_bytes {}\nferrum_capture_outbox_entries {}",
                outbox.bytes, outbox.entries
            );
        }
        let ready = capture.coverage_ready().unwrap_or(false);
        let _ = writeln!(text, "ferrum_capture_coverage_ready {}", u8::from(ready));
    }
    if let Ok(budget) = BudgetLedger::inspect(&state.spool) {
        let _ = writeln!(
            text,
            "ferrum_remote_budget_storage_bytes {}\nferrum_remote_budget_download_bytes {}\nferrum_remote_budget_package_download_bytes {}\nferrum_remote_budget_certain {}",
            budget.storage,
            budget.download,
            budget.package_download,
            u8::from(budget.certain)
        );
    }
    let _ = writeln!(text, "# TYPE ferrum_sync_total counter");
    for (index, outcome) in SYNC_OUTCOMES.iter().enumerate() {
        let value = metrics.sync[index].load(Ordering::Relaxed);
        let _ = writeln!(text, "ferrum_sync_total{{outcome=\"{outcome}\"}} {value}");
    }
    let age = state
        .catalog
        .load()
        .map_or(0, |view| view.confirmed_at.elapsed().as_secs());
    let _ = writeln!(text, "# TYPE ferrum_active_generation_age_seconds gauge");
    let _ = writeln!(text, "ferrum_active_generation_age_seconds {age}");
    for suite in suite_health(&state.catalog, state.catalog.clock_valid()).await {
        let repository = &suite.repository;
        let name = &suite.suite;
        let _ = writeln!(
            text,
            "ferrum_suite_ready{{repository=\"{repository}\",suite=\"{name}\"}} {}",
            u8::from(suite.ready)
        );
        for (metric, value) in [
            (
                "ferrum_suite_observed_age_seconds",
                suite.observed_age_seconds,
            ),
            (
                "ferrum_suite_confirmed_age_seconds",
                suite.confirmed_age_seconds,
            ),
            (
                "ferrum_suite_publication_lag_seconds",
                suite.publication_lag_seconds,
            ),
            ("ferrum_suite_lease_deadline_seconds", suite.lease_deadline),
            (
                "ferrum_suite_lease_remaining_seconds",
                suite.lease_remaining_seconds,
            ),
        ] {
            if let Some(value) = value {
                let _ = writeln!(
                    text,
                    "{metric}{{repository=\"{repository}\",suite=\"{name}\"}} {value}"
                );
            }
        }
        if let Some(sequence) = suite.checkpoint_sequence {
            let _ = writeln!(
                text,
                "ferrum_suite_checkpoint_sequence{{repository=\"{repository}\",suite=\"{name}\"}} {sequence}"
            );
        }
        for severity in ["warn", "page"] {
            let active = u8::from(suite.alert_state == severity);
            let _ = writeln!(
                text,
                "ferrum_suite_alert{{repository=\"{repository}\",suite=\"{name}\",severity=\"{severity}\"}} {active}"
            );
        }
        for class in SUITE_ERROR_CLASSES {
            let active = u8::from(suite.last_error.as_deref() == Some(class));
            let _ = writeln!(
                text,
                "ferrum_suite_error{{repository=\"{repository}\",suite=\"{name}\",class=\"{class}\"}} {active}"
            );
        }
    }
    text
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::sync::ActiveView;
    use ferrum_storage::checkpoint::SuiteKey;
    use std::time::Duration;

    #[tokio::test]
    async fn aggregate_health_keeps_distinct_ubuntu_pockets_and_clock_gating() {
        let pairs = [
            ("debian", "trixie"),
            ("debian", "trixie-updates"),
            ("debian-security", "trixie-security"),
            ("ubuntu", "noble"),
            ("ubuntu", "noble-updates"),
            ("ubuntu-security", "noble-security"),
        ];
        let views = pairs
            .iter()
            .map(|(repository, suite)| {
                let mut view = ActiveView::for_tests(
                    Vec::new(),
                    if *suite == "noble-security" {
                        Duration::ZERO
                    } else {
                        Duration::from_secs(60)
                    },
                );
                view.repository = (*repository).to_owned();
                view.suite = (*suite).to_owned();
                (SuiteKey::new(repository, suite).expect("fixed suite"), view)
            })
            .collect();
        let catalog = Catalog::for_suite_tests(views);
        let suites = suite_health(&catalog, catalog.clock_valid()).await;
        assert_eq!(suites.len(), 6);
        assert_eq!(suites.iter().filter(|suite| suite.ready).count(), 5);
        for (repository, suite) in pairs {
            let health = suites
                .iter()
                .find(|health| health.repository == repository && health.suite == suite)
                .expect("suite health");
            assert_eq!(health.ready, suite != "noble-security");
            assert!(health.lease_deadline.is_some());
        }
        catalog.set_clock_synchronized(false);
        assert!(
            suite_health(&catalog, catalog.clock_valid())
                .await
                .iter()
                .all(|suite| !suite.ready)
        );
    }

    #[test]
    fn sync_trigger_matches_all_repository_or_exact_suite() {
        let keys = vec![
            SuiteKey::new("debian", "trixie").expect("suite"),
            SuiteKey::new("debian", "trixie-updates").expect("suite"),
            SuiteKey::new("archlinux", "core").expect("suite"),
        ];
        let trigger = crate::sync::SyncTrigger::new(keys.clone());
        assert_eq!(
            trigger.trigger(Some("debian"), None),
            Some(vec![keys[0].clone(), keys[1].clone()])
        );
        assert_eq!(trigger.take_pending(), vec![0, 1]);
        assert_eq!(
            trigger.trigger(Some("archlinux"), Some("core")),
            Some(vec![keys[2].clone()])
        );
        assert_eq!(trigger.take_pending(), vec![2]);
        assert_eq!(trigger.trigger(None, None), Some(keys));
        assert_eq!(trigger.take_pending(), vec![0, 1, 2]);
        assert!(trigger.trigger(Some("unknown"), None).is_none());
        assert!(trigger.trigger(Some("debian"), Some("unknown")).is_none());
    }
}
