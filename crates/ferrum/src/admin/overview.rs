//! Existing real gateway overview and local-cache projection.
use super::model::Permission;
use super::routes::authenticate;
use crate::health::{
    FILL_OUTCOMES, HealthState, REQUEST_CLASSES, REQUEST_OUTCOMES, SYNC_OUTCOMES, SuiteHealth,
    suite_health,
};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ferrum_apt::release::UnixTime;
use ferrum_storage::budget::BudgetLedger;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SpoolOverview {
    installed_bytes: u64,
    reserved_bytes: u64,
    managed_ceiling_bytes: u64,
    catalog_bytes: u64,
    managed_bytes: u64,
    filesystem_available_bytes: u64,
    resident_entries: usize,
    active_reservations: usize,
    admission_open: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteOverview {
    storage_bytes: u64,
    download_bytes: u64,
    package_download_bytes: u64,
    certain: bool,
    outbox_entries: u64,
    outbox_bytes: u64,
    coverage_ready: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClassTraffic {
    class: &'static str,
    ok_2xx: u64,
    redirect_3xx: u64,
    client_4xx: u64,
    server_5xx: u64,
    ttfb_nanos: u64,
    response_bytes: u64,
    body_duration_nanos: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FillStat {
    outcome: &'static str,
    count: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncStat {
    outcome: &'static str,
    count: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatsOverview {
    requests: Vec<ClassTraffic>,
    completed_transfers: u64,
    aborted_transfers: u64,
    fills: Vec<FillStat>,
    fill_waiters: u64,
    waiter_timeouts: u64,
    sync_outcomes: Vec<SyncStat>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SuiteOverview {
    repository: String,
    suite: String,
    ready: bool,
    generation_id: Option<String>,
    lease_deadline: Option<i64>,
    lease_remaining_seconds: Option<i64>,
    observed_age_seconds: Option<i64>,
    confirmed_age_seconds: Option<i64>,
    publication_lag_seconds: Option<i64>,
    checkpoint_sequence: Option<u64>,
    checkpoint_status: &'static str,
    alert_state: &'static str,
    last_error: Option<String>,
}

impl From<SuiteHealth> for SuiteOverview {
    fn from(item: SuiteHealth) -> Self {
        Self {
            repository: item.repository,
            suite: item.suite,
            ready: item.ready,
            generation_id: item.generation_id,
            lease_deadline: item.lease_deadline,
            lease_remaining_seconds: item.lease_remaining_seconds,
            observed_age_seconds: item.observed_age_seconds,
            confirmed_age_seconds: item.confirmed_age_seconds,
            publication_lag_seconds: item.publication_lag_seconds,
            checkpoint_sequence: item.checkpoint_sequence,
            checkpoint_status: item.checkpoint_status,
            alert_state: item.alert_state,
            last_error: item.last_error,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OverviewResponse {
    boot_id: String,
    sample_at: Option<i64>,
    stale: bool,
    cache_sources: std::collections::BTreeMap<String, String>,
    latency: serde_json::Value,
    alerts: Option<Vec<super::telemetry::Alert>>,
    admission: Option<super::telemetry::Admission>,
    ready: bool,
    clock_valid: bool,
    mode: &'static str,
    verifier_version: String,
    last_error: Option<String>,
    suites: Vec<SuiteOverview>,
    spool: SpoolOverview,
    remote: Option<RemoteOverview>,
    stats: StatsOverview,
}

pub(super) fn build_spool_overview(state: &HealthState) -> SpoolOverview {
    let accounting = state.spool.accounting();
    if let Ok(usage) = state.spool.usage() {
        SpoolOverview {
            installed_bytes: usage.objects.installed,
            reserved_bytes: usage.objects.reserved,
            managed_ceiling_bytes: usage.objects.ceiling,
            catalog_bytes: usage.catalog_bytes,
            managed_bytes: usage.managed_bytes,
            filesystem_available_bytes: usage.filesystem_available,
            resident_entries: usage.resident_entries,
            active_reservations: usage.reservations,
            admission_open: usage.admission_open,
        }
    } else {
        SpoolOverview {
            installed_bytes: accounting.installed,
            reserved_bytes: accounting.reserved,
            managed_ceiling_bytes: accounting.ceiling,
            catalog_bytes: 0,
            managed_bytes: accounting.installed.saturating_add(accounting.reserved),
            filesystem_available_bytes: 0,
            resident_entries: 0,
            active_reservations: 0,
            admission_open: false,
        }
    }
}

pub(super) async fn get_overview(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await
    {
        return response;
    }
    let view = state.catalog.load();
    let clock_valid = state.catalog.clock_valid();
    let raw_suites = suite_health(&state.catalog, clock_valid).await;
    let capture_ready = state
        .capture
        .as_ref()
        .is_none_or(|capture| capture.coverage_ready().unwrap_or(false));
    let ready = if state.catalog.is_fixture() {
        view.as_ref()
            .is_some_and(|v| clock_valid && v.is_fresh(Instant::now(), UnixTime::now()))
    } else {
        clock_valid && raw_suites.iter().all(|suite| suite.ready)
    } && capture_ready;
    let suites: Vec<SuiteOverview> = if state.catalog.is_fixture() && raw_suites.is_empty() {
        let lease_deadline = view.as_ref().map(|v| {
            let lease = i64::try_from(v.lease.as_secs()).unwrap_or(i64::MAX);
            v.confirmed_at_unix.as_secs().saturating_add(lease)
        });
        let now_secs = UnixTime::now().as_secs();
        vec![SuiteOverview {
            repository: "fixture".into(),
            suite: crate::config::SUITE.into(),
            ready,
            generation_id: view.as_ref().map(|v| v.generation_id.to_hex()),
            lease_deadline,
            lease_remaining_seconds: lease_deadline.map(|d| d.saturating_sub(now_secs).max(0)),
            observed_age_seconds: view.as_ref().map(|v| {
                now_secs
                    .saturating_sub(v.confirmed_at_unix.as_secs())
                    .max(0)
            }),
            confirmed_age_seconds: view.as_ref().map(|v| {
                now_secs
                    .saturating_sub(v.confirmed_at_unix.as_secs())
                    .max(0)
            }),
            publication_lag_seconds: Some(0),
            checkpoint_sequence: Some(1),
            checkpoint_status: if ready { "active" } else { "missing" },
            alert_state: if ready { "ok" } else { "page" },
            last_error: state.catalog.last_error(),
        }]
    } else {
        raw_suites.into_iter().map(SuiteOverview::from).collect()
    };

    let spool = build_spool_overview(&state);
    let remote = BudgetLedger::inspect(&state.spool).ok().map(|budget| {
        let (outbox_entries, outbox_bytes) = state
            .capture
            .as_ref()
            .and_then(|c| c.usage().ok())
            .map_or((0, 0), |u| (u.entries, u.bytes));
        RemoteOverview {
            storage_bytes: budget.storage,
            download_bytes: budget.download,
            package_download_bytes: budget.package_download,
            certain: budget.certain,
            outbox_entries,
            outbox_bytes,
            coverage_ready: capture_ready,
        }
    });

    let metrics = &state.metrics;
    let requests = REQUEST_CLASSES
        .iter()
        .enumerate()
        .map(|(idx, class)| {
            let _ = REQUEST_OUTCOMES;
            ClassTraffic {
                class,
                ok_2xx: metrics.requests[idx][0].load(Ordering::Relaxed),
                redirect_3xx: metrics.requests[idx][1].load(Ordering::Relaxed),
                client_4xx: metrics.requests[idx][2].load(Ordering::Relaxed),
                server_5xx: metrics.requests[idx][3].load(Ordering::Relaxed),
                ttfb_nanos: metrics.request_ttfb_nanos[idx].load(Ordering::Relaxed),
                response_bytes: metrics.response_bytes[idx].load(Ordering::Relaxed),
                body_duration_nanos: metrics.body_duration_nanos[idx].load(Ordering::Relaxed),
            }
        })
        .collect();
    let fills = FILL_OUTCOMES
        .iter()
        .enumerate()
        .map(|(idx, outcome)| FillStat {
            outcome,
            count: metrics.fills[idx].load(Ordering::Relaxed),
        })
        .collect();
    let sync_outcomes = SYNC_OUTCOMES
        .iter()
        .enumerate()
        .map(|(idx, outcome)| SyncStat {
            outcome,
            count: metrics.sync[idx].load(Ordering::Relaxed),
        })
        .collect();

    let stats = StatsOverview {
        requests,
        completed_transfers: metrics.body_transfers[0].load(Ordering::Relaxed),
        aborted_transfers: metrics.body_transfers[1].load(Ordering::Relaxed),
        fills,
        fill_waiters: metrics.fill_waiters(),
        waiter_timeouts: metrics.waiter_timeouts.load(Ordering::Relaxed),
        sync_outcomes,
    };
    let telemetry = state.telemetry.snapshot();

    (
        StatusCode::OK,
        Json(OverviewResponse {
            boot_id: state.telemetry.boot_id.clone(),
            sample_at: telemetry.as_ref().map(|sample| sample.sample_at),
            stale: telemetry.as_ref().is_none_or(|sample| UnixTime::now().as_secs().saturating_sub(sample.sample_at) > 10),
            cache_sources: crate::health::CACHE_SOURCES.iter().enumerate().map(|(i, name)| (name.to_string(), metrics.cache_sources[i].load(Ordering::Relaxed).to_string())).collect(),
            latency: telemetry.as_ref().map_or(serde_json::Value::Null, |sample| serde_json::json!({
                "p95Seconds": sample.latency_p95_seconds,
                "fillP95Seconds": sample.fill_p95_seconds,
                "buckets": sample.latency_buckets,
                "resolutionSeconds": sample.resolution_seconds,
                "gap": sample.gap,
                "semantics": "Server response readiness, not client ACK latency. Quantiles are bucket upper-bound estimates; +Inf is unavailable."
            })),
            alerts: telemetry.as_ref().map(|sample| sample.alerts.clone()),
            admission: telemetry.as_ref().map(|sample| sample.admission.clone()),
            ready,
            clock_valid,
            mode: if state.catalog.is_fixture() {
                "fixture"
            } else {
                "durable"
            },
            verifier_version: state.verifier_version.clone(),
            last_error: state.catalog.last_error(),
            suites,
            spool,
            remote,
            stats,
        }),
    )
        .into_response()
}
