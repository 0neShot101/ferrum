//! Read-only dashboard projections. All blocking catalog/filesystem work runs
//! outside async workers; no browsing path dispatches a provider operation.
use super::model::Permission;
use super::routes::{authenticate, error_reply};
use crate::config::{ALL_DISTRIBUTION_SUITES, Config, Repository};
use crate::health::{HealthState, SuiteHealth, suite_health};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use ferrum_apt::digest::Sha256Digest;
use ferrum_storage::budget::{BudgetDiagnostics, BudgetLedger};
use ferrum_storage::capture::inventory::{CapturedPackage, InventoryFilter, InventorySummary};
use ferrum_storage::catalog::CatalogError;
use ferrum_storage::{Spool, SpoolError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
struct SummarySnapshot {
    value: InventorySummary,
    sampled_at: i64,
    collected: Instant,
}
/// Install one shared Arc as an Axum Extension, not one state per request.
pub struct AdminInventoryState {
    queries: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
    summary: Mutex<Option<SummarySnapshot>>,
}
impl Default for AdminInventoryState {
    fn default() -> Self {
        Self::new()
    }
}
impl AdminInventoryState {
    pub fn new() -> Self {
        Self {
            queries: Arc::new(Semaphore::new(2)),
            waiters: Arc::new(Semaphore::new(4)),
            summary: Mutex::new(None),
        }
    }
    async fn acquire(&self) -> Result<OwnedSemaphorePermit, Response> {
        if let Ok(permit) = self.queries.clone().try_acquire_owned() {
            return Ok(permit);
        }
        let _waiting = self
            .waiters
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        self.queries
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| unavailable())
    }
    fn summary(
        &self,
        spool: &Spool,
    ) -> (
        Option<InventorySummary>,
        Option<i64>,
        bool,
        Option<&'static str>,
    ) {
        let cached = self
            .summary
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(snapshot) = &cached
            && snapshot.collected.elapsed() < Duration::from_secs(60)
        {
            return (
                Some(snapshot.value.clone()),
                Some(snapshot.sampled_at),
                false,
                None,
            );
        }
        match spool.captured_summary() {
            Ok(value) => {
                let sampled_at = now();
                *self.summary.lock().unwrap_or_else(|p| p.into_inner()) = Some(SummarySnapshot {
                    value: value.clone(),
                    sampled_at,
                    collected: Instant::now(),
                });
                (Some(value), Some(sampled_at), false, None)
            }
            Err(_) => (
                cached.as_ref().map(|s| s.value.clone()),
                cached.map(|s| s.sampled_at),
                true,
                Some("Summary unavailable; narrow queries remain available."),
            ),
        }
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
        .unwrap_or(0)
}
fn busy() -> Response {
    error_reply(
        StatusCode::TOO_MANY_REQUESTS,
        "busy",
        "Inventory query capacity is full; retry shortly.",
    )
}
fn unavailable() -> Response {
    error_reply(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "Inventory or storage diagnostics are temporarily unavailable.",
    )
}
fn invalid_cursor() -> Response {
    error_reply(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_cursor",
        "Inventory cursor is invalid, expired, or belongs to different filters.",
    )
}
fn storage_error(error: SpoolError) -> Response {
    match error {
        SpoolError::Catalog(CatalogError::Busy) => error_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "narrow_search",
            "Inventory exceeded its bounded query window; narrow the filters and retry.",
        ),
        _ => unavailable(),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageQuery {
    pub repository: Option<String>,
    pub suite: Option<String>,
    pub digest_prefix: Option<String>,
    pub path_prefix: Option<String>,
    pub cache_status: Option<String>,
    pub remote_status: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<usize>,
}
impl PackageQuery {
    fn parse_uri(uri: &Uri) -> Result<Self, ()> {
        let mut out = Self::default();
        let mut seen = std::collections::BTreeSet::new();
        let Some(raw) = uri.query() else {
            return Ok(out);
        };
        if raw.len() > 8192 {
            return Err(());
        }
        for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
            if !seen.insert(k.to_string()) {
                return Err(());
            }
            match k.as_ref() {
                "repository" => out.repository = Some(v.into_owned()),
                "suite" => out.suite = Some(v.into_owned()),
                "digestPrefix" => out.digest_prefix = Some(v.into_owned()),
                "pathPrefix" => out.path_prefix = Some(v.into_owned()),
                "cacheStatus" => out.cache_status = Some(v.into_owned()),
                "remoteStatus" => out.remote_status = Some(v.into_owned()),
                "cursor" => out.cursor = Some(v.into_owned()),
                "limit" => out.limit = Some(v.parse::<usize>().map_err(|_| ())?),
                _ => return Err(()),
            }
        }
        Ok(out)
    }
    fn filter(&self) -> InventoryFilter {
        InventoryFilter {
            repository: self.repository.clone(),
            suite: self.suite.clone(),
            digest_prefix: self.digest_prefix.clone(),
            path_prefix: self.path_prefix.clone().filter(|s| !s.is_empty()),
            cache_status: self.cache_status.clone(),
            remote_status: self.remote_status.clone(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    v: u8,
    repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_hash: Option<String>,
    filter_hash: String,
    expires_at: i64,
}
#[derive(Debug, PartialEq, Eq)]
enum CursorAnchor {
    Inline(String, String),
    Hashed(String, String),
}
fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    value
}
fn decode_hex(value: &str, maximum: usize) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() > maximum || !value.len().is_multiple_of(2) {
        return None;
    }
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}
fn filter_hash(filter: &InventoryFilter) -> Result<String, Response> {
    serde_json::to_vec(filter)
        .map(|v| Sha256Digest::of(&v).to_hex())
        .map_err(|_| unavailable())
}
fn decode_cursor(
    value: Option<&str>,
    filter: &InventoryFilter,
    at: i64,
) -> Result<Option<CursorAnchor>, Response> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = decode_hex(value, 6 * 1024).ok_or_else(invalid_cursor)?;
    let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid_cursor())?;
    let locator = InventoryFilter {
        repository: Some(cursor.repo.clone()),
        path_prefix: cursor.path.clone(),
        digest_prefix: cursor.path_hash.clone(),
        ..InventoryFilter::default()
    };
    if cursor.v != 1
        || cursor.expires_at <= at
        || cursor.expires_at > at.saturating_add(3600)
        || !locator.validate()
        || cursor.filter_hash != filter_hash(filter)?
    {
        return Err(invalid_cursor());
    }
    match (cursor.path, cursor.path_hash) {
        (Some(path), None) if path.len() <= 1024 => {
            Ok(Some(CursorAnchor::Inline(cursor.repo, path)))
        }
        (None, Some(hash)) if hash.len() == 64 => Ok(Some(CursorAnchor::Hashed(cursor.repo, hash))),
        _ => Err(invalid_cursor()),
    }
}
fn encode_cursor(
    repository: &str,
    path: &str,
    path_hash: &str,
    hash: String,
    at: i64,
) -> Result<String, Response> {
    let (path, path_hash) = if path.len() <= 1024 {
        (Some(path.to_owned()), None)
    } else {
        (None, Some(path_hash.to_owned()))
    };
    let cursor = Cursor {
        v: 1,
        repo: repository.into(),
        path,
        path_hash,
        filter_hash: hash,
        expires_at: at.saturating_add(3600),
    };
    serde_json::to_vec(&cursor)
        .map(|v| encode_hex(&v))
        .map_err(|_| unavailable())
}
// The path hash is persisted and indexed by capture_paths_receipt. Unlike
// hex(path), this ID also represents legal 8 KiB paths below the 1024-char cap.
fn package_id(repository: &str, path_hash: &str) -> String {
    encode_hex(format!("{repository}:{path_hash}").as_bytes())
}
fn decode_package_id(value: &str) -> Option<(String, String)> {
    let text = String::from_utf8(decode_hex(value, 1024)?).ok()?;
    let (repository, digest) = text.split_once(':')?;
    let filter = InventoryFilter {
        repository: Some(repository.into()),
        digest_prefix: Some(digest.into()),
        ..InventoryFilter::default()
    };
    if digest.len() != 64 || !filter.validate() {
        return None;
    }
    Some((repository.into(), digest.into()))
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PackageView {
    id: String,
    display_name: String,
    metadata_status: &'static str,
    object_key: Option<String>,
    remote_evidence: &'static str,
    #[serde(flatten)]
    record: CapturedPackage,
}
fn package_view(record: CapturedPackage, state: &HealthState) -> PackageView {
    let object_key = state.s3.as_ref().and_then(|store| {
        store
            .package_key(&format!("v1/objects/sha256/{}", record.digest))
            .ok()
    });
    PackageView {
        id: package_id(&record.repository, &record.path_hash),
        display_name: record
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&record.path)
            .to_owned(),
        metadata_status: "path_only",
        remote_evidence: "recorded_catalog_not_live_provider_check",
        object_key,
        record,
    }
}

pub async fn get_packages(
    State(state): State<Arc<HealthState>>,
    Extension(inventory): Extension<Arc<AdminInventoryState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if let Err(response) =
        authenticate(&state, &headers, false, Some(Permission::ViewInventory)).await
    {
        return response;
    }
    let Ok(query) = PackageQuery::parse_uri(&uri) else {
        return error_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_filter",
            "Invalid inventory query parameters.",
        );
    };
    let filter = query.filter();
    let limit = query.limit.unwrap_or(50);
    if !filter.validate() || !(1..=100).contains(&limit) {
        return error_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_filter",
            "Invalid inventory filter or limit (1–100).",
        );
    }
    let after = match decode_cursor(query.cursor.as_deref(), &filter, now()) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if state.config.is_fixture() {
        return Json(json!({"items":[],"nextCursor":null,"hasMore":false,"summary":null,"sampledAt":null,"mode":"fixture","unavailable":"Durable captured inventory is unavailable in fixture mode."})).into_response();
    }
    let permit = match inventory.acquire().await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let spool = state.spool.clone();
    let hash = match filter_hash(&filter) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let after = match after {
            Some(CursorAnchor::Inline(repository, path)) => Some((repository, path)),
            Some(CursorAnchor::Hashed(repository, hash)) => {
                let anchor = spool
                    .captured_package_by_hash(repository, hash)
                    .map_err(|error| match error {
                        SpoolError::Catalog(CatalogError::InvalidState) => invalid_cursor(),
                        other => storage_error(other),
                    })?
                    .ok_or_else(invalid_cursor)?;
                Some((anchor.repository, anchor.path))
            }
            None => None,
        };
        let page = spool
            .captured_packages(filter, after, limit)
            .map_err(storage_error)?;
        let summary = inventory.summary(&spool);
        Ok::<_, Response>((page, summary, now()))
    })
    .await;
    let (page, (summary, summary_at, summary_stale, summary_error), sampled_at) = match result {
        Ok(Ok(value)) => value,
        Ok(Err(response)) => return response,
        Err(_) => return unavailable(),
    };
    let next_cursor = if page.has_more {
        match page.items.last() {
            Some(last) => match encode_cursor(
                &last.repository,
                &last.path,
                &last.path_hash,
                hash,
                sampled_at,
            ) {
                Ok(value) => Some(value),
                Err(response) => return response,
            },
            None => return unavailable(),
        }
    } else {
        None
    };
    let items: Vec<_> = page
        .items
        .into_iter()
        .map(|p| package_view(p, &state))
        .collect();
    let response = json!({"items":items,"nextCursor":next_cursor,"hasMore":page.has_more,"summary":summary,"sampledAt":sampled_at,
        "summarySampledAt":summary_at,"summaryStale":summary_stale,"summaryError":summary_error,"summaryScope":"all_captured_blobs_deduplicated","mode":"durable"});
    // Both the catalog and HTTP envelopes are bounded, including escaped paths.
    match serde_json::to_vec(&response) {
        Ok(bytes) if bytes.len() < 2 * 1024 * 1024 => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        _ => unavailable(),
    }
}
pub async fn get_package_detail(
    State(state): State<Arc<HealthState>>,
    Extension(inventory): Extension<Arc<AdminInventoryState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) =
        authenticate(&state, &headers, false, Some(Permission::ViewInventory)).await
    {
        return response;
    }
    let Some((repository, path_hash)) = decode_package_id(&id) else {
        return error_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_package_id",
            "Invalid captured package identity.",
        );
    };
    if state.config.is_fixture() {
        return error_reply(
            StatusCode::NOT_FOUND,
            "inventory_unavailable",
            "Durable captured inventory is unavailable in fixture mode.",
        );
    }
    let permit = match inventory.acquire().await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let spool = state.spool.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        spool.captured_package_by_hash(repository, path_hash)
    })
    .await
    {
        Ok(Ok(Some(record))) => {
            Json(json!({"package":package_view(record,&state),"sampledAt":now(),"mode":"durable"}))
                .into_response()
        }
        Ok(Ok(None)) => error_reply(
            StatusCode::NOT_FOUND,
            "not_found",
            "Captured package not found.",
        ),
        Ok(Err(error)) => storage_error(error),
        Err(_) => unavailable(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MirrorView {
    repository: String,
    suite: String,
    origin: String,
    ecosystem: &'static str,
    architectures: &'static [&'static str],
    configured: bool,
    retained_locked: Option<bool>,
    bootstrap_authorized: Option<bool>,
    keyring_configured: bool,
    keyring_exists: bool,
    status: &'static str,
    qualification: &'static str,
    health: Option<Value>,
}
fn health_value(health: &SuiteHealth) -> Value {
    json!({"ready":health.ready,"generationId":health.generation_id,"leaseDeadline":health.lease_deadline,
        "leaseRemainingSeconds":health.lease_remaining_seconds,"observedAgeSeconds":health.observed_age_seconds,
        "confirmedAgeSeconds":health.confirmed_age_seconds,"publicationLagSeconds":health.publication_lag_seconds,
        "checkpointSequence":health.checkpoint_sequence.map(|v| v.to_string()),"checkpointStatus":health.checkpoint_status,
        "alertState":health.alert_state,"lastError":health.last_error})
}
fn candidate_keyring(config: &Config, profile: Option<Repository>) -> Option<&std::path::Path> {
    use crate::config::DurableTrust;
    let Some(durable) = config.durable() else {
        return profile
            .is_none()
            .then_some(config.fixture.keyring.as_path());
    };
    match &durable.trust {
        DurableTrust::Fixture { keyring } => profile.is_none().then_some(keyring.as_path()),
        DurableTrust::Distributions(keys) => Some(match profile? {
            Repository::Debian | Repository::DebianSecurity => &keys.debian,
            Repository::Ubuntu | Repository::UbuntuSecurity | Repository::UbuntuPorts => {
                &keys.ubuntu
            }
            Repository::Kali => &keys.kali,
            Repository::Parrot => &keys.parrot,
            Repository::Trisquel => &keys.trisquel,
            Repository::RaspberryPi => &keys.raspberrypi,
            Repository::ProxmoxPve | Repository::ProxmoxPbs => &keys.proxmox,
            Repository::ArchLinux => &keys.archlinux,
            Repository::ChaoticAur => &keys.chaoticaur,
            Repository::DockerDebian | Repository::DockerUbuntu => &keys.docker,
            Repository::TailscaleDebian | Repository::TailscaleUbuntu => &keys.tailscale,
            Repository::PostgresqlApt => &keys.postgresql,
            Repository::GrafanaApt => &keys.grafana,
            Repository::CachyOs => &keys.cachyos,
            Repository::ArchLinuxCn => &keys.archlinuxcn,
            Repository::EndeavourOs => &keys.endeavouros,
            Repository::AlmaLinux => &keys.almalinux,
            Repository::RockyLinux => &keys.rockylinux,
        }),
    }
}
fn mirrors(state: &HealthState) -> Result<Vec<MirrorView>, ()> {
    let configured = state.config.suites().map_err(|_| ())?;
    let health = suite_health(&state.catalog, state.catalog.clock_valid());
    let retained = match &state.publisher {
        Some(publisher) => Some(publisher.retained_suites().map_err(|_| ())?),
        None => None,
    };
    let mut candidates: Vec<_> = ALL_DISTRIBUTION_SUITES
        .iter()
        .map(|candidate| {
            (
                candidate.repository.name(),
                candidate.suite,
                Some(candidate.repository),
            )
        })
        .collect();
    if state.config.is_fixture() || state.config.is_durable_fixture() {
        candidates.push((crate::config::REPOSITORY_PREFIX, crate::config::SUITE, None));
    }
    let mut items = Vec::with_capacity(candidates.len());
    for (repository, suite, profile) in candidates {
        let selection = configured
            .iter()
            .find(|s| s.key.repository() == repository && s.key.suite() == suite);
        let live = health
            .iter()
            .find(|h| h.repository == repository && h.suite == suite);
        let bootstrap = match &state.publisher {
            Some(publisher) => {
                let key =
                    ferrum_storage::checkpoint::SuiteKey::new(repository, suite).map_err(|_| ())?;
                Some(publisher.state(&key).map_err(|_| ())?.bootstrap_authorized)
            }
            None => None,
        };
        let fixture_health = if profile.is_none() && live.is_none() {
            let view = state.catalog.load();
            Some(
                json!({"ready":view.as_ref().is_some_and(|v| state.catalog.clock_valid() && v.is_fresh(Instant::now(),ferrum_apt::release::UnixTime::now())),
                "generationId":view.as_ref().map(|v| v.generation_id.to_hex()),"checkpointStatus":"fixture","lastError":state.catalog.last_error()}),
            )
        } else {
            None
        };
        let ready = live
            .map(|h| h.ready)
            .or_else(|| {
                fixture_health
                    .as_ref()
                    .and_then(|h| h.get("ready"))
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false);
        let keyring = candidate_keyring(&state.config, profile);
        items.push(MirrorView {
            repository: repository.into(),
            suite: suite.into(),
            origin: profile.map_or_else(
                || selection.map(|s| s.origin.to_string()).unwrap_or_default(),
                |p| p.origin().into(),
            ),
            ecosystem: profile.map_or("apt", Repository::ecosystem),
            architectures: profile.map_or(&["amd64"] as &[&str], Repository::architectures),
            configured: selection.is_some(),
            retained_locked: retained.as_ref().map(|keys| {
                keys.iter()
                    .any(|k| k.repository() == repository && k.suite() == suite)
            }),
            bootstrap_authorized: bootstrap,
            keyring_configured: keyring.is_some_and(|p| !p.as_os_str().is_empty()),
            keyring_exists: keyring.is_some_and(std::path::Path::is_file),
            status: if selection.is_none() {
                "candidate_unconfigured"
            } else if ready {
                "ready"
            } else {
                "configured_not_ready"
            },
            qualification: "candidate_registry_is_not_origin_qualification",
            health: live.map(health_value).or(fixture_health),
        });
    }
    Ok(items)
}
pub async fn get_mirrors(
    State(state): State<Arc<HealthState>>,
    Extension(inventory): Extension<Arc<AdminInventoryState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await
    {
        return response;
    }
    let permit = match inventory.acquire().await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        mirrors(&state)
    })
    .await
    {
        Ok(Ok(items)) => Json(json!({"mirrors":items,"sampledAt":now()})).into_response(),
        _ => unavailable(),
    }
}
pub async fn get_mirror_detail(
    State(state): State<Arc<HealthState>>,
    Extension(inventory): Extension<Arc<AdminInventoryState>>,
    headers: HeaderMap,
    Path((repository, suite)): Path<(String, String)>,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await
    {
        return response;
    }
    if repository.len() > 64 || suite.len() > 128 {
        return error_reply(
            StatusCode::NOT_FOUND,
            "not_found",
            "Mirror candidate not found.",
        );
    }
    let permit = match inventory.acquire().await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        mirrors(&state).map(|items| {
            items
                .into_iter()
                .find(|v| v.repository == repository && v.suite == suite)
        })
    })
    .await
    {
        Ok(Ok(Some(item))) => Json(json!({"mirror":item,"sampledAt":now()})).into_response(),
        Ok(Ok(None)) => error_reply(
            StatusCode::NOT_FOUND,
            "not_found",
            "Mirror candidate not found.",
        ),
        _ => unavailable(),
    }
}
fn protection(value: ferrum_storage::disk::CacheProtection) -> Value {
    json!({"objects":value.objects.to_string(),"bytes":value.bytes.to_string()})
}
fn preview_value(value: ferrum_storage::disk::CachePreview) -> Value {
    json!({"eligible":protection(value.eligible),"protected":{"pinned":protection(value.pinned),"metadata":protection(value.metadata),
        "staged":protection(value.staged),"liveReaders":protection(value.live_reader),"evicting":protection(value.evicting)},
        "sampledAt":value.sampled_at,"executionRechecksEligibility":true,"scope":"local_package_cache_only"})
}
pub async fn post_cache_preview(
    State(state): State<Arc<HealthState>>,
    Extension(inventory): Extension<Arc<AdminInventoryState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, true, Some(Permission::ManageCache)).await
    {
        return response;
    }
    let permit = match inventory.acquire().await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let spool = state.spool.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        spool.preview_evictable_cache()
    })
    .await
    {
        Ok(Ok(value)) => Json(preview_value(value)).into_response(),
        Ok(Err(error)) => storage_error(error),
        Err(_) => unavailable(),
    }
}
fn budget_value(value: BudgetDiagnostics, config: &Config) -> Value {
    let limits = config.durable().map(|d| json!({"storage":d.budget.storage.to_string(),"storageControlReserve":d.budget.storage_control.to_string(),
        "monthlyDownload":d.budget.monthly_download.to_string(),"downloadControlReserve":d.budget.download_control.to_string()}));
    let provider = value.provider.as_ref().map(|p| json!({"endpoint":p.endpoint(),"bucket":p.bucket(),"region":p.region(),"packagePrefix":p.package_prefix(),"checkpointPrefix":p.checkpoint_prefix()}));
    json!({"period":value.period,"periodUtc":format!("{:04}-{:02}",value.period.div_euclid(12),value.period.rem_euclid(12)+1),"periodConvention":"UTC_year_times_12_plus_zero_based_month","highTime":value.high_time,
        "downloadBytes":value.download.to_string(),"packageDownloadBytes":value.package_download.to_string(),
        "controlDownloadBytes":value.download.saturating_sub(value.package_download).to_string(),
        "storageBytes":value.storage.to_string(),"packageStorageBytes":value.package_storage.to_string(),
        "controlStorageBytes":value.storage.saturating_sub(value.package_storage).to_string(),"certain":value.certain,
        "reservations":{"count":value.reservation_count.to_string(),"bytes":value.reserved_download.to_string(),"packageBytes":value.reserved_package_download.to_string()},
        "readbackEscrow":{"count":value.escrow_count.to_string(),"bytes":value.escrow_bytes.to_string(),"includedInReservations":true},
        "storageAccounting":"logical_committed_and_reserved","forbidden":value.forbidden,"provider":provider,"limits":limits,"evidence":"recorded_catalog_not_live_provider_check"})
}
pub async fn get_storage(
    State(state): State<Arc<HealthState>>,
    Extension(inventory): Extension<Arc<AdminInventoryState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await
    {
        return response;
    }
    let permit = match inventory.acquire().await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match tokio::task::spawn_blocking(move || -> Result<Value,SpoolError> {
        let _permit = permit;
        let usage = state.spool.usage()?;
        let limits = state.spool.durable_limits().map(|v| json!({"freeSpaceFloorBytes":v.free_space_floor.to_string(),"temporaryCeilingBytes":v.temporary_ceiling.to_string(),
            "metadataTemporaryReserveBytes":v.metadata_temporary_reserve.to_string(),"metadataCeilingBytes":v.metadata_ceiling.to_string(),"catalogCeilingBytes":v.catalog_ceiling.to_string(),
            "maxEntries":v.max_entries.to_string(),"evictionHighWatermarkBytes":v.eviction_high_watermark.to_string(),"evictionLowWatermarkBytes":v.eviction_low_watermark.to_string()}));
        let (remote,remote_error) = if state.config.is_fixture() { (None,Some("Durable storage diagnostics are unavailable in fixture mode.")) }
            else { match BudgetLedger::inspect_detailed(&state.spool) { Ok(v) => (Some(budget_value(v,&state.config)),None),Err(_) => (None,Some("Recorded remote allowance diagnostics are unavailable.")) } };
        let (capture,capture_error) = match &state.capture {
            Some(capture) => match (capture.usage(),capture.coverage_ready()) {
                (Ok(u),Ok(coverage)) => (Some(json!({"outboxEntries":u.entries.to_string(),"outboxBytes":u.bytes.to_string(),"coverageReady":coverage})),None),
                _ => (None,Some("Capture coverage or outbox diagnostics are unavailable.")),
            }, None => (None,None),
        };
        Ok(json!({"mode":if state.config.is_fixture(){"fixture"}else{"durable"},"sampledAt":now(),
            "local":{"installedBytes":usage.objects.installed.to_string(),"reservedBytes":usage.objects.reserved.to_string(),"managedCeilingBytes":usage.objects.ceiling.to_string(),
                "metadataInstalledBytes":usage.metadata_installed_bytes.to_string(),"metadataReservedBytes":usage.metadata_reserved_bytes.to_string(),
                "catalogBytes":usage.catalog_bytes.to_string(),"catalogReservedBytes":usage.catalog_reserved_bytes.to_string(),"managedBytes":usage.managed_bytes.to_string(),
                "filesystemAvailableBytes":usage.filesystem_available.to_string(),"residentEntries":usage.resident_entries.to_string(),"reservations":usage.reservations.to_string(),"admissionOpen":usage.admission_open,"limits":limits},
            "remote":remote,"remoteError":remote_error,"capture":capture,"captureError":capture_error,
            "circuitOpen":state.s3.as_ref().map(|s| s.circuit_open())}))
    }).await {
        Ok(Ok(value)) => Json(value).into_response(), Ok(Err(error)) => storage_error(error), Err(_) => unavailable(),
    }
}
pub(crate) fn config_projection(config: &Config) -> Value {
    let limits = &config.limits;
    let suites = config.suites().ok().map(|s| {
        s.into_iter()
            .map(|s| format!("{}/{}", s.key.repository(), s.key.suite()))
            .collect::<Vec<_>>()
    });
    // Project validated running values without touching credential paths.
    let remote = config.durable().map(|d| json!({"endpoint":d.provider.endpoint,"bucket":d.provider.bucket,
        "region":d.provider.region,"packagePrefix":d.provider.package_prefix,"checkpointPrefix":d.provider.checkpoint_prefix,
        "qualificationRunId":d.qualification_run_id}));
    let budget = config.durable().map(|d| json!({"storageBytes":d.budget.storage.to_string(),"storageControlReserveBytes":d.budget.storage_control.to_string(),
        "monthlyDownloadBytes":d.budget.monthly_download.to_string(),"downloadControlReserveBytes":d.budget.download_control.to_string()}));
    json!({"mode":if config.is_fixture(){"private-fixture"}else if config.is_durable_fixture(){"private-durable-fixture"}else if config.is_public(){"public-durable"}else{"private-durable"},
        "listen":{"public":config.listen.public.to_string(),"admin":config.listen.admin.to_string(),"publicHost":config.listen.public_host},
        "admin":{"origin":config.admin.origin,"managedConfigEnabled":config.admin.managed_config},
        "suites":suites,"provider":remote,"budget":budget,"credentials":"redacted","keyrings":"paths_and_contents_redacted","statePaths":"redacted",
        "limits":{"managedCeilingBytes":limits.managed_ceiling_bytes.to_string(),"maxObjectBytes":limits.max_object_bytes.to_string(),
            "concurrentFills":limits.concurrent_fills,"waitersPerObject":limits.waiters_per_object,"activeBodies":limits.active_bodies,"requestSlots":limits.request_slots,
            "readerBufferBytes":limits.reader_buffer_bytes.to_string(),"sourceAttempts":limits.source_attempts,"failureMapEntries":limits.failure_map_entries,
            "waiterTimeoutSeconds":limits.waiter_timeout.as_secs(),"producerDeadlineSeconds":limits.producer_deadline.as_secs(),
            "connectTimeoutSeconds":limits.connect_timeout.as_secs(),"responseHeaderTimeoutSeconds":limits.response_header_timeout.as_secs(),
            "readIdleTimeoutSeconds":limits.read_idle_timeout.as_secs(),"admissionWaitSeconds":limits.admission_wait.as_secs(),
            "failureBackoffSeconds":limits.failure_backoff.as_secs(),"syncIntervalSeconds":limits.sync_interval.as_secs(),
            "activeLeaseHours":limits.active_lease.as_secs()/3600,"bodyWriteIdleSeconds":limits.body_write_idle.as_secs(),"bodyLifetimeSeconds":limits.body_lifetime.as_secs()},
        "verifier":{"binary":"redacted","timeoutSeconds":config.verifier.timeout.as_secs()}})
}
pub async fn get_config(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    super::settings::get_config(State(state), headers).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    fn cursor_is_versioned_expiring_and_filter_bound() {
        let filter = InventoryFilter::default();
        let cursor =
            encode_cursor("debian", "pool/a", "", filter_hash(&filter).unwrap(), 100).unwrap();
        assert_eq!(
            decode_cursor(Some(&cursor), &filter, 101).unwrap(),
            Some(CursorAnchor::Inline("debian".into(), "pool/a".into()))
        );
        assert!(decode_cursor(Some(&cursor), &filter, 3700).is_err());
        let other = InventoryFilter {
            repository: Some("ubuntu".into()),
            ..filter.clone()
        };
        assert!(decode_cursor(Some(&cursor), &other, 101).is_err());
        assert!(decode_cursor(Some("abcdef"), &filter, 101).is_err());
        let bytes = decode_hex(&cursor, 128 * 1024).unwrap();
        let mut parsed: Cursor = serde_json::from_slice(&bytes).unwrap();
        parsed.v = 2;
        assert!(
            decode_cursor(
                Some(&encode_hex(&serde_json::to_vec(&parsed).unwrap())),
                &filter,
                101
            )
            .is_err()
        );
    }
    #[test]
    fn long_path_ids_remain_bounded_and_preserve_repository() {
        let path = format!("pool/{}", "a".repeat(8000));
        let path_hash = Sha256Digest::of(path.as_bytes()).to_hex();
        let id = package_id("debian", &path_hash);
        assert!(id.len() < 1024);
        assert_eq!(
            decode_package_id(&id),
            Some(("debian".into(), Sha256Digest::of(path.as_bytes()).to_hex()))
        );
        assert_ne!(id, package_id("ubuntu", &path_hash));
        assert!(decode_package_id("00").is_none());
        let filter = InventoryFilter::default();
        let cursor = encode_cursor(
            "debian",
            &path,
            &path_hash,
            filter_hash(&filter).unwrap(),
            100,
        )
        .unwrap();
        assert!(cursor.len() < 6 * 1024);
        assert_eq!(
            decode_cursor(Some(&cursor), &filter, 101).unwrap(),
            Some(CursorAnchor::Hashed(
                "debian".into(),
                Sha256Digest::of(path.as_bytes()).to_hex()
            ))
        );
    }
    #[tokio::test]
    async fn inventory_admission_bounds_and_cancelled_waiters() {
        let state = Arc::new(AdminInventoryState::new());
        let first = state.acquire().await.unwrap();
        let second = state.acquire().await.unwrap();
        assert_eq!(state.queries.available_permits(), 0);
        let mut waiters = Vec::new();
        for _ in 0..4 {
            let state = state.clone();
            waiters.push(tokio::spawn(async move { state.acquire().await }));
        }
        while state.waiters.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            state.acquire().await.unwrap_err().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        for waiter in waiters {
            waiter.abort();
            let _ = waiter.await;
        }
        assert_eq!(state.waiters.available_permits(), 4);
        drop((first, second));
        assert_eq!(state.queries.available_permits(), 2);
    }
    #[tokio::test]
    async fn dashboard_reads_without_s3_preserve_ledger_rows() {
        let _password_serial = super::super::password::TEST_LOCK.lock().await;
        let root = tempfile::tempdir().unwrap();
        let config = Config::parse(
            r#"
mode = "private-durable"
[listen]
public = "127.0.0.1:8080"
admin = "127.0.0.1:9090"
[durable]
state_dir = "state"
[durable.provider]
endpoint = "https://s3.example.org"
region = "us-east-1"
bucket = "ferrum"
package_prefix = "linux-packages/"
checkpoint_prefix = "linux-checkpoints/"
shared_nonisolated = true
credentials_file = "DO_NOT_READ_CREDENTIAL_CONTENTS.toml"
[durable.keyrings]
debian = "debian.gpg"
ubuntu = "ubuntu.gpg"
[durable.budget]
mode = "existing"
[verifier]
"#,
            root.path(),
        )
        .unwrap();
        let mut limits = ferrum_storage::DurableSpoolConfig::new(root.path().join("state"));
        const MIB: u64 = 1024 * 1024;
        limits.spool.managed_ceiling = 32 * MIB;
        limits.spool.max_object_size = 4 * MIB;
        limits.spool.io_workers = 2;
        limits.spool.read_chunk = 4096;
        limits.free_space_floor = 0;
        limits.temporary_ceiling = 4 * MIB;
        limits.metadata_temporary_reserve = MIB;
        limits.metadata_ceiling = 8 * MIB;
        limits.catalog_ceiling = 16 * MIB;
        limits.catalog_memory_budget = 32 * MIB;
        limits.max_entries = 128;
        limits.database_queue = 8;
        limits.eviction_high_watermark = 14 * MIB;
        limits.eviction_low_watermark = 12 * MIB;
        let spool = Spool::open_durable(limits).unwrap();
        let durable = config.durable().unwrap();
        let provider = durable.provider.provider_identity(None).unwrap();
        let _ledger =
            BudgetLedger::initialize_for_provider(spool.clone(), durable.budget, &provider)
                .unwrap();
        let identity = ferrum_apt::digest::ObjectIdentity {
            sha256: Sha256Digest::of(b"package"),
            size: 7,
        };
        let reservation = spool.reserve(7).unwrap();
        let mut writer = spool.begin_write(reservation, identity).await.unwrap();
        writer
            .write(bytes::Bytes::from_static(b"package"))
            .await
            .unwrap();
        drop(writer.commit().await.unwrap());
        let database = rusqlite::Connection::open(spool.root().join("state.sqlite")).unwrap();
        let digest = Sha256Digest::of(b"package").to_hex();
        database
            .execute(
                "INSERT INTO capture_proofs(generation,manifest,durable) VALUES('g',?1,1)",
                [r#"{"repository":"debian","suite":"trixie","generation_id":"g"}"#],
            )
            .unwrap();
        database.execute("INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,7,1,100,0)",[&digest]).unwrap();
        let long_path = format!("pool/{}", "a".repeat(8000));
        for path in [long_path.as_str(), "pool/z"] {
            database
                .execute(
                    "INSERT INTO capture_paths VALUES('debian',?1,?2,?3,'g',0,1,100)",
                    rusqlite::params![path, Sha256Digest::of(path.as_bytes()).to_hex(), digest],
                )
                .unwrap();
        }
        database
            .execute_batch(
                "UPDATE remote_budget SET period=1,high_time=2,used=11,data_used=7;
            INSERT INTO download_reservations VALUES('held',8,0,1);
            INSERT INTO readback_escrow VALUES('held','linux-packages/v1/objects/sha256/held');
            INSERT INTO remote_health(id,forbidden) VALUES(1,0) ON CONFLICT(id) DO NOTHING;",
            )
            .unwrap();
        fn rows(connection: &rusqlite::Connection) -> Vec<String> {
            [
                "SELECT json_array(period,high_time,used,data_used,certain) FROM remote_budget ORDER BY id",
                "SELECT json_array(id,amount,class,period) FROM download_reservations ORDER BY id",
                "SELECT json_array(id,key) FROM readback_escrow ORDER BY id",
                "SELECT json_array(total,data) FROM remote_storage_totals ORDER BY id",
                "SELECT json_array(forbidden) FROM remote_health ORDER BY id",
                "SELECT json_array(key,size,class,committed,mutation_intent,intent_at,gc_owned) FROM remote_storage ORDER BY key",
                "SELECT json_array(key) FROM remote_quarantine ORDER BY key",
                "SELECT json_array(key,upload_id,started,size,completing,uploaded_bytes,discovered) FROM multipart_uploads ORDER BY key",
                "SELECT json_array(endpoint,bucket,region,package_prefix,checkpoint_prefix) FROM remote_provider ORDER BY id",
            ].iter().flat_map(|sql| {
                connection.prepare(sql).unwrap().query_map([],|r| r.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap()
            }).collect()
        }
        let before = rows(&database);
        let store = Arc::new(super::super::AdminStore::open(&root.path().join("admin")).unwrap());
        let token = super::super::store::read_bootstrap_token(&root.path().join("admin")).unwrap();
        let grant = store
            .setup(
                token,
                "admin".into(),
                "Administrator".into(),
                "Correct horse battery staple".into(),
            )
            .await
            .unwrap();
        let jobs = Arc::new(super::super::jobs::JobRegistry::new((*store).clone()));
        let state = Arc::new(HealthState {
            catalog: Arc::new(crate::sync::Catalog::new()),
            metrics: Arc::new(crate::health::Metrics::default()),
            spool,
            capture: None,
            sync_trigger: None,
            admin: store,
            admin_http: Arc::new(
                super::super::AdminHttpState::new("http://127.0.0.1:9090").unwrap(),
            ),
            jobs,
            verifier_version: "inventory-test".into(),
            telemetry: Arc::new(super::super::telemetry::TelemetryHub::new()),
            config: Arc::new(config),
            publisher: None,
            s3: None,
            fills: None,
            request_slots: None,
            active_bodies: None,
        });
        // No provider transport exists; real catalog-backed handlers still work.
        assert!(state.s3.is_none());
        let inventory = Arc::new(AdminInventoryState::new());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("ferrum_admin_session={}", grant.token)
                .parse()
                .unwrap(),
        );
        async fn body(response: Response) -> Value {
            assert_eq!(response.status(), StatusCode::OK);
            serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
                    .await
                    .unwrap(),
            )
            .unwrap()
        }
        fn uri(qs: &str) -> Uri {
            format!("/api/admin/packages{qs}").parse().unwrap()
        }
        assert_eq!(
            get_packages(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone(),
                uri("?limit=invalid")
            )
            .await
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            get_packages(
                State(state.clone()),
                Extension(inventory.clone()),
                HeaderMap::new(),
                uri("")
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut machine = HeaderMap::new();
        machine.insert(
            axum::http::header::AUTHORIZATION,
            format!(
                "Bearer {}",
                super::super::store::read_control_token(&root.path().join("admin")).unwrap()
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(
            get_packages(
                State(state.clone()),
                Extension(inventory.clone()),
                machine,
                uri("")
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        for limit in [0, 101] {
            assert_eq!(
                get_packages(
                    State(state.clone()),
                    Extension(inventory.clone()),
                    headers.clone(),
                    uri(&format!("?limit={limit}"))
                )
                .await
                .status(),
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        let first = body(
            get_packages(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone(),
                uri("?limit=1"),
            )
            .await,
        )
        .await;
        assert_eq!(first["summary"]["blobs"], "1");
        assert_eq!(first["summary"]["blobBytes"], "7");
        assert_eq!(first["summary"]["verifiedBlobs"], "0");
        let cursor = first["nextCursor"].as_str().unwrap().to_owned();
        assert!(cursor.len() < 6 * 1024);
        let next = body(
            get_packages(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone(),
                uri(&format!("?limit=1&cursor={cursor}")),
            )
            .await,
        )
        .await;
        assert_eq!(next["items"][0]["path"], "pool/z");
        assert_eq!(next["hasMore"], false);
        let detail = body(
            get_package_detail(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone(),
                Path(package_id(
                    "debian",
                    &Sha256Digest::of(long_path.as_bytes()).to_hex(),
                )),
            )
            .await,
        )
        .await;
        assert_eq!(detail["package"]["path"], long_path);
        assert_eq!(detail["package"]["metadataStatus"], "path_only");
        let storage = body(
            get_storage(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone(),
            )
            .await,
        )
        .await;
        assert_eq!(storage["remote"]["period"], 1);
        assert_eq!(storage["remote"]["downloadBytes"], "11");
        assert_eq!(storage["remote"]["reservations"]["bytes"], "8");
        let configuration = body(get_config(State(state.clone()), headers.clone()).await).await;
        assert!(
            !configuration
                .to_string()
                .contains("DO_NOT_READ_CREDENTIAL_CONTENTS")
        );
        assert_eq!(configuration["runningRevision"].as_str().unwrap().len(), 64);
        let mirrors = body(
            get_mirrors(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone(),
            )
            .await,
        )
        .await;
        assert_eq!(mirrors["mirrors"].as_array().unwrap().len(), 106);
        assert_eq!(
            mirrors["mirrors"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m["configured"] == true)
                .count(),
            6
        );
        assert!(
            mirrors["mirrors"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m["configured"] == false)
                .all(|m| m["status"] == "candidate_unconfigured")
        );
        let detail = body(
            get_mirror_detail(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone(),
                Path(("debian".into(), "trixie".into())),
            )
            .await,
        )
        .await;
        assert_eq!(detail["mirror"]["configured"], true);
        assert_eq!(
            post_cache_preview(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone()
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        headers.insert("x-ferrum-csrf", grant.auth.csrf_token.parse().unwrap());
        let preview = body(
            post_cache_preview(
                State(state.clone()),
                Extension(inventory.clone()),
                headers.clone(),
            )
            .await,
        )
        .await;
        assert_eq!(preview["eligible"]["bytes"], "0");
        assert_eq!(preview["protected"]["staged"]["bytes"], "7");
        // A deleted long-path anchor requires a fresh query, never hash ordering.
        database
            .execute("DELETE FROM capture_paths WHERE path=?1", [&long_path])
            .unwrap();
        assert_eq!(
            get_packages(
                State(state),
                Extension(inventory),
                headers,
                uri(&format!("?cursor={cursor}"))
            )
            .await
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(rows(&database), before);
    }
    #[tokio::test]
    async fn cache_batches_preserve_live_readers_pins_and_metadata() {
        use ferrum_apt::digest::ObjectIdentity;
        use ferrum_storage::{PinKind, ReservationClass, SpoolConfig};
        let root = tempfile::tempdir().unwrap();
        let spool = Spool::open_exclusive_fixture(SpoolConfig {
            root: root.path().join("spool"),
            managed_ceiling: 1024 * 1024,
            max_object_size: 1024,
            io_workers: 2,
            read_chunk: 4096,
        })
        .unwrap();
        let mut reader = None;
        let mut pinned_identity = None;
        let mut metadata_identity = None;
        for index in 0u64..66 {
            let bytes = bytes::Bytes::copy_from_slice(&index.to_be_bytes());
            let identity = ObjectIdentity {
                sha256: Sha256Digest::of(&bytes),
                size: 8,
            };
            let class = if index == 65 {
                ReservationClass::Metadata
            } else {
                ReservationClass::Package
            };
            let reservation = spool.reserve_class(8, class).unwrap();
            let mut writer = spool.begin_write(reservation, identity).await.unwrap();
            writer.write(bytes).await.unwrap();
            let object = writer.commit().await.unwrap();
            if index == 0 {
                reader = Some(object);
            }
            if index == 1 {
                pinned_identity = Some(identity);
            }
            if index == 65 {
                metadata_identity = Some(identity);
            }
        }
        let pinned_identity = pinned_identity.unwrap();
        let pin = spool
            .pin(pinned_identity, PinKind::Upload)
            .unwrap()
            .unwrap();
        let preview = spool.preview_evictable_cache().unwrap();
        assert_eq!(
            (preview.eligible.objects, preview.eligible.bytes),
            (63, 504)
        );
        assert_eq!((preview.pinned.objects, preview.pinned.bytes), (1, 8));
        assert_eq!(
            (preview.live_reader.objects, preview.live_reader.bytes),
            (1, 8)
        );
        assert_eq!((preview.metadata.objects, preview.metadata.bytes), (1, 8));
        // More than 32 eligible objects exercises multiple bounded batches.
        assert_eq!(spool.clear_evictable_cache().unwrap(), (63, 504));
        assert!(spool.lookup(pinned_identity).is_some());
        assert!(spool.lookup(metadata_identity.unwrap()).is_some());
        drop((reader, pin));
        assert_eq!(spool.clear_evictable_cache().unwrap(), (2, 16));
        assert_eq!(spool.preview_evictable_cache().unwrap().metadata.bytes, 8);
    }
}
