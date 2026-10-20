//! Bounded, schema-validated personal preferences. No workspace can contain code
//! or authorize a query; page endpoints remain the permission boundary.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    AdminStore,
    model::{AuthContext, Permission, StoreError},
    password,
    routes::{authenticate, error_reply, store_error},
    store::{actor, audit},
};
use crate::{config::ALL_DISTRIBUTION_SUITES, health::HealthState};

const MAX_BODY: usize = 64 * 1024;
pub const WIDGET_IDS: [&str; 12] = [
    "readiness_overview",
    "traffic_rates",
    "latency_quantiles",
    "cache_sources",
    "storage_headroom",
    "s3_allowance",
    "active_jobs",
    "pinned_mirrors",
    "recent_alerts",
    "admission_pressure",
    "outbox_status",
    "process_resources",
];
const PAGES: [&str; 8] = [
    "overview", "mirrors", "packages", "storage", "activity", "settings", "account", "users",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceWidget {
    pub id: String,
    pub col_span: u8,
    pub row_span: u8,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedMirror {
    pub repository: String,
    pub suite: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSort {
    pub field: String,
    pub direction: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspacePreferences {
    pub name: String,
    pub schema_version: u32,
    pub default_page: String,
    pub widgets: Vec<WorkspaceWidget>,
    #[serde(default)]
    pub pinned_mirrors: Vec<PinnedMirror>,
    #[serde(default)]
    pub columns: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub filters: BTreeMap<String, BTreeMap<String, Value>>,
    #[serde(default)]
    pub sorts: BTreeMap<String, WorkspaceSort>,
    pub time_range: String,
    pub refresh_mode: String,
    #[serde(default)]
    pub is_default: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceView {
    pub id: String,
    pub revision: i64,
    #[serde(flatten)]
    pub preferences: WorkspacePreferences,
}
/// The JSON extractor accepts Value to enforce the serialized bound before
/// decoding the strict preference schema (flatten + deny_unknown_fields conflict).
pub type WorkspacePayload = Result<Json<Value>, JsonRejection>;

fn safe_text(value: &str, max: usize) -> bool {
    value.len() <= max
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>'))
}
fn columns_for(page: &str) -> &'static [&'static str] {
    match page {
        "mirrors" => &[
            "repository",
            "suite",
            "ecosystem",
            "status",
            "ready",
            "configured",
            "origin",
            "generation",
            "lease",
            "lastObservation",
            "lastConfirmation",
            "phase",
        ],
        "packages" => &[
            "path",
            "repository",
            "digest",
            "size",
            "suite",
            "cacheStatus",
            "remoteStatus",
            "generation",
            "retainUntil",
        ],
        "activity" => &[
            "id",
            "kind",
            "state",
            "actor",
            "createdAt",
            "updatedAt",
            "action",
            "target",
            "outcome",
            "reason",
        ],
        _ => &[],
    }
}
fn valid_filters(page: &str, filters: &BTreeMap<String, Value>) -> bool {
    if filters.len() > 12 {
        return false;
    }
    filters.iter().all(|(key, value)| {
        let allowed: &[&str] = match page {
            "mirrors" => &[
                "repository",
                "suite",
                "ecosystem",
                "readiness",
                "errorsOnly",
                "favoritesOnly",
                "configuredOnly",
                "search",
            ],
            "packages" => &[
                "repository",
                "suite",
                "digestPrefix",
                "pathPrefix",
                "cacheStatus",
                "remoteStatus",
            ],
            "activity" => &["kind", "state", "action", "actor", "target", "outcome"],
            _ => &[],
        };
        if !allowed.contains(&key.as_str()) {
            return false;
        }
        if matches!(
            key.as_str(),
            "errorsOnly" | "favoritesOnly" | "configuredOnly"
        ) {
            return value.is_boolean();
        }
        let Some(text) = value.as_str() else {
            return false;
        };
        if !safe_text(text, 512) {
            return false;
        }
        match key.as_str() {
            "ecosystem" => ["", "apt", "pacman", "rpm"].contains(&text),
            "readiness" => ["", "ready", "not_ready", "candidate_unconfigured"].contains(&text),
            "cacheStatus" => [
                "",
                "resident_pinned",
                "resident_cached",
                "resident_staged",
                "evicting",
                "remote_only",
            ]
            .contains(&text),
            "remoteStatus" => [
                "",
                "quarantined",
                "gc_pending",
                "admitted_filling",
                "outbox_uploading",
                "outbox_backoff",
                "outbox_queued",
                "verified_durable",
                "pending_verification",
                "recorded_unverified",
            ]
            .contains(&text),
            "digestPrefix" => text.len() <= 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
            "kind" => ["", "sync", "cache_clear"].contains(&text),
            "state" => [
                "",
                "queued",
                "running",
                "succeeded",
                "partial",
                "failed",
                "cancelled",
                "interrupted",
            ]
            .contains(&text),
            _ => true,
        }
    })
}
fn validate(preferences: &WorkspacePreferences) -> Result<(), StoreError> {
    if preferences.schema_version != 1
        || preferences.name.trim().is_empty()
        || !safe_text(&preferences.name, 128)
        || !PAGES.contains(&preferences.default_page.as_str())
        || !["live", "5s", "15s", "30s", "60s", "manual"]
            .contains(&preferences.refresh_mode.as_str())
        || !["15m", "1h", "24h", "7d"].contains(&preferences.time_range.as_str())
        || preferences.widgets.len() > 12
        || preferences.pinned_mirrors.len() > 128
        || preferences.columns.len() > 3
        || preferences.filters.len() > 3
        || preferences.sorts.len() > 3
    {
        return Err(StoreError::Invalid);
    }
    let mut seen = BTreeSet::new();
    for widget in &preferences.widgets {
        if !WIDGET_IDS.contains(&widget.id.as_str())
            || !seen.insert(&widget.id)
            || !(1..=12).contains(&widget.col_span)
            || !(1..=4).contains(&widget.row_span)
        {
            return Err(StoreError::Invalid);
        }
    }
    let mut pinned = BTreeSet::new();
    for mirror in &preferences.pinned_mirrors {
        let known = (mirror.repository == "fixture" && mirror.suite == "ferrum-test")
            || ALL_DISTRIBUTION_SUITES
                .iter()
                .any(|s| s.repository.name() == mirror.repository && s.suite == mirror.suite);
        if !known || !pinned.insert((&mirror.repository, &mirror.suite)) {
            return Err(StoreError::Invalid);
        }
    }
    for (page, columns) in &preferences.columns {
        let allowed = columns_for(page);
        let mut seen = BTreeSet::new();
        if allowed.is_empty()
            || columns.len() > allowed.len()
            || columns
                .iter()
                .any(|column| !allowed.contains(&column.as_str()) || !seen.insert(column))
        {
            return Err(StoreError::Invalid);
        }
    }
    if preferences.filters.iter().any(|(page, filters)| {
        !["mirrors", "packages", "activity"].contains(&page.as_str())
            || !valid_filters(page, filters)
    }) || preferences.sorts.iter().any(|(page, sort)| {
        !columns_for(page).contains(&sort.field.as_str())
            || !["asc", "desc"].contains(&sort.direction.as_str())
    }) {
        return Err(StoreError::Invalid);
    }
    if serde_json::to_vec(preferences)
        .map_err(|_| StoreError::Invalid)?
        .len()
        > MAX_BODY
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn human(auth: &AuthContext) -> Result<(), StoreError> {
    if auth.machine {
        Err(StoreError::Forbidden)
    } else {
        Ok(())
    }
}
fn load(
    connection: &Connection,
    user_id: &str,
    id: &str,
) -> Result<Option<WorkspaceView>, StoreError> {
    let row: Option<(String, i64, String, bool)> = connection
        .query_row(
            "SELECT id,revision,body,is_default FROM workspaces WHERE user_id=?1 AND id=?2",
            params![user_id, id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(id, revision, body, is_default)| {
        let mut preferences: WorkspacePreferences =
            serde_json::from_str(&body).map_err(|_| StoreError::Unavailable)?;
        validate(&preferences).map_err(|_| StoreError::Unavailable)?;
        preferences.is_default = is_default;
        Ok(WorkspaceView {
            id,
            revision,
            preferences,
        })
    })
    .transpose()
}
async fn list(admin: &AdminStore, auth: AuthContext) -> Result<Vec<WorkspaceView>, StoreError> {
    human(&auth)?;
    admin
        .read(move |connection| {
            let user = actor(connection, &auth, Some(Permission::ViewStatus))?;
            let mut statement = connection.prepare(
                "SELECT id FROM workspaces WHERE user_id=?1 ORDER BY is_default DESC,id LIMIT 16",
            )?;
            let ids = statement
                .query_map([&user.id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids.into_iter()
                .map(|id| load(connection, &user.id, &id)?.ok_or(StoreError::Unavailable))
                .collect()
        })
        .await
}
async fn create(
    admin: &AdminStore,
    auth: AuthContext,
    preferences: WorkspacePreferences,
) -> Result<WorkspaceView, StoreError> {
    human(&auth)?;
    validate(&preferences)?;
    let body = serde_json::to_string(&preferences).map_err(|_| StoreError::Invalid)?;
    admin.write(move |tx| {
        let user = actor(tx, &auth, Some(Permission::ViewStatus))?;
        let count: i64 = tx.query_row("SELECT count(*) FROM workspaces WHERE user_id=?1", [&user.id], |row| row.get(0))?;
        if count >= 16 { return Err(StoreError::Busy); }
        if preferences.is_default { tx.execute("UPDATE workspaces SET is_default=0,revision=revision+1 WHERE user_id=?1 AND is_default=1", [&user.id])?; }
        let id = password::random_token();
        tx.execute("INSERT INTO workspaces(id,user_id,name,schema_version,revision,body,is_default) VALUES(?1,?2,?3,1,1,?4,?5)", params![id,user.id,preferences.name,body,preferences.is_default])?;
        audit(tx, &user.id, "workspace.create", &id, "success", "")?;
        Ok(WorkspaceView { id, revision: 1, preferences })
    }).await
}
async fn detail(
    admin: &AdminStore,
    auth: AuthContext,
    id: String,
) -> Result<Option<WorkspaceView>, StoreError> {
    human(&auth)?;
    admin
        .read(move |connection| {
            let user = actor(connection, &auth, Some(Permission::ViewStatus))?;
            load(connection, &user.id, &id)
        })
        .await
}
async fn update(
    admin: &AdminStore,
    auth: AuthContext,
    id: String,
    expected: i64,
    preferences: WorkspacePreferences,
) -> Result<Option<WorkspaceView>, StoreError> {
    human(&auth)?;
    validate(&preferences)?;
    if expected < 1 || expected == i64::MAX {
        return Err(StoreError::Invalid);
    }
    let body = serde_json::to_string(&preferences).map_err(|_| StoreError::Invalid)?;
    admin.write(move |tx| {
        let user = actor(tx, &auth, Some(Permission::ViewStatus))?;
        let Some(current) = load(tx, &user.id, &id)? else { return Ok(None); };
        if current.revision != expected { return Err(StoreError::Conflict); }
        if preferences.is_default { tx.execute("UPDATE workspaces SET is_default=0,revision=revision+1 WHERE user_id=?1 AND id<>?2 AND is_default=1", params![user.id,id])?; }
        let changed = tx.execute("UPDATE workspaces SET name=?1,schema_version=1,revision=revision+1,body=?2,is_default=?3 WHERE user_id=?4 AND id=?5 AND revision=?6", params![preferences.name,body,preferences.is_default,user.id,id,expected])?;
        if changed != 1 { return Err(StoreError::Conflict); }
        audit(tx, &user.id, "workspace.update", &id, "success", "")?;
        Ok(Some(WorkspaceView { id, revision: expected + 1, preferences }))
    }).await
}
async fn remove(admin: &AdminStore, auth: AuthContext, id: String) -> Result<bool, StoreError> {
    human(&auth)?;
    admin
        .write(move |tx| {
            let user = actor(tx, &auth, Some(Permission::ViewStatus))?;
            let deleted = tx.execute(
                "DELETE FROM workspaces WHERE user_id=?1 AND id=?2",
                params![user.id, id],
            )?;
            if deleted != 0 {
                audit(tx, &user.id, "workspace.delete", &id, "success", "")?;
            }
            Ok(deleted != 0)
        })
        .await
}
fn decode(
    payload: WorkspacePayload,
    updating: bool,
) -> Result<(WorkspacePreferences, Option<i64>), Response> {
    let Json(mut value) = payload.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            error_reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Workspace exceeds 64 KiB.",
            )
        } else {
            invalid()
        }
    })?;
    if serde_json::to_vec(&value).map_err(|_| invalid())?.len() > MAX_BODY {
        return Err(error_reply(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "Workspace exceeds 64 KiB.",
        ));
    }
    let expected = if updating {
        Some(
            value
                .as_object_mut()
                .and_then(|object| object.remove("expectedRevision"))
                .and_then(|v| v.as_i64())
                .ok_or_else(invalid)?,
        )
    } else {
        None
    };
    let preferences = serde_json::from_value(value).map_err(|_| invalid())?;
    validate(&preferences).map_err(|_| invalid())?;
    Ok((preferences, expected))
}
fn invalid() -> Response {
    error_reply(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_workspace",
        "Workspace schema, preferences, or widget layout is invalid.",
    )
}
fn not_found() -> Response {
    error_reply(StatusCode::NOT_FOUND, "not_found", "Workspace not found.")
}
fn workspace_response(result: Result<Option<WorkspaceView>, StoreError>) -> Response {
    match result {
        Ok(Some(workspace)) => Json(json!({"workspace":workspace})).into_response(),
        Ok(None) => not_found(),
        Err(error) => store_error(error),
    }
}
pub async fn get_workspaces(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match list(&state.admin, auth).await {
        Ok(workspaces) => {
            Json(json!({"workspaces":workspaces,"availableWidgets":WIDGET_IDS})).into_response()
        }
        Err(error) => store_error(error),
    }
}
pub async fn post_workspace(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    payload: WorkspacePayload,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ViewStatus)).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let (preferences, _) = match decode(payload, false) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match create(&state.admin, auth, preferences).await {
        Ok(workspace) => {
            (StatusCode::CREATED, Json(json!({"workspace":workspace}))).into_response()
        }
        Err(error) => store_error(error),
    }
}
pub async fn get_workspace_detail(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    workspace_response(detail(&state.admin, auth, id).await)
}
pub async fn put_workspace(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: WorkspacePayload,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ViewStatus)).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let (preferences, expected) = match decode(payload, true) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(expected) = expected else {
        return invalid();
    };
    workspace_response(update(&state.admin, auth, id, expected, preferences).await)
}
pub async fn delete_workspace(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ViewStatus)).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match remove(&state.admin, auth, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(),
        Err(error) => store_error(error),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    fn preferences() -> WorkspacePreferences {
        serde_json::from_value(json!({"name":"Operations","schemaVersion":1,"defaultPage":"overview","widgets":[{"id":"traffic_rates","colSpan":6,"rowSpan":1}],"timeRange":"1h","refreshMode":"live"})).unwrap()
    }
    #[test]
    fn widget_and_preference_allowlists_reject_executable_or_unbounded_layouts() {
        assert!(validate(&preferences()).is_ok());
        for id in ["<script>alert(1)</script>", "custom_sql", "unknown"] {
            let mut workspace = preferences();
            workspace.widgets[0].id = id.into();
            assert_eq!(validate(&workspace), Err(StoreError::Invalid));
        }
        let mut workspace = preferences();
        workspace.widgets[0].col_span = 13;
        assert!(validate(&workspace).is_err());
        workspace = preferences();
        workspace.widgets[0].row_span = 0;
        assert!(validate(&workspace).is_err());
        workspace = preferences();
        workspace.widgets = vec![workspace.widgets[0].clone(); 13];
        assert!(validate(&workspace).is_err());
        workspace = preferences();
        workspace.filters.insert(
            "packages".into(),
            BTreeMap::from([("sql".into(), json!("SELECT *"))]),
        );
        assert!(validate(&workspace).is_err());
        workspace = preferences();
        workspace.refresh_mode = "1ms".into();
        assert!(validate(&workspace).is_err());
        let mut body = serde_json::to_value(preferences()).unwrap();
        body["html"] = json!("<b>unsafe</b>");
        assert!(decode(Ok(Json(body)), false).is_err());
    }
    #[tokio::test]
    async fn two_users_cannot_read_or_mutate_each_others_workspaces_and_cas_is_atomic() {
        let _serial = password::TEST_LOCK.lock().await;
        let root = tempfile::tempdir().unwrap();
        let admin_root = root.path().join("admin");
        let admin = AdminStore::open(&admin_root).unwrap();
        let owner = admin
            .setup(
                super::super::store::read_bootstrap_token(&admin_root).unwrap(),
                "owner".into(),
                "Owner".into(),
                "a strong owner password".into(),
            )
            .await
            .unwrap();
        admin
            .create_user(
                owner.auth.clone(),
                "viewer".into(),
                "Viewer".into(),
                "a strong viewer password".into(),
                vec![Permission::ViewStatus],
            )
            .await
            .unwrap();
        let viewer = admin
            .login("viewer".into(), "a strong viewer password".into())
            .await
            .unwrap();
        let mut prefs = preferences();
        prefs.is_default = true;
        let first = create(&admin, owner.auth.clone(), prefs.clone())
            .await
            .unwrap();
        assert!(list(&admin, viewer.auth.clone()).await.unwrap().is_empty());
        assert!(
            detail(&admin, viewer.auth.clone(), first.id.clone())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            update(
                &admin,
                viewer.auth.clone(),
                first.id.clone(),
                1,
                prefs.clone()
            )
            .await
            .unwrap()
            .is_none()
        );
        assert!(
            !remove(&admin, viewer.auth.clone(), first.id.clone())
                .await
                .unwrap()
        );
        let updated = update(
            &admin,
            owner.auth.clone(),
            first.id.clone(),
            1,
            prefs.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(updated.revision, 2);
        assert!(matches!(
            update(
                &admin,
                owner.auth.clone(),
                first.id.clone(),
                1,
                prefs.clone()
            )
            .await,
            Err(StoreError::Conflict)
        ));
        let second = create(&admin, owner.auth.clone(), prefs.clone())
            .await
            .unwrap();
        assert!(second.preferences.is_default);
        assert!(
            !detail(&admin, owner.auth.clone(), first.id.clone())
                .await
                .unwrap()
                .unwrap()
                .preferences
                .is_default
        );
        for _ in 2..16 {
            create(&admin, owner.auth.clone(), prefs.clone())
                .await
                .unwrap();
        }
        assert!(matches!(
            create(&admin, owner.auth.clone(), prefs.clone()).await,
            Err(StoreError::Busy)
        ));
        assert!(remove(&admin, owner.auth.clone(), first.id).await.unwrap());
        assert!(list(&admin, viewer.auth).await.unwrap().is_empty());
    }
}
