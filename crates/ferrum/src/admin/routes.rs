use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{
    ConnectInfo, DefaultBodyLimit, Path, Request, State, rejection::JsonRejection,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::model::{AuthContext, Permission, SessionGrant, StoreError, UserView};
use super::overview::get_overview;
use crate::health::HealthState;

const SESSION_COOKIE: &str = "ferrum_admin_session";
const CSRF_HEADER: &str = "x-ferrum-csrf";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionState {
    setup_required: bool,
    user: Option<UserView>,
    csrf_token: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetupRequest {
    bootstrap_token: String,
    username: Option<String>,
    display_name: Option<String>,
    password: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountRequest {
    username: Option<String>,
    display_name: Option<String>,
    current_password: Option<String>,
    new_password: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasswordRequest {
    current_password: String,
    new_password: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateUserRequest {
    username: String,
    display_name: Option<String>,
    password: String,
    permissions: Vec<Permission>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateUserRequest {
    display_name: Option<String>,
    password: Option<String>,
    permissions: Vec<Permission>,
    disabled: Option<bool>,
}

pub fn routes() -> Router<Arc<HealthState>> {
    let auth = Router::new()
        .route("/api/admin/setup", post(post_setup))
        .route("/api/admin/login", post(post_login))
        .layer(DefaultBodyLimit::max(8 * 1024));
    Router::new()
        .merge(auth)
        .route("/api/admin/session", get(get_session))
        .route("/api/admin/logout", post(post_logout))
        .route("/api/admin/overview", get(get_overview))
        .route("/api/admin/events", get(super::telemetry::get_events))
        .route(
            "/api/admin/metrics/history",
            get(super::telemetry::get_metrics_history),
        )
        .route("/api/admin/alerts", get(super::telemetry::get_alerts))
        .route(
            "/api/admin/alerts/{id}/acknowledge",
            post(super::telemetry::post_acknowledge_alert),
        )
        .route("/api/admin/activity", get(super::telemetry::get_activity))
        .route("/api/admin/mirrors", get(super::inventory::get_mirrors))
        .route(
            "/api/admin/mirrors/{repository}/{suite}",
            get(super::inventory::get_mirror_detail),
        )
        .route("/api/admin/packages", get(super::inventory::get_packages))
        .route(
            "/api/admin/packages/{id}",
            get(super::inventory::get_package_detail),
        )
        .route("/api/admin/storage", get(super::inventory::get_storage))
        .route(
            "/api/admin/cache/preview",
            post(super::inventory::post_cache_preview),
        )
        .route(
            "/api/admin/cache/clear",
            post(super::jobs::post_clear_cache),
        )
        .route("/api/admin/config", get(super::settings::get_config))
        .route(
            "/api/admin/config/preview",
            post(super::settings::post_config_preview),
        )
        .route(
            "/api/admin/config/proposals",
            post(super::settings::post_config_proposal),
        )
        .route(
            "/api/admin/config/proposals/{id}/save",
            post(super::settings::post_config_save),
        )
        .route("/api/admin/sync", post(super::jobs::post_sync))
        .route("/api/admin/jobs", get(super::jobs::get_jobs))
        .route("/api/admin/jobs/{id}", get(super::jobs::get_job_detail))
        .route(
            "/api/admin/jobs/{id}/cancel",
            post(super::jobs::post_cancel_job),
        )
        .route(
            "/api/admin/workspaces",
            get(super::workspaces::get_workspaces).post(super::workspaces::post_workspace),
        )
        .route(
            "/api/admin/workspaces/{id}",
            get(super::workspaces::get_workspace_detail)
                .put(super::workspaces::put_workspace)
                .delete(super::workspaces::delete_workspace),
        )
        .route("/api/admin/account", put(put_account))
        .route("/api/admin/account/password", put(put_password))
        .route("/api/admin/users", get(get_users).post(post_user))
        .route("/api/admin/users/{id}", put(put_user).delete(delete_user))
        .route("/api/admin/sessions", get(get_sessions))
        .route("/api/admin/sessions/{id}", delete(delete_session))
        .route("/api/admin/users/{id}/sessions", get(get_user_sessions))
        .route(
            "/api/admin/users/{id}/sessions/{session_id}",
            delete(delete_user_session),
        )
        .layer(axum::Extension(Arc::new(
            super::inventory::AdminInventoryState::new(),
        )))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .fallback(get(serve_ui))
}

/// Apply to the whole admin listener so failures and static assets receive security headers too.
pub async fn security_boundary(
    State(state): State<Arc<HealthState>>,
    request: Request,
    next: Next,
) -> Response {
    let probe = matches!(request.uri().path(), "/healthz" | "/livez" | "/readyz")
        || request.uri().path().starts_with("/readyz/");
    let response = if !probe && !state.admin_http.valid_host(request.headers()) {
        error_reply(
            StatusCode::FORBIDDEN,
            "invalid_host",
            "Invalid administration host.",
        )
    } else if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) && !(request.uri().path() == "/api/admin/sync"
        && bearer_token(request.headers()).is_some())
        && !state.admin_http.valid_origin(request.headers())
    {
        error_reply(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "Exact administration Origin required.",
        )
    } else {
        next.run(request).await
    };
    security_headers(&state, response)
}
fn security_headers(state: &HealthState, mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Ok(csp) = HeaderValue::from_str(&state.admin_http.assets.csp) {
        headers.insert(header::CONTENT_SECURITY_POLICY, csp);
    }
    response
}
pub(super) fn error_reply(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({"code": code, "error": message})),
    )
        .into_response();
    if status == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("12"));
    }
    response
}
pub(super) fn store_error(error: StoreError) -> Response {
    match error {
        StoreError::Unauthorized => error_reply(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication failed or session expired.",
        ),
        StoreError::Forbidden => error_reply(
            StatusCode::FORBIDDEN,
            "forbidden",
            "This action is not permitted.",
        ),
        StoreError::Conflict => error_reply(
            StatusCode::CONFLICT,
            "conflict",
            "The change conflicts with current administration state.",
        ),
        StoreError::Invalid => error_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_value",
            "Invalid administration values.",
        ),
        StoreError::Busy => error_reply(
            StatusCode::TOO_MANY_REQUESTS,
            "busy",
            "Administration capacity is temporarily full.",
        ),
        StoreError::Unavailable => error_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Administration state is unavailable.",
        ),
    }
}
fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, Response> {
    payload.map(|Json(value)| value).map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            error_reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Request body exceeds its limit.",
            )
        } else {
            error_reply(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_json",
                "Invalid request body.",
            )
        }
    })
}
fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let mut token = None;
    for cookie in headers.get_all(header::COOKIE) {
        for part in cookie.to_str().ok()?.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == SESSION_COOKIE {
                if token.is_some()
                    || value.len() != 64
                    || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return None;
                }
                token = Some(value.to_owned());
            }
        }
    }
    token
}
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let token = values.next()?.to_str().ok()?.strip_prefix("Bearer ")?;
    if values.next().is_some()
        || token.len() != 64
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(token.to_owned())
}
fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0, |difference, (a, b)| difference | (a ^ b))
        == 0
}
pub(crate) async fn authenticate(
    state: &HealthState,
    headers: &HeaderMap,
    mutation: bool,
    permission: Option<Permission>,
) -> Result<AuthContext, Response> {
    let auth = if headers.contains_key(header::AUTHORIZATION) {
        let token = bearer_token(headers).ok_or_else(|| store_error(StoreError::Unauthorized))?;
        let auth = state
            .admin
            .authenticate_control(token)
            .await
            .map_err(store_error)?;
        if !matches!(
            permission,
            Some(Permission::ViewStatus | Permission::TriggerSync)
        ) {
            return Err(store_error(StoreError::Forbidden));
        }
        auth
    } else {
        let token = cookie_token(headers).ok_or_else(|| store_error(StoreError::Unauthorized))?;
        let auth = state.admin.authenticate(token).await.map_err(store_error)?;
        if mutation {
            let mut csrf = headers.get_all(CSRF_HEADER).iter();
            let provided = csrf
                .next()
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if csrf.next().is_some() || !constant_time_eq(provided, &auth.csrf_token) {
                return Err(error_reply(
                    StatusCode::FORBIDDEN,
                    "csrf",
                    "Invalid CSRF token.",
                ));
            }
        }
        auth
    };
    if permission.is_some_and(|permission| !auth.user.permissions.contains(&permission)) {
        return Err(store_error(StoreError::Forbidden));
    }
    Ok(auth)
}
fn set_cookie(state: &HealthState, response: &mut Response, token: &str, max_age: u32) {
    let secure = if state.admin_http.secure {
        "; Secure"
    } else {
        ""
    };
    let value = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}
fn session_response(state: &HealthState, grant: SessionGrant) -> Response {
    let mut response = Json(SessionState {
        setup_required: false,
        user: Some(grant.auth.user),
        csrf_token: Some(grant.auth.csrf_token),
    })
    .into_response();
    set_cookie(state, &mut response, &grant.token, 8 * 60 * 60);
    response
}
type Peer = Result<ConnectInfo<SocketAddr>, axum::extract::rejection::ExtensionRejection>;
fn admit_login(state: &HealthState, peer: Peer, username: &str) -> Result<(), Response> {
    if username.len() > 64 {
        return Err(store_error(StoreError::Invalid));
    }
    let Ok(ConnectInfo(source)) = peer else {
        return Err(error_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "peer_unavailable",
            "Authentication source unavailable.",
        ));
    };
    if !state
        .admin_http
        .admit_login(source.ip(), &username.trim().to_ascii_lowercase())
    {
        return Err(error_reply(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Authentication rate limit reached.",
        ));
    }
    Ok(())
}
async fn get_session(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    let setup_required = match state.admin.setup_required().await {
        Ok(value) => value,
        Err(error) => return store_error(error),
    };
    let mut response = SessionState {
        setup_required,
        user: None,
        csrf_token: None,
    };
    if let Some(token) = cookie_token(&headers) {
        match state.admin.authenticate(token).await {
            Ok(auth) => {
                response.user = Some(auth.user);
                response.csrf_token = Some(auth.csrf_token);
            }
            Err(StoreError::Unauthorized) => {}
            Err(error) => return store_error(error),
        }
    }
    Json(response).into_response()
}
async fn post_setup(
    State(state): State<Arc<HealthState>>,
    peer: Peer,
    payload: Result<Json<SetupRequest>, JsonRejection>,
) -> Response {
    let payload = match json_payload(payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let username = payload.username.unwrap_or_else(|| "admin".into());
    if let Err(response) = admit_login(&state, peer, &username) {
        return response;
    }
    let display_name = payload
        .display_name
        .unwrap_or_else(|| "Administrator".into());
    match state
        .admin
        .setup(
            payload.bootstrap_token,
            username,
            display_name,
            payload.password,
        )
        .await
    {
        Ok(grant) => session_response(&state, grant),
        Err(error) => store_error(error),
    }
}
async fn post_login(
    State(state): State<Arc<HealthState>>,
    peer: Peer,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Response {
    let payload = match json_payload(payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(response) = admit_login(&state, peer, &payload.username) {
        return response;
    }
    match state.admin.login(payload.username, payload.password).await {
        Ok(grant) => session_response(&state, grant),
        Err(error) => store_error(error),
    }
}
async fn post_logout(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    let auth = match authenticate(&state, &headers, true, None).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    match state.admin.logout(auth).await {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            set_cookie(&state, &mut response, "", 0);
            response
        }
        Err(error) => store_error(error),
    }
}
async fn put_account(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    payload: Result<Json<AccountRequest>, JsonRejection>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, None).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let payload = match json_payload(payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match state
        .admin
        .update_account(
            auth,
            payload.username,
            payload.display_name,
            payload.current_password,
            payload.new_password,
        )
        .await
    {
        Ok(user) => {
            let mut response = Json(serde_json::json!({"user": user})).into_response();
            set_cookie(&state, &mut response, "", 0);
            response
        }
        Err(error) => store_error(error),
    }
}
async fn put_password(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    payload: Result<Json<PasswordRequest>, JsonRejection>,
) -> Response {
    let payload = match json_payload(payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    put_account(
        State(state),
        headers,
        Ok(Json(AccountRequest {
            username: None,
            display_name: None,
            current_password: Some(payload.current_password),
            new_password: Some(payload.new_password),
        })),
    )
    .await
}
async fn get_users(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ManageUsers)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    match state.admin.list_users(auth).await {
        Ok(users) => Json(serde_json::json!({"users": users})).into_response(),
        Err(error) => store_error(error),
    }
}
async fn post_user(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    payload: Result<Json<CreateUserRequest>, JsonRejection>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ManageUsers)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let payload = match json_payload(payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let display_name = payload
        .display_name
        .unwrap_or_else(|| payload.username.clone());
    match state
        .admin
        .create_user(
            auth,
            payload.username,
            display_name,
            payload.password,
            payload.permissions,
        )
        .await
    {
        Ok(user) => (StatusCode::CREATED, Json(serde_json::json!({"user": user}))).into_response(),
        Err(error) => store_error(error),
    }
}
async fn put_user(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ManageUsers)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let payload = match json_payload(payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match state
        .admin
        .update_user(
            auth,
            id,
            payload.display_name,
            payload.password,
            payload.permissions,
            payload.disabled,
        )
        .await
    {
        Ok(user) => Json(serde_json::json!({"user": user})).into_response(),
        Err(error) => store_error(error),
    }
}
async fn delete_user(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ManageUsers)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    match state.admin.delete_user(auth, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => store_error(error),
    }
}
async fn get_sessions(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    let auth = match authenticate(&state, &headers, false, None).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    match state.admin.list_sessions(auth, None).await {
        Ok(sessions) => Json(serde_json::json!({"sessions": sessions})).into_response(),
        Err(error) => store_error(error),
    }
}
async fn get_user_sessions(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ManageUsers)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    match state.admin.list_sessions(auth, Some(id)).await {
        Ok(sessions) => Json(serde_json::json!({"sessions": sessions})).into_response(),
        Err(error) => store_error(error),
    }
}
async fn delete_session(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, None).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    match state.admin.revoke_session(auth, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => store_error(error),
    }
}
async fn delete_user_session(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path((id, session_id)): Path<(String, String)>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ManageUsers)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    match state.admin.list_sessions(auth.clone(), Some(id)).await {
        Ok(sessions) if sessions.iter().any(|session| session.id == session_id) => {}
        Ok(_) => return error_reply(StatusCode::NOT_FOUND, "not_found", "Session not found."),
        Err(error) => return store_error(error),
    }
    match state.admin.revoke_session(auth, session_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => store_error(error),
    }
}
async fn serve_ui(State(state): State<Arc<HealthState>>, uri: Uri) -> Response {
    state.admin_http.assets.serve(uri.path())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn ambiguous_credentials_are_not_accepted() {
        let token = "a".repeat(64);
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{SESSION_COOKIE}={token}; {SESSION_COOKIE}={token}"
            ))
            .unwrap(),
        );
        assert!(cookie_token(&headers).is_none());
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        assert!(bearer_token(&headers).is_none());
    }
    #[test]
    fn csrf_requires_exact_token() {
        assert!(constant_time_eq("same", "same"));
        assert!(!constant_time_eq("same", "samb"));
        assert!(!constant_time_eq("same", "same-longer"));
    }
}
