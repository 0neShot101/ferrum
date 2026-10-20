//! Consumer-visible HTTP boundary tests; no provider or network dependency.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_arguments)]
use super::{AdminHttpState, AdminStore};
use crate::health::{HealthState, Metrics};
use crate::sync::Catalog;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use ferrum_storage::{Spool, SpoolConfig};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:8081";
const ORIGIN: &str = "http://127.0.0.1:8081";
struct Fixture {
    state: Arc<HealthState>,
    root: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("fixture root");
        let spool = Spool::open_exclusive_fixture(SpoolConfig {
            root: root.path().join("spool"),
            managed_ceiling: 16 * 1024 * 1024,
            max_object_size: 1024 * 1024,
            io_workers: 2,
            read_chunk: 4096,
        })
        .expect("fixture spool");
        let config_text = format!(
            "mode = \"private-fixture\"\n[listen]\npublic = \"127.0.0.1:0\"\nadmin = \"127.0.0.1:0\"\n[fixture]\nkeyring = \"{}\"\nwork_dir = \"{}\"\n[verifier]\n",
            root.path().join("unused.gpg").display(),
            root.path().display(),
        );
        let config =
            Arc::new(crate::config::Config::parse(&config_text, root.path()).expect("test config"));
        let admin =
            Arc::new(AdminStore::open(&root.path().join("spool.admin")).expect("admin store"));
        let jobs = Arc::new(super::jobs::JobRegistry::new((*admin).clone()));
        let state = Arc::new(HealthState {
            catalog: Arc::new(Catalog::new()),
            metrics: Arc::new(Metrics::default()),
            spool,
            capture: None,
            sync_trigger: Some(crate::sync::SyncTrigger::new(vec![
                ferrum_storage::checkpoint::SuiteKey::new("debian", "trixie").expect("suite"),
            ])),
            admin,
            admin_http: Arc::new(AdminHttpState::new(ORIGIN).expect("HTTP policy")),
            jobs,
            telemetry: Arc::new(super::telemetry::TelemetryHub::new()),
            config,
            publisher: None,
            s3: None,
            fills: None,
            request_slots: Some(Arc::new(tokio::sync::Semaphore::new(1024))),
            active_bodies: Some(Arc::new(tokio::sync::Semaphore::new(256))),
            verifier_version: "route-test".into(),
        });
        Self { root, state }
    }
    fn secret(&self, name: &str) -> String {
        std::fs::read_to_string(self.root.path().join("spool.admin").join(name))
            .expect("local token")
            .trim()
            .to_owned()
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        cookie: Option<&str>,
        csrf: Option<&str>,
        origin: Option<&str>,
        host: &str,
        bearer: Option<&str>,
    ) -> Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host)
            .header("content-type", "application/json");
        if let Some(value) = cookie {
            builder = builder.header("cookie", value);
        }
        if let Some(value) = csrf {
            builder = builder.header("x-ferrum-csrf", value);
        }
        if let Some(value) = origin {
            builder = builder.header("origin", value);
        }
        if let Some(value) = bearer {
            builder = builder.header("authorization", format!("Bearer {value}"));
        }
        let mut request = builder.body(Body::from(body.to_string())).expect("request");
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:41000".parse::<SocketAddr>().expect("peer"),
        ));
        crate::health::router(self.state.clone())
            .oneshot(request)
            .await
            .expect("router")
    }
    async fn setup(&self) -> (String, String, String) {
        let response = self.request("POST", "/api/admin/setup", json!({
            "bootstrapToken": self.secret("bootstrap.token"), "username":"admin", "displayName":"Administrator", "password":"Correct Horse Battery Staple"
        }), None, None, Some(ORIGIN), HOST, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()["set-cookie"].to_str().expect("cookie");
        assert!(cookie.contains("HttpOnly; SameSite=Strict"));
        assert!(!cookie.contains("; Secure"));
        let cookie = cookie.split(';').next().expect("cookie token").to_owned();
        let value = body(response).await;
        (
            cookie,
            value["csrfToken"].as_str().expect("CSRF").into(),
            value["user"]["id"].as_str().expect("user ID").into(),
        )
    }
}
async fn body(response: Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("bounded body"),
    )
    .expect("JSON")
}
#[tokio::test]
async fn exact_origin_host_and_csrf_protect_logout_and_revocation() {
    let _serial = super::password::TEST_LOCK.lock().await;
    let fixture = Fixture::new();
    let (cookie, csrf, _) = fixture.setup().await;
    let response = fixture
        .request(
            "POST",
            "/api/admin/logout",
            json!({}),
            Some(&cookie),
            Some(&csrf),
            Some("http://attacker.invalid"),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let response = fixture
        .request(
            "POST",
            "/api/admin/logout",
            json!({}),
            Some(&cookie),
            None,
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = fixture
        .request(
            "GET",
            "/api/admin/session",
            Value::Null,
            Some(&cookie),
            None,
            None,
            "attacker.invalid",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = fixture
        .request(
            "POST",
            "/api/admin/logout",
            json!({}),
            Some(&cookie),
            Some(&csrf),
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = fixture
        .request(
            "GET",
            "/api/admin/session",
            Value::Null,
            Some(&cookie),
            None,
            None,
            HOST,
            None,
        )
        .await;
    assert!(body(response).await["user"].is_null());
}
#[tokio::test]
async fn control_token_is_narrow_and_legacy_mutations_do_not_exist() {
    let fixture = Fixture::new();
    let control = fixture.secret("control.token");
    let response = fixture
        .request("GET", "/metrics", Value::Null, None, None, None, HOST, None)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = fixture
        .request(
            "GET",
            "/metrics",
            Value::Null,
            None,
            None,
            None,
            HOST,
            Some(&control),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = fixture
        .request(
            "GET",
            "/api/admin/users",
            Value::Null,
            None,
            None,
            None,
            HOST,
            Some(&control),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    for path in ["/sync", "/sync/debian", "/sync/debian/trixie"] {
        let response = fixture
            .request(
                "POST",
                path,
                json!({}),
                None,
                None,
                Some(ORIGIN),
                HOST,
                None,
            )
            .await;
        assert!(matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ));
    }
    assert!(
        fixture
            .state
            .sync_trigger
            .as_ref()
            .unwrap()
            .take_pending()
            .is_empty()
    );
    let response = fixture
        .request(
            "POST",
            "/api/admin/sync",
            json!({"repository":"debian","suite":"trixie"}),
            None,
            None,
            None,
            HOST,
            Some(&control),
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let sync_body = body(response).await;
    assert_eq!(sync_body["triggered"], json!(["debian/trixie"]));
    assert_eq!(sync_body["job"]["kind"], "sync");
    assert_eq!(sync_body["job"]["state"], "queued");
    assert_eq!(
        fixture.state.sync_trigger.as_ref().unwrap().take_pending(),
        vec![0]
    );
    let response = fixture
        .request(
            "GET",
            "/readyz",
            Value::Null,
            None,
            None,
            None,
            "probe",
            None,
        )
        .await;
    let value = body(response).await;
    assert_eq!(value, json!({"ready": false}));
}
#[tokio::test]
async fn session_revocation_and_account_change_invalidate_credentials() {
    let _serial = super::password::TEST_LOCK.lock().await;
    let fixture = Fixture::new();
    let (cookie, csrf, _) = fixture.setup().await;
    let sessions = fixture
        .request(
            "GET",
            "/api/admin/sessions",
            Value::Null,
            Some(&cookie),
            None,
            None,
            HOST,
            None,
        )
        .await;
    let sessions = body(sessions).await;
    let id = sessions["sessions"][0]["id"].as_str().expect("session ID");
    assert_eq!(sessions["sessions"][0]["current"], true);
    let response = fixture
        .request(
            "DELETE",
            &format!("/api/admin/sessions/{id}"),
            Value::Null,
            Some(&cookie),
            Some(&csrf),
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = fixture
        .request(
            "GET",
            "/api/admin/sessions",
            Value::Null,
            Some(&cookie),
            None,
            None,
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = fixture
        .request(
            "POST",
            "/api/admin/login",
            json!({"username":"admin","password":"Correct Horse Battery Staple"}),
            None,
            None,
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = body(response).await["csrfToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = fixture
        .request(
            "PUT",
            "/api/admin/account",
            json!({"displayName":"Renamed Administrator"}),
            Some(&cookie),
            Some(&csrf),
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = fixture
        .request(
            "GET",
            "/api/admin/sessions",
            Value::Null,
            Some(&cookie),
            None,
            None,
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn last_administrator_and_bootstrap_boundaries_hold_through_http() {
    let _serial = super::password::TEST_LOCK.lock().await;
    let fixture = Fixture::new();
    let response = fixture
        .request(
            "POST",
            "/api/admin/setup",
            json!({"bootstrapToken":"wrong","password":"Correct Horse Battery Staple"}),
            None,
            None,
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert!(!response.status().is_success());
    assert!(
        fixture
            .state
            .admin
            .setup_required()
            .await
            .expect("setup state")
    );
    let (cookie, csrf, id) = fixture.setup().await;
    let response = fixture
        .request(
            "DELETE",
            &format!("/api/admin/users/{id}"),
            Value::Null,
            Some(&cookie),
            Some(&csrf),
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let response = fixture
        .request(
            "PUT",
            &format!("/api/admin/users/{id}"),
            json!({"permissions":["view_status"],"disabled":true}),
            Some(&cookie),
            Some(&csrf),
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let response = fixture
        .request(
            "POST",
            "/api/admin/login",
            json!({"username":"admin","password":"x".repeat(9000)}),
            None,
            None,
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn cache_mutation_requires_permission_and_runs_the_real_local_operation() {
    let _serial = super::password::TEST_LOCK.lock().await;
    let fixture = Fixture::new();
    let (cookie, csrf, _) = fixture.setup().await;
    let control = fixture.secret("control.token");
    let response = fixture
        .request(
            "POST",
            "/api/admin/cache/clear",
            json!({}),
            None,
            None,
            Some(ORIGIN),
            HOST,
            Some(&control),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = fixture
        .request(
            "POST",
            "/api/admin/cache/clear",
            json!({}),
            Some(&cookie),
            Some(&csrf),
            Some(ORIGIN),
            HOST,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = body(response).await;
    assert_eq!(value["evictedObjects"], 0);
    assert_eq!(value["freedBytes"], 0);
    let auth = fixture
        .state
        .admin
        .authenticate(cookie.split_once('=').unwrap().1.into())
        .await
        .expect("current session");
    let audit = fixture
        .state
        .admin
        .list_audit(auth, None, 100)
        .await
        .expect("audited mutation");
    assert!(
        audit
            .iter()
            .any(|event| event.action == "cache.clear" && event.outcome == "intent")
    );
    assert!(
        audit
            .iter()
            .any(|event| event.action == "cache.clear" && event.outcome == "completed")
    );
}
