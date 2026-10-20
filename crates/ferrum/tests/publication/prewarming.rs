use super::*;

use ferrum::admin::{AdminHttpState, AdminStore};
use ferrum::health::HealthState;
use ferrum::prewarm::Prewarm;
use ferrum_storage::capture::{CaptureManager, CaptureTrust};
use serde_json::Value;

const SMALL: &str = "pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb";
const LARGE: &str = "pool/main/f/ferrum-pacer/ferrum-pacer_1.0_all.deb";

async fn cli(config: &Path, arguments: &[&str]) -> std::process::Output {
    let config = config.to_owned();
    let arguments: Vec<_> = arguments.iter().map(|value| (*value).to_owned()).collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_ferrum"))
            .arg("prewarm")
            .arg("--config")
            .arg(config)
            .args(arguments)
            .output()
            .expect("run real ferrum prewarm command")
    })
    .await
    .expect("CLI worker")
}

fn successful(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "CLI failed ({status}):\nstdout: {stdout}\nstderr: {stderr}",
        status = output.status,
        stdout = String::from_utf8_lossy(&output.stdout),
        stderr = String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("CLI JSON output")
}

async fn terminal(config: &Path, id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let value = successful(cli(config, &["status", id]).await);
        if !matches!(value["job"]["state"].as_str(), Some("queued" | "running")) {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "prewarm job remained active"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn origin_gets(harness: &Harness, path: &str) -> usize {
    harness
        .origin
        .origin()
        .log()
        .snapshot()
        .iter()
        .filter(|entry| entry.method == "GET" && entry.path == path)
        .count()
}

#[tokio::test]
#[ignore = "requires generated signed B09 fixture and ferrum-verifier"]
async fn authenticated_cli_prewarm_budget_cache_retirement_and_shared_cancel() {
    let harness = Harness::new().await;
    let capture = Arc::new(
        CaptureManager::new(harness.spool.clone(), harness.store.clone()).expect("capture manager"),
    );
    let trusts: Vec<_> = harness
        .config
        .suites()
        .expect("trust suites")
        .into_iter()
        .map(|suite| CaptureTrust {
            key: suite.key,
            policy: suite.policy,
            floor_trust: ferrum_storage::checkpoint::FloorTrust::IntactTrusted,
        })
        .collect();
    Box::pin(capture.reconcile(
        &trusts,
        &harness.verifier,
        UnixTime::now().as_secs(),
        tokio::time::Instant::now() + Duration::from_secs(120),
        &harness.cancel,
    ))
    .await
    .expect("authenticate retained capture coverage");

    // Debian's authenticated descriptor remains durably retained, but its
    // suite is absent from the active route set, as after operator retirement.
    let active = SuiteKey::new("ubuntu", "noble").expect("active suite");
    let catalog = Arc::new(
        Catalog::configured(vec![active.clone()], harness.publisher.clone())
            .expect("active catalog"),
    );
    catalog.set_test_clock_synchronized(true);
    catalog
        .publish_suite(&active, (*harness.view(&active)).clone())
        .expect("active view");
    let mut state = Arc::try_unwrap(http_state(&harness, Duration::from_secs(30)))
        .ok()
        .expect("exclusive test state");
    state.catalog = catalog;
    state.limits.concurrent_fills = 2;
    let client = Arc::new(
        UpstreamClient::new(
            format!("http://{}/fixture/ubuntu/", harness.origin.data_addr())
                .parse()
                .expect("origin"),
            &state.limits,
        )
        .expect("active package client"),
    );
    state.client = client.clone();
    state.clients = vec![("ubuntu".into(), client.clone())];
    state.capture = Some(capture.clone());
    state.s3 = Some(harness.store.clone());
    state.registry = FillRegistry::new(
        harness.spool.clone(),
        client,
        Some(harness.store.clone()),
        state.limits,
        CancellationToken::new(),
        state.metrics.clone(),
    );
    let state = Arc::new(state);
    let prewarm = Arc::new(Prewarm::new(state.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("private listener");
    let address = listener.local_addr().expect("admin address");
    let origin = format!("http://{address}");
    let admin_dir = harness._directory.path().join("prewarm-admin");
    let admin = Arc::new(AdminStore::open(&admin_dir).expect("admin store"));
    let jobs = Arc::new(ferrum::admin::jobs::JobRegistry::new((*admin).clone()));
    let health = Arc::new(HealthState {
        catalog: state.catalog.clone(),
        metrics: state.metrics.clone(),
        spool: state.spool.clone(),
        capture: Some(capture),
        sync_trigger: None,
        admin,
        admin_http: Arc::new(AdminHttpState::new(&origin).expect("admin HTTP policy")),
        verifier_version: "prewarm-test".into(),
        jobs,
        telemetry: Arc::new(ferrum::admin::telemetry::TelemetryHub::new()),
        config: harness.config.clone(),
        publisher: Some(harness.publisher.clone()),
        s3: Some(harness.store.clone()),
        fills: Some(state.registry.clone()),
        request_slots: Some(state.request_slots.clone()),
        active_bodies: Some(state.active_bodies.clone()),
        prewarm: Some(prewarm.clone()),
    });
    let shutdown = CancellationToken::new();
    let stopped = shutdown.clone();
    let admin_server = tokio::spawn(async move {
        axum::serve(
            listener,
            ferrum::health::router(health)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(stopped.cancelled_owned())
        .await
        .expect("admin server");
    });
    let config = harness._directory.path().join("prewarm.toml");
    std::fs::write(&config, format!(
        "mode = \"private-durable\"\n[listen]\npublic = \"127.0.0.1:0\"\nadmin = \"{address}\"\n\
         [admin]\nstate_dir = \"{}\"\norigin = \"{origin}\"\n\
         [durable]\nstate_dir = \"{}\"\nsuites = [\"ubuntu/noble\"]\n\
         [durable.provider]\nregion = \"us-east-1\"\nbucket = \"ferrum\"\ncredentials_file = \"{}\"\n\
         [durable.keyrings]\ndebian = \"{}\"\nubuntu = \"{}\"\n[durable.budget]\nmode = \"existing\"\n[verifier]\n",
        admin_dir.display(), harness._directory.path().join("state").display(),
        harness._directory.path().join("unused.env").display(),
        harness.fixture.join("b09/policy.gpg").display(),
        harness.fixture.join("b09/policy.gpg").display(),
    )).expect("CLI configuration");
    harness.origin.origin().log().clear();
    let small_path = format!("ubuntu/{SMALL}");
    let large_path = format!("ubuntu/{LARGE}");
    let small_size = std::fs::metadata(harness.fixture.join("b09/g000").join(&small_path))
        .expect("small fixture")
        .len()
        .to_string();
    let large_size = std::fs::metadata(harness.fixture.join("b09/g000").join(&large_path))
        .expect("large fixture")
        .len()
        .to_string();

    let before = harness.remote.requests().expect("remote trace").len();
    assert!(
        !cli(&config, &["run", "--max-bytes", "1", &small_path])
            .await
            .status
            .success()
    );
    assert!(
        !cli(
            &config,
            &["run", "--max-bytes", &small_size, "ubuntu/pool/unknown.deb"]
        )
        .await
        .status
        .success()
    );
    assert!(
        !cli(
            &config,
            &[
                "run",
                "--max-bytes",
                &small_size,
                &format!("debian/{SMALL}")
            ]
        )
        .await
        .status
        .success()
    );
    assert!(harness.origin.origin().log().snapshot().is_empty());
    assert_eq!(
        harness.remote.requests().expect("remote trace").len(),
        before
    );

    let first = successful(cli(&config, &["run", "--max-bytes", &small_size, &small_path]).await);
    let first = terminal(&config, first["job"]["id"].as_str().expect("job id")).await;
    assert_eq!(first["job"]["state"], "succeeded");
    assert_eq!(first["job"]["prewarm"]["filled"], 1);
    assert_eq!(origin_gets(&harness, &small_path), 1);
    let repeat = successful(cli(&config, &["run", "--max-bytes", &small_size, &small_path]).await);
    let repeat = terminal(&config, repeat["job"]["id"].as_str().expect("job id")).await;
    assert_eq!(repeat["job"]["prewarm"]["cacheHits"], 1);
    assert_eq!(
        origin_gets(&harness, &small_path),
        1,
        "repeat must not download from origin"
    );

    harness
        .origin
        .origin()
        .faults()
        .set(
            large_path.clone(),
            Fault {
                kind: FaultKind::Pace {
                    chunk: 4096,
                    interval_ms: 20,
                },
                remaining: None,
            },
        )
        .expect("paced cold package");
    let warming = successful(cli(&config, &["run", "--max-bytes", &large_size, &large_path]).await);
    let id = warming["job"]["id"].as_str().expect("job id").to_owned();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while state.metrics.fill_waiters() == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "background waiter not attached"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let foreground_state = state.clone();
    let public_path = format!("/{large_path}");
    let foreground = tokio::spawn(async move {
        let response = request(&foreground_state, Method::GET, &public_path, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .expect("foreground bytes")
    });
    while state.metrics.fill_waiters() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "foreground did not join fill"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    successful(cli(&config, &["cancel", &id]).await);
    let cancelled = terminal(&config, &id).await;
    assert_eq!(cancelled["job"]["state"], "cancelled");
    assert_eq!(
        cancelled["job"]["prewarm"]["chargedBytes"],
        large_size.parse::<u64>().expect("size")
    );
    let bytes = foreground.await.expect("foreground task");
    assert_eq!(
        bytes.as_ref(),
        std::fs::read(harness.fixture.join("b09/g000").join(&large_path))
            .expect("expected foreground body")
    );
    assert_eq!(
        origin_gets(&harness, &large_path),
        1,
        "shared fill survives cancellation"
    );

    prewarm.shutdown().await;
    state.registry.shutdown().await;
    shutdown.cancel();
    admin_server.await.expect("admin shutdown");
    harness.shutdown().await;
}
