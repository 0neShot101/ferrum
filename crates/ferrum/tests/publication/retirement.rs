use super::*;
use ferrum_storage::capture::{CaptureManager, CaptureTrust};
use ferrum_storage::checkpoint::FloorTrust;

fn retired_config(harness: &Harness) -> Config {
    let root = harness._directory.path();
    let selection = IDENTITIES
        .iter()
        .map(|(repository, suite)| format!("\"{repository}/{suite}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let keyring = harness.fixture.join("b09/policy.gpg");
    let text = format!(
        "mode = \"private-durable\"\n[listen]\npublic = \"127.0.0.1:0\"\nadmin = \"127.0.0.1:0\"\n\
         [durable]\nstate_dir = \"{}\"\nsuites = []\nretired_suites = [{selection}]\n\
         [durable.provider]\nregion = \"us-east-1\"\nbucket = \"ferrum\"\ncredentials_file = \"unused.env\"\n\
         [durable.keyrings]\ndebian = \"{}\"\nubuntu = \"{}\"\n\
         [durable.budget]\nmode = \"existing\"\n[verifier]\n",
        harness.config.spool_dir().display(),
        keyring.display(),
        keyring.display(),
    );
    let mut config = Config::parse(&text, root).expect("explicit retired selection");
    config
        .set_test_suite_origins(
            format!("http://{}/fixture/", harness.origin.data_addr())
                .parse()
                .expect("loopback origin"),
            keyring,
        )
        .expect("same distribution test policy");
    config
}

async fn reconcile(capture: &CaptureManager, config: &Config, harness: &Harness) {
    let trusts = config
        .trust_suites()
        .expect("active and retired trust")
        .into_iter()
        .map(|suite| CaptureTrust {
            key: suite.key,
            policy: suite.policy,
            floor_trust: FloorTrust::IntactTrusted,
        })
        .collect::<Vec<_>>();
    capture
        .reconcile(
            &trusts,
            &harness.verifier,
            UnixTime::now().as_secs(),
            tokio::time::Instant::now() + Duration::from_secs(120),
            &harness.cancel,
        )
        .await
        .expect("current-key historical capture reconciliation");
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn explicit_retirement_preserves_capture_trust_and_reactivation() {
    let harness = Harness::new().await;
    let key = keys().remove(0);
    let floor = harness.publisher.state(&key).expect("active state").floor;
    let capture = Arc::new(
        CaptureManager::new(harness.spool.clone(), harness.store.clone()).expect("capture manager"),
    );
    reconcile(&capture, &harness.config, &harness).await;

    let packages = std::fs::read_to_string(
        harness
            .fixture
            .join("b09/g000/debian/dists/trixie/main/binary-amd64/Packages"),
    )
    .expect("signed fixture package index");
    let package = packages
        .lines()
        .find_map(|line| line.strip_prefix("Filename: "))
        .expect("fixture package path");
    let package_path = ferrum_apt::path::RepositoryPath::parse_decoded(package)
        .expect("authenticated package path");
    let public_path = format!("/debian/{package}");
    let mut active = http_state(&harness, Duration::from_secs(30));
    let state = Arc::get_mut(&mut active).expect("unshared HTTP state");
    state.capture = Some(capture.clone());
    state.s3 = Some(harness.store.clone());
    state.registry = FillRegistry::new(
        harness.spool.clone(),
        state.client.clone(),
        Some(harness.store.clone()),
        state.limits,
        harness.cancel.clone(),
        state.metrics.clone(),
    );
    let response = request(&active, Method::GET, &public_path, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .expect("verified package bytes");
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(&bytes),
        size: bytes.len() as u64,
    };
    capture
        .complete(
            identity,
            tokio::time::Instant::now() + Duration::from_secs(120),
            &harness.cancel,
        )
        .await
        .expect("durable package and authenticated receipt");
    assert_eq!(
        capture
            .lookup("debian", &package_path)
            .expect("capture lookup"),
        Some(identity)
    );
    let storage = BudgetLedger::inspect(&harness.spool)
        .expect("retained accounting")
        .storage;

    // Recreate runtime objects from persisted checkpoint state and the retired
    // configuration. No retained view is installed into a public catalog.
    let config = Arc::new(retired_config(&harness));
    assert!(config.suites().expect("active selection").is_empty());
    let publisher = Arc::new(
        CheckpointPublisher::new(
            harness.spool.clone(),
            harness.store.clone(),
            RecoveryProfile::SharedNonisolated,
        )
        .expect("restarted publisher"),
    );
    assert_eq!(
        publisher.state(&key).expect("retained checkpoint").floor,
        floor
    );
    let catalog =
        Arc::new(Catalog::configured(Vec::new(), publisher.clone()).expect("retired catalog"));
    catalog.set_test_clock_synchronized(true);
    let mut synchronizer = DurableSynchronizer::new(
        config.clone(),
        harness.verifier.clone(),
        harness.spool.clone(),
        publisher.clone(),
        catalog.clone(),
        Arc::new(Metrics::default()),
    )
    .await
    .expect("retired-only synchronizer");
    assert!(synchronizer.trigger_handle().matching(None, None).is_none());
    let mut retired = http_state(&harness, Duration::from_secs(30));
    Arc::get_mut(&mut retired)
        .expect("unshared retired HTTP state")
        .catalog = catalog.clone();
    let origin_requests = harness.origin.origin().log().snapshot().len();
    let remote_requests = harness.remote.requests().expect("remote requests").len();
    assert!(
        synchronizer
            .synchronize_once(&key, &harness.cancel)
            .await
            .is_err()
    );
    let index = std::fs::read(
        harness
            .fixture
            .join("b09/g000/debian/dists/trixie")
            .join(INDEX),
    )
    .expect("signed by-hash representation");
    for path in [
        "/debian/dists/trixie/InRelease".to_owned(),
        "/debian/dists/trixie/main/binary-amd64/Packages".to_owned(),
        format!(
            "/debian/dists/trixie/main/binary-amd64/by-hash/SHA256/{}",
            Sha256Digest::of(&index)
        ),
        public_path.clone(),
    ] {
        assert_eq!(
            request(&retired, Method::GET, &path, None).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        harness.origin.origin().log().snapshot().len(),
        origin_requests
    );
    assert_eq!(
        harness.remote.requests().expect("remote requests").len(),
        remote_requests
    );
    assert!(catalog.load_suite(&key).is_none());

    let recovered = CaptureManager::new(harness.spool.clone(), harness.store.clone())
        .expect("restarted capture manager");
    recovered
        .begin_reconciliation(UnixTime::now().as_secs())
        .expect("restart capture verification");
    reconcile(&recovered, &config, &harness).await;
    assert!(recovered.coverage_ready().expect("recovered coverage"));
    assert_eq!(
        recovered
            .lookup("debian", &package_path)
            .expect("retired capture authority"),
        Some(identity)
    );
    assert_eq!(publisher.state(&key).expect("retained floor").floor, floor);
    assert_eq!(
        BudgetLedger::inspect(&harness.spool)
            .expect("accounting after retirement")
            .storage,
        storage
    );

    let reactivated =
        Arc::new(Catalog::configured(keys(), publisher.clone()).expect("active selection"));
    reactivated.set_test_clock_synchronized(true);
    let mut synchronizer = DurableSynchronizer::new(
        harness.config.clone(),
        harness.verifier.clone(),
        harness.spool.clone(),
        publisher.clone(),
        reactivated.clone(),
        Arc::new(Metrics::default()),
    )
    .await
    .expect("reactivated synchronizer");
    synchronizer
        .synchronize_once(&key, &harness.cancel)
        .await
        .expect("recover retained floor without bootstrap");
    let mut state = http_state(&harness, Duration::from_secs(30));
    Arc::get_mut(&mut state)
        .expect("unshared reactivated state")
        .catalog = reactivated;
    assert_eq!(
        request(&state, Method::GET, "/debian/dists/trixie/InRelease", None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        publisher.state(&key).expect("reactivated floor").floor,
        floor
    );
    harness.shutdown().await;
}
