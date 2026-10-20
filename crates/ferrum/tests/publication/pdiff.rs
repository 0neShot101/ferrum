//! Run through fixture/pdiff-smoke.sh. Real stock APT, signed metadata, production
//! publication/recovery/router, and isolated local-only object storage transport.

use super::*;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

#[derive(Debug)]
struct Transfer {
    path: String,
    status: u16,
    size: u64,
}

type Transfers = Arc<Mutex<Vec<Transfer>>>;

async fn gateway(
    harness: &Harness,
    address: SocketAddr,
    transfers: Transfers,
) -> (
    SocketAddr,
    Arc<AppState>,
    CancellationToken,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("isolated HTTP listener");
    let address = listener.local_addr().expect("listener address");
    let mut state = http_state(harness, Duration::from_secs(30));
    Arc::get_mut(&mut state)
        .expect("new unshared state")
        .authority = address.to_string();
    let router = server::router(state.clone()).layer(axum::middleware::from_fn(
        move |request: Request<Body>, next: axum::middleware::Next| {
            let transfers = transfers.clone();
            async move {
                let path = request.uri().path().to_owned();
                let response = next.run(request).await;
                let size = response
                    .headers()
                    .get("content-length")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                transfers.lock().expect("transfer log").push(Transfer {
                    path,
                    status: response.status().as_u16(),
                    size,
                });
                response
            }
        },
    ));
    let stop = CancellationToken::new();
    let task = tokio::spawn(server::serve(
        listener,
        router,
        stop.clone(),
        Duration::from_secs(30),
        Duration::from_secs(5),
    ));
    (address, state, stop, task)
}

struct Apt {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

impl Apt {
    fn new(address: SocketAddr, keyring: &Path) -> Self {
        let directory = tempfile::tempdir().expect("isolated APT state");
        let root = directory.path().to_owned();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
            .expect("traverse state");
        for path in ["lists/partial", "cache/archives/partial", "etc"] {
            std::fs::create_dir_all(root.join(path)).expect("APT directories");
        }
        std::fs::copy(keyring, root.join("trusted.gpg")).expect("test-only public keyring");
        std::fs::write(root.join("status"), b"").expect("isolated dpkg status");
        std::fs::write(
            root.join("etc/sources.list"),
            format!(
                "deb [arch=amd64 signed-by={}] http://{address}/debian trixie main\n",
                root.join("trusted.gpg").display(),
            ),
        )
        .expect("isolated source");
        Self {
            _directory: directory,
            root,
        }
    }

    async fn update(&self, pdiffs: bool) -> String {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let output = std::process::Command::new("apt-get")
                .env("LC_ALL", "C")
                .args([
                    "-o",
                    &format!(
                        "Dir::Etc::sourcelist={}",
                        root.join("etc/sources.list").display()
                    ),
                ])
                .args(["-o", "Dir::Etc::sourceparts=-"])
                .args([
                    "-o",
                    &format!("Dir::State::lists={}", root.join("lists").display()),
                ])
                .args([
                    "-o",
                    &format!("Dir::State::status={}", root.join("status").display()),
                ])
                .args([
                    "-o",
                    &format!("Dir::Cache={}", root.join("cache").display()),
                ])
                .args([
                    "-o",
                    &format!(
                        "APT::Sandbox::User={}",
                        std::env::var("USER").unwrap_or_else(|_| "root".into())
                    ),
                ])
                .args(["-o", &format!("Acquire::PDiffs={pdiffs}")])
                .args([
                    "-o",
                    "Acquire::Languages=none",
                    "-o",
                    "APT::Architecture=amd64",
                ])
                .args([
                    "-o",
                    "Acquire::IndexTargets::deb::DEP-11::DefaultEnabled=false",
                ])
                .args([
                    "-o",
                    "Acquire::IndexTargets::deb::Packages::KeepCompressed=false",
                ])
                .args([
                    "-o",
                    "Acquire::Retries=0",
                    "-o",
                    "Acquire::http::Timeout=20",
                ])
                .arg("update")
                .output()
                .expect("stock apt-get installed");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.status.success(), "stock APT update failed:\n{text}");
            assert!(
                !text.contains("W:") && !text.contains("E:"),
                "stock APT warnings:\n{text}"
            );
            text
        })
        .await
        .expect("APT worker")
    }

    fn packages(&self) -> Vec<u8> {
        let path = std::fs::read_dir(self.root.join("lists"))
            .expect("APT lists")
            .map(|entry| entry.expect("list entry").path())
            .find(|path| {
                let name = path.file_name().expect("filename").to_string_lossy();
                name.ends_with("_binary-amd64_Packages")
                    || name.ends_with("_binary-amd64_Packages.lz4")
                    || name.ends_with("_binary-amd64_Packages.gz")
            })
            .expect("stock APT installed Packages list");
        let output = std::process::Command::new("/usr/lib/apt/apt-helper")
            .arg("cat-file")
            .arg(path)
            .output()
            .expect("stock apt-helper installed");
        assert!(output.status.success(), "read stock APT Packages");
        output.stdout
    }
}

fn clear(transfers: &Transfers) {
    transfers.lock().expect("transfer log").clear();
}

fn index_bytes(transfers: &Transfers) -> u64 {
    transfers
        .lock()
        .expect("transfer log")
        .iter()
        .filter(|entry| entry.status == 200 && entry.path.contains("/main/binary-amd64/"))
        .map(|entry| entry.size)
        .sum()
}

fn requested(transfers: &Transfers, suffix: &str) -> bool {
    transfers
        .lock()
        .expect("transfer log")
        .iter()
        .any(|entry| entry.status == 200 && entry.path.ends_with(suffix))
}

fn expected(harness: &Harness, generation: usize) -> Vec<u8> {
    std::fs::read(harness.fixture.join(format!(
        "pdiff/g{generation:03}/debian/dists/trixie/main/binary-amd64/Packages"
    )))
    .expect("generated exact Packages")
}

async fn select(harness: &Harness, generation: usize) {
    harness
        .origin
        .origin()
        .set_root(harness.fixture.join(format!("pdiff/g{generation:03}")))
        .await
        .expect("select signed PDiff generation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Linux stock apt-get, apt-helper, ferrum-verifier, B09 and fixture/pdiff.py output"]
async fn stock_apt_applies_pdiff_recovers_authority_and_falls_back() {
    let mut harness = Harness::with_seed(false).await;
    let key = SuiteKey::new("debian", "trixie").expect("test suite");
    select(&harness, 0).await;
    let audit = BootstrapAudit::acknowledge_reset(
        "local PDiff qualification",
        "new disposable test catalog; not recovery",
        UnixTime::now().as_secs(),
        "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED",
    )
    .expect("explicit bootstrap audit");
    harness
        .synchronizer
        .bootstrap_once(&key, audit, &harness.cancel)
        .await
        .expect("bootstrap signed full-index generation");
    let transfers = Arc::new(Mutex::new(Vec::new()));
    let (address, state, stop, task) = gateway(
        &harness,
        "127.0.0.1:0".parse().expect("loopback"),
        transfers.clone(),
    )
    .await;
    let baseline = Apt::new(address, &harness.fixture.join("b09/policy.gpg"));
    let client = Apt::new(address, &harness.fixture.join("b09/policy.gpg"));
    baseline.update(false).await;
    client.update(true).await;
    assert_eq!(client.packages(), expected(&harness, 0));

    select(&harness, 1).await;
    harness.publish(&key).await;
    clear(&transfers);
    baseline.update(false).await;
    assert_eq!(baseline.packages(), expected(&harness, 1));
    let full_bytes = index_bytes(&transfers);
    clear(&transfers);
    let apt_output = client.update(true).await;
    assert_eq!(client.packages(), expected(&harness, 1));
    assert!(
        requested(&transfers, "/Packages.diff/000-to-001.gz"),
        "APT did not request the authenticated patch: {apt_output}\n{:?}",
        transfers.lock().expect("log")
    );
    let diff_bytes = index_bytes(&transfers);
    assert!(
        diff_bytes > 0 && diff_bytes < full_bytes,
        "PDiff {diff_bytes}, full {full_bytes}"
    );
    println!(
        "PDiff stock-APT index transfer: full={full_bytes} bytes, diff={diff_bytes} bytes, saved={} bytes",
        full_bytes - diff_bytes
    );

    // Replace all publication/serving owners. Their empty proof caches must
    // reconstruct authority from the durable generation, not the prior view.
    stop.cancel();
    task.await.expect("HTTP task").expect("HTTP shutdown");
    state.registry.shutdown().await;
    drop(state);
    harness.publisher = Arc::new(
        CheckpointPublisher::new(
            harness.spool.clone(),
            harness.store.clone(),
            RecoveryProfile::SharedNonisolated,
        )
        .expect("reopened checkpoint owner"),
    );
    harness.catalog =
        Arc::new(Catalog::configured(keys(), harness.publisher.clone()).expect("reopened catalog"));
    harness.catalog.set_test_clock_synchronized(true);
    harness.synchronizer = DurableSynchronizer::new(
        harness.config.clone(),
        harness.verifier.clone(),
        harness.spool.clone(),
        harness.publisher.clone(),
        harness.catalog.clone(),
        Arc::new(Metrics::default()),
    )
    .await
    .expect("reopened synchronizer");
    harness
        .synchronizer
        .synchronize_once(&key, &harness.cancel)
        .await
        .expect("durable PDiff recovery");
    let (_, state, stop, task) = gateway(&harness, address, transfers.clone()).await;
    let patch_path = "/debian/dists/trixie/main/binary-amd64/Packages.diff/000-to-001.gz";
    let response = request(&state, Method::GET, patch_path, None).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "recovered patch authority"
    );
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("patch body");
    assert_eq!(
        bytes.as_ref(),
        std::fs::read(
            harness.fixture.join(
                "pdiff/g001/debian/dists/trixie/main/binary-amd64/Packages.diff/000-to-001.gz"
            )
        )
        .expect("fixture patch")
    );

    for generation in [2, 3, 4, 5] {
        select(&harness, generation).await;
        harness.publish(&key).await;
        let response = request(&state, Method::GET, patch_path, None).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "old canonical patch must not inherit new-generation authority"
        );
        clear(&transfers);
        // Keep the comparison client at generation 1 until the rotated-history
        // case, while the main client exercises every malformed/missing closure.
        let updating = if generation == 5 { &baseline } else { &client };
        updating.update(true).await;
        assert_eq!(updating.packages(), expected(&harness, generation));
        let patch = format!("/Packages.diff/{:03}-to-{generation:03}.gz", generation - 1);
        assert!(
            !requested(&transfers, &patch),
            "unusable patch must not be served/applied"
        );
        assert!(
            index_bytes(&transfers) > diff_bytes,
            "full fallback must transfer the full index"
        );
        if generation != 5 {
            let response = request(
                &state,
                Method::GET,
                "/debian/dists/trixie/main/binary-amd64/Packages.diff/Index",
                None,
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "bad optional closure must be absent, not partially published"
            );
        }
    }
    stop.cancel();
    task.await.expect("HTTP task").expect("HTTP shutdown");
    state.registry.shutdown().await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Linux ferrum-verifier, B09 and fixture/pdiff.py output"]
async fn optional_pdiff_timeout_still_publishes_full_index() {
    let mut harness = Harness::with_seed(false).await;
    let key = SuiteKey::new("debian", "trixie").expect("test suite");
    select(&harness, 0).await;
    let audit = BootstrapAudit::acknowledge_reset(
        "local PDiff deadline qualification",
        "new disposable test catalog; not recovery",
        UnixTime::now().as_secs(),
        "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED",
    )
    .expect("explicit bootstrap audit");
    harness
        .synchronizer
        .bootstrap_once(&key, audit, &harness.cancel)
        .await
        .expect("bootstrap full index");

    let mut config = (*harness.config).clone();
    let deadline = Duration::from_secs(5);
    config.limits.producer_deadline = deadline;
    config.limits.source_attempts = 1;
    harness.config = Arc::new(config);
    harness.synchronizer = DurableSynchronizer::new(
        harness.config.clone(),
        harness.verifier.clone(),
        harness.spool.clone(),
        harness.publisher.clone(),
        harness.catalog.clone(),
        Arc::new(Metrics::default()),
    )
    .await
    .expect("bounded synchronizer");
    select(&harness, 1).await;
    harness
        .origin
        .origin()
        .faults()
        .set(
            "debian/dists/trixie/main/binary-amd64/Packages.diff/000-to-001.gz".into(),
            Fault {
                kind: FaultKind::Delay { ms: 10_000 },
                remaining: None,
            },
        )
        .expect("delayed optional patch");
    let started = Instant::now();
    harness.publish(&key).await;
    assert!(
        started.elapsed() >= deadline,
        "optional acquisition must time out"
    );

    let state = http_state(&harness, Duration::from_secs(30));
    let response = request(
        &state,
        Method::GET,
        "/debian/dists/trixie/main/binary-amd64/Packages.diff/Index",
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "no partial closure"
    );
    let response = request(
        &state,
        Method::GET,
        "/debian/dists/trixie/main/binary-amd64/Packages",
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "full index remains available"
    );
    assert_eq!(
        to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("full index")
            .as_ref(),
        expected(&harness, 1),
    );
    state.registry.shutdown().await;
    harness.shutdown().await;
}
