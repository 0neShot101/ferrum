//! Shared harness: an in-process fault-injectable origin, a gateway on
//! ephemeral ports and an unsigned scratch package tree with known identities.

#![allow(dead_code, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use ferrum::app::{self, RunningGateway};
use ferrum::config::Config;
use ferrum::sync::ActiveView;
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use ferrum_apt::path::RepositoryPath;
use ferrum_fixture_origin::{LogEntry, OriginConfig, RunningOrigin};
use tokio_util::sync::CancellationToken;

pub const SMALL_PACKAGE: &str = "pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb";
pub const LARGE_PACKAGE: &str = "pool/main/f/ferrum-pacer/ferrum-pacer_1.0_all.deb";

/// One unsigned scratch package.
pub struct ScratchPackage {
    pub path: RepositoryPath,
    pub identity: ObjectIdentity,
    pub bytes: Vec<u8>,
}

/// Deterministic incompressible-looking bytes of `length`.
pub fn pattern(seed: u64, length: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        })
        .collect()
}

/// Writes `pool/` packages below `root` and returns their identities.
pub fn scratch_tree(root: &Path) -> Vec<ScratchPackage> {
    let specs = [
        (SMALL_PACKAGE, 1u64, 682usize),
        (LARGE_PACKAGE, 2, 1_065_152),
    ];
    specs
        .iter()
        .map(|(relative, seed, length)| {
            let bytes = pattern(*seed, *length);
            let file = root.join(relative);
            std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
            std::fs::write(&file, &bytes).expect("write package");
            ScratchPackage {
                path: RepositoryPath::parse_decoded(relative).expect("path"),
                identity: ObjectIdentity {
                    sha256: Sha256Digest::of(&bytes),
                    size: bytes.len() as u64,
                },
                bytes,
            }
        })
        .collect()
}

pub async fn start_origin(root: PathBuf) -> RunningOrigin {
    RunningOrigin::bind(OriginConfig {
        root,
        listen: "127.0.0.1:0".parse().expect("addr"),
        control: "127.0.0.1:0".parse().expect("addr"),
        prefix: "/fixture/".to_owned(),
    })
    .await
    .expect("origin")
}

/// Builds a configuration bound to ephemeral ports with `extra_limits` TOML
/// lines appended under `[limits]`.
pub fn config(work: &Path, origin: &RunningOrigin, keyring: &Path, extra_limits: &str) -> Config {
    let text = format!(
        "mode = \"private-fixture\"\n[listen]\npublic = \"127.0.0.1:0\"\nadmin = \"127.0.0.1:0\"\n\
         [fixture]\nkeyring = \"{}\"\nwork_dir = \"{}\"\n[verifier]\n[limits]\n{extra_limits}\n",
        keyring.display(),
        work.display()
    );
    let mut config = Config::parse(&text, work).expect("config");
    config
        .set_test_origin(
            format!("http://{}/fixture/", origin.data_addr())
                .parse()
                .expect("origin url"),
        )
        .expect("loopback test origin");
    config
}

/// Gateway with a pre-published unsigned view of `packages`.
pub async fn start_gateway(config: Config, packages: &[ScratchPackage]) -> RunningGateway {
    let view = ActiveView::for_tests(
        packages
            .iter()
            .map(|package| (package.path.clone(), package.identity))
            .collect(),
        Duration::from_secs(3600),
    );
    app::start_with_view(config, Some(view), CancellationToken::new())
        .await
        .expect("gateway start")
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(45))
        .build()
        .expect("client")
}

pub fn url(gateway: &RunningGateway, relative: &str) -> String {
    format!("http://{}/fixture/{relative}", gateway.public_addr)
}

pub fn admin_url(gateway: &RunningGateway, route: &str) -> String {
    format!("http://{}{route}", gateway.admin_addr)
}

/// Origin GET requests whose relative path equals `relative`.
pub fn origin_gets(origin: &RunningOrigin, relative: &str) -> Vec<LogEntry> {
    origin
        .origin()
        .log()
        .snapshot()
        .into_iter()
        .filter(|entry| entry.method == "GET" && entry.path == relative)
        .collect()
}

pub fn origin_request_count(origin: &RunningOrigin) -> usize {
    origin.origin().log().snapshot().len()
}

/// Polls `predicate` until it holds or `timeout` elapses.
pub async fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    predicate()
}
