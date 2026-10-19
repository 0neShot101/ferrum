//! Explicit signed-fixture suite: generate fixture/public first and run with
//! ferrum-verifier 0.1.0 on PATH plus /usr/bin/prlimit. No test substitutes a verifier.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use ferrum::app;
use ferrum_apt::digest::{Sha256Digest, Sha512Digest};
use ferrum_apt::release::{ParseLimits, Release};
use ferrum_fixture_origin::{Fault, FaultKind, RunningOrigin};
use reqwest::StatusCode;
use tokio_util::sync::CancellationToken;

const INRELEASE: &str = "dists/ferrum-test/InRelease";
const PACKAGES: &str = "dists/ferrum-test/main/binary-amd64/Packages";

fn fixture() -> PathBuf {
    std::env::var_os("FERRUM_FIXTURE_PUBLIC")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixture/public"))
        .canonicalize()
        .expect("run fixture/generate.sh before signed_fixture tests")
}

fn set_fault(origin: &RunningOrigin, path: &str, kind: FaultKind) {
    origin
        .origin()
        .faults()
        .set(
            path.to_owned(),
            Fault {
                kind,
                remaining: None,
            },
        )
        .expect("set fault");
}

async fn wait_health(gateway: &app::RunningGateway, expected: &str) -> String {
    let client = client();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let text = client
                .get(admin_url(gateway, "/readyz"))
                .send()
                .await
                .expect("health")
                .text()
                .await
                .expect("health body");
            if text.contains(expected) {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("expected signed publisher health transition")
}

async fn assert_unavailable(gateway: &app::RunningGateway) {
    let response = client()
        .get(url(gateway, INRELEASE))
        .header("If-None-Match", "*")
        .send()
        .await
        .expect("unavailable metadata");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "5");
    assert!(response.bytes().await.expect("error body").is_empty());
}

#[tokio::test]
#[ignore = "requires generated fixture/public, ferrum-verifier 0.1.0 on PATH and /usr/bin/prlimit"]
async fn signed_fixture_publishes_exact_complete_metadata_and_reauthenticates_after_restart() {
    let fixture = fixture();
    let directory = tempfile::tempdir().expect("work directory");
    let origin = start_origin(fixture.join("repo")).await;
    let config = config(
        &directory.path().join("work"),
        &origin,
        &fixture.join("ferrum-fixture.gpg"),
        "",
    );
    let gateway = app::start(config.clone(), CancellationToken::new())
        .await
        .expect("real verifier startup");
    wait_health(&gateway, "\"ready\":true").await;
    let client = client();
    for relative in [
        INRELEASE,
        "dists/ferrum-test/Release",
        "dists/ferrum-test/Release.gpg",
        PACKAGES,
        "dists/ferrum-test/main/binary-amd64/Packages.gz",
        "dists/ferrum-test/main/binary-amd64/Release",
    ] {
        let response = client
            .get(url(&gateway, relative))
            .send()
            .await
            .expect("published metadata");
        assert_eq!(response.status(), StatusCode::OK, "{relative}");
        assert_eq!(response.headers()["cache-control"], "no-cache");
        assert_eq!(
            response.bytes().await.expect("metadata body").as_ref(),
            std::fs::read(fixture.join("repo").join(relative)).expect("fixture bytes")
        );
    }
    let release = Release::parse(
        &std::fs::read(fixture.join("repo/dists/ferrum-test/Release")).expect("Release"),
        &ParseLimits::default(),
    )
    .expect("fixture Release");
    for entry in release.entries() {
        let expected = std::fs::read(
            fixture
                .join("repo/dists/ferrum-test")
                .join(entry.path.as_str()),
        )
        .expect("index bytes");
        assert_eq!(
            Sha256Digest::of(&expected),
            entry.sha256.expect("fixture SHA256")
        );
        assert_eq!(
            Sha512Digest::of(&expected),
            entry.sha512.expect("fixture SHA512")
        );
        for (algorithm, digest) in [
            ("SHA256", entry.sha256.expect("SHA256").to_hex()),
            ("SHA512", entry.sha512.expect("SHA512").to_hex()),
        ] {
            let alias = format!("dists/ferrum-test/main/binary-amd64/by-hash/{algorithm}/{digest}");
            let response = client
                .get(url(&gateway, &alias))
                .send()
                .await
                .expect("authorized alias");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["cache-control"],
                "public, max-age=31536000, immutable"
            );
            assert_eq!(
                response.bytes().await.expect("alias body").as_ref(),
                expected
            );
        }
    }
    let response = client
        .get(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("signed-authorized cold package");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("verified package").as_ref(),
        std::fs::read(fixture.join("repo").join(SMALL_PACKAGE)).expect("fixture package")
    );
    assert_eq!(origin_gets(&origin, SMALL_PACKAGE).len(), 1);
    assert!(
        origin
            .origin()
            .log()
            .snapshot()
            .iter()
            .any(|entry| entry.path.contains("/by-hash/"))
    );
    origin.shutdown().await;
    let response = client
        .get(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("warm offline package");
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.expect("warm bytes");
    gateway.shutdown().await.expect("shutdown");
    let gateway = app::start(config, CancellationToken::new())
        .await
        .expect("restart verifier");
    wait_health(&gateway, "source dists/ferrum-test/InRelease").await;
    assert_unavailable(&gateway).await;
    let response = client
        .get(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("discarded authority");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    gateway.shutdown().await.expect("restart shutdown");
}

#[tokio::test]
#[ignore = "requires generated fixture/public, ferrum-verifier 0.1.0 on PATH and /usr/bin/prlimit"]
async fn unknown_signer_corrupt_index_and_incomplete_detached_pair_never_publish() {
    let fixture = fixture();
    let release = Release::parse(
        &std::fs::read(fixture.join("repo/dists/ferrum-test/Release")).expect("Release"),
        &ParseLimits::default(),
    )
    .expect("fixture Release");
    let packages = release
        .entries()
        .iter()
        .find(|entry| entry.path.as_str() == "main/binary-amd64/Packages")
        .expect("Packages entry");
    let alias = format!(
        "dists/ferrum-test/main/binary-amd64/by-hash/SHA256/{}",
        packages.sha256.expect("SHA256")
    );
    for case in [
        "unknown signer",
        "corrupt index",
        "missing detached signature",
    ] {
        let directory = tempfile::tempdir().expect("work directory");
        let origin = start_origin(fixture.join(if case == "unknown signer" {
            "repo-untrusted"
        } else {
            "repo"
        }))
        .await;
        let error = match case {
            "corrupt index" => {
                set_fault(
                    &origin,
                    &alias,
                    FaultKind::Corrupt {
                        offset: packages.size - 1,
                    },
                );
                "index fill corrupt"
            }
            "missing detached signature" => {
                set_fault(&origin, "dists/ferrum-test/Release.gpg", FaultKind::Delete);
                "source dists/ferrum-test/Release.gpg: not found"
            }
            _ => "signature rejected: InRelease",
        };
        let config = config(
            &directory.path().join("work"),
            &origin,
            &fixture.join("ferrum-fixture.gpg"),
            "",
        );
        let gateway = app::start(config, CancellationToken::new())
            .await
            .expect("verifier startup");
        wait_health(&gateway, error).await;
        assert_unavailable(&gateway).await;
        assert_eq!(
            client()
                .get(url(&gateway, PACKAGES))
                .send()
                .await
                .expect("no partial index")
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        gateway.shutdown().await.expect("shutdown");
        origin.shutdown().await;
    }
}

#[tokio::test]
#[ignore = "requires generated fixture/public, ferrum-verifier 0.1.0 on PATH and /usr/bin/prlimit"]
async fn expired_signed_release_never_publishes_or_replaces_an_active_view() {
    let fixture = fixture();
    let directory = tempfile::tempdir().expect("work directory");
    let origin = start_origin(fixture.join("repo-expired")).await;
    let config = config(
        &directory.path().join("work"),
        &origin,
        &fixture.join("ferrum-fixture.gpg"),
        "sync_interval_seconds = 1",
    );
    let gateway = app::start(config, CancellationToken::new())
        .await
        .expect("real verifier startup");
    wait_health(&gateway, "Valid-Until has passed").await;
    assert_unavailable(&gateway).await;
    origin
        .origin()
        .set_root(fixture.join("repo"))
        .await
        .expect("valid repository");
    wait_health(&gateway, "\"ready\":true").await;
    let expected = std::fs::read(fixture.join("repo").join(INRELEASE)).expect("active metadata");
    origin
        .origin()
        .set_root(fixture.join("repo-expired"))
        .await
        .expect("expired repository");
    wait_health(&gateway, "Valid-Until has passed").await;
    let response = client()
        .get(url(&gateway, INRELEASE))
        .send()
        .await
        .expect("unchanged active metadata");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("active bytes").as_ref(),
        expected
    );
    gateway.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
#[ignore = "requires generated fixture/public, ferrum-verifier 0.1.0 on PATH and /usr/bin/prlimit"]
async fn observed_unpublishable_successor_prevents_old_payload_from_renewing_freshness() {
    let fixture = fixture();
    let directory = tempfile::tempdir().expect("work directory");
    let origin = start_origin(fixture.join("repo")).await;
    let mut config = config(
        &directory.path().join("work"),
        &origin,
        &fixture.join("ferrum-fixture.gpg"),
        "sync_interval_seconds = 1",
    );
    config.limits.active_lease = Duration::from_secs(3);
    let gateway = app::start(config, CancellationToken::new())
        .await
        .expect("verifier startup");
    wait_health(&gateway, "\"ready\":true").await;
    let original = std::fs::read(fixture.join("repo").join(PACKAGES)).expect("index");
    let alias = format!(
        "dists/ferrum-test/main/binary-amd64/by-hash/SHA256/{}",
        Sha256Digest::of(&original)
    );
    set_fault(&origin, "dists/ferrum-test/Release.gpg", FaultKind::Delete);
    origin
        .origin()
        .set_root(fixture.join("repo-gen2"))
        .await
        .expect("successor root");
    wait_health(&gateway, "source dists/ferrum-test/Release.gpg: not found").await;
    origin
        .origin()
        .set_root(fixture.join("repo"))
        .await
        .expect("replayed old root");
    origin.origin().faults().clear();
    wait_health(&gateway, "rollback rejected").await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_unavailable(&gateway).await;
    let response = client()
        .get(url(&gateway, &alias))
        .send()
        .await
        .expect("retained immutable alias");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("alias bytes").as_ref(),
        original
    );
    gateway.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
#[ignore = "requires generated fixture/public, ferrum-verifier 0.1.0 on PATH and /usr/bin/prlimit"]
async fn unowned_scratch_directory_is_refused_without_deleting_user_files() {
    let fixture = fixture();
    let directory = tempfile::tempdir().expect("work directory");
    let work = directory.path().join("work");
    std::fs::create_dir_all(work.join("scratch")).expect("user scratch");
    let user_file = work.join("scratch/user-data");
    std::fs::write(&user_file, b"do not delete").expect("user file");
    let origin = start_origin(fixture.join("repo")).await;
    let config = config(&work, &origin, &fixture.join("ferrum-fixture.gpg"), "");
    assert!(app::start(config, CancellationToken::new()).await.is_err());
    assert_eq!(
        std::fs::read(&user_file).expect("preserved user file"),
        b"do not delete"
    );
    origin.shutdown().await;
}
