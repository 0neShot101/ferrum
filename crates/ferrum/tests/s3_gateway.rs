//! Consumer-visible S3 failure, authority, singleflight and persisted allowance regressions.
#![allow(clippy::expect_used, clippy::panic)]
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use ferrum::app::{self, RunningGateway};
use ferrum::sync::ActiveView;
use ferrum_fixture_origin::RunningOrigin;
use ferrum_storage::s3::testing::{ScriptedRequests, ScriptedResponse};
use ferrum_storage::s3::{PrivateS3Config, S3Store};
use reqwest::StatusCode;
use tokio_util::sync::CancellationToken;

fn s3_config(root: &std::path::Path) -> PrivateS3Config {
    PrivateS3Config {
        endpoint: "https://s3.us-central-1.idrivee2.com".into(),
        region: "us-central-1".into(),
        bucket: "s3-andrew".into(),
        package_prefix: "linux-packages/_ferrum-b05/0123456789abcdef0123456789abcdef/".into(),
        credentials_file: root.join("provider.env"),
        transfer_journal: root.join("journal"),
    }
}
fn response(method: &'static str, status: u16, body: Vec<u8>, size: u64) -> ScriptedResponse {
    ScriptedResponse {
        method,
        status,
        content_length: size,
        body,
        delay: Duration::ZERO,
        headers: vec![],
        lose_ack: false,
    }
}
fn error_response(method: &'static str, status: u16, code: &str) -> ScriptedResponse {
    let body =
        format!("<Error><Code>{code}</Code><Message>private scripted failure</Message></Error>")
            .into_bytes();
    let size = body.len() as u64;
    response(method, status, body, size)
}
async fn gateway(
    root: &std::path::Path,
    origin: &RunningOrigin,
    packages: &[ScratchPackage],
    store: Arc<S3Store>,
) -> RunningGateway {
    let config = config(&root.join("work"), origin, &root.join("unused.gpg"), "");
    let view = ActiveView::for_tests(
        packages
            .iter()
            .map(|package| (package.path.clone(), package.identity))
            .collect(),
        Duration::from_secs(3600),
    );
    app::start_with_view_and_s3(config, view, store, CancellationToken::new())
        .await
        .expect("gateway")
}
fn store(
    config: &PrivateS3Config,
    responses: Vec<ScriptedResponse>,
) -> (Arc<S3Store>, ScriptedRequests) {
    let (store, requests) =
        S3Store::scripted_private(config.clone(), responses).expect("scripted SDK adapter");
    (Arc::new(store), requests)
}
async fn empty_error(response: reqwest::Response, status: StatusCode) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(response.headers().get("etag").is_none());
    assert!(response.headers().get("content-range").is_none());
    assert!(response.bytes().await.expect("error body").is_empty());
}

#[tokio::test]
async fn cold_s3_get_is_singleflight_and_range_waiters_share_verified_bytes() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let mut get = response(
        "GET",
        200,
        packages[0].bytes.clone(),
        packages[0].identity.size,
    );
    get.delay = Duration::from_millis(150);
    let (store, requests) = store(&config, vec![get]);
    let gateway = gateway(root.path(), &origin, &packages, store.clone()).await;
    let client = client();
    let url = url(&gateway, SMALL_PACKAGE);
    let results = futures_util::future::join_all((0..12).map(|index| {
        let request = client.get(&url);
        async move {
            let request = if index % 2 == 0 {
                request.header("Range", "bytes=0-0")
            } else {
                request
            };
            let response = request.send().await.expect("response");
            (response.status(), response.bytes().await.expect("body"))
        }
    }))
    .await;
    for (index, (status, bytes)) in results.into_iter().enumerate() {
        if index % 2 == 0 {
            assert_eq!(status, StatusCode::PARTIAL_CONTENT);
            assert_eq!(bytes.as_ref(), &packages[0].bytes[..1]);
        } else {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(bytes.as_ref(), packages[0].bytes);
        }
    }
    assert_eq!(requests.snapshot().expect("requests"), ["GET"]);
    assert_eq!(origin_request_count(&origin), 0);
    assert_eq!(store.status().expect("status").attempts, 1);
    gateway.shutdown().await.expect("stop");
    origin.shutdown().await;
}

#[tokio::test]
async fn corrupt_s3_never_falls_back_or_installs_and_quarantine_survives_restart() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let mut corrupt = packages[0].bytes.clone();
    corrupt[0] ^= 1;
    let (first_store, requests) = store(
        &config,
        vec![response("GET", 200, corrupt, packages[0].identity.size)],
    );
    let first = gateway(root.path(), &origin, &packages, first_store.clone()).await;
    empty_error(
        client()
            .get(url(&first, SMALL_PACKAGE))
            .send()
            .await
            .expect("corrupt"),
        StatusCode::BAD_GATEWAY,
    )
    .await;
    assert!(first_store.is_quarantined(packages[0].identity));
    assert_eq!(requests.snapshot().expect("requests"), ["GET"]);
    assert_eq!(origin_request_count(&origin), 0);
    first.shutdown().await.expect("shutdown");
    drop(first_store);
    let (second_store, requests) = store(&config, vec![]);
    let second = gateway(root.path(), &origin, &packages, second_store).await;
    // A matching conditional must not hide a known failed object behind 304.
    let etag = format!("\"sha256-{}\"", packages[0].identity.sha256);
    empty_error(
        client()
            .get(url(&second, SMALL_PACKAGE))
            .header("If-None-Match", etag)
            .send()
            .await
            .expect("quarantined"),
        StatusCode::BAD_GATEWAY,
    )
    .await;
    assert!(requests.snapshot().expect("requests").is_empty());
    assert_eq!(origin_request_count(&origin), 0);
    second.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn forbidden_opens_persistent_circuit_and_is_not_absence_or_origin_fallback() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let (first_store, requests) = store(
        &config,
        vec![error_response("GET", 403, "InvalidAccessKeyId")],
    );
    let first = gateway(root.path(), &origin, &packages, first_store.clone()).await;
    empty_error(
        client()
            .get(url(&first, SMALL_PACKAGE))
            .send()
            .await
            .expect("forbidden"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert!(first_store.circuit_open());
    let status = first_store.status().expect("status");
    assert!(status.download_observed > 0 && status.download_observed <= status.download_reserved);
    assert_eq!(requests.snapshot().expect("requests"), ["GET"]);
    assert_eq!(origin_request_count(&origin), 0);
    first.shutdown().await.expect("shutdown");
    drop(first_store);
    let (second_store, requests) = store(&config, vec![]);
    assert!(second_store.circuit_open());
    let second = gateway(root.path(), &origin, &packages, second_store).await;
    empty_error(
        client()
            .get(url(&second, LARGE_PACKAGE))
            .send()
            .await
            .expect("latched circuit"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert!(requests.snapshot().expect("requests").is_empty());
    assert_eq!(origin_request_count(&origin), 0);
    second.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn only_true_not_found_falls_back_to_origin_in_the_same_verified_fill() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let missing = error_response("GET", 404, "NoSuchKey");
    let observed_error_bytes = missing.body.len() as u64;
    let (store, requests) = store(&config, vec![missing]);
    let gateway = gateway(root.path(), &origin, &packages, store.clone()).await;
    let response = client()
        .get(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("fallback");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("body").as_ref(),
        packages[0].bytes
    );
    assert_eq!(requests.snapshot().expect("requests"), ["GET"]);
    assert_eq!(origin_gets(&origin, SMALL_PACKAGE).len(), 1);
    assert_eq!(
        store
            .status()
            .expect("error body metered exactly once")
            .download_observed,
        observed_error_bytes
    );
    gateway.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn cold_head_probes_s3_without_filling_then_get_rehydrates_directly() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let size = packages[0].identity.size;
    let (store, requests) = store(
        &config,
        vec![
            response("HEAD", 200, vec![], size),
            response("GET", 200, packages[0].bytes.clone(), size),
        ],
    );
    let gateway = gateway(root.path(), &origin, &packages, store).await;
    let client = client();
    let head = client
        .head(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("HEAD");
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(
        head.headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .expect("authenticated representation length")
            .to_str()
            .expect("decimal length"),
        size.to_string(),
    );
    assert!(head.bytes().await.expect("HEAD body").is_empty());
    assert_eq!(requests.snapshot().expect("requests"), ["HEAD"]);
    let get = client
        .get(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("GET");
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.bytes().await.expect("body").as_ref(), packages[0].bytes);
    assert_eq!(requests.snapshot().expect("requests"), ["HEAD", "GET"]);
    assert_eq!(origin_request_count(&origin), 0);
    gateway.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn cold_head_length_mismatch_is_zero_byte_corruption_not_success() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let (store, _) = store(
        &config,
        vec![response("HEAD", 200, vec![], packages[0].identity.size + 1)],
    );
    let gateway = gateway(root.path(), &origin, &packages, store).await;
    empty_error(
        client()
            .head(url(&gateway, SMALL_PACKAGE))
            .send()
            .await
            .expect("HEAD"),
        StatusCode::BAD_GATEWAY,
    )
    .await;
    assert_eq!(origin_request_count(&origin), 0);
    gateway.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn restarted_allowance_refuses_more_sdk_egress_without_origin_fallback() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let identity = packages[1].identity;
    // Even an abandoned streaming response keeps its full pessimistic reservation.
    let responses = (0..10)
        .map(|_| response("GET", 200, packages[1].bytes.clone(), identity.size))
        .collect();
    let (first, requests) = store(&config, responses);
    for _ in 0..10 {
        drop(
            first
                .get(
                    identity,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                    CancellationToken::new(),
                )
                .await
                .expect("reserved attempt"),
        );
    }
    let reserved = first.status().expect("status").download_reserved;
    assert_eq!(requests.snapshot().expect("requests").len(), 10);
    drop(first);
    let (second, requests) = store(&config, vec![]);
    assert_eq!(
        second.status().expect("restarted status").download_reserved,
        reserved
    );
    let gateway = gateway(root.path(), &origin, &packages, second.clone()).await;
    let refusal = client()
        .get(url(&gateway, LARGE_PACKAGE))
        .send()
        .await
        .expect("exhausted");
    assert_eq!(refusal.headers()["retry-after"], "3600");
    empty_error(refusal, StatusCode::SERVICE_UNAVAILABLE).await;
    assert!(
        requests
            .snapshot()
            .expect("no provider attempt after cap")
            .is_empty()
    );
    assert_eq!(
        second
            .status()
            .expect("unchanged pessimistic usage")
            .download_reserved,
        reserved
    );
    assert_eq!(origin_request_count(&origin), 0);
    gateway.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn production_budget_refuses_get_and_head_before_provider_or_origin_contact() {
    use ferrum_storage::budget::{BudgetLedger, BudgetLimits};
    use ferrum_storage::s3::S3Config;
    use ferrum_storage::{DurableSpoolConfig, Spool};
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    const MIB: u64 = 1024 * 1024;
    let mut disk = DurableSpoolConfig::new(root.path().join("durable"));
    disk.spool.managed_ceiling = 32 * MIB;
    disk.spool.max_object_size = 4 * MIB;
    disk.free_space_floor = 0;
    disk.temporary_ceiling = 8 * MIB;
    disk.metadata_temporary_reserve = 2 * MIB;
    disk.metadata_ceiling = 8 * MIB;
    disk.catalog_ceiling = 8 * MIB;
    disk.eviction_high_watermark = 24 * MIB;
    disk.eviction_low_watermark = 16 * MIB;
    let spool = Spool::open_durable(disk).expect("durable ledger");
    let ledger = BudgetLedger::initialize(
        spool,
        BudgetLimits {
            storage: 16 * MIB,
            storage_control: MIB,
            monthly_download: 128 * 1024,
            download_control: 64 * 1024,
        },
    )
    .expect("explicit bounded allowance");
    let config = S3Config {
        endpoint: "https://s3.us-central-1.idrivee2.com".into(),
        region: "us-central-1".into(),
        bucket: "s3-andrew".into(),
        package_prefix: "linux-packages/".into(),
        checkpoint_prefix: "linux-checkpoints/".into(),
        credentials_file: root.path().join("unused-scripted-credentials"),
        shared_nonisolated: true,
    };
    let (backend, requests) = S3Store::scripted_production(config, ledger, vec![])
        .expect("real admission boundary before scripted transport");
    let gateway = gateway(root.path(), &origin, &packages, Arc::new(backend)).await;
    // HEAD's control request and GET's independent fill both exceed this allowance.
    for method in [reqwest::Method::HEAD, reqwest::Method::GET] {
        let refusal = client()
            .request(method, url(&gateway, LARGE_PACKAGE))
            .send()
            .await
            .expect("budget refusal");
        assert_eq!(refusal.headers()["retry-after"], "3600");
        empty_error(refusal, StatusCode::SERVICE_UNAVAILABLE).await;
    }
    assert!(requests.snapshot().expect("provider requests").is_empty());
    assert_eq!(origin_request_count(&origin), 0);
    gateway.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn non_key_404_never_falls_back_and_cold_head_absence_only_probes_origin() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let (store, requests) = store(
        &config,
        vec![
            error_response("HEAD", 404, "NotFound"),
            error_response("GET", 404, "NoSuchBucket"),
            error_response("GET", 404, "NoSuchBucket"),
        ],
    );
    let gateway = gateway(root.path(), &origin, &packages, store).await;
    let head = client()
        .head(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("HEAD fallback");
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(origin_gets(&origin, SMALL_PACKAGE).len(), 0);
    empty_error(
        client()
            .get(url(&gateway, SMALL_PACKAGE))
            .send()
            .await
            .expect("NoSuchBucket"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(
        requests.snapshot().expect("requests"),
        ["HEAD", "GET", "GET"]
    );
    assert_eq!(origin_gets(&origin, SMALL_PACKAGE).len(), 0);
    gateway.shutdown().await.expect("shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn queued_get_rechecks_circuit_or_quarantine_after_control_probe_finishes() {
    use std::task::Poll;
    for forbidden in [true, false] {
        let root = tempfile::tempdir().expect("root");
        let packages = scratch_tree(&root.path().join("origin"));
        let config = s3_config(root.path());
        S3Store::initialize_private_journal(&config).expect("init");
        let identity = packages[0].identity;
        let head = if forbidden {
            error_response("HEAD", 403, "AccessDenied")
        } else {
            response("HEAD", 200, vec![], identity.size + 1)
        };
        let (store, requests) = store(&config, vec![head]);
        let gate = store.hold_data_slots_for_test().expect("occupy data slots");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut queued = Box::pin(store.get(identity, deadline, CancellationToken::new()));
        std::future::poll_fn(|context| {
            assert!(queued.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(
            store
                .head(identity, deadline, CancellationToken::new())
                .await
                .is_err()
        );
        drop(gate);
        let expected = if forbidden {
            ferrum_storage::s3::S3Error::Forbidden
        } else {
            ferrum_storage::s3::S3Error::Corrupt
        };
        assert!(matches!(queued.await, Err(error) if error == expected));
        assert_eq!(
            requests.snapshot().expect("no queued GET dispatch"),
            ["HEAD"]
        );
        assert_eq!(store.status().expect("one attempt only").attempts, 1);
    }
}

#[tokio::test]
async fn empty_get_404_is_not_confirmed_absence() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let (store, requests) = store(
        &config,
        vec![
            response("GET", 404, vec![], 0),
            response("GET", 404, vec![], 0),
        ],
    );
    let gateway = gateway(root.path(), &origin, &packages, store).await;
    empty_error(
        client()
            .get(url(&gateway, SMALL_PACKAGE))
            .send()
            .await
            .expect("empty 404"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(requests.snapshot().expect("attempts"), ["GET", "GET"]);
    assert_eq!(origin_request_count(&origin), 0);
    gateway.shutdown().await.expect("stop");
    origin.shutdown().await;
}

async fn verified_fixture(
    root: &std::path::Path,
    package: &ScratchPackage,
) -> ferrum_storage::VerifiedObject {
    let spool = ferrum_storage::Spool::open_exclusive_fixture(ferrum_storage::SpoolConfig {
        root: root.join("seed-spool"),
        managed_ceiling: 4 * 1024 * 1024,
        max_object_size: 2 * 1024 * 1024,
        io_workers: 2,
        read_chunk: 256 * 1024,
    })
    .expect("seed spool");
    let reservation = spool.reserve(package.identity.size).expect("reserve");
    let mut writer = spool
        .begin_write(reservation, package.identity)
        .await
        .expect("writer");
    writer
        .write(bytes::Bytes::copy_from_slice(&package.bytes))
        .await
        .expect("write");
    writer.commit().await.expect("verified fixture lease")
}

#[tokio::test]
async fn lost_corruption_ack_reconciles_unique_intent_but_rejects_foreign_replacement() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let object = verified_fixture(root.path(), &packages[0]).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let mut lost = response("PUT", 200, vec![], 0);
    lost.lose_ack = true;
    let (first, _) = store(&config, vec![response("PUT", 200, vec![], 0), lost]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    first
        .put_file(&object, deadline, CancellationToken::new())
        .await
        .expect("seed");
    assert!(matches!(
        first
            .corrupt_private_fixture(&object, deadline, CancellationToken::new())
            .await,
        Err(ferrum_storage::s3::S3Error::Timeout)
    ));
    let token = first
        .status()
        .expect("durable unknown outcome")
        .objects
        .values()
        .next()
        .expect("owned object")
        .replacement
        .as_ref()
        .expect("pending mutation")
        .token
        .clone();
    drop(first);
    let head = |mutation: String| {
        let mut head = response("HEAD", 200, vec![], object.size());
        head.headers = vec![
            ("etag".into(), "\"changed-etag\"".into()),
            (
                "x-amz-meta-ferrum-b05-run".into(),
                "0123456789abcdef0123456789abcdef".into(),
            ),
            ("x-amz-meta-ferrum-b05-mutation".into(), mutation),
        ];
        head
    };
    let (foreign, requests) = store(&config, vec![head("foreign-token".into())]);
    assert_eq!(
        foreign
            .cleanup_private(deadline, CancellationToken::new())
            .await,
        Err(ferrum_storage::s3::S3Error::Conflict)
    );
    assert_eq!(requests.snapshot().expect("no deletion"), ["HEAD"]);
    drop(foreign);
    let (recovered, requests) = store(
        &config,
        vec![head(token), response("DELETE", 204, vec![], 0)],
    );
    recovered
        .cleanup_private(deadline, CancellationToken::new())
        .await
        .expect("conditional recovered cleanup");
    assert_eq!(
        requests.snapshot().expect("owned-key cleanup"),
        ["HEAD", "DELETE"]
    );
    let status = recovered.status().expect("status");
    let record = status.objects.values().next().expect("owned record");
    assert!(record.deleted && record.replacement.is_none());
}

#[tokio::test]
async fn corruption_response_version_id_is_rejected_without_clearing_pending_intent() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let object = verified_fixture(root.path(), &packages[0]).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let mut versioned = response("PUT", 200, vec![], 0);
    versioned
        .headers
        .push(("x-amz-version-id".into(), "unexpected-version".into()));
    let (store, _) = store(&config, vec![response("PUT", 200, vec![], 0), versioned]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    store
        .put_file(&object, deadline, CancellationToken::new())
        .await
        .expect("seed");
    assert_eq!(
        store
            .corrupt_private_fixture(&object, deadline, CancellationToken::new())
            .await,
        Err(ferrum_storage::s3::S3Error::Unsupported)
    );
    assert!(
        store
            .status()
            .expect("status")
            .objects
            .values()
            .next()
            .expect("owned record")
            .replacement
            .is_some()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn aliased_journal_is_rejected_before_fixture_startup_can_clean_it() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let objects = root.path().join("work/spool/objects");
    std::fs::create_dir_all(&objects).expect("objects");
    let sentinel = objects.join("must-survive");
    std::fs::write(&sentinel, b"usage evidence").expect("sentinel");
    std::os::unix::fs::symlink(&objects, root.path().join("alias")).expect("ancestor alias");
    let mut s3 = s3_config(root.path());
    s3.transfer_journal = root.path().join("alias/journal");
    assert!(S3Store::initialize_private_journal(&s3).is_err());
    let mut gateway_config = config(
        &root.path().join("work"),
        &origin,
        &root.path().join("unused.gpg"),
        "",
    );
    gateway_config.s3 = Some(s3);
    let view = ActiveView::for_tests(
        packages
            .iter()
            .map(|package| (package.path.clone(), package.identity))
            .collect(),
        Duration::from_secs(3600),
    );
    assert!(
        app::start_with_view(gateway_config, Some(view), CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(&sentinel).expect("not cleaned"),
        b"usage evidence"
    );
    origin.shutdown().await;
}

#[tokio::test]
async fn oversized_error_frame_keeps_exact_usage_reopen_and_owned_cleanup_available() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let object = verified_fixture(root.path(), &packages[0]).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    // Deliberately lying framing: the transport wrapper must account for the entire
    // already-observed frame, not clamp it to its control/error-body delivery limit.
    let oversized = response("GET", 500, vec![b'x'; 700_000], 0);
    let (first, _) = store(&config, vec![response("PUT", 200, vec![], 0), oversized]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    first
        .put_file(&object, deadline, CancellationToken::new())
        .await
        .expect("seed");
    assert!(
        first
            .get(object.identity(), deadline, CancellationToken::new())
            .await
            .is_err()
    );
    let status = first.status().expect("valid known overrun");
    assert!(status.overrun);
    assert_eq!(status.download_observed, 700_000);
    assert!(status.download_observed > status.download_reserved);
    drop(first);
    let mut head = response("HEAD", 200, vec![], object.size());
    head.headers.push((
        "x-amz-meta-ferrum-b05-run".into(),
        "0123456789abcdef0123456789abcdef".into(),
    ));
    let (reopened, requests) = store(&config, vec![head, response("DELETE", 204, vec![], 0)]);
    assert_eq!(
        reopened
            .status()
            .expect("known usage reopens")
            .download_observed,
        700_000
    );
    assert!(reopened.allowance_blocked());
    assert!(
        reopened
            .get(object.identity(), deadline, CancellationToken::new())
            .await
            .is_err()
    );
    assert!(
        requests
            .snapshot()
            .expect("normal admission refused")
            .is_empty()
    );
    reopened
        .cleanup_private(deadline, CancellationToken::new())
        .await
        .expect("owned cleanup despite overrun");
    assert_eq!(
        requests.snapshot().expect("cleanup controls"),
        ["HEAD", "DELETE"]
    );
    assert!(
        reopened
            .status()
            .expect("status")
            .objects
            .values()
            .next()
            .expect("record")
            .deleted
    );
}

#[tokio::test]
async fn sdk_error_hint_header_cannot_authorize_non_s3_404_fallback() {
    let root = tempfile::tempdir().expect("root");
    let packages = scratch_tree(&root.path().join("origin"));
    let origin = start_origin(root.path().join("origin")).await;
    let config = s3_config(root.path());
    S3Store::initialize_private_journal(&config).expect("init");
    let body = b"<html><Code>NoSuchKey</Code></html>";
    let responses = (0..2)
        .map(|_| {
            let mut missing = response("GET", 404, body.to_vec(), body.len() as u64);
            missing
                .headers
                .push(("x-amz-error-code".into(), "NoSuchKey".into()));
            missing
        })
        .collect();
    let (store, requests) = store(&config, responses);
    let gateway = gateway(root.path(), &origin, &packages, store.clone()).await;
    empty_error(
        client()
            .get(url(&gateway, SMALL_PACKAGE))
            .send()
            .await
            .expect("non-S3 404"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(
        requests.snapshot().expect("bounded attempts"),
        ["GET", "GET"]
    );
    assert_eq!(origin_request_count(&origin), 0);
    assert_eq!(
        store
            .status()
            .expect("metered error bytes")
            .download_observed,
        2 * body.len() as u64
    );
    gateway.shutdown().await.expect("stop");
    origin.shutdown().await;
}
