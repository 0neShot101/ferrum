//! HTTP boundary tests use real sockets, the shared spool/fill path and the
//! fault-injectable origin. Unsigned authority exists only with test-harness.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use ferrum::app::{self, RunningGateway};
use ferrum_fixture_origin::{Fault, FaultKind, RunningOrigin};
use reqwest::{Client, StatusCode};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::sync::Barrier;
use tokio_util::sync::CancellationToken;

struct Harness {
    directory: TempDir,
    packages: Vec<ScratchPackage>,
    origin: RunningOrigin,
    gateway: RunningGateway,
    client: Client,
}

impl Harness {
    async fn new(limits: &str) -> Self {
        let directory = tempfile::tempdir().expect("temporary fixture");
        let root = directory.path().join("origin");
        let packages = scratch_tree(&root);
        let origin = start_origin(root).await;
        let config = config(
            &directory.path().join("work"),
            &origin,
            &directory.path().join("unused.gpg"),
            limits,
        );
        let gateway = start_gateway(config, &packages).await;
        Self {
            directory,
            packages,
            origin,
            gateway,
            client: client(),
        }
    }

    fn fault(&self, path: &str, kind: FaultKind, remaining: Option<u64>) {
        self.origin
            .origin()
            .faults()
            .set(path.to_owned(), Fault { kind, remaining })
            .expect("set fault");
    }

    async fn stop(self) {
        self.gateway.shutdown().await.expect("gateway shutdown");
        self.origin.shutdown().await;
    }
}

async fn empty_error(response: reqwest::Response, expected: StatusCode) {
    assert_eq!(response.status(), expected);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(response.headers().get("etag").is_none());
    assert!(response.headers().get("content-range").is_none());
    if expected == StatusCode::SERVICE_UNAVAILABLE {
        assert_eq!(response.headers()["retry-after"], "5");
    }
    assert!(response.bytes().await.expect("error body").is_empty());
}

async fn metrics(client: &Client, gateway: &RunningGateway) -> String {
    let token = ferrum::admin::migration::read_control_token(&gateway.admin_state_dir)
        .expect("protected local metrics token");
    client
        .get(admin_url(gateway, "/metrics"))
        .bearer_auth(token)
        .send()
        .await
        .expect("metrics response")
        .text()
        .await
        .expect("metrics text")
}

async fn wait_metric(client: &Client, gateway: &RunningGateway, line: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if metrics(client, gateway)
                .await
                .lines()
                .any(|value| value == line)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("metric reached expected value");
}

#[tokio::test]
async fn corrupt_first_and_final_bytes_never_reach_clients_or_cache() {
    for offset in [0, 1_065_151] {
        let harness = Harness::new("").await;
        harness.fault(LARGE_PACKAGE, FaultKind::Corrupt { offset }, None);
        let response = harness
            .client
            .get(url(&harness.gateway, LARGE_PACKAGE))
            .header("Range", "bytes=0-0")
            .send()
            .await
            .expect("corrupt response");
        empty_error(response, StatusCode::BAD_GATEWAY).await;
        assert_eq!(origin_gets(&harness.origin, LARGE_PACKAGE).len(), 1);
        let etag = format!("\"sha256-{}\"", harness.packages[1].identity.sha256);
        let response = harness
            .client
            .get(url(&harness.gateway, LARGE_PACKAGE))
            .header("If-None-Match", etag)
            .send()
            .await
            .expect("known failure conditional");
        empty_error(response, StatusCode::BAD_GATEWAY).await;
        assert_eq!(
            origin_gets(&harness.origin, LARGE_PACKAGE).len(),
            1,
            "failure backoff must not refetch"
        );
        let text = metrics(&harness.client, &harness.gateway).await;
        assert!(text.contains("ferrum_spool_bytes{state=\"installed\"} 0"));
        wait_metric(
            &harness.client,
            &harness.gateway,
            "ferrum_spool_bytes{state=\"reserved\"} 0",
        )
        .await;
        harness.stop().await;
    }
}

#[tokio::test]
async fn verified_warm_hit_needs_no_running_origin() {
    let harness = Harness::new("").await;
    let response = harness
        .client
        .get(url(&harness.gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("cold response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["etag"],
        format!("\"sha256-{}\"", harness.packages[0].identity.sha256)
    );
    assert_eq!(
        response.bytes().await.expect("cold body").as_ref(),
        harness.packages[0].bytes
    );
    assert_eq!(origin_gets(&harness.origin, SMALL_PACKAGE).len(), 1);
    harness.origin.shutdown().await;
    let response = harness
        .client
        .get(url(&harness.gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("warm response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("warm body").as_ref(),
        harness.packages[0].bytes
    );
    harness.gateway.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_four_callers_share_one_fill_and_disconnects_detach_only_readers() {
    let harness = Harness::new("").await;
    harness.fault(
        LARGE_PACKAGE,
        FaultKind::Pace {
            chunk: 32_768,
            interval_ms: 100,
        },
        None,
    );
    // Eight loopback source addresses exercise the global64/object bound without
    // bypassing the production limit of16 cold requests per source address.
    let clients: Vec<_> = (2..10)
        .map(|last| {
            Client::builder()
                .no_proxy()
                .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    127, 0, 0, last,
                )))
                .build()
                .expect("bound client")
        })
        .collect();
    let barrier = Arc::new(Barrier::new(65));
    let mut tasks = Vec::new();
    for index in 0..64 {
        let client = clients[index / 8].clone();
        let barrier = Arc::clone(&barrier);
        let address = url(&harness.gateway, LARGE_PACKAGE);
        let authority = harness.gateway.public_addr;
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let request = client.get(address);
            let request = if index % 3 == 0 {
                request.header("Range", "bytes=0-0")
            } else {
                request
            };
            if index < 8 {
                let socket = tokio::net::TcpSocket::new_v4().expect("disconnect socket");
                socket
                    .bind("127.0.0.2:0".parse().expect("source address"))
                    .expect("bind source");
                let mut stream = socket.connect(authority).await.expect("connect gateway");
                stream
                    .write_all(format!("GET /fixture/{LARGE_PACKAGE} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n").as_bytes())
                    .await
                    .expect("send cold request");
                let result = std::future::pending::<(usize, StatusCode, bytes::Bytes)>().await;
                drop(stream);
                return result;
            }
            let response = request.send().await.expect("shared response");
            let status = response.status();
            (index, status, response.bytes().await.expect("shared body"))
        }));
    }
    barrier.wait().await;
    wait_metric(&harness.client, &harness.gateway, "ferrum_fill_waiters 64").await;
    empty_error(
        harness
            .client
            .get(url(&harness.gateway, LARGE_PACKAGE))
            .send()
            .await
            .expect("65th waiter"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    for task in tasks.iter().take(8) {
        task.abort();
    }
    wait_metric(&harness.client, &harness.gateway, "ferrum_fill_waiters 56").await;
    for (index, task) in tasks.into_iter().enumerate() {
        if index < 8 {
            assert!(task.await.expect_err("disconnected caller").is_cancelled());
            continue;
        }
        let (index, status, bytes) = task.await.expect("caller task");
        if index % 3 == 0 {
            assert_eq!(status, StatusCode::PARTIAL_CONTENT);
            assert_eq!(bytes.as_ref(), &harness.packages[1].bytes[..1]);
        } else {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(bytes.as_ref(), harness.packages[1].bytes);
        }
    }
    wait_metric(&harness.client, &harness.gateway, "ferrum_fill_waiters 0").await;
    assert_eq!(origin_gets(&harness.origin, LARGE_PACKAGE).len(), 1);
    harness.stop().await;
}

#[tokio::test]
async fn actual_thirty_second_wait_times_out_while_the_admitted_producer_continues() {
    let harness = Harness::new("").await;
    harness.fault(
        LARGE_PACKAGE,
        FaultKind::Pace {
            chunk: 65_536,
            interval_ms: 2_000,
        },
        None,
    );
    let started = Instant::now();
    let response = harness
        .client
        .get(url(&harness.gateway, LARGE_PACKAGE))
        .header("Range", "bytes=0-0")
        .send()
        .await
        .expect("bounded waiter");
    empty_error(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert!(started.elapsed() >= Duration::from_secs(29));
    assert!(started.elapsed() < Duration::from_secs(34));
    wait_metric(&harness.client, &harness.gateway, "ferrum_fill_waiters 0").await;
    let response = harness
        .client
        .get(url(&harness.gateway, LARGE_PACKAGE))
        .header("Range", "bytes=0-0")
        .send()
        .await
        .expect("same-flight retry");
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.bytes().await.expect("verified range").as_ref(),
        &harness.packages[1].bytes[..1]
    );
    assert_eq!(origin_gets(&harness.origin, LARGE_PACKAGE).len(), 1);
    harness.stop().await;
}

#[tokio::test]
async fn source_truncation_retries_from_zero_without_splicing() {
    let harness = Harness::new("").await;
    harness.fault(LARGE_PACKAGE, FaultKind::Truncate { at: 80_000 }, Some(1));
    let response = harness
        .client
        .get(url(&harness.gateway, LARGE_PACKAGE))
        .send()
        .await
        .expect("retry response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("retried body").as_ref(),
        harness.packages[1].bytes
    );
    let requests = origin_gets(&harness.origin, LARGE_PACKAGE);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].bytes_sent, 80_000);
    assert_eq!(requests[1].bytes_sent, harness.packages[1].identity.size);
    assert!(
        requests.iter().all(|request| request.range.is_none()),
        "retry must fetch from zero"
    );
    harness.stop().await;
}

#[tokio::test]
async fn exhausted_source_attempts_wake_every_waiter_and_release_reservations() {
    let harness = Harness::new("").await;
    harness.fault(LARGE_PACKAGE, FaultKind::Truncate { at: 80_000 }, None);
    let barrier = Arc::new(Barrier::new(17));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let client = harness.client.clone();
        let address = url(&harness.gateway, LARGE_PACKAGE);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            empty_error(
                client.get(address).send().await.expect("failure response"),
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await;
        }));
    }
    barrier.wait().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        for task in tasks {
            task.await.expect("failed waiter wakes");
        }
    })
    .await
    .expect("all failures delivered before waiter timeout");
    assert_eq!(origin_gets(&harness.origin, LARGE_PACKAGE).len(), 2);
    wait_metric(&harness.client, &harness.gateway, "ferrum_fill_waiters 0").await;
    let text = metrics(&harness.client, &harness.gateway).await;
    assert!(text.contains("ferrum_spool_bytes{state=\"installed\"} 0"));
    assert!(text.contains("ferrum_spool_bytes{state=\"reserved\"} 0"));
    harness.stop().await;
}

#[tokio::test]
async fn unknown_paths_and_unauthorized_by_hash_never_fetch() {
    let harness = Harness::new("").await;
    for relative in [
        "pool/not-catalogued.deb".to_owned(),
        "dists/ferrum-test/main/binary-amd64/Packages.diff/Index".to_owned(),
        format!(
            "dists/ferrum-test/main/binary-amd64/by-hash/SHA256/{}",
            harness.packages[0].identity.sha256
        ),
        "pool%2fsecret.deb".to_owned(),
    ] {
        empty_error(
            harness
                .client
                .get(url(&harness.gateway, &relative))
                .send()
                .await
                .expect("unknown response"),
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    empty_error(
        harness
            .client
            .get(url(&harness.gateway, SMALL_PACKAGE))
            .header("Host", "attacker.invalid")
            .send()
            .await
            .expect("host rejection"),
        StatusCode::BAD_REQUEST,
    )
    .await;
    empty_error(
        harness
            .client
            .get(format!("{}?bypass=1", url(&harness.gateway, SMALL_PACKAGE)))
            .send()
            .await
            .expect("query rejection"),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let response = harness
        .client
        .post(url(&harness.gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("method rejection");
    assert_eq!(response.headers()["allow"], "GET, HEAD");
    empty_error(response, StatusCode::METHOD_NOT_ALLOWED).await;
    assert_eq!(origin_request_count(&harness.origin), 0);
    harness.stop().await;
}

#[tokio::test]
async fn head_and_descriptor_preconditions_do_not_enqueue_a_fill() {
    let harness = Harness::new("").await;
    let etag = format!("\"sha256-{}\"", harness.packages[0].identity.sha256);
    let address = url(&harness.gateway, SMALL_PACKAGE);
    let response = harness
        .client
        .get(&address)
        .header("If-None-Match", format!("W/{etag}"))
        .header("Range", "bytes=0-0")
        .send()
        .await
        .expect("descriptor304");
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert!(response.bytes().await.expect("304 body").is_empty());
    empty_error(
        harness
            .client
            .get(&address)
            .header("If-Match", "\"wrong\"")
            .header("If-None-Match", &etag)
            .send()
            .await
            .expect("precedence412"),
        StatusCode::PRECONDITION_FAILED,
    )
    .await;
    assert_eq!(origin_request_count(&harness.origin), 0);
    let response = harness
        .client
        .head(&address)
        .header("Range", "bytes=0-0")
        .send()
        .await
        .expect("cold HEAD");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-length"],
        harness.packages[0].identity.size.to_string()
    );
    assert!(response.headers().get("content-range").is_none());
    assert!(response.bytes().await.expect("HEAD body").is_empty());
    assert!(origin_gets(&harness.origin, SMALL_PACKAGE).is_empty());
    harness.origin.origin().set_head_enabled(false);
    empty_error(
        harness
            .client
            .head(&address)
            .send()
            .await
            .expect("unsupported HEAD"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert!(origin_gets(&harness.origin, SMALL_PACKAGE).is_empty());
    let response = harness
        .client
        .get(&address)
        .send()
        .await
        .expect("GET remains supported");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.bytes().await.expect("GET body").as_ref(),
        harness.packages[0].bytes
    );
    harness.stop().await;
}

#[tokio::test]
async fn cold_and_warm_ranges_and_repeated_preconditions_follow_rfc9110() {
    let harness = Harness::new("").await;
    let address = url(&harness.gateway, SMALL_PACKAGE);
    let expected = &harness.packages[0].bytes;
    let etag = format!("\"sha256-{}\"", harness.packages[0].identity.sha256);
    for (range, status, slice) in [
        ("bytes=0-0", StatusCode::PARTIAL_CONTENT, &expected[..1]),
        ("bytes=680-", StatusCode::PARTIAL_CONTENT, &expected[680..]),
        ("bytes=-2", StatusCode::PARTIAL_CONTENT, &expected[680..]),
        (
            "bytes=680-999",
            StatusCode::PARTIAL_CONTENT,
            &expected[680..],
        ),
        ("bytes=0-0,2-3", StatusCode::OK, expected.as_slice()),
        ("items=0-0", StatusCode::OK, expected.as_slice()),
        (
            "bytes=18446744073709551616-",
            StatusCode::OK,
            expected.as_slice(),
        ),
    ] {
        let response = harness
            .client
            .get(&address)
            .header("Range", range)
            .send()
            .await
            .expect("range response");
        assert_eq!(response.status(), status, "{range}");
        assert_eq!(response.headers()["accept-ranges"], "bytes");
        assert_eq!(
            response.headers()["content-length"],
            slice.len().to_string()
        );
        if range == "bytes=0-0" {
            assert_eq!(response.headers()["content-range"], "bytes 0-0/682");
        }
        assert_eq!(response.bytes().await.expect("range body").as_ref(), slice);
    }
    for range in ["bytes=682-", "bytes=-0"] {
        let response = harness
            .client
            .get(&address)
            .header("Range", range)
            .send()
            .await
            .expect("unsatisfiable range");
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers()["content-range"], "bytes */682");
        assert!(response.bytes().await.expect("416 body").is_empty());
    }
    for if_range in [
        etag.clone(),
        format!("W/{etag}"),
        "\"other\"".to_owned(),
        "Sat, 17 Oct 2026 00:00:00 GMT".to_owned(),
    ] {
        let response = harness
            .client
            .get(&address)
            .header("Range", "bytes=0-0")
            .header("If-Range", &if_range)
            .send()
            .await
            .expect("If-Range");
        let partial = if_range == etag;
        assert_eq!(
            response.status(),
            if partial {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            }
        );
        assert_eq!(
            response.bytes().await.expect("If-Range body").as_ref(),
            if partial { &expected[..1] } else { expected }
        );
    }
    let response = harness
        .client
        .get(&address)
        .header("If-Match", "\"other\"")
        .header("If-Match", &etag)
        .header("Range", "bytes=0-0")
        .header("Range", "bytes=2-3")
        .send()
        .await
        .expect("repeated headers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .bytes()
            .await
            .expect("full multi-field range")
            .as_ref(),
        expected
    );
    let response = harness
        .client
        .get(&address)
        .header("If-None-Match", "\"other\"")
        .header("If-None-Match", &etag)
        .send()
        .await
        .expect("repeated If-None-Match");
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(origin_gets(&harness.origin, SMALL_PACKAGE).len(), 1);
    harness.stop().await;
}

#[tokio::test]
async fn restart_discards_verified_files_and_old_authority() {
    let harness = Harness::new("").await;
    let response = harness
        .client
        .get(url(&harness.gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("initial fill");
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.expect("body");
    let config = config(
        &harness.directory.path().join("work"),
        &harness.origin,
        &harness.directory.path().join("unused.gpg"),
        "",
    );
    harness.gateway.shutdown().await.expect("first shutdown");
    harness.origin.shutdown().await;
    let gateway = app::start_with_view(config, None, CancellationToken::new())
        .await
        .expect("restart without view");
    empty_error(
        harness
            .client
            .get(url(&gateway, SMALL_PACKAGE))
            .send()
            .await
            .expect("no authority"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(
        harness
            .client
            .get(admin_url(&gateway, "/readyz"))
            .send()
            .await
            .expect("readiness")
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let text = metrics(&harness.client, &gateway).await;
    assert!(text.contains("ferrum_spool_bytes{state=\"installed\"} 0"));
    gateway.shutdown().await.expect("restart shutdown");
}

#[tokio::test]
async fn producer_deadline_wakes_waiters_before_their_timeout() {
    let harness = Harness::new("producer_deadline_seconds = 1").await;
    harness.fault(
        LARGE_PACKAGE,
        FaultKind::Pace {
            chunk: 65_536,
            interval_ms: 200,
        },
        None,
    );
    let client = harness.client.clone();
    let address = url(&harness.gateway, LARGE_PACKAGE);
    let waiter =
        tokio::spawn(async move { client.get(address).send().await.expect("terminated fill") });
    wait_metric(&harness.client, &harness.gateway, "ferrum_fill_waiters 1").await;
    let response = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("producer deadline")
        .expect("waiter task");
    empty_error(response, StatusCode::SERVICE_UNAVAILABLE).await;
    harness.stop().await;
}

#[tokio::test]
async fn shutdown_drains_an_admitted_fill_to_its_verified_response() {
    let harness = Harness::new("").await;
    harness.fault(
        LARGE_PACKAGE,
        FaultKind::Pace {
            chunk: 65_536,
            interval_ms: 200,
        },
        None,
    );
    let client = harness.client.clone();
    let address = url(&harness.gateway, LARGE_PACKAGE);
    let waiter = tokio::spawn(async move {
        let response = client.get(address).send().await.expect("draining response");
        let status = response.status();
        (
            status,
            response.bytes().await.expect("complete draining body"),
        )
    });
    wait_metric(&harness.client, &harness.gateway, "ferrum_fill_waiters 1").await;
    let (stopped, response) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(harness.gateway.shutdown(), waiter)
    })
    .await
    .expect("admitted response drains within shutdown window");
    stopped.expect("gateway shutdown");
    let (status, body) = response.expect("waiter task");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), harness.packages[1].bytes.as_slice());
    assert_eq!(origin_gets(&harness.origin, LARGE_PACKAGE).len(), 1);
    harness.origin.shutdown().await;
}

#[tokio::test]
async fn cold_unsatisfiable_range_still_verifies_and_zero_length_ignores_range() {
    let mut harness = Harness::new("").await;
    harness.fault(SMALL_PACKAGE, FaultKind::Corrupt { offset: 681 }, None);
    empty_error(
        harness
            .client
            .get(url(&harness.gateway, SMALL_PACKAGE))
            .header("Range", "bytes=99999-")
            .send()
            .await
            .expect("cold invalid range"),
        StatusCode::BAD_GATEWAY,
    )
    .await;
    assert_eq!(origin_gets(&harness.origin, SMALL_PACKAGE).len(), 1);
    harness.gateway.shutdown().await.expect("first shutdown");
    harness.origin.origin().faults().clear();
    std::fs::write(
        harness.directory.path().join("origin").join(SMALL_PACKAGE),
        [],
    )
    .expect("empty object");
    harness.packages[0].bytes.clear();
    harness.packages[0].identity = ferrum_apt::digest::ObjectIdentity {
        sha256: ferrum_apt::digest::Sha256Digest::of(&[]),
        size: 0,
    };
    let config = config(
        &harness.directory.path().join("work"),
        &harness.origin,
        &harness.directory.path().join("unused.gpg"),
        "",
    );
    harness.gateway = start_gateway(config, &harness.packages).await;
    let response = harness
        .client
        .get(url(&harness.gateway, SMALL_PACKAGE))
        .header("Range", "bytes=0-0")
        .send()
        .await
        .expect("zero-length response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-length"], "0");
    assert!(response.headers().get("content-range").is_none());
    assert!(response.bytes().await.expect("empty body").is_empty());
    harness.stop().await;
}

#[tokio::test]
async fn byte_ceiling_refuses_cold_fill_before_any_origin_fetch() {
    let harness = Harness::new("managed_ceiling_bytes = 1024\nmax_object_bytes = 1024").await;
    empty_error(
        harness
            .client
            .get(url(&harness.gateway, LARGE_PACKAGE))
            .send()
            .await
            .expect("admission response"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(origin_request_count(&harness.origin), 0);
    harness.stop().await;
}

#[tokio::test]
async fn seventeenth_cold_request_from_one_ip_is_rejected_without_duplicate_fetch() {
    let harness = Harness::new("").await;
    harness.fault(
        LARGE_PACKAGE,
        FaultKind::Pace {
            chunk: 32_768,
            interval_ms: 100,
        },
        None,
    );
    let mut waiters = Vec::new();
    for _ in 0..16 {
        let client = harness.client.clone();
        let address = url(&harness.gateway, LARGE_PACKAGE);
        waiters.push(tokio::spawn(async move {
            let response = client.get(address).send().await.expect("admitted waiter");
            assert_eq!(response.status(), StatusCode::OK);
            response.bytes().await.expect("verified body")
        }));
    }
    wait_metric(&harness.client, &harness.gateway, "ferrum_fill_waiters 16").await;
    empty_error(
        harness
            .client
            .get(url(&harness.gateway, LARGE_PACKAGE))
            .send()
            .await
            .expect("IP admission"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    for waiter in waiters {
        assert_eq!(
            waiter.await.expect("waiter task").as_ref(),
            harness.packages[1].bytes
        );
    }
    assert_eq!(origin_gets(&harness.origin, LARGE_PACKAGE).len(), 1);
    harness.stop().await;
}
