//! Behavioural tests against an in-process origin on ephemeral loopback ports.

#![allow(clippy::expect_used)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use ferrum_fixture_origin::faults::{FAULT_CAPACITY, MAX_FAULT_PATH_LEN};
use ferrum_fixture_origin::{LogEntry, OriginConfig, RunningOrigin, require_loopback};
use http::header::{ALLOW, CONTENT_LENGTH, CONTENT_TYPE, RANGE};
use reqwest::{Client, StatusCode};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PREFIX: &str = "/fixture/";

struct Fixture {
    running: RunningOrigin,
    root: TempDir,
    client: Client,
}

impl Fixture {
    async fn start() -> Self {
        let root = TempDir::new().expect("temporary root");
        let running = RunningOrigin::bind(OriginConfig {
            root: root.path().to_path_buf(),
            listen: loopback(),
            control: loopback(),
            prefix: PREFIX.to_owned(),
        })
        .await
        .expect("origin binds on ephemeral loopback ports");
        Self {
            running,
            root,
            client: Client::new(),
        }
    }

    fn write(&self, relative: &str, contents: &[u8]) {
        write_file(self.root.path(), relative, contents);
    }

    fn data_url(&self, relative: &str) -> String {
        format!("http://{}{PREFIX}{relative}", self.running.data_addr())
    }

    fn control_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.running.control_addr())
    }

    async fn get(&self, relative: &str) -> reqwest::Response {
        self.client
            .get(self.data_url(relative))
            .send()
            .await
            .expect("GET reaches origin")
    }

    async fn put_json(&self, path: &str, body: &serde_json::Value) -> reqwest::Response {
        self.client
            .put(self.control_url(path))
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(body).expect("serialise control body"))
            .send()
            .await
            .expect("PUT reaches control API")
    }

    async fn set_fault(&self, path: &str, body: serde_json::Value) {
        let response = self.put_json(&format!("/faults/{path}"), &body).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "fault accepted");
    }

    async fn faults(&self) -> serde_json::Value {
        let response = self
            .client
            .get(self.control_url("/faults"))
            .send()
            .await
            .expect("GET /faults");
        serde_json::from_slice(&response.bytes().await.expect("faults body")).expect("faults JSON")
    }

    async fn log(&self) -> Vec<LogEntry> {
        let response = self
            .client
            .get(self.control_url("/log"))
            .send()
            .await
            .expect("GET /log");
        serde_json::from_slice(&response.bytes().await.expect("log body")).expect("log JSON")
    }

    /// Streamed responses are logged when their body finishes; wait briefly for that.
    async fn wait_for_log(&self, expected_entries: usize) -> Vec<LogEntry> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let entries = self.log().await;
            if entries.len() >= expected_entries || Instant::now() > deadline {
                return entries;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Send a raw HTTP/1.1 request so the target reaches the server unnormalised.
    async fn raw_status(&self, target: &str) -> u16 {
        let mut stream = tokio::net::TcpStream::connect(self.running.data_addr())
            .await
            .expect("connect to data listener");
        let request = format!("GET {target} HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write raw request");
        let mut response = Vec::new();
        stream
            .take(4096)
            .read_to_end(&mut response)
            .await
            .expect("read raw response");
        let head = String::from_utf8_lossy(&response);
        head.split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status code in raw response")
    }
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback address")
}

fn write_file(root: &Path, relative: &str, contents: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent directories");
    }
    std::fs::write(path, contents).expect("write fixture file");
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from((index.wrapping_mul(31) ^ (index >> 7)) & 0xff).unwrap_or(0))
        .collect()
}

fn content_length(response: &reqwest::Response) -> u64 {
    response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .expect("Content-Length header")
}

#[tokio::test]
async fn get_and_head_serve_exact_bytes() {
    let fixture = Fixture::start().await;
    let contents = pattern(100 * 1024 + 7);
    fixture.write("pool/main/a/a_1.0_all.deb", &contents);

    let response = fixture.get("pool/main/a/a_1.0_all.deb").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(content_length(&response), contents.len() as u64);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .map(|value| value.as_bytes()),
        Some(b"application/octet-stream".as_slice())
    );
    assert_eq!(
        response.bytes().await.expect("body").as_ref(),
        contents.as_slice()
    );

    let response = fixture
        .client
        .head(fixture.data_url("pool/main/a/a_1.0_all.deb"))
        .send()
        .await
        .expect("HEAD");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(content_length(&response), contents.len() as u64);
    assert!(response.bytes().await.expect("HEAD body").is_empty());

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn range_is_ignored_and_logged() {
    let fixture = Fixture::start().await;
    let contents = pattern(4096);
    fixture.write("dists/ferrum-test/InRelease", &contents);

    let response = fixture
        .client
        .get(fixture.data_url("dists/ferrum-test/InRelease"))
        .header(RANGE, "bytes=0-9")
        .send()
        .await
        .expect("ranged GET");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.expect("body").len(), contents.len());

    let log = fixture.wait_for_log(1).await;
    let entry = log.last().expect("one log entry");
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.path, "dists/ferrum-test/InRelease");
    assert_eq!(entry.status, 200);
    assert_eq!(entry.bytes_sent, contents.len() as u64);
    assert_eq!(entry.range.as_deref(), Some("bytes=0-9"));
    assert_eq!(entry.fault, None);
    assert_eq!(entry.seq, 0);

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn invalid_paths_are_not_found_and_other_methods_are_rejected() {
    let fixture = Fixture::start().await;
    fixture.write("dir/file", b"inside");

    assert_eq!(fixture.raw_status("/fixture/../escaped-secret").await, 404);
    assert_eq!(fixture.raw_status("/fixture/dir/../dir/file").await, 404);
    assert_eq!(fixture.raw_status("/fixture/dir//file").await, 404);
    assert_eq!(fixture.raw_status("/fixture/dir/").await, 404);
    assert_eq!(fixture.raw_status("/fixture/").await, 404);
    assert_eq!(fixture.raw_status("/other/dir/file").await, 404);
    assert_eq!(fixture.raw_status("/fixture/dir%2Ffile").await, 404);
    assert_eq!(fixture.raw_status("/fixture/dir%2ffile").await, 404);
    assert_eq!(fixture.raw_status("/fixture/dir/fi%00le").await, 404);
    assert_eq!(fixture.raw_status("/fixture/dir/fi%zzle").await, 404);
    assert_eq!(
        fixture.raw_status("/fixture/dir").await,
        404,
        "directories are not files"
    );
    assert_eq!(fixture.raw_status("/fixture/dir/file").await, 200);

    #[cfg(unix)]
    {
        let outside = TempDir::new().expect("outside directory");
        std::fs::write(outside.path().join("secret"), b"outside").expect("outside file");
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            fixture.root.path().join("link"),
        )
        .expect("symlink");
        assert_eq!(
            fixture.raw_status("/fixture/link").await,
            404,
            "symlink escape"
        );
    }

    let response = fixture
        .client
        .post(fixture.data_url("dir/file"))
        .send()
        .await
        .expect("POST");
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response.headers().get(ALLOW).map(|value| value.as_bytes()),
        Some(b"GET, HEAD".as_slice())
    );

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn delay_fault_with_remaining_applies_once() {
    let fixture = Fixture::start().await;
    fixture.write("slow", b"slow body");
    fixture
        .set_fault(
            "slow",
            serde_json::json!({"kind": "delay", "ms": 300, "remaining": 1}),
        )
        .await;

    let started = Instant::now();
    let response = fixture.get("slow").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        started.elapsed() >= Duration::from_millis(300),
        "delay applied"
    );

    let started = Instant::now();
    let response = fixture.get("slow").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "fault cleared after one use"
    );
    assert_eq!(fixture.faults().await, serde_json::json!({}));

    let log = fixture.wait_for_log(2).await;
    assert_eq!(log[0].fault.as_deref(), Some("delay"));
    assert_eq!(log[1].fault, None);

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn truncate_sends_exact_prefix_then_aborts() {
    let fixture = Fixture::start().await;
    let contents = pattern(200 * 1024);
    let at = 70_000usize;
    fixture.write("pool/big.deb", &contents);
    fixture
        .set_fault(
            "pool/big.deb",
            serde_json::json!({"kind": "truncate", "at": at}),
        )
        .await;

    let mut response = fixture.get("pool/big.deb").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        content_length(&response),
        contents.len() as u64,
        "full length declared"
    );

    let mut received = Vec::new();
    let error = loop {
        match response.chunk().await {
            Ok(Some(chunk)) => received.extend_from_slice(&chunk),
            Ok(None) => break None,
            Err(error) => break Some(error),
        }
    };
    let error = error.expect("body must end with a transport error, not a clean EOF");
    assert_eq!(
        received.len(),
        at,
        "client saw exactly `at` bytes before error {error}"
    );
    assert_eq!(received.as_slice(), &contents[..at]);

    let log = fixture.wait_for_log(1).await;
    let entry = log.last().expect("truncated request logged");
    assert_eq!(entry.status, 200);
    assert_eq!(entry.bytes_sent, at as u64);
    assert_eq!(entry.fault.as_deref(), Some("truncate"));

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn corrupt_flips_exactly_one_byte() {
    let fixture = Fixture::start().await;
    let contents = pattern(100 * 1024);
    let offset = 65_540usize;
    fixture.write("pool/pkg.deb", &contents);
    fixture
        .set_fault(
            "pool/pkg.deb",
            serde_json::json!({"kind": "corrupt", "offset": offset}),
        )
        .await;

    let body = fixture
        .get("pool/pkg.deb")
        .await
        .bytes()
        .await
        .expect("body");
    assert_eq!(body.len(), contents.len());
    let differences: Vec<usize> = body
        .iter()
        .zip(contents.iter())
        .enumerate()
        .filter(|(_, (served, original))| served != original)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(differences, vec![offset]);
    assert_eq!(body[offset], contents[offset] ^ 0xFF);

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn delete_wildcard_and_clear() {
    let fixture = Fixture::start().await;
    fixture.write("a", b"a");
    fixture.write("b", b"b");
    fixture
        .set_fault("*", serde_json::json!({"kind": "delete"}))
        .await;

    assert_eq!(fixture.get("a").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(fixture.get("b").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        fixture.faults().await,
        serde_json::json!({"*": {"kind": "delete"}})
    );

    let response = fixture
        .client
        .delete(fixture.control_url("/faults"))
        .send()
        .await
        .expect("DELETE /faults");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(fixture.get("a").await.status(), StatusCode::OK);
    assert_eq!(fixture.get("b").await.status(), StatusCode::OK);

    fixture
        .set_fault("a", serde_json::json!({"kind": "delete"}))
        .await;
    assert_eq!(fixture.get("a").await.status(), StatusCode::NOT_FOUND);
    assert_eq!(fixture.get("b").await.status(), StatusCode::OK);
    let response = fixture
        .client
        .delete(fixture.control_url("/faults/a"))
        .send()
        .await
        .expect("DELETE /faults/a");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(fixture.get("a").await.status(), StatusCode::OK);

    let log = fixture.wait_for_log(7).await;
    assert_eq!(log[0].status, 404);
    assert_eq!(log[0].fault.as_deref(), Some("delete"));

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn invalid_fault_definitions_are_rejected() {
    let fixture = Fixture::start().await;

    let response = fixture
        .put_json(
            "/faults/a",
            &serde_json::json!({"kind": "pace", "chunk": 0, "interval_ms": 1}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = fixture
        .put_json(
            "/faults/a",
            &serde_json::json!({"kind": "delete", "remaining": 0}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // `..` would be normalised away by the client URL parser; empty segments and
    // trailing separators reach the server intact.
    for invalid in ["/faults/a//b", "/faults/a/"] {
        let response = fixture
            .put_json(invalid, &serde_json::json!({"kind": "delete"}))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{invalid}");
    }

    let response = fixture
        .put_json("/faults/a", &serde_json::json!({"kind": "explode"}))
        .await;
    assert_eq!(response.status().as_u16() / 100, 4);
    assert_eq!(fixture.faults().await, serde_json::json!({}));

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn fault_table_is_bounded_and_replacement_is_free() {
    let fixture = Fixture::start().await;
    let delete = serde_json::json!({"kind": "delete"});

    for index in 0..FAULT_CAPACITY {
        fixture
            .set_fault(&format!("cap/{index}"), delete.clone())
            .await;
    }
    assert_eq!(
        fixture.faults().await.as_object().map(|table| table.len()),
        Some(FAULT_CAPACITY)
    );

    let response = fixture.put_json("/faults/cap/overflow", &delete).await;
    assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.expect("error body")).expect("error JSON");
    assert_eq!(body, serde_json::json!({"error": "fault table full"}));

    // Replacing an existing path consumes no budget even when the table is full.
    fixture
        .set_fault("cap/0", serde_json::json!({"kind": "delay", "ms": 1}))
        .await;

    let too_long = format!("/faults/{}", "x".repeat(MAX_FAULT_PATH_LEN + 1));
    let response = fixture.put_json(&too_long, &delete).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn pace_streams_chunks_at_interval_after_immediate_headers() {
    let fixture = Fixture::start().await;
    let contents = pattern(8 * 1024);
    fixture.write("pool/paced.deb", &contents);
    fixture
        .set_fault(
            "pool/paced.deb",
            serde_json::json!({"kind": "pace", "chunk": 1024, "interval_ms": 50}),
        )
        .await;

    let started = Instant::now();
    let response = fixture.get("pool/paced.deb").await;
    let headers_after = started.elapsed();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(content_length(&response), contents.len() as u64);
    let body = response.bytes().await.expect("paced body");
    let total = started.elapsed();

    assert_eq!(body.as_ref(), contents.as_slice());
    assert!(
        total >= Duration::from_millis(7 * 50),
        "seven intervals elapsed: {total:?}"
    );
    assert!(
        headers_after < Duration::from_millis(7 * 50),
        "headers before body: {headers_after:?}"
    );

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn head_can_be_disabled_without_affecting_get() {
    let fixture = Fixture::start().await;
    fixture.write("file", b"contents");

    let response = fixture
        .put_json("/settings", &serde_json::json!({"head_enabled": false}))
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = fixture
        .client
        .head(fixture.data_url("file"))
        .send()
        .await
        .expect("HEAD");
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response.headers().get(ALLOW).map(|value| value.as_bytes()),
        Some(b"GET".as_slice())
    );
    assert_eq!(fixture.get("file").await.status(), StatusCode::OK);

    fixture
        .put_json("/settings", &serde_json::json!({"head_enabled": true}))
        .await;
    let response = fixture
        .client
        .head(fixture.data_url("file"))
        .send()
        .await
        .expect("HEAD");
    assert_eq!(response.status(), StatusCode::OK);

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn root_can_be_swapped_to_an_existing_directory() {
    let fixture = Fixture::start().await;
    fixture.write("only-in-first", b"first");
    let second = TempDir::new().expect("second root");
    write_file(second.path(), "only-in-second", b"second");

    let response = fixture
        .put_json("/root", &serde_json::json!({"root": second.path()}))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture.get("only-in-first").await.status(),
        StatusCode::NOT_FOUND
    );
    let response = fixture.get("only-in-second").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.expect("body").as_ref(), b"second");

    let missing = second.path().join("does-not-exist");
    let response = fixture
        .put_json("/root", &serde_json::json!({"root": missing}))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(fixture.get("only-in-second").await.status(), StatusCode::OK);

    let file_not_dir = second.path().join("only-in-second");
    let response = fixture
        .put_json("/root", &serde_json::json!({"root": file_not_dir}))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    fixture.running.shutdown().await;
}

#[tokio::test]
async fn request_log_can_be_cleared_and_healthz_answers() {
    let fixture = Fixture::start().await;
    fixture.write("file", b"contents");
    fixture.get("file").await.bytes().await.expect("body");
    assert_eq!(fixture.wait_for_log(1).await.len(), 1);

    let response = fixture
        .client
        .delete(fixture.control_url("/log"))
        .send()
        .await
        .expect("DELETE /log");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(fixture.log().await.is_empty());

    let response = fixture
        .client
        .get(fixture.control_url("/healthz"))
        .send()
        .await
        .expect("GET /healthz");
    assert_eq!(response.status(), StatusCode::OK);

    fixture.running.shutdown().await;
}

#[test]
fn non_loopback_listeners_are_refused() {
    let any_v4: SocketAddr = "0.0.0.0:0".parse().expect("address");
    let any_v6: SocketAddr = "[::]:0".parse().expect("address");
    let public: SocketAddr = "192.0.2.1:18080".parse().expect("address");
    assert!(require_loopback(any_v4).is_err());
    assert!(require_loopback(any_v6).is_err());
    assert!(require_loopback(public).is_err());
    assert!(require_loopback(loopback()).is_ok());
    assert!(require_loopback("[::1]:0".parse().expect("address")).is_ok());
}

#[tokio::test]
async fn binding_a_non_loopback_data_listener_fails() {
    let root = TempDir::new().expect("root");
    let result = RunningOrigin::bind(OriginConfig {
        root: root.path().to_path_buf(),
        listen: "0.0.0.0:0".parse().expect("address"),
        control: loopback(),
        prefix: PREFIX.to_owned(),
    })
    .await;
    assert!(result.is_err(), "non-loopback --listen must be refused");
}
