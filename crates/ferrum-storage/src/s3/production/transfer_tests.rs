#![allow(clippy::expect_used, clippy::panic)]

use super::*;
use crate::{capture::tests as capture_test, recovery::test_support};
use aws_smithy_runtime_api::client::{
    http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
        SharedHttpConnector,
    },
    orchestrator::HttpRequest,
    result::ConnectorError,
    runtime_components::RuntimeComponents,
};
use aws_smithy_runtime_api::http::{Response, StatusCode};
use aws_smithy_types::body::SdkBody;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn verified_fetch_rejects_corruption_even_when_the_object_is_local() {
    for bytes in [b"changed".as_slice(), b"pack", b"packages"] {
        let root = tempfile::tempdir().expect("fixture directory");
        let spool = test_support::open_spool(&root.path().join("state"));
        let object = capture_test::install(&spool, b"package").await;
        let identity = object.identity();
        let mut response = capture_test::response("GET", 200, bytes);
        response.content_length = identity.size;
        let (manager, _, requests) = capture_test::setup(spool.clone(), vec![response]);
        let result = manager
            .store()
            .fetch_verified(
                &spool,
                identity,
                Instant::now() + Duration::from_secs(10),
                CancellationToken::new(),
            )
            .await;
        assert!(matches!(result, Err(FetchError::S3(S3Error::Corrupt))));
        assert!(manager.store().is_quarantined(identity));
        assert_eq!(requests.snapshot().expect("requests"), ["GET"]);
        assert_eq!(
            object.read_bounded(7).await.expect("local bytes"),
            b"package"
        );
    }
}

#[tokio::test]
async fn verified_fetch_cannot_cross_store_identity_operation_or_spool() {
    for rejection in 0..4 {
        let root = tempfile::tempdir().expect("fixture directory");
        let spool = test_support::open_spool(&root.path().join("state"));
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(b"package"),
            size: 7,
        };
        let (manager, ledger, requests) = capture_test::setup(
            spool.clone(),
            vec![capture_test::response("GET", 200, b"package")],
        );
        let (_, mut fetched) = manager
            .store()
            .fetch_verified(
                &spool,
                identity,
                Instant::now() + Duration::from_secs(10),
                CancellationToken::new(),
            )
            .await
            .expect("fresh verified transfer");
        let (other, other_requests) =
            S3Store::scripted_production(capture_test::config(&spool), ledger, Vec::new())
                .expect("second adapter");
        let other_spool = test_support::open_spool(&root.path().join("other"));
        let mut expected = identity;
        if rejection == 1 {
            expected.sha256 = Sha256Digest::of(b"another");
        }
        if rejection == 2 {
            // Only this child test can alter the private capability field.
            fetched.operation = OperationIdentity::Checkpoint;
        }
        let store = if rejection == 0 {
            &other
        } else {
            manager.store().as_ref()
        };
        let owner = if rejection == 3 { &other_spool } else { &spool };
        assert_eq!(
            fetched.consume(store, owner, expected),
            Err(S3Error::Boundary)
        );
        assert_eq!(requests.snapshot().expect("requests"), ["GET"]);
        assert!(
            other_requests
                .snapshot()
                .expect("other requests")
                .is_empty()
        );
    }
}

#[derive(Default, Debug)]
struct WindowState {
    active: AtomicUsize,
    maximum: AtomicUsize,
    starts: Mutex<Vec<usize>>,
    finishes: Mutex<Vec<usize>>,
    third_started: tokio::sync::Notify,
    slots: Mutex<Option<Arc<Semaphore>>>,
    completion: Mutex<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct WindowRemote(Arc<WindowState>);

impl HttpClient for WindowRemote {
    fn http_connector(
        &self,
        _: &HttpConnectorSettings,
        _: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}

impl HttpConnector for WindowRemote {
    fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
        let state = self.0.clone();
        HttpConnectorFuture::new(async move {
            let uri = url::Url::parse(request.uri()).expect("SDK URI");
            let number = uri
                .query_pairs()
                .find(|(key, _)| key == "partNumber")
                .map(|(_, value)| value.parse::<usize>().expect("part number"));
            let (status, bytes): (u16, &[u8]) = match request.method() {
                "GET" => (404, b"<Error><Code>NoSuchKey</Code></Error>"),
                "POST" if uri.query_pairs().any(|(key, _)| key == "uploads") => (
                    200,
                    b"<InitiateMultipartUploadResult><UploadId>rolling</UploadId></InitiateMultipartUploadResult>",
                ),
                "PUT" => {
                    let number = number.expect("numbered upload part");
                    let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
                    state.maximum.fetch_max(active, Ordering::SeqCst);
                    state.starts.lock().expect("starts").push(number);
                    let available = state
                        .slots
                        .lock()
                        .expect("slots")
                        .as_ref()
                        .expect("shared slots")
                        .available_permits();
                    assert!(available <= 14 - active);
                    let mut body = ByteStream::new(request.take_body());
                    let mut size = 0u64;
                    while let Some(bytes) = body.next().await {
                        let bytes = bytes.expect("owned part body");
                        assert!(bytes.len() <= CHUNK);
                        size += bytes.len() as u64;
                    }
                    assert_eq!(
                        size,
                        if number == 4 {
                            1024 * 1024
                        } else {
                            16 * 1024 * 1024
                        }
                    );
                    if number == 1 {
                        state.third_started.notified().await;
                    } else if number == 3 {
                        state.third_started.notify_one();
                    }
                    state.finishes.lock().expect("finishes").push(number);
                    state.active.fetch_sub(1, Ordering::SeqCst);
                    (200, b"")
                }
                "POST" => {
                    let mut body = ByteStream::new(request.take_body());
                    while let Some(bytes) = body.next().await {
                        let bytes = bytes.expect("completion body");
                        let mut completion = state.completion.lock().expect("completion");
                        assert!(completion.len() + bytes.len() <= 16 * 1024);
                        completion.extend_from_slice(&bytes);
                    }
                    (
                        200,
                        b"<CompleteMultipartUploadResult><ETag>complete</ETag></CompleteMultipartUploadResult>",
                    )
                }
                method => panic!("unexpected method {method}"),
            };
            let mut response = Response::new(
                StatusCode::try_from(status).expect("status"),
                SdkBody::from(bytes),
            );
            response
                .headers_mut()
                .insert("content-length", bytes.len().to_string());
            response.headers_mut().insert("etag", "\"part\"");
            response
                .headers_mut()
                .insert("content-type", "application/xml");
            Ok(response)
        })
    }
}

#[tokio::test]
async fn multipart_refills_the_free_slot_and_keeps_completion_order() {
    let root = tempfile::tempdir().expect("fixture directory");
    let spool = test_support::open_spool(&root.path().join("state"));
    let size = 49 * 1024 * 1024;
    let zero = Bytes::from(vec![0u8; 256 * 1024]);
    let mut hash = Sha256Hasher::new();
    for _ in 0..size / zero.len() as u64 {
        hash.update(&zero);
    }
    let identity = ObjectIdentity {
        sha256: hash.finalize(),
        size,
    };
    let reservation = spool.reserve(size).expect("reserve object");
    let mut writer = spool
        .begin_write(reservation, identity)
        .await
        .expect("writer");
    for _ in 0..size / zero.len() as u64 {
        writer.write(zero.clone()).await.expect("write object");
    }
    let object = writer.commit().await.expect("verified object");
    let ledger = BudgetLedger::initialize(spool.clone(), capture_test::limits()).expect("ledger");
    let state = Arc::new(WindowState::default());
    let adapter = S3Store::scripted(
        capture_test::config(&spool),
        ledger.clone(),
        SharedHttpClient::new(WindowRemote(state.clone())),
    )
    .expect("scripted adapter");
    let store = adapter.production().expect("production mode");
    *state.slots.lock().expect("slots") = Some(store.data.clone());
    let key = store.object_key(identity);
    ledger
        .reserve_storage(&key, size, BudgetClass::Package)
        .expect("storage budget");
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(20),
        store.multipart(
            &object,
            &key,
            BudgetClass::Package,
            Instant::now() + Duration::from_secs(30),
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("part 3 must start while part 1 waits; paired scheduling deadlocks");
    // Deliberately absent readback cannot grant durability, even after completion.
    assert_eq!(outcome, Err(S3Error::NotFound));
    assert_eq!(state.maximum.load(Ordering::SeqCst), 2);
    assert_eq!(*state.starts.lock().expect("starts"), [1, 2, 3, 4]);
    let finishes = state.finishes.lock().expect("finishes");
    assert!(
        finishes.iter().position(|number| *number == 2)
            < finishes.iter().position(|number| *number == 1)
    );
    let completion =
        String::from_utf8(state.completion.lock().expect("completion").clone()).expect("XML");
    let mut previous = 0;
    for number in 1..=4 {
        let position = completion
            .find(&format!("<PartNumber>{number}</PartNumber>"))
            .expect("ordered part");
        assert!(position > previous);
        previous = position;
    }
    let retained = spool
        .durable_catalog()
        .expect("catalog")
        .read(move |connection| {
            Ok(connection.query_row(
                "SELECT upload_id,completing,uploaded_bytes FROM multipart_uploads WHERE key=?1",
                [key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )?)
        })
        .expect("retained completion");
    assert_eq!(retained, ("rolling".into(), true, size as i64));
    eprintln!(
        "rolling window: parts=4 maximum_active=2 elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

#[derive(Debug, Default)]
struct FailureState {
    starts: Mutex<Vec<usize>>,
    second_started: tokio::sync::Notify,
    first_failed: tokio::sync::Notify,
    release: tokio::sync::Notify,
    accepted: AtomicUsize,
    aborts: AtomicUsize,
}

#[derive(Clone, Debug)]
struct FailureRemote(Arc<FailureState>);

impl HttpClient for FailureRemote {
    fn http_connector(
        &self,
        _: &HttpConnectorSettings,
        _: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}

impl HttpConnector for FailureRemote {
    fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
        let state = self.0.clone();
        HttpConnectorFuture::new(async move {
            let uri = url::Url::parse(request.uri()).expect("SDK URI");
            let (status, bytes): (u16, &[u8]) = match request.method() {
                "GET" => (404, b"<Error><Code>NoSuchKey</Code></Error>"),
                "POST" if uri.query_pairs().any(|(key, _)| key == "uploads") => (
                    200,
                    b"<InitiateMultipartUploadResult><UploadId>uncertain</UploadId></InitiateMultipartUploadResult>",
                ),
                "PUT" => {
                    let number = uri
                        .query_pairs()
                        .find(|(key, _)| key == "partNumber")
                        .expect("part number")
                        .1
                        .parse::<usize>()
                        .expect("numeric part");
                    state.starts.lock().expect("starts").push(number);
                    if number == 2 {
                        state.second_started.notify_one();
                    }
                    let mut body = ByteStream::new(request.take_body());
                    let mut size = 0;
                    while let Some(bytes) = body.next().await {
                        size += bytes.expect("part body").len();
                    }
                    assert_eq!(size, 16 * 1024 * 1024);
                    match number {
                        1 => {
                            state.second_started.notified().await;
                            state.first_failed.notify_one();
                            (501, b"<Error><Code>NotImplemented</Code></Error>")
                        }
                        2 => {
                            state.release.notified().await;
                            // The provider accepted the delayed part, but its
                            // response is lost. An abort of a sibling is not
                            // positive evidence that this request stopped.
                            state.accepted.fetch_add(1, Ordering::SeqCst);
                            return Err(ConnectorError::timeout(
                                std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "accepted delayed part lost acknowledgment",
                                )
                                .into(),
                            ));
                        }
                        _ => panic!("another part started after permanent failure"),
                    }
                }
                "DELETE" => {
                    state.aborts.fetch_add(1, Ordering::SeqCst);
                    (204, b"")
                }
                method => panic!("unexpected method {method}"),
            };
            let mut response = Response::new(
                StatusCode::try_from(status).expect("status"),
                SdkBody::from(bytes),
            );
            response
                .headers_mut()
                .insert("content-length", bytes.len().to_string());
            response
                .headers_mut()
                .insert("content-type", "application/xml");
            Ok(response)
        })
    }
}

#[tokio::test]
async fn multipart_permanent_failure_drains_uncertain_sibling_and_retains_id() {
    let root = tempfile::tempdir().expect("fixture directory");
    let spool = test_support::open_spool(&root.path().join("state"));
    let size = 33 * 1024 * 1024;
    let zero = Bytes::from(vec![0u8; CHUNK]);
    let mut hash = Sha256Hasher::new();
    for _ in 0..size / zero.len() as u64 {
        hash.update(&zero);
    }
    let identity = ObjectIdentity {
        sha256: hash.finalize(),
        size,
    };
    let reservation = spool.reserve(size).expect("reserve object");
    let mut writer = spool
        .begin_write(reservation, identity)
        .await
        .expect("writer");
    for _ in 0..size / zero.len() as u64 {
        writer.write(zero.clone()).await.expect("write object");
    }
    let object = writer.commit().await.expect("verified object");
    let ledger = BudgetLedger::initialize(spool.clone(), capture_test::limits()).expect("ledger");
    let state = Arc::new(FailureState::default());
    let adapter = Arc::new(
        S3Store::scripted(
            capture_test::config(&spool),
            ledger.clone(),
            SharedHttpClient::new(FailureRemote(state.clone())),
        )
        .expect("scripted adapter"),
    );
    let key = adapter
        .production()
        .expect("production")
        .object_key(identity);
    ledger
        .reserve_storage(&key, size, BudgetClass::Package)
        .expect("storage budget");
    let task_key = key.clone();
    let task = tokio::spawn(async move {
        adapter
            .production()
            .expect("production")
            .multipart(
                &object,
                &task_key,
                BudgetClass::Package,
                Instant::now() + Duration::from_secs(30),
                &CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(20), state.first_failed.notified())
        .await
        .expect("permanent failure after sibling starts");
    state.release.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("drained upload")
        .expect("upload task");
    assert_eq!(outcome, Err(S3Error::Unsupported));
    assert_eq!(*state.starts.lock().expect("starts"), [1, 2]);
    assert_eq!(state.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(state.aborts.load(Ordering::SeqCst), 0);
    let retained = spool
        .durable_catalog()
        .expect("catalog")
        .read(move |connection| {
            Ok(connection.query_row(
                "SELECT upload_id,completing,uploaded_bytes FROM multipart_uploads WHERE key=?1",
                [key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )?)
        })
        .expect("uncertain part retains its ID and byte liability");
    assert_eq!(retained, ("uncertain".into(), false, 32 * 1024 * 1024));
    assert_eq!(ledger.usage().expect("usage").storage, size);
}
