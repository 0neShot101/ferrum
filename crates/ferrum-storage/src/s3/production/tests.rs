#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::{
    capture::tests as capture_test, recovery::test_support, s3::testing::ScriptedResponse,
};
fn etag(mut response: ScriptedResponse) -> ScriptedResponse {
    response
        .headers
        .push(("etag".into(), "\"scripted-etag\"".into()));
    response
}

#[test]
fn explicit_provider_keeps_transport_and_namespace_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let mut config = capture_test::config(&spool);
    config.endpoint = "https://objects.example.org".into();
    config.region = "custom-region-1".into();
    config.bucket = "my-packages".into();
    config.validate().unwrap();
    for endpoint in [
        "http://objects.example.org",
        "https://127.0.0.1",
        "https://[::1]",
        "https://localhost",
        "https://objects.example.org:8443",
        "https://user:secret@objects.example.org",
        "https://objects.example.org/path",
        "https://objects.example.org?query=1",
        "https://objects.example.org#fragment",
    ] {
        let mut invalid = config.clone();
        invalid.endpoint = endpoint.into();
        assert!(invalid.validate().is_err(), "{endpoint}");
    }
    for bucket in ["", "a", "../bucket", "Bucket", "192.168.1.1", "a..b"] {
        let mut invalid = config.clone();
        invalid.bucket = bucket.into();
        assert!(invalid.validate().is_err(), "{bucket}");
    }
    let mut invalid = config.clone();
    invalid.shared_nonisolated = false;
    assert!(invalid.validate().is_err());
    invalid = config.clone();
    invalid.package_prefix = "another-prefix/".into();
    assert!(invalid.validate().is_err());
    invalid = config;
    invalid.checkpoint_prefix = "another-prefix/".into();
    assert!(invalid.validate().is_err());
}

#[tokio::test]
async fn configured_provider_reaches_signed_sdk_request_without_network() {
    use aws_smithy_runtime_api::client::{
        http::{
            HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings,
            SharedHttpClient, SharedHttpConnector,
        },
        orchestrator::HttpRequest,
        runtime_components::RuntimeComponents,
    };
    use aws_smithy_runtime_api::http::{Response, StatusCode};
    use aws_smithy_types::body::SdkBody;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone)]
    struct Target {
        calls: Arc<AtomicUsize>,
        path: String,
    }
    impl HttpClient for Target {
        fn http_connector(
            &self,
            _: &HttpConnectorSettings,
            _: &RuntimeComponents,
        ) -> SharedHttpConnector {
            SharedHttpConnector::new(self.clone())
        }
    }
    impl HttpConnector for Target {
        fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
            let target = self.clone();
            HttpConnectorFuture::new(async move {
                assert_eq!(request.method(), "HEAD");
                let uri = url::Url::parse(request.uri()).unwrap();
                assert_eq!(uri.host_str(), Some("objects.example.org"));
                assert_eq!(uri.path(), target.path);
                assert!(
                    request
                        .headers()
                        .get("authorization")
                        .unwrap()
                        .contains("/custom-region-1/s3/aws4_request")
                );
                target.calls.fetch_add(1, Ordering::SeqCst);
                let mut response =
                    Response::new(StatusCode::try_from(200).unwrap(), SdkBody::empty());
                response.headers_mut().insert("content-length", "7");
                Ok(response)
            })
        }
    }
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let ledger = BudgetLedger::initialize(spool.clone(), capture_test::limits()).unwrap();
    let mut config = capture_test::config(&spool);
    config.endpoint = "https://objects.example.org".into();
    config.region = "custom-region-1".into();
    config.bucket = "my-packages".into();
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"package"),
        size: 7,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let target = Target {
        calls: calls.clone(),
        path: format!(
            "/my-packages/linux-packages/v1/objects/sha256/{}",
            identity.sha256.to_hex()
        ),
    };
    let store = S3Store::scripted(
        config.clone(),
        ledger.clone(),
        SharedHttpClient::new(target.clone()),
    )
    .unwrap();
    store
        .head(
            identity,
            Instant::now() + Duration::from_secs(10),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for field in 0..3 {
        let mut different = config.clone();
        match field {
            0 => different.bucket = "another-bucket".into(),
            1 => different.endpoint = "https://another.example.org".into(),
            _ => different.region = "another-region".into(),
        }
        assert!(matches!(
            S3Store::open(different.clone(), ledger.clone()),
            Err(S3Error::Journal(_))
        ));
        assert!(matches!(
            S3Store::scripted(
                different.clone(),
                ledger.clone(),
                SharedHttpClient::new(target.clone()),
            ),
            Err(S3Error::Journal(_))
        ));
        let unused_root = root.path().join(format!("rejected-disk-{field}"));
        assert!(matches!(
            S3Store::disk_backed_production(
                different,
                ledger.clone(),
                unused_root.clone(),
                1024 * 1024,
            ),
            Err(S3Error::Journal(_))
        ));
        assert!(
            !unused_root.exists(),
            "mismatch must precede local provider construction"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    drop(store);
    drop(ledger);
    drop(spool);
    let reopened = test_support::open_spool(&root.path().join("state"));
    let ledger = BudgetLedger::open_for_provider(
        reopened,
        capture_test::limits(),
        &config.provider_identity(None).unwrap(),
    )
    .unwrap();
    let store = S3Store::scripted(config, ledger, SharedHttpClient::new(target)).unwrap();
    store
        .head(
            identity,
            Instant::now() + Duration::from_secs(10),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn only_authenticated_wire_no_such_key_is_a_missing_package() {
    for (status, body, expected) in [
        (
            404,
            b"<Error><Code>NoSuchKey</Code></Error>".as_slice(),
            S3Error::NotFound,
        ),
        (
            404,
            b"<html>proxy error</html>".as_slice(),
            S3Error::Unavailable,
        ),
        (
            404,
            b"<Error><Code>NoSuchBucket</Code></Error>".as_slice(),
            S3Error::Unavailable,
        ),
        (
            403,
            b"<Error><Code>AccessDenied</Code></Error>".as_slice(),
            S3Error::Forbidden,
        ),
        (
            429,
            b"<Error><Code>SlowDown</Code></Error>".as_slice(),
            S3Error::Throttled,
        ),
        (
            500,
            b"<Error><Code>InternalError</Code></Error>".as_slice(),
            S3Error::Unavailable,
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let spool = test_support::open_spool(&root.path().join("state"));
        let (manager, _, requests) =
            capture_test::setup(spool, vec![capture_test::response("GET", status, body)]);
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(b"package"),
            size: 7,
        };
        let error = match manager
            .store()
            .get(
                identity,
                Instant::now() + Duration::from_secs(10),
                CancellationToken::new(),
            )
            .await
        {
            Ok(_) => panic!("error became package bytes"),
            Err(error) => error,
        };
        assert_eq!(error, expected);
        assert!(!manager.store().is_quarantined(identity));
        assert_eq!(requests.snapshot().unwrap(), ["GET"]);
    }
}
#[tokio::test]
async fn byte_stream_errors_preserve_typed_failures_without_relabeling_transport_outages() {
    struct FailedBody(Option<aws_smithy_types::body::Error>);
    impl http_body::Body for FailedBody {
        type Data = Bytes;
        type Error = aws_smithy_types::body::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            std::task::Poll::Ready(self.0.take().map(Err))
        }
    }

    for expected in [S3Error::Corrupt, S3Error::Budget, S3Error::Boundary] {
        let mut body = ByteStream::new(aws_smithy_types::body::SdkBody::from_body_1_x(FailedBody(
            Some(expected.clone().into()),
        )));
        assert_eq!(
            classify_body_error(body.next().await.unwrap().unwrap_err()),
            expected
        );
    }

    let mut body = ByteStream::new(aws_smithy_types::body::SdkBody::from_body_1_x(FailedBody(
        Some(
            std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection reset during response",
            )
            .into(),
        ),
    )));
    assert_eq!(
        classify_body_error(body.next().await.unwrap().unwrap_err()),
        S3Error::Unavailable
    );
}

#[tokio::test]
async fn successful_truncation_and_overflow_quarantine_but_error_envelopes_do_not() {
    for truncated in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let spool = test_support::open_spool(&root.path().join("state"));
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(b"package"),
            size: 7,
        };
        let mut reply =
            capture_test::response("GET", 200, if truncated { b"pack" } else { b"packages" });
        reply.content_length = 7;
        let (manager, _, requests) = capture_test::setup(spool, vec![reply]);
        assert_eq!(
            manager
                .store()
                .verify_seed(
                    identity,
                    Instant::now() + Duration::from_secs(10),
                    CancellationToken::new()
                )
                .await,
            Err(S3Error::Corrupt)
        );
        assert!(manager.store().is_quarantined(identity));
        assert!(matches!(
            manager
                .store()
                .get(
                    identity,
                    Instant::now() + Duration::from_secs(10),
                    CancellationToken::new()
                )
                .await,
            Err(S3Error::Corrupt)
        ));
        assert_eq!(requests.snapshot().unwrap(), ["GET"]);
    }
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"package"),
        size: 7,
    };
    let (manager, _, _) = capture_test::setup(
        spool,
        vec![capture_test::response("GET", 500, &vec![b'x'; 128 * 1024])],
    );
    let result = manager
        .store()
        .get(
            identity,
            Instant::now() + Duration::from_secs(10),
            CancellationToken::new(),
        )
        .await;
    assert!(result.is_err());
    assert!(!manager.store().is_quarantined(identity));
}
#[tokio::test]
async fn versioned_or_delete_marker_404_is_not_proof_of_absence() {
    for (header, value) in [
        ("x-amz-version-id", "version-2"),
        ("x-amz-delete-marker", "true"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let spool = test_support::open_spool(&root.path().join("state"));
        let mut reply =
            capture_test::response("GET", 404, b"<Error><Code>NoSuchKey</Code></Error>");
        reply.headers.push((header.into(), value.into()));
        let (manager, _, _) = capture_test::setup(spool, vec![reply]);
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(b"package"),
            size: 7,
        };
        assert!(matches!(
            manager
                .store()
                .get(
                    identity,
                    Instant::now() + Duration::from_secs(10),
                    CancellationToken::new()
                )
                .await,
            Err(S3Error::Unsupported)
        ));
    }
}
#[tokio::test]
async fn readback_token_requires_one_full_get_for_ack_conflict_and_lost_ack() {
    for outcome in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let spool = test_support::open_spool(&root.path().join("state"));
        let object = capture_test::install(&spool, b"file backed payload").await;
        let mut put = etag(capture_test::response(
            "PUT",
            if outcome == 1 { 412 } else { 200 },
            b"",
        ));
        if outcome == 2 {
            put.lose_ack = true;
        }
        let (manager, _, requests) = capture_test::setup(
            spool,
            vec![
                put,
                etag(capture_test::response("GET", 200, b"file backed payload")),
            ],
        );
        let verified = manager
            .store()
            .put_file_verified(
                &object,
                Instant::now() + Duration::from_secs(10),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(verified.identity(), object.identity());
        assert_eq!(
            verified.key(),
            format!("linux-packages/v1/objects/sha256/{}", object.sha256())
        );
        assert!(!verified.etag().is_empty());
        assert_eq!(requests.snapshot().unwrap(), ["PUT", "GET"]);
    }
}
#[tokio::test]
async fn put_ack_and_head_metadata_never_promote_owner_durability() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let object = capture_test::install(&spool, b"not durable from metadata").await;
    let identity = object.identity();
    let mut head = etag(capture_test::response("HEAD", 200, b""));
    head.content_length = identity.size;
    let (manager, _, requests) = capture_test::setup(
        spool.clone(),
        vec![head, etag(capture_test::response("PUT", 200, b""))],
    );
    let now = now().unwrap();
    capture_test::seed_paths(&spool, identity, true, now, now + 30 * 86400);
    manager
        .store()
        .head(
            identity,
            Instant::now() + Duration::from_secs(10),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    manager
        .store()
        .put_file(
            &object,
            Instant::now() + Duration::from_secs(10),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(!manager.is_durable(identity).unwrap());
    assert_eq!(spool.reclaim(identity.size).unwrap(), 0);
    assert_eq!(requests.snapshot().unwrap(), ["HEAD", "PUT"]);
}
#[tokio::test]
async fn forbidden_circuit_survives_adapter_restart_without_another_wire_attempt() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let config = capture_test::config(&spool);
    let (manager, ledger, requests) = capture_test::setup(
        spool,
        vec![capture_test::response(
            "GET",
            403,
            b"<Error><Code>AccessDenied</Code></Error>",
        )],
    );
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"package"),
        size: 7,
    };
    assert!(matches!(
        manager
            .store()
            .get(
                identity,
                Instant::now() + Duration::from_secs(10),
                CancellationToken::new()
            )
            .await,
        Err(S3Error::Forbidden)
    ));
    drop(manager);
    let (store, restarted) = S3Store::scripted_production(config, ledger, Vec::new()).unwrap();
    assert!(matches!(
        store
            .get(
                identity,
                Instant::now() + Duration::from_secs(10),
                CancellationToken::new()
            )
            .await,
        Err(S3Error::Forbidden)
    ));
    assert_eq!(requests.snapshot().unwrap(), ["GET"]);
    assert!(restarted.snapshot().unwrap().is_empty());
}
#[tokio::test]
async fn ambiguous_multipart_completion_retains_id_and_byte_liability_until_reconciliation() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let path = root.path().join("multipart.body");
    let file = std::fs::File::create(&path).unwrap();
    let size = 33 * 1024 * 1024;
    file.set_len(size).unwrap();
    drop(file);
    let mut hash = Sha256Hasher::new();
    let zero = [0u8; 64 * 1024];
    for _ in 0..size / (zero.len() as u64) {
        hash.update(&zero);
    }
    let identity = ObjectIdentity {
        sha256: hash.finalize(),
        size,
    };
    let mut complete = capture_test::response(
        "POST",
        200,
        b"<CompleteMultipartUploadResult><ETag>completed</ETag></CompleteMultipartUploadResult>",
    );
    complete.lose_ack = true;
    let responses = vec![
        capture_test::response("GET", 404, b"<Error><Code>NoSuchKey</Code></Error>"),
        capture_test::response(
            "POST",
            200,
            b"<InitiateMultipartUploadResult><UploadId>owned-upload-1</UploadId></InitiateMultipartUploadResult>",
        ),
        etag(capture_test::response("PUT", 200, b"")),
        etag(capture_test::response("PUT", 200, b"")),
        etag(capture_test::response("PUT", 200, b"")),
        complete,
        capture_test::response("GET", 404, b"<Error><Code>NoSuchKey</Code></Error>"),
        capture_test::response("GET", 404, b"<Error><Code>NoSuchKey</Code></Error>"),
        capture_test::response("DELETE", 404, b"<Error><Code>NoSuchUpload</Code></Error>"),
        capture_test::response("GET", 404, b"<Error><Code>NoSuchKey</Code></Error>"),
        capture_test::response(
            "POST",
            200,
            b"<InitiateMultipartUploadResult><UploadId>owned-upload-2</UploadId></InitiateMultipartUploadResult>",
        ),
        capture_test::response("PUT", 500, b"<Error><Code>InternalError</Code></Error>"),
        etag(capture_test::response("PUT", 200, b"")),
    ];
    let (manager, ledger, requests) = capture_test::setup(spool.clone(), responses);
    let store = manager.store().production().unwrap();
    let key = store.object_key(identity);
    ledger
        .reserve_storage(&key, size, BudgetClass::Package)
        .unwrap();
    let object = UploadFile {
        path: &path,
        identity,
    };
    assert_eq!(
        store
            .multipart(
                &object,
                &key,
                BudgetClass::Package,
                Instant::now() + Duration::from_secs(60),
                &CancellationToken::new()
            )
            .await,
        Err(S3Error::NotFound)
    );
    let recorded = key.clone();
    let state = spool
        .durable_catalog()
        .unwrap()
        .read(move |connection| {
            Ok(connection.query_row(
                "SELECT upload_id,completing,uploaded_bytes FROM multipart_uploads WHERE key=?1",
                [recorded],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        crate::catalog::read_unsigned(row, 2)?,
                    ))
                },
            )?)
        })
        .unwrap();
    assert_eq!(state, ("owned-upload-1".into(), true, size));
    assert!(spool.lookup(identity).is_none());
    assert_eq!(
        store
            .multipart(
                &object,
                &key,
                BudgetClass::Package,
                Instant::now() + Duration::from_secs(60),
                &CancellationToken::new()
            )
            .await,
        Err(S3Error::Unavailable)
    );
    let state = spool
        .durable_catalog()
        .unwrap()
        .read(move |connection| {
            Ok(connection.query_row(
                "SELECT upload_id,completing,uploaded_bytes FROM multipart_uploads WHERE key=?1",
                [key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        crate::catalog::read_unsigned(row, 2)?,
                    ))
                },
            )?)
        })
        .unwrap();
    assert_eq!(state, ("owned-upload-2".into(), false, 32 * 1024 * 1024));
    assert_eq!(ledger.usage().unwrap().storage, size);
    let methods = requests.snapshot().unwrap();
    assert_eq!(
        methods,
        [
            "GET", "POST", "PUT", "PUT", "PUT", "POST", "GET", "GET", "DELETE", "GET", "POST",
            "PUT", "PUT"
        ]
    );
    let targets = requests.targets().unwrap();
    let abort = methods
        .iter()
        .zip(&targets)
        .filter(|(method, _)| method.as_str() == "DELETE")
        .map(|(_, target)| target)
        .collect::<Vec<_>>();
    assert_eq!(abort.len(), 1);
    assert!(abort[0].contains("uploadId=owned-upload-1"));
    assert!(!abort[0].contains("owned-upload-2"));
}

#[tokio::test]
async fn canonical_adapter_cannot_dispatch_after_qualification_binding() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let ledger =
        BudgetLedger::initialize(spool.clone(), crate::budget::BudgetLimits::default()).unwrap();
    let (store, requests) = S3Store::scripted_production(
        capture_test::config(&spool),
        ledger.clone(),
        vec![capture_test::response("GET", 200, b"package")],
    )
    .unwrap();
    ledger
        .initialize_qualification(crate::budget::QualificationLimits {
            upload: 64 * 1024 * 1024,
            download: 64 * 1024 * 1024,
            storage: 64 * 1024 * 1024,
        })
        .unwrap();
    ledger
        .bind_qualification("0123456789abcdef0123456789abcdef")
        .unwrap();
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"package"),
        size: 7,
    };
    assert!(
        store
            .get(
                identity,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new()
            )
            .await
            .is_err()
    );
    assert!(requests.snapshot().unwrap().is_empty());
    assert_eq!(ledger.usage().unwrap().download, 0);
    let qualification = ledger.qualification_usage().unwrap();
    assert_eq!((qualification.uploaded, qualification.downloaded), (0, 0));
}
