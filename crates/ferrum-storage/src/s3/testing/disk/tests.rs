#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::budget::BudgetLedger;
use crate::capture::tests as capture;
use crate::recovery::test_support;
use crate::s3::{ControlCondition, OperationIdentity};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use futures_util::StreamExt;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

fn remote(root: &std::path::Path, maximum: u64) -> DiskBackedRemote {
    DiskBackedRemote::new(
        root.join("remote"),
        maximum,
        ["linux-packages/".into(), "linux-checkpoints/".into()],
    )
    .unwrap()
}
fn client(remote: &DiskBackedRemote) -> aws_sdk_s3::Client {
    aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::v2026_01_12())
            .region(Region::new(config::REGION))
            .endpoint_url(config::ENDPOINT)
            .force_path_style(true)
            .credentials_provider(Credentials::new(
                "TESTACCESS",
                "not-a-real-secret",
                None,
                None,
                "disk-tests",
            ))
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .response_checksum_validation(
                aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
            )
            .retry_config(RetryConfig::disabled())
            .http_client(remote.clone())
            .build(),
    )
}
fn request(method: &str, suffix: &str, bytes: &'static [u8]) -> HttpRequest {
    let mut request =
        HttpRequest::get(format!("{}/{}/{suffix}", config::ENDPOINT, config::BUCKET)).unwrap();
    request.set_method(method).unwrap();
    request
        .headers_mut()
        .insert("content-length", bytes.len().to_string());
    *request.body_mut() = SdkBody::from(bytes);
    request
}
async fn put(client: &aws_sdk_s3::Client, key: &str, bytes: &'static [u8]) -> String {
    client
        .put_object()
        .bucket(config::BUCKET)
        .key(key)
        .body(ByteStream::from_static(bytes))
        .send()
        .await
        .unwrap()
        .e_tag()
        .unwrap()
        .to_owned()
}
async fn read(client: &aws_sdk_s3::Client, key: &str) -> Vec<u8> {
    let output = client
        .get_object()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    assert!(output.content_length().unwrap() <= 1024);
    output.body.collect().await.unwrap().into_bytes().to_vec()
}

#[tokio::test]
async fn sdk_put_get_head_ranges_and_exact_missing_codes() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 1024);
    let client = client(&remote);
    let key = "linux-packages/range";
    let etag = put(&client, key, b"0123456789").await;
    assert_eq!(remote.reserved_bytes(), 10);
    let head = client
        .head_object()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(10));
    assert_eq!(head.e_tag(), Some(etag.as_str()));
    for (range, expected, content_range) in [
        ("bytes=0-0", b"0".as_slice(), "bytes 0-0/10"),
        ("bytes=8-", b"89", "bytes 8-9/10"),
        ("bytes=-3", b"789", "bytes 7-9/10"),
        ("bytes=7-100", b"789", "bytes 7-9/10"),
        ("bytes=-100", b"0123456789", "bytes 0-9/10"),
    ] {
        let output = client
            .get_object()
            .bucket(config::BUCKET)
            .key(key)
            .range(range)
            .send()
            .await
            .unwrap();
        assert_eq!(output.content_length(), Some(expected.len() as i64));
        assert_eq!(output.content_range(), Some(content_range));
        assert_eq!(
            output.body.collect().await.unwrap().into_bytes().as_ref(),
            expected
        );
    }
    for range in [
        "bytes=10-",
        "bytes=-0",
        "bytes=2-1",
        "bytes=0-1,3-4",
        "bytes=18446744073709551616-",
        "items=0-1",
    ] {
        let error = client
            .get_object()
            .bucket(config::BUCKET)
            .key(key)
            .range(range)
            .send()
            .await
            .unwrap_err();
        assert_eq!(error.raw_response().unwrap().status().as_u16(), 416);
    }
    put(&client, "linux-packages/empty", b"").await;
    assert!(read(&client, "linux-packages/empty").await.is_empty());
    let missing = client
        .get_object()
        .bucket(config::BUCKET)
        .key("linux-packages/missing")
        .send()
        .await
        .unwrap_err();
    use aws_sdk_s3::error::ProvideErrorMetadata;
    assert_eq!(
        missing.as_service_error().unwrap().code(),
        Some("NoSuchKey")
    );
}

#[tokio::test]
async fn sdk_conditional_writes_have_one_winner_and_preserve_old_read_leases() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 1024);
    let client = client(&remote);
    let key = "linux-checkpoints/cas";
    let etag = put(&client, key, b"original").await;
    let old = client
        .get_object()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        client
            .put_object()
            .bucket(config::BUCKET)
            .key(key)
            .if_match(&etag)
            .body(ByteStream::from_static(b"left"))
            .send(),
        client
            .put_object()
            .bucket(config::BUCKET)
            .key(key)
            .if_match(&etag)
            .body(ByteStream::from_static(b"right"))
            .send(),
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let (winner, expected) = if left.is_ok() {
        (left.unwrap(), b"left".as_slice())
    } else {
        (right.unwrap(), b"right".as_slice())
    };
    assert_eq!(read(&client, key).await, expected);
    assert_eq!(remote.reserved_bytes(), 8 + expected.len() as u64);
    assert_eq!(
        old.body.collect().await.unwrap().into_bytes().as_ref(),
        b"original"
    );
    assert_eq!(remote.reserved_bytes(), expected.len() as u64);
    let duplicate = client
        .put_object()
        .bucket(config::BUCKET)
        .key(key)
        .if_none_match("*")
        .body(ByteStream::from_static(b"forbidden"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(duplicate.raw_response().unwrap().status().as_u16(), 412);
    let stale = client
        .delete_object()
        .bucket(config::BUCKET)
        .key(key)
        .if_match(etag)
        .send()
        .await
        .unwrap_err();
    assert_eq!(stale.raw_response().unwrap().status().as_u16(), 412);
    let leased = client
        .get_object()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    client
        .delete_object()
        .bucket(config::BUCKET)
        .key(key)
        .if_match(winner.e_tag().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(remote.reserved_bytes(), expected.len() as u64);
    drop(leased);
    assert_eq!(remote.reserved_bytes(), 0);
}

#[tokio::test]
async fn sdk_lists_real_bounded_pages_without_crossing_prefixes() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 1024);
    let client = client(&remote);
    for number in 0..65 {
        put(&client, &format!("linux-packages/item-{number:02}"), b"x").await;
    }
    put(&client, "linux-checkpoints/not-listed", b"y").await;
    let first = client
        .list_objects_v2()
        .bucket(config::BUCKET)
        .prefix("linux-packages/")
        .max_keys(64)
        .send()
        .await
        .unwrap();
    assert_eq!(first.contents().len(), 64);
    assert_eq!(first.is_truncated(), Some(true));
    let second = client
        .list_objects_v2()
        .bucket(config::BUCKET)
        .prefix("linux-packages/")
        .max_keys(64)
        .continuation_token(first.next_continuation_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(second.contents().len(), 1);
    assert_eq!(second.contents()[0].key(), Some("linux-packages/item-64"));
    assert_eq!(second.is_truncated(), Some(false));
    assert!(
        client
            .list_objects_v2()
            .bucket(config::BUCKET)
            .prefix("linux-packages/")
            .max_keys(65)
            .send()
            .await
            .is_err()
    );
    assert!(
        client
            .list_objects_v2()
            .bucket(config::BUCKET)
            .send()
            .await
            .is_err()
    );
    assert!(
        client
            .list_objects_v2()
            .bucket(config::BUCKET)
            .prefix("linux-packages/")
            .continuation_token("linux-checkpoints/not-listed")
            .send()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn sdk_multipart_lists_replaces_validates_completes_and_aborts_real_parts() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 64 * 1024 * 1024);
    let client = client(&remote);
    let key = "linux-packages/multipart";
    let created = client
        .create_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .metadata("ferrum-owner", "local-owner")
        .send()
        .await
        .unwrap();
    let id = created.upload_id().unwrap();
    let first = client
        .upload_part()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .part_number(1)
        .body(ByteStream::from(vec![b'a'; 5 * 1024 * 1024]))
        .send()
        .await
        .unwrap();
    let second = client
        .upload_part()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .part_number(2)
        .body(ByteStream::from_static(b"old"))
        .send()
        .await
        .unwrap();
    let replacement = client
        .upload_part()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .part_number(2)
        .body(ByteStream::from_static(b"tail"))
        .send()
        .await
        .unwrap();
    assert_eq!(remote.reserved_bytes(), 5 * 1024 * 1024 + 4);
    let listed = client
        .list_parts()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .max_parts(1)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.parts().len(), 1);
    assert_eq!(listed.parts()[0].size(), Some(5 * 1024 * 1024));
    assert_eq!(listed.is_truncated(), Some(true));
    let final_page = client
        .list_parts()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .max_parts(1)
        .part_number_marker("1")
        .send()
        .await
        .unwrap();
    assert_eq!(final_page.parts()[0].e_tag(), replacement.e_tag());
    let completed = |etag: &str| {
        CompletedMultipartUpload::builder()
            .parts(
                CompletedPart::builder()
                    .part_number(1)
                    .e_tag(first.e_tag().unwrap())
                    .build(),
            )
            .parts(CompletedPart::builder().part_number(2).e_tag(etag).build())
            .build()
    };
    let stale = client
        .complete_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .multipart_upload(completed(second.e_tag().unwrap()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(stale.raw_response().unwrap().status().as_u16(), 400);
    client
        .complete_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .if_none_match("*")
        .multipart_upload(completed(replacement.e_tag().unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(remote.reserved_bytes(), 5 * 1024 * 1024 + 4);
    let head = client
        .head_object()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.metadata()
            .unwrap()
            .get("ferrum-owner")
            .map(String::as_str),
        Some("local-owner")
    );
    let mut output = client
        .get_object()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    let mut offset = 0usize;
    while let Some(bytes) = output.body.next().await {
        let bytes = bytes.unwrap();
        assert!(bytes.len() <= CHUNK);
        for byte in bytes {
            assert_eq!(
                byte,
                if offset < 5 * 1024 * 1024 {
                    b'a'
                } else {
                    b"tail"[offset - 5 * 1024 * 1024]
                }
            );
            offset += 1;
        }
    }
    assert_eq!(offset, 5 * 1024 * 1024 + 4);
    let abort = client
        .abort_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .send()
        .await
        .unwrap_err();
    use aws_sdk_s3::error::ProvideErrorMetadata;
    assert_eq!(
        abort.as_service_error().unwrap().code(),
        Some("NoSuchUpload")
    );
    let mut ids = Vec::new();
    for _ in 0..3 {
        let upload = client
            .create_multipart_upload()
            .bucket(config::BUCKET)
            .key(key)
            .send()
            .await
            .unwrap();
        ids.push(upload.upload_id().unwrap().to_owned());
    }
    let uploads = client
        .list_multipart_uploads()
        .bucket(config::BUCKET)
        .prefix("linux-packages/")
        .max_uploads(2)
        .send()
        .await
        .unwrap();
    assert_eq!(uploads.uploads().len(), 2);
    assert!(uploads.uploads()[0].initiated().is_some());
    let last = client
        .list_multipart_uploads()
        .bucket(config::BUCKET)
        .prefix("linux-packages/")
        .max_uploads(2)
        .key_marker(uploads.next_key_marker().unwrap())
        .upload_id_marker(uploads.next_upload_id_marker().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(last.uploads().len(), 1);
    client
        .upload_part()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(&ids[0])
        .part_number(1)
        .body(ByteStream::from_static(b"orphan"))
        .send()
        .await
        .unwrap();
    assert_eq!(remote.reserved_bytes(), offset as u64 + 6);
    for id in ids {
        client
            .abort_multipart_upload()
            .bucket(config::BUCKET)
            .key(key)
            .upload_id(id)
            .send()
            .await
            .unwrap();
    }
    assert_eq!(remote.reserved_bytes(), offset as u64);
}

#[tokio::test]
async fn reservations_precede_body_polling_and_cancelled_writes_leave_no_object() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 6);
    let mut first = Box::pin(remote.call(request("PUT", "linux-packages/first", b"1234")));
    let waker = std::task::Waker::noop();
    let mut context = Context::from_waker(waker);
    assert!(first.as_mut().poll(&mut context).is_pending());
    assert_eq!(remote.reserved_bytes(), 4);
    assert!(
        remote
            .call(request("PUT", "linux-packages/second", b"1234"))
            .await
            .is_err()
    );
    assert_eq!(remote.reserved_bytes(), 4);
    drop(first);
    assert_eq!(remote.reserved_bytes(), 0);
    assert!(remote.state().unwrap().objects.is_empty());
    assert_eq!(
        std::fs::read_dir(root.path().join("remote"))
            .unwrap()
            .count(),
        0
    );
    let mut truncated = request("PUT", "linux-packages/truncated", b"1");
    truncated.headers_mut().insert("content-length", "2");
    assert!(remote.call(truncated).await.is_err());
    assert_eq!(remote.reserved_bytes(), 0);
    let mut excessive = request("PUT", "linux-packages/excessive", b"12");
    excessive.headers_mut().insert("content-length", "1");
    assert!(remote.call(excessive).await.is_err());
    assert_eq!(remote.reserved_bytes(), 0);
}

#[tokio::test]
async fn completion_reserves_copy_and_cancellation_preserves_parts() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 6);
    let client = client(&remote);
    let key = "linux-packages/multipart";
    let created = client
        .create_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    let id = created.upload_id().unwrap();
    let part = client
        .upload_part()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .part_number(1)
        .body(ByteStream::from_static(b"1234"))
        .send()
        .await
        .unwrap();
    let completion = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        quoted(part.e_tag().unwrap())
    );
    let target = || Target {
        key: key.into(),
        query: BTreeMap::from([("uploadId".into(), id.into())]),
        operation: "CompleteMultipartUpload",
    };
    assert!(
        remote
            .complete(
                target(),
                SdkBody::from(completion.clone()),
                Conditions::default()
            )
            .await
            .is_err()
    );
    assert_eq!(remote.reserved_bytes(), 4);
    let replacement = client
        .upload_part()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .part_number(1)
        .body(ByteStream::from_static(b"12"))
        .send()
        .await
        .unwrap();
    let completion = completion.replace(
        &quoted(part.e_tag().unwrap()),
        &quoted(replacement.e_tag().unwrap()),
    );
    let mut pending =
        Box::pin(remote.complete(target(), SdkBody::from(completion), Conditions::default()));
    assert!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    assert_eq!(remote.reserved_bytes(), 4);
    drop(pending);
    assert_eq!(remote.reserved_bytes(), 2);
    assert_eq!(
        remote.state().unwrap().uploads.get(id).unwrap().parts.len(),
        1
    );
    assert!(remote.state().unwrap().objects.is_empty());
}

#[tokio::test]
async fn endpoint_query_and_size_boundaries_fail_without_creating_data() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 1024);
    for uri in [
        "http://s3.us-central-1.idrivee2.com/s3-andrew/linux-packages/key",
        "https://example.com/s3-andrew/linux-packages/key",
        "https://s3.us-central-1.idrivee2.com/other/linux-packages/key",
        "https://s3.us-central-1.idrivee2.com/s3-andrew/unowned/key",
        "https://s3.us-central-1.idrivee2.com/s3-andrew/linux-packages/key?versionId=1",
        "https://s3.us-central-1.idrivee2.com/s3-andrew/linux-packages/key?x-id=PutObject",
        "https://s3.us-central-1.idrivee2.com/s3-andrew/linux-packages/key?x-id=GetObject&x-id=GetObject",
        "https://s3.us-central-1.idrivee2.com/s3-andrew/linux-packages/%2e%2e/unowned",
    ] {
        assert!(
            remote.call(HttpRequest::get(uri).unwrap()).await.is_err(),
            "{uri}"
        );
    }
    let mut large = request("PUT", "linux-packages/large", b"");
    large
        .headers_mut()
        .insert("content-length", (MAX_OBJECT + 1).to_string());
    assert!(remote.call(large).await.is_err());
    let mut encoded = request("PUT", "linux-packages/chunked", b"1");
    encoded
        .headers_mut()
        .insert("content-encoding", "aws-chunked");
    assert!(remote.call(encoded).await.is_err());
    assert_eq!(remote.reserved_bytes(), 0);
}

#[test]
fn completion_xml_is_strict_bounded_and_has_no_entity_expansion() {
    let valid = "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Part><ETag>&quot;abc&quot;</ETag><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>";
    assert_eq!(parse_parts(valid).unwrap(), [(1, "\"abc\"".into())]);
    for text in [
        "<CompleteMultipartUpload/>",
        "<CompleteMultipartUpload><Part><ETag>abc</ETag><PartNumber>0</PartNumber></Part></CompleteMultipartUpload>",
        "<CompleteMultipartUpload><Part><ETag>abc</ETag><PartNumber>65</PartNumber></Part></CompleteMultipartUpload>",
        "<CompleteMultipartUpload><Part><ETag>abc</ETag><ETag>def</ETag><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>",
        "<!DOCTYPE a [<!ENTITY x 'abc'>]><CompleteMultipartUpload><Part><ETag>&x;</ETag><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>",
        "<CompleteMultipartUpload><Part><ETag>abc</ETag><PartNumber>1</PartNumber></Part><Part><ETag>def</ETag><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>",
    ] {
        assert!(parse_parts(text).is_err(), "{text}");
    }
}

#[tokio::test]
async fn owned_root_is_exclusive_and_cleanup_waits_for_readers() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 1024);
    assert!(
        DiskBackedRemote::new(
            root.path().join("remote"),
            1024,
            ["linux-packages/".into(), "linux-checkpoints/".into()]
        )
        .is_err()
    );
    let client = client(&remote);
    put(&client, "linux-packages/key", b"kept").await;
    let output = client
        .get_object()
        .bucket(config::BUCKET)
        .key("linux-packages/key")
        .send()
        .await
        .unwrap();
    drop(client);
    drop(remote);
    assert!(root.path().join("remote").exists());
    assert_eq!(
        output.body.collect().await.unwrap().into_bytes().as_ref(),
        b"kept"
    );
    assert!(!root.path().join("remote").exists());
}

#[tokio::test]
async fn production_adapter_streams_above_single_put_threshold_and_uses_supplied_ledger() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let ledger = BudgetLedger::initialize(spool.clone(), capture::limits()).unwrap();
    let (store, remote) = S3Store::disk_backed_production(
        capture::config(&spool),
        ledger.clone(),
        root.path().join("remote"),
        256 * 1024 * 1024,
    )
    .unwrap();
    let chunk = Bytes::from(vec![0x5a; CHUNK]);
    let size = 65 * 1024 * 1024;
    let mut hash = Sha256Hasher::new();
    for _ in 0..size / CHUNK {
        hash.update(&chunk);
    }
    let identity = ferrum_apt::digest::ObjectIdentity {
        sha256: hash.finalize(),
        size: size as u64,
    };
    let mut writer = spool
        .begin_write(spool.reserve(identity.size).unwrap(), identity)
        .await
        .unwrap();
    for _ in 0..size / CHUNK {
        writer.write(chunk.clone()).await.unwrap();
    }
    let object = writer.commit().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    let verified = store
        .put_file_verified(&object, deadline, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(verified.identity(), identity);
    assert_eq!(remote.reserved_bytes(), identity.size);
    assert!(remote.state().unwrap().uploads.is_empty());
    let usage = ledger.usage().unwrap();
    assert!(usage.download >= identity.size);
    assert!(usage.storage >= identity.size);
    let mut response = store
        .get(identity, deadline, CancellationToken::new())
        .await
        .unwrap()
        .into_stream();
    let mut actual = Sha256Hasher::new();
    let mut count = 0;
    while let Some(bytes) = response.next().await {
        let bytes = bytes.unwrap();
        assert!(bytes.len() <= CHUNK);
        count += bytes.len();
        actual.update(&bytes);
    }
    assert_eq!(count, size);
    assert_eq!(actual.finalize(), identity.sha256);
    assert!(ledger.usage().unwrap().download >= usage.download + identity.size);
    let listed = store
        .maintenance_list(None, deadline, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        listed.keys,
        [format!(
            "linux-packages/v1/objects/sha256/{}",
            identity.sha256
        )]
    );
}

#[tokio::test]
async fn production_checkpoint_conditions_and_maintenance_do_not_bypass_accounting() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let ledger = BudgetLedger::initialize(spool.clone(), capture::limits()).unwrap();
    let (store, remote) = S3Store::disk_backed_production(
        capture::config(&spool),
        ledger.clone(),
        root.path().join("remote"),
        1024,
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let suffix = "v1/checkpoints/local/current.json";
    store
        .control_put(
            OperationIdentity::Checkpoint,
            suffix,
            b"one",
            ControlCondition::Create,
            deadline,
            &cancel,
        )
        .await
        .unwrap();
    let first = store
        .control_get(
            OperationIdentity::Checkpoint,
            suffix,
            1024,
            deadline,
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(first.bytes, b"one");
    store
        .control_put(
            OperationIdentity::Checkpoint,
            suffix,
            b"two",
            ControlCondition::Match(first.etag.clone()),
            deadline,
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .control_put(
                OperationIdentity::Checkpoint,
                suffix,
                b"bad",
                ControlCondition::Match(first.etag),
                deadline,
                &cancel
            )
            .await,
        Err(S3Error::Conflict)
    );
    assert_eq!(
        store
            .control_get(
                OperationIdentity::Checkpoint,
                suffix,
                1024,
                deadline,
                &cancel
            )
            .await
            .unwrap()
            .bytes,
        b"two"
    );
    assert_eq!(remote.reserved_bytes(), 3);
    assert!(ledger.usage().unwrap().download >= 6);
    assert!(ledger.usage().unwrap().storage >= 3);
    let package = capture::install(&spool, b"package").await;
    store
        .put_file_verified(&package, deadline, cancel.clone())
        .await
        .unwrap();
    let key = format!(
        "linux-packages/v1/objects/sha256/{}",
        package.identity().sha256
    );
    assert!(
        !store
            .confirm_absent(
                OperationIdentity::OfflineMaintenance,
                &key,
                deadline,
                &cancel
            )
            .await
            .unwrap()
    );
    store
        .maintenance_delete(&key, deadline, &cancel)
        .await
        .unwrap();
    assert!(
        store
            .confirm_absent(
                OperationIdentity::OfflineMaintenance,
                &key,
                deadline,
                &cancel
            )
            .await
            .unwrap()
    );
    assert_eq!(remote.reserved_bytes(), 3);
}

#[tokio::test]
async fn multipart_conditions_choose_one_winner_and_abort_cannot_resurrect_parts() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 1024);
    let client = client(&remote);
    let key = "linux-packages/atomic-completion";
    let first = client
        .create_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    let second = client
        .create_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    let first_id = first.upload_id().unwrap();
    let second_id = second.upload_id().unwrap();
    let first_part = client
        .upload_part()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(first_id)
        .part_number(1)
        .body(ByteStream::from_static(b"left"))
        .send()
        .await
        .unwrap();
    let second_part = client
        .upload_part()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(second_id)
        .part_number(1)
        .body(ByteStream::from_static(b"right"))
        .send()
        .await
        .unwrap();
    let parts = |etag: &str| {
        CompletedMultipartUpload::builder()
            .parts(CompletedPart::builder().part_number(1).e_tag(etag).build())
            .build()
    };
    let (left, right) = tokio::join!(
        client
            .complete_multipart_upload()
            .bucket(config::BUCKET)
            .key(key)
            .upload_id(first_id)
            .if_none_match("*")
            .multipart_upload(parts(first_part.e_tag().unwrap()))
            .send(),
        client
            .complete_multipart_upload()
            .bucket(config::BUCKET)
            .key(key)
            .upload_id(second_id)
            .if_none_match("*")
            .multipart_upload(parts(second_part.e_tag().unwrap()))
            .send(),
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let (loser, error, expected) = match (left, right) {
        (Ok(_), Err(error)) => (second_id, error, b"left".as_slice()),
        (Err(error), Ok(_)) => (first_id, error, b"right".as_slice()),
        _ => panic!("exactly one conditional completion must win"),
    };
    assert_eq!(error.raw_response().unwrap().status().as_u16(), 412);
    assert_eq!(read(&client, key).await, expected);
    client
        .abort_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(loser)
        .send()
        .await
        .unwrap();
    assert_eq!(remote.reserved_bytes(), expected.len() as u64);

    let created = client
        .create_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .send()
        .await
        .unwrap();
    let id = created.upload_id().unwrap();
    let mut pending = Box::pin(remote.call(request(
        "PUT",
        &format!("{key}?uploadId={id}&partNumber=1"),
        b"pending",
    )));
    assert!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    client
        .abort_multipart_upload()
        .bucket(config::BUCKET)
        .key(key)
        .upload_id(id)
        .send()
        .await
        .unwrap();
    assert_eq!(pending.await.unwrap().status().as_u16(), 404);
    assert_eq!(remote.reserved_bytes(), expected.len() as u64);
    assert!(remote.state().unwrap().uploads.is_empty());
}

#[tokio::test]
async fn upload_part_control_and_inflight_count_bounds_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let remote = remote(root.path(), 1024);
    let client = client(&remote);
    let key = "linux-packages/limits";
    let mut ids = Vec::new();
    for _ in 0..MAX_UPLOADS {
        let created = client
            .create_multipart_upload()
            .bucket(config::BUCKET)
            .key(key)
            .send()
            .await
            .unwrap();
        ids.push(created.upload_id().unwrap().to_owned());
    }
    assert!(
        client
            .create_multipart_upload()
            .bucket(config::BUCKET)
            .key(key)
            .send()
            .await
            .is_err()
    );
    let id = &ids[0];
    assert!(
        client
            .upload_part()
            .bucket(config::BUCKET)
            .key(key)
            .upload_id(id)
            .part_number(65)
            .body(ByteStream::from_static(b"x"))
            .send()
            .await
            .is_err()
    );
    let wrong_key = client
        .upload_part()
        .bucket(config::BUCKET)
        .key("linux-packages/not-associated")
        .upload_id(id)
        .part_number(1)
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(wrong_key.raw_response().unwrap().status().as_u16(), 404);
    let mut excessive = request("PUT", &format!("{key}?uploadId={id}&partNumber=1"), b"");
    excessive
        .headers_mut()
        .insert("content-length", (MAX_PART + 1).to_string());
    assert!(remote.call(excessive).await.is_err());
    assert!(
        completed_parts(SdkBody::from(vec![b' '; MAX_CONTROL + 1]))
            .await
            .is_err()
    );
    let held = remote.slots.clone().try_acquire_many_owned(32).unwrap();
    assert!(remote.call(request("GET", key, b"")).await.is_err());
    drop(held);
    assert_eq!(remote.reserved_bytes(), 0);
    for id in ids {
        client
            .abort_multipart_upload()
            .bucket(config::BUCKET)
            .key(key)
            .upload_id(id)
            .send()
            .await
            .unwrap();
    }
}

#[cfg(unix)]
#[test]
fn root_refuses_symlink_ancestors_without_touching_target() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("sentinel"), b"untouched").unwrap();
    std::os::unix::fs::symlink(&target, root.path().join("linked")).unwrap();
    assert!(
        DiskBackedRemote::new(
            root.path().join("linked/remote"),
            1024,
            ["linux-packages/".into(), "linux-checkpoints/".into()]
        )
        .is_err()
    );
    assert!(!target.join("remote").exists());
    assert_eq!(
        std::fs::read(target.join("sentinel")).unwrap(),
        b"untouched"
    );
}
