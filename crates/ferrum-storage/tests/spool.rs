//! Consumer-visible behavior of the fixture spool: commit/lookup, overflow and
//! mismatch handling, accounting, exclusive ownership, startup cleanup and
//! positional range streams.

#![allow(clippy::expect_used)]

use bytes::Bytes;
use std::fs;
use std::path::Path;

use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use ferrum_storage::{Accounting, Spool, SpoolConfig, SpoolError, VerifiedObject};
use futures_util::StreamExt;

const CEILING: u64 = 1024 * 1024;
const MAX_OBJECT: u64 = 256 * 1024;

fn config(root: &Path, read_chunk: usize) -> SpoolConfig {
    SpoolConfig {
        root: root.to_path_buf(),
        managed_ceiling: CEILING,
        max_object_size: MAX_OBJECT,
        io_workers: 2,
        read_chunk,
    }
}

fn open(root: &Path) -> Spool {
    Spool::open_exclusive_fixture(config(root, 4096)).expect("spool opens on an empty directory")
}

fn identity_of(bytes: &[u8]) -> ObjectIdentity {
    ObjectIdentity {
        sha256: Sha256Digest::of(bytes),
        size: bytes.len() as u64,
    }
}

fn payload(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

fn temporary_entries(root: &Path) -> Vec<String> {
    fs::read_dir(root.join("temporary"))
        .expect("temporary directory exists")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// (file count, total bytes) of every regular file below `objects/`.
fn object_files(root: &Path) -> (usize, u64) {
    fn walk(directory: &Path, count: &mut usize, total: &mut u64) {
        for entry in fs::read_dir(directory).expect("directory readable") {
            let entry = entry.expect("entry");
            let file_type = entry.file_type().expect("file type");
            if file_type.is_dir() {
                walk(&entry.path(), count, total);
            } else {
                *count += 1;
                *total += entry.metadata().expect("metadata").len();
            }
        }
    }
    let mut count = 0;
    let mut total = 0;
    walk(&root.join("objects"), &mut count, &mut total);
    (count, total)
}

async fn prepared_writer(spool: &Spool, bytes: &[u8]) -> ferrum_storage::SpoolWriter {
    let expected = identity_of(bytes);
    let reservation = spool.reserve(expected.size).expect("reservation fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("temporary created");
    writer
        .write(Bytes::copy_from_slice(bytes))
        .await
        .expect("write within reservation");
    writer
}

async fn install(spool: &Spool, bytes: &[u8], chunk: usize) -> VerifiedObject {
    let expected = identity_of(bytes);
    let reservation = spool.reserve(expected.size).expect("reservation fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("temporary created");
    for piece in bytes.chunks(chunk) {
        writer
            .write(Bytes::copy_from_slice(piece))
            .await
            .expect("write within reservation");
    }
    writer.commit().await.expect("commit of correct bytes")
}

async fn collect(object: &VerifiedObject, start: u64, end: u64) -> Vec<u8> {
    let mut stream = object.stream_range(start, end).expect("valid range");
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        bytes.extend_from_slice(&chunk.expect("chunk read"));
    }
    bytes
}

#[tokio::test]
async fn bounded_reads_preserve_size_limits_across_the_chunk_boundary() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());

    for size in [4095, 4096, 4097] {
        let expected = payload(size);
        let object = install(&spool, &expected, 4096).await;

        assert!(matches!(
            object.read_bounded(size - 1).await,
            Err(SpoolError::TooLarge)
        ));
        assert_eq!(
            object.read_bounded(size).await.expect("exact bound"),
            expected
        );
    }
}

#[tokio::test]
async fn bounded_single_chunk_read_rejects_a_truncated_object() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(&spool, &payload(4096), 4096).await;
    fs::OpenOptions::new()
        .write(true)
        .open(object.path())
        .expect("fixture object")
        .set_len(4095)
        .expect("truncate fixture");

    assert!(matches!(
        object.read_bounded(4096).await,
        Err(SpoolError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
    ));
}

#[tokio::test]
async fn commit_installs_exact_bytes_at_digest_path_and_accounts_them() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let bytes = payload(10_000);
    let expected = identity_of(&bytes);

    let object = install(&spool, &bytes, 3000).await;

    assert_eq!(object.identity(), expected);
    let hex = expected.sha256.to_hex();
    let digest_path = root
        .path()
        .join("objects/sha256")
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(&hex);
    assert_eq!(object.path(), digest_path);
    assert_eq!(fs::read(&digest_path).expect("object readable"), bytes);
    assert!(temporary_entries(root.path()).is_empty());
    assert_eq!(
        spool.lookup(expected).map(|found| found.identity()),
        Some(expected)
    );
    assert_eq!(
        spool.accounting(),
        Accounting {
            reserved: 0,
            installed: expected.size,
            ceiling: CEILING
        }
    );
    assert_eq!(
        object.read_bounded(10_000).await.expect("fits"),
        bytes,
        "read_bounded returns the exact object"
    );
    assert!(matches!(
        object.read_bounded(9_999).await,
        Err(SpoolError::TooLarge)
    ));
}

#[tokio::test]
async fn write_beyond_expected_size_overflows_and_abort_removes_temporary() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let bytes = payload(100);
    let expected = identity_of(&bytes);
    let reservation = spool.reserve(expected.size).expect("fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("temporary created");
    writer
        .write(Bytes::copy_from_slice(&bytes[..90]))
        .await
        .expect("within size");
    assert_eq!(temporary_entries(root.path()).len(), 1);

    let overflow = writer.write(Bytes::copy_from_slice(&bytes[90..])).await;
    assert!(
        matches!(overflow, Ok(())),
        "exact fill is accepted: {overflow:?}"
    );
    let overflow = writer.write(Bytes::from_static(&[0])).await;
    assert!(
        matches!(overflow, Err(SpoolError::Overflow { expected: 100 })),
        "got {overflow:?}"
    );
    assert_eq!(writer.written(), 100);
    assert_eq!(spool.accounting().reserved, 100);

    writer.abort().await;
    assert!(temporary_entries(root.path()).is_empty());
    assert_eq!(spool.accounting().reserved, 0);
    assert!(spool.lookup(expected).is_none());
}

#[tokio::test]
async fn wrong_digest_is_a_mismatch_with_nothing_installed() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let bytes = payload(500);
    let mut corrupted = bytes.clone();
    corrupted[7] ^= 0xff;
    let expected = identity_of(&bytes);
    let reservation = spool.reserve(expected.size).expect("fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("temporary created");
    writer
        .write(Bytes::copy_from_slice(&corrupted))
        .await
        .expect("within size");

    let result = writer.commit().await;
    let actual = Sha256Digest::of(&corrupted);
    assert!(
        matches!(
            result,
            Err(SpoolError::Mismatch {
                expected: reported,
                actual_size: 500,
                actual_sha256,
            }) if reported == expected && actual_sha256 == actual
        ),
        "expected Mismatch, got {result:?}"
    );
    assert!(spool.lookup(expected).is_none());
    assert!(temporary_entries(root.path()).is_empty());
    assert!(
        !root
            .path()
            .join("objects/sha256")
            .join(&expected.sha256.to_hex()[0..2])
            .exists(),
        "no digest directory was created for a rejected object"
    );
    assert_eq!(
        spool.accounting(),
        Accounting {
            reserved: 0,
            installed: 0,
            ceiling: CEILING
        }
    );
}

#[tokio::test]
async fn short_write_is_a_mismatch() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let bytes = payload(64);
    let expected = identity_of(&bytes);
    let reservation = spool.reserve(expected.size).expect("fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("temporary created");
    writer
        .write(Bytes::copy_from_slice(&bytes[..10]))
        .await
        .expect("within size");
    assert!(matches!(
        writer.commit().await,
        Err(SpoolError::Mismatch {
            actual_size: 10,
            ..
        })
    ));
}

#[tokio::test]
async fn reset_after_bad_attempt_allows_a_correct_commit() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let bytes = payload(9_000);
    let expected = identity_of(&bytes);
    let reservation = spool.reserve(expected.size).expect("fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("temporary created");
    writer
        .write(Bytes::from(payload(4_000)))
        .await
        .expect("first attempt");
    writer
        .write(Bytes::from_static(b"garbage"))
        .await
        .expect("first attempt");

    writer.reset().await.expect("reset");
    assert_eq!(writer.written(), 0);
    assert_eq!(
        spool.accounting().reserved,
        9_000,
        "reservation survives reset"
    );
    for piece in bytes.chunks(2_500) {
        writer
            .write(Bytes::copy_from_slice(piece))
            .await
            .expect("second attempt");
    }
    let object = writer.commit().await.expect("second attempt commits");
    assert_eq!(fs::read(object.path()).expect("object readable"), bytes);
    assert_eq!(spool.accounting().installed, 9_000);
}

#[tokio::test]
async fn reservation_mismatch_is_rejected_and_released() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let reservation = spool.reserve(10).expect("fits");
    let expected = identity_of(&payload(11));
    assert!(matches!(
        spool.begin_write(reservation, expected).await,
        Err(SpoolError::ReservationMismatch)
    ));
    assert_eq!(spool.accounting().reserved, 0);
}

#[test]
fn reserve_enforces_ceiling_and_object_limit_and_drop_releases() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());

    assert!(matches!(
        spool.reserve(MAX_OBJECT + 1),
        Err(SpoolError::ObjectTooLarge {
            size,
            max: MAX_OBJECT
        }) if size == MAX_OBJECT + 1
    ));

    let held: Vec<_> = (0..4)
        .map(|_| spool.reserve(MAX_OBJECT).expect("four maximum objects fit"))
        .collect();
    assert_eq!(spool.accounting().reserved, CEILING);
    let exhausted = spool.reserve(1);
    assert!(
        matches!(
            exhausted,
            Err(SpoolError::CapacityExhausted {
                requested: 1,
                available: 0,
            })
        ),
        "expected CapacityExhausted, got {exhausted:?}"
    );

    drop(held);
    assert_eq!(spool.accounting().reserved, 0);
    let reservation = spool.reserve(MAX_OBJECT).expect("fits again after release");
    assert_eq!(reservation.size(), MAX_OBJECT);
}

#[test]
fn second_opener_on_a_live_spool_is_not_exclusive() {
    let root = tempfile::tempdir().expect("tempdir");
    let first = open(root.path());
    let second = Spool::open_exclusive_fixture(config(root.path(), 4096));
    assert!(
        matches!(second, Err(SpoolError::NotExclusive(_))),
        "got {:?}",
        second.err()
    );

    drop(first);
    let reopened = Spool::open_exclusive_fixture(config(root.path(), 4096));
    assert!(
        reopened.is_ok(),
        "lock released on drop: {:?}",
        reopened.err()
    );
}

#[test]
fn non_empty_directory_without_marker_is_refused_untouched() {
    let root = tempfile::tempdir().expect("tempdir");
    fs::write(root.path().join("precious.txt"), b"user data").expect("write");
    fs::create_dir(root.path().join("objects")).expect("mkdir");
    fs::write(root.path().join("objects/keep"), b"more").expect("write");

    let result = Spool::open_exclusive_fixture(config(root.path(), 4096));
    assert!(
        matches!(result, Err(SpoolError::UnsafeDirectory(_))),
        "got {:?}",
        result.err()
    );
    assert_eq!(
        fs::read(root.path().join("precious.txt")).expect("kept"),
        b"user data"
    );
    assert_eq!(
        fs::read(root.path().join("objects/keep")).expect("kept"),
        b"more"
    );
    assert!(
        !root.path().join("lock").exists(),
        "no lock file was created"
    );
    assert!(!root.path().join(".ferrum-fixture-spool").exists());
}

#[test]
fn marked_directory_with_unexpected_entry_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    drop(open(root.path()));
    fs::write(root.path().join("stray"), b"?").expect("write");
    let result = Spool::open_exclusive_fixture(config(root.path(), 4096));
    assert!(matches!(result, Err(SpoolError::UnsafeDirectory(_))));
}

#[test]
fn symlink_under_objects_refuses_startup() {
    let root = tempfile::tempdir().expect("tempdir");
    drop(open(root.path()));
    let outside = tempfile::tempdir().expect("tempdir");
    fs::write(outside.path().join("target"), b"outside").expect("write");
    std::os::unix::fs::symlink(
        outside.path().join("target"),
        root.path().join("objects/link"),
    )
    .expect("symlink");
    let result = Spool::open_exclusive_fixture(config(root.path(), 4096));
    assert!(matches!(result, Err(SpoolError::UnsafeDirectory(_))));
    assert_eq!(
        fs::read(outside.path().join("target")).expect("kept"),
        b"outside"
    );
}

#[tokio::test]
async fn reopen_removes_leftovers_but_keeps_marker_and_lock() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(&spool, &payload(2_000), 512).await;
    let object_path = object.path().to_path_buf();
    let identity = object.identity();
    fs::write(root.path().join("temporary/abandoned.part"), b"partial").expect("write");
    fs::write(root.path().join("objects/sha256/stray"), b"x").expect("write");
    drop(object);
    drop(spool);

    let reopened = open(root.path());
    assert!(
        !object_path.exists(),
        "objects are not trusted across restarts"
    );
    assert!(temporary_entries(root.path()).is_empty());
    assert!(!root.path().join("objects/sha256/stray").exists());
    assert!(root.path().join(".ferrum-fixture-spool").is_file());
    assert!(root.path().join("lock").is_file());
    assert_eq!(
        reopened.accounting(),
        Accounting {
            reserved: 0,
            installed: 0,
            ceiling: CEILING
        }
    );
    assert!(reopened.lookup(identity).is_none());
}

#[tokio::test]
async fn stream_range_returns_exact_bytes_in_bounded_chunks() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = Spool::open_exclusive_fixture(config(root.path(), 1000)).expect("opens");
    let bytes = payload(10_000);
    let object = install(&spool, &bytes, 4096).await;

    assert_eq!(collect(&object, 0, 9_999).await, bytes, "whole object");
    assert_eq!(collect(&object, 0, 2_499).await, bytes[..2_500], "prefix");
    assert_eq!(
        collect(&object, 7_000, 9_999).await,
        bytes[7_000..],
        "suffix"
    );
    assert_eq!(
        collect(&object, 1_234, 5_678).await,
        bytes[1_234..=5_678],
        "interior"
    );
    assert_eq!(
        collect(&object, 4_242, 4_242).await,
        bytes[4_242..=4_242],
        "single byte"
    );
    assert_eq!(
        collect(&object, 9_999, 9_999).await,
        bytes[9_999..],
        "last byte"
    );

    let mut stream = object.stream_range(0, 2_999).expect("valid");
    let mut lengths = Vec::new();
    while let Some(chunk) = stream.next().await {
        lengths.push(chunk.expect("chunk").len());
    }
    assert_eq!(
        lengths,
        vec![1000, 1000, 1000],
        "chunks never exceed read_chunk"
    );

    for (start, end) in [(1, 0), (0, 10_000), (10_000, 10_000), (5_000, 4_999)] {
        assert!(
            matches!(
                object.stream_range(start, end),
                Err(SpoolError::InvalidRange)
            ),
            "range {start}..={end} must be invalid"
        );
    }
}

#[tokio::test]
async fn concurrent_streams_keep_independent_offsets() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = Spool::open_exclusive_fixture(config(root.path(), 700)).expect("opens");
    let bytes = payload(20_000);
    let object = install(&spool, &bytes, 4096).await;

    let mut first = object.stream_range(0, 19_999).expect("valid");
    let mut second = object.stream_range(10_000, 19_999).expect("valid");
    let mut first_bytes = Vec::new();
    let mut second_bytes = Vec::new();
    loop {
        let (left, right) = tokio::join!(first.next(), second.next());
        let mut progressed = false;
        if let Some(chunk) = left {
            first_bytes.extend_from_slice(&chunk.expect("chunk"));
            progressed = true;
        }
        if let Some(chunk) = right {
            second_bytes.extend_from_slice(&chunk.expect("chunk"));
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    assert_eq!(first_bytes, bytes);
    assert_eq!(second_bytes, bytes[10_000..]);
}

#[tokio::test]
async fn committing_an_already_installed_identity_reuses_the_object() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let bytes = payload(3_000);
    let first = install(&spool, &bytes, 1_000).await;
    let second = install(&spool, &bytes, 1_000).await;
    assert_eq!(first.path(), second.path());
    assert_eq!(
        spool.accounting(),
        Accounting {
            reserved: 0,
            installed: 3_000,
            ceiling: CEILING
        },
        "a duplicate commit does not double-count installed bytes"
    );
    assert!(temporary_entries(root.path()).is_empty());
}

#[tokio::test]
async fn empty_object_commits_and_reads_as_empty() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(&spool, &[], 1).await;
    assert_eq!(object.size(), 0);
    assert!(object.read_bounded(0).await.expect("empty").is_empty());
    assert!(matches!(
        object.stream_range(0, 0),
        Err(SpoolError::InvalidRange)
    ));
}

#[tokio::test]
async fn reservation_from_another_spool_is_rejected() {
    let first_root = tempfile::tempdir().expect("tempdir");
    let second_root = tempfile::tempdir().expect("tempdir");
    let first = open(first_root.path());
    let second = open(second_root.path());
    let expected = identity_of(&payload(10));
    let foreign = second.reserve(expected.size).expect("fits");
    assert!(matches!(
        first.begin_write(foreign, expected).await,
        Err(SpoolError::ReservationMismatch)
    ));
    assert_eq!(first.accounting().reserved, 0);
    assert_eq!(
        second.accounting().reserved,
        0,
        "rejected reservation is released"
    );
    assert!(temporary_entries(first_root.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_commits_of_one_identity_install_and_charge_once() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = Spool::open_exclusive_fixture(SpoolConfig {
        io_workers: 4,
        ..config(root.path(), 4096)
    })
    .expect("opens");
    let bytes = payload(30_000);
    let expected = identity_of(&bytes);
    let mut writers = Vec::new();
    for _ in 0..6 {
        writers.push(prepared_writer(&spool, &bytes).await);
    }
    assert_eq!(spool.accounting().reserved, 6 * expected.size);

    let commits: Vec<_> = writers
        .into_iter()
        .map(|writer| tokio::spawn(writer.commit()))
        .collect();
    let mut paths = Vec::new();
    for commit in commits {
        let object = commit.await.expect("join").expect("commit succeeds");
        assert_eq!(object.identity(), expected);
        paths.push(object.path().to_path_buf());
    }
    paths.dedup();
    assert_eq!(paths.len(), 1, "all commits share one digest path");
    assert_eq!(object_files(root.path()), (1, expected.size));
    assert_eq!(
        spool.accounting(),
        Accounting {
            reserved: 0,
            installed: expected.size,
            ceiling: CEILING
        }
    );
    assert!(temporary_entries(root.path()).is_empty());
    assert_eq!(
        fs::read(&paths[0]).expect("object readable"),
        bytes,
        "the published inode holds the verified bytes"
    );
}
