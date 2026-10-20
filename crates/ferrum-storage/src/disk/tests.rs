//! Private operation gates stop real filesystem work after it has detached.
//! Tests assert public admission, accounting, delivery and exclusive ownership.

#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};

use bytes::Bytes;
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use futures_util::StreamExt;
use tokio::sync::oneshot;

use super::{Spool, SpoolConfig, SpoolError, SpoolWriter, lock_unpoisoned};

pub(super) struct Hook {
    pub(super) operation: &'static str,
    entered: oneshot::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl Hook {
    pub(super) fn pause(self) {
        self.entered
            .send(())
            .expect("test observes operation entry");
        self.release
            .recv()
            .expect("test releases blocking operation");
    }
}

pub(super) fn pause(slot: &Mutex<Option<Hook>>, operation: &'static str) {
    let hook = {
        let mut slot = lock_unpoisoned(slot);
        if slot
            .as_ref()
            .is_some_and(|hook| hook.operation == operation)
        {
            slot.take()
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        hook.pause();
    }
}

/// Releases even if an assertion panics, so a failing test cannot hang Tokio's
/// blocking-pool shutdown. Entry itself is awaited, never inferred from time.
pub(super) struct Gate {
    entered: oneshot::Receiver<()>,
    release: Option<mpsc::Sender<()>>,
}

impl Gate {
    pub(super) fn arm(spool: &Spool, operation: &'static str) -> Self {
        let (entered, receiver) = oneshot::channel();
        let (release, resume) = mpsc::channel();
        let previous = lock_unpoisoned(&spool.0.hook).replace(Hook {
            operation,
            entered,
            release: resume,
        });
        assert!(previous.is_none(), "one pending hook per spool");
        Self {
            entered: receiver,
            release: Some(release),
        }
    }

    pub(super) async fn entered(&mut self) {
        (&mut self.entered)
            .await
            .expect("blocking operation entered");
    }

    pub(super) fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}

fn config(root: &Path) -> SpoolConfig {
    SpoolConfig {
        root: root.to_owned(),
        managed_ceiling: 128,
        max_object_size: 64,
        io_workers: 2,
        read_chunk: 8,
    }
}

fn open(root: &Path) -> Spool {
    Spool::open_exclusive_fixture(config(root)).expect("fixture spool opens")
}

fn identity(bytes: &[u8]) -> ObjectIdentity {
    ObjectIdentity {
        sha256: Sha256Digest::of(bytes),
        size: bytes.len() as u64,
    }
}

async fn writer(spool: &Spool, bytes: &'static [u8]) -> SpoolWriter {
    let expected = identity(bytes);
    let reservation = spool.reserve(expected.size).expect("fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("create");
    writer
        .write(Bytes::from_static(bytes))
        .await
        .expect("write");
    writer
}

async fn drained(spool: &Spool) {
    // Blocking closures drop their file guards before releasing their permits.
    let permits = Arc::clone(spool.0.io_permits())
        .acquire_many_owned(2)
        .await
        .expect("I/O pool");
    drop(permits);
}

fn temporary_path(spool: &Spool) -> std::path::PathBuf {
    fs::read_dir(spool.root().join("temporary"))
        .expect("temporary directory")
        .next()
        .expect("one temporary")
        .expect("entry")
        .path()
}

#[tokio::test]
async fn cancelled_write_retains_bytes_until_the_detached_inode_closes() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let expected = identity(b"verified");
    let reservation = spool.reserve(expected.size).expect("fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("create");
    let path = temporary_path(&spool);
    let mut gate = Gate::arm(&spool, "write");
    let task = tokio::spawn(async move { writer.write(Bytes::from_static(b"verified")).await });
    gate.entered().await;
    task.abort();
    assert!(task.await.expect_err("cancelled writer").is_cancelled());
    assert!(path.exists(), "detached operation still owns the inode");
    assert_eq!(spool.accounting().reserved, expected.size);
    let held = spool.reserve(64).expect("remaining admission");
    assert!(
        spool.reserve(57).is_err(),
        "detached bytes still reduce capacity"
    );
    drop(held);
    gate.release();
    drained(&spool).await;
    assert!(!path.exists());
    assert_eq!(spool.accounting().reserved, 0);
    assert!(spool.lookup(expected).is_none());
}

#[tokio::test]
async fn cancelled_reset_is_poisoned_and_recovery_waits_for_truncation() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let mut writer = writer(&spool, b"verified").await;
    let mut gate = Gate::arm(&spool, "reset");
    {
        let reset = writer.reset();
        tokio::pin!(reset);
        tokio::select! {
            result = &mut reset => panic!("reset completed while gate held: {result:?}"),
            () = gate.entered() => {}
        }
    }
    assert!(
        writer.write(Bytes::new()).await.is_err(),
        "cancelled reset poisons hashing"
    );
    let recovery = tokio::spawn(async move {
        writer.reset().await.expect("serialized reset");
        writer
            .write(Bytes::from_static(b"verified"))
            .await
            .expect("rewrite");
        writer.commit().await.expect("verified commit")
    });
    assert_eq!(spool.accounting().reserved, 8);
    gate.release();
    let object = recovery.await.expect("recovery task");
    assert_eq!(
        object.read_bounded(8).await.expect("verified bytes"),
        b"verified"
    );
    assert_eq!(spool.accounting().reserved, 0);
    assert_eq!(spool.accounting().installed, 8);
}

#[tokio::test]
async fn dropping_writer_during_detached_reset_keeps_its_charge() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let mut writer = writer(&spool, b"verified").await;
    let path = temporary_path(&spool);
    let mut gate = Gate::arm(&spool, "reset");
    let task = tokio::spawn(async move { writer.reset().await });
    gate.entered().await;
    task.abort();
    assert!(task.await.expect_err("cancelled reset").is_cancelled());
    assert_eq!(spool.accounting().reserved, 8);
    assert!(path.exists());
    gate.release();
    drained(&spool).await;
    assert_eq!(spool.accounting().reserved, 0);
    assert!(!path.exists());
}

#[tokio::test]
async fn cancelled_commit_keeps_every_retained_file_charged() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let writer = writer(&spool, b"verified").await;
    let mut gate = Gate::arm(&spool, "commit");
    let task = tokio::spawn(writer.commit());
    gate.entered().await;
    task.abort();
    assert!(task.await.expect_err("cancelled commit").is_cancelled());
    assert_eq!(spool.accounting().reserved, 8);
    assert!(spool.lookup(identity(b"verified")).is_none());
    gate.release();
    drained(&spool).await;
    let object = spool
        .lookup(identity(b"verified"))
        .expect("detached commit registered");
    assert_eq!(
        object.read_bounded(8).await.expect("verified bytes"),
        b"verified"
    );
    assert_eq!(spool.accounting().reserved, 0);
    assert_eq!(spool.accounting().installed, 8);
}

#[tokio::test]
async fn second_commit_waits_for_first_directory_fsync_and_reuses_its_inode() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let first = writer(&spool, b"verified").await;
    let second = writer(&spool, b"verified").await;
    let mut linked = Gate::arm(&spool, "linked");
    let winner = tokio::spawn(first.commit());
    linked.entered().await;
    let path = spool.0.object_path(&identity(b"verified").sha256);
    let inode = fs::metadata(&path).expect("linked inode").ino();
    assert_eq!(
        spool.accounting().installed,
        0,
        "not registered before directory fsync"
    );
    assert_eq!(spool.accounting().reserved, 16);
    let mut committing = Gate::arm(&spool, "commit");
    let loser = tokio::spawn(second.commit());
    committing.entered().await;
    committing.release();
    // The winner still owns the install lock; no size-only reuse is possible.
    assert_eq!(spool.accounting().installed, 0);
    linked.release();
    let first = winner
        .await
        .expect("winner joined")
        .expect("winner installed");
    let second = loser
        .await
        .expect("loser joined")
        .expect("registered reuse");
    assert_eq!(first.path(), second.path());
    assert_eq!(
        fs::metadata(first.path()).expect("installed inode").ino(),
        inode
    );
    assert_eq!(
        second.read_bounded(8).await.expect("delivered bytes"),
        b"verified"
    );
    assert_eq!(spool.accounting().installed, 8);
    assert_eq!(spool.accounting().reserved, 0);
}

#[tokio::test]
async fn failed_temporary_unlink_preserves_charge_and_closes_admission() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let writer = writer(&spool, b"verified").await;
    let path = temporary_path(&spool);
    let retained = path.with_extension("retained");
    fs::rename(&path, &retained).expect("retain real inode");
    fs::create_dir(&path).expect("make unlink fail independently of user privileges");
    writer.abort().await;
    assert_eq!(fs::read(&retained).expect("retained bytes"), b"verified");
    assert_eq!(spool.accounting().reserved, 8);
    assert!(matches!(spool.reserve(1), Err(SpoolError::AdmissionClosed)));
    assert!(spool.lookup(identity(b"verified")).is_none());
}

#[tokio::test]
async fn post_link_cleanup_failure_never_publishes_or_releases_charge() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let writer = writer(&spool, b"verified").await;
    let mut gate = Gate::arm(&spool, "linked");
    let task = tokio::spawn(writer.commit());
    gate.entered().await;
    let path = spool.0.object_path(&identity(b"verified").sha256);
    let retained = path.with_extension("retained");
    fs::rename(&path, &retained).expect("retain linked inode");
    fs::create_dir(&path).expect("make object open and cleanup fail");
    gate.release();
    assert!(task.await.expect("commit joined").is_err());
    assert_eq!(
        fs::read(&retained).expect("retained inode bytes"),
        b"verified"
    );
    assert_eq!(spool.accounting().reserved, 8);
    assert_eq!(spool.accounting().installed, 0);
    assert!(spool.lookup(identity(b"verified")).is_none());
    assert!(matches!(spool.reserve(1), Err(SpoolError::AdmissionClosed)));
}

#[tokio::test]
async fn size_only_orphan_is_never_reused_or_replaced() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let writer = writer(&spool, b"verified").await;
    let path = spool.0.object_path(&identity(b"verified").sha256);
    fs::create_dir_all(path.parent().expect("parent")).expect("parents");
    fs::write(&path, b"tampered").expect("same-size orphan");
    let inode = fs::metadata(&path).expect("orphan inode").ino();
    assert!(writer.commit().await.is_err());
    assert!(spool.lookup(identity(b"verified")).is_none());
    assert_eq!(fs::read(&path).expect("orphan preserved"), b"tampered");
    assert_eq!(fs::metadata(&path).expect("same inode").ino(), inode);
    assert!(matches!(spool.reserve(1), Err(SpoolError::AdmissionClosed)));
    assert_eq!(spool.accounting().reserved, 8);
}

#[tokio::test]
async fn verified_handle_keeps_exclusive_ownership_after_spool_drop() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = writer(&spool, b"verified")
        .await
        .commit()
        .await
        .expect("commit");
    let path = object.path().to_owned();
    drop(spool);
    assert!(matches!(
        Spool::open_exclusive_fixture(config(root.path())),
        Err(SpoolError::NotExclusive(_))
    ));
    assert_eq!(
        object.read_bounded(8).await.expect("live handle"),
        b"verified"
    );
    assert!(path.exists());
    drop(object);
    let reopened = open(root.path());
    assert!(!path.exists());
    assert_eq!(reopened.accounting().installed, 0);
}

#[tokio::test]
async fn detached_read_keeps_lock_and_accounting_until_its_handle_closes() {
    for bounded in [false, true] {
        let root = tempfile::tempdir().expect("tempdir");
        let spool = open(root.path());
        let object = writer(&spool, b"verified")
            .await
            .commit()
            .await
            .expect("commit");
        let lifetime = Arc::downgrade(&spool.0.lifetime);
        let permits = Arc::clone(spool.0.io_permits());
        let mut gate = Gate::arm(&spool, "read");
        let reader = object.clone();
        let task = tokio::spawn(async move {
            if bounded {
                reader.read_bounded(8).await.map(|_| ())
            } else {
                let mut stream = reader.stream_range(0, 7).expect("range");
                stream.next().await.transpose().map(|_| ())
            }
        });
        gate.entered().await;
        task.abort();
        assert!(task.await.expect_err("cancelled read").is_cancelled());
        drop(object);
        drop(spool);
        assert!(matches!(
            Spool::open_exclusive_fixture(config(root.path())),
            Err(SpoolError::NotExclusive(_))
        ));
        assert_eq!(
            lock_unpoisoned(&lifetime.upgrade().expect("detached lease").ledger)
                .snapshot()
                .installed,
            8
        );
        gate.release();
        drop(
            permits
                .acquire_many_owned(2)
                .await
                .expect("detached read finished"),
        );
        assert!(lifetime.upgrade().is_none());
        let reopened = open(root.path());
        assert_eq!(reopened.accounting().installed, 0);
    }
}

#[tokio::test]
async fn cancelled_open_keeps_the_new_inode_and_reservation_together() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let expected = identity(b"verified");
    let reservation = spool.reserve(expected.size).expect("fits");
    let mut gate = Gate::arm(&spool, "create");
    let owner = spool.clone();
    let task = tokio::spawn(async move { owner.begin_write(reservation, expected).await });
    gate.entered().await;
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(
        temporary_path(&spool).exists(),
        "exclusive open has actually run"
    );
    assert_eq!(
        spool.accounting().reserved,
        8,
        "detached open owns the charge"
    );
    assert!(matches!(
        Spool::open_exclusive_fixture(config(root.path())),
        Err(SpoolError::NotExclusive(_))
    ));
    gate.release();
    drained(&spool).await;
}

#[tokio::test]
async fn reset_after_cancelled_write_waits_for_the_old_write_before_reusing_offsets() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let expected = identity(b"verified");
    let reservation = spool.reserve(8).expect("fits");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("create");
    let mut gate = Gate::arm(&spool, "write");
    {
        let write = writer.write(Bytes::from_static(b"garbage!"));
        tokio::pin!(write);
        tokio::select! {
            result = &mut write => panic!("write completed while gate held: {result:?}"),
            () = gate.entered() => {}
        }
    }
    assert!(
        writer.write(Bytes::new()).await.is_err(),
        "cancelled write poisons hashing"
    );
    let recovered = tokio::spawn(async move {
        writer.reset().await.expect("reset waits for old write");
        writer
            .write(Bytes::from_static(b"verified"))
            .await
            .expect("new bytes");
        writer.commit().await.expect("new bytes verify")
    });
    gate.release();
    let object = recovered.await.expect("recovery task");
    assert_eq!(
        object.read_bounded(8).await.expect("verified delivery"),
        b"verified"
    );
    assert_eq!(spool.accounting().reserved, 0);
    assert_eq!(spool.accounting().installed, 8);
}

#[test]
fn physical_capacity_query_failure_does_not_admit_or_charge_bytes() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("spool");
    let spool = open(&path);
    let moved = root.path().join("moved");
    fs::rename(&path, &moved).expect("make configured filesystem path unavailable");
    assert!(matches!(spool.reserve(8), Err(SpoolError::Io(_))));
    assert_eq!(spool.accounting().reserved, 0);
    assert_eq!(spool.accounting().installed, 0);
}

#[tokio::test]
async fn retained_chunk_views_and_concurrent_ranges_are_never_overwritten() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = writer(&spool, b"01234567abcdefghABCDEFGH")
        .await
        .commit()
        .await
        .expect("commit");
    let mut first = object.stream_range(0, 23).expect("first range");
    let mut second = object.stream_range(4, 19).expect("second range");
    let retained = first.next().await.expect("first").expect("read");
    let view = retained.slice(2..6);
    let clone = retained.clone();
    drop(retained);

    let (next, other) = tokio::join!(first.next(), second.next());
    let next = next.expect("next").expect("read");
    let other = other.expect("other").expect("read");
    assert_eq!(&next[..], b"abcdefgh");
    assert_eq!(&other[..], b"4567abcd");
    assert_eq!(&view[..], b"2345");
    assert_eq!(&clone[..], b"01234567");
    drop(next);
    drop(other);

    assert_eq!(
        &first.next().await.expect("last").expect("read")[..],
        b"ABCDEFGH"
    );
    assert_eq!(
        &second.next().await.expect("last").expect("read")[..],
        b"efghABCD"
    );
    assert_eq!(&view[..], b"2345");
    assert_eq!(&clone[..], b"01234567");
    assert!(first.next().await.is_none());
    assert!(second.next().await.is_none());
}

#[tokio::test]
async fn short_read_emits_one_error_without_exposing_reused_bytes() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = writer(&spool, b"01234567abcdefghABCDEFGH")
        .await
        .commit()
        .await
        .expect("commit");
    let mut stream = object.stream_range(0, 23).expect("range");
    let first = stream.next().await.expect("first").expect("read");
    assert_eq!(&first[..], b"01234567");
    drop(first);

    fs::OpenOptions::new()
        .write(true)
        .open(object.path())
        .expect("fault injection descriptor")
        .set_len(12)
        .expect("inject short read");
    assert!(matches!(
        stream.next().await,
        Some(Err(SpoolError::Io(error))) if error.kind() == std::io::ErrorKind::UnexpectedEof
    ));
    assert!(stream.next().await.is_none());
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn cancelled_sdk_body_keeps_lease_until_the_detached_read_finishes() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = writer(&spool, b"verified")
        .await
        .commit()
        .await
        .expect("commit");
    let lifetime = Arc::downgrade(&spool.0.lifetime);
    let permits = Arc::clone(spool.0.io_permits());
    let mut body = crate::s3::object_body_for_test(&object, 0, 8).expect("valid upload range");
    let mut gate = Gate::arm(&spool, "read");
    let task = tokio::spawn(async move { body.next().await });
    gate.entered().await;
    task.abort();
    assert!(task.await.expect_err("cancelled SDK body").is_cancelled());
    drop(object);
    drop(spool);

    assert!(matches!(
        Spool::open_exclusive_fixture(config(root.path())),
        Err(SpoolError::NotExclusive(_))
    ));
    assert_eq!(
        lock_unpoisoned(&lifetime.upgrade().expect("detached lease").ledger)
            .snapshot()
            .installed,
        8
    );

    gate.release();
    drop(
        permits
            .acquire_many_owned(2)
            .await
            .expect("detached SDK read finished"),
    );
    assert!(lifetime.upgrade().is_none());
    assert!(open(root.path()).lookup(identity(b"verified")).is_none());
}

#[tokio::test]
async fn verified_fetch_bounds_filesystem_waits_without_granting_capture() {
    use crate::s3::{FetchError, S3Error};
    use std::time::Duration;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    for operation in ["create", "write", "commit"] {
        for cancelled in [false, true] {
            let root = tempfile::tempdir().expect("tempdir");
            let spool = crate::recovery::test_support::open_spool(&root.path().join("state"));
            let expected = identity(b"verified");
            let (manager, _, requests) = crate::capture::tests::setup(
                spool.clone(),
                vec![crate::capture::tests::response("GET", 200, b"verified")],
            );
            let store = Arc::clone(manager.store());
            let owner = spool.clone();
            let permits = Arc::clone(&spool.0.io_permits);
            let workers = permits.available_permits() as u32;
            let mut gate = Gate::arm(&spool, operation);
            let cancel = CancellationToken::new();
            let task_cancel = cancel.clone();
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut task = tokio::spawn(async move {
                store
                    .fetch_verified(&owner, expected, deadline, task_cancel)
                    .await
            });
            gate.entered().await;

            // Freeze only after the real filesystem worker has entered its
            // gate, so virtual time cannot expire before the operation starts.
            tokio::time::pause();
            if cancelled {
                cancel.cancel();
            } else {
                tokio::time::advance(Duration::from_secs(31)).await;
            }
            let joined = tokio::time::timeout(Duration::from_secs(1), &mut task).await;
            let charged = spool.accounting().reserved;
            gate.release();
            tokio::time::resume();
            if joined.is_err() {
                task.abort();
                let _ = task.await;
            }
            let outcome = joined
                .expect("deadline/cancellation must interrupt the filesystem wait")
                .expect("fetch task");
            let expected_error = if cancelled {
                S3Error::Cancelled
            } else {
                S3Error::Timeout
            };
            assert!(
                matches!(outcome, Err(FetchError::S3(error)) if error == expected_error),
                "{operation}: no late fetch capability may escape"
            );
            assert_eq!(
                charged, expected.size,
                "{operation}: detached I/O retains charge"
            );
            drop(
                permits
                    .acquire_many_owned(workers)
                    .await
                    .expect("detached filesystem work finished"),
            );
            assert_eq!(requests.snapshot().expect("requests"), ["GET"]);
            assert!(!spool.capture_is_durable(expected).expect("capture state"));
            if operation == "commit" {
                let object = spool.lookup(expected).expect("admitted commit may finish");
                assert_eq!(
                    object.read_bounded(8).await.expect("local bytes"),
                    b"verified"
                );
            } else {
                assert!(spool.lookup(expected).is_none());
            }
        }
    }
}
