//! Real SQLite/filesystem behavior with narrow transition fault injection.
//! No provider requests or unverified production durability promotion.

#![allow(clippy::expect_used, clippy::panic)]

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use futures_util::StreamExt;
use rusqlite::{Connection, params};

use crate::catalog::read_unsigned;

use super::tests::Gate;
use super::{
    DurableSpoolConfig, PinKind, ReservationClass, Spool, SpoolError, SpoolWriter, VerifiedObject,
    lock_unpoisoned,
};

const MIB: u64 = 1024 * 1024;

pub(super) fn config(root: &Path) -> DurableSpoolConfig {
    let mut config = DurableSpoolConfig::new(root.to_owned());
    config.spool.managed_ceiling = 32 * MIB;
    config.spool.max_object_size = 4 * MIB;
    config.spool.io_workers = 2;
    config.spool.read_chunk = 4096;
    config.free_space_floor = 0;
    config.temporary_ceiling = 4 * MIB;
    config.metadata_temporary_reserve = MIB;
    config.metadata_ceiling = 8 * MIB;
    config.catalog_ceiling = 16 * MIB;
    config.catalog_memory_budget = 32 * MIB;
    config.max_entries = 128;
    config.database_queue = 8;
    config.eviction_high_watermark = 14 * MIB;
    config.eviction_low_watermark = 12 * MIB;
    config
}

fn identity(bytes: &[u8]) -> ObjectIdentity {
    ObjectIdentity {
        sha256: Sha256Digest::of(bytes),
        size: bytes.len() as u64,
    }
}
fn open(root: &Path) -> Spool {
    Spool::open_durable(config(root)).expect("durable store opens")
}
fn database(root: &Path) -> Connection {
    Connection::open(root.join("state.sqlite")).expect("catalog inspection connection")
}
fn pending(root: &Path) -> u64 {
    database(root)
        .query_row(
            "SELECT COALESCE(SUM(size),0) FROM reservations",
            [],
            |row| read_unsigned(row, 0),
        )
        .expect("reservation sum")
}

async fn writer(spool: &Spool, bytes: Bytes, class: ReservationClass) -> SpoolWriter {
    let expected = identity(&bytes);
    let reservation = spool.reserve_class(expected.size, class).expect("reserved");
    let mut writer = spool
        .begin_write(reservation, expected)
        .await
        .expect("temporary created");
    writer.write(bytes).await.expect("bounded writes");
    writer
}
async fn install(spool: &Spool, bytes: Bytes, class: ReservationClass) -> VerifiedObject {
    writer(spool, bytes, class)
        .await
        .commit()
        .await
        .expect("verified install")
}

#[tokio::test]
async fn persistent_verified_lookup_survives_restart_and_fixture_cannot_wipe_it() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(
        &spool,
        Bytes::from_static(b"persistent authenticated bytes"),
        ReservationClass::Package,
    )
    .await;
    let expected = object.identity();
    let path = object.path().to_owned();
    assert_eq!(pending(root.path()), 0);
    let row: (u64, i64) = database(root.path())
        .query_row(
            "SELECT size,resident FROM objects WHERE digest=?1",
            [expected.sha256.to_hex()],
            |row| Ok((read_unsigned(row, 0)?, row.get(1)?)),
        )
        .expect("authoritative row");
    assert_eq!(row, (expected.size, 1));
    drop(object);
    drop(spool);
    assert!(matches!(
        Spool::open_exclusive_fixture(config(root.path()).spool),
        Err(SpoolError::UnsafeDirectory(_))
    ));
    let reopened = open(root.path());
    let object = reopened
        .lookup(expected)
        .expect("persistent authority and residency");
    assert_eq!(
        object.read_bounded(128).await.expect("read"),
        b"persistent authenticated bytes"
    );
    assert_eq!(object.path(), path);
    assert_eq!(reopened.accounting().installed, expected.size);
    let usage = reopened.usage().expect("usage");
    assert!(usage.catalog_bytes > 0);
    assert!(usage.managed_bytes <= usage.objects.ceiling);
}

#[test]
fn reservations_are_persisted_before_fetch_and_abandoned_capacity_is_reconciled() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let mut reservation = spool.reserve(MIB).expect("reserve");
    assert_eq!(pending(root.path()), MIB);
    assert_eq!(
        spool.usage().expect("usage").catalog_reserved_bytes,
        super::SQL_OPERATION_RESERVE
    );
    // Model loss of the process after the reservation transaction but before
    // file creation, without invoking normal graceful reservation release.
    reservation.held = false;
    drop(reservation);
    drop(spool);
    assert_eq!(pending(root.path()), MIB);
    let reopened = open(root.path());
    assert_eq!(pending(root.path()), 0);
    assert_eq!(reopened.accounting().reserved, 0);
    assert!(reopened.reserve(MIB).is_ok());
}

#[test]
fn incomplete_temporary_and_unknown_digest_names_never_become_resident() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let expected = identity(b"matching but unauthenticated orphan");
    let path = spool.0.object_path(&expected.sha256);
    drop(spool);
    fs::create_dir_all(path.parent().expect("parent")).expect("orphan parents");
    fs::write(&path, b"matching but unauthenticated orphan").expect("orphan bytes");
    fs::write(root.path().join("temporary/abandoned.part"), b"partial").expect("partial");
    let connection = database(root.path());
    connection
        .execute(
            "INSERT INTO reservations(id,size,class,digest,temporary_name) VALUES(?1,?2,0,?3,?4)",
            params![
                "0123456789abcdef0123456789abcdef",
                4096,
                expected.sha256.to_hex(),
                "abandoned.part"
            ],
        )
        .expect("persisted incomplete descriptor");
    drop(connection);
    let reopened = open(root.path());
    assert!(reopened.lookup(expected).is_none());
    assert!(!path.exists());
    assert_eq!(
        fs::read_dir(root.path().join("temporary"))
            .expect("temporary")
            .count(),
        0
    );
    assert_eq!(pending(root.path()), 0);
    assert_eq!(reopened.accounting().installed, 0);
}

#[tokio::test]
async fn failed_file_fsync_does_not_publish_or_lose_reservation_accounting() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let writer = writer(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Package,
    )
    .await;
    *lock_unpoisoned(&spool.0.failure) = Some("file-fsync");
    assert!(writer.commit().await.is_err());
    assert!(spool.lookup(identity(b"verified")).is_none());
    assert_eq!(spool.accounting().reserved, 0);
    assert_eq!(pending(root.path()), 0);
    assert!(!spool.0.object_path(&identity(b"verified").sha256).exists());
}

#[tokio::test]
async fn failed_directory_fsync_retains_renamed_orphan_until_restart() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let writer = writer(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Package,
    )
    .await;
    let path = spool.0.object_path(&identity(b"verified").sha256);
    *lock_unpoisoned(&spool.0.failure) = Some("directory-fsync");
    assert!(writer.commit().await.is_err());
    assert!(path.is_file());
    assert!(spool.lookup(identity(b"verified")).is_none());
    assert_eq!(spool.accounting().reserved, 8);
    assert_eq!(pending(root.path()), 8);
    assert!(matches!(spool.reserve(1), Err(SpoolError::AdmissionClosed)));
    drop(spool);
    let reopened = open(root.path());
    assert!(!path.exists());
    assert_eq!(pending(root.path()), 0);
    assert_eq!(reopened.accounting().reserved, 0);
}

#[tokio::test]
async fn actual_sql_failure_after_rename_is_not_a_published_object() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let writer = writer(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Package,
    )
    .await;
    database(root.path())
        .execute_batch("CREATE TRIGGER fail_install BEFORE INSERT ON objects BEGIN SELECT RAISE(ABORT,'injected SQL commit failure'); END;")
        .expect("failure trigger");
    assert!(matches!(writer.commit().await, Err(SpoolError::Catalog(_))));
    let path = spool.0.object_path(&identity(b"verified").sha256);
    assert!(path.is_file());
    assert!(spool.lookup(identity(b"verified")).is_none());
    assert_eq!(spool.accounting().reserved, 8);
    assert_eq!(pending(root.path()), 8);
    assert_eq!(
        database(root.path())
            .query_row("SELECT COUNT(*) FROM objects", [], |row| read_unsigned(
                row, 0
            ))
            .expect("count"),
        0
    );
    drop(spool);
    database(root.path())
        .execute_batch("DROP TRIGGER fail_install;")
        .expect("remove injected failure");
    let reopened = open(root.path());
    assert!(!path.exists());
    assert_eq!(reopened.accounting().reserved, 0);
    assert!(reopened.lookup(identity(b"verified")).is_none());
}

#[tokio::test]
async fn uncertain_temporary_cleanup_retains_bytes_and_reconciles_before_admission() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let writer = writer(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Package,
    )
    .await;
    *lock_unpoisoned(&spool.0.failure) = Some("temporary-unlink");
    writer.abort().await;
    assert_eq!(spool.accounting().reserved, 8);
    assert_eq!(pending(root.path()), 8);
    assert!(matches!(spool.reserve(1), Err(SpoolError::AdmissionClosed)));
    assert_eq!(
        fs::read_dir(root.path().join("temporary"))
            .expect("temporary")
            .count(),
        1
    );
    drop(spool);
    let reopened = open(root.path());
    assert_eq!(reopened.accounting().reserved, 0);
    assert_eq!(pending(root.path()), 0);
    assert!(reopened.reserve(8).is_ok());
}

#[tokio::test]
async fn reader_stream_and_all_explicit_pin_classes_protect_reclaim() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Metadata,
    )
    .await;
    let expected = object.identity();
    let path = object.path().to_owned();
    assert_eq!(spool.reclaim(8).expect("reader pin"), 0);
    let mut stream = object.stream_range(0, 7).expect("range");
    drop(object);
    assert_eq!(spool.reclaim(8).expect("stream pin"), 0);
    assert_eq!(
        stream.next().await.expect("chunk").expect("read"),
        b"verified"[..]
    );
    drop(stream);
    for kind in [PinKind::Fill, PinKind::Upload, PinKind::Generation] {
        let pin = spool
            .pin(expected, kind)
            .expect("pin operation")
            .expect("resident");
        assert_eq!(spool.reclaim(8).expect("explicit pin"), 0);
        assert!(path.exists());
        drop(pin);
    }
    assert_eq!(spool.reclaim(8).expect("unpinned metadata reclaim"), 8);
    assert!(!path.exists());
    assert!(spool.lookup(expected).is_none());
    assert_eq!(spool.accounting().installed, 0);
}

#[tokio::test]
async fn generation_references_are_idempotent_and_persist_across_restart() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(
        &spool,
        Bytes::from_static(b"metadata closure"),
        ReservationClass::Metadata,
    )
    .await;
    let expected = object.identity();
    let generation = Sha256Digest::of(b"authenticated InRelease");
    spool
        .retain_generation(generation, &[expected])
        .expect("retain");
    spool
        .retain_generation(generation, &[expected])
        .expect("idempotent retain");
    drop(object);
    drop(spool);
    let reopened = open(root.path());
    assert_eq!(
        reopened
            .reclaim(expected.size)
            .expect("persisted generation pin"),
        0
    );
    reopened
        .release_generation(generation)
        .expect("retirement owner release");
    assert_eq!(
        reopened.reclaim(expected.size).expect("eligible metadata"),
        expected.size
    );
}

#[tokio::test]
async fn pending_packages_never_gain_eviction_authority_from_upload_readback_alone() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(
        &spool,
        Bytes::from_static(b"package capture pending"),
        ReservationClass::Package,
    )
    .await;
    let expected = object.identity();
    let path = object.path().to_owned();
    drop(object);
    assert_eq!(
        spool.reclaim(u64::MAX).expect("no receipt, not eligible"),
        0
    );
    assert!(path.exists());
    assert_eq!(spool.accounting().installed, expected.size);
    assert!(spool.lookup(expected).is_some());
}

#[tokio::test]
async fn all_pinned_admission_refuses_then_same_owner_reclaims_after_release() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut limits = config(root.path());
    limits.spool.managed_ceiling = 8 * MIB;
    limits.temporary_ceiling = 4 * MIB;
    limits.metadata_ceiling = 8 * MIB;
    limits.catalog_ceiling = 8 * MIB;
    limits.eviction_high_watermark = 6 * MIB;
    limits.eviction_low_watermark = 4 * MIB;
    let spool = Spool::open_durable(limits).expect("bounded store");
    let object = install(
        &spool,
        Bytes::from(vec![7; (3 * MIB) as usize]),
        ReservationClass::Metadata,
    )
    .await;
    let expected = object.identity();
    let path = object.path().to_owned();
    assert!(matches!(
        spool.reserve_class(3 * MIB, ReservationClass::Metadata),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    assert!(path.exists());
    assert_eq!(spool.accounting().installed, 3 * MIB);
    assert!(spool.usage().expect("bounds").managed_bytes <= 8 * MIB);
    drop(object);
    let reservation = spool
        .reserve_class(3 * MIB, ReservationClass::Metadata)
        .expect("bounded eligible reclaim");
    assert!(spool.lookup(expected).is_none());
    assert!(!path.exists());
    assert_eq!(spool.accounting().installed, 0);
    drop(reservation);
}

#[tokio::test]
async fn lookup_cannot_acquire_a_lease_after_owner_marks_evicting() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Metadata,
    )
    .await;
    let expected = object.identity();
    drop(object);
    let mut gate = Gate::arm(&spool, "evicting");
    let owner = spool.clone();
    let eviction = std::thread::spawn(move || owner.reclaim(8));
    gate.entered().await;
    let owner = spool.clone();
    let lookup = std::thread::spawn(move || owner.lookup(expected));
    gate.release();
    assert_eq!(
        eviction.join().expect("eviction thread").expect("eviction"),
        8
    );
    assert!(lookup.join().expect("lookup thread").is_none());
}

#[tokio::test]
async fn detached_positional_read_is_still_a_lease_until_its_final_handle_closes() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Metadata,
    )
    .await;
    let path = object.path().to_owned();
    let mut stream = object.stream_range(0, 7).expect("range");
    let mut gate = Gate::arm(&spool, "read");
    let read = tokio::spawn(async move { stream.next().await });
    gate.entered().await;
    read.abort();
    assert!(read.await.expect_err("aborted read").is_cancelled());
    drop(object);
    assert_eq!(spool.reclaim(8).expect("detached pin"), 0);
    assert!(path.exists());
    assert_eq!(spool.accounting().installed, 8);
    gate.release();
    drop(
        Arc::clone(spool.0.io_permits())
            .acquire_many_owned(2)
            .await
            .expect("drained pool"),
    );
    assert_eq!(spool.reclaim(8).expect("final descriptor closed"), 8);
    assert!(!path.exists());
}

#[tokio::test]
async fn failed_eviction_cleanup_preserves_accounting_and_restart_finishes_it() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Metadata,
    )
    .await;
    let expected = object.identity();
    let path = object.path().to_owned();
    drop(object);
    *lock_unpoisoned(&spool.0.failure) = Some("unlink");
    assert!(spool.reclaim(8).is_err());
    assert!(path.exists());
    assert!(spool.lookup(expected).is_none());
    assert_eq!(spool.accounting().installed, 8);
    assert!(matches!(spool.reserve(1), Err(SpoolError::AdmissionClosed)));
    drop(spool);
    let reopened = open(root.path());
    assert!(!path.exists());
    assert_eq!(reopened.accounting().installed, 0);
    assert!(reopened.lookup(expected).is_none());
}

#[test]
fn physical_floor_metadata_staging_and_zero_byte_entry_bounds_are_enforced() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut spool = open(root.path());
    Arc::get_mut(&mut spool.0)
        .expect("no escaped owners")
        .durable
        .as_mut()
        .expect("durable")
        .free_space_floor = u64::MAX;
    assert!(matches!(
        spool.reserve(1),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    assert!(matches!(
        spool.reserve(0),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    assert_eq!(
        spool.usage().expect("no physical admission").reservations,
        0
    );
    assert_eq!(spool.accounting().reserved, 0);
    Arc::get_mut(&mut spool.0)
        .expect("no owners")
        .durable
        .as_mut()
        .expect("durable")
        .free_space_floor = 0;
    let package = spool.reserve(3 * MIB).expect("package staging share");
    assert!(matches!(
        spool.reserve(1),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    let metadata = spool
        .reserve_class(MIB, ReservationClass::Metadata)
        .expect("reserved metadata headroom");
    assert_eq!(spool.accounting().reserved, 4 * MIB);
    drop((package, metadata));
    drop(spool);
    let mut limits = config(root.path());
    limits.max_entries = 3;
    let spool = Spool::open_durable(limits).expect("bounded entries");
    let held = [
        spool.reserve(0).expect("one"),
        spool.reserve(0).expect("two"),
        spool.reserve(0).expect("three"),
    ];
    assert!(matches!(
        spool.reserve(0),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    assert_eq!(spool.usage().expect("usage").reservations, 3);
    drop(held);
    assert!(spool.reserve(0).is_ok());
}

#[tokio::test]
async fn actual_wal_growth_is_charged_and_stops_new_admission_but_not_verified_hits() {
    let root = tempfile::tempdir().expect("tempdir");
    let limits = config(root.path());
    let spool = Spool::open_durable(limits.clone()).expect("store");
    let object = install(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Package,
    )
    .await;
    let expected = object.identity();
    OpenOptions::new()
        .write(true)
        .open(root.path().join("state.sqlite-wal"))
        .expect("WAL")
        .set_len(limits.catalog_ceiling + 1)
        .expect("grow actual WAL file");
    let usage = spool.usage().expect("usage");
    assert!(usage.catalog_bytes > limits.catalog_ceiling);
    assert!(matches!(
        spool.reserve(1),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    let hit = spool.lookup(expected).expect("verified hit unaffected");
    assert_eq!(hit.read_bounded(8).await.expect("read"), b"verified");
}

#[test]
fn memory_budget_missing_catalog_and_cross_mode_startups_fail_closed() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut limits = config(root.path());
    limits.catalog_memory_budget = 1;
    assert!(Spool::open_durable(limits).is_err());
    let spool = open(root.path());
    assert!(matches!(
        Spool::open_durable(config(root.path())),
        Err(SpoolError::NotExclusive(_))
    ));
    drop(spool);
    fs::remove_file(root.path().join("state.sqlite")).expect("lose catalog");
    assert!(matches!(
        Spool::open_durable(config(root.path())),
        Err(SpoolError::UnsafeDirectory(_))
    ));
    let fixture_root = tempfile::tempdir().expect("tempdir");
    drop(Spool::open_exclusive_fixture(config(fixture_root.path()).spool).expect("fixture"));
    assert!(matches!(
        Spool::open_durable(config(fixture_root.path())),
        Err(SpoolError::UnsafeDirectory(_))
    ));
}

#[tokio::test]
async fn shared_metadata_identity_becomes_package_retention_protected_before_reuse() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let metadata = install(
        &spool,
        Bytes::from_static(b"shared bytes"),
        ReservationClass::Metadata,
    )
    .await;
    let expected = metadata.identity();
    drop(metadata);
    let package = install(
        &spool,
        Bytes::from_static(b"shared bytes"),
        ReservationClass::Package,
    )
    .await;
    assert_eq!(spool.accounting().installed, expected.size);
    assert_eq!(
        lock_unpoisoned(&spool.0.lifetime.ledger).metadata_installed(),
        0
    );
    assert_eq!(
        database(root.path())
            .query_row(
                "SELECT class FROM objects WHERE digest=?1",
                [expected.sha256.to_hex()],
                |row| row.get::<_, i64>(0)
            )
            .expect("persisted class"),
        0
    );
    drop(package);
    assert_eq!(
        spool
            .reclaim(expected.size)
            .expect("pending package protected"),
        0
    );
    drop(spool);
    let reopened = open(root.path());
    assert_eq!(
        reopened
            .reclaim(expected.size)
            .expect("persistent protection"),
        0
    );
    assert!(reopened.lookup(expected).is_some());
}

#[tokio::test]
async fn a_rejected_pinned_clock_candidate_does_not_hide_the_next_eligible_object() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let pinned = install(
        &spool,
        Bytes::from_static(b"pinned_a"),
        ReservationClass::Metadata,
    )
    .await;
    let eligible = install(
        &spool,
        Bytes::from_static(b"evict__b"),
        ReservationClass::Metadata,
    )
    .await;
    let path = eligible.path().to_owned();
    drop(eligible);
    assert_eq!(
        spool.reclaim(8).expect("continue after skipped candidate"),
        8
    );
    assert!(pinned.path().exists());
    assert!(!path.exists());
    assert_eq!(spool.accounting().installed, 8);
}

#[tokio::test]
async fn failed_sql_after_unlink_keeps_the_open_inode_charged_until_owner_shutdown() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let object = install(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Metadata,
    )
    .await;
    let expected = object.identity();
    let path = object.path().to_owned();
    drop(object);
    *lock_unpoisoned(&spool.0.failure) = Some("eviction-sql");
    assert!(spool.reclaim(8).is_err());
    assert!(!path.exists());
    assert_eq!(
        spool.accounting().installed,
        8,
        "the unlinked open inode is not free capacity"
    );
    assert!(spool.lookup(expected).is_none());
    assert!(matches!(spool.reserve(1), Err(SpoolError::AdmissionClosed)));
    assert!(matches!(
        Spool::open_durable(config(root.path())),
        Err(SpoolError::NotExclusive(_))
    ));
    drop(spool);
    let reopened = open(root.path());
    assert_eq!(reopened.accounting().installed, 0);
    assert!(reopened.lookup(expected).is_none());
}

#[test]
fn failed_reservation_sql_retains_the_uncertain_charge_and_closes_admission() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    database(root.path())
        .execute_batch("CREATE TRIGGER fail_reservation BEFORE INSERT ON reservations BEGIN SELECT RAISE(ABORT,'injected reservation failure'); END;")
        .expect("failure trigger");
    assert!(matches!(spool.reserve(8), Err(SpoolError::Catalog(_))));
    assert_eq!(spool.accounting().reserved, 8);
    assert!(matches!(spool.reserve(1), Err(SpoolError::AdmissionClosed)));
    database(root.path())
        .execute_batch("DROP TRIGGER fail_reservation;")
        .expect("remove injected failure");
    drop(spool);
    let reopened = open(root.path());
    assert_eq!(reopened.accounting().reserved, 0);
    assert!(reopened.reserve(8).is_ok());
}

#[tokio::test]
async fn generation_reference_transaction_preserves_other_sql_reservations_and_physical_floor() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut limits = config(root.path());
    limits.catalog_ceiling = 6 * MIB;
    let mut spool = Spool::open_durable(limits).expect("store");
    let object = install(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Metadata,
    )
    .await;
    let expected = object.identity();
    let generation = Sha256Digest::of(b"generation");
    let first = spool.reserve(0).expect("first SQL headroom");
    let second = spool.reserve(0).expect("second SQL headroom");
    assert!(matches!(
        spool.retain_generation(generation, &[expected]),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    drop((first, second));
    Arc::get_mut(&mut spool.0)
        .expect("no SpoolInner owners")
        .durable
        .as_mut()
        .expect("durable")
        .free_space_floor = u64::MAX;
    assert!(matches!(
        spool.retain_generation(generation, &[expected]),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    Arc::get_mut(&mut spool.0)
        .expect("no SpoolInner owners")
        .durable
        .as_mut()
        .expect("durable")
        .free_space_floor = 0;
    spool
        .retain_generation(generation, &[expected])
        .expect("bounded reference transaction");
    assert!(
        spool.retain_generation(generation, &[expected; 9]).is_err(),
        "large transactions are split by their owner"
    );
}

#[tokio::test]
async fn zero_byte_admission_cannot_overpromise_managed_sql_headroom() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut limits = config(root.path());
    limits.spool.managed_ceiling = 5 * MIB;
    limits.metadata_ceiling = 5 * MIB;
    limits.catalog_ceiling = 5 * MIB;
    limits.eviction_high_watermark = 4 * MIB;
    limits.eviction_low_watermark = 3 * MIB;
    let spool = Spool::open_durable(limits).expect("small store");
    let package = install(
        &spool,
        Bytes::from(vec![7; (2 * MIB) as usize]),
        ReservationClass::Package,
    )
    .await;
    drop(package);
    let first = spool.reserve(0).expect("one SQL headroom reservation fits");
    assert!(matches!(
        spool.reserve(0),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    let usage = spool.usage().expect("usage");
    assert_eq!(usage.reservations, 1);
    assert!(usage.managed_bytes <= 5 * MIB);
    assert_eq!(
        database(root.path())
            .query_row(
                "SELECT COUNT(*) FROM reservations",
                [],
                |row| read_unsigned(row, 0)
            )
            .expect("rows"),
        1
    );
    drop(first);
    assert!(spool.reserve(0).is_ok());
}

#[tokio::test]
async fn ordinary_retirement_capacity_refusal_does_not_poison_future_admission() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut limits = config(root.path());
    limits.catalog_ceiling = 6 * MIB;
    let spool = Spool::open_durable(limits).expect("store");
    let object = install(
        &spool,
        Bytes::from_static(b"verified"),
        ReservationClass::Metadata,
    )
    .await;
    let generation = Sha256Digest::of(b"generation");
    spool
        .retain_generation(generation, &[object.identity()])
        .expect("retain");
    let first = spool.reserve(0).expect("first SQL headroom");
    let second = spool.reserve(0).expect("second SQL headroom");
    assert!(matches!(
        spool.release_generation(generation),
        Err(SpoolError::CapacityExhausted { .. })
    ));
    assert!(spool.usage().expect("not poisoned").admission_open);
    drop((first, second));
    spool
        .release_generation(generation)
        .expect("capacity refusal is recoverable");
    assert!(spool.reserve(0).is_ok());
}

#[tokio::test]
async fn snapshot_adoption_preserves_inode_and_exact_accounting_at_object_cap() {
    use std::os::unix::fs::MetadataExt;

    let root = tempfile::tempdir().expect("tempdir");
    let mut limits = config(root.path());
    limits.spool.max_object_size = MIB;
    limits.metadata_temporary_reserve = 4096;
    let spool = Spool::open_durable(limits).expect("store");
    let snapshot = super::SnapshotFile::create(&spool, MIB)
        .await
        .expect("cap plus step is admitted as separate reservations");
    let path = snapshot.path().expect("temporary path").to_owned();
    let bytes = b"one inode, no full snapshot copy";
    fs::write(&path, bytes).expect("snapshot output");
    let inode = fs::metadata(&path).expect("temporary metadata").ino();
    assert_eq!(spool.accounting().reserved, MIB + 256 * 1024);
    assert_eq!(pending(root.path()), MIB + 256 * 1024);
    let mut gate = Gate::arm(&spool, "snapshot-install");
    let job = tokio::spawn(async move {
        snapshot
            .install(std::time::Instant::now() + std::time::Duration::from_secs(30))
            .await
    });
    gate.entered().await;
    assert_eq!(spool.accounting().reserved, bytes.len() as u64);
    assert_eq!(pending(root.path()), bytes.len() as u64);
    assert_eq!(spool.usage().expect("usage").reservations, 1);
    assert_eq!(
        fs::read_dir(root.path().join("temporary"))
            .expect("temporary directory")
            .count(),
        1
    );
    gate.release();
    let snapshot = job.await.expect("snapshot task").expect("installed");
    let object = snapshot.object().expect("owned object");
    assert_eq!(object.identity(), identity(bytes));
    assert_eq!(
        fs::metadata(object.path())
            .expect("installed metadata")
            .ino(),
        inode
    );
    assert_eq!(object.read_bounded(128).await.expect("read"), bytes);
    assert!(!path.exists());
    assert_eq!(spool.accounting().reserved, 0);
    assert_eq!(pending(root.path()), 0);
    assert_eq!(spool.accounting().installed, bytes.len() as u64);
    snapshot.cleanup().expect("owned cleanup");
    assert_eq!(spool.accounting().installed, 0);
}

#[tokio::test]
async fn snapshot_over_cap_hash_or_install_failure_cleans_raw_reservations() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let snapshot = super::SnapshotFile::create(&spool, MIB)
        .await
        .expect("snapshot reservation");
    let path = snapshot.path().expect("path").to_owned();
    OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("owned file")
        .set_len(MIB + 1)
        .expect("sparse oversized output");
    assert!(matches!(
        snapshot
            .install(std::time::Instant::now() + std::time::Duration::from_secs(30))
            .await,
        Err(SpoolError::ObjectTooLarge { size, max }) if size == MIB + 1 && max == MIB
    ));
    assert!(!path.exists());
    assert_eq!(pending(root.path()), 0);
    assert_eq!(spool.accounting().reserved, 0);
    let snapshot = super::SnapshotFile::create(&spool, MIB)
        .await
        .expect("second snapshot");
    let path = snapshot.path().expect("path").to_owned();
    fs::write(&path, b"expired hash deadline").expect("output");
    assert!(snapshot.install(std::time::Instant::now()).await.is_err());
    assert!(!path.exists());
    assert_eq!(pending(root.path()), 0);
    assert_eq!(spool.accounting().reserved, 0);
    assert_eq!(spool.accounting().installed, 0);
    let snapshot = super::SnapshotFile::create(&spool, MIB)
        .await
        .expect("third snapshot");
    let path = snapshot.path().expect("path").to_owned();
    fs::write(&path, b"failed fsync").expect("output");
    *lock_unpoisoned(&spool.0.failure) = Some("file-fsync");
    assert!(
        snapshot
            .install(std::time::Instant::now() + std::time::Duration::from_secs(30))
            .await
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(pending(root.path()), 0);
    assert_eq!(spool.accounting().reserved, 0);
    assert_eq!(spool.accounting().installed, 0);
}

#[tokio::test]
async fn snapshot_cleanup_failure_retains_charge_until_recovery() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    let snapshot = super::SnapshotFile::create(&spool, MIB)
        .await
        .expect("snapshot");
    let path = snapshot.path().expect("path").to_owned();
    fs::write(&path, b"expired hash deadline").expect("output");
    *lock_unpoisoned(&spool.0.failure) = Some("temporary-unlink");
    assert!(snapshot.install(std::time::Instant::now()).await.is_err());
    assert!(path.exists());
    assert_eq!(pending(root.path()), MIB);
    assert_eq!(spool.accounting().reserved, MIB);
    assert!(!spool.usage().expect("usage").admission_open);
    drop(spool);
    let spool = open(root.path());
    assert!(!path.exists());
    assert_eq!(pending(root.path()), 0);
    assert_eq!(spool.accounting().reserved, 0);
}

#[tokio::test]
async fn cancelled_snapshot_worker_retains_accounting_and_cleans_undelivered_install() {
    for (operation, expected_charge) in
        [("snapshot-hash", MIB + 256 * 1024), ("snapshot-install", 8)]
    {
        let root = tempfile::tempdir().expect("tempdir");
        let spool = open(root.path());
        let snapshot = super::SnapshotFile::create(&spool, MIB)
            .await
            .expect("snapshot");
        let path = snapshot.path().expect("path").to_owned();
        fs::write(&path, b"snapshot").expect("output");
        let mut gate = Gate::arm(&spool, operation);
        let job = tokio::spawn(async move {
            snapshot
                .install(std::time::Instant::now() + std::time::Duration::from_secs(30))
                .await
        });
        gate.entered().await;
        job.abort();
        assert!(matches!(job.await, Err(error) if error.is_cancelled()));
        assert!(path.exists());
        assert_eq!(spool.accounting().reserved, expected_charge);
        assert_eq!(pending(root.path()), expected_charge);
        gate.release();
        let permits = Arc::clone(spool.0.io_permits())
            .acquire_many_owned(2)
            .await
            .expect("all detached I/O finished");
        drop(permits);
        assert!(!path.exists());
        assert_eq!(pending(root.path()), 0);
        assert_eq!(spool.accounting().reserved, 0);
        assert_eq!(spool.accounting().installed, 0);
        assert!(spool.lookup(identity(b"snapshot")).is_none());
    }
}

#[tokio::test]
async fn owned_installed_snapshot_cleans_error_and_cancel_but_preserves_shared_lease() {
    let root = tempfile::tempdir().expect("tempdir");
    let spool = open(root.path());
    for cancelled in [false, true] {
        let snapshot = super::SnapshotFile::create(&spool, MIB)
            .await
            .expect("snapshot");
        fs::write(snapshot.path().expect("path"), b"snapshot").expect("output");
        let snapshot = snapshot
            .install(std::time::Instant::now() + std::time::Duration::from_secs(30))
            .await
            .expect("installed");
        let (ready, started) = tokio::sync::oneshot::channel();
        let job = tokio::spawn(async move {
            let _snapshot = snapshot;
            ready.send(()).expect("started");
            if cancelled {
                std::future::pending::<()>().await;
            }
            Err::<(), _>(std::io::Error::other("local operation failed"))
        });
        started.await.expect("started");
        if cancelled {
            job.abort();
            assert!(job.await.expect_err("cancelled").is_cancelled());
        } else {
            assert!(job.await.expect("error task").is_err());
        }
        assert_eq!(spool.accounting().installed, 0);
        assert!(spool.lookup(identity(b"snapshot")).is_none());
    }
    let snapshot = super::SnapshotFile::create(&spool, MIB)
        .await
        .expect("snapshot");
    fs::write(snapshot.path().expect("path"), b"snapshot").expect("output");
    let snapshot = snapshot
        .install(std::time::Instant::now() + std::time::Duration::from_secs(30))
        .await
        .expect("installed");
    let lease = snapshot.object().expect("object").clone();
    drop(snapshot);
    assert_eq!(
        lease.read_bounded(8).await.expect("shared read"),
        b"snapshot"
    );
    assert_eq!(spool.accounting().installed, 8);
    drop(lease);
    assert!(
        spool
            .discard_unreferenced_metadata(identity(b"snapshot"))
            .expect("cleanup")
    );
}
