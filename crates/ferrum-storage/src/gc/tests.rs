#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::{budget::BudgetClass, capture::tests as capture_test, recovery::test_support};
use ferrum_apt::digest::ObjectIdentity;
use tokio::time::Duration;
fn owner(manager: &crate::capture::CaptureManager) -> OfflineGc {
    OfflineGc {
        spool: manager.spool().clone(),
        store: manager.store().clone(),
    }
}
fn receipt_key(repository: &str, identity: ObjectIdentity) -> String {
    format!(
        "linux-packages/v1/captures/{repository}/{}/{}.json",
        Sha256Digest::of(b"pool/main/p/package_1_all.deb"),
        identity.sha256
    )
}
#[tokio::test]
async fn unknown_backups_checkpoint_names_and_unowned_hashes_are_never_delete_authority() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, ledger, requests) = capture_test::setup(spool, Vec::new());
    let gc = owner(&manager);
    let now = crate::s3::production_now().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancel = CancellationToken::new();
    for key in [
        format!(
            "linux-packages/v1/objects/sha256/{}",
            Sha256Digest::of(b"unknown")
        ),
        format!(
            "linux-packages/v1/backups/2026071700/{}.sqlite",
            Sha256Digest::of(b"backup")
        ),
        "linux-packages/unknown-user-object".into(),
    ] {
        ledger
            .reserve_storage(&key, 1, BudgetClass::Control)
            .unwrap();
        assert!(!gc.candidate(&key, now, deadline, &cancel).unwrap());
    }
    assert!(
        gc.candidate(
            "linux-checkpoints/v1/checkpoints/debian/stable.json",
            now,
            deadline,
            &cancel
        )
        .is_err()
    );
    assert!(requests.snapshot().unwrap().is_empty());
}
#[tokio::test]
async fn receipts_are_deleted_before_blob_and_every_reference_retention_is_directly_rechecked() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, ledger, _) = capture_test::setup(spool.clone(), Vec::new());
    let object = capture_test::install(&spool, b"retired retained object").await;
    let identity = object.identity();
    let now = crate::s3::production_now().unwrap();
    capture_test::seed_paths(&spool, identity, true, now - 40 * 86400, now + 1);
    let gc = owner(&manager);
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancel = CancellationToken::new();
    let blob = format!("linux-packages/v1/objects/sha256/{}", identity.sha256);
    ledger
        .reserve_storage(&blob, identity.size, BudgetClass::Package)
        .unwrap();
    let a = receipt_key("origin-a", identity);
    let b = receipt_key("origin-b", identity);
    for key in [&a, &b] {
        ledger
            .reserve_storage(key, 512, BudgetClass::Control)
            .unwrap();
    }
    assert!(!gc.candidate(&a, now, deadline, &cancel).unwrap());
    spool
        .catalog_write(move |connection| {
            connection.execute(
                "UPDATE capture_paths SET referenced=0,retain_until=?1",
                [now - 1],
            )?;
            connection.execute("UPDATE capture_blobs SET retain_until=?1", [now - 1])?;
            Ok(())
        })
        .unwrap();
    assert!(gc.candidate(&a, now, deadline, &cancel).unwrap());
    assert!(!gc.candidate(&blob, now, deadline, &cancel).unwrap());
    // Only the persisted conditional-delete outcome boundary may acknowledge a
    // deletion. This test exercises that local transition, not provider behavior.
    assert!(gc.record_delete(&a, now).is_err());
    assert_eq!(ledger.usage().unwrap().storage, identity.size + 1024);
    journal::prepare(&spool, &a, now).unwrap();
    assert!(!manager.usage().unwrap().coverage);
    gc.record_delete(&a, now).unwrap();
    assert!(manager.usage().unwrap().coverage);
    assert!(!gc.candidate(&blob, now, deadline, &cancel).unwrap());
    journal::prepare(&spool, &b, now).unwrap();
    gc.record_delete(&b, now).unwrap();
    assert!(gc.candidate(&blob, now, deadline, &cancel).unwrap());
    let generation = Sha256Digest::of(b"new retained generation");
    spool
        .catalog_write(move |connection| {
            connection.execute(
                "INSERT INTO capture_generation_refs(generation,digest) VALUES(?1,?2)",
                params![generation.to_hex(), identity.sha256.to_hex()],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(!gc.candidate(&blob, now, deadline, &cancel).unwrap());
    spool
        .catalog_write(move |connection| {
            connection.execute(
                "DELETE FROM capture_generation_refs WHERE generation=?1",
                [generation.to_hex()],
            )?;
            Ok(())
        })
        .unwrap();
    drop(object);
    journal::prepare(&spool, &blob, now).unwrap();
    gc.record_delete(&blob, now).unwrap();
    assert!(spool.lookup(identity).is_none());
    assert_eq!(ledger.usage().unwrap().storage, 0);
}
#[test]
fn interrupted_gc_cannot_regrant_coverage_after_an_unfinished_full_reconciliation() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, _, _) = capture_test::setup(spool.clone(), Vec::new());
    let key = format!(
        "linux-packages/v1/objects/sha256/{}",
        Sha256Digest::of(b"intent")
    );
    journal::prepare(&spool, &key, 1).unwrap();
    assert!(!manager.usage().unwrap().coverage);
    assert!(owner(&manager).ensure_open().is_ok());
    assert!(owner(&manager).ensure_certain().is_err());
    manager.begin_reconciliation(2).unwrap();
    journal::cancel(&spool, &key).unwrap();
    assert!(!manager.usage().unwrap().coverage);
    assert!(owner(&manager).ensure_open().is_err());
}
#[tokio::test]
async fn current_public_metadata_and_owned_multipart_state_block_gc() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, ledger, _) = capture_test::setup(spool.clone(), Vec::new());
    let object = capture_test::install(&spool, b"multipart retained object").await;
    let identity = object.identity();
    let now = crate::s3::production_now().unwrap();
    capture_test::seed_paths(&spool, identity, true, now - 40 * 86400, now - 1);
    let key = receipt_key("origin-a", identity);
    ledger
        .reserve_storage(&key, 512, BudgetClass::Control)
        .unwrap();
    let recorded = key.clone();
    spool
        .catalog_write(move |connection| {
            connection.execute("UPDATE capture_paths SET referenced=0", [])?;
            connection.execute(
                "INSERT INTO multipart_uploads(key,upload_id,started,size,completing) VALUES(?1,'owned-id',?2,512,1)",
                params![recorded, now - 86401],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(
        !owner(&manager)
            .candidate(
                &key,
                now,
                Instant::now() + Duration::from_secs(10),
                &CancellationToken::new()
            )
            .unwrap()
    );
}
