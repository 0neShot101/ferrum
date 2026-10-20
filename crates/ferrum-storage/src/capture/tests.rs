#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::{
    budget::{BudgetLedger, BudgetLimits},
    recovery::{self, test_support},
    s3::{
        S3Config,
        testing::{ScriptedRequests, ScriptedResponse},
    },
};
use bytes::Bytes;
use tokio::time::Duration;
pub(crate) fn response(method: &'static str, status: u16, body: &[u8]) -> ScriptedResponse {
    ScriptedResponse {
        method,
        status,
        content_length: body.len() as u64,
        body: body.to_vec(),
        delay: Duration::ZERO,
        headers: Vec::new(),
        lose_ack: false,
    }
}
pub(crate) fn limits() -> BudgetLimits {
    BudgetLimits {
        storage: 256 * 1024 * 1024,
        storage_control: 32 * 1024 * 1024,
        monthly_download: 1024 * 1024 * 1024,
        download_control: 128 * 1024 * 1024,
    }
}
pub(crate) fn config(spool: &Spool) -> S3Config {
    let credentials = spool.root().parent().unwrap().join("scripted.credentials");
    if !credentials.exists() {
        std::fs::write(&credentials, b"non-secret scripted fixture").unwrap();
    }
    S3Config {
        endpoint: crate::s3::config::DEFAULT_ENDPOINT.into(),
        region: crate::s3::config::DEFAULT_REGION.into(),
        bucket: crate::s3::config::DEFAULT_BUCKET.into(),
        package_prefix: "linux-packages/".into(),
        checkpoint_prefix: "linux-checkpoints/".into(),
        credentials_file: credentials,
        shared_nonisolated: true,
    }
}
pub(crate) fn setup(
    spool: Spool,
    responses: Vec<ScriptedResponse>,
) -> (CaptureManager, BudgetLedger, ScriptedRequests) {
    let ledger = BudgetLedger::initialize(spool.clone(), limits()).unwrap();
    let (store, requests) =
        S3Store::scripted_production(config(&spool), ledger.clone(), responses).unwrap();
    let manager = CaptureManager::new(spool, Arc::new(store)).unwrap();
    manager
        .initialize(crate::s3::production_now().unwrap())
        .unwrap();
    (manager, ledger, requests)
}
pub(crate) async fn install(spool: &Spool, bytes: &'static [u8]) -> crate::VerifiedObject {
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(bytes),
        size: bytes.len() as u64,
    };
    let reservation = spool.reserve(identity.size).unwrap();
    let mut writer = spool.begin_write(reservation, identity).await.unwrap();
    writer.write(Bytes::from_static(bytes)).await.unwrap();
    writer.commit().await.unwrap()
}
/// These rows isolate already-authenticated persistence/owner transitions. The
/// real verifier/Packages authority is exercised independently below, not fabricated
/// by these setup rows or claimed as an end-to-end signed package installation.
pub(crate) fn seed_paths(
    spool: &Spool,
    identity: ObjectIdentity,
    receipt: bool,
    first: i64,
    retain: i64,
) {
    let generation = Sha256Digest::of(b"post-authenticated owner transition").to_hex();
    spool
        .catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,?2,?3,?4,0)",
                params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?,
                    first,
                    retain
                ],
            )?;
            transaction.execute(
                "INSERT INTO capture_proofs(generation,manifest,durable) VALUES(?1,'{}',1)",
                [&generation],
            )?;
            for repository in ["origin-a", "origin-b"] {
                let path = "pool/main/p/package_1_all.deb";
                transaction.execute(
                    "INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES(?1,?2,?3,?4,?5,?6,1,?7)",
                    params![
                        repository,
                        path,
                        Sha256Digest::of(path.as_bytes()).to_hex(),
                        identity.sha256.to_hex(),
                        generation,
                        receipt,
                        retain
                    ],
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
}
pub(super) async fn authenticated(
    root: &std::path::Path,
) -> (test_support::SignedFixture, VerifiedCaptureProof) {
    let fixture = test_support::signed_fixture(root).await;
    let proof = Arc::new(
        recovery::verify_historical_proof(
            &fixture.spool,
            &fixture.manifest,
            &fixture.policy,
            &fixture.verifier,
        )
        .await
        .unwrap(),
    );
    let path =
        RepositoryPath::parse_decoded("pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb")
            .unwrap();
    let identity = ObjectIdentity {
        sha256: Sha256Digest::from_hex(
            "bbf3d2c1ae800e53631d807f7818799a9de281f178f408658e392907a2036e62",
        )
        .unwrap(),
        size: 1234,
    };
    let capture = VerifiedCaptureProof::from_index(
        &fixture.spool,
        proof,
        "main/binary-amd64/Packages",
        path,
        identity,
        Instant::now() + Duration::from_secs(60),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    (fixture, capture)
}
#[tokio::test]
async fn authenticated_index_and_capture_capabilities_cannot_cross_disk_owners() {
    let root = tempfile::tempdir().unwrap();
    let (fixture, capture) = authenticated(&root.path().join("first")).await;
    let other = test_support::signed_fixture(&root.path().join("second")).await;
    let deadline = Instant::now() + Duration::from_secs(60);
    let cancel = CancellationToken::new();
    assert!(matches!(
        stage_package_index(
            &other.spool,
            capture.proof.clone(),
            "main/binary-amd64/Packages",
            deadline,
            &cancel
        )
        .await,
        Err(CaptureError::Proof)
    ));
    let (manager, _, requests) = setup(other.spool.clone(), Vec::new());
    assert!(matches!(
        manager.reserve(&capture, crate::s3::production_now().unwrap()),
        Err(CaptureError::Proof)
    ));
    assert!(matches!(
        manager
            .capture_verified_hit(&capture, deadline, &cancel)
            .await,
        Err(CaptureError::Proof)
    ));
    let receipt = CaptureReceipt {
        schema_version: 1,
        repository: capture.repository().into(),
        public_package_path: capture.path().as_str().into(),
        sha256: capture.identity().sha256.to_hex(),
        size: capture.identity().size,
        proof_generation_id: capture.manifest().generation_id.clone(),
        first_capture_time: 1,
        package_signature: None,
    };
    assert!(matches!(
        manager
            .recover_receipt(&receipt, &capture, 2, deadline, &cancel)
            .await,
        Err(CaptureError::Proof)
    ));
    assert!(requests.snapshot().unwrap().is_empty());
    let source = capture.proof.artifact("InRelease").unwrap().clone();
    assert!(matches!(
        recovery::materialize_derived(
            &other.spool,
            source,
            "Packages.gz",
            capture.identity(),
            cancel
        )
        .await,
        Err(crate::checkpoint::CheckpointError::Proof)
    ));
    drop(fixture);
}
#[tokio::test]
async fn actual_signed_compressed_packages_bind_exact_filename_size_and_digest() {
    let root = tempfile::tempdir().unwrap();
    let (fixture, capture) = authenticated(&root.path().join("state")).await;
    let index = stage_package_index(
        &fixture.spool,
        capture.proof.clone(),
        "main/binary-amd64/Packages",
        Instant::now() + Duration::from_secs(60),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        index.lookup(capture.path()).unwrap(),
        Some(capture.identity())
    );
    assert!(
        index
            .authorize(
                capture.proof.clone(),
                RepositoryPath::parse_decoded("pool/unknown.deb").unwrap()
            )
            .unwrap()
            .is_none()
    );
    let wrong = ObjectIdentity {
        sha256: Sha256Digest::of(b"not the signed checksum"),
        size: capture.identity.size,
    };
    assert!(
        VerifiedCaptureProof::from_index(
            &fixture.spool,
            capture.proof.clone(),
            "main/binary-amd64/Packages",
            capture.path.clone(),
            wrong,
            Instant::now() + Duration::from_secs(60),
            &CancellationToken::new()
        )
        .await
        .is_err()
    );

    let id = index.id.clone();
    fixture
        .spool
        .catalog_write(move |connection| {
            connection.execute("UPDATE capture_indexes SET verified=0 WHERE id=?1", [id])?;
            Ok(())
        })
        .unwrap();

    assert!(matches!(
        index.lookup(capture.path()),
        Err(CaptureError::Catalog(CatalogError::InvalidState))
    ));
}
#[tokio::test]
async fn cancelled_capture_refunds_unwritten_controls_and_releases_only_capture_pins() {
    let root = tempfile::tempdir().unwrap();
    let (fixture, capture) = authenticated(&root.path().join("state")).await;
    let (manager, ledger, requests) = setup(fixture.spool.clone(), Vec::new());
    let public = Sha256Digest::of(b"independent public owner");
    let identities = fixture
        .manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.identity().unwrap())
        .collect::<Vec<_>>();
    fixture
        .spool
        .retain_generation(public, &identities)
        .unwrap();
    let reservation = manager
        .reserve(&capture, crate::s3::production_now().unwrap())
        .unwrap();
    assert_eq!(manager.usage().unwrap().entries, 1);
    drop(reservation);
    assert_eq!(manager.usage().unwrap().entries, 0);
    assert_eq!(ledger.usage().unwrap().download, 0);
    let owned = fixture
        .spool
        .durable_catalog()
        .unwrap()
        .read(move |connection| {
            Ok(connection.query_row(
                "SELECT COUNT(*) FROM generation_pins WHERE generation=?1",
                [lifecycle::proof_pin(&capture.manifest().scope_id().to_hex()).to_hex()],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .unwrap();
    assert_eq!(owned, 0);
    // Shared public pins and their reserved control rows are intentionally kept.
    fixture.spool.release_generation(public).unwrap();
    cleanup::unused(&fixture.spool).unwrap();
    assert_eq!(ledger.usage().unwrap().storage, 0);
    assert!(requests.snapshot().unwrap().is_empty());
}
#[tokio::test]
async fn cancelling_one_concurrent_authenticated_alias_does_not_remove_other_admission() {
    let root = tempfile::tempdir().unwrap();
    let (fixture, capture) = authenticated(&root.path().join("state")).await;
    let (manager, ledger, requests) = setup(fixture.spool.clone(), Vec::new());
    // Isolate post-authorization ownership: real repositories may advertise two
    // Filenames for identical bytes. Signature/path rejection is tested above.
    let alias = VerifiedCaptureProof {
        proof: capture.proof.clone(),
        path: RepositoryPath::parse_decoded("pool/main/f/ferrum-fixture/alias_1.0_all.deb")
            .unwrap(),
        identity: capture.identity,
        package_signature: None,
        package_objects: None,
        request_authentication: std::sync::OnceLock::new(),
    };
    let first = manager
        .reserve(&capture, crate::s3::production_now().unwrap())
        .unwrap();
    let second = manager
        .reserve(&alias, crate::s3::production_now().unwrap())
        .unwrap();
    assert_eq!(manager.usage().unwrap().entries, 1);
    drop(first);
    assert_eq!(manager.usage().unwrap().entries, 1);
    let state = fixture
        .spool
        .durable_catalog()
        .unwrap()
        .read(|connection| {
            Ok(connection.query_row(
                "SELECT (SELECT COUNT(*) FROM capture_paths),(SELECT owners FROM capture_admission_owners)",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(state, (2, 1));
    drop(second);
    assert_eq!(manager.usage().unwrap().entries, 0);
    assert_eq!(ledger.usage().unwrap().download, 0);
    assert!(requests.snapshot().unwrap().is_empty());
}
#[tokio::test]
async fn invalid_receipt_pointer_never_dispatches_or_promotes_from_metadata() {
    let root = tempfile::tempdir().unwrap();
    let (fixture, capture) = authenticated(&root.path().join("state")).await;
    let (manager, _, requests) = setup(fixture.spool.clone(), Vec::new());
    let receipt = CaptureReceipt {
        schema_version: 1,
        repository: capture.repository().into(),
        public_package_path: capture.path().as_str().into(),
        size: 1234,
        sha256: Sha256Digest::of(b"forged metadata").to_hex(),
        proof_generation_id: capture.manifest().generation_id.clone(),
        first_capture_time: 1,
        package_signature: None,
    };
    assert!(
        manager
            .recover_receipt(
                &receipt,
                &capture,
                crate::s3::production_now().unwrap(),
                Instant::now() + Duration::from_secs(30),
                &CancellationToken::new()
            )
            .await
            .is_err()
    );
    assert!(requests.snapshot().unwrap().is_empty());
    assert_eq!(manager.usage().unwrap().entries, 0);
}
#[tokio::test]
async fn both_origin_receipts_and_full_blob_readback_are_required_for_owner_durable() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, _, _) = setup(spool.clone(), Vec::new());
    let object = install(&spool, b"owner checked bytes").await;
    let identity = object.identity();
    let now = crate::s3::production_now().unwrap();
    seed_paths(&spool, identity, false, now, now + GRACE);
    assert!(!manager.is_durable(identity).unwrap());
    assert!(!spool.promote_capture(identity).unwrap());
    spool
        .catalog_write(move |connection| {
            connection.execute(
                "UPDATE capture_blobs SET readback_verified=1 WHERE digest=?1",
                [identity.sha256.to_hex()],
            )?;
            connection.execute(
                "UPDATE capture_paths SET receipt_verified=1 WHERE repository='origin-a'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(!spool.promote_capture(identity).unwrap());
    assert!(!manager.is_durable(identity).unwrap());
    spool
        .catalog_write(|connection| {
            connection.execute(
                "UPDATE capture_paths SET receipt_verified=1 WHERE repository='origin-b'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(spool.promote_capture(identity).unwrap());
    assert!(manager.is_durable(identity).unwrap());
    assert_eq!(
        manager
            .lookup(
                "origin-a",
                &RepositoryPath::parse_decoded("pool/main/p/package_1_all.deb").unwrap()
            )
            .unwrap(),
        Some(identity)
    );
    assert_eq!(
        manager
            .lookup(
                "origin-b",
                &RepositoryPath::parse_decoded("pool/main/p/package_1_all.deb").unwrap()
            )
            .unwrap(),
        Some(identity)
    );
    manager.store.quarantine(identity).unwrap();
    assert!(!manager.is_durable(identity).unwrap());
    assert_eq!(spool.reclaim(identity.size).unwrap(), 0);
}
#[tokio::test]
async fn durable_rehydration_does_not_use_or_increment_a_full_outbox() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let body = b"already off VM bytes";
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(body),
        size: body.len() as u64,
    };
    let (manager, _, requests) = setup(spool.clone(), vec![response("GET", 200, body)]);
    let now = crate::s3::production_now().unwrap();
    seed_paths(&spool, identity, true, now, now + GRACE);
    spool
        .catalog_write_reserved(8 * 1024 * 1024, move |connection| {
            let transaction = connection.transaction()?;
            for number in 0..OUTBOX_ENTRIES {
                let digest = Sha256Digest::of(&number.to_be_bytes()).to_hex();
                transaction.execute(
                    "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,0,1,?2,0)",
                    params![digest, now + GRACE],
                )?;
                transaction.execute(
                    "INSERT INTO capture_outbox(digest,size,queued_at) VALUES(?1,0,1)",
                    [digest],
                )?;
            }
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    let before = manager.usage().unwrap();
    assert_eq!(before.entries, OUTBOX_ENTRIES);
    let object = manager
        .rehydrate(
            identity,
            Instant::now() + Duration::from_secs(30),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(object.identity(), identity);
    assert!(manager.is_durable(identity).unwrap());
    assert_eq!(manager.usage().unwrap().entries, before.entries);
    assert_eq!(requests.snapshot().unwrap(), ["GET"]);
}
#[tokio::test]
async fn restart_rolls_forward_resident_capture_admission_to_atomic_outbox() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state");
    let spool = test_support::open_spool(&path);
    let (manager, ledger, _) = setup(spool.clone(), Vec::new());
    let object = install(&spool, b"commit survived rename").await;
    let identity = object.identity();
    seed_paths(&spool, identity, false, 0, GRACE);
    spool
        .catalog_write(move |connection| {
            connection.execute(
                "INSERT INTO capture_admissions(digest,size) VALUES(?1,?2)",
                params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
            )?;
            Ok(())
        })
        .unwrap();
    drop(object);
    drop(manager);
    drop(ledger);
    drop(spool);
    let reopened = test_support::open_spool(&path);
    let (first, outbox, admissions) = reopened
        .durable_catalog()
        .unwrap()
        .read(move |connection| {
            Ok(connection.query_row(
                "SELECT first_capture,(SELECT COUNT(*) FROM capture_outbox WHERE digest=?1),(SELECT COUNT(*) FROM capture_admissions WHERE digest=?1) FROM capture_blobs WHERE digest=?1",
                [identity.sha256.to_hex()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )?)
        })
        .unwrap();
    assert!(first > 0);
    assert_eq!((outbox, admissions), (1, 0));
}
#[tokio::test]
async fn initialization_never_adopts_populated_capture_state_as_fresh() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, _, requests) = setup(spool.clone(), Vec::new());
    let now = crate::s3::production_now().unwrap();
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"retained state"),
        size: 14,
    };
    seed_paths(&spool, identity, true, now, now + GRACE);
    spool
        .catalog_write(|connection| {
            connection.execute("DELETE FROM capture_state", [])?;
            Ok(())
        })
        .unwrap();
    assert!(manager.initialize(now).is_err());
    assert!(requests.snapshot().unwrap().is_empty());
}
#[tokio::test]
async fn expired_finite_reference_does_not_leave_an_indefinite_path_flag() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, _, _) = setup(spool.clone(), Vec::new());
    let now = crate::s3::production_now().unwrap();
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"finite reference"),
        size: 16,
    };
    seed_paths(&spool, identity, true, now, now + GRACE);
    let current = Sha256Digest::of(b"current");
    let older = Sha256Digest::of(b"older");
    spool
        .catalog_write(move |connection| {
            connection.execute(
                "INSERT INTO capture_generation_refs(generation,digest,retain_until) VALUES(?1,?2,9223372036854775807)",
                params![current.to_hex(), identity.sha256.to_hex()],
            )?;
            connection.execute(
                "INSERT INTO capture_generation_refs(generation,digest,retain_until) VALUES(?1,?2,?3)",
                params![older.to_hex(), identity.sha256.to_hex(), now + 2 * GRACE],
            )?;
            Ok(())
        })
        .unwrap();
    manager.retire_metadata_references(current, now).unwrap();
    let (count, retention) = spool
        .durable_catalog()
        .unwrap()
        .read(|connection| {
            Ok(connection.query_row(
                "SELECT SUM(referenced),MIN(retain_until) FROM capture_paths",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!(count, 0);
    assert!(retention >= now + 2 * GRACE);
}
#[test]
fn fallback_never_reinterprets_auth_corruption_or_unknown_errors_as_missing() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, _, _) = setup(spool, Vec::new());
    for error in [
        S3Error::Corrupt,
        S3Error::Unsupported,
        S3Error::Boundary,
        S3Error::Budget,
        S3Error::AdmissionRefused,
        S3Error::Conflict,
    ] {
        assert!(matches!(
            manager.fallback(error, true),
            FallbackDecision::Fail(_)
        ));
    }
    assert!(matches!(
        manager.fallback(S3Error::NotFound, false),
        FallbackDecision::CaptureUpstream
    ));
    assert!(matches!(
        manager.fallback(S3Error::Forbidden, false),
        FallbackDecision::Fail(S3Error::Forbidden)
    ));
    assert!(matches!(
        manager.fallback(S3Error::Timeout, true),
        FallbackDecision::CaptureUpstream
    ));
}
#[tokio::test]
async fn incomplete_reconciliation_blocks_upload_replay_before_any_wire_or_credit() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, ledger, requests) = setup(spool.clone(), Vec::new());
    let object = install(&spool, b"pending verified local bytes").await;
    let identity = object.identity();
    let now = crate::s3::production_now().unwrap();
    seed_paths(&spool, identity, false, now, now + GRACE);
    spool
        .catalog_write(move |connection| {
            connection.execute(
                "INSERT INTO capture_outbox(digest,size,queued_at) VALUES(?1,?2,?3)",
                params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?,
                    now
                ],
            )?;
            Ok(())
        })
        .unwrap();
    manager.begin_reconciliation(now).unwrap();
    let before = ledger.usage().unwrap().download;

    let path = RepositoryPath::parse_decoded("pool/main/p/package_1_all.deb").unwrap();

    assert!(matches!(
        manager.lookup("origin-a", &path),
        Err(CaptureError::Admission)
    ));
    assert!(matches!(
        manager.is_durable(identity),
        Err(CaptureError::Admission)
    ));
    assert!(matches!(
        manager
            .rehydrate(
                identity,
                Instant::now() + Duration::from_secs(10),
                &CancellationToken::new()
            )
            .await,
        Err(CaptureError::Admission)
    ));

    assert!(matches!(
        manager
            .complete(
                identity,
                Instant::now() + Duration::from_secs(10),
                &CancellationToken::new()
            )
            .await,
        Err(CaptureError::Admission)
    ));
    assert!(matches!(
        crate::upload::UploadWorker::new(manager.clone())
            .drain_once(
                Instant::now() + Duration::from_secs(10),
                &CancellationToken::new()
            )
            .await,
        Err(CaptureError::ReconciliationPending)
    ));
    let cancel = CancellationToken::new();
    let worker = crate::upload::UploadWorker::new(manager).run(cancel.clone());
    tokio::pin!(worker);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut worker)
            .await
            .is_err(),
        "pending reconciliation must keep the upload worker alive"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .expect("pending upload worker must remain cancellable")
        .unwrap();
    assert_eq!(ledger.usage().unwrap().download, before);
    assert!(requests.snapshot().unwrap().is_empty());
}
#[test]
fn capture_never_pairs_a_catalog_with_another_owners_budget_and_transport() {
    let root = tempfile::tempdir().unwrap();
    let first = test_support::open_spool(&root.path().join("first"));
    let (manager, _, requests) = setup(first, Vec::new());
    let other = test_support::open_spool(&root.path().join("other"));
    assert!(matches!(
        CaptureManager::new(other, manager.store().clone()),
        Err(CaptureError::Admission)
    ));
    assert!(requests.snapshot().unwrap().is_empty());
}
#[tokio::test]
async fn actual_receipt_and_signed_remote_closure_recover_pending_mapping_but_not_body_durability()
{
    let root = tempfile::tempdir().unwrap();
    let (fixture, capture) = authenticated(&root.path().join("state")).await;
    let receipt = CaptureReceipt {
        schema_version: 1,
        repository: capture.repository().into(),
        public_package_path: capture.path().as_str().into(),
        size: capture.identity.size,
        sha256: capture.identity.sha256.to_hex(),
        proof_generation_id: capture.manifest().generation_id.clone(),
        first_capture_time: 1,
        package_signature: None,
    };
    let mut responses = vec![response("GET", 200, &serde_json::to_vec(&receipt).unwrap())];
    for artifact in &fixture.manifest.artifacts {
        let object = fixture.spool.lookup(artifact.identity().unwrap()).unwrap();
        let bytes = object.read_bounded(1024 * 1024).await.unwrap();
        responses.push(response("GET", 200, &bytes));
    }
    responses.push(response("GET", 200, &fixture.manifest.encode().unwrap()));
    let (manager, _, requests) = setup(fixture.spool.clone(), responses);
    let now = crate::s3::production_now().unwrap();
    let guard = manager.reserve(&capture, now).unwrap();
    // Model a restored post-commit catalog whose non-durable local body was
    // lost. The snapshot retains its outbox intent, not a live producer lock.
    let digest = capture.identity().sha256.to_hex();
    fixture
        .spool
        .catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO capture_outbox(digest,size,queued_at) SELECT digest,size,?2 FROM capture_admissions WHERE digest=?1",
                params![digest, now],
            )?;
            transaction.execute("DELETE FROM capture_admissions WHERE digest=?1", [digest])?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    drop(guard);
    manager
        .recover_receipt(
            &receipt,
            &capture,
            now,
            Instant::now() + Duration::from_secs(60),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let state = fixture
        .spool
        .durable_catalog()
        .unwrap()
        .read(|connection| {
            Ok(connection.query_row(
                "SELECT p.receipt_verified,q.durable,b.readback_verified,b.first_capture FROM capture_paths p JOIN capture_proofs q ON q.generation=p.generation JOIN capture_blobs b ON b.digest=p.digest",
                [],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?)
        })
        .unwrap();
    assert_eq!(state, (true, true, false, now));
    assert_eq!(
        manager
            .lookup(capture.repository(), capture.path())
            .unwrap(),
        Some(capture.identity())
    );
    assert!(!manager.is_durable(capture.identity()).unwrap());
    assert_eq!(manager.usage().unwrap().entries, 1);
    let methods = requests.snapshot().unwrap();
    assert_eq!(methods.len(), fixture.manifest.artifacts.len() + 2);
    assert!(methods.iter().all(|method| method == "GET"));
}

// These tests exercise post-authentication persistence, not a second signature
// fixture. Signed-index rejection is independently exercised above; the second
// generation references the same bytes in another repository and path.
fn seed_second_public_generation(spool: &Spool, capture: &VerifiedCaptureProof) -> Sha256Digest {
    let mut manifest = capture.manifest().clone();
    manifest.generation_id = Sha256Digest::of(b"second previously published generation").to_hex();
    manifest.repository = "other-origin".into();
    let second = manifest.scope_id();
    let generation = second.to_hex();
    let identity = capture.identity();
    let encoded = String::from_utf8(manifest.encode().unwrap()).unwrap();
    spool
        .catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO capture_proofs(generation,manifest,durable,was_public) VALUES(?1,?2,1,1)",
                params![generation, encoded],
            )?;
            transaction.execute(
                "INSERT INTO capture_indexes(id,verified) VALUES(?1,1)",
                [&generation],
            )?;
            transaction.execute(
                "INSERT INTO capture_index_entries(index_id,path,digest,size) VALUES(?1,'pool/other-origin/alias.deb',?2,?3)",
                params![
                    generation,
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
            )?;
            transaction.execute(
                "INSERT INTO capture_proof_indexes(generation,path,index_id) VALUES(?1,'main/binary-amd64/Packages',?1)",
                [&generation],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    second
}

fn captured_reference_state(spool: &Spool, identity: ObjectIdentity) -> (i64, bool, i64) {
    spool
        .durable_catalog()
        .unwrap()
        .read(move |connection| {
            Ok(connection.query_row(
                "SELECT (SELECT COUNT(*) FROM capture_generation_refs WHERE digest=?1),referenced,retain_until FROM capture_paths WHERE digest=?1",
                [identity.sha256.to_hex()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?)
        })
        .unwrap()
}

#[tokio::test]
async fn cold_capture_binds_preexisting_cross_repository_and_path_content_references() {
    let root = tempfile::tempdir().unwrap();
    let (fixture, capture) = authenticated(&root.path().join("state")).await;
    let (manager, _, requests) = setup(fixture.spool.clone(), Vec::new());
    let deadline = Instant::now() + Duration::from_secs(60);
    let cancel = CancellationToken::new();
    manager
        .retain_metadata_references(
            capture.proof.clone(),
            "main/binary-amd64/Packages",
            deadline,
            &cancel,
        )
        .await
        .unwrap();
    let second = seed_second_public_generation(&fixture.spool, &capture);
    let now = crate::s3::production_now().unwrap();
    let reservation = manager.reserve(&capture, now).unwrap();
    assert_eq!(
        captured_reference_state(&fixture.spool, capture.identity()).0,
        2
    );
    manager
        .retire_metadata_references(capture.manifest().scope_id(), now)
        .unwrap();
    assert!(captured_reference_state(&fixture.spool, capture.identity()).1);
    assert!(
        manager
            .lookup(
                "other-origin",
                &RepositoryPath::parse_decoded("pool/other-origin/alias.deb").unwrap()
            )
            .unwrap()
            .is_none()
    );
    manager
        .retire_metadata_references(second, now + 17)
        .unwrap();
    let (references, referenced, retain) =
        captured_reference_state(&fixture.spool, capture.identity());
    assert_eq!(references, 0);
    assert!(!referenced);
    assert!(retain >= now + 17 + GRACE);
    drop(reservation);
    assert!(requests.snapshot().unwrap().is_empty());
}

#[tokio::test]
async fn verified_hits_keep_cross_repository_path_reference_until_its_grace() {
    let root = tempfile::tempdir().unwrap();
    let (fixture, signed) = authenticated(&root.path().join("state")).await;
    let body = b"post-authenticated retained package";
    let object = install(&fixture.spool, body).await;
    let identity = object.identity();
    // The static signed fixture does not include its .deb body. Substitute only
    // at this already-authenticated owner boundary so real body hashing/receipt
    // I/O and the indexed retention graph are exercised without forged crypto.
    let capture = VerifiedCaptureProof {
        proof: signed.proof.clone(),
        path: signed.path.clone(),
        identity,
        package_signature: None,
        package_objects: None,
        request_authentication: std::sync::OnceLock::new(),
    };
    let receipt = CaptureReceipt {
        schema_version: 1,
        repository: capture.repository().into(),
        public_package_path: capture.path().as_str().into(),
        size: identity.size,
        sha256: identity.sha256.to_hex(),
        proof_generation_id: capture.manifest().generation_id.clone(),
        first_capture_time: 1,
        package_signature: None,
    };
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let (manager, _, requests) = setup(
        fixture.spool.clone(),
        vec![
            response("GET", 200, body),
            response("PUT", 200, b""),
            response("GET", 200, &bytes),
            response("GET", 200, body),
            response("GET", 200, &bytes),
        ],
    );
    let first = capture.manifest().scope_id().to_hex();
    let encoded = String::from_utf8(capture.manifest().encode().unwrap()).unwrap();
    let path = capture.path().as_str().to_owned();
    fixture
        .spool
        .catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO capture_proofs(generation,manifest,durable,was_public) VALUES(?1,?2,1,1)",
                params![first, encoded],
            )?;
            transaction.execute(
                "UPDATE capture_index_entries SET digest=?1,size=?2 WHERE path=?3",
                params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?,
                    path
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    let second = seed_second_public_generation(&fixture.spool, &capture);
    let now = crate::s3::production_now().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let cancel = CancellationToken::new();
    assert_eq!(
        manager
            .capture_verified_hit(&capture, deadline, &cancel)
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(captured_reference_state(&fixture.spool, identity).0, 2);
    manager
        .retire_metadata_references(capture.manifest().scope_id(), now)
        .unwrap();
    assert!(captured_reference_state(&fixture.spool, identity).1);
    assert_eq!(
        manager
            .capture_verified_hit(&capture, deadline, &cancel)
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(captured_reference_state(&fixture.spool, identity).0, 2);
    let mappings = fixture
        .spool
        .durable_catalog()
        .unwrap()
        .read(|connection| {
            Ok(
                connection.query_row("SELECT COUNT(*) FROM capture_paths", [], |row| {
                    row.get::<_, i64>(0)
                })?,
            )
        })
        .unwrap();
    assert_eq!(mappings, 1);
    assert_eq!(manager.usage().unwrap().entries, 0);

    let receipt_key = manager.store.package_key(&receipt.suffix()).unwrap();
    let blob_key = manager
        .store
        .package_key(&format!("v1/objects/sha256/{}", identity.sha256))
        .unwrap();
    let receipt_intent = receipt_key.clone();
    let blob_intent = blob_key.clone();
    fixture
        .spool
        .catalog_write(move |connection| {
            for key in [receipt_intent, blob_intent] {
                connection.execute(
                    "INSERT INTO capture_gc_intents(key,authorized_at) VALUES(?1,?2)",
                    params![key, now],
                )?;
            }
            Ok(())
        })
        .unwrap();
    // Exercise GC's actual local acknowledgment guard, not a duplicate test SQL
    // eligibility predicate. Public generation two protects both remote records.
    assert!(
        crate::gc::journal::acknowledge(
            &fixture.spool,
            &receipt_key,
            manager.store.package_prefix().unwrap(),
            now + 2 * GRACE
        )
        .is_err()
    );
    assert!(
        crate::gc::journal::acknowledge(
            &fixture.spool,
            &blob_key,
            manager.store.package_prefix().unwrap(),
            now + 2 * GRACE
        )
        .is_err()
    );
    assert_eq!(
        manager
            .lookup(capture.repository(), capture.path())
            .unwrap(),
        Some(identity)
    );
    assert!(
        manager
            .lookup(
                "other-origin",
                &RepositoryPath::parse_decoded("pool/other-origin/alias.deb").unwrap()
            )
            .unwrap()
            .is_none()
    );
    let retired = now + GRACE + 17;
    manager.retire_metadata_references(second, retired).unwrap();
    let expiry = retired + GRACE;
    // OfflineGc::run expires finite generation leases before checking candidates.
    fixture
        .spool
        .catalog_write(move |connection| {
            connection.execute(
                "DELETE FROM capture_generation_refs WHERE retain_until<=?1",
                [expiry - 1],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(!captured_reference_state(&fixture.spool, identity).1);
    assert!(
        crate::gc::journal::acknowledge(
            &fixture.spool,
            &receipt_key,
            manager.store.package_prefix().unwrap(),
            expiry - 1
        )
        .is_err()
    );
    assert!(
        crate::gc::journal::acknowledge(
            &fixture.spool,
            &blob_key,
            manager.store.package_prefix().unwrap(),
            expiry - 1
        )
        .is_err()
    );
    crate::gc::journal::acknowledge(
        &fixture.spool,
        &receipt_key,
        manager.store.package_prefix().unwrap(),
        expiry,
    )
    .unwrap();
    assert!(
        manager
            .lookup(capture.repository(), capture.path())
            .unwrap()
            .is_none()
    );
    drop(object);
    crate::gc::journal::acknowledge(
        &fixture.spool,
        &blob_key,
        manager.store.package_prefix().unwrap(),
        expiry,
    )
    .unwrap();
    assert!(fixture.spool.lookup(identity).is_none());
    assert_eq!(
        requests.snapshot().unwrap(),
        ["GET", "PUT", "GET", "GET", "GET"]
    );
}

#[test]
fn retained_content_matches_global_digest_size_without_granting_mapping_authority() {
    let root = tempfile::tempdir().unwrap();
    let spool = test_support::open_spool(&root.path().join("state"));
    let (manager, _, requests) = setup(spool.clone(), Vec::new());
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"exact retained mapping"),
        size: 22,
    };
    let now = 100;
    let finite = now + 2 * GRACE;
    let path = "pool/main/p/package_1_all.deb";
    spool
        .catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,?2,?3,?4,1)",
                params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?,
                    now,
                    now + GRACE
                ],
            )?;
            for (generation, repository, entry_path, size, verified, public, recovery) in [
                ("current", "origin-a", path, identity.size, true, true, 0),
                (
                    "finite",
                    "origin-b",
                    "pool/finite-alias.deb",
                    identity.size,
                    true,
                    false,
                    finite,
                ),
                ("foreign", "origin-b", path, identity.size, true, true, 0),
                (
                    "alias",
                    "origin-a",
                    "pool/other.deb",
                    identity.size,
                    true,
                    true,
                    0,
                ),
                (
                    "wrong-size",
                    "origin-a",
                    path,
                    identity.size + 1,
                    true,
                    true,
                    0,
                ),
                (
                    "unverified",
                    "origin-a",
                    path,
                    identity.size,
                    false,
                    true,
                    0,
                ),
                (
                    "proof-only",
                    "origin-a",
                    path,
                    identity.size,
                    true,
                    false,
                    0,
                ),
                ("expired", "origin-a", path, identity.size, true, false, now),
            ] {
                let manifest = serde_json::json!({"repository":repository,"generation_id":generation}).to_string();
                transaction.execute(
                    "INSERT INTO capture_proofs(generation,manifest,durable,was_public,recovery_retention) VALUES(?1,?2,1,?3,?4)",
                    params![generation, manifest, public, recovery],
                )?;
                transaction.execute(
                    "INSERT INTO capture_indexes(id,verified) VALUES(?1,?2)",
                    params![generation, verified],
                )?;
                transaction.execute(
                    "INSERT INTO capture_proof_indexes(generation,path,index_id) VALUES(?1,'main/binary-amd64/Packages',?1)",
                    [generation],
                )?;
                transaction.execute(
                    "INSERT INTO capture_index_entries(index_id,path,digest,size) VALUES(?1,?2,?3,?4)",
                    params![
                        generation,
                        entry_path,
                        identity.sha256.to_hex(),
                        crate::catalog::signed(size)?
                    ],
                )?;
            }
            transaction.execute(
                "INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES('origin-a',?1,?2,?3,'current',1,0,?4)",
                params![
                    path,
                    Sha256Digest::of(path.as_bytes()).to_hex(),
                    identity.sha256.to_hex(),
                    now + GRACE
                ],
            )?;
            bind_retained_mapping(&transaction, "origin-a", path, identity, now)?;
            bind_retained_mapping(&transaction, "origin-a", path, identity, now)?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    let refs = spool
        .durable_catalog()
        .unwrap()
        .read(|connection| {
            let mut statement = connection.prepare(
                "SELECT generation,retain_until FROM capture_generation_refs ORDER BY generation",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .unwrap();
    assert_eq!(
        refs,
        vec![
            ("alias".into(), i64::MAX),
            ("current".into(), i64::MAX),
            ("finite".into(), finite),
            ("foreign".into(), i64::MAX)
        ]
    );
    assert_eq!(
        captured_reference_state(&spool, identity),
        (4, true, finite)
    );
    let original = RepositoryPath::parse_decoded(path).unwrap();
    assert_eq!(
        manager.lookup("origin-a", &original).unwrap(),
        Some(identity)
    );
    assert!(manager.lookup("origin-b", &original).unwrap().is_none());
    for alias in ["pool/other.deb", "pool/finite-alias.deb"] {
        let alias = RepositoryPath::parse_decoded(alias).unwrap();
        assert!(manager.lookup("origin-a", &alias).unwrap().is_none());
        assert!(manager.lookup("origin-b", &alias).unwrap().is_none());
    }
    let authority = spool
        .durable_catalog()
        .unwrap()
        .read(|connection| {
            Ok(connection.query_row(
                "SELECT COUNT(*),MIN(repository),MIN(path),MIN(generation),MIN(receipt_verified) FROM capture_paths",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                },
            )?)
        })
        .unwrap();
    assert_eq!(
        authority,
        (1, "origin-a".into(), path.into(), "current".into(), true)
    );
    assert!(requests.snapshot().unwrap().is_empty());
}

#[tokio::test]
async fn stale_authorized_capture_cannot_insert_over_checkpoint_candidate_claim() {
    let root = tempfile::tempdir().unwrap();
    let (fixture, capture) = authenticated(&root.path().join("state")).await;
    let (manager, _, requests) = setup(fixture.spool.clone(), Vec::new());
    let identity = capture.identity();
    let path = capture.path().as_str().to_owned();
    let repository = capture.repository().to_owned();
    let saved_repository = repository.clone();
    let saved_path = path.clone();
    // Isolate the post-authentication race: A's real signed proof has already
    // been authorized, then B acquires the per-path checkpoint candidate claim.
    fixture
        .spool
        .catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT OR IGNORE INTO suite_checkpoints(repository,suite) VALUES(?1,'candidate')",
                [&saved_repository],
            )?;
            transaction.execute(
                "INSERT INTO capture_indexes(id,verified) VALUES('race-index',1)",
                [],
            )?;
            transaction.execute(
                "INSERT INTO capture_index_entries(index_id,path,digest,size) VALUES('race-index',?1,?2,?3)",
                params![
                    saved_path,
                    Sha256Digest::of(b"successor package").to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
            )?;
            transaction.execute(
                "INSERT INTO capture_proof_indexes(generation,path,index_id) VALUES('race-generation','main/binary-amd64/Packages','race-index')",
                [],
            )?;
            transaction.execute(
                "INSERT INTO publication_candidates(generation,repository,suite) VALUES('race-generation',?1,'candidate')",
                [saved_repository],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    // Reservation drop refunds at the current wall time. Sample each later
    // operation afresh rather than presenting that ledger with an older time.
    let clock = || crate::s3::production_now().unwrap();
    let now = clock();
    let receipt = CaptureReceipt {
        schema_version: 1,
        repository: repository.clone(),
        public_package_path: path.clone(),
        sha256: identity.sha256.to_hex(),
        size: identity.size,
        proof_generation_id: capture.manifest().generation_id.clone(),
        first_capture_time: now,
        package_signature: None,
    };
    assert!(manager.reserve(&capture, clock()).is_err());
    assert!(
        manager
            .record_recovered_receipt(&receipt, &capture, clock())
            .is_err()
    );
    let digest = identity.sha256.to_hex();
    fixture
        .spool
        .catalog_write(move |connection| {
            connection.execute(
                "UPDATE capture_index_entries SET digest=?1,size=size+1 WHERE index_id='race-index'",
                [digest],
            )?;
            Ok(())
        })
        .unwrap();
    // Equal digest alone is insufficient: the signed size is part of identity.
    assert!(manager.reserve(&capture, clock()).is_err());
    assert!(
        manager
            .record_recovered_receipt(&receipt, &capture, clock())
            .is_err()
    );
    let mappings = fixture
        .spool
        .durable_catalog()
        .unwrap()
        .read(|connection| {
            Ok(
                connection.query_row("SELECT COUNT(*) FROM capture_paths", [], |row| {
                    row.get::<_, i64>(0)
                })?,
            )
        })
        .unwrap();
    assert_eq!(mappings, 0);
    fixture
        .spool
        .catalog_write(|connection| {
            connection.execute(
                "UPDATE capture_index_entries SET size=size-1 WHERE index_id='race-index'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    // Same-identity publication and capture claims deliberately deduplicate.
    drop(manager.reserve(&capture, clock()).unwrap());
    manager
        .record_recovered_receipt(&receipt, &capture, clock())
        .unwrap();
    // A different origin's conflicting path must not block this origin.
    fixture
        .spool
        .catalog_write(|connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO suite_checkpoints(repository,suite) VALUES('independent-origin','candidate')",
                [],
            )?;
            transaction.execute(
                "UPDATE publication_candidates SET repository='independent-origin' WHERE generation='race-generation'",
                [],
            )?;
            transaction.execute(
                "UPDATE capture_index_entries SET digest=?1 WHERE index_id='race-index'",
                [Sha256Digest::of(b"unrelated origin package").to_hex()],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    drop(manager.reserve(&capture, clock()).unwrap());
    manager
        .record_recovered_receipt(&receipt, &capture, clock())
        .unwrap();
    assert!(requests.snapshot().unwrap().is_empty());
}
