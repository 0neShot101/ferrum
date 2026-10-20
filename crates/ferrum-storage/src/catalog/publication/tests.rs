#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::recovery::ManifestArtifact;

fn stage(
    catalog: &Catalog,
    (repository, suite): (&str, &str),
    sequence: u64,
    now: i64,
    valid_until: Option<i64>,
    path: &str,
    digest: Sha256Digest,
) -> Activation {
    let paths = if SuiteKey::new(repository, suite)
        .unwrap()
        .uses_transport_candidate_metadata()
    {
        [
            "os/x86_64/core.db",
            "os/x86_64/canary-1-1-any.pkg.tar.zst",
            "os/x86_64/canary-1-1-any.pkg.tar.zst.sig",
        ]
    } else {
        ["InRelease", "Release", "Release.gpg"]
    };
    let artifacts = paths
        .into_iter()
        .map(|path| ManifestArtifact {
            path: path.into(),
            sha256: Sha256Digest::of(format!("{repository}/{suite}/{sequence}/{path}").as_bytes())
                .to_hex(),
            size: 1,
        })
        .collect::<Vec<_>>();
    let manifest = GenerationManifest {
        schema_version: 1,
        repository: repository.into(),
        suite: suite.into(),
        generation_id: format!("{sequence:064x}"),
        release_content_sha256: format!("{:064x}", sequence + 100),
        release_date: sequence as i64,
        artifacts,
        derived: Vec::new(),
    };
    let intent = PublicationIntent {
        schema_version: 1,
        repository: repository.into(),
        suite: suite.into(),
        sequence,
        generation_id: manifest.generation_id.clone(),
        manifest_sha256: Sha256Digest::of(&manifest.encode().unwrap()).to_hex(),
        release_content_sha256: manifest.release_content_sha256.clone(),
        release_date: sequence as i64,
    };
    let scope = manifest.scope_id().to_hex();
    let index = format!("index-{scope}");
    let name = path.to_owned();
    let artifacts = manifest.artifacts.clone();
    catalog
        .write(move |connection| {
            let transaction = connection.transaction()?;
            for artifact in artifacts {
                transaction.execute(
                    "INSERT OR IGNORE INTO objects(digest,size,class,resident) VALUES(?1,1,1,1)",
                    [artifact.sha256],
                )?;
            }
            transaction.execute(
                "INSERT INTO capture_indexes(id,verified) VALUES(?1,1)",
                [&index],
            )?;
            transaction.execute(
                "INSERT INTO capture_index_entries(index_id,path,digest,size) VALUES(?1,?2,?3,1)",
                params![index, name, digest.to_hex()],
            )?;
            transaction.execute(
                "INSERT INTO capture_proof_indexes(generation,path,index_id) VALUES(?1,'main/binary-amd64/Packages',?2)",
                params![scope, index],
            )?;
            transaction.execute(
                "INSERT INTO capture_index_generations(generation,path_set,verified) VALUES(?1,'selected',1)",
                [scope],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    let metadata = manifest
        .artifacts
        .iter()
        .map(|artifact| MetadataRecord {
            path: artifact.path.clone(),
            directory: String::new(),
            identity: artifact.identity().unwrap(),
            sha256_alias: false,
            sha512: None,
            source_path: artifact.path.clone(),
        })
        .collect();
    Activation {
        intent,
        manifest,
        valid_until,
        now,
        confirmed_at: Some(now),
        metadata,
    }
}
fn prepare(catalog: &Catalog, activation: &Activation) {
    let key = activation.intent.key().unwrap();
    if catalog
        .checkpoint_state(key.clone())
        .unwrap()
        .floor
        .is_none()
    {
        catalog
            .checkpoint_bootstrap(
                key,
                0,
                "operator".into(),
                "test-only reset".into(),
                "historical rollback protection reset".into(),
            )
            .unwrap();
        catalog
            .checkpoint_prepare_bootstrap(activation.intent.clone())
            .unwrap();
    } else {
        catalog
            .checkpoint_prepare(activation.intent.clone())
            .unwrap();
    }
    catalog
        .checkpoint_accept(activation.intent.clone())
        .unwrap();
}
fn install(catalog: &Catalog, activation: Activation) {
    prepare(catalog, &activation);
    catalog.publication_activate(activation).unwrap();
}
fn count(catalog: &Catalog, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    catalog
        .read(move |connection| Ok(connection.query_row(&sql, [], |row| row.get(0))?))
        .unwrap()
}
#[test]
fn late_sql_failure_rolls_back_active_history_metadata_pins_and_capture_references() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let digest = Sha256Digest::of(b"package");
    let first = stage(
        &catalog,
        ("debian", "trixie"),
        1,
        10,
        None,
        "pool/pkg.deb",
        digest,
    );
    let old = first.intent.clone();
    install(&catalog, first);
    let next = stage(
        &catalog,
        ("debian", "trixie"),
        2,
        20,
        None,
        "pool/pkg.deb",
        digest,
    );
    prepare(&catalog, &next);
    catalog
        .write(|connection| {
            connection.execute_batch("CREATE TRIGGER injected_activation_failure BEFORE UPDATE OF active ON suite_checkpoints WHEN NEW.active IS NOT OLD.active BEGIN SELECT RAISE(ABORT,'injected late activation failure'); END")?;
            Ok(())
        })
        .unwrap();
    assert!(catalog.publication_activate(next).is_err());
    assert_eq!(
        catalog.checkpoint_state(old.key().unwrap()).unwrap().active,
        Some(old)
    );
    assert_eq!(count(&catalog, "public_generations"), 1);
    assert_eq!(count(&catalog, "publication_metadata"), 3);
    assert_eq!(count(&catalog, "capture_proofs"), 1);
    assert_eq!(count(&catalog, "generation_pins"), 3);
    let consistent = catalog
        .read(|connection| {
            Ok(connection.query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM objects o WHERE o.generation_references<>(SELECT COUNT(*) FROM generation_pins p WHERE p.digest=o.digest))",
                [],
                |row| row.get::<_, bool>(0),
            )?)
        })
        .unwrap();
    assert!(consistent);
    catalog
        .write(|connection| {
            connection.execute_batch("DROP TRIGGER injected_activation_failure")?;
            Ok(())
        })
        .unwrap();
}
#[test]
fn conflicts_are_rejected_before_intent_and_rechecked_at_atomic_activation() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let first = stage(
        &catalog,
        ("debian", "trixie"),
        1,
        10,
        None,
        "pool/shared.deb",
        Sha256Digest::of(b"old"),
    );
    let old = first.intent.clone();
    install(&catalog, first);
    let conflict = stage(
        &catalog,
        ("debian", "trixie-updates"),
        1,
        20,
        None,
        "pool/shared.deb",
        Sha256Digest::of(b"conflict"),
    );
    let key = conflict.intent.key().unwrap();
    catalog
        .checkpoint_bootstrap(key.clone(), 0, "test".into(), "test".into(), "reset".into())
        .unwrap();
    assert!(
        catalog
            .checkpoint_prepare_bootstrap(conflict.intent.clone())
            .is_err()
    );
    assert!(
        catalog
            .checkpoint_state(key.clone())
            .unwrap()
            .pending
            .is_none()
    );
    assert!(
        !catalog
            .checkpoint_state(old.key().unwrap())
            .unwrap()
            .blocked
    );
    // Recovery can encounter an already accepted external intent; its activation
    // must still reject the conflict without changing any old public reference.
    catalog.checkpoint_accept(conflict.intent.clone()).unwrap();
    assert!(catalog.publication_activate(conflict).is_err());
    assert_eq!(count(&catalog, "public_generations"), 1);
    assert_eq!(count(&catalog, "generation_pins"), 3);
    let independent = stage(
        &catalog,
        ("ubuntu", "noble"),
        1,
        30,
        None,
        "pool/shared.deb",
        Sha256Digest::of(b"different repository"),
    );
    install(&catalog, independent);
    assert_eq!(count(&catalog, "public_generations"), 2);
}
#[test]
fn concurrent_candidate_claims_prevent_two_conflicting_remote_intents() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let a = stage(
        &catalog,
        ("ubuntu", "noble"),
        1,
        10,
        None,
        "pool/shared.deb",
        Sha256Digest::of(b"a"),
    );
    let b = stage(
        &catalog,
        ("ubuntu", "noble-updates"),
        1,
        10,
        None,
        "pool/shared.deb",
        Sha256Digest::of(b"b"),
    );
    for activation in [&a, &b] {
        catalog
            .checkpoint_bootstrap(
                activation.intent.key().unwrap(),
                0,
                "test".into(),
                "test".into(),
                "reset".into(),
            )
            .unwrap();
    }
    catalog
        .checkpoint_prepare_bootstrap(a.intent.clone())
        .unwrap();
    assert!(
        catalog
            .checkpoint_prepare_bootstrap(b.intent.clone())
            .is_err()
    );
    catalog
        .checkpoint_cancel_unwritten(a.intent.key().unwrap(), None, true, false)
        .unwrap();
    catalog
        .checkpoint_prepare_bootstrap(b.intent.clone())
        .unwrap();
}
#[test]
fn successor_observations_and_revalidated_304_payload_do_not_renew_active_or_other_suite() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let a = stage(
        &catalog,
        ("ubuntu", "noble"),
        1,
        10,
        None,
        "pool/a.deb",
        Sha256Digest::of(b"a"),
    );
    let active = a.intent.clone();
    install(&catalog, a);
    let b = stage(
        &catalog,
        ("ubuntu", "noble-updates"),
        1,
        11,
        None,
        "pool/a.deb",
        Sha256Digest::of(b"a"),
    );
    let other = b.intent.clone();
    install(&catalog, b);
    let key = active.key().unwrap();
    catalog
        .publication_observe(
            key.clone(),
            active.generation_id.clone(),
            1,
            active.release_content_sha256.clone(),
            20,
        )
        .unwrap();
    assert_eq!(
        catalog.checkpoint_state(key.clone()).unwrap().confirmed_at,
        Some(20)
    );
    catalog
        .publication_observe(
            key.clone(),
            "f".repeat(64),
            1,
            active.release_content_sha256.clone(),
            25,
        )
        .unwrap();
    let resigned = catalog.checkpoint_state(key.clone()).unwrap();
    assert_eq!(resigned.confirmed_at, Some(20));
    assert_eq!(resigned.candidate_generation, Some("f".repeat(64)));
    assert!(resigned.successor_seen_at.is_none());
    let successor = format!("{:064x}", 102);
    catalog
        .publication_observe(key.clone(), "e".repeat(64), 2, successor.clone(), 30)
        .unwrap();
    // OriginVerifier uses this same transaction after authenticating exact saved
    // bytes on a 304; transport success itself never grants freshness.
    catalog
        .publication_observe(key.clone(), "e".repeat(64), 2, successor, 90_000)
        .unwrap();
    let state = catalog.checkpoint_state(key.clone()).unwrap();
    assert_eq!(state.confirmed_at, Some(20));
    assert_eq!(state.observed_at, Some(90_000));
    assert_eq!(state.successor_seen_at, Some(30));
    assert_eq!(
        catalog
            .checkpoint_state(other.key().unwrap())
            .unwrap()
            .confirmed_at,
        Some(11)
    );
    assert!(
        catalog
            .publication_observe(
                key.clone(),
                active.generation_id.clone(),
                1,
                active.release_content_sha256,
                90_001
            )
            .is_err()
    );
    assert_eq!(
        catalog.checkpoint_state(key).unwrap().confirmed_at,
        Some(20)
    );
}
#[test]
fn public_retention_respects_grace_valid_until_two_distinct_predecessors_and_capture_grace() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let key = SuiteKey::new("debian", "trixie").unwrap();
    let first = stage(
        &catalog,
        ("debian", "trixie"),
        1,
        0,
        Some(2 * METADATA_GRACE),
        "pool/pkg-1.deb",
        Sha256Digest::of(b"first"),
    );
    let scope = first.manifest.scope_id().to_hex();
    install(&catalog, first);
    let bound = scope.clone();
    let initial = 4 * CAPTURE_GRACE;
    catalog
        .write(move |connection| {
            let transaction = connection.transaction()?;
            let digest = Sha256Digest::of(b"first").to_hex();
            transaction.execute(
                "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,1,0,?2,1)",
                params![digest, initial],
            )?;
            transaction.execute(
                "INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES('debian','pool/pkg-1.deb',?1,?2,?3,1,1,?4)",
                params![
                    Sha256Digest::of(b"pool/pkg-1.deb").to_hex(),
                    digest,
                    bound,
                    initial
                ],
            )?;
            transaction.execute(
                "INSERT INTO capture_generation_refs(generation,digest) VALUES(?1,?2)",
                params![bound, digest],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    for (sequence, now) in [
        (2, 1),
        (3, 2),
        (4, METADATA_GRACE + 1),
        (5, 2 * METADATA_GRACE - 1),
    ] {
        let path = format!("pool/pkg-{sequence}.deb");
        let next = stage(
            &catalog,
            ("debian", "trixie"),
            sequence,
            now,
            None,
            &path,
            Sha256Digest::of(path.as_bytes()),
        );
        install(&catalog, next);
    }
    assert!(
        catalog
            .publication_manifests(key.clone())
            .unwrap()
            .iter()
            .any(|manifest| manifest.scope_id().to_hex() == scope)
    );
    let next = stage(
        &catalog,
        ("debian", "trixie"),
        6,
        2 * METADATA_GRACE,
        None,
        "pool/pkg-6.deb",
        Sha256Digest::of(b"six"),
    );
    install(&catalog, next);
    let manifests = catalog.publication_manifests(key).unwrap();
    assert!(
        !manifests
            .iter()
            .any(|manifest| manifest.scope_id().to_hex() == scope)
    );
    assert!(manifests.len() >= 3);
    let (referenced, retain, proof_only) = catalog
        .read(move |connection| {
            Ok((
                connection.query_row(
                    "SELECT referenced,retain_until FROM capture_paths WHERE path='pool/pkg-1.deb'",
                    [],
                    |row| Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?)),
                )?,
                connection.query_row(
                    "SELECT was_public=1 AND public_retired_at IS NOT NULL FROM capture_proofs WHERE generation=?1",
                    [scope],
                    |row| row.get::<_, bool>(0),
                )?,
            ))
        })
        .map(|((referenced, retain), proof)| (referenced, retain, proof))
        .unwrap();
    assert!(!referenced);
    assert!(retain >= initial);
    assert!(retain >= 2 * METADATA_GRACE + CAPTURE_GRACE);
    assert!(proof_only);
}
#[test]
fn fewer_than_two_previous_generations_never_expire_and_unconfirmed_recovery_stays_closed() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let key = SuiteKey::new("debian", "trixie").unwrap();
    for sequence in 1..=3 {
        let path = format!("pool/pkg-{sequence}.deb");
        let mut next = stage(
            &catalog,
            ("debian", "trixie"),
            sequence,
            (sequence as i64) * 100 * METADATA_GRACE,
            None,
            &path,
            Sha256Digest::of(path.as_bytes()),
        );
        if sequence == 3 {
            next.confirmed_at = None;
        }
        install(&catalog, next);
    }
    assert_eq!(catalog.publication_manifests(key.clone()).unwrap().len(), 3);
    let state = catalog.checkpoint_state(key).unwrap();
    assert!(state.blocked);
    assert!(state.recovery_ready);
    assert!(state.confirmed_at.is_none());
}
#[test]
fn signature_only_publications_keep_two_previous_raw_generations_without_unbounded_retention() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let key = SuiteKey::new("debian", "trixie").unwrap();
    let content = Sha256Digest::of(b"unchanged Release content").to_hex();
    for sequence in 1..=8 {
        let path = format!("pool/pkg-{sequence}.deb");
        let mut next = stage(
            &catalog,
            ("debian", "trixie"),
            sequence,
            (sequence as i64 - 1) * METADATA_GRACE,
            None,
            &path,
            Sha256Digest::of(path.as_bytes()),
        );
        next.manifest.release_content_sha256 = content.clone();
        next.manifest.release_date = 1;
        next.intent.release_content_sha256 = content.clone();
        next.intent.release_date = 1;
        next.intent.manifest_sha256 = Sha256Digest::of(&next.manifest.encode().unwrap()).to_hex();
        install(&catalog, next);
        let retained = catalog.publication_manifests(key.clone()).unwrap();
        assert_eq!(retained.len(), (sequence as usize).min(3));
        assert!(
            retained
                .iter()
                .all(|manifest| manifest.release_content_sha256 == content)
        );
    }
    let retained = catalog.publication_manifests(key).unwrap();
    assert_eq!(
        retained
            .iter()
            .map(|manifest| manifest.generation_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    assert!(
        retained
            .iter()
            .all(|manifest| manifest.generation_id != format!("{:064x}", 1))
    );
}

#[test]
fn capture_path_claims_cover_candidates_public_history_identity_and_origin() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"claimed"),
        size: 1,
    };
    let candidate = stage(
        &catalog,
        ("debian", "trixie"),
        1,
        10,
        None,
        "pool/shared.deb",
        identity.sha256,
    );
    prepare(&catalog, &candidate);
    let check = |repository: &str, identity: ObjectIdentity| {
        let repository = repository.to_owned();
        catalog
            .write(move |connection| {
                let transaction = connection.transaction()?;
                capture_path_conflicts(&transaction, &repository, "pool/shared.deb", identity)
            })
            .unwrap()
    };
    // An accepted checkpoint claim already excludes stale request admissions,
    // before there is either a public generation or a capture mapping.
    assert_eq!(count(&catalog, "capture_paths"), 0);
    assert_eq!(count(&catalog, "public_generations"), 0);
    assert!(!check("debian", identity));
    assert!(check(
        "debian",
        ObjectIdentity {
            sha256: Sha256Digest::of(b"stale"),
            ..identity
        }
    ));
    assert!(check(
        "debian",
        ObjectIdentity {
            size: 2,
            ..identity
        }
    ));
    assert!(!check(
        "ubuntu",
        ObjectIdentity {
            sha256: Sha256Digest::of(b"stale"),
            size: 2
        }
    ));
    catalog.publication_activate(candidate).unwrap();
    assert_eq!(count(&catalog, "publication_candidates"), 0);
    assert!(!check("debian", identity));
    assert!(check(
        "debian",
        ObjectIdentity {
            sha256: Sha256Digest::of(b"stale"),
            ..identity
        }
    ));
    assert!(check(
        "debian",
        ObjectIdentity {
            size: 2,
            ..identity
        }
    ));
    assert!(!check(
        "ubuntu",
        ObjectIdentity {
            sha256: Sha256Digest::of(b"stale"),
            size: 2
        }
    ));
    // A retired but retained generation still owns its immutable pool path.
    let successor = stage(
        &catalog,
        ("debian", "trixie"),
        2,
        20,
        None,
        "pool/other.deb",
        identity.sha256,
    );
    install(&catalog, successor);
    assert!(check(
        "debian",
        ObjectIdentity {
            size: 2,
            ..identity
        }
    ));
}

#[test]
fn activation_delay_preserves_confirmation_and_full_retirement_grace() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let key = SuiteKey::new("debian", "trixie").unwrap();
    let first = stage(
        &catalog,
        ("debian", "trixie"),
        1,
        1,
        None,
        "pool/first.deb",
        Sha256Digest::of(b"first"),
    );
    let first_scope = first.manifest.scope_id();
    install(&catalog, first);
    let mut delayed = stage(
        &catalog,
        ("debian", "trixie"),
        2,
        160,
        None,
        "pool/second.deb",
        Sha256Digest::of(b"second"),
    );
    delayed.confirmed_at = Some(100);
    install(&catalog, delayed);
    let state = catalog.checkpoint_state(key.clone()).unwrap();
    assert_eq!(state.confirmed_at, Some(100));
    assert_eq!(state.observed_at, Some(100));
    // At the confirmation-based deadline the oldest generation has more than
    // two successors, but cannot lose its references sixty seconds early.
    for (sequence, now) in [
        (3, 161),
        (4, 100 + METADATA_GRACE),
        (5, 160 + METADATA_GRACE - 1),
    ] {
        let path = format!("pool/{sequence}.deb");
        let next = stage(
            &catalog,
            ("debian", "trixie"),
            sequence,
            now,
            None,
            &path,
            Sha256Digest::of(path.as_bytes()),
        );
        install(&catalog, next);
        assert!(
            catalog
                .publication_manifests(key.clone())
                .unwrap()
                .iter()
                .any(|manifest| manifest.scope_id() == first_scope)
        );
    }
    let next = stage(
        &catalog,
        ("debian", "trixie"),
        6,
        160 + METADATA_GRACE,
        None,
        "pool/six.deb",
        Sha256Digest::of(b"six"),
    );
    install(&catalog, next);
    assert!(
        !catalog
            .publication_manifests(key)
            .unwrap()
            .iter()
            .any(|manifest| manifest.scope_id() == first_scope)
    );
}

#[test]
fn invalid_or_out_of_order_confirmation_never_activates() {
    for confirmation in [-1, 9, 21] {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path(), 4, true).unwrap();
        let mut candidate = stage(
            &catalog,
            ("debian", "trixie"),
            1,
            20,
            None,
            "pool/pkg.deb",
            Sha256Digest::of(b"package"),
        );
        let key = candidate.intent.key().unwrap();
        prepare(&catalog, &candidate);
        catalog
            .publication_observe(
                key.clone(),
                candidate.intent.generation_id.clone(),
                candidate.intent.release_date,
                candidate.intent.release_content_sha256.clone(),
                10,
            )
            .unwrap();
        candidate.confirmed_at = Some(confirmation);
        assert!(catalog.publication_activate(candidate).is_err());
        assert_eq!(count(&catalog, "public_generations"), 0);
        assert!(catalog.checkpoint_state(key).unwrap().active.is_none());
    }
}

#[test]
fn capture_mapping_claim_checks_digest_size_and_repository_without_publication() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let identity = ObjectIdentity {
        sha256: Sha256Digest::of(b"captured"),
        size: 7,
    };
    catalog
        .write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,7,1,100,1)",
                [identity.sha256.to_hex()],
            )?;
            transaction.execute(
                "INSERT INTO capture_proofs(generation,manifest,durable) VALUES('captured-proof','{}',1)",
                [],
            )?;
            transaction.execute(
                "INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES('debian','pool/captured.deb',?1,?2,'captured-proof',1,1,100)",
                params![
                    Sha256Digest::of(b"pool/captured.deb").to_hex(),
                    identity.sha256.to_hex()
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    catalog
        .write(move |connection| {
            let transaction = connection.transaction()?;
            assert!(!capture_path_conflicts(
                &transaction,
                "debian",
                "pool/captured.deb",
                identity
            )?);
            assert!(capture_path_conflicts(
                &transaction,
                "debian",
                "pool/captured.deb",
                ObjectIdentity {
                    size: 8,
                    ..identity
                }
            )?);
            assert!(capture_path_conflicts(
                &transaction,
                "debian",
                "pool/captured.deb",
                ObjectIdentity {
                    sha256: Sha256Digest::of(b"other"),
                    ..identity
                }
            )?);
            assert!(!capture_path_conflicts(
                &transaction,
                "ubuntu",
                "pool/captured.deb",
                ObjectIdentity {
                    sha256: Sha256Digest::of(b"other"),
                    size: 8
                }
            )?);
            Ok(())
        })
        .unwrap();
}

#[test]
fn pacman_candidate_revisions_do_not_inherit_package_build_time_rollback_rules() {
    let directory = tempfile::tempdir().unwrap();
    let catalog = Catalog::open(directory.path(), 4, true).unwrap();
    let key = SuiteKey::new("archlinux", "core").unwrap();
    // A database-only metadata change leaves max BUILDDATE unchanged; removing
    // the newest-built package can lower it. Neither is a signed repository date.
    for (sequence, build_date) in [(1, 200), (2, 200), (3, 100)] {
        let mut revision = stage(
            &catalog,
            ("archlinux", "core"),
            sequence,
            sequence as i64 * 10,
            None,
            "core/os/x86_64/retained-1-1-any.pkg.tar.zst",
            Sha256Digest::of(b"retained"),
        );
        revision.manifest.release_date = build_date;
        revision.intent.release_date = build_date;
        revision.intent.manifest_sha256 =
            Sha256Digest::of(&revision.manifest.encode().unwrap()).to_hex();
        catalog
            .publication_observe(
                key.clone(),
                revision.intent.generation_id.clone(),
                build_date,
                revision.intent.release_content_sha256.clone(),
                revision.now,
            )
            .unwrap();
        let expected = revision.intent.clone();
        install(&catalog, revision);
        let state = catalog.checkpoint_state(key.clone()).unwrap();
        assert_eq!(state.active, Some(expected));
        assert_eq!(state.confirmed_at, Some(sequence as i64 * 10));
    }
    // Sequence and wall-clock regressions remain rejected even for candidates.
    assert!(
        catalog
            .publication_observe(key, "f".repeat(64), 100, "e".repeat(64), 29)
            .is_err()
    );
}
