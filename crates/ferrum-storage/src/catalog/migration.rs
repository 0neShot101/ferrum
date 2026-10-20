//! Migration fixtures exercise the exact previous schema, not a fresh ledger reset.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::checkpoint::{PublicationIntent, SuiteKey};

fn version_two(directory: &Path) -> PublicationIntent {
    let catalog = Catalog::open(directory, 4, true).unwrap();
    let intent = PublicationIntent {
        schema_version: 1,
        repository: "debian".into(),
        suite: "trixie".into(),
        sequence: 17,
        generation_id: "a".repeat(64),
        manifest_sha256: "b".repeat(64),
        release_content_sha256: "c".repeat(64),
        release_date: 123,
    };
    let encoded = intent.encode().unwrap();
    catalog
        .write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO remote_budget(id,period,high_time,used,data_used,certain) VALUES(1,202601,123,777,555,1)",
                [],
            )?;
            transaction.execute(
                "INSERT INTO download_reservations(id,amount,class,period) VALUES('outstanding',99,0,202601)",
                [],
            )?;
            transaction.execute(
                "INSERT INTO remote_storage(key,size,class,committed) VALUES('linux-packages/owned',42,0,1)",
                [],
            )?;
            transaction.execute(
                "INSERT INTO qualification_budget(id,run,upload_limit,download_limit,storage_limit,uploaded,downloaded,cleanup_upload,cleanup_download,general_upload,general_download) VALUES(1,'6e11358885394eea8bc768badaaa89e9',1000000,1000000,1000000,111,222,300,400,500,600)",
                [],
            )?;
            transaction.execute(
                "INSERT INTO capture_state(id,coverage,recovery_time,gc_resume) VALUES(1,1,123,0)",
                [],
            )?;
            transaction.execute(
                "INSERT INTO suite_checkpoints(repository,suite,observed_date,observed_content,floor,active,blocked) VALUES('debian','trixie',123,?1,?2,?2,0)",
                params!["c".repeat(64), encoded],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .unwrap();
    drop(catalog);
    let mut connection = Connection::open(directory.join("state.sqlite")).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
        .unwrap();
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
        .unwrap();
    for table in [
        "capture_package_signatures",
        "derived_residency",
        "publication_metadata",
        "publication_artifacts",
        "publication_candidates",
        "public_generations",
        "suite_publication",
    ] {
        transaction
            .execute_batch(&format!("DROP TABLE {table}"))
            .unwrap();
    }
    for (table, _) in crate::budget::provider::SCHEMA.iter().rev() {
        transaction
            .execute_batch(&format!("DROP TABLE {table}"))
            .unwrap();
    }
    transaction.pragma_update(None, "user_version", 2).unwrap();
    transaction.commit().unwrap();
    intent
}
#[test]
fn version_two_upgrade_preserves_budget_reservations_private_run_and_trusted_floor() {
    let directory = tempfile::tempdir().unwrap();
    let intent = version_two(directory.path());
    let catalog = Catalog::open(directory.path(), 4, false).unwrap();
    let (used, data, amount, total, uploaded, downloaded, run) = catalog
        .read(|connection| {
            Ok((
                connection.query_row("SELECT used FROM remote_budget WHERE id=1", [], |row| {
                    row.get::<_, i64>(0)
                })?,
                connection.query_row(
                    "SELECT data_used FROM remote_budget WHERE id=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                connection.query_row(
                    "SELECT amount FROM download_reservations WHERE id='outstanding'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                connection.query_row(
                    "SELECT total FROM remote_storage_totals WHERE id=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                connection.query_row(
                    "SELECT uploaded FROM qualification_budget WHERE id=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                connection.query_row(
                    "SELECT downloaded FROM qualification_budget WHERE id=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                connection.query_row(
                    "SELECT run FROM qualification_budget WHERE id=1",
                    [],
                    |row| row.get::<_, String>(0),
                )?,
            ))
        })
        .unwrap();
    assert_eq!(
        (used, data, amount, total, uploaded, downloaded),
        (777, 555, 99, 42, 111, 222)
    );
    assert_eq!(run, "6e11358885394eea8bc768badaaa89e9");
    let state = catalog
        .checkpoint_state(SuiteKey::new("debian", "trixie").unwrap())
        .unwrap();
    assert_eq!(state.floor, Some(intent.clone()));
    assert_eq!(state.active, Some(intent));
    assert!(state.blocked);
    assert!(state.confirmed_at.is_none());
    assert!(!state.recovery_ready);
    assert!(
        catalog
            .publication_manifests(SuiteKey::new("debian", "trixie").unwrap())
            .unwrap()
            .is_empty()
    );
}
#[test]
fn corrupt_or_unknown_version_two_catalog_is_rejected_before_any_migration_write() {
    for corrupt in 0..4 {
        let directory = tempfile::tempdir().unwrap();
        version_two(directory.path());
        let connection = Connection::open(directory.path().join("state.sqlite")).unwrap();
        if corrupt == 1 {
            connection
                .execute_batch("DROP INDEX capture_entries_path; CREATE INDEX capture_entries_path ON capture_index_entries(digest)")
                .unwrap();
        } else if corrupt == 2 {
            connection
                .execute(
                    "INSERT INTO objects(digest,size,class,resident,generation_references) VALUES(?1,1,1,1,1)",
                    ["d".repeat(64)],
                )
                .unwrap();
        } else if corrupt == 3 {
            connection
                .execute("UPDATE remote_storage_totals SET total=43 WHERE id=1", [])
                .unwrap();
        } else {
            connection
                .execute_batch("CREATE TABLE unknown_authority(value TEXT) STRICT")
                .unwrap();
        }
        drop(connection);
        assert!(Catalog::open(directory.path(), 4, false).is_err());
        let connection = Connection::open_with_flags(
            directory.path().join("state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let used: i64 = connection
            .query_row("SELECT used FROM remote_budget WHERE id=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let new_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name='suite_publication'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((version, used, new_tables), (2, 777, 0));
    }
}

fn authority_rows(connection: &Connection) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'capture_package_signatures' ORDER BY name")
        .unwrap();
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut statement = connection
                .prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))
                .unwrap();
            let columns = statement.column_count();
            let values = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get(column))
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (name, values)
        })
        .collect()
}

#[test]
fn version_four_package_proof_upgrade_preserves_all_existing_authority_rows() {
    let directory = tempfile::tempdir().unwrap();
    version_two(directory.path());
    drop(Catalog::open(directory.path(), 4, false).unwrap());
    let path = directory.path().join("state.sqlite");
    let mut connection = Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
        .unwrap();
    transaction
        .execute_batch("DROP TABLE capture_package_signatures")
        .unwrap();
    transaction
        .execute(
            "INSERT INTO remote_provider(id,endpoint,bucket,region,package_prefix,checkpoint_prefix) VALUES(1,'https://storage.example.invalid','fixture','local','linux-packages/','linux-checkpoints/')",
            [],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO legacy_provider_adoption(id,provider_id,adopted_at,operator,reason,disclosure) VALUES(1,1,123,'fixture operator','fixture historical adoption','LEGACY PROVIDER VERIFIED; NO DATA OR ALLOWANCE RESET')",
            [],
        )
        .unwrap();
    transaction.pragma_update(None, "user_version", 4).unwrap();
    transaction.commit().unwrap();
    let before = authority_rows(&connection);
    drop(connection);

    let catalog = Catalog::open(directory.path(), 4, false).unwrap();
    let after = catalog
        .read(|connection| Ok(authority_rows(connection)))
        .unwrap();
    assert_eq!(
        after, before,
        "upgrade must not reset balances, reservations, provider ownership, capture coverage, audit history or publication floors"
    );
    drop(catalog);
    let reopened = Catalog::open(directory.path(), 4, false).unwrap();
    assert_eq!(
        reopened
            .read(|connection| Ok(authority_rows(connection)))
            .unwrap(),
        before,
        "reopening the upgraded catalog must remain idempotent"
    );
}
