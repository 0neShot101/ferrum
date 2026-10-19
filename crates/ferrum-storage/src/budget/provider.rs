//! Immutable remote destination ownership, independent of credentials and allowances.
use super::{BudgetError, BudgetLedger};
use crate::Spool;
use crate::catalog::CatalogError;
use rusqlite::{Connection, OptionalExtension, params};

pub(crate) const SCHEMA: &[(&str, &str)] = &[
    (
        "remote_provider",
        "CREATE TABLE remote_provider (id INTEGER PRIMARY KEY CHECK(id=1), endpoint TEXT NOT NULL, bucket TEXT NOT NULL, region TEXT NOT NULL, package_prefix TEXT NOT NULL, checkpoint_prefix TEXT NOT NULL) STRICT",
    ),
    (
        "remote_provider_initialization",
        "CREATE TABLE remote_provider_initialization (id INTEGER PRIMARY KEY CHECK(id=1)) STRICT",
    ),
    (
        "legacy_provider_adoption",
        "CREATE TABLE legacy_provider_adoption (id INTEGER PRIMARY KEY CHECK(id=1), provider_id INTEGER NOT NULL CHECK(provider_id=1) REFERENCES remote_provider(id), adopted_at INTEGER NOT NULL CHECK(adopted_at>0), operator TEXT NOT NULL, reason TEXT NOT NULL, disclosure TEXT NOT NULL) STRICT",
    ),
];

/// Exact non-secret remote authority. Constructed only from a validated S3 configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub(crate) endpoint: String,
    pub(crate) bucket: String,
    pub(crate) region: String,
    pub(crate) package_prefix: String,
    pub(crate) checkpoint_prefix: String,
}

impl ProviderIdentity {
    fn read(connection: &Connection) -> Result<Option<Self>, CatalogError> {
        Ok(connection
            .query_row(
                "SELECT endpoint,bucket,region,package_prefix,checkpoint_prefix FROM remote_provider WHERE id=1",
                [],
                |row| {
                    Ok(Self {
                        endpoint: row.get(0)?,
                        bucket: row.get(1)?,
                        region: row.get(2)?,
                        package_prefix: row.get(3)?,
                        checkpoint_prefix: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub(super) fn insert(&self, connection: &Connection) -> Result<(), CatalogError> {
        connection.execute(
            "INSERT INTO remote_provider(id,endpoint,bucket,region,package_prefix,checkpoint_prefix) VALUES(1,?1,?2,?3,?4,?5)",
            params![
                self.endpoint,
                self.bucket,
                self.region,
                self.package_prefix,
                self.checkpoint_prefix
            ],
        )?;
        Ok(())
    }
}

/// Mandatory acknowledgement for the offline, non-migrating legacy adoption operation.
pub const LEGACY_PROVIDER_DISCLOSURE: &str = "LEGACY PROVIDER VERIFIED; NO DATA OR ALLOWANCE RESET";

/// Audited operator assertion of the only destination supported before provider binding.
pub struct LegacyProviderAdoption {
    operator: String,
    reason: String,
    adopted_at: i64,
}

impl LegacyProviderAdoption {
    pub fn acknowledge(
        operator: &str,
        reason: &str,
        adopted_at: i64,
        disclosure: &str,
    ) -> Result<Self, BudgetError> {
        if operator.trim().is_empty()
            || operator.len() > 256
            || operator.chars().any(char::is_control)
            || reason.trim().is_empty()
            || reason.len() > 2048
            || reason.chars().any(char::is_control)
            || adopted_at <= 0
            || disclosure != LEGACY_PROVIDER_DISCLOSURE
        {
            return Err(BudgetError::Refused);
        }
        Ok(Self {
            operator: operator.to_owned(),
            reason: reason.to_owned(),
            adopted_at,
        })
    }
}

/// Must run inside the same writer transaction as any subsequent accounting reconciliation.
pub(super) fn bind(
    connection: &Connection,
    identity: &ProviderIdentity,
) -> Result<(), CatalogError> {
    if let Some(previous) = ProviderIdentity::read(connection)? {
        return if previous == *identity {
            Ok(())
        } else {
            Err(CatalogError::InvalidState)
        };
    }
    let fresh: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM remote_provider_initialization WHERE id=1)",
        [],
        |row| row.get(0),
    )?;
    // Only the new explicit initializer may grant first-bind authority. Even that
    // authority expires if any remote usage/history exists before the first bind.
    if !fresh || !unused(connection)? {
        return Err(CatalogError::InvalidState);
    }
    identity.insert(connection)?;
    connection.execute("DELETE FROM remote_provider_initialization WHERE id=1", [])?;
    Ok(())
}

pub(super) fn unused(connection: &Connection) -> Result<bool, CatalogError> {
    let populated: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM remote_budget WHERE used<>0 OR data_used<>0 OR certain=0 UNION ALL SELECT 1 FROM remote_storage UNION ALL SELECT 1 FROM download_reservations UNION ALL SELECT 1 FROM remote_quarantine UNION ALL SELECT 1 FROM remote_health WHERE forbidden<>0 UNION ALL SELECT 1 FROM multipart_uploads UNION ALL SELECT 1 FROM qualification_ownership UNION ALL SELECT 1 FROM qualification_budget WHERE uploaded<>0 OR downloaded<>0 UNION ALL SELECT 1 FROM capture_state UNION ALL SELECT 1 FROM capture_blobs UNION ALL SELECT 1 FROM capture_proofs UNION ALL SELECT 1 FROM suite_checkpoints WHERE floor IS NOT NULL OR active IS NOT NULL OR pending IS NOT NULL)",
        [],
        |row| row.get(0),
    )?;
    Ok(!populated)
}

impl BudgetLedger {
    /// Bind only an explicitly initialized, still-unused ledger, or verify its
    /// immutable existing binding. Serialized with all accounting writes.
    pub fn bind_provider(&self, identity: &ProviderIdentity) -> Result<(), BudgetError> {
        let identity = identity.clone();
        self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            bind(&transaction, &identity)?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }

    /// Read-only provider check, suitable for offline status. Never adopts or binds.
    pub fn check_provider(spool: &Spool, identity: &ProviderIdentity) -> Result<(), BudgetError> {
        let identity = identity.clone();
        spool.durable_catalog()?.read(move |connection| {
            if ProviderIdentity::read(connection)?.as_ref() != Some(&identity) {
                return Err(CatalogError::InvalidState);
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Offline legacy adoption only: adds identity and audit without reopening,
    /// reconciling, resetting, or otherwise editing any prior accounting/history.
    /// The caller must already hold the durable spool's exclusive process lock.
    pub fn adopt_legacy_provider(
        spool: &Spool,
        identity: &ProviderIdentity,
        audit: LegacyProviderAdoption,
    ) -> Result<(), BudgetError> {
        let identity = identity.clone();
        spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            let ineligible: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM remote_provider UNION ALL SELECT 1 FROM remote_provider_initialization UNION ALL SELECT 1 FROM legacy_provider_adoption) OR NOT EXISTS(SELECT 1 FROM remote_budget WHERE id=1)",
                [],
                |row| row.get(0),
            )?;
            let qualification: Option<Option<String>> = transaction
                .query_row(
                    "SELECT run FROM qualification_budget WHERE id=1",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            let prefixes = match qualification {
                None => (
                    "linux-packages/".to_owned(),
                    "linux-checkpoints/".to_owned(),
                ),
                Some(Some(run)) if valid_run(&run) => (
                    format!("linux-packages/_ferrum-b07/{run}/"),
                    format!("linux-checkpoints/_ferrum-b07/{run}/"),
                ),
                _ => return Err(CatalogError::InvalidState),
            };
            if ineligible || identity.endpoint != "https://s3.us-central-1.idrivee2.com/" || identity.region != "us-central-1" || identity.bucket != "s3-andrew" || identity.package_prefix != prefixes.0 || identity.checkpoint_prefix != prefixes.1 {
                return Err(CatalogError::InvalidState);
            }
            identity.insert(&transaction)?;
            transaction.execute(
                "INSERT INTO legacy_provider_adoption(id,provider_id,adopted_at,operator,reason,disclosure) VALUES(1,1,?1,?2,?3,?4)",
                params![
                    audit.adopted_at,
                    audit.operator,
                    audit.reason,
                    LEGACY_PROVIDER_DISCLOSURE
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }
}

pub(crate) fn valid_run(run: &str) -> bool {
    run.len() == 32
        && run
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::budget::{BudgetClass, BudgetLimits};
    use crate::recovery::test_support;
    use crate::s3::S3Config;
    use std::path::Path;
    use std::sync::{Arc, Barrier};

    fn config(root: &Path) -> S3Config {
        S3Config {
            endpoint: "https://s3.us-central-1.idrivee2.com".into(),
            region: "us-central-1".into(),
            bucket: "s3-andrew".into(),
            package_prefix: "linux-packages/".into(),
            checkpoint_prefix: "linux-checkpoints/".into(),
            credentials_file: root.join("unused-credentials"),
            shared_nonisolated: true,
        }
    }

    type Snapshot = Vec<(String, String, Vec<Vec<rusqlite::types::Value>>)>;

    fn history(spool: &Spool) -> Snapshot {
        spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                let mut tables = connection.prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('remote_provider','remote_provider_initialization','legacy_provider_adoption') ORDER BY name")?;
                let tables = tables
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                tables
                    .into_iter()
                    .map(|(name, schema)| {
                        let mut rows = connection.prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))?;
                        let columns = rows.column_count();
                        let values = rows
                            .query_map([], |row| {
                                (0..columns)
                                    .map(|index| row.get(index))
                                    .collect::<Result<Vec<_>, _>>()
                            })?
                            .collect::<Result<Vec<_>, _>>()?;
                        Ok((name, schema, values))
                    })
                    .collect()
            })
            .unwrap()
    }

    fn legacy(root: &Path) -> (Spool, Snapshot) {
        let spool = test_support::open_spool(root);
        let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default()).unwrap();
        ledger
            .reserve_storage("linux-packages/owned", 42, BudgetClass::Package)
            .unwrap();
        spool
            .catalog_write(|connection| {
                let transaction = connection.transaction()?;
                transaction.execute(
                    "UPDATE remote_budget SET period=1,high_time=1,used=777,data_used=555 WHERE id=1",
                    [],
                )?;
                transaction.execute(
                    "INSERT INTO download_reservations(id,amount,class,period) VALUES('outstanding',99,0,1)",
                    [],
                )?;
                transaction.execute(
                    "INSERT INTO remote_quarantine(key) VALUES('linux-packages/quarantined')",
                    [],
                )?;
                transaction.execute(
                    "INSERT INTO capture_state(id,coverage,recovery_time,gc_resume) VALUES(1,1,123,0)",
                    [],
                )?;
                for (table, _) in SCHEMA.iter().rev() {
                    transaction.execute_batch(&format!("DROP TABLE {table}"))?;
                }
                transaction.pragma_update(None, "user_version", 3)?;
                transaction.commit()?;
                Ok(())
            })
            .unwrap();
        let before = history(&spool);
        drop(ledger);
        drop(spool);
        let spool = test_support::open_spool(root);
        assert_eq!(
            history(&spool),
            before,
            "v3 migration must only add binding metadata"
        );
        (spool, before)
    }

    fn audit() -> LegacyProviderAdoption {
        LegacyProviderAdoption::acknowledge(
            "operator",
            "verified historical destination",
            123,
            LEGACY_PROVIDER_DISCLOSURE,
        )
        .unwrap()
    }

    #[test]
    fn fresh_first_binding_is_atomic_and_cannot_be_retargeted() {
        let root = tempfile::tempdir().unwrap();
        let spool = test_support::open_spool(&root.path().join("state"));
        let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default()).unwrap();
        let first = config(root.path()).provider_identity(None).unwrap();
        let mut second = first.clone();
        second.bucket = "other-bucket".into();
        let barrier = Arc::new(Barrier::new(2));
        let handles = [first.clone(), second].map(|identity| {
            let ledger = ledger.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let accepted = ledger.bind_provider(&identity).is_ok();
                (identity, accepted)
            })
        });
        let outcomes = handles.map(|handle| handle.join().unwrap());
        assert_eq!(outcomes.iter().filter(|(_, accepted)| *accepted).count(), 1);
        for (identity, accepted) in outcomes {
            assert_eq!(
                BudgetLedger::check_provider(&spool, &identity).is_ok(),
                accepted
            );
            assert_eq!(ledger.bind_provider(&identity).is_ok(), accepted);
        }
    }

    #[test]
    fn explicit_initialization_records_normalized_destination_before_first_open() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let spool = test_support::open_spool(&state);
        let mut configured = config(root.path());
        configured.endpoint = "https://S3.US-CENTRAL-1.IDRIVEE2.COM:443/".into();
        let identity = configured.provider_identity(None).unwrap();
        let ledger = BudgetLedger::initialize_for_provider(
            spool.clone(),
            BudgetLimits::default(),
            &identity,
        )
        .unwrap();
        let canonical = config(root.path()).provider_identity(None).unwrap();
        assert_eq!(identity, canonical);
        BudgetLedger::check_provider(&spool, &canonical).unwrap();
        assert!(
            BudgetLedger::initialize_for_provider(
                spool.clone(),
                BudgetLimits::default(),
                &canonical,
            )
            .is_err()
        );
        drop(ledger);
        drop(spool);
        let reopened = test_support::open_spool(&state);
        BudgetLedger::open_for_provider(reopened, BudgetLimits::default(), &canonical).unwrap();
    }

    #[test]
    fn populated_fresh_unbound_ledger_is_not_silently_bound() {
        let root = tempfile::tempdir().unwrap();
        let spool = test_support::open_spool(&root.path().join("state"));
        let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default()).unwrap();
        ledger.reserve_download(99, BudgetClass::Control).unwrap();
        let before = history(&spool);
        let identity = config(root.path()).provider_identity(None).unwrap();
        assert!(ledger.bind_provider(&identity).is_err());
        assert!(
            BudgetLedger::open_for_provider(spool.clone(), BudgetLimits::default(), &identity,)
                .is_err()
        );
        assert_eq!(history(&spool), before);
    }

    #[test]
    fn fresh_ledger_rejects_legacy_adoption_and_markerless_empty_ledger_requires_it() {
        let root = tempfile::tempdir().unwrap();
        let spool = test_support::open_spool(&root.path().join("state"));
        let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default()).unwrap();
        let identity = config(root.path()).provider_identity(None).unwrap();
        assert!(BudgetLedger::adopt_legacy_provider(&spool, &identity, audit()).is_err());
        spool
            .catalog_write(|connection| {
                connection.execute("DELETE FROM remote_provider_initialization", [])?;
                Ok(())
            })
            .unwrap();
        assert!(ledger.bind_provider(&identity).is_err());
        BudgetLedger::adopt_legacy_provider(&spool, &identity, audit()).unwrap();
        BudgetLedger::check_provider(&spool, &identity).unwrap();
    }

    #[test]
    fn legacy_unknown_rejects_open_without_touching_balances_and_adoption_preserves_history() {
        let root = tempfile::tempdir().unwrap();
        let (spool, before) = legacy(&root.path().join("state"));
        let identity = config(root.path()).provider_identity(None).unwrap();
        assert!(
            BudgetLedger::open_for_provider(spool.clone(), BudgetLimits::default(), &identity,)
                .is_err()
        );
        assert_eq!(history(&spool), before);
        for field in 0..5 {
            let mut arbitrary = identity.clone();
            match field {
                0 => arbitrary.endpoint = "https://other.example.org/".into(),
                1 => arbitrary.bucket = "another-bucket".into(),
                2 => arbitrary.region = "another-region".into(),
                3 => arbitrary.package_prefix = "other-packages/".into(),
                _ => arbitrary.checkpoint_prefix = "other-checkpoints/".into(),
            }
            assert!(BudgetLedger::adopt_legacy_provider(&spool, &arbitrary, audit()).is_err());
            assert_eq!(history(&spool), before);
        }
        assert!(LegacyProviderAdoption::acknowledge("operator", "reason", 123, "yes").is_err());
        assert!(
            LegacyProviderAdoption::acknowledge("", "reason", 123, LEGACY_PROVIDER_DISCLOSURE)
                .is_err()
        );
        assert!(
            LegacyProviderAdoption::acknowledge("operator", "", 123, LEGACY_PROVIDER_DISCLOSURE)
                .is_err()
        );
        BudgetLedger::adopt_legacy_provider(&spool, &identity, audit()).unwrap();
        assert_eq!(history(&spool), before);
        BudgetLedger::check_provider(&spool, &identity).unwrap();
        assert!(BudgetLedger::adopt_legacy_provider(&spool, &identity, audit()).is_err());
        let mut different = identity;
        different.bucket = "another-bucket".into();
        assert!(BudgetLedger::adopt_legacy_provider(&spool, &different, audit()).is_err());
        assert_eq!(history(&spool), before);
        let recorded = spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT operator,reason,adopted_at,disclosure FROM legacy_provider_adoption WHERE id=1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )?)
            })
            .unwrap();
        assert_eq!(
            recorded,
            (
                "operator".into(),
                "verified historical destination".into(),
                123,
                LEGACY_PROVIDER_DISCLOSURE.into()
            )
        );
    }

    #[test]
    fn legacy_qualification_adopts_only_its_persisted_fixed_provider_namespace() {
        let root = tempfile::tempdir().unwrap();
        let (spool, before) = legacy(&root.path().join("state"));
        let run = "0123456789abcdef0123456789abcdef";
        spool
            .catalog_write(move |connection| {
                connection.execute(
                    "INSERT INTO qualification_budget(id,run,upload_limit,download_limit,storage_limit,cleanup_upload,cleanup_download,general_upload,general_download) VALUES(1,?1,1000000,1000000,1000000,100,200,100,200)",
                    [run],
                )?;
                Ok(())
            })
            .unwrap();
        let with_qualification = history(&spool);
        assert_ne!(with_qualification, before);
        let configured = config(root.path());
        let unscoped = configured.provider_identity(None).unwrap();
        assert!(BudgetLedger::adopt_legacy_provider(&spool, &unscoped, audit()).is_err());
        let wrong_run = configured
            .provider_identity(Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
            .unwrap();
        assert!(BudgetLedger::adopt_legacy_provider(&spool, &wrong_run, audit()).is_err());
        let identity = configured.provider_identity(Some(run)).unwrap();
        BudgetLedger::adopt_legacy_provider(&spool, &identity, audit()).unwrap();
        assert_eq!(history(&spool), with_qualification);
    }
}
