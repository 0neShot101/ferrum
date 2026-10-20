use super::{CheckpointError, CheckpointPublisher, MAX_SUITES, SuiteKey};

impl CheckpointPublisher {
    /// Local checkpoint identities that must remain covered by recovery trust.
    /// Reads only persisted identities; does not clear coverage or authenticate content.
    pub fn retained_suites(&self) -> Result<Vec<SuiteKey>, CheckpointError> {
        let retained = self.spool.durable_catalog()?.read(|connection| {
            let mut statement = connection.prepare(
                "SELECT repository,suite FROM suite_checkpoints \
                 WHERE floor IS NOT NULL OR active IS NOT NULL OR pending IS NOT NULL \
                 ORDER BY repository,suite LIMIT ?1",
            )?;
            let rows = statement.query_map([MAX_SUITES as i64 + 1], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        if retained.len() > MAX_SUITES {
            return Err(CheckpointError::Invalid);
        }
        retained
            .into_iter()
            .map(|(repository, suite)| SuiteKey::new(&repository, &suite))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{capture::tests as capture_test, recovery::test_support};
    use std::sync::Arc;

    #[test]
    fn retained_selection_is_bounded_read_only_and_ignores_unused_bootstrap() {
        let root = tempfile::tempdir().unwrap();
        let spool = test_support::open_spool(&root.path().join("state"));
        let (capture, _, requests) = capture_test::setup(spool.clone(), vec![]);
        let publisher = CheckpointPublisher::new(
            spool.clone(),
            Arc::clone(capture.store()),
            super::super::RecoveryProfile::SharedNonisolated,
        )
        .unwrap();
        // Persistence markers test selection only, not publication authentication.
        spool
            .catalog_write(|connection| {
                for (suite, floor, active, pending) in [
                    ("floor", Some("floor-marker"), None, None),
                    ("active", None, Some("active-marker"), None),
                    ("pending", None, None, Some("pending-marker")),
                    ("unused", None, None, None),
                ] {
                    connection.execute(
                        "INSERT INTO suite_checkpoints(repository,suite,floor,active,pending) VALUES('debian',?1,?2,?3,?4)",
                        rusqlite::params![suite, floor, active, pending],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(
            publisher.retained_suites().unwrap(),
            vec![
                SuiteKey::new("debian", "active").unwrap(),
                SuiteKey::new("debian", "floor").unwrap(),
                SuiteKey::new("debian", "pending").unwrap(),
            ]
        );
        assert!(capture.coverage_ready().unwrap());
        let markers = spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT COUNT(*) FROM suite_checkpoints WHERE floor='floor-marker' OR active='active-marker' OR pending='pending-marker'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .unwrap();
        assert_eq!(markers, 3);
        assert!(requests.snapshot().unwrap().is_empty());
        spool
            .catalog_write(|connection| {
                for index in 0..103 {
                    connection.execute(
                        "INSERT INTO suite_checkpoints(repository,suite,floor) VALUES('inventory',?1,'marker')",
                        [format!("suite-{index}")],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(publisher.retained_suites().unwrap().len(), 106);
        spool
            .catalog_write(|connection| {
                for index in 0..MAX_SUITES {
                    connection.execute(
                        "INSERT INTO suite_checkpoints(repository,suite,floor) VALUES('extra',?1,'marker')",
                        [index.to_string()],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        assert!(publisher.retained_suites().is_err());
        assert!(capture.coverage_ready().unwrap());
    }

    #[test]
    fn retained_selection_survives_spool_reopen() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        {
            let spool = test_support::open_spool(&state);
            let (capture, ledger, _) = capture_test::setup(spool.clone(), vec![]);
            let reserved = capture
                .store()
                .package_key(&format!(
                    "v1/objects/sha256/{}",
                    ferrum_apt::digest::Sha256Digest::of(b"retained reservation")
                ))
                .unwrap();
            ledger
                .reserve_storage(&reserved, 4096, crate::budget::BudgetClass::Package)
                .unwrap();
            let publisher = CheckpointPublisher::new(
                spool.clone(),
                Arc::clone(capture.store()),
                super::super::RecoveryProfile::SharedNonisolated,
            )
            .unwrap();
            spool
                .catalog_write(|connection| {
                    connection.execute(
                        "INSERT INTO suite_checkpoints(repository,suite,floor,active) \
                         VALUES('debian','trixie','retained-floor','retained-active')",
                        [],
                    )?;
                    Ok(())
                })
                .unwrap();
            assert_eq!(publisher.retained_suites().unwrap().len(), 1);
            spool.checkpoint().unwrap();
        }

        let spool = test_support::open_spool(&state);
        let ledger =
            crate::budget::BudgetLedger::open(spool.clone(), capture_test::limits()).unwrap();
        assert_eq!(ledger.usage().unwrap().storage, 4096);
        let (store, _) =
            crate::s3::S3Store::scripted_production(capture_test::config(&spool), ledger, vec![])
                .unwrap();
        let publisher = CheckpointPublisher::new(
            spool.clone(),
            Arc::new(store),
            super::super::RecoveryProfile::SharedNonisolated,
        )
        .unwrap();
        assert_eq!(
            publisher.retained_suites().unwrap(),
            vec![SuiteKey::new("debian", "trixie").unwrap()]
        );
        let preserved = spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT floor,active FROM suite_checkpoints \
                     WHERE repository='debian' AND suite='trixie'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )?)
            })
            .unwrap();
        assert_eq!(
            preserved,
            ("retained-floor".into(), "retained-active".into())
        );
    }
}
