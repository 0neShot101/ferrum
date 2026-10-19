//! Reconstructible metadata is locally evictable, but never package Durable.
use super::{Spool, SpoolError, lock_unpoisoned};
use crate::catalog::CatalogError;
use ferrum_apt::digest::ObjectIdentity;
use rusqlite::params;

/// An owner-issued deletion-eligibility capability, not package durability or
/// serving authority. A selected request may finish after public retirement.
pub(crate) struct DerivedPermit {
    owner: Spool,
    expected: ObjectIdentity,
}

fn authorized(
    connection: &rusqlite::Connection,
    expected: ObjectIdentity,
    source: ObjectIdentity,
    name: &str,
) -> Result<bool, CatalogError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM publication_metadata m JOIN publication_metadata s ON s.generation=m.generation AND s.path=m.source_path JOIN public_generations g ON g.generation=m.generation WHERE m.path<>m.source_path AND m.digest=?1 AND m.size=?2 AND m.source_path=?3 AND s.digest=?4 AND s.size=?5)",
        params![
            expected.sha256.to_hex(),
            crate::catalog::signed(expected.size)?,
            name,
            source.sha256.to_hex(),
            crate::catalog::signed(source.size)?
        ],
        |row| row.get(0),
    )?)
}
impl Spool {
    pub(crate) fn authorize_derived(
        &self,
        expected: ObjectIdentity,
        source: ObjectIdentity,
        name: &str,
    ) -> Result<Option<DerivedPermit>, SpoolError> {
        let name = name.to_owned();
        let authorized = self
            .durable_catalog()?
            .read(move |connection| authorized(connection, expected, source, &name))?;
        Ok(authorized.then(|| DerivedPermit {
            owner: self.clone(),
            expected,
        }))
    }
    pub(crate) fn finish_derived(&self, permit: DerivedPermit) -> Result<(), SpoolError> {
        if !self.same_owner(&permit.owner) {
            return Err(SpoolError::ReservationMismatch);
        }
        let expected = permit.expected;
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0
            .check_catalog_operation(super::SQL_OPERATION_RESERVE)?;
        if registry
            .entries
            .get(&expected)
            .is_none_or(|entry| entry.evicting)
        {
            return Err(SpoolError::ReservationMismatch);
        }
        let reconstructible = self.durable_catalog()?.write(move |connection| {
            let transaction = connection.transaction()?;
            let captured: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_blobs WHERE digest=?1)",
                [expected.sha256.to_hex()],
                |row| row.get(0),
            )?;
            if !captured {
                transaction.execute(
                    "INSERT OR IGNORE INTO derived_residency(digest) VALUES(?1)",
                    [expected.sha256.to_hex()],
                )?;
            }
            transaction.commit()?;
            Ok(!captured)
        })?;
        if let Some(entry) = registry.entries.get_mut(&expected) {
            entry.reconstructible = reconstructible;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::{ReservationClass, VerifiedObject};
    use ferrum_apt::digest::Sha256Digest;
    use std::io::Write;
    const PATH: &str = "main/binary-amd64/Packages.gz";
    const BODY: &[u8] = b"bounded derived metadata\n";
    async fn install(spool: &Spool, bytes: &[u8], class: ReservationClass) -> VerifiedObject {
        let expected = ObjectIdentity {
            sha256: Sha256Digest::of(bytes),
            size: bytes.len() as u64,
        };
        let reservation = spool.reserve_class(expected.size, class).unwrap();
        let mut writer = spool.begin_write(reservation, expected).await.unwrap();
        writer
            .write(bytes::Bytes::copy_from_slice(bytes))
            .await
            .unwrap();
        writer.commit().await.unwrap()
    }
    async fn selected_source(spool: &Spool) -> VerifiedObject {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(BODY).unwrap();
        let compressed = encoder.finish().unwrap();
        let source = install(spool, &compressed, ReservationClass::Metadata).await;
        let source_identity = source.identity();
        let expanded = ObjectIdentity {
            sha256: Sha256Digest::of(BODY),
            size: BODY.len() as u64,
        };
        // Post-authentication descriptor rows isolate disk ownership; the signed
        // publication tests establish their upstream authentication separately.
        spool
            .catalog_write(move |connection| {
                let transaction = connection.transaction()?;
                transaction.execute(
                    "INSERT INTO suite_checkpoints(repository,suite) VALUES('fixture','ferrum-test')",
                    [],
                )?;
                transaction.execute(
                    "INSERT INTO public_generations(generation,repository,suite,raw_generation,release_content,release_date,activated_at,intent,manifest) VALUES(?1,'fixture','ferrum-test',?1,?1,0,0,'{}','{}')",
                    ["a".repeat(64)],
                )?;
                transaction.execute(
                    "INSERT INTO publication_metadata(generation,path,directory,digest,size,sha256_alias,source_path) VALUES(?1,?2,'main/binary-amd64',?3,?4,1,?2)",
                    params![
                        "a".repeat(64),
                        PATH,
                        source_identity.sha256.to_hex(),
                        crate::catalog::signed(source_identity.size)?
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO publication_metadata(generation,path,directory,digest,size,sha256_alias,source_path) VALUES(?1,'main/binary-amd64/Packages','main/binary-amd64',?2,?3,1,?4)",
                    params![
                        "a".repeat(64),
                        expanded.sha256.to_hex(),
                        crate::catalog::signed(expanded.size)?,
                        PATH
                    ],
                )?;
                transaction.commit()?;
                Ok(())
            })
            .unwrap();
        spool
            .retain_generation(
                Sha256Digest::of(b"selected source pin"),
                &[source.identity()],
            )
            .unwrap();
        source
    }
    #[tokio::test]
    async fn reconstructed_metadata_is_evictable_without_upload_or_durability() {
        let root = tempfile::tempdir().unwrap();
        let spool = Spool::open_durable(super::super::durable_tests::config(root.path())).unwrap();
        let source = selected_source(&spool).await;
        let expected = ObjectIdentity {
            sha256: Sha256Digest::of(BODY),
            size: BODY.len() as u64,
        };
        let object = crate::recovery::materialize_derived(
            &spool,
            source.clone(),
            PATH,
            expected,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(object.read_bounded(1024).await.unwrap(), BODY);
        {
            let registry = lock_unpoisoned(&spool.0.installed);
            let entry = registry.entries.get(&expected).unwrap();
            assert!(entry.reconstructible);
            assert!(!entry.durable);
            assert_eq!(entry.generation_references, 0);
        }
        let pending = spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT (SELECT COUNT(*) FROM capture_outbox)+(SELECT COUNT(*) FROM capture_admissions)",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .unwrap();
        assert_eq!(pending, 0);
        drop(object);
        drop(source);
        assert!(spool.reclaim(expected.size).unwrap() >= expected.size);
        assert!(spool.lookup(expected).is_none());
    }
    #[tokio::test]
    async fn restart_preserves_reconstruction_eligibility_and_capture_revokes_it() {
        let root = tempfile::tempdir().unwrap();
        let config = super::super::durable_tests::config(root.path());
        let spool = Spool::open_durable(config.clone()).unwrap();
        let source = selected_source(&spool).await;
        let expected = ObjectIdentity {
            sha256: Sha256Digest::of(BODY),
            size: BODY.len() as u64,
        };
        let object = crate::recovery::materialize_derived(
            &spool,
            source.clone(),
            PATH,
            expected,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        drop((object, source, spool));
        let spool = Spool::open_durable(config.clone()).unwrap();
        assert!(
            lock_unpoisoned(&spool.0.installed)
                .entries
                .get(&expected)
                .unwrap()
                .reconstructible
        );
        let lease = spool.lookup(expected).unwrap();
        assert_eq!(spool.reclaim(expected.size).unwrap(), 0);
        drop(lease);
        spool
            .capture_write(expected, move |connection| {
                connection.execute(
                    "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,?2,1,2592001,0)",
                    params![
                        expected.sha256.to_hex(),
                        crate::catalog::signed(expected.size)?
                    ],
                )?;
                Ok(())
            })
            .unwrap();
        assert!(
            !lock_unpoisoned(&spool.0.installed)
                .entries
                .get(&expected)
                .unwrap()
                .reconstructible
        );
        assert_eq!(spool.reclaim(expected.size).unwrap(), 0);
        drop(spool);
        let spool = Spool::open_durable(config).unwrap();
        assert!(
            !lock_unpoisoned(&spool.0.installed)
                .entries
                .get(&expected)
                .unwrap()
                .reconstructible
        );
        assert_eq!(spool.reclaim(expected.size).unwrap(), 0);
    }
}
