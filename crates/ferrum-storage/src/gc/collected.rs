//! SQL gc_pending is written only after an acknowledged owned remote deletion.
//! It makes local reference/file cleanup restartable without another DELETE.
use crate::{Spool, SpoolError, catalog::CatalogError};
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use rusqlite::{OptionalExtension, params};
pub(crate) fn reconcile_collected(spool: &Spool) -> Result<(), SpoolError> {
    reconcile_packages(spool)?;
    reconcile_indexes(spool)
}

/// Only acknowledged package deletions are safe to finish while staging is live.
pub(super) fn reconcile_packages(spool: &Spool) -> Result<(), SpoolError> {
    loop {
        let rows = spool.durable_catalog()?.read(|connection| {
            let mut statement = connection.prepare(
                "SELECT digest,size FROM capture_blobs WHERE gc_pending=1 ORDER BY digest LIMIT 1",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    crate::catalog::read_unsigned(row, 1)?,
                ))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        let Some((digest, size)) = rows.into_iter().next() else {
            break;
        };
        loop {
            let digest = digest.clone();
            let removed = spool.catalog_write_reserved(8 * 1024 * 1024, move |connection| {
                Ok(connection.execute(
                    "DELETE FROM capture_paths WHERE rowid IN (SELECT rowid FROM capture_paths WHERE digest=?1 LIMIT 64)",
                    [digest],
                )?)
            })?;
            if removed == 0 {
                break;
            }
        }
        let identity = ObjectIdentity {
            sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?,
            size,
        };
        spool.discard_collected_package(identity)?;
        spool.catalog_write(move |connection| {
            let changed = connection.execute(
                "DELETE FROM capture_blobs WHERE digest=?1 AND gc_pending=1 AND NOT EXISTS(SELECT 1 FROM capture_paths WHERE digest=?1) AND NOT EXISTS(SELECT 1 FROM capture_generation_refs WHERE digest=?1) AND NOT EXISTS(SELECT 1 FROM capture_outbox WHERE digest=?1) AND NOT EXISTS(SELECT 1 FROM capture_admissions WHERE digest=?1)",
                params![digest],
            )?;
            if changed != 1 {
                return Err(CatalogError::InvalidState);
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// Startup and OfflineGc own the spool exclusively. An unreferenced index may
/// otherwise belong to a producer that has not installed its generation link.
fn reconcile_indexes(spool: &Spool) -> Result<(), SpoolError> {
    loop {
        let orphan: Option<String> = spool.durable_catalog()?.read(|connection| {
            Ok(connection
                .query_row(
                    "SELECT id FROM capture_indexes WHERE NOT EXISTS(SELECT 1 FROM capture_proof_indexes m WHERE m.index_id=capture_indexes.id) ORDER BY id LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .optional()?)
        })?;
        let Some(index_id) = orphan else {
            return Ok(());
        };
        loop {
            let index_id = index_id.clone();
            let removed = spool.catalog_write_reserved(8 * 1024 * 1024, move |connection| {
                Ok(connection.execute(
                    "DELETE FROM capture_index_entries WHERE rowid IN (SELECT rowid FROM capture_index_entries WHERE index_id=?1 AND NOT EXISTS(SELECT 1 FROM capture_proof_indexes m WHERE m.index_id=?1) LIMIT 128)",
                    [index_id],
                )?)
            })?;
            if removed == 0 {
                break;
            }
        }
        let index_id_check = index_id.clone();
        let deleted = spool.catalog_write_reserved(8 * 1024 * 1024, move |connection| {
            let transaction = connection.transaction()?;
            let referenced: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_proof_indexes WHERE index_id=?1)",
                [&index_id_check],
                |row| row.get(0),
            )?;
            if referenced {
                return Ok(false);
            }
            transaction.execute(
                "DELETE FROM capture_index_sources WHERE index_id=?1",
                [&index_id_check],
            )?;
            transaction.execute("DELETE FROM capture_indexes WHERE id=?1", [&index_id_check])?;
            transaction.commit()?;
            Ok(true)
        })?;
        if !deleted {
            return Ok(());
        }
    }
}
