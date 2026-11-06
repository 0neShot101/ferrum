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
            let removed = spool.catalog_cleanup(8 * 1024 * 1024, move |connection| {
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
        spool.catalog_cleanup(2 * 1024 * 1024, move |connection| {
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

pub(crate) fn reclaim_unreferenced_index(spool: &Spool, index_id: &str) -> Result<(), SpoolError> {
    let Some(_slot) = crate::capture::index::try_lock_index(spool, index_id) else {
        return Ok(());
    };
    let check = index_id.to_owned();
    let referenced: bool = spool.durable_catalog()?.read(move |connection| {
        Ok(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_proof_indexes WHERE index_id=?1)",
            [check],
            |row| row.get(0),
        )?)
    })?;
    if referenced {
        return Ok(());
    }
    let invalidated = index_id.to_owned();
    let unreferenced = spool.catalog_cleanup(2 * 1024 * 1024, move |connection| {
        let transaction = connection.transaction()?;
        let referenced: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_proof_indexes WHERE index_id=?1)",
            [&invalidated],
            |row| row.get(0),
        )?;
        if referenced {
            return Ok(false);
        }
        transaction.execute(
            "UPDATE capture_indexes SET verified=0 WHERE id=?1",
            [&invalidated],
        )?;
        transaction.execute(
            "DELETE FROM capture_index_sources WHERE index_id=?1",
            [&invalidated],
        )?;
        transaction.commit()?;
        Ok(true)
    })?;
    if !unreferenced {
        return Ok(());
    }
    loop {
        let batch_id = index_id.to_owned();
        let removed = spool.catalog_cleanup(8 * 1024 * 1024, move |connection| {
            Ok(connection.execute(
                "DELETE FROM capture_index_entries WHERE rowid IN (SELECT rowid FROM capture_index_entries WHERE index_id=?1 AND NOT EXISTS(SELECT 1 FROM capture_proof_indexes m WHERE m.index_id=?1) LIMIT 512)",
                [batch_id],
            )?)
        })?;
        if removed == 0 {
            break;
        }
    }
    let final_id = index_id.to_owned();
    spool.catalog_cleanup(2 * 1024 * 1024, move |connection| {
        let transaction = connection.transaction()?;
        let busy: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_proof_indexes WHERE index_id=?1 UNION SELECT 1 FROM capture_index_entries WHERE index_id=?1)",
            [&final_id],
            |row| row.get(0),
        )?;
        if busy {
            return Ok(());
        }
        transaction.execute(
            "DELETE FROM capture_index_sources WHERE index_id=?1",
            [&final_id],
        )?;
        transaction.execute("DELETE FROM capture_indexes WHERE id=?1", [&final_id])?;
        transaction.commit()?;
        Ok(())
    })
}

/// Startup and OfflineGc own the spool exclusively. Retired proof-only index
/// links without captured paths or references are detached before sweeping.
fn reconcile_indexes(spool: &Spool) -> Result<(), SpoolError> {
    loop {
        let changed = spool.catalog_cleanup(2 * 1024 * 1024, |connection| {
            Ok(connection.execute(
                "UPDATE capture_proofs SET recovery_retention=public_retired_at+?1 WHERE generation IN (SELECT generation FROM capture_proofs WHERE public_retired_at IS NOT NULL AND recovery_retention=9223372036854775807 LIMIT 128)",
                [crate::capture::GRACE],
            )?)
        })?;
        if changed == 0 {
            break;
        }
    }
    loop {
        let removed = spool.catalog_cleanup(8 * 1024 * 1024, |connection| {
            Ok(connection.execute(
                "DELETE FROM capture_proof_indexes WHERE rowid IN (
                   SELECT m.rowid FROM capture_proof_indexes m
                   JOIN capture_proofs q ON q.generation=m.generation
                   WHERE q.public_retired_at IS NOT NULL
                     AND NOT EXISTS(SELECT 1 FROM public_generations g WHERE g.generation=m.generation)
                     AND NOT EXISTS(SELECT 1 FROM publication_candidates c WHERE c.generation=m.generation)
                     AND NOT EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=m.generation)
                     AND NOT EXISTS(SELECT 1 FROM capture_generation_refs r WHERE r.generation=m.generation)
                   LIMIT 128
                 )",
                [],
            )?)
        })?;
        if removed == 0 {
            break;
        }
    }
    loop {
        let removed = spool.catalog_cleanup(2 * 1024 * 1024, |connection| {
            Ok(connection.execute(
                "DELETE FROM capture_index_generations WHERE rowid IN (
                   SELECT g.rowid FROM capture_index_generations g
                   JOIN capture_proofs q ON q.generation=g.generation
                   WHERE q.public_retired_at IS NOT NULL
                     AND NOT EXISTS(SELECT 1 FROM public_generations p WHERE p.generation=g.generation)
                     AND NOT EXISTS(SELECT 1 FROM publication_candidates c WHERE c.generation=g.generation)
                     AND NOT EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=g.generation)
                     AND NOT EXISTS(SELECT 1 FROM capture_generation_refs r WHERE r.generation=g.generation)
                   LIMIT 128
                 )",
                [],
            )?)
        })?;
        if removed == 0 {
            break;
        }
    }
    let mut after = String::new();
    loop {
        let cursor = after.clone();
        let orphan: Option<String> = spool.durable_catalog()?.read(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT id FROM capture_indexes WHERE id>?1 AND NOT EXISTS(SELECT 1 FROM capture_proof_indexes m WHERE m.index_id=capture_indexes.id) ORDER BY id LIMIT 1",
                    [cursor],
                    |row| row.get(0),
                )
                .optional()?)
        })?;
        let Some(index_id) = orphan else {
            return Ok(());
        };
        after.clone_from(&index_id);
        reclaim_unreferenced_index(spool, &index_id)?;
    }
}
