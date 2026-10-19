use crate::{Spool, capture::CaptureError, catalog::CatalogError};
use rusqlite::params;
/// A GC intent closes new capture admission until its conditional outcome is
/// recorded. Only the stopped gateway's previously reconciled owner creates it.
pub(crate) fn prepare(spool: &Spool, key: &str, now: i64) -> Result<(), CaptureError> {
    let key = key.to_owned();
    spool.catalog_write(move |connection| {
        let transaction = connection.transaction()?;
        let coverage: bool =
            transaction.query_row("SELECT coverage FROM capture_state WHERE id=1", [], |row| {
                row.get(0)
            })?;
        if !coverage {
            return Err(CatalogError::InvalidState);
        }
        transaction.execute(
            "INSERT OR IGNORE INTO capture_gc_intents(key,authorized_at) VALUES(?1,?2)",
            params![key, now],
        )?;
        transaction.execute(
            "UPDATE capture_state SET coverage=0,gc_resume=1 WHERE id=1",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    })?;
    Ok(())
}
fn finish(transaction: &rusqlite::Transaction<'_>, key: &str) -> Result<(), CatalogError> {
    transaction.execute("DELETE FROM capture_gc_intents WHERE key=?1", [key])?;
    transaction.execute(
        "UPDATE capture_state SET coverage=1,gc_resume=0 WHERE id=1 AND gc_resume=1 AND NOT EXISTS(SELECT 1 FROM capture_gc_intents)",
        [],
    )?;
    Ok(())
}
pub(crate) fn cancel(spool: &Spool, key: &str) -> Result<(), CaptureError> {
    let key = key.to_owned();
    spool.catalog_write(move |connection| {
        let transaction = connection.transaction()?;
        finish(&transaction, &key)?;
        transaction.commit()?;
        Ok(())
    })?;
    Ok(())
}
pub(crate) fn acknowledge(
    spool: &Spool,
    key: &str,
    prefix: &str,
    now: i64,
) -> Result<(), CaptureError> {
    let suffix = key
        .strip_prefix(prefix)
        .ok_or(CaptureError::Proof)?
        .to_owned();
    let key = key.to_owned();
    spool.catalog_write_reserved(8 * 1024 * 1024, move |connection| {
        let transaction = connection.transaction()?;
        let intended: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_gc_intents WHERE key=?1)",
            [&key],
            |row| row.get(0),
        )?;
        if !intended {
            return Err(CatalogError::InvalidState);
        }
        if let Some(digest) = suffix.strip_prefix("v1/objects/sha256/") {
            let package: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_blobs WHERE digest=?1)",
                [digest],
                |row| row.get(0),
            )?;
            if package {
                if !super::package_eligible(&transaction, digest, now)? {
                    return Err(CatalogError::InvalidState);
                }
                transaction.execute(
                    "UPDATE capture_blobs SET gc_pending=1,readback_verified=0 WHERE digest=?1",
                    [digest],
                )?;
                transaction.execute(
                    "UPDATE objects SET upload_state=0 WHERE digest=?1",
                    [digest],
                )?;
            }
            transaction.execute("DELETE FROM capture_gc_artifacts WHERE digest=?1", [digest])?;
        } else {
            let parts: Vec<_> = suffix.split('/').collect();
            match parts.as_slice() {
                ["v1", "captures", repository, path_hash, file] => {
                    let digest = file
                        .strip_suffix(".json")
                        .ok_or(CatalogError::InvalidState)?;
                    if !super::package_eligible(&transaction, digest, now)? {
                        return Err(CatalogError::InvalidState);
                    }
                    transaction.execute(
                        "DELETE FROM capture_paths WHERE repository=?1 AND path_hash=?2 AND digest=?3",
                        params![repository, path_hash, digest],
                    )?;
                }
                [
                    "v1",
                    "generations",
                    repository,
                    suite,
                    generation,
                    "manifest.json",
                ] => {
                    let generation = crate::recovery::generation_scope(repository, suite, generation).to_hex();
                    let referenced: bool = transaction.query_row(
                        "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE generation=?1 UNION SELECT 1 FROM capture_generation_refs WHERE generation=?1 UNION SELECT 1 FROM generation_pins WHERE generation=?1)",
                        [&generation],
                        |row| row.get(0),
                    )?;
                    if referenced || super::floor_generations(&transaction)?.contains(&generation) {
                        return Err(CatalogError::InvalidState);
                    }
                    transaction.execute(
                        "INSERT OR IGNORE INTO capture_gc_artifacts(digest) SELECT digest FROM capture_artifacts WHERE generation=?1",
                        [&generation],
                    )?;
                    transaction.execute(
                        "DELETE FROM capture_artifacts WHERE generation=?1",
                        [&generation],
                    )?;
                    transaction.execute(
                        "DELETE FROM capture_proofs WHERE generation=?1",
                        [&generation],
                    )?;
                    transaction.execute(
                        "DELETE FROM capture_proof_indexes WHERE generation=?1",
                        [&generation],
                    )?;
                    transaction.execute(
                        "DELETE FROM capture_index_generations WHERE generation=?1",
                        [&generation],
                    )?;
                }
                _ => return Err(CatalogError::InvalidState),
            }
        }
        transaction.execute("DELETE FROM remote_storage WHERE key=?1", [&key])?;
        finish(&transaction, &key)?;
        transaction.commit()?;
        Ok(())
    })?;
    super::reconcile_packages(spool)?;
    Ok(())
}
