//! Local accounting cleanup only. No provider deletion or LIST authority.
use crate::{Spool, SpoolError, catalog::CatalogError};
use ferrum_apt::digest::Sha256Digest;
use rusqlite::params;
pub(crate) fn unused(spool: &Spool) -> Result<(), SpoolError> {
    let mut after = String::new();
    loop {
        let cursor = after.clone();
        let generations = spool.durable_catalog()?.read(move |connection| {
            let mut statement = connection.prepare("SELECT generation FROM capture_proofs WHERE durable=0 AND generation>?1 AND NOT EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=capture_proofs.generation) ORDER BY generation LIMIT 8")?;
            let rows = statement.query_map([cursor], |row| row.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        if generations.is_empty() {
            break;
        }
        for generation in generations {
            after = generation.clone();
            spool.discard_unused_capture_proof(&generation)?;
        }
    }
    let mut after = String::new();
    loop {
        let cursor = after.clone();
        let keys = spool.durable_catalog()?.read(move |connection| {
            let mut statement = connection.prepare("SELECT key FROM remote_storage WHERE committed=0 AND mutation_intent=0 AND class=1 AND key>?1 ORDER BY key LIMIT 64")?;
            let rows = statement.query_map([cursor], |row| row.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        if keys.is_empty() {
            break;
        }
        after = keys.last().ok_or(CatalogError::InvalidState)?.clone();
        spool.catalog_write_reserved(8 * 1024 * 1024, move |connection| {
            let transaction = connection.transaction()?;
            for key in keys {
                let Some((_, suffix)) = key.split_once("/v1/") else {
                    continue;
                };
                let referenced = if let Some(digest) = suffix.strip_prefix("objects/sha256/") {
                    if Sha256Digest::from_hex(digest).is_err() {
                        continue;
                    }
                    transaction.query_row(
                        "SELECT EXISTS(SELECT 1 FROM generation_pins WHERE digest=?1 UNION SELECT 1 FROM capture_blobs WHERE digest=?1 UNION SELECT 1 FROM capture_artifacts a JOIN capture_paths p ON p.generation=a.generation WHERE a.digest=?1)",
                        [digest],
                        |row| row.get::<_, bool>(0),
                    )?
                } else {
                    let parts: Vec<_> = suffix.split('/').collect();
                    match parts.as_slice() {
                        [
                            "generations",
                            repository,
                            suite,
                            generation,
                            "manifest.json",
                        ] => transaction.query_row(
                            "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE generation=?1 UNION SELECT 1 FROM generation_pins WHERE generation=?1)",
                            [crate::recovery::generation_scope(repository, suite, generation).to_hex()],
                            |row| row.get(0),
                        )?,
                        ["captures", repository, path_hash, file] => {
                            let Some(digest) = file.strip_suffix(".json") else {
                                continue;
                            };
                            transaction.query_row(
                                "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE repository=?1 AND path_hash=?2 AND digest=?3)",
                                params![repository, path_hash, digest],
                                |row| row.get(0),
                            )?
                        }
                        _ => continue,
                    }
                };
                if !referenced {
                    transaction.execute(
                        "DELETE FROM remote_storage WHERE key=?1 AND committed=0 AND mutation_intent=0 AND class=1",
                        [key],
                    )?;
                }
            }
            transaction.commit()?;
            Ok(())
        })?;
    }
    Ok(())
}
