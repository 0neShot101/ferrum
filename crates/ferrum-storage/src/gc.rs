//! Exclusive stopped-gateway package-prefix maintenance. LIST supplies candidates,
//! never deletion authority; every delete rechecks the reconciled SQLite graph.
mod collected;
pub(crate) mod journal;
use crate::budget::{BudgetLedger, BudgetLimits};
use crate::capture::CaptureError;
use crate::catalog::CatalogError;
use crate::recovery::GenerationManifest;
use crate::s3::{S3Config, S3Store};
use crate::{DurableSpoolConfig, Spool};
pub(crate) use collected::reconcile_collected;
use collected::reconcile_packages;
use ferrum_apt::digest::Sha256Digest;
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub struct OfflineGc {
    spool: Spool,
    store: Arc<S3Store>,
}
#[derive(Default, Clone, Copy, Debug)]
pub struct GcReport {
    pub discovered: u64,
    pub deleted: u64,
    pub retained_or_unknown: u64,
    pub multipart_reaped: u64,
}
impl OfflineGc {
    /// Acquires the same exclusive process lock as the serving gateway before
    /// opening its catalog. There is deliberately no constructor taking a live
    /// gateway Spool or an online DELETE handle.
    pub fn open(
        config: DurableSpoolConfig,
        remote: S3Config,
        limits: BudgetLimits,
    ) -> Result<Self, CaptureError> {
        let spool = Spool::open_durable(config)?;
        let ledger = BudgetLedger::open_for_provider(
            spool.clone(),
            limits,
            &remote.provider_identity(None)?,
        )?;
        let store = Arc::new(S3Store::open(remote, ledger)?);
        let owner = Self { spool, store };
        owner.ensure_open()?;
        Ok(owner)
    }
    pub fn open_qualification(
        config: DurableSpoolConfig,
        remote: S3Config,
        limits: BudgetLimits,
        run_id: &str,
    ) -> Result<Self, CaptureError> {
        let spool = Spool::open_durable(config)?;
        let ledger = BudgetLedger::open_for_provider(
            spool.clone(),
            limits,
            &remote.provider_identity(Some(run_id))?,
        )?;
        let store = Arc::new(S3Store::open_qualification(remote, ledger, run_id)?);
        let owner = Self { spool, store };
        owner.ensure_open()?;
        Ok(owner)
    }
    fn ensure_open(&self) -> Result<(), CaptureError> {
        if !self.store.ledger()?.usage()?.certain {
            return Err(CaptureError::Admission);
        }
        let permitted = self.spool.durable_catalog()?.read(|connection| {
            Ok(connection.query_row(
                "SELECT coverage OR EXISTS(SELECT 1 FROM capture_gc_intents) FROM capture_state WHERE id=1",
                [],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if permitted {
            Ok(())
        } else {
            Err(CaptureError::Admission)
        }
    }
    async fn resume_intents(
        &self,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
        report: &mut GcReport,
    ) -> Result<(), CaptureError> {
        let mut after = String::new();
        loop {
            let cursor = after.clone();
            let keys = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare(
                    "SELECT key FROM capture_gc_intents WHERE key>?1 ORDER BY key LIMIT 64",
                )?;
                let rows = statement.query_map([cursor], |row| row.get::<_, String>(0))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                after = key.clone();
                if self.candidate(&key, now, deadline, cancel)? {
                    self.store
                        .maintenance_delete(&key, deadline, cancel)
                        .await?;
                    self.record_delete(&key, now)?;
                    report.deleted += 1;
                } else {
                    journal::cancel(&self.spool, &key)?;
                    report.retained_or_unknown += 1;
                }
            }
        }
        Ok(())
    }
    fn ensure_certain(&self) -> Result<(), CaptureError> {
        if !self.store.ledger()?.usage()?.certain {
            return Err(CaptureError::Admission);
        }
        let certain = self.spool.durable_catalog()?.read(|connection| {
            Ok(connection.query_row(
                "SELECT coverage FROM capture_state WHERE id=1",
                [],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if certain {
            Ok(())
        } else {
            Err(CaptureError::Admission)
        }
    }
    pub async fn run(
        &mut self,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<GcReport, CaptureError> {
        self.ensure_open()?;
        let mut report = GcReport::default();
        self.resume_intents(now, deadline, cancel, &mut report)
            .await?;
        self.ensure_certain()?;
        let mut continuation = None;
        loop {
            let changed = self.spool.catalog_write(move |connection| {
                Ok(connection.execute(
                    "DELETE FROM capture_generation_refs WHERE rowid IN (SELECT rowid FROM capture_generation_refs WHERE retain_until<=?1 LIMIT 128)",
                    [now],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        reconcile_collected(&self.spool)?;
        loop {
            let page = self
                .store
                .maintenance_list(continuation.clone(), deadline, cancel)
                .await?;
            for key in page.keys {
                report.discovered += 1;
                if !self.candidate(&key, now, deadline, cancel)? {
                    report.retained_or_unknown += 1;
                    continue;
                }
                // Direct graph recheck after discovery, immediately before the
                // conditional HEAD/DELETE. No serving writer can race this owner.
                self.ensure_certain()?;
                if !self.candidate(&key, now, deadline, cancel)? {
                    report.retained_or_unknown += 1;
                    continue;
                }
                journal::prepare(&self.spool, &key, now)?;
                self.store
                    .maintenance_delete(&key, deadline, cancel)
                    .await?;
                self.record_delete(&key, now)?;
                report.deleted += 1;
            }
            let Some(next) = page.continuation else {
                break;
            };
            if continuation.as_ref() == Some(&next) {
                return Err(CaptureError::Proof);
            }
            continuation = Some(next);
        }
        // Catalog-known keys need no LIST appearance. Two bounded passes allow
        // receipts/package removal, then newly unreferenced proof closure.
        for _ in 0..2 {
            let prefix = self.store.package_prefix()?.to_owned();
            let end = format!("{prefix}~");
            let mut after = prefix.clone();
            loop {
                let cursor = after.clone();
                let end = end.clone();
                let keys = self.spool.durable_catalog()?.read(move |connection| {
                    let mut statement = connection.prepare("SELECT key FROM remote_storage WHERE key>?1 AND key<?2 ORDER BY key LIMIT 64")?;
                    let rows = statement.query_map(params![cursor, end], |row| row.get::<_, String>(0))?;
                    Ok(rows.collect::<Result<Vec<_>, _>>()?)
                })?;
                if keys.is_empty() {
                    break;
                }
                for key in keys {
                    after = key.clone();
                    if !key.starts_with(&prefix) {
                        return Err(CaptureError::Proof);
                    }
                    if !self.candidate(&key, now, deadline, cancel)? {
                        continue;
                    }
                    self.ensure_certain()?;
                    if !self.candidate(&key, now, deadline, cancel)? {
                        continue;
                    }
                    journal::prepare(&self.spool, &key, now)?;
                    self.store
                        .maintenance_delete(&key, deadline, cancel)
                        .await?;
                    self.record_delete(&key, now)?;
                    report.deleted += 1;
                }
            }
        }
        reconcile_collected(&self.spool)?;
        report.multipart_reaped = self
            .store
            .maintenance_multipart(now, deadline, cancel)
            .await?;
        Ok(report)
    }
    fn candidate(
        &self,
        key: &str,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<bool, CaptureError> {
        let prefix = self.store.package_prefix()?.to_owned();
        let suffix = key
            .strip_prefix(&prefix)
            .ok_or(CaptureError::Proof)?
            .to_owned();
        let key = key.to_owned();
        let cancel = cancel.clone();
        Ok(self.spool.durable_catalog()?.read(move |connection| {
            let known: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM remote_storage WHERE key=?1)",
                [&key],
                |row| row.get(0),
            )?;
            let uploading: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM multipart_uploads WHERE key=?1)",
                [&key],
                |row| row.get(0),
            )?;
            if uploading {
                return Ok(false);
            }
            if !known {
                return Ok(false);
            }
            let floors = floor_generations(connection)?;
            if let Some(digest) = suffix.strip_prefix("v1/objects/sha256/") {
                if Sha256Digest::from_hex(digest).is_err() {
                    return Ok(false);
                }
                let package: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM capture_blobs WHERE digest=?1)",
                    [digest],
                    |row| row.get(0),
                )?;
                if package {
                    return Ok(package_eligible(connection, digest, now)? && !artifact_referenced(connection, digest, &floors, true)? && all_receipts_gone(connection, digest, &prefix, deadline.into_std(), &cancel)?);
                }
                let live_proof: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM capture_artifacts WHERE digest=?1)",
                    [digest],
                    |row| row.get(0),
                )?;
                if live_proof {
                    return Ok(false);
                }
                let released: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM capture_gc_artifacts WHERE digest=?1)",
                    [digest],
                    |row| row.get(0),
                )?;
                return Ok(released && !artifact_referenced(connection, digest, &floors, false)?);
            }
            if suffix.starts_with("v1/captures/") {
                let parts: Vec<_> = suffix.split('/').collect();
                if let ["v1", "captures", repository, path_hash, file] = parts.as_slice() {
                    let Some(digest) = file.strip_suffix(".json") else {
                        return Ok(false);
                    };
                    let found: bool = connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE repository=?1 AND digest=?2 AND path_hash=?3 AND receipt_verified=1)",
                        params![repository, digest, path_hash],
                        |row| row.get(0),
                    )?;
                    return Ok(found && package_eligible(connection, digest, now)?);
                }
                return Ok(false);
            }
            if suffix.starts_with("v1/generations/") {
                let parts: Vec<_> = suffix.split('/').collect();
                if let [
                    "v1",
                    "generations",
                    repository,
                    suite,
                    generation,
                    "manifest.json",
                ] = parts.as_slice()
                {
                    let generation = crate::recovery::generation_scope(repository, suite, generation).to_hex();
                    let manifest: Option<String> = connection
                        .query_row(
                            "SELECT manifest FROM capture_proofs WHERE generation=?1 AND (durable=1 OR was_public=1) AND public_retired_at IS NOT NULL",
                            [&generation],
                            |row| row.get(0),
                        )
                        .optional()?;
                    let Some(manifest) = manifest else {
                        return Ok(false);
                    };
                    let manifest: GenerationManifest = serde_json::from_str(&manifest).map_err(|_| CatalogError::InvalidState)?;
                    if manifest.suffix() != suffix {
                        return Ok(false);
                    }
                    let referenced: bool = connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE generation=?1 UNION SELECT 1 FROM generation_pins WHERE generation=?1 UNION SELECT 1 FROM capture_generation_refs WHERE generation=?1)",
                        [&generation],
                        |row| row.get(0),
                    )?;
                    return Ok(!referenced && !floors.contains(&generation));
                }
            }
            // Backups, unknown keys and all checkpoint keys are never collected
            // by package GC. A retention policy is not inferred from LIST age.
            Ok(false)
        })?)
    }
    fn record_delete(&self, key: &str, now: i64) -> Result<(), CaptureError> {
        journal::acknowledge(&self.spool, key, self.store.package_prefix()?, now)
    }
}
fn package_eligible(
    connection: &rusqlite::Connection,
    digest: &str,
    now: i64,
) -> Result<bool, CatalogError> {
    let eligible: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM capture_blobs b WHERE b.digest=?1 AND b.first_capture>0 AND b.retain_until<=?2 AND NOT EXISTS(SELECT 1 FROM capture_paths p WHERE p.digest=b.digest AND (p.referenced=1 OR p.retain_until>?2 OR p.receipt_verified=0)) AND NOT EXISTS(SELECT 1 FROM capture_outbox WHERE digest=b.digest) AND NOT EXISTS(SELECT 1 FROM capture_admissions WHERE digest=b.digest) AND NOT EXISTS(SELECT 1 FROM capture_admission_owners WHERE digest=b.digest) AND NOT EXISTS(SELECT 1 FROM generation_pins WHERE digest=b.digest) AND NOT EXISTS(SELECT 1 FROM capture_generation_refs WHERE digest=b.digest))",
        params![digest, now],
        |row| row.get(0),
    )?;
    Ok(eligible)
}

fn floor_generations(connection: &rusqlite::Connection) -> Result<Vec<String>, CatalogError> {
    let mut statement =
        connection.prepare("SELECT floor,active,pending FROM suite_checkpoints LIMIT 65")?;
    let mut rows = statement.query([])?;
    let mut generations = Vec::with_capacity(crate::checkpoint::MAX_SUITES * 3);
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > crate::checkpoint::MAX_SUITES {
            return Err(CatalogError::InvalidState);
        }
        for column in 0..3 {
            if let Some(value) = row.get::<_, Option<String>>(column)? {
                let intent = crate::checkpoint::PublicationIntent::decode(value.as_bytes())
                    .map_err(|_| CatalogError::InvalidState)?;
                generations.push(
                    crate::recovery::generation_scope(
                        &intent.repository,
                        &intent.suite,
                        &intent.generation_id,
                    )
                    .to_hex(),
                );
            }
        }
    }
    Ok(generations)
}
fn artifact_referenced(
    connection: &rusqlite::Connection,
    digest: &str,
    floors: &[String],
    ignore_self: bool,
) -> Result<bool, CatalogError> {
    let pinned: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM generation_pins WHERE digest=?1)",
        [digest],
        |row| row.get(0),
    )?;
    if pinned {
        return Ok(true);
    }
    let mut statement = connection.prepare("SELECT a.generation,EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=a.generation AND (p.digest<>?1 OR ?2=0)),EXISTS(SELECT 1 FROM capture_generation_refs r WHERE r.generation=a.generation),q.public_retired_at IS NULL FROM capture_artifacts a JOIN capture_proofs q ON q.generation=a.generation WHERE a.digest=?1")?;
    let mut rows = statement.query(params![digest, ignore_self])?;
    while let Some(row) = rows.next()? {
        let generation: String = row.get(0)?;
        if row.get::<_, bool>(1)?
            || row.get::<_, bool>(2)?
            || row.get::<_, bool>(3)?
            || floors.contains(&generation)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn all_receipts_gone(
    connection: &rusqlite::Connection,
    digest: &str,
    prefix: &str,
    deadline: std::time::Instant,
    cancel: &CancellationToken,
) -> Result<bool, CatalogError> {
    let _ = (prefix, deadline, cancel);
    Ok(!connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE digest=?1)",
        [digest],
        |row| row.get::<_, bool>(0),
    )?)
}
#[cfg(test)]
mod tests;
