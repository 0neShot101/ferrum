use super::{CaptureError, CaptureManager, CaptureReceipt, GRACE, stage_package_index};
use crate::checkpoint::{
    CHECKPOINT_LIMIT, FloorTrust, MANIFEST_LIMIT, PublicationIntent, SuiteKey,
};
use crate::recovery::{
    GenerationManifest, TrustPolicy, VerifiedHistoricalProof, verify_historical_proof,
};
use crate::s3::{OperationIdentity, S3Error};
use crate::{SpoolError, budget::BudgetClass, catalog::CatalogError, disk::ReservationClass};
use ferrum_apt::{
    digest::{Sha256Digest, Sha256Hasher},
    signature::SignatureVerifier,
};
use futures_util::StreamExt;
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct CaptureTrust {
    pub key: SuiteKey,
    pub policy: TrustPolicy,
    pub floor_trust: FloorTrust,
}
impl CaptureManager {
    /// A complete restartable traversal, not a caller-controlled coverage flag.
    /// Every receipt and immutable manifest is directly read and authenticated;
    /// missing trust/floor/artifacts or an unknown key leaves coverage disabled.
    pub async fn reconcile(
        &self,
        trusts: &[CaptureTrust],
        verifier: &SignatureVerifier,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        let _reconciliation = self.store.reconciliation_slot(deadline, cancel).await?;
        if trusts.is_empty()
            || trusts.len() > crate::checkpoint::MAX_SUITES
            || trusts.iter().enumerate().any(|(index, trust)| {
                trust.floor_trust != FloorTrust::IntactTrusted
                    || trusts[..index]
                        .iter()
                        .any(|previous| previous.key == trust.key)
            })
        {
            return Err(CaptureError::Proof);
        }
        if now < 0 {
            return Err(CaptureError::Admission);
        }
        self.spool.catalog_write(move |connection| {
            connection.execute(
                "INSERT INTO capture_state(id,coverage,recovery_time) VALUES(1,0,?1) ON CONFLICT(id) DO UPDATE SET coverage=0,gc_resume=0,recovery_time=MAX(recovery_time,excluded.recovery_time)",
                [now],
            )?;
            Ok(())
        })?;
        self.spool.reset_capture_verification()?;
        self.reconcile_gc_intents(now, deadline, cancel).await?;
        let suites = self.spool.durable_catalog()?.read(|connection| {
            let mut statement = connection.prepare("SELECT repository,suite FROM suite_checkpoints WHERE floor IS NOT NULL OR active IS NOT NULL OR pending IS NOT NULL LIMIT ?1")?;
            let rows = statement.query_map([crate::checkpoint::MAX_SUITES as i64 + 1], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        if suites.len() > crate::checkpoint::MAX_SUITES
            || suites.iter().any(|(repository, suite)| {
                !trusts
                    .iter()
                    .any(|trust| trust.key.repository() == repository && trust.key.suite() == suite)
            })
        {
            return Err(CaptureError::Proof);
        }
        let mut floors = Vec::with_capacity(trusts.len());
        let mut floor_keys = Vec::with_capacity(trusts.len());
        let mut unbootstrapped = std::collections::HashSet::new();
        for trust in trusts {
            let local = self
                .spool
                .durable_catalog()?
                .checkpoint_state(trust.key.clone())?;
            if local.bootstrap_authorized
                && local.floor.is_none()
                && local.active.is_none()
                && local.pending.is_none()
            {
                match self
                    .store
                    .control_get(
                        OperationIdentity::Checkpoint,
                        &trust.key.suffix(),
                        CHECKPOINT_LIMIT,
                        deadline,
                        cancel,
                    )
                    .await
                {
                    Err(S3Error::NotFound) => {
                        unbootstrapped.insert(trust.key.clone());
                        continue;
                    }
                    Ok(_) => return Err(CaptureError::Proof),
                    Err(error) => return Err(error.into()),
                }
            }
            let read = self
                .store
                .control_get(
                    OperationIdentity::Checkpoint,
                    &trust.key.suffix(),
                    CHECKPOINT_LIMIT,
                    deadline,
                    cancel,
                )
                .await?;
            let intent = PublicationIntent::decode(&read.bytes).map_err(|_| CaptureError::Proof)?;
            if intent.key().map_err(|_| CaptureError::Proof)? != trust.key
                || local.pending.is_some()
                || (local.blocked && !local.recovery_ready)
                || local.floor.as_ref() != Some(&intent)
                || local.active.as_ref() != Some(&intent)
            {
                return Err(CaptureError::Proof);
            }
            self.store.account_observed(
                OperationIdentity::Checkpoint,
                &trust.key.suffix(),
                read.bytes.len() as u64,
                BudgetClass::Control,
            )?;
            let suffix = format!(
                "v1/generations/{}/{}/{}/manifest.json",
                intent.repository, intent.suite, intent.generation_id
            );
            let key = self.store.package_key(&suffix)?;
            floor_keys.push(key);
            floors.push(intent);
        }
        if floors.is_empty() {
            return Err(CaptureError::Proof);
        }
        {
            let gate = super::index::reconciliation_gate(&self.spool)?;
            let _reset = tokio::select! {
                () = cancel.cancelled() => return Err(CaptureError::Admission),
                reset = tokio::time::timeout_at(
                    deadline,
                    gate.acquire_many_owned(super::index::INDEX_OWNERS),
                ) => reset.map_err(|_| CaptureError::Admission)?.map_err(|_| CaptureError::Admission)?,
            };
            self.reset_reconciliation(now)?;
        }
        loop {
            let changed = self
                .spool
                .catalog_write_reserved(8 * 1024 * 1024, |connection| {
                    Ok(connection.execute(
                        "DELETE FROM capture_inventory WHERE rowid IN (SELECT rowid FROM capture_inventory LIMIT 128)",
                        [],
                    )?)
                })?;
            if changed == 0 {
                break;
            }
        }
        let mut continuation = None;
        loop {
            let page = self
                .store
                .maintenance_list(continuation.clone(), deadline, cancel)
                .await?;
            let prefix = self.store.package_prefix()?.to_owned();
            self.spool
                .catalog_write_reserved(8 * 1024 * 1024, move |connection| {
                    let transaction = connection.transaction()?;
                    for key in page.keys {
                        let suffix = key
                            .strip_prefix(&prefix)
                            .ok_or(CatalogError::InvalidState)?;
                        if !prefix.contains("/_ferrum-b07/") && is_qualification_namespace(suffix) {
                            continue;
                        }
                        let kind = kind(suffix).ok_or(CatalogError::InvalidState)?;
                        transaction.execute(
                            "INSERT OR IGNORE INTO capture_inventory(key,kind) VALUES(?1,?2)",
                            params![key, kind],
                        )?;
                    }
                    transaction.commit()?;
                    Ok(())
                })?;
            let Some(next) = page.continuation else {
                break;
            };
            if continuation.as_ref() == Some(&next) {
                return Err(CaptureError::Proof);
            }
            continuation = Some(next);
        }
        // LIST is discovery only. Existing catalog references and direct current
        // floors are added even when discovery omitted their keys.
        self.add_known_references()?;
        for key in &floor_keys {
            self.inventory(key, 1)?;
        }
        let mut after = String::new();
        loop {
            let rows = self.inventory_page(1, &after)?;
            if rows.is_empty() {
                break;
            }
            for key in rows {
                after = key.clone();
                let prefix = self.store.package_prefix()?;
                let suffix = key.strip_prefix(prefix).ok_or(CaptureError::Proof)?;
                let read = match self
                    .store
                    .control_get(
                        OperationIdentity::Object,
                        suffix,
                        MANIFEST_LIMIT,
                        deadline,
                        cancel,
                    )
                    .await
                {
                    Ok(read) => read,
                    Err(S3Error::NotFound)
                        if self.pending_absence(&key, floor_keys.contains(&key))? =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let manifest: GenerationManifest = serde_json::from_slice(&read.bytes)?;
                if manifest.suffix() != suffix {
                    return Err(CaptureError::Proof);
                }
                let trust = trusts
                    .iter()
                    .find(|trust| {
                        manifest
                            .key()
                            .is_ok_and(|key| key == trust.key && !unbootstrapped.contains(&key))
                    })
                    .ok_or(CaptureError::Proof)?;
                let proof = Arc::new(
                    self.load_proof(&manifest, &trust.policy, verifier, deadline, cancel)
                        .await?,
                );
                if floors.iter().any(|floor| {
                    intent_scope(floor) == manifest.scope_id()
                        && floor.manifest_sha256 != Sha256Digest::of(&read.bytes).to_hex()
                }) {
                    return Err(CaptureError::Proof);
                }
                self.accept_reconciled_proof(proof, read.bytes, now, deadline, cancel)
                    .await?;
            }
        }
        after.clear();
        loop {
            let rows = self.inventory_page(2, &after)?;
            if rows.is_empty() {
                break;
            }
            for key in rows {
                after = key.clone();
                let suffix = key
                    .strip_prefix(self.store.package_prefix()?)
                    .ok_or(CaptureError::Proof)?;
                let read = match self
                    .store
                    .control_get(
                        OperationIdentity::Object,
                        suffix,
                        super::RECEIPT_LIMIT,
                        deadline,
                        cancel,
                    )
                    .await
                {
                    Ok(read) => read,
                    Err(S3Error::NotFound) if self.pending_absence(&key, false)? => continue,
                    Err(error) => return Err(error.into()),
                };
                let receipt: CaptureReceipt = serde_json::from_slice(&read.bytes)?;
                let identity = receipt.validate()?;
                if receipt.suffix() != suffix {
                    return Err(CaptureError::Proof);
                }
                self.ensure_receipt_proof(&receipt, trusts, verifier, now, deadline, cancel)
                    .await?;
                let authenticated = self
                    .authenticate_package_receipt(
                        &receipt, trusts, verifier, deadline, cancel, true,
                    )
                    .await?;
                self.record_indexed_receipt(&receipt, authenticated.as_ref(), now)?;
                self.store.account_observed(
                    OperationIdentity::Object,
                    suffix,
                    read.bytes.len() as u64,
                    BudgetClass::Control,
                )?;
                self.inventory(
                    &self
                        .store
                        .package_key(&format!("v1/objects/sha256/{}", identity.sha256))?,
                    0,
                )?;
            }
        }
        self.authenticate_pending_proofs(trusts, verifier, deadline, cancel)
            .await?;
        self.authenticate_pending_packages(trusts, verifier, deadline, cancel)
            .await?;
        // Rebuild references only for proofs authenticated in this traversal.
        // A crash midway through retirement must not leave an obsolete infinity
        // lease forever; unresolvable/orphan references remain fail-closed.
        loop {
            let changed = self
                .spool
                .catalog_write_reserved(8 * 1024 * 1024, |connection| {
                    Ok(connection.execute(
                        "DELETE FROM capture_generation_refs WHERE rowid IN (SELECT r.rowid FROM capture_generation_refs r JOIN capture_proofs q ON q.generation=r.generation AND q.reconciled=1 LIMIT 128)",
                        [],
                    )?)
                })?;
            if changed == 0 {
                break;
            }
        }
        // Proof presence is not publication history. Keep all uncertain public
        // generations until the publication owner proves RFC retirement. Known
        // retired proof-only generations do not gain a new public7-day lease.
        let mut generation_cursor = String::new();
        loop {
            let cursor = generation_cursor.clone();
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT generation,recovery_retention FROM capture_proofs WHERE reconciled=1 AND generation>?1 ORDER BY generation LIMIT 64")?;
                let rows = statement.query_map([cursor], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if rows.is_empty() {
                break;
            }
            for (generation, retention) in rows {
                generation_cursor = generation.clone();
                let keep = if floors
                    .iter()
                    .any(|floor| intent_scope(floor).to_hex() == generation)
                {
                    i64::MAX
                } else {
                    retention
                };
                self.retain_indexed_references(&generation, None, keep, deadline, cancel)?;
            }
        }
        // Account every discovered owned object, including unreceipted orphans
        // and backups. A name authenticates nothing; only verified proofs grant
        // path mappings. Unknown/unbounded/absent keys prevent finalization.
        for object_kind in [0, 3] {
            after.clear();
            loop {
                let rows = self.inventory_page(object_kind, &after)?;
                if rows.is_empty() {
                    break;
                }
                for key in rows {
                    after = key.clone();
                    let meta = match self.store.observe_owned(&key, deadline, cancel).await {
                        Ok(meta) => meta,
                        Err(S3Error::NotFound) if self.pending_absence(&key, false)? => {
                            if self
                                .store
                                .confirm_absent(
                                    OperationIdentity::OfflineMaintenance,
                                    &key,
                                    deadline,
                                    cancel,
                                )
                                .await?
                            {
                                continue;
                            }
                            return Err(S3Error::Unavailable.into());
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let class = if object_kind == 3 {
                        BudgetClass::Control
                    } else {
                        let digest = key
                            .rsplit('/')
                            .next()
                            .ok_or(CaptureError::Proof)?
                            .to_owned();
                        let proof = self.spool.durable_catalog()?.read(move |connection| {
                            Ok(connection.query_row(
                                "SELECT EXISTS(SELECT 1 FROM capture_artifacts WHERE digest=?1)",
                                [digest],
                                |row| row.get::<_, bool>(0),
                            )?)
                        })?;
                        if proof {
                            BudgetClass::Control
                        } else {
                            BudgetClass::Package
                        }
                    };
                    let suffix = key
                        .strip_prefix(self.store.package_prefix()?)
                        .ok_or(CaptureError::Proof)?;
                    self.store.account_observed(
                        OperationIdentity::Object,
                        suffix,
                        meta.content_length,
                        class,
                    )?;
                }
            }
        }
        if !self.store.ledger()?.usage()?.certain {
            return Err(CaptureError::Admission);
        }
        let retain = now.checked_add(GRACE).ok_or(CaptureError::Admission)?;
        loop {
            let changed = self.spool.catalog_write(move |connection| {
                Ok(connection.execute(
                    "UPDATE capture_blobs SET retain_until=?1 WHERE digest IN (SELECT digest FROM capture_blobs WHERE retain_until<?1 LIMIT 128)",
                    [retain],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        loop {
            let changed = self.spool.catalog_write(move |connection| {
                Ok(connection.execute(
                    "UPDATE capture_paths SET retain_until=?1 WHERE rowid IN (SELECT rowid FROM capture_paths WHERE retain_until<?1 LIMIT 64)",
                    [retain],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        let mut cursor = 0i64;
        loop {
            let after = cursor;
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare(
                    "SELECT rowid FROM capture_paths WHERE rowid>?1 ORDER BY rowid LIMIT 64",
                )?;
                let rows = statement.query_map([after], |row| row.get::<_, i64>(0))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if rows.is_empty() {
                break;
            }
            cursor = *rows.last().ok_or(CaptureError::Proof)?;
            self.spool
                .catalog_write_reserved(8 * 1024 * 1024, move |connection| {
                    let transaction = connection.transaction()?;
                    for row in rows {
                        transaction.execute(
                            "UPDATE capture_paths SET referenced=EXISTS(SELECT 1 FROM capture_generation_refs r WHERE r.digest=capture_paths.digest AND r.retain_until=9223372036854775807),retain_until=MAX(retain_until,COALESCE((SELECT MAX(retain_until) FROM capture_generation_refs r WHERE r.digest=capture_paths.digest AND r.retain_until<9223372036854775807),0)) WHERE rowid=?1",
                            [row],
                        )?;
                    }
                    transaction.commit()?;
                    Ok(())
                })?;
        }
        let invalid = self.spool.durable_catalog()?.read(|connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_paths p JOIN capture_blobs b ON b.digest=p.digest WHERE NOT EXISTS(SELECT 1 FROM capture_proofs q JOIN capture_proof_indexes m ON m.generation=q.generation JOIN capture_indexes i ON i.id=m.index_id AND i.verified=1 JOIN capture_index_entries e ON e.index_id=i.id WHERE q.generation=p.generation AND q.reconciled=1 AND q.repository=p.repository AND e.path=p.path AND e.digest=p.digest AND e.size=b.size))",
                [],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if invalid {
            return Err(CaptureError::Proof);
        }
        let orphaned = self.spool.durable_catalog()?.read(|connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_generation_refs r WHERE NOT EXISTS(SELECT 1 FROM capture_proofs q WHERE q.generation=r.generation))",
                [],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if orphaned {
            return Err(CaptureError::Proof);
        }
        self.spool.catalog_write(|connection| {
            let unresolved: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_gc_intents)",
                [],
                |row| row.get(0),
            )?;
            if unresolved {
                return Err(CatalogError::InvalidState);
            }
            connection.execute(
                "UPDATE capture_state SET coverage=1,gc_resume=0 WHERE id=1",
                [],
            )?;
            Ok(())
        })?;
        Ok(())
    }
    async fn reconcile_gc_intents(
        &self,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
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
                if self
                    .store
                    .confirm_absent(
                        OperationIdentity::OfflineMaintenance,
                        &key,
                        deadline,
                        cancel,
                    )
                    .await?
                {
                    crate::gc::journal::acknowledge(
                        &self.spool,
                        &key,
                        self.store.package_prefix()?,
                        now,
                    )?;
                } else {
                    crate::gc::journal::cancel(&self.spool, &key)?;
                }
            }
        }
        Ok(())
    }
    async fn accept_reconciled_proof(
        &self,
        proof: Arc<VerifiedHistoricalProof>,
        bytes: Vec<u8>,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        let manifest = proof.manifest();
        for index in package_indexes(manifest) {
            stage_package_index(&self.spool, proof.clone(), &index, deadline, cancel).await?;
        }
        let bound = manifest.scope_id().to_hex();
        let retired = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT public_retired_at FROM capture_proofs WHERE generation=?1",
                    [bound],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()?
                .flatten())
        })?;
        let known_retired = retired.filter(|retired| {
            *retired <= now
                && *retired >= proof.release().date.as_secs()
                && proof
                    .release()
                    .valid_until
                    .is_none_or(|until| *retired >= until.as_secs())
        });
        let recovery_retention = match known_retired {
            Some(retired) => retired.checked_add(GRACE).ok_or(CaptureError::Admission)?,
            None => i64::MAX,
        };
        let generation = manifest.scope_id().to_hex();
        let encoded = String::from_utf8(bytes).map_err(|_| CaptureError::Proof)?;
        let size = encoded.len() as u64;
        let artifacts = manifest.artifacts.clone();
        self.spool
            .catalog_write_reserved(8 * 1024 * 1024, move |connection| {
                let transaction = connection.transaction()?;
                transaction.execute(
                    "INSERT INTO capture_proofs(generation,manifest,durable,reconciled,recovery_retention) VALUES(?1,?2,1,1,?3) ON CONFLICT(generation) DO UPDATE SET manifest=excluded.manifest,durable=1,reconciled=1,recovery_retention=MAX(recovery_retention,excluded.recovery_retention)",
                    params![generation, encoded, recovery_retention],
                )?;
                for artifact in artifacts {
                    transaction.execute(
                        "INSERT OR IGNORE INTO capture_artifacts(generation,digest,size) VALUES(?1,?2,?3)",
                        params![
                            generation,
                            artifact.sha256,
                            crate::catalog::signed(artifact.size)?
                        ],
                    )?;
                }
                transaction.commit()?;
                Ok(())
            })?;
        self.store.account_observed(
            OperationIdentity::Object,
            &manifest.suffix(),
            size,
            BudgetClass::Control,
        )?;
        self.spool
            .release_generation(super::lifecycle::proof_pin(&manifest.scope_id().to_hex()))?;
        Ok(())
    }
    async fn ensure_receipt_proof(
        &self,
        receipt: &CaptureReceipt,
        trusts: &[CaptureTrust],
        verifier: &SignatureVerifier,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        let repository = receipt.repository.clone();
        let generation = receipt.proof_generation_id.clone();
        let ready = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_proofs WHERE reconciled=1 AND repository=?1 AND raw_generation=?2)",
                params![repository, generation],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if ready {
            return Ok(());
        }
        // A receipt is a locator only. LIST omission never excuses reading and
        // authenticating its actual configured-suite manifest and signed indexes.
        for trust in trusts
            .iter()
            .filter(|trust| trust.key.repository() == receipt.repository)
        {
            let suffix = format!(
                "v1/generations/{}/{}/{}/manifest.json",
                receipt.repository,
                trust.key.suite(),
                receipt.proof_generation_id
            );
            let read = match self
                .store
                .control_get(
                    OperationIdentity::Object,
                    &suffix,
                    MANIFEST_LIMIT,
                    deadline,
                    cancel,
                )
                .await
            {
                Ok(read) => read,
                Err(S3Error::NotFound) => continue,
                Err(error) => return Err(error.into()),
            };
            let manifest: GenerationManifest = serde_json::from_slice(&read.bytes)?;
            if manifest.suffix() != suffix
                || manifest.key().map_err(|_| CaptureError::Proof)? != trust.key
            {
                return Err(CaptureError::Proof);
            }
            let proof = Arc::new(
                self.load_proof(&manifest, &trust.policy, verifier, deadline, cancel)
                    .await?,
            );
            self.accept_reconciled_proof(proof, read.bytes, now, deadline, cancel)
                .await?;
            return Ok(());
        }
        Err(CaptureError::Proof)
    }
    async fn authenticate_package_receipt(
        &self,
        receipt: &CaptureReceipt,
        trusts: &[CaptureTrust],
        verifier: &SignatureVerifier,
        deadline: Instant,
        cancel: &CancellationToken,
        require_remote: bool,
    ) -> Result<Option<super::VerifiedCaptureProof>, CaptureError> {
        if !ferrum_apt::pacman::is_pacman_package_path(&receipt.public_package_path) {
            return if receipt.package_signature.is_none() {
                Ok(None)
            } else {
                Err(CaptureError::Proof)
            };
        }
        let package_path = receipt
            .public_package_path
            .strip_suffix(".sig")
            .unwrap_or(&receipt.public_package_path)
            .to_owned();
        let repository = receipt.repository.clone();
        let raw_generation = receipt.proof_generation_id.clone();
        let candidate_path = package_path.clone();
        let (encoded, digest, size, index_path) = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT q.manifest,e.digest,e.size,m.path FROM capture_proofs q JOIN capture_proof_indexes m ON m.generation=q.generation JOIN capture_indexes i ON i.id=m.index_id AND i.verified=1 JOIN capture_index_entries e ON e.index_id=i.id WHERE q.reconciled=1 AND q.repository=?1 AND q.raw_generation=?2 AND e.path=?3 ORDER BY q.generation LIMIT 1",
                params![repository,raw_generation,candidate_path],
                |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,crate::catalog::read_unsigned(row,2)?,row.get::<_,String>(3)?)),
            )?)
        })?;
        let manifest: GenerationManifest = serde_json::from_str(&encoded)?;
        let trust = trusts
            .iter()
            .find(|trust| manifest.key().is_ok_and(|key| key == trust.key))
            .filter(|trust| trust.policy.is_pacman())
            .ok_or(CaptureError::Proof)?;
        let historical = Arc::new(
            tokio::time::timeout_at(
                deadline,
                verify_historical_proof(&self.spool, &manifest, &trust.policy, verifier),
            )
            .await
            .map_err(|_| CaptureError::Admission)?
            .map_err(|_| CaptureError::Proof)?,
        );
        let identity = ferrum_apt::digest::ObjectIdentity {
            sha256: Sha256Digest::from_hex(&digest).map_err(|_| CaptureError::Proof)?,
            size,
        };
        let path = ferrum_apt::path::RepositoryPath::parse_decoded(&package_path)
            .map_err(|_| CaptureError::Proof)?;
        let candidate = super::VerifiedCaptureProof::from_index(
            &self.spool,
            historical.clone(),
            &index_path,
            path,
            identity,
            deadline,
            cancel,
        )
        .await?;
        let signature_identity = if let Some(binding) = &receipt.package_signature {
            if binding.package_path() != package_path || binding.package_identity()? != identity {
                return Err(CaptureError::Proof);
            }
            binding.signature_identity()?
        } else if receipt.public_package_path.ends_with(".sig") {
            receipt.validate()?
        } else if let Some(identity) = candidate.candidate_signature_identity()? {
            identity
        } else {
            // Legacy dynamic receipts have no binding field. The sibling is only
            // a bounded locator: its actual bytes must still verify this package.
            let prefix = self.store.package_key(&format!(
                "v1/captures/{}/{}/",
                receipt.repository,
                Sha256Digest::of(format!("{package_path}.sig").as_bytes())
            ))?;
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT key FROM capture_inventory WHERE key>=?1 AND key<?2 AND kind=2 ORDER BY key LIMIT 2")?;
                let rows = statement.query_map(params![prefix,format!("{prefix}~")],|row|row.get::<_,String>(0))?;
                Ok(rows.collect::<Result<Vec<_>,_>>()?)
            })?;
            if rows.len() != 1 {
                return Err(CaptureError::Proof);
            }
            let suffix = rows[0]
                .strip_prefix(self.store.package_prefix()?)
                .ok_or(CaptureError::Proof)?;
            let read = self
                .store
                .control_get(
                    OperationIdentity::Object,
                    suffix,
                    super::RECEIPT_LIMIT,
                    deadline,
                    cancel,
                )
                .await?;
            let sibling: CaptureReceipt = serde_json::from_slice(&read.bytes)?;
            if sibling.repository != receipt.repository
                || sibling.proof_generation_id != receipt.proof_generation_id
                || sibling.public_package_path != format!("{package_path}.sig")
                || sibling.suffix() != suffix
            {
                return Err(CaptureError::Proof);
            }
            sibling.validate()?
        };
        let package = self
            .restore_binding_object(identity, deadline, cancel, require_remote)
            .await?;
        let signature = self
            .restore_binding_object(signature_identity, deadline, cancel, require_remote)
            .await?;
        let verified = candidate
            .authenticate_package(&package, &signature, deadline, cancel)
            .await?;
        if receipt
            .package_signature
            .as_ref()
            .is_some_and(|binding| Some(binding) != verified.package_signature())
        {
            return Err(CaptureError::Proof);
        }
        let path = ferrum_apt::path::RepositoryPath::parse_decoded(&receipt.public_package_path)
            .map_err(|_| CaptureError::Proof)?;
        let authenticated = super::VerifiedCaptureProof {
            proof: historical,
            path,
            identity: receipt.validate()?,
            package_signature: verified.package_signature.clone(),
            package_objects: verified.package_objects.clone(),
            request_authentication: std::sync::OnceLock::new(),
        };
        authenticated.require_package_authentication()?;
        if let Some(binding) = authenticated.package_signature() {
            let signature = binding.signature_identity()?;
            let pin = super::lifecycle::signature_pin(
                &authenticated.manifest().scope_id().to_hex(),
                binding.package_path(),
                signature,
            );
            if require_remote {
                self.spool.release_generation(pin)?;
            } else {
                self.spool.retain_generation(pin, &[signature])?;
            }
        }
        let signature_suffix = format!("v1/objects/sha256/{}", signature_identity.sha256);
        self.inventory(&self.store.package_key(&signature_suffix)?, 0)?;
        self.store.account_observed(
            OperationIdentity::Object,
            &signature_suffix,
            signature_identity.size,
            BudgetClass::Control,
        )?;
        Ok(Some(authenticated))
    }
    async fn authenticate_pending_packages(
        &self,
        trusts: &[CaptureTrust],
        verifier: &SignatureVerifier,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        let mut after_repository = String::new();
        let mut after_path = String::new();
        loop {
            let repository = after_repository.clone();
            let path = after_path.clone();
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare(
                    "SELECT p.repository,p.path,p.digest,b.size,q.raw_generation,b.first_capture,p.generation FROM capture_paths p JOIN capture_blobs b ON b.digest=p.digest JOIN capture_proofs q ON q.generation=p.generation WHERE q.reconciled=1 AND p.receipt_verified=0 AND (p.repository,p.path)>(?1,?2) ORDER BY p.repository,p.path LIMIT 32"
                )?;
                let rows = statement.query_map(params![repository,path], |row| Ok((
                    CaptureReceipt {
                        schema_version: 1, repository: row.get(0)?, public_package_path: row.get(1)?,
                        sha256: row.get(2)?, size: crate::catalog::read_unsigned(row,3)?,
                        proof_generation_id: row.get(4)?, first_capture_time: row.get(5)?,
                        package_signature: None,
                    }, row.get::<_,String>(6)?,
                )))?;
                Ok(rows.collect::<Result<Vec<_>,_>>()?)
            })?;
            if rows.is_empty() {
                return Ok(());
            }
            for (mut receipt, generation) in rows {
                after_repository.clone_from(&receipt.repository);
                after_path.clone_from(&receipt.public_package_path);
                if ferrum_apt::pacman::is_pacman_package_path(&receipt.public_package_path) {
                    receipt.package_signature =
                        self.package_binding(&generation, &receipt.public_package_path)?;
                    self.authenticate_package_receipt(
                        &receipt, trusts, verifier, deadline, cancel, false,
                    )
                    .await?;
                }
            }
        }
    }
    fn inventory(&self, key: &str, kind: i64) -> Result<(), CaptureError> {
        let key = key.to_owned();
        self.spool.catalog_write(move |connection| {
            connection.execute(
                "INSERT OR IGNORE INTO capture_inventory(key,kind) VALUES(?1,?2)",
                params![key, kind],
            )?;
            Ok(())
        })?;
        Ok(())
    }
    fn inventory_page(&self, kind: i64, after: &str) -> Result<Vec<String>, CaptureError> {
        let after = after.to_owned();
        Ok(self.spool.durable_catalog()?.read(move |connection| {
            let mut statement = connection.prepare(
                "SELECT key FROM capture_inventory WHERE kind=?1 AND key>?2 ORDER BY key LIMIT 8",
            )?;
            let rows = statement.query_map(params![kind, after], |row| row.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?)
    }
    fn add_known_references(&self) -> Result<(), CaptureError> {
        let mut cursor = self.store.package_prefix()?.to_owned();
        let end = format!("{cursor}~");
        loop {
            let after = cursor.clone();
            let bound = end.clone();
            let keys = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT key FROM remote_storage WHERE key>?1 AND key<?2 AND (committed=1 OR mutation_intent=1) ORDER BY key LIMIT 64")?;
                let rows = statement.query_map(params![after, bound], |row| row.get::<_, String>(0))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                cursor = key.clone();
                let suffix = key
                    .strip_prefix(self.store.package_prefix()?)
                    .ok_or(CaptureError::Proof)?;
                self.inventory(&key, kind(suffix).ok_or(CaptureError::Proof)?)?;
            }
        }
        let mut after = String::new();
        loop {
            let cursor = after.clone();
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT generation,manifest FROM capture_proofs WHERE generation>?1 AND (durable=1 OR was_public=1 OR EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=capture_proofs.generation AND p.receipt_verified=1)) ORDER BY generation LIMIT 8")?;
                let rows = statement.query_map([cursor], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if rows.is_empty() {
                break;
            }
            for (generation, encoded) in rows {
                after = generation;
                let manifest: GenerationManifest = serde_json::from_str(&encoded)?;
                self.inventory(&self.store.package_key(&manifest.suffix())?, 1)?;
            }
        }
        let mut after_repository = String::new();
        let mut after_path = String::new();
        loop {
            let repository = after_repository.clone();
            let path = after_path.clone();
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT p.repository,p.path,p.digest,b.size,q.raw_generation,b.first_capture FROM capture_paths p JOIN capture_blobs b ON b.digest=p.digest JOIN capture_proofs q ON q.generation=p.generation WHERE (p.repository,p.path)>(?1,?2) AND p.receipt_verified=1 ORDER BY p.repository,p.path LIMIT 64")?;
                let rows = statement.query_map(params![repository, path], |row| {
                    Ok(CaptureReceipt {
                        schema_version: 1,
                        repository: row.get(0)?,
                        public_package_path: row.get(1)?,
                        sha256: row.get(2)?,
                        size: crate::catalog::read_unsigned(row, 3)?,
                        proof_generation_id: row.get(4)?,
                        first_capture_time: row.get(5)?,
                        package_signature: None,
                    })
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if rows.is_empty() {
                break;
            }
            for receipt in rows {
                after_repository = receipt.repository.clone();
                after_path = receipt.public_package_path.clone();
                self.inventory(&self.store.package_key(&receipt.suffix())?, 2)?;
            }
        }
        Ok(())
    }
    /// Only an uncommitted owned mutation may be absent. Its reservation and
    /// pending work stay charged; known receipts/public closures remain mandatory.
    fn pending_absence(&self, key: &str, required_floor: bool) -> Result<bool, CaptureError> {
        if required_floor {
            return Ok(false);
        }
        let prefix = self.store.package_prefix()?;
        if !key.starts_with(prefix) {
            return Err(CaptureError::Proof);
        }
        let prefix_length = prefix.len();
        let key = key.to_owned();
        Ok(self.spool.durable_catalog()?.read(move |connection| {
            let unfinished: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM remote_storage WHERE key=?1 AND committed=0)",
                [&key],
                |row| row.get(0),
            )?;
            if !unfinished {
                return Ok(false);
            }
            let mut parts = key[prefix_length..].split('/');
            let segments: [Option<&str>; 6] = std::array::from_fn(|_| parts.next());
            if parts.next().is_some() {
                return Err(CatalogError::InvalidState);
            }
            let required: bool = match segments {
                [
                    Some("v1"),
                    Some("generations"),
                    Some(repository),
                    Some(suite),
                    Some(raw),
                    Some("manifest.json"),
                ] => {
                    let scope = crate::recovery::generation_scope(repository, suite, raw).to_hex();
                    connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM capture_proofs q WHERE generation=?1 AND (durable=1 OR was_public=1 OR EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=q.generation AND p.receipt_verified=1)))",
                        [scope],
                        |row| row.get(0),
                    )?
                }
                [
                    Some("v1"),
                    Some("captures"),
                    Some(repository),
                    Some(path_hash),
                    Some(file),
                    None,
                ] => {
                    let digest = file
                        .strip_suffix(".json")
                        .ok_or(CatalogError::InvalidState)?;
                    connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE repository=?1 AND path_hash=?2 AND digest=?3 AND receipt_verified=1)",
                        params![repository, path_hash, digest],
                        |row| row.get(0),
                    )?
                }
                [
                    Some("v1"),
                    Some("objects"),
                    Some("sha256"),
                    Some(digest),
                    None,
                    None,
                ] => connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE digest=?1 AND receipt_verified=1 UNION ALL SELECT 1 FROM capture_artifacts a JOIN capture_proofs q ON q.generation=a.generation WHERE a.digest=?1 AND (q.durable=1 OR q.was_public=1 OR EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=q.generation AND p.receipt_verified=1)))",
                    [digest],
                    |row| row.get(0),
                )?,
                [Some("v1"), Some("backups"), Some(_), Some(_), None, None] => false,
                _ => return Err(CatalogError::InvalidState),
            };
            Ok(!required)
        })?)
    }
    async fn authenticate_pending_proofs(
        &self,
        trusts: &[CaptureTrust],
        verifier: &SignatureVerifier,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        let mut after = String::new();
        loop {
            let cursor = after.clone();
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT q.generation,q.manifest FROM capture_proofs q WHERE q.generation>?1 AND q.reconciled=0 AND EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=q.generation AND p.receipt_verified=0 AND (EXISTS(SELECT 1 FROM capture_outbox o WHERE o.digest=p.digest) OR EXISTS(SELECT 1 FROM capture_admissions a WHERE a.digest=p.digest))) ORDER BY q.generation LIMIT 8")?;
                let rows = statement.query_map([cursor], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if rows.is_empty() {
                break;
            }
            for (scope, encoded) in rows {
                after = scope.clone();
                if cancel.is_cancelled() || Instant::now() >= deadline {
                    return Err(CaptureError::Admission);
                }
                let manifest: GenerationManifest = serde_json::from_str(&encoded)?;
                if manifest.scope_id().to_hex() != scope {
                    return Err(CaptureError::Proof);
                }
                let trust = trusts
                    .iter()
                    .find(|trust| manifest.key().is_ok_and(|key| key == trust.key))
                    .ok_or(CaptureError::Proof)?;
                let proof = Arc::new(
                    tokio::time::timeout_at(
                        deadline,
                        verify_historical_proof(&self.spool, &manifest, &trust.policy, verifier),
                    )
                    .await
                    .map_err(|_| CaptureError::Admission)?
                    .map_err(|_| CaptureError::Proof)?,
                );
                for index in package_indexes(&manifest) {
                    stage_package_index(&self.spool, proof.clone(), &index, deadline, cancel)
                        .await?;
                }
                self.spool.catalog_write(move |connection| {
                    connection.execute(
                        "UPDATE capture_proofs SET reconciled=1 WHERE generation=?1",
                        [scope],
                    )?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
    async fn load_proof(
        &self,
        manifest: &GenerationManifest,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<VerifiedHistoricalProof, CaptureError> {
        for descriptor in &manifest.artifacts {
            let identity = descriptor.identity().map_err(|_| CaptureError::Proof)?;
            let suffix = format!("v1/objects/sha256/{}", identity.sha256);
            let key = self.store.package_key(&suffix)?;
            self.inventory(&key, 0)?;
            let bound = key.clone();
            let remote_verified = self.spool.durable_catalog()?.read(move |connection| {
                Ok(connection.query_row(
                    "SELECT verified FROM capture_inventory WHERE key=?1",
                    [bound],
                    |row| row.get::<_, bool>(0),
                )?)
            })?;
            let local = self.spool.lookup(identity);
            if !remote_verified || local.is_none() {
                let reservation = if local.is_none() {
                    Some(
                        self.spool
                            .reserve_class(identity.size, ReservationClass::Metadata)?,
                    )
                } else {
                    None
                };
                let response = self
                    .store
                    .control_get_stream(
                        OperationIdentity::Object,
                        &suffix,
                        identity,
                        deadline,
                        cancel,
                    )
                    .await?;
                let mut stream = response.into_stream();
                if let Some(reservation) = reservation {
                    let mut writer = self.spool.begin_write(reservation, identity).await?;
                    while let Some(bytes) = stream.next().await {
                        if let Err(error) = writer.write(bytes?).await {
                            if matches!(
                                error,
                                SpoolError::Overflow { .. } | SpoolError::Mismatch { .. }
                            ) {
                                self.store.quarantine(identity)?;
                            }
                            return Err(error.into());
                        }
                    }
                    if let Err(error) = writer.commit().await {
                        if matches!(
                            error,
                            SpoolError::Overflow { .. } | SpoolError::Mismatch { .. }
                        ) {
                            self.store.quarantine(identity)?;
                        }
                        return Err(error.into());
                    }
                } else {
                    let mut hash = Sha256Hasher::new();
                    let mut size = 0u64;
                    while let Some(bytes) = stream.next().await {
                        let bytes = bytes?;
                        size = size
                            .checked_add(bytes.len() as u64)
                            .ok_or(CaptureError::Proof)?;
                        hash.update(&bytes);
                    }
                    if size != identity.size || hash.finalize() != identity.sha256 {
                        self.store.quarantine(identity)?;
                        return Err(CaptureError::Proof);
                    }
                }
                self.spool.catalog_write(move |connection| {
                    connection.execute(
                        "UPDATE capture_inventory SET verified=1 WHERE key=?1",
                        [key],
                    )?;
                    Ok(())
                })?;
            }
            self.store.account_observed(
                OperationIdentity::Object,
                &format!("v1/objects/sha256/{}", identity.sha256),
                identity.size,
                BudgetClass::Control,
            )?;
        }
        let proof = tokio::time::timeout_at(
            deadline,
            verify_historical_proof(&self.spool, manifest, policy, verifier),
        )
        .await
        .map_err(|_| CaptureError::Admission)?
        .map_err(|_| CaptureError::Proof)?;
        let keys = manifest
            .artifacts
            .iter()
            .map(|artifact| {
                self.store
                    .package_key(&format!("v1/objects/sha256/{}", artifact.sha256))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.spool
            .catalog_write_reserved(8 * 1024 * 1024, move |connection| {
                let transaction = connection.transaction()?;
                for key in keys {
                    transaction
                        .execute("UPDATE remote_storage SET gc_owned=1 WHERE key=?1", [key])?;
                }
                transaction.commit()?;
                Ok(())
            })?;
        Ok(proof)
    }
    #[cfg(test)]
    pub(crate) async fn retain_metadata_references(
        &self,
        proof: Arc<VerifiedHistoricalProof>,
        index: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        let staged =
            stage_package_index(&self.spool, proof.clone(), index, deadline, cancel).await?;
        let generation = proof.manifest().scope_id().to_hex();
        let manifest =
            String::from_utf8(proof.manifest().encode().map_err(|_| CaptureError::Proof)?)
                .map_err(|_| CaptureError::Proof)?;
        let artifacts = proof.manifest().artifacts.clone();
        self.spool
            .catalog_write_reserved(8 * 1024 * 1024, move |connection| {
                let transaction = connection.transaction()?;
                transaction.execute(
                    "INSERT INTO capture_proofs(generation,manifest,durable,was_public) VALUES(?1,?2,0,1) ON CONFLICT(generation) DO UPDATE SET was_public=1",
                    params![generation, manifest],
                )?;
                for artifact in artifacts {
                    transaction.execute(
                        "INSERT OR IGNORE INTO capture_artifacts(generation,digest,size) VALUES(?1,?2,?3)",
                        params![
                            generation,
                            artifact.sha256,
                            crate::catalog::signed(artifact.size)?
                        ],
                    )?;
                }
                transaction.commit()?;
                Ok(())
            })?;
        self.retain_indexed_references(
            &proof.manifest().scope_id().to_hex(),
            Some(staged.id),
            i64::MAX,
            deadline,
            cancel,
        )
    }
    /// Invoke only after the publication owner has retired this generation under
    /// the RFC's 7-day/Valid-Until/two-previous-generation retention rules.
    /// `generation` is GenerationManifest::scope_id(), not the raw RFC SHA.
    #[cfg(test)]
    pub(crate) fn retire_metadata_references(
        &self,
        generation: Sha256Digest,
        now: i64,
    ) -> Result<(), CaptureError> {
        let retain = now.checked_add(GRACE).ok_or(CaptureError::Admission)?;
        self.spool.catalog_write(move |connection| {
            connection.execute(
                "UPDATE capture_proofs SET public_retired_at=?1,recovery_retention=?2 WHERE generation=?3",
                params![now, retain, generation.to_hex()],
            )?;
            Ok(())
        })?;
        loop {
            let count = self.spool.catalog_write(move |connection| {
                let transaction = connection.transaction()?;
                let values = {
                    let mut statement = transaction.prepare("SELECT digest FROM capture_generation_refs WHERE generation=?1 LIMIT 128")?;
                    let rows = statement.query_map([generation.to_hex()], |row| row.get::<_, String>(0))?;
                    rows.collect::<Result<Vec<_>, _>>()?
                };
                let count = values.len();
                for digest in values {
                    transaction.execute(
                        "UPDATE capture_blobs SET retain_until=MAX(retain_until,?1) WHERE digest=?2",
                        params![retain, digest],
                    )?;
                    transaction.execute(
                        "DELETE FROM capture_generation_refs WHERE generation=?1 AND digest=?2",
                        params![generation.to_hex(), digest],
                    )?;
                }
                transaction.commit()?;
                Ok(count)
            })?;
            if count == 0 {
                break;
            }
        }
        loop {
            let changed = self.spool.catalog_write(move |connection| {
                Ok(connection.execute(
                    "UPDATE capture_paths SET referenced=0,retain_until=MAX(retain_until,?1,COALESCE((SELECT MAX(retain_until) FROM capture_generation_refs r WHERE r.digest=capture_paths.digest AND r.retain_until<9223372036854775807),0)) WHERE rowid IN (SELECT rowid FROM capture_paths WHERE referenced=1 AND NOT EXISTS(SELECT 1 FROM capture_generation_refs r WHERE r.digest=capture_paths.digest AND r.retain_until=9223372036854775807) LIMIT 64)",
                    [retain],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        Ok(())
    }
}
impl CaptureManager {
    fn record_indexed_receipt(
        &self,
        receipt: &CaptureReceipt,
        authenticated: Option<&super::VerifiedCaptureProof>,
        now: i64,
    ) -> Result<(), CaptureError> {
        let identity = receipt.validate()?;
        if ferrum_apt::pacman::is_pacman_package_path(&receipt.public_package_path) {
            let authenticated = authenticated.ok_or(CaptureError::Proof)?;
            authenticated.require_package_authentication()?;
            if authenticated.identity() != identity
                || authenticated.path().as_str() != receipt.public_package_path
                || authenticated.repository() != receipt.repository
                || authenticated.manifest().generation_id != receipt.proof_generation_id
                || receipt.package_signature.as_ref().is_some_and(|binding| {
                    Some(binding) != authenticated.package_signature.as_ref()
                })
            {
                return Err(CaptureError::Proof);
            }
        } else if receipt.package_signature.is_some() {
            return Err(CaptureError::Proof);
        }
        let saved = receipt.clone();
        let remote_package_verified = authenticated.is_some();
        let retain = now.checked_add(GRACE).ok_or(CaptureError::Admission)?;
        let accepted = self.spool.capture_write(identity, move |connection| {
            let transaction = connection.transaction()?;
            let size = crate::catalog::signed(saved.size)?;
            let authenticated: Option<String> = transaction
                .query_row(
                    "SELECT q.generation FROM capture_proofs q JOIN capture_proof_indexes m ON m.generation=q.generation JOIN capture_indexes i ON i.id=m.index_id AND i.verified=1 JOIN capture_index_entries e ON e.index_id=i.id WHERE q.raw_generation=?1 AND q.reconciled=1 AND q.repository=?2 AND e.path=?3 AND e.digest=?4 AND e.size=?5 ORDER BY q.generation LIMIT 1",
                    params![
                        saved.proof_generation_id,
                        saved.repository,
                        saved.public_package_path,
                        saved.sha256,
                        size
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(generation) = authenticated else {
                return Ok(false);
            };
            if crate::catalog::publication::capture_path_conflicts(
                &transaction,
                &saved.repository,
                &saved.public_package_path,
                identity,
            )? {
                return Ok(false);
            }
            transaction.execute(
                "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,?2,?3,?4,0) ON CONFLICT(digest) DO UPDATE SET first_capture=CASE WHEN first_capture>0 THEN first_capture ELSE excluded.first_capture END,retain_until=MAX(retain_until,excluded.retain_until)",
                params![saved.sha256, size, now, retain],
            )?;
            transaction.execute(
                "INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES(?1,?2,?6,?3,?4,1,0,?5) ON CONFLICT(repository,path) DO UPDATE SET generation=excluded.generation,receipt_verified=1,retain_until=MAX(retain_until,excluded.retain_until)",
                params![
                    saved.repository,
                    saved.public_package_path,
                    saved.sha256,
                    generation,
                    retain,
                    Sha256Digest::of(saved.public_package_path.as_bytes()).to_hex()
                ],
            )?;
            if remote_package_verified {
                // This receipt's exact package and signature were both read back
                // and cryptographically verified above. Only deletion eligibility
                // is granted here; suite coverage remains closed until traversal ends.
                transaction.execute(
                    "UPDATE capture_blobs SET readback_verified=1 WHERE digest=?1",
                    [identity.sha256.to_hex()],
                )?;
                transaction.execute(
                    "INSERT OR IGNORE INTO derived_residency(digest) SELECT digest FROM objects WHERE digest=?1",
                    [identity.sha256.to_hex()],
                )?;
            } else {
                transaction.execute(
                    "DELETE FROM derived_residency WHERE digest=?1",
                    [identity.sha256.to_hex()],
                )?;
            }
            transaction.commit()?;
            Ok(true)
        })?;
        if accepted {
            Ok(())
        } else {
            Err(CaptureError::Proof)
        }
    }
    fn retain_indexed_references(
        &self,
        generation: &str,
        index: Option<String>,
        retain: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        let mut after = String::new();
        loop {
            if cancel.is_cancelled() || Instant::now() >= deadline {
                return Err(CaptureError::Admission);
            }
            let queried = generation.to_owned();
            let selected = index.clone();
            let cursor = after.clone();
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT DISTINCT b.digest FROM capture_blobs b JOIN capture_index_entries e ON e.digest=b.digest AND e.size=b.size JOIN capture_proof_indexes m ON m.index_id=e.index_id JOIN capture_indexes i ON i.id=e.index_id AND i.verified=1 WHERE m.generation=?1 AND (?2 IS NULL OR e.index_id=?2) AND b.digest>?3 ORDER BY b.digest LIMIT 128")?;
                let rows = statement.query_map(params![queried, selected, cursor], |row| {
                    row.get::<_, String>(0)
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if rows.is_empty() {
                break;
            }
            after = rows.last().ok_or(CaptureError::Proof)?.clone();
            let generation = generation.to_owned();
            self.spool.catalog_write(move |connection| {
                let transaction = connection.transaction()?;
                for digest in rows {
                    transaction.execute(
                        "INSERT INTO capture_generation_refs(generation,digest,retain_until) VALUES(?1,?2,?3) ON CONFLICT(generation,digest) DO UPDATE SET retain_until=MAX(retain_until,excluded.retain_until)",
                        params![generation, digest, retain],
                    )?;
                }
                transaction.commit()?;
                Ok(())
            })?;
        }
        Ok(())
    }
}
fn kind(suffix: &str) -> Option<i64> {
    if suffix.starts_with("v1/objects/sha256/") {
        Some(0)
    } else if suffix.starts_with("v1/generations/") && suffix.ends_with("/manifest.json") {
        Some(1)
    } else if suffix.starts_with("v1/captures/") && suffix.ends_with(".json") {
        Some(2)
    } else if suffix.starts_with("v1/backups/") {
        Some(3)
    } else {
        None
    }
}
fn is_qualification_namespace(suffix: &str) -> bool {
    suffix
        .strip_prefix("_ferrum-b07/")
        .and_then(|scoped| scoped.split_once('/'))
        .is_some_and(|(run, tail)| {
            run.len() == 32
                && run
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && kind(tail).is_some()
        })
}
fn package_indexes(manifest: &GenerationManifest) -> Vec<String> {
    manifest
        .artifacts
        .iter()
        .map(|artifact| &artifact.path)
        .chain(manifest.derived.iter().map(|artifact| &artifact.path))
        .filter(|path| super::is_index_path(path))
        .cloned()
        .collect()
}
fn intent_scope(intent: &PublicationIntent) -> Sha256Digest {
    crate::recovery::generation_scope(&intent.repository, &intent.suite, &intent.generation_id)
}

#[cfg(test)]
mod pending_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::{
        capture::{
            VerifiedCaptureProof,
            index::test_support::{Pause, Point},
            tests,
        },
        recovery::test_support,
    };
    use ferrum_apt::{digest::ObjectIdentity, path::RepositoryPath};
    use tokio::time::Duration;

    fn assert_fixture_packages(
        index: &crate::capture::AuthenticatedPackageIndex,
        capture: &VerifiedCaptureProof,
    ) {
        assert_eq!(
            index.lookup(capture.path()).unwrap(),
            Some(capture.identity())
        );
        let path =
            RepositoryPath::parse_decoded("pool/main/f/ferrum-pacer/ferrum-pacer_1.0_all.deb")
                .unwrap();
        assert_eq!(
            index.lookup(&path).unwrap(),
            Some(ObjectIdentity {
                sha256: Sha256Digest::from_hex(
                    "8262f30ecf25c2c27f2f139f62e31e06dde76fe4f3a0a02b8348865969fd1ec7"
                )
                .unwrap(),
                size: 1_050_000,
            })
        );
    }

    #[tokio::test]
    async fn online_gc_acknowledgment_preserves_inflight_authenticated_index() {
        let root = tempfile::tempdir().unwrap();
        let (fixture, capture) = tests::authenticated(&root.path().join("state")).await;
        let (manager, _, requests) = tests::setup(
            fixture.spool.clone(),
            vec![tests::response(
                "GET",
                404,
                b"<Error><Code>NoSuchKey</Code></Error>",
            )],
        );
        let now = crate::s3::production_now().unwrap();
        let key = format!(
            "linux-packages/v1/objects/sha256/{}",
            Sha256Digest::of(b"unrelated interrupted collection")
        );
        crate::gc::journal::prepare(&fixture.spool, &key, now).unwrap();
        manager.begin_reconciliation(now).unwrap();

        let mut pause = Pause::new(&fixture.spool, Point::Flush);
        let spool = fixture.spool.clone();
        let proof = capture.proof.clone();
        let deadline = Instant::now() + Duration::from_secs(60);
        let staging = tokio::spawn(async move {
            stage_package_index(
                &spool,
                proof,
                "main/binary-amd64/Packages",
                deadline,
                &CancellationToken::new(),
            )
            .await
        });
        pause.reached().await;
        let staged = fixture
            .spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT (SELECT COUNT(*) FROM capture_index_entries),(SELECT COUNT(*) FROM capture_indexes),(SELECT COUNT(*) FROM capture_proof_indexes)",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?)
            })
            .unwrap();
        assert_eq!(staged, (2, 1, 0));
        manager
            .reconcile_gc_intents(now, deadline, &CancellationToken::new())
            .await
            .unwrap();
        assert!(matches!(
            manager.begin_reconciliation(now),
            Err(CaptureError::Admission)
        ));
        let retained = fixture
            .spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT (SELECT COUNT(*) FROM capture_index_entries),(SELECT COUNT(*) FROM capture_indexes),(SELECT COUNT(*) FROM capture_gc_intents)",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?)
            })
            .unwrap();
        assert_eq!(retained, (2, 1, 0));
        pause.resume();
        let index = tokio::time::timeout(Duration::from_secs(10), staging)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_fixture_packages(&index, &capture);
        let attestations = fixture
            .spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT COUNT(*) FROM capture_index_sources",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .unwrap();
        assert_eq!(attestations, 1);
        assert_eq!(requests.snapshot().unwrap(), ["GET"]);
    }

    #[tokio::test]
    async fn reconciliation_reset_excludes_staging_until_links_are_invalidated() {
        let root = tempfile::tempdir().unwrap();
        let (fixture, capture) = tests::authenticated(&root.path().join("state")).await;
        let (manager, _, requests) = tests::setup(fixture.spool.clone(), Vec::new());
        let mut pause = Pause::new(&fixture.spool, Point::Reset);
        let reset_manager = manager.clone();
        let now = crate::s3::production_now().unwrap();
        let reset = tokio::task::spawn_blocking(move || reset_manager.begin_reconciliation(now));
        pause.reached().await;

        let spool = fixture.spool.clone();
        let proof = capture.proof.clone();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut staging = tokio::spawn(async move {
            stage_package_index(
                &spool,
                proof,
                "main/binary-amd64/Packages",
                deadline,
                &CancellationToken::new(),
            )
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut staging)
                .await
                .is_err(),
            "generation staging must wait for the complete reset"
        );
        pause.resume();
        reset.await.unwrap().unwrap();
        let index = tokio::time::timeout(Duration::from_secs(10), staging)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_fixture_packages(&index, &capture);
        let reused = stage_package_index(
            &fixture.spool,
            capture.proof.clone(),
            "main/binary-amd64/Packages",
            deadline,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_fixture_packages(&reused, &capture);
        assert!(requests.snapshot().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pending_signed_admission_is_authenticated_without_claiming_remote_durability() {
        let root = tempfile::tempdir().unwrap();
        let fixture = test_support::signed_fixture(&root.path().join("state")).await;
        let deadline = Instant::now() + Duration::from_secs(60);
        let cancel = CancellationToken::new();
        let proof = Arc::new(
            verify_historical_proof(
                &fixture.spool,
                &fixture.manifest,
                &fixture.policy,
                &fixture.verifier,
            )
            .await
            .unwrap(),
        );
        let identity = ObjectIdentity {
            sha256: Sha256Digest::from_hex(
                "bbf3d2c1ae800e53631d807f7818799a9de281f178f408658e392907a2036e62",
            )
            .unwrap(),
            size: 1234,
        };
        let path =
            RepositoryPath::parse_decoded("pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb")
                .unwrap();
        let capture = VerifiedCaptureProof::from_index(
            &fixture.spool,
            proof,
            "main/binary-amd64/Packages",
            path,
            identity,
            deadline,
            &cancel,
        )
        .await
        .unwrap();
        let (manager, ledger, requests) = tests::setup(fixture.spool.clone(), Vec::new());
        let now = crate::s3::production_now().unwrap();
        let reservation = manager.reserve(&capture, now).unwrap();
        let charged = ledger.usage().unwrap().storage;
        manager.begin_reconciliation(now).unwrap();
        manager.add_known_references().unwrap();
        for kind in 0..=3 {
            assert!(manager.inventory_page(kind, "").unwrap().is_empty());
        }
        let trust = CaptureTrust {
            key: fixture.manifest.key().unwrap(),
            policy: fixture.policy.clone(),
            floor_trust: FloorTrust::IntactTrusted,
        };
        manager
            .authenticate_pending_proofs(&[trust], &fixture.verifier, deadline, &cancel)
            .await
            .unwrap();
        let scope = fixture.manifest.scope_id().to_hex();
        let flags = fixture
            .spool
            .durable_catalog()
            .unwrap()
            .read(move |connection| {
                Ok(connection.query_row(
                    "SELECT reconciled,durable,(SELECT receipt_verified FROM capture_paths LIMIT 1) FROM capture_proofs WHERE generation=?1",
                    [scope],
                    |row| {
                        Ok((
                            row.get::<_, bool>(0)?,
                            row.get::<_, bool>(1)?,
                            row.get::<_, bool>(2)?,
                        ))
                    },
                )?)
            })
            .unwrap();
        assert_eq!(flags, (true, false, false));
        assert_eq!(manager.usage().unwrap().entries, 1);
        assert!(!manager.usage().unwrap().coverage);
        assert!(matches!(
            manager.is_durable(identity),
            Err(CaptureError::Admission)
        ));
        assert_eq!(ledger.usage().unwrap().storage, charged);
        assert!(requests.snapshot().unwrap().is_empty());
        let receipt_key = manager
            .store
            .package_key(&format!(
                "v1/captures/{}/{}/{}.json",
                capture.repository(),
                Sha256Digest::of(capture.path().as_str().as_bytes()),
                identity.sha256
            ))
            .unwrap();
        assert!(manager.pending_absence(&receipt_key, false).unwrap());
        let manifest_key = manager
            .store
            .package_key(&fixture.manifest.suffix())
            .unwrap();
        assert!(manager.pending_absence(&manifest_key, false).unwrap());
        assert!(!manager.pending_absence(&manifest_key, true).unwrap());
        fixture
            .spool
            .catalog_write(|connection| {
                connection.execute("UPDATE capture_paths SET receipt_verified=1", [])?;
                Ok(())
            })
            .unwrap();
        assert!(!manager.pending_absence(&receipt_key, false).unwrap());
        assert!(!manager.pending_absence(&manifest_key, false).unwrap());
        drop(reservation);
    }
}
