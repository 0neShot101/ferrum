use super::{
    CaptureError, CaptureManager, CaptureReceipt, GRACE, VerifiedCaptureProof, put_readback,
};
use crate::budget::BudgetClass;
use crate::s3::{OperationIdentity, S3Error, VerifiedFetch};
use crate::{SpoolError, VerifiedObject};
use ferrum_apt::digest::ObjectIdentity;
use futures_util::StreamExt;
use rusqlite::params;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
#[cfg(test)]
mod tests;

impl CaptureManager {
    pub fn is_durable(&self, identity: ObjectIdentity) -> Result<bool, CaptureError> {
        if !self.coverage_ready()? {
            return Err(CaptureError::Admission);
        }
        Ok(self.spool.capture_is_durable(identity)?)
    }
    /// True when the local catalog records an existing or in-progress remote object
    /// for `identity`, avoiding a pointless S3 GET when coverage is already reconciled
    /// and the package has never been captured.
    pub fn has_remote_candidate(&self, identity: ObjectIdentity) -> Result<bool, CaptureError> {
        let digest = identity.sha256.to_hex();
        let pattern = format!("%/v1/objects/sha256/{digest}");
        Ok(self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_blobs WHERE digest=?1 AND gc_pending=0 UNION SELECT 1 FROM remote_storage WHERE key LIKE ?2 AND committed=1)",
                params![digest, pattern],
                |row| row.get(0),
            )?)
        })?)
    }
    /// Restores an already receipted mapping without reserving or incrementing
    /// the package outbox. The actual GET is hashed by the shared spool commit.
    /// A concurrent new unreceipted path may keep the object non-evictable, but
    /// does not invalidate these fully authenticated local representation bytes.
    pub async fn rehydrate(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<VerifiedObject, CaptureError> {
        if !self.coverage_ready()? {
            return Err(CaptureError::Admission);
        }
        let known = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_blobs b JOIN capture_paths p ON p.digest=b.digest JOIN capture_proofs q ON q.generation=p.generation WHERE b.digest=?1 AND b.size=?2 AND b.gc_pending=0 AND p.receipt_verified=1 AND q.durable=1)",
                params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if !known {
            return Err(CaptureError::Proof);
        }
        if let Some(object) = self.spool.lookup(identity) {
            if !self.is_durable(identity)? {
                self.store
                    .verify_seed(identity, deadline, cancel.clone())
                    .await?;
                self.spool.catalog_write(move |connection| {
                    connection.execute(
                        "UPDATE capture_blobs SET readback_verified=1 WHERE digest=?1",
                        [identity.sha256.to_hex()],
                    )?;
                    Ok(())
                })?;
                let _promoted = self.spool.promote_capture(identity)?;
            }
            return Ok(object);
        }
        let reservation = self.spool.reserve(identity.size)?;
        let response = self.store.get(identity, deadline, cancel.clone()).await?;
        let mut writer = self.spool.begin_write(reservation, identity).await?;
        let mut stream = response.into_stream();
        while let Some(bytes) = stream.next().await {
            if let Err(error) = writer.write(bytes?).await {
                if matches!(
                    error,
                    SpoolError::Mismatch { .. } | SpoolError::Overflow { .. }
                ) {
                    self.store.quarantine(identity)?;
                    return Err(S3Error::Corrupt.into());
                }
                return Err(error.into());
            }
        }
        let object = match writer.commit().await {
            Ok(object) => object,
            Err(error) => {
                if matches!(
                    error,
                    SpoolError::Mismatch { .. } | SpoolError::Overflow { .. }
                ) {
                    self.store.quarantine(identity)?;
                    return Err(S3Error::Corrupt.into());
                }
                return Err(error.into());
            }
        };
        self.spool.catalog_write(move |connection| {
            connection.execute(
                "UPDATE capture_blobs SET readback_verified=1 WHERE digest=?1 AND size=?2",
                params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
            )?;
            Ok(())
        })?;
        let _fully_receipted = self.spool.promote_capture(identity)?;
        Ok(object)
    }
    /// Adds a newly discovered repository/path reference on a verified S3 hit.
    /// Healthy immediate receipt persistence needs no package outbox admission;
    /// a failure grants no new durable mapping. Upstream fallback still requires
    /// reserve() and its persisted bounded outbox/verification escrow.
    pub async fn capture_verified_hit(
        &self,
        proof: &VerifiedCaptureProof,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<CaptureReceipt, CaptureError> {
        self.capture_hit(proof, None, deadline, cancel).await
    }

    /// Consumes evidence from a fresh GET through this exact store. The evidence
    /// replaces only the package readback, never metadata or receipt authority.
    pub async fn capture_fetched_hit(
        &self,
        proof: &VerifiedCaptureProof,
        fetched: VerifiedFetch,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<CaptureReceipt, CaptureError> {
        self.capture_hit(proof, Some(fetched), deadline, cancel)
            .await
    }

    async fn capture_hit(
        &self,
        proof: &VerifiedCaptureProof,
        fetched: Option<VerifiedFetch>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<CaptureReceipt, CaptureError> {
        let has_fetch = fetched.is_some();
        if let Some(fetched) = fetched {
            fetched.consume(&self.store, &self.spool, proof.identity())?;
        }

        if !self.spool.same_owner(&proof.proof.owner) {
            return Err(CaptureError::Proof);
        }
        proof.require_package_authentication()?;
        let _path_slot = self
            .store
            .capture_path_slot(proof.repository(), proof.path().as_str(), deadline, cancel)
            .await?;
        if !self.coverage_ready()? {
            return Err(CaptureError::Admission);
        }
        let identity = proof.identity();
        let now = crate::s3::production_now()?;
        let _object = self.spool.lookup(identity).ok_or(CaptureError::Admission)?;
        let repository = proof.repository().to_owned();
        let path = proof.path().as_str().to_owned();
        let conflict = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_paths p JOIN capture_blobs b ON b.digest=p.digest WHERE repository=?1 AND path=?2 AND (p.digest<>?3 OR b.size<>?4))",
                params![
                    repository,
                    path,
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if conflict {
            return Err(CaptureError::Proof);
        }
        self.store.ledger()?.reserve_storage(
            &self
                .store
                .package_key(&format!("v1/objects/sha256/{}", identity.sha256))?,
            identity.size,
            BudgetClass::Package,
        )?;
        let repository = proof.repository().to_owned();
        let path = proof.path().as_str().to_owned();
        let previous = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT q.raw_generation,p.receipt_verified AND q.durable,b.first_capture FROM capture_paths p JOIN capture_proofs q ON q.generation=p.generation JOIN capture_blobs b ON b.digest=p.digest WHERE p.repository=?1 AND p.path=?2",
                    params![repository, path],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, bool>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?)
        })?;
        if let Some((generation, verified, first)) = previous {
            if verified {
                if !has_fetch {
                    self.store
                        .verify_seed(identity, deadline, cancel.clone())
                        .await?;
                }
                self.spool.catalog_write(move |connection| {
                    connection.execute(
                        "UPDATE capture_blobs SET readback_verified=1 WHERE digest=?1",
                        [identity.sha256.to_hex()],
                    )?;
                    Ok(())
                })?;
            } else {
                self.complete(identity, deadline, cancel).await?;
            }
            let expected = CaptureReceipt {
                schema_version: 1,
                repository: proof.repository().to_owned(),
                public_package_path: proof.path().as_str().to_owned(),
                size: identity.size,
                sha256: identity.sha256.to_hex(),
                proof_generation_id: generation,
                first_capture_time: first,
                package_signature: proof.package_signature.clone(),
            };
            let actual = super::receipt::read(&self.store, &expected, deadline, cancel).await?;
            let repository = proof.repository().to_owned();
            let path = proof.path().as_str().to_owned();
            self.spool.capture_write(identity, move |connection| {
                let transaction = connection.transaction()?;
                super::bind_retained_mapping(&transaction, &repository, &path, identity, now)?;
                transaction.commit()?;
                Ok(())
            })?;
            let _promoted = self.spool.promote_capture(identity)?;
            return Ok(actual);
        }
        if !has_fetch {
            self.store
                .verify_seed(identity, deadline, cancel.clone())
                .await?;
        }
        let manifest = proof.manifest();
        let _proof_slot = self
            .store
            .capture_proof_slot(&manifest.suffix(), deadline, cancel)
            .await?;
        let generation = manifest.scope_id().to_hex();
        let existing = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT durable FROM capture_proofs WHERE generation=?1",
                    [generation],
                    |row| row.get::<_, bool>(0),
                )
                .optional()?
                .unwrap_or(false))
        })?;
        if !existing {
            for artifact in &manifest.artifacts {
                let object = proof
                    .proof
                    .artifact(&artifact.path)
                    .ok_or(CaptureError::Proof)?;
                self.store
                    .control_put_file(
                        &format!("v1/objects/sha256/{}", artifact.sha256),
                        object.path(),
                        object.identity(),
                        deadline,
                        cancel,
                    )
                    .await?;
            }
            put_readback(
                &self.store,
                &manifest.suffix(),
                &manifest.encode().map_err(|_| CaptureError::Proof)?,
                deadline,
                cancel,
            )
            .await?;
        }
        let first = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT first_capture FROM capture_blobs WHERE digest=?1",
                    [identity.sha256.to_hex()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .filter(|time| *time > 0)
                .unwrap_or(now))
        })?;
        let receipt = CaptureReceipt {
            schema_version: 1,
            repository: proof.repository().to_owned(),
            public_package_path: proof.path().as_str().to_owned(),
            size: identity.size,
            sha256: identity.sha256.to_hex(),
            proof_generation_id: manifest.generation_id.clone(),
            first_capture_time: first,
            package_signature: proof.package_signature.clone(),
        };
        self.persist_package_signature(
            receipt.package_signature.as_ref(),
            &manifest.scope_id().to_hex(),
            deadline,
            cancel,
        )
        .await?;
        let observed = super::receipt::put(&self.store, &receipt, deadline, cancel).await?;
        self.store.account_observed(
            OperationIdentity::Object,
            &format!("v1/objects/sha256/{}", identity.sha256),
            identity.size,
            BudgetClass::Package,
        )?;
        let manifest_text = String::from_utf8(manifest.encode().map_err(|_| CaptureError::Proof)?)
            .map_err(|_| CaptureError::Proof)?;
        let generation = manifest.scope_id().to_hex();
        let manifest = manifest.clone();
        let saved = receipt.clone();
        let retain = now.checked_add(GRACE).ok_or(CaptureError::Admission)?;
        self.spool.capture_write(identity, move |connection| {
            let transaction = connection.transaction()?;
            let size = crate::catalog::signed(saved.size)?;
            if crate::catalog::publication::capture_path_conflicts(
                &transaction,
                &saved.repository,
                &saved.public_package_path,
                identity,
            )? {
                return Err(crate::catalog::CatalogError::InvalidState);
            }
            transaction.execute(
                "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,?2,?3,?4,1) ON CONFLICT(digest) DO UPDATE SET readback_verified=1,retain_until=MAX(retain_until,excluded.retain_until)",
                params![saved.sha256, size, first, retain],
            )?;
            transaction.execute(
                "INSERT INTO capture_proofs(generation,manifest,durable) VALUES(?1,?2,1) ON CONFLICT(generation) DO UPDATE SET durable=1",
                params![generation, manifest_text],
            )?;
            for artifact in manifest.artifacts {
                transaction.execute(
                    "INSERT OR IGNORE INTO capture_artifacts(generation,digest,size) VALUES(?1,?2,?3)",
                    params![
                        generation,
                        artifact.sha256,
                        crate::catalog::signed(artifact.size)?
                    ],
                )?;
            }
            transaction.execute(
                "INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES(?1,?2,?6,?3,?4,1,1,?5) ON CONFLICT(repository,path) DO UPDATE SET receipt_verified=1,referenced=1,retain_until=MAX(retain_until,excluded.retain_until)",
                params![
                    saved.repository,
                    saved.public_package_path,
                    saved.sha256,
                    generation,
                    retain,
                    ferrum_apt::digest::Sha256Digest::of(saved.public_package_path.as_bytes()).to_hex()
                ],
            )?;
            super::bind_retained_mapping(
                &transaction,
                &saved.repository,
                &saved.public_package_path,
                identity,
                now,
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        self.spool.release_generation(super::lifecycle::proof_pin(
            &proof.manifest().scope_id().to_hex(),
        ))?;
        let _fully_receipted = self.spool.promote_capture(identity)?;
        Ok(observed)
    }
}
use rusqlite::OptionalExtension;
