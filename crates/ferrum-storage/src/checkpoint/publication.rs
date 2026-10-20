//! Authenticated runtime handles backed by indexed durable publication authority.
use super::{CheckpointError, CheckpointPublisher, SuiteKey};
use crate::{
    capture::{AuthenticatedPackageIndex, CaptureError, VerifiedCaptureProof},
    catalog::CatalogError,
    recovery::{GenerationManifest, TrustPolicy, VerifiedHistoricalProof},
};
use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest},
    path::RepositoryPath,
    signature::SignatureVerifier,
};
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct PackageDescriptor {
    identity: ObjectIdentity,
    path: RepositoryPath,
    proof: Arc<VerifiedHistoricalProof>,
    index: AuthenticatedPackageIndex,
    index_path: String,
}
impl PackageDescriptor {
    pub fn path(&self) -> &RepositoryPath {
        &self.path
    }
    pub fn proof(&self) -> &Arc<VerifiedHistoricalProof> {
        &self.proof
    }
    pub fn identity(&self) -> ObjectIdentity {
        self.identity
    }
    pub fn generation(&self) -> &GenerationManifest {
        self.proof.manifest()
    }
    pub fn index_path(&self) -> &str {
        &self.index_path
    }
    pub fn authorize(&self) -> Result<VerifiedCaptureProof, CaptureError> {
        self.index
            .authorize(self.proof.clone(), self.path.clone())?
            .ok_or(CaptureError::Proof)
    }
}
impl CheckpointPublisher {
    pub fn record_error(
        &self,
        key: &SuiteKey,
        class: &str,
        next_check_at: i64,
    ) -> Result<(), CheckpointError> {
        if class.is_empty()
            || class.len() > 64
            || !class
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'-' | b'_'))
            || next_check_at < 0
        {
            return Err(CheckpointError::Invalid);
        }
        super::catalog_update(&self.spool, |catalog| {
            catalog.publication_schedule(key.clone(), Some(class.to_owned()), next_check_at)
        })
    }
    pub fn set_next_check(
        &self,
        key: &SuiteKey,
        next_check_at: i64,
    ) -> Result<(), CheckpointError> {
        if next_check_at < 0 {
            return Err(CheckpointError::Invalid);
        }
        super::catalog_update(&self.spool, |catalog| {
            catalog.publication_schedule(key.clone(), None, next_check_at)
        })
    }
    pub fn retained_manifests(
        &self,
        key: &SuiteKey,
    ) -> Result<Vec<GenerationManifest>, CheckpointError> {
        Ok(self
            .spool
            .durable_catalog()?
            .publication_manifests(key.clone())?)
    }
    pub(crate) fn cache_proof(
        &self,
        proof: Arc<VerifiedHistoricalProof>,
    ) -> Result<(), CheckpointError> {
        if !self.spool.same_owner(&proof.owner) {
            return Err(CheckpointError::Proof);
        }
        let mut proofs = self.proofs.lock().map_err(|_| CheckpointError::Proof)?;
        proofs.insert(proof.manifest().scope_id().to_hex(), proof);
        // Proof-only captures do not retain public aliases. A stale handle held
        // by a request remains leased, but cannot authorize a new lookup.
        let live = self.spool.durable_catalog()?.read(|connection| {
            let mut statement = connection.prepare("SELECT generation FROM public_generations UNION SELECT generation FROM capture_paths")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            Ok(rows.collect::<Result<std::collections::HashSet<_>, _>>()?)
        })?;
        proofs.retain(|scope, _| live.contains(scope));
        Ok(())
    }
    /// Reuses authenticated content/index work, never a past trust decision.
    /// Rejection removes the proof from new metadata and package lookups.
    pub(crate) async fn revalidate_cached(
        &self,
        scope: &str,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        deadline: Instant,
    ) -> Result<Option<Arc<VerifiedHistoricalProof>>, CheckpointError> {
        let proof = {
            let mut proofs = self.proofs.lock().map_err(|_| CheckpointError::Proof)?;
            let proof = proofs
                .get(scope)
                .filter(|proof| {
                    self.spool.same_owner(&proof.owner)
                        && proof.manifest().artifacts.iter().all(|artifact| {
                            artifact
                                .identity()
                                .is_ok_and(|id| self.spool.lookup(id).is_some())
                        })
                })
                .cloned();
            if proof.is_none() {
                proofs.remove(scope);
            }
            proof
        };
        let Some(proof) = proof else {
            return Ok(None);
        };
        if let Err(error) = tokio::time::timeout_at(deadline, proof.revalidate(policy, verifier))
            .await
            .map_err(|_| CheckpointError::Proof)
            .and_then(|result| result)
        {
            self.proofs
                .lock()
                .map_err(|_| CheckpointError::Proof)?
                .remove(scope);
            return Err(error);
        }
        // The cached content may be reused, but request-time package verification
        // must use the exact policy and verifier that just revalidated it.
        let mut rebound = (*proof).clone();
        rebound.package_authority = policy
            .is_pacman()
            .then(|| (verifier.clone(), policy.keyring().to_path_buf()));
        let proof = Arc::new(rebound);
        self.proofs
            .lock()
            .map_err(|_| CheckpointError::Proof)?
            .insert(scope.to_owned(), proof.clone());
        Ok(Some(proof))
    }
    /// Persisted JSON is not a capability. Only proofs authenticated in this
    /// owner process can supply metadata/package request handles.
    pub fn retained_proofs(
        &self,
        key: &SuiteKey,
    ) -> Result<Vec<Arc<VerifiedHistoricalProof>>, CheckpointError> {
        let manifests = self.retained_manifests(key)?;
        let proofs = self.proofs.lock().map_err(|_| CheckpointError::Proof)?;
        manifests
            .iter()
            .map(|manifest| {
                proofs
                    .get(&manifest.scope_id().to_hex())
                    .cloned()
                    .ok_or(CheckpointError::Proof)
            })
            .collect()
    }
    /// Reauthenticates retained public and captured proof-only authority, including
    /// cached proofs. Old Valid-Until is allowed for immutable proof, never activation.
    pub async fn restore_retained(
        &self,
        key: &SuiteKey,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CheckpointError> {
        let mut after = String::new();
        loop {
            let key = key.clone();
            let cursor = after.clone();
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT q.generation,q.manifest FROM capture_proofs q WHERE q.generation>?1 AND q.repository=?2 AND json_extract(q.manifest,'$.suite')=?3 AND (EXISTS(SELECT 1 FROM public_generations g WHERE g.generation=q.generation) OR EXISTS(SELECT 1 FROM capture_paths p WHERE p.generation=q.generation)) ORDER BY q.generation LIMIT 8")?;
                let rows = statement.query_map(params![cursor, key.repository(), key.suite()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if rows.is_empty() {
                return Ok(());
            }
            for (scope, encoded) in rows {
                after = scope.clone();
                if cancel.is_cancelled() || Instant::now() >= deadline {
                    return Err(CheckpointError::Origin);
                }
                let manifest: GenerationManifest = serde_json::from_str(&encoded)?;
                if manifest.scope_id().to_hex() != scope {
                    return Err(CheckpointError::Proof);
                }
                self.restore_artifacts(&manifest, deadline, cancel).await?;
                if self
                    .revalidate_cached(&scope, policy, verifier, deadline)
                    .await?
                    .is_some()
                {
                    continue;
                }
                let proof = tokio::time::timeout_at(
                    deadline,
                    crate::recovery::verify_historical_proof(
                        &self.spool,
                        &manifest,
                        policy,
                        verifier,
                    ),
                )
                .await
                .map_err(|_| CheckpointError::Proof)??;
                self.cache_proof(Arc::new(proof))?;
            }
        }
    }
    /// Repository/path resolution uses the persistent path/index B-trees, never
    /// scans a Packages stream or constructs a repository package HashMap.
    pub fn lookup_package(
        &self,
        repository: &str,
        path: &RepositoryPath,
    ) -> Result<Option<PackageDescriptor>, CheckpointError> {
        if !crate::capture::is_package_path(path.as_str()) {
            return Ok(None);
        }
        let repository = repository.to_owned();
        let name = path.as_str().to_owned();
        let row = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT e.digest,e.size,m.generation,m.path,m.index_id FROM capture_index_entries e JOIN capture_proof_indexes m ON m.index_id=e.index_id JOIN capture_indexes i ON i.id=e.index_id AND i.verified=1 WHERE e.path=?2 AND (EXISTS(SELECT 1 FROM public_generations g WHERE g.generation=m.generation AND g.repository=?1) OR EXISTS(SELECT 1 FROM capture_paths p JOIN capture_proofs q ON q.generation=p.generation WHERE p.repository=?1 AND p.path=?2 AND p.generation=m.generation AND p.digest=e.digest AND p.receipt_verified=1 AND q.reconciled=1)) ORDER BY m.generation,m.path LIMIT 1",
                    params![repository, name],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            crate::catalog::read_unsigned(row, 1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    },
                )
                .optional()?)
        })?;
        let Some((digest, size, scope, index_path, id)) = row else {
            return Ok(None);
        };
        let proof = self
            .proofs
            .lock()
            .map_err(|_| CheckpointError::Proof)?
            .get(&scope)
            .cloned();
        let proof = proof.ok_or(CheckpointError::Proof)?;
        let identity = ObjectIdentity {
            sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?,
            size,
        };
        let index = AuthenticatedPackageIndex::bound(
            self.spool.clone(),
            id,
            proof.clone(),
            index_path.clone(),
        )
        .map_err(|_| CheckpointError::Proof)?;
        Ok(Some(PackageDescriptor {
            identity,
            path: path.clone(),
            proof,
            index,
            index_path,
        }))
    }
}
