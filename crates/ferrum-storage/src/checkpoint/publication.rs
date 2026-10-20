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

/// Each insertion has its own validation lineage, even when its proof Arc is reused.
/// Rebinding preserves that lineage so rejection also revokes a concurrent rebind.
pub(crate) struct CachedProof {
    pub(super) proof: Arc<VerifiedHistoricalProof>,
    validation: Arc<tokio::sync::Mutex<()>>,
}

/// Immutable serving selection, separate from retained recovery authority.
pub struct PackageScope {
    suites: Arc<str>,
}

impl PackageScope {
    pub fn new(keys: &[SuiteKey]) -> Result<Self, CheckpointError> {
        if keys.len() > super::MAX_SUITES {
            return Err(CheckpointError::Invalid);
        }

        Ok(Self {
            suites: serde_json::to_string(keys)?.into(),
        })
    }
}

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
    pub async fn authorize(&self) -> Result<VerifiedCaptureProof, CaptureError> {
        self.index
            .authorize_async(self.proof.clone(), self.path.clone())
            .await?
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
        let scope = proof.manifest().scope_id().to_hex();
        let (previous, snapshot) = {
            let mut proofs = self.proofs.lock().map_err(|_| CheckpointError::Proof)?;
            let previous = proofs.insert(
                scope,
                Arc::new(CachedProof {
                    proof,
                    validation: Arc::new(tokio::sync::Mutex::new(())),
                }),
            );
            let snapshot = proofs
                .iter()
                .map(|(scope, entry)| (scope.clone(), entry.clone()))
                .collect::<Vec<_>>();
            (previous, snapshot)
        };
        drop(previous);

        // Snapshot insertion identities before SQL. A concurrent insertion must
        // survive this older live-set observation, including a reused proof Arc.
        let obsolete = self.spool.durable_catalog()?.read(move |connection| {
            let mut statement = connection.prepare_cached(
                "SELECT generation FROM public_generations UNION SELECT generation FROM capture_paths",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            let live = rows.collect::<Result<std::collections::HashSet<_>, _>>()?;
            Ok(snapshot
                .into_iter()
                .filter(|(scope, _)| !live.contains(scope))
                .collect::<Vec<_>>())
        })?;

        for (scope, entry) in obsolete {
            self.remove_cached(&scope, &entry)?;
        }
        Ok(())
    }

    pub(crate) fn remove_cached(
        &self,
        scope: &str,
        entry: &Arc<CachedProof>,
    ) -> Result<(), CheckpointError> {
        let removed = {
            let mut proofs = self.proofs.lock().map_err(|_| CheckpointError::Proof)?;
            if proofs
                .get(scope)
                .is_some_and(|current| Arc::ptr_eq(&current.validation, &entry.validation))
            {
                proofs.remove(scope)
            } else {
                None
            }
        };
        // Proof leases can release object handles; never do that under the cache lock.
        drop(removed);
        Ok(())
    }

    pub(crate) fn rebind_cached(
        &self,
        scope: &str,
        entry: &Arc<CachedProof>,
        proof: Arc<VerifiedHistoricalProof>,
    ) -> Result<(), CheckpointError> {
        let previous = {
            let mut proofs = self.proofs.lock().map_err(|_| CheckpointError::Proof)?;
            let Some(current) = proofs.get_mut(scope) else {
                return Err(CheckpointError::Conflict);
            };
            if !Arc::ptr_eq(&current.validation, &entry.validation) {
                return Err(CheckpointError::Conflict);
            }
            std::mem::replace(
                current,
                Arc::new(CachedProof {
                    proof,
                    validation: entry.validation.clone(),
                }),
            )
        };
        drop(previous);
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
        let entry = self
            .proofs
            .lock()
            .map_err(|_| CheckpointError::Proof)?
            .get(scope)
            .cloned();
        let Some(entry) = entry else {
            return Ok(None);
        };

        // Only revalidation of this insertion is serialized. Requests and other
        // proof scopes never wait on this gate. Refresh the snapshot after waiting
        // so an older success cannot undo a newer policy rejection.
        let _validation = match tokio::time::timeout_at(deadline, entry.validation.lock()).await {
            Ok(guard) => guard,
            Err(_) => {
                self.remove_cached(scope, &entry)?;
                return Err(CheckpointError::Proof);
            }
        };
        let current = self
            .proofs
            .lock()
            .map_err(|_| CheckpointError::Proof)?
            .get(scope)
            .filter(|current| Arc::ptr_eq(&current.validation, &entry.validation))
            .cloned()
            .ok_or(CheckpointError::Conflict)?;

        let proof = &current.proof;
        if !self.spool.same_owner(&proof.owner)
            || !proof.manifest().artifacts.iter().all(|artifact| {
                artifact
                    .identity()
                    .is_ok_and(|identity| self.spool.lookup(identity).is_some())
            })
        {
            self.remove_cached(scope, &current)?;
            return Ok(None);
        }

        if let Err(error) = tokio::time::timeout_at(deadline, proof.revalidate(policy, verifier))
            .await
            .map_err(|_| CheckpointError::Proof)
            .and_then(|result| result)
        {
            self.remove_cached(scope, &current)?;
            return Err(error);
        }

        // The cached content may be reused, but request-time package verification
        // must use the exact policy and verifier that just revalidated it.
        let mut rebound = (**proof).clone();
        rebound.package_authority = policy
            .is_pacman()
            .then(|| (verifier.clone(), policy.keyring().to_path_buf()));
        let proof = Arc::new(rebound);
        self.rebind_cached(scope, &current, proof.clone())?;
        Ok(Some(proof))
    }
    /// Persisted JSON is not a capability. Only proofs authenticated in this
    /// owner process can supply metadata/package request handles.
    pub fn retained_proofs(
        &self,
        key: &SuiteKey,
    ) -> Result<Vec<Arc<VerifiedHistoricalProof>>, CheckpointError> {
        let scopes = self
            .retained_manifests(key)?
            .into_iter()
            .map(|manifest| manifest.scope_id().to_hex())
            .collect::<Vec<_>>();
        let proofs = self.proofs.lock().map_err(|_| CheckpointError::Proof)?;
        scopes
            .iter()
            .map(|scope| {
                proofs
                    .get(scope)
                    .map(|entry| entry.proof.clone())
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
    /// A full reader queue fails immediately. Cancellation drops the response,
    /// not the bounded worker job that already owns the query.
    pub async fn lookup_package(
        &self,
        repository: &str,
        path: &RepositoryPath,
    ) -> Result<Option<PackageDescriptor>, CheckpointError> {
        self.package_lookup(repository, path, None).await
    }

    /// Resolves only configured serving suites, without discarding retained proof state.
    pub async fn lookup_package_in(
        &self,
        repository: &str,
        path: &RepositoryPath,
        scope: &PackageScope,
    ) -> Result<Option<PackageDescriptor>, CheckpointError> {
        self.package_lookup(repository, path, Some(scope.suites.clone()))
            .await
    }

    async fn package_lookup(
        &self,
        repository: &str,
        path: &RepositoryPath,
        suites: Option<Arc<str>>,
    ) -> Result<Option<PackageDescriptor>, CheckpointError> {
        if !crate::capture::is_package_path(path.as_str()) {
            return Ok(None);
        }
        let repository = repository.to_owned();
        let name = path.as_str().to_owned();
        let row = self.spool.durable_catalog()?.read_async(move |connection| {
            Ok(connection
                .prepare_cached(
                    "SELECT e.digest,e.size,m.generation,m.path,m.index_id FROM capture_index_entries e JOIN capture_proof_indexes m ON m.index_id=e.index_id JOIN capture_indexes i ON i.id=e.index_id AND i.verified=1 JOIN capture_proofs q ON q.generation=m.generation WHERE e.path=?2 AND (?3 IS NULL OR EXISTS(SELECT 1 FROM json_each(?3) s WHERE json_extract(s.value,'$.repository')=?1 AND json_extract(s.value,'$.suite')=json_extract(q.manifest,'$.suite'))) AND (EXISTS(SELECT 1 FROM public_generations g WHERE g.generation=m.generation AND g.repository=?1) OR EXISTS(SELECT 1 FROM capture_paths p WHERE p.repository=?1 AND p.path=?2 AND p.generation=m.generation AND p.digest=e.digest AND p.receipt_verified=1 AND q.reconciled=1)) ORDER BY m.generation,m.path LIMIT 1",
                )?
                .query_row(params![repository, name, suites.as_deref()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .optional()?)
        }).await?;
        let Some((digest, size, scope, index_path, id)) = row else {
            return Ok(None);
        };
        let proof = self
            .proofs
            .lock()
            .map_err(|_| CheckpointError::Proof)?
            .get(&scope)
            .map(|entry| entry.proof.clone());
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
