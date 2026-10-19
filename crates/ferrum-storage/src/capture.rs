//! Authenticated repository-qualified capture mappings and durable bounded outbox.
//! A receipt is a recovery pointer, never an authentication token.
pub(crate) mod index;
mod proof;
pub use index::{AuthenticatedPackageIndex, stage_package_index};
pub(crate) mod cleanup;
pub(crate) mod lifecycle;
mod receipt;
mod reconcile;
mod rehydrate;
use crate::budget::{BudgetClass, BudgetError};
use crate::catalog::CatalogError;
use crate::recovery::{GenerationManifest, VerifiedHistoricalProof};
use crate::s3::{ControlCondition, OperationIdentity, S3Error, S3Store};
use crate::{Spool, SpoolError};
use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest},
    path::RepositoryPath,
};
pub use lifecycle::CaptureReservation;
pub use proof::parse_proof_packages;
pub use reconcile::CaptureTrust;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) const SCHEMA: &[(&str, &str)] = &[
    (
        "capture_state",
        "CREATE TABLE capture_state (id INTEGER PRIMARY KEY CHECK(id=1), coverage INTEGER NOT NULL CHECK(coverage IN (0,1)), recovery_time INTEGER NOT NULL, gc_resume INTEGER NOT NULL DEFAULT 0 CHECK(gc_resume IN (0,1))) STRICT",
    ),
    (
        "capture_blobs",
        "CREATE TABLE capture_blobs (digest TEXT PRIMARY KEY, size INTEGER NOT NULL CHECK(size>=0), first_capture INTEGER NOT NULL, retain_until INTEGER NOT NULL, readback_verified INTEGER NOT NULL CHECK(readback_verified IN (0,1)), gc_pending INTEGER NOT NULL DEFAULT 0 CHECK(gc_pending IN (0,1)), verify_after INTEGER NOT NULL DEFAULT 0 CHECK(verify_after>=0)) STRICT",
    ),
    (
        "capture_proofs",
        "CREATE TABLE capture_proofs (generation TEXT PRIMARY KEY, manifest TEXT NOT NULL, repository TEXT GENERATED ALWAYS AS (json_extract(manifest,'$.repository')) STORED, raw_generation TEXT GENERATED ALWAYS AS (json_extract(manifest,'$.generation_id')) STORED, durable INTEGER NOT NULL CHECK(durable IN (0,1)), reconciled INTEGER NOT NULL DEFAULT 0 CHECK(reconciled IN (0,1)), recovery_retention INTEGER NOT NULL DEFAULT 0, public_retired_at INTEGER, was_public INTEGER NOT NULL DEFAULT 0 CHECK(was_public IN (0,1))) STRICT",
    ),
    (
        "capture_artifacts",
        "CREATE TABLE capture_artifacts (generation TEXT NOT NULL REFERENCES capture_proofs(generation), digest TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0), PRIMARY KEY(generation,digest)) STRICT",
    ),
    (
        "capture_paths",
        "CREATE TABLE capture_paths (repository TEXT NOT NULL, path TEXT NOT NULL, path_hash TEXT NOT NULL CHECK(length(path_hash)=64), digest TEXT NOT NULL REFERENCES capture_blobs(digest), generation TEXT NOT NULL REFERENCES capture_proofs(generation), receipt_verified INTEGER NOT NULL CHECK(receipt_verified IN (0,1)), referenced INTEGER NOT NULL CHECK(referenced IN (0,1)), retain_until INTEGER NOT NULL, PRIMARY KEY(repository,path)) STRICT",
    ),
    (
        "capture_admissions",
        "CREATE TABLE capture_admissions (digest TEXT PRIMARY KEY REFERENCES capture_blobs(digest), size INTEGER NOT NULL CHECK(size>=0)) STRICT",
    ),
    (
        "capture_outbox",
        "CREATE TABLE capture_outbox (digest TEXT PRIMARY KEY REFERENCES capture_blobs(digest), size INTEGER NOT NULL CHECK(size>=0), queued_at INTEGER NOT NULL, next_attempt INTEGER NOT NULL DEFAULT 0, quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0,1))) STRICT",
    ),
    (
        "capture_admission_owners",
        "CREATE TABLE capture_admission_owners (digest TEXT PRIMARY KEY REFERENCES capture_blobs(digest), owners INTEGER NOT NULL CHECK(owners>0)) STRICT",
    ),
    (
        "capture_inventory",
        "CREATE TABLE capture_inventory (key TEXT PRIMARY KEY, kind INTEGER NOT NULL CHECK(kind IN (0,1,2,3)), verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1))) STRICT",
    ),
    (
        "capture_generation_refs",
        "CREATE TABLE capture_generation_refs (generation TEXT NOT NULL, digest TEXT NOT NULL REFERENCES capture_blobs(digest), retain_until INTEGER NOT NULL DEFAULT 9223372036854775807, PRIMARY KEY(generation,digest)) STRICT",
    ),
    (
        "capture_indexes",
        "CREATE TABLE capture_indexes (id TEXT PRIMARY KEY, verified INTEGER NOT NULL CHECK(verified IN (0,1))) STRICT",
    ),
    (
        "capture_index_entries",
        "CREATE TABLE capture_index_entries (index_id TEXT NOT NULL REFERENCES capture_indexes(id), path TEXT NOT NULL, digest TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0), PRIMARY KEY(index_id,path)) STRICT",
    ),
    (
        "capture_index_sources",
        "CREATE TABLE capture_index_sources (index_id TEXT NOT NULL REFERENCES capture_indexes(id), digest TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0), PRIMARY KEY(index_id,digest)) STRICT",
    ),
    (
        "capture_proof_indexes",
        "CREATE TABLE capture_proof_indexes (generation TEXT NOT NULL, path TEXT NOT NULL, index_id TEXT NOT NULL REFERENCES capture_indexes(id), PRIMARY KEY(generation,path)) STRICT",
    ),
    (
        "capture_index_generations",
        "CREATE TABLE capture_index_generations (generation TEXT NOT NULL, path_set TEXT NOT NULL, verified INTEGER NOT NULL CHECK(verified IN (0,1)), PRIMARY KEY(generation,path_set)) STRICT",
    ),
    (
        "capture_gc_artifacts",
        "CREATE TABLE capture_gc_artifacts (digest TEXT PRIMARY KEY) STRICT",
    ),
    (
        "capture_gc_intents",
        "CREATE TABLE capture_gc_intents (key TEXT PRIMARY KEY, authorized_at INTEGER NOT NULL) STRICT",
    ),
];
pub(crate) const AUX_SCHEMA: &[(&str, &str)] = &[
    (
        "capture_entries_identity",
        "CREATE INDEX capture_entries_identity ON capture_index_entries(digest,size,index_id)",
    ),
    (
        "capture_entries_path",
        "CREATE INDEX capture_entries_path ON capture_index_entries(path,index_id,digest,size)",
    ),
    (
        "capture_proof_index_authority",
        "CREATE INDEX capture_proof_index_authority ON capture_proof_indexes(index_id,generation)",
    ),
    (
        "capture_resident_verification",
        "CREATE INDEX capture_resident_verification ON objects(resident,upload_state,digest)",
    ),
    (
        "capture_paths_receipt",
        "CREATE INDEX capture_paths_receipt ON capture_paths(repository,path_hash,digest)",
    ),
    (
        "capture_paths_digest",
        "CREATE INDEX capture_paths_digest ON capture_paths(digest,receipt_verified)",
    ),
    (
        "capture_paths_generation",
        "CREATE INDEX capture_paths_generation ON capture_paths(generation)",
    ),
    (
        "capture_proof_locator",
        "CREATE INDEX capture_proof_locator ON capture_proofs(repository,raw_generation,reconciled,generation)",
    ),
    (
        "capture_artifacts_digest",
        "CREATE INDEX capture_artifacts_digest ON capture_artifacts(digest)",
    ),
];
const GRACE: i64 = 30 * 24 * 60 * 60;
const OUTBOX_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const OUTBOX_ENTRIES: u64 = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("capture admission unavailable or outbox full")]
    Admission,
    #[error("capture reconciliation has not established coverage")]
    ReconciliationPending,
    #[error("capture signature/index proof invalid or path conflicts")]
    Proof,
    #[error(transparent)]
    Spool(#[from] SpoolError),
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error(transparent)]
    S3(#[from] S3Error),
    #[error(transparent)]
    Budget(#[from] BudgetError),
    #[error("capture serialization: {0}")]
    Json(#[from] serde_json::Error),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaptureReceipt {
    pub schema_version: u32,
    pub repository: String,
    pub public_package_path: String,
    pub size: u64,
    pub sha256: String,
    pub proof_generation_id: String,
    pub first_capture_time: i64,
}
pub fn is_package_path(path: &str) -> bool {
    path.starts_with("pool/")
        || (path.starts_with("dists/") && path.ends_with(".deb"))
        || ferrum_apt::pacman::is_pacman_package_path(path)
        || ferrum_apt::rpm::is_rpm_package_path(path)
}
/// Recognizes supported authenticated binary package indexes.
pub fn is_index_path(path: &str) -> bool {
    path.ends_with("/binary-amd64/Packages")
        || path.ends_with("/binary-arm64/Packages")
        || path.ends_with("/binary-all/Packages")
        || ferrum_apt::pacman::pacman_package_prefix(path).is_some()
        || ferrum_apt::rpm::is_rpm_primary_index_path(path)
}
impl CaptureReceipt {
    pub fn suffix(&self) -> String {
        format!(
            "v1/captures/{}/{}/{}.json",
            self.repository,
            Sha256Digest::of(self.public_package_path.as_bytes()),
            self.sha256
        )
    }
    fn validate(&self) -> Result<ObjectIdentity, CaptureError> {
        if self.schema_version != 1
            || self.repository.is_empty()
            || !self
                .repository
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !is_package_path(&self.public_package_path)
            || self.size > 8 * 1024 * 1024 * 1024
        {
            return Err(CaptureError::Proof);
        }
        RepositoryPath::parse_decoded(&self.public_package_path)
            .map_err(|_| CaptureError::Proof)?;
        let sha256 = Sha256Digest::from_hex(&self.sha256).map_err(|_| CaptureError::Proof)?;
        let generation =
            Sha256Digest::from_hex(&self.proof_generation_id).map_err(|_| CaptureError::Proof)?;
        if sha256.to_hex() != self.sha256 || generation.to_hex() != self.proof_generation_id {
            return Err(CaptureError::Proof);
        }
        Ok(ObjectIdentity {
            sha256,
            size: self.size,
        })
    }
}
/// Private fields enforce the shared signature verifier -> signed index -> exact
/// Filename/Size/SHA256 chain before any path can enter capture authority.
pub struct VerifiedCaptureProof {
    proof: Arc<VerifiedHistoricalProof>,
    path: RepositoryPath,
    identity: ObjectIdentity,
}
impl VerifiedCaptureProof {
    pub async fn from_index(
        spool: &Spool,
        proof: Arc<VerifiedHistoricalProof>,
        index_path: &str,
        path: RepositoryPath,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Self, CaptureError> {
        if !is_package_path(path.as_str()) {
            return Err(CaptureError::Proof);
        }
        let index = stage_package_index(spool, proof.clone(), index_path, deadline, cancel).await?;
        if index.lookup(&path)? != Some(identity) {
            return Err(CaptureError::Proof);
        }
        Ok(Self {
            proof,
            path,
            identity,
        })
    }
    pub fn identity(&self) -> ObjectIdentity {
        self.identity
    }
    pub fn repository(&self) -> &str {
        &self.proof.manifest().repository
    }
    pub fn path(&self) -> &RepositoryPath {
        &self.path
    }
    pub fn manifest(&self) -> &GenerationManifest {
        self.proof.manifest()
    }
}
#[derive(Clone)]
pub struct CaptureManager {
    spool: Spool,
    store: Arc<S3Store>,
}
#[derive(Clone, Copy, Debug)]
pub struct OutboxUsage {
    pub bytes: u64,
    pub entries: u64,
    pub coverage: bool,
}
pub enum FallbackDecision {
    CaptureUpstream,
    Fail(S3Error),
}
impl CaptureManager {
    pub fn new(spool: Spool, store: Arc<S3Store>) -> Result<Self, CaptureError> {
        spool.durable_catalog()?;
        if !spool.same_owner(store.ledger()?.spool()) {
            return Err(CaptureError::Admission);
        }
        Ok(Self { spool, store })
    }
    /// Explicit initialization for a new, empty capture catalog. Recovery instead
    /// starts reconciliation and establishes coverage only after all owned pages.
    pub fn initialize(&self, now: i64) -> Result<(), CaptureError> {
        if now < 0 {
            return Err(CaptureError::Admission);
        }
        self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            let populated: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_state UNION ALL SELECT 1 FROM capture_blobs UNION ALL SELECT 1 FROM capture_paths UNION ALL SELECT 1 FROM capture_admissions UNION ALL SELECT 1 FROM capture_admission_owners UNION ALL SELECT 1 FROM capture_outbox UNION ALL SELECT 1 FROM capture_proofs UNION ALL SELECT 1 FROM capture_artifacts UNION ALL SELECT 1 FROM capture_inventory UNION ALL SELECT 1 FROM capture_generation_refs UNION ALL SELECT 1 FROM capture_gc_artifacts UNION ALL SELECT 1 FROM capture_gc_intents)",
                [],
                |row| row.get(0),
            )?;
            if populated {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "INSERT INTO capture_state(id,coverage,recovery_time) VALUES(1,1,?1)",
                [now],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }
    pub fn usage(&self) -> Result<OutboxUsage, CaptureError> {
        Ok(self.spool.durable_catalog()?.read(|connection| {
            let (bytes, entries): (u64, u64) = connection.query_row(
                "SELECT COALESCE(SUM(size),0),COUNT(*) FROM (SELECT digest,size FROM capture_outbox UNION SELECT digest,size FROM capture_admissions)",
                [],
                |row| {
                    Ok((
                        crate::catalog::read_unsigned(row, 0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                    ))
                },
            )?;
            let coverage = connection.query_row("SELECT coverage FROM capture_state WHERE id=1", [], |row| {
                row.get(0)
            })?;
            Ok(OutboxUsage {
                bytes,
                entries,
                coverage,
            })
        })?)
    }
    /// Reads only the recovery gate, without scanning the capture outbox.
    pub fn coverage_ready(&self) -> Result<bool, CaptureError> {
        Ok(self.spool.durable_catalog()?.read(|connection| {
            Ok(connection.query_row(
                "SELECT coverage FROM capture_state WHERE id=1",
                [],
                |row| row.get(0),
            )?)
        })?)
    }
    /// Must precede the upstream body. Durable rehydration deliberately does not
    /// call this operation and is independent of outbox occupancy.
    pub fn reserve(
        &self,
        proof: &VerifiedCaptureProof,
        now: i64,
    ) -> Result<CaptureReservation, CaptureError> {
        if !self.spool.same_owner(&proof.proof.owner) {
            return Err(CaptureError::Proof);
        }
        if now < 0 {
            return Err(CaptureError::Admission);
        }
        let identity = proof.identity;
        let manifest = proof.manifest();
        let generation = manifest.scope_id().to_hex();
        let encoded = String::from_utf8(manifest.encode().map_err(|_| CaptureError::Proof)?)
            .map_err(|_| CaptureError::Proof)?;
        let repository = proof.repository().to_owned();
        let path = proof.path.as_str().to_owned();
        let retain = now.checked_add(GRACE).ok_or(CaptureError::Admission)?;
        let path_slot = self.store.try_capture_path_slot(&repository, &path)?;
        let usage = self.usage()?;
        let digest = identity.sha256.to_hex();
        let queued = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_admissions WHERE digest=?1 UNION SELECT 1 FROM capture_outbox WHERE digest=?1)",
                [digest],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if !usage.coverage
            || (!queued
                && (usage.entries >= OUTBOX_ENTRIES
                    || usage
                        .bytes
                        .checked_add(identity.size)
                        .is_none_or(|size| size > OUTBOX_BYTES)))
        {
            return Err(CaptureError::Admission);
        }
        let mut reservation = CaptureReservation {
            manager: self.clone(),
            identity,
            _path: path_slot,
            registered: false,
        };
        let key = self
            .store
            .package_key(&format!("v1/objects/sha256/{}", identity.sha256))?;
        self.store.ledger()?.fund_capture(
            &key,
            identity.size.max(64 * 1024).saturating_add(256 * 1024),
        )?;
        self.store
            .ledger()?
            .reserve_storage(&key, identity.size, BudgetClass::Package)?;
        // Closure/control storage is reserved before accepting bytes, not after
        // the package has consumed the remaining commercial allowance.
        for artifact in &manifest.artifacts {
            self.store.ledger()?.reserve_storage(
                &self
                    .store
                    .package_key(&format!("v1/objects/sha256/{}", artifact.sha256))?,
                artifact.size,
                BudgetClass::Control,
            )?;
        }
        self.store.ledger()?.reserve_storage(
            &self.store.package_key(&manifest.suffix())?,
            encoded.len() as u64,
            BudgetClass::Control,
        )?;
        let receipt = CaptureReceipt {
            schema_version: 1,
            repository: repository.clone(),
            public_package_path: path.clone(),
            size: identity.size,
            sha256: identity.sha256.to_hex(),
            proof_generation_id: manifest.generation_id.clone(),
            first_capture_time: now,
        };
        self.store.ledger()?.reserve_storage(
            &self.store.package_key(&receipt.suffix())?,
            serde_json::to_vec(&receipt)?.len() as u64,
            BudgetClass::Control,
        )?;
        let artifacts = manifest.artifacts.clone();
        let admitted = self.spool.capture_write(identity, move |connection| {
            let transaction = connection.transaction()?;
            let coverage: bool = transaction.query_row("SELECT coverage FROM capture_state WHERE id=1", [], |row| {
                row.get(0)
            })?;
            if !coverage {
                return Ok(false);
            }
            if crate::catalog::publication::capture_path_conflicts(&transaction, &repository, &path, identity)? {
                return Err(CatalogError::InvalidState);
            }
            let queued: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_outbox WHERE digest=?1 UNION SELECT 1 FROM capture_admissions WHERE digest=?1)",
                [identity.sha256.to_hex()],
                |row| row.get(0),
            )?;
            let (bytes, entries): (u64, u64) = transaction.query_row(
                "SELECT COALESCE(SUM(size),0),COUNT(*) FROM (SELECT digest,size FROM capture_outbox UNION SELECT digest,size FROM capture_admissions)",
                [],
                |row| {
                    Ok((
                        crate::catalog::read_unsigned(row, 0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                    ))
                },
            )?;
            if !queued
                && (entries >= OUTBOX_ENTRIES
                    || bytes
                        .checked_add(identity.size)
                        .is_none_or(|n| n > OUTBOX_BYTES))
            {
                return Ok(false);
            }
            let size = crate::catalog::signed(identity.size)?;
            transaction.execute(
                "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,?2,0,?3,0) ON CONFLICT(digest) DO UPDATE SET retain_until=MAX(retain_until,excluded.retain_until)",
                params![identity.sha256.to_hex(), size, retain],
            )?;
            transaction.execute(
                "INSERT OR IGNORE INTO capture_proofs(generation,manifest,durable) VALUES(?1,?2,0)",
                params![generation, encoded],
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
            transaction.execute(
                "INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES(?1,?2,?6,?3,?4,0,1,?5) ON CONFLICT(repository,path) DO UPDATE SET receipt_verified=0,referenced=1,retain_until=MAX(retain_until,excluded.retain_until)",
                params![
                    repository,
                    path,
                    identity.sha256.to_hex(),
                    generation,
                    retain,
                    Sha256Digest::of(path.as_bytes()).to_hex()
                ],
            )?;
            transaction.execute(
                "INSERT OR IGNORE INTO capture_admissions(digest,size) VALUES(?1,?2)",
                params![identity.sha256.to_hex(), size],
            )?;
            transaction.execute(
                "UPDATE objects SET upload_state=0,class=0 WHERE digest=?1 AND EXISTS(SELECT 1 FROM capture_paths WHERE digest=?1 AND receipt_verified=0)",
                [identity.sha256.to_hex()],
            )?;
            bind_retained_mapping(&transaction, &repository, &path, identity, now)?;
            transaction.execute(
                "INSERT INTO capture_admission_owners(digest,owners) VALUES(?1,1) ON CONFLICT(digest) DO UPDATE SET owners=owners+1",
                [identity.sha256.to_hex()],
            )?;
            transaction.commit()?;
            Ok(true)
        })?;
        if !admitted {
            return Err(CaptureError::Admission);
        }
        reservation.registered = true;
        // Retain signed proof files locally until their remote closure is verified.
        let proof_id = manifest.scope_id().to_hex();
        let needed = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT durable=0 FROM capture_proofs WHERE generation=?1",
                [proof_id],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if needed {
            let pin = lifecycle::proof_pin(&manifest.scope_id().to_hex());
            for batch in manifest.artifacts.chunks(8) {
                let identities = batch
                    .iter()
                    .map(|artifact| artifact.identity().map_err(|_| CaptureError::Proof))
                    .collect::<Result<Vec<_>, _>>()?;
                self.spool.retain_generation(pin, &identities)?;
            }
            let proof_id = manifest.scope_id().to_hex();
            let completed = self.spool.durable_catalog()?.read(move |connection| {
                Ok(connection.query_row(
                    "SELECT durable FROM capture_proofs WHERE generation=?1",
                    [proof_id],
                    |row| row.get::<_, bool>(0),
                )?)
            })?;
            if completed {
                self.spool.release_generation(pin)?;
            }
        }
        self.spool
            .durable_catalog()?
            .enqueue_installed_capture(identity)?;
        Ok(reservation)
    }
    pub fn fallback(&self, error: S3Error, degraded_outbox: bool) -> FallbackDecision {
        match error {
            S3Error::NotFound => FallbackDecision::CaptureUpstream,
            S3Error::Forbidden if degraded_outbox => FallbackDecision::CaptureUpstream,
            S3Error::Timeout | S3Error::Unavailable | S3Error::Throttled if degraded_outbox => {
                FallbackDecision::CaptureUpstream
            }
            error => FallbackDecision::Fail(error),
        }
    }
    pub fn lookup(
        &self,
        repository: &str,
        path: &RepositoryPath,
    ) -> Result<Option<ObjectIdentity>, CaptureError> {
        if !self.usage()?.coverage {
            return Err(CaptureError::Admission);
        }
        let repository = repository.to_owned();
        let path = path.as_str().to_owned();
        Ok(self.spool.durable_catalog()?.read(move |connection| {
            let row: Option<(String, u64)> = connection
                .query_row(
                    "SELECT p.digest,b.size FROM capture_paths p JOIN capture_blobs b ON b.digest=p.digest WHERE p.repository=?1 AND p.path=?2",
                    params![repository, path],
                    |row| Ok((row.get(0)?, crate::catalog::read_unsigned(row, 1)?)),
                )
                .optional()?;
            row.map(|(digest, size)| {
                Ok(ObjectIdentity {
                    sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?,
                    size,
                })
            })
            .transpose()
        })?)
    }
    /// A verified S3 hit discovered for a new path still needs a read-back receipt.
    pub async fn complete(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        if !self.usage()?.coverage {
            return Err(CaptureError::Admission);
        }
        let key = self
            .store
            .package_key(&format!("v1/objects/sha256/{}", identity.sha256))?;
        self.store.ledger()?.fund_capture(
            &key,
            identity.size.max(64 * 1024).saturating_add(256 * 1024),
        )?;
        let object = self.spool.lookup(identity).ok_or(CaptureError::Admission)?;
        let _pin = self
            .spool
            .pin(identity, crate::disk::PinKind::Upload)?
            .ok_or(CaptureError::Admission)?;
        let _verified = self
            .store
            .put_file_verified(&object, deadline, cancel.clone())
            .await?;
        let digest = identity.sha256.to_hex();
        let recorded = digest.clone();
        self.spool.catalog_write(move |connection| {
            connection.execute(
                "UPDATE capture_blobs SET readback_verified=1 WHERE digest=?1",
                [recorded],
            )?;
            Ok(())
        })?;
        loop {
            let after = digest.clone();
            let rows = self.spool.durable_catalog()?.read(move |connection| {
                let mut statement = connection.prepare("SELECT p.repository,p.path,p.generation,b.first_capture,q.manifest FROM capture_paths p JOIN capture_blobs b ON b.digest=p.digest JOIN capture_proofs q ON q.generation=p.generation WHERE p.digest=?1 AND p.receipt_verified=0 ORDER BY p.repository,p.path LIMIT 32")?;
                let rows = statement.query_map([after], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })?;
            if rows.is_empty() {
                break;
            }
            for (repository, path, generation, first_capture, encoded) in rows {
                let manifest: GenerationManifest = serde_json::from_str(&encoded)?;
                let _proof_slot = self
                    .store
                    .capture_proof_slot(&manifest.suffix(), deadline, cancel)
                    .await?;
                let proof_id = generation.clone();
                let durable = self.spool.durable_catalog()?.read(move |connection| {
                    Ok(connection.query_row(
                        "SELECT durable FROM capture_proofs WHERE generation=?1",
                        [proof_id],
                        |row| row.get::<_, bool>(0),
                    )?)
                })?;
                if !durable {
                    for artifact in &manifest.artifacts {
                        let object = self
                            .spool
                            .lookup(artifact.identity().map_err(|_| CaptureError::Proof)?)
                            .ok_or(CaptureError::Proof)?;
                        let suffix = format!("v1/objects/sha256/{}", artifact.sha256);
                        self.store
                            .control_put_file(
                                &suffix,
                                object.path(),
                                object.identity(),
                                deadline,
                                cancel,
                            )
                            .await?;
                    }
                    let bytes = manifest.encode().map_err(|_| CaptureError::Proof)?;
                    put_readback(&self.store, &manifest.suffix(), &bytes, deadline, cancel).await?;
                }
                let receipt = CaptureReceipt {
                    schema_version: 1,
                    repository: repository.clone(),
                    public_package_path: path.clone(),
                    size: identity.size,
                    sha256: digest.clone(),
                    proof_generation_id: manifest.generation_id.clone(),
                    first_capture_time: first_capture,
                };
                let _observed = receipt::put(&self.store, &receipt, deadline, cancel).await?;
                self.spool.catalog_write(move |connection| {
                    let transaction = connection.transaction()?;
                    transaction.execute(
                        "UPDATE capture_proofs SET durable=1 WHERE generation=?1",
                        [&generation],
                    )?;
                    transaction.execute(
                        "UPDATE capture_paths SET receipt_verified=1 WHERE repository=?1 AND path=?2 AND generation=?3",
                        params![repository, path, generation],
                    )?;
                    transaction.commit()?;
                    Ok(())
                })?;
                self.spool
                    .release_generation(lifecycle::proof_pin(&manifest.scope_id().to_hex()))?;
            }
        }
        if !self.spool.promote_capture(identity)? {
            return Err(CaptureError::Admission);
        }
        self.store.ledger()?.release_capture_credit(&key)?;
        Ok(())
    }
    /// Retire only after every publicly retained generation ceased referencing
    /// this path. The 30-day grace is monotonic and never follows hot eviction.
    pub fn retire_path(
        &self,
        repository: &str,
        path: &RepositoryPath,
        now: i64,
    ) -> Result<(), CaptureError> {
        let repository = repository.to_owned();
        let path = path.as_str().to_owned();
        let retain = now.checked_add(GRACE).ok_or(CaptureError::Admission)?;
        self.spool.catalog_write(move |connection| {
            connection.execute(
                "UPDATE capture_paths SET referenced=0,retain_until=MAX(retain_until,?1) WHERE repository=?2 AND path=?3",
                params![retain, repository, path],
            )?;
            Ok(())
        })?;
        Ok(())
    }
    /// Clears capture authority only when no index producer owns the spool.
    /// A busy producer returns admission failure without partially resetting it.
    pub fn begin_reconciliation(&self, now: i64) -> Result<(), CaptureError> {
        if now < 0 {
            return Err(CaptureError::Admission);
        }
        let _reset = index::reconciliation_gate(&self.spool)?
            .try_acquire_many_owned(index::INDEX_OWNERS)
            .map_err(|_| CaptureError::Admission)?;
        self.reset_reconciliation(now)
    }

    fn reset_reconciliation(&self, now: i64) -> Result<(), CaptureError> {
        self.spool.catalog_write(move |connection| {
            connection.execute(
                "INSERT INTO capture_state(id,coverage,recovery_time) VALUES(1,0,?1) ON CONFLICT(id) DO UPDATE SET coverage=0,gc_resume=0,recovery_time=MAX(recovery_time,excluded.recovery_time)",
                [now],
            )?;
            Ok(())
        })?;
        self.spool.reset_capture_verification()?;
        loop {
            let changed = self.spool.catalog_write(|connection| {
                Ok(connection.execute(
                    "UPDATE capture_index_generations SET verified=0 WHERE rowid IN (SELECT rowid FROM capture_index_generations WHERE verified=1 LIMIT 128)",
                    [],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        #[cfg(test)]
        index::test_support::at(&self.spool, index::test_support::Point::Reset);
        loop {
            let changed = self.spool.catalog_write(|connection| {
                Ok(connection.execute(
                    "DELETE FROM capture_proof_indexes WHERE rowid IN (SELECT rowid FROM capture_proof_indexes LIMIT 128)",
                    [],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        loop {
            let changed = self.spool.catalog_write(|connection| {
                Ok(connection.execute(
                    "UPDATE capture_indexes SET verified=0 WHERE id IN (SELECT id FROM capture_indexes WHERE verified=1 LIMIT 128)",
                    [],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        loop {
            let changed = self.spool.catalog_write(|connection| {
                Ok(connection.execute(
                    "DELETE FROM capture_index_sources WHERE rowid IN (SELECT rowid FROM capture_index_sources LIMIT 128)",
                    [],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        loop {
            let changed = self.spool.catalog_write(|connection| {
                Ok(connection.execute(
                    "UPDATE capture_proofs SET reconciled=0 WHERE generation IN (SELECT generation FROM capture_proofs WHERE reconciled=1 LIMIT 128)",
                    [],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
        Ok(())
    }
    /// Receipt metadata is checked against the already reverified signed index.
    /// Its timestamp is not trusted to shorten retention after a restore.
    pub async fn recover_receipt(
        &self,
        receipt: &CaptureReceipt,
        proof: &VerifiedCaptureProof,
        recovery_time: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        if !self.spool.same_owner(&proof.proof.owner) {
            return Err(CaptureError::Proof);
        }
        let identity = receipt.validate()?;
        if identity != proof.identity
            || receipt.repository != proof.repository()
            || receipt.public_package_path != proof.path.as_str()
            || receipt.proof_generation_id != proof.manifest().generation_id
        {
            return Err(CaptureError::Proof);
        }
        let _path = self
            .store
            .capture_path_slot(
                &receipt.repository,
                &receipt.public_package_path,
                deadline,
                cancel,
            )
            .await?;
        let observed = self
            .store
            .control_get(
                OperationIdentity::Object,
                &receipt.suffix(),
                16 * 1024,
                deadline,
                cancel,
            )
            .await?;
        let size = observed.bytes.len() as u64;
        let observed: CaptureReceipt = serde_json::from_slice(&observed.bytes)?;
        if observed != *receipt {
            return Err(CaptureError::Proof);
        }
        receipt::verify_closure(self, proof, deadline, cancel).await?;
        self.store.ledger()?.reserve_storage(
            &self
                .store
                .package_key(&format!("v1/objects/sha256/{}", identity.sha256))?,
            identity.size,
            BudgetClass::Package,
        )?;
        self.store.account_observed(
            OperationIdentity::Object,
            &receipt.suffix(),
            size,
            BudgetClass::Control,
        )?;
        self.record_recovered_receipt(receipt, proof, recovery_time)
    }
    pub(super) fn record_recovered_receipt(
        &self,
        receipt: &CaptureReceipt,
        proof: &VerifiedCaptureProof,
        recovery_time: i64,
    ) -> Result<(), CaptureError> {
        if !self.spool.same_owner(&proof.proof.owner) {
            return Err(CaptureError::Proof);
        }
        let identity = receipt.validate()?;
        if identity != proof.identity
            || receipt.repository != proof.repository()
            || receipt.public_package_path != proof.path.as_str()
            || receipt.proof_generation_id != proof.manifest().generation_id
        {
            return Err(CaptureError::Proof);
        }
        let receipt = receipt.clone();
        let manifest = proof.manifest().clone();
        let generation = manifest.scope_id().to_hex();
        let encoded = String::from_utf8(manifest.encode().map_err(|_| CaptureError::Proof)?)
            .map_err(|_| CaptureError::Proof)?;
        let retain = recovery_time
            .checked_add(GRACE)
            .ok_or(CaptureError::Admission)?;
        self.spool.capture_write(identity, move |connection| {
            let transaction = connection.transaction()?;
            if crate::catalog::publication::capture_path_conflicts(
                &transaction,
                &receipt.repository,
                &receipt.public_package_path,
                identity,
            )? {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,?2,?3,?4,0) ON CONFLICT(digest) DO UPDATE SET first_capture=CASE WHEN first_capture>0 THEN first_capture ELSE excluded.first_capture END,retain_until=MAX(retain_until,excluded.retain_until)",
                params![
                    receipt.sha256,
                    crate::catalog::signed(receipt.size)?,
                    recovery_time,
                    retain
                ],
            )?;
            transaction.execute(
                "INSERT INTO capture_proofs(generation,manifest,durable) VALUES(?1,?2,1) ON CONFLICT(generation) DO UPDATE SET durable=1",
                params![generation, encoded],
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
                "INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES(?1,?2,?6,?3,?4,1,0,?5) ON CONFLICT(repository,path) DO UPDATE SET generation=excluded.generation,receipt_verified=1,retain_until=MAX(retain_until,excluded.retain_until)",
                params![
                    receipt.repository,
                    receipt.public_package_path,
                    receipt.sha256,
                    generation,
                    retain,
                    Sha256Digest::of(receipt.public_package_path.as_bytes()).to_hex()
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        self.spool
            .release_generation(lifecycle::proof_pin(&proof.manifest().scope_id().to_hex()))?;
        Ok(())
    }
    pub(crate) fn spool(&self) -> &Spool {
        &self.spool
    }
    #[cfg(test)]
    pub(crate) fn store(&self) -> &Arc<S3Store> {
        &self.store
    }
}

/// Bind global authenticated content references without granting path authority.
/// Proof-only retention is a finite lease, not a recreated public generation.
pub(super) fn bind_retained_mapping(
    transaction: &rusqlite::Transaction<'_>,
    repository: &str,
    path: &str,
    identity: ObjectIdentity,
    now: i64,
) -> Result<(), CatalogError> {
    let digest = identity.sha256.to_hex();
    let coverage: bool =
        transaction.query_row("SELECT coverage FROM capture_state WHERE id=1", [], |row| {
            row.get(0)
        })?;
    if !coverage {
        return Err(CatalogError::InvalidState);
    }
    transaction.execute(
        "INSERT INTO capture_generation_refs(generation,digest,retain_until)
         SELECT q.generation,?1,MAX(CASE WHEN q.was_public=1 AND q.public_retired_at IS NULL THEN 9223372036854775807 ELSE q.recovery_retention END)
         FROM capture_index_entries e
         JOIN capture_indexes i ON i.id=e.index_id AND i.verified=1
         JOIN capture_proof_indexes m ON m.index_id=e.index_id
         JOIN capture_proofs q ON q.generation=m.generation
         WHERE e.digest=?1 AND e.size=?2
           AND ((q.was_public=1 AND q.public_retired_at IS NULL) OR q.recovery_retention>?3)
         GROUP BY q.generation
         ON CONFLICT(generation,digest) DO UPDATE SET retain_until=MAX(retain_until,excluded.retain_until)",
        params![digest, crate::catalog::signed(identity.size)?, now],
    )?;
    transaction.execute(
        "UPDATE capture_paths SET
         referenced=EXISTS(SELECT 1 FROM capture_generation_refs WHERE digest=?3 AND retain_until=9223372036854775807),
         retain_until=MAX(retain_until,COALESCE((SELECT MAX(retain_until) FROM capture_generation_refs WHERE digest=?3 AND retain_until<9223372036854775807),0))
         WHERE repository=?1 AND path=?2 AND digest=?3",
        params![repository, path, digest],
    )?;
    Ok(())
}
async fn put_readback(
    store: &S3Store,
    suffix: &str,
    bytes: &[u8],
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(), CaptureError> {
    if let Err(error) = store
        .control_put(
            OperationIdentity::Object,
            suffix,
            bytes,
            ControlCondition::Create,
            deadline,
            cancel,
        )
        .await
        && !matches!(
            error,
            S3Error::Conflict | S3Error::Timeout | S3Error::Unavailable
        )
    {
        return Err(error.into());
    }
    let read = store
        .control_get(
            OperationIdentity::Object,
            suffix,
            bytes.len().max(1) as u64,
            deadline,
            cancel,
        )
        .await?;
    if read.bytes != bytes {
        store.quarantine_control(suffix)?;
        return Err(CaptureError::Proof);
    }
    Ok(())
}
#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod path_tests {
    use super::{is_index_path, is_package_path};

    #[test]
    fn recognizes_debian_pacman_and_rpm_binary_paths() {
        for path in [
            "pool/main/p/package.deb",
            "dists/stable/main/package.deb",
            "core/os/x86_64/package-1-1-x86_64.pkg.tar.zst",
            "extra/os/x86_64/package-1-1-any.pkg.tar.xz.sig",
            "chaotic-aur/x86_64/package-1-1-any.pkg.tar.gz",
            "archlinuxcn/x86_64/package-1-1-any.pkg.tar.zst",
            "endeavouros/x86_64/package-1-1-any.pkg.tar.zst",
            "x86_64/cachyos/package-1-1-x86_64_v3.pkg.tar.zst",
            "9/BaseOS/aarch64/os/Packages/p/package-1-1.aarch64.rpm",
        ] {
            assert!(is_package_path(path), "{path}");
        }
        for path in [
            "main/binary-amd64/Packages",
            "main/binary-arm64/Packages",
            "main/binary-all/Packages",
            "os/x86_64/core.db",
            "os/x86_64/extra.db",
            "os/x86_64/multilib.db",
            "x86_64/chaotic-aur.db",
            "os/aarch64/core.db",
            "x86_64/cachyos.db",
            "x86_64/archlinuxcn.db",
            "x86_64/endeavouros.db",
            "9/BaseOS/aarch64/os/repodata/primary.xml.gz",
        ] {
            assert!(is_index_path(path), "{path}");
        }
        assert!(!is_package_path("core/os/x86_64/core.db"));
        assert!(!is_index_path("main/source/Sources"));
        assert!(!is_index_path("9/BaseOS/aarch64/os/repodata/repomd.xml"));
    }
}
