use super::{CaptureError, CaptureManager, VerifiedCaptureProof};
use crate::{VerifiedObject, catalog::CatalogError, disk::ReservationClass};
use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest},
    path::RepositoryPath,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) const PACKAGE_SIGNATURE_SCHEMA: &[(&str, &str)] = &[(
    "capture_package_signatures",
    "CREATE TABLE capture_package_signatures (generation TEXT NOT NULL REFERENCES capture_proofs(generation) ON DELETE CASCADE, package_path TEXT NOT NULL, binding TEXT NOT NULL CHECK(length(CAST(binding AS BLOB))<=32768), PRIMARY KEY(generation,package_path)) STRICT",
)];

/// A recovery pointer, not a capability: both exact objects must be verified again.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageSignatureBinding {
    package_path: String,
    package_sha256: String,
    package_size: u64,
    signature_sha256: String,
    signature_size: u64,
}
impl PackageSignatureBinding {
    pub fn package_path(&self) -> &str {
        &self.package_path
    }
    pub fn package_identity(&self) -> Result<ObjectIdentity, CaptureError> {
        if self.package_size > 8 * 1024 * 1024 * 1024
            || self.package_path.ends_with(".sig")
            || !ferrum_apt::pacman::is_pacman_package_path(&self.package_path)
        {
            return Err(CaptureError::Proof);
        }
        RepositoryPath::parse_decoded(&self.package_path).map_err(|_| CaptureError::Proof)?;
        Ok(ObjectIdentity {
            sha256: Sha256Digest::from_hex(&self.package_sha256)
                .map_err(|_| CaptureError::Proof)?,
            size: self.package_size,
        })
    }
    pub fn signature_identity(&self) -> Result<ObjectIdentity, CaptureError> {
        if self.signature_size == 0
            || self.signature_size > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64
        {
            return Err(CaptureError::Proof);
        }
        Ok(ObjectIdentity {
            sha256: Sha256Digest::from_hex(&self.signature_sha256)
                .map_err(|_| CaptureError::Proof)?,
            size: self.signature_size,
        })
    }
    pub(super) fn matches(&self, path: &RepositoryPath, identity: ObjectIdentity) -> bool {
        if path.as_str() == self.package_path {
            self.package_identity().ok() == Some(identity)
        } else if path.as_str().strip_suffix(".sig") == Some(self.package_path.as_str()) {
            self.signature_identity().ok() == Some(identity)
        } else {
            false
        }
    }
}
impl VerifiedCaptureProof {
    pub fn requires_package_signature(&self) -> bool {
        self.proof.package_authority.is_some()
    }
    pub fn package_signature(&self) -> Option<&PackageSignatureBinding> {
        self.package_signature.as_ref()
    }
    /// Reuses only the verification performed for this freshly authorized request.
    /// Catalog rows and other requests never populate this process-owned slot.
    pub fn request_authentication(&self) -> Option<&Self> {
        self.request_authentication
            .get()
            .map(std::sync::Arc::as_ref)
    }
    /// Authenticates resident representations for HEAD/304 without registration,
    /// capture admission, or any package/signature source request.
    pub async fn verify_resident_package(
        &self,
        package: &VerifiedObject,
        signature: &VerifiedObject,
        deadline: Instant,
    ) -> Result<(), CaptureError> {
        let (verifier, keyring) = self
            .proof
            .package_authority
            .as_ref()
            .ok_or(CaptureError::Proof)?;
        let (_, identity) = self.package_candidate()?;
        if !package.belongs_to(&self.proof.owner)
            || !signature.belongs_to(&self.proof.owner)
            || package.identity() != identity
            || self.candidate_signature_identity()? != Some(signature.identity())
        {
            return Err(CaptureError::Proof);
        }
        let scratch = self.proof.owner.reserve_class(
            ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64,
            ReservationClass::Metadata,
        )?;
        tokio::time::timeout_at(
            deadline,
            verifier.verify_package_owned(
                keyring,
                package.path(),
                signature.path(),
                identity.size,
                (
                    scratch,
                    package.clone(),
                    signature.clone(),
                    self.proof.clone(),
                ),
            ),
        )
        .await
        .map_err(|_| CaptureError::Admission)?
        .map_err(|_| CaptureError::Proof)
    }
    pub(super) fn require_package_authentication(&self) -> Result<(), CaptureError> {
        if self.requires_package_signature()
            && (self.package_objects.is_none()
                || !self
                    .package_signature
                    .as_ref()
                    .is_some_and(|binding| binding.matches(&self.path, self.identity)))
        {
            return Err(CaptureError::Proof);
        }
        Ok(())
    }
    pub fn authenticated_package_proof(&self) -> Result<Self, CaptureError> {
        self.require_package_authentication()?;
        let binding = self.package_signature.as_ref().ok_or(CaptureError::Proof)?;
        Ok(Self {
            proof: self.proof.clone(),
            path: RepositoryPath::parse_decoded(binding.package_path())
                .map_err(|_| CaptureError::Proof)?,
            identity: binding.package_identity()?,
            package_signature: Some(binding.clone()),
            package_objects: self.package_objects.clone(),
            request_authentication: std::sync::OnceLock::new(),
        })
    }
    /// Resolves only the database's candidate checksum; this grants no capture authority.
    pub fn package_candidate(&self) -> Result<(RepositoryPath, ObjectIdentity), CaptureError> {
        let path = RepositoryPath::parse_decoded(
            self.path
                .as_str()
                .strip_suffix(".sig")
                .unwrap_or(self.path.as_str()),
        )
        .map_err(|_| CaptureError::Proof)?;
        let identity = self.candidate_identity(&path)?.ok_or(CaptureError::Proof)?;
        Ok((path, identity))
    }
    pub fn candidate_signature_identity(&self) -> Result<Option<ObjectIdentity>, CaptureError> {
        let (path, _) = self.package_candidate()?;
        let signature = RepositoryPath::parse_decoded(&format!("{path}.sig"))
            .map_err(|_| CaptureError::Proof)?;
        let identity = self.candidate_identity(&signature)?;
        if identity.is_some_and(|identity| {
            identity.size == 0 || identity.size > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64
        }) {
            return Err(CaptureError::Proof);
        }
        Ok(identity)
    }
    fn candidate_identity(
        &self,
        path: &RepositoryPath,
    ) -> Result<Option<ObjectIdentity>, CaptureError> {
        let scope = self.manifest().scope_id().to_hex();
        let path = path.as_str().to_owned();
        Ok(self.proof.owner.durable_catalog()?.read(move |connection| {
            let row = connection.query_row(
                "SELECT e.digest,e.size FROM capture_index_entries e JOIN capture_proof_indexes m ON m.index_id=e.index_id JOIN capture_indexes i ON i.id=e.index_id AND i.verified=1 WHERE m.generation=?1 AND e.path=?2 LIMIT 1",
                params![scope,path], |row| Ok((row.get::<_, String>(0)?, crate::catalog::read_unsigned(row,1)?)),
            ).optional()?;
            row.map(|(digest,size)| Ok(ObjectIdentity {
                sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?, size,
            })).transpose()
        })?)
    }
    pub async fn embedded_package_signature(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Option<Vec<u8>>, CaptureError> {
        let (package, _) = self.package_candidate()?;
        let database = self
            .manifest()
            .artifacts
            .first()
            .ok_or(CaptureError::Proof)?;
        let source = self
            .proof
            .artifact(&database.path)
            .ok_or(CaptureError::Proof)?
            .clone();
        let name = database.path.clone();
        let permit = tokio::select! {
            () = cancel.cancelled() => return Err(CaptureError::Admission),
            permit = tokio::time::timeout_at(deadline, crate::recovery::PROOF_CPU.clone().acquire_owned()) =>
                permit.map_err(|_|CaptureError::Admission)?.map_err(|_|CaptureError::Admission)?,
        };
        let child = cancel.child_token();
        let _cancel_on_drop = child.clone().drop_guard();
        Ok(self
            .proof
            .owner
            .catalog_work_async(move |_| {
                let _permit = permit;
                let file = std::fs::File::open(source.path())?;
                let mut reader = crate::recovery::proof_reader(file, &name, child)?;
                ferrum_apt::pacman::package_embedded_signature_reader(
                    &mut reader,
                    &name,
                    &package,
                    &ferrum_apt::release::ParseLimits::default(),
                )
                .map_err(|_| CatalogError::InvalidState)
            })
            .await?)
    }
    /// The configured proof's keyring, never a caller-selected key, authenticates
    /// this exact package and signature before any index or receipt is promoted.
    pub async fn authenticate_package(
        &self,
        package: &VerifiedObject,
        signature: &VerifiedObject,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<std::sync::Arc<Self>, CaptureError> {
        let (verifier, keyring) = self
            .proof
            .package_authority
            .as_ref()
            .ok_or(CaptureError::Proof)?;
        let (path, identity) = self.package_candidate()?;
        if !package.belongs_to(&self.proof.owner)
            || !signature.belongs_to(&self.proof.owner)
            || package.identity() != identity
            || signature.size() == 0
            || signature.size() > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64
            || self
                .candidate_signature_identity()?
                .is_some_and(|expected| expected != signature.identity())
        {
            return Err(CaptureError::Proof);
        }
        let scratch = self.proof.owner.reserve_class(
            ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64,
            ReservationClass::Metadata,
        )?;
        tokio::time::timeout_at(
            deadline,
            verifier.verify_package_owned(
                keyring,
                package.path(),
                signature.path(),
                identity.size,
                (
                    scratch,
                    package.clone(),
                    signature.clone(),
                    self.proof.clone(),
                ),
            ),
        )
        .await
        .map_err(|_| CaptureError::Admission)?
        .map_err(|_| CaptureError::Proof)?;
        let _owner = super::index::index_owner(&self.proof.owner, deadline, cancel).await?;
        if self.package_candidate()? != (path.clone(), identity) {
            return Err(CaptureError::Proof);
        }
        let binding = PackageSignatureBinding {
            package_path: path.as_str().to_owned(),
            package_sha256: identity.sha256.to_hex(),
            package_size: identity.size,
            signature_sha256: signature.sha256().to_hex(),
            signature_size: signature.size(),
        };
        if !binding.matches(&self.path, self.identity) {
            return Err(CaptureError::Proof);
        }
        let generation = self.manifest().scope_id().to_hex();
        let manifest =
            String::from_utf8(self.manifest().encode().map_err(|_| CaptureError::Proof)?)
                .map_err(|_| CaptureError::Proof)?;
        let encoded = serde_json::to_string(&binding)?;
        let package_path = path.as_str().to_owned();
        if encoded.len() > 32 * 1024 {
            return Err(CaptureError::Proof);
        }
        let sig_path = format!("{path}.sig");
        let signature_identity = signature.identity();
        let known_generation = generation.clone();
        let known_path = package_path.clone();
        let known = self.proof.owner.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT binding FROM capture_package_signatures WHERE generation=?1 AND package_path=?2",
                params![known_generation,known_path], |row| row.get::<_, String>(0),
            ).optional()?)
        })?;
        if known.as_deref() == Some(encoded.as_str())
            && self.candidate_signature_identity()? == Some(signature_identity)
        {
            return self.retain_request_authentication(binding, package, signature);
        }
        // Bounded catalog accounting and the reset owner apply to dynamic entries
        // exactly as to parsed index batches. Stored JSON alone grants no authority.
        self.proof.owner.catalog_write_reserved(8 * 1024 * 1024, move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute("INSERT OR IGNORE INTO capture_proofs(generation,manifest,durable) VALUES(?1,?2,0)", params![generation,manifest])?;
            let index: String = transaction.query_row(
                "SELECT m.index_id FROM capture_proof_indexes m JOIN capture_index_entries e ON e.index_id=m.index_id JOIN capture_indexes i ON i.id=m.index_id AND i.verified=1 WHERE m.generation=?1 AND e.path=?2 AND e.digest=?3 AND e.size=?4 LIMIT 1",
                params![generation,package_path,identity.sha256.to_hex(),crate::catalog::signed(identity.size)?], |row| row.get(0),
            )?;
            transaction.execute("INSERT OR IGNORE INTO capture_index_entries(index_id,path,digest,size) VALUES(?1,?2,?3,?4)", params![index,sig_path,signature_identity.sha256.to_hex(),crate::catalog::signed(signature_identity.size)?])?;
            let conflict: bool = transaction.query_row("SELECT digest<>?3 OR size<>?4 FROM capture_index_entries WHERE index_id=?1 AND path=?2",params![index,sig_path,signature_identity.sha256.to_hex(),crate::catalog::signed(signature_identity.size)?],|row|row.get(0))?;
            if conflict { return Err(CatalogError::InvalidState); }
            transaction.execute("INSERT INTO capture_package_signatures(generation,package_path,binding) VALUES(?1,?2,?3) ON CONFLICT(generation,package_path) DO UPDATE SET binding=excluded.binding WHERE binding<>excluded.binding", params![generation,package_path,encoded])?;
            transaction.execute(
                "INSERT OR IGNORE INTO capture_artifacts(generation,digest,size) VALUES(?1,?2,?3)",
                params![generation,signature_identity.sha256.to_hex(),crate::catalog::signed(signature_identity.size)?],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        self.retain_request_authentication(binding, package, signature)
    }
    fn retain_request_authentication(
        &self,
        binding: PackageSignatureBinding,
        package: &VerifiedObject,
        signature: &VerifiedObject,
    ) -> Result<std::sync::Arc<Self>, CaptureError> {
        let authenticated = std::sync::Arc::new(Self {
            proof: self.proof.clone(),
            path: self.path.clone(),
            identity: self.identity,
            package_signature: Some(binding),
            package_objects: Some((package.clone(), signature.clone())),
            request_authentication: std::sync::OnceLock::new(),
        });
        if self
            .request_authentication
            .set(authenticated.clone())
            .is_err()
            && self.request_authentication.get().is_none_or(|existing| {
                existing.package_signature != authenticated.package_signature
            })
        {
            return Err(CaptureError::Proof);
        }
        Ok(authenticated)
    }
}
impl CaptureManager {
    pub(super) fn package_binding(
        &self,
        generation: &str,
        path: &str,
    ) -> Result<Option<PackageSignatureBinding>, CaptureError> {
        let generation = generation.to_owned();
        let path = path.strip_suffix(".sig").unwrap_or(path).to_owned();
        let encoded = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row("SELECT binding FROM capture_package_signatures WHERE generation=?1 AND package_path=?2",params![generation,path],|row| row.get::<_,String>(0)).optional()?)
        })?;
        encoded
            .map(|value| serde_json::from_str(&value).map_err(CaptureError::from))
            .transpose()
    }
    pub(super) async fn persist_package_signature(
        &self,
        binding: Option<&PackageSignatureBinding>,
        generation: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        let Some(binding) = binding else {
            return Ok(());
        };
        let identity = binding.signature_identity()?;
        let object = self
            .restore_binding_object(identity, deadline, cancel, false)
            .await?;
        self.store
            .control_put_file(
                &format!("v1/objects/sha256/{}", identity.sha256),
                object.path(),
                identity,
                deadline,
                cancel,
            )
            .await?;
        self.spool
            .release_generation(super::lifecycle::signature_pin(
                generation,
                binding.package_path(),
                identity,
            ))?;
        let package_identity = binding.package_identity()?;
        if !self.is_durable(package_identity)? {
            let package = self
                .spool
                .lookup(package_identity)
                .ok_or(CaptureError::Proof)?;
            self.store
                .put_file_verified(&package, deadline, cancel.clone())
                .await?;
        }
        Ok(())
    }
    pub(super) async fn restore_binding_object(
        &self,
        identity: ObjectIdentity,
        deadline: Instant,
        cancel: &CancellationToken,
        require_remote: bool,
    ) -> Result<VerifiedObject, CaptureError> {
        use ferrum_apt::digest::Sha256Hasher;
        use futures_util::StreamExt;
        let local = self.spool.lookup(identity);
        if !require_remote && let Some(object) = &local {
            return Ok(object.clone());
        }
        let mut writer = if local.is_none() {
            Some(
                self.spool
                    .begin_write(self.spool.reserve(identity.size)?, identity)
                    .await?,
            )
        } else {
            None
        };
        let response = self.store.get(identity, deadline, cancel.clone()).await?;
        let mut stream = response.into_stream();
        let mut hash = Sha256Hasher::new();
        let mut size = 0u64;
        while let Some(bytes) = stream.next().await {
            let bytes = bytes?;
            if let Some(writer) = &mut writer {
                writer.write(bytes).await?;
            } else {
                size = size
                    .checked_add(bytes.len() as u64)
                    .ok_or(CaptureError::Proof)?;
                if size > identity.size {
                    self.store.quarantine(identity)?;
                    return Err(CaptureError::Proof);
                }
                hash.update(&bytes);
            }
        }
        if let Some(writer) = writer {
            return match writer.commit_candidate().await {
                Ok(object) => Ok(object),
                Err(error) => {
                    self.store.quarantine(identity)?;
                    Err(error.into())
                }
            };
        }
        if size != identity.size || hash.finalize() != identity.sha256 {
            self.store.quarantine(identity)?;
            return Err(CaptureError::Proof);
        }
        local.ok_or(CaptureError::Proof)
    }
}
