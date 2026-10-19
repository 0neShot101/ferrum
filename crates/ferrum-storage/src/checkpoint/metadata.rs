//! Indexed metadata authority. Digests only select aliases actually signed in
//! Release; internal SHA-256 identities do not fabricate a public by-hash alias.
use super::{CheckpointError, CheckpointPublisher, SuiteKey};
use crate::{VerifiedObject, catalog::CatalogError, recovery::VerifiedHistoricalProof};
use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest, Sha512Digest},
    path::RepositoryPath,
};
use rusqlite::{OptionalExtension, params};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub enum MetadataHash {
    Sha256(Sha256Digest),
    Sha512(Sha512Digest),
}
#[derive(Clone)]
pub struct MetadataDescriptor {
    identity: ObjectIdentity,
    path: String,
    source_path: String,
    source: VerifiedObject,
    proof: Arc<VerifiedHistoricalProof>,
}
impl MetadataDescriptor {
    pub fn identity(&self) -> ObjectIdentity {
        self.identity
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn source_path(&self) -> &str {
        &self.source_path
    }
    pub fn source(&self) -> &VerifiedObject {
        &self.source
    }
    pub fn proof(&self) -> Arc<VerifiedHistoricalProof> {
        self.proof.clone()
    }
    pub fn is_derived(&self) -> bool {
        self.path != self.source_path
    }
}
impl CheckpointPublisher {
    pub fn lookup_metadata(
        &self,
        key: &SuiteKey,
        path: &RepositoryPath,
    ) -> Result<Option<MetadataDescriptor>, CheckpointError> {
        self.metadata_lookup(key, Some(path.as_str()), "", None)
    }
    pub fn lookup_by_hash(
        &self,
        key: &SuiteKey,
        directory: &str,
        hash: MetadataHash,
    ) -> Result<Option<MetadataDescriptor>, CheckpointError> {
        if !directory.is_empty() {
            RepositoryPath::parse_decoded(directory).map_err(|_| CheckpointError::Invalid)?;
        }
        self.metadata_lookup(key, None, directory, Some(hash))
    }
    fn metadata_lookup(
        &self,
        key: &SuiteKey,
        path: Option<&str>,
        directory: &str,
        hash: Option<MetadataHash>,
    ) -> Result<Option<MetadataDescriptor>, CheckpointError> {
        let key = key.clone();
        let path = path.map(str::to_owned);
        let directory = directory.to_owned();
        let row = self.spool.durable_catalog()?.read(move |connection| {
            let read = |row: &rusqlite::Row<'_>| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    crate::catalog::read_unsigned(row, 3)?,
                    row.get::<_, String>(4)?,
                ))
            };
            if let Some(path) = path {
                Ok(connection
                    .query_row(
                        "SELECT m.generation,m.path,m.digest,m.size,m.source_path FROM public_generations g JOIN publication_metadata m ON m.generation=g.generation AND m.path=?3 WHERE g.repository=?1 AND g.suite=?2 AND g.retired_at IS NULL LIMIT 1",
                        params![key.repository(), key.suite(), path],
                        read,
                    )
                    .optional()?)
            } else {
                let (sql, digest) = match hash {
                    Some(MetadataHash::Sha256(digest)) => (
                        "SELECT m.generation,m.path,m.digest,m.size,m.source_path FROM publication_metadata m INDEXED BY publication_metadata_sha256 JOIN public_generations g ON g.generation=m.generation WHERE m.directory=?3 AND m.digest=?4 AND m.sha256_alias=1 AND g.repository=?1 AND g.suite=?2 ORDER BY g.activated_at DESC,g.generation LIMIT 1",
                        digest.to_hex(),
                    ),
                    Some(MetadataHash::Sha512(digest)) => (
                        "SELECT m.generation,m.path,m.digest,m.size,m.source_path FROM publication_metadata m INDEXED BY publication_metadata_sha512 JOIN public_generations g ON g.generation=m.generation WHERE m.directory=?3 AND m.sha512=?4 AND g.repository=?1 AND g.suite=?2 ORDER BY g.activated_at DESC,g.generation LIMIT 1",
                        digest.to_hex(),
                    ),
                    None => return Err(CatalogError::InvalidState),
                };
                Ok(connection
                    .query_row(
                        sql,
                        params![key.repository(), key.suite(), directory, digest],
                        read,
                    )
                    .optional()?)
            }
        })?;
        let Some((scope, path, digest, size, source_path)) = row else {
            return Ok(None);
        };
        let proof = self
            .proofs
            .lock()
            .map_err(|_| CheckpointError::Proof)?
            .get(&scope)
            .cloned()
            .ok_or(CheckpointError::Proof)?;
        let identity = ObjectIdentity {
            sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?,
            size,
        };
        if proof.identity(&path) != Some(identity) {
            return Err(CheckpointError::Proof);
        }
        let source = proof
            .artifact(&source_path)
            .ok_or(CheckpointError::Proof)?
            .clone();
        Ok(Some(MetadataDescriptor {
            identity,
            path,
            source_path,
            source,
            proof,
        }))
    }
}
