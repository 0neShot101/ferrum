//! One authenticated streamed binary index parser for Debian, Pacman, and RPM packages.
use super::CaptureError;
use crate::{
    Spool,
    catalog::CatalogError,
    recovery::{PROOF_CPU, VerifiedHistoricalProof, proof_reader},
};
use ferrum_apt::{
    digest::{Sha256Hasher, Sha512Hasher},
    index::{IndexError, PackageRecord, parse_packages},
    release::{ParseLimits, ReleaseEntry},
};
use std::io::{BufReader, Read};
use std::sync::Arc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Parses all stanzas under the authenticated expanded-size and SHA-2 bounds.
/// Compressed bytes remain file-backed. Cancellation retains the shared CPU permit
/// until the admitted reader job exits; no transaction survives this operation.
pub async fn parse_proof_packages<S>(
    spool: &Spool,
    proof: Arc<VerifiedHistoricalProof>,
    index_path: &str,
    cancel: CancellationToken,
    deadline: Instant,
    mut sink: S,
) -> Result<u64, CaptureError>
where
    S: FnMut(PackageRecord) -> Result<(), IndexError> + Send + 'static,
{
    if !spool.same_owner(&proof.owner) {
        return Err(CaptureError::Proof);
    }
    if !super::is_index_path(index_path) {
        return Err(CaptureError::Proof);
    }
    let (object, entry) = proof
        .packages_source(index_path)
        .ok_or(CaptureError::Proof)?;
    let object = object.clone();
    let entry = entry.clone();
    let source = proof
        .manifest()
        .derived
        .iter()
        .find(|derived| derived.path == index_path)
        .map_or(index_path, |derived| derived.source_path.as_str())
        .to_owned();
    let permit = tokio::select! {()=cancel.cancelled()=>return Err(CaptureError::Admission),permit=tokio::time::timeout_at(deadline,PROOF_CPU.clone().acquire_owned())=>permit.map_err(|_|CaptureError::Admission)?.map_err(|_|CaptureError::Admission)?};
    let job_cancel = cancel.child_token();
    let _cancel_on_drop = job_cancel.clone().drop_guard();
    Ok(spool
        .catalog_work_async(move |_| {
            let _permit = permit;
            let _proof = proof;
            let file = std::fs::File::open(object.path())?;
            let reader = checked_reader(file, &source, entry, job_cancel, deadline)?;
            let mut reader = BufReader::with_capacity(256 * 1024, reader);
            let mut accepted = |record: PackageRecord| {
                if matches!(
                    record.architecture.as_str(),
                    "amd64"
                        | "arm64"
                        | "all"
                        | "x86_64"
                        | "x86_64_v3"
                        | "x86_64_v4"
                        | "aarch64"
                        | "noarch"
                        | "any"
                ) {
                    sink(record)?;
                }
                Ok(())
            };
            let count = if ferrum_apt::pacman::pacman_package_prefix(&source).is_some() {
                ferrum_apt::pacman::parse_pacman_db(
                    &mut reader,
                    &source,
                    &ParseLimits::default(),
                    &mut accepted,
                )
            } else if ferrum_apt::rpm::is_rpm_primary_index_path(&source) {
                ferrum_apt::rpm::parse_rpm_primary_xml(
                    &mut reader,
                    &source,
                    &ParseLimits::default(),
                    &mut accepted,
                )
            } else {
                parse_packages(&mut reader, &ParseLimits::default(), &mut accepted)
            }
            .map_err(|_| CatalogError::InvalidState)?;
            if !reader.get_ref().verified {
                return Err(CatalogError::InvalidState);
            }
            u64::try_from(count).map_err(|_| CatalogError::InvalidState)
        })
        .await?)
}
pub(super) struct CheckedReader {
    inner: Box<dyn Read>,
    entry: ReleaseEntry,
    total: u64,
    sha256: Option<Sha256Hasher>,
    sha512: Option<Sha512Hasher>,
    verified: bool,
    cancel: CancellationToken,
    deadline: std::time::Instant,
}
impl CheckedReader {
    pub(super) fn verified(&self) -> bool {
        self.verified
    }
}
pub(super) fn checked_reader(
    file: std::fs::File,
    source: &str,
    entry: ReleaseEntry,
    cancel: CancellationToken,
    deadline: Instant,
) -> Result<CheckedReader, CatalogError> {
    let inner = proof_reader(file, source, cancel.clone())?;
    let sha256 = entry.sha256.map(|_| Sha256Hasher::new());
    let sha512 = entry.sha512.map(|_| Sha512Hasher::new());
    if sha256.is_none() && sha512.is_none() {
        return Err(CatalogError::InvalidState);
    }
    Ok(CheckedReader {
        inner,
        entry,
        total: 0,
        sha256,
        sha512,
        verified: false,
        cancel,
        deadline: deadline.into_std(),
    })
}
impl Read for CheckedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancel.is_cancelled() || std::time::Instant::now() >= self.deadline {
            return Err(std::io::Error::other(
                "proof decoding cancelled or deadline exceeded",
            ));
        }
        let limit = buffer
            .len()
            .min(256 * 1024)
            .min(self.entry.size.saturating_add(1).saturating_sub(self.total) as usize);
        if limit == 0 && !buffer.is_empty() {
            return Err(std::io::Error::other(
                "signed expanded Packages size exceeded",
            ));
        }
        let size = self.inner.read(&mut buffer[..limit])?;
        self.total = self
            .total
            .checked_add(size as u64)
            .ok_or_else(|| std::io::Error::other("proof size overflow"))?;
        if self.total > self.entry.size {
            return Err(std::io::Error::other(
                "signed expanded Packages size exceeded",
            ));
        }
        if let Some(hash) = &mut self.sha256 {
            hash.update(&buffer[..size]);
        }
        if let Some(hash) = &mut self.sha512 {
            hash.update(&buffer[..size]);
        }
        if size == 0 {
            if self.total != self.entry.size {
                return Err(std::io::Error::other("signed expanded Packages truncated"));
            }
            if let Some(hash) = self.sha256.take()
                && self
                    .entry
                    .sha256
                    .is_some_and(|expected| expected != hash.finalize())
            {
                return Err(std::io::Error::other(
                    "signed expanded Packages SHA256 mismatch",
                ));
            }
            if let Some(hash) = self.sha512.take()
                && self
                    .entry
                    .sha512
                    .is_some_and(|expected| expected != hash.finalize())
            {
                return Err(std::io::Error::other(
                    "signed expanded Packages SHA512 mismatch",
                ));
            }
            self.verified = true;
        }
        Ok(size)
    }
}
