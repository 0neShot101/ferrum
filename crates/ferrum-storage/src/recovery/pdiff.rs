//! Optional PDiff artifacts have exactly the same generation lifetime as their
//! full indexes. The manifest carries bytes, not trust: replay every Index link
//! from the signed Release before allowing either canonical serving or retention.

use std::collections::BTreeMap;

use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest},
    path::RepositoryPath,
    pdiff::{Index, MAX_INDEX_BYTES, MAX_SUITE_BYTES, Patch},
    release::Release,
    selection::Target,
};

use super::{GenerationManifest, PROOF_CPU, proof_reader};
use crate::{Spool, VerifiedObject, checkpoint::CheckpointError, disk::ReservationClass};
use tokio_util::sync::CancellationToken;

/// Verify compressed patch syntax and its independent expanded SHA256/size.
/// The object must already match the authenticated download identity.
pub async fn verify_patch(
    spool: &Spool,
    object: &VerifiedObject,
    patch: &Patch,
) -> Result<(), CheckpointError> {
    if object.identity() != patch.download {
        return Err(CheckpointError::Proof);
    }
    let permit = PROOF_CPU
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| CheckpointError::Proof)?;
    let scratch = spool.reserve_class(128 * 1024, ReservationClass::Metadata)?;
    let object = object.clone();
    let expanded = patch.expanded;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _scratch = scratch;
        let file = std::fs::File::open(object.path())?;
        let reader = proof_reader(file, "patch.gz", CancellationToken::new())
            .map_err(|_| CheckpointError::Proof)?;
        ferrum_apt::pdiff::verify_patch(reader, expanded).map_err(|_| CheckpointError::Proof)
    })
    .await
    .map_err(|_| CheckpointError::Proof)?
}

pub(super) async fn authenticate(
    spool: &Spool,
    manifest: &GenerationManifest,
    release: &Release,
    selected: &[Target],
    artifacts: &[VerifiedObject],
) -> Result<BTreeMap<String, ObjectIdentity>, CheckpointError> {
    let mut closure = BTreeMap::new();
    let mut bytes = 0u64;
    for entry in ferrum_apt::selection::pdiffs(release, selected) {
        let path = entry.path.as_str();
        let Some(position) = manifest
            .artifacts
            .iter()
            .position(|artifact| artifact.path == path)
        else {
            continue;
        };
        let root = &artifacts[position];
        let expected = ObjectIdentity {
            sha256: entry.sha256.ok_or(CheckpointError::Proof)?,
            size: entry.size,
        };
        if root.identity() != expected {
            return Err(CheckpointError::Proof);
        }
        let index_bytes = root.read_bounded(MAX_INDEX_BYTES).await?;
        if Sha256Digest::of(&index_bytes) != expected.sha256 {
            return Err(CheckpointError::Proof);
        }
        let base = path
            .strip_suffix(".diff/Index")
            .ok_or(CheckpointError::Proof)?;
        let full_path = RepositoryPath::parse_decoded(base).map_err(|_| CheckpointError::Proof)?;
        let full = release.entry(&full_path).ok_or(CheckpointError::Proof)?;
        let index = Index::parse(
            &index_bytes,
            ObjectIdentity {
                sha256: full.sha256.ok_or(CheckpointError::Proof)?,
                size: full.size,
            },
        )
        .map_err(|_| CheckpointError::Proof)?;
        bytes = bytes
            .checked_add(expected.size)
            .ok_or(CheckpointError::Proof)?;
        closure.insert(path.to_owned(), expected);
        for patch in &index.patches {
            bytes = bytes
                .checked_add(patch.download.size)
                .and_then(|size| size.checked_add(patch.expanded.size))
                .ok_or(CheckpointError::Proof)?;
            if bytes > MAX_SUITE_BYTES {
                return Err(CheckpointError::Proof);
            }
            let path = format!("{base}.diff/{}.gz", patch.name);
            // An independently advertised Release path may not conflict with
            // Index authority, even if that representation is not selected.
            let parsed =
                RepositoryPath::parse_decoded(&path).map_err(|_| CheckpointError::Proof)?;
            if let Some(entry) = release.entry(&parsed)
                && (entry.sha256 != Some(patch.download.sha256)
                    || entry.size != patch.download.size)
            {
                return Err(CheckpointError::Proof);
            }
            let position = manifest
                .artifacts
                .iter()
                .position(|artifact| artifact.path == path)
                .ok_or(CheckpointError::Proof)?;
            let object = &artifacts[position];
            verify_patch(spool, object, patch).await?;
            if closure.insert(path, patch.download).is_some() {
                return Err(CheckpointError::Proof);
            }
        }
    }
    Ok(closure)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::disk::DurableSpoolConfig;
    use crate::recovery::ManifestArtifact;
    use ferrum_apt::release::ParseLimits;
    use std::io::Write;

    async fn install(spool: &Spool, bytes: Vec<u8>) -> VerifiedObject {
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(&bytes),
            size: bytes.len() as u64,
        };
        let reservation = spool
            .reserve_class(identity.size, ReservationClass::Metadata)
            .expect("metadata reservation");
        let mut writer = spool
            .begin_write(reservation, identity)
            .await
            .expect("writer");
        writer.write(bytes.into()).await.expect("bounded bytes");
        writer.commit().await.expect("verified object")
    }

    #[tokio::test]
    async fn recovery_requires_complete_same_generation_patch_closure() {
        let directory = tempfile::tempdir().expect("state");
        let mut config = DurableSpoolConfig::new(directory.path().join("state"));
        config.free_space_floor = 0;
        let spool = Spool::open_durable(config).expect("durable spool");
        let patch = b"1c\nnew\n.\n";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(patch).expect("compress fixture");
        let compressed = gzip.finish().expect("gzip");
        let wire = install(&spool, compressed).await;
        let current = Sha256Digest::of(b"new\n");
        let index = format!(
            "SHA256-Current: {current} 4\nSHA256-History:\n {} 4 step\n\
             SHA256-Patches:\n {} {} step\nSHA256-Download:\n {} {} step.gz\n",
            Sha256Digest::of(b"old\n"),
            Sha256Digest::of(patch),
            patch.len(),
            wire.sha256(),
            wire.size(),
        );
        let root = install(&spool, index.into_bytes()).await;
        let release = format!(
            "Origin: Debian\nSuite: trixie\nCodename: trixie\nArchitectures: amd64\n\
             Components: main\nDate: Thu, 01 Jan 1970 00:00:00 UTC\nSHA256:\n \
             {current} 4 main/binary-amd64/Packages\n \
             {} {} main/binary-amd64/Packages.diff/Index\n",
            root.sha256(),
            root.size(),
        );
        let release = Release::parse(release.as_bytes(), &ParseLimits::default()).expect("Release");
        let (selected, _) =
            ferrum_apt::selection::select(&release, &["main"], false).expect("selected full index");
        let paths = [
            "main/binary-amd64/Packages.diff/Index",
            "main/binary-amd64/Packages.diff/step.gz",
        ];
        let objects = vec![root, wire];
        let mut manifest = GenerationManifest {
            schema_version: 1,
            repository: "debian".into(),
            suite: "trixie".into(),
            generation_id: Sha256Digest::of(b"generation").to_hex(),
            release_content_sha256: release.content_sha256().to_hex(),
            release_date: 0,
            artifacts: paths
                .iter()
                .zip(&objects)
                .map(|(path, object)| ManifestArtifact {
                    path: (*path).into(),
                    sha256: object.sha256().to_hex(),
                    size: object.size(),
                })
                .collect(),
            derived: Vec::new(),
        };
        let closure = authenticate(&spool, &manifest, &release, &selected, &objects)
            .await
            .expect("full authenticated closure");
        assert_eq!(closure.len(), 2);
        manifest.artifacts.pop();
        assert!(
            authenticate(&spool, &manifest, &release, &selected, &objects[..1])
                .await
                .is_err()
        );
        manifest.artifacts.clear();
        assert!(
            authenticate(&spool, &manifest, &release, &selected, &[])
                .await
                .expect("omission permits full fallback")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn wire_identity_and_expanded_patch_are_both_required() {
        let directory = tempfile::tempdir().expect("state");
        let mut config = DurableSpoolConfig::new(directory.path().join("state"));
        config.free_space_floor = 0;
        let spool = Spool::open_durable(config).expect("durable spool");
        let malformed = b"1w\n";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(malformed).expect("gzip bytes");
        let wire = install(&spool, gzip.finish().expect("finish")).await;
        let mut patch = Patch {
            name: "step".into(),
            history: ObjectIdentity {
                sha256: Sha256Digest::of(b"old\n"),
                size: 4,
            },
            expanded: ObjectIdentity {
                sha256: Sha256Digest::of(malformed),
                size: 3,
            },
            download: wire.identity(),
        };
        assert!(
            verify_patch(&spool, &wire, &patch).await.is_err(),
            "signed malformed rred"
        );
        patch.download.sha256 = Sha256Digest::of(b"unrelated");
        assert!(
            verify_patch(&spool, &wire, &patch).await.is_err(),
            "untrusted wire identity"
        );
    }
}
