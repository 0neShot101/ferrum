//! The complete, authenticated active generation served by the public listener.
//!
//! A view is immutable once published. Every resolvable path maps to a verified
//! object (metadata, by-hash aliases) or to an authenticated identity (packages)
//! that the fill path must reproduce byte for byte.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use ferrum_apt::path::RepositoryPath;
use ferrum_apt::release::UnixTime;
use ferrum_storage::VerifiedObject;
use ferrum_storage::checkpoint::CheckpointError;
use ferrum_storage::recovery::VerifiedHistoricalProof;

use crate::config::SUITE;

/// Caching policy of a served representation (`PLAN.md` §3 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheClass {
    /// `dists/<suite>/{InRelease,Release,Release.gpg}`.
    Mutable,
    /// Canonical index paths below `dists/<suite>/<component>/`.
    Canonical,
    /// Retained by-hash aliases.
    ByHash,
    /// Pool packages.
    Package,
}

impl CacheClass {
    /// `Cache-Control` value for success responses of this class.
    pub fn cache_control(self) -> &'static str {
        match self {
            CacheClass::Mutable | CacheClass::Canonical => "no-cache",
            CacheClass::ByHash => "public, max-age=31536000, immutable",
            CacheClass::Package => "public, max-age=86400",
        }
    }

    /// Whether the suite freshness gate applies before serving.
    pub fn requires_freshness(self) -> bool {
        matches!(self, CacheClass::Mutable | CacheClass::Canonical)
    }

    /// Bounded label for `ferrum_requests_total{class=...}`.
    pub fn metrics_label(self) -> &'static str {
        match self {
            CacheClass::Mutable | CacheClass::Canonical => "metadata",
            CacheClass::ByHash => "by_hash",
            CacheClass::Package => "package",
        }
    }
}

/// Digest algorithm of a by-hash directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    fn from_directory(name: &str) -> Option<Self> {
        match name {
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// `(directory, algorithm, lowercase hex)` of one authorized by-hash alias; the
/// directory is relative to `dists/<suite>/` (for example `main/binary-amd64`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ByHashKey {
    pub directory: String,
    pub algorithm: HashAlgorithm,
    pub hex: String,
}

/// An authenticated expanded representation and its pinned compressed source.
#[derive(Debug, Clone)]
pub struct DerivedDescriptor {
    pub identity: ObjectIdentity,
    pub source: VerifiedObject,
    pub source_path: String,
}

/// Outcome of resolving a path below the repository prefix.
#[derive(Debug, Clone)]
pub enum Resolution {
    /// Verified metadata object with its cache class.
    Metadata {
        object: VerifiedObject,
        class: CacheClass,
    },
    /// Authorized by-hash alias.
    ByHash(VerifiedObject),
    Derived {
        descriptor: DerivedDescriptor,
        class: CacheClass,
    },
    /// Catalogued package; may or may not be installed locally.
    Package {
        identity: ObjectIdentity,
        path: RepositoryPath,
    },
    /// Nothing authenticated at that path; never triggers a backend request.
    Unknown,
}

/// Immutable generation descriptors shared by confirmation-only renewals.
#[derive(Debug, Clone)]
struct Descriptors {
    metadata: HashMap<RepositoryPath, (VerifiedObject, CacheClass)>,
    by_hash: HashMap<ByHashKey, VerifiedObject>,
    // Only the explicit fixture uses in-memory package authority.
    packages: HashMap<RepositoryPath, ObjectIdentity>,
    derived: HashMap<RepositoryPath, DerivedDescriptor>,
    derived_by_hash: HashMap<ByHashKey, DerivedDescriptor>,
}

/// One published generation.
#[derive(Debug, Clone)]
pub struct ActiveView {
    pub repository: String,
    pub suite: String,
    /// SHA-256 of the exact InRelease or Pacman database bytes.
    pub generation_id: Sha256Digest,
    /// Signed Release date; Pacman retains a descriptive max package build time,
    /// never a cryptographic revision or freshness bound.
    pub release_date: UnixTime,
    /// Exact signed metadata content or transport-candidate database content digest.
    pub content_sha256: Sha256Digest,
    /// Authenticated `Valid-Until`, if present.
    pub valid_until: Option<UnixTime>,
    /// Monotonic confirmation instant (freshness lease base).
    pub confirmed_at: Instant,
    /// Wall-clock confirmation time for health reporting.
    pub confirmed_at_unix: UnixTime,
    /// Lease length after which metadata is stale without reconfirmation.
    pub lease: Duration,
    expires_after: Duration,
    descriptors: Arc<Descriptors>,
}

impl ActiveView {
    #[must_use]
    pub fn with_lease(&self, lease: Duration) -> Self {
        let mut copy = self.clone();
        copy.lease = lease;
        copy.expires_after = lease;
        copy
    }
}

/// Inputs that build a view (the synchronizer fills them from authenticated data).
#[derive(Debug)]
pub struct ViewParts {
    pub generation_id: Sha256Digest,
    pub release_date: UnixTime,
    pub content_sha256: Sha256Digest,
    pub valid_until: Option<UnixTime>,
    pub confirmed_at: Instant,
    pub confirmed_at_unix: UnixTime,
    pub lease: Duration,
    pub metadata: HashMap<RepositoryPath, (VerifiedObject, CacheClass)>,
    pub by_hash: HashMap<ByHashKey, VerifiedObject>,
    pub packages: HashMap<RepositoryPath, ObjectIdentity>,
}

impl ActiveView {
    pub(crate) fn from_parts(parts: ViewParts) -> Self {
        Self {
            repository: "fixture".to_owned(),
            suite: SUITE.to_owned(),
            expires_after: expiry_bound(parts.valid_until, parts.confirmed_at_unix, parts.lease),
            generation_id: parts.generation_id,
            release_date: parts.release_date,
            content_sha256: parts.content_sha256,
            valid_until: parts.valid_until,
            confirmed_at: parts.confirmed_at,
            confirmed_at_unix: parts.confirmed_at_unix,
            lease: parts.lease,
            descriptors: Arc::new(Descriptors {
                metadata: parts.metadata,
                by_hash: parts.by_hash,
                packages: parts.packages,
                derived: HashMap::new(),
                derived_by_hash: HashMap::new(),
            }),
        }
    }

    /// Builds only from storage's authenticated publication proof. In particular,
    /// the detached Release retains its independently verified exact bytes: the
    /// cleartext payload may omit the terminal LF covered by Release.gpg.
    /// Durable activation is still required before Catalog can publish this view.
    pub fn from_generation(
        proof: &VerifiedHistoricalProof,
        confirmed_at: i64,
        lease: Duration,
    ) -> Result<Self, CheckpointError> {
        let manifest = proof.manifest();
        let release = proof.release();
        let is_pacman = matches!(
            manifest.repository.as_str(),
            "archlinux" | "chaotic-aur" | "cachyos" | "archlinuxcn" | "endeavouros"
        );
        let is_rpm = matches!(manifest.repository.as_str(), "almalinux" | "rockylinux");
        let generation_id = Sha256Digest::from_hex(&manifest.generation_id)
            .map_err(|_| CheckpointError::Invalid)?;
        if release.content_sha256().to_hex() != manifest.release_content_sha256
            || release.date.as_secs() != manifest.release_date
            || confirmed_at < 0
        {
            return Err(CheckpointError::Proof);
        }
        let wall = UnixTime::now();
        let age = wall
            .as_secs()
            .checked_sub(confirmed_at)
            .filter(|age| *age >= 0)
            .ok_or(CheckpointError::Proof)? as u64;
        let monotonic = Instant::now()
            .checked_sub(Duration::from_secs(age))
            .ok_or(CheckpointError::Proof)?;
        let mut view = Self::from_parts(ViewParts {
            generation_id,
            release_date: release.date,
            content_sha256: release.content_sha256(),
            valid_until: release.valid_until,
            confirmed_at: monotonic,
            confirmed_at_unix: UnixTime::from_secs(confirmed_at),
            lease,
            metadata: HashMap::new(),
            by_hash: HashMap::new(),
            packages: HashMap::new(),
        });
        view.repository.clone_from(&manifest.repository);
        view.suite.clone_from(&manifest.suite);
        let descriptors = Arc::make_mut(&mut view.descriptors);
        for artifact in &manifest.artifacts {
            // Canary objects are proof closure, not metadata serving authority.
            // Every Pacman package and .sig follows the package verifier path.
            if is_pacman && artifact.path != manifest.artifacts[0].path {
                continue;
            }
            let identity = artifact.identity()?;
            let object = proof
                .artifact(&artifact.path)
                .ok_or(CheckpointError::Proof)?
                .clone();
            let path = RepositoryPath::parse_decoded(&artifact.path)
                .map_err(|_| CheckpointError::Invalid)?;
            let mutable = if is_pacman {
                artifact.path.ends_with(".db")
            } else if is_rpm {
                artifact.path.ends_with("/repodata/repomd.xml")
                    || artifact.path.ends_with("/repodata/repomd.xml.asc")
            } else {
                matches!(
                    artifact.path.as_str(),
                    "InRelease" | "Release" | "Release.gpg"
                )
            };
            if mutable
                && (is_pacman
                    || artifact.path == "InRelease"
                    || artifact.path.ends_with("/repodata/repomd.xml"))
                && identity.sha256 != generation_id
            {
                return Err(CheckpointError::Proof);
            }
            if is_pacman || is_rpm || !mutable {
                if let Some(entry) = release.entry(&path) {
                    if entry.sha256 != Some(identity.sha256) || entry.size != identity.size {
                        return Err(CheckpointError::Proof);
                    }
                    if !is_pacman && !is_rpm {
                        for key in alias_keys(artifact.path.as_str(), entry.sha256, entry.sha512) {
                            descriptors.by_hash.insert(key, object.clone());
                        }
                    }
                } else if is_pacman || is_rpm || !ferrum_apt::pdiff::is_patch_path(path.as_str()) {
                    return Err(CheckpointError::Proof);
                }
                // Historical proof verification already checked every patch
                // against its same-generation authenticated Index. Patches
                // absent from Release have canonical authority, never aliases.
            }
            let public = if is_rpm {
                path
            } else {
                let public = if view.repository == "cachyos" {
                    format!(
                        "{}/{}/{}",
                        ferrum_apt::pacman::cachyos_suite_arch(&view.suite)
                            .ok_or(CheckpointError::Proof)?,
                        view.suite,
                        artifact
                            .path
                            .split_once('/')
                            .ok_or(CheckpointError::Proof)?
                            .1
                    )
                } else if is_pacman {
                    format!("{}/{}", view.suite, artifact.path)
                } else {
                    format!("dists/{}/{}", view.suite, artifact.path)
                };
                RepositoryPath::parse_decoded(&public).map_err(|_| CheckpointError::Invalid)?
            };
            descriptors.metadata.insert(
                public,
                (
                    object,
                    if mutable {
                        CacheClass::Mutable
                    } else {
                        CacheClass::Canonical
                    },
                ),
            );
        }
        for derived in &manifest.derived {
            let path = RepositoryPath::parse_decoded(&derived.path)
                .map_err(|_| CheckpointError::Invalid)?;
            let entry = release.entry(&path).ok_or(CheckpointError::Proof)?;
            let source = proof
                .artifact(&derived.source_path)
                .ok_or(CheckpointError::Proof)?;
            let descriptor = DerivedDescriptor {
                identity: ObjectIdentity {
                    sha256: entry.sha256.ok_or(CheckpointError::Proof)?,
                    size: entry.size,
                },
                source: source.clone(),
                source_path: derived.source_path.clone(),
            };
            if !is_pacman && !is_rpm {
                for key in alias_keys(&derived.path, entry.sha256, entry.sha512) {
                    descriptors.derived_by_hash.insert(key, descriptor.clone());
                }
            }
            let public = if is_pacman {
                format!("{}/{}", view.suite, derived.path)
            } else {
                format!("dists/{}/{}", view.suite, derived.path)
            };
            let public =
                RepositoryPath::parse_decoded(&public).map_err(|_| CheckpointError::Invalid)?;
            descriptors.derived.insert(public, descriptor);
        }
        Ok(view)
    }

    /// Test-only constructor: a view that authorizes `packages` and nothing else,
    /// fresh for `lease` from now, without any signature verification.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-harness"))]
    pub fn for_tests(packages: Vec<(RepositoryPath, ObjectIdentity)>, lease: Duration) -> Self {
        let generation_id = Sha256Digest::of(b"test-view");
        Self::from_parts(ViewParts {
            generation_id,
            release_date: UnixTime::now(),
            content_sha256: generation_id,
            valid_until: None,
            confirmed_at: Instant::now(),
            confirmed_at_unix: UnixTime::now(),
            lease,
            metadata: HashMap::new(),
            by_hash: HashMap::new(),
            packages: packages.into_iter().collect(),
        })
    }

    /// Same generation with a renewed confirmation (same objects, new lease base).
    pub(crate) fn renewed(&self, confirmed_at: Instant, confirmed_at_unix: UnixTime) -> Self {
        Self {
            repository: self.repository.clone(),
            suite: self.suite.clone(),
            generation_id: self.generation_id,
            release_date: self.release_date,
            content_sha256: self.content_sha256,
            valid_until: self.valid_until,
            confirmed_at,
            confirmed_at_unix,
            lease: self.lease,
            expires_after: expiry_bound(self.valid_until, confirmed_at_unix, self.lease),
            descriptors: Arc::clone(&self.descriptors),
        }
    }

    /// `now < min(valid_until, confirmed_at + lease)`: the live lease uses
    /// monotonic time; `Valid-Until` needs wall time.
    pub fn is_fresh(&self, now: Instant, wall_now: UnixTime) -> bool {
        let lease_alive = now
            .checked_duration_since(self.confirmed_at)
            .is_some_and(|elapsed| elapsed < self.lease && elapsed < self.expires_after);
        let valid = self
            .valid_until
            .is_none_or(|valid_until| wall_now < valid_until);
        lease_alive && valid
    }

    /// Resolves a path relative to the repository prefix.
    pub fn resolve(&self, rest: &str) -> Resolution {
        if let Some(below_dists) = rest
            .strip_prefix("dists/")
            .and_then(|tail| tail.strip_prefix(self.suite.as_str()))
            .and_then(|tail| tail.strip_prefix('/'))
            && let Some((directory, algorithm, hex)) = split_by_hash(below_dists)
        {
            let key = ByHashKey {
                directory: directory.to_owned(),
                algorithm,
                hex: hex.to_owned(),
            };
            return match (
                self.descriptors.by_hash.get(&key),
                self.descriptors.derived_by_hash.get(&key),
            ) {
                (Some(object), _) => Resolution::ByHash(object.clone()),
                (_, Some(descriptor)) => Resolution::Derived {
                    descriptor: descriptor.clone(),
                    class: CacheClass::ByHash,
                },
                _ => Resolution::Unknown,
            };
        }
        if let Ok(path) = RepositoryPath::parse_decoded(rest) {
            if let Some(descriptor) = self.descriptors.derived.get(&path) {
                return Resolution::Derived {
                    descriptor: descriptor.clone(),
                    class: CacheClass::Canonical,
                };
            }
            if let Some((object, class)) = self.descriptors.metadata.get(&path) {
                return Resolution::Metadata {
                    object: object.clone(),
                    class: *class,
                };
            }
            if let Some(identity) = self.descriptors.packages.get(&path) {
                return Resolution::Package {
                    identity: *identity,
                    path,
                };
            }
        }
        Resolution::Unknown
    }

    /// Number of authorized package paths.
    pub fn package_count(&self) -> usize {
        self.descriptors.packages.len()
    }

    /// Keep prior authenticated immutable aliases and reject ambiguous pool paths.
    pub(crate) fn retain_from(&mut self, previous: &Self) -> Result<(), RepositoryPath> {
        let descriptors = Arc::make_mut(&mut self.descriptors);
        for (path, identity) in &previous.descriptors.packages {
            if descriptors
                .packages
                .get(path)
                .is_some_and(|current| current != identity)
            {
                return Err(path.clone());
            }
            descriptors.packages.insert(path.clone(), *identity);
        }
        for (key, object) in &previous.descriptors.by_hash {
            descriptors
                .by_hash
                .entry(key.clone())
                .or_insert_with(|| object.clone());
        }
        Ok(())
    }
}

fn alias_keys(
    path: &str,
    sha256: Option<Sha256Digest>,
    sha512: Option<ferrum_apt::digest::Sha512Digest>,
) -> Vec<ByHashKey> {
    let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
    let mut keys = Vec::with_capacity(2);
    if let Some(digest) = sha256 {
        keys.push(ByHashKey {
            directory: directory.to_owned(),
            algorithm: HashAlgorithm::Sha256,
            hex: digest.to_hex(),
        });
    }
    if let Some(digest) = sha512 {
        keys.push(ByHashKey {
            directory: directory.to_owned(),
            algorithm: HashAlgorithm::Sha512,
            hex: digest.to_hex(),
        });
    }
    keys
}

fn expiry_bound(valid_until: Option<UnixTime>, confirmed: UnixTime, lease: Duration) -> Duration {
    valid_until.map_or(lease, |until| {
        let seconds = until.as_secs().saturating_sub(confirmed.as_secs()).max(0) as u64;
        lease.min(Duration::from_secs(seconds))
    })
}

/// Splits `<dir>/by-hash/<ALGO>/<hex>` into its parts.
pub(super) fn split_by_hash(below_dists: &str) -> Option<(&str, HashAlgorithm, &str)> {
    let (directory, tail) = below_dists.strip_prefix("by-hash/").map_or_else(
        || below_dists.split_once("/by-hash/"),
        |tail| Some(("", tail)),
    )?;
    let (algorithm, hex) = tail.split_once('/')?;
    if hex.is_empty() || hex.contains('/') {
        return None;
    }
    let algorithm = HashAlgorithm::from_directory(algorithm)?;
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((directory, algorithm, hex))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn view() -> ActiveView {
        let path = RepositoryPath::parse_decoded("pool/main/f/x/x_1.0_all.deb").expect("path");
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(b"x"),
            size: 1,
        };
        ActiveView::for_tests(vec![(path, identity)], Duration::from_secs(60))
    }

    #[test]
    fn resolves_known_packages_and_rejects_the_rest() {
        let view = view();
        assert!(matches!(
            view.resolve("pool/main/f/x/x_1.0_all.deb"),
            Resolution::Package { .. }
        ));
        assert!(matches!(
            view.resolve("pool/other.deb"),
            Resolution::Unknown
        ));
        assert!(matches!(
            view.resolve("dists/ferrum-test/InRelease"),
            Resolution::Unknown
        ));
        assert!(matches!(
            view.resolve("dists/ferrum-test/main/binary-amd64/by-hash/SHA256/00ff"),
            Resolution::Unknown
        ));
    }

    #[test]
    fn by_hash_grammar() {
        assert!(split_by_hash("main/binary-amd64/by-hash/SHA256/abc").is_some());
        assert!(split_by_hash("main/binary-amd64/by-hash/SHA512/abc").is_some());
        assert!(split_by_hash("main/binary-amd64/by-hash/MD5Sum/abc").is_none());
        assert!(split_by_hash("main/binary-amd64/by-hash/SHA256/ab/c").is_none());
        assert!(split_by_hash("main/binary-amd64/by-hash/SHA256/xyz").is_none());
        assert!(split_by_hash("by-hash/SHA256/abc").is_some());
    }

    #[test]
    fn freshness_uses_lease_and_valid_until() {
        let mut view = view();
        let now = Instant::now();
        let wall = UnixTime::now();
        assert!(view.is_fresh(now, wall));
        assert!(!view.is_fresh(now + Duration::from_secs(61), wall));
        view.valid_until = Some(UnixTime::from_secs(wall.as_secs() - 1));
        assert!(!view.is_fresh(now, wall));
    }

    #[test]
    fn wall_rollback_cannot_resurrect_an_expired_monotonic_view() {
        let mut view = view();
        let wall = UnixTime::now();
        view.valid_until = Some(UnixTime::from_secs(wall.as_secs() + 2));
        let now = Instant::now();
        let view = view.renewed(now, wall);
        assert!(view.is_fresh(now, wall));
        assert!(!view.is_fresh(
            now + Duration::from_secs(3),
            UnixTime::from_secs(wall.as_secs() - 100)
        ));
    }

    #[test]
    fn retained_package_paths_reject_conflicts_and_keep_removed_authority() {
        let original = view();
        let path = RepositoryPath::parse_decoded("pool/main/f/x/x_1.0_all.deb").expect("path");
        let mut replacement = ActiveView::for_tests(
            vec![(
                path.clone(),
                ObjectIdentity {
                    sha256: Sha256Digest::of(b"different"),
                    size: 9,
                },
            )],
            Duration::from_secs(60),
        );
        assert_eq!(replacement.retain_from(&original), Err(path.clone()));
        let mut replacement = ActiveView::for_tests(Vec::new(), Duration::from_secs(60));
        replacement
            .retain_from(&original)
            .expect("retain immutable authorization");
        assert!(matches!(
            replacement.resolve(path.as_str()),
            Resolution::Package { .. }
        ));
    }

    #[test]
    fn renewal_shares_descriptors_and_fixture_retention_is_copy_on_write() {
        let original = view();
        let mut renewed = original.renewed(Instant::now(), UnixTime::now());
        assert!(Arc::ptr_eq(&original.descriptors, &renewed.descriptors));

        let path = RepositoryPath::parse_decoded("pool/main/y/y_1.0_all.deb").expect("path");
        let added = ActiveView::for_tests(
            vec![(
                path.clone(),
                ObjectIdentity {
                    sha256: Sha256Digest::of(b"y"),
                    size: 1,
                },
            )],
            Duration::from_secs(60),
        );
        renewed
            .retain_from(&added)
            .expect("retain new fixture authority");
        assert!(!Arc::ptr_eq(&original.descriptors, &renewed.descriptors));
        assert_eq!(original.package_count(), 1);
        assert_eq!(renewed.package_count(), 2);
        assert!(matches!(
            original.resolve(path.as_str()),
            Resolution::Unknown
        ));

        let mut replacement = ActiveView::for_tests(Vec::new(), Duration::from_secs(60));
        let unique = Arc::as_ptr(&replacement.descriptors);
        replacement
            .retain_from(&original)
            .expect("retain into unique candidate");
        assert_eq!(unique, Arc::as_ptr(&replacement.descriptors));
    }
}
