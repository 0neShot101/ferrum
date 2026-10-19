//! Fixed APT/Pacman suite slots and durable request authority. Fixture authority
//! cannot supply a fallback for configured durable routes.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use ferrum_apt::path::RepositoryPath;
use ferrum_apt::release::UnixTime;
use ferrum_apt::signature::SignatureVerifier;
use ferrum_storage::checkpoint::{
    CheckpointError, CheckpointPublisher, MetadataDescriptor, MetadataHash, PackageDescriptor,
    SuiteKey,
};
use ferrum_storage::recovery::VerifiedHistoricalProof;

use super::view::{
    ActiveView, CacheClass, DerivedDescriptor, HashAlgorithm, Resolution, split_by_hash,
};

struct SuiteSlot {
    key: SuiteKey,
    view: ArcSwapOption<ActiveView>,
}

pub struct Catalog {
    fixture: ArcSwapOption<ActiveView>,
    slots: Vec<SuiteSlot>,
    publisher: Option<Arc<CheckpointPublisher>>,
    last_error: Mutex<Option<String>>,
    clock: Mutex<(Option<UnixTime>, bool)>,
    package_signatures: Mutex<Option<PackageSignatureAuthority>>,
    synchronized: AtomicBool,
}

struct PackageSignatureAuthority {
    verifier: SignatureVerifier,
    keyrings: Vec<(SuiteKey, std::path::PathBuf)>,
}

pub(crate) struct AuthorizedRequest<'a> {
    pub repository: &'a str,
    pub view: Option<Arc<ActiveView>>,
    pub resolution: Resolution,
    pub package: Option<PackageDescriptor>,
    pub historical: Option<Arc<VerifiedHistoricalProof>>,
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            fixture: ArcSwapOption::empty(),
            slots: Vec::new(),
            publisher: None,
            last_error: Mutex::new(None),
            clock: Mutex::new((None, false)),
            package_signatures: Mutex::new(None),
            synchronized: AtomicBool::new(true),
        }
    }
}

impl Catalog {
    // Publication owns the verifier and installs its configured keyrings here;
    // request-time signatures must use the package's exact retained suite proof.
    pub(super) fn configure_package_signatures(
        &self,
        verifier: &SignatureVerifier,
        suites: &[crate::config::SuiteConfig],
    ) -> Result<(), CheckpointError> {
        let keyrings = suites
            .iter()
            .filter(|suite| suite.policy.is_pacman())
            .map(|suite| (suite.key.clone(), suite.policy.keyring().to_path_buf()))
            .collect();
        *self
            .package_signatures
            .lock()
            .map_err(|_| CheckpointError::Proof)? = Some(PackageSignatureAuthority {
            verifier: verifier.clone(),
            keyrings,
        });
        Ok(())
    }

    pub(crate) fn package_signature_authority(
        &self,
        package: &PackageDescriptor,
    ) -> Result<(SignatureVerifier, std::path::PathBuf), CheckpointError> {
        let authority = self
            .package_signatures
            .lock()
            .map_err(|_| CheckpointError::Proof)?;
        let authority = authority.as_ref().ok_or(CheckpointError::Proof)?;
        let manifest = package.proof().manifest();
        let (_, keyring) = authority
            .keyrings
            .iter()
            .find(|(key, _)| {
                key.repository() == manifest.repository && key.suite() == manifest.suite
            })
            .ok_or(CheckpointError::Proof)?;
        Ok((authority.verifier.clone(), keyring.clone()))
    }

    pub(crate) fn register_package_signature(
        &self,
        package: &PackageDescriptor,
        path: &RepositoryPath,
        identity: ferrum_apt::digest::ObjectIdentity,
    ) -> Result<PackageDescriptor, CheckpointError> {
        self.publisher
            .as_ref()
            .ok_or(CheckpointError::Invalid)?
            .register_verified_package_signature(package, path, identity)
    }

    /// Binds a newly registered descriptor to the originally requested public path.
    pub(crate) fn package_request<'a>(
        &self,
        path: &'a RepositoryPath,
        package: PackageDescriptor,
    ) -> Result<AuthorizedRequest<'a>, CheckpointError> {
        let (repository, relative) = path
            .as_str()
            .split_once('/')
            .ok_or(CheckpointError::Invalid)?;
        if repository != package.generation().repository || relative != package.path().as_str() {
            return Err(CheckpointError::Proof);
        }
        Ok(AuthorizedRequest {
            repository,
            view: None,
            resolution: Resolution::Package {
                identity: package.identity(),
                path: package.path().clone(),
            },
            package: Some(package),
            historical: None,
        })
    }

    /// The single-suite, exclusively private fixture authority.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn configured(
        keys: Vec<SuiteKey>,
        publisher: Arc<CheckpointPublisher>,
    ) -> Result<Self, CheckpointError> {
        if keys.is_empty() || keys.len() > ferrum_storage::checkpoint::MAX_SUITES {
            return Err(CheckpointError::Invalid);
        }
        let mut slots: Vec<SuiteSlot> = Vec::with_capacity(keys.len());
        for key in keys {
            let allowed = crate::config::ALL_DISTRIBUTION_SUITES.iter().any(|entry| {
                entry.repository.name() == key.repository() && entry.suite == key.suite()
            }) || (key.repository() == "fixture" && key.suite() == "ferrum-test");
            if !allowed || slots.iter().any(|slot| slot.key == key) {
                return Err(CheckpointError::Invalid);
            }
            slots.push(SuiteSlot {
                key,
                view: ArcSwapOption::empty(),
            });
        }
        Ok(Self {
            slots,
            publisher: Some(publisher),
            synchronized: AtomicBool::new(false),
            ..Self::default()
        })
    }

    pub fn is_fixture(&self) -> bool {
        self.slots.is_empty()
    }
    pub fn load(&self) -> Option<Arc<ActiveView>> {
        self.fixture.load_full()
    }
    pub fn publish(&self, view: ActiveView) {
        if self.is_fixture() {
            self.fixture.store(Some(Arc::new(view)));
        }
    }
    pub fn load_suite(&self, key: &SuiteKey) -> Option<Arc<ActiveView>> {
        self.slots
            .iter()
            .find(|slot| slot.key == *key)
            .and_then(|slot| slot.view.load_full())
    }
    pub fn publish_suite(&self, key: &SuiteKey, view: ActiveView) -> Result<(), CheckpointError> {
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.key == *key)
            .ok_or(CheckpointError::Invalid)?;
        if view.repository != key.repository() || view.suite != key.suite() {
            return Err(CheckpointError::Proof);
        }
        let state = self
            .publisher
            .as_ref()
            .ok_or(CheckpointError::Invalid)?
            .state(key)?;
        if state.blocked
            || state.pending.is_some()
            || state
                .active
                .as_ref()
                .is_none_or(|active| active.generation_id != view.generation_id.to_hex())
        {
            return Err(CheckpointError::Conflict);
        }
        slot.view.store(Some(Arc::new(view)));
        Ok(())
    }
    pub fn keys(&self) -> Vec<SuiteKey> {
        self.slots.iter().map(|slot| slot.key.clone()).collect()
    }
    pub fn publisher(&self) -> Option<&Arc<CheckpointPublisher>> {
        self.publisher.as_ref()
    }
    pub fn suite_available(&self, view: &ActiveView) -> bool {
        let Some(publisher) = &self.publisher else {
            return true;
        };
        let Ok(key) = SuiteKey::new(&view.repository, &view.suite) else {
            return false;
        };
        publisher
            .state(&key)
            .is_ok_and(|state| !state.blocked && state.pending.is_none() && state.active.is_some())
    }
    /// New requests/readiness must select the handle matching durable activation.
    /// Already held requests may finish on the prior, still-retained generation.
    pub fn current_view_available(&self, view: &ActiveView) -> bool {
        let Some(publisher) = &self.publisher else {
            return true;
        };
        let Ok(key) = SuiteKey::new(&view.repository, &view.suite) else {
            return false;
        };
        publisher.state(&key).is_ok_and(|state| {
            !state.blocked
                && state.pending.is_none()
                && state
                    .active
                    .is_some_and(|active| active.generation_id == view.generation_id.to_hex())
        })
    }
    pub fn clock_valid(&self) -> bool {
        let now = UnixTime::now();
        let mut clock = self.clock.lock().unwrap_or_else(|error| error.into_inner());
        if clock.0.is_some_and(|previous| now < previous) {
            clock.1 = true;
        }
        clock.0 = Some(now);
        !clock.1 && self.synchronized.load(Ordering::Acquire)
    }
    pub(crate) fn set_clock_synchronized(&self, synchronized: bool) {
        self.synchronized.store(synchronized, Ordering::Release);
    }
    #[cfg(feature = "test-harness")]
    pub fn set_test_clock_synchronized(&self, synchronized: bool) {
        self.set_clock_synchronized(synchronized);
    }
    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
    pub(super) fn set_last_error(&self, error: Option<String>) {
        *self
            .last_error
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            error.map(|text| super::truncate(text, 256));
    }

    #[cfg(test)]
    pub(crate) fn for_suite_tests(views: Vec<(SuiteKey, ActiveView)>) -> Self {
        Self {
            slots: views
                .into_iter()
                .map(|(key, view)| SuiteSlot {
                    key,
                    view: ArcSwapOption::from(Some(Arc::new(view))),
                })
                .collect(),
            ..Self::default()
        }
    }

    pub(crate) async fn resolve<'a>(
        &self,
        path: &'a RepositoryPath,
        fixture_prefix: &RepositoryPath,
    ) -> Result<Option<AuthorizedRequest<'a>>, CheckpointError> {
        if self.is_fixture() {
            let Some(rest) = path.strip_prefix(fixture_prefix) else {
                return Ok(None);
            };
            let view = self.load().ok_or(CheckpointError::Proof)?;
            return Ok(Some(AuthorizedRequest {
                repository: "fixture",
                resolution: view.resolve(rest),
                view: Some(view),
                package: None,
                historical: None,
            }));
        }
        let Some((repository, rest)) = path.as_str().split_once('/') else {
            return Ok(None);
        };
        let is_pacman = matches!(
            repository,
            "archlinux" | "chaotic-aur" | "cachyos" | "archlinuxcn" | "endeavouros"
        );
        let is_rpm = matches!(repository, "almalinux" | "rockylinux");
        if !self
            .slots
            .iter()
            .any(|slot| slot.key.repository() == repository)
        {
            return Ok(None);
        }
        if ferrum_storage::capture::is_package_path(rest) {
            let publisher = self.publisher.as_ref().ok_or(CheckpointError::Invalid)?;
            let package_path =
                RepositoryPath::parse_decoded(rest).map_err(|_| CheckpointError::Invalid)?;
            let Some(package) = publisher.lookup_package(repository, &package_path)? else {
                return Ok(None);
            };
            return Ok(Some(AuthorizedRequest {
                repository,
                view: None,
                resolution: Resolution::Package {
                    identity: package.identity(),
                    path: package_path,
                },
                package: Some(package),
                historical: None,
            }));
        }
        let suite_path = if is_rpm {
            ferrum_apt::rpm::split_rpm_suite_path(rest)
        } else if repository == "cachyos" {
            rest.strip_prefix("x86_64/")
                .and_then(|tail| tail.split_once('/'))
        } else if is_pacman {
            rest.split_once('/')
        } else {
            rest.strip_prefix("dists/")
                .and_then(|tail| tail.split_once('/'))
        };
        let Some((suite, relative)) = suite_path else {
            return Ok(None);
        };
        let Some(slot) = self
            .slots
            .iter()
            .find(|slot| slot.key.repository() == repository && slot.key.suite() == suite)
        else {
            return Ok(None);
        };
        let Some(publisher) = &self.publisher else {
            #[cfg(test)]
            {
                let view = slot.view.load_full().ok_or(CheckpointError::Proof)?;
                return Ok(Some(AuthorizedRequest {
                    repository,
                    resolution: view.resolve(rest),
                    view: Some(view),
                    package: None,
                    historical: None,
                }));
            }
            #[cfg(not(test))]
            return Err(CheckpointError::Proof);
        };
        let relative = if is_rpm {
            let root = ferrum_apt::rpm::rpm_suite_root(suite).ok_or(CheckpointError::Invalid)?;
            std::borrow::Cow::Owned(format!("{root}/{relative}"))
        } else if repository == "cachyos" {
            std::borrow::Cow::Owned(format!("x86_64/{relative}"))
        } else {
            std::borrow::Cow::Borrowed(relative)
        };
        if let Some((directory, algorithm, hex)) = split_by_hash(&relative) {
            let hash = match algorithm {
                HashAlgorithm::Sha256 => match ferrum_apt::digest::Sha256Digest::from_hex(hex) {
                    Ok(digest) => MetadataHash::Sha256(digest),
                    Err(_) => return Ok(None),
                },
                HashAlgorithm::Sha512 => match ferrum_apt::digest::Sha512Digest::from_hex(hex) {
                    Ok(digest) => MetadataHash::Sha512(digest),
                    Err(_) => return Ok(None),
                },
            };
            let Some(descriptor) = publisher.lookup_by_hash(&slot.key, directory, hash)? else {
                return Ok(None);
            };
            let historical = Some(descriptor.proof());
            return Ok(Some(AuthorizedRequest {
                repository,
                view: None,
                resolution: metadata_resolution(&descriptor, CacheClass::ByHash),
                package: None,
                historical,
            }));
        }
        if relative.contains("by-hash/") {
            return Ok(None);
        }
        let view = slot.view.load_full().ok_or(CheckpointError::Proof)?;
        if !self.current_view_available(&view) {
            return Err(CheckpointError::Conflict);
        }
        let relative =
            RepositoryPath::parse_decoded(&relative).map_err(|_| CheckpointError::Invalid)?;
        let Some(descriptor) = publisher.lookup_metadata(&slot.key, &relative)? else {
            return Ok(None);
        };
        let proof = descriptor.proof();
        if proof.manifest().generation_id != view.generation_id.to_hex() {
            return Err(CheckpointError::Conflict);
        }
        let class = if matches!(relative.as_str(), "InRelease" | "Release" | "Release.gpg")
            || relative.as_str().ends_with(".db")
            || relative.as_str().ends_with("/repodata/repomd.xml")
            || relative.as_str().ends_with("/repodata/repomd.xml.asc")
        {
            CacheClass::Mutable
        } else {
            CacheClass::Canonical
        };
        Ok(Some(AuthorizedRequest {
            repository,
            view: Some(view),
            resolution: metadata_resolution(&descriptor, class),
            package: None,
            historical: Some(proof),
        }))
    }
}

fn metadata_resolution(descriptor: &MetadataDescriptor, class: CacheClass) -> Resolution {
    if descriptor.is_derived() {
        Resolution::Derived {
            descriptor: DerivedDescriptor {
                identity: descriptor.identity(),
                source: descriptor.source().clone(),
                source_path: descriptor.source_path().to_owned(),
            },
            class,
        }
    } else if class == CacheClass::ByHash {
        Resolution::ByHash(descriptor.source().clone())
    } else {
        Resolution::Metadata {
            object: descriptor.source().clone(),
            class,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn clock_failure_remains_latched() {
        let catalog = Catalog::new();
        *catalog.clock.lock().expect("clock") = (
            Some(UnixTime::from_secs(UnixTime::now().as_secs() + 100)),
            false,
        );
        assert!(!catalog.clock_valid());
        catalog.set_clock_synchronized(false);
        catalog.set_clock_synchronized(true);
        assert!(!catalog.clock_valid());
    }

    #[test]
    fn unsynchronized_clock_blocks_mutable_service_until_probe_recovers() {
        let catalog = Catalog::new();
        catalog.set_clock_synchronized(false);
        assert!(!catalog.clock_valid());
        catalog.set_clock_synchronized(true);
        assert!(catalog.clock_valid());
    }

    #[test]
    fn fixture_error_text_is_bounded_on_unicode_boundaries() {
        let catalog = Catalog::new();
        catalog.set_last_error(Some("é".repeat(1000)));
        assert_eq!(catalog.last_error().expect("bounded error").len(), 256);
    }
}
