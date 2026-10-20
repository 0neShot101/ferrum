//! Private fixture and explicitly configured durable distribution storage.
//!
//! Durable mode fixes distribution origins and uses explicit operator-owned
//! distribution keyrings and NONISOLATED storage identities. Public mode requires
//! an explicit hostname and external TLS boundary; no mode resets unknown usage.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Loopback-only signed fixture mode without durable distribution state.
pub const MODE_PRIVATE_FIXTURE: &str = "private-fixture";
/// Durable distribution integration remains private and loopback-only.
pub const MODE_PRIVATE_DURABLE: &str = "private-durable";
/// A durable, qualified fixture uses the same publication/capture pipeline.
pub const MODE_PRIVATE_DURABLE_FIXTURE: &str = "private-durable-fixture";
/// Public durable distribution mode behind the local Nginx TLS boundary.
pub const MODE_PUBLIC_DURABLE: &str = "public-durable";
/// Repository prefix served below the public listener (`/fixture/...`).
pub const REPOSITORY_PREFIX: &str = "fixture";
/// Suite directory below `dists/`.
pub const SUITE: &str = "ferrum-test";
/// The single selected component.
pub const COMPONENT: &str = "main";
/// The single selected binary architecture.
pub const ARCHITECTURE: &str = "amd64";
/// Required `Origin` field of the authenticated Release.
pub const RELEASE_ORIGIN: &str = "FerrumTest";
/// Required `Codename` field of the authenticated Release.
pub const RELEASE_CODENAME: &str = "ferrum-test";
/// Fixture origin base URL (loopback fault-injectable origin).
pub const ORIGIN_BASE_URL: &str = "http://127.0.0.1:18080/fixture/";
/// Largest control file (InRelease, Release, Release.gpg, Packages) accepted.
pub const MAX_METADATA_BYTES: u64 = 32 * 1024 * 1024;
/// Byte limit for raw request paths (§3.1: longer targets answer 414).
pub const MAX_REQUEST_PATH_BYTES: usize = 8 * 1024;
/// Byte limit for the request head (§3.1: larger heads answer 431).
pub const MAX_REQUEST_HEAD_BYTES: usize = 16 * 1024;

mod admin;
mod distribution;
pub use admin::AdminConfig;
pub use distribution::{
    ALL_DISTRIBUTION_SUITES, DEFAULT_DISTRIBUTION_SUITES, DistributionSuite, Repository,
};

/// Resolves an optional `durable.suites` list against the fixed distribution allowlist.
pub fn resolve_distribution_suites(
    configured: Option<&[String]>,
) -> Result<Vec<DistributionSuite>, String> {
    let Some(entries) = configured else {
        return Ok(DEFAULT_DISTRIBUTION_SUITES.to_vec());
    };
    if entries.is_empty() {
        return Err("must not be empty".into());
    }
    if entries.len() > ferrum_storage::checkpoint::MAX_SUITES {
        return Err(format!(
            "must contain at most {} suites",
            ferrum_storage::checkpoint::MAX_SUITES
        ));
    }
    if entries.len() == 1 && entries[0] == "all" {
        return Ok(ALL_DISTRIBUTION_SUITES.to_vec());
    }
    let mut selected = Vec::with_capacity(entries.len());
    for item in entries {
        let Some((repository, suite)) = item.split_once('/') else {
            return Err(format!(
                "invalid suite {item:?}; expected <repository>/<suite>"
            ));
        };
        let Some(&matched) = ALL_DISTRIBUTION_SUITES
            .iter()
            .find(|entry| entry.repository.name() == repository && entry.suite == suite)
        else {
            return Err(format!("unsupported distribution suite {item:?}"));
        };
        if selected.contains(&matched) {
            return Err(format!("duplicate suite {item:?}"));
        }
        selected.push(matched);
    }
    Ok(selected)
}

/// Resolves disjoint serving and retained-trust selections without dropping identities.
pub fn resolve_suite_selection(
    configured: Option<&[String]>,
    retired: &[String],
) -> Result<(Vec<DistributionSuite>, Vec<DistributionSuite>), String> {
    if retired.iter().any(|entry| entry == "all") {
        return Err("retired_suites requires explicit <repository>/<suite> identities".into());
    }

    let retired = if retired.is_empty() {
        Vec::new()
    } else {
        resolve_distribution_suites(Some(retired))?
    };
    let active = if configured.is_some_and(|entries| entries.is_empty()) && !retired.is_empty() {
        Vec::new()
    } else {
        resolve_distribution_suites(configured)?
    };

    if active.iter().any(|entry| retired.contains(entry)) {
        return Err(
            "suites and retired_suites must not overlap; move each identity between lists".into(),
        );
    }
    if active.len() + retired.len() > ferrum_storage::checkpoint::MAX_SUITES {
        return Err("combined active and retired selection exceeds the suite limit".into());
    }

    Ok((active, retired))
}

/// Why a configuration file was refused, without retaining raw configuration text.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("configuration is invalid TOML or contains missing or unsupported fields")]
    Parse,
    #[error("mode {found:?} is not supported")]
    UnsupportedMode { found: String },
    #[error("{field} must be a loopback address, got {address}")]
    NotLoopback {
        field: &'static str,
        address: SocketAddr,
    },
    #[error("{field}: {reason}")]
    Invalid { field: &'static str, reason: String },
}

/// Validated gateway configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: Listen,
    pub fixture: Fixture,
    pub verifier: Verifier,
    pub limits: Limits,
    pub admin: AdminConfig,
    /// Optional private fixture rehydration, separate from durable distribution storage.
    pub s3: Option<ferrum_storage::s3::PrivateS3Config>,
    /// Fixed in normal builds; only the opt-in integration harness may override it.
    pub(crate) origin_base: Url,
    durable: Option<DurableConfig>,
    public_durable: bool,
    source_path: Option<PathBuf>,
    base_dir: PathBuf,
    #[cfg(feature = "test-harness")]
    test_suites: Option<(Url, PathBuf)>,
}

#[derive(Debug, Clone)]
pub struct Listen {
    pub public: SocketAddr,
    pub admin: SocketAddr,
    pub public_host: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Fixture {
    /// Raw binary OpenPGP keyring for `ferrum-verifier --keyring` (absolute after load).
    pub keyring: PathBuf,
    /// Spool at `<work_dir>/spool`, scratch at `<work_dir>/scratch`.
    pub work_dir: PathBuf,
}

/// Fixed authenticated suite identity, shared by publication and routing.
#[derive(Debug, Clone)]
pub struct SuiteConfig {
    pub key: ferrum_storage::checkpoint::SuiteKey,
    pub policy: ferrum_storage::recovery::TrustPolicy,
    pub origin: Url,
}

#[derive(Debug, Clone)]
pub struct DurableConfig {
    pub state_dir: PathBuf,
    pub provider: ferrum_storage::s3::S3Config,
    pub budget: ferrum_storage::budget::BudgetLimits,
    pub qualification_run_id: Option<String>,
    pub trust: DurableTrust,
    pub suites: Option<Vec<String>>,
    /// Explicitly retained trust identities, never served or synchronized.
    pub retired_suites: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DistributionKeyrings {
    pub debian: PathBuf,
    pub ubuntu: PathBuf,
    pub kali: PathBuf,
    pub parrot: PathBuf,
    pub trisquel: PathBuf,
    pub raspberrypi: PathBuf,
    pub proxmox: PathBuf,
    pub archlinux: PathBuf,
    pub chaoticaur: PathBuf,
    pub docker: PathBuf,
    pub tailscale: PathBuf,
    pub postgresql: PathBuf,
    pub grafana: PathBuf,
    pub cachyos: PathBuf,
    pub archlinuxcn: PathBuf,
    pub endeavouros: PathBuf,
    pub almalinux: PathBuf,
    pub rockylinux: PathBuf,
}

#[derive(Debug, Clone)]
pub enum DurableTrust {
    Distributions(Box<DistributionKeyrings>),
    Fixture { keyring: PathBuf },
}

impl DurableConfig {
    pub fn store_config(&self) -> ferrum_storage::s3::S3Config {
        self.provider.clone()
    }
}

#[derive(Debug, Clone)]
pub struct Verifier {
    pub binary: PathBuf,
    pub timeout: Duration,
}

/// Operational limits (`PLAN.md` §0/§3/§4/§7); every field has the RFC default.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub managed_ceiling_bytes: u64,
    pub max_object_bytes: u64,
    pub waiter_timeout: Duration,
    pub producer_deadline: Duration,
    pub concurrent_fills: usize,
    pub waiters_per_object: usize,
    pub active_bodies: usize,
    pub request_slots: usize,
    pub reader_buffer_bytes: usize,
    pub connect_timeout: Duration,
    pub response_header_timeout: Duration,
    pub read_idle_timeout: Duration,
    pub admission_wait: Duration,
    pub source_attempts: u32,
    pub failure_backoff: Duration,
    pub failure_map_entries: usize,
    pub sync_interval: Duration,
    pub active_lease: Duration,
    pub body_write_idle: Duration,
    pub body_lifetime: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            managed_ceiling_bytes: 268_435_456,
            max_object_bytes: 67_108_864,
            waiter_timeout: Duration::from_secs(30),
            producer_deadline: Duration::from_secs(600),
            concurrent_fills: 8,
            waiters_per_object: 64,
            active_bodies: 256,
            request_slots: 1024,
            reader_buffer_bytes: 262_144,
            connect_timeout: Duration::from_secs(3),
            response_header_timeout: Duration::from_secs(10),
            read_idle_timeout: Duration::from_secs(30),
            admission_wait: Duration::from_secs(2),
            source_attempts: 2,
            failure_backoff: Duration::from_secs(30),
            failure_map_entries: 10_000,
            sync_interval: Duration::from_secs(300),
            active_lease: Duration::from_secs(24 * 3600),
            body_write_idle: Duration::from_secs(30),
            body_lifetime: Duration::from_secs(900),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    mode: String,
    listen: RawListen,
    fixture: Option<RawFixture>,
    durable: Option<RawDurable>,
    verifier: RawVerifier,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    admin: admin::RawAdmin,
    #[serde(default)]
    s3: Option<ferrum_storage::s3::PrivateS3Config>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListen {
    public: SocketAddr,
    admin: SocketAddr,
    public_host: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFixture {
    keyring: PathBuf,
    work_dir: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDurable {
    state_dir: PathBuf,
    provider: ferrum_storage::s3::S3Config,
    keyrings: Option<RawKeyrings>,
    fixture_keyring: Option<PathBuf>,
    qualification_run_id: Option<String>,
    suites: Option<Vec<String>>,
    #[serde(default)]
    retired_suites: Vec<String>,
    budget: RawBudget,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudget {
    mode: String,
    storage_bytes: Option<u64>,
    storage_control_bytes: Option<u64>,
    monthly_download_bytes: Option<u64>,
    download_control_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyrings {
    debian: PathBuf,
    ubuntu: PathBuf,
    kali: Option<PathBuf>,
    parrot: Option<PathBuf>,
    trisquel: Option<PathBuf>,
    raspberrypi: Option<PathBuf>,
    proxmox: Option<PathBuf>,
    archlinux: Option<PathBuf>,
    chaoticaur: Option<PathBuf>,
    docker: Option<PathBuf>,
    tailscale: Option<PathBuf>,
    postgresql: Option<PathBuf>,
    grafana: Option<PathBuf>,
    cachyos: Option<PathBuf>,
    archlinuxcn: Option<PathBuf>,
    endeavouros: Option<PathBuf>,
    almalinux: Option<PathBuf>,
    rockylinux: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVerifier {
    #[serde(default = "default_verifier_binary")]
    binary: PathBuf,
    #[serde(default = "default_verifier_timeout")]
    timeout_seconds: u64,
}

fn default_verifier_binary() -> PathBuf {
    PathBuf::from("ferrum-verifier")
}

fn default_verifier_timeout() -> u64 {
    30
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    managed_ceiling_bytes: Option<u64>,
    max_object_bytes: Option<u64>,
    waiter_timeout_seconds: Option<u64>,
    producer_deadline_seconds: Option<u64>,
    concurrent_fills: Option<usize>,
    waiters_per_object: Option<usize>,
    active_bodies: Option<usize>,
    request_slots: Option<usize>,
    reader_buffer_bytes: Option<usize>,
    connect_timeout_seconds: Option<u64>,
    response_header_timeout_seconds: Option<u64>,
    read_idle_timeout_seconds: Option<u64>,
    admission_wait_seconds: Option<u64>,
    source_attempts: Option<u32>,
    failure_backoff_seconds: Option<u64>,
    failure_map_entries: Option<usize>,
    sync_interval_seconds: Option<u64>,
    active_lease_hours: Option<u64>,
    body_write_idle_seconds: Option<u64>,
    body_lifetime_seconds: Option<u64>,
}

impl Config {
    /// Reads and validates `path`; relative fixture paths resolve against the
    /// file's directory.
    ///
    /// # Errors
    /// [`ConfigError`] naming the offending field.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let abs_path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let base = abs_path.parent().unwrap_or_else(|| Path::new("."));
        let mut config = Self::parse(&text, base)?;
        config.source_path = Some(abs_path);
        Ok(config)
    }

    /// Parses TOML text; relative fixture paths resolve against `base_dir`.
    ///
    /// # Errors
    /// A sanitized parse error or a failure naming the validated field.
    pub fn parse(text: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        // Parser diagnostics include source lines, which can contain misplaced credentials.
        let raw: RawConfig = toml::from_str(text).map_err(|_| ConfigError::Parse)?;
        if !matches!(
            raw.mode.as_str(),
            MODE_PRIVATE_FIXTURE
                | MODE_PRIVATE_DURABLE
                | MODE_PRIVATE_DURABLE_FIXTURE
                | MODE_PUBLIC_DURABLE
        ) {
            return Err(ConfigError::UnsupportedMode { found: raw.mode });
        }
        require_loopback("listen.public", raw.listen.public)?;
        require_loopback("listen.admin", raw.listen.admin)?;
        let public_durable = raw.mode == MODE_PUBLIC_DURABLE;
        let public_host = match raw.listen.public_host {
            Some(_) if !public_durable => {
                return Err(invalid(
                    "listen.public_host",
                    "is forbidden in private modes; use public-durable mode for a public host",
                ));
            }
            Some(host) => Some(validate_public_host(&host)?),
            None if public_durable => {
                return Err(invalid(
                    "listen.public_host",
                    "is required in public-durable mode",
                ));
            }
            None => None,
        };
        let durable_fixture = raw.mode == MODE_PRIVATE_DURABLE_FIXTURE;
        let durable = raw.mode != MODE_PRIVATE_FIXTURE;
        let limits = limits_from_raw(raw.limits, durable)?;
        let (fixture, durable) = if durable {
            if raw.fixture.is_some() || raw.s3.is_some() {
                return Err(invalid(
                    "durable",
                    "fixture and private S3 settings are forbidden",
                ));
            }
            let state = raw
                .durable
                .ok_or_else(|| invalid("durable", "is required"))?;
            if state.budget.mode != "existing" {
                return Err(invalid(
                    "durable.budget.mode",
                    "must be existing; unknown usage requires external operator reconciliation, never a reset",
                ));
            }
            let base_dir = if base_dir.is_absolute() {
                base_dir.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|source| ConfigError::Io {
                        path: base_dir.to_path_buf(),
                        source,
                    })?
                    .join(base_dir)
            };
            if let Some(run) = &state.qualification_run_id {
                if public_durable {
                    return Err(invalid(
                        "durable.qualification_run_id",
                        "is forbidden in public-durable mode",
                    ));
                }
                validate_qualification_run(run)?;
            }
            let trust = if durable_fixture {
                if state.keyrings.is_some()
                    || state.suites.is_some()
                    || !state.retired_suites.is_empty()
                {
                    return Err(invalid(
                        "durable.keyrings",
                        "distribution trust and suite lists are forbidden in durable fixture mode",
                    ));
                }
                if state.qualification_run_id.is_none() {
                    return Err(invalid(
                        "durable.qualification_run_id",
                        "is required in durable fixture mode",
                    ));
                }
                let keyring = state
                    .fixture_keyring
                    .ok_or_else(|| invalid("durable.fixture_keyring", "is required"))?;
                DurableTrust::Fixture {
                    keyring: base_dir.join(keyring),
                }
            } else {
                if state.fixture_keyring.is_some() {
                    return Err(invalid(
                        "durable.fixture_keyring",
                        "is forbidden in distribution mode",
                    ));
                }
                let keyrings = state.keyrings.ok_or_else(|| {
                    invalid(
                        "durable.keyrings",
                        "per-distribution operator keyrings are required",
                    )
                })?;
                let ubuntu_path = base_dir.join(keyrings.ubuntu);
                let sibling_dir = ubuntu_path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| base_dir.clone());
                let resolve_optional = |opt: Option<PathBuf>, default_name: &str| {
                    opt.map_or_else(|| sibling_dir.join(default_name), |p| base_dir.join(p))
                };
                DurableTrust::Distributions(Box::new(DistributionKeyrings {
                    debian: base_dir.join(keyrings.debian),
                    ubuntu: ubuntu_path,
                    kali: resolve_optional(keyrings.kali, "kali-archive-keyring.gpg"),
                    parrot: resolve_optional(keyrings.parrot, "parrot-archive-keyring.gpg"),
                    trisquel: resolve_optional(keyrings.trisquel, "trisquel-archive-keyring.gpg"),
                    raspberrypi: resolve_optional(
                        keyrings.raspberrypi,
                        "raspberrypi-archive-keyring.gpg",
                    ),
                    proxmox: resolve_optional(keyrings.proxmox, "proxmox-archive-keyring.gpg"),
                    archlinux: resolve_optional(keyrings.archlinux, "archlinux-keyring.gpg"),
                    chaoticaur: resolve_optional(keyrings.chaoticaur, "chaotic-keyring.gpg"),
                    docker: resolve_optional(keyrings.docker, "docker-archive-keyring.gpg"),
                    tailscale: resolve_optional(
                        keyrings.tailscale,
                        "tailscale-archive-keyring.gpg",
                    ),
                    postgresql: resolve_optional(
                        keyrings.postgresql,
                        "postgresql-archive-keyring.gpg",
                    ),
                    grafana: resolve_optional(keyrings.grafana, "grafana-archive-keyring.gpg"),
                    cachyos: resolve_optional(keyrings.cachyos, "cachyos-keyring.gpg"),
                    archlinuxcn: resolve_optional(keyrings.archlinuxcn, "archlinuxcn-keyring.gpg"),
                    endeavouros: resolve_optional(keyrings.endeavouros, "endeavouros-keyring.gpg"),
                    almalinux: resolve_optional(keyrings.almalinux, "almalinux-keyring.gpg"),
                    rockylinux: resolve_optional(keyrings.rockylinux, "rockylinux-keyring.gpg"),
                }))
            };
            if !durable_fixture {
                resolve_suite_selection(state.suites.as_deref(), &state.retired_suites)
                    .map_err(|reason| invalid("durable.suites", reason))?;
            }
            let defaults = ferrum_storage::budget::BudgetLimits::default();
            let budget = ferrum_storage::budget::BudgetLimits {
                storage: positive(
                    "durable.budget.storage_bytes",
                    state.budget.storage_bytes,
                    defaults.storage,
                )?,
                storage_control: positive(
                    "durable.budget.storage_control_bytes",
                    state.budget.storage_control_bytes,
                    defaults.storage_control,
                )?,
                monthly_download: positive(
                    "durable.budget.monthly_download_bytes",
                    state.budget.monthly_download_bytes,
                    defaults.monthly_download,
                )?,
                download_control: positive(
                    "durable.budget.download_control_bytes",
                    state.budget.download_control_bytes,
                    defaults.download_control,
                )?,
            };
            if budget.storage_control >= budget.storage
                || budget.download_control >= budget.monthly_download
            {
                return Err(invalid(
                    "durable.budget",
                    "control headroom must be smaller than its total ceiling",
                ));
            }
            let mut provider = state.provider;
            provider.credentials_file = base_dir.join(provider.credentials_file);
            provider
                .validate()
                .map_err(|error| invalid("durable.provider", error.to_string()))?;
            let state = DurableConfig {
                state_dir: base_dir.join(state.state_dir),
                provider,
                qualification_run_id: state.qualification_run_id,
                trust,
                suites: state.suites,
                retired_suites: state.retired_suites,
                budget,
            };
            let keyrings_absolute = match &state.trust {
                DurableTrust::Distributions(keyrings) => {
                    let DistributionKeyrings {
                        debian,
                        ubuntu,
                        kali,
                        parrot,
                        trisquel,
                        raspberrypi,
                        proxmox,
                        archlinux,
                        chaoticaur,
                        docker,
                        tailscale,
                        postgresql,
                        grafana,
                        cachyos,
                        archlinuxcn,
                        endeavouros,
                        almalinux,
                        rockylinux,
                    } = keyrings.as_ref();
                    debian.is_absolute()
                        && ubuntu.is_absolute()
                        && kali.is_absolute()
                        && parrot.is_absolute()
                        && trisquel.is_absolute()
                        && raspberrypi.is_absolute()
                        && proxmox.is_absolute()
                        && archlinux.is_absolute()
                        && chaoticaur.is_absolute()
                        && docker.is_absolute()
                        && tailscale.is_absolute()
                        && postgresql.is_absolute()
                        && grafana.is_absolute()
                        && cachyos.is_absolute()
                        && archlinuxcn.is_absolute()
                        && endeavouros.is_absolute()
                        && almalinux.is_absolute()
                        && rockylinux.is_absolute()
                }
                DurableTrust::Fixture { keyring } => keyring.is_absolute(),
            };
            if !state.state_dir.is_absolute()
                || !state.provider.credentials_file.is_absolute()
                || !keyrings_absolute
            {
                return Err(invalid(
                    "durable",
                    "state, credentials and keyrings must resolve to absolute paths",
                ));
            }
            // Fixture compatibility fields never select distribution trust.
            let keyring = match &state.trust {
                DurableTrust::Distributions(keyrings) => keyrings.debian.clone(),
                DurableTrust::Fixture { keyring } => keyring.clone(),
            };
            (
                Fixture {
                    keyring,
                    work_dir: state.state_dir.clone(),
                },
                Some(state),
            )
        } else {
            if raw.durable.is_some() {
                return Err(invalid("durable", "is forbidden in fixture mode"));
            }
            let fixture = raw
                .fixture
                .ok_or_else(|| invalid("fixture", "is required"))?;
            (
                Fixture {
                    keyring: base_dir.join(fixture.keyring),
                    work_dir: base_dir.join(fixture.work_dir),
                },
                None,
            )
        };
        if raw.verifier.timeout_seconds == 0 || raw.verifier.timeout_seconds > 30 {
            return Err(invalid("verifier.timeout_seconds", "must be in 1..=30"));
        }
        let origin_base = Url::parse(ORIGIN_BASE_URL)
            .map_err(|error| invalid("origin", format!("constant origin URL: {error}")))?;
        let spool = durable.as_ref().map_or_else(
            || fixture.work_dir.join("spool"),
            |durable| durable.state_dir.clone(),
        );
        let admin = AdminConfig::resolve(
            raw.admin,
            base_dir,
            &spool,
            &fixture.work_dir.join("scratch"),
            raw.listen.admin,
        )?;
        Ok(Self {
            listen: Listen {
                public: raw.listen.public,
                admin: raw.listen.admin,
                public_host,
            },
            admin,
            fixture,
            durable,
            public_durable,
            #[cfg(feature = "test-harness")]
            test_suites: None,
            verifier: Verifier {
                binary: raw.verifier.binary,
                timeout: Duration::from_secs(raw.verifier.timeout_seconds),
            },
            limits,
            s3: raw.s3,
            origin_base,
            source_path: None,
            base_dir: base_dir.to_path_buf(),
        })
    }
    /// Selects an ephemeral loopback fixture origin in integration-test builds.
    #[cfg(feature = "test-harness")]
    pub fn set_test_origin(&mut self, origin: Url) -> Result<(), ConfigError> {
        if !self.is_fixture() {
            return Err(invalid(
                "test origin",
                "only fixture mode permits a test origin",
            ));
        }
        let loopback = origin
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if origin.scheme() != "http"
            || !loopback
            || origin.path() != "/fixture/"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(invalid(
                "test origin",
                "must be a loopback HTTP fixture URL",
            ));
        }
        self.origin_base = origin;
        Ok(())
    }

    /// Explicit loopback-only distribution harness; production TOML cannot set it.
    #[cfg(feature = "test-harness")]
    pub fn set_test_suite_origins(
        &mut self,
        base: Url,
        keyring: PathBuf,
    ) -> Result<(), ConfigError> {
        let loopback = base
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if self.is_fixture()
            || self.is_durable_fixture()
            || base.scheme() != "http"
            || !loopback
            || !base.path().ends_with('/')
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !keyring.is_absolute()
        {
            return Err(invalid(
                "test suites",
                "requires durable mode, a loopback HTTP base and an absolute test keyring",
            ));
        }
        self.test_suites = Some((base, keyring));
        Ok(())
    }

    pub(crate) fn validate_runtime(&self) -> Result<(), ConfigError> {
        require_loopback("listen.public", self.listen.public)?;
        require_loopback("listen.admin", self.listen.admin)?;
        self.admin
            .validate_separation(&self.spool_dir(), &self.scratch_dir(), true)?;
        match &self.listen.public_host {
            Some(host) if self.public_durable => {
                validate_public_host(host)?;
            }
            None if !self.public_durable => {}
            _ => {
                return Err(invalid(
                    "listen.public_host",
                    "must be set only in public-durable mode",
                ));
            }
        }
        validate_limits(&self.limits, self.durable.is_some())?;
        if let Some(s3) = &self.s3 {
            s3.validate_separation(&self.spool_dir(), &self.scratch_dir())
                .map_err(|error| {
                    invalid(
                        "s3.transfer_journal",
                        format!("must be physically separate from spool/scratch, without symlink ancestors or parent traversal: {error}"),
                    )
                })?;
        }
        if self.verifier.timeout.is_zero() || self.verifier.timeout > Duration::from_secs(30) {
            return Err(invalid("verifier.timeout_seconds", "must be in 1..=30"));
        }
        #[cfg(not(feature = "test-harness"))]
        if self.is_fixture() && self.origin_base.as_str() != ORIGIN_BASE_URL {
            return Err(invalid("origin", "must be the fixed fixture origin"));
        }
        if let Some(durable) = &self.durable {
            durable
                .provider
                .validate()
                .map_err(|error| invalid("durable.provider", error.to_string()))?;
            if let Some(run) = &durable.qualification_run_id {
                if self.is_public() {
                    return Err(invalid(
                        "durable.qualification_run_id",
                        "is forbidden in public-durable mode",
                    ));
                }
                validate_qualification_run(run)?;
            }
        }
        Ok(())
    }

    pub fn is_fixture(&self) -> bool {
        self.durable.is_none()
    }

    pub fn is_durable_fixture(&self) -> bool {
        matches!(
            self.durable.as_ref().map(|durable| &durable.trust),
            Some(DurableTrust::Fixture { .. })
        )
    }

    pub fn is_public(&self) -> bool {
        self.public_durable
    }

    pub fn durable(&self) -> Option<&DurableConfig> {
        self.durable.as_ref()
    }

    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn set_source_path(&mut self, path: PathBuf) {
        if let Some(parent) = path.parent() {
            self.base_dir = parent.to_path_buf();
        }
        self.source_path = Some(path);
    }

    /// Fixed identities actively served and synchronized; TOML cannot add routes.
    pub fn suites(&self) -> Result<Vec<SuiteConfig>, ConfigError> {
        self.selected_suites(false)
    }

    /// Active and explicitly retired identities used for recovery and capture trust.
    pub fn trust_suites(&self) -> Result<Vec<SuiteConfig>, ConfigError> {
        self.selected_suites(true)
    }

    fn selected_suites(&self, include_retired: bool) -> Result<Vec<SuiteConfig>, ConfigError> {
        use ferrum_storage::checkpoint::SuiteKey;
        use ferrum_storage::recovery::TrustPolicy;
        if self.is_fixture() {
            return Ok(vec![SuiteConfig {
                key: SuiteKey::new(REPOSITORY_PREFIX, SUITE)
                    .map_err(|error| invalid("suite", error.to_string()))?,
                policy: TrustPolicy::LoopbackFixture {
                    keyring: self.fixture.keyring.clone(),
                },
                origin: self.origin_base.clone(),
            }]);
        }
        let durable = self
            .durable
            .as_ref()
            .ok_or_else(|| invalid("durable", "is required"))?;
        let (
            debian_keyring,
            ubuntu_keyring,
            kali_keyring,
            parrot_keyring,
            trisquel_keyring,
            rpi_keyring,
            proxmox_keyring,
            archlinux_keyring,
            chaoticaur_keyring,
            docker_keyring,
            tailscale_keyring,
            postgresql_keyring,
            grafana_keyring,
            cachyos_keyring,
            archlinuxcn_keyring,
            endeavouros_keyring,
            almalinux_keyring,
            rockylinux_keyring,
        ) = match &durable.trust {
            DurableTrust::Fixture { keyring } => {
                return Ok(vec![SuiteConfig {
                    key: SuiteKey::new(REPOSITORY_PREFIX, SUITE)
                        .map_err(|error| invalid("suite", error.to_string()))?,
                    policy: TrustPolicy::LoopbackFixture {
                        keyring: keyring.clone(),
                    },
                    origin: Url::parse(ORIGIN_BASE_URL)
                        .map_err(|error| invalid("origin", error.to_string()))?,
                }]);
            }
            DurableTrust::Distributions(keyrings) => (
                &keyrings.debian,
                &keyrings.ubuntu,
                &keyrings.kali,
                &keyrings.parrot,
                &keyrings.trisquel,
                &keyrings.raspberrypi,
                &keyrings.proxmox,
                &keyrings.archlinux,
                &keyrings.chaoticaur,
                &keyrings.docker,
                &keyrings.tailscale,
                &keyrings.postgresql,
                &keyrings.grafana,
                &keyrings.cachyos,
                &keyrings.archlinuxcn,
                &keyrings.endeavouros,
                &keyrings.almalinux,
                &keyrings.rockylinux,
            ),
        };
        let (mut selected, retired) =
            resolve_suite_selection(durable.suites.as_deref(), &durable.retired_suites)
                .map_err(|reason| invalid("durable.suites", reason))?;
        if include_retired {
            selected.extend(retired);
        }
        selected
            .into_iter()
            .map(|entry| {
                let repository = entry.repository.name();
                let suite = entry.suite;
                let keyring = match repository {
                    "ubuntu" | "ubuntu-security" | "ubuntu-ports" => ubuntu_keyring,
                    "kali" => kali_keyring,
                    "parrot" => parrot_keyring,
                    "trisquel" => trisquel_keyring,
                    "raspberrypi" => rpi_keyring,
                    "proxmox-pve" | "proxmox-pbs" => proxmox_keyring,
                    "archlinux" => archlinux_keyring,
                    "chaotic-aur" => chaoticaur_keyring,
                    "docker-debian" | "docker-ubuntu" => docker_keyring,
                    "tailscale-debian" | "tailscale-ubuntu" => tailscale_keyring,
                    "postgresql-apt" => postgresql_keyring,
                    "grafana-apt" => grafana_keyring,
                    "cachyos" => cachyos_keyring,
                    "archlinuxcn" => archlinuxcn_keyring,
                    "endeavouros" => endeavouros_keyring,
                    "almalinux" => almalinux_keyring,
                    "rockylinux" => rockylinux_keyring,
                    _ => debian_keyring,
                };
                let origin = Url::parse(entry.repository.origin())
                    .map_err(|error| invalid("origin", error.to_string()))?;
                #[cfg(feature = "test-harness")]
                let (origin, keyring) = if let Some((base, test_keyring)) = &self.test_suites {
                    (
                        base.join(&format!("{repository}/"))
                            .map_err(|error| invalid("test suites", error.to_string()))?,
                        test_keyring,
                    )
                } else {
                    (origin, keyring)
                };
                let policy = match repository {
                    "ubuntu-ports" => TrustPolicy::UbuntuPorts {
                        keyring: keyring.clone(),
                    },
                    "docker-debian" => TrustPolicy::DockerDebian {
                        keyring: keyring.clone(),
                    },
                    "docker-ubuntu" => TrustPolicy::DockerUbuntu {
                        keyring: keyring.clone(),
                    },
                    "tailscale-debian" => TrustPolicy::TailscaleDebian {
                        keyring: keyring.clone(),
                    },
                    "tailscale-ubuntu" => TrustPolicy::TailscaleUbuntu {
                        keyring: keyring.clone(),
                    },
                    "postgresql-apt" => TrustPolicy::PostgresqlApt {
                        keyring: keyring.clone(),
                    },
                    "grafana-apt" => TrustPolicy::GrafanaApt {
                        keyring: keyring.clone(),
                    },
                    "cachyos" => TrustPolicy::CachyOs {
                        keyring: keyring.clone(),
                    },
                    "archlinuxcn" => TrustPolicy::ArchLinuxCn {
                        keyring: keyring.clone(),
                    },
                    "endeavouros" => TrustPolicy::EndeavourOs {
                        keyring: keyring.clone(),
                    },
                    "almalinux" => TrustPolicy::AlmaLinux {
                        keyring: keyring.clone(),
                    },
                    "rockylinux" => TrustPolicy::RockyLinux {
                        keyring: keyring.clone(),
                    },
                    "archlinux" => TrustPolicy::ArchLinux {
                        keyring: keyring.clone(),
                    },
                    "chaotic-aur" => TrustPolicy::ChaoticAur {
                        keyring: keyring.clone(),
                    },
                    "ubuntu" | "ubuntu-security" => TrustPolicy::Ubuntu {
                        keyring: keyring.clone(),
                    },
                    "kali" => TrustPolicy::Kali {
                        keyring: keyring.clone(),
                    },
                    "parrot" => TrustPolicy::Parrot {
                        keyring: keyring.clone(),
                    },
                    "trisquel" => TrustPolicy::Trisquel {
                        keyring: keyring.clone(),
                    },
                    "raspberrypi" => TrustPolicy::RaspberryPi {
                        keyring: keyring.clone(),
                    },
                    "proxmox-pve" => TrustPolicy::ProxmoxPve {
                        keyring: keyring.clone(),
                    },
                    "proxmox-pbs" => TrustPolicy::ProxmoxPbs {
                        keyring: keyring.clone(),
                    },
                    _ => TrustPolicy::Debian {
                        keyring: keyring.clone(),
                    },
                };
                Ok(SuiteConfig {
                    key: SuiteKey::new(repository, suite)
                        .map_err(|error| invalid("suite", error.to_string()))?,
                    policy,
                    origin,
                })
            })
            .collect()
    }

    /// Spool directory, exclusively owned by the gateway process.
    pub fn spool_dir(&self) -> PathBuf {
        self.durable.as_ref().map_or_else(
            || self.fixture.work_dir.join("spool"),
            |durable| durable.state_dir.clone(),
        )
    }

    /// Synchronizer scratch directory, wiped at startup.
    pub fn scratch_dir(&self) -> PathBuf {
        self.fixture.work_dir.join("scratch")
    }
}

fn require_loopback(field: &'static str, address: SocketAddr) -> Result<(), ConfigError> {
    if address.ip().is_loopback() {
        return Ok(());
    }
    Err(ConfigError::NotLoopback { field, address })
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field,
        reason: reason.into(),
    }
}

fn seconds(
    field: &'static str,
    value: Option<u64>,
    default: Duration,
) -> Result<Duration, ConfigError> {
    match value {
        None => Ok(default),
        Some(0) => Err(invalid(field, "must be at least 1 second")),
        Some(value) => Ok(Duration::from_secs(value)),
    }
}

fn positive<T: Copy + PartialOrd + Default>(
    field: &'static str,
    value: Option<T>,
    default: T,
) -> Result<T, ConfigError> {
    match value {
        None => Ok(default),
        Some(value) if value > T::default() => Ok(value),
        Some(_) => Err(invalid(field, "must be greater than zero")),
    }
}

fn limits_from_raw(raw: RawLimits, durable: bool) -> Result<Limits, ConfigError> {
    let defaults = mode_limits(durable);
    let limits = Limits {
        managed_ceiling_bytes: positive(
            "limits.managed_ceiling_bytes",
            raw.managed_ceiling_bytes,
            defaults.managed_ceiling_bytes,
        )?,
        max_object_bytes: positive(
            "limits.max_object_bytes",
            raw.max_object_bytes,
            defaults.max_object_bytes,
        )?,
        waiter_timeout: seconds(
            "limits.waiter_timeout_seconds",
            raw.waiter_timeout_seconds,
            defaults.waiter_timeout,
        )?,
        producer_deadline: seconds(
            "limits.producer_deadline_seconds",
            raw.producer_deadline_seconds,
            defaults.producer_deadline,
        )?,
        concurrent_fills: positive(
            "limits.concurrent_fills",
            raw.concurrent_fills,
            defaults.concurrent_fills,
        )?,
        waiters_per_object: positive(
            "limits.waiters_per_object",
            raw.waiters_per_object,
            defaults.waiters_per_object,
        )?,
        active_bodies: positive(
            "limits.active_bodies",
            raw.active_bodies,
            defaults.active_bodies,
        )?,
        request_slots: positive(
            "limits.request_slots",
            raw.request_slots,
            defaults.request_slots,
        )?,
        reader_buffer_bytes: positive(
            "limits.reader_buffer_bytes",
            raw.reader_buffer_bytes,
            defaults.reader_buffer_bytes,
        )?,
        connect_timeout: seconds(
            "limits.connect_timeout_seconds",
            raw.connect_timeout_seconds,
            defaults.connect_timeout,
        )?,
        response_header_timeout: seconds(
            "limits.response_header_timeout_seconds",
            raw.response_header_timeout_seconds,
            defaults.response_header_timeout,
        )?,
        read_idle_timeout: seconds(
            "limits.read_idle_timeout_seconds",
            raw.read_idle_timeout_seconds,
            defaults.read_idle_timeout,
        )?,
        admission_wait: seconds(
            "limits.admission_wait_seconds",
            raw.admission_wait_seconds,
            defaults.admission_wait,
        )?,
        source_attempts: positive(
            "limits.source_attempts",
            raw.source_attempts,
            defaults.source_attempts,
        )?,
        failure_backoff: seconds(
            "limits.failure_backoff_seconds",
            raw.failure_backoff_seconds,
            defaults.failure_backoff,
        )?,
        failure_map_entries: positive(
            "limits.failure_map_entries",
            raw.failure_map_entries,
            defaults.failure_map_entries,
        )?,
        sync_interval: seconds(
            "limits.sync_interval_seconds",
            raw.sync_interval_seconds,
            defaults.sync_interval,
        )?,
        active_lease: match raw.active_lease_hours {
            None => defaults.active_lease,
            Some(0) => return Err(invalid("limits.active_lease_hours", "must be at least 1")),
            Some(hours) => Duration::from_secs(
                hours
                    .checked_mul(3600)
                    .ok_or_else(|| invalid("limits.active_lease_hours", "overflows"))?,
            ),
        },
        body_write_idle: seconds(
            "limits.body_write_idle_seconds",
            raw.body_write_idle_seconds,
            defaults.body_write_idle,
        )?,
        body_lifetime: seconds(
            "limits.body_lifetime_seconds",
            raw.body_lifetime_seconds,
            defaults.body_lifetime,
        )?,
    };
    if limits.reader_buffer_bytes > ferrum_storage::disk::MAX_READ_CHUNK {
        return Err(invalid(
            "limits.reader_buffer_bytes",
            format!("must be at most {}", ferrum_storage::disk::MAX_READ_CHUNK),
        ));
    }
    if limits.max_object_bytes > limits.managed_ceiling_bytes {
        return Err(invalid(
            "limits.max_object_bytes",
            "must not exceed limits.managed_ceiling_bytes",
        ));
    }
    validate_limits(&limits, durable)?;
    Ok(limits)
}
fn mode_limits(durable: bool) -> Limits {
    let mut limits = Limits::default();
    if durable {
        limits.managed_ceiling_bytes = 200 * 1024 * 1024 * 1024;
        limits.max_object_bytes = 8 * 1024 * 1024 * 1024;
    }
    limits
}

fn validate_limits(limits: &Limits, durable: bool) -> Result<(), ConfigError> {
    let defaults = mode_limits(durable);
    if durable && limits.sync_interval != Duration::from_secs(300) {
        return Err(invalid(
            "limits.sync_interval_seconds",
            "durable observation cadence is fixed at 300 seconds before scheduler jitter",
        ));
    }
    for (field, value, maximum) in [
        (
            "managed_ceiling_bytes",
            limits.managed_ceiling_bytes,
            defaults.managed_ceiling_bytes,
        ),
        (
            "max_object_bytes",
            limits.max_object_bytes,
            defaults.max_object_bytes,
        ),
        ("concurrent_fills", limits.concurrent_fills as u64, 64),
        ("waiters_per_object", limits.waiters_per_object as u64, 64),
        ("active_bodies", limits.active_bodies as u64, 256),
        ("request_slots", limits.request_slots as u64, 1024),
        (
            "reader_buffer_bytes",
            limits.reader_buffer_bytes as u64,
            262_144,
        ),
        ("source_attempts", u64::from(limits.source_attempts), 2),
        (
            "failure_map_entries",
            limits.failure_map_entries as u64,
            10_000,
        ),
    ] {
        if value == 0 || value > maximum {
            return Err(invalid(field, format!("must be in 1..={maximum}")));
        }
    }
    for (field, value, maximum) in [
        (
            "waiter_timeout_seconds",
            limits.waiter_timeout,
            defaults.waiter_timeout,
        ),
        (
            "producer_deadline_seconds",
            limits.producer_deadline,
            defaults.producer_deadline,
        ),
        (
            "connect_timeout_seconds",
            limits.connect_timeout,
            defaults.connect_timeout,
        ),
        (
            "response_header_timeout_seconds",
            limits.response_header_timeout,
            defaults.response_header_timeout,
        ),
        (
            "read_idle_timeout_seconds",
            limits.read_idle_timeout,
            defaults.read_idle_timeout,
        ),
        (
            "admission_wait_seconds",
            limits.admission_wait,
            Duration::from_secs(10),
        ),
        (
            "active_lease_hours",
            limits.active_lease,
            defaults.active_lease,
        ),
        (
            "body_write_idle_seconds",
            limits.body_write_idle,
            defaults.body_write_idle,
        ),
        (
            "body_lifetime_seconds",
            limits.body_lifetime,
            defaults.body_lifetime,
        ),
        (
            "failure_backoff_seconds",
            limits.failure_backoff,
            defaults.failure_backoff,
        ),
        (
            "sync_interval_seconds",
            limits.sync_interval,
            defaults.sync_interval,
        ),
    ] {
        if value.is_zero() || value > maximum {
            return Err(invalid(
                field,
                format!("must be positive and at most {maximum:?}"),
            ));
        }
    }
    if limits.max_object_bytes > limits.managed_ceiling_bytes {
        return Err(invalid("max_object_bytes", "exceeds managed ceiling"));
    }
    Ok(())
}

fn validate_qualification_run(run: &str) -> Result<(), ConfigError> {
    if run.len() != 32
        || !run
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "durable.qualification_run_id",
            "must be exactly 32 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn validate_public_host(host: &str) -> Result<String, ConfigError> {
    if host.is_empty() || host.len() > 253 {
        return Err(invalid(
            "listen.public_host",
            "must be a non-empty hostname of at most 253 bytes",
        ));
    }
    let (name, port) = match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') => (name, Some(port)),
        _ => (host, None),
    };
    if let Some(port) = port {
        let parsed: u16 = port
            .parse()
            .map_err(|_| invalid("listen.public_host", "invalid port"))?;
        if parsed == 0 {
            return Err(invalid("listen.public_host", "port must be non-zero"));
        }
    }
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with('.')
        || !name.contains('.')
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(invalid(
            "listen.public_host",
            "must be a lowercase DNS domain name without scheme or path",
        ));
    }
    Ok(host.to_owned())
}
#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
mode = "private-fixture"
[listen]
public = "127.0.0.1:8080"
admin = "127.0.0.1:9090"
[fixture]
keyring = "public/ferrum-fixture.gpg"
work_dir = "run"
[verifier]
"#;

    #[test]
    fn verifier_uses_the_isolated_helper_default_and_explicit_binary() {
        let config = Config::parse(MINIMAL, Path::new(".")).expect("default verifier config");
        assert_eq!(config.verifier.binary, Path::new("ferrum-verifier"));
        assert_eq!(config.verifier.timeout, Duration::from_secs(30));

        let text = format!("{MINIMAL}\nbinary = \"/opt/ferrum/ferrum-verifier\"\n");
        let config = Config::parse(&text, Path::new(".")).expect("explicit verifier binary");
        assert_eq!(
            config.verifier.binary,
            Path::new("/opt/ferrum/ferrum-verifier")
        );

        let obsolete = format!("{MINIMAL}\nsqv_binary = \"sqv\"\n");
        assert!(
            Config::parse(&obsolete, Path::new(".")).is_err(),
            "the old field must not silently retain the weaker verifier policy"
        );
    }

    #[test]
    fn rejects_non_loopback_listeners() {
        let text = MINIMAL.replace("127.0.0.1:8080", "0.0.0.0:8080");
        let error = Config::parse(&text, Path::new(".")).expect_err("public must be loopback");
        assert!(matches!(
            error,
            ConfigError::NotLoopback {
                field: "listen.public",
                ..
            }
        ));
        let text = MINIMAL.replace("127.0.0.1:9090", "10.0.0.1:9090");
        let error = Config::parse(&text, Path::new(".")).expect_err("admin must be loopback");
        assert!(matches!(
            error,
            ConfigError::NotLoopback {
                field: "listen.admin",
                ..
            }
        ));
    }

    #[test]
    fn rejects_other_modes_and_zero_limits() {
        let text = MINIMAL.replace("private-fixture", "public");
        assert!(matches!(
            Config::parse(&text, Path::new(".")),
            Err(ConfigError::UnsupportedMode { .. })
        ));
        let text = format!("{MINIMAL}\n[limits]\nconcurrent_fills = 0\n");
        match Config::parse(&text, Path::new(".")) {
            Err(ConfigError::Invalid { field, .. }) => assert_eq!(field, "limits.concurrent_fills"),
            other => panic!("expected invalid limit, got {other:?}"),
        }
        let text = format!("{MINIMAL}\n[limits]\nreader_buffer_bytes = 262145\n");
        assert!(matches!(
            Config::parse(&text, Path::new(".")),
            Err(ConfigError::Invalid {
                field: "limits.reader_buffer_bytes",
                ..
            })
        ));
        let text = format!("{MINIMAL}\n[limits]\nunknown = 1\n");
        assert!(matches!(
            Config::parse(&text, Path::new(".")),
            Err(ConfigError::Parse)
        ));
    }

    #[test]
    fn parser_errors_never_retain_configuration_secrets() {
        let secret = "sentinel-private-credential";
        for text in [
            format!("password = '{secret}'\n{MINIMAL}"),
            format!("mode = '{secret}"),
        ] {
            let error = Config::parse(&text, Path::new(".")).expect_err("invalid configuration");
            assert!(matches!(&error, ConfigError::Parse));
            assert!(!format!("{error:?}").contains(secret));
            let error = anyhow::Error::new(error);
            assert!(!format!("{error:#}").contains(secret));
            assert!(
                error
                    .chain()
                    .all(|cause| !cause.to_string().contains(secret))
            );
        }
    }

    #[test]
    fn rejects_test_bypasses_and_excessive_resource_limits() {
        for extra in [
            "origin_base = \"http://127.0.0.1:9999/fixture/\"",
            "skip_signatures = true",
            "initial_view = true",
        ] {
            assert!(Config::parse(&format!("{extra}\n{MINIMAL}"), Path::new(".")).is_err());
        }
        for limit in [
            "managed_ceiling_bytes = 268435457",
            "max_object_bytes = 67108865",
            "concurrent_fills = 65",
            "waiters_per_object = 65",
            "active_bodies = 257",
            "request_slots = 1025",
            "waiter_timeout_seconds = 31",
            "producer_deadline_seconds = 601",
            "admission_wait_seconds = 11",
            "source_attempts = 3",
            "active_lease_hours = 25",
            "body_lifetime_seconds = 901",
        ] {
            assert!(
                Config::parse(&format!("{MINIMAL}\n[limits]\n{limit}\n"), Path::new(".")).is_err(),
                "{limit}"
            );
        }
    }

    #[test]
    fn accepts_expanded_admission_limits() {
        let text =
            format!("{MINIMAL}\n[limits]\nconcurrent_fills = 64\nadmission_wait_seconds = 10\n");
        let config = Config::parse(&text, Path::new(".")).expect("admission limits");
        assert_eq!(config.limits.concurrent_fills, 64);
        assert_eq!(config.limits.admission_wait, Duration::from_secs(10));
    }
    const DURABLE: &str = r#"
mode = "private-durable"
[listen]
public = "127.0.0.1:8080"
admin = "[::1]:9090"
[verifier]
[durable]
state_dir = "state"
[durable.provider]
endpoint = "https://s3.example.org"
region = "us-east-1"
bucket = "ferrum"
package_prefix = "linux-packages/"
checkpoint_prefix = "linux-checkpoints/"
shared_nonisolated = true
credentials_file = "credentials.toml"
[durable.keyrings]
debian = "keyrings/debian.gpg"
ubuntu = "keyrings/ubuntu.gpg"
[durable.budget]
mode = "existing"
"#;

    #[test]
    fn durable_uses_six_fixed_identities_and_separate_keyrings() {
        let config = Config::parse(DURABLE, &std::env::temp_dir()).expect("durable configuration");
        assert!(!config.is_fixture());
        let suites = config.suites().expect("fixed suites");
        assert_eq!(suites.len(), 6);
        for suite in &suites {
            assert_eq!(suite.origin.scheme(), "https");
            match &suite.policy {
                ferrum_storage::recovery::TrustPolicy::Debian { keyring } => {
                    assert_eq!(keyring, &std::env::temp_dir().join("keyrings/debian.gpg"));
                }
                ferrum_storage::recovery::TrustPolicy::Ubuntu { keyring } => {
                    assert_eq!(keyring, &std::env::temp_dir().join("keyrings/ubuntu.gpg"));
                }
                _ => panic!("production cannot use fixture trust"),
            }
        }
        assert_eq!(suites[3].key.suite(), "noble");
        assert_eq!(suites[4].key.suite(), "noble-updates");
        assert_eq!(suites[5].key.repository(), "ubuntu-security");
        assert_eq!(
            config.spool_dir(),
            config.durable().expect("durable").state_dir
        );
        assert_eq!(config.limits.max_object_bytes, 8 * 1024 * 1024 * 1024);
    }

    #[test]
    fn retirement_preserves_trust_and_requires_explicit_reactivation() {
        let root = std::env::temp_dir();
        let retired = DURABLE.replace(
            "state_dir = \"state\"",
            "state_dir = \"state\"\nsuites = []\nretired_suites = [\"debian/trixie\"]",
        );
        let config = Config::parse(&retired, &root).expect("retired-only configuration");
        assert!(config.suites().expect("active selection").is_empty());
        let trust = config.trust_suites().expect("retained trust");
        assert_eq!(trust.len(), 1);
        assert_eq!(trust[0].key.suite(), "trixie");
        assert_eq!(trust[0].policy.keyring(), root.join("keyrings/debian.gpg"));

        let active = retired.replace(
            "suites = []\nretired_suites = [\"debian/trixie\"]",
            "suites = [\"debian/trixie\"]\nretired_suites = []",
        );
        let reactivated = Config::parse(&active, &root).expect("reactivation");
        assert_eq!(reactivated.suites().expect("active").len(), 1);
        assert_eq!(reactivated.trust_suites().expect("trust").len(), 1);

        for selection in [
            "suites = [\"debian/trixie\"]\nretired_suites = [\"debian/trixie\"]",
            "suites = []\nretired_suites = []",
            "suites = []\nretired_suites = [\"all\"]",
            "suites = []\nretired_suites = [\"debian/unknown\"]",
            "suites = []\nretired_suites = [\"debian/trixie\", \"debian/trixie\"]",
        ] {
            let text = DURABLE.replace(
                "state_dir = \"state\"",
                &format!("state_dir = \"state\"\n{selection}"),
            );
            assert!(Config::parse(&text, &root).is_err(), "{selection}");
        }
    }

    #[test]
    fn durable_resolves_all_allowlisted_suites() {
        let with_all = DURABLE.replace(
            "state_dir = \"state\"",
            "state_dir = \"state\"\nsuites = [\"all\"]",
        );
        let config = Config::parse(&with_all, &std::env::temp_dir()).expect("all suites config");
        let suites = config.suites().expect("allowlisted distribution suites");
        assert_eq!(ALL_DISTRIBUTION_SUITES.len(), 106);
        assert_eq!(suites.len(), ALL_DISTRIBUTION_SUITES.len());
        for suite in &suites {
            assert_eq!(suite.origin.scheme(), "https");
        }
        for suite in &suites {
            let default_keyring = match suite.key.repository() {
                "ubuntu-ports" => "ubuntu.gpg",
                "docker-debian" | "docker-ubuntu" => "docker-archive-keyring.gpg",
                "tailscale-debian" | "tailscale-ubuntu" => "tailscale-archive-keyring.gpg",
                "postgresql-apt" => "postgresql-archive-keyring.gpg",
                "grafana-apt" => "grafana-archive-keyring.gpg",
                "cachyos" => "cachyos-keyring.gpg",
                "archlinuxcn" => "archlinuxcn-keyring.gpg",
                "endeavouros" => "endeavouros-keyring.gpg",
                "almalinux" => "almalinux-keyring.gpg",
                "rockylinux" => "rockylinux-keyring.gpg",
                _ => continue,
            };
            assert_eq!(
                suite.policy.keyring(),
                std::env::temp_dir().join("keyrings").join(default_keyring)
            );
        }
        let invalid_suite = DURABLE.replace(
            "state_dir = \"state\"",
            "state_dir = \"state\"\nsuites = [\"ubuntu/unknown\"]",
        );
        assert!(Config::parse(&invalid_suite, &std::env::temp_dir()).is_err());
    }

    #[test]
    fn configured_suite_limit_is_rejected_before_entry_resolution() {
        let entries =
            vec!["not-a-valid-profile".to_owned(); ferrum_storage::checkpoint::MAX_SUITES + 1];
        let reason = resolve_distribution_suites(Some(&entries)).expect_err("bounded inventory");
        assert_eq!(
            reason,
            format!(
                "must contain at most {} suites",
                ferrum_storage::checkpoint::MAX_SUITES
            )
        );
    }

    #[test]
    fn durable_resolves_explicit_vendor_keyrings() {
        let assignments = [
            ("docker", "docker-debian"),
            ("docker", "docker-ubuntu"),
            ("tailscale", "tailscale-debian"),
            ("tailscale", "tailscale-ubuntu"),
            ("postgresql", "postgresql-apt"),
            ("grafana", "grafana-apt"),
            ("cachyos", "cachyos"),
            ("archlinuxcn", "archlinuxcn"),
            ("endeavouros", "endeavouros"),
            ("almalinux", "almalinux"),
            ("rockylinux", "rockylinux"),
        ];
        for (field, repository) in assignments {
            let text = DURABLE
                .replace(
                    "state_dir = \"state\"",
                    "state_dir = \"state\"\nsuites = [\"all\"]",
                )
                .replace(
                    "[durable.keyrings]",
                    &format!("[durable.keyrings]\n{field} = \"custom/{field}.gpg\""),
                );
            let root = std::env::temp_dir();
            let config = Config::parse(&text, &root).expect("explicit vendor keyring");
            let suites = config.suites().expect("vendor suites");
            let selected: Vec<_> = suites
                .iter()
                .filter(|suite| suite.key.repository() == repository)
                .collect();
            assert!(!selected.is_empty(), "missing repository {repository}");
            for suite in selected {
                assert_eq!(
                    suite.policy.keyring(),
                    root.join(format!("custom/{field}.gpg"))
                );
            }
        }
    }

    #[test]
    fn durable_selects_pacman_suites_and_keyrings() {
        use ferrum_storage::recovery::TrustPolicy;

        let selected = DURABLE.replace(
            "state_dir = \"state\"",
            "state_dir = \"state\"\nsuites = [\"archlinux/core\", \"archlinux/extra\", \"archlinux/multilib\", \"chaotic-aur/chaotic-aur\"]",
        );
        for explicit in [false, true] {
            let text = if explicit {
                selected.replace(
                    "ubuntu = \"keyrings/ubuntu.gpg\"",
                    "ubuntu = \"keyrings/ubuntu.gpg\"\narchlinux = \"arch.gpg\"\nchaoticaur = \"chaotic.gpg\"",
                )
            } else {
                selected.clone()
            };
            let root = std::env::temp_dir();
            let config = Config::parse(&text, &root).expect("Pacman configuration");
            let suites = config.suites().expect("Pacman suites");
            assert_eq!(suites.len(), 4);
            for (suite, expected_suite) in
                suites
                    .iter()
                    .zip(["core", "extra", "multilib", "chaotic-aur"])
            {
                assert_eq!(suite.key.suite(), expected_suite);
                let (default_keyring, explicit_keyring, origin) = match &suite.policy {
                    TrustPolicy::ArchLinux { .. } => (
                        "keyrings/archlinux-keyring.gpg",
                        "arch.gpg",
                        "https://geo.mirror.pkgbuild.com/",
                    ),
                    TrustPolicy::ChaoticAur { .. } => (
                        "keyrings/chaotic-keyring.gpg",
                        "chaotic.gpg",
                        "https://builds.garudalinux.org/repos/",
                    ),
                    _ => panic!("Pacman suites require Pacman trust"),
                };
                assert_eq!(suite.origin.as_str(), origin);
                assert_eq!(
                    suite.policy.keyring(),
                    root.join(if explicit {
                        explicit_keyring
                    } else {
                        default_keyring
                    })
                );
            }
        }
    }

    #[test]
    fn durable_rejects_reset_public_claims_and_arbitrary_origins() {
        for extra in [
            "origin = \"https://attacker.example/\"",
            "keyring = \"/tmp/test.gpg\"",
            "profile = \"provider-isolated\"",
            "public_authorized = true",
        ] {
            assert!(Config::parse(&format!("{extra}\n{DURABLE}"), &std::env::temp_dir()).is_err());
        }
        for mode in ["initialize", "reset", "unknown", "fresh"] {
            assert!(
                Config::parse(
                    &DURABLE.replace("\"existing\"", &format!("\"{mode}\"")),
                    &std::env::temp_dir()
                )
                .is_err()
            );
        }
        assert!(
            Config::parse(
                &DURABLE.replace("127.0.0.1:8080", "0.0.0.0:8080"),
                &std::env::temp_dir()
            )
            .is_err()
        );
        assert!(
            Config::parse(
                &DURABLE.replace("[::1]:9090", "[::]:9090"),
                &std::env::temp_dir()
            )
            .is_err()
        );
        assert!(
            Config::parse(
                &DURABLE.replace("private-durable", "production"),
                &std::env::temp_dir()
            )
            .is_err()
        );
    }

    #[test]
    fn durable_resolves_operator_keyrings_and_rejects_profile_assertions() {
        let config = Config::parse(DURABLE, Path::new(".")).expect("relative config directory");
        let durable = config.durable().expect("durable");
        assert!(durable.state_dir.is_absolute());
        match &durable.trust {
            DurableTrust::Distributions(keyrings) => {
                assert!(keyrings.debian.is_absolute());
                assert!(keyrings.ubuntu.is_absolute());
            }
            DurableTrust::Fixture { .. } => panic!("distribution trust required"),
        }
        for extra in [
            "reset_unknown = true",
            "initialize = true",
            "profile = \"isolated\"",
        ] {
            assert!(Config::parse(&format!("{DURABLE}\n{extra}\n"), Path::new(".")).is_err());
        }
    }

    #[test]
    fn durable_requires_five_minute_cadence_but_fixture_can_poll_faster() {
        for seconds in [1, 299, 301] {
            let text = format!("{DURABLE}\n[limits]\nsync_interval_seconds = {seconds}\n");
            assert!(Config::parse(&text, Path::new(".")).is_err());
        }
        let text = format!("{DURABLE}\n[limits]\nsync_interval_seconds = 300\n");
        let mut config = Config::parse(&text, Path::new(".")).expect("fixed durable cadence");
        config.limits.sync_interval = Duration::from_secs(1);
        assert!(config.validate_runtime().is_err());
        let text = format!("{MINIMAL}\n[limits]\nsync_interval_seconds = 1\n");
        let config = Config::parse(&text, Path::new(".")).expect("fixture test cadence");
        assert_eq!(config.limits.sync_interval, Duration::from_secs(1));
    }

    #[cfg(feature = "test-harness")]
    #[test]
    fn durable_test_origin_seam_is_explicit_and_loopback_only() {
        let mut config = Config::parse(DURABLE, Path::new(".")).expect("durable");
        assert!(
            config
                .set_test_suite_origins(
                    Url::parse("http://192.168.1.1:18080/").expect("url"),
                    std::env::temp_dir().join("test.gpg"),
                )
                .is_err()
        );
        config
            .set_test_suite_origins(
                Url::parse("http://127.0.0.1:18080/").expect("url"),
                std::env::temp_dir().join("test.gpg"),
            )
            .expect("explicit loopback seam");
        let suites = config.suites().expect("suites");
        assert_eq!(
            suites[2].origin.as_str(),
            "http://127.0.0.1:18080/debian-security/"
        );
        assert!(matches!(
            suites[2].policy,
            ferrum_storage::recovery::TrustPolicy::Debian { .. }
        ));
    }

    const DURABLE_FIXTURE: &str = r#"
mode = "private-durable-fixture"
[listen]
public = "127.0.0.1:8080"
admin = "127.0.0.1:9090"
[verifier]
[durable]
state_dir = "existing-state"
fixture_keyring = "fixture.gpg"
qualification_run_id = "6e11358885394eea8bc768badaaa89e9"
[durable.provider]
endpoint = "https://s3.example.org"
region = "us-east-1"
bucket = "ferrum"
package_prefix = "linux-packages/"
checkpoint_prefix = "linux-checkpoints/"
shared_nonisolated = true
credentials_file = "credentials.toml"
[durable.budget]
mode = "existing"
"#;

    #[test]
    fn durable_fixture_has_only_fixed_fixture_authority() {
        let config = Config::parse(DURABLE_FIXTURE, Path::new(".")).expect("durable fixture");
        assert!(!config.is_fixture());
        assert!(config.is_durable_fixture());
        assert!(config.durable().is_some());
        let suites = config.suites().expect("suite");
        assert_eq!(suites.len(), 1);
        assert_eq!(suites[0].key.repository(), "fixture");
        assert_eq!(suites[0].key.suite(), "ferrum-test");
        assert_eq!(suites[0].origin.as_str(), ORIGIN_BASE_URL);
        assert!(matches!(
            suites[0].policy,
            ferrum_storage::recovery::TrustPolicy::LoopbackFixture { .. }
        ));
        assert_eq!(
            config.spool_dir(),
            config.durable().expect("durable").state_dir
        );
    }

    #[test]
    fn durable_fixture_rejects_unscoped_reset_and_foreign_trust() {
        for line in [
            "qualification_run_id = \"6e11358885394eea8bc768badaaa89e9\"\n",
            "fixture_keyring = \"fixture.gpg\"\n",
        ] {
            assert!(Config::parse(&DURABLE_FIXTURE.replace(line, ""), Path::new(".")).is_err());
        }
        for run in ["", "ABCDEFABCDEFABCDEFABCDEFABCDEFABCD", "../run", "1234"] {
            assert!(
                Config::parse(
                    &DURABLE_FIXTURE.replace("6e11358885394eea8bc768badaaa89e9", run),
                    Path::new(".")
                )
                .is_err()
            );
        }
        for extra in [
            "[durable.keyrings]\ndebian = \"debian.gpg\"\nubuntu = \"ubuntu.gpg\"\n",
            "[fixture]\nkeyring = \"other.gpg\"\nwork_dir = \"other\"\n",
            "[durable.origin]\nbase = \"http://127.0.0.1:9000/fixture/\"\n",
        ] {
            assert!(Config::parse(&format!("{DURABLE_FIXTURE}\n{extra}"), Path::new(".")).is_err());
        }
        assert!(
            Config::parse(
                &DURABLE_FIXTURE.replace("127.0.0.1:8080", "0.0.0.0:8080"),
                Path::new(".")
            )
            .is_err()
        );
        assert!(
            Config::parse(
                &DURABLE_FIXTURE.replace("\"existing\"", "\"initialize\""),
                Path::new(".")
            )
            .is_err()
        );
    }

    #[test]
    fn distribution_qualification_is_optional_and_explicit() {
        let text = DURABLE.replace(
            "[durable.provider]",
            "qualification_run_id = \"0123456789abcdef0123456789abcdef\"\n[durable.provider]",
        );
        let config =
            Config::parse(&text, Path::new(".")).expect("explicit future qualification identity");
        assert!(!config.is_durable_fixture());
        assert_eq!(config.suites().expect("default suites").len(), 6);
        assert_eq!(
            config
                .durable()
                .expect("durable")
                .qualification_run_id
                .as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn private_modes_reject_public_host() {
        for source in [MINIMAL, DURABLE, DURABLE_FIXTURE] {
            let text = source.replace(
                "[listen]",
                "[listen]\npublic_host = \"packages.example.org\"",
            );
            assert!(matches!(
                Config::parse(&text, Path::new(".")),
                Err(ConfigError::Invalid {
                    field: "listen.public_host",
                    ..
                })
            ));
            let mut config = Config::parse(source, Path::new(".")).expect("private config");
            config.listen.public_host = Some("packages.example.org".into());
            assert!(!config.is_public());
            assert!(matches!(
                config.validate_runtime(),
                Err(ConfigError::Invalid {
                    field: "listen.public_host",
                    ..
                })
            ));
        }
        let qualified = DURABLE
            .replace(
                "[durable.provider]",
                "qualification_run_id = \"0123456789abcdef0123456789abcdef\"\n[durable.provider]",
            )
            .replace(
                "[listen]",
                "[listen]\npublic_host = \"packages.example.org\"",
            );
        assert!(matches!(
            Config::parse(&qualified, Path::new(".")),
            Err(ConfigError::Invalid {
                field: "listen.public_host",
                ..
            })
        ));
    }

    #[test]
    fn durable_requires_explicit_provider_and_preserves_boundaries() {
        let root = tempfile::tempdir().expect("root");
        let config = Config::parse(DURABLE, root.path()).expect("explicit provider");
        let provider = &config.durable().expect("durable").provider;
        assert_eq!(provider.endpoint, "https://s3.example.org");
        assert_eq!(provider.region, "us-east-1");
        assert_eq!(provider.bucket, "ferrum");
        assert_eq!(
            provider.credentials_file,
            root.path().join("credentials.toml")
        );
        let minimal = DURABLE
            .replace("endpoint = \"https://s3.example.org\"\n", "")
            .replace("package_prefix = \"linux-packages/\"\n", "")
            .replace("checkpoint_prefix = \"linux-checkpoints/\"\n", "")
            .replace("shared_nonisolated = true\n", "");
        let minimal = Config::parse(&minimal, root.path()).expect("defaulted S3 provider");
        let defaulted = &minimal.durable().expect("durable").provider;
        assert_eq!(defaulted.endpoint, "https://s3.us-east-1.amazonaws.com");
        assert_eq!(defaulted.package_prefix, "linux-packages/");
        assert_eq!(defaulted.checkpoint_prefix, "linux-checkpoints/");
        assert!(defaulted.shared_nonisolated);

        let custom_prefixes = DURABLE
            .replace("linux-packages/", "custom-packages/")
            .replace("linux-checkpoints/", "custom-checkpoints/");
        Config::parse(&custom_prefixes, root.path()).expect("custom S3 prefixes");
        let r2_preset = DURABLE
            .replace(
                "endpoint = \"https://s3.example.org\"\nregion = \"us-east-1\"",
                "provider = \"cloudflare-r2\"\naccount_id = \"0123456789abcdef0123456789abcdef\"",
            )
            .replace("package_prefix = \"linux-packages/\"\n", "")
            .replace("checkpoint_prefix = \"linux-checkpoints/\"\n", "")
            .replace("shared_nonisolated = true\n", "");
        let r2 = Config::parse(&r2_preset, root.path()).expect("Cloudflare R2 preset");
        let r2_provider = &r2.durable().expect("durable").provider;
        assert_eq!(
            r2_provider.endpoint,
            "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"
        );
        assert_eq!(r2_provider.region, "auto");

        let idrive_preset = DURABLE
            .replace(
                "endpoint = \"https://s3.example.org\"\nregion = \"us-east-1\"",
                "provider = \"idrive-e2\"\nregion = \"us-central-1\"",
            )
            .replace("package_prefix = \"linux-packages/\"\n", "")
            .replace("checkpoint_prefix = \"linux-checkpoints/\"\n", "")
            .replace("shared_nonisolated = true\n", "");
        let idrive = Config::parse(&idrive_preset, root.path()).expect("IDrive e2 preset");
        let idrive_provider = &idrive.durable().expect("durable").provider;
        assert_eq!(
            idrive_provider.endpoint,
            "https://s3.us-central-1.idrivee2.com"
        );
        assert_eq!(idrive_provider.region, "us-central-1");

        for (field, value, replacement) in [
            (
                "endpoint",
                "https://s3.example.org",
                "http://s3.example.org",
            ),
            ("package_prefix", "linux-packages/", "linux-checkpoints/"),
            (
                "checkpoint_prefix",
                "linux-checkpoints/",
                "invalid-no-slash",
            ),
            ("shared_nonisolated", "true", "false"),
        ] {
            let text = DURABLE.replace(value, replacement);
            assert!(Config::parse(&text, root.path()).is_err(), "{field}");
        }
        let legacy = DURABLE.replace(
            "[durable.provider]",
            "credentials_file = \"legacy.env\"\n[durable.provider]",
        );
        assert!(matches!(
            Config::parse(&legacy, root.path()),
            Err(ConfigError::Parse)
        ));
        let missing = DURABLE.replace("bucket = \"ferrum\"\n", "");
        assert!(matches!(
            Config::parse(&missing, root.path()),
            Err(ConfigError::Parse)
        ));
    }

    #[test]
    fn public_durable_requires_public_host_and_forbids_qualification_run() {
        let missing_host = DURABLE.replace("private-durable", "public-durable");
        assert!(Config::parse(&missing_host, Path::new(".")).is_err());

        let valid = DURABLE
            .replace("private-durable", "public-durable")
            .replace(
                "public = \"127.0.0.1:8080\"",
                "public = \"127.0.0.1:8080\"\npublic_host = \"ferrum.oneshot.wtf\"",
            );
        let config = Config::parse(&valid, Path::new(".")).expect("valid public-durable");
        assert!(config.is_public());
        assert_eq!(
            config.listen.public_host.as_deref(),
            Some("ferrum.oneshot.wtf")
        );
        assert_eq!(config.suites().expect("default suites").len(), 6);

        let with_qual = valid.replace(
            "[durable.provider]",
            "qualification_run_id = \"0123456789abcdef0123456789abcdef\"\n[durable.provider]",
        );
        assert!(Config::parse(&with_qual, Path::new(".")).is_err());

        for bad_host in [
            "https://ferrum.oneshot.wtf",
            "ferrum.oneshot.wtf/debian",
            "FERRUM.ONESHOT.WTF",
            "localhost",
            "-bad.example.org",
        ] {
            let text = valid.replace("ferrum.oneshot.wtf", bad_host);
            assert!(Config::parse(&text, Path::new(".")).is_err(), "{bad_host}");
        }
    }
}
