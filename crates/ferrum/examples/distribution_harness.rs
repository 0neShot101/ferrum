//! Local-only B10 full-distribution validation harness.
//!
//! Runs the production six-suite gateway (`debian/trixie`, `debian/trixie-updates`,
//! `debian-security/trixie-security`, `ubuntu/noble`, `ubuntu/noble-updates`,
//! `ubuntu-security/noble-security`) over a fresh, exclusively owned local SQLite
//! catalog and [`ferrum_storage::s3::testing::DiskBackedRemote`] transport.
//!
//! Boundary:
//! - Uses fixed official HTTPS distribution origins and distinct Debian/Ubuntu
//!   archive keyrings verified through `ferrum-verifier`.
//! - Performs an explicitly disclosed local-only bootstrap (`BootstrapAudit`),
//!   streaming all selected metadata and `Packages` indexes without whole-file RAM
//!   buffering (except bounded 32 MiB signature documents).
//! - Uses dummy SDK credentials in `DiskBackedRemote`; never touches live q78
//!   state, credentials, or any remote S3 endpoint.
//! - Binds loopback-only HTTP and admin listeners and serves until `SIGTERM`/`SIGINT`.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use clap::Parser;
use ferrum::app::{self, RunningGateway};
use ferrum::config::{Config, SuiteConfig};
use ferrum_apt::path::RepositoryPath;
use ferrum_apt::release::UnixTime;
use ferrum_storage::budget::BudgetLedger;
use ferrum_storage::checkpoint::RecoveryProfile;
use ferrum_storage::disk::{DurableSpoolConfig, Spool};
use ferrum_storage::s3::S3Store;
use ferrum_storage::s3::testing::DiskBackedRemote;
use reqwest::StatusCode;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

const BOOTSTRAP_OPERATOR: &str = "local B10 distribution_harness";
const BOOTSTRAP_REASON: &str = "new disposable local-only B10 six-suite validation catalog and disk-backed test S3 store; no live provider or historical floor recovery claimed";
const BOOTSTRAP_DISCLOSURE: &str = "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED";
const LOCAL_ONLY_BOUNDARY: &str = "Local-only B10 HTTP/APT validation over DiskBackedRemote and fresh disposable SQLite catalog; no live S3 provider traffic, no q78 ledger/state reuse, no public listener exposure";

#[derive(Parser, Debug)]
#[command(
    name = "distribution_harness",
    about = "Private loopback-only B10 full-six-suite validation harness"
)]
struct Arguments {
    /// New directory to create and exclusively own for this validation run.
    #[arg(long)]
    work_dir: PathBuf,

    /// Official Debian archive keyring file.
    #[arg(long)]
    debian_keyring: PathBuf,

    /// Official Ubuntu archive keyring file.
    #[arg(long)]
    ubuntu_keyring: PathBuf,

    /// Path to the isolated `ferrum-verifier` helper binary.
    #[arg(long, default_value = "ferrum-verifier")]
    verifier: PathBuf,

    /// Loopback address for the private APT HTTP listener.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Loopback address for the admin `/healthz`, `/readyz`, `/metrics` listener.
    #[arg(long, default_value = "127.0.0.1:9090")]
    admin: SocketAddr,

    /// Optional public Host authority when running behind the local Nginx TLS boundary.
    #[arg(long)]
    public_host: Option<String>,
    /// Maximum bytes reserved in the local disk-backed S3 transport (1..=16 GiB).
    #[arg(
        long = "remote-storage-bytes",
        default_value_t = 8 * GIB,
        value_parser = clap::value_parser!(u64).range(GIB..=16 * GIB)
    )]
    remote_storage_bytes: u64,

    /// Managed byte ceiling for the local durable spool (4..=200 GiB).
    #[arg(
        long,
        default_value_t = 32 * GIB,
        value_parser = clap::value_parser!(u64).range(4 * GIB..=200 * GIB)
    )]
    spool_bytes: u64,

    /// Per-suite producer/bootstrap deadline in seconds (60..=600).
    #[arg(
        long,
        default_value_t = 600,
        value_parser = clap::value_parser!(u64).range(60..=600)
    )]
    producer_deadline_seconds: u64,

    /// Atomic readiness + authenticated manifest JSON output path (defaults to `<work-dir>/ready.json`).
    #[arg(long)]
    ready_file: Option<PathBuf>,

    /// Atomic evidence JSON output path (defaults to `<work-dir>/evidence.json`).
    #[arg(long)]
    evidence_file: Option<PathBuf>,
}

#[derive(Serialize)]
struct RepresentationEvidence {
    path: String,
    public_path: String,
    kind: &'static str,
    source_path: Option<String>,
    size: u64,
    sha256: String,
    sha512: Option<String>,
    by_hash_sha256: Option<String>,
    by_hash_sha512: Option<String>,
    public_by_hash_sha256: Option<String>,
    public_by_hash_sha512: Option<String>,
}

#[derive(Serialize)]
struct SuiteEvidence {
    repository: String,
    suite: String,
    origin: String,
    generation_id: String,
    release_content_sha256: String,
    release_date: i64,
    valid_until: Option<i64>,
    checkpoint_sequence: u64,
    manifest_file: String,
    pinned_artifact_count: usize,
    derived_artifact_count: usize,
    pinned_bytes: u64,
    derived_bytes: u64,
    representations: Vec<RepresentationEvidence>,
}

#[derive(Serialize)]
struct SpoolUsageEvidence {
    installed_bytes: u64,
    reserved_bytes: u64,
    ceiling_bytes: u64,
    catalog_bytes: u64,
    catalog_reserved_bytes: u64,
    managed_bytes: u64,
    filesystem_available_bytes: u64,
    resident_entries: usize,
    reservations: usize,
    admission_open: bool,
}

#[derive(Serialize)]
struct BudgetUsageEvidence {
    storage_bytes: u64,
    download_bytes: u64,
    package_download_bytes: u64,
    certain: bool,
}

#[derive(Serialize)]
struct OutboxUsageEvidence {
    bytes: u64,
    entries: u64,
    coverage: bool,
}

#[derive(Serialize)]
struct HarnessEvidence {
    schema_version: u32,
    status: &'static str,
    started_at_unix: i64,
    ready_at_unix: i64,
    finished_at_unix: Option<i64>,
    public_addr: String,
    admin_addr: String,
    work_dir: String,
    state_dir: String,
    remote_dir: String,
    manifests_dir: String,
    debian_keyring: String,
    ubuntu_keyring: String,
    verifier_binary: String,
    bootstrap_operator: &'static str,
    bootstrap_reason: &'static str,
    bootstrap_disclosure: String,
    local_only_boundary: &'static str,
    capture_coverage_ready: bool,
    readyz_http_status: u16,
    spool_usage: SpoolUsageEvidence,
    budget_usage: BudgetUsageEvidence,
    capture_outbox: OutboxUsageEvidence,
    remote_reserved_bytes: u64,
    remote_request_count: usize,
    completed_fills_count: usize,
    suites: Vec<SuiteEvidence>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Arguments::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = format!("{error:#}"), "distribution_harness failed");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Arguments) -> anyhow::Result<()> {
    ensure!(
        args.listen.ip().is_loopback(),
        "--listen must be a loopback address, got {}",
        args.listen
    );
    ensure!(
        args.admin.ip().is_loopback(),
        "--admin must be a loopback address, got {}",
        args.admin
    );
    ensure!(
        args.listen != args.admin,
        "--listen and --admin must use distinct loopback ports"
    );

    let started_at_unix = UnixTime::now().as_secs();
    let work_dir = create_exclusive_work_dir(&args.work_dir)?;
    let debian_keyring = validate_keyring(&args.debian_keyring, "debian-keyring")?;
    let ubuntu_keyring = validate_keyring(&args.ubuntu_keyring, "ubuntu-keyring")?;
    ensure!(
        debian_keyring != ubuntu_keyring,
        "Debian and Ubuntu keyrings must be distinct distribution archive keyrings"
    );

    let state_dir = work_dir.join("state");
    let remote_dir = work_dir.join("remote");
    let manifests_dir = work_dir.join("manifests");
    fs::create_dir(&manifests_dir)
        .with_context(|| format!("create manifests directory {}", manifests_dir.display()))?;
    let ready_file = args
        .ready_file
        .clone()
        .unwrap_or_else(|| work_dir.join("ready.json"));
    let evidence_file = args
        .evidence_file
        .clone()
        .unwrap_or_else(|| work_dir.join("evidence.json"));
    let dummy_credentials = work_dir.join("unused-local-credentials.toml");

    let config = build_config(
        &args,
        &work_dir,
        &state_dir,
        &dummy_credentials,
        &debian_keyring,
        &ubuntu_keyring,
    )?;
    let durable = config
        .durable()
        .context("durable configuration missing")?
        .clone();
    let suites = config.suites().context("fixed suite configuration")?;
    ensure!(
        suites.len() == 6,
        "expected 6 configured distribution suites"
    );

    let disk = build_spool_config(
        &state_dir,
        args.spool_bytes,
        config.limits.reader_buffer_bytes,
    );
    let spool = tokio::task::spawn_blocking(move || Spool::open_durable(disk))
        .await
        .context("open_durable join")?
        .with_context(|| format!("open fresh durable spool {}", state_dir.display()))?;
    let ledger = BudgetLedger::initialize(spool.clone(), durable.budget)
        .context("initialize disposable local test budget ledger")?;
    let (store, remote) = S3Store::disk_backed_production(
        durable.store_config(),
        ledger.clone(),
        remote_dir.clone(),
        args.remote_storage_bytes,
    )
    .context("initialize local DiskBackedRemote S3 store")?;
    let store = Arc::new(store);

    let shutdown = CancellationToken::new();
    let signal_cancel = shutdown.clone();
    let signal_watcher = tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received; cancelling bootstrap/gateway");
        signal_cancel.cancel();
    });

    tracing::info!(
        work_dir = %work_dir.display(),
        listen = %args.listen,
        admin = %args.admin,
        remote_storage_bytes = args.remote_storage_bytes,
        spool_bytes = args.spool_bytes,
        "starting B10 full-six-suite bootstrap and gateway"
    );

    let gateway = app::start_with_bootstrapped_durable_store(
        config,
        spool.clone(),
        Arc::clone(&store),
        BOOTSTRAP_OPERATOR,
        BOOTSTRAP_REASON,
        BOOTSTRAP_DISCLOSURE,
        shutdown.clone(),
    )
    .await
    .context("bootstrap and start durable distribution gateway")?;

    let readyz_status = verify_admin_readyz(gateway.admin_addr).await?;
    let ready_at_unix = UnixTime::now().as_secs();
    let suite_evidence = collect_suite_evidence(&gateway, &suites, &manifests_dir)?;

    let ready_snapshot = build_evidence(
        "ready",
        started_at_unix,
        ready_at_unix,
        None,
        &args,
        &gateway,
        &work_dir,
        &state_dir,
        &remote_dir,
        &manifests_dir,
        &debian_keyring,
        &ubuntu_keyring,
        readyz_status,
        &spool,
        &ledger,
        &remote,
        suite_evidence,
    )?;
    write_json_atomic(&ready_file, &ready_snapshot)
        .with_context(|| format!("write readiness file {}", ready_file.display()))?;
    write_json_atomic(&evidence_file, &ready_snapshot)
        .with_context(|| format!("write initial evidence file {}", evidence_file.display()))?;

    println!(
        "READY public=http://{} admin=http://{} ready_file={} evidence_file={}",
        gateway.public_addr,
        gateway.admin_addr,
        ready_file.display(),
        evidence_file.display()
    );
    std::io::stdout().flush().context("flush readiness line")?;
    tracing::info!(
        public = %gateway.public_addr,
        admin = %gateway.admin_addr,
        ready_file = %ready_file.display(),
        evidence_file = %evidence_file.display(),
        "B10 distribution harness ready and serving all six suites"
    );
    let expire_file = work_dir.join("expire-suite.txt");
    let expired_ack = work_dir.join("expired-ack.txt");
    let mut saved_views: Vec<(
        ferrum_storage::checkpoint::SuiteKey,
        std::sync::Arc<ferrum::sync::ActiveView>,
    )> = Vec::with_capacity(suites.len());
    for suite in &suites {
        if let Some(view) = gateway.catalog().load_suite(&suite.key) {
            saved_views.push((suite.key.clone(), view));
        }
    }
    let mut currently_expired: Option<ferrum_storage::checkpoint::SuiteKey> = None;
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                if let Ok(text) = fs::read_to_string(&expire_file) {
                    let target = text.trim();
                    if let Some((repo, name)) = target.split_once('/')
                        && let Ok(key) = ferrum_storage::checkpoint::SuiteKey::new(repo, name)
                        && currently_expired.as_ref() != Some(&key)
                        && let Some((_, original)) = saved_views.iter().find(|(k, _)| k == &key)
                    {
                        if let Some(prev) = currently_expired.take()
                            && let Some((_, restored)) = saved_views.iter().find(|(k, _)| k == &prev)
                        {
                            let _ = gateway.catalog().publish_suite(&prev, (**restored).clone());
                        }
                        let expired = original.with_lease(Duration::ZERO);
                        if gateway.catalog().publish_suite(&key, expired).is_ok() {
                            currently_expired = Some(key);
                            let _ = fs::write(&expired_ack, format!("{target}\n"));
                        }
                    }
                } else if let Some(prev) = currently_expired.take() {
                    if let Some((_, restored)) = saved_views.iter().find(|(k, _)| k == &prev) {
                        let _ = gateway.catalog().publish_suite(&prev, (**restored).clone());
                    }
                    let _ = fs::remove_file(&expired_ack);
                }
            }
        }
    }
    signal_watcher.abort();
    tracing::info!("draining B10 distribution gateway");

    let final_suites = collect_suite_evidence(&gateway, &suites, &manifests_dir)?;
    let completed_fills_count = gateway.completed_fills().len();
    let public_addr = gateway.public_addr;
    let admin_addr = gateway.admin_addr;
    let capture_outbox = gateway
        .capture()
        .context("durable capture manager")?
        .usage()
        .context("capture outbox usage")?;
    let capture_coverage_ready = capture_outbox.coverage;

    gateway.shutdown().await.context("gateway shutdown drain")?;

    let finished_at_unix = UnixTime::now().as_secs();
    let spool_usage = spool_usage_evidence(&spool)?;
    let budget_usage = budget_usage_evidence(&ledger)?;
    let remote_reserved_bytes = remote.reserved_bytes();
    let remote_request_count = remote.requests().context("remote request trace")?.len();

    let final_evidence = HarnessEvidence {
        schema_version: 1,
        status: "completed",
        started_at_unix,
        ready_at_unix,
        finished_at_unix: Some(finished_at_unix),
        public_addr: public_addr.to_string(),
        admin_addr: admin_addr.to_string(),
        work_dir: work_dir.display().to_string(),
        state_dir: state_dir.display().to_string(),
        remote_dir: remote_dir.display().to_string(),
        manifests_dir: manifests_dir.display().to_string(),
        debian_keyring: debian_keyring.display().to_string(),
        ubuntu_keyring: ubuntu_keyring.display().to_string(),
        verifier_binary: args.verifier.display().to_string(),
        bootstrap_operator: BOOTSTRAP_OPERATOR,
        bootstrap_reason: BOOTSTRAP_REASON,
        bootstrap_disclosure: format!(
            "{BOOTSTRAP_DISCLOSURE}. {}",
            RecoveryProfile::SharedNonisolated.disclosure()
        ),
        local_only_boundary: LOCAL_ONLY_BOUNDARY,
        capture_coverage_ready,
        readyz_http_status: readyz_status,
        spool_usage,
        budget_usage,
        capture_outbox: OutboxUsageEvidence {
            bytes: capture_outbox.bytes,
            entries: capture_outbox.entries,
            coverage: capture_outbox.coverage,
        },
        remote_reserved_bytes,
        remote_request_count,
        completed_fills_count,
        suites: final_suites,
    };
    write_json_atomic(&evidence_file, &final_evidence)
        .with_context(|| format!("write final evidence file {}", evidence_file.display()))?;

    drop(store);
    drop(remote);
    drop(ledger);
    drop(spool);
    tracing::info!(
        evidence_file = %evidence_file.display(),
        "B10 distribution harness stopped cleanly"
    );
    Ok(())
}

fn create_exclusive_work_dir(requested: &Path) -> anyhow::Result<PathBuf> {
    ensure!(
        !requested.as_os_str().is_empty(),
        "--work-dir must not be empty"
    );
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .context("current directory")?
            .join(requested)
    };
    let parent = absolute
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("--work-dir must have an existing parent directory")?;
    ensure_no_symlink_ancestors(parent)?;
    fs::create_dir(&absolute).with_context(|| {
        format!(
            "refusing existing or inaccessible --work-dir {}; strict create-new required",
            absolute.display()
        )
    })?;
    let canonical = fs::canonicalize(&absolute)
        .with_context(|| format!("canonicalize {}", absolute.display()))?;
    ensure_no_symlink_ancestors(&canonical)?;
    Ok(canonical)
}

fn validate_keyring(path: &Path, flag: &str) -> anyhow::Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("canonicalize --{flag} {}", path.display()))?;
    let metadata =
        fs::metadata(&canonical).with_context(|| format!("--{flag} {}", path.display()))?;
    ensure!(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= 32 * MIB,
        "--{flag} {} must be a non-empty regular file within 32 MiB",
        path.display()
    );
    ensure_no_symlink_ancestors(&canonical)?;
    Ok(canonical)
}

fn ensure_no_symlink_ancestors(path: &Path) -> anyhow::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(part) => {
                current.push(part);
                let metadata = fs::symlink_metadata(&current)
                    .with_context(|| format!("inspect path component {}", current.display()))?;
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "symlink path component refused: {}",
                    current.display()
                );
            }
            Component::CurDir | Component::ParentDir => {
                bail!("relative traversal component refused in {}", path.display());
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct HarnessToml<'a> {
    mode: &'static str,
    listen: HarnessListenToml<'a>,
    durable: HarnessDurableToml<'a>,
    verifier: HarnessVerifierToml<'a>,
    limits: HarnessLimitsToml,
}

#[derive(Serialize)]
struct HarnessListenToml<'a> {
    public: SocketAddr,
    admin: SocketAddr,
    public_host: Option<&'a str>,
}

#[derive(Serialize)]
struct HarnessDurableToml<'a> {
    state_dir: &'a Path,
    provider: HarnessProviderToml<'a>,
    keyrings: HarnessKeyringsToml<'a>,
    budget: HarnessBudgetToml,
}

#[derive(Serialize)]
struct HarnessProviderToml<'a> {
    endpoint: &'static str,
    region: &'static str,
    bucket: &'static str,
    package_prefix: &'static str,
    checkpoint_prefix: &'static str,
    shared_nonisolated: bool,
    credentials_file: &'a Path,
}

#[derive(Serialize)]
struct HarnessKeyringsToml<'a> {
    debian: &'a Path,
    ubuntu: &'a Path,
}

#[derive(Serialize)]
struct HarnessBudgetToml {
    mode: &'static str,
}

#[derive(Serialize)]
struct HarnessVerifierToml<'a> {
    binary: &'a Path,
    timeout_seconds: u64,
}

#[derive(Serialize)]
struct HarnessLimitsToml {
    managed_ceiling_bytes: u64,
    max_object_bytes: u64,
    producer_deadline_seconds: u64,
}

fn build_config(
    args: &Arguments,
    work_dir: &Path,
    state_dir: &Path,
    dummy_credentials: &Path,
    debian_keyring: &Path,
    ubuntu_keyring: &Path,
) -> anyhow::Result<Config> {
    let max_object_bytes = (args.spool_bytes / 2).clamp(GIB, 8 * GIB);
    let raw = HarnessToml {
        mode: if args.public_host.is_some() {
            "public-durable"
        } else {
            "private-durable"
        },
        listen: HarnessListenToml {
            public: args.listen,
            admin: args.admin,
            public_host: args.public_host.as_deref(),
        },
        durable: HarnessDurableToml {
            state_dir,
            provider: HarnessProviderToml {
                endpoint: "https://s3.us-central-1.idrivee2.com",
                region: "us-central-1",
                bucket: "s3-andrew",
                package_prefix: "linux-packages/",
                checkpoint_prefix: "linux-checkpoints/",
                shared_nonisolated: true,
                credentials_file: dummy_credentials,
            },
            keyrings: HarnessKeyringsToml {
                debian: debian_keyring,
                ubuntu: ubuntu_keyring,
            },
            budget: HarnessBudgetToml { mode: "existing" },
        },
        verifier: HarnessVerifierToml {
            binary: &args.verifier,
            timeout_seconds: 30,
        },
        limits: HarnessLimitsToml {
            managed_ceiling_bytes: args.spool_bytes,
            max_object_bytes,
            producer_deadline_seconds: args.producer_deadline_seconds,
        },
    };
    let text = toml::to_string(&raw).context("serialize durable configuration")?;
    Config::parse(&text, work_dir).context("parse durable configuration")
}

fn build_spool_config(state_dir: &Path, spool_bytes: u64, read_chunk: usize) -> DurableSpoolConfig {
    let mut disk = DurableSpoolConfig::new(state_dir.to_path_buf());
    disk.free_space_floor = GIB;
    disk.spool.managed_ceiling = spool_bytes;
    disk.spool.max_object_size = (spool_bytes / 2).clamp(GIB, 8 * GIB);
    disk.spool.read_chunk = read_chunk;
    disk.temporary_ceiling = (spool_bytes / 2).clamp(2 * GIB, 20 * GIB);
    disk.metadata_temporary_reserve = (disk.temporary_ceiling / 4).clamp(512 * MIB, 2 * GIB);
    disk.metadata_ceiling = (spool_bytes * 3 / 4).clamp(2 * GIB, 25 * GIB);
    disk.catalog_ceiling = (spool_bytes / 8).clamp(256 * MIB, GIB);
    disk.eviction_high_watermark = spool_bytes / 10 * 9;
    disk.eviction_low_watermark = spool_bytes / 5 * 4;
    disk
}

async fn verify_admin_readyz(admin_addr: SocketAddr) -> anyhow::Result<u16> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build admin HTTP client")?;
    let url = format!("http://{admin_addr}/readyz");
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    ensure!(
        status == StatusCode::OK,
        "admin /readyz returned {status}: {body}"
    );
    Ok(status.as_u16())
}

fn collect_suite_evidence(
    gateway: &RunningGateway,
    suites: &[SuiteConfig],
    manifests_dir: &Path,
) -> anyhow::Result<Vec<SuiteEvidence>> {
    let catalog = gateway.catalog();
    let publisher = catalog
        .publisher()
        .context("durable catalog publisher missing")?;
    let now = Instant::now();
    let wall = UnixTime::now();
    let mut output = Vec::with_capacity(suites.len());

    for suite in suites {
        let view = catalog.load_suite(&suite.key).with_context(|| {
            format!(
                "active view missing for {}/{}",
                suite.key.repository(),
                suite.key.suite()
            )
        })?;
        ensure!(
            catalog.current_view_available(&view) && view.is_fresh(now, wall),
            "suite {}/{} is not fresh and active",
            suite.key.repository(),
            suite.key.suite()
        );
        let state = publisher.state(&suite.key).with_context(|| {
            format!(
                "checkpoint state for {}/{}",
                suite.key.repository(),
                suite.key.suite()
            )
        })?;
        let floor = state.floor.as_ref().with_context(|| {
            format!(
                "trusted floor missing for {}/{}",
                suite.key.repository(),
                suite.key.suite()
            )
        })?;
        ensure!(
            state.active.as_ref() == Some(floor) && state.pending.is_none() && !state.blocked,
            "checkpoint state for {}/{} is not cleanly active",
            suite.key.repository(),
            suite.key.suite()
        );

        let retained = publisher.retained_proofs(&suite.key).with_context(|| {
            format!(
                "retained proofs for {}/{}",
                suite.key.repository(),
                suite.key.suite()
            )
        })?;
        let proof = retained
            .into_iter()
            .find(|candidate| candidate.manifest().generation_id == view.generation_id.to_hex())
            .with_context(|| {
                format!(
                    "authenticated proof missing for active generation {} in {}/{}",
                    view.generation_id,
                    suite.key.repository(),
                    suite.key.suite()
                )
            })?;

        let manifest = proof.manifest();
        let release = proof.release();
        let manifest_path = manifests_dir.join(format!(
            "{}-{}.json",
            suite.key.repository(),
            suite.key.suite()
        ));
        write_json_atomic(&manifest_path, manifest)
            .with_context(|| format!("write suite manifest {}", manifest_path.display()))?;

        let mut pinned_bytes = 0_u64;
        let mut derived_bytes = 0_u64;
        let mut representations =
            Vec::with_capacity(manifest.artifacts.len() + manifest.derived.len());

        for artifact in &manifest.artifacts {
            let identity = artifact
                .identity()
                .with_context(|| format!("artifact identity {}", artifact.path))?;
            pinned_bytes = pinned_bytes.saturating_add(identity.size);
            let mutable = matches!(
                artifact.path.as_str(),
                "InRelease" | "Release" | "Release.gpg"
            );
            let (
                sha512,
                by_hash_sha256,
                by_hash_sha512,
                public_by_hash_sha256,
                public_by_hash_sha512,
            ) = if mutable {
                (None, None, None, None, None)
            } else {
                let parsed = RepositoryPath::parse_decoded(&artifact.path)
                    .with_context(|| format!("parse metadata path {}", artifact.path))?;
                let entry = release
                    .entry(&parsed)
                    .with_context(|| format!("Release entry {}", artifact.path))?;
                build_by_hash_paths(
                    suite.key.repository(),
                    suite.key.suite(),
                    &artifact.path,
                    entry.sha256.map(|digest| digest.to_hex()),
                    entry.sha512.map(|digest| digest.to_hex()),
                )
            };
            representations.push(RepresentationEvidence {
                public_path: format!(
                    "/{}/dists/{}/{}",
                    suite.key.repository(),
                    suite.key.suite(),
                    artifact.path
                ),
                path: artifact.path.clone(),
                kind: if mutable { "mutable" } else { "pinned" },
                source_path: None,
                size: identity.size,
                sha256: identity.sha256.to_hex(),
                sha512,
                by_hash_sha256,
                by_hash_sha512,
                public_by_hash_sha256,
                public_by_hash_sha512,
            });
        }

        for derived in &manifest.derived {
            let identity = proof
                .identity(&derived.path)
                .with_context(|| format!("derived identity {}", derived.path))?;
            derived_bytes = derived_bytes.saturating_add(identity.size);
            let parsed = RepositoryPath::parse_decoded(&derived.path)
                .with_context(|| format!("parse derived path {}", derived.path))?;
            let entry = release
                .entry(&parsed)
                .with_context(|| format!("Release entry {}", derived.path))?;
            let (
                sha512,
                by_hash_sha256,
                by_hash_sha512,
                public_by_hash_sha256,
                public_by_hash_sha512,
            ) = build_by_hash_paths(
                suite.key.repository(),
                suite.key.suite(),
                &derived.path,
                entry.sha256.map(|digest| digest.to_hex()),
                entry.sha512.map(|digest| digest.to_hex()),
            );
            representations.push(RepresentationEvidence {
                public_path: format!(
                    "/{}/dists/{}/{}",
                    suite.key.repository(),
                    suite.key.suite(),
                    derived.path
                ),
                path: derived.path.clone(),
                kind: "derived",
                source_path: Some(derived.source_path.clone()),
                size: identity.size,
                sha256: identity.sha256.to_hex(),
                sha512,
                by_hash_sha256,
                by_hash_sha512,
                public_by_hash_sha256,
                public_by_hash_sha512,
            });
        }

        output.push(SuiteEvidence {
            repository: suite.key.repository().to_owned(),
            suite: suite.key.suite().to_owned(),
            origin: suite.origin.to_string(),
            generation_id: manifest.generation_id.clone(),
            release_content_sha256: manifest.release_content_sha256.clone(),
            release_date: manifest.release_date,
            valid_until: release.valid_until.map(|until| until.as_secs()),
            checkpoint_sequence: floor.sequence,
            manifest_file: manifest_path.display().to_string(),
            pinned_artifact_count: manifest.artifacts.len(),
            derived_artifact_count: manifest.derived.len(),
            pinned_bytes,
            derived_bytes,
            representations,
        });
    }

    Ok(output)
}

type ByHashTuple = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn build_by_hash_paths(
    repository: &str,
    suite: &str,
    relative_path: &str,
    sha256: Option<String>,
    sha512: Option<String>,
) -> ByHashTuple {
    let directory = relative_path
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    let prefix = if directory.is_empty() {
        String::new()
    } else {
        format!("{directory}/")
    };
    let by_hash_sha256 = sha256
        .as_ref()
        .map(|digest| format!("{prefix}by-hash/SHA256/{digest}"));
    let by_hash_sha512 = sha512
        .as_ref()
        .map(|digest| format!("{prefix}by-hash/SHA512/{digest}"));
    let public_by_hash_sha256 = by_hash_sha256
        .as_ref()
        .map(|by_hash| format!("/{repository}/dists/{suite}/{by_hash}"));
    let public_by_hash_sha512 = by_hash_sha512
        .as_ref()
        .map(|by_hash| format!("/{repository}/dists/{suite}/{by_hash}"));
    (
        sha512,
        by_hash_sha256,
        by_hash_sha512,
        public_by_hash_sha256,
        public_by_hash_sha512,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_evidence(
    status: &'static str,
    started_at_unix: i64,
    ready_at_unix: i64,
    finished_at_unix: Option<i64>,
    args: &Arguments,
    gateway: &RunningGateway,
    work_dir: &Path,
    state_dir: &Path,
    remote_dir: &Path,
    manifests_dir: &Path,
    debian_keyring: &Path,
    ubuntu_keyring: &Path,
    readyz_http_status: u16,
    spool: &Spool,
    ledger: &BudgetLedger,
    remote: &DiskBackedRemote,
    suites: Vec<SuiteEvidence>,
) -> anyhow::Result<HarnessEvidence> {
    let spool_usage = spool_usage_evidence(spool)?;
    let budget_usage = budget_usage_evidence(ledger)?;
    let capture_outbox = gateway
        .capture()
        .context("durable capture manager")?
        .usage()
        .context("capture outbox usage")?;
    ensure!(
        capture_outbox.coverage,
        "capture reconciliation coverage is not ready"
    );
    let remote_reserved_bytes = remote.reserved_bytes();
    let remote_request_count = remote.requests().context("remote request trace")?.len();
    Ok(HarnessEvidence {
        schema_version: 1,
        status,
        started_at_unix,
        ready_at_unix,
        finished_at_unix,
        public_addr: gateway.public_addr.to_string(),
        admin_addr: gateway.admin_addr.to_string(),
        work_dir: work_dir.display().to_string(),
        state_dir: state_dir.display().to_string(),
        remote_dir: remote_dir.display().to_string(),
        manifests_dir: manifests_dir.display().to_string(),
        debian_keyring: debian_keyring.display().to_string(),
        ubuntu_keyring: ubuntu_keyring.display().to_string(),
        verifier_binary: args.verifier.display().to_string(),
        bootstrap_operator: BOOTSTRAP_OPERATOR,
        bootstrap_reason: BOOTSTRAP_REASON,
        bootstrap_disclosure: format!(
            "{BOOTSTRAP_DISCLOSURE}. {}",
            RecoveryProfile::SharedNonisolated.disclosure()
        ),
        local_only_boundary: LOCAL_ONLY_BOUNDARY,
        capture_coverage_ready: capture_outbox.coverage,
        readyz_http_status,
        spool_usage,
        budget_usage,
        capture_outbox: OutboxUsageEvidence {
            bytes: capture_outbox.bytes,
            entries: capture_outbox.entries,
            coverage: capture_outbox.coverage,
        },
        remote_reserved_bytes,
        remote_request_count,
        completed_fills_count: gateway.completed_fills().len(),
        suites,
    })
}

fn spool_usage_evidence(spool: &Spool) -> anyhow::Result<SpoolUsageEvidence> {
    let usage = spool.usage().context("spool usage")?;
    Ok(SpoolUsageEvidence {
        installed_bytes: usage.objects.installed,
        reserved_bytes: usage.objects.reserved,
        ceiling_bytes: usage.objects.ceiling,
        catalog_bytes: usage.catalog_bytes,
        catalog_reserved_bytes: usage.catalog_reserved_bytes,
        managed_bytes: usage.managed_bytes,
        filesystem_available_bytes: usage.filesystem_available,
        resident_entries: usage.resident_entries,
        reservations: usage.reservations,
        admission_open: usage.admission_open,
    })
}

fn budget_usage_evidence(ledger: &BudgetLedger) -> anyhow::Result<BudgetUsageEvidence> {
    let usage = ledger.usage().context("budget ledger usage")?;
    Ok(BudgetUsageEvidence {
        storage_bytes: usage.storage,
        download_bytes: usage.download,
        package_download_bytes: usage.package_download,
        certain: usage.certain,
    })
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("output file must have a parent directory")?;
    ensure_no_symlink_ancestors(parent)?;
    let bytes = serde_json::to_vec_pretty(value).context("serialize JSON")?;
    let temp = parent.join(format!(
        ".{}.{:032x}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("output"),
        rand::random::<u128>()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .with_context(|| format!("create temporary file {}", temp.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("write temporary file {}", temp.display()))?;
    file.sync_all()
        .with_context(|| format!("sync temporary file {}", temp.display()))?;
    drop(file);
    fs::rename(&temp, path).with_context(|| {
        format!(
            "rename temporary file {} to {}",
            temp.display(),
            path.display()
        )
    })?;
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::warn!(%error, "SIGTERM handler unavailable; only SIGINT stops the harness");
                let _ = interrupt.await;
                return;
            }
        };
        tokio::select! {
            _ = interrupt => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}
