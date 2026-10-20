//! Startup order, wiring and shutdown (`PLAN.md` §8 shutdown, gateway contract).
//!
//! Fixture and durable modes share verification, routing and bounded fills.
//! Durable startup reopens known ledgers, recovers suite floors, reconciles
//! captures, and supervises outbox and hourly backup workers. No startup path
//! initializes unknown remote usage or authorizes public exposure.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use ferrum_apt::path::RepositoryPath;
use ferrum_apt::signature::SignatureVerifier;
use ferrum_storage::backup::BackupService;
use ferrum_storage::budget::BudgetLedger;
use ferrum_storage::capture::{CaptureManager, CaptureTrust};
use ferrum_storage::checkpoint::{CheckpointPublisher, FloorTrust, RecoveryProfile};
use ferrum_storage::s3::S3Store;
use ferrum_storage::upload::UploadWorker;
use ferrum_storage::{DurableSpoolConfig, Spool, SpoolConfig};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::config::{Config, REPOSITORY_PREFIX};
use crate::fetch::{FillRegistry, UpstreamClient};
use crate::health::{self, HealthState, Metrics};
use crate::server::{self, AppState};
use crate::sync::{ActiveView, Catalog, DurableSynchronizer, Synchronizer};

/// Maximum time open responses may take to finish after shutdown begins.
pub const DRAIN_WINDOW: Duration = Duration::from_secs(30);
/// Blocking filesystem workers for the spool.
const SPOOL_IO_WORKERS: usize = 8;

/// A started gateway; dropping it does not stop the tasks, call
/// [`RunningGateway::shutdown`].
pub struct RunningGateway {
    pub public_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    #[cfg(feature = "test-harness")]
    pub admin_state_dir: std::path::PathBuf,
    shutdown: CancellationToken,
    supervisor: JoinHandle<anyhow::Result<()>>,
    #[cfg(feature = "test-harness")]
    fills: FillRegistry,
    #[cfg(feature = "test-harness")]
    catalog: Arc<Catalog>,
    #[cfg(feature = "test-harness")]
    capture: Option<Arc<CaptureManager>>,
}

#[cfg(feature = "test-harness")]
struct InjectedDurable {
    spool: Spool,
    store: Arc<S3Store>,
    bootstrap: Option<(String, String, String)>,
}

impl RunningGateway {
    /// Source-to-verified-spool samples from the explicit fixture harness.
    #[cfg(feature = "test-harness")]
    pub fn completed_fills(&self) -> Vec<crate::fetch::flight::CompletedFill> {
        self.fills.completed_fills()
    }

    /// Active suite catalog handle for test-harness readiness and manifest inspection.
    #[cfg(feature = "test-harness")]
    pub fn catalog(&self) -> &Arc<Catalog> {
        &self.catalog
    }

    /// Capture manager handle for test-harness coverage and outbox inspection.
    #[cfg(feature = "test-harness")]
    pub fn capture(&self) -> Option<&Arc<CaptureManager>> {
        self.capture.as_ref()
    }
    /// Requests shutdown and waits for the drain to complete.
    ///
    /// # Errors
    /// When the supervisor task panicked.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        self.supervisor.await.context("gateway supervisor")?
    }

    /// Waits for a shutdown requested elsewhere (through the start token).
    ///
    /// # Errors
    /// When the supervisor task panicked.
    pub async fn finished(self) -> anyhow::Result<()> {
        self.supervisor.await.context("gateway supervisor")?
    }
}

/// Runs the gateway until `shutdown` resolves, then drains and returns.
///
/// # Errors
/// Any startup failure (verifier, spool, listeners); the process must exit
/// non-zero.
pub async fn run(config: Config, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    let token = CancellationToken::new();
    let gateway = start(config, token.clone()).await?;
    tracing::info!(public = %gateway.public_addr, admin = %gateway.admin_addr, "gateway listening");
    tokio::select! {
        () = shutdown => {}
        () = token.cancelled() => {}
    }
    tracing::info!("shutdown requested; draining");
    gateway.shutdown().await
}

/// Starts every component with the real verifier and synchronizer.
///
/// # Errors
/// Missing/incompatible signature verifier, spool ownership failure, listener bind failure.
pub async fn start(config: Config, shutdown: CancellationToken) -> anyhow::Result<RunningGateway> {
    config.validate_runtime().context("runtime configuration")?;
    let verifier = SignatureVerifier::new(config.verifier.binary.clone(), config.verifier.timeout)
        .await
        .context("signature verifier capability check")?;
    start_inner(
        config,
        Some(verifier),
        None,
        None,
        #[cfg(feature = "test-harness")]
        None,
        shutdown,
    )
    .await
}

/// Test harness: starts the listeners with `view` already published and no
/// synchronizer or verifier, so behavioral tests can run without `ferrum-verifier`.
#[doc(hidden)]
#[cfg(feature = "test-harness")]
pub async fn start_with_view(
    config: Config,
    view: Option<ActiveView>,
    shutdown: CancellationToken,
) -> anyhow::Result<RunningGateway> {
    anyhow::ensure!(config.is_fixture(), "unsigned views are fixture-only");
    start_inner(
        config,
        None,
        view,
        None,
        #[cfg(feature = "test-harness")]
        None,
        shutdown,
    )
    .await
}

/// Behavioral tests inject the real adapter over a scripted SDK connector, never a configurable endpoint.
#[doc(hidden)]
#[cfg(feature = "test-harness")]
pub async fn start_with_view_and_s3(
    config: Config,
    view: ActiveView,
    s3: Arc<ferrum_storage::s3::S3Store>,
    shutdown: CancellationToken,
) -> anyhow::Result<RunningGateway> {
    anyhow::ensure!(
        config.is_fixture(),
        "injected fixture adapters are fixture-only"
    );
    start_inner(
        config,
        None,
        Some(view),
        Some(s3),
        #[cfg(feature = "test-harness")]
        None,
        shutdown,
    )
    .await
}

/// Test harness: starts the full durable gateway over an explicitly injected
/// owned durable [`Spool`] and [`S3Store`]. Rejects fixture configurations or
/// mismatched storage owners.
#[doc(hidden)]
#[cfg(feature = "test-harness")]
pub async fn start_with_durable_store(
    config: Config,
    spool: Spool,
    store: Arc<S3Store>,
    shutdown: CancellationToken,
) -> anyhow::Result<RunningGateway> {
    validate_injected_durable_store(&config, &spool, &store)?;
    let verifier = SignatureVerifier::new(config.verifier.binary.clone(), config.verifier.timeout)
        .await
        .context("signature verifier capability check")?;
    start_inner(
        config,
        Some(verifier),
        None,
        None,
        Some(InjectedDurable {
            spool,
            store,
            bootstrap: None,
        }),
        shutdown,
    )
    .await
}

/// Test harness: performs an audited initial bootstrap of every configured
/// suite over an explicitly injected owned durable [`Spool`] and [`S3Store`],
/// reconciles initial capture coverage, and starts the full durable gateway
/// using the same authenticated publisher, catalog and synchronizer state.
#[doc(hidden)]
#[cfg(feature = "test-harness")]
pub async fn start_with_bootstrapped_durable_store(
    config: Config,
    spool: Spool,
    store: Arc<S3Store>,
    operator: &str,
    reason: &str,
    disclosure: &str,
    shutdown: CancellationToken,
) -> anyhow::Result<RunningGateway> {
    validate_injected_durable_store(&config, &spool, &store)?;
    let now = ferrum_apt::release::UnixTime::now().as_secs();
    let _ = ferrum_storage::recovery::BootstrapAudit::acknowledge_reset(
        operator, reason, now, disclosure,
    )
    .context("bootstrap audit")?;
    let verifier = SignatureVerifier::new(config.verifier.binary.clone(), config.verifier.timeout)
        .await
        .context("signature verifier capability check")?;
    start_inner(
        config,
        Some(verifier),
        None,
        None,
        Some(InjectedDurable {
            spool,
            store,
            bootstrap: Some((
                operator.to_owned(),
                reason.to_owned(),
                disclosure.to_owned(),
            )),
        }),
        shutdown,
    )
    .await
}

async fn start_inner(
    config: Config,
    verifier: Option<SignatureVerifier>,
    initial_view: Option<ActiveView>,
    injected_s3: Option<Arc<ferrum_storage::s3::S3Store>>,
    #[cfg(feature = "test-harness")] injected_durable: Option<InjectedDurable>,
    shutdown: CancellationToken,
) -> anyhow::Result<RunningGateway> {
    config.validate_runtime().context("runtime configuration")?;
    let suites = config.suites().context("fixed suite configuration")?;
    let config = Arc::new(config);
    let limits = config.limits;
    let spool_dir = config.spool_dir();
    anyhow::ensure!(
        !crate::admin::migration::legacy_present(&spool_dir)?,
        "legacy admin users require offline `ferrum admin migrate --config <path>` before startup"
    );
    #[cfg(feature = "test-harness")]
    let mut bootstrap_audit = None;
    let (spool, s3, publisher, capture, backup) = if let Some(durable) = config.durable() {
        anyhow::ensure!(
            spool_dir.join("state.sqlite").is_file(),
            "existing durable catalog required; startup never initializes lost ledgers or floors",
        );
        let now = ferrum_apt::release::UnixTime::now().as_secs();
        #[cfg(feature = "test-harness")]
        let injected = if let Some(injected) = injected_durable {
            validate_injected_durable_store(&config, &injected.spool, &injected.store)?;
            bootstrap_audit = injected.bootstrap;
            Some((injected.spool, injected.store))
        } else {
            None
        };
        #[cfg(not(feature = "test-harness"))]
        let injected: Option<(Spool, Arc<S3Store>)> = None;
        let mut disk = DurableSpoolConfig::new(spool_dir.clone());
        disk.catalog_ceiling = disk
            .catalog_ceiling
            .min((limits.managed_ceiling_bytes / 4).max(16 * 1024 * 1024));
        let backup_ceiling = disk.catalog_ceiling;
        let (spool, store) = match injected {
            Some(storage) => storage,
            None => {
                disk.spool.managed_ceiling = limits.managed_ceiling_bytes;
                disk.spool.max_object_size = limits.max_object_bytes;
                disk.spool.read_chunk = limits.reader_buffer_bytes;
                // Watermarks and sub-ceilings remain proportional when the operator
                // lowers the hard cap; open_durable also applies physical capacity.
                disk.eviction_high_watermark = limits.managed_ceiling_bytes / 10 * 9;
                disk.eviction_low_watermark = limits.managed_ceiling_bytes / 5 * 4;
                disk.metadata_ceiling = disk.metadata_ceiling.min(limits.managed_ceiling_bytes / 2);
                disk.temporary_ceiling =
                    disk.temporary_ceiling.min(limits.managed_ceiling_bytes / 4);
                disk.metadata_temporary_reserve = disk
                    .metadata_temporary_reserve
                    .min(disk.temporary_ceiling / 2);
                let spool = tokio::task::spawn_blocking(move || Spool::open_durable(disk))
                    .await
                    .context("durable spool startup task")?
                    .with_context(|| format!("durable state {}", spool_dir.display()))?;
                let provider = durable
                    .store_config()
                    .provider_identity(durable.qualification_run_id.as_deref())?;
                let ledger =
                    BudgetLedger::open_for_provider(spool.clone(), durable.budget, &provider)
                        .context(
                            "existing remote budget and matching provider identity required",
                        )?;
                let store = Arc::new(match &durable.qualification_run_id {
                    Some(run) => {
                        let usage = ledger
                            .qualification_usage()
                            .context("existing qualification allocation required; startup never initializes it")?;
                        let gib = 1024 * 1024 * 1024;
                        anyhow::ensure!(
                            usage.limits.upload == 8 * gib
                                && usage.limits.download == 16 * gib
                                && usage.limits.storage == 8 * gib,
                            "existing qualification allocation must remain 8/16/8 GiB upload/download/storage",
                        );
                        S3Store::open_qualification(durable.store_config(), ledger, run)
                            .context("existing correlated private qualification namespaces")?
                    }
                    None => S3Store::open(durable.store_config(), ledger)
                        .context("fixed NONISOLATED S3 operation identities")?,
                });
                (spool, store)
            }
        };
        let publisher = Arc::new(
            CheckpointPublisher::new(
                spool.clone(),
                Arc::clone(&store),
                RecoveryProfile::SharedNonisolated,
            )
            .context("checkpoint publisher")?,
        );
        let retained = publisher
            .retained_suites()
            .context("read retained checkpoint suites before changing capture coverage")?;
        validate_retained_suites(&retained, &suites)?;
        let capture = Arc::new(
            CaptureManager::new(spool.clone(), Arc::clone(&store)).context("capture manager")?,
        );
        if !capture.coverage_ready().unwrap_or(false) {
            capture
                .begin_reconciliation(now)
                .context("disable captures until proof reconciliation")?;
        }
        let backup = BackupService::new(spool.clone(), Arc::clone(&store), backup_ceiling)
            .context("online catalog backup service")?;
        (
            spool,
            Some(store),
            Some(publisher),
            Some(capture),
            Some(backup),
        )
    } else {
        std::fs::create_dir_all(&config.fixture.work_dir).context("fixture work directory")?;
        let spool = Spool::open_exclusive_fixture(SpoolConfig {
            root: spool_dir.clone(),
            managed_ceiling: limits.managed_ceiling_bytes,
            max_object_size: limits.max_object_bytes,
            io_workers: SPOOL_IO_WORKERS,
            read_chunk: limits.reader_buffer_bytes,
        })
        .with_context(|| format!("spool {}", spool_dir.display()))?;
        let store = match injected_s3 {
            Some(store) => Some(store),
            None => config
                .s3
                .clone()
                .map(S3Store::open_private)
                .transpose()
                .context("private S3 adapter and existing transfer journal")?
                .map(Arc::new),
        };
        (spool, store, None, None, None)
    };
    let mut clients: Vec<(String, Arc<UpstreamClient>)> = Vec::new();
    if !config.is_fixture() {
        for suite in &suites {
            if !clients
                .iter()
                .any(|(repository, _)| repository == suite.key.repository())
            {
                clients.push((
                    suite.key.repository().to_owned(),
                    Arc::new(
                        UpstreamClient::new(suite.origin.clone(), &limits)
                            .context("distribution origin client")?,
                    ),
                ));
            }
        }
    }
    let client = match clients.first() {
        Some((_, client)) => Arc::clone(client),
        None => Arc::new(
            UpstreamClient::new(config.origin_base.clone(), &limits)
                .context("fixture origin client")?,
        ),
    };
    let metrics = Arc::new(Metrics::default());
    let catalog = Arc::new(match &publisher {
        Some(publisher) => Catalog::configured(
            suites.iter().map(|suite| suite.key.clone()).collect(),
            Arc::clone(publisher),
        )
        .context("configured durable suite catalog")?,
        None => Catalog::new(),
    });
    if !config.is_fixture() {
        refresh_clock(&catalog).await;
    }
    if let Some(view) = initial_view {
        catalog.publish(view);
    }
    // Fills and upload transports survive admission shutdown until responses drain.
    let transports = CancellationToken::new();
    let registry = FillRegistry::new(
        spool.clone(),
        Arc::clone(&client),
        s3.clone(),
        limits,
        transports.child_token(),
        Arc::clone(&metrics),
    );
    let verifier_version = verifier.as_ref().map_or_else(
        || "unavailable".to_owned(),
        |verifier| verifier.version().to_owned(),
    );

    let admin_listener = TcpListener::bind(config.listen.admin)
        .await
        .with_context(|| format!("bind admin listener {}", config.listen.admin))?;
    let public_listener = TcpListener::bind(config.listen.public)
        .await
        .with_context(|| format!("bind public listener {}", config.listen.public))?;
    let admin_addr = admin_listener.local_addr().context("admin address")?;
    let public_addr = public_listener.local_addr().context("public address")?;

    let request_slots = Arc::new(Semaphore::new(limits.request_slots));
    let active_bodies = Arc::new(Semaphore::new(limits.active_bodies));
    let public_router = server::router(Arc::new(AppState {
        catalog: Arc::clone(&catalog),
        spool: spool.clone(),
        client: Arc::clone(&client),
        clients,
        capture: capture.clone(),
        s3: s3.clone(),
        registry: registry.clone(),
        metrics: Arc::clone(&metrics),
        limits,
        request_slots: Arc::clone(&request_slots),
        active_bodies: Arc::clone(&active_bodies),
        cold_clients: Default::default(),
        authority: config
            .listen
            .public_host
            .clone()
            .unwrap_or_else(|| public_addr.to_string()),
        trust_proxy_ip: config.listen.public_host.is_some(),
        request_ids: std::sync::atomic::AtomicU64::new(0),
        prefix: RepositoryPath::parse_decoded(REPOSITORY_PREFIX).context("repository prefix")?,
    }));
    let mut workers: JoinSet<anyhow::Result<()>> = JoinSet::new();
    // Complete all fallible construction before spawning any unowned tasks.
    let capture_verifier = match &capture {
        Some(_) => Some(
            verifier
                .clone()
                .context("durable captures require signature verification")?,
        ),
        None => None,
    };
    let durable_sync = match (&publisher, verifier.as_ref()) {
        (Some(publisher), Some(verifier)) => Some(
            DurableSynchronizer::new(
                Arc::clone(&config),
                verifier.clone(),
                spool.clone(),
                Arc::clone(publisher),
                Arc::clone(&catalog),
                Arc::clone(&metrics),
            )
            .await
            .context("durable suite synchronizer")?,
        ),
        _ => None,
    };
    #[cfg(feature = "test-harness")]
    let mut durable_sync = durable_sync;
    #[cfg(feature = "test-harness")]
    if let Some((operator, reason, disclosure)) = bootstrap_audit {
        let synchronizer = durable_sync
            .as_mut()
            .context("durable bootstrap requires durable synchronizer")?;
        anyhow::ensure!(
            catalog.clock_valid(),
            "trusted synchronized host clock required before durable bootstrap"
        );
        for suite in &suites {
            tracing::info!(
                repository = suite.key.repository(),
                suite = suite.key.suite(),
                origin = %suite.origin,
                "bootstrapping authenticated suite closure"
            );
            let now = ferrum_apt::release::UnixTime::now().as_secs();
            let audit = ferrum_storage::recovery::BootstrapAudit::acknowledge_reset(
                &operator,
                &reason,
                now,
                &disclosure,
            )
            .context("bootstrap audit")?;
            synchronizer
                .bootstrap_once(&suite.key, audit, &shutdown)
                .await
                .with_context(|| {
                    format!(
                        "bootstrap suite {}/{}",
                        suite.key.repository(),
                        suite.key.suite()
                    )
                })?;
            tracing::info!(
                repository = suite.key.repository(),
                suite = suite.key.suite(),
                "suite bootstrap complete and active"
            );
        }
        if let (Some(capture), Some(verifier)) = (&capture, &capture_verifier) {
            let trusts: Vec<_> = suites
                .iter()
                .map(|suite| CaptureTrust {
                    key: suite.key.clone(),
                    policy: suite.policy.clone(),
                    floor_trust: FloorTrust::IntactTrusted,
                })
                .collect();
            capture
                .reconcile(
                    &trusts,
                    verifier,
                    ferrum_apt::release::UnixTime::now().as_secs(),
                    tokio::time::Instant::now() + limits.producer_deadline,
                    &shutdown,
                )
                .await
                .context("initial capture reconciliation after bootstrap")?;
            tracing::info!("initial capture reconciliation complete; admission open");
        }
    }
    let fixture_sync = if config.is_fixture() {
        match verifier {
            Some(verifier) => Some(
                Synchronizer::new(
                    Arc::clone(&config),
                    verifier,
                    spool.clone(),
                    Arc::clone(&client),
                    Arc::clone(&catalog),
                    Arc::clone(&metrics),
                )
                .await
                .context("fixture synchronizer")?,
            ),
            None => None,
        }
    } else {
        None
    };
    let admin = Arc::new(
        match crate::admin::AdminStore::open(&config.admin.state_dir) {
            Ok(store) => store,
            Err(error) => {
                tracing::error!(%error, "administration unavailable; existing gateway authority preserved");
                crate::admin::AdminStore::unavailable()
            }
        },
    );
    if let Err(error) = crate::admin::jobs::JobRegistry::reconcile_startup(&admin).await {
        tracing::warn!(%error, "could not reconcile interrupted admin operation jobs at startup");
    }
    if let Err(error) = crate::admin::settings::reconcile_config_proposals(&admin, &config).await {
        tracing::warn!(%error, "could not reconcile admin configuration proposals at startup");
    }
    let jobs = Arc::new(crate::admin::jobs::JobRegistry::new((*admin).clone()));
    let durable_sync = durable_sync.map(|sync| sync.with_job_registry(Arc::clone(&jobs)));
    let fixture_sync = fixture_sync.map(|sync| sync.with_job_registry(Arc::clone(&jobs)));
    let sync_trigger = durable_sync
        .as_ref()
        .map(DurableSynchronizer::trigger_handle)
        .or_else(|| fixture_sync.as_ref().map(Synchronizer::trigger_handle));
    let admin_http = Arc::new(
        crate::admin::AdminHttpState::new(&config.admin.origin_for_listener(admin_addr))
            .map_err(anyhow::Error::msg)?,
    );
    let telemetry = Arc::new(crate::admin::telemetry::TelemetryHub::new());
    let health_state = Arc::new(HealthState {
        catalog: Arc::clone(&catalog),
        metrics: Arc::clone(&metrics),
        spool: spool.clone(),
        capture: capture.clone(),
        sync_trigger,
        admin,
        admin_http,
        jobs,
        telemetry,
        config: Arc::clone(&config),
        publisher: publisher.clone(),
        s3: s3.clone(),
        fills: Some(registry.clone()),
        request_slots: Some(request_slots),
        active_bodies: Some(active_bodies),
        verifier_version,
    });
    let sampler_state = Arc::clone(&health_state);
    let sampler_cancel = shutdown.child_token();
    workers.spawn(async move {
        crate::admin::telemetry::spawn_sampler(sampler_state, sampler_cancel)
            .await
            .context("telemetry sampler")
    });
    let health_router = health::router(health_state);
    if !config.is_fixture() {
        let catalog = Arc::clone(&catalog);
        let cancel = shutdown.child_token();
        workers.spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    () = tokio::time::sleep(Duration::from_secs(60)) => {}
                }
                refresh_clock(&catalog).await;
            }
        });
    }
    if let (Some(capture), Some(verifier), Some(publisher)) =
        (&capture, &capture_verifier, &publisher)
        && !capture.coverage_ready().unwrap_or(false)
        && catalog.clock_valid()
        && suites.iter().any(|suite| {
            publisher
                .state(&suite.key)
                .is_ok_and(|state| state.floor.is_some())
        })
    {
        let trusts: Vec<_> = suites
            .iter()
            .map(|suite| CaptureTrust {
                key: suite.key.clone(),
                policy: suite.policy.clone(),
                floor_trust: FloorTrust::IntactTrusted,
            })
            .collect();
        match capture
            .reconcile(
                &trusts,
                verifier,
                ferrum_apt::release::UnixTime::now().as_secs(),
                tokio::time::Instant::now() + limits.producer_deadline,
                &shutdown,
            )
            .await
        {
            Ok(()) => tracing::info!("startup capture reconciliation complete before sync loop"),
            Err(error) => {
                tracing::warn!(%error, "startup capture reconciliation deferred to background worker");
            }
        }
    }
    if let Some(synchronizer) = durable_sync {
        let cancel = shutdown.child_token();
        workers.spawn(async move {
            synchronizer.run(cancel).await;
            Ok(())
        });
    }
    if let Some(synchronizer) = fixture_sync {
        let cancel = shutdown.child_token();
        workers.spawn(async move {
            synchronizer.run(cancel).await;
            Ok(())
        });
    }
    #[cfg(feature = "test-harness")]
    let capture_handle = capture.clone();
    if let (Some(capture), Some(verifier)) = (capture, capture_verifier) {
        let trusts: Vec<_> = suites
            .into_iter()
            .map(|suite| CaptureTrust {
                key: suite.key,
                policy: suite.policy,
                floor_trust: FloorTrust::IntactTrusted,
            })
            .collect();
        let manager = Arc::clone(&capture);
        let catalog = Arc::clone(&catalog);
        let cancel = shutdown.child_token();
        workers.spawn(async move {
            loop {
                if manager.coverage_ready().unwrap_or(false) {
                    cancel.cancelled().await;
                    return Ok(());
                }
                if !catalog.clock_valid() {
                    tokio::select! {
                        () = cancel.cancelled() => return Ok(()),
                        () = tokio::time::sleep(Duration::from_secs(30)) => continue,
                    }
                }
                let result = manager
                    .reconcile(
                        &trusts,
                        &verifier,
                        ferrum_apt::release::UnixTime::now().as_secs(),
                        tokio::time::Instant::now() + limits.producer_deadline,
                        &cancel,
                    )
                    .await;
                match result {
                    Ok(()) => {
                        // Coverage is durable; keep the supervisor task alive until shutdown.
                        cancel.cancelled().await;
                        return Ok(());
                    }
                    Err(_) if cancel.is_cancelled() => return Ok(()),
                    Err(error) => tracing::warn!(%error, "capture recovery incomplete; admission remains closed"),
                }
                tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    () = tokio::time::sleep(Duration::from_secs(30)) => {}
                }
            }
        });
        let cancel = transports.child_token();
        workers.spawn(async move {
            match UploadWorker::new(capture.as_ref().clone())
                .run(cancel.clone())
                .await
            {
                Err(ferrum_storage::capture::CaptureError::S3(
                    ferrum_storage::s3::S3Error::Cancelled,
                )) if cancel.is_cancelled() => Ok(()),
                result => result.context("upload worker"),
            }
        });
    }
    if let Some(backup) = backup {
        let cancel = transports.child_token();
        workers.spawn(async move {
            match backup.run_hourly(&cancel).await {
                Err(ferrum_storage::checkpoint::CheckpointError::Transport(
                    ferrum_storage::s3::S3Error::Cancelled,
                )) if cancel.is_cancelled() => Ok(()),
                result => result.context("hourly backup worker"),
            }
        });
    }
    let admin_cancel = shutdown.child_token();
    workers.spawn(async move {
        server::serve(
            admin_listener,
            health_router,
            admin_cancel,
            limits.body_write_idle,
            DRAIN_WINDOW,
        )
        .await
        .context("admin listener")
    });
    let public_cancel = shutdown.child_token();
    workers.spawn(async move {
        server::serve(
            public_listener,
            public_router,
            public_cancel,
            limits.body_write_idle,
            DRAIN_WINDOW,
        )
        .await
        .context("public listener")
    });

    let token = shutdown.clone();
    let durable = publisher.is_some();
    #[cfg(feature = "test-harness")]
    let fills = registry.clone();
    let supervisor = tokio::spawn(async move {
        let mut failure = None;
        tokio::select! {
            () = token.cancelled() => {}
            result = workers.join_next() => {
                if !token.is_cancelled() {
                    failure = Some(worker_exit(result));
                }
                token.cancel();
            }
        }
        // Listener shutdown stops admission and drains current bodies. Their
        // fills still have live transport tokens throughout this window.
        let deadline = tokio::time::Instant::now() + DRAIN_WINDOW;
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => break,
                result = workers.join_next(), if !workers.is_empty() => {
                    if let Some(result) = result {
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => { failure.get_or_insert(error); }
                            Err(error) => { failure.get_or_insert_with(|| anyhow::anyhow!("gateway worker task failed: {error}")); }
                        }
                    }
                }
            }
            if workers.is_empty() {
                break;
            }
        }
        transports.cancel();
        registry.shutdown().await;
        // Do not abort filesystem/signature work: bounded operations own their
        // cancellation and keep the process lock until their real termination.
        while let Some(result) = workers.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert_with(|| {
                        anyhow::anyhow!("gateway worker task failed: {error}")
                    });
                }
            }
        }
        if durable {
            let owner = spool.clone();
            match tokio::task::spawn_blocking(move || owner.checkpoint()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert_with(|| {
                        anyhow::anyhow!("durable shutdown checkpoint: {error}")
                    });
                }
                Err(error) => {
                    failure.get_or_insert_with(|| {
                        anyhow::anyhow!("durable checkpoint task failed: {error}")
                    });
                }
            }
        }
        // The spool lock lives as long as this handle; releasing it last keeps
        // the directory exclusively owned until every reader is gone.
        drop(spool);
        tracing::info!("gateway stopped");
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    });

    Ok(RunningGateway {
        public_addr,
        admin_addr,
        #[cfg(feature = "test-harness")]
        admin_state_dir: config.admin.state_dir.clone(),
        shutdown,
        supervisor,
        #[cfg(feature = "test-harness")]
        fills,
        #[cfg(feature = "test-harness")]
        catalog,
        #[cfg(feature = "test-harness")]
        capture: capture_handle,
    })
}

/// Retained checkpoints still participate in recovery even when their routes are removed.
/// Refuse that unsupported cutover before capture coverage or verification is cleared.
fn validate_retained_suites(
    retained: &[ferrum_storage::checkpoint::SuiteKey],
    suites: &[crate::config::SuiteConfig],
) -> anyhow::Result<()> {
    for key in retained {
        let repository = key.repository();
        let suite = key.suite();
        anyhow::ensure!(
            suites.iter().any(|configured| &configured.key == key),
            "durable.suites omits retained checkpoint {repository}/{suite}; removing a published \
             suite is not supported: restore this suite to the serving selection; retained \
             checkpoints and capture coverage have not been cleared",
        );
    }
    Ok(())
}

#[cfg(feature = "test-harness")]
fn validate_injected_durable_store(
    config: &Config,
    spool: &Spool,
    store: &Arc<S3Store>,
) -> anyhow::Result<()> {
    config.validate_runtime().context("runtime configuration")?;
    anyhow::ensure!(
        !config.is_fixture(),
        "durable store injection requires durable mode"
    );
    let spool_dir = config.spool_dir();
    anyhow::ensure!(
        spool_dir.join("state.sqlite").is_file(),
        "existing durable catalog required; startup never initializes lost ledgers or floors",
    );
    anyhow::ensure!(
        same_directory(spool.root(), &spool_dir),
        "injected durable spool root {} does not match configured state_dir {}",
        spool.root().display(),
        spool_dir.display(),
    );
    let durable = config
        .durable()
        .context("durable provider configuration required")?;
    let provider = durable
        .store_config()
        .provider_identity(durable.qualification_run_id.as_deref())?;
    BudgetLedger::check_provider(spool, &provider)
        .context("injected durable store provider mismatch")?;
    anyhow::ensure!(
        spool
            .usage()
            .context("injected durable spool usage")?
            .admission_open,
        "injected durable spool admission is closed",
    );
    let _ = CheckpointPublisher::new(
        spool.clone(),
        Arc::clone(store),
        RecoveryProfile::SharedNonisolated,
    )
    .context("injected durable store owner mismatch")?;
    let _ = CaptureManager::new(spool.clone(), Arc::clone(store))
        .context("injected capture store owner mismatch")?;
    Ok(())
}

#[cfg(feature = "test-harness")]
fn same_directory(left: &std::path::Path, right: &std::path::Path) -> bool {
    if left == right {
        return true;
    }
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn worker_exit(
    result: Option<Result<anyhow::Result<()>, tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok(Err(error))) => error,
        Some(Err(error)) => anyhow::anyhow!("gateway worker task failed: {error}"),
        Some(Ok(Ok(()))) => anyhow::anyhow!("gateway worker exited unexpectedly"),
        None => anyhow::anyhow!("gateway has no supervised workers"),
    }
}

async fn refresh_clock(catalog: &Catalog) {
    match crate::clock::require_synchronized_clock().await {
        Ok(()) => catalog.set_clock_synchronized(true),
        Err(error) => {
            catalog.set_clock_synchronized(false);
            tracing::warn!(%error, "trusted clock unavailable; mutable distribution service remains closed");
        }
    }
}

/// Triggers synchronization through the authenticated loopback admin API.
/// A direct offline pass requires the explicit `offline` flag.
pub async fn sync(
    config: Config,
    target: Option<String>,
    repository: Option<String>,
    suite: Option<String>,
    offline: bool,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !(target.is_some() && (repository.is_some() || suite.is_some())),
        "specify either a positional target or --repository/--suite, not both"
    );
    let (repository, suite) = if let Some(target) = target {
        if target == "all" {
            (None, None)
        } else if let Some((repo, suite)) = target.split_once('/') {
            anyhow::ensure!(
                !repo.is_empty() && !suite.is_empty() && !suite.contains('/'),
                "invalid sync target {target}; expected <repository> or <repository>/<suite>"
            );
            (Some(repo.to_owned()), Some(suite.to_owned()))
        } else {
            (Some(target), None)
        }
    } else {
        anyhow::ensure!(
            suite.is_none() || repository.is_some(),
            "--suite requires --repository"
        );
        (repository, suite)
    };
    let configured: Vec<ferrum_storage::checkpoint::SuiteKey> = if config.is_fixture() {
        vec![ferrum_storage::checkpoint::SuiteKey::new(
            "fixture",
            crate::config::SUITE,
        )?]
    } else {
        config
            .suites()?
            .into_iter()
            .map(|entry| entry.key)
            .collect()
    };
    let matched: Vec<ferrum_storage::checkpoint::SuiteKey> = configured
        .iter()
        .filter(|key| match (repository.as_deref(), suite.as_deref()) {
            (None, None) | (Some("all"), None) => true,
            (Some(repo), None) => key.repository() == repo,
            (Some(repo), Some(suite)) => key.repository() == repo && key.suite() == suite,
            (None, Some(_)) => false,
        })
        .cloned()
        .collect();
    anyhow::ensure!(
        !matched.is_empty(),
        "no configured mirror/suite matches target"
    );
    if !offline {
        let token = crate::admin::migration::read_control_token(&config.admin.state_dir)
            .context("read protected local admin control token")?;
        let origin = url::Url::parse(&config.admin.origin).context("configured admin origin")?;
        let authority = &origin[url::Position::BeforeHost..url::Position::AfterPort];
        let url = format!("http://{}/api/admin/sync", config.listen.admin);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .context("admin HTTP client")?;
        let response = client
            .post(&url)
            .header(reqwest::header::HOST, authority)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(token)
            .body(serde_json::to_vec(&serde_json::json!({
                "repository": repository,
                "suite": suite,
            }))?)
            .send()
            .await
            .context("live gateway unreachable; offline synchronization requires --offline")?;
        let status = response.status();
        anyhow::ensure!(status.is_success(), "admin sync request refused ({status})");
        let body = response.text().await.context("admin sync response")?;
        println!(
            "triggered_live=true admin={} response={body}",
            config.listen.admin
        );
        return Ok(());
    }
    anyhow::ensure!(
        !config.is_fixture(),
        "offline synchronization requires durable mode"
    );
    config.validate_runtime().context("runtime configuration")?;
    crate::clock::require_synchronized_clock()
        .await
        .context("trusted synchronized host clock required before offline synchronization")?;
    let verifier = SignatureVerifier::new(config.verifier.binary.clone(), config.verifier.timeout)
        .await
        .context("signature verifier capability check")?;
    let durable = config.durable().context("durable configuration required")?;
    let spool_dir = config.spool_dir();
    anyhow::ensure!(
        spool_dir.join("state.sqlite").is_file(),
        "existing durable catalog required; run `ferrum storage init` first"
    );
    let limits = config.limits;
    let mut disk = DurableSpoolConfig::new(spool_dir.clone());
    disk.catalog_ceiling = disk
        .catalog_ceiling
        .min((limits.managed_ceiling_bytes / 4).max(16 * 1024 * 1024));
    disk.spool.managed_ceiling = limits.managed_ceiling_bytes;
    disk.spool.max_object_size = limits.max_object_bytes;
    disk.spool.read_chunk = limits.reader_buffer_bytes;
    disk.eviction_high_watermark = limits.managed_ceiling_bytes / 10 * 9;
    disk.eviction_low_watermark = limits.managed_ceiling_bytes / 5 * 4;
    disk.metadata_ceiling = disk.metadata_ceiling.min(limits.managed_ceiling_bytes / 2);
    disk.temporary_ceiling = disk.temporary_ceiling.min(limits.managed_ceiling_bytes / 4);
    disk.metadata_temporary_reserve = disk
        .metadata_temporary_reserve
        .min(disk.temporary_ceiling / 2);
    let spool = tokio::task::spawn_blocking(move || Spool::open_durable(disk))
        .await
        .context("durable spool startup task")?
        .with_context(|| format!("durable state {}", spool_dir.display()))?;
    let provider = durable
        .store_config()
        .provider_identity(durable.qualification_run_id.as_deref())?;
    let ledger = BudgetLedger::open_for_provider(spool.clone(), durable.budget, &provider)
        .context("existing remote budget and matching provider identity required")?;
    let store = Arc::new(match &durable.qualification_run_id {
        Some(run) => S3Store::open_qualification(durable.store_config(), ledger, run)
            .context("existing correlated private qualification namespaces")?,
        None => S3Store::open(durable.store_config(), ledger)
            .context("fixed NONISOLATED S3 operation identities")?,
    });
    let publisher = Arc::new(
        CheckpointPublisher::new(
            spool.clone(),
            Arc::clone(&store),
            RecoveryProfile::SharedNonisolated,
        )
        .context("checkpoint publisher")?,
    );
    let catalog =
        Arc::new(Catalog::configured(configured, Arc::clone(&publisher)).context("suite catalog")?);
    catalog.set_clock_synchronized(true);
    let metrics = Arc::new(Metrics::default());
    let mut synchronizer = DurableSynchronizer::new(
        Arc::new(config),
        verifier,
        spool.clone(),
        publisher,
        catalog,
        metrics,
    )
    .await
    .context("durable suite synchronizer")?;
    let cancel = CancellationToken::new();
    let guard = cancel.clone();
    tokio::pin!(shutdown);
    for key in &matched {
        let outcome = tokio::select! {
            () = &mut shutdown => {
                guard.cancel();
                anyhow::bail!("synchronization interrupted");
            }
            result = synchronizer.synchronize_once(key, &cancel) => {
                result.with_context(|| format!("synchronize {}/{}", key.repository(), key.suite()))?
            }
        };
        println!(
            "synced suite={}/{} outcome={}",
            key.repository(),
            key.suite(),
            match outcome {
                crate::sync::SyncOutcome::Published => "published",
                crate::sync::SyncOutcome::Renewed => "renewed",
            }
        );
    }
    spool.checkpoint().context("checkpoint durable catalog")?;
    Ok(())
}

#[cfg(all(test, feature = "test-harness"))]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ferrum_storage::budget::BudgetLimits;

    fn test_durable_spool(root: &std::path::Path) -> Spool {
        let mut disk = DurableSpoolConfig::new(root.to_path_buf());
        disk.free_space_floor = 0;
        disk.spool.managed_ceiling = 256 * 1024 * 1024;
        disk.spool.max_object_size = 32 * 1024 * 1024;
        disk.temporary_ceiling = 128 * 1024 * 1024;
        disk.metadata_temporary_reserve = 64 * 1024 * 1024;
        disk.metadata_ceiling = 128 * 1024 * 1024;
        disk.catalog_ceiling = 64 * 1024 * 1024;
        disk.eviction_high_watermark = 220 * 1024 * 1024;
        disk.eviction_low_watermark = 200 * 1024 * 1024;
        disk.max_entries = 4096;
        Spool::open_durable(disk).expect("durable test spool")
    }

    fn test_durable_config(root: &std::path::Path, state_dir: &std::path::Path) -> Config {
        let keyring = root.join("policy.gpg");
        let text = format!(
            "mode = \"private-durable\"\n[listen]\npublic = \"127.0.0.1:0\"\nadmin = \"127.0.0.1:0\"\n\
             [durable]\nstate_dir = \"{}\"\n\
             [durable.provider]\nregion = \"us-east-1\"\n\
             bucket = \"ferrum\"\ncredentials_file = \"{}\"\n\
             [durable.keyrings]\ndebian = \"{}\"\nubuntu = \"{}\"\n\
             [durable.budget]\nmode = \"existing\"\n[verifier]\n",
            state_dir.display(),
            root.join("unused-provider.env").display(),
            keyring.display(),
            keyring.display(),
        );
        Config::parse(&text, root).expect("durable config")
    }

    #[test]
    fn durable_store_injection_rejects_foreign_storage_owners() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_a = temp.path().join("state-a");
        let state_b = temp.path().join("state-b");
        let spool_a = test_durable_spool(&state_a);
        let spool_b = test_durable_spool(&state_b);
        let config_a = test_durable_config(temp.path(), &state_a);
        let durable_a = config_a.durable().expect("durable");

        let ledger_a =
            BudgetLedger::initialize(spool_a.clone(), BudgetLimits::default()).expect("ledger a");
        let (store_a, _remote_a) = S3Store::disk_backed_production(
            durable_a.store_config(),
            ledger_a,
            temp.path().join("remote-a"),
            64 * 1024 * 1024,
        )
        .expect("disk-backed store a");
        let store_a = Arc::new(store_a);

        let ledger_b =
            BudgetLedger::initialize(spool_b.clone(), BudgetLimits::default()).expect("ledger b");
        let (store_b, _remote_b) = S3Store::disk_backed_production(
            durable_a.store_config(),
            ledger_b,
            temp.path().join("remote-b"),
            64 * 1024 * 1024,
        )
        .expect("disk-backed store b");
        let store_b = Arc::new(store_b);

        validate_injected_durable_store(&config_a, &spool_a, &store_a)
            .expect("matching owned spool and store must succeed");
        assert!(
            validate_injected_durable_store(&config_a, &spool_a, &store_b).is_err(),
            "foreign S3Store bound to a different spool must be rejected"
        );
        assert!(
            validate_injected_durable_store(&config_a, &spool_b, &store_b).is_err(),
            "spool rooted outside configured state_dir must be rejected"
        );
    }

    #[test]
    fn retained_suite_selection_rejects_removal_but_allows_additions() {
        let root = tempfile::tempdir().expect("root");
        let config = test_durable_config(root.path(), &root.path().join("state"));
        let suites = config.suites().expect("configured suites");
        let retained =
            vec![ferrum_storage::checkpoint::SuiteKey::new("debian", "trixie").expect("suite")];
        validate_retained_suites(&retained, &suites).expect("retained suite selected");
        let selected: Vec<_> = suites
            .into_iter()
            .filter(|suite| suite.key.suite() != "trixie")
            .collect();
        let error =
            validate_retained_suites(&retained, &selected).expect_err("removed retained suite");
        assert!(error.to_string().contains("debian/trixie"));
        validate_retained_suites(&[], &selected).expect("fresh selection");
    }
}
