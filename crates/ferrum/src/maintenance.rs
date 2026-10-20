//! Offline maintenance of an existing durable store. Never initializes missing accounting.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, ensure};
use ferrum_storage::budget::{BudgetLedger, BudgetLimits, LegacyProviderAdoption};
use ferrum_storage::checkpoint::{CheckpointPublisher, RecoveryProfile, SuiteKey};
use ferrum_storage::gc::OfflineGc;
use ferrum_storage::recovery::BootstrapAudit;
use ferrum_storage::s3::S3Config;
use ferrum_storage::{DurableSpoolConfig, Spool};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::config::{ALL_DISTRIBUTION_SUITES, resolve_suite_selection};

#[derive(Clone)]
pub enum MaintenanceCommand {
    Status,
    Init {
        operator: String,
        reason: String,
        disclosure: String,
    },
    AdoptLegacyProvider {
        operator: String,
        reason: String,
        disclosure: String,
    },
    AuthorizeBootstrap {
        repository: Option<String>,
        suite: Option<String>,
        operator: String,
        reason: String,
        disclosure: String,
    },
    Gc {
        execute: bool,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceConfig {
    state_directory: PathBuf,
    provider: S3Config,
    budget: ApprovedBudget,
    /// Only an explicitly owned private qualifier uses this field; no arbitrary prefix.
    qualification_run_id: Option<String>,
    #[serde(default)]
    suites: Option<Vec<String>>,
    #[serde(default)]
    retired_suites: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedBudget {
    storage_bytes: u64,
    storage_control_bytes: u64,
    monthly_download_bytes: u64,
    download_control_bytes: u64,
}

impl ApprovedBudget {
    fn limits(&self) -> BudgetLimits {
        BudgetLimits {
            storage: self.storage_bytes,
            storage_control: self.storage_control_bytes,
            monthly_download: self.monthly_download_bytes,
            download_control: self.download_control_bytes,
        }
    }
}

impl MaintenanceConfig {
    fn load(path: &Path, require_existing: bool) -> anyhow::Result<Self> {
        const LIMIT: usize = 64 * 1024;
        let mut text = String::new();
        std::fs::File::open(path)
            .context("open maintenance configuration")?
            .take((LIMIT + 1) as u64)
            .read_to_string(&mut text)
            .context("read bounded maintenance configuration")?;
        ensure!(
            text.len() <= LIMIT,
            "maintenance configuration exceeds 64 KiB"
        );
        // Do not print parser errors containing the input: configuration must not leak secrets.
        let config: Self = toml::from_str(&text)
            .map_err(|_| anyhow::anyhow!("invalid maintenance configuration"))?;
        ensure!(
            config.state_directory.is_absolute(),
            "absolute state directory required"
        );
        ensure!(
            config.provider.credentials_file.is_absolute(),
            "absolute credential file required"
        );
        let catalog_exists = config.state_directory.join("state.sqlite").exists();
        if require_existing {
            ensure!(
                config.state_directory.join("state.sqlite").is_file(),
                "existing durable catalog required; maintenance never initializes missing state"
            );
        } else {
            ensure!(
                !catalog_exists,
                "durable catalog already exists; init never resets existing state"
            );
        }
        if let Some(run) = &config.qualification_run_id {
            ensure!(
                run.len() == 32
                    && run
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "invalid private qualification identity"
            );
        }
        resolve_suite_selection(config.suites.as_deref(), &config.retired_suites)
            .map_err(|reason| anyhow::anyhow!("invalid maintenance suites: {reason}"))?;
        Ok(config)
    }
}

pub async fn run(
    path: &Path,
    command: MaintenanceCommand,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    if matches!(command, MaintenanceCommand::Gc { execute: false }) {
        anyhow::bail!("GC deletes expired catalog-owned objects; explicit --execute required");
    }
    let require_existing = !matches!(command, MaintenanceCommand::Init { .. });
    let config = MaintenanceConfig::load(path, require_existing)?;
    let provider = config
        .provider
        .provider_identity(config.qualification_run_id.as_deref())?;
    if !matches!(command, MaintenanceCommand::Status) && config.qualification_run_id.is_none() {
        crate::clock::require_synchronized_clock()
            .await
            .context("trusted host clock inspection failed; maintenance operation refused")?;
    }
    let limits = config.budget.limits();
    let disk = DurableSpoolConfig::new(config.state_directory.clone());
    match command {
        MaintenanceCommand::Status => {
            // Same exclusive process lock: status cannot reconcile under a live server.
            let spool = Spool::open_durable(disk)?;
            BudgetLedger::check_provider(&spool, &provider)
                .context("configured provider does not match the catalog binding")?;
            let remote = BudgetLedger::inspect(&spool)?;
            println!(
                "remote_storage_bytes={} download_charged_bytes={} package_download_charged_bytes={} accounting_certain={}",
                remote.storage, remote.download, remote.package_download, remote.certain
            );
            println!("local_storage={:?}", spool.usage()?);
            let (active, retired) =
                resolve_suite_selection(config.suites.as_deref(), &config.retired_suites)
                    .map_err(|reason| anyhow::anyhow!(reason))?;
            for (status, suites) in [("active", active), ("retired", retired)] {
                for suite in suites {
                    println!(
                        "suite={}/{} status={status}",
                        suite.repository.name(),
                        suite.suite
                    );
                }
            }
            Ok(())
        }
        MaintenanceCommand::Init {
            operator,
            reason,
            disclosure,
        } => {
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            let _ = BootstrapAudit::acknowledge_reset(&operator, &reason, now, &disclosure)?;
            std::fs::create_dir_all(&config.state_directory)
                .context("create durable state directory")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &config.state_directory,
                    std::fs::Permissions::from_mode(0o700),
                )
                .context("restrict durable state directory permissions")?;
            }
            let spool = Spool::open_durable(disk)?;
            let _ledger = BudgetLedger::initialize_for_provider(spool.clone(), limits, &provider)?;
            let (configured, _) =
                resolve_suite_selection(config.suites.as_deref(), &config.retired_suites)
                    .map_err(|reason| anyhow::anyhow!(reason))?;
            for entry in &configured {
                let key = SuiteKey::new(entry.repository.name(), entry.suite)?;
                let audit =
                    BootstrapAudit::acknowledge_reset(&operator, &reason, now, &disclosure)?;
                CheckpointPublisher::authorize_bootstrap(
                    &spool,
                    RecoveryProfile::SharedNonisolated,
                    &key,
                    audit,
                )?;
            }
            spool.checkpoint()?;
            println!(
                "initialized=true suites={} state_directory={}",
                configured.len(),
                config.state_directory.display()
            );
            Ok(())
        }
        MaintenanceCommand::AdoptLegacyProvider {
            operator,
            reason,
            disclosure,
        } => {
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            let audit = LegacyProviderAdoption::acknowledge(&operator, &reason, now, &disclosure).context("legacy adoption requires operator, reason and exact disclosure: LEGACY PROVIDER VERIFIED; NO DATA OR ALLOWANCE RESET")?;
            let spool = Spool::open_durable(disk)?;
            BudgetLedger::adopt_legacy_provider(&spool, &provider, audit).context("only an unbound legacy catalog belonging to the original fixed provider may be adopted")?;
            spool.checkpoint()?;
            println!("legacy_provider_adopted=true accounting_reset=false");
            Ok(())
        }
        MaintenanceCommand::AuthorizeBootstrap {
            repository,
            suite,
            operator,
            reason,
            disclosure,
        } => {
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            let _ = BootstrapAudit::acknowledge_reset(&operator, &reason, now, &disclosure)?;
            let (active, retired) =
                resolve_suite_selection(config.suites.as_deref(), &config.retired_suites)
                    .map_err(|reason| anyhow::anyhow!(reason))?;
            let targets: Vec<SuiteKey> = match (repository, suite) {
                (None, None) => active
                    .into_iter()
                    .map(|entry| SuiteKey::new(entry.repository.name(), entry.suite))
                    .collect::<Result<_, _>>()?,
                (Some(repo), Some(name)) => {
                    let allowed = ALL_DISTRIBUTION_SUITES
                        .iter()
                        .any(|entry| entry.repository.name() == repo && entry.suite == name)
                        || (config.qualification_run_id.is_some()
                            && repo == crate::config::REPOSITORY_PREFIX
                            && name == crate::config::SUITE);
                    ensure!(allowed, "unconfigured repository/suite for bootstrap");
                    ensure!(
                        !retired.iter().any(|entry| {
                            entry.repository.name() == repo && entry.suite == name
                        }),
                        "retired suite cannot be authorized for bootstrap; reactivate it first"
                    );
                    vec![SuiteKey::new(&repo, &name)?]
                }
                _ => anyhow::bail!("--repository and --suite must be supplied together or omitted"),
            };
            let spool = Spool::open_durable(disk)?;
            let _ledger = BudgetLedger::open_for_provider(spool.clone(), limits, &provider)?;
            for key in &targets {
                let audit =
                    BootstrapAudit::acknowledge_reset(&operator, &reason, now, &disclosure)?;
                CheckpointPublisher::authorize_bootstrap(
                    &spool,
                    RecoveryProfile::SharedNonisolated,
                    key,
                    audit,
                )?;
            }
            spool.checkpoint()?;
            println!("bootstrap_authorized={}", targets.len());
            Ok(())
        }
        MaintenanceCommand::Gc { .. } => {
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            let mut gc = match config.qualification_run_id {
                Some(run) => OfflineGc::open_qualification(disk, config.provider, limits, &run)?,
                None => OfflineGc::open(disk, config.provider, limits)?,
            };
            let cancel = CancellationToken::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
            let operation = gc.run(now, deadline, &cancel);
            tokio::pin!(operation);
            let report = tokio::select! {
                result = &mut operation => result?,
                () = shutdown => {
                    cancel.cancel();
                    operation.await?
                }
            };
            println!(
                "discovered={} deleted={} retained_or_unknown={} multipart_reaped={}",
                report.discovered,
                report.deleted,
                report.retained_or_unknown,
                report.multipart_reaped
            );
            Ok(())
        }
    }
}
