//! `ferrum serve --config <path>`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "ferrum", version, about = "Ferrum APT mirror gateway")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the configured repository until SIGTERM/SIGINT.
    Serve {
        /// Path to the TOML configuration file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Trigger or run synchronization for all mirrors, one mirror repository, or one suite.
    Sync {
        /// Path to the TOML configuration file.
        #[arg(long)]
        config: PathBuf,
        /// Optional target (`all`, `<repository>`, or `<repository>/<suite>`).
        target: Option<String>,
        /// Optional mirror repository name (e.g. `debian`, `ubuntu`, `archlinux`, `almalinux`).
        #[arg(long)]
        repository: Option<String>,
        /// Optional suite name within the repository (e.g. `trixie`, `noble`, `core`).
        #[arg(long)]
        suite: Option<String>,
        /// Run one direct offline synchronization pass instead of signaling a running gateway.
        #[arg(long)]
        offline: bool,
    },
    /// Warm explicit authenticated package paths through a running private admin listener.
    Prewarm {
        #[arg(long)]
        config: PathBuf,
        #[command(subcommand)]
        operation: PrewarmOperation,
    },
    /// Explicit owned-prefix private fixture operations (never production durability).
    PrivateS3 {
        #[arg(long)]
        config: PathBuf,
        #[command(subcommand)]
        operation: PrivateS3Operation,
    },
    /// Offline maintenance; refuses a live gateway lock or missing durable accounting.
    Storage {
        #[arg(long)]
        config: PathBuf,
        #[command(subcommand)]
        operation: StorageOperation,
    },
    /// Local administration credentials and explicit offline state migration.
    Admin {
        #[command(subcommand)]
        operation: AdminOperation,
    },
}

#[derive(Subcommand)]
enum PrewarmOperation {
    /// Submit bounded background fills; never downloads package bodies to the CLI.
    Run {
        /// Explicit repository package paths (not URLs, metadata, or globs).
        #[arg(required = true)]
        paths: Vec<String>,
        /// Cap admitted authenticated package/signature bytes, not retry or wire bytes.
        /// Existing durable transfer allowances independently bound provider traffic.
        #[arg(long)]
        max_bytes: u64,
        /// Cap package plus possible detached-signature objects.
        #[arg(long, default_value_t = 128)]
        max_objects: usize,
        /// Stop admission and background-only work after this deadline.
        #[arg(long, default_value_t = 300)]
        timeout_seconds: u64,
        /// Background producers; must leave at least one configured fill slot free.
        #[arg(long, default_value_t = 1)]
        concurrency: usize,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Read durable job results, cache hits, failures, and conservative byte charges.
    Status { id: String },
    /// Cancel admission and background-only work; shared foreground fills may finish.
    Cancel { id: String },
}

#[derive(Subcommand)]
enum AdminOperation {
    /// Move legacy users out of the exclusively locked spool without changing its ledger.
    Migrate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Print the protected, one-time first-administrator setup token to this terminal.
    SetupToken {
        #[arg(long)]
        config: PathBuf,
    },
    /// Print the protected status/sync token for local administrative tooling.
    ControlToken {
        #[arg(long)]
        config: PathBuf,
    },
    /// Produce a validated, relative-path-resolved managed configuration copy.
    AdoptConfig {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum PrivateS3Operation {
    /// Fresh 8 MiB upload / 16 MiB download allowance; refuses an existing directory.
    InitLedger,
    /// Authenticate fixed fixture, create-only PUT, full verified GET readback.
    Seed,
    /// Conditional same-size corruption of the recorded owned fixture key.
    Corrupt,
    /// Real provider 403 with invalid sentinel; persistently opens backend circuit.
    Forbidden,
    /// Conditional deletion of only recorded, reconciled owned keys; no sweeps.
    Cleanup,
    /// Non-secret private allowance and ownership evidence.
    Status,
}

#[derive(Subcommand)]
enum StorageOperation {
    /// Report retained usage without provider requests or resetting the transfer allowance.
    Status,
    /// Initialize a fresh durable catalog, budget ledger, and audited initial bootstrap.
    Init {
        #[arg(long)]
        operator: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        disclosure: String,
    },
    /// Offline audited binding to the original fixed provider; never migrates or resets state.
    AdoptLegacyProvider {
        #[arg(long)]
        operator: String,
        #[arg(long)]
        reason: String,
        /// Exact acknowledgement: LEGACY PROVIDER VERIFIED; NO DATA OR ALLOWANCE RESET
        #[arg(long)]
        disclosure: String,
    },
    /// Authorize an audited bootstrap from current authenticated origins while offline.
    AuthorizeBootstrap {
        #[arg(long)]
        repository: Option<String>,
        #[arg(long)]
        suite: Option<String>,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        disclosure: String,
    },
    /// Delete only expired catalog-owned package artifacts; never checkpoints or unknown keys.
    Gc {
        /// Explicitly permit the maintenance deletion pass.
        #[arg(long)]
        execute: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve { config } => serve(&config).await,
        Command::Prewarm { config, operation } => {
            async {
                use ferrum::prewarm::{PrewarmCommand, PrewarmRequest};

                let config = ferrum::config::Config::load(&config)?;
                let command = match operation {
                    PrewarmOperation::Run {
                        paths,
                        max_bytes,
                        max_objects,
                        timeout_seconds,
                        concurrency,
                        reason,
                        idempotency_key,
                    } => PrewarmCommand::Run(PrewarmRequest {
                        paths,
                        max_bytes,
                        max_objects,
                        timeout_seconds,
                        concurrency,
                        reason,
                        idempotency_key,
                    }),
                    PrewarmOperation::Status { id } => PrewarmCommand::Status(id),
                    PrewarmOperation::Cancel { id } => PrewarmCommand::Cancel(id),
                };
                let result = ferrum::prewarm::execute(&config, command).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                Ok(())
            }
            .await
        }
        Command::Admin { operation } => {
            tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                match operation {
                    AdminOperation::Migrate { config } => {
                        let config = ferrum::config::Config::load(&config)?;
                        let report = ferrum::admin::migration::migrate(
                            &config.spool_dir(),
                            &config.admin.state_dir,
                        )?;
                        println!(
                            "users={} already_migrated={}",
                            report.users, report.already_migrated
                        );
                    }
                    AdminOperation::SetupToken { config } => {
                        let config = ferrum::config::Config::load(&config)?;
                        println!(
                            "{}",
                            ferrum::admin::migration::read_bootstrap_token(
                                &config.admin.state_dir,
                            )?
                        );
                    }
                    AdminOperation::ControlToken { config } => {
                        let config = ferrum::config::Config::load(&config)?;
                        println!(
                            "{}",
                            ferrum::admin::migration::read_control_token(&config.admin.state_dir,)?
                        );
                    }
                    AdminOperation::AdoptConfig { config, output } => {
                        let report =
                            ferrum::admin::settings::adopt_managed_config(&config, &output)
                                .map_err(anyhow::Error::msg)?;
                        println!(
                            "source={} output={} revision={} restart_required={}",
                            report.source_path.display(),
                            report.output_path.display(),
                            report.revision,
                            report.restart_required
                        );
                    }
                }
                Ok(())
            })
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("local administration task failed")))
        }
        Command::Sync {
            config,
            target,
            repository,
            suite,
            offline,
        } => {
            async {
                let loaded = ferrum::config::Config::load(&config)?;
                ferrum::app::sync(
                    loaded,
                    target,
                    repository,
                    suite,
                    offline,
                    shutdown_signal(),
                )
                .await
            }
            .await
        }
        Command::PrivateS3 { config, operation } => {
            use ferrum::fixture_s3::PrivateS3Command;
            let operation = match operation {
                PrivateS3Operation::InitLedger => PrivateS3Command::InitLedger,
                PrivateS3Operation::Seed => PrivateS3Command::Seed,
                PrivateS3Operation::Corrupt => PrivateS3Command::Corrupt,
                PrivateS3Operation::Forbidden => PrivateS3Command::Forbidden,
                PrivateS3Operation::Cleanup => PrivateS3Command::Cleanup,
                PrivateS3Operation::Status => PrivateS3Command::Status,
            };
            ferrum::fixture_s3::run(&config, operation).await
        }
        Command::Storage { config, operation } => {
            use ferrum::maintenance::MaintenanceCommand;
            let command = match operation {
                StorageOperation::Status => MaintenanceCommand::Status,
                StorageOperation::Init {
                    operator,
                    reason,
                    disclosure,
                } => MaintenanceCommand::Init {
                    operator,
                    reason,
                    disclosure,
                },
                StorageOperation::AdoptLegacyProvider {
                    operator,
                    reason,
                    disclosure,
                } => MaintenanceCommand::AdoptLegacyProvider {
                    operator,
                    reason,
                    disclosure,
                },
                StorageOperation::AuthorizeBootstrap {
                    repository,
                    suite,
                    operator,
                    reason,
                    disclosure,
                } => MaintenanceCommand::AuthorizeBootstrap {
                    repository,
                    suite,
                    operator,
                    reason,
                    disclosure,
                },
                StorageOperation::Gc { execute } => MaintenanceCommand::Gc { execute },
            };
            ferrum::maintenance::run(&config, command, shutdown_signal()).await
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = format!("{error:#}"), "ferrum failed");
            ExitCode::FAILURE
        }
    }
}

async fn serve(path: &std::path::Path) -> anyhow::Result<()> {
    let config = ferrum::config::Config::load(path)?;
    ferrum::app::run(config, shutdown_signal()).await
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
                tracing::warn!(%error, "SIGTERM handler unavailable; only SIGINT stops the gateway");
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
