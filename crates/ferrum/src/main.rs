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
