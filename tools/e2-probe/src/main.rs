#![forbid(unsafe_code)]

mod config;
mod journal;
mod probe;
mod wire;

use anyhow::{Result, bail, ensure};
use serde_json::json;
use std::{fs::OpenOptions, io::Read, path::PathBuf};

struct Arguments {
    cleanup: bool,
    inspect: bool,
    profile: config::BudgetProfile,
    environment: PathBuf,
    directory: PathBuf,
}

fn arguments() -> Result<Arguments> {
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("run, qualify, cleanup or inspect required"))?;
    let cleanup = command == "cleanup";
    let inspect = command == "inspect";
    let profile = if command == "qualify" {
        config::BudgetProfile::Qualification
    } else if command == "run" || cleanup || inspect {
        config::BudgetProfile::LegacyBlob
    } else {
        bail!("run, qualify, cleanup or inspect required")
    };
    let mut environment = None;
    let mut directory = None;
    let mut approved = false;
    while let Some(argument) = arguments.next() {
        if argument == "--env-file" {
            ensure!(environment.is_none(), "duplicate env-file");
            environment = Some(PathBuf::from(
                arguments
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("env-file value missing"))?,
            ));
        } else if argument == "--run-dir" {
            ensure!(directory.is_none(), "duplicate run-dir");
            directory = Some(PathBuf::from(
                arguments
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("run-dir value missing"))?,
            ));
        } else if argument == "--approve-disposable-probe" {
            ensure!(!approved, "duplicate approval");
            approved = true;
        } else {
            bail!("unknown probe argument");
        }
    }
    ensure!(
        approved,
        "explicit disposable-prefix operation approval flag required"
    );
    ensure!(
        cfg!(target_os = "linux"),
        "probe runtime is restricted to the approved Linux host"
    );
    let environment = environment.ok_or_else(|| anyhow::anyhow!("env-file required"))?;
    let directory = directory.ok_or_else(|| anyhow::anyhow!("run-dir required"))?;
    ensure!(
        environment.is_absolute() && directory.is_absolute(),
        "absolute credential and evidence paths required"
    );
    Ok(Arguments {
        cleanup,
        inspect,
        profile,
        environment,
        directory,
    })
}

fn random_prefix() -> Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    use std::fmt::Write;
    let mut prefix = String::with_capacity(config::ROOT.len() + 33);
    prefix.push_str(config::ROOT);
    for byte in bytes {
        write!(&mut prefix, "{byte:02x}")?;
    }
    prefix.push('/');
    config::validate_prefix(&prefix)?;
    Ok(prefix)
}

async fn interrupted() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn execute(arguments: Arguments) -> Result<()> {
    let journal = if arguments.cleanup || arguments.inspect {
        journal::Journal::open(&arguments.directory)?
    } else {
        journal::Journal::create(&arguments.directory, random_prefix()?, arguments.profile)?
    };
    let lock_path = arguments.directory.join("active.lock");
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(&lock_path)?;
    lock.sync_all()?;
    journal::sync_directory(&arguments.directory)?;
    let result = async {
        let wire = wire::Wire::new(journal.clone());
        let client = config::client(&arguments.environment, wire.clone())?;
        let probe = probe::Probe::new(client, wire.clone(), journal.clone(), &arguments.directory)?;
        if arguments.inspect {
            // Reopen the existing allowance. No cleanup, object write, LIST or matrix rerun.
            return probe.inspect_configuration().await;
        }
        let run = if arguments.cleanup {
            Ok(())
        } else {
            tokio::select! {
                result = probe.run() => result,
                signal = interrupted() => {
                    signal?;
                    journal::lock(&journal)?.event(json!({"kind":"interruption", "outcome":"cancelled_then_cleanup"}))?;
                    Err(anyhow::anyhow!("probe interrupted"))
                }
            }
        };
        // Cleanup is attempted after every ordinary operation error and handled signal. A failed
        // cleanup never discards the manifest, upload IDs, reservation ledger or evidence.
        let cleanup = probe.cleanup().await;
        let (uploaded, downloaded) = wire.totals();
        let mut journal = journal::lock(&journal)?;
        journal.manifest.outcome = if run.is_ok() && cleanup.is_ok() {
            if arguments.cleanup {
                "cleanup_complete"
            } else if arguments.profile == config::BudgetProfile::Qualification {
                "qualification_matrix_pass_cleaned_review_report"
            } else {
                "subset_pass_cleaned_full_b02_open"
            }
        } else {
            "failed_retained_manifest"
        }
        .to_owned();
        let outcome = journal.manifest.outcome.clone();
        let summary = json!({"kind":"summary", "outcome":outcome, "run_success":run.is_ok(), "cleanup_success":cleanup.is_ok(), "process_upload_body_bytes":uploaded, "process_download_body_bytes":downloaded, "upload_reserved":journal.manifest.upload_reserved, "download_reserved":journal.manifest.download_reserved, "budget_profile":journal.manifest.budget_profile, "credential_profile":"shared_NONISOLATED", "full_b02":"requires_report_review", "billing_accuracy_claim":false});
        journal.event(summary)?;
        run?;
        cleanup
    }
    .await;
    if result.is_err() {
        let mut journal = journal::lock(&journal)?;
        journal.manifest.outcome = "failed_retained_manifest".to_owned();
        journal.event(json!({"kind":"exit", "outcome":"nonzero", "details":"inspect redacted evidence and retained manifest; do not start another run to reset this allowance"}))?;
    }
    drop(lock);
    std::fs::remove_file(lock_path)?;
    journal::sync_directory(&arguments.directory)?;
    result
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let result = match arguments() {
        Ok(arguments) => execute(arguments).await,
        Err(error) => Err(error),
    };
    if result.is_err() {
        // Never format SDK errors, credential values, authorization headers or URLs containing
        // credentials. Detailed evidence is restricted to explicit safe classifications.
        eprintln!(
            "Probe failed. Require run|qualify|cleanup|inspect --env-file ABSOLUTE --run-dir ABSOLUTE --approve-disposable-probe; retain manifest.json and evidence.jsonl if created. No qualification is implied."
        );
        std::process::exit(1);
    }
    println!(
        "Requested bounded operation completed. Review manifest.json and evidence.jsonl; unknown configuration is not approval, shared credentials are NONISOLATED. No deployment authorization."
    );
}
