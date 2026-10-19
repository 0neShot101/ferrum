//! Explicit private-fixture provider operations; no production writer or durability claim.
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use ferrum_apt::signature::SignatureVerifier;
use ferrum_storage::s3::S3Store;
use ferrum_storage::{Spool, SpoolConfig, VerifiedObject};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::fetch::{UpstreamClient, fill_object};
use crate::health::Metrics;
use crate::sync::{Catalog, Resolution, Synchronizer};

const FIXTURE_PACKAGE: &str = "pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb";

#[derive(Clone, Copy)]
pub enum PrivateS3Command {
    InitLedger,
    Seed,
    Corrupt,
    Forbidden,
    Cleanup,
    Status,
}

/// All commands validate the same private mode, fixed origin and loopback listeners.
/// Mutating package commands authenticate signed metadata and fetch through the
/// ordinary origin-to-verified-spool pipeline. Run with the gateway stopped.
pub async fn run(path: &Path, command: PrivateS3Command) -> anyhow::Result<()> {
    let config = Config::load(path)?;
    config.validate_runtime()?;
    let s3 = config
        .s3
        .clone()
        .context("private-s3 requires an explicit [s3] section")?;
    if matches!(command, PrivateS3Command::InitLedger) {
        S3Store::initialize_private_journal(&s3)?;
        println!(
            "initialized private-test allowance: upload=8388608 download=16777216; reopen only, no reset"
        );
        return Ok(());
    }
    let store = S3Store::open_private(s3)?;
    let deadline = tokio::time::Instant::now() + config.limits.producer_deadline;
    let cancel = CancellationToken::new();
    match command {
        PrivateS3Command::InitLedger => unreachable_command(),
        PrivateS3Command::Cleanup => {
            store.cleanup_private(deadline, cancel).await?;
            println!("conditional cleanup completed for recorded owned keys only");
            Ok(())
        }
        PrivateS3Command::Status => {
            println!("{}", serde_json::to_string_pretty(&store.status()?)?);
            Ok(())
        }
        PrivateS3Command::Seed | PrivateS3Command::Corrupt | PrivateS3Command::Forbidden => {
            let object = authenticate_fixture_package(config).await?;
            match command {
                PrivateS3Command::Seed => {
                    store.put_file(&object, deadline, cancel.clone()).await?;
                    store
                        .verify_seed(object.identity(), deadline, cancel)
                        .await?;
                    println!(
                        "private fixture seeded and fully GET-verified: sha256={} size={}; NOT Durable",
                        object.sha256(),
                        object.size()
                    );
                }
                PrivateS3Command::Corrupt => {
                    store
                        .corrupt_private_fixture(&object, deadline, cancel)
                        .await?;
                    println!(
                        "owned private fixture conditionally corrupted for negative GET verification"
                    );
                }
                PrivateS3Command::Forbidden => {
                    store
                        .probe_forbidden_private(object.identity(), deadline, cancel)
                        .await?;
                    println!(
                        "provider returned Forbidden for invalid sentinel; persistent circuit open, no origin fallback"
                    );
                }
                _ => return unreachable_command(),
            }
            Ok(())
        }
    }
}

fn unreachable_command() -> anyhow::Result<()> {
    bail!("private-s3 command dispatch invariant failed")
}

async fn authenticate_fixture_package(config: Config) -> anyhow::Result<VerifiedObject> {
    let config = Arc::new(config);
    std::fs::create_dir_all(&config.fixture.work_dir)?;
    let spool = Spool::open_exclusive_fixture(SpoolConfig {
        root: config.spool_dir(),
        managed_ceiling: config.limits.managed_ceiling_bytes,
        max_object_size: config.limits.max_object_bytes,
        io_workers: 8,
        read_chunk: config.limits.reader_buffer_bytes,
    })?;
    let client = Arc::new(UpstreamClient::new(
        config.origin_base.clone(),
        &config.limits,
    )?);
    let verifier =
        SignatureVerifier::new(config.verifier.binary.clone(), config.verifier.timeout).await?;
    let catalog = Arc::new(Catalog::new());
    let synchronizer = Synchronizer::new(
        config.clone(),
        verifier,
        spool.clone(),
        client.clone(),
        catalog.clone(),
        Arc::new(Metrics::default()),
    )
    .await?;
    synchronizer
        .authenticate_once()
        .await
        .context("authenticate fixed signed fixture metadata before provider operation")?;
    let view = catalog
        .load()
        .context("authenticated fixture active view")?;
    let Resolution::Package { identity, path } = view.resolve(FIXTURE_PACKAGE) else {
        bail!("fixed package is absent from authenticated fixture closure");
    };
    let object = tokio::time::timeout(
        config.limits.producer_deadline,
        fill_object(&client, &spool, identity, &path, &config.limits),
    )
    .await??;
    // VerifiedObject retains the spool lease through PUT and readback after this scope.
    Ok(object)
}
