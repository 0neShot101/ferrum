//! `ferrum-fixture-origin`: loopback-only fault-injectable static origin.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;
use ferrum_fixture_origin::{OriginConfig, RunningOrigin, require_loopback};

#[derive(Parser, Debug)]
#[command(name = "ferrum-fixture-origin", about, version)]
struct Arguments {
    /// Directory whose regular files are served.
    #[arg(long)]
    root: PathBuf,
    /// Loopback address for the data server.
    #[arg(long, default_value = "127.0.0.1:18080")]
    listen: SocketAddr,
    /// Loopback address for the JSON control API.
    #[arg(long, default_value = "127.0.0.1:18081")]
    control: SocketAddr,
    /// URL prefix under which `--root` is exposed; must start and end with '/'.
    #[arg(long, default_value = "/fixture/")]
    prefix: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    require_loopback(arguments.listen).context("--listen")?;
    require_loopback(arguments.control).context("--control")?;

    let running = RunningOrigin::bind(OriginConfig {
        root: arguments.root,
        listen: arguments.listen,
        control: arguments.control,
        prefix: arguments.prefix,
    })
    .await?;

    tokio::signal::ctrl_c()
        .await
        .context("waiting for shutdown signal")?;
    tracing::info!("shutting down");
    running.shutdown().await;
    Ok(())
}
