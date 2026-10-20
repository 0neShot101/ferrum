//! Disposable loopback throughput measurement. The server uses fixture authority only.
//! Run server and load modes in separate processes; never point load at production.

use anyhow::{Context, ensure};
use clap::{Parser, Subcommand};
use ferrum::{app, config::Config, sync::ActiveView};
use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest, Sha256Hasher},
    path::RepositoryPath,
};
use ferrum_fixture_origin::{OriginConfig, RunningOrigin};
use futures_util::StreamExt;
use serde::Serialize;
use std::{
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
    },
    Load {
        #[arg(long)]
        address: SocketAddr,
        #[arg(long, default_value_t = 4_194_304)]
        bytes: u64,
        #[arg(long, default_value_t = 16)]
        clients: usize,
        #[arg(long, default_value_t = 16)]
        requests: usize,
        #[arg(long, default_value_t = false)]
        range: bool,
        /// Trust this local test certificate and connect through HTTPS.
        #[arg(long)]
        tls_ca: Option<PathBuf>,
    },
}

#[derive(Serialize)]
struct Report {
    clients: usize,
    requests: usize,
    bytes: u64,
    elapsed_ns: u128,
    headers_p99_ns: u128,
    completion_p99_ns: u128,
}

const SIZES: [u64; 3] = [65_536, 4_194_304, 16_777_216];

fn block() -> Vec<u8> {
    (0..65_536).map(|offset| (offset % 251) as u8).collect()
}

fn identity(size: u64, block: &[u8]) -> ObjectIdentity {
    let mut hasher = Sha256Hasher::new();

    for _ in 0..size / block.len() as u64 {
        hasher.update(block);
    }

    ObjectIdentity {
        sha256: hasher.finalize(),
        size,
    }
}

async fn serve(listen: SocketAddr) -> anyhow::Result<()> {
    ensure!(
        listen.ip().is_loopback(),
        "fixture listener must be loopback"
    );
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("origin");
    std::fs::create_dir_all(root.join("pool"))?;
    let block = block();
    let mut packages = Vec::new();

    for size in SIZES {
        let path = RepositoryPath::parse_decoded(&format!("pool/{size}.deb"))?;
        let mut file = std::fs::File::create(root.join(path.as_str()))?;

        for _ in 0..size / block.len() as u64 {
            file.write_all(&block)?;
        }

        packages.push((path, identity(size, &block)));
    }

    let origin = RunningOrigin::bind(OriginConfig {
        root,
        listen: "127.0.0.1:0".parse()?,
        control: "127.0.0.1:0".parse()?,
        prefix: "/fixture/".to_owned(),
    })
    .await?;
    let work = directory.path().join("work");
    let text = format!(
        "mode = \"private-fixture\"\n[listen]\npublic = \"{listen}\"\nadmin = \"127.0.0.1:0\"\n\
         [fixture]\nkeyring = \"{}\"\nwork_dir = \"{}\"\n[verifier]\n[limits]\n",
        directory.path().join("unused.gpg").display(),
        work.display()
    );
    let mut config = Config::parse(&text, &work)?;
    config.set_test_origin(format!("http://{}/fixture/", origin.data_addr()).parse()?)?;
    let admin_state = config.admin.state_dir.clone();
    let view = ActiveView::for_tests(packages, Duration::from_secs(3600));
    let gateway = app::start_with_view(config, Some(view), CancellationToken::new()).await?;

    println!(
        "{}",
        serde_json::json!({
            "address": gateway.public_addr,
            "admin_address": gateway.admin_addr,
            "admin_state": admin_state,
            "pid": std::process::id()
        })
    );
    std::io::stdout().flush()?;
    tokio::signal::ctrl_c().await?;
    gateway.shutdown().await?;
    origin.shutdown().await;

    Ok(())
}

async fn request(
    client: &reqwest::Client,
    url: &str,
    expected: ObjectIdentity,
    range: bool,
) -> anyhow::Result<(u128, u128)> {
    let started = Instant::now();
    let mut request = client.get(url).header("Accept-Encoding", "identity");

    if range {
        request = request.header("Range", "bytes=0-0");
    }

    let response = request.send().await?;
    let headers = started.elapsed().as_nanos();
    let size = if range { 1 } else { expected.size };
    ensure!(
        response.status().as_u16() == if range { 206 } else { 200 },
        "unexpected status {}",
        response.status()
    );
    ensure!(response.content_length() == Some(size), "wrong length");
    let mut stream = response.bytes_stream();
    let mut hasher = Sha256Hasher::new();
    let mut received = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        hasher.update(&chunk);
        received += chunk.len() as u64;
        ensure!(received <= size, "overlong body");
    }

    ensure!(received == size, "truncated body");
    let digest = if range {
        Sha256Digest::of(&[0])
    } else {
        expected.sha256
    };
    ensure!(hasher.finalize() == digest, "wrong body digest");

    Ok((headers, started.elapsed().as_nanos()))
}

async fn load(
    address: SocketAddr,
    size: u64,
    clients: usize,
    requests: usize,
    range: bool,
    tls_ca: Option<PathBuf>,
) -> anyhow::Result<()> {
    ensure!(address.ip().is_loopback(), "load is limited to loopback");
    ensure!(SIZES.contains(&size), "unsupported fixture size");
    ensure!(
        (1..=64).contains(&clients) && (1..=256).contains(&requests),
        "invalid load bound"
    );
    let transferred = size
        .checked_mul(clients as u64)
        .and_then(|value| value.checked_mul(requests as u64))
        .context("load overflow")?;
    ensure!(
        transferred <= 4 * 1024 * 1024 * 1024,
        "load exceeds 4 GiB bound"
    );
    let expected = identity(size, &block());
    let scheme = if tls_ca.is_some() { "https" } else { "http" };
    let url = format!("{scheme}://{address}/fixture/pool/{size}.deb");
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(clients);

    if let Some(certificate) = tls_ca {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            certificate,
        )?)?);
    }

    let client = builder.build()?;

    // Verify and populate the fixture before timing warm responses.
    request(&client, &url, expected, false).await?;
    let started = Instant::now();
    let mut jobs = JoinSet::new();

    for _ in 0..clients {
        let client = client.clone();
        let url = url.clone();
        jobs.spawn(async move {
            let mut samples = Vec::with_capacity(requests);

            for _ in 0..requests {
                samples.push(request(&client, &url, expected, range).await?);
            }

            Ok::<_, anyhow::Error>(samples)
        });
    }

    let mut headers = Vec::with_capacity(clients * requests);
    let mut completions = Vec::with_capacity(clients * requests);

    while let Some(result) = jobs.join_next().await {
        for (head, complete) in result?? {
            headers.push(head);
            completions.push(complete);
        }
    }

    let elapsed_ns = started.elapsed().as_nanos();
    headers.sort_unstable();
    completions.sort_unstable();
    let percentile = (headers.len() * 99).div_ceil(100) - 1;
    println!(
        "{}",
        serde_json::to_string(&Report {
            clients,
            requests: clients * requests,
            bytes: if range {
                (clients * requests) as u64
            } else {
                transferred
            },
            elapsed_ns,
            headers_p99_ns: headers[percentile],
            completion_p99_ns: completions[percentile],
        })?
    );

    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    match Arguments::parse().command {
        Command::Serve { listen } => serve(listen).await,
        Command::Load {
            address,
            bytes,
            clients,
            requests,
            range,
            tls_ca,
        } => load(address, bytes, clients, requests, range, tls_ca).await,
    }
}
