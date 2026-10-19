//! Local fixture measurements through the real gateway. No provider traffic.
use anyhow::{Context, bail, ensure};
use clap::Parser;
use ferrum::{
    app,
    config::{Config, ORIGIN_BASE_URL},
};
use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest, Sha256Hasher},
    path::RepositoryPath,
};
use futures_util::StreamExt;
use reqwest::{Client, StatusCode, header};
use serde::Serialize;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    package_path: String,
    #[arg(long)]
    sha256: String,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=67_108_864))]
    bytes: u64,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(5..=20))]
    runs: u32,
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=64))]
    clients: u32,
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u32).range(1..=64))]
    requests_per_client: u32,
    #[arg(long)]
    hardware_label: String,
    #[arg(long)]
    os_cache_label: String,
}

#[derive(Clone, Copy, Serialize)]
struct Sample {
    headers_ready_ns: u64,
    verified_completion_ns: u64,
    bytes: u64,
}
#[derive(Serialize)]
struct Percentiles {
    minimum: u64,
    median: u64,
    p95: u64,
    p99: u64,
    maximum: u64,
}
#[derive(Serialize)]
struct Batch {
    requests: u64,
    verified_bytes: u64,
    wall_ns: u64,
    verified_client_bytes_per_second: f64,
    headers_ready_ns: Percentiles,
    verified_completion_ns: Percentiles,
}
#[derive(Serialize)]
struct Run {
    number: u32,
    source_baseline: Sample,
    cold_gateway: Sample,
    source_slot_to_verified_spool_ns: u64,
    source_slot_to_verified_spool_bytes_per_second: f64,
    warm_full: Batch,
    warm_one_byte_range: Batch,
    successful_package_fills: usize,
}
#[derive(Serialize)]
struct Report {
    schema_version: u32,
    synthetic_fixture: bool,
    hardware_label: String,
    os_cache_label: String,
    os: &'static str,
    architecture: &'static str,
    available_parallelism: usize,
    package_path: String,
    sha256: String,
    package_bytes: u64,
    limitations: [&'static str; 6],
    runs: Vec<Run>,
}
struct Target {
    url: Url,
    identity: ObjectIdentity,
    etag: String,
    range_header: String,
    first_byte: u8,
}

fn nanos(duration: Duration) -> anyhow::Result<u64> {
    u64::try_from(duration.as_nanos()).context("duration exceeds measurement range")
}
fn percentiles(mut values: Vec<u64>) -> anyhow::Result<Percentiles> {
    ensure!(!values.is_empty(), "no latency samples");
    values.sort_unstable();
    let percentile = |percentage: usize| values[(values.len() * percentage).div_ceil(100) - 1];
    Ok(Percentiles {
        minimum: values[0],
        median: percentile(50),
        p95: percentile(95),
        p99: percentile(99),
        maximum: values[values.len() - 1],
    })
}
fn package_url(mut base: Url, package: &RepositoryPath) -> anyhow::Result<Url> {
    base.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("fixture URL cannot hold path segments"))?
        .pop_if_empty()
        .extend(package.segments());
    Ok(base)
}

async fn fetch(
    client: &Client,
    target: &Target,
    range: bool,
    gateway: bool,
) -> anyhow::Result<(Sample, u8)> {
    let start = Instant::now();
    let mut request = client
        .get(target.url.clone())
        .header(header::ACCEPT_ENCODING, "identity");
    if range {
        request = request.header(header::RANGE, "bytes=0-0");
    }
    let response = request.send().await.context("HTTP request")?;
    let headers_ready_ns = nanos(start.elapsed())?;
    let expected_status = if range {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    ensure!(
        response.status() == expected_status,
        "unexpected HTTP status {}",
        response.status()
    );
    let expected_size = if range { 1 } else { target.identity.size };
    ensure!(
        response.content_length() == Some(expected_size),
        "wrong Content-Length"
    );
    if gateway {
        ensure!(
            response
                .headers()
                .get(header::ETAG)
                .and_then(|value| value.to_str().ok())
                == Some(target.etag.as_str()),
            "wrong gateway ETag"
        );
    }
    if range {
        ensure!(
            response
                .headers()
                .get(header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                == Some(target.range_header.as_str()),
            "wrong Content-Range"
        );
    }
    let mut stream = response.bytes_stream();
    let mut bytes = 0_u64;
    let mut first = None;
    let mut hash = (!range).then(Sha256Hasher::new);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("HTTP body")?;
        bytes = bytes
            .checked_add(u64::try_from(chunk.len())?)
            .context("body length overflow")?;
        ensure!(bytes <= expected_size, "body exceeds authenticated size");
        if first.is_none() {
            first = chunk.first().copied();
        }
        if let Some(hash) = &mut hash {
            hash.update(&chunk);
        }
    }
    ensure!(bytes == expected_size, "short HTTP body");
    let first = first.context("empty package response")?;
    if range {
        ensure!(
            first == target.first_byte,
            "range differs from verified complete package"
        );
    }
    if let Some(hash) = hash {
        ensure!(
            hash.finalize() == target.identity.sha256,
            "package digest mismatch"
        );
    }
    Ok((
        Sample {
            headers_ready_ns,
            verified_completion_ns: nanos(start.elapsed())?,
            bytes,
        },
        first,
    ))
}

async fn batch(
    client: &Client,
    target: Arc<Target>,
    clients: u32,
    count: u32,
    range: bool,
) -> anyhow::Result<Batch> {
    let start = Instant::now();
    let mut jobs = JoinSet::new();
    for _ in 0..clients {
        let client = client.clone();
        let target = target.clone();
        jobs.spawn(async move {
            let mut samples = Vec::with_capacity(usize::try_from(count)?);
            for _ in 0..count {
                samples.push(fetch(&client, &target, range, true).await?.0);
            }
            Ok::<_, anyhow::Error>(samples)
        });
    }
    let mut samples = Vec::with_capacity(usize::try_from(clients)?);
    while let Some(result) = jobs.join_next().await {
        samples.push(result.context("client task")??);
    }
    let elapsed = start.elapsed();
    ensure!(!elapsed.is_zero(), "clock resolution cannot measure batch");
    let requests = u64::from(clients) * u64::from(count);
    let verified_bytes = requests
        .checked_mul(if range { 1 } else { target.identity.size })
        .context("verified byte count overflow")?;
    Ok(Batch {
        requests,
        verified_bytes,
        wall_ns: nanos(elapsed)?,
        verified_client_bytes_per_second: verified_bytes as f64 / elapsed.as_secs_f64(),
        headers_ready_ns: percentiles(
            samples
                .iter()
                .flatten()
                .map(|sample| sample.headers_ready_ns)
                .collect(),
        )?,
        verified_completion_ns: percentiles(
            samples
                .iter()
                .flatten()
                .map(|sample| sample.verified_completion_ns)
                .collect(),
        )?,
    })
}

async fn wait_ready(client: &Client, address: SocketAddr) -> anyhow::Result<()> {
    let url = Url::parse(&format!("http://{address}/readyz"))?;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let response = client.get(url.clone()).send().await?;
            let status = response.status();
            let mut stream = response.bytes_stream();
            let mut count = 0usize;
            while let Some(bytes) = stream.next().await {
                count = count
                    .checked_add(bytes?.len())
                    .context("health length overflow")?;
                ensure!(count <= 64 * 1024, "oversized health response");
            }
            if status.is_success() {
                return Ok::<(), anyhow::Error>(());
            }
            ensure!(
                status == StatusCode::SERVICE_UNAVAILABLE,
                "unexpected readiness status"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("fixture readiness deadline")?
}

async fn measure_run(
    args: &Arguments,
    client: &Client,
    gateway: &app::RunningGateway,
    number: u32,
    identity: ObjectIdentity,
    package: &RepositoryPath,
) -> anyhow::Result<Run> {
    wait_ready(client, gateway.admin_addr).await?;
    let source = Target {
        url: package_url(Url::parse(ORIGIN_BASE_URL)?, package)?,
        identity,
        etag: String::new(),
        range_header: String::new(),
        first_byte: 0,
    };
    let (source_baseline, first_byte) = fetch(client, &source, false, false).await?;
    let target = Arc::new(Target {
        url: package_url(
            Url::parse(&format!("http://{}/fixture/", gateway.public_addr))?,
            package,
        )?,
        identity,
        etag: format!("\"sha256-{}\"", identity.sha256),
        first_byte,
        range_header: format!("bytes 0-0/{}", identity.size),
    });
    let (cold_gateway, _) = fetch(client, &target, false, true).await?;
    let warm_full = batch(
        client,
        target.clone(),
        args.clients,
        args.requests_per_client,
        false,
    )
    .await?;
    let warm_one_byte_range =
        batch(client, target, args.clients, args.requests_per_client, true).await?;
    let fills = gateway
        .completed_fills()
        .into_iter()
        .filter(|fill| fill.identity == identity)
        .collect::<Vec<_>>();
    ensure!(
        fills.len() == 1,
        "fresh fixture run must complete exactly one package producer"
    );
    let elapsed = fills[0].elapsed;
    ensure!(!elapsed.is_zero(), "clock resolution cannot measure fill");
    Ok(Run {
        number,
        source_baseline,
        cold_gateway,
        source_slot_to_verified_spool_ns: nanos(elapsed)?,
        source_slot_to_verified_spool_bytes_per_second: identity.size as f64
            / elapsed.as_secs_f64(),
        warm_full,
        warm_one_byte_range,
        successful_package_fills: fills.len(),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arguments::parse();
    let package = RepositoryPath::parse_decoded(&args.package_path)?;
    ensure!(
        package.as_str().starts_with("pool/"),
        "benchmark requires a signed package path"
    );
    ensure!(
        args.hardware_label.len() <= 512 && args.os_cache_label.len() <= 512,
        "label too large"
    );
    ensure!(
        std::fs::metadata(&args.config)?.len() <= 64 * 1024,
        "configuration exceeds bound"
    );
    let template = Config::load(&args.config)?;
    ensure!(
        template.durable().is_none() && template.s3.is_none(),
        "benchmark permits local-only fixture mode, never S3/durable operation"
    );
    let identity = ObjectIdentity {
        sha256: Sha256Digest::from_hex(&args.sha256)?,
        size: args.bytes,
    };
    let per_run = (u64::from(args.clients) * u64::from(args.requests_per_client) + 2)
        .checked_mul(args.bytes)
        .context("benchmark transfer overflow")?
        .checked_add(u64::from(args.clients) * u64::from(args.requests_per_client))
        .context("benchmark transfer overflow")?;
    ensure!(
        per_run
            .checked_mul(u64::from(args.runs))
            .context("benchmark transfer overflow")?
            <= 2 * 1024 * 1024 * 1024,
        "local measured HTTP body transfer exceeds 2 GiB bound"
    );
    std::fs::create_dir(&args.output).context("output must be a new owned directory")?;
    let output_root = args.output.canonicalize()?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(usize::try_from(args.clients)?)
        .build()?;
    let mut runs = Vec::with_capacity(usize::try_from(args.runs)?);
    for number in 0..args.runs {
        let scratch = tempfile::Builder::new()
            .prefix("fixture-run-")
            .tempdir_in(&output_root)?;
        let mut config = template.clone();
        config.fixture.work_dir = scratch.path().join("runtime");
        config.listen.public = SocketAddr::from(([127, 0, 0, 1], 0));
        config.listen.admin = SocketAddr::from(([127, 0, 0, 1], 0));
        let gateway = app::start(config, CancellationToken::new()).await?;
        let measured = measure_run(&args, &client, &gateway, number, identity, &package).await;
        let stopped = gateway.shutdown().await;
        match (measured, stopped) {
            (Ok(run), Ok(())) => runs.push(run),
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error.context("gateway shutdown")),
            (Err(measurement), Err(shutdown)) => {
                bail!("measurement failed: {measurement}; shutdown failed: {shutdown}")
            }
        }
        scratch
            .close()
            .context("cleaning owned benchmark scratch")?;
    }
    let report = Report {
        schema_version: 1,
        synthetic_fixture: true,
        hardware_label: args.hardware_label,
        os_cache_label: args.os_cache_label,
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        available_parallelism: std::thread::available_parallelism()?.get(),
        package_path: args.package_path,
        sha256: args.sha256,
        package_bytes: args.bytes,
        limitations: [
            "Loopback HTTP fixture, no TLS, provider traffic, LAN generator or production throughput qualification",
            "Each run has a fresh gateway spool; source baseline warms source bytes in the OS page cache",
            "OS page cache is not dropped; these small files do not measure NVMe capacity or disk-heavy performance",
            "Headers-ready latency is not exact first-wire-byte TTFB; complete-body latency includes client SHA-256 verification",
            "Source-slot-to-verified-spool timing excludes HTTP client completion and is reported separately",
            "Synthetic fixture results cannot select a production replacement policy",
        ],
        runs,
    };
    let output = std::fs::File::create_new(args.output.join("report.json"))?;
    serde_json::to_writer_pretty(output, &report)?;
    println!(
        "verified {} fresh-spool runs; report={}",
        report.runs.len(),
        args.output.join("report.json").display()
    );
    Ok(())
}
