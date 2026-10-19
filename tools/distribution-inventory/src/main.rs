#![forbid(unsafe_code)]

mod scan;
mod selection;
mod transfer;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use ferrum_apt::release::{ParseLimits, Release, UnixTime};
use ferrum_apt::signature::SignatureVerifier;
use serde::Serialize;
use serde_json::{Value, json};

use selection::{Excluded, Suite, Target};
use transfer::{Budget, Download};

const GIB: u64 = 1024 * 1024 * 1024;
const PINNED_CAP: u64 = 25 * GIB;
const REPORT_CAP: u64 = 64 * 1024 * 1024;

/// B01 read-only signed metadata size inventory. Never downloads packages or publishes.
#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    debian_keyring: PathBuf,
    #[arg(long)]
    ubuntu_keyring: PathBuf,
    /// Fresh, nonexistent output directory. Signed manifests and report.json are preserved.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value = "ferrum-verifier")]
    verifier: PathBuf,
}

#[derive(Serialize)]
struct PackageInspection {
    path: String,
    download: Download,
    summary: scan::PackageSummary,
}

#[derive(Serialize)]
struct SuiteReport {
    repository: &'static str,
    suite: &'static str,
    upstream: &'static str,
    components: &'static [&'static str],
    observed_clock: String,
    signature_verified: bool,
    complete: bool,
    failure: Option<String>,
    inrelease: Option<Download>,
    authenticated_release: Option<Value>,
    #[serde(serialize_with = "selection::serialize_targets")]
    selected: Vec<Target>,
    #[serde(serialize_with = "selection::serialize_excluded")]
    excluded: Vec<Excluded>,
    packages: Vec<PackageInspection>,
}

impl SuiteReport {
    fn new(suite: &Suite) -> Self {
        Self {
            repository: suite.repository,
            suite: suite.name,
            upstream: suite.root,
            components: suite.components(),
            observed_clock: UnixTime::now().to_string(),
            signature_verified: false,
            complete: false,
            failure: None,
            inrelease: None,
            authenticated_release: None,
            selected: Vec::new(),
            excluded: Vec::new(),
            packages: Vec::new(),
        }
    }
}

fn validate_identity(release: &Release, suite: &Suite, now: UnixTime) -> Result<()> {
    if suite.ubuntu {
        ensure!(
            release.origin == "Ubuntu",
            "unexpected Origin {:?}",
            release.origin
        );
        let codename = suite
            .name
            .split_once('-')
            .map_or(suite.name, |(base, _)| base);
        ensure!(
            release.codename == codename,
            "unexpected Codename {:?}",
            release.codename
        );
        ensure!(
            release.suite == suite.name,
            "unexpected Ubuntu pocket {:?}",
            release.suite
        );
    } else {
        let origin_ok = if suite.name.ends_with("-backports") {
            matches!(release.origin.as_str(), "Debian" | "Debian Backports")
        } else {
            release.origin == "Debian"
        };
        ensure!(origin_ok, "unexpected Origin {:?}", release.origin);
        ensure!(
            release.codename == suite.name,
            "unexpected Codename {:?}",
            release.codename
        );
    }
    ensure!(release.acquire_by_hash, "Acquire-By-Hash: yes is required");
    ensure!(
        release.date.as_secs() <= now.as_secs().checked_add(600).context("clock overflow")?,
        "Release Date more than ten minutes in future"
    );
    if let Some(expiry) = release.valid_until {
        ensure!(expiry > now, "Release Valid-Until expired at {expiry}");
    }
    ensure!(
        release.architectures.iter().any(|value| value == "amd64"),
        "amd64 absent from signed Architectures"
    );
    // Component names in the signed header need not match acquisition path prefixes
    // (Debian security advertises updates/main but signs main/binary-amd64/Packages).
    // Selection requires authenticated Packages paths for every configured component.
    Ok(())
}

async fn inventory_suite(
    arguments: &Arguments,
    verifier: &SignatureVerifier,
    client: &reqwest::Client,
    budget: &mut Budget,
    suite: &Suite,
    report: &mut SuiteReport,
) -> Result<()> {
    let directory = arguments
        .output
        .join(format!("{}-{}", suite.repository, suite.name));
    tokio::fs::create_dir(&directory).await?;
    let inrelease = directory.join("InRelease");
    report.inrelease = Some(transfer::inrelease(client, budget, suite, &inrelease).await?);
    let keyring = if suite.ubuntu {
        &arguments.ubuntu_keyring
    } else {
        &arguments.debian_keyring
    };
    let authenticated = verifier
        .verify_cleartext(keyring, &inrelease, &directory, transfer::MANIFEST_CAP)
        .await?;
    report.signature_verified = true;
    // Exact helper output, not a regenerated Release or a detached signature claim.
    tokio::fs::write(directory.join("authenticated-Release"), &authenticated).await?;
    let release = Release::parse(&authenticated, &ParseLimits::default())?;
    validate_identity(&release, suite, UnixTime::now())?;
    report.authenticated_release = Some(json!({
        "file": "authenticated-Release", "bytes": authenticated.len(),
        "sha256": release.content_sha256().to_hex(), "date": release.date.to_string(),
        "date_unix_seconds": release.date.as_secs(),
        "valid_until": release.valid_until.map(|value| value.to_string()),
        "origin": release.origin, "suite": release.suite, "codename": release.codename,
        "acquire_by_hash": release.acquire_by_hash,
        "release_components": release.components,
        "configured_components": suite.components(),
        "component_scope": "configured paths must exist in the signed checksum table; Components header is recorded verbatim, not treated as a URL prefix",
        "no_support_for_architecture_all": release.no_support_for_architecture_all,
        "identity_and_current_time_validated": true,
        "rollback_high_water_mark": "unmeasured: independent current snapshot; no previous accepted generation supplied"
    }));
    let (selected, excluded) = selection::select(&release, suite)?;
    report.selected = selected;
    report.excluded = excluded;
    let entries = selection::packages(&release, &report.selected)?;
    for entry in entries {
        let path = directory.join("Packages.download");
        let result = async {
            let download = transfer::packages(client, budget, suite, entry, &path).await?;
            let (logical, compression) = selection::representation(entry.path.as_str());
            let expanded = release
                .entries()
                .iter()
                .find(|candidate| candidate.path.as_str() == logical)
                .cloned();
            let compression = compression
                .context("selected Packages has no supported compression")?
                .to_owned();
            let decode_path = path.clone();
            let summary = tokio::task::spawn_blocking(move || {
                scan::inspect(&decode_path, &compression, expanded.as_ref())
            })
            .await??;
            Ok::<_, anyhow::Error>(PackageInspection {
                path: entry.path.as_str().to_owned(),
                download,
                summary,
            })
        }
        .await;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("removing temporary Packages file"),
        }
        report.packages.push(result?);
    }
    report.complete = true;
    Ok(())
}

fn sum(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0_u64, |total, value| {
        total.checked_add(value).context("inventory total overflow")
    })
}

fn identity(target: &Target) -> Result<String> {
    if let Some(digest) = &target.sha256 {
        return Ok(format!("SHA256:{digest}"));
    }
    Ok(format!(
        "SHA512:{}",
        target
            .sha512
            .as_ref()
            .context("selected target has no signed SHA-2 digest")?
    ))
}

fn totals(suites: &[SuiteReport]) -> Result<Value> {
    let mut pinned = BTreeMap::new();
    let mut expanded = BTreeMap::new();
    let mut unknown_expanded = 0_u64;
    let mut decode_work = 0_u64;
    let mut decoded_variants = 0_u64;
    for suite in suites {
        for target in &suite.selected {
            let key = (identity(target)?, target.signed_size);
            if target.pinned {
                pinned.insert(key.clone(), target.signed_size);
            }
            if target.compression.is_none() {
                expanded.insert(key, target.signed_size);
            } else if let Some(logical) = suite
                .selected
                .iter()
                .find(|candidate| candidate.path == target.logical)
            {
                decode_work = decode_work
                    .checked_add(logical.signed_size)
                    .context("decode work overflow")?;
                decoded_variants += 1;
            } else {
                unknown_expanded += 1;
            }
        }
    }
    let pinned_bytes = sum(pinned.values().copied())?;
    let signed_expanded = sum(expanded.values().copied())?;
    let mut manifests = BTreeMap::new();
    for suite in suites {
        if let Some(manifest) = &suite.inrelease
            && suite.signature_verified
        {
            manifests.insert((&manifest.sha256, manifest.bytes), manifest.bytes);
        }
    }
    let manifest_bytes = sum(manifests.values().copied())?;
    let snapshot = pinned_bytes
        .checked_add(manifest_bytes)
        .context("snapshot size overflow")?;
    let three = snapshot
        .checked_mul(3)
        .context("generation projection overflow")?;
    let largest = suites
        .iter()
        .flat_map(|suite| &suite.packages)
        .filter_map(|index| index.summary.largest.as_ref())
        .max_by_key(|package| package.bytes);
    let complete = suites.len() == 6 && suites.iter().all(|suite| suite.complete);
    Ok(json!({
        "complete_six_suite_snapshot": complete,
        "deduplication": "signed SHA256 plus size; SHA512 plus size only for entries without SHA256; no cross-algorithm equivalence assumed",
        "signed_declared_pinned_index_objects": pinned.len(),
        "signed_declared_pinned_index_bytes": pinned_bytes,
        "verified_signed_inrelease_unique_bytes": manifest_bytes,
        "current_snapshot_bytes_including_inrelease": snapshot,
        "signed_declared_unique_expanded_or_standalone_bytes": signed_expanded,
        "signed_declared_decode_work_all_compressed_variants_bytes": decode_work,
        "compressed_variants_with_signed_expanded_size": decoded_variants,
        "compressed_variants_without_signed_expanded_size": unknown_expanded,
        "expanded_accounting": "logical uncompressed entries counted once by signed digest/size, never also pinned when a compressed sibling exists; absent expanded declarations remain unknown",
        "other_metadata_measurement": "selected sizes/digests are signed declarations only; non-Packages metadata availability and bytes not downloaded or independently verified",
        "actual_hash_verified_packages_compressed_bytes": sum(suites.iter().flat_map(|suite| &suite.packages).map(|index| index.download.bytes))?,
        "actual_decoded_packages_bytes": sum(suites.iter().flat_map(|suite| &suite.packages).map(|index| index.summary.expanded_bytes))?,
        "package_records_with_duplicates": sum(suites.iter().flat_map(|suite| &suite.packages).map(|index| index.summary.records))?,
        "largest_advertised_package": largest,
        "package_limit_bytes": scan::PACKAGE_CAP,
        "packages_exceeding_8_gib_with_duplicates": sum(suites.iter().flat_map(|suite| &suite.packages).map(|index| index.summary.over_8_gib))?,
        "package_payloads_downloaded": 0,
        "parser_limits": { "line_bytes": 1024 * 1024, "stanza_bytes": 8 * 1024 * 1024, "all_selected_packages_passed": complete,
            "failure_policy": "first violation aborts the index and marks suite/report incomplete; error recorded, never a zero-violation success" },
        "capacity_model": {
            "pinned_budget_bytes": PINNED_CAP,
            "current_within_budget": complete && snapshot <= PINNED_CAP,
            "current_headroom_bytes": PINNED_CAP.saturating_sub(snapshot),
            "current_deficit_bytes": snapshot.saturating_sub(PINNED_CAP),
            "three_distinct_equal_footprint_generations_no_cross_generation_dedup_bytes": three,
            "three_generation_scenario_within_budget": complete && three <= PINNED_CAP,
            "three_generation_headroom_bytes": PINNED_CAP.saturating_sub(three),
            "three_generation_deficit_bytes": three.saturating_sub(PINNED_CAP),
            "model": "current plus two distinct previous generations, each the current footprint, conservatively no cross-generation deduplication; NOT an upper bound on future generation sizes or count",
            "detached_release_pair": "not fetched under six-InRelease-only transfer contract; Release.gpg size unknown and not included; exact authenticated Release is derivable from preserved InRelease",
            "historical_retention_measured": false,
            "seven_day_retention_proven": false,
            "retention_requirement": "at least seven days after retirement, until signed Valid-Until if later, and at least two previous distinct generations per suite",
            "missing_evidence": "historical distinct generation cadence, seven-day unique-object churn, later Valid-Until/retirement overlap and detached signature overhead; a current snapshot times three does not prove retention fits",
            "decision_scope": "snapshot/model headroom only; all headroom is provisional when incomplete and excludes unknown detached-pair overhead"
        }
    }))
}

struct LimitedWriter<W> {
    inner: W,
    bytes: u64,
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        if self
            .bytes
            .checked_add(length)
            .is_none_or(|total| total > REPORT_CAP)
        {
            return Err(io::Error::other(
                "report exceeds 64 MiB scratch reservation",
            ));
        }
        let count = self.inner.write(bytes)?;
        self.bytes += u64::try_from(count).map_err(io::Error::other)?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn keyring_identity(path: &Path) -> Result<Value> {
    use std::io::Read;
    let metadata = std::fs::metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= transfer::MANIFEST_CAP,
        "keyring must be a regular file at most 32 MiB: {}",
        path.display()
    );
    let mut file = File::open(path)?;
    let mut hasher = ferrum_apt::digest::Sha256Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(u64::try_from(count)?)
            .context("keyring size overflow")?;
        ensure!(bytes <= transfer::MANIFEST_CAP, "keyring grew beyond cap");
        hasher.update(&buffer[..count]);
    }
    Ok(json!({ "path": path, "bytes": bytes, "sha256": hasher.finalize().to_hex() }))
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let started = UnixTime::now();
    let keyrings = json!({ "debian": keyring_identity(&arguments.debian_keyring)?, "ubuntu": keyring_identity(&arguments.ubuntu_keyring)? });
    let verifier =
        SignatureVerifier::new(arguments.verifier.clone(), Duration::from_secs(30)).await?;
    let client = transfer::client()?;
    tokio::fs::create_dir(&arguments.output)
        .await
        .context("output must be a fresh nonexistent directory")?;
    let mut budget = Budget::default();
    let mut suites = Vec::with_capacity(6);
    for suite in &selection::SUITES {
        let mut report = SuiteReport::new(suite);
        if let Err(error) = inventory_suite(
            &arguments,
            &verifier,
            &client,
            &mut budget,
            suite,
            &mut report,
        )
        .await
        {
            report.failure = Some(format!("{error:#}"));
        }
        suites.push(report);
    }
    let complete = suites.iter().all(|suite| suite.complete);
    let report = json!({
        "schema_version": 1, "tool": "distribution-inventory", "purpose": "B01 read-only size inventory, not a production publisher",
        "complete": complete, "started_clock_utc": started.to_string(), "started_unix_seconds": started.as_secs(),
        "finished_clock_utc": UnixTime::now().to_string(), "verifier_version": verifier.version(), "keyrings": keyrings,
        "scope": "PLAN section 6 selected closure across all six fixed suites and configured components; no S3, persistence, package downloads, provider writes, or detached Release fetches",
        "limits": { "public_transfer_bytes": transfer::TRANSFER_CAP, "scratch_bytes": 2 * GIB,
            "scratch_reservation": "6*(32 MiB InRelease + 32 MiB authenticated output) + 32 MiB verifier provisional + at most 1 GiB sequential compressed spool + 64 MiB report = 1504 MiB; expanded Packages streamed, not spooled",
            "metadata_request_seconds": 600, "decoder_wall_seconds": 180, "decoder_cpu_seconds": 120, "decoder_address_space_bytes": GIB,
            "redirects": "forbidden; fixed HTTPS roots, signed paths appended as encoded segments", "retries": "none; canonical fallback only after by-hash HTTP 404/410 and must match the signed size and all listed SHA-2 hashes" },
        "transfer": { "counters": budget, "charged_bytes": budget.charged()?,
            "accounting": "actual received HTTP body bytes plus 64 KiB per-response/header/protocol/prefetch allowance; reserve full signed size before each request; no automatic retries or content decoding; not an exact wire-byte measurement" },
        "summary": totals(&suites)?, "suites": suites
    });
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(arguments.output.join("report.json"))?;
    let mut writer = LimitedWriter {
        inner: std::io::BufWriter::new(file),
        bytes: 0,
    };
    serde_json::to_writer_pretty(&mut writer, &report)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    println!("{}", arguments.output.join("report.json").display());
    ensure!(
        complete,
        "inventory incomplete: inspect per-suite failures in report.json; no capacity/retention acceptance claimed"
    );
    Ok(())
}
