//! Local-only B11 comparison. This executable never starts HTTP or contacts a provider.
//! Usage: policy_replay <trace.json|synthetic> <NEW-output-dir> <5..20-runs>
//!                     <OS-cache-condition-label> <hardware-label>

use ferrum_storage::replay::{PolicyKind, RunReport, Trace, run};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

#[derive(serde::Serialize)]
struct Distribution {
    count: usize,
    minimum: f64,
    maximum: f64,
    mean: f64,
    standard_deviation: f64,
}

fn distribution(values: &[f64]) -> Distribution {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    Distribution {
        count: values.len(),
        minimum: values.iter().copied().fold(f64::INFINITY, f64::min),
        maximum: values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        mean,
        standard_deviation: (values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / values.len() as f64)
            .sqrt(),
    }
}

#[derive(serde::Serialize)]
struct Comparison {
    schema_version: u32,
    trace_sha256: String,
    trace: Trace,
    operating_system: &'static str,
    architecture: &'static str,
    logical_cpus: usize,
    hardware_operator_label: String,
    os_cache_operator_label: String,
    run_order: &'static str,
    runs: Vec<RunReport>,
    dispersion: BTreeMap<String, BTreeMap<String, Distribution>>,
    production_selection: &'static str,
    remaining_gates: &'static str,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 6 {
        return Err("usage: policy_replay <trace.json|synthetic> <NEW-output-dir> <5..20-runs> <OS-cache-label> <hardware-label>".into());
    }
    let repetitions: usize = arguments[3].parse()?;
    if !(5..=20).contains(&repetitions)
        || arguments[4].is_empty()
        || arguments[5].is_empty()
        || arguments[4].len() > 256
        || arguments[5].len() > 256
    {
        return Err("require 5..=20 runs and nonempty labels up to 256 bytes".into());
    }
    let trace = if arguments[1] == "synthetic" {
        Trace::synthetic()
    } else {
        Trace::read(std::path::Path::new(&arguments[1]))?
    };
    trace.validate()?;
    // Fingerprint the parsed, versioned dataset rather than whitespace in the source file.
    let trace_bytes = serde_json::to_vec(&trace)?;
    let trace_sha256 = ferrum_apt::digest::Sha256Digest::of(&trace_bytes).to_hex();
    let output = PathBuf::from(&arguments[2]);
    std::fs::create_dir(&output)?;
    let mut trace_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("trace.json"))?;
    trace_file.write_all(&trace_bytes)?;
    let trace = std::sync::Arc::new(trace);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let policies = [
        PolicyKind::Fifo,
        PolicyKind::Clock,
        PolicyKind::Lru,
        PolicyKind::SegmentedClock,
    ];
    let mut reports = Vec::with_capacity(repetitions * policies.len());
    for repetition in 0..repetitions {
        // Rotating order reduces fixed first-policy/last-policy drift; not an
        // assertion that OS caches were dropped or thermal state controlled.
        for offset in 0..policies.len() {
            let policy = policies[(offset + repetition) % policies.len()];
            let scratch = output.join(format!("scratch-{repetition}-{offset}"));
            reports.push(runtime.block_on(run(
                trace.clone(),
                scratch,
                policy,
                std::time::Instant::now() + std::time::Duration::from_secs(600),
            ))?);
        }
    }
    let mut dispersion = BTreeMap::new();
    for policy in policies {
        let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for report in reports.iter().filter(|report| report.policy == policy) {
            let value = serde_json::to_value(report)?;
            if let Some(fields) = value.as_object() {
                for (name, value) in fields {
                    if let Some(number) = value.as_f64() {
                        samples.entry(name.clone()).or_default().push(number);
                    }
                }
            }
            let value = serde_json::to_value(report.policy_stats)?;
            if let Some(fields) = value.as_object() {
                for (name, value) in fields {
                    if let Some(number) = value.as_f64() {
                        samples
                            .entry(format!("policy.{name}"))
                            .or_default()
                            .push(number);
                    }
                }
            }
        }
        let name = serde_json::to_value(policy)?
            .as_str()
            .ok_or("policy name")?
            .to_owned();
        dispersion.insert(
            name,
            samples
                .into_iter()
                .map(|(name, values)| (name, distribution(&values)))
                .collect(),
        );
    }
    let comparison = Comparison {
        schema_version: 1,
        trace_sha256,
        trace: std::sync::Arc::try_unwrap(trace).map_err(|_| "replay worker still owns trace")?,
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism()?.get(),
        hardware_operator_label: arguments[5].clone(),
        os_cache_operator_label: arguments[4].clone(),
        run_order: "repetition-major; rotate FIFO/CLOCK/LRU/segmented CLOCK by repetition",
        runs: reports,
        dispersion,
        production_selection: "clock (unchanged; no production selection authority)",
        remaining_gates: "Representative anonymized request trace still required; generated bodies and modeled remote tiers are not actual wire evidence. Local HTTP verify-before-serve, OS-page-cache-controlled and disk-read-heavy comparisons, production throughput/latency and complete safety/CPU/memory qualification remain separate parent-run gates. Synthetic trace cannot close B11 representative gate.",
    };
    let mut report = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("report.json"))?;
    serde_json::to_writer_pretty(&mut report, &comparison)?;
    writeln!(report)?;
    println!("{}", output.join("report.json").display());
    Ok(())
}
