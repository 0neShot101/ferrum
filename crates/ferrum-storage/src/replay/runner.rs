use super::{Event, MAX_OBJECTS, Pin, PolicyKind, PolicyStats, ReplayError, Source, Trace};
use crate::disk::{DurableSpoolConfig, ObjectPin, PinKind, Spool, SpoolError, VerifiedObject};
use bytes::Bytes;
use ferrum_apt::digest::{ObjectIdentity, Sha256Hasher};
use futures_util::StreamExt;
use std::time::Instant;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const CHUNK: usize = 64 * 1024;
const HEADROOM: u64 = 64 * 1024 * 1024;

#[derive(Debug, serde::Serialize)]
pub struct RunReport {
    pub policy: PolicyKind,
    pub synthetic: bool,
    pub dataset: String,
    pub seed: u64,
    pub requests: u64,
    pub hits: u64,
    pub rejected: u64,
    pub requested_bytes: u64,
    pub hit_bytes: u64,
    pub object_hit_ratio: f64,
    pub byte_hit_ratio: f64,
    pub modeled_upstream_bytes: u64,
    pub modeled_e2_bytes: u64,
    pub actual_network_wire_bytes: u64,
    pub payload_written_bytes: u64,
    pub payload_read_bytes: u64,
    pub payload_write_amplification: f64,
    pub process_storage_written_bytes: Option<u64>,
    pub process_storage_read_bytes: Option<u64>,
    pub process_storage_write_amplification: Option<f64>,
    pub physical_write_amplification: Option<f64>,
    pub catalog_bytes_final: u64,
    pub policy_stats: PolicyStats,
    pub policy_memory_peak_estimate_bytes: usize,
    pub request_p50_wall_nanos: Option<u64>,
    pub request_p95_wall_nanos: Option<u64>,
    pub request_p99_wall_nanos: Option<u64>,
    pub rejected_p95_wall_nanos: Option<u64>,
    pub lookup_hit_process_cpu_nanos: Option<u64>,
    pub run_process_cpu_nanos: Option<u64>,
    pub run_wall_nanos: u64,
    pub selected_production_policy: PolicyKind,
    pub selection_reason: &'static str,
    pub measurement_limits: &'static str,
}

enum HeldPin {
    Owner(ObjectPin),
    Reader(VerifiedObject),
}

fn payload(seed: u64) -> Bytes {
    let mut chunk = vec![0; CHUNK];
    let bytes = seed.to_le_bytes();
    for part in chunk.as_chunks_mut::<8>().0 {
        *part = bytes;
    }
    Bytes::from(chunk)
}

fn identity(size: u64, chunk: &Bytes, deadline: Instant) -> Result<ObjectIdentity, ReplayError> {
    let mut hasher = Sha256Hasher::new();
    let mut remaining = size;
    while remaining > 0 {
        check_deadline(deadline)?;
        let length = remaining.min(CHUNK as u64) as usize;
        hasher.update(&chunk[..length]);
        remaining -= length as u64;
    }
    Ok(ObjectIdentity {
        sha256: hasher.finalize(),
        size,
    })
}

fn check_deadline(deadline: Instant) -> Result<(), ReplayError> {
    if Instant::now() >= deadline {
        Err(ReplayError::Deadline)
    } else {
        Ok(())
    }
}

fn nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn cpu() -> Option<u64> {
    #[cfg(all(target_os = "linux", feature = "test-harness"))]
    {
        let time = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        u64::try_from(time.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(time.tv_nsec).ok()?)
    }
    #[cfg(not(all(target_os = "linux", feature = "test-harness")))]
    {
        None
    }
}

fn difference(end: Option<u64>, start: Option<u64>) -> Option<u64> {
    end?.checked_sub(start?)
}

fn storage_io() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut text = String::new();
        std::fs::File::open("/proc/self/io")
            .ok()?
            .take(4097)
            .read_to_string(&mut text)
            .ok()?;
        if text.len() > 4096 {
            return None;
        }
        let mut written = None;
        let mut read = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("write_bytes:") {
                written = value.trim().parse::<u64>().ok();
            }
            if let Some(value) = line.strip_prefix("read_bytes:") {
                read = value.trim().parse::<u64>().ok();
            }
        }
        Some((written?, read?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    // Nearest-rank percentile, including failures only in their own series.
    sorted[(sorted.len() * percent).div_ceil(100).saturating_sub(1)]
}

async fn read(object: &VerifiedObject) -> Result<u64, ReplayError> {
    if object.size() == 0 {
        return Ok(0);
    }
    let mut stream = object.stream_range(0, object.size() - 1)?;
    let mut bytes = 0;
    while let Some(chunk) = stream.next().await {
        bytes += chunk?.len() as u64;
    }
    if bytes != object.size() {
        return Err(ReplayError::Invalid("short verified read"));
    }
    Ok(bytes)
}

/// Runs against a new, exclusive scratch directory without network traffic.
/// The blocking worker retains the owner until all work finishes. The absolute
/// deadline stops cooperative work, not an in-flight filesystem syscall; no
/// successful report is returned after it. Failures before cleanup preserve
/// scratch for diagnosis; cleanup failures can leave a partial directory.
pub async fn run(
    trace: Arc<Trace>,
    scratch: PathBuf,
    kind: PolicyKind,
    deadline: Instant,
) -> Result<RunReport, ReplayError> {
    check_deadline(deadline)?;
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                run_inner(&trace, &scratch, kind, deadline),
            )
            .await
            .map_err(|_| ReplayError::Deadline)?
        })
    })
    .await?
}

async fn run_inner(
    trace: &Trace,
    scratch: &Path,
    kind: PolicyKind,
    deadline: Instant,
) -> Result<RunReport, ReplayError> {
    check_deadline(deadline)?;
    trace.validate()?;
    std::fs::create_dir(scratch)?;
    let mut config = DurableSpoolConfig::new(scratch.to_path_buf());
    config.spool.managed_ceiling = trace.cache_bytes + HEADROOM;
    config.spool.max_object_size = super::MAX_OBJECT_BYTES;
    config.spool.io_workers = 2;
    config.spool.read_chunk = CHUNK;
    config.free_space_floor = 0;
    config.temporary_ceiling = super::MAX_OBJECT_BYTES;
    config.metadata_temporary_reserve = 0;
    config.metadata_ceiling = HEADROOM;
    config.catalog_ceiling = HEADROOM / 2;
    config.max_entries = MAX_OBJECTS;
    config.catalog_memory_budget = 64 * 1024 * 1024;
    config.database_queue = 8;
    // Package residency is explicitly enforced below; owner SQL/physical
    // capacity checks remain active with independent bounded headroom.
    config.eviction_high_watermark = config.spool.managed_ceiling;
    config.eviction_low_watermark = config.spool.managed_ceiling;
    let spool = Spool::open_durable(config)?;
    spool.replay_select_policy(kind)?;
    let mut identities = Vec::with_capacity(trace.objects.len());
    let mut unique = std::collections::HashSet::with_capacity(trace.objects.len());
    for object in &trace.objects {
        let identity = identity(object.size, &payload(object.content_seed), deadline)?;
        if !unique.insert(identity) {
            return Err(ReplayError::Invalid(
                "duplicate generated identity: use one object index",
            ));
        }
        identities.push(identity);
    }
    let mut pending = vec![false; trace.objects.len()];
    let mut pins: Vec<Option<HeldPin>> = (0..MAX_OBJECTS).map(|_| None).collect();
    let mut latencies = Vec::with_capacity(trace.events.len());
    let mut failures = Vec::new();
    let mut requests = 0u64;
    let mut hits = 0u64;
    let mut requested_bytes = 0u64;
    let mut hit_bytes = 0u64;
    let mut upstream = 0u64;
    let mut e2 = 0u64;
    let mut written = 0u64;
    let mut read_bytes = 0u64;
    let mut hit_cpu = cpu().map(|_| 0u64);
    let mut memory_peak = 0;
    let started = Instant::now();
    let cpu_started = cpu();
    let io_started = storage_io();
    for event in &trace.events {
        tokio::task::yield_now().await;
        check_deadline(deadline)?;
        match *event {
            Event::Request { object, source } => {
                requests += 1;
                let identity = identities[object];
                requested_bytes += identity.size;
                let started = Instant::now();
                let lookup_started = cpu();
                let resident = spool.lookup(identity);
                let lookup_cpu = difference(cpu(), lookup_started);
                if let Some(resident) = resident {
                    hits += 1;
                    hit_bytes += identity.size;
                    hit_cpu = hit_cpu
                        .zip(lookup_cpu)
                        .map(|(total, elapsed)| total + elapsed);
                    read_bytes += read(&resident).await?;
                    latencies.push(nanos(started.elapsed()));
                    continue;
                }
                if identity.size > trace.cache_bytes {
                    failures.push(nanos(started.elapsed()));
                    continue;
                }
                let needed = spool
                    .accounting()
                    .installed
                    .saturating_add(identity.size)
                    .saturating_sub(trace.cache_bytes);
                if needed > 0 {
                    spool.reclaim(needed)?;
                }
                if spool.accounting().installed.saturating_add(identity.size) > trace.cache_bytes {
                    failures.push(nanos(started.elapsed()));
                    continue;
                }
                let reservation = match spool.reserve(identity.size) {
                    Ok(reservation) => reservation,
                    Err(SpoolError::CapacityExhausted { .. }) => {
                        failures.push(nanos(started.elapsed()));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let mut writer = spool.begin_write(reservation, identity).await?;
                let chunk = payload(trace.objects[object].content_seed);
                let mut remaining = identity.size;
                while remaining > 0 {
                    check_deadline(deadline)?;
                    let length = remaining.min(CHUNK as u64) as usize;
                    writer.write(chunk.slice(..length)).await?;
                    written += length as u64;
                    remaining -= length as u64;
                }
                let installed = writer.commit().await?;
                spool.replay_set_eligible(identity, !pending[object])?;
                match source {
                    Source::Upstream => upstream += identity.size,
                    Source::E2 => e2 += identity.size,
                }
                read_bytes += read(&installed).await?;
                latencies.push(nanos(started.elapsed()));
            }
            Event::Pin { object, slot, kind } => {
                let identity = identities[object];
                pins[slot] = Some(match kind {
                    Pin::Reader => HeldPin::Reader(spool.replay_lease(identity).ok_or(
                        ReplayError::Invalid("reader pin targets nonresident object"),
                    )?),
                    _ => {
                        let kind = match kind {
                            Pin::Fill | Pin::Reader => PinKind::Fill,
                            Pin::Upload => PinKind::Upload,
                            Pin::Generation => PinKind::Generation,
                        };
                        HeldPin::Owner(
                            spool
                                .pin(identity, kind)?
                                .ok_or(ReplayError::Invalid("pin targets nonresident object"))?,
                        )
                    }
                });
            }
            Event::Unpin { slot } => {
                pins[slot] = None;
            }
            Event::Outbox {
                object,
                pending: value,
            } => {
                pending[object] = value;
                spool.replay_set_eligible(identities[object], !value)?;
            }
            Event::Reclaim { bytes } => {
                spool.reclaim(bytes)?;
            }
        }
        memory_peak = memory_peak.max(spool.replay_policy_stats().memory_estimate_bytes);
        check_deadline(deadline)?;
    }
    let elapsed_cpu = difference(cpu(), cpu_started);
    let elapsed = nanos(started.elapsed());
    let io_finished = storage_io();
    let storage_written = io_finished
        .zip(io_started)
        .and_then(|(end, start)| end.0.checked_sub(start.0));
    let storage_read = io_finished
        .zip(io_started)
        .and_then(|(end, start)| end.1.checked_sub(start.1));
    latencies.sort_unstable();
    failures.sort_unstable();
    let stats = spool.replay_policy_stats();
    let report = RunReport {
        policy: kind,
        synthetic: trace.synthetic,
        dataset: trace.dataset.clone(),
        seed: trace.seed,
        requests,
        hits,
        rejected: failures.len() as u64,
        requested_bytes,
        hit_bytes,
        object_hit_ratio: hits as f64 / requests as f64,
        byte_hit_ratio: if requested_bytes == 0 {
            0.0
        } else {
            hit_bytes as f64 / requested_bytes as f64
        },
        modeled_upstream_bytes: upstream,
        modeled_e2_bytes: e2,
        actual_network_wire_bytes: 0,
        payload_written_bytes: written,
        payload_read_bytes: read_bytes,
        payload_write_amplification: if upstream + e2 == 0 {
            0.0
        } else {
            written as f64 / (upstream + e2) as f64
        },
        process_storage_written_bytes: storage_written,
        process_storage_read_bytes: storage_read,
        process_storage_write_amplification: storage_written
            .filter(|_| upstream + e2 != 0)
            .map(|bytes| bytes as f64 / (upstream + e2) as f64),
        physical_write_amplification: None,
        catalog_bytes_final: spool.usage()?.catalog_bytes,
        policy_stats: stats,
        policy_memory_peak_estimate_bytes: memory_peak,
        request_p50_wall_nanos: if latencies.is_empty() {
            None
        } else {
            Some(percentile(&latencies, 50))
        },
        request_p95_wall_nanos: if latencies.is_empty() {
            None
        } else {
            Some(percentile(&latencies, 95))
        },
        request_p99_wall_nanos: if latencies.is_empty() {
            None
        } else {
            Some(percentile(&latencies, 99))
        },
        rejected_p95_wall_nanos: if failures.is_empty() {
            None
        } else {
            Some(percentile(&failures, 95))
        },
        lookup_hit_process_cpu_nanos: hit_cpu,
        run_process_cpu_nanos: elapsed_cpu,
        run_wall_nanos: elapsed,
        selected_production_policy: PolicyKind::Clock,
        selection_reason: "retain CLOCK: local replay alone cannot satisfy representative-trace, HTTP latency, CPU/memory and all safety selection gates",
        measurement_limits: "generated bodies at declared sizes; no network; source bytes modeled; payload write ratio excludes SQLite/WAL/fsync/physical-device writes; process storage I/O is optional Linux /proc/self/io during replay only (includes worker SQL, excludes startup/cleanup, not device/NAND amplification); capacity memory estimate excludes HashMap bucket/control/allocator slack; latency is successful local spool lookup/fill plus full read, NOT HTTP TTFB; rejected latency separate; CPU is Linux process CPU including workers and sampling overhead; Instant is wall time; OS cache not controlled; no production winner",
    };
    // Explicitly drop guards before the owner and delete only our fresh directory.
    // Reading held fields makes their lifetime role explicit, not dead storage.
    for pin in pins.into_iter().flatten() {
        match pin {
            HeldPin::Owner(pin) => drop(pin),
            HeldPin::Reader(object) => drop(object),
        }
    }
    drop(spool);
    check_deadline(deadline)?;
    std::fs::remove_dir_all(scratch)?;
    check_deadline(deadline)?;
    Ok(report)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn existing_scratch_is_never_opened_or_deleted() {
        let directory = tempfile::tempdir().expect("scratch parent");
        let sentinel = directory.path().join("keep");
        std::fs::write(&sentinel, b"untouched").expect("sentinel");
        assert!(
            run(
                Arc::new(Trace::synthetic()),
                directory.path().to_path_buf(),
                PolicyKind::Clock,
                Instant::now() + std::time::Duration::from_secs(60)
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(sentinel).expect("preserved"), b"untouched");
    }

    #[tokio::test]
    async fn identical_owner_oracle_protects_outbox_readers_and_uploads() {
        use super::super::TraceObject;
        let trace = Trace {
            schema_version: 1,
            synthetic: true,
            dataset: "synthetic-owner-safety".into(),
            seed: 0,
            cache_bytes: 64,
            objects: [8, 16, 24, 32, 40]
                .into_iter()
                .enumerate()
                .map(|(index, size)| TraceObject {
                    size,
                    content_seed: index as u64 + 1,
                })
                .collect(),
            events: vec![
                Event::Request {
                    object: 0,
                    source: Source::Upstream,
                },
                Event::Outbox {
                    object: 0,
                    pending: true,
                },
                Event::Request {
                    object: 1,
                    source: Source::Upstream,
                },
                Event::Pin {
                    object: 1,
                    slot: 0,
                    kind: Pin::Reader,
                },
                Event::Reclaim { bytes: 64 },
                Event::Request {
                    object: 2,
                    source: Source::Upstream,
                },
                Event::Pin {
                    object: 2,
                    slot: 1,
                    kind: Pin::Upload,
                },
                Event::Request {
                    object: 3,
                    source: Source::Upstream,
                },
                Event::Unpin { slot: 0 },
                Event::Outbox {
                    object: 0,
                    pending: false,
                },
                Event::Reclaim { bytes: 64 },
                Event::Request {
                    object: 4,
                    source: Source::E2,
                },
            ],
        };
        let trace = Arc::new(trace);
        let directory = tempfile::tempdir().expect("scratch parent");
        for (index, policy) in [
            PolicyKind::Fifo,
            PolicyKind::Clock,
            PolicyKind::Lru,
            PolicyKind::SegmentedClock,
        ]
        .into_iter()
        .enumerate()
        {
            let scratch = directory.path().join(index.to_string());
            let report = run(
                trace.clone(),
                scratch.clone(),
                policy,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .await
            .expect("same safety owner");
            assert_eq!(report.requests, 5);
            assert_eq!(report.rejected, 1);
            assert_eq!(report.hits, 0);
            assert_eq!(report.modeled_upstream_bytes, 48);
            assert_eq!(report.modeled_e2_bytes, 40);
            assert_eq!(report.payload_written_bytes, 88);
            assert_eq!(report.actual_network_wire_bytes, 0);
            assert_eq!(report.policy_stats.demand_hits, 0);
            assert_eq!(report.selected_production_policy, PolicyKind::Clock);
            assert!(!scratch.exists());
        }
    }

    #[tokio::test]
    async fn impossible_admission_preserves_residents_for_every_policy() {
        let trace = Arc::new(Trace {
            schema_version: 1,
            synthetic: true,
            dataset: "oversized-admission".into(),
            seed: 0,
            cache_bytes: 8,
            objects: vec![
                super::super::TraceObject {
                    size: 8,
                    content_seed: 1,
                },
                super::super::TraceObject {
                    size: 16,
                    content_seed: 2,
                },
            ],
            events: [0, 0, 1, 0]
                .into_iter()
                .map(|object| Event::Request {
                    object,
                    source: Source::Upstream,
                })
                .collect(),
        });
        let directory = tempfile::tempdir().expect("scratch parent");
        for (index, policy) in [
            PolicyKind::Fifo,
            PolicyKind::Clock,
            PolicyKind::Lru,
            PolicyKind::SegmentedClock,
        ]
        .into_iter()
        .enumerate()
        {
            let report = run(
                trace.clone(),
                directory.path().join(index.to_string()),
                policy,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            .await
            .expect("replay");
            assert_eq!(report.hits, 2);
            assert_eq!(report.rejected, 1);
            assert_eq!(report.payload_written_bytes, 8);
        }
    }

    #[tokio::test]
    async fn expired_deadline_cannot_create_scratch_or_report_success() {
        let directory = tempfile::tempdir().expect("scratch parent");
        let scratch = directory.path().join("expired");
        let result = run(
            Arc::new(Trace::synthetic()),
            scratch.clone(),
            PolicyKind::Clock,
            Instant::now(),
        )
        .await;
        assert!(matches!(result, Err(ReplayError::Deadline)));
        assert!(!scratch.exists());
    }
}
