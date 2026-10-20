#![allow(clippy::expect_used)]

use super::{Catalog, CatalogError, Job, Worker};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::time::{Instant, MissedTickBehavior};

struct Gate {
    release: mpsc::Sender<()>,
    cancel: mpsc::Sender<()>,
    rescue: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Gate {
    fn drop(&mut self) {
        let _ = self.release.send(());
        let _ = self.cancel.send(());
        if let Some(rescue) = self.rescue.take() {
            rescue.join().expect("gate watchdog joins");
        }
    }
}

async fn block(worker: &Worker) -> Gate {
    let (release, wait) = mpsc::channel();
    let (ready, started) = tokio::sync::oneshot::channel();
    let job: Job = Box::new(move |_| {
        let _ = ready.send(());
        let _ = wait.recv();
    });
    assert!(
        worker
            .sender
            .as_ref()
            .expect("worker sender")
            .try_send(job)
            .is_ok()
    );

    let (cancel, cancelled) = mpsc::channel();
    let rescue_release = release.clone();
    let rescue = std::thread::spawn(move || {
        if cancelled.recv_timeout(Duration::from_secs(5)).is_err() {
            let _ = rescue_release.send(());
        }
    });
    started.await.expect("worker reaches gate");

    Gate {
        release,
        cancel,
        rescue: Some(rescue),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn short_read_wait_does_not_block_executor_or_use_long_worker() {
    let directory = tempfile::tempdir().expect("temporary catalog");
    let catalog = Arc::new(Catalog::open(directory.path(), 4, true).expect("catalog"));
    let short_gate = block(&catalog.readers[0]).await;
    let long_gate = block(&catalog.readers[3]).await;
    let read_catalog = catalog.clone();
    let read = tokio::spawn(async move { read_catalog.read_async(|_| Ok(17)).await });

    let start = Instant::now();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "executor was blocked"
    );
    assert!(
        !read.is_finished(),
        "read must await its selected short worker"
    );

    drop(short_gate);
    assert_eq!(read.await.expect("read task").expect("short read"), 17);
    assert_eq!(
        catalog
            .read_async(|_| Ok(23))
            .await
            .expect("independent short read"),
        23,
        "long-running work must not own short reads"
    );
    drop(long_gate);
}

#[tokio::test(flavor = "current_thread")]
async fn full_short_queue_rejects_without_queuing_another_task() {
    let directory = tempfile::tempdir().expect("temporary catalog");
    let catalog = Catalog::open(directory.path(), 1, true).expect("catalog");
    let gate = block(&catalog.readers[0]).await;
    let queued: Job = Box::new(|_| {});
    assert!(
        catalog.readers[0]
            .sender
            .as_ref()
            .expect("sender")
            .try_send(queued)
            .is_ok()
    );

    assert!(matches!(
        catalog.read_async(|_| Ok(())).await,
        Err(CatalogError::Busy)
    ));
    assert_eq!(
        catalog.read_async(|_| Ok(31)).await.expect("other reader"),
        31
    );
    drop(gate);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_reply_keeps_admitted_work_owned_and_bounded() {
    let directory = tempfile::tempdir().expect("temporary catalog");
    let catalog = Arc::new(Catalog::open(directory.path(), 2, true).expect("catalog"));
    let gate = block(&catalog.readers[0]).await;
    let executed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completed = executed.clone();
    let read_catalog = catalog.clone();
    let read = tokio::spawn(async move {
        read_catalog
            .read_async(move |_| {
                completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await
    });
    tokio::task::yield_now().await;
    read.abort();
    assert!(read.await.expect_err("cancelled caller").is_cancelled());

    drop(gate);
    catalog.readers[0]
        .call_async(|_| Ok(()))
        .await
        .expect("queue drained");
    assert_eq!(executed.load(std::sync::atomic::Ordering::SeqCst), 1);
}

fn lookup(connection: &mut rusqlite::Connection) -> Result<i64, CatalogError> {
    Ok(connection
        .prepare_cached("SELECT size FROM objects WHERE digest=?1 AND resident=1")?
        .query_row(
            [concat!(
                "0000000000000000",
                "0000000000000000",
                "0000000000000000",
                "0000000000000fff"
            )],
            |row| row.get(0),
        )?)
}

fn scan(connection: &mut rusqlite::Connection) -> Result<i64, CatalogError> {
    Ok(connection
        .prepare_cached("SELECT SUM(size) FROM objects WHERE resident=1")?
        .query_row([], |row| row.get(0))?)
}

fn percentile(samples: &mut [u128], percent: usize) -> u128 {
    samples.sort_unstable();
    samples[(samples.len() - 1) * percent / 100]
}

/// Fixed indexed object lookups competing with catalog scans, not a network benchmark.
/// Both modes execute identical SQL and record timer lateness from scheduled tick times.
/// Lookup latency includes time ready on the executor, not only time inside SQL.
/// Compare FERRUM_CATALOG_MODE=blocking with FERRUM_CATALOG_MODE=awaitable.
#[tokio::test(flavor = "current_thread")]
#[ignore = "bounded catalog scheduling benchmark; run explicitly in release mode"]
async fn catalog_scheduling_benchmark() {
    let client_count = std::env::var("FERRUM_CATALOG_CLIENTS").map_or(48, |value| {
        value.parse::<usize>().expect("numeric client count")
    });
    assert!((1..=48).contains(&client_count));

    const READS: usize = 24;
    const SCANS: usize = 256;
    const OBJECTS: i64 = 8192;

    let mode = std::env::var("FERRUM_CATALOG_MODE").unwrap_or_else(|_| "awaitable".into());
    assert!(matches!(mode.as_str(), "blocking" | "awaitable"));
    let directory = tempfile::tempdir().expect("temporary catalog");
    let catalog =
        Arc::new(Catalog::open(directory.path(), client_count + 3, true).expect("catalog"));
    catalog
        .write(|connection| {
            let transaction = connection.transaction()?;
            {
                let mut insert = transaction.prepare(
                    "INSERT INTO objects(digest,size,class,resident) VALUES(?1,4096,0,1)",
                )?;
                for number in 0..OBJECTS {
                    insert.execute([format!("{number:064x}")])?;
                }
            }
            transaction.commit()?;
            Ok(())
        })
        .expect("seed bounded object catalog");
    let expected = catalog.read(lookup).expect("reference indexed lookup");
    assert_eq!(expected, 4096);

    let (stop, stopped) = tokio::sync::oneshot::channel();
    let ticker = tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_millis(1));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut stopped = stopped;
        let mut delays = Vec::new();
        loop {
            tokio::select! {
                scheduled = timer.tick() => {
                    delays.push(Instant::now().saturating_duration_since(scheduled).as_micros());
                }
                _ = &mut stopped => break,
            }
        }
        delays
    });
    tokio::task::yield_now().await;

    let started = Instant::now();
    let mut scanning = Vec::with_capacity(3);
    for _ in 0..3 {
        let catalog = catalog.clone();
        scanning.push(std::thread::spawn(move || {
            for _ in 0..SCANS {
                assert_eq!(catalog.read(scan).expect("catalog scan"), OBJECTS * 4096);
            }
        }));
    }
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..client_count {
        let catalog = catalog.clone();
        let awaitable = mode == "awaitable";
        let mut ready = Instant::now();
        clients.spawn(async move {
            let mut latency = Vec::with_capacity(READS);
            for _ in 0..READS {
                let result = if awaitable {
                    catalog.read_async(lookup).await
                } else {
                    catalog.read(lookup)
                };
                assert_eq!(result.expect("admitted catalog read"), expected);
                latency.push(ready.elapsed().as_micros());
                ready = Instant::now();
                tokio::task::yield_now().await;
            }
            latency
        });
    }
    let mut latency = Vec::with_capacity(client_count * READS);
    while let Some(result) = clients.join_next().await {
        latency.extend(result.expect("client task"));
    }
    tokio::task::spawn_blocking(move || {
        for scanning in scanning {
            scanning.join().expect("catalog scan worker");
        }
    })
    .await
    .expect("scan completion");
    let elapsed = started.elapsed();
    stop.send(()).expect("ticker alive");
    let mut delays = ticker.await.expect("ticker task");
    assert!(!delays.is_empty());

    println!(
        "catalog mode={mode} clients={client_count} scans={} objects={OBJECTS} reads={} elapsed_ms={} reads_per_second={:.1} latency_p50_us={} latency_p95_us={} latency_p99_us={} scheduler_p50_us={} scheduler_p95_us={} scheduler_p99_us={} scheduler_max_us={}",
        3 * SCANS,
        client_count * READS,
        elapsed.as_millis(),
        (client_count * READS) as f64 / elapsed.as_secs_f64(),
        percentile(&mut latency, 50),
        percentile(&mut latency, 95),
        percentile(&mut latency, 99),
        percentile(&mut delays, 50),
        percentile(&mut delays, 95),
        percentile(&mut delays, 99),
        delays.last().expect("scheduler samples"),
    );
}
