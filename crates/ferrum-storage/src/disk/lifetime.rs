//! Last-owner destruction can occur on a database reader after runtime shutdown.
//! Hand the catalog AND process lock to a shutdown owner before joining that reader.
use super::SpoolLifetime;
use crate::catalog::Catalog;
use std::{fs::File, sync::mpsc, thread};
impl Drop for SpoolLifetime {
    fn drop(&mut self) {
        let catalog = self.catalog.take();
        let lock = self._lock.take();
        let Some(catalog) = catalog else {
            drop(lock);
            return;
        };
        if !catalog.on_worker_thread() {
            drop(catalog);
            drop(lock);
            return;
        }
        let (sender, receiver) = mpsc::sync_channel::<(Catalog, Option<fd_lock::RwLock<File>>)>(0);
        match thread::Builder::new()
            .name("ferrum-sql-shutdown".into())
            .spawn(move || {
                if let Ok((catalog, lock)) = receiver.recv() {
                    drop(catalog);
                    drop(lock);
                }
            }) {
            Ok(owner) => {
                if let Err(error) = sender.send((catalog, lock)) {
                    // Releasing the lock while an unjoined worker can still
                    // commit is worse than retaining resources until exit.
                    std::mem::forget(error.0);
                    tracing::error!(
                        "catalog shutdown handoff failed; ownership retained fail-closed"
                    );
                }
                drop(owner);
            }
            Err(error) => {
                std::mem::forget((catalog, lock));
                tracing::error!(%error,"cannot create catalog shutdown owner; ownership retained fail-closed");
            }
        }
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Spool, catalog::CatalogError, disk::DurableSpoolConfig};
    use std::time::{Duration, Instant};
    fn config(root: &std::path::Path) -> DurableSpoolConfig {
        let mut config = DurableSpoolConfig::new(root.to_owned());
        config.spool.managed_ceiling = 64 * 1024 * 1024;
        config.spool.max_object_size = 1024;
        config.free_space_floor = 0;
        config.temporary_ceiling = 1024 * 1024;
        config.metadata_temporary_reserve = 0;
        config.metadata_ceiling = 16 * 1024 * 1024;
        config.catalog_ceiling = 16 * 1024 * 1024;
        config.eviction_high_watermark = 48 * 1024 * 1024;
        config.eviction_low_watermark = 32 * 1024 * 1024;
        config
    }
    #[test]
    fn runtime_shutdown_and_last_reader_drop_preserve_exclusive_ownership_until_sql_drains() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("state");
        let spool = Spool::open_durable(config(&root)).unwrap();
        let closure_owner = spool.clone();
        let task_owner = spool.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = mpsc::sync_channel(0);
        let (finished, last_drop) = mpsc::sync_channel(0);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let _task = tokio::spawn(async move {
                let _result = task_owner
                    .catalog_work_async(move |connection| {
                        let _: i64 = connection.query_row("SELECT 1", [], |row| row.get(0))?;
                        let _sent = started.send(());
                        gate.recv_timeout(Duration::from_secs(10))
                            .map_err(|_| CatalogError::InvalidState)?;
                        // With the runtime/supervisor gone this is the final owner on
                        // the actual SQLite reader, not merely a cancelled caller.
                        drop(closure_owner);
                        let _sent = finished.send(());
                        Ok(())
                    })
                    .await;
            });
            tokio::time::timeout(Duration::from_secs(5), ready)
                .await
                .expect("reader entered")
                .expect("reader start signal");
        });
        drop(spool);
        drop(runtime);
        assert!(Spool::open_durable(config(&root)).is_err());
        release.send(()).unwrap();
        last_drop
            .recv_timeout(Duration::from_secs(5))
            .expect("last-reader drop must not self-join or panic");
        let deadline = Instant::now() + Duration::from_secs(5);
        let reopened = loop {
            match Spool::open_durable(config(&root)) {
                Ok(spool) => break spool,
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "shutdown did not release lock: {error}"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
            }
        };
        drop(reopened);
    }
}
