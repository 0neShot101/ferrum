//! Replayable upload owner. SQLite holds work; no in-memory body queue exists.
use crate::capture::{CaptureError, CaptureManager};
use crate::catalog::CatalogError;
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
pub struct UploadWorker {
    manager: CaptureManager,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct UploadReport {
    pub completed: u64,
    pub verified_resident: u64,
    pub failed: u64,
}
impl UploadWorker {
    pub fn new(manager: CaptureManager) -> Self {
        Self { manager }
    }
    /// Two bounded work items, sharing the transport's two-upload/16-operation
    /// limits. Restored resident verification is separate from outbox admission.
    pub async fn drain_once(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<UploadReport, CaptureError> {
        if !self.manager.usage()?.coverage {
            return Err(CaptureError::ReconciliationPending);
        }
        let now = crate::s3::production_now()?;
        let mut objects = self
            .manager
            .spool()
            .durable_catalog()?
            .read(move |connection| {
                let mut statement = connection.prepare("SELECT digest,size FROM capture_outbox WHERE next_attempt<=?1 AND quarantined=0 ORDER BY queued_at,digest LIMIT 2")?;
                let rows = statement.query_map([now], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                    ))
                })?;
                rows.map(|row| {
                    let (digest, size) = row?;
                    Ok((
                        ObjectIdentity {
                            sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?,
                            size,
                        },
                        false,
                    ))
                })
                .collect::<Result<Vec<_>, CatalogError>>()
            })?;
        let verification = self
            .manager
            .spool()
            .durable_catalog()?
            .read(move |connection| {
                let mut statement = connection.prepare("SELECT b.digest,b.size FROM objects o JOIN capture_blobs b ON b.digest=o.digest WHERE o.resident=1 AND o.upload_state=0 AND b.readback_verified=0 AND b.gc_pending=0 AND b.verify_after<=?1 AND NOT EXISTS(SELECT 1 FROM capture_outbox WHERE digest=b.digest) AND NOT EXISTS(SELECT 1 FROM capture_admissions WHERE digest=b.digest) AND EXISTS(SELECT 1 FROM capture_paths p JOIN capture_proofs q ON q.generation=p.generation WHERE p.digest=b.digest AND p.receipt_verified=1 AND q.durable=1) ORDER BY b.digest LIMIT 2")?;
                let rows = statement.query_map([now], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                    ))
                })?;
                rows.map(|row| {
                    let (digest, size) = row?;
                    Ok((
                        ObjectIdentity {
                            sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?,
                            size,
                        },
                        true,
                    ))
                })
                .collect::<Result<Vec<_>, CatalogError>>()
            })?;
        if !verification.is_empty() {
            objects.truncate(1);
            objects.extend(verification.into_iter().take(2 - objects.len()));
        }
        let mut report = UploadReport::default();
        if objects.len() == 2 {
            let (first, second) = tokio::join!(
                self.perform(objects[0], deadline, cancel),
                self.perform(objects[1], deadline, cancel)
            );
            for (item, result) in objects.into_iter().zip([first, second]) {
                self.record(item, result, &mut report)?;
            }
        } else if let Some(item) = objects.first() {
            self.record(
                *item,
                self.perform(*item, deadline, cancel).await,
                &mut report,
            )?;
        }
        Ok(report)
    }
    async fn perform(
        &self,
        item: (ObjectIdentity, bool),
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CaptureError> {
        if item.1 {
            self.manager
                .rehydrate(item.0, deadline, cancel)
                .await
                .map(|_| ())
        } else {
            self.manager.complete(item.0, deadline, cancel).await
        }
    }
    fn record(
        &self,
        (identity, verification): (ObjectIdentity, bool),
        result: Result<(), CaptureError>,
        report: &mut UploadReport,
    ) -> Result<(), CaptureError> {
        match result {
            Ok(()) => {
                if verification {
                    report.verified_resident += 1;
                } else {
                    report.completed += 1;
                }
            }
            Err(error) => {
                report.failed += 1;
                let quarantine = matches!(
                    error,
                    CaptureError::Proof | CaptureError::S3(crate::s3::S3Error::Corrupt)
                );
                let next = if verification && quarantine {
                    i64::MAX
                } else {
                    crate::s3::production_now()?.saturating_add(30)
                };
                self.manager.spool().catalog_write(move |connection| {
                    if verification {
                        connection.execute(
                            "UPDATE capture_blobs SET verify_after=?1 WHERE digest=?2",
                            rusqlite::params![next, identity.sha256.to_hex()],
                        )?;
                    } else {
                        connection.execute(
                            "UPDATE capture_outbox SET next_attempt=?1,quarantined=?2 WHERE digest=?3",
                            rusqlite::params![next, quarantine, identity.sha256.to_hex()],
                        )?;
                    }
                    Ok(())
                })?;
                tracing::warn!(%error,quarantine,verification,"capture work remains non-evictable and persisted");
            }
        }
        Ok(())
    }
    pub async fn run(self, cancel: CancellationToken) -> Result<(), CaptureError> {
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let report = match self
                .drain_once(Instant::now() + Duration::from_secs(600), &cancel)
                .await
            {
                Ok(report) => report,
                // Startup recovery owns coverage. Keep the worker supervised,
                // but perform no upload or allowance reservation until it finishes.
                Err(CaptureError::ReconciliationPending) => UploadReport::default(),
                Err(error) => return Err(error),
            };
            let delay = if report.completed + report.verified_resident > 0 && report.failed == 0 {
                Duration::from_millis(10)
            } else {
                Duration::from_secs(5)
            };
            tokio::select! {()=cancel.cancelled()=>return Ok(()),()=tokio::time::sleep(delay)=>{}}
        }
    }
}
