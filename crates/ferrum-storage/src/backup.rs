//! Hourly immutable package-prefix online SQLite snapshots. A WAL-live main file
//! is never copied: SQLite's backup API owns the consistent snapshot, whose one
//! temporary inode is hashed and installed through the normal spool transaction.
use crate::{
    Spool,
    checkpoint::CheckpointError,
    disk::{ReservationClass, SnapshotFile, SnapshotObject},
    s3::{ControlCondition, OperationIdentity, S3Store},
};
use ferrum_apt::digest::ObjectIdentity;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupDescriptor {
    pub schema_version: u32,
    pub hour: i64,
    pub created_at: i64,
    pub object_key: String,
    pub sha256: String,
    pub size: u64,
    pub recovery_disclosure: String,
}

static SNAPSHOT_JOB: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));
/// Produces a bounded, consistent, immutable local snapshot using the same online
/// backup path as the hourly service. Useful for operator inspection and smoke.
pub async fn online_snapshot(
    spool: &Spool,
    maximum: u64,
    deadline: Instant,
) -> Result<crate::VerifiedObject, CheckpointError> {
    Ok(owned_online_snapshot(spool, maximum, deadline)
        .await?
        .into_object()?)
}

async fn owned_online_snapshot(
    spool: &Spool,
    maximum: u64,
    deadline: Instant,
) -> Result<SnapshotObject, CheckpointError> {
    let permit = SNAPSHOT_JOB
        .clone()
        .try_acquire_owned()
        .map_err(|_| crate::catalog::CatalogError::Busy)?;
    let spool = spool.clone();
    // Detached work owns its temporary and installed cleanup guard. Dropping
    // this future cannot release accounting while the file is still in I/O.
    tokio::spawn(async move { snapshot_owned(&spool, maximum, deadline, permit).await })
        .await
        .map_err(|_| crate::catalog::CatalogError::Closed)?
}
async fn snapshot_owned(
    spool: &Spool,
    maximum: u64,
    deadline: Instant,
    _permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<SnapshotObject, CheckpointError> {
    if !(4096..=8 * 1024 * 1024 * 1024).contains(&maximum) {
        return Err(CheckpointError::Invalid);
    }
    let snapshot = SnapshotFile::create(spool, maximum).await?;
    let path = snapshot.path()?.to_owned();
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(60));
    let snapshot = spool
        .online_backup(
            path,
            maximum,
            std::time::Instant::now() + remaining,
            snapshot,
        )
        .await?;
    Ok(snapshot.install(deadline.into_std()).await?)
}

pub struct BackupService {
    spool: Spool,
    store: Arc<S3Store>,
    maximum: u64,
    gate: tokio::sync::Mutex<()>,
}
impl BackupService {
    pub fn new(spool: Spool, store: Arc<S3Store>, maximum: u64) -> Result<Self, CheckpointError> {
        spool.durable_catalog()?;
        if !spool.same_owner(store.ledger()?.spool()) {
            return Err(CheckpointError::Proof);
        }
        if !(4096..=8 * 1024 * 1024 * 1024).contains(&maximum) {
            return Err(CheckpointError::Invalid);
        }
        Ok(Self {
            spool,
            store,
            maximum,
            gate: tokio::sync::Mutex::new(()),
        })
    }
    /// Idempotent for a completed UTC hour. Failed/ambiguous uploads are resolved
    /// by immutable-key full readback; no mutable latest pointer is recovery truth.
    pub async fn backup_if_due(
        &self,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Option<BackupDescriptor>, CheckpointError> {
        let _gate = self
            .gate
            .try_lock()
            .map_err(|_| crate::catalog::CatalogError::Busy)?;
        let hour = now.div_euclid(3600);
        let catalog = self.spool.durable_catalog()?;
        if catalog.backup_last_hour()?.is_some_and(|last| hour <= last) {
            return Ok(None);
        }
        let snapshot = owned_online_snapshot(&self.spool, self.maximum, deadline).await?;
        let object = snapshot.object()?;
        let identity = object.identity();
        let size = identity.size;
        let result: Result<BackupDescriptor, CheckpointError> = async {
            let suffix = format!("v1/backups/{hour}/{}.sqlite", identity.sha256);
            // The concrete adapter performs complete authenticated streamed readback,
            // including lost mutation ACK reconciliation, before returning success.
            self.store
                .control_put_file(&suffix, object.path(), identity, deadline, cancel)
                .await?;
            let descriptor = BackupDescriptor {
                schema_version: 1,
                hour,
                created_at: hour.checked_mul(3600).ok_or(CheckpointError::Invalid)?,
                object_key: self.store.package_key(&suffix)?,
                sha256: identity.sha256.to_hex(),
                size,
                recovery_disclosure: "Backup active pointers are not a recovery floor. Direct trusted sibling checkpoint, signature/hash verification, authenticated origin reconfirmation, and budget/receipt/retention reconciliation are required; GC and new captures remain disabled until reconciled.".into(),
            };
            let encoded = serde_json::to_vec(&descriptor)?;
            let descriptor_key = format!("v1/backups/{hour}/{}.json", identity.sha256);
            let write = self
                .store
                .control_put(
                    OperationIdentity::Object,
                    &descriptor_key,
                    &encoded,
                    ControlCondition::Create,
                    deadline,
                    cancel,
                )
                .await;
            let read = self
                .store
                .control_get(
                    OperationIdentity::Object,
                    &descriptor_key,
                    16 * 1024,
                    deadline,
                    cancel,
                )
                .await?;
            if read.bytes != encoded {
                let _ = write;
                return Err(CheckpointError::Proof);
            }
            let encoded = String::from_utf8(encoded).map_err(|_| CheckpointError::Invalid)?;
            crate::checkpoint::catalog_update(&self.spool, |catalog| {
                catalog.backup_record(
                    hour,
                    descriptor.object_key.clone(),
                    descriptor.sha256.clone(),
                    size,
                    encoded,
                )
            })?;
            Ok(descriptor)
        }
        .await;
        // Exact owner-authorized cleanup also runs from Drop on cancellation.
        // Existing shared/pinned digest dedup remains protected by the disk owner.
        let cleanup = snapshot.cleanup();
        let descriptor = result?;
        cleanup?;
        Ok(Some(descriptor))
    }
    /// Runs immediately and then at each UTC hour boundary; caller owns shutdown.
    /// Backup failures are logged and retried with bounded backoff; invalid clock
    /// progression is terminal. A failed attempt never records a completed hour.
    pub async fn run_hourly(&self, cancel: &CancellationToken) -> Result<(), CheckpointError> {
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let now = ferrum_apt::release::UnixTime::now().as_secs();
            match self
                .backup_if_due(now, Instant::now() + Duration::from_secs(600), cancel)
                .await
            {
                Ok(_) => {}
                Err(CheckpointError::Transport(crate::s3::S3Error::Cancelled))
                    if cancel.is_cancelled() =>
                {
                    return Ok(());
                }
                Err(error) => {
                    let backoff = match &error {
                        CheckpointError::Transport(
                            crate::s3::S3Error::Forbidden
                            | crate::s3::S3Error::Budget
                            | crate::s3::S3Error::AdmissionRefused,
                        )
                        | CheckpointError::Spool(
                            crate::SpoolError::CapacityExhausted { .. }
                            | crate::SpoolError::AdmissionClosed,
                        ) => Duration::from_secs(900),
                        _ => Duration::from_secs(30),
                    };
                    tracing::warn!(%error, ?backoff, "hourly catalog backup incomplete; retrying after backoff");
                    tokio::select! {
                        () = cancel.cancelled() => return Ok(()),
                        () = tokio::time::sleep(backoff) => continue,
                    }
                }
            }
            let after = ferrum_apt::release::UnixTime::now().as_secs();
            let delay = next_hour_delay(now, after)?;
            if delay.is_zero() {
                continue;
            }
            tokio::select! {_ = cancel.cancelled()=>return Ok(()),_ = tokio::time::sleep(delay)=>{}}
        }
    }
}

impl BackupService {
    /// Reads an operator-selected immutable descriptor and its complete SQLite
    /// bytes into the existing verified spool. This does not activate any suite
    /// or grant capture/GC authority; the trusted direct floors still govern.
    pub async fn retrieve(
        &self,
        hour: i64,
        digest: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(BackupDescriptor, crate::VerifiedObject), CheckpointError> {
        let digest = crate::checkpoint::canonical_digest(digest)?;
        let descriptor_key = format!("v1/backups/{hour}/{digest}.json");
        let object = self
            .store
            .control_get(
                OperationIdentity::Object,
                &descriptor_key,
                16 * 1024,
                deadline,
                cancel,
            )
            .await?;
        let descriptor: BackupDescriptor = serde_json::from_slice(&object.bytes)?;
        let suffix = format!("v1/backups/{hour}/{digest}.sqlite");
        let expected_key = self.store.package_key(&suffix)?;
        if descriptor.schema_version != 1
            || descriptor.hour != hour
            || descriptor.object_key != expected_key
            || descriptor.sha256 != digest.to_hex()
            || descriptor.size > self.maximum
        {
            return Err(CheckpointError::Invalid);
        }
        let expected = ObjectIdentity {
            sha256: digest,
            size: descriptor.size,
        };
        let reservation = self
            .spool
            .reserve_class(expected.size, ReservationClass::Metadata)?;
        let response = self
            .store
            .control_get_stream(
                OperationIdentity::Object,
                &suffix,
                expected,
                deadline,
                cancel,
            )
            .await?;
        let mut writer = self.spool.begin_write(reservation, expected).await?;
        use futures_util::StreamExt;
        let mut stream = response.into_stream();
        while let Some(chunk) = stream.next().await {
            writer.write(chunk?).await?;
        }
        let object = writer.commit().await?;
        self.spool.validate_backup(object.clone()).await?;
        Ok((descriptor, object))
    }
}

fn next_hour_delay(started: i64, finished: i64) -> Result<Duration, CheckpointError> {
    if finished < started {
        return Err(crate::catalog::CatalogError::InvalidState.into());
    }
    if finished.div_euclid(3600) > started.div_euclid(3600) {
        return Ok(Duration::ZERO);
    }
    Ok(Duration::from_secs(
        (3600 - finished.rem_euclid(3600)) as u64,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    fn backup_duration_does_not_drift_hourly_snapshot_start() {
        assert_eq!(next_hour_delay(0, 600).unwrap(), Duration::from_secs(3000));
        assert_eq!(next_hour_delay(3300, 3900).unwrap(), Duration::ZERO);
        assert!(next_hour_delay(3600, 3599).is_err());
    }

    #[tokio::test]
    async fn online_snapshot_accepts_full_object_cap_and_cleans_over_cap_output() {
        let directory = tempfile::tempdir().unwrap();
        let spool = crate::recovery::test_support::open_spool(directory.path());
        // The fixture's per-object cap is exactly 128 MiB. The old raw
        // reservation added a step to that cap and failed before any SQLite I/O.
        let object = online_snapshot(
            &spool,
            128 * 1024 * 1024,
            Instant::now() + Duration::from_secs(30),
        )
        .await
        .unwrap();
        spool.validate_backup(object.clone()).await.unwrap();
        let identity = object.identity();
        assert!(identity.size > 4096);
        assert_eq!(spool.accounting().installed, identity.size);
        assert_eq!(spool.accounting().reserved, 0);
        drop(object);
        assert!(spool.discard_unreferenced_metadata(identity).unwrap());
        assert!(
            online_snapshot(&spool, 4096, Instant::now() + Duration::from_secs(30))
                .await
                .is_err()
        );
        assert_eq!(spool.accounting().reserved, 0);
        assert_eq!(spool.accounting().installed, 0);
        assert_eq!(
            std::fs::read_dir(spool.root().join("temporary"))
                .unwrap()
                .count(),
            0
        );
    }
}
