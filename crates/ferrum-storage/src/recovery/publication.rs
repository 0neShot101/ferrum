//! Publication transport and bounded derived reconstruction share the same owners.
use super::*;
use crate::budget::BudgetClass;
use crate::catalog::{CatalogError, signed};
use crate::s3::ControlCondition;
use rusqlite::{OptionalExtension, params};

impl CheckpointPublisher {
    pub(crate) fn artifact_attested(
        &self,
        suffix: &str,
        identity: ObjectIdentity,
    ) -> Result<bool, CheckpointError> {
        let key = self.store.package_key(suffix)?;
        Ok(self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM publication_artifacts a JOIN remote_storage s ON s.key=a.key WHERE a.key=?1 AND a.digest=?2 AND a.size=?3 AND s.committed=1 AND NOT EXISTS(SELECT 1 FROM remote_quarantine q WHERE q.key=a.key))",
                params![key, identity.sha256.to_hex(), signed(identity.size)?],
                |row| row.get(0),
            )?)
        })?)
    }
    pub(crate) fn attest_artifact(
        &self,
        suffix: &str,
        identity: ObjectIdentity,
    ) -> Result<(), CheckpointError> {
        self.store.account_observed(
            OperationIdentity::Object,
            suffix,
            identity.size,
            BudgetClass::Control,
        )?;
        let key = self.store.package_key(suffix)?;
        self.spool.catalog_write(move |connection| {
            let old: Option<(String, u64)> = connection
                .query_row(
                    "SELECT digest,size FROM publication_artifacts WHERE key=?1",
                    [&key],
                    |row| Ok((row.get(0)?, crate::catalog::read_unsigned(row, 1)?)),
                )
                .optional()?;
            if old.is_some_and(|(digest, size)| {
                digest != identity.sha256.to_hex() || size != identity.size
            }) {
                return Err(CatalogError::InvalidState);
            }
            connection.execute(
                "INSERT OR IGNORE INTO publication_artifacts(key,digest,size) VALUES(?1,?2,?3)",
                params![key, identity.sha256.to_hex(), signed(identity.size)?],
            )?;
            Ok(())
        })?;
        Ok(())
    }
    /// Uploads/read-backs exact local closure bytes and then the immutable
    /// manifest. This grants no authentication or activation capability.
    pub async fn persist_generation(
        &self,
        manifest: &GenerationManifest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), CheckpointError> {
        manifest.validate()?;
        for artifact in &manifest.artifacts {
            if cancel.is_cancelled() || Instant::now() >= deadline {
                return Err(S3Error::Cancelled.into());
            }
            let identity = artifact.identity()?;
            let object = self.spool.lookup(identity).ok_or(CheckpointError::Proof)?;
            let suffix = format!("v1/objects/sha256/{}", identity.sha256);
            if !self.artifact_attested(&suffix, identity)? {
                self.store
                    .control_put_file(&suffix, object.path(), identity, deadline, cancel)
                    .await?;
                self.attest_artifact(&suffix, identity)?;
            }
        }
        let bytes = manifest.encode()?;
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(&bytes),
            size: bytes.len() as u64,
        };
        let suffix = manifest.suffix();
        if self.artifact_attested(&suffix, identity)? {
            return Ok(());
        }
        if let Err(error) = self
            .store
            .control_put(
                OperationIdentity::Object,
                &suffix,
                &bytes,
                ControlCondition::Create,
                deadline,
                cancel,
            )
            .await
            && !matches!(
                error,
                S3Error::Conflict | S3Error::Timeout | S3Error::Unavailable
            )
        {
            return Err(error.into());
        }
        let readback = self
            .store
            .control_get(
                OperationIdentity::Object,
                &suffix,
                MANIFEST_LIMIT,
                deadline,
                cancel,
            )
            .await?;
        if readback.bytes != bytes {
            self.store.quarantine_control(&suffix)?;
            return Err(CheckpointError::Proof);
        }
        self.attest_artifact(&suffix, identity)
    }
}

/// Reconstructs an authenticated derived descriptor into the normal verified
/// spool. The caller owns the descriptor and single flight; no outbox or public
/// metadata reference is created. Cancellation stops bounded decoder work.
pub async fn materialize_derived(
    spool: &Spool,
    source: VerifiedObject,
    source_path: &str,
    expected: ObjectIdentity,
    cancel: CancellationToken,
) -> Result<VerifiedObject, CheckpointError> {
    if !source.belongs_to(spool)
        || ![".xz", ".gz", ".bz2"]
            .iter()
            .any(|suffix| source_path.ends_with(suffix))
    {
        return Err(CheckpointError::Proof);
    }
    let reconstruction = spool
        .authorize_derived(expected, source.identity(), source_path)?
        .ok_or(CheckpointError::Proof)?;
    if let Some(object) = spool.lookup(expected) {
        return Ok(object);
    }
    let deadline = Instant::now() + Duration::from_secs(600);
    let child = cancel.child_token();
    let _cancel = child.clone().drop_guard();
    let permit = tokio::select! {
        ()=child.cancelled()=>return Err(S3Error::Cancelled.into()),
        permit=tokio::time::timeout_at(deadline,PROOF_CPU.clone().acquire_owned())=>permit.map_err(|_|CheckpointError::Proof)?.map_err(|_|CheckpointError::Proof)?,
    };
    let reservation = spool.reserve_class(expected.size, ReservationClass::Package)?;
    let mut writer = spool.begin_write(reservation, expected).await?;
    let (send, mut receive) = tokio::sync::mpsc::channel(2);
    let worker_spool = spool.clone();
    let worker_cancel = child.clone();
    let name = source_path.to_owned();
    let worker = tokio::spawn(async move {
        worker_spool
            .catalog_work_async(move |_| {
                let _permit = permit;
                let mut reader =
                    proof_reader(std::fs::File::open(source.path())?, &name, worker_cancel)?;
                let mut total = 0u64;
                loop {
                    use std::io::Read;
                    let maximum =
                        usize::try_from(expected.size.saturating_sub(total).saturating_add(1))
                            .unwrap_or(256 * 1024)
                            .min(256 * 1024);
                    let mut buffer = vec![0u8; maximum];
                    let count = reader.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    total = total
                        .checked_add(count as u64)
                        .ok_or(CatalogError::InvalidState)?;
                    if total > expected.size {
                        return Err(CatalogError::InvalidState);
                    }
                    buffer.truncate(count);
                    send.blocking_send(bytes::Bytes::from(buffer))
                        .map_err(|_| CatalogError::Closed)?;
                }
                if total != expected.size {
                    return Err(CatalogError::InvalidState);
                }
                Ok(())
            })
            .await
    });
    while let Some(bytes) = tokio::select! {()=child.cancelled()=>return Err(S3Error::Cancelled.into()),bytes=receive.recv()=>bytes}
    {
        writer.write(bytes).await?;
    }
    worker.await.map_err(|_| CheckpointError::Proof)??;
    let object = writer.commit().await?;
    spool.finish_derived(reconstruction)?;
    Ok(object)
}
