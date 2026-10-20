use super::{CaptureError, CaptureManager};
use crate::{Spool, catalog::CatalogError};
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use rusqlite::params;
#[must_use = "hold the capture reservation through the verified spool commit"]
pub struct CaptureReservation {
    pub(super) manager: CaptureManager,
    pub(super) identity: ObjectIdentity,
    pub(super) _path: tokio::sync::OwnedSemaphorePermit,
    pub(super) registered: bool,
}
impl CaptureReservation {
    pub fn identity(&self) -> ObjectIdentity {
        self.identity
    }
}
impl Drop for CaptureReservation {
    fn drop(&mut self) {
        if let Err(error) = self
            .manager
            .abandon_uncommitted(self.identity, self.registered)
        {
            tracing::error!(%error,"capture cancellation accounting retained; reconciliation required");
            self.manager.spool.close_capture_admission();
        }
    }
}
pub(crate) fn proof_pin(generation: &str) -> Sha256Digest {
    let mut hash = ferrum_apt::digest::Sha256Hasher::new();
    hash.update(b"ferrum-capture-proof-v1:");
    hash.update(generation.as_bytes());
    hash.finalize()
}
pub(crate) fn signature_pin(
    generation: &str,
    package_path: &str,
    signature: ObjectIdentity,
) -> Sha256Digest {
    let mut hash = ferrum_apt::digest::Sha256Hasher::new();
    hash.update(b"ferrum-capture-package-signature-v1:");
    hash.update(generation.as_bytes());
    hash.update(&[0]);
    hash.update(package_path.as_bytes());
    hash.update(&[0]);
    hash.update(signature.sha256.as_bytes());
    hash.update(&signature.size.to_le_bytes());
    hash.finalize()
}
/// A disk reservation or admitted commit owns the capture until its own cleanup.
/// This is called within the same SQL transaction that removes the last disk
/// reservation, preventing a cancelled commit from losing its outbox intent.
pub(crate) fn abandon_transaction(
    transaction: &rusqlite::Transaction<'_>,
    digest: &str,
) -> Result<(), CatalogError> {
    let live: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM reservations WHERE digest=?1 UNION SELECT 1 FROM objects WHERE digest=?1 AND resident=1 UNION SELECT 1 FROM capture_outbox WHERE digest=?1 UNION SELECT 1 FROM capture_admission_owners WHERE digest=?1)",
        [digest],
        |row| row.get(0),
    )?;
    if live {
        return Ok(());
    }
    transaction.execute("DELETE FROM capture_admissions WHERE digest=?1", [digest])?;
    transaction.execute(
        "DELETE FROM capture_paths WHERE digest=?1 AND receipt_verified=0",
        [digest],
    )?;
    transaction.execute(
        "DELETE FROM capture_generation_refs WHERE digest=?1 AND NOT EXISTS(SELECT 1 FROM capture_paths WHERE digest=?1) AND EXISTS(SELECT 1 FROM capture_blobs WHERE digest=?1 AND readback_verified=0)",
        [digest],
    )?;
    transaction.execute(
        "DELETE FROM capture_blobs WHERE digest=?1 AND readback_verified=0 AND NOT EXISTS(SELECT 1 FROM capture_paths WHERE digest=?1)",
        [digest],
    )?;
    transaction.execute(
        "DELETE FROM remote_storage WHERE class=0 AND committed=0 AND mutation_intent=0 AND key LIKE ?1 AND NOT EXISTS(SELECT 1 FROM capture_blobs WHERE digest=?2) AND NOT EXISTS(SELECT 1 FROM generation_pins WHERE digest=?2) AND NOT EXISTS(SELECT 1 FROM multipart_uploads WHERE multipart_uploads.key=remote_storage.key)",
        params![format!("%/v1/objects/sha256/{digest}"), digest],
    )?;
    Ok(())
}
impl CaptureManager {
    pub(super) fn abandon_uncommitted(
        &self,
        identity: ObjectIdentity,
        registered: bool,
    ) -> Result<(), CaptureError> {
        let digest = identity.sha256.to_hex();
        self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            if registered {
                let removed = transaction.execute(
                    "DELETE FROM capture_admission_owners WHERE digest=?1 AND owners=1",
                    [&digest],
                )?;
                if removed == 0 {
                    transaction.execute(
                        "UPDATE capture_admission_owners SET owners=owners-1 WHERE digest=?1 AND owners>1",
                        [&digest],
                    )?;
                }
            }
            abandon_transaction(&transaction, &digest)?;
            transaction.commit()?;
            Ok(())
        })?;
        let live = self.spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_admissions WHERE digest=?1 UNION SELECT 1 FROM capture_outbox WHERE digest=?1)",
                [identity.sha256.to_hex()],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if !live {
            self.store.ledger()?.release_capture_credit(
                &self
                    .store
                    .package_key(&format!("v1/objects/sha256/{}", identity.sha256))?,
            )?;
        }
        super::cleanup::unused(&self.spool)?;
        Ok(())
    }
}
/// Runs after filesystem reconciliation and before the gateway accepts requests.
pub(crate) fn reconcile_startup(spool: &Spool) -> Result<(), crate::SpoolError> {
    loop {
        let removed = spool.catalog_write(|connection| {
            Ok(connection.execute(
                "DELETE FROM capture_admission_owners WHERE rowid IN (SELECT rowid FROM capture_admission_owners LIMIT 128)",
                [],
            )?)
        })?;
        if removed == 0 {
            break;
        }
    }
    loop {
        let rows = spool.durable_catalog()?.read(|connection| {
            let mut statement = connection.prepare("SELECT a.digest,a.size FROM capture_admissions a JOIN objects o ON o.digest=a.digest WHERE o.resident=1 ORDER BY a.digest LIMIT 128")?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    crate::catalog::read_unsigned(row, 1)?,
                ))
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        if rows.is_empty() {
            break;
        }
        for (digest, size) in rows {
            let identity = ObjectIdentity {
                sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?,
                size,
            };
            spool
                .durable_catalog()?
                .enqueue_installed_capture(identity)?;
        }
    }
    loop {
        let rows = spool.durable_catalog()?.read(|connection| {
            let mut statement = connection.prepare("SELECT digest FROM capture_admissions WHERE NOT EXISTS(SELECT 1 FROM objects WHERE objects.digest=capture_admissions.digest AND resident=1) ORDER BY digest LIMIT 128")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })?;
        if rows.is_empty() {
            break;
        }
        spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            for digest in rows {
                abandon_transaction(&transaction, &digest)?;
            }
            transaction.commit()?;
            Ok(())
        })?;
    }
    super::cleanup::unused(spool)
}
