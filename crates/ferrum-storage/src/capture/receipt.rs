use super::{CaptureError, CaptureManager, CaptureReceipt, VerifiedCaptureProof};
use crate::{
    budget::BudgetClass,
    s3::{ControlCondition, OperationIdentity, S3Error, S3Store},
};
use ferrum_apt::digest::Sha256Hasher;
use futures_util::StreamExt;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
pub(super) async fn read(
    store: &S3Store,
    expected: &CaptureReceipt,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<CaptureReceipt, CaptureError> {
    let suffix = expected.suffix();
    let response = store
        .control_get(
            OperationIdentity::Object,
            &suffix,
            super::RECEIPT_LIMIT,
            deadline,
            cancel,
        )
        .await?;
    let mut actual: CaptureReceipt = match serde_json::from_slice(&response.bytes) {
        Ok(receipt) => receipt,
        Err(_) => {
            store.quarantine_control(&suffix)?;
            return Err(CaptureError::Proof);
        }
    };
    if actual.validate().is_err() {
        store.quarantine_control(&suffix)?;
        return Err(CaptureError::Proof);
    }
    // This unsigned timestamp is informational, never retention/authentication.
    // Restore intentionally chooses a later conservative catalog timestamp.
    let observed_time = actual.first_capture_time;
    actual.first_capture_time = expected.first_capture_time;
    if actual != *expected {
        store.quarantine_control(&suffix)?;
        return Err(CaptureError::Proof);
    }
    actual.first_capture_time = observed_time;
    Ok(actual)
}
pub(super) async fn put(
    store: &S3Store,
    expected: &CaptureReceipt,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<CaptureReceipt, CaptureError> {
    let bytes = serde_json::to_vec(expected)?;
    if bytes.len() as u64 > super::RECEIPT_LIMIT {
        return Err(CaptureError::Proof);
    }
    if let Err(error) = store
        .control_put(
            OperationIdentity::Object,
            &expected.suffix(),
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
    read(store, expected, deadline, cancel).await
}
pub(super) async fn verify_closure(
    manager: &CaptureManager,
    proof: &VerifiedCaptureProof,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(), CaptureError> {
    if !manager.spool.same_owner(&proof.proof.owner) {
        return Err(CaptureError::Proof);
    }
    for artifact in &proof.manifest().artifacts {
        let identity = artifact.identity().map_err(|_| CaptureError::Proof)?;
        let suffix = format!("v1/objects/sha256/{}", identity.sha256);
        let response = manager
            .store
            .control_get_stream(
                OperationIdentity::Object,
                &suffix,
                identity,
                deadline,
                cancel,
            )
            .await?;
        let mut stream = response.into_stream();
        let mut hash = Sha256Hasher::new();
        let mut size = 0u64;
        while let Some(bytes) = stream.next().await {
            let bytes = bytes?;
            size = size
                .checked_add(bytes.len() as u64)
                .ok_or(CaptureError::Proof)?;
            hash.update(&bytes);
        }
        if size != identity.size || hash.finalize() != identity.sha256 {
            manager.store.quarantine(identity)?;
            return Err(CaptureError::Proof);
        }
        manager.store.account_observed(
            OperationIdentity::Object,
            &suffix,
            identity.size,
            BudgetClass::Control,
        )?;
    }
    let manifest = proof.manifest();
    let actual = manager
        .store
        .control_get(
            OperationIdentity::Object,
            &manifest.suffix(),
            1024 * 1024,
            deadline,
            cancel,
        )
        .await?;
    if actual.bytes != manifest.encode().map_err(|_| CaptureError::Proof)? {
        manager.store.quarantine_control(&manifest.suffix())?;
        return Err(CaptureError::Proof);
    }
    manager.store.account_observed(
        OperationIdentity::Object,
        &manifest.suffix(),
        actual.bytes.len() as u64,
        BudgetClass::Control,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::{
        capture::{GRACE, tests as fixture},
        recovery::test_support,
    };
    use ferrum_apt::digest::Sha256Digest;
    use tokio::time::Duration;

    #[tokio::test]
    async fn observed_bad_receipt_revokes_only_its_path_and_owner_eviction_authority() {
        for malformed in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let spool = test_support::open_spool(&root.path().join("state"));
            let bytes = b"receipt authority regression";
            let digest = Sha256Digest::of(bytes);
            let expected = CaptureReceipt {
                schema_version: 1,
                repository: "origin-a".into(),
                public_package_path: "pool/main/p/package_1_all.deb".into(),
                size: bytes.len() as u64,
                sha256: digest.to_hex(),
                proof_generation_id: Sha256Digest::of(b"post-authenticated owner transition")
                    .to_hex(),
                first_capture_time: 1,
                package_signature: None,
            };
            let mut other = expected.clone();
            other.repository = "origin-b".into();
            let mut mismatch = expected.clone();
            mismatch.proof_generation_id = Sha256Digest::of(b"wrong proof").to_hex();
            let corrupt = if malformed {
                b"not json".to_vec()
            } else {
                serde_json::to_vec(&mismatch).unwrap()
            };
            let (manager, _, requests) = fixture::setup(
                spool.clone(),
                vec![
                    fixture::response("GET", 200, &serde_json::to_vec(&expected).unwrap()),
                    fixture::response("GET", 200, &serde_json::to_vec(&other).unwrap()),
                    fixture::response("GET", 200, &corrupt),
                ],
            );
            let object = fixture::install(&spool, bytes).await;
            let identity = object.identity();
            let now = crate::s3::production_now().unwrap();
            fixture::seed_paths(&spool, identity, false, now, now + GRACE);
            let cancel = CancellationToken::new();
            let deadline = Instant::now() + Duration::from_secs(30);
            // Establish both receipt authorities through real bounded GET/parse/
            // equality verification before exercising the owner promotion.
            read(&manager.store, &expected, deadline, &cancel)
                .await
                .unwrap();
            read(&manager.store, &other, deadline, &cancel)
                .await
                .unwrap();
            spool
                .catalog_write(move |connection| {
                    connection.execute(
                        "UPDATE capture_paths SET receipt_verified=1 WHERE digest=?1",
                        [identity.sha256.to_hex()],
                    )?;
                    connection.execute(
                        "UPDATE capture_blobs SET readback_verified=1 WHERE digest=?1",
                        [identity.sha256.to_hex()],
                    )?;
                    Ok(())
                })
                .unwrap();
            assert!(spool.promote_capture(identity).unwrap());
            let mut unknown = expected.clone();
            unknown.repository = "origin-c".into();
            manager.store.quarantine_control(&unknown.suffix()).unwrap();
            assert!(manager.is_durable(identity).unwrap());
            assert!(matches!(
                manager.store.quarantine_control("v1/unknown/control.json"),
                Err(crate::s3::S3Error::Boundary)
            ));
            assert!(manager.is_durable(identity).unwrap());
            drop(object); // No live reader may be the reason reclaim rejects it.
            assert!(matches!(
                read(&manager.store, &expected, deadline, &cancel).await,
                Err(CaptureError::Proof)
            ));
            assert!(!manager.is_durable(identity).unwrap());
            let authority = spool
                .durable_catalog()
                .unwrap()
                .read(move |connection| {
                    Ok(connection.query_row(
                        "SELECT (SELECT receipt_verified FROM capture_paths WHERE repository='origin-a'),(SELECT receipt_verified FROM capture_paths WHERE repository='origin-b'),(SELECT upload_state FROM objects WHERE digest=?1),(SELECT readback_verified FROM capture_blobs WHERE digest=?1)",
                        [identity.sha256.to_hex()],
                        |row| {
                            Ok((
                                row.get::<_, bool>(0)?,
                                row.get::<_, bool>(1)?,
                                row.get::<_, bool>(2)?,
                                row.get::<_, bool>(3)?,
                            ))
                        },
                    )?)
                })
                .unwrap();
            assert_eq!(authority, (false, true, false, true));
            assert!(!spool.promote_capture(identity).unwrap());
            assert_eq!(spool.reclaim(identity.size).unwrap(), 0);
            assert!(spool.lookup(identity).is_some());
            assert_eq!(requests.snapshot().unwrap(), ["GET", "GET", "GET"]);
        }
    }
}
