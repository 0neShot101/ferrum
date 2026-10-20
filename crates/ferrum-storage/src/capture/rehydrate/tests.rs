#![allow(clippy::expect_used)]

use super::*;
use crate::capture::tests::{authenticated, response, setup};
use ferrum_apt::digest::Sha256Digest;
use std::sync::OnceLock;
use std::time::Duration;

#[tokio::test]
async fn fetched_hit_removes_one_full_get_for_new_and_existing_mappings() {
    for reuse in [false, true] {
        let root = tempfile::tempdir().expect("fixture directory");
        let (fixture, signed) = authenticated(&root.path().join("state")).await;
        let body = b"post-authenticated remote package";
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(body),
            size: body.len() as u64,
        };
        // The signed fixture has no .deb payload. As in the retention tests,
        // substitute only at the already-authenticated persistence boundary.
        let proof = VerifiedCaptureProof {
            proof: signed.proof.clone(),
            path: signed.path.clone(),
            identity,
            package_signature: None,
            package_objects: None,
            request_authentication: OnceLock::new(),
        };
        let receipt = CaptureReceipt {
            schema_version: 1,
            repository: proof.repository().into(),
            public_package_path: proof.path().as_str().into(),
            size: identity.size,
            sha256: identity.sha256.to_hex(),
            proof_generation_id: proof.manifest().generation_id.clone(),
            first_capture_time: 1,
            package_signature: None,
        };
        let receipt_bytes = serde_json::to_vec(&receipt).expect("receipt bytes");
        let mut responses = Vec::new();
        for existing in [false, true] {
            responses.push(response("GET", 200, body));
            if !reuse {
                responses.push(response("GET", 200, body));
            }
            if !existing {
                responses.push(response("PUT", 200, b""));
            }
            responses.push(response("GET", 200, &receipt_bytes));
        }
        let (manager, ledger, requests) = setup(fixture.spool.clone(), responses);
        let generation = proof.manifest().scope_id().to_hex();
        let manifest = String::from_utf8(proof.manifest().encode().expect("manifest"))
            .expect("manifest UTF-8");
        let path = proof.path().as_str().to_owned();
        fixture
            .spool
            .catalog_write(move |connection| {
                let transaction = connection.transaction()?;
                transaction.execute(
                    "INSERT INTO capture_proofs(generation,manifest,durable,was_public) VALUES(?1,?2,1,1)",
                    params![generation, manifest],
                )?;
                transaction.execute(
                    "UPDATE capture_index_entries SET digest=?1,size=?2 WHERE path=?3",
                    params![
                        identity.sha256.to_hex(),
                        crate::catalog::signed(identity.size)?,
                        path
                    ],
                )?;
                // Preserve the receipt's first-capture timestamp without granting
                // package readback or mapping authority.
                transaction.execute(
                    "INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,?2,1,1,0)",
                    params![
                        identity.sha256.to_hex(),
                        crate::catalog::signed(identity.size)?
                    ],
                )?;
                transaction.commit()?;
                Ok(())
            })
            .expect("authenticated owner state");

        let deadline = Instant::now() + Duration::from_secs(60);
        let cancel = CancellationToken::new();
        for _ in 0..2 {
            let (object, fetched) = manager
                .store()
                .fetch_verified(&fixture.spool, identity, deadline, cancel.clone())
                .await
                .expect("complete remote transfer");
            let observed = if reuse {
                manager
                    .capture_fetched_hit(&proof, fetched, deadline, &cancel)
                    .await
            } else {
                drop(fetched);
                manager
                    .capture_verified_hit(&proof, deadline, &cancel)
                    .await
            }
            .expect("verified receipt");
            assert_eq!(observed, receipt);
            assert_eq!(object.read_bounded(1024).await.expect("read package"), body);
            assert_eq!(
                manager
                    .lookup(proof.repository(), proof.path())
                    .expect("mapping"),
                Some(identity)
            );
            assert!(manager.is_durable(identity).expect("durable package"));
            assert_eq!(manager.usage().expect("capture usage").entries, 0);
        }

        let methods = requests.snapshot().expect("methods");
        let targets = requests.targets().expect("targets");
        let suffix = format!("/v1/objects/sha256/{}", identity.sha256);
        let package_gets = methods
            .iter()
            .zip(targets.iter())
            .filter(|(method, target)| method.as_str() == "GET" && target.contains(&suffix))
            .count();
        assert_eq!(package_gets, if reuse { 2 } else { 4 });
        assert_eq!(
            methods
                .iter()
                .filter(|method| method.as_str() == "PUT")
                .count(),
            1
        );
        assert_eq!(
            methods
                .iter()
                .filter(|method| method.as_str() == "GET")
                .count(),
            package_gets + 2
        );
        assert!(ledger.usage().expect("ledger").certain);
        eprintln!(
            "capture reuse={reuse}: package_gets={package_gets}, package_bytes={}",
            package_gets as u64 * identity.size
        );
    }
}
