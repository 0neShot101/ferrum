use std::io::Read;
use std::time::{Duration, SystemTime};

use openpgp::cert::prelude::*;
use openpgp::parse::{
    Parse,
    stream::{GoodChecksum, MessageLayer, MessageStructure, VerificationHelper},
};
use openpgp::policy::{HashAlgoSecurity, Policy};
use openpgp::types::{RevocationStatus, SignatureType};
use openpgp::{Cert, KeyHandle};
use sequoia_openpgp as openpgp;

use crate::Failure;

const MAX_CERTIFICATES: usize = 128;
const MAX_KEYS: usize = 1024;
const MAX_SIGNATURES: usize = 256;

pub(crate) fn load(reader: impl Read + Send + Sync) -> Result<Vec<Cert>, Failure> {
    let parser = CertParser::from_reader(reader).map_err(|_| Failure::Keyring)?;
    let mut certs = Vec::new();
    let mut keys = 0usize;
    for cert in parser {
        let cert = cert.map_err(|_| Failure::Keyring)?;
        keys += cert.keys().count();
        if cert.is_tsk() || certs.len() >= MAX_CERTIFICATES || keys > MAX_KEYS {
            return Err(Failure::Keyring);
        }
        certs.push(cert);
    }
    if certs.is_empty() {
        return Err(Failure::Keyring);
    }
    certs.sort_by_key(Cert::fingerprint);
    let mut merged: Vec<Cert> = Vec::with_capacity(certs.len());
    for cert in certs {
        if merged
            .last()
            .is_some_and(|last| last.fingerprint() == cert.fingerprint())
        {
            // Merge all copies before verification: an older copy must not
            // bypass a revocation or an updated expiration in another copy.
            let previous = merged.pop().ok_or(Failure::Keyring)?;
            merged.push(previous.merge_public(cert).map_err(|_| Failure::Keyring)?);
        } else {
            merged.push(cert);
        }
    }
    Ok(merged)
}

pub(crate) struct Helper<'a> {
    certs: Vec<Cert>,
    policy: &'a dyn Policy,
    now: SystemTime,
    signature_type: SignatureType,
}

impl<'a> Helper<'a> {
    pub(crate) fn new(
        certs: Vec<Cert>,
        policy: &'a dyn Policy,
        now: SystemTime,
        signature_type: SignatureType,
    ) -> Self {
        Self {
            certs,
            policy,
            now,
            signature_type,
        }
    }

    fn currently_trusted(&self, GoodChecksum { sig, ka, .. }: &GoodChecksum<'_>) -> bool {
        // GoodChecksum already proves the cryptography and binding/liveness
        // at signature creation.  It does NOT prove current key/cert liveness.
        if sig.typ() != self.signature_type
            || sig
                .signature_creation_time()
                .is_none_or(|created| created > self.now)
            || sig.signature_alive(self.now, Duration::ZERO).is_err()
            || self
                .policy
                .signature(sig, HashAlgoSecurity::CollisionResistance)
                .is_err()
        {
            return false;
        }
        // Rebind the exact cryptographically proven key, not a different live
        // key in this certificate.  Sequoia checks both this key's algorithm
        // and the primary key's algorithm when constructing this amalgamation.
        let Ok(key) = ka.with_policy(self.policy, self.now) else {
            return false;
        };
        let cert = key.valid_cert();
        cert.alive().is_ok()
            && matches!(cert.revocation_status(), RevocationStatus::NotAsFarAsWeKnow)
            && key.alive().is_ok()
            && matches!(key.revocation_status(), RevocationStatus::NotAsFarAsWeKnow)
            && key.for_signing()
    }
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self
            .certs
            .iter()
            .filter(|cert| cert.keys().key_handles(ids.iter()).next().is_some())
            .cloned()
            .collect())
    }

    fn check(&mut self, structure: MessageStructure<'_>) -> openpgp::Result<()> {
        let mut good = false;
        let mut total = 0usize;
        for layer in structure.into_iter() {
            match layer {
                MessageLayer::SignatureGroup { results } => {
                    total += results.len();
                    anyhow::ensure!(total <= MAX_SIGNATURES, "signature count limit");
                    // Bad, unknown, expired, and revoked additional signers
                    // cannot defeat another currently-valid trusted signer.
                    for checksum in results.into_iter().flatten() {
                        good = good || self.currently_trusted(&checksum);
                    }
                }
                _ => anyhow::bail!("unsupported signed message structure"),
            }
        }
        anyhow::ensure!(good, "no currently valid trusted signature");
        Ok(())
    }
}
