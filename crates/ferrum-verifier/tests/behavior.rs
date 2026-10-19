#![allow(clippy::expect_used)]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use openpgp::cert::prelude::*;
use openpgp::crypto::KeyPair;
use openpgp::packet::Signature;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::parse::{
    Parse,
    stream::{
        DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
        VerifierBuilder,
    },
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::{
    Serialize,
    stream::{Message, Signer},
};
use openpgp::types::{HashAlgorithm, KeyFlags, ReasonForRevocation, SignatureType};
use openpgp::{Cert, KeyHandle, Packet};
use sequoia_openpgp as openpgp;
use tempfile::{TempDir, tempdir};

const DATA: &[u8] = b"Origin: Ferrum\nSuite: stable\n- dash escaped metadata\n";
const HOUR: Duration = Duration::from_secs(3600);
const LIMIT: u64 = 32 * 1024 * 1024;

fn creation() -> SystemTime {
    SystemTime::now() - HOUR * 4
}

fn certificate(primary_expiry: bool, subkey_expiry: bool) -> Cert {
    CertBuilder::new()
        .set_creation_time(creation())
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .set_validity_period(primary_expiry.then_some(HOUR * 2))
        .add_userid("Ferrum verifier test")
        .add_subkey(
            KeyFlags::empty().set_signing(),
            subkey_expiry.then_some(HOUR * 2),
            None,
        )
        // An unrelated currently-live signing subkey must not rescue the
        // expired exact signing subkey used in an artifact.
        .add_signing_subkey()
        .generate()
        .expect("generate test certificate")
        .0
}

fn keypair(cert: &Cert, subkey: bool) -> KeyPair {
    let key = cert
        .keys()
        .nth(usize::from(subkey))
        .expect("test signing key");
    key.key()
        .clone()
        .parts_into_secret()
        .expect("test secret parts")
        .into_keypair()
        .expect("test keypair")
}

fn signature(cert: &Cert, subkey: bool, time: SystemTime, hash: HashAlgorithm) -> Signature {
    SignatureBuilder::new(SignatureType::Binary)
        .set_signature_creation_time(time)
        .expect("signature timestamp")
        .set_hash_algo(hash)
        .sign_message(&mut keypair(cert, subkey), DATA)
        .expect("sign test data")
}

fn revoke(cert: Cert, subkey: bool, hard: bool) -> Cert {
    let reason = if hard {
        ReasonForRevocation::KeyCompromised
    } else {
        ReasonForRevocation::KeyRetired
    };
    let mut signer = keypair(&cert, false);
    let revocation = if subkey {
        SubkeyRevocationBuilder::new()
            .set_reason_for_revocation(reason, b"test revocation")
            .expect("reason")
            .set_signature_creation_time(creation() + HOUR * 2)
            .expect("revocation time")
            .build(
                &mut signer,
                &cert,
                cert.keys().subkeys().next().expect("subkey").key(),
                None,
            )
            .expect("subkey revocation")
    } else {
        CertRevocationBuilder::new()
            .set_reason_for_revocation(reason, b"test revocation")
            .expect("reason")
            .set_signature_creation_time(creation() + HOUR * 2)
            .expect("revocation time")
            .build(&mut signer, &cert, None)
            .expect("primary revocation")
    };
    cert.insert_packets([Packet::from(revocation)])
        .expect("insert revocation")
        .0
}

struct Artifact {
    directory: TempDir,
}

impl Artifact {
    fn new(certs: &[&Cert], signatures: &[Signature]) -> Self {
        let artifact = Self {
            directory: tempdir().expect("test directory"),
        };
        let mut keyring = File::create(artifact.path("keys")).expect("keyring");
        for cert in certs {
            cert.serialize(&mut keyring).expect("serialize public cert");
        }
        fs::write(artifact.path("data"), DATA).expect("data");
        let mut file = File::create(artifact.path("sig")).expect("signature file");
        for signature in signatures {
            Packet::from(signature.clone())
                .serialize(&mut file)
                .expect("serialize signature");
        }
        artifact
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.directory.path().join(name)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ferrum-verifier"));
        command
            .env_clear()
            .args(["--keyring"])
            .arg(self.path("keys"))
            .args(["--signatures", "1"]);
        command
    }

    fn detached(&self) -> Output {
        let output = self
            .command()
            .arg("--signature-file")
            .arg(self.path("sig"))
            .arg(self.path("data"))
            .output()
            .expect("run verifier");
        assert!(output.stdout.is_empty(), "verification never emits stdout");
        assert!(output.stderr.len() <= 64 * 1024, "bounded diagnostics");
        output
    }

    fn cleartext(&self) -> Output {
        self.command()
            .arg("--cleartext")
            .arg("--output")
            .arg(self.path("output"))
            .arg(self.path("cleartext"))
            .output()
            .expect("run cleartext verifier")
    }
}

// Prove these are valid historical signatures, not rejection tests that pass
// merely because a fixture never had a valid certificate/key binding.
struct Historical(Vec<Cert>);
impl VerificationHelper for Historical {
    fn get_certs(&mut self, _: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.0.clone())
    }
    fn check(&mut self, structure: MessageStructure<'_>) -> openpgp::Result<()> {
        let good = structure.into_iter().any(|layer| match layer {
            MessageLayer::SignatureGroup { results } => results.iter().any(Result::is_ok),
            _ => false,
        });
        anyhow::ensure!(good, "expected genuine historically valid signature");
        Ok(())
    }
}

fn historically_valid(artifact: &Artifact, cert: &Cert) {
    let policy = StandardPolicy::new();
    DetachedVerifierBuilder::from_file(artifact.path("sig"))
        .expect("parse signatures")
        .with_policy(
            &policy,
            Some(SystemTime::now()),
            Historical(vec![cert.clone()]),
        )
        .expect("historical verifier")
        .verify_bytes(DATA)
        .expect("historical validity");
}

fn historically_valid_cleartext(artifact: &Artifact, cert: &Cert) {
    let policy = StandardPolicy::new();
    let mut verifier = VerifierBuilder::from_file(artifact.path("cleartext"))
        .expect("parse cleartext")
        .with_policy(
            &policy,
            Some(SystemTime::now()),
            Historical(vec![cert.clone()]),
        )
        .expect("historical cleartext verifier");
    let mut content = Vec::new();
    verifier
        .read_to_end(&mut content)
        .expect("historical cleartext validity");
    assert_eq!(
        content, DATA,
        "historically authenticated cleartext payload"
    );
}

#[test]
fn current_primary_expiry_rejects_a_valid_historical_signature() {
    let cert = certificate(true, false);
    let signed_at = creation() + HOUR;
    let signature = signature(&cert, true, signed_at, HashAlgorithm::SHA256);
    let artifact = Artifact::new(&[&cert], &[signature]);
    historically_valid(&artifact, &cert);
    assert!(!artifact.detached().status.success());
    write_cleartext(&artifact.path("cleartext"), keypair(&cert, true), signed_at);
    historically_valid_cleartext(&artifact, &cert);
    assert!(!artifact.cleartext().status.success());
    assert!(
        !artifact.path("output").exists(),
        "expired primary leaves no cleartext output"
    );
}

#[test]
fn current_exact_subkey_expiry_cannot_use_another_live_subkey() {
    let cert = certificate(false, true);
    let policy = StandardPolicy::new();
    let now = SystemTime::now();
    let signed_at = creation() + HOUR;
    let expired = cert
        .keys()
        .subkeys()
        .with_policy(&policy, signed_at)
        .for_signing()
        .find(|key| key.binding_signature().key_validity_period() == Some(HOUR * 2))
        .expect("historically valid expiring signing subkey");
    let fingerprint = expired.key().fingerprint();
    assert!(expired.alive().is_ok());
    assert!(
        expired
            .with_policy(&policy, now)
            .expect("current exact binding")
            .alive()
            .is_err()
    );
    assert!(
        cert.keys()
            .subkeys()
            .with_policy(&policy, now)
            .for_signing()
            .alive()
            .any(|key| key.key().fingerprint() != fingerprint),
        "distinct live rescue subkey"
    );
    let mut signer = expired
        .key()
        .clone()
        .parts_into_secret()
        .expect("secret signing key")
        .into_keypair()
        .expect("exact expired signer");
    assert_eq!(signer.public().fingerprint(), fingerprint);
    let signature = SignatureBuilder::new(SignatureType::Binary)
        .set_signature_creation_time(signed_at)
        .expect("historical signature time")
        .set_hash_algo(HashAlgorithm::SHA256)
        .sign_message(&mut signer, DATA)
        .expect("sign with exact expiring key");
    let artifact = Artifact::new(&[&cert], &[signature]);
    historically_valid(&artifact, &cert);
    assert!(!artifact.detached().status.success());
    write_cleartext(&artifact.path("cleartext"), signer, signed_at);
    historically_valid_cleartext(&artifact, &cert);
    assert!(!artifact.cleartext().status.success());
    assert!(
        !artifact.path("output").exists(),
        "expired exact subkey leaves no cleartext output"
    );
}

#[test]
fn soft_primary_and_subkey_revocations_reject_historical_signatures() {
    for subkey in [false, true] {
        let cert = certificate(false, false);
        let signature = signature(&cert, true, creation() + HOUR, HashAlgorithm::SHA256);
        let cert = revoke(cert, subkey, false);
        let artifact = Artifact::new(&[&cert], &[signature]);
        historically_valid(&artifact, &cert);
        assert!(
            !artifact.detached().status.success(),
            "revoked subkey: {subkey}"
        );
    }
}

#[test]
fn hard_primary_and_subkey_revocations_reject() {
    for subkey in [false, true] {
        let cert = certificate(false, false);
        let signature = signature(&cert, true, creation() + HOUR, HashAlgorithm::SHA256);
        let cert = revoke(cert, subkey, true);
        assert!(
            !Artifact::new(&[&cert], &[signature])
                .detached()
                .status
                .success()
        );
    }
}

#[test]
fn good_signer_survives_unknown_expired_and_revoked_additional_signers() {
    let good = certificate(false, false);
    let unknown = certificate(false, false);
    let expired = certificate(true, false);
    let revoked = revoke(certificate(false, false), true, false);
    let sign_time = creation() + HOUR;
    let good_signature = signature(&good, true, sign_time, HashAlgorithm::SHA256);
    for extra in [&unknown, &expired, &revoked] {
        let signatures = [
            signature(extra, true, sign_time, HashAlgorithm::SHA256),
            good_signature.clone(),
        ];
        let certs = if extra.fingerprint() == unknown.fingerprint() {
            vec![&good]
        } else {
            vec![&good, extra]
        };
        assert!(
            Artifact::new(&certs, &signatures)
                .detached()
                .status
                .success()
        );
        let reversed = [signatures[1].clone(), signatures[0].clone()];
        assert!(Artifact::new(&certs, &reversed).detached().status.success());
    }
}

#[test]
fn duplicate_certificate_cannot_strip_current_revocation() {
    let original = certificate(false, false);
    let signed = signature(&original, true, creation() + HOUR, HashAlgorithm::SHA256);
    let revoked = revoke(original.clone(), false, false);
    for certs in [[&original, &revoked], [&revoked, &original]] {
        assert!(
            !Artifact::new(&certs, std::slice::from_ref(&signed))
                .detached()
                .status
                .success()
        );
    }
}

#[test]
fn weak_hash_and_future_or_expired_signatures_reject() {
    let cert = CertBuilder::new()
        .set_creation_time(creation())
        .set_cipher_suite(CipherSuite::RSA2k)
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .generate()
        .expect("RSA test cert")
        .0;
    let weak = signature(&cert, false, creation() + HOUR, HashAlgorithm::SHA1);
    assert!(
        !Artifact::new(&[&cert], std::slice::from_ref(&weak))
            .detached()
            .status
            .success()
    );
    let strong = signature(&cert, false, creation() + HOUR, HashAlgorithm::SHA256);
    assert!(
        Artifact::new(&[&cert], &[weak, strong])
            .detached()
            .status
            .success()
    );
    let future = signature(
        &cert,
        false,
        SystemTime::now() + HOUR,
        HashAlgorithm::SHA256,
    );
    assert!(
        !Artifact::new(&[&cert], &[future])
            .detached()
            .status
            .success()
    );
    let expired = SignatureBuilder::new(SignatureType::Binary)
        .set_signature_creation_time(creation() + HOUR)
        .expect("timestamp")
        .set_signature_validity_period(HOUR)
        .expect("validity")
        .sign_message(&mut keypair(&cert, false), DATA)
        .expect("expired signature");
    assert!(
        !Artifact::new(&[&cert], &[expired])
            .detached()
            .status
            .success()
    );
}

#[test]
fn detached_signatures_authenticate_exact_bytes() {
    let cert = certificate(false, false);
    let signature = signature(&cert, true, creation() + HOUR, HashAlgorithm::SHA256);
    let artifact = Artifact::new(&[&cert], &[signature]);
    assert!(artifact.detached().status.success());
    for changed in [
        b"Origin: Attacker\n".as_slice(),
        b"Origin: Ferrum\r\nSuite: stable\r\n- dash escaped metadata\r\n",
    ] {
        fs::write(artifact.path("data"), changed).expect("tampered data");
        assert!(!artifact.detached().status.success());
    }
}

#[test]
fn detached_canonical_text_signatures_cannot_authorize_different_bytes() {
    let cert = certificate(false, false);
    let signed = SignatureBuilder::new(SignatureType::Text)
        .set_signature_creation_time(creation() + HOUR)
        .expect("timestamp")
        .sign_message(&mut keypair(&cert, true), DATA)
        .expect("text signature");
    let artifact = Artifact::new(&[&cert], &[signed]);
    assert!(!artifact.detached().status.success());
}

fn write_cleartext(path: &Path, keypair: KeyPair, signed_at: SystemTime) {
    let mut file = File::create(path).expect("cleartext file");
    let message = Message::new(&mut file);
    let mut signer = Signer::new(message, keypair)
        .expect("signer")
        .cleartext()
        .creation_time(signed_at)
        .build()
        .expect("cleartext signer");
    signer.write_all(DATA).expect("cleartext data");
    signer.finalize().expect("finalize cleartext");
}

#[test]
fn cleartext_authenticates_and_extracts_dash_escaped_release_content() {
    let cert = certificate(false, false);
    let artifact = Artifact::new(&[&cert], &[]);
    write_cleartext(
        &artifact.path("cleartext"),
        keypair(&cert, true),
        creation() + HOUR,
    );
    let output = artifact.cleartext();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(output.stdout.is_empty());
    // Sequoia's cleartext signer adds its framing line ending. The verified
    // payload must round-trip the original bytes, including dash unescaping.
    assert_eq!(
        fs::read(artifact.path("output")).expect("verified output"),
        DATA
    );
    fs::remove_file(artifact.path("output")).expect("remove output");
    let original = fs::read_to_string(artifact.path("cleartext")).expect("read cleartext");
    fs::write(
        artifact.path("cleartext"),
        original.replace("Origin: Ferrum", "Origin: Forged"),
    )
    .expect("tamper cleartext");
    assert!(!artifact.cleartext().status.success());
    assert!(!artifact.path("output").exists());
}

#[test]
fn unsupported_modes_and_overwrites_are_rejected() {
    let cert = certificate(false, false);
    let artifact = Artifact::new(&[&cert], &[]);
    write_cleartext(
        &artifact.path("cleartext"),
        keypair(&cert, true),
        creation() + HOUR,
    );
    fs::write(artifact.path("output"), b"preserve this file").expect("existing output");
    assert!(!artifact.cleartext().status.success());
    assert_eq!(
        fs::read(artifact.path("output")).expect("preserved output"),
        b"preserve this file"
    );
    for option in ["--time", "--policy-as-of", "--message", "--overwrite"] {
        assert!(
            !artifact
                .command()
                .arg(option)
                .arg("now")
                .arg(artifact.path("data"))
                .output()
                .expect("unsupported option")
                .status
                .success()
        );
    }
    assert!(
        !artifact
            .command()
            .args(["--signatures", "2", "--signature-file"])
            .arg(artifact.path("sig"))
            .arg(artifact.path("data"))
            .output()
            .expect("threshold")
            .status
            .success()
    );
    assert!(
        !artifact
            .command()
            .arg("--cleartext")
            .arg(artifact.path("cleartext"))
            .output()
            .expect("missing output")
            .status
            .success()
    );
    fs::remove_file(artifact.path("output")).expect("remove preserved file");
    fs::write(artifact.path("cleartext"), b"not cleartext OpenPGP").expect("wrong mode");
    assert!(!artifact.cleartext().status.success());
    assert!(!artifact.path("output").exists());
}

#[test]
fn oversized_inputs_and_nonregular_files_reject() {
    let cert = certificate(false, false);
    let signed = signature(&cert, true, creation() + HOUR, HashAlgorithm::SHA256);
    for name in ["keys", "sig", "data"] {
        let artifact = Artifact::new(&[&cert], std::slice::from_ref(&signed));
        File::options()
            .write(true)
            .open(artifact.path(name))
            .expect("open oversized")
            .set_len(LIMIT + 1)
            .expect("oversized input");
        assert!(!artifact.detached().status.success(), "oversized {name}");
    }
    let artifact = Artifact::new(&[&cert], &[signed]);
    fs::remove_file(artifact.path("data")).expect("remove data");
    fs::create_dir(artifact.path("data")).expect("directory input");
    assert!(!artifact.detached().status.success());
}

#[cfg(unix)]
#[test]
fn distribution_keyring_symlinks_resolve_only_to_regular_bounded_files() {
    use std::os::unix::fs::symlink;
    let cert = certificate(false, false);
    let signed = signature(&cert, true, creation() + HOUR, HashAlgorithm::SHA256);
    let artifact = Artifact::new(&[&cert], &[signed]);
    fs::rename(artifact.path("keys"), artifact.path("archive-keyring.pgp"))
        .expect("public keyring");
    symlink("archive-keyring.pgp", artifact.path("keys")).expect("distribution keyring alias");
    assert!(artifact.detached().status.success());
    File::options()
        .write(true)
        .open(artifact.path("archive-keyring.pgp"))
        .expect("keyring target")
        .set_len(LIMIT + 1)
        .expect("oversized target");
    assert!(!artifact.detached().status.success());
    fs::remove_file(artifact.path("archive-keyring.pgp")).expect("remove keyring target");
    fs::create_dir(artifact.path("archive-keyring.pgp")).expect("nonregular target");
    assert!(!artifact.detached().status.success());
}

#[test]
fn empty_secret_and_excessive_keyrings_reject() {
    let cert = certificate(false, false);
    let signed = signature(&cert, true, creation() + HOUR, HashAlgorithm::SHA256);
    let artifact = Artifact::new(&[&cert], &[signed]);
    fs::write(artifact.path("keys"), []).expect("empty keyring");
    assert!(!artifact.detached().status.success());
    let mut file = File::create(artifact.path("keys")).expect("secret keyring");
    cert.as_tsk()
        .serialize(&mut file)
        .expect("serialize test secret material");
    drop(file);
    assert!(!artifact.detached().status.success());
    let mut file = File::create(artifact.path("keys")).expect("excessive keyring");
    for _ in 0..129 {
        cert.serialize(&mut file).expect("serialize repeated cert");
    }
    drop(file);
    assert!(!artifact.detached().status.success());
}

#[test]
fn excessive_signature_count_rejects_even_a_trusted_signer() {
    let cert = certificate(false, false);
    let signed = signature(&cert, true, creation() + HOUR, HashAlgorithm::SHA256);
    let artifact = Artifact::new(&[&cert], &vec![signed; 257]);
    assert!(!artifact.detached().status.success());
}

#[test]
fn exact_input_size_limit_is_supported() {
    let cert = certificate(false, false);
    let artifact = Artifact::new(&[&cert], &[]);
    let mut data = File::create(artifact.path("data")).expect("boundary data");
    let mut signature_file = File::create(artifact.path("sig")).expect("boundary signature");
    let mut signer = Signer::new(Message::new(&mut signature_file), keypair(&cert, true))
        .expect("boundary signer")
        .detached()
        .creation_time(creation() + HOUR)
        .build()
        .expect("build boundary signer");
    let chunk = [b'x'; 16 * 1024];
    for _ in 0..LIMIT / chunk.len() as u64 {
        data.write_all(&chunk).expect("boundary write");
        signer.write_all(&chunk).expect("boundary sign");
    }
    signer.finalize().expect("finalize boundary signature");
    drop(data);
    assert!(artifact.detached().status.success());
}

#[test]
fn version_is_the_exact_pinned_cli_identity() {
    let output = Command::new(env!("CARGO_BIN_EXE_ferrum-verifier"))
        .arg("--version")
        .output()
        .expect("verifier version");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ferrum-verifier 0.1.0\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn user_environment_cannot_replace_system_policy() {
    let cert = certificate(false, false);
    let signed = signature(&cert, true, creation() + HOUR, HashAlgorithm::SHA256);
    let artifact = Artifact::new(&[&cert], &[signed]);
    let output = artifact
        .command()
        .env("SEQUOIA_CRYPTO_POLICY", artifact.path("nonexistent-policy"))
        .arg("--signature-file")
        .arg(artifact.path("sig"))
        .arg(artifact.path("data"))
        .output()
        .expect("environment-independent policy");
    assert!(output.status.success());
}
