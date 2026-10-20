//! Local-only B09 qualification, using ferrum-verifier and the production publisher/SDK adapter.
//!
//! Linux prerequisites: ferrum-verifier 0.2.0 on PATH, /usr/bin/prlimit, GnuPG, dpkg-deb, gzip,
//! OpenSSL, GNU coreutils, and enough local disk for the durable SQLite catalog.
//! Includes exact trailing-LF Release publication, lost-local-floor recovery,
//! and authenticated derived HTTP Range/corruption/deadline/retention regressions.
//! From the repository root:
//! Build `cargo build --locked -p ferrum-verifier` and add `target/debug` to PATH.
//! `B09=1 bash fixture/generate.sh` only if fixture/public/b09 has not been generated.
//! Generate the PDiff extension as described in fixture/README.md before the full ignored suite.
//! `cargo test --locked -p ferrum --features test-harness --test publication -- --ignored --test-threads=1`
//! No live provider credentials or network access to a distribution is used. The
//! scripted transport implements HTTP storage only: signatures, spool commits,
//! proof verification, readback, checkpoint CAS and activation remain production code.
#![cfg(feature = "test-harness")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode};
use ferrum::config::{Config, Limits};
use ferrum::fetch::{FillRegistry, UpstreamClient};
use ferrum::health::Metrics;
use ferrum::server::{self, AppState};
use ferrum::sync::scheduler::FairRounds;
use ferrum::sync::{ActiveView, Catalog, DurableSynchronizer, Resolution, SyncOutcome};
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use ferrum_apt::release::{ParseLimits, Release, UnixTime};
use ferrum_apt::signature::SignatureVerifier;
use ferrum_fixture_origin::{Fault, FaultKind, OriginConfig, RunningOrigin};
use ferrum_storage::Spool;
use ferrum_storage::budget::{BudgetLedger, BudgetLimits};
use ferrum_storage::checkpoint::{CheckpointError, CheckpointPublisher, RecoveryProfile, SuiteKey};
use ferrum_storage::disk::{DurableSpoolConfig, ReservationClass};
use ferrum_storage::recovery::{
    BootstrapAudit, DerivedArtifact, GenerationManifest, ManifestArtifact, OriginVerifier,
    PublicationVerification, TrustPolicy,
};
use ferrum_storage::s3::testing::StatefulRemote;
use ferrum_storage::s3::{ControlCondition, OperationIdentity, S3Store};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[path = "publication/prewarming.rs"]
mod prewarming;

#[path = "publication/retirement.rs"]
mod retirement;

#[cfg(unix)]
#[path = "publication/pdiff.rs"]
mod pdiff;

#[tokio::test]
async fn all_configured_distribution_profiles_reach_the_bounded_catalog() {
    let directory = tempfile::tempdir().expect("inventory state");
    let root = directory.path();
    let config = Config::parse(
        r#"mode = "private-durable"
[listen]
public = "127.0.0.1:18080"
admin = "127.0.0.1:19090"
[durable]
state_dir = "state"
suites = ["all"]
[durable.provider]
region = "us-east-1"
bucket = "ferrum"
credentials_file = "unused.env"
[durable.keyrings]
debian = "debian.gpg"
ubuntu = "ubuntu.gpg"
[durable.budget]
mode = "existing"
[verifier]
"#,
        root,
    )
    .expect("all inventory configuration");
    let suites = config.suites().expect("all suite identities");
    assert_eq!(suites.len(), 106);
    let mut disk = DurableSpoolConfig::new(root.join("state"));
    disk.free_space_floor = 0;
    let spool = Spool::open_durable(disk).expect("disposable durable state");
    let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default())
        .expect("explicit disposable test allowance");
    let (store, remote) =
        S3Store::stateful_production(config.durable().expect("durable").store_config(), ledger)
            .expect("local-only scripted store");
    let publisher = Arc::new(
        CheckpointPublisher::new(spool, Arc::new(store), RecoveryProfile::SharedNonisolated)
            .expect("checkpoint publisher"),
    );
    let keys: Vec<_> = suites.into_iter().map(|suite| suite.key).collect();
    let catalog = Catalog::configured(keys.clone(), publisher.clone()).expect("full inventory");
    assert_eq!(catalog.keys(), keys);
    let too_many = vec![keys[0].clone(); ferrum_storage::checkpoint::MAX_SUITES + 1];
    assert!(Catalog::configured(too_many, publisher).is_err());
    assert!(remote.requests().expect("local request log").is_empty());
}

const PREREQUISITES: &str =
    "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, generated fixture/public/b09";
const INDEX: &str = "main/binary-amd64/Packages.gz";
const IDENTITIES: [(&str, &str); 6] = [
    ("debian", "trixie"),
    ("debian", "trixie-updates"),
    ("debian-security", "trixie-security"),
    ("ubuntu", "noble"),
    ("ubuntu", "noble-updates"),
    ("ubuntu-security", "noble-security"),
];

fn fixture() -> PathBuf {
    let root = std::env::var_os("FERRUM_FIXTURE_PUBLIC")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixture/public"))
        .canonicalize()
        .expect(PREREQUISITES);
    assert!(root.join("b09/g100").is_dir(), "{PREREQUISITES}");
    root
}

fn keys() -> Vec<SuiteKey> {
    IDENTITIES
        .iter()
        .map(|(repository, suite)| SuiteKey::new(repository, suite).expect("fixed suite identity"))
        .collect()
}

struct Harness {
    _directory: tempfile::TempDir,
    fixture: PathBuf,
    origin: RunningOrigin,
    verifier: SignatureVerifier,
    config: Arc<Config>,
    spool: Spool,
    store: Arc<S3Store>,
    publisher: Arc<CheckpointPublisher>,
    catalog: Arc<Catalog>,
    synchronizer: DurableSynchronizer,
    remote: StatefulRemote,
    cancel: CancellationToken,
}

impl Harness {
    async fn new() -> Self {
        Self::with_seed(true).await
    }

    // A fresh disposable catalog receives an explicit test allowance, never a
    // reset of an existing ledger. Without seed there is no local or remote floor.
    async fn with_seed(seed: bool) -> Self {
        let fixture = fixture();
        let directory = tempfile::tempdir().expect("qualification directory");
        let root = directory.path();
        let origin = RunningOrigin::bind(OriginConfig {
            root: fixture.join("b09/g000"),
            listen: "127.0.0.1:0".parse().expect("loopback"),
            control: "127.0.0.1:0".parse().expect("loopback"),
            prefix: "/fixture/".into(),
        })
        .await
        .expect("local fixture origin");
        let base = format!("http://{}/fixture/", origin.data_addr());
        let keyring = fixture.join("b09/policy.gpg");
        let text = format!(
            "mode = \"private-durable\"\n[listen]\npublic = \"127.0.0.1:0\"\nadmin = \"127.0.0.1:0\"\n\
             [durable]\nstate_dir = \"{}\"\n\
             [durable.provider]\nregion = \"us-east-1\"\n\
             bucket = \"ferrum\"\ncredentials_file = \"{}\"\n\
             [durable.keyrings]\ndebian = \"{}\"\nubuntu = \"{}\"\n\
             [durable.budget]\nmode = \"existing\"\n[verifier]\n[limits]\n",
            root.join("state").display(),
            root.join("unused-provider.env").display(),
            keyring.display(),
            keyring.display(),
        );
        let mut config = Config::parse(&text, root).expect("durable configuration");
        config
            .set_test_suite_origins(base.parse().expect("base URL"), keyring)
            .expect("explicit loopback distribution seam");
        config.limits.sync_interval = Duration::from_millis(50);
        let mut disk = DurableSpoolConfig::new(root.join("state"));
        disk.free_space_floor = 0;
        disk.spool.managed_ceiling = 1024 * 1024 * 1024;
        disk.spool.max_object_size = 32 * 1024 * 1024;
        // Two bulk proofs and two observation slots retain multiple bounded
        // 32 MiB reservations concurrently, even for these small signed fixtures.
        disk.temporary_ceiling = 512 * 1024 * 1024;
        disk.metadata_temporary_reserve = 256 * 1024 * 1024;
        // Metadata admission charges installed bytes and outstanding reservations.
        disk.metadata_ceiling = 512 * 1024 * 1024;
        disk.catalog_ceiling = 128 * 1024 * 1024;
        disk.eviction_high_watermark = 900 * 1024 * 1024;
        disk.eviction_low_watermark = 800 * 1024 * 1024;
        disk.max_entries = 10_000;
        let spool = Spool::open_durable(disk).expect("real durable spool");
        let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default())
            .expect("explicit test allowance");
        let (store, remote) =
            S3Store::stateful_production(config.durable().expect("durable").store_config(), ledger)
                .expect("production SDK with explicit local scripted transport");
        let store = Arc::new(store);
        let publisher = Arc::new(
            CheckpointPublisher::new(
                spool.clone(),
                store.clone(),
                RecoveryProfile::SharedNonisolated,
            )
            .expect("publisher"),
        );
        let catalog = Arc::new(Catalog::configured(keys(), publisher.clone()).expect("six slots"));
        let verifier = SignatureVerifier::new("ferrum-verifier".into(), Duration::from_secs(30))
            .await
            .expect(PREREQUISITES);
        let cancel = CancellationToken::new();
        catalog.set_test_clock_synchronized(true);
        // Bootstrap is an explicit audited reset, never a fake pre-existing floor.
        let origin_verifier = OriginVerifier::loopback_for_tests(&base).expect("loopback verifier");
        for suite in config
            .suites()
            .expect("suite configurations")
            .into_iter()
            .filter(|_| seed)
        {
            let manifest = seed_manifest(
                &spool,
                &fixture.join("b09/g000"),
                &suite.key,
                &suite.policy,
                &verifier,
            )
            .await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
            publisher
                .persist_generation(&manifest, deadline, &cancel)
                .await
                .expect("upload and read back complete initial signed closure");
            let now = UnixTime::now().as_secs();
            let audit = BootstrapAudit::acknowledge_reset(
                "local B09 qualification",
                "new disposable test catalog; no historical recovery claimed",
                now,
                "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED",
            )
            .expect("bootstrap audit");
            publisher
                .bootstrap_current(
                    &manifest,
                    &PublicationVerification {
                        policy: &suite.policy,
                        verifier: &verifier,
                        origin: &origin_verifier,
                    },
                    audit,
                    deadline,
                    &cancel,
                )
                .await
                .expect("real signature, origin, durable closure and CAS bootstrap");
        }
        let config = Arc::new(config);
        let mut synchronizer = DurableSynchronizer::new(
            config.clone(),
            verifier.clone(),
            spool.clone(),
            publisher.clone(),
            catalog.clone(),
            Arc::new(Metrics::default()),
        )
        .await
        .expect("durable synchronizer");
        for key in keys().into_iter().filter(|_| seed) {
            let original_manifest = publisher
                .state(&key)
                .expect("seed checkpoint")
                .floor
                .expect("seed trusted floor")
                .manifest_sha256;
            synchronizer
                .synchronize_once(&key, &cancel)
                .await
                .expect("recover trusted seed");
            assert!(catalog.load_suite(&key).is_some());
            assert_eq!(
                publisher
                    .state(&key)
                    .expect("recovered checkpoint")
                    .floor
                    .expect("recovered trusted floor")
                    .manifest_sha256,
                original_manifest,
                "same-generation recovery must preserve the original immutable manifest bytes"
            );
        }
        Self {
            _directory: directory,
            fixture,
            origin,
            verifier,
            publisher,
            catalog,
            synchronizer,
            remote,
            cancel,
            config,
            spool,
            store,
        }
    }

    async fn select(&self, generation: usize) {
        self.origin
            .origin()
            .set_root(self.fixture.join(format!("b09/g{generation:03}")))
            .await
            .expect("select immutable signed tree");
    }

    fn view(&self, key: &SuiteKey) -> Arc<ActiveView> {
        self.catalog.load_suite(key).expect("active suite")
    }

    async fn publish(&mut self, key: &SuiteKey) {
        assert_eq!(
            self.synchronizer
                .synchronize_once(key, &self.cancel)
                .await
                .expect("complete authenticated publication"),
            SyncOutcome::Published
        );
        let state = self.publisher.state(key).expect("persisted state");
        assert!(state.pending.is_none() && !state.blocked);
        assert_eq!(
            state.active.as_ref().expect("active intent"),
            state.floor.as_ref().expect("accepted off-VM floor")
        );
        let remote_key = format!(
            "linux-checkpoints/v1/checkpoints/{}/{}.json",
            key.repository(),
            key.suite()
        );
        let remote_bytes = self
            .remote
            .bytes(&remote_key)
            .expect("scripted provider state")
            .expect("checkpoint must actually have been stored by SDK PUT");
        let remote_intent: ferrum_storage::checkpoint::PublicationIntent =
            serde_json::from_slice(&remote_bytes).expect("actual checkpoint wire bytes");
        assert_eq!(
            &remote_intent,
            state.active.as_ref().expect("local active intent")
        );
        assert_eq!(
            self.view(key).generation_id.to_hex(),
            state.active.expect("active").generation_id
        );
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        self.origin.shutdown().await;
    }
}

async fn seed_manifest(
    spool: &Spool,
    root: &Path,
    key: &SuiteKey,
    policy: &TrustPolicy,
    verifier: &SignatureVerifier,
) -> GenerationManifest {
    let directory = root.join(key.repository()).join("dists").join(key.suite());
    let scratch = tempfile::tempdir().expect("private authentication output directory");
    let authenticated = verifier
        .verify_cleartext(
            policy.keyring(),
            &directory.join("InRelease"),
            scratch.path(),
            32 * 1024 * 1024,
        )
        .await
        .expect("authenticate seed InRelease");
    let release = Release::parse(&authenticated, &ParseLimits::default())
        .expect("parse exact helper-authenticated seed payload");
    let (targets, _) = ferrum_apt::selection::select(
        &release,
        policy.components(),
        matches!(policy, TrustPolicy::Ubuntu { .. }),
    )
    .expect("shared selected closure");
    let mut paths = vec![
        "InRelease".to_owned(),
        "Release".to_owned(),
        "Release.gpg".to_owned(),
    ];
    let mut derived = Vec::new();
    for target in targets {
        if let Some(source_path) = target.derived_from {
            derived.push(DerivedArtifact {
                path: target.path,
                source_path,
            });
        } else if target.pinned {
            paths.push(target.path);
        }
    }
    let mut artifacts = Vec::new();
    for path in paths {
        let bytes = std::fs::read(directory.join(&path)).expect("tiny metadata fixture");
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(&bytes),
            size: bytes.len() as u64,
        };
        if spool.lookup(identity).is_none() {
            let reservation = spool
                .reserve_class(identity.size, ReservationClass::Metadata)
                .expect("metadata admission");
            let mut writer = spool
                .begin_write(reservation, identity)
                .await
                .expect("spool writer");
            writer
                .write(bytes.into())
                .await
                .expect("write signed metadata");
            writer
                .commit()
                .await
                .expect("verify and fsync initial closure");
        }
        artifacts.push(ManifestArtifact {
            path,
            sha256: identity.sha256.to_hex(),
            size: identity.size,
        });
    }
    let generation_id = artifacts
        .iter()
        .find(|artifact| artifact.path == "InRelease")
        .expect("InRelease artifact")
        .sha256
        .clone();
    // Deliberately differ from live candidate assembly order: signed generation
    // identity must never authorize rewriting its existing immutable manifest.
    artifacts.reverse();
    GenerationManifest {
        schema_version: 1,
        repository: key.repository().into(),
        suite: key.suite().into(),
        generation_id,
        release_content_sha256: release.content_sha256().to_hex(),
        release_date: release.date.as_secs(),
        artifacts,
        derived,
    }
}

async fn representation(view: &ActiveView, relative: &str) -> Vec<u8> {
    match view.resolve(&format!("dists/{}/{relative}", view.suite)) {
        Resolution::Metadata { object, .. } | Resolution::ByHash(object) => object
            .read_bounded(32 * 1024 * 1024)
            .await
            .expect("leased exact metadata bytes"),
        other => panic!("expected pinned representation, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn publication_context_does_not_age_confirmation_before_durable_readback() {
    let mut harness = Harness::new().await;
    let suite = harness.config.suites().expect("suites").remove(0);
    harness.select(1).await;
    let manifest = seed_manifest(
        &harness.spool,
        &harness.fixture.join("b09/g001"),
        &suite.key,
        &suite.policy,
        &harness.verifier,
    )
    .await;
    let origin = OriginVerifier::loopback_for_tests(&format!(
        "http://{}/fixture/",
        harness.origin.data_addr()
    ))
    .expect("loopback origin");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    harness
        .publisher
        .persist_generation(&manifest, deadline, &harness.cancel)
        .await
        .expect("durable successor");
    let started = UnixTime::now().as_secs();
    let verification = PublicationVerification {
        policy: &suite.policy,
        verifier: &harness.verifier,
        origin: &origin,
    };
    // An independent observation commits after context creation but before
    // publication readback/reconfirmation. Its authenticated time must survive.
    tokio::time::timeout(Duration::from_secs(3), async {
        while UnixTime::now().as_secs() <= started {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cross the catalog's one-second timestamp boundary");
    harness
        .synchronizer
        .observe_once(&suite.key, &harness.cancel)
        .await
        .expect("independent authenticated successor observation");
    let observed = harness.publisher.state(&suite.key).expect("observed state");
    assert!(observed.observed_at.expect("observation time") > started);
    let generation = harness
        .publisher
        .verify_durable_generation(&manifest, &verification, deadline, &harness.cancel)
        .await
        .expect("later real origin reconfirmation must not carry context-creation time");
    assert!(generation.confirmed_at() >= observed.observed_at.expect("observation time"));
    let intent = harness
        .publisher
        .publish(&generation, deadline, &harness.cancel)
        .await
        .expect("durable intent");
    harness
        .publisher
        .activate(&generation, &intent)
        .expect("activate freshly confirmed successor");
    let active = harness.publisher.state(&suite.key).expect("active state");
    assert_eq!(active.active.as_ref(), Some(&intent));
    assert_eq!(active.floor.as_ref(), Some(&intent));
    assert!(active.pending.is_none());
    assert_eq!(active.confirmed_at, Some(generation.confirmed_at()));
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn one_hundred_actual_transitions_with_ten_thousand_held_release_sequences() {
    let mut harness = Harness::new().await;
    let key = keys().remove(0);
    let mut transitions = 0usize;
    let mut sequences = 0usize;
    let initial_sequence = harness
        .publisher
        .state(&key)
        .expect("state")
        .active
        .expect("active")
        .sequence;
    for generation in 1..=100 {
        let held = harness.view(&key);
        let held_releases = futures_util::future::join_all((0..100).map(|_| {
            let held = &held;
            async move { representation(held, "InRelease").await }
        }))
        .await;
        for bytes in &held_releases {
            assert_eq!(Sha256Digest::of(bytes), held.generation_id);
        }
        let held_index = representation(&held, INDEX).await;
        let held_hash = Sha256Digest::of(&held_index);
        harness.select(generation).await;
        harness.publish(&key).await;
        let active = harness.view(&key);
        assert_ne!(active.generation_id, held.generation_id);
        assert!(active.release_date > held.release_date);
        transitions += 1;
        // Every client starts with A's authenticated InRelease, spans a genuine
        // committed B transition, then resolves A's by-hash via retained state.
        let clients = futures_util::future::join_all((0..100).map(|_| {
            let publisher = &harness.publisher;
            let key = &key;
            async move {
                let descriptor = publisher
                    .lookup_by_hash(
                        key,
                        "main/binary-amd64",
                        ferrum_storage::checkpoint::MetadataHash::Sha256(held_hash),
                    )
                    .await
                    .expect("production indexed retained authority")
                    .expect("held signed by-hash remains authorized after transition");
                assert!(
                    !descriptor.is_derived(),
                    "compressed representation must remain pinned"
                );
                assert_eq!(descriptor.identity().sha256, held_hash);
                descriptor
                    .source()
                    .read_bounded(32 * 1024 * 1024)
                    .await
                    .expect("leased retained representation")
            }
        }))
        .await;
        for (held_release, bytes) in held_releases.into_iter().zip(clients) {
            assert_eq!(Sha256Digest::of(&held_release), held.generation_id);
            assert_eq!(
                bytes, held_index,
                "generation {generation}: retained by-hash mismatch"
            );
            sequences += 1;
        }
        // Canonical paths are intentionally not session-pinned: this mismatch
        // must be detectable by APT's authenticated hash, not hidden by the test.
        assert_ne!(
            Sha256Digest::of(&representation(&active, INDEX).await),
            Sha256Digest::of(&held_index)
        );
    }
    assert!(
        transitions >= 100,
        "a publisher that never advances cannot qualify"
    );
    assert!(
        sequences >= 10_000,
        "fixed-view reads are not update sequences"
    );
    let final_sequence = harness
        .publisher
        .state(&key)
        .expect("state")
        .active
        .expect("active")
        .sequence;
    assert_eq!(final_sequence - initial_sequence, transitions as u64);
    assert!(
        harness
            .publisher
            .retained_manifests(&key)
            .expect("retention")
            .len()
            >= 100
    );
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn incomplete_successor_and_its_exact_saved_304_never_renew_active_lease() {
    let mut harness = Harness::new().await;
    let key = keys().remove(0);
    let old_confirmation = harness.publisher.state(&key).expect("state").confirmed_at;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    harness
        .synchronizer
        .observe_once(&key, &harness.cancel)
        .await
        .expect("exact active 304");
    assert!(
        harness
            .publisher
            .state(&key)
            .expect("active 304")
            .confirmed_at
            > old_confirmation
    );
    let active = harness.view(&key);
    let before = harness.publisher.state(&key).expect("state");
    harness.select(1).await;
    let path = "debian/dists/trixie/Release.gpg";
    harness
        .origin
        .origin()
        .faults()
        .set(
            path.into(),
            Fault {
                kind: FaultKind::Delete,
                remaining: None,
            },
        )
        .expect("incomplete detached pair");
    assert!(
        harness
            .synchronizer
            .synchronize_once(&key, &harness.cancel)
            .await
            .is_err()
    );
    let successor = harness.publisher.state(&key).expect("successor state");
    assert!(successor.successor_seen_at.is_some());
    assert_eq!(successor.active, before.active);
    assert_eq!(successor.confirmed_at, before.confirmed_at);
    assert_eq!(harness.view(&key).generation_id, active.generation_id);
    // A second observation carries the exact B validator. The local origin
    // must actually answer 304; an ordinary second 200 does not prove this gate.
    harness.origin.origin().log().clear();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    harness
        .synchronizer
        .observe_once(&key, &harness.cancel)
        .await
        .expect("saved successor revalidation");
    assert!(
        harness
            .origin
            .origin()
            .log()
            .snapshot()
            .iter()
            .any(|entry| entry.path == "debian/dists/trixie/InRelease" && entry.status == 304)
    );
    let after = harness.publisher.state(&key).expect("304 state");
    assert_eq!(after.confirmed_at, before.confirmed_at);
    assert_eq!(after.active, before.active);
    assert_eq!(after.successor_seen_at, successor.successor_seen_at);
    assert!(after.observed_at > successor.observed_at);
    assert!(!active.is_fresh(
        active.confirmed_at + Duration::from_secs(86_400),
        UnixTime::now()
    ));
    // The same production freshness predicate gates both mutable 200 and 304.
    assert!(active.is_fresh(Instant::now(), UnixTime::now()));
    harness.origin.origin().faults().remove(path);
    harness.publish(&key).await;
    assert!(
        harness
            .publisher
            .state(&key)
            .expect("published")
            .successor_seen_at
            .is_none()
    );
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn signature_key_policy_and_detached_pair_races_use_real_verifier() {
    let mut harness = Harness::new().await;
    let key = keys().remove(0);
    let before = harness.publisher.state(&key).expect("state");
    for variant in ["unknown-key", "expired-key", "revoked-key", "weak-key"] {
        harness
            .origin
            .origin()
            .set_root(harness.fixture.join("b09").join(variant))
            .await
            .expect("policy fixture");
        let error = match harness
            .synchronizer
            .synchronize_once(&key, &harness.cancel)
            .await
        {
            Ok(outcome) => {
                panic!("{variant}: verifier policy must reject signed candidate, got {outcome:?}")
            }
            Err(error) => error,
        };
        assert!(error.is_rejection(), "{variant}: {error}");
        let after = harness.publisher.state(&key).expect("state");
        assert_eq!(after.active, before.active, "{variant}");
        assert_eq!(after.confirmed_at, before.confirmed_at, "{variant}");
    }
    harness.select(100).await;
    harness.publish(&key).await;
    let original_signature = harness.view(&key);
    let original_sequence = harness
        .publisher
        .state(&key)
        .expect("original signature state")
        .active
        .expect("original active intent")
        .sequence;
    harness
        .origin
        .origin()
        .set_root(harness.fixture.join("b09/mixed-signatures"))
        .await
        .expect("mixed trusted plus unknown signatures");
    harness.publish(&key).await;
    let accepted = harness
        .publisher
        .state(&key)
        .expect("mixed-signature trust threshold accepted");
    let rotated_signature = harness.view(&key);
    assert_eq!(
        rotated_signature.content_sha256,
        original_signature.content_sha256
    );
    assert_ne!(
        rotated_signature.generation_id,
        original_signature.generation_id
    );
    assert_eq!(
        accepted
            .active
            .as_ref()
            .expect("signature replacement intent")
            .sequence,
        original_sequence + 1,
        "signature-only replacement requires a new durable checkpoint"
    );
    harness
        .origin
        .origin()
        .set_root(harness.fixture.join("b09/equal-date-conflict"))
        .await
        .expect("genuinely signed conflicting content at equal Date");
    assert!(
        harness
            .synchronizer
            .synchronize_once(&key, &harness.cancel)
            .await
            .is_err()
    );
    let conflict = harness
        .publisher
        .state(&key)
        .expect("equal-date conflict state");
    assert_eq!(conflict.active, accepted.active);
    assert_eq!(conflict.confirmed_at, accepted.confirmed_at);
    // Separate Release and Release.gpg HTTP requests cannot identify a session.
    // Holding old Release while fetching new Release.gpg MUST fail cryptographic
    // verification; neither atomic pointer publication nor retries remove this.
    let old_release = harness.fixture.join("b09/g000/debian/dists/trixie/Release");
    let new_signature = harness
        .fixture
        .join("b09/g100/debian/dists/trixie/Release.gpg");
    assert!(
        harness
            .verifier
            .verify_detached(
                &harness.fixture.join("b09/policy.gpg"),
                &old_release,
                &new_signature
            )
            .await
            .is_err()
    );
    harness.shutdown().await;
}

#[test]
fn six_suite_security_first_rounds_do_not_restart_after_failed_admission() {
    let keys = keys();
    let mut scheduler = FairRounds::new(&keys).expect("production scheduler");
    for round in 0..100 {
        let mut seen = [false; 6];
        for position in 0..6 {
            let (actual_round, index) = scheduler.next_opportunity();
            assert_eq!(actual_round, round);
            assert!(!seen[index], "new security work cannot rewind a round");
            seen[index] = true;
            assert_eq!(keys[index].suite().ends_with("-security"), position < 2);
            // Refused admission deliberately does not retry this suite. The
            // production dispatcher advances the same cursor on refusal.
        }
        assert!(seen.into_iter().all(|visited| visited));
    }
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn every_failed_suite_keeps_its_own_slot_while_five_others_publish() {
    let mut harness = Harness::new().await;
    let keys = keys();
    for failed in 0..6 {
        let before: Vec<_> = keys
            .iter()
            .map(|key| harness.publisher.state(key).expect("state"))
            .collect();
        harness.select(failed + 1).await;
        let path = format!(
            "{}/dists/{}/Release.gpg",
            keys[failed].repository(),
            keys[failed].suite()
        );
        harness
            .origin
            .origin()
            .faults()
            .set(
                path.clone(),
                Fault {
                    kind: FaultKind::Delete,
                    remaining: None,
                },
            )
            .expect("isolated suite fault");
        assert!(
            harness
                .synchronizer
                .synchronize_once(&keys[failed], &harness.cancel)
                .await
                .is_err()
        );
        for (index, key) in keys.iter().enumerate() {
            if index == failed {
                continue;
            }
            harness.publish(key).await;
            assert_ne!(
                harness.publisher.state(key).expect("state").active,
                before[index].active
            );
        }
        let after = harness
            .publisher
            .state(&keys[failed])
            .expect("failed suite state");
        assert_eq!(after.active, before[failed].active);
        assert_eq!(after.confirmed_at, before[failed].confirmed_at);
        assert!(
            harness
                .view(&keys[failed])
                .is_fresh(Instant::now(), UnixTime::now())
        );
        harness.origin.origin().faults().remove(&path);
        harness.publish(&keys[failed]).await;
        // Ubuntu's identical Codename never aliases its three Suite slots.
        let ubuntu: Vec<_> = keys[3..]
            .iter()
            .map(|key| harness.view(key).generation_id)
            .collect();
        assert_ne!(ubuntu[0], ubuntu[1]);
        assert_ne!(ubuntu[1], ubuntu[2]);
    }
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn live_actor_isolates_slow_bulk_and_checkpoint_failure_without_blocking_observations() {
    let mut harness = Harness::new().await;
    let keys = keys();
    // Hold a real HTTP request until the test releases it. Unlike a fixed delay,
    // this proves overlap, rather than hoping healthy work beats a sleep.
    let armed = CancellationToken::new();
    let entered = CancellationToken::new();
    let release = CancellationToken::new();
    let controls = CancellationToken::new();
    let router = harness
        .origin
        .origin()
        .data_router()
        .layer(axum::middleware::from_fn({
            let armed = armed.clone();
            let entered = entered.clone();
            let release = release.clone();
            let controls = controls.clone();
            move |request: Request<Body>, next: axum::middleware::Next| {
                let armed = armed.clone();
                let entered = entered.clone();
                let release = release.clone();
                let controls = controls.clone();
                async move {
                    if armed.is_cancelled() {
                        match request.uri().path() {
                            "/fixture/ubuntu/dists/noble/Release.gpg" => {
                                entered.cancel();
                                release.cancelled().await;
                            }
                            path if path.ends_with("/InRelease") => {
                                // No healthy successor can publish before the
                                // bulk hold is entered. The two observation
                                // slots may wait here without owning bulk slots.
                                let conditional = path == "/fixture/ubuntu/dists/noble/InRelease"
                                    && request.headers().contains_key("if-none-match");
                                tokio::select! {
                                    () = entered.cancelled() => {}
                                    () = release.cancelled() => {}
                                }
                                let response = next.run(request).await;
                                if conditional && response.status() == StatusCode::NOT_MODIFIED {
                                    controls.cancel();
                                }
                                return response;
                            }
                            _ => {}
                        }
                    }
                    next.run(request).await
                }
            }
        }));
    let listener = ferrum_fixture_origin::bind_loopback("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect("held origin listener");
    let base = format!(
        "http://{}/fixture/",
        listener.local_addr().expect("held origin address")
    );
    let stop = CancellationToken::new();
    let server = tokio::spawn({
        let stop = stop.clone();
        async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .expect("held origin server");
        }
    });
    let mut config = (*harness.config).clone();
    // The 50ms harness cadence repeatedly launches six real verifier jobs and is not
    // a production liveness contract. Keep the 300s cadence and make the first
    // actor observation conditional by saving the successor before it starts.
    config.limits.sync_interval = Limits::default().sync_interval;
    assert_eq!(config.limits.sync_interval, Duration::from_secs(300));
    config
        .set_test_suite_origins(
            base.parse().expect("held origin URL"),
            harness.fixture.join("b09/policy.gpg"),
        )
        .expect("explicit loopback distribution seam");
    harness.synchronizer = DurableSynchronizer::new(
        Arc::new(config),
        harness.verifier.clone(),
        harness.spool.clone(),
        harness.publisher.clone(),
        harness.catalog.clone(),
        Arc::new(Metrics::default()),
    )
    .await
    .expect("live synchronizer with production cadence");
    for key in &keys {
        harness
            .synchronizer
            .synchronize_once(key, &harness.cancel)
            .await
            .expect("recover exact seed at held origin");
    }
    harness.select(1).await;
    harness
        .synchronizer
        .observe_once(&keys[3], &harness.cancel)
        .await
        .expect("save authenticated successor and its conditional validator");
    let previous: Vec<_> = keys
        .iter()
        .map(|key| harness.publisher.state(key).expect("initial state"))
        .collect();
    harness
        .remote
        .set_fault(
            "linux-checkpoints/v1/checkpoints/debian/trixie.json",
            Some(412),
        )
        .expect("one suite checkpoint CAS failure");
    // Publication timestamps have one-second resolution. Cross that explicit
    // boundary so a later observed_at proves the 304 was *authenticated*, not
    // merely returned by the HTTP server before actor cancellation.
    let observed_at = previous[3]
        .observed_at
        .expect("saved successor observation");
    while UnixTime::now().as_secs() <= observed_at {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    armed.cancel();
    harness.origin.origin().log().clear();
    let Harness {
        _directory,
        origin,
        publisher,
        catalog,
        synchronizer,
        remote,
        cancel,
        ..
    } = harness;
    let actor = tokio::spawn(synchronizer.run(cancel.clone()));
    // The Ubuntu successor is already queued. It must occupy only one of the
    // two bulk slots while all four healthy suites publish, and its 304 must
    // still be fetched and authenticated on the separate observation plane.
    let outcome = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let healthy = [1usize, 2, 4, 5].iter().all(|index| {
                publisher.state(&keys[*index]).expect("live state").active
                    != previous[*index].active
            });
            if healthy
                && entered.is_cancelled()
                && controls.is_cancelled()
                && publisher
                    .state(&keys[3])
                    .expect("conditional observation state")
                    .observed_at
                    .is_some_and(|time| time > observed_at)
                && publisher
                    .state(&keys[0])
                    .expect("checkpoint failure state")
                    .last_error
                    .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let states: Vec<_> = keys
        .iter()
        .map(|key| publisher.state(key).expect("live suite diagnostic"))
        .collect();
    let requests = remote.requests().expect("actual SDK trace");
    let observations = origin.origin().log().snapshot();
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), actor)
        .await
        .expect("actor cancellation deadline while bulk is still held")
        .expect("actor task");
    assert!(
        !release.is_cancelled(),
        "the bulk gate must never complete early"
    );
    release.cancel();
    stop.cancel();
    server.await.expect("held origin server task");
    assert!(
        outcome.is_ok(),
        "healthy publication, checkpoint rejection and authenticated conditional observation \
         must proceed while bulk is held; entered={}, conditional={}; states={states:?}; \
         origin={observations:?}; SDK={requests:?}",
        entered.is_cancelled(),
        controls.is_cancelled(),
    );
    for index in [0usize, 3] {
        let state = &states[index];
        assert_eq!(state.active, previous[index].active);
        assert_eq!(state.confirmed_at, previous[index].confirmed_at);
    }
    for index in [1usize, 2, 4, 5] {
        let view = catalog
            .load_suite(&keys[index])
            .expect("independent healthy view");
        assert!(view.is_fresh(Instant::now(), UnixTime::now()));
    }
    let checkpoint_key = "linux-checkpoints/v1/checkpoints/debian/trixie.json";
    assert!(
        remote
            .requests()
            .expect("actual SDK trace")
            .iter()
            .any(|(method, key)| method == "GET" && key == checkpoint_key)
    );
    origin.shutdown().await;
    drop(_directory);
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn missing_selected_index_and_corrupt_canonical_fallback_never_replace_active() {
    let mut harness = Harness::new().await;
    let key = keys().remove(0);
    let before = harness.publisher.state(&key).expect("initial authority");
    harness.select(1).await;
    let index = std::fs::read(
        harness
            .fixture
            .join("b09/g001/debian/dists/trixie")
            .join(INDEX),
    )
    .expect("new signed compressed index");
    let alias = format!(
        "debian/dists/trixie/main/binary-amd64/by-hash/SHA256/{}",
        Sha256Digest::of(&index)
    );
    let canonical = format!("debian/dists/trixie/{INDEX}");
    for path in [&alias, &canonical] {
        harness
            .origin
            .origin()
            .faults()
            .set(
                path.clone(),
                Fault {
                    kind: FaultKind::Delete,
                    remaining: None,
                },
            )
            .expect("missing selected representation");
    }
    assert!(
        harness
            .synchronizer
            .synchronize_once(&key, &harness.cancel)
            .await
            .is_err()
    );
    assert_eq!(
        harness
            .publisher
            .state(&key)
            .expect("missing closure")
            .active,
        before.active
    );
    harness
        .origin
        .origin()
        .faults()
        .set(
            canonical.clone(),
            Fault {
                kind: FaultKind::Corrupt { offset: 0 },
                remaining: None,
            },
        )
        .expect("racing canonical bytes");
    assert!(
        harness
            .synchronizer
            .synchronize_once(&key, &harness.cancel)
            .await
            .is_err()
    );
    let rejected = harness.publisher.state(&key).expect("corrupt closure");
    assert_eq!(rejected.active, before.active);
    assert_eq!(rejected.confirmed_at, before.confirmed_at);
    harness.origin.origin().faults().clear();
    harness.publish(&key).await;
    let accepted = harness.publisher.state(&key).expect("accepted successor");
    harness.select(0).await;
    assert!(
        harness
            .synchronizer
            .synchronize_once(&key, &harness.cancel)
            .await
            .is_err()
    );
    let rollback = harness.publisher.state(&key).expect("rollback rejected");
    assert_eq!(rollback.active, accepted.active);
    assert_eq!(rollback.confirmed_at, accepted.confirmed_at);
    harness.shutdown().await;
}

fn http_state(harness: &Harness, waiter_timeout: Duration) -> Arc<AppState> {
    let limits = Limits {
        waiter_timeout,
        ..Limits::default()
    };
    let client = Arc::new(
        UpstreamClient::new(
            format!("http://{}/fixture/debian/", harness.origin.data_addr())
                .parse()
                .expect("origin"),
            &limits,
        )
        .expect("HTTP client"),
    );
    let metrics = Arc::new(Metrics::default());
    let registry = FillRegistry::new(
        harness.spool.clone(),
        client.clone(),
        None,
        limits,
        CancellationToken::new(),
        metrics.clone(),
    );
    Arc::new(AppState {
        catalog: harness.catalog.clone(),
        spool: harness.spool.clone(),
        client: client.clone(),
        s3: None,
        capture: None,
        clients: vec![("debian".into(), client)],
        registry,
        metrics,
        limits,
        request_slots: Arc::new(tokio::sync::Semaphore::new(limits.request_slots)),
        active_bodies: Arc::new(tokio::sync::Semaphore::new(limits.active_bodies)),
        cold_clients: Default::default(),
        authority: "fixture.test".into(),
        trust_proxy_ip: true,
        request_ids: std::sync::atomic::AtomicU64::new(0),
        prefix: ferrum_apt::path::RepositoryPath::parse_decoded("fixture").expect("prefix"),
    })
}

async fn request(
    state: &Arc<AppState>,
    method: Method,
    path: &str,
    condition: Option<(&str, &str)>,
) -> Response<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", &state.authority);
    if let Some((name, value)) = condition {
        builder = builder.header(name, value);
    }
    let mut request = builder.body(Body::empty()).expect("request");
    request
        .extensions_mut()
        .insert("127.0.0.1".parse::<std::net::IpAddr>().expect("peer"));
    server::router(state.clone())
        .oneshot(request)
        .await
        .expect("infallible router")
}

fn derived(harness: &Harness) -> ferrum::sync::view::DerivedDescriptor {
    match harness
        .view(&keys().remove(0))
        .resolve("dists/trixie/main/binary-amd64/Packages")
    {
        Resolution::Derived { descriptor, .. } => descriptor,
        other => panic!("signed selected Packages must remain derived, got {other:?}"),
    }
}

fn expanded(harness: &Harness) -> Vec<u8> {
    std::fs::read(
        harness
            .fixture
            .join("b09/g000/debian/dists/trixie/main/binary-amd64/Packages"),
    )
    .expect("genuine signed Packages payload")
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn trailing_lf_release_is_exactly_servable_only_after_durable_activation() {
    let harness = Harness::with_seed(false).await;
    let suite = harness.config.suites().expect("suites").remove(0);
    let manifest = seed_manifest(
        &harness.spool,
        &harness.fixture.join("b09/g000"),
        &suite.key,
        &suite.policy,
        &harness.verifier,
    )
    .await;
    let detached = std::fs::read(
        harness
            .fixture
            .join("b09/g000")
            .join(suite.key.repository())
            .join("dists")
            .join(suite.key.suite())
            .join("Release"),
    )
    .expect("ordinary detached Release");
    assert!(detached.ends_with(b"\n"));
    assert_ne!(
        Sha256Digest::of(&detached).to_hex(),
        manifest.release_content_sha256,
        "cleartext authentication strips the terminal LF, not detached artifact identity"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    harness
        .publisher
        .persist_generation(&manifest, deadline, &harness.cancel)
        .await
        .expect("durable closure");
    let origin = OriginVerifier::loopback_for_tests(&format!(
        "http://{}/fixture/",
        harness.origin.data_addr()
    ))
    .expect("origin verifier");
    let now = UnixTime::now().as_secs();
    let audit = BootstrapAudit::acknowledge_reset(
        "trailing LF qualification",
        "new disposable catalog, not recovery",
        now,
        "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED",
    )
    .expect("explicit bootstrap");
    let generation = harness
        .publisher
        .verify_durable_generation(
            &manifest,
            &PublicationVerification {
                policy: &suite.policy,
                verifier: &harness.verifier,
                origin: &origin,
            },
            deadline,
            &harness.cancel,
        )
        .await
        .expect("real detached and cleartext authentication");
    let view = || {
        ActiveView::from_generation(
            &generation.proof(),
            generation.confirmed_at(),
            Duration::from_secs(60),
        )
        .expect("verified proof builds exact artifact view")
    };
    assert!(
        harness.catalog.publish_suite(&suite.key, view()).is_err(),
        "durable signed closure without local activation must not authorize serving"
    );
    let state = http_state(&harness, Duration::from_secs(5));
    let path = format!(
        "/{}/dists/{}/Release",
        suite.key.repository(),
        suite.key.suite()
    );
    let reply = request(&state, Method::GET, &path, None).await;
    assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
    harness
        .publisher
        .bootstrap_current(
            &manifest,
            &PublicationVerification {
                policy: &suite.policy,
                verifier: &harness.verifier,
                origin: &origin,
            },
            audit,
            deadline,
            &harness.cancel,
        )
        .await
        .expect("audited bootstrap includes durable activation");
    harness
        .catalog
        .publish_suite(&suite.key, view())
        .expect("publish activated proof");
    assert_eq!(
        representation(&harness.view(&suite.key), "Release").await,
        detached
    );
    let reply = request(&state, Method::GET, &path, None).await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(reply.into_body(), 32 * 1024 * 1024)
            .await
            .expect("exact Release"),
        detached.as_slice()
    );
    state.registry.shutdown().await;
    harness.shutdown().await;
}

// Recreate genuine off-VM bytes in a separate scripted provider, using only the
// production metered PUT path. No publisher/bootstrap call runs in the target
// catalog, so its existing reconciled allowance does not imply a local floor.
async fn copy_remote(source: &Harness, target: &Harness) {
    let objects: std::collections::BTreeSet<_> = source
        .remote
        .requests()
        .expect("SDK trace")
        .into_iter()
        .filter_map(|(method, key)| (method == "PUT").then_some(key))
        .collect();
    for key in objects {
        let bytes = source
            .remote
            .bytes(&key)
            .expect("remote read")
            .expect("stored exact bytes");
        let (identity, suffix) = if let Some(suffix) = key.strip_prefix("linux-checkpoints/") {
            (OperationIdentity::Checkpoint, suffix)
        } else {
            (
                OperationIdentity::Object,
                key.strip_prefix("linux-packages/")
                    .expect("object namespace"),
            )
        };
        target
            .store
            .control_put(
                identity,
                suffix,
                &bytes,
                ControlCondition::Create,
                tokio::time::Instant::now() + Duration::from_secs(120),
                &target.cancel,
            )
            .await
            .expect("copy exact genuine off-VM state");
    }
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn absent_local_floor_recovers_intact_remote_without_bootstrap_or_canonical_fallback() {
    let source = Harness::new().await;
    let mut target = Harness::with_seed(false).await;
    copy_remote(&source, &target).await;
    let key = keys().remove(0);
    let original = source
        .publisher
        .state(&key)
        .expect("source state")
        .floor
        .expect("trusted floor");
    let before = target.publisher.state(&key).expect("empty local suite");
    assert!(before.floor.is_none() && before.active.is_none() && before.pending.is_none());
    let request_count = target.remote.requests().expect("trace").len();
    assert_eq!(
        target
            .synchronizer
            .synchronize_once(&key, &target.cancel)
            .await
            .expect("authenticate trusted remote floor, artifacts, then current origin"),
        SyncOutcome::Published
    );
    let recovered = target.publisher.state(&key).expect("recovered state");
    assert_eq!(recovered.floor.as_ref(), Some(&original));
    assert_eq!(recovered.active.as_ref(), Some(&original));
    assert!(recovered.pending.is_none() && !recovered.blocked);
    assert_eq!(
        target.view(&key).generation_id.to_hex(),
        original.generation_id
    );
    let requests = target.remote.requests().expect("trace");
    let recovery_requests = &requests[request_count..];
    assert!(
        recovery_requests.iter().all(|(method, _)| method == "GET"),
        "recovery must not issue a new checkpoint or bootstrap: {recovery_requests:?}"
    );
    assert!(
        recovery_requests.iter().any(|(method, path)| {
            method == "GET" && path.starts_with("linux-packages/v1/objects/sha256/")
        }),
        "lost local artifacts must actually be restored from durable remote objects: \
         {recovery_requests:?}"
    );
    // Origin confirmation authenticates InRelease, and candidate staging also
    // authenticates the current detached Release/Release.gpg pair. Those signed
    // root documents are legitimate, not a canonical index reconstruction.
    let observations = target.origin.origin().log().snapshot();
    assert!(
        observations
            .iter()
            .any(|entry| { entry.path == "debian/dists/trixie/InRelease" && entry.status == 200 }),
        "remote recovery still requires current-origin confirmation: {observations:?}"
    );
    assert!(
        observations.iter().all(|entry| {
            matches!(
                entry.path.as_str(),
                "debian/dists/trixie/InRelease"
                    | "debian/dists/trixie/Release"
                    | "debian/dists/trixie/Release.gpg"
            )
        }),
        "remote floor recovery must never reconstruct selected indexes from canonical \
         or by-hash origin paths: {observations:?}"
    );
    assert_eq!(
        representation(&target.view(&key), "Release").await,
        representation(&source.view(&key), "Release").await
    );
    target.shutdown().await;
    source.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn absent_local_and_remote_floor_stays_closed_without_origin_bootstrap() {
    let mut harness = Harness::with_seed(false).await;
    let key = keys().remove(0);
    let error = harness
        .synchronizer
        .synchronize_once(&key, &harness.cancel)
        .await
        .expect_err("missing off-VM floor cannot be recovered");
    assert!(matches!(
        error,
        ferrum::sync::SyncError::Publication(CheckpointError::Transport(
            ferrum_storage::s3::S3Error::NotFound
        ))
    ));
    let state = harness.publisher.state(&key).expect("closed suite");
    assert!(state.floor.is_none() && state.active.is_none() && state.pending.is_none());
    assert!(state.blocked && !state.recovery_ready);
    assert!(harness.catalog.load_suite(&key).is_none());
    assert!(
        harness.origin.origin().log().snapshot().is_empty(),
        "a missing remote floor cannot trigger canonical bootstrap"
    );
    let requests = harness.remote.requests().expect("actual SDK requests");
    assert_eq!(
        requests,
        vec![(
            "GET".to_owned(),
            "linux-checkpoints/v1/checkpoints/debian/trixie.json".to_owned()
        )]
    );
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn derived_head_and_304_never_expand_and_cold_range_verifies_first() {
    let harness = Harness::new().await;
    let descriptor = derived(&harness);
    let expected = expanded(&harness);
    let identity = descriptor.identity;
    let state = http_state(&harness, Duration::from_secs(5));
    let path = "/debian/dists/trixie/main/binary-amd64/Packages";
    let reply = request(&state, Method::HEAD, path, Some(("range", "bytes=0-0"))).await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.headers()["content-length"], identity.size.to_string());
    assert!(reply.headers().get("content-range").is_none());
    let etag = format!("\"sha256-{}\"", identity.sha256);
    let reply = request(&state, Method::GET, path, Some(("if-none-match", &etag))).await;
    assert_eq!(reply.status(), StatusCode::NOT_MODIFIED);
    assert!(state.spool.lookup(identity).is_none());
    assert_eq!(state.registry.active_flights(), 0);
    let replies = futures_util::future::join_all(
        (0..8).map(|_| request(&state, Method::GET, path, Some(("range", "bytes=0-0")))),
    )
    .await;
    for reply in replies {
        assert_eq!(reply.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            to_bytes(reply.into_body(), 16)
                .await
                .expect("range")
                .as_ref(),
            &expected[..1]
        );
    }
    let verified = state
        .spool
        .lookup(identity)
        .expect("expanded object committed only after verification");
    assert_eq!(
        verified
            .read_bounded(32 * 1024 * 1024)
            .await
            .expect("verified expansion"),
        expected
    );
    state.registry.shutdown().await;
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn derived_corruption_has_no_representation_and_replayed_error_precedes_304() {
    use std::io::Write;
    let harness = Harness::new().await;
    let descriptor = derived(&harness);
    let identity = descriptor.identity;
    let mut corrupt = expanded(&harness);
    corrupt[0] ^= 1;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&corrupt)
        .expect("valid but unauthenticated compressed payload");
    std::fs::write(
        descriptor.source.path(),
        gzip.finish().expect("valid gzip member"),
    )
    .expect("inject post-activation disk corruption into the authenticated pinned source");
    let state = http_state(&harness, Duration::from_secs(5));
    let path = "/debian/dists/trixie/main/binary-amd64/Packages";
    let etag = format!("\"sha256-{}\"", identity.sha256);
    for condition in [None, Some(("if-none-match", etag.as_str()))] {
        let reply = request(&state, Method::GET, path, condition).await;
        assert_eq!(reply.status(), StatusCode::BAD_GATEWAY);
        assert!(reply.headers().get("etag").is_none());
        assert!(
            to_bytes(reply.into_body(), 16)
                .await
                .expect("error")
                .is_empty()
        );
        assert!(state.spool.lookup(identity).is_none());
    }
    state.registry.shutdown().await;
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn derived_waiter_timeout_leaves_single_producer_for_retry() {
    let harness = Harness::new().await;
    let identity = derived(&harness).identity;
    let expected = expanded(&harness);
    let state = http_state(&harness, Duration::from_millis(10));
    let permits = ferrum_apt::signature::cpu_gate()
        .acquire_many_owned(2)
        .await
        .expect("CPU gate");
    let path = "/debian/dists/trixie/main/binary-amd64/Packages";
    let reply = request(&state, Method::GET, path, None).await;
    assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.headers()["retry-after"], "5");
    assert_eq!(state.registry.active_flights(), 1);
    assert!(state.spool.lookup(identity).is_none());
    drop(permits);
    let joined = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let reply = request(&state, Method::GET, path, Some(("range", "bytes=0-0"))).await;
            if reply.status() == StatusCode::PARTIAL_CONTENT {
                break reply;
            }
            assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("same producer completes");
    assert_eq!(
        to_bytes(joined.into_body(), 16)
            .await
            .expect("range")
            .as_ref(),
        &expected[..1]
    );
    assert_eq!(state.metrics.fill_waiters(), 0);
    state.registry.shutdown().await;
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn stale_canonical_derived_metadata_does_not_disable_retained_immutable_alias() {
    let mut harness = Harness::new().await;
    let key = keys().remove(0);
    let identity = derived(&harness).identity;
    let expected = expanded(&harness);
    harness.select(1).await;
    harness.publish(&key).await;
    let view = harness.view(&key);
    let index = ferrum_apt::path::RepositoryPath::parse_decoded(INDEX).expect("source path");
    let proof = harness
        .publisher
        .lookup_metadata(&key, &index)
        .await
        .expect("activated metadata")
        .expect("durable metadata row")
        .proof();
    let stale =
        ActiveView::from_generation(&proof, view.confirmed_at_unix.as_secs(), Duration::ZERO)
            .expect("same authenticated generation with expired lease");
    harness
        .catalog
        .publish_suite(&key, stale)
        .expect("same activated generation, expired process lease");
    let state = http_state(&harness, Duration::from_secs(5));
    let etag = format!("\"sha256-{}\"", identity.sha256);
    let reply = request(
        &state,
        Method::GET,
        "/debian/dists/trixie/main/binary-amd64/Packages",
        Some(("if-none-match", &etag)),
    )
    .await;
    assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(state.spool.lookup(identity).is_none());
    let alias = format!(
        "/debian/dists/trixie/main/binary-amd64/by-hash/SHA256/{}",
        identity.sha256
    );
    let reply = request(&state, Method::GET, &alias, Some(("range", "bytes=0-0"))).await;
    assert_eq!(reply.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        reply.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        to_bytes(reply.into_body(), 16)
            .await
            .expect("retained immutable range")
            .as_ref(),
        &expected[..1]
    );
    assert!(state.spool.lookup(identity).is_some());
    state.registry.shutdown().await;
    harness.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn absent_local_floor_does_not_trust_malformed_remote_checkpoint() {
    let mut harness = Harness::with_seed(false).await;
    let key = keys().remove(0);
    harness
        .store
        .control_put(
            OperationIdentity::Checkpoint,
            "v1/checkpoints/debian/trixie.json",
            b"untrusted checkpoint bytes",
            ControlCondition::Create,
            tokio::time::Instant::now() + Duration::from_secs(120),
            &harness.cancel,
        )
        .await
        .expect("present but unauthenticated off-VM state");
    let request_count = harness.remote.requests().expect("trace").len();
    assert!(
        harness
            .synchronizer
            .synchronize_once(&key, &harness.cancel)
            .await
            .is_err()
    );
    let state = harness.publisher.state(&key).expect("closed suite");
    assert!(state.floor.is_none() && state.active.is_none() && state.pending.is_none());
    assert!(state.blocked && !state.recovery_ready);
    assert!(harness.catalog.load_suite(&key).is_none());
    assert!(harness.origin.origin().log().snapshot().is_empty());
    assert!(
        harness.remote.requests().expect("trace")[request_count..]
            .iter()
            .all(|(method, _)| method == "GET"),
        "untrusted floor must never be overwritten by bootstrap"
    );
    harness.shutdown().await;
}

fn pacman_tar_entry(path: &str, body: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());
    header[100..107].copy_from_slice(b"0000644");
    header[108..115].copy_from_slice(b"0000000");
    header[116..123].copy_from_slice(b"0000000");
    let size_octal = format!("{:011o}\0", body.len());
    header[124..136].copy_from_slice(size_octal.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    let chk_octal = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(chk_octal.as_bytes());
    let mut out = header.to_vec();
    out.extend_from_slice(body);
    let pad = (512 - (body.len() % 512)) % 512;
    out.resize(out.len() + pad, 0);
    out
}

#[cfg(target_os = "linux")]
fn pacman_signed_test_package(
    directory: &Path,
    signing_home: &Path,
    name: &str,
    size: u64,
    fill: u8,
) -> (ObjectIdentity, Vec<u8>) {
    use std::io::Write;
    let path = directory.join(name);
    let mut file = std::fs::File::create(&path).expect("signed test package");
    let chunk = [fill; 64 * 1024];
    let mut remaining = size;
    let mut hash = ferrum_apt::digest::Sha256Hasher::new();
    while remaining > 0 {
        let count = usize::try_from(remaining.min(chunk.len() as u64)).expect("bounded chunk");
        file.write_all(&chunk[..count]).expect("test package bytes");
        hash.update(&chunk[..count]);
        remaining -= count as u64;
    }
    drop(file);
    let status = std::process::Command::new("gpg")
        .args([
            "--homedir",
            signing_home.to_str().expect("utf8"),
            "--batch",
            "--passphrase",
            "",
            "--detach-sign",
            path.to_str().expect("utf8"),
        ])
        .status()
        .expect("sign test package");
    assert!(status.success());
    let signature = std::fs::read(format!("{}.sig", path.display())).expect("test signature");
    (
        ObjectIdentity {
            sha256: hash.finalize(),
            size,
        },
        signature,
    )
}

#[cfg(target_os = "linux")]
type PacmanTestPackage = (String, ObjectIdentity, Vec<u8>);

#[cfg(target_os = "linux")]
struct PacmanTestContext<'a> {
    state: &'a Arc<AppState>,
    publisher: &'a CheckpointPublisher,
    capture: &'a ferrum_storage::capture::CaptureManager,
    verifier: &'a SignatureVerifier,
    cancel: &'a CancellationToken,
    key: &'a SuiteKey,
    deadline: tokio::time::Instant,
}

#[cfg(target_os = "linux")]
impl PacmanTestContext<'_> {
    async fn check_current_policy(
        &self,
        package: (&str, ObjectIdentity),
        keyrings: (&Path, &Path),
    ) {
        let canary_only = TrustPolicy::ChaoticAur {
            keyring: keyrings.0.canonicalize().expect("canary-only keyring"),
        };
        // These control-plane futures contain the complete recovery state
        // machine. Keep them off the enclosing HTTP test's inline future frame.
        Box::pin(self.publisher.restore_retained(
            self.key,
            &canary_only,
            self.verifier,
            self.deadline,
            self.cancel,
        ))
        .await
        .expect("canary passes the replacement trust policy");
        let etag = format!("\"sha256-{}\"", package.1.sha256);
        let reply = request(
            self.state,
            Method::GET,
            package.0,
            Some(("if-none-match", &etag)),
        )
        .await;
        assert_eq!(
            reply.status(),
            StatusCode::BAD_GATEWAY,
            "a revalidated cached proof must not retain a removed package signer"
        );
        let combined = TrustPolicy::ChaoticAur {
            keyring: keyrings.1.to_path_buf(),
        };
        Box::pin(self.publisher.restore_retained(
            self.key,
            &combined,
            self.verifier,
            self.deadline,
            self.cancel,
        ))
        .await
        .expect("restore current combined policy");
    }

    async fn check_capture_lifetimes(
        &self,
        roots: &[ObjectIdentity],
        packages: &[PacmanTestPackage],
        keyrings: (&Path, &Path),
    ) {
        let (pending_name, pending_identity, pending_signature) = &packages[0];
        let pending_public = format!("/chaotic-aur/chaotic-aur/x86_64/{pending_name}");
        let reply = request(
            self.state,
            Method::GET,
            &pending_public,
            Some(("range", "bytes=0-0")),
        )
        .await;
        assert_eq!(reply.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            to_bytes(reply.into_body(), 16)
                .await
                .expect("pending package range")
                .len(),
            1
        );
        let signature_identity = ObjectIdentity {
            sha256: Sha256Digest::of(pending_signature),
            size: pending_signature.len() as u64,
        };
        for identity in roots {
            Box::pin(self.capture.complete(*identity, self.deadline, self.cancel))
                .await
                .expect("persist package/signature closure");
        }
        self.state
            .spool
            .reclaim(u64::MAX)
            .expect("reclaim after the first package completes");
        assert!(
            self.state.spool.lookup(signature_identity).is_some(),
            "completing package A cannot unpin package B's unuploaded metadata signature"
        );
        assert!(
            self.state.spool.lookup(*pending_identity).is_some(),
            "capture admission must revoke provisional package eviction before upload"
        );
        self.check_current_policy((&pending_public, *pending_identity), keyrings)
            .await;
        Box::pin(self.capture.complete(*pending_identity, self.deadline, self.cancel)).await
            .expect("package B completes after package A and eviction, without reacquiring origin signatures");
        for (name, identity, _) in packages.iter().skip(1) {
            let path = format!("/chaotic-aur/chaotic-aur/x86_64/{name}");
            let reply = request(self.state, Method::GET, &path, Some(("range", "bytes=0-0"))).await;
            assert_eq!(reply.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                to_bytes(reply.into_body(), 16)
                    .await
                    .expect("archived package range")
                    .len(),
                1
            );
            Box::pin(self.capture.complete(*identity, self.deadline, self.cancel))
                .await
                .expect("persist the next package");
        }
        assert_eq!(self.capture.usage().expect("completed capture").entries, 0);
    }

    async fn check_origin_off_recovery(
        &self,
        config: &Config,
        origin: RunningOrigin,
        primary: (&str, ObjectIdentity),
        packages: &[PacmanTestPackage],
    ) {
        origin.shutdown().await;
        self.state
            .spool
            .reclaim(512 * 1024 * 1024)
            .expect("evict durably captured payloads");
        assert!(self.state.spool.lookup(primary.1).is_none());
        self.capture
            .begin_reconciliation(UnixTime::now().as_secs())
            .expect("reset verification");
        let trusts = config
            .suites()
            .expect("configured trust")
            .into_iter()
            .map(|suite| ferrum_storage::capture::CaptureTrust {
                key: suite.key,
                policy: suite.policy,
                floor_trust: ferrum_storage::checkpoint::FloorTrust::IntactTrusted,
            })
            .collect::<Vec<_>>();
        Box::pin(self.capture.reconcile(
            &trusts,
            self.verifier,
            UnixTime::now().as_secs(),
            self.deadline,
            self.cancel,
        ))
        .await
        .expect("origin-off cryptographic package and dynamic signature recovery");
        assert!(self.capture.coverage_ready().expect("reconciled coverage"));
        let signature_public = format!("{}.sig", primary.0);
        for path in [primary.0, &signature_public] {
            let reply = request(self.state, Method::GET, path, Some(("range", "bytes=0-0"))).await;
            assert_eq!(reply.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                to_bytes(reply.into_body(), 16)
                    .await
                    .expect("origin-off range")
                    .len(),
                1
            );
        }
        for (index, (name, _, _)) in packages.iter().enumerate() {
            let path = format!("/chaotic-aur/chaotic-aur/x86_64/{name}");
            let reply = request(self.state, Method::GET, &path, Some(("range", "bytes=0-0"))).await;
            assert_eq!(reply.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                to_bytes(reply.into_body(), 16)
                    .await
                    .expect("archive larger than spool range")
                    .as_ref(),
                &[(index + 1) as u8]
            );
        }
        let relative = primary
            .0
            .strip_prefix("/chaotic-aur/")
            .expect("package repository");
        let receipt_suffix = format!(
            "v1/captures/chaotic-aur/{}/{}.json",
            Sha256Digest::of(relative.as_bytes()),
            primary.1.sha256
        );
        let store = self.state.s3.as_ref().expect("local disk-backed store");
        let saved = Box::pin(store.control_get(
            OperationIdentity::Object,
            &receipt_suffix,
            16 * 1024,
            self.deadline,
            self.cancel,
        ))
        .await
        .expect("saved package/signature binding receipt");
        let mut forged: serde_json::Value =
            serde_json::from_slice(&saved.bytes).expect("receipt JSON");
        let invalid_signature = b"not an OpenPGP package signature";
        let invalid_digest = Sha256Digest::of(invalid_signature);
        Box::pin(store.control_put(
            OperationIdentity::Object,
            &format!("v1/objects/sha256/{invalid_digest}"),
            invalid_signature,
            ControlCondition::Create,
            self.deadline,
            self.cancel,
        ))
        .await
        .expect("untrusted remote signature pointer");
        forged["package_signature"]["signature_sha256"] = invalid_digest.to_hex().into();
        forged["package_signature"]["signature_size"] = (invalid_signature.len() as u64).into();
        Box::pin(store.control_put(
            OperationIdentity::Object,
            &receipt_suffix,
            &serde_json::to_vec(&forged).expect("forged binding receipt"),
            ControlCondition::Match(saved.etag),
            self.deadline,
            self.cancel,
        ))
        .await
        .expect("replace unsigned receipt");
        self.capture
            .begin_reconciliation(UnixTime::now().as_secs())
            .expect("reset before forged recovery");
        assert!(
            Box::pin(self.capture.reconcile(
                &trusts,
                self.verifier,
                UnixTime::now().as_secs(),
                self.deadline,
                self.cancel,
            ))
            .await
            .is_err(),
            "receipt/index rows alone must not authenticate a package signature"
        );
        assert!(
            !self
                .capture
                .coverage_ready()
                .expect("failed recovery remains closed")
        );
        assert!(self.capture.is_durable(primary.1).is_err());
    }
}

#[cfg(target_os = "linux")]
async fn recover_unchanged_repository_catalog(
    config: Arc<Config>,
    verifier: SignatureVerifier,
    spool: Spool,
    publisher: Arc<CheckpointPublisher>,
) -> Arc<Catalog> {
    let keys: Vec<_> = config
        .suites()
        .expect("configured repositories")
        .into_iter()
        .map(|suite| suite.key)
        .collect();
    let catalog = Arc::new(
        Catalog::configured(keys.clone(), publisher.clone()).expect("fresh runtime catalog"),
    );
    catalog.set_test_clock_synchronized(true);
    let mut synchronizer = DurableSynchronizer::new(
        config,
        verifier,
        spool,
        publisher.clone(),
        catalog.clone(),
        Arc::new(Metrics::default()),
    )
    .await
    .expect("restarted synchronizer");
    for key in keys {
        let floor = publisher.state(&key).expect("existing floor").floor;
        assert_eq!(
            Box::pin(synchronizer.synchronize_once(&key, &CancellationToken::new()))
                .await
                .expect("unchanged authenticated origin recovers after restart"),
            SyncOutcome::Published
        );
        assert_eq!(
            publisher.state(&key).expect("recovered floor").floor,
            floor,
            "recovery must not manufacture a new publication checkpoint"
        );
    }
    catalog
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn pacman_arch_and_chaotic_aur_bootstrap_serve_packages_and_verify_detached_signatures() {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    let data_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ferrum-apt/tests/data");
    let keyring = data_dir
        .join("keyring.gpg")
        .canonicalize()
        .expect("keyring");
    let signed_pkg = std::fs::read(data_dir.join("Release")).expect("signed payload bytes");
    let signed_sig = std::fs::read(data_dir.join("Release.gpg")).expect("detached signature bytes");
    let pkg_sha256 = Sha256Digest::of(&signed_pkg).to_hex();
    let pkg_size = signed_pkg.len();

    let mut sig_b64 = String::new();
    {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in signed_sig.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            sig_b64.push(TABLE[(b0 >> 2) as usize] as char);
            sig_b64.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            sig_b64.push(if chunk.len() > 1 {
                TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
            } else {
                '='
            });
            sig_b64.push(if chunk.len() > 2 {
                TABLE[(b2 & 0x3f) as usize] as char
            } else {
                '='
            });
        }
    }

    let directory = tempfile::tempdir().expect("pacman test directory");
    let root = directory.path();
    let origin_root = root.join("origin");
    let arch_dir = origin_root.join("archlinux/core/os/x86_64");
    let chaotic_dir = origin_root.join("chaotic-aur/chaotic-aur/x86_64");
    std::fs::create_dir_all(&arch_dir).expect("arch dir");
    std::fs::create_dir_all(&chaotic_dir).expect("chaotic dir");
    let large_size = 32 * 1024 * 1024 + 1u64;
    let large_name = "large-verified-1.0-1-x86_64.pkg.tar.zst";
    let gpg_home = root.join("pacman-gnupg");
    std::fs::create_dir(&gpg_home).expect("package signing home");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gpg_home, std::fs::Permissions::from_mode(0o700))
            .expect("private signing home");
    }
    let status = std::process::Command::new("gpg")
        .args([
            "--homedir",
            gpg_home.to_str().expect("utf8"),
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "PacmanTest <pacman@example.test>",
            "ed25519",
            "sign",
            "1d",
        ])
        .status()
        .expect("test-only signing key");
    assert!(status.success());
    let exported = std::process::Command::new("gpg")
        .args([
            "--homedir",
            gpg_home.to_str().expect("utf8"),
            "--batch",
            "--export",
            "PacmanTest",
        ])
        .output()
        .expect("export package certificate");
    assert!(exported.status.success());
    let mut combined = std::fs::read(&keyring).expect("fixture certificate");
    combined.extend_from_slice(&exported.stdout);
    let keyring = root.join("pacman-combined-keyring.gpg");
    std::fs::write(&keyring, combined).expect("combined package keyring");
    let (large_identity, large_signature) =
        pacman_signed_test_package(&chaotic_dir, &gpg_home, large_name, large_size, 0x5a);
    let large_digest = large_identity.sha256;
    let mut extra_packages = Vec::new();
    for index in 1..=3u8 {
        let name = format!("large-extra-{index}-1.0-1-x86_64.pkg.tar.zst");
        let (identity, signature) =
            pacman_signed_test_package(&chaotic_dir, &gpg_home, &name, large_size, index);
        extra_packages.push((name, identity, signature));
    }

    let build_date = UnixTime::now().as_secs().saturating_sub(60);
    let arch_desc = format!(
        "%FILENAME%\nferrum-core-1.0-1-x86_64.pkg.tar.zst\n\n%NAME%\nferrum-core\n\n%VERSION%\n1.0-1\n\n%CSIZE%\n{pkg_size}\n\n%SHA256SUM%\n{pkg_sha256}\n\n%PGPSIG%\n{sig_b64}\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n{build_date}\n\n"
    );
    let mut arch_tar = pacman_tar_entry("ferrum-core-1.0-1/desc", arch_desc.as_bytes());
    arch_tar.resize(arch_tar.len() + 1024, 0);
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&arch_tar).expect("compress core.db");
    let core_db = gz.finish().expect("finish core.db");
    std::fs::write(arch_dir.join("core.db"), &core_db).expect("write core.db");
    std::fs::write(
        arch_dir.join("ferrum-core-1.0-1-x86_64.pkg.tar.zst"),
        &signed_pkg,
    )
    .expect("write core pkg");
    std::fs::write(
        arch_dir.join("ferrum-core-1.0-1-x86_64.pkg.tar.zst.sig"),
        &signed_sig,
    )
    .expect("write core sig");

    let canary_desc = format!(
        "%FILENAME%\naaa-canary-1.0-1-any.pkg.tar.zst\n\n%NAME%\naaa-canary\n\n%VERSION%\n1.0-1\n\n%CSIZE%\n{pkg_size}\n\n%SHA256SUM%\n{pkg_sha256}\n\n%ARCH%\nany\n\n%BUILDDATE%\n{build_date}\n\n"
    );
    let aur_desc = format!(
        "%FILENAME%\nyay-bin-12.4.2-1-x86_64.pkg.tar.zst\n\n%NAME%\nyay-bin\n\n%VERSION%\n12.4.2-1\n\n%CSIZE%\n{pkg_size}\n\n%SHA256SUM%\n{pkg_sha256}\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n{build_date}\n\n"
    );
    let mut chaotic_tar = pacman_tar_entry("aaa-canary-1.0-1/desc", canary_desc.as_bytes());
    chaotic_tar.extend_from_slice(&pacman_tar_entry(
        "yay-bin-12.4.2-1/desc",
        aur_desc.as_bytes(),
    ));
    let large_desc = format!(
        "%FILENAME%\n{large_name}\n\n%NAME%\nlarge-verified\n\n%VERSION%\n1.0-1\n\n%CSIZE%\n{large_size}\n\n%SHA256SUM%\n{large_digest}\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n{build_date}\n\n"
    );
    chaotic_tar.extend_from_slice(&pacman_tar_entry(
        "large-verified-1.0-1/desc",
        large_desc.as_bytes(),
    ));
    for (index, (name, identity, _)) in extra_packages.iter().enumerate() {
        let desc = format!(
            "%FILENAME%\n{name}\n\n%NAME%\nlarge-extra-{index}\n\n%VERSION%\n1.0-1\n\n%CSIZE%\n{}\n\n%SHA256SUM%\n{}\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n{build_date}\n\n",
            identity.size, identity.sha256,
        );
        chaotic_tar.extend_from_slice(&pacman_tar_entry(
            &format!("large-extra-{index}-1.0-1/desc"),
            desc.as_bytes(),
        ));
    }
    let mut unsigned_identities = Vec::new();
    for (name, embedded, detached) in [
        ("missing", false, false),
        ("replaced", false, true),
        ("invalid", false, true),
        ("embedded-invalid", true, false),
    ] {
        let mut bytes = signed_pkg.clone();
        bytes.extend_from_slice(name.as_bytes());
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(&bytes),
            size: bytes.len() as u64,
        };
        let filename = format!("{name}-1.0-1-x86_64.pkg.tar.zst");
        let embedded = if embedded {
            format!("%PGPSIG%\n{sig_b64}\n\n")
        } else {
            String::new()
        };
        let desc = format!(
            "%FILENAME%\n{filename}\n\n%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%CSIZE%\n{}\n\n%SHA256SUM%\n{}\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n{build_date}\n\n{embedded}",
            identity.size, identity.sha256,
        );
        chaotic_tar.extend_from_slice(&pacman_tar_entry(
            &format!("{name}-1.0-1/desc"),
            desc.as_bytes(),
        ));
        std::fs::write(chaotic_dir.join(&filename), bytes).expect("distinct unsigned package");
        if detached {
            std::fs::write(
                chaotic_dir.join(format!("{filename}.sig")),
                if name == "invalid" {
                    b"invalid signature".as_slice()
                } else {
                    signed_sig.as_slice()
                },
            )
            .expect("invalid or replaced detached signature");
        }
        unsigned_identities.push((filename, identity));
    }
    chaotic_tar.resize(chaotic_tar.len() + 1024, 0);
    std::fs::write(chaotic_dir.join("chaotic-aur.db"), &chaotic_tar).expect("write chaotic-aur.db");
    for name in [
        "aaa-canary-1.0-1-any.pkg.tar.zst",
        "yay-bin-12.4.2-1-x86_64.pkg.tar.zst",
    ] {
        std::fs::write(chaotic_dir.join(name), &signed_pkg).expect("write chaotic pkg");
        std::fs::write(chaotic_dir.join(format!("{name}.sig")), &signed_sig)
            .expect("write chaotic sig");
    }

    let origin = RunningOrigin::bind(OriginConfig {
        root: origin_root,
        listen: "127.0.0.1:0".parse().expect("loopback"),
        control: "127.0.0.1:0".parse().expect("loopback"),
        prefix: "/fixture/".into(),
    })
    .await
    .expect("pacman origin");
    let base = format!("http://{}/fixture/", origin.data_addr());
    let text = format!(
        "mode = \"private-durable\"\n[listen]\npublic = \"127.0.0.1:0\"\nadmin = \"127.0.0.1:0\"\n\
         [durable]\nstate_dir = \"{}\"\nsuites = [\"archlinux/core\", \"chaotic-aur/chaotic-aur\"]\n\
         [durable.provider]\nregion = \"us-east-1\"\n\
         bucket = \"ferrum\"\ncredentials_file = \"{}\"\n\
         [durable.keyrings]\ndebian = \"{}\"\nubuntu = \"{}\"\narchlinux = \"{}\"\nchaoticaur = \"{}\"\n\
         [durable.budget]\nmode = \"existing\"\n[verifier]\n[limits]\n",
        root.join("state").display(),
        root.join("unused-provider.env").display(),
        keyring.display(),
        keyring.display(),
        keyring.display(),
        keyring.display(),
    );
    let mut config = Config::parse(&text, root).expect("pacman durable config");
    config
        .set_test_suite_origins(base.parse().expect("base URL"), keyring.clone())
        .expect("loopback seam");
    let mut disk = DurableSpoolConfig::new(root.join("state"));
    disk.free_space_floor = 0;
    disk.spool.managed_ceiling = 128 * 1024 * 1024;
    disk.spool.max_object_size = 64 * 1024 * 1024;
    disk.temporary_ceiling = 96 * 1024 * 1024;
    disk.metadata_temporary_reserve = 32 * 1024 * 1024;
    disk.metadata_ceiling = 96 * 1024 * 1024;
    disk.catalog_ceiling = 64 * 1024 * 1024;
    disk.eviction_high_watermark = 112 * 1024 * 1024;
    disk.eviction_low_watermark = 64 * 1024 * 1024;
    disk.max_entries = 10_000;
    let spool = Spool::open_durable(disk).expect("durable spool");
    let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default()).expect("ledger");
    let (store, _remote) = S3Store::disk_backed_production(
        config.durable().expect("durable").store_config(),
        ledger,
        root.join("remote"),
        1024 * 1024 * 1024,
    )
    .expect("s3 store");
    let store = Arc::new(store);
    let publisher = Arc::new(
        CheckpointPublisher::new(
            spool.clone(),
            store.clone(),
            RecoveryProfile::SharedNonisolated,
        )
        .expect("publisher"),
    );
    let capture = Arc::new(
        ferrum_storage::capture::CaptureManager::new(spool.clone(), store.clone())
            .expect("capture manager"),
    );
    capture
        .initialize(UnixTime::now().as_secs())
        .expect("fresh capture coverage");
    let arch_key = SuiteKey::new("archlinux", "core").expect("arch key");
    let chaotic_key = SuiteKey::new("chaotic-aur", "chaotic-aur").expect("chaotic key");
    let catalog = Arc::new(
        Catalog::configured(
            vec![arch_key.clone(), chaotic_key.clone()],
            publisher.clone(),
        )
        .expect("catalog"),
    );
    catalog.set_test_clock_synchronized(true);
    let verifier = SignatureVerifier::new("ferrum-verifier".into(), Duration::from_secs(30))
        .await
        .expect("verifier");
    let config = Arc::new(config);
    let mut synchronizer = DurableSynchronizer::new(
        config.clone(),
        verifier.clone(),
        spool.clone(),
        publisher.clone(),
        catalog.clone(),
        Arc::new(Metrics::default()),
    )
    .await
    .expect("synchronizer");
    let cancel = CancellationToken::new();
    for key in [&arch_key, &chaotic_key] {
        let now = UnixTime::now().as_secs();
        let audit = BootstrapAudit::acknowledge_reset(
            "pacman test",
            "fresh disposable pacman suite",
            now,
            "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED",
        )
        .expect("audit");
        assert_eq!(
            synchronizer
                .bootstrap_once(key, audit, &cancel)
                .await
                .expect("bootstrap pacman suite"),
            SyncOutcome::Published
        );
    }
    drop(synchronizer);
    drop(catalog);
    let catalog = Box::pin(recover_unchanged_repository_catalog(
        config.clone(),
        verifier.clone(),
        spool.clone(),
        publisher.clone(),
    ))
    .await;

    let limits = Limits::default();
    let arch_client = Arc::new(
        UpstreamClient::new(format!("{base}archlinux/").parse().expect("url"), &limits)
            .expect("arch client"),
    );
    let chaotic_client = Arc::new(
        UpstreamClient::new(format!("{base}chaotic-aur/").parse().expect("url"), &limits)
            .expect("chaotic client"),
    );
    let metrics = Arc::new(Metrics::default());
    let registry = FillRegistry::new(
        spool.clone(),
        arch_client.clone(),
        Some(store.clone()),
        limits,
        CancellationToken::new(),
        metrics.clone(),
    );
    let state = Arc::new(AppState {
        catalog,
        spool,
        client: arch_client.clone(),
        s3: Some(store),
        capture: Some(capture.clone()),
        clients: vec![
            ("archlinux".into(), arch_client),
            ("chaotic-aur".into(), chaotic_client),
        ],
        registry,
        metrics,
        limits,
        request_slots: Arc::new(tokio::sync::Semaphore::new(limits.request_slots)),
        active_bodies: Arc::new(tokio::sync::Semaphore::new(limits.active_bodies)),
        cold_clients: Default::default(),
        authority: "fixture.test".into(),
        trust_proxy_ip: true,
        request_ids: std::sync::atomic::AtomicU64::new(0),
        prefix: ferrum_apt::path::RepositoryPath::parse_decoded("fixture").expect("prefix"),
    });
    let alias = format!("/archlinux/core/os/x86_64/by-hash/SHA256/{pkg_sha256}");
    let reply = request(&state, Method::GET, &alias, None).await;
    assert_eq!(
        reply.status(),
        StatusCode::NOT_FOUND,
        "proof canaries cannot bypass package verification through metadata aliases"
    );
    let cold_signature = "/chaotic-aur/chaotic-aur/x86_64/missing-1.0-1-x86_64.pkg.tar.zst.sig";
    let origin_requests = origin.origin().log().snapshot().len();
    let usage = capture.usage().expect("capture usage before HEAD");
    let reply = request(&state, Method::HEAD, cold_signature, None).await;
    assert_eq!(reply.status(), StatusCode::NOT_FOUND);
    assert_eq!(origin.origin().log().snapshot().len(), origin_requests);
    assert_eq!(
        capture.usage().expect("usage after HEAD").entries,
        usage.entries
    );
    assert_eq!(state.registry.active_flights(), 0);
    assert!(state.spool.lookup(unsigned_identities[0].1).is_none());
    let reply = request(
        &state,
        Method::HEAD,
        cold_signature,
        Some(("if-none-match", "*")),
    )
    .await;
    assert_eq!(reply.status(), StatusCode::NOT_FOUND);
    let reply = request(
        &state,
        Method::GET,
        cold_signature,
        Some(("if-none-match", "*")),
    )
    .await;
    assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
    let missing_package = "/chaotic-aur/chaotic-aur/x86_64/missing-1.0-1-x86_64.pkg.tar.zst";
    let candidate_etag = format!("\"sha256-{}\"", unsigned_identities[0].1.sha256);
    let reply = request(
        &state,
        Method::GET,
        missing_package,
        Some(("if-none-match", &candidate_etag)),
    )
    .await;
    assert_eq!(
        reply.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an unsigned candidate checksum cannot authorize a positive 304"
    );
    assert_eq!(origin.origin().log().snapshot().len(), origin_requests);
    assert_eq!(
        capture.usage().expect("usage after conditional").entries,
        usage.entries
    );
    let candidate_path = ferrum_apt::path::RepositoryPath::parse_decoded(&format!(
        "chaotic-aur/x86_64/{}",
        unsigned_identities[0].0
    ))
    .expect("candidate package path");
    let candidate = publisher
        .lookup_package("chaotic-aur", &candidate_path)
        .await
        .expect("candidate lookup")
        .expect("indexed unsigned candidate")
        .authorize()
        .await
        .expect("descriptor is not yet package authenticity");
    assert!(matches!(
        capture.reserve(&candidate, UnixTime::now().as_secs()),
        Err(ferrum_storage::capture::CaptureError::Proof)
    ));

    for (filename, _) in &unsigned_identities {
        let path = format!("/chaotic-aur/chaotic-aur/x86_64/{filename}");
        for _ in 0..2 {
            let reply = request(&state, Method::GET, &path, None).await;
            assert!(
                matches!(
                    reply.status(),
                    StatusCode::NOT_FOUND | StatusCode::BAD_GATEWAY
                ),
                "unsigned package must not be served, cold or warm: {filename}"
            );
            assert!(
                capture
                    .lookup(
                        "chaotic-aur",
                        &ferrum_apt::path::RepositoryPath::parse_decoded(&format!(
                            "chaotic-aur/x86_64/{filename}"
                        ))
                        .expect("path")
                    )
                    .expect("capture mapping")
                    .is_none()
            );
        }
    }
    state
        .spool
        .reclaim(u64::MAX)
        .expect("discard rejected provisional candidates");
    for (_, identity) in &unsigned_identities {
        assert!(
            state.spool.lookup(*identity).is_none(),
            "rejected package candidates must not permanently consume the spool"
        );
    }

    let reply = request(
        &state,
        Method::GET,
        "/archlinux/core/os/x86_64/core.db",
        None,
    )
    .await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.headers()["cache-control"], "no-cache");
    assert_eq!(
        to_bytes(reply.into_body(), 1024 * 1024)
            .await
            .expect("core.db"),
        core_db.as_slice()
    );

    let reply = request(
        &state,
        Method::GET,
        "/archlinux/core/os/x86_64/ferrum-core-1.0-1-x86_64.pkg.tar.zst",
        None,
    )
    .await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(reply.into_body(), 1024 * 1024)
            .await
            .expect("core pkg"),
        signed_pkg.as_slice()
    );

    let reply = request(
        &state,
        Method::GET,
        "/archlinux/core/os/x86_64/ferrum-core-1.0-1-x86_64.pkg.tar.zst.sig",
        None,
    )
    .await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(reply.into_body(), 64 * 1024)
            .await
            .expect("core sig"),
        signed_sig.as_slice()
    );

    let reply = request(
        &state,
        Method::GET,
        "/chaotic-aur/chaotic-aur/x86_64/chaotic-aur.db",
        None,
    )
    .await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.headers()["cache-control"], "no-cache");
    assert_eq!(
        to_bytes(reply.into_body(), 1024 * 1024)
            .await
            .expect("chaotic-aur.db"),
        chaotic_tar.as_slice()
    );

    let reply = request(
        &state,
        Method::GET,
        "/chaotic-aur/chaotic-aur/x86_64/yay-bin-12.4.2-1-x86_64.pkg.tar.zst.sig",
        None,
    )
    .await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(reply.into_body(), 64 * 1024)
            .await
            .expect("verified on-demand chaotic-aur sig"),
        signed_sig.as_slice()
    );
    let dynamic_signature =
        "/chaotic-aur/chaotic-aur/x86_64/yay-bin-12.4.2-1-x86_64.pkg.tar.zst.sig";
    let before_conditional = origin.origin().log().snapshot().len();
    let etag = format!("\"sha256-{}\"", Sha256Digest::of(&signed_sig));
    let reply = request(
        &state,
        Method::GET,
        dynamic_signature,
        Some(("if-none-match", &etag)),
    )
    .await;
    assert_eq!(reply.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(origin.origin().log().snapshot().len(), before_conditional);

    let large_public = format!("/chaotic-aur/chaotic-aur/x86_64/{large_name}");
    for _ in 0..2 {
        use futures_util::StreamExt;
        let reply = request(&state, Method::GET, &large_public, None).await;
        assert_eq!(reply.status(), StatusCode::OK);
        let mut body = reply.into_body().into_data_stream();
        let mut hash = ferrum_apt::digest::Sha256Hasher::new();
        let mut size = 0u64;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.expect("streamed verified large package");
            size += chunk.len() as u64;
            hash.update(&chunk);
        }
        assert_eq!(size, large_size);
        assert_eq!(hash.finalize(), large_digest);
    }
    let large_signature_public = format!("{large_public}.sig");
    let reply = request(&state, Method::GET, &large_signature_public, None).await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(reply.into_body(), 64 * 1024)
            .await
            .expect("large signature"),
        large_signature.as_slice()
    );

    let checks = PacmanTestContext {
        state: &state,
        publisher: publisher.as_ref(),
        capture: capture.as_ref(),
        verifier: &verifier,
        cancel: &cancel,
        key: &chaotic_key,
        deadline: tokio::time::Instant::now() + Duration::from_secs(600),
    };
    checks
        .check_capture_lifetimes(
            &[
                ObjectIdentity {
                    sha256: Sha256Digest::of(&signed_pkg),
                    size: signed_pkg.len() as u64,
                },
                ObjectIdentity {
                    sha256: Sha256Digest::of(&signed_sig),
                    size: signed_sig.len() as u64,
                },
                large_identity,
                ObjectIdentity {
                    sha256: Sha256Digest::of(&large_signature),
                    size: large_signature.len() as u64,
                },
            ],
            &extra_packages,
            (&data_dir.join("keyring.gpg"), &keyring),
        )
        .await;
    assert!(
        large_size
            + extra_packages
                .iter()
                .map(|(_, identity, _)| identity.size)
                .sum::<u64>()
            > 128 * 1024 * 1024,
        "the remote retained package set must exceed the entire local spool"
    );
    assert_eq!(
        publisher
            .retained_proofs(&chaotic_key)
            .expect("candidate proof")[0]
            .release()
            .authority(),
        ferrum_apt::release::MetadataAuthority::TransportCandidate
    );

    checks
        .check_origin_off_recovery(
            &config,
            origin,
            (&large_public, large_identity),
            &extra_packages,
        )
        .await;

    let reply = request(
        &state,
        Method::GET,
        "/chaotic-aur/chaotic-aur/x86_64/unknown-1.0-1-x86_64.pkg.tar.zst.sig",
        None,
    )
    .await;
    assert_eq!(reply.status(), StatusCode::NOT_FOUND);

    state.registry.shutdown().await;
    // The origin is already stopped before reset/recovery above.
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn rpm_almalinux_bootstrap_serves_repomd_primary_and_packages() {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use std::process::Command;

    let directory = tempfile::tempdir().expect("rpm test dir");
    let root = directory.path();
    let gpg_home = root.join("gnupg");
    std::fs::create_dir_all(&gpg_home).expect("gnupg home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gpg_home, std::fs::Permissions::from_mode(0o700))
            .expect("chmod gnupg");
    }
    let status = Command::new("gpg")
        .args([
            "--homedir",
            gpg_home.to_str().expect("utf8"),
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "AlmaTest <alma@example.test>",
            "ed25519",
            "sign",
            "1d",
        ])
        .status()
        .expect("gpg keygen");
    assert!(status.success(), "gpg keygen must succeed");
    let keyring = root.join("almalinux-keyring.gpg");
    let exported = Command::new("gpg")
        .args([
            "--homedir",
            gpg_home.to_str().expect("utf8"),
            "--batch",
            "--export",
            "AlmaTest",
        ])
        .output()
        .expect("gpg export");
    assert!(exported.status.success());
    std::fs::write(&keyring, &exported.stdout).expect("write keyring");

    let rpm_bytes = b"verified-rpm-binary-payload-almalinux-9".to_vec();
    let rpm_sha256 = Sha256Digest::of(&rpm_bytes).to_hex();
    let rpm_size = rpm_bytes.len();

    let primary_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
<package type="rpm">
  <name>bash</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="5.2.15" rel="2.el9"/>
  <checksum type="sha256" pkgid="YES">{rpm_sha256}</checksum>
  <size package="{rpm_size}" installed="4096" archive="4096"/>
  <location href="Packages/bash-5.2.15-2.el9.x86_64.rpm"/>
</package>
</metadata>"#
    );
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(primary_xml.as_bytes())
        .expect("compress primary.xml");
    let primary_gz = gz.finish().expect("finish primary.xml.gz");
    let primary_sha256 = Sha256Digest::of(&primary_gz).to_hex();
    let primary_size = primary_gz.len();
    let primary_rel = format!("repodata/{primary_sha256}-primary.xml.gz");

    let ts = UnixTime::now().as_secs().saturating_sub(60);
    let repomd_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>{ts}</revision>
  <data type="primary">
    <checksum type="sha256">{primary_sha256}</checksum>
    <location href="{primary_rel}"/>
    <timestamp>{ts}</timestamp>
    <size>{primary_size}</size>
  </data>
</repomd>"#
    );

    let origin_root = root.join("origin");
    let alma_root = origin_root.join("almalinux/9/BaseOS/x86_64/os");
    std::fs::create_dir_all(alma_root.join("repodata")).expect("repodata dir");
    std::fs::create_dir_all(alma_root.join("Packages")).expect("Packages dir");
    let repomd_file = alma_root.join("repodata/repomd.xml");
    let repomd_asc_file = alma_root.join("repodata/repomd.xml.asc");
    std::fs::write(&repomd_file, repomd_xml.as_bytes()).expect("write repomd.xml");
    let sign_status = Command::new("gpg")
        .args([
            "--homedir",
            gpg_home.to_str().expect("utf8"),
            "--batch",
            "--yes",
            "--armor",
            "--detach-sign",
            "--output",
            repomd_asc_file.to_str().expect("utf8"),
            repomd_file.to_str().expect("utf8"),
        ])
        .status()
        .expect("gpg sign repomd.xml");
    assert!(sign_status.success());
    let _ = Command::new("gpgconf")
        .args([
            "--homedir",
            gpg_home.to_str().expect("utf8"),
            "--kill",
            "gpg-agent",
        ])
        .status();
    std::fs::write(alma_root.join(&primary_rel), &primary_gz).expect("write primary.xml.gz");
    std::fs::write(
        alma_root.join("Packages/bash-5.2.15-2.el9.x86_64.rpm"),
        &rpm_bytes,
    )
    .expect("write rpm");

    let origin = RunningOrigin::bind(OriginConfig {
        root: origin_root,
        listen: "127.0.0.1:0".parse().expect("loopback"),
        control: "127.0.0.1:0".parse().expect("loopback"),
        prefix: "/fixture/".into(),
    })
    .await
    .expect("rpm origin");
    let base = format!("http://{}/fixture/", origin.data_addr());
    let text = format!(
        "mode = \"private-durable\"\n[listen]\npublic = \"127.0.0.1:0\"\nadmin = \"127.0.0.1:0\"\n\
         [durable]\nstate_dir = \"{}\"\nsuites = [\"almalinux/9-baseos-x86-64\"]\n\
         [durable.provider]\nregion = \"us-east-1\"\n\
         bucket = \"ferrum\"\ncredentials_file = \"{}\"\n\
         [durable.keyrings]\ndebian = \"{}\"\nubuntu = \"{}\"\nalmalinux = \"{}\"\n\
         [durable.budget]\nmode = \"existing\"\n[verifier]\n[limits]\n",
        root.join("state").display(),
        root.join("unused-provider.env").display(),
        keyring.display(),
        keyring.display(),
        keyring.display(),
    );
    let mut config = Config::parse(&text, root).expect("rpm durable config");
    config
        .set_test_suite_origins(base.parse().expect("base URL"), keyring.clone())
        .expect("loopback seam");
    let mut disk = DurableSpoolConfig::new(root.join("state"));
    disk.free_space_floor = 0;
    disk.spool.managed_ceiling = 512 * 1024 * 1024;
    disk.spool.max_object_size = 32 * 1024 * 1024;
    disk.temporary_ceiling = 256 * 1024 * 1024;
    disk.metadata_temporary_reserve = 128 * 1024 * 1024;
    disk.metadata_ceiling = 256 * 1024 * 1024;
    disk.catalog_ceiling = 64 * 1024 * 1024;
    disk.eviction_high_watermark = 450 * 1024 * 1024;
    disk.eviction_low_watermark = 400 * 1024 * 1024;
    disk.max_entries = 10_000;
    let spool = Spool::open_durable(disk).expect("durable spool");
    let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default()).expect("ledger");
    let (store, _remote) =
        S3Store::stateful_production(config.durable().expect("durable").store_config(), ledger)
            .expect("s3 store");
    let store = Arc::new(store);
    let publisher = Arc::new(
        CheckpointPublisher::new(
            spool.clone(),
            store.clone(),
            RecoveryProfile::SharedNonisolated,
        )
        .expect("publisher"),
    );
    let capture = Arc::new(
        ferrum_storage::capture::CaptureManager::new(spool.clone(), store.clone())
            .expect("capture manager"),
    );
    capture
        .initialize(UnixTime::now().as_secs())
        .expect("fresh capture coverage");
    let alma_key = SuiteKey::new("almalinux", "9-baseos-x86-64").expect("alma key");
    let catalog =
        Arc::new(Catalog::configured(vec![alma_key.clone()], publisher.clone()).expect("catalog"));
    catalog.set_test_clock_synchronized(true);
    let verifier = SignatureVerifier::new("ferrum-verifier".into(), Duration::from_secs(30))
        .await
        .expect("verifier");
    let config = Arc::new(config);
    let mut synchronizer = DurableSynchronizer::new(
        config.clone(),
        verifier.clone(),
        spool.clone(),
        publisher.clone(),
        catalog.clone(),
        Arc::new(Metrics::default()),
    )
    .await
    .expect("synchronizer");
    let cancel = CancellationToken::new();
    let audit = BootstrapAudit::acknowledge_reset(
        "rpm test",
        "fresh disposable rpm suite",
        UnixTime::now().as_secs(),
        "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED",
    )
    .expect("audit");
    assert_eq!(
        synchronizer
            .bootstrap_once(&alma_key, audit, &cancel)
            .await
            .expect("bootstrap rpm suite"),
        SyncOutcome::Published
    );
    drop(synchronizer);
    drop(catalog);
    let catalog = Box::pin(recover_unchanged_repository_catalog(
        config.clone(),
        verifier,
        spool.clone(),
        publisher.clone(),
    ))
    .await;

    let limits = Limits::default();
    let alma_client = Arc::new(
        UpstreamClient::new(format!("{base}almalinux/").parse().expect("url"), &limits)
            .expect("alma client"),
    );
    let metrics = Arc::new(Metrics::default());
    let registry = FillRegistry::new(
        spool.clone(),
        alma_client.clone(),
        Some(store.clone()),
        limits,
        CancellationToken::new(),
        metrics.clone(),
    );
    let state = Arc::new(AppState {
        catalog,
        spool,
        client: alma_client.clone(),
        s3: Some(store),
        capture: Some(capture),
        clients: vec![("almalinux".into(), alma_client)],
        registry,
        metrics,
        limits,
        request_slots: Arc::new(tokio::sync::Semaphore::new(limits.request_slots)),
        active_bodies: Arc::new(tokio::sync::Semaphore::new(limits.active_bodies)),
        cold_clients: Default::default(),
        authority: "fixture.test".into(),
        trust_proxy_ip: true,
        request_ids: std::sync::atomic::AtomicU64::new(0),
        prefix: ferrum_apt::path::RepositoryPath::parse_decoded("fixture").expect("prefix"),
    });

    let reply = request(
        &state,
        Method::GET,
        "/almalinux/9/BaseOS/x86_64/os/repodata/repomd.xml",
        None,
    )
    .await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.headers()["cache-control"], "no-cache");
    assert_eq!(
        to_bytes(reply.into_body(), 1024 * 1024)
            .await
            .expect("repomd.xml"),
        repomd_xml.as_bytes()
    );

    let reply = request(
        &state,
        Method::GET,
        "/almalinux/9/BaseOS/x86_64/os/Packages/bash-5.2.15-2.el9.x86_64.rpm",
        None,
    )
    .await;
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(reply.into_body(), 1024 * 1024).await.expect("rpm"),
        rpm_bytes.as_slice()
    );

    state.registry.shutdown().await;
    origin.shutdown().await;
}

#[tokio::test]
#[ignore = "Linux, ferrum-verifier 0.2.0 on PATH, prlimit, and generated fixture/public/b09"]
async fn retired_catalog_closes_routes_but_preserves_shared_package_authority() {
    let harness = Harness::new().await;
    let key = keys().remove(0);
    let active_key = keys().remove(1);
    let before = harness.publisher.state(&key).expect("retained checkpoint");
    let view = harness.view(&key);
    let package_path = ferrum_apt::path::RepositoryPath::parse_decoded(
        "pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb",
    )
    .expect("package path");
    let scope = ferrum_storage::checkpoint::PackageScope::new(std::slice::from_ref(&active_key))
        .expect("active-only package scope");
    let package = harness
        .publisher
        .lookup_package_in("debian", &package_path, &scope)
        .await
        .expect("scoped shared package lookup")
        .expect("active suite retains the shared package");
    assert_eq!(package.generation().suite, active_key.suite());

    let index = representation(&view, INDEX).await;
    let alias = format!(
        "/debian/dists/trixie/main/binary-amd64/by-hash/SHA256/{}",
        Sha256Digest::of(&index)
    );
    let retired = Catalog::configured(Vec::new(), harness.publisher.clone())
        .expect("all suites explicitly retired");
    assert!(
        !retired.is_fixture(),
        "empty durable selection is not fixture authority"
    );
    assert!(!retired.suite_available(&view).await);
    assert!(!retired.current_view_available(&view).await);

    let mut state = http_state(&harness, Duration::from_secs(5));
    Arc::get_mut(&mut state)
        .expect("unshared HTTP state")
        .catalog = Arc::new(retired);
    for path in [
        "/debian/dists/trixie/InRelease",
        "/debian/dists/trixie/main/binary-amd64/Packages.gz",
        alias.as_str(),
        "/debian/pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb",
    ] {
        assert_eq!(
            request(&state, Method::GET, path, None).await.status(),
            StatusCode::NOT_FOUND,
            "retired route {path}"
        );
    }
    let after = harness.publisher.state(&key).expect("unchanged checkpoint");
    assert_eq!(after.active, before.active);
    assert_eq!(after.floor, before.floor);
    assert!(
        harness
            .publisher
            .lookup_package("debian", &package_path)
            .await
            .expect("retained lookup")
            .is_some(),
        "serving selection must not destroy recovery authority"
    );

    state.registry.shutdown().await;
    harness.shutdown().await;
}
