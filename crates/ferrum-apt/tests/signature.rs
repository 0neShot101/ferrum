//! Behavioral tests for the external `ferrum-verifier` supervisor.
//!
//! Adversarial child processes exercise Linux's real `prlimit`, timeout, reaping
//! and cleanup boundaries. Real trust verdicts use static vectors under
//! `tests/data/` and ferrum-verifier 0.2.0 located through `FERRUM_VERIFIER` or
//! `PATH`; without one they fail unless `FERRUM_SKIP_VERIFIER_TESTS=1`.
#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, Instant};

use ferrum_apt::digest::Sha256Digest;
use ferrum_apt::release::{ParseLimits, Release};
use ferrum_apt::signature::{SignatureError, SignatureVerifier};

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");
const TIMEOUT: Duration = Duration::from_secs(30);

fn data(name: &str) -> PathBuf {
    Path::new(DATA).join(name)
}

/// Writes an executable `/bin/sh` stand-in answering the helper protocol probe
/// and otherwise runs `body` with the original arguments.
fn fake_verifier(dir: &Path, version_line: &str, body: &str) -> PathBuf {
    let path = dir.join("ferrum-verifier");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"{version_line}\"; exit 0; fi\n{body}\n"
    );
    std::fs::write(&path, script).expect("write adversarial helper");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod adversarial helper");
    path
}

/// Shell snippet that finds the `--output` argument and stores it in `$out`.
const FIND_OUTPUT: &str = "out=\"\"\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=\"$2\"; shift; fi\n  shift\ndone\n";

fn is_empty_dir(path: &Path) -> bool {
    std::fs::read_dir(path)
        .expect("read scratch dir")
        .next()
        .is_none()
}

fn real_helper() -> Option<PathBuf> {
    static SKIP_NOTICE: Once = Once::new();
    if let Some(configured) = std::env::var_os("FERRUM_VERIFIER") {
        return Some(PathBuf::from(configured));
    }
    let found = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("ferrum-verifier"))
            .find(|candidate| candidate.is_file())
    });
    if found.is_some() {
        return found;
    }
    if std::env::var_os("FERRUM_SKIP_VERIFIER_TESTS").is_some_and(|value| value == "1") {
        SKIP_NOTICE.call_once(|| {
            println!("skipped: ferrum-verifier not found; FERRUM_SKIP_VERIFIER_TESTS=1");
        });
        return None;
    }
    panic!(
        "ferrum-verifier 0.2.0 not found: build -p ferrum-verifier and put target/debug on PATH, \
         set FERRUM_VERIFIER=/path/to/ferrum-verifier, or explicitly set FERRUM_SKIP_VERIFIER_TESTS=1"
    );
}

async fn real_verifier() -> Option<SignatureVerifier> {
    let binary = real_helper()?;
    Some(
        SignatureVerifier::new(binary, TIMEOUT)
            .await
            .expect("real ferrum-verifier must be usable"),
    )
}

#[tokio::test]
async fn missing_binary_is_a_startup_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let absent = dir.path().join("absent-verifier");
    let error = SignatureVerifier::new(absent.clone(), TIMEOUT)
        .await
        .expect_err("absent binary");
    assert!(matches!(error, SignatureError::VerifierMissing(path) if path == absent));
}

#[tokio::test]
async fn stock_sqv_and_incompatible_helper_protocols_are_refused_at_startup() {
    let dir = tempfile::tempdir().expect("tempdir");
    for response in [
        "sqv 1.3.0 (sequoia-openpgp 2.0.0)",
        "sqv 2.0.0",
        "gpgv (GnuPG) 2.4.7",
        "ferrum-verifier 0.0.9",
        "ferrum-verifier 0.1.0",
        "ferrum-verifier 0.3.0",
        "ferrum-verifier 0.2.0-extra",
        "ferrum-verifier 0.2.0\nunexpected second line",
    ] {
        let binary = fake_verifier(dir.path(), response, "exit 0");
        let error = SignatureVerifier::new(binary, TIMEOUT)
            .await
            .expect_err("incompatible protocol cannot establish the required trust policy");
        assert!(
            matches!(error, SignatureError::UnparseableVersion(_)),
            "{response:?}: {error}"
        );
    }
}

#[tokio::test]
async fn hanging_verifier_is_killed_at_timeout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", "exec sleep 30");
    let verifier = SignatureVerifier::new(binary, Duration::from_millis(300))
        .await
        .expect("version probe");
    let started = Instant::now();
    let error = verifier
        .verify_detached(&data("keyring.gpg"), &data("Release"), &data("Release.gpg"))
        .await
        .expect_err("hang must time out");
    assert!(matches!(error, SignatureError::Timeout));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "timeout must kill the child"
    );
}

#[tokio::test]
async fn rejection_reports_status_and_diagnostics() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = "printf 'rejected by test policy' >&2\nexit 3";
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", body);
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let error = verifier
        .verify_detached(&data("keyring.gpg"), &data("Release"), &data("Release.gpg"))
        .await
        .expect_err("exit 3 is a rejection");
    match error {
        SignatureError::Rejected { status, stderr } => {
            assert_eq!(status, Some(3));
            assert_eq!(stderr, "rejected by test policy");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test]
async fn cleartext_output_is_bounded_and_provisional_file_always_removed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).expect("scratch dir");
    let body = format!("{FIND_OUTPUT}printf '0123456789' > \"$out\" || exit 1\nexit 0");
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", &body);
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");

    let error = verifier
        .verify_cleartext(&data("keyring.gpg"), &data("InRelease"), &scratch, 9)
        .await
        .expect_err("ten bytes exceed a nine-byte limit");
    assert!(matches!(
        error,
        SignatureError::OutputTooLarge | SignatureError::Rejected { .. }
    ));
    assert!(is_empty_dir(&scratch), "oversized output must be deleted");

    let body = verifier
        .verify_cleartext(&data("keyring.gpg"), &data("InRelease"), &scratch, 10)
        .await
        .expect("exact limit is allowed");
    assert_eq!(body, b"0123456789");
    assert!(
        is_empty_dir(&scratch),
        "authenticated output must be deleted after reading"
    );

    let failing = format!("{FIND_OUTPUT}printf 'partial' > \"$out\"\necho bad >&2\nexit 1");
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", &failing);
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let error = verifier
        .verify_cleartext(&data("keyring.gpg"), &data("InRelease"), &scratch, 1024)
        .await
        .expect_err("exit 1 is a rejection");
    assert!(matches!(
        error,
        SignatureError::Rejected {
            status: Some(1),
            ..
        }
    ));
    assert!(
        is_empty_dir(&scratch),
        "provisional output must be deleted on rejection"
    );
}

#[tokio::test]
async fn unbounded_diagnostics_terminate_without_draining_forever() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = fake_verifier(
        dir.path(),
        "ferrum-verifier 0.2.0",
        "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' >&2; done",
    );
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let started = Instant::now();
    let error = verifier
        .verify_detached(&data("keyring.gpg"), &data("Release"), &data("Release.gpg"))
        .await
        .expect_err("diagnostic overflow must stop the verifier");
    assert!(matches!(error, SignatureError::DiagnosticsTooLarge));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn kernel_limit_prevents_output_growth_past_reserved_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).expect("scratch dir");
    let observed = dir.path().join("observed-length");
    // Ignore SIGXFSZ to exercise the EFBIG path too: even a writer that survives
    // the signal cannot extend the file past the hard limit.
    let body = format!(
        "{FIND_OUTPUT}trap '' XFSZ\n\
         dd if=/dev/zero of=\"$out\" bs=1048576 count=4 2>/dev/null\n\
         wc -c < \"$out\" > '{}'\nexit 1",
        observed.display(),
    );
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", &body);
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let error = verifier
        .verify_cleartext(&data("keyring.gpg"), &data("InRelease"), &scratch, 4096)
        .await
        .expect_err("attempted 4 MiB output cannot verify within 4 KiB");
    assert!(matches!(error, SignatureError::Rejected { .. }));
    let length: u64 = std::fs::read_to_string(observed)
        .expect("writer recorded its size before cleanup")
        .trim()
        .parse()
        .expect("file length");
    assert_eq!(length, 4096, "kernel must prevent even temporary overshoot");
    assert!(is_empty_dir(&scratch));
}

#[tokio::test]
async fn verifier_inherits_hard_and_soft_resource_limits() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Shell builtins report limits inherited from the real prlimit supervisor,
    // not command-line text emitted by a mock prlimit.
    let binary = fake_verifier(
        dir.path(),
        "ferrum-verifier 0.2.0",
        "{ ulimit -S -v; ulimit -H -v; ulimit -S -t; ulimit -H -t; \
         ulimit -S -f; ulimit -H -f; ulimit -S -c; ulimit -H -c; } >&2\nexit 3",
    );
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let error = verifier
        .verify_detached(&data("keyring.gpg"), &data("Release"), &data("Release.gpg"))
        .await
        .expect_err("child reports inherited limits through a rejection");
    match error {
        SignatureError::Rejected { status, stderr } => {
            assert_eq!(status, Some(3));
            assert_eq!(
                stderr.lines().collect::<Vec<_>>(),
                ["1048576", "1048576", "30", "30", "0", "0", "0", "0"]
            );
        }
        other => panic!("unexpected supervisor error: {other}"),
    }
}

#[test]
fn address_space_limit_child() {
    if std::env::var_os("FERRUM_ADDRESS_SPACE_CHILD").is_none() {
        return;
    }
    // The allocation must fail without touching 2 GiB of physical memory.
    let mut allocation = Vec::<u8>::new();
    if allocation
        .try_reserve_exact(2 * 1024 * 1024 * 1024)
        .is_err()
    {
        eprintln!("address-space allocation refused");
        std::process::exit(42);
    }
    std::process::exit(43);
}

#[tokio::test]
async fn kernel_address_space_limit_refuses_an_oversized_allocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let executable = std::env::current_exe().expect("test executable");
    let executable = executable
        .to_str()
        .expect("UTF-8 test executable")
        .replace('\'', "'\\''");
    let binary = fake_verifier(
        dir.path(),
        "ferrum-verifier 0.2.0",
        &format!(
            "export FERRUM_ADDRESS_SPACE_CHILD=1\n\
             exec '{executable}' --exact address_space_limit_child --nocapture"
        ),
    );
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let error = verifier
        .verify_detached(&data("keyring.gpg"), &data("Release"), &data("Release.gpg"))
        .await
        .expect_err("kernel must refuse the allocation");
    match error {
        SignatureError::Rejected { status, stderr } => {
            assert_eq!(status, Some(42));
            assert!(
                stderr.contains("address-space allocation refused"),
                "{stderr}"
            );
        }
        other => panic!("unexpected supervisor error: {other}"),
    }
}

#[tokio::test]
async fn kernel_cpu_limit_terminates_a_spinning_verifier() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Shorten the inherited soft limit to exercise the kernel failure path
    // without spending the production 30-second CPU allowance.
    let binary = fake_verifier(
        dir.path(),
        "ferrum-verifier 0.2.0",
        "ulimit -S -t 1\nwhile :; do :; done",
    );
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let started = Instant::now();
    let error = verifier
        .verify_detached(&data("keyring.gpg"), &data("Release"), &data("Release.gpg"))
        .await
        .expect_err("kernel CPU limit must terminate the verifier");
    assert!(
        matches!(error, SignatureError::Rejected { status: None, .. }),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn oversized_inputs_are_refused_before_verifier_execution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).expect("scratch dir");
    let oversized = dir.path().join("oversized");
    std::fs::File::create(&oversized)
        .expect("sparse input")
        .set_len(32 * 1024 * 1024 + 1)
        .expect("input size");
    let marker = dir.path().join("executed");
    let binary = fake_verifier(
        dir.path(),
        "ferrum-verifier 0.2.0",
        &format!("touch '{}'\nexit 0", marker.display()),
    );
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let error = verifier
        .verify_cleartext(&data("keyring.gpg"), &oversized, &scratch, 1024)
        .await
        .expect_err("oversized InRelease");
    assert!(matches!(error, SignatureError::InputTooLarge(_)));
    for (release, signature) in [
        (oversized.clone(), data("Release.gpg")),
        (data("Release"), oversized.clone()),
    ] {
        let error = verifier
            .verify_detached(&data("keyring.gpg"), &release, &signature)
            .await
            .expect_err("oversized detached input");
        assert!(matches!(error, SignatureError::InputTooLarge(_)));
    }
    assert!(!marker.exists(), "invalid inputs must not reach the helper");
    assert!(is_empty_dir(&scratch));
}

struct CleanupGuard {
    scratch: PathBuf,
    pid_file: PathBuf,
    completed: Option<tokio::sync::oneshot::Sender<bool>>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let pid = std::fs::read_to_string(&self.pid_file).expect("child pid");
        let reaped = !Path::new("/proc").join(pid.trim()).exists();
        if let Some(completed) = self.completed.take() {
            let _ = completed.send(reaped && is_empty_dir(&self.scratch));
        }
    }
}

async fn wait_for_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("child reached output-writing boundary");
}

#[tokio::test]
async fn timeout_reaps_and_unlinks_before_releasing_scratch_guard() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).expect("scratch dir");
    let pid_file = dir.path().join("pid");
    let body = format!(
        "{FIND_OUTPUT}printf 'partial' > \"$out\"\necho $$ > '{}'\nexec sleep 30",
        pid_file.display(),
    );
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", &body);
    let verifier = SignatureVerifier::new(binary, Duration::from_millis(500))
        .await
        .expect("version probe");
    let (completed, completion) = tokio::sync::oneshot::channel();
    let guard = CleanupGuard {
        scratch: scratch.clone(),
        pid_file,
        completed: Some(completed),
    };
    let error = verifier
        .verify_cleartext_owned(
            &data("keyring.gpg"),
            &data("InRelease"),
            &scratch,
            1024,
            guard,
        )
        .await
        .expect_err("timeout");
    assert!(matches!(error, SignatureError::Timeout));
    assert!(completion.await.expect("guard released after cleanup"));
}

#[tokio::test]
async fn dropping_caller_reaps_and_unlinks_before_releasing_scratch_guard() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).expect("scratch dir");
    let pid_file = dir.path().join("pid");
    let body = format!(
        "{FIND_OUTPUT}printf 'partial' > \"$out\"\necho $$ > '{}'\nexec sleep 30",
        pid_file.display(),
    );
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", &body);
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let (completed, completion) = tokio::sync::oneshot::channel();
    let guard = CleanupGuard {
        scratch: scratch.clone(),
        pid_file: pid_file.clone(),
        completed: Some(completed),
    };
    let caller = tokio::spawn(async move {
        verifier
            .verify_cleartext_owned(
                &data("keyring.gpg"),
                &data("InRelease"),
                &scratch,
                1024,
                guard,
            )
            .await
    });
    wait_for_file(&pid_file).await;
    caller.abort();
    assert!(caller.await.expect_err("caller aborted").is_cancelled());
    let cleaned = tokio::time::timeout(Duration::from_secs(5), completion)
        .await
        .expect("supervisor must clean up after caller cancellation")
        .expect("guard released");
    assert!(
        cleaned,
        "release requires both reaping and provisional unlink"
    );
}

#[tokio::test]
async fn cleanup_failure_retains_storage_guard_but_releases_reaped_child_cpu_capacity() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Reservation(Arc<AtomicBool>);
    impl Drop for Reservation {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).expect("scratch dir");
    let detached_started = dir.path().join("detached-started");
    std::fs::create_dir(&detached_started).expect("detached pid directory");
    // Directories make unlink fail even under a privileged runner. Their child
    // names record the actual verifier PID without writing a regular file.
    // Detached verification deliberately rejects: only real process progress,
    // not a fake trust verdict, is relevant to this resource-lifecycle test.
    let body = format!(
        "{FIND_OUTPUT}if [ -n \"$out\" ]; then\n  mkdir \"$out\" && mkdir \"$out/$$\" || exit 8\n  exit 0\nfi\nmkdir '{}'/\"$$\" || exit 8\nexit 7",
        detached_started.display(),
    );
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", &body);
    let verifier = SignatureVerifier::new(binary.clone(), TIMEOUT)
        .await
        .expect("version probe");
    // Leave exactly one slot for verification. Completion, not a sampled permit
    // count or a scheduling delay, proves each reaped process returned its slot.
    let _other_cpu_job = ferrum_apt::signature::cpu_gate()
        .acquire_owned()
        .await
        .expect("reserve the other CPU slot");
    let reservations: Vec<_> = (0..2).map(|_| Arc::new(AtomicBool::new(false))).collect();
    for released in &reservations {
        let error = tokio::time::timeout(
            TIMEOUT,
            verifier.verify_cleartext_owned(
                &data("keyring.gpg"),
                &data("InRelease"),
                &scratch,
                1024,
                Reservation(released.clone()),
            ),
        )
        .await
        .expect("a previous failed unlink must not block CPU admission")
        .expect_err("failed unlink is never success");
        assert!(matches!(error, SignatureError::Cleanup(_)));
        assert!(
            !released.load(Ordering::SeqCst),
            "accounting must remain reserved"
        );
    }
    let outputs: Vec<_> = std::fs::read_dir(&scratch)
        .expect("provisional outputs")
        .map(|entry| entry.expect("provisional directory").path())
        .collect();
    assert_eq!(
        outputs.len(),
        2,
        "failed unlinks leave both outputs reserved"
    );
    for output in outputs {
        let pid = std::fs::read_dir(output)
            .expect("verifier PID directory")
            .next()
            .expect("verifier recorded its PID")
            .expect("PID entry")
            .file_name();
        assert!(
            !Path::new("/proc").join(pid).exists(),
            "the process must already be reaped despite its retained output"
        );
    }
    let next_verifier = tokio::time::timeout(TIMEOUT, SignatureVerifier::new(binary, TIMEOUT))
        .await
        .expect("version probing must progress after failed unlinks")
        .expect("subsequent version probe");
    let error = tokio::time::timeout(
        TIMEOUT,
        next_verifier.verify_detached(&data("keyring.gpg"), &data("Release"), &data("Release.gpg")),
    )
    .await
    .expect("subsequent verification must obtain CPU capacity")
    .expect_err("adversarial helper deliberately rejects");
    assert!(matches!(
        error,
        SignatureError::Rejected {
            status: Some(7),
            ..
        }
    ));
    assert!(!is_empty_dir(&detached_started), "detached child executed");
    assert!(
        reservations
            .iter()
            .all(|released| !released.load(Ordering::SeqCst)),
        "subsequent verification must not release retained storage accounting"
    );
}

async fn input_cancellation(package: bool) {
    struct InputGuard {
        started: PathBuf,
        completed: Option<tokio::sync::oneshot::Sender<bool>>,
    }
    impl Drop for InputGuard {
        fn drop(&mut self) {
            let pid = std::fs::read_dir(&self.started)
                .expect("pid directory")
                .next()
                .expect("child announced pid")
                .expect("pid entry")
                .file_name();
            let reaped = !Path::new("/proc").join(pid).exists();
            if let Some(completed) = self.completed.take() {
                let _ = completed.send(reaped);
            }
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let started = dir.path().join("started");
    std::fs::create_dir(&started).expect("pid directory");
    // Detached verification forbids regular-file output entirely. A directory
    // communicates the PID without weakening that limit for this test.
    let body = format!("mkdir '{}'/\"$$\"\nexec sleep 30", started.display());
    let binary = fake_verifier(dir.path(), "ferrum-verifier 0.2.0", &body);
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let (completed, completion) = tokio::sync::oneshot::channel();
    let guard = InputGuard {
        started: started.clone(),
        completed: Some(completed),
    };
    let caller = tokio::spawn(async move {
        if package {
            verifier
                .verify_package_owned(
                    &data("keyring.gpg"),
                    &data("Release"),
                    &data("Release.gpg"),
                    std::fs::metadata(data("Release"))
                        .expect("package size")
                        .len(),
                    guard,
                )
                .await
        } else {
            verifier
                .verify_detached_owned(
                    &data("keyring.gpg"),
                    &data("Release"),
                    &data("Release.gpg"),
                    guard,
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while is_empty_dir(&started) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("detached child started");
    caller.abort();
    assert!(caller.await.expect_err("caller aborted").is_cancelled());
    assert!(
        tokio::time::timeout(Duration::from_secs(5), completion)
            .await
            .expect("cleanup completed")
            .expect("input guard released")
    );
}

#[tokio::test]
async fn detached_cancellation_reaps_before_releasing_input_guard() {
    input_cancellation(false).await;
}

#[tokio::test]
async fn package_cancellation_reaps_before_releasing_input_guard() {
    input_cancellation(true).await;
}

#[tokio::test]
async fn real_helper_accepts_valid_and_mixed_cleartext_signatures() {
    let Some(verifier) = real_verifier().await else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let release = std::fs::read(data("Release")).expect("Release vector");
    // The cleartext signature framework does not cover the final line break.
    let expected = release
        .strip_suffix(b"\n")
        .expect("Release ends with newline");
    for name in ["InRelease", "InRelease.mixed"] {
        let body = verifier
            .verify_cleartext(&data("keyring.gpg"), &data(name), dir.path(), 1 << 20)
            .await
            .unwrap_or_else(|error| panic!("{name} must verify: {error}"));
        assert_eq!(
            Sha256Digest::of(&body),
            Sha256Digest::of(expected),
            "{name}"
        );
        let parsed = Release::parse(&body, &ParseLimits::default()).expect("authenticated body");
        assert_eq!(parsed.origin, "FerrumTest");
        assert_eq!(parsed.suite.as_deref(), Some("ferrum-test"));
        assert!(parsed.acquire_by_hash);
        assert!(
            is_empty_dir(dir.path()),
            "{name}: provisional output left behind"
        );
    }
}

#[tokio::test]
async fn real_helper_rejects_untrusted_expired_revoked_and_tampered_cleartext() {
    let Some(verifier) = real_verifier().await else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, keyring) in [
        ("InRelease.unknown", "keyring.gpg"),
        ("InRelease.tampered", "keyring.gpg"),
        ("InRelease.expired", "keyring-expired.gpg"),
        ("InRelease.revoked", "keyring-revoked.gpg"),
        ("InRelease", "keyring-expired.gpg"),
    ] {
        let error = verifier
            .verify_cleartext(&data(keyring), &data(name), dir.path(), 1 << 20)
            .await
            .err()
            .unwrap_or_else(|| panic!("{name} with {keyring} must be rejected"));
        assert!(
            matches!(error, SignatureError::Rejected { .. }),
            "{name}: {error}"
        );
        assert!(
            is_empty_dir(dir.path()),
            "{name}: provisional output left behind"
        );
    }
}

#[tokio::test]
async fn real_helper_detached_verification_binds_signature_to_data() {
    let Some(verifier) = real_verifier().await else {
        return;
    };
    verifier
        .verify_detached(&data("keyring.gpg"), &data("Release"), &data("Release.gpg"))
        .await
        .expect("Release.gpg must verify Release");

    let dir = tempfile::tempdir().expect("tempdir");
    let tampered = dir.path().join("Release");
    let release = std::fs::read_to_string(data("Release")).expect("Release vector");
    std::fs::write(&tampered, release.replace("FerrumTest", "FerrumTampered"))
        .expect("write tampered");
    let error = verifier
        .verify_detached(&data("keyring.gpg"), &tampered, &data("Release.gpg"))
        .await
        .expect_err("modified data must be rejected");
    assert!(matches!(error, SignatureError::Rejected { .. }), "{error}");

    let error = verifier
        .verify_detached(
            &data("keyring-expired.gpg"),
            &data("Release"),
            &data("Release.gpg"),
        )
        .await
        .expect_err("wrong keyring must be rejected");
    assert!(matches!(error, SignatureError::Rejected { .. }), "{error}");
}

#[tokio::test]
async fn package_size_and_metadata_caps_reject_before_helper_execution() {
    const PACKAGE_CAP: u64 = 8 * 1024 * 1024 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let oversized = dir.path().join("oversized");
    std::fs::File::create(&oversized)
        .expect("sparse metadata input")
        .set_len(32 * 1024 * 1024 + 1)
        .expect("oversized metadata");
    let marker = dir.path().join("executed");
    let binary = fake_verifier(
        dir.path(),
        "ferrum-verifier 0.2.0",
        &format!("mkdir '{}'\nexit 7", marker.display()),
    );
    let verifier = SignatureVerifier::new(binary, TIMEOUT)
        .await
        .expect("version probe");
    let package = data("Release");
    let size = std::fs::metadata(&package).expect("package size").len();
    for expected_size in [size - 1, size + 1, PACKAGE_CAP + 1, u64::MAX] {
        let error = verifier
            .verify_package_owned(
                &data("keyring.gpg"),
                &package,
                &data("Release.gpg"),
                expected_size,
                (),
            )
            .await
            .expect_err("wrong or excessive package size");
        assert!(
            matches!(error, SignatureError::PackageInput { .. }),
            "{error}"
        );
    }
    for (keyring, signature) in [
        (oversized.clone(), data("Release.gpg")),
        (data("keyring.gpg"), oversized),
    ] {
        let error = verifier
            .verify_package_owned(&keyring, &package, &signature, size, ())
            .await
            .expect_err("package mode must not widen metadata input limits");
        assert!(matches!(error, SignatureError::InputTooLarge(_)), "{error}");
    }
    assert!(
        !marker.exists(),
        "rejected inputs must not execute a helper"
    );
}

#[tokio::test]
async fn real_helper_package_mode_authenticates_only_exact_admitted_bytes() {
    let Some(verifier) = real_verifier().await else {
        return;
    };
    let package = data("Release");
    let size = std::fs::metadata(&package).expect("package size").len();
    verifier
        .verify_package_owned(
            &data("keyring.gpg"),
            &package,
            &data("Release.gpg"),
            size,
            (),
        )
        .await
        .expect("binary package signature");
    let dir = tempfile::tempdir().expect("tempdir");
    let tampered = dir.path().join("package");
    let mut body = std::fs::read(package).expect("package vector");
    body[0] ^= 1;
    std::fs::write(&tampered, body).expect("same-size tampered package");
    let error = verifier
        .verify_package_owned(
            &data("keyring.gpg"),
            &tampered,
            &data("Release.gpg"),
            size,
            (),
        )
        .await
        .expect_err("same-size tampering must fail cryptographic verification");
    assert!(matches!(error, SignatureError::Rejected { .. }), "{error}");
}
