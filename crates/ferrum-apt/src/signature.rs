//! OpenPGP signature verification through the external `ferrum-verifier` helper.
//!
//! The helper enforces signature-time validity and current certificate/key policy.
//! Linux `prlimit` enforces file size, address space and CPU limits.
//! An owned supervisor kills and reaps on timeout, diagnostic overflow or caller
//! cancellation before removing provisional output and releasing scratch guards.
//! CPU admission is cancellation-aware and retained until the child is reaped,
//! independently of scratch guards retained after provisional-output unlink errors.
//! Only a successful exit permits reading the authenticated, bounded Release.

use std::collections::hash_map::RandomState;
use std::ffi::OsString;
use std::hash::BuildHasher;
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::oneshot;

/// One process-wide two-job gate for signature verification and metadata decode.
/// Verifier admission is internal; callers acquire only for other CPU work.
pub fn cpu_gate() -> std::sync::Arc<tokio::sync::Semaphore> {
    static CPU: std::sync::LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| std::sync::Arc::new(tokio::sync::Semaphore::new(2)));
    CPU.clone()
}

/// Exact helper protocol supported by this client; stock sqv is not compatible.
const PROTOCOL_VERSION: &str = "0.2.0";

/// Bytes of stderr (and `--version` stdout) retained for diagnostics.
const CAPTURE_CAP: usize = 64 * 1024;

/// Release, InRelease, detached signature and keyring input ceiling (§2).
const INPUT_CAP: u64 = 32 * 1024 * 1024;

/// Only detached package data may use the admitted package ceiling of 8 GiB.
const PACKAGE_CAP: u64 = 8 * 1024 * 1024 * 1024;
const PRLIMIT: &str = "/usr/bin/prlimit";

/// Why verification could not establish trust.
#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("signature verifier not found at {0}")]
    VerifierMissing(PathBuf),
    #[error("signature verifier version output not understood: {0:?}")]
    UnparseableVersion(String),
    #[error("signature verifier exceeded its timeout and was killed")]
    Timeout,
    #[error("signature rejected (verifier status {status:?}): {stderr}")]
    Rejected { status: Option<i32>, stderr: String },
    #[error("authenticated output exceeds the configured limit")]
    OutputTooLarge,
    #[error("signature verifier input is not a regular file within the 32 MiB limit: {0}")]
    InputTooLarge(PathBuf),
    #[error(
        "package signature input must be a regular file of exactly {expected_size} bytes within the 8 GiB limit: {path}"
    )]
    PackageInput { path: PathBuf, expected_size: u64 },
    #[error("signature verifier diagnostic output reached its 64 KiB limit")]
    DiagnosticsTooLarge,
    #[error("signature verification cancelled")]
    Cancelled,
    #[error("signature verifier cleanup failed; scratch reservation retained: {0}")]
    Cleanup(String),
    #[error("signature verifier I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Handle to a capability-checked `ferrum-verifier` binary.
#[derive(Debug, Clone)]
pub struct SignatureVerifier {
    binary: PathBuf,
    timeout: Duration,
    version: String,
}

struct Outcome {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl SignatureVerifier {
    /// Capability-checks the helper under the same resource limits as verification.
    ///
    /// Linux and util-linux's `prlimit` are runtime prerequisites. The wrapper
    /// must successfully apply hard/soft limits and execute helper protocol 0.2.0.
    /// The caller's timeout is capped at the RFC's 30 seconds.
    ///
    /// # Errors
    /// Missing/incompatible binaries, excessive diagnostics and timeout fail startup.
    pub async fn new(binary: PathBuf, timeout: Duration) -> Result<Self, SignatureError> {
        let timeout = timeout.min(Duration::from_secs(30));
        let probe_binary = binary.clone();
        let outcome = supervise((), move |mut cancelled| async move {
            run_bounded(
                &probe_binary,
                &[OsString::from("--version")],
                timeout,
                INPUT_CAP,
                true,
                &mut cancelled,
            )
            .await
        })
        .await?;
        if outcome.status.code() == Some(127) {
            return Err(SignatureError::VerifierMissing(binary));
        }
        let stdout = String::from_utf8_lossy(&outcome.stdout);
        if !outcome.status.success() {
            return Err(SignatureError::UnparseableVersion(format!(
                "{stdout}{}",
                String::from_utf8_lossy(&outcome.stderr)
            )));
        }
        let version_text = parse_version_line(&stdout)
            .ok_or_else(|| SignatureError::UnparseableVersion(stdout.trim().to_owned()))?;
        tracing::debug!(binary = %binary.display(), version = version_text, "signature verifier ready");
        Ok(Self {
            binary,
            timeout,
            version: version_text.to_owned(),
        })
    }

    /// The compatible protocol version reported by the binary.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Verifies a cleartext-signed `InRelease` and returns the authenticated body.
    ///
    /// The output is hard-limited to `min(max_output, 32 MiB)` while the helper runs.
    /// Input files must be regular, immutable private files of at most 32 MiB.
    /// The supervisor reaps and removes output even if this future is dropped.
    /// Owners of scratch reservations must use [`Self::verify_cleartext_owned`]
    /// so cancellation cannot release their accounting before cleanup completes.
    ///
    /// # Errors
    /// Nonzero exit, timeout, input/output/diagnostic limits and I/O fail closed.
    /// Cleanup errors are never a successful verification.
    pub async fn verify_cleartext(
        &self,
        keyring: &Path,
        inrelease: &Path,
        scratch_dir: &Path,
        max_output: u64,
    ) -> Result<Vec<u8>, SignatureError> {
        self.verify_cleartext_owned(keyring, inrelease, scratch_dir, max_output, ())
            .await
    }

    /// Like [`Self::verify_cleartext`], transferring a scratch-directory/reservation
    /// guard to the supervisor. The guard is released only after reaping and
    /// unlinking; cleanup failure or supervisor loss conservatively retains it.
    ///
    /// # Errors
    /// As [`Self::verify_cleartext`].
    pub async fn verify_cleartext_owned<G: Send + 'static>(
        &self,
        keyring: &Path,
        inrelease: &Path,
        scratch_dir: &Path,
        max_output: u64,
        guard: G,
    ) -> Result<Vec<u8>, SignatureError> {
        let verifier = self.clone();
        let keyring = keyring.to_owned();
        let inrelease = inrelease.to_owned();
        let output = scratch_dir.join(provisional_name());
        let max_output = max_output.min(INPUT_CAP);
        supervise(guard, move |mut cancelled| async move {
            check_input(&keyring).await?;
            check_input(&inrelease).await?;
            let arguments = [
                OsString::from("--keyring"),
                keyring.into_os_string(),
                OsString::from("--signatures"),
                OsString::from("1"),
                OsString::from("--cleartext"),
                OsString::from("--output"),
                output.as_os_str().to_owned(),
                inrelease.into_os_string(),
            ];
            let result = match verifier
                .run_expecting_success(&arguments, max_output, &mut cancelled)
                .await
            {
                Ok(()) => read_bounded_file(&output, max_output).await,
                Err(error) => Err(error),
            };
            // A reaping failure means the writer may still be alive. Never unlink
            // or free its reservation in that case.
            if matches!(&result, Err(SignatureError::Cleanup(_))) {
                return result;
            }
            remove_provisional(&output).await?;
            result
        })
        .await
    }

    /// Verifies detached signatures using the helper's `--signature-file SIG DATA` form.
    ///
    /// # Errors
    /// As [`Self::verify_cleartext`], without the output variants.
    pub async fn verify_detached(
        &self,
        keyring: &Path,
        data: &Path,
        signature: &Path,
    ) -> Result<(), SignatureError> {
        self.verify_detached_owned(keyring, data, signature, ())
            .await
    }

    /// Detached verification with an owned guard for the immutable input files.
    /// Cancellation reaps the verifier before releasing the guard.
    ///
    /// # Errors
    /// As [`Self::verify_detached`]; cleanup failure retains the guard.
    pub async fn verify_detached_owned<G: Send + 'static>(
        &self,
        keyring: &Path,
        data: &Path,
        signature: &Path,
        guard: G,
    ) -> Result<(), SignatureError> {
        let verifier = self.clone();
        let keyring = keyring.to_owned();
        let data = data.to_owned();
        let signature = signature.to_owned();
        supervise(guard, move |mut cancelled| async move {
            check_input(&keyring).await?;
            check_input(&data).await?;
            check_input(&signature).await?;
            let arguments = [
                OsString::from("--keyring"),
                keyring.into_os_string(),
                OsString::from("--signatures"),
                OsString::from("1"),
                OsString::from("--signature-file"),
                signature.into_os_string(),
                data.into_os_string(),
            ];
            verifier
                .run_expecting_success(&arguments, 0, &mut cancelled)
                .await
        })
        .await
    }

    /// Verifies the exact bytes of a detached-signed package, streaming at most
    /// 8 GiB through the helper. `expected_size` is the admitted package size;
    /// keyrings and detached signatures retain their separate 32 MiB ceilings.
    ///
    /// The caller must retain immutable private inputs in `guard`. Cancellation
    /// kills and reaps the helper before releasing that guard or CPU admission.
    ///
    /// # Errors
    /// Incorrect size, nonregular or changed input, invalid signatures, timeout,
    /// diagnostics and I/O fail closed. Cleanup failure retains the guard.
    pub async fn verify_package_owned<G: Send + 'static>(
        &self,
        keyring: &Path,
        data: &Path,
        signature: &Path,
        expected_size: u64,
        guard: G,
    ) -> Result<(), SignatureError> {
        let verifier = self.clone();
        let keyring = keyring.to_owned();
        let data = data.to_owned();
        let signature = signature.to_owned();
        supervise(guard, move |mut cancelled| async move {
            check_input(&keyring).await?;
            check_input(&signature).await?;
            check_package_input(&data, expected_size).await?;
            let arguments = [
                OsString::from("--keyring"),
                keyring.into_os_string(),
                OsString::from("--signatures"),
                OsString::from("1"),
                OsString::from("--package"),
                OsString::from("--expected-size"),
                OsString::from(expected_size.to_string()),
                OsString::from("--signature-file"),
                signature.into_os_string(),
                data.into_os_string(),
            ];
            verifier
                .run_expecting_success(&arguments, 0, &mut cancelled)
                .await
        })
        .await
    }

    async fn run_expecting_success(
        &self,
        arguments: &[OsString],
        max_output: u64,
        cancelled: &mut oneshot::Receiver<()>,
    ) -> Result<(), SignatureError> {
        let outcome = run_bounded(
            &self.binary,
            arguments,
            self.timeout,
            max_output,
            false,
            cancelled,
        )
        .await?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::ExitStatusExt;
            if outcome.status.signal() == Some(25) {
                return Err(SignatureError::OutputTooLarge);
            }
        }
        if outcome.status.success() {
            return Ok(());
        }
        Err(SignatureError::Rejected {
            status: outcome.status.code(),
            stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        })
    }
}

/// The cancellation sender lives in the calling future, not its detached task.
/// Dropping that future wakes the supervisor; dropping its JoinHandle never
/// aborts cleanup. ManuallyDrop retains accounting if the runtime drops the task.
async fn supervise<G, T, F, Fut>(guard: G, job: F) -> Result<T, SignatureError>
where
    G: Send + 'static,
    T: Send + 'static,
    F: FnOnce(oneshot::Receiver<()>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, SignatureError>> + Send + 'static,
{
    let (cancel, cancelled) = oneshot::channel();
    let (complete, completed) = oneshot::channel();
    // Establish conservative ownership before spawning: even a task never
    // polled by a shutting-down runtime cannot prematurely release the guard.
    let guard = ManuallyDrop::new(guard);
    tokio::spawn(async move {
        let result = job(cancelled).await;
        if !matches!(&result, Err(SignatureError::Cleanup(_))) {
            drop(ManuallyDrop::into_inner(guard));
        }
        // A cancelled caller has no result receiver; cleanup still ran.
        let _ = complete.send(result);
    });
    let result = completed
        .await
        .map_err(|_| SignatureError::Cleanup("supervisor did not complete".into()));
    drop(cancel);
    result?
}

async fn check_input(path: &Path) -> Result<(), SignatureError> {
    let metadata = tokio::fs::metadata(path).await?;
    if !metadata.is_file() || metadata.len() > INPUT_CAP {
        return Err(SignatureError::InputTooLarge(path.to_owned()));
    }
    Ok(())
}

async fn check_package_input(path: &Path, expected_size: u64) -> Result<(), SignatureError> {
    let invalid = || SignatureError::PackageInput {
        path: path.to_owned(),
        expected_size,
    };
    if expected_size > PACKAGE_CAP {
        return Err(invalid());
    }
    let metadata = tokio::fs::metadata(path).await?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err(invalid());
    }
    Ok(())
}

/// A kernel-enforced file-size ceiling has no polling interval or overshoot.
/// Both diagnostic pipes stop at their cap; errors cancel the joined wait and
/// explicitly kill/reap before returning. The deadline covers pipe EOF as well.
async fn run_bounded(
    binary: &Path,
    arguments: &[OsString],
    timeout: Duration,
    max_output: u64,
    capture_stdout: bool,
    cancelled: &mut oneshot::Receiver<()>,
) -> Result<Outcome, SignatureError> {
    let permit = tokio::select! {
        biased;
        _ = &mut *cancelled => return Err(SignatureError::Cancelled),
        permit = cpu_gate().acquire_owned() => {
            permit.map_err(|_| std::io::Error::other("CPU gate closed"))?
        }
    };
    let mut command = Command::new(PRLIMIT);
    command
        .arg(format!("--fsize={max_output}:{max_output}"))
        .arg("--core=0:0")
        .arg("--as=1073741824:1073741824")
        .arg("--cpu=30:30")
        .arg("--")
        .arg(binary)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(if capture_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            SignatureError::VerifierMissing(PathBuf::from(PRLIMIT))
        } else {
            SignatureError::Io(error)
        }
    })?;
    // From spawn until confirmed reaping, even supervisor/runtime loss must not
    // advertise free CPU capacity while the child might still be running.
    let permit = ManuallyDrop::new(permit);
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let collect = async {
        let (stdout, stderr, status) = tokio::try_join!(
            read_capped(stdout, CAPTURE_CAP),
            read_capped(stderr, CAPTURE_CAP),
            async { child.wait().await.map_err(SignatureError::Io) }
        )?;
        Ok(Outcome {
            status,
            stdout,
            stderr,
        })
    };
    let result = tokio::select! {
        biased;
        _ = cancelled => Err(SignatureError::Cancelled),
        result = tokio::time::timeout(timeout, collect) => {
            result.unwrap_or(Err(SignatureError::Timeout))
        }
    };
    if result.is_err() {
        child
            .kill()
            .await
            .map_err(|error| SignatureError::Cleanup(error.to_string()))?;
    }
    // kill().await also waits for exit. A failed kill/reap returns above and
    // retains this permit, while later provisional-output cleanup cannot.
    drop(ManuallyDrop::into_inner(permit));
    result
}

/// Stop reading at the cap instead of draining arbitrary child output.
async fn read_capped<R: AsyncRead + Unpin>(
    pipe: Option<R>,
    cap: usize,
) -> Result<Vec<u8>, SignatureError> {
    let Some(pipe) = pipe else {
        return Ok(Vec::new());
    };
    let mut retained = Vec::new();
    pipe.take(cap as u64).read_to_end(&mut retained).await?;
    if retained.len() == cap {
        return Err(SignatureError::DiagnosticsTooLarge);
    }
    Ok(retained)
}

/// Reads the provisional output, refusing anything above `max_output` bytes.
async fn read_bounded_file(path: &Path, max_output: u64) -> Result<Vec<u8>, SignatureError> {
    let file = tokio::fs::File::open(path).await?;
    if file.metadata().await?.len() > max_output {
        return Err(SignatureError::OutputTooLarge);
    }
    let limit = max_output.checked_add(1).unwrap_or(max_output);
    let mut body = Vec::new();
    file.take(limit).read_to_end(&mut body).await?;
    if u64::try_from(body.len()).map_or(true, |length| length > max_output) {
        return Err(SignatureError::OutputTooLarge);
    }
    Ok(body)
}

async fn remove_provisional(path: &Path) -> Result<(), SignatureError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SignatureError::Cleanup(format!(
            "{}: {error}",
            path.display()
        ))),
    }
}

/// Unpredictable file name for provisional output; the helper creates it with
/// exclusive semantics, so a collision fails closed instead of reusing a file.
/// The on-disk prefix remains stable so startup also cleans pre-cutover output.
fn provisional_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let random = RandomState::new().hash_one(nanos);
    format!(
        "sqv-{}-{nanos:x}-{random:016x}.provisional",
        std::process::id()
    )
}

/// Accepts only the complete version response for our explicitly supported protocol.
fn parse_version_line(stdout: &str) -> Option<&str> {
    let line = stdout.strip_suffix('\n').unwrap_or(stdout);
    let version = line.strip_prefix("ferrum-verifier ")?;
    (version == PROTOCOL_VERSION).then_some(version)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn version_probe_requires_the_exact_helper_protocol() {
        assert_eq!(parse_version_line("ferrum-verifier 0.2.0\n"), Some("0.2.0"));
        assert_eq!(parse_version_line("ferrum-verifier 0.2.0"), Some("0.2.0"));
        for incompatible in [
            "sqv 1.3.0\n",
            "sqv 2.0.0\n",
            "gpgv (GnuPG) 2.4.7\n",
            "ferrum-verifier 0.0.9\n",
            "ferrum-verifier 0.1.0\n",
            "ferrum-verifier 0.3.0\n",
            "ferrum-verifier 0.2.0-extra\n",
            "ferrum-verifier 0.1\n",
            "ferrum-verifier 0.2.0 additional-output\n",
            "ferrum-verifier 0.2.0\nunexpected second line\n",
            "",
        ] {
            assert!(
                parse_version_line(incompatible).is_none(),
                "{incompatible:?}"
            );
        }
    }
}
