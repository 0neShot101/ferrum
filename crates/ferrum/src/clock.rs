//! One trusted host-clock policy for durable serving and offline deletion.
//! This observes system policy; it never changes the clock or host configuration.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, ensure};
use tokio::io::AsyncReadExt;

/// Requires an affirmative, bounded systemd clock-synchronization observation.
/// Missing tools, unknown state, oversized output and timeout all fail closed.
/// The child is killed and reaped on an inspection failure, never left running.
pub async fn require_synchronized_clock() -> anyhow::Result<()> {
    let mut child = tokio::process::Command::new("/usr/bin/timedatectl")
        .args(["show", "--property=NTPSynchronized", "--value"])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("trusted host clock inspection unavailable")?;
    let mut stdout = child
        .stdout
        .take()
        .context("clock inspection stdout unavailable")?;
    let inspection = async {
        let mut bytes = [0_u8; 65];
        let mut length = 0;
        loop {
            let count = stdout.read(&mut bytes[length..]).await?;
            if count == 0 {
                break;
            }
            length += count;
            ensure!(length < bytes.len(), "oversized clock inspection response");
        }
        let status = child.wait().await?;
        ensure!(
            status.success() && matches!(&bytes[..length], b"yes" | b"yes\n"),
            "host clock is not confirmed synchronized"
        );
        Ok::<(), anyhow::Error>(())
    };
    let result = match tokio::time::timeout(Duration::from_secs(3), inspection).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("host clock inspection deadline")),
    };
    if result.is_err()
        && child
            .try_wait()
            .context("clock inspection child status unavailable")?
            .is_none()
    {
        tokio::time::timeout(Duration::from_secs(3), child.kill())
            .await
            .context("clock inspection reap deadline")?
            .context("clock inspection kill/reap failed")?;
    }
    result
}
