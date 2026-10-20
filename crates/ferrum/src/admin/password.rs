//! Password work owns its concurrency permit until the blocking task finishes.
use super::model::StoreError;
use argon2::{
    Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version,
    password_hash::{PasswordHash, SaltString},
};
use ferrum_apt::digest::Sha256Hasher;
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

#[cfg(test)]
pub(crate) static TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
fn permits() -> &'static Arc<Semaphore> {
    static PERMITS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
    &PERMITS
}
fn algorithm() -> Result<Argon2<'static>, StoreError> {
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| StoreError::Unavailable)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}
pub(crate) fn validate(password: &str) -> Result<(), StoreError> {
    if (12..=1024).contains(&password.len()) {
        Ok(())
    } else {
        Err(StoreError::Invalid)
    }
}
pub(crate) fn random_token() -> String {
    format!(
        "{:032x}{:032x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    )
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    let mut h = Sha256Hasher::new();
    h.update(bytes);
    let d = h.finalize();
    let mut out = String::with_capacity(64);
    for b in d.as_bytes() {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}
pub(crate) fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
}
fn hash_sync(password: &str) -> Result<String, StoreError> {
    let salt =
        SaltString::encode_b64(&rand::random::<[u8; 16]>()).map_err(|_| StoreError::Unavailable)?;
    algorithm()?
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| StoreError::Unavailable)
}
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    let permit = permits()
        .clone()
        .try_acquire_owned()
        .map_err(|_| StoreError::Busy)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| StoreError::Unavailable)?
}
pub(crate) async fn hash(password: String) -> Result<String, StoreError> {
    validate(&password)?;
    blocking(move || hash_sync(&password)).await
}
/// Returns a replacement PHC only after a valid imported legacy hash.
pub(crate) async fn verify(password: String, stored: String) -> Result<Option<String>, StoreError> {
    if password.len() > 1024 {
        return Err(StoreError::Unauthorized);
    }
    blocking(move || {
        if let Some(legacy) = stored.strip_prefix("legacy:") {
            let (salt, expected) = legacy.split_once(':').ok_or(StoreError::Unavailable)?;
            let verified = constant_eq(&legacy_hash(salt, &password), expected);
            // Imported accounts must not acquire a cheap wrong-password timing path.
            let replacement = hash_sync(&password)?;
            if !verified {
                return Err(StoreError::Unauthorized);
            }
            return Ok(Some(replacement));
        }
        let parsed = PasswordHash::new(&stored).map_err(|_| StoreError::Unavailable)?;
        if parsed.algorithm.as_str() != "argon2id"
            || parsed.version != Some(19)
            || parsed.params.get("m").and_then(|v| v.decimal().ok()) != Some(65_536)
            || parsed.params.get("t").and_then(|v| v.decimal().ok()) != Some(3)
            || parsed.params.get("p").and_then(|v| v.decimal().ok()) != Some(1)
            || parsed.hash.as_ref().map(|h| h.len()) != Some(32)
        {
            return Err(StoreError::Unavailable);
        }
        algorithm()?
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| StoreError::Unauthorized)?;
        Ok(None)
    })
    .await
}
pub(crate) async fn dummy(_password: String) -> Result<(), StoreError> {
    let _ = hash("ferrum fixed dummy password".into()).await?;
    Err(StoreError::Unauthorized)
}
pub(crate) fn legacy_hash(salt: &str, password: &str) -> String {
    let mut state = [0u8; 32];
    for round in 0u32..50_000 {
        let mut h = Sha256Hasher::new();
        h.update(b"ferrum-admin-password-v1:");
        h.update(&state);
        h.update(b":");
        h.update(salt.as_bytes());
        h.update(b":");
        h.update(&round.to_le_bytes());
        h.update(b":");
        h.update(password.as_bytes());
        state = *h.finalize().as_bytes();
    }
    let mut out = String::with_capacity(64);
    for b in state {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn argon_parameters_and_legacy_upgrade() {
        let _serial = TEST_LOCK.lock().await;
        let phc = hash("a sufficiently long password".into()).await.unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(verify("wrong password".into(), phc.clone()).await.is_err());
        assert_eq!(
            verify("a sufficiently long password".into(), phc)
                .await
                .unwrap(),
            None
        );
        let legacy = format!("legacy:salt:{}", legacy_hash("salt", "old-password"));
        assert!(
            verify("old-password".into(), legacy)
                .await
                .unwrap()
                .unwrap()
                .starts_with("$argon2id$")
        );
    }
    #[tokio::test]
    async fn saturation_rejects_without_queued_hashes() {
        let _serial = TEST_LOCK.lock().await;
        let a = permits().clone().acquire_owned().await.unwrap();
        let b = permits().clone().acquire_owned().await.unwrap();
        assert_eq!(
            hash("valid password here".into()).await.unwrap_err(),
            StoreError::Busy
        );
        drop((a, b));
    }
    #[tokio::test]
    async fn cancelled_request_does_not_release_executing_permit() {
        let _serial = TEST_LOCK.lock().await;
        let other = permits().clone().acquire_owned().await.unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::sync_channel(1);
        let request = tokio::spawn(blocking(move || {
            let _ = started.send(());
            blocked.recv().unwrap();
            Ok(())
        }));
        ready.await.unwrap();
        request.abort();
        assert_eq!(permits().available_permits(), 0);
        assert_eq!(
            hash("valid password here".into()).await.unwrap_err(),
            StoreError::Busy
        );
        release.send(()).unwrap();
        let completed = permits().clone().acquire_owned().await.unwrap();
        drop((completed, other));
    }
}
