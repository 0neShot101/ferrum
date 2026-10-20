//! Dedicated durable administration boundary, separate from the public gateway.
#![allow(clippy::result_large_err)]
mod assets;
pub mod migration;
pub mod model;
mod overview;
pub(crate) mod password;
pub(crate) mod routes;
pub mod store;

pub mod inventory;
pub mod jobs;
pub mod settings;
pub mod telemetry;
pub mod workspaces;
pub use model::{AuthContext, Permission, StoreError, UserView};
pub use routes::{routes, security_boundary};
pub use store::AdminStore;
pub(crate) async fn authorize_metrics(
    state: &crate::health::HealthState,
    headers: &axum::http::HeaderMap,
) -> Result<(), axum::response::Response> {
    routes::authenticate(state, headers, false, Some(Permission::ViewStatus))
        .await
        .map(|_| ())
}

use axum::http::{HeaderMap, Uri, header};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Host-controlled HTTP policy and preloaded static assets. Construct before serving.
pub struct AdminHttpState {
    origin: String,
    host: String,
    secure: bool,
    assets: assets::Assets,
    cache_operation: std::sync::Arc<tokio::sync::Semaphore>,
    admission: Mutex<LoginAdmission>,
}
impl AdminHttpState {
    pub fn new(origin: &str) -> Result<Self, String> {
        let uri: Uri = origin.parse().map_err(|_| "Invalid admin origin")?;
        let scheme = uri.scheme_str().ok_or("Admin origin requires a scheme")?;
        let authority = uri.authority().ok_or("Admin origin requires a host")?;
        if !matches!(scheme, "http" | "https")
            || authority.as_str().contains('@')
            || authority.port().is_some() && authority.port_u16().is_none()
            || uri
                .path_and_query()
                .is_some_and(|path| path.as_str() != "/")
        {
            return Err("Admin origin must be an exact HTTP(S) origin".into());
        }
        if scheme == "http" {
            let host = authority.host().trim_matches(['[', ']']);
            if host != "localhost"
                && !host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
            {
                return Err("Non-Secure admin cookies require a loopback origin".into());
            }
        }
        Ok(Self {
            origin: format!("{scheme}://{authority}"),
            host: authority.as_str().to_ascii_lowercase(),
            secure: scheme == "https",
            assets: assets::Assets::load()?,
            admission: Mutex::new(LoginAdmission::new()),
            cache_operation: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
    fn valid_host(&self, headers: &HeaderMap) -> bool {
        let mut hosts = headers.get_all(header::HOST).iter();
        let valid = hosts
            .next()
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case(&self.host));
        valid && hosts.next().is_none()
    }
    fn valid_origin(&self, headers: &HeaderMap) -> bool {
        let mut origins = headers.get_all(header::ORIGIN).iter();
        let valid =
            origins.next().and_then(|value| value.to_str().ok()) == Some(self.origin.as_str());
        valid && origins.next().is_none()
    }
    fn admit_login(&self, source: IpAddr, username: &str) -> bool {
        self.admission
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .admit(source, username, Instant::now())
    }
}
struct Bucket {
    tokens: f64,
    updated: Instant,
}
impl Bucket {
    fn new(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            updated: now,
        }
    }
    fn take(&mut self, capacity: f64, per_second: f64, now: Instant) -> bool {
        self.tokens = (self.tokens + now.duration_since(self.updated).as_secs_f64() * per_second)
            .min(capacity);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}
struct LoginAdmission {
    global: Bucket,
    sources: BTreeMap<IpAddr, Bucket>,
    accounts: BTreeMap<String, Bucket>,
}
impl LoginAdmission {
    fn new() -> Self {
        Self {
            global: Bucket::new(10.0, Instant::now()),
            sources: BTreeMap::new(),
            accounts: BTreeMap::new(),
        }
    }
    fn admit(&mut self, source: IpAddr, account: &str, now: Instant) -> bool {
        if !self.global.take(10.0, 2.0, now) {
            return false;
        }
        let idle = Duration::from_secs(15 * 60);
        self.sources
            .retain(|_, bucket| now.duration_since(bucket.updated) < idle);
        self.accounts
            .retain(|_, bucket| now.duration_since(bucket.updated) < idle);
        let needed = usize::from(!self.sources.contains_key(&source))
            + usize::from(!self.accounts.contains_key(account));
        if self.sources.len() + self.accounts.len() + needed > 1024 {
            return false;
        }
        if !self
            .sources
            .entry(source)
            .or_insert_with(|| Bucket::new(5.0, now))
            .take(5.0, 20.0 / 60.0, now)
        {
            return false;
        }
        self.accounts
            .entry(account.to_owned())
            .or_insert_with(|| Bucket::new(5.0, now))
            .take(5.0, 5.0 / 60.0, now)
    }
}
#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn rate_admission_is_bounded_before_hashing() {
        let now = Instant::now();
        let mut admission = LoginAdmission::new();
        let source = IpAddr::from([127, 0, 0, 1]);
        for _ in 0..5 {
            assert!(admission.admit(source, "admin", now));
        }
        assert!(!admission.admit(source, "admin", now));
        assert!(admission.admit(source, "admin", now + Duration::from_secs(12)));
    }
    #[test]
    fn external_plaintext_origin_is_rejected() {
        assert!(AdminHttpState::new("http://example.com:8081").is_err());
        assert!(AdminHttpState::new("http://127.0.0.1:8081/path").is_err());
        assert!(AdminHttpState::new("http://user@127.0.0.1:8081").is_err());
    }
}

#[cfg(test)]
mod tests;
