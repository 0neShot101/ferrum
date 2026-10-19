//! Outbound HTTP clients bound to fixed repository origins or the private fixture.
//!
//! URLs are built by appending validated [`RepositoryPath`] segments to the base;
//! no client-supplied host or path ever reaches the connector. Redirects and
//! environment proxies are disabled (`PLAN.md` §7).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ferrum_apt::path::RepositoryPath;
use futures_util::{Stream, stream};
use http::{Method, StatusCode};
use reqwest::redirect::Policy;
use thiserror::Error;
use tokio::sync::Semaphore;
use url::Url;

use crate::config::Limits;

/// Classified failure of one origin request (`PLAN.md` §7 taxonomy).
#[derive(Debug, Clone, Error)]
pub enum SourceError {
    /// Origin answered 404 or 410: confirmed absence.
    #[error("origin reports the object absent")]
    NotFound,
    /// Origin answered 403.
    #[error("origin refused the request")]
    Forbidden,
    /// Origin answered 408, 429 or 5xx, or the connection failed.
    #[error("transient origin failure: {0}")]
    Transient(String),
    /// Response headers did not arrive within the header timeout, or a read idled.
    #[error("origin timed out")]
    Timeout,
    /// The origin's declared length contradicts the signed size.
    #[error("origin response contradicts the signed descriptor: {0}")]
    Corrupt(String),
    /// Any other status.
    #[error("unexpected origin status {0}")]
    Unexpected(u16),
    /// Body transfer failed mid-stream (reset, truncation, idle timeout).
    #[error("origin body transfer failed: {0}")]
    Io(String),
}

#[derive(Debug, Default)]
struct Circuit {
    failures: u8,
    open_until: Option<Instant>,
    probing: bool,
}

struct SourcePermit {
    circuit: Arc<Mutex<Circuit>>,
    half_open: bool,
    completed: bool,
}

impl SourcePermit {
    fn acquire(circuit: &Arc<Mutex<Circuit>>) -> Result<Self, SourceError> {
        let mut state = circuit.lock().unwrap_or_else(|error| error.into_inner());
        let half_open = state.open_until.is_some();
        if state.probing || state.open_until.is_some_and(|until| until > Instant::now()) {
            return Err(SourceError::Transient("origin circuit is open".to_owned()));
        }
        if half_open {
            state.probing = true;
        }
        Ok(Self {
            circuit: Arc::clone(circuit),
            half_open,
            completed: false,
        })
    }

    fn finish(mut self, transient: bool) {
        self.completed = true;
        let mut state = self
            .circuit
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.open_until.is_some() && !self.half_open {
            return;
        }
        state.probing = false;
        if transient {
            state.failures = state.failures.saturating_add(1);
            if state.failures >= 5 || self.half_open {
                state.open_until = Some(Instant::now() + Duration::from_secs(30));
            }
        } else {
            state.failures = 0;
            state.open_until = None;
        }
    }
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        if self.half_open && !self.completed {
            let mut state = self
                .circuit
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.probing = false;
            state.open_until = Some(Instant::now() + Duration::from_secs(30));
        }
    }
}

fn transient(error: &SourceError) -> bool {
    matches!(
        error,
        SourceError::Transient(_) | SourceError::Timeout | SourceError::Io(_)
    )
}

/// A 200 response whose headers passed classification; the body is unverified.
pub struct SourceResponse {
    content_length: Option<u64>,
    response: reqwest::Response,
    permit: Option<SourcePermit>,
}

impl SourceResponse {
    /// Declared `Content-Length`, if any.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// Bounded body chunks as produced by the transport.
    pub fn into_stream(
        self,
    ) -> impl Stream<Item = Result<Bytes, SourceError>> + Send + Unpin + 'static {
        Box::pin(stream::unfold(self, |mut source| async move {
            source.permit.as_ref()?;
            match source.response.chunk().await {
                Ok(Some(chunk)) => Some((Ok(chunk), source)),
                Ok(None) => {
                    if let Some(permit) = source.permit.take() {
                        permit.finish(false);
                    }
                    None
                }
                Err(error) => {
                    if let Some(permit) = source.permit.take() {
                        permit.finish(true);
                    }
                    let error = if error.is_timeout() {
                        SourceError::Timeout
                    } else {
                        SourceError::Io(error.to_string())
                    };
                    Some((Err(error), source))
                }
            }
        }))
    }
}

/// HTTP/1.1 client pinned to one base URL.
#[derive(Debug, Clone)]
pub struct UpstreamClient {
    client: reqwest::Client,
    base: Url,
    response_header_timeout: Duration,
    circuit: Arc<Mutex<Circuit>>,
    head_slots: Arc<Semaphore>,
    admission_wait: Duration,
}

impl UpstreamClient {
    /// Builds the client for `base` (must end with `/`).
    ///
    /// # Errors
    /// `reqwest` construction failure or a base without a trailing slash.
    pub fn new(base: Url, limits: &Limits) -> Result<Self, SourceError> {
        if !base.path().ends_with('/') || base.cannot_be_a_base() {
            return Err(SourceError::Unexpected(0));
        }
        let distribution = crate::config::ALL_DISTRIBUTION_SUITES
            .iter()
            .any(|entry| entry.repository.origin() == base.as_str());
        let fixture = base.as_str() == "http://127.0.0.1:18080/fixture/";
        #[cfg(any(test, feature = "test-harness"))]
        let fixture = fixture
            || (base.scheme() == "http"
                && base
                    .path()
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .is_some_and(|segment| {
                        segment == "fixture"
                            || crate::config::ALL_DISTRIBUTION_SUITES
                                .iter()
                                .any(|entry| entry.repository.name() == segment)
                    })
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none()
                && match base.host() {
                    Some(url::Host::Ipv4(address)) => address.is_loopback(),
                    Some(url::Host::Ipv6(address)) => address.is_loopback(),
                    _ => false,
                });
        if !distribution && !fixture {
            return Err(SourceError::Forbidden);
        }
        let mut builder = reqwest::Client::builder();
        if distribution {
            builder = builder.dns_resolver(Arc::new(ferrum_storage::recovery::PublicResolver));
        }
        let client = builder
            .redirect(Policy::none())
            .no_proxy()
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(limits.connect_timeout)
            .read_timeout(limits.read_idle_timeout)
            .user_agent(concat!("ferrum/", env!("CARGO_PKG_VERSION")))
            .http1_only()
            .build()
            .map_err(|error| SourceError::Transient(error.to_string()))?;
        Ok(Self {
            client,
            base,
            response_header_timeout: limits.response_header_timeout,
            circuit: Arc::new(Mutex::new(Circuit::default())),
            head_slots: Arc::new(Semaphore::new(2)),
            admission_wait: limits.admission_wait,
        })
    }

    /// The origin base URL.
    pub fn base(&self) -> &Url {
        &self.base
    }

    /// Joins a validated path below the base, encoding each segment.
    fn url_for(&self, path: &RepositoryPath) -> Result<Url, SourceError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| SourceError::Unexpected(0))?
            .pop_if_empty()
            .extend(path.segments());
        Ok(url)
    }

    /// `GET path`; `expected_size` is the signed size when known. The response
    /// headers must arrive within the response-header timeout.
    ///
    /// # Errors
    /// Classified [`SourceError`]; a `Content-Length` contradicting
    /// `expected_size` is [`SourceError::Corrupt`].
    pub async fn get(
        &self,
        path: &RepositoryPath,
        expected_size: Option<u64>,
    ) -> Result<SourceResponse, SourceError> {
        let (response, permit) = self.send(Method::GET, path).await?;
        let content_length = match classify(&response, expected_size) {
            Ok(length) => length,
            Err(error) => {
                permit.finish(transient(&error));
                return Err(error);
            }
        };
        Ok(SourceResponse {
            content_length,
            response,
            permit: Some(permit),
        })
    }

    /// `HEAD path`; returns the declared `Content-Length` after the same
    /// classification as [`UpstreamClient::get`].
    ///
    /// # Errors
    /// As [`UpstreamClient::get`]; a 405 is [`SourceError::Unexpected`].
    pub async fn head(
        &self,
        path: &RepositoryPath,
        expected_size: Option<u64>,
    ) -> Result<Option<u64>, SourceError> {
        let _permit = tokio::time::timeout(
            self.admission_wait,
            Arc::clone(&self.head_slots).acquire_owned(),
        )
        .await
        .map_err(|_| SourceError::Timeout)?
        .map_err(|_| SourceError::Transient("HEAD admission closed".to_owned()))?;
        let (response, permit) = self.send(Method::HEAD, path).await?;
        let result = classify(&response, expected_size);
        permit.finish(result.as_ref().err().is_some_and(transient));
        result
    }

    async fn send(
        &self,
        method: Method,
        path: &RepositoryPath,
    ) -> Result<(reqwest::Response, SourcePermit), SourceError> {
        let url = self.url_for(path)?;
        let permit = SourcePermit::acquire(&self.circuit)?;
        let request = self.client.request(method, url).send();
        let result = match tokio::time::timeout(self.response_header_timeout, request).await {
            Ok(Ok(response)) => return Ok((response, permit)),
            Ok(Err(error)) if error.is_timeout() => SourceError::Timeout,
            Ok(Err(error)) => SourceError::Transient(error.to_string()),
            Err(_elapsed) => SourceError::Timeout,
        };
        permit.finish(true);
        Err(result)
    }
}

/// Maps the status to the §7 taxonomy and checks the declared length.
fn classify(
    response: &reqwest::Response,
    expected_size: Option<u64>,
) -> Result<Option<u64>, SourceError> {
    let status = response.status();
    match status {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND | StatusCode::GONE => return Err(SourceError::NotFound),
        StatusCode::FORBIDDEN => return Err(SourceError::Forbidden),
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS => {
            return Err(SourceError::Transient(format!("origin status {status}")));
        }
        other if other.is_server_error() => {
            return Err(SourceError::Transient(format!("origin status {status}")));
        }
        other => return Err(SourceError::Unexpected(other.as_u16())),
    }
    let content_length = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .ok()
                .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or_else(|| SourceError::Corrupt("invalid Content-Length".to_owned()))
        })
        .transpose()?;
    if let (Some(declared), Some(expected)) = (content_length, expected_size)
        && declared != expected
    {
        return Err(SourceError::Corrupt(format!(
            "declared length {declared} differs from signed size {expected}"
        )));
    }
    Ok(content_length)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn urls_join_segments_below_the_base() {
        let base = Url::parse("http://127.0.0.1:18080/fixture/").expect("base");
        let client = UpstreamClient::new(base, &Limits::default()).expect("client");
        let path = RepositoryPath::parse_decoded("pool/main/f/a b/x_1.0_all.deb").expect("path");
        assert_eq!(
            client.url_for(&path).expect("url").as_str(),
            "http://127.0.0.1:18080/fixture/pool/main/f/a%20b/x_1.0_all.deb"
        );
        let odd = RepositoryPath::parse_decoded("http:evil/x").expect("path");
        assert_eq!(
            client.url_for(&odd).expect("url").as_str(),
            "http://127.0.0.1:18080/fixture/http:evil/x"
        );
    }

    #[test]
    fn base_must_end_with_a_slash() {
        let base = Url::parse("http://127.0.0.1:18080/fixture").expect("base");
        assert!(UpstreamClient::new(base, &Limits::default()).is_err());
    }

    #[test]
    fn fixed_origins_and_explicit_loopback_repository_harness_are_distinct() {
        for base in [
            "https://deb.debian.org/debian/",
            "https://deb.debian.org/debian-security/",
            "https://archive.ubuntu.com/ubuntu/",
            "https://security.ubuntu.com/ubuntu/",
            "https://geo.mirror.pkgbuild.com/",
            "https://builds.garudalinux.org/repos/",
            "http://127.0.0.1:18081/g000/debian/",
            "http://127.0.0.1:18081/g000/ubuntu-security/",
            "http://127.0.0.1:18081/g000/archlinux/",
            "http://127.0.0.1:18081/g000/chaotic-aur/",
        ] {
            assert!(
                UpstreamClient::new(base.parse().expect("base"), &Limits::default()).is_ok(),
                "{base}"
            );
        }
        for base in [
            "https://example.org/debian/",
            "http://deb.debian.org/debian/",
            "https://deb.debian.org/elsewhere/",
            "https://deb.debian.org:444/debian/",
            "https://user@deb.debian.org/debian/",
            "http://127.0.0.1:18081/arbitrary/",
            "http://192.168.1.1:18081/debian/",
            "http://[::ffff:127.0.0.1]:18081/debian/",
            "http://192.168.1.1:18081/archlinux/",
            "http://192.168.1.1:18081/chaotic-aur/",
        ] {
            assert!(
                UpstreamClient::new(base.parse().expect("base"), &Limits::default()).is_err(),
                "{base}"
            );
        }
    }

    #[test]
    fn five_transient_failures_open_one_bounded_half_open_probe() {
        let circuit = Arc::new(Mutex::new(Circuit::default()));
        for _ in 0..5 {
            SourcePermit::acquire(&circuit)
                .expect("closed circuit")
                .finish(true);
        }
        assert!(SourcePermit::acquire(&circuit).is_err());
        circuit.lock().expect("circuit").open_until = Some(Instant::now());
        let probe = SourcePermit::acquire(&circuit).expect("half-open probe");
        assert!(SourcePermit::acquire(&circuit).is_err(), "only one probe");
        drop(probe);
        assert!(
            SourcePermit::acquire(&circuit).is_err(),
            "cancelled probe reopens"
        );
        circuit.lock().expect("circuit").open_until = Some(Instant::now());
        SourcePermit::acquire(&circuit)
            .expect("next probe")
            .finish(false);
        assert!(SourcePermit::acquire(&circuit).is_ok());
    }
}
