//! Opt-in deterministic SDK transport for consumer regressions. No endpoint override or network server.
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region, retry::RetryConfig};
use aws_smithy_runtime_api::client::{
    http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
        SharedHttpConnector,
    },
    orchestrator::HttpRequest,
    result::ConnectorError,
    runtime_components::RuntimeComponents,
};
use aws_smithy_runtime_api::http::{Response, StatusCode};
use aws_smithy_types::body::SdkBody;

use super::{PrivateS3Config, PrivateStore, S3Error, S3Store, config, journal, wire::Wire};

mod disk;
pub use disk::DiskBackedRemote;

pub struct ScriptedResponse {
    pub method: &'static str,
    pub status: u16,
    pub content_length: u64,
    pub body: Vec<u8>,
    pub delay: Duration,
    pub headers: Vec<(String, String)>,
    /// Injected acknowledgment loss after the scripted provider accepts the request.
    pub lose_ack: bool,
}

#[derive(Clone, Default)]
pub struct ScriptedRequests(Arc<Mutex<Vec<(String, String)>>>);
impl ScriptedRequests {
    pub fn snapshot(&self) -> Result<Vec<String>, S3Error> {
        self.0
            .lock()
            .map(|requests| requests.iter().map(|(method, _)| method.clone()).collect())
            .map_err(|_| S3Error::Unavailable)
    }
    pub fn targets(&self) -> Result<Vec<String>, S3Error> {
        self.0
            .lock()
            .map(|requests| requests.iter().map(|(_, target)| target.clone()).collect())
            .map_err(|_| S3Error::Unavailable)
    }
}

#[derive(Clone)]
struct Scripted {
    responses: Arc<Mutex<VecDeque<ScriptedResponse>>>,
    requests: ScriptedRequests,
}
impl fmt::Debug for Scripted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScriptedPrivateS3")
    }
}
impl HttpClient for Scripted {
    fn http_connector(
        &self,
        _: &HttpConnectorSettings,
        _: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}
impl HttpConnector for Scripted {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let state = self.clone();
        HttpConnectorFuture::new(async move {
            let error = || {
                ConnectorError::user(
                    std::io::Error::other("scripted provider request mismatch").into(),
                )
            };
            let response = state
                .responses
                .lock()
                .map_err(|_| error())?
                .pop_front()
                .ok_or_else(error)?;
            state
                .requests
                .0
                .lock()
                .map_err(|_| error())?
                .push((request.method().to_owned(), request.uri().to_string()));
            if request.method() != response.method {
                return Err(error());
            }
            tokio::time::sleep(response.delay).await;
            if response.lose_ack {
                return Err(ConnectorError::timeout(
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "INJECTED lost private mutation acknowledgment",
                    )
                    .into(),
                ));
            }
            let status = StatusCode::try_from(response.status).map_err(|_| error())?;
            let mut output = Response::new(status, SdkBody::from(response.body));
            output
                .headers_mut()
                .insert("content-length", response.content_length.to_string());
            output
                .headers_mut()
                .insert("etag", "\"private-scripted-etag\"");
            output
                .headers_mut()
                .insert("content-type", "application/xml");
            for (name, value) in response.headers {
                output.headers_mut().insert(name, value);
            }
            Ok(output)
        })
    }
}

impl PrivateStore {
    /// Occupies all data slots so a regression can deterministically queue before a control failure.
    pub fn hold_data_slots_for_test(&self) -> Result<tokio::sync::OwnedSemaphorePermit, S3Error> {
        self.data
            .clone()
            .try_acquire_many_owned(14)
            .map_err(|_| S3Error::Unavailable)
    }
    /// Uses exactly the adapter, bounded connector and persisted allowance used by real S3.
    /// Call initialize_private_journal once before this constructor; restarts only reopen.
    pub fn scripted_private(
        config: PrivateS3Config,
        responses: Vec<ScriptedResponse>,
    ) -> Result<(Self, ScriptedRequests), S3Error> {
        config.validate()?;
        let journal = journal::Journal::reopen(&config)?;
        let config = Arc::new(config);
        let requests = ScriptedRequests::default();
        let inner = SharedHttpClient::new(Scripted {
            responses: Arc::new(Mutex::new(responses.into())),
            requests: requests.clone(),
        });
        let wire = Wire::with_inner(config.clone(), journal.clone(), inner);
        let sdk = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::v2026_01_12())
            .region(Region::new(config::REGION))
            .endpoint_url(config::ENDPOINT)
            .force_path_style(true)
            .credentials_provider(Credentials::new(
                "TESTACCESS",
                "not-a-real-secret",
                None,
                None,
                "scripted-private-fixture",
            ))
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .response_checksum_validation(
                aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
            )
            .retry_config(RetryConfig::disabled())
            .http_client(wire.clone())
            .build();
        Ok((
            Self {
                client: aws_sdk_s3::Client::from_conf(sdk),
                wire,
                config,
                journal,
                operations: Arc::new(tokio::sync::Semaphore::new(16)),
                data: Arc::new(tokio::sync::Semaphore::new(14)),
                uploads: Arc::new(tokio::sync::Semaphore::new(2)),
            },
            requests,
        ))
    }
}

impl S3Store {
    pub fn hold_data_slots_for_test(&self) -> Result<tokio::sync::OwnedSemaphorePermit, S3Error> {
        match &self.mode {
            super::production::Mode::Private(store) => store.hold_data_slots_for_test(),
            super::production::Mode::Production(store) => store
                .data
                .clone()
                .try_acquire_many_owned(14)
                .map_err(|_| S3Error::Unavailable),
        }
    }

    pub fn scripted_private(
        config: PrivateS3Config,
        responses: Vec<ScriptedResponse>,
    ) -> Result<(Self, ScriptedRequests), S3Error> {
        let (store, requests) = PrivateStore::scripted_private(config, responses)?;
        Ok((
            Self {
                mode: super::production::Mode::Private(store),
            },
            requests,
        ))
    }

    pub fn scripted_production(
        config: super::S3Config,
        ledger: crate::budget::BudgetLedger,
        responses: Vec<ScriptedResponse>,
    ) -> Result<(Self, ScriptedRequests), S3Error> {
        let requests = ScriptedRequests::default();
        let inner = SharedHttpClient::new(Scripted {
            responses: Arc::new(Mutex::new(responses.into())),
            requests: requests.clone(),
        });
        Ok((Self::scripted(config, ledger, inner)?, requests))
    }
}

/// Bounded local-only HTTP object storage used through the real production SDK,
/// metering, namespace checks and ledger. It grants no verification authority.
#[derive(Clone, Default)]
pub struct StatefulRemote(Arc<Mutex<RemoteState>>);

#[derive(Default)]
struct RemoteState {
    objects: std::collections::BTreeMap<String, (Vec<u8>, String)>,
    faults: std::collections::BTreeMap<String, u16>,
    requests: Vec<(String, String)>,
    bytes: usize,
}

impl StatefulRemote {
    pub fn requests(&self) -> Result<Vec<(String, String)>, S3Error> {
        self.0
            .lock()
            .map(|state| state.requests.clone())
            .map_err(|_| S3Error::Unavailable)
    }

    /// Inject a semantic HTTP failure for one exact provider key. Clearing it
    /// does not manufacture a successful response or mutate stored bytes.
    pub fn set_fault(&self, key: &str, status: Option<u16>) -> Result<(), S3Error> {
        if !remote_key(key) || status.is_some_and(|status| !(400..=599).contains(&status)) {
            return Err(S3Error::Boundary);
        }
        let mut state = self.0.lock().map_err(|_| S3Error::Unavailable)?;
        if let Some(status) = status {
            if state.faults.len() >= 128 && !state.faults.contains_key(key) {
                return Err(S3Error::Boundary);
            }
            state.faults.insert(key.to_owned(), status);
        } else {
            state.faults.remove(key);
        }
        Ok(())
    }

    pub fn bytes(&self, key: &str) -> Result<Option<Vec<u8>>, S3Error> {
        self.0
            .lock()
            .map(|state| state.objects.get(key).map(|(bytes, _)| bytes.clone()))
            .map_err(|_| S3Error::Unavailable)
    }
}

fn remote_key(key: &str) -> bool {
    key.len() <= 4096
        && (key.starts_with("linux-packages/") || key.starts_with("linux-checkpoints/"))
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        && !key.split('/').any(|part| part == ".." || part == ".")
}

impl fmt::Debug for StatefulRemote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalStatefulS3Transport")
    }
}

impl HttpClient for StatefulRemote {
    fn http_connector(
        &self,
        _: &HttpConnectorSettings,
        _: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}

fn remote_error(message: &'static str) -> ConnectorError {
    ConnectorError::user(std::io::Error::other(message).into())
}

fn remote_response(
    status: u16,
    bytes: Vec<u8>,
    etag: Option<String>,
    size: usize,
) -> Result<Response<SdkBody>, ConnectorError> {
    let mut response = Response::new(
        StatusCode::try_from(status).map_err(|_| remote_error("invalid local status"))?,
        SdkBody::from(bytes),
    );
    response
        .headers_mut()
        .insert("content-length", size.to_string());
    response
        .headers_mut()
        .insert("content-type", "application/octet-stream");
    if let Some(etag) = etag {
        response.headers_mut().insert("etag", etag);
    }
    Ok(response)
}

fn remote_failure(status: u16) -> Result<Response<SdkBody>, ConnectorError> {
    let code = match status {
        404 => "NoSuchKey",
        403 => "AccessDenied",
        412 => "PreconditionFailed",
        429 => "SlowDown",
        _ => "InternalError",
    };
    let bytes =
        format!("<Error><Code>{code}</Code><Message>injected local S3 failure</Message></Error>")
            .into_bytes();
    let size = bytes.len();
    remote_response(status, bytes, None, size)
}

impl HttpConnector for StatefulRemote {
    fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
        let remote = self.clone();
        HttpConnectorFuture::new(async move {
            use http_body::Body;
            const MAX_OBJECT: usize = 32 * 1024 * 1024;
            const MAX_TOTAL: usize = 256 * 1024 * 1024;
            const MAX_OBJECTS: usize = 20_000;
            let url = url::Url::parse(request.uri())
                .map_err(|_| remote_error("invalid local SDK target"))?;
            if url.scheme() != "https" || url.host_str() != Some("s3.us-central-1.idrivee2.com") {
                return Err(remote_error("local transport refuses arbitrary endpoint"));
            }
            let key = url
                .path()
                .strip_prefix("/s3-andrew/")
                .ok_or_else(|| remote_error("local transport refuses arbitrary bucket"))?
                .to_owned();
            let method = request.method().to_owned();
            let operation = match method.as_str() {
                "PUT" => "PutObject",
                "GET" => "GetObject",
                "HEAD" => "HeadObject",
                _ => return Err(remote_error("unsupported local SDK operation")),
            };
            if !remote_key(&key)
                || url.query_pairs().count() > 1
                || !url
                    .query_pairs()
                    .all(|(name, value)| name == "x-id" && value == operation)
            {
                return Err(remote_error("unsupported local object key or operation"));
            }
            let condition_none = request.headers().get("if-none-match").map(str::to_owned);
            let condition_match = request.headers().get("if-match").map(str::to_owned);
            {
                let mut state = remote
                    .0
                    .lock()
                    .map_err(|_| remote_error("local state poisoned"))?;
                if state.requests.len() >= 100_000 {
                    return Err(remote_error("local request trace ceiling"));
                }
                state.requests.push((method.clone(), key.clone()));
                if let Some(status) = state.faults.get(&key) {
                    return remote_failure(*status);
                }
            }
            // Consume the actual SDK file body, including the production
            // metering wrapper, before acknowledging any PUT.
            let mut bytes = Vec::new();
            if method == "PUT" {
                let mut body = request.take_body();
                while let Some(frame) = std::future::poll_fn(|context| {
                    std::pin::Pin::new(&mut body).poll_frame(context)
                })
                .await
                {
                    let frame = frame.map_err(|_| remote_error("local SDK body failed"))?;
                    if let Some(data) = frame.data_ref() {
                        if data.len() > MAX_OBJECT.saturating_sub(bytes.len()) {
                            return Err(remote_error("local per-object ceiling"));
                        }
                        bytes.extend_from_slice(data);
                    }
                }
            }
            let mut state = remote
                .0
                .lock()
                .map_err(|_| remote_error("local state poisoned"))?;
            match method.as_str() {
                "PUT" => {
                    let existing = state.objects.get(&key);
                    if condition_none.as_deref() == Some("*") && existing.is_some()
                        || condition_match.as_ref().is_some_and(|expected| {
                            existing.is_none_or(|(_, etag)| etag != expected)
                        })
                    {
                        return remote_failure(412);
                    }
                    let previous = existing.map_or(0, |(bytes, _)| bytes.len());
                    let total = state
                        .bytes
                        .checked_sub(previous)
                        .and_then(|total| total.checked_add(bytes.len()))
                        .ok_or_else(|| remote_error("local storage accounting overflow"))?;
                    if total > MAX_TOTAL || existing.is_none() && state.objects.len() >= MAX_OBJECTS
                    {
                        return Err(remote_error("local aggregate storage ceiling"));
                    }
                    let etag = format!("\"{}\"", ferrum_apt::digest::Sha256Digest::of(&bytes));
                    state.objects.insert(key, (bytes, etag.clone()));
                    state.bytes = total;
                    remote_response(200, Vec::new(), Some(etag), 0)
                }
                "GET" | "HEAD" => {
                    let Some((bytes, etag)) = state.objects.get(&key) else {
                        return remote_failure(404);
                    };
                    let body = if method == "HEAD" {
                        Vec::new()
                    } else {
                        bytes.clone()
                    };
                    remote_response(200, body, Some(etag.clone()), bytes.len())
                }
                _ => Err(remote_error("unsupported local SDK operation")),
            }
        })
    }
}

impl S3Store {
    pub fn stateful_production(
        config: super::S3Config,
        ledger: crate::budget::BudgetLedger,
    ) -> Result<(Self, StatefulRemote), S3Error> {
        let remote = StatefulRemote::default();
        let store = Self::scripted(config, ledger, SharedHttpClient::new(remote.clone()))?;
        Ok((store, remote))
    }
}
