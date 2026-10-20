//! Reserve and fsync before every actual connector attempt, including errors and cleanup.
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use aws_smithy_runtime_api::client::{
    http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
        SharedHttpConnector,
    },
    orchestrator::HttpRequest,
    result::ConnectorError,
    runtime_components::RuntimeComponents,
};
use aws_smithy_types::body::SdkBody;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

use super::{
    CONTROL, PrivateS3Config, S3Error,
    journal::{self, SharedJournal},
};

#[derive(Clone)]
pub(crate) struct Wire {
    inner: SharedHttpClient,
    journal: SharedJournal,
    config: Arc<PrivateS3Config>,
    cleanup: bool,
    sentinel: bool,
}

impl fmt::Debug for Wire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedPrivateFixtureHttpClient")
    }
}

impl Wire {
    pub(crate) fn new(
        config: Arc<PrivateS3Config>,
        journal: SharedJournal,
    ) -> Result<Self, S3Error> {
        let host = super::config::valid_endpoint_and_host(&config.endpoint)?;
        Ok(Self {
            inner: aws_smithy_http_client::Builder::new()
                .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                    aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
                ))
                .build_with_resolver(super::production::dns::PublicResolver::new(host.into())),
            journal,
            config,
            cleanup: false,
            sentinel: false,
        })
    }

    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn with_inner(
        config: Arc<PrivateS3Config>,
        journal: SharedJournal,
        inner: SharedHttpClient,
    ) -> Self {
        Self {
            inner,
            journal,
            config,
            cleanup: false,
            sentinel: false,
        }
    }

    pub(crate) fn for_cleanup(&self) -> Self {
        Self {
            cleanup: true,
            sentinel: false,
            ..self.clone()
        }
    }

    pub(crate) fn for_forbidden_probe(&self) -> Self {
        Self {
            cleanup: false,
            sentinel: true,
            ..self.clone()
        }
    }
}

impl HttpClient for Wire {
    fn http_connector(
        &self,
        settings: &HttpConnectorSettings,
        components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(Connector {
            inner: self.inner.http_connector(settings, components),
            wire: self.clone(),
        })
    }
}

#[derive(Debug)]
struct Connector {
    inner: SharedHttpConnector,
    wire: Wire,
}

fn denied(error: S3Error) -> ConnectorError {
    ConnectorError::user(Box::new(error))
}

fn boundary(request: &HttpRequest, config: &PrivateS3Config) -> Result<String, S3Error> {
    let expected_host = super::config::valid_endpoint_and_host(&config.endpoint)?;
    let uri = url::Url::parse(request.uri()).map_err(|_| S3Error::Boundary)?;
    if uri.scheme() != "https"
        || uri.host_str() != Some(expected_host.as_str())
        || uri.port().is_some()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
    {
        return Err(S3Error::Boundary);
    }
    let key = uri
        .path()
        .strip_prefix(&format!("/{}/", config.bucket))
        .ok_or(S3Error::Boundary)?;
    config.validate_key(key)?;
    let operation = match request.method() {
        "GET" => "GetObject",
        "HEAD" => "HeadObject",
        "PUT" => "PutObject",
        "DELETE" => "DeleteObject",
        _ => return Err(S3Error::Boundary),
    };
    let pairs: Vec<_> = uri.query_pairs().collect();
    if pairs.len() > 1
        || !pairs
            .iter()
            .all(|(name, value)| name == "x-id" && value == operation)
    {
        return Err(S3Error::Boundary);
    }
    if request.method() == "PUT"
        && (request.headers().get("x-amz-meta-ferrum-b05-run") != Some(config.marker())
            || !(request.headers().get("if-none-match") == Some("*")
                || request.headers().get("if-match").is_some()))
    {
        return Err(S3Error::Boundary);
    }
    if request.method() == "DELETE" && request.headers().get("if-match").is_none() {
        return Err(S3Error::Boundary);
    }
    Ok(key.into())
}

impl HttpConnector for Connector {
    fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
        let wire = self.wire.clone();
        let inner = self.inner.clone();
        HttpConnectorFuture::new(async move {
            let key = boundary(&request, &wire.config).map_err(denied)?;
            let method = request.method().to_owned();
            let (upload, download) = {
                let mut journal = journal::lock(&wire.journal).map_err(denied)?;
                let record = journal.object(&key).map_err(denied)?;
                // Producers may have queued behind operation slots since their first check.
                if !wire.cleanup && !wire.sentinel {
                    if journal.is_forbidden() {
                        return Err(denied(S3Error::Forbidden));
                    }
                    if record.quarantined {
                        return Err(denied(S3Error::Corrupt));
                    }
                    if journal.has_overrun() {
                        return Err(denied(S3Error::Budget));
                    }
                }
                if wire.sentinel
                    && (method != "GET"
                        || !request.headers().get("authorization").is_some_and(|value| {
                            value.contains("Credential=FERRUMINTENTIONALLYINVALID/")
                        }))
                {
                    return Err(denied(S3Error::Boundary));
                }
                if wire.cleanup
                    && (!record.mutation_intent || !["HEAD", "DELETE"].contains(&method.as_str()))
                {
                    return Err(denied(S3Error::Boundary));
                }
                if method == "DELETE" && !wire.cleanup {
                    return Err(denied(S3Error::Boundary));
                }
                if ["PUT", "DELETE"].contains(&method.as_str()) && !record.mutation_intent {
                    return Err(denied(S3Error::Boundary));
                }
                if method == "DELETE" && record.etag.as_deref() != request.headers().get("if-match")
                {
                    return Err(denied(S3Error::Boundary));
                }
                if method == "PUT"
                    && request.headers().get("if-match").is_some()
                    && record.etag.as_deref() != request.headers().get("if-match")
                {
                    return Err(denied(S3Error::Boundary));
                }
                if method == "PUT"
                    && request.headers().get("if-match").is_some()
                    && !record.replacement.as_ref().is_some_and(|intent| {
                        request.headers().get("if-match") == Some(intent.prior_etag.as_str())
                            && request.headers().get("x-amz-meta-ferrum-b05-mutation")
                                == Some(intent.token.as_str())
                    })
                {
                    return Err(denied(S3Error::Boundary));
                }
                let payload = request
                    .body()
                    .content_length()
                    .ok_or_else(|| denied(S3Error::Boundary))?;
                if (method == "PUT" && payload != record.size) || (method != "PUT" && payload != 0)
                {
                    return Err(denied(S3Error::Boundary));
                }
                let upload = payload
                    .checked_add(CONTROL)
                    .ok_or_else(|| denied(S3Error::Budget))?;
                let download = if method == "GET" {
                    record.size.saturating_add(1).max(CONTROL)
                } else {
                    CONTROL
                };
                // Headroom is pessimistically charged, not asserted to be a proven frame bound.
                // A larger frame is recorded exactly and persistently halts normal admission.
                journal
                    .reserve(
                        upload,
                        download.saturating_add(super::PROTOCOL_BUFFER),
                        wire.cleanup,
                    )
                    .map_err(denied)?;
                (upload, download)
            };
            let body = request.take_body();
            *request.body_mut() = SdkBody::from_body_1_x(LimitedBody {
                inner: body,
                remaining: upload,
                journal: wire.journal.clone(),
                upload: true,
                key: key.clone(),
                quarantine_on_overflow: false,
                failed: false,
            });
            let mut response = inner.call(request).await?;
            let status = response.status().as_u16();
            if status == 403 {
                journal::lock(&wire.journal)
                    .and_then(|mut journal| journal.forbidden())
                    .map_err(denied)?;
                tracing::error!(
                    "S3 Forbidden: persistent private backend circuit open; origin fallback prohibited"
                );
            }
            if method == "GET" && (200..300).contains(&status) {
                let expected = journal::lock(&wire.journal)
                    .map_err(denied)?
                    .object(&key)
                    .map_err(denied)?
                    .size;
                let length = response
                    .headers()
                    .get("content-length")
                    .and_then(|length| length.parse::<u64>().ok());
                if status != 200 || length != Some(expected) {
                    journal::lock(&wire.journal)
                        .and_then(|mut journal| journal.quarantine(&key))
                        .map_err(denied)?;
                    return Err(denied(S3Error::Corrupt));
                }
            }
            let limit = if !(200..300).contains(&status) {
                CONTROL
            } else if method == "HEAD" {
                0
            } else {
                download
            };
            if method != "HEAD"
                && !(200..300).contains(&status)
                && response
                    .headers()
                    .get("content-length")
                    .and_then(|length| length.parse::<u64>().ok())
                    .is_some_and(|length| length > CONTROL)
            {
                journal::lock(&wire.journal)
                    .and_then(|mut journal| journal.observe(false, 0, true))
                    .map_err(denied)?;
                return Err(denied(S3Error::Budget));
            }
            let body = std::mem::replace(response.body_mut(), SdkBody::taken());
            *response.body_mut() = SdkBody::from_body_1_x(LimitedBody {
                inner: body,
                remaining: limit,
                journal: wire.journal.clone(),
                upload: false,
                key,
                quarantine_on_overflow: method == "GET" && (200..300).contains(&status),
                failed: false,
            });
            if method == "GET" && status == 404 {
                // The SDK can synthesize NotFound from a bare HTTP 404. Only
                // authenticated-endpoint XML evidence may authorize origin fallback.
                let body = std::mem::replace(response.body_mut(), SdkBody::taken());
                let bytes = confirmed_key_absence(body).await?;
                // These control bytes were already metered while settling the body.
                *response.body_mut() = SdkBody::from(bytes);
            }
            Ok(response)
        })
    }
}

pub(super) async fn confirmed_key_absence(mut body: SdkBody) -> Result<Vec<u8>, ConnectorError> {
    let mut bytes = Vec::new();
    loop {
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)),
        )
        .await
        .map_err(|_| denied(S3Error::Timeout))?;
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(|_| denied(S3Error::Unavailable))?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > CONTROL as usize {
                return Err(denied(S3Error::Unavailable));
            }
            bytes.extend_from_slice(data);
        }
    }
    if !is_key_absence(&bytes) {
        return Err(denied(S3Error::Unavailable));
    }
    Ok(bytes)
}

fn is_key_absence(bytes: &[u8]) -> bool {
    use xmlparser::{ElementEnd, Token, Tokenizer};
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut stack = Vec::new();
    let mut pending = None;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut code_seen = false;
    let mut code_closed = false;
    let mut code = String::new();
    for token in Tokenizer::from(text) {
        let Ok(token) = token else {
            return false;
        };
        match token {
            Token::ElementStart { prefix, local, .. } => {
                if !prefix.as_str().is_empty() || stack.last() == Some(&"Code") {
                    return false;
                }
                if stack.is_empty() {
                    if root_seen || local.as_str() != "Error" {
                        return false;
                    }
                    root_seen = true;
                }
                if local.as_str() == "Code" {
                    if stack.len() != 1 || code_seen {
                        return false;
                    }
                    code_seen = true;
                }
                pending = Some(local.as_str());
            }
            Token::Attribute {
                prefix,
                local,
                value,
                ..
            } => {
                if prefix.as_str() == "xmlns"
                    || (prefix.as_str().is_empty()
                        && local.as_str() == "xmlns"
                        && !matches!(
                            value.as_str(),
                            "" | "http://s3.amazonaws.com/doc/2006-03-01/"
                        ))
                {
                    return false;
                }
            }
            Token::ElementEnd {
                end: ElementEnd::Open,
                ..
            } => {
                let Some(name) = pending.take() else {
                    return false;
                };
                stack.push(name);
            }
            Token::ElementEnd {
                end: ElementEnd::Close(prefix, local),
                ..
            } => {
                if !prefix.as_str().is_empty() || stack.pop() != Some(local.as_str()) {
                    return false;
                }
                if local.as_str() == "Code" {
                    code_closed = true;
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Token::ElementEnd {
                end: ElementEnd::Empty,
                ..
            } => {
                let Some(name) = pending.take() else {
                    return false;
                };
                if name == "Code" {
                    return false;
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Token::Text { text } => {
                if stack.last() == Some(&"Code") {
                    if code.len().saturating_add(text.as_str().len()) > 128 {
                        return false;
                    }
                    code.push_str(text.as_str());
                } else if stack.is_empty() && !text.as_str().trim().is_empty() {
                    return false;
                }
            }
            Token::DtdStart { .. }
            | Token::EmptyDtd { .. }
            | Token::EntityDeclaration { .. }
            | Token::Cdata { .. } => return false,
            _ => {}
        }
    }
    root_seen
        && root_closed
        && stack.is_empty()
        && pending.is_none()
        && code_seen
        && code_closed
        && matches!(code.trim(), "NoSuchKey" | "NotFound")
}

struct LimitedBody {
    inner: SdkBody,
    remaining: u64,
    journal: SharedJournal,
    upload: bool,
    key: String,
    quarantine_on_overflow: bool,
    failed: bool,
}

impl Body for LimitedBody {
    type Data = Bytes;
    type Error = aws_smithy_types::body::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let length = data.len() as u64;
                    let result = journal::lock(&self.journal).and_then(|mut journal| {
                        journal.observe(self.upload, length, length > self.remaining)
                    });
                    if result.is_err() || length > self.remaining {
                        if self.quarantine_on_overflow {
                            let result = journal::lock(&self.journal)
                                .and_then(|mut journal| journal.quarantine(&self.key));
                            if let Err(error) = result {
                                tracing::error!(%error, "cannot persist S3 corruption quarantine");
                            }
                        }
                        self.failed = true;
                        return Poll::Ready(Some(Err(std::io::Error::other(
                            "body exceeded persisted private transfer reservation",
                        )
                        .into())));
                    }
                    self.remaining -= length;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub(crate) fn fixture_body(
    first: u8,
    tail: Option<crate::ObjectStream>,
    size: u64,
) -> aws_sdk_s3::primitives::ByteStream {
    aws_sdk_s3::primitives::ByteStream::new(SdkBody::from_body_1_x(FixtureBody {
        first: Some(first),
        tail: tail.map(Mutex::new),
        remaining: size,
    }))
}

struct FixtureBody {
    first: Option<u8>,
    // SdkBody requires Sync; polling still has exclusive access and never locks.
    tail: Option<Mutex<crate::ObjectStream>>,
    remaining: u64,
}

impl Body for FixtureBody {
    type Data = Bytes;
    type Error = aws_smithy_types::body::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        use futures_util::Stream;
        if let Some(first) = self.first.take() {
            self.remaining -= 1;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(&[first])))));
        }
        let Some(tail) = self.tail.as_mut() else {
            return Poll::Ready(None);
        };
        let tail = match tail.get_mut() {
            Ok(tail) => tail,
            Err(_) => {
                return Poll::Ready(Some(Err(std::io::Error::other(
                    "private fixture stream mutex poisoned",
                )
                .into())));
            }
        };
        match Pin::new(tail).poll_next(context) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.remaining = self.remaining.saturating_sub(bytes.len() as u64);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(std::io::Error::other(error.to_string()).into())))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn rejects_checkpoints_bucket_listing_and_unowned_prefix() {
        let config = PrivateS3Config::test_config(std::env::temp_dir().join("journal"));
        for suffix in [
            "?list-type=2",
            "/linux-checkpoints/v1/state",
            "/linux-packages/v1/objects/sha256/0000",
        ] {
            let request =
                HttpRequest::get(format!("{}/{}{suffix}", config.endpoint, config.bucket))
                    .expect("request");
            assert!(boundary(&request, &config).is_err());
        }
    }

    #[test]
    fn get_absence_requires_structural_provider_error_not_sdk_status_synthesis() {
        for bytes in [
            &b"<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>"[..],
            &b"<?xml version=\"1.0\"?><Error xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Code>NotFound</Code></Error>"[..],
        ] {
            assert!(is_key_absence(bytes));
        }
        for bytes in [
            &b""[..],
            &b"<html><Code>NoSuchKey</Code></html>"[..],
            &b"<Error><Code>NoSuchBucket</Code></Error>"[..],
            &b"<Error><Message><Code>NoSuchKey</Code></Message></Error>"[..],
            &b"<Error><Code>NoSuchKey</Code><Code>NoSuchBucket</Code></Error>"[..],
            &b"<Error><Code>NoSuchKey</Code>"[..],
            &b"<Error xmlns=\"urn:not-s3\"><Code>NoSuchKey</Code></Error>"[..],
            &b"<!DOCTYPE Error [<!ENTITY missing \"NoSuchKey\">]><Error><Code>&missing;</Code></Error>"[..],
        ] {
            assert!(!is_key_absence(bytes));
        }
    }
}
