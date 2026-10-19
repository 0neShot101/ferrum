use crate::{
    config::{self, CONTROL},
    journal::{self, SharedJournal},
};
use anyhow::{Result, ensure};
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
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use serde_json::json;
use std::{
    collections::VecDeque,
    fmt,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

#[derive(Clone)]
pub(crate) struct Wire {
    inner: SharedHttpClient,
    journal: SharedJournal,
    permits: Arc<Mutex<VecDeque<Permit>>>,
    upload_bytes: Arc<AtomicU64>,
    download_bytes: Arc<AtomicU64>,
}

#[derive(Clone)]
struct Permit {
    operation: &'static str,
    upload: u64,
    download: u64,
}

impl fmt::Debug for Wire {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedProbeHttpClient")
    }
}

impl Wire {
    pub(crate) fn new(journal: SharedJournal) -> Self {
        let inner = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
            ))
            .build_https();
        Self {
            inner,
            journal,
            permits: Arc::new(Mutex::new(VecDeque::new())),
            upload_bytes: Arc::new(AtomicU64::new(0)),
            download_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn permit(
        &self,
        operation: &'static str,
        upload: u64,
        download: u64,
        cleanup: bool,
    ) -> Result<()> {
        // Budget is durable before the one-use connector permit becomes visible. A retry cannot
        // reuse it, and failed/partial attempts are charged their full ceiling permanently.
        journal::lock(&self.journal)?.reserve(upload, download, cleanup)?;
        let mut permits = self
            .permits
            .lock()
            .map_err(|_| anyhow::anyhow!("permit lock poisoned"))?;
        ensure!(permits.len() < 2, "too many pending operations");
        ensure!(
            permits
                .front()
                .is_none_or(|pending| operation == "checkpoint_concurrent_update"
                    && pending.operation == operation
                    && pending.upload == upload + CONTROL
                    && pending.download == download.max(CONTROL)),
            "only identical same-target checkpoint CAS permits may coexist"
        );
        permits.push_back(Permit {
            operation,
            upload: upload + CONTROL,
            download: download.max(CONTROL),
        });
        Ok(())
    }

    pub(crate) fn clear_permits(&self) -> Result<()> {
        self.permits
            .lock()
            .map_err(|_| anyhow::anyhow!("permit lock poisoned"))?
            .clear();
        Ok(())
    }

    pub(crate) fn totals(&self) -> (u64, u64) {
        (
            self.upload_bytes.load(Ordering::Relaxed),
            self.download_bytes.load(Ordering::Relaxed),
        )
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

fn denied(message: &'static str) -> ConnectorError {
    ConnectorError::user(std::io::Error::other(message).into())
}

fn boundary(
    request: &HttpRequest,
    prefix: &str,
    checkpoint: Option<&str>,
    operation: &str,
) -> Result<()> {
    let uri = url::Url::parse(request.uri())?;
    ensure!(
        uri.scheme() == "https"
            && uri.host_str() == Some("s3.us-central-1.idrivee2.com")
            && uri.port().is_none()
            && uri.username().is_empty()
            && uri.password().is_none()
            && uri.fragment().is_none(),
        "request endpoint outside approval"
    );
    let expected_method = match operation {
        "head" | "cleanup_head" | "checkpoint_head" | "checkpoint_cleanup_head" => "HEAD",
        "put_create"
        | "put_duplicate_create"
        | "put_if_match_overwrite"
        | "put_stale_if_match"
        | "upload_part"
        | "checkpoint_create"
        | "checkpoint_duplicate"
        | "checkpoint_match"
        | "checkpoint_stale"
        | "checkpoint_concurrent_update" => "PUT",
        "multipart_create" | "multipart_complete" | "multipart_complete_lost_response" => "POST",
        "multipart_abort" | "cleanup_delete" | "checkpoint_cleanup_delete" => "DELETE",
        "get_full"
        | "get_range"
        | "get_missing"
        | "get_invalid_sentinel"
        | "checkpoint_get"
        | "injected_timeout"
        | "injected_429"
        | "injected_503"
        | "list_parts"
        | "list_parts_after_abort"
        | "list_objects_v2"
        | "inspect_versioning"
        | "inspect_lifecycle"
        | "list_multipart_uploads" => "GET",
        _ => anyhow::bail!("unapproved operation"),
    };
    ensure!(
        request.method() == expected_method,
        "method does not match reserved operation"
    );
    let sdk_operation = match (expected_method, operation) {
        ("HEAD", _) => "HeadObject",
        ("PUT", "upload_part") => "UploadPart",
        ("PUT", _) => "PutObject",
        ("POST", "multipart_create") => "CreateMultipartUpload",
        ("POST", _) => "CompleteMultipartUpload",
        ("DELETE", "multipart_abort") => "AbortMultipartUpload",
        ("DELETE", _) => "DeleteObject",
        ("GET", "list_parts" | "list_parts_after_abort") => "ListParts",
        ("GET", "list_objects_v2") => "ListObjectsV2",
        ("GET", "list_multipart_uploads") => "ListMultipartUploads",
        ("GET", "inspect_versioning") => "GetBucketVersioning",
        ("GET", "inspect_lifecycle") => "GetBucketLifecycleConfiguration",
        _ => "GetObject",
    };
    let pairs: Vec<_> = uri.query_pairs().collect();
    let mut names = std::collections::BTreeSet::new();
    ensure!(
        pairs.iter().all(|(name, _)| names.insert(name.as_ref())),
        "duplicate query parameter"
    );
    let bucket = format!("/{}", config::BUCKET);
    if matches!(operation, "inspect_versioning" | "inspect_lifecycle") {
        let selector = if operation == "inspect_versioning" {
            "versioning"
        } else {
            "lifecycle"
        };
        ensure!(
            (uri.path() == bucket || uri.path() == format!("{bucket}/"))
                && pairs
                    .iter()
                    .any(|(name, value)| name == selector && value.is_empty())
                && pairs
                    .iter()
                    .all(|(name, value)| (name == selector && value.is_empty())
                        || (name == "x-id" && value == sdk_operation)),
            "configuration inspection must use exact bucket and read-only selector"
        );
        return Ok(());
    }
    if uri.path() == bucket || uri.path() == format!("{bucket}/") {
        let allowed = match operation {
            "list_objects_v2" => &["list-type", "prefix", "max-keys", "continuation-token"][..],
            "list_multipart_uploads" => &[
                "uploads",
                "prefix",
                "max-uploads",
                "key-marker",
                "upload-id-marker",
            ][..],
            _ => anyhow::bail!("bucket operation forbidden"),
        };
        ensure!(
            pairs
                .iter()
                .all(|(name, value)| (name == "x-id" && value == sdk_operation)
                    || allowed.contains(&name.as_ref())),
            "unexpected listing query"
        );
        let prefixes: Vec<_> = pairs
            .iter()
            .filter(|(name, _)| name == "prefix")
            .map(|(_, value)| value.as_ref())
            .collect();
        ensure!(
            prefixes == [prefix],
            "LIST must target exact package run prefix"
        );
        ensure!(
            pairs
                .iter()
                .any(|(name, value)| (operation == "list_objects_v2"
                    && name == "list-type"
                    && value == "2")
                    || (operation == "list_multipart_uploads" && name == "uploads")),
            "listing selector missing"
        );
    } else {
        let key = uri
            .path()
            .strip_prefix(&format!("{bucket}/"))
            .ok_or_else(|| anyhow::anyhow!("request bucket outside approval"))?;
        config::validate_owned_key(prefix, checkpoint, key)?;
        let checkpoint_key = checkpoint.is_some_and(|scope| key.starts_with(scope));
        if operation.starts_with("checkpoint_") {
            ensure!(checkpoint_key, "checkpoint adapter escaped its prefix");
            if operation == "checkpoint_concurrent_update" {
                ensure!(
                    key.ends_with("/state"),
                    "concurrent checkpoint target mismatch"
                );
            }
        } else {
            ensure!(!checkpoint_key, "package adapter targeted checkpoints");
        }
        let allowed: &[&str] = match operation {
            "multipart_create" => &["uploads"],
            "multipart_complete" | "multipart_complete_lost_response" | "multipart_abort" => {
                &["uploadId"]
            }
            "list_parts" | "list_parts_after_abort" => {
                &["uploadId", "max-parts", "part-number-marker"]
            }
            "upload_part" => &["uploadId", "partNumber"],
            _ => &[],
        };
        ensure!(
            pairs
                .iter()
                .all(|(name, value)| (name == "x-id" && value == sdk_operation)
                    || allowed.contains(&name.as_ref())),
            "unexpected object query"
        );
        let query = |name: &str| {
            pairs
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, value)| value.as_ref())
        };
        match operation {
            "multipart_create" => ensure!(
                query("uploads").is_some(),
                "multipart create selector missing"
            ),
            "multipart_complete"
            | "multipart_complete_lost_response"
            | "multipart_abort"
            | "list_parts"
            | "list_parts_after_abort" => ensure!(
                query("uploadId").is_some_and(|id| !id.is_empty()),
                "multipart ID missing"
            ),
            "upload_part" => {
                let number = query("partNumber").and_then(|number| number.parse::<u32>().ok());
                ensure!(
                    query("uploadId").is_some_and(|id| !id.is_empty()),
                    "part upload ID missing"
                );
                ensure!(
                    if key == format!("{prefix}abort") {
                        number == Some(1)
                    } else {
                        key == format!("{prefix}multipart")
                            && number.is_some_and(|number| (1..=5).contains(&number))
                    },
                    "multipart part target outside fixed matrix"
                );
            }
            _ => {}
        }
        if request.method() == "PUT" && operation != "upload_part" {
            let marker = &prefix[config::ROOT.len()..prefix.len() - 1];
            ensure!(
                request.headers().get("x-amz-meta-ferrum-probe-run") == Some(marker),
                "write ownership marker missing"
            );
        }
        if [
            "put_create",
            "put_duplicate_create",
            "checkpoint_create",
            "checkpoint_duplicate",
            "multipart_complete",
            "multipart_complete_lost_response",
        ]
        .contains(&operation)
        {
            ensure!(
                request.headers().get("if-none-match") == Some("*"),
                "conditional create guard missing"
            );
        }
        if [
            "put_if_match_overwrite",
            "put_stale_if_match",
            "checkpoint_match",
            "checkpoint_stale",
            "checkpoint_concurrent_update",
            "cleanup_delete",
            "checkpoint_cleanup_delete",
        ]
        .contains(&operation)
        {
            ensure!(
                request
                    .headers()
                    .get("if-match")
                    .is_some_and(|token| !token.is_empty() && token != "*"),
                "exact CAS validator missing"
            );
        }
        if operation == "get_range" {
            ensure!(
                key == format!("{prefix}small")
                    && request.headers().get("range") == Some("bytes=100-1099"),
                "unexpected range target"
            );
        }
        if [
            "get_invalid_sentinel",
            "injected_timeout",
            "injected_429",
            "injected_503",
        ]
        .contains(&operation)
        {
            ensure!(
                key == format!("{prefix}small"),
                "fault/authentication probe target mismatch"
            );
        }
    }
    Ok(())
}

impl HttpConnector for Connector {
    fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
        let inner = self.inner.clone();
        let wire = self.wire.clone();
        HttpConnectorFuture::new(async move {
            let permit = wire
                .permits
                .lock()
                .map_err(|_| denied("permit lock poisoned"))?
                .pop_front()
                .ok_or_else(|| denied("no one-use transfer permit; automatic retry refused"))?;
            {
                let journal =
                    journal::lock(&wire.journal).map_err(|_| denied("journal unavailable"))?;
                boundary(
                    &request,
                    &journal.manifest.prefix,
                    journal.manifest.checkpoint_prefix.as_deref(),
                    permit.operation,
                )
                .map_err(|_| denied("request escaped probe boundary"))?;
                let uri =
                    url::Url::parse(request.uri()).map_err(|_| denied("invalid request URI"))?;
                if let Some(key) = uri.path().strip_prefix(&format!("/{}/", config::BUCKET)) {
                    if ["PUT", "POST", "DELETE"].contains(&request.method()) {
                        let object = journal
                            .manifest
                            .objects
                            .get(key)
                            .ok_or_else(|| denied("mutation lacks durable intent"))?;
                        if ["cleanup_delete", "checkpoint_cleanup_delete"]
                            .contains(&permit.operation)
                            && !object.owned
                        {
                            return Err(denied("deletion requires reconciled ownership"));
                        }
                    }
                    if let Some((_, id)) = uri.query_pairs().find(|(name, _)| name == "uploadId")
                        && !journal
                            .manifest
                            .uploads
                            .iter()
                            .any(|upload| upload.key == key && upload.id == id)
                    {
                        return Err(denied("upload ID is not owned by this key"));
                    }
                }
            }
            if permit.operation.starts_with("injected_") {
                journal::lock(&wire.journal)
                    .and_then(|mut journal| {
                        journal.fault(
                            permit.operation,
                            "delivered_locally_without_provider_request",
                        )
                    })
                    .map_err(|_| denied("could not persist local fault"))?;
                if permit.operation == "injected_timeout" {
                    return Err(ConnectorError::timeout(
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "INJECTED transport timeout",
                        )
                        .into(),
                    ));
                }
                let (status, code) = if permit.operation == "injected_429" {
                    (429, "SlowDown")
                } else {
                    (503, "ServiceUnavailable")
                };
                let status =
                    StatusCode::try_from(status).map_err(|_| denied("invalid local status"))?;
                return Ok(Response::new(
                    status,
                    SdkBody::from(format!(
                        "<Error><Code>{code}</Code><Message>INJECTED local transport fault</Message></Error>"
                    )),
                ));
            }
            if let Some(length) = request.body().content_length()
                && length > permit.upload
            {
                return Err(denied("request body exceeds reservation"));
            }
            let started = Instant::now();
            let is_head = request.method() == "HEAD";
            let body = request.take_body();
            *request.body_mut() = SdkBody::from_body_1_x(LimitedBody::new(
                body,
                permit.upload,
                wire.upload_bytes.clone(),
            ));
            let mut response = inner.call(request).await?;
            let status = response.status().as_u16();
            let request_id = response
                .headers()
                .get("x-amz-request-id")
                .filter(|value| value.len() <= 256 && value.is_ascii())
                .map(str::to_owned);
            journal::lock(&wire.journal)
                .and_then(|mut journal| journal.event(json!({"kind":"http_response", "operation":permit.operation, "status":status, "request_id":request_id, "headers_ms":started.elapsed().as_millis()})))
                .map_err(|_| denied("could not persist response evidence"))?;
            let limit = if (200..300).contains(&status) {
                permit.download
            } else {
                CONTROL
            };
            if (permit.operation == "get_range" && (200..300).contains(&status) && status != 206)
                || (permit.operation == "get_full" && (200..300).contains(&status) && status != 200)
            {
                return Err(denied(
                    "GET response status does not match requested representation",
                ));
            }
            if let Some(length) = response
                .headers()
                .get("content-length")
                .and_then(|value| value.parse::<u64>().ok())
            {
                // HEAD's Content-Length describes the representation, not a response body.
                if !is_head && length > limit {
                    return Err(denied("response Content-Length exceeds reservation"));
                }
            }
            let body = std::mem::replace(response.body_mut(), SdkBody::taken());
            *response.body_mut() =
                SdkBody::from_body_1_x(LimitedBody::new(body, limit, wire.download_bytes.clone()));
            if permit.operation == "multipart_complete_lost_response"
                && (200..300).contains(&status)
            {
                let mut body = std::mem::replace(response.body_mut(), SdkBody::taken());
                let mut settled = Vec::new();
                while let Some(frame) =
                    std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
                {
                    let frame = frame
                        .map_err(|_| denied("Complete response body failed before settlement"))?;
                    if let Some(data) = frame.data_ref() {
                        if settled.len() + data.len() > CONTROL as usize {
                            return Err(denied("Complete response body exceeded control ceiling"));
                        }
                        settled.extend_from_slice(data);
                    }
                }
                if accepted_completion(&settled) {
                    journal::lock(&wire.journal)
                        .and_then(|mut journal| {
                            journal.fault(
                                permit.operation,
                                "provider_success_body_settled_acknowledgment_suppressed",
                            )
                        })
                        .map_err(|_| denied("could not persist settled completion"))?;
                    return Err(ConnectorError::timeout(
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "INJECTED lost Complete acknowledgment after provider success",
                        )
                        .into(),
                    ));
                }
                // An HTTP200 <Error> is a genuine provider failure, never an injected success.
                *response.body_mut() = SdkBody::from(settled);
            }
            Ok(response)
        })
    }
}

fn accepted_completion(bytes: &[u8]) -> bool {
    use xmlparser::{ElementEnd, Token, Tokenizer};
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut stack = Vec::new();
    let mut pending = None;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut etag = false;
    for token in Tokenizer::from(text) {
        let Ok(token) = token else { return false };
        match token {
            Token::ElementStart { local, .. } => {
                if stack.is_empty() {
                    if root_seen || local.as_str() != "CompleteMultipartUploadResult" {
                        return false;
                    }
                    root_seen = true;
                }
                if local.as_str() == "Error" {
                    return false;
                }
                pending = Some(local.as_str());
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
                end: ElementEnd::Close(_, local),
                ..
            } => {
                if stack.pop() != Some(local.as_str()) {
                    return false;
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Token::ElementEnd {
                end: ElementEnd::Empty,
                ..
            } => {
                if pending.take().is_none() {
                    return false;
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Token::Text { text }
                if stack.last() == Some(&"ETag") && !text.as_str().trim().is_empty() =>
            {
                etag = true
            }
            Token::DtdStart { .. } | Token::EmptyDtd { .. } | Token::EntityDeclaration { .. } => {
                return false;
            }
            _ => {}
        }
    }
    root_seen && root_closed && stack.is_empty() && etag
}

struct LimitedBody {
    inner: SdkBody,
    remaining: u64,
    total: Arc<AtomicU64>,
    failed: bool,
}

impl LimitedBody {
    fn new(inner: SdkBody, remaining: u64, total: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            remaining,
            total,
            failed: false,
        }
    }
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
                    self.total.fetch_add(length, Ordering::Relaxed);
                    if length > self.remaining {
                        self.failed = true;
                        return Poll::Ready(Some(Err(std::io::Error::other(
                            "body exceeded durable transfer reservation",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_inspection_cannot_escape_read_only_bucket_selectors() -> Result<()> {
        let prefix = "linux-packages/_ferrum-probe/0123456789abcdef0123456789abcdef/";
        for (operation, selector) in [
            ("inspect_versioning", "versioning"),
            ("inspect_lifecycle", "lifecycle"),
        ] {
            let request = HttpRequest::get(format!(
                "{}/{}/?{selector}",
                config::ENDPOINT,
                config::BUCKET
            ))?;
            assert!(boundary(&request, prefix, None, operation).is_ok());
            for suffix in [
                format!("?{selector}&prefix={prefix}"),
                format!("?{selector}&{selector}"),
                format!("?{selector}=enabled"),
                format!("{prefix}object?{selector}"),
                "?policy".to_owned(),
                "?list-type=2".to_owned(),
            ] {
                let request =
                    HttpRequest::get(format!("{}/{}/{suffix}", config::ENDPOINT, config::BUCKET))?;
                assert!(
                    boundary(&request, prefix, None, operation).is_err(),
                    "{suffix}"
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn response_guard_rejects_oversize_without_collecting() {
        let total = Arc::new(AtomicU64::new(0));
        let mut body = LimitedBody::new(SdkBody::from("12345"), 4, total.clone());
        let frame = std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await;
        assert!(matches!(frame, Some(Err(_))));
        assert_eq!(total.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn transport_refuses_bucketwide_listing() -> Result<()> {
        let prefix = "linux-packages/_ferrum-probe/0123456789abcdef0123456789abcdef/";
        let request = HttpRequest::get(format!(
            "{}/{}/?list-type=2",
            config::ENDPOINT,
            config::BUCKET
        ))?;
        assert!(boundary(&request, prefix, None, "list_objects_v2").is_err());
        Ok(())
    }

    #[test]
    fn completion_injection_requires_settled_success_xml_not_http200_error() {
        assert!(accepted_completion(
            br#"<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ETag>"token"</ETag></CompleteMultipartUploadResult>"#
        ));
        assert!(!accepted_completion(
            b"<Error><Code>InternalError</Code></Error>"
        ));
        assert!(!accepted_completion(
            b"<CompleteMultipartUploadResult><ETag>token</ETag>"
        ));
        assert!(!accepted_completion(
            b"<CompleteMultipartUploadResult><Error>failure</Error><ETag>token</ETag></CompleteMultipartUploadResult>"
        ));
        assert!(!accepted_completion(b"<CompleteMultipartUploadResult/>"));
    }

    #[test]
    fn checkpoint_adapter_cannot_target_packages_or_live_keys() -> Result<()> {
        let prefix = "linux-packages/_ferrum-probe/0123456789abcdef0123456789abcdef/";
        let checkpoint = config::checkpoint_prefix(prefix)?;
        let request = HttpRequest::get(format!(
            "{}/{}/{}state",
            config::ENDPOINT,
            config::BUCKET,
            checkpoint
        ))?;
        assert!(boundary(&request, prefix, Some(&checkpoint), "checkpoint_get").is_ok());
        assert!(boundary(&request, prefix, Some(&checkpoint), "get_full").is_err());
        let package = HttpRequest::get(format!(
            "{}/{}/{}small",
            config::ENDPOINT,
            config::BUCKET,
            prefix
        ))?;
        assert!(boundary(&package, prefix, Some(&checkpoint), "checkpoint_get").is_err());
        let live = HttpRequest::get(format!(
            "{}/{}/linux-checkpoints/live",
            config::ENDPOINT,
            config::BUCKET
        ))?;
        assert!(boundary(&live, prefix, Some(&checkpoint), "checkpoint_get").is_err());
        let bucket = HttpRequest::get(format!("{}/{}/?policy", config::ENDPOINT, config::BUCKET))?;
        assert!(boundary(&bucket, prefix, Some(&checkpoint), "list_objects_v2").is_err());
        Ok(())
    }

    #[test]
    fn locked_sdk_operation_query_tags_preserve_strict_boundaries() -> Result<()> {
        let prefix = "linux-packages/_ferrum-probe/0123456789abcdef0123456789abcdef/";
        let marker = "0123456789abcdef0123456789abcdef";
        for (operation, method, name, query) in [
            ("get_missing", "GET", "missing", "x-id=GetObject"),
            ("head", "HEAD", "small", "x-id=HeadObject"),
            ("put_create", "PUT", "small", "x-id=PutObject"),
            (
                "upload_part",
                "PUT",
                "multipart",
                "partNumber=1&uploadId=owned-id&x-id=UploadPart",
            ),
            (
                "multipart_create",
                "POST",
                "multipart",
                "uploads&x-id=CreateMultipartUpload",
            ),
            (
                "multipart_complete_lost_response",
                "POST",
                "multipart",
                "uploadId=owned-id&x-id=CompleteMultipartUpload",
            ),
            (
                "multipart_abort",
                "DELETE",
                "abort",
                "uploadId=owned-id&x-id=AbortMultipartUpload",
            ),
            (
                "list_parts",
                "GET",
                "multipart",
                "uploadId=owned-id&max-parts=2&x-id=ListParts",
            ),
        ] {
            let mut request = HttpRequest::get(format!(
                "{}/{}/{prefix}{name}?{query}",
                config::ENDPOINT,
                config::BUCKET
            ))?;
            request.set_method(method)?;
            request
                .headers_mut()
                .insert("x-amz-meta-ferrum-probe-run", marker);
            request.headers_mut().insert("if-none-match", "*");
            assert!(
                boundary(&request, prefix, None, operation).is_ok(),
                "{operation}"
            );
        }
        for (operation, query) in [
            (
                "list_objects_v2",
                format!("list-type=2&prefix={prefix}&max-keys=2&x-id=ListObjectsV2"),
            ),
            (
                "list_multipart_uploads",
                format!("uploads&prefix={prefix}&max-uploads=2&x-id=ListMultipartUploads"),
            ),
        ] {
            let request =
                HttpRequest::get(format!("{}/{}/?{query}", config::ENDPOINT, config::BUCKET))?;
            assert!(boundary(&request, prefix, None, operation).is_ok());
        }
        for query in [
            "x-id=DeleteBucket",
            "x-id=PutObject",
            "x-id=GetObject&x-id=GetObject",
            "x-id=GetObject&policy",
        ] {
            let request = HttpRequest::get(format!(
                "{}/{}/{prefix}small?{query}",
                config::ENDPOINT,
                config::BUCKET
            ))?;
            assert!(boundary(&request, prefix, None, "get_full").is_err());
        }
        Ok(())
    }
}
