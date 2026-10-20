use super::{CONTROL, OperationIdentity, S3Error};
use crate::budget::{BudgetClass, BudgetLedger, DownloadReservation};
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
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
#[derive(Clone)]
pub(super) struct Metered {
    inner: SharedHttpClient,
    target: std::sync::Arc<ProviderTarget>,
    pub(super) ledger: BudgetLedger,
    scope: Option<(OperationIdentity, String, u64, BudgetClass)>,
    listing: bool,
    readback: bool,
    circuit: Option<std::sync::Arc<std::sync::Mutex<super::Circuit>>>,
}
#[derive(Debug)]
struct ProviderTarget {
    host: std::sync::Arc<str>,
    bucket_path: String,
    package_prefix: Box<str>,
    checkpoint_prefix: Box<str>,
}

impl ProviderTarget {
    fn new(config: &super::S3Config) -> Result<Self, S3Error> {
        let endpoint = url::Url::parse(&config.endpoint).map_err(|_| S3Error::Boundary)?;
        Ok(Self {
            host: endpoint.host_str().ok_or(S3Error::Boundary)?.into(),
            bucket_path: format!("/{}", config.bucket),
            package_prefix: config.package_prefix.clone().into_boxed_str(),
            checkpoint_prefix: config.checkpoint_prefix.clone().into_boxed_str(),
        })
    }
}
impl fmt::Debug for Metered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoundedMonthlyS3Connector")
    }
}
impl Metered {
    pub(super) fn new(ledger: BudgetLedger, config: &super::S3Config) -> Result<Self, S3Error> {
        let target = std::sync::Arc::new(ProviderTarget::new(config)?);
        Ok(Self {
            inner: aws_smithy_http_client::Builder::new()
                .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                    aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
                ))
                .build_with_resolver(super::dns::PublicResolver::new(target.host.clone())),
            ledger,
            target,
            scope: None,
            listing: false,
            readback: false,
            circuit: None,
        })
    }
    pub(super) fn scoped(
        &self,
        identity: OperationIdentity,
        key: String,
        maximum: u64,
        class: BudgetClass,
    ) -> Self {
        Self {
            scope: Some((identity, key, maximum, class)),
            listing: false,
            ..self.clone()
        }
    }
    pub(super) fn listing(&self, prefix: String, maximum: u64) -> Self {
        Self {
            scope: Some((
                OperationIdentity::OfflineMaintenance,
                prefix,
                maximum,
                BudgetClass::Control,
            )),
            listing: true,
            ..self.clone()
        }
    }
    pub(super) fn private_listing(&self, prefix: String, maximum: u64) -> Self {
        Self {
            scope: Some((
                OperationIdentity::PrivateQualificationCleanup,
                prefix,
                maximum,
                BudgetClass::Control,
            )),
            listing: true,
            circuit: None,
            ..self.clone()
        }
    }
    pub(super) fn with_readback(mut self, readback: bool) -> Self {
        self.readback = readback;
        self
    }
    pub(super) fn with_circuit(
        mut self,
        circuit: Option<std::sync::Arc<std::sync::Mutex<super::Circuit>>>,
    ) -> Self {
        self.circuit = circuit;
        self
    }
    #[cfg(any(test, feature = "test-harness"))]
    pub(in crate::s3) fn scripted(
        ledger: BudgetLedger,
        inner: SharedHttpClient,
        config: &super::S3Config,
    ) -> Result<Self, S3Error> {
        Ok(Self {
            inner,
            target: std::sync::Arc::new(ProviderTarget::new(config)?),
            ledger,
            scope: None,
            listing: false,
            readback: false,
            circuit: None,
        })
    }
}
impl HttpClient for Metered {
    fn http_connector(
        &self,
        settings: &HttpConnectorSettings,
        components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(Connector {
            inner: self.inner.http_connector(settings, components),
            metered: self.clone(),
        })
    }
}
#[derive(Debug)]
struct Connector {
    inner: SharedHttpConnector,
    metered: Metered,
}
fn denied(error: impl std::error::Error + Send + Sync + 'static) -> ConnectorError {
    ConnectorError::user(Box::new(error))
}
impl HttpConnector for Connector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let metered = self.metered.clone();
        let inner = self.inner.clone();
        HttpConnectorFuture::new(async move {
            let (identity, key, maximum, class) = metered
                .scope
                .as_ref()
                .ok_or_else(|| denied(S3Error::Boundary))?;
            let uri = url::Url::parse(request.uri()).map_err(denied)?;
            let bucket_path = &metered.target.bucket_path;
            let path = format!("{bucket_path}/{key}");
            if uri.scheme() != "https"
                || uri.host_str() != Some(metered.target.host.as_ref())
                || uri.port().is_some()
                || !uri.username().is_empty()
                || uri.password().is_some()
                || uri.fragment().is_some()
            {
                return Err(denied(S3Error::Boundary));
            }
            if metered.listing {
                if request.method() != "GET"
                    || !(uri.path() == bucket_path.as_str()
                        || uri.path().strip_suffix('/') == Some(bucket_path.as_str()))
                    || !uri
                        .query_pairs()
                        .any(|(name, value)| name == "prefix" && value == key.as_str())
                    || !super::namespace_suffix(
                        *identity,
                        key,
                        &metered.target.package_prefix,
                        &metered.target.checkpoint_prefix,
                    )
                    .map_err(denied)?
                    .is_empty()
                {
                    return Err(denied(S3Error::Boundary));
                }
            } else {
                if uri.path() != path {
                    return Err(denied(S3Error::Boundary));
                }
                let suffix = super::namespace_suffix(
                    *identity,
                    key,
                    &metered.target.package_prefix,
                    &metered.target.checkpoint_prefix,
                )
                .map_err(denied)?;
                super::validate_suffix(*identity, suffix).map_err(denied)?;
            }
            let method = request.method().to_owned();
            if !matches!(method.as_str(), "GET" | "HEAD" | "PUT" | "POST" | "DELETE")
                || (method == "DELETE"
                    && !matches!(
                        *identity,
                        OperationIdentity::OfflineMaintenance
                            | OperationIdentity::PrivateQualificationCleanup
                    )
                    && !uri.query_pairs().any(|(k, _)| k == "uploadId"))
            {
                return Err(denied(S3Error::Boundary));
            }
            for (name, value) in uri.query_pairs() {
                if !matches!(
                    name.as_ref(),
                    "x-id"
                        | "uploadId"
                        | "partNumber"
                        | "uploads"
                        | "key-marker"
                        | "upload-id-marker"
                        | "max-uploads"
                        | "prefix"
                        | "list-type"
                        | "continuation-token"
                        | "max-keys"
                ) || value.len() > 8192
                {
                    return Err(denied(S3Error::Boundary));
                }
            }
            let maximum = maximum
                .max(&CONTROL)
                .checked_add(super::super::PROTOCOL_BUFFER)
                .ok_or_else(|| denied(S3Error::Budget))?;
            let mut circuit = match &metered.circuit {
                Some(state) => {
                    Some(super::circuit::CircuitPermit::acquire(state.clone()).map_err(denied)?)
                }
                None => None,
            };
            let cleanup = *identity == OperationIdentity::PrivateQualificationCleanup;
            let reservation = metered
                .ledger
                .reserve_transfer(
                    key,
                    maximum,
                    *class,
                    metered.readback && method == "GET",
                    cleanup,
                )
                .map_err(|_| denied(S3Error::AdmissionRefused))?;
            if key.contains("/_ferrum-b07/") {
                let upload = request
                    .body()
                    .content_length()
                    .and_then(|size| size.checked_add(CONTROL))
                    .ok_or_else(|| denied(S3Error::Boundary))?;
                metered
                    .ledger
                    .reserve_qualification(
                        upload,
                        maximum,
                        cleanup,
                        if cleanup && !metered.listing {
                            Some(key)
                        } else {
                            None
                        },
                    )
                    .map_err(|_| denied(S3Error::AdmissionRefused))?;
            }
            let object_get =
                method == "GET" && !metered.listing && request.headers().get("range").is_none();
            let mut response = inner.call(request).await?;
            let status = response.status().as_u16();
            if response
                .headers()
                .get("x-amz-version-id")
                .is_some_and(|version| version != "null")
                || response
                    .headers()
                    .get("x-amz-delete-marker")
                    .is_some_and(|marker| marker != "false")
            {
                return Err(denied(S3Error::Unsupported));
            }
            if method == "GET"
                && status == 200
                && let Some(permit) = &mut circuit
            {
                permit.body_started();
            }
            if status == 403 {
                if let Some(state) = &metered.circuit {
                    state
                        .lock()
                        .map_err(|_| denied(S3Error::Unavailable))?
                        .forbidden = true;
                }
                metered
                    .ledger
                    .spool()
                    .catalog_write(|connection| {
                        connection
                            .execute("UPDATE remote_health SET forbidden=1 WHERE id=1", [])?;
                        Ok(())
                    })
                    .map_err(denied)?;
            }
            let limit = if method == "HEAD" {
                0
            } else if !(200..300).contains(&status) {
                CONTROL
            } else {
                maximum - super::super::PROTOCOL_BUFFER
            };
            if response
                .headers()
                .get("content-length")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|n| method != "HEAD" && n > limit)
            {
                if object_get && status == 200 {
                    let _ = super::quarantine_key(&metered.ledger, key);
                    return Err(denied(S3Error::Corrupt));
                }
                return Err(denied(S3Error::Budget));
            }
            // Check object framing before SDK length validation can turn a
            // representation mismatch into an unclassified ByteStream error.
            let expected_length = if object_get && status == 200 {
                response
                    .headers()
                    .get("content-length")
                    .and_then(|length| length.parse().ok())
            } else {
                None
            };
            let body = std::mem::replace(response.body_mut(), SdkBody::taken());
            *response.body_mut() = SdkBody::from_body_1_x(MeteredBody {
                inner: body,
                ledger: metered.ledger.clone(),
                key: key.clone(),
                object_get: object_get && status == 200,
                reservation: Some(reservation),
                expected_length,
                maximum: limit,
                actual: 0,
                failed: false,
                circuit,
            });
            if method == "GET" && status == 404 {
                let body = std::mem::replace(response.body_mut(), SdkBody::taken());
                let bytes = super::super::wire::confirmed_key_absence(body).await?;
                *response.body_mut() = SdkBody::from(bytes);
            }
            Ok(response)
        })
    }
}
struct MeteredBody {
    inner: SdkBody,
    ledger: BudgetLedger,
    key: String,
    object_get: bool,
    reservation: Option<DownloadReservation>,
    maximum: u64,
    expected_length: Option<u64>,
    actual: u64,
    failed: bool,
    circuit: Option<super::circuit::CircuitPermit>,
}
impl Body for MeteredBody {
    type Data = Bytes;
    type Error = aws_smithy_types::body::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    self.actual = self.actual.saturating_add(bytes.len() as u64);
                    if self.actual > self.maximum
                        || self
                            .expected_length
                            .is_some_and(|length| self.actual > length)
                    {
                        self.failed = true;
                        let error = if self.object_get {
                            let _ = super::quarantine_key(&self.ledger, &self.key);
                            S3Error::Corrupt
                        } else {
                            S3Error::Budget
                        };
                        return Poll::Ready(Some(Err(error.into())));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                if self
                    .expected_length
                    .is_some_and(|length| self.actual != length)
                {
                    self.failed = true;
                    let _ = super::quarantine_key(&self.ledger, &self.key);
                    return Poll::Ready(Some(Err(S3Error::Corrupt.into())));
                }
                if let Some(circuit) = &mut self.circuit {
                    circuit.finish_body(None);
                }
                if let Some(token) = self.reservation.take() {
                    let result = self
                        .ledger
                        .settle_download(
                            token,
                            self.actual.saturating_add(super::super::PROTOCOL_BUFFER),
                        )
                        .map_err(|error| error.to_string());
                    if let Err(error) = result {
                        self.failed = true;
                        return Poll::Ready(Some(Err(std::io::Error::other(error).into())));
                    }
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.failed = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        false
    }
}
