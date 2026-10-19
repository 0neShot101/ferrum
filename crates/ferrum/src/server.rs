//! Public listener: the HTTP/1.1 connection loop and the request pipeline of
//! `PLAN.md` §3 (slot, validation, prefix, view, resolution, preconditions,
//! Range, bounded body).

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::{Extension, Router};
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES;
use ferrum_apt::path::RepositoryPath;
use ferrum_apt::release::UnixTime;
use ferrum_storage::capture::{CaptureManager, VerifiedCaptureProof};
use ferrum_storage::checkpoint::PackageDescriptor;
use ferrum_storage::disk::ReservationClass;
use ferrum_storage::s3::{S3Error, S3Store};
use ferrum_storage::{Spool, VerifiedObject};
use futures_util::StreamExt;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Sleep;
use tokio_util::sync::CancellationToken;

use crate::config::{Limits, MAX_REQUEST_HEAD_BYTES};
use crate::fetch::{FillError, FillRegistry, JoinOutcome, SourceError, UpstreamClient};
use crate::health::{Metrics, RequestClass};
use crate::http::request::{self, Rejection, RequestMethod, ValidRequest};
use crate::http::response::{self, Representation, ResponsePlan};
use crate::http::{BodyPermits, BodyStream};
use crate::sync::view::{ActiveView, DerivedDescriptor};
use crate::sync::{CacheClass, Catalog, Resolution};

/// Time allowed for a client to send a complete request head.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause after a failed `accept` so a descriptor shortage cannot spin the loop.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(50);

/// Shared state of the public request pipeline.
pub struct AppState {
    pub catalog: Arc<Catalog>,
    pub spool: Spool,
    pub client: Arc<UpstreamClient>,
    pub s3: Option<Arc<S3Store>>,
    pub capture: Option<Arc<CaptureManager>>,
    pub clients: Vec<(String, Arc<UpstreamClient>)>,
    pub registry: FillRegistry,
    pub metrics: Arc<Metrics>,
    pub limits: Limits,
    pub request_slots: Arc<Semaphore>,
    pub active_bodies: Arc<Semaphore>,
    pub cold_clients: Mutex<HashMap<IpAddr, usize>>,
    pub authority: String,
    pub trust_proxy_ip: bool,
    pub request_ids: AtomicU64,
    pub prefix: RepositoryPath,
}

/// Router whose every path runs the repository pipeline.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new().fallback(handle).with_state(state)
}
struct ColdClient {
    state: Arc<AppState>,
    address: IpAddr,
}

impl ColdClient {
    fn acquire(state: &Arc<AppState>, address: IpAddr) -> Option<Self> {
        let mut clients = state
            .cold_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = clients.entry(address).or_default();
        if *count >= 16 {
            return None;
        }
        *count += 1;
        Some(Self {
            state: Arc::clone(state),
            address,
        })
    }
}

impl Drop for ColdClient {
    fn drop(&mut self) {
        let mut clients = self
            .state
            .cold_clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(count) = clients.get_mut(&self.address) {
            *count -= 1;
            if *count == 0 {
                clients.remove(&self.address);
            }
        }
    }
}

/// Accepts connections until `cancel` fires, then drains for at most `drain`.
///
/// Each connection is served by hyper's HTTP/1.1 server with a 16 KiB request
/// head limit (larger heads answer 431), a header read timeout, and a write
/// idle timeout enforced on the socket so a stalled client cannot pin a body.
///
/// # Errors
/// Only listener-level failures; per-connection errors are logged.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    cancel: CancellationToken,
    write_idle: Duration,
    drain: Duration,
) -> io::Result<()> {
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(1024));
    let mut connections = JoinSet::new();
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_REQUEST_HEAD_BYTES);
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => break,
            _ = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "accept failed");
                tokio::time::sleep(ACCEPT_RETRY_PAUSE).await;
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let service = TowerToHyperService::new(router.clone().layer(Extension(peer.ip())));
        let io = TokioIo::new(TimedIo::new(stream, write_idle));
        let connection = http.serve_connection(io, service);
        let watched = graceful.watch(connection);
        connections.spawn(async move {
            let _slot = slot;
            if let Err(error) = watched.await {
                tracing::debug!(%error, "connection ended with error");
            }
        });
    }
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(drain) => {
            tracing::warn!("drain window elapsed with connections still open");
            connections.abort_all();
        }
    }
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            tracing::warn!(%error, "connection task failed");
        }
    }
    Ok(())
}

/// Socket wrapper that fails a write which makes no progress for `write_idle`.
struct TimedIo {
    inner: TcpStream,
    write_idle: Duration,
    write_timer: Option<Pin<Box<Sleep>>>,
}

impl TimedIo {
    fn new(inner: TcpStream, write_idle: Duration) -> Self {
        Self {
            inner,
            write_idle,
            write_timer: None,
        }
    }

    fn pending_or_timeout<T>(&mut self, context: &mut Context<'_>) -> Poll<io::Result<T>> {
        let idle = self.write_idle;
        let timer = self
            .write_timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
        if timer.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "client write idle timeout",
            )));
        }
        Poll::Pending
    }
}

impl AsyncRead for TimedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for TimedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(context, buffer) {
            Poll::Pending => self.pending_or_timeout(context),
            ready => {
                self.write_timer = None;
                ready
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(context) {
            Poll::Pending => self.pending_or_timeout(context),
            ready => {
                self.write_timer = None;
                ready
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

async fn handle(
    State(state): State<Arc<AppState>>,
    Extension(peer): Extension<IpAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let request_id = state.request_ids.fetch_add(1, Ordering::Relaxed) + 1;
    let (parts, _body) = request.into_parts();
    let (class, validated_path, response) =
        pipeline(&state, peer, &parts.method, &parts.uri, &parts.headers).await;
    state
        .metrics
        .record_request_timed(class, response.status(), started.elapsed());
    tracing::info!(
        request_id,
        method = %parts.method,
        path = validated_path.as_deref().unwrap_or("<rejected>"),
        status = response.status().as_u16(),
        class = ?class,
        "request"
    );
    response
}

fn resolve_client_ip(state: &AppState, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, ()> {
    if state.trust_proxy_ip && peer.is_loopback() {
        let mut values = headers.get_all("x-real-ip").iter();
        let Some(first) = values.next() else {
            return Ok(peer.to_canonical());
        };
        if values.next().is_some() {
            return Err(());
        }
        let parsed: IpAddr = first
            .to_str()
            .map_err(|_| ())?
            .trim()
            .parse()
            .map_err(|_| ())?;
        return Ok(parsed.to_canonical());
    }
    Ok(peer.to_canonical())
}

/// Steps 1-7 of the pipeline; returns the metrics class, validated path and response.
async fn pipeline(
    state: &Arc<AppState>,
    peer: IpAddr,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> (RequestClass, Option<String>, Response<Body>) {
    let Some(slot) = acquire_request_slot(state).await else {
        return (RequestClass::Other, None, response::service_unavailable());
    };
    let valid = match request::validate(method, uri) {
        Ok(valid) => valid,
        Err(rejection) => return (RequestClass::Other, None, reject(rejection)),
    };
    let validated_path = Some(valid.path.as_str().to_owned());
    let mut hosts = headers.get_all(axum::http::header::HOST).iter();
    if !hosts
        .next()
        .and_then(|host| host.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case(state.authority.as_str()))
        || hosts.next().is_some()
        || uri
            .authority()
            .is_some_and(|authority| !authority.as_str().eq_ignore_ascii_case(&state.authority))
    {
        return (
            RequestClass::Other,
            validated_path,
            response::error(StatusCode::BAD_REQUEST),
        );
    }
    let Ok(client_ip) = resolve_client_ip(state, peer, headers) else {
        return (
            RequestClass::Other,
            validated_path,
            response::error(StatusCode::BAD_REQUEST),
        );
    };
    let authorized = match state.catalog.resolve(&valid.path, &state.prefix).await {
        Ok(Some(authorized)) => authorized,
        Ok(None) => {
            match tokio::time::timeout(
                state.limits.waiter_timeout,
                resolve_package_signature(state, client_ip, &valid.path),
            )
            .await
            {
                Ok(Ok(Some(package))) => {
                    match state.catalog.package_request(&valid.path, package) {
                        Ok(authorized) => authorized,
                        Err(error) => {
                            tracing::warn!(%error, "signature authority unavailable");
                            return (
                                RequestClass::Package,
                                validated_path,
                                response::service_unavailable(),
                            );
                        }
                    }
                }
                Ok(Ok(None)) => {
                    return (
                        RequestClass::Other,
                        validated_path,
                        response::error(StatusCode::NOT_FOUND),
                    );
                }
                Ok(Err(error)) => {
                    return (
                        RequestClass::Package,
                        validated_path,
                        fill_error_response(&error),
                    );
                }
                Err(_) => {
                    return (
                        RequestClass::Package,
                        validated_path,
                        response::service_unavailable(),
                    );
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "request authority unavailable");
            return (
                RequestClass::Other,
                validated_path,
                response::service_unavailable(),
            );
        }
    };
    let view = authorized.view;
    let package = authorized.package;
    let historical = authorized.historical;
    let (class, reply) = match authorized.resolution {
        Resolution::Unknown => (RequestClass::Other, response::error(StatusCode::NOT_FOUND)),
        Resolution::Metadata { object, class } => {
            if class.requires_freshness() && !fresh_view(state, view.as_deref()) {
                return (
                    RequestClass::Metadata,
                    validated_path,
                    response::service_unavailable(),
                );
            }
            let reply = serve_verified(state, &valid, headers, slot, &object, class).await;
            if class.requires_freshness() && !fresh_view(state, view.as_deref()) {
                return (
                    RequestClass::Metadata,
                    validated_path,
                    response::service_unavailable(),
                );
            }
            (RequestClass::Metadata, reply)
        }
        Resolution::ByHash(object) => {
            let reply =
                serve_verified(state, &valid, headers, slot, &object, CacheClass::ByHash).await;
            (RequestClass::ByHash, reply)
        }
        Resolution::Derived { descriptor, class } => {
            if class.requires_freshness() && !fresh_view(state, view.as_deref()) {
                return (
                    RequestClass::Metadata,
                    validated_path,
                    response::service_unavailable(),
                );
            }
            let reply =
                serve_derived(state, client_ip, &valid, headers, slot, &descriptor, class).await;
            if class.requires_freshness() && !fresh_view(state, view.as_deref()) {
                return (
                    RequestClass::Metadata,
                    validated_path,
                    response::service_unavailable(),
                );
            }
            (
                if class == CacheClass::ByHash {
                    RequestClass::ByHash
                } else {
                    RequestClass::Metadata
                },
                reply,
            )
        }
        Resolution::Package { identity, path } => {
            let client = if state.catalog.is_fixture() {
                Arc::clone(&state.client)
            } else {
                let Some((_, client)) = state
                    .clients
                    .iter()
                    .find(|(repository, _)| repository.as_str() == authorized.repository)
                else {
                    return (
                        RequestClass::Package,
                        validated_path,
                        response::service_unavailable(),
                    );
                };
                Arc::clone(client)
            };
            let proof = match package
                .as_ref()
                .map(PackageDescriptor::authorize)
                .transpose()
            {
                Ok(proof) => proof.map(Arc::new),
                Err(error) => {
                    return (
                        RequestClass::Package,
                        validated_path,
                        fill_error_response(&error.into()),
                    );
                }
            };
            let request = PackageRequest {
                identity,
                path,
                client,
                proof,
                deadline: tokio::time::Instant::now() + state.limits.waiter_timeout,
            };
            let reply = serve_package(state, client_ip, &valid, headers, slot, &request).await;
            (RequestClass::Package, reply)
        }
    };
    // The request's exact generation/proof survives pointer replacement and
    // retirement until its final body chunk or disconnect. ObjectStream owns
    // the independent open-file lease.
    let (parts, body) = reply.into_parts();
    let stream = body.into_data_stream().map(move |chunk| {
        let _authority = (&view, &package, &historical);
        chunk
    });
    (
        class,
        validated_path,
        Response::from_parts(parts, Body::from_stream(stream)),
    )
}

/// A missing detached Pacman signature is authoritative only after verification
/// against the exact package authorized by its retained database generation.
async fn resolve_package_signature(
    state: &Arc<AppState>,
    peer: IpAddr,
    path: &RepositoryPath,
) -> Result<Option<PackageDescriptor>, FillError> {
    let Some((repository, relative)) = path.as_str().split_once('/') else {
        return Ok(None);
    };
    if !matches!(
        repository,
        "archlinux" | "chaotic-aur" | "cachyos" | "archlinuxcn" | "endeavouros"
    ) || !relative.ends_with(".sig")
        || !ferrum_storage::capture::is_package_path(relative)
    {
        return Ok(None);
    }
    let Some(package_path) = path.as_str().strip_suffix(".sig") else {
        return Ok(None);
    };
    let package_path = RepositoryPath::parse_decoded(package_path)
        .map_err(|error| FillError::Internal(error.to_string()))?;
    let Some(authorized) = state
        .catalog
        .resolve(&package_path, &state.prefix)
        .await
        .map_err(|error| FillError::Internal(error.to_string()))?
    else {
        return Ok(None);
    };
    let (Resolution::Package { identity, path }, Some(package)) =
        (authorized.resolution, authorized.package)
    else {
        return Ok(None);
    };
    let _cold_client = ColdClient::acquire(state, peer).ok_or(FillError::Admission)?;
    let (verifier, keyring) = state
        .catalog
        .package_signature_authority(&package)
        .map_err(|error| FillError::Internal(error.to_string()))?;
    let client = state
        .clients
        .iter()
        .find(|(name, _)| name == repository)
        .map(|(_, client)| Arc::clone(client))
        .ok_or(FillError::Admission)?;
    let proof = Arc::new(package.authorize()?);
    let request = PackageRequest {
        identity,
        path,
        client,
        proof: Some(Arc::clone(&proof)),
        deadline: tokio::time::Instant::now() + state.limits.waiter_timeout,
    };
    let package_object = if let Some(object) = state.spool.lookup(identity) {
        object
    } else {
        let capture = state.capture.as_ref().ok_or(FillError::Admission)?;
        match state
            .registry
            .join_authorized(
                identity,
                &request.path,
                Arc::clone(&request.client),
                Arc::clone(capture),
                proof,
            )
            .await
        {
            JoinOutcome::Verified(object) => object,
            JoinOutcome::Failed(error) => return Err(error),
            JoinOutcome::Timeout | JoinOutcome::TooManyWaiters => return Err(FillError::Timeout),
        }
    };
    retain_package_reference(state, &request).await?;
    let signature_path = RepositoryPath::parse_decoded(relative)
        .map_err(|error| FillError::Internal(error.to_string()))?;
    let scratch = state
        .spool
        .reserve_class(MAX_PACMAN_SIG_BYTES as u64, ReservationClass::Metadata)?;
    let response = request.client.get(&signature_path, None).await?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PACMAN_SIG_BYTES as u64)
    {
        return Err(FillError::Corrupt(
            "Pacman signature exceeds size limit".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(MAX_PACMAN_SIG_BYTES);
    let mut stream = response.into_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > MAX_PACMAN_SIG_BYTES - bytes.len() {
            return Err(FillError::Corrupt(
                "Pacman signature exceeds size limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let signature_identity = ObjectIdentity {
        sha256: Sha256Digest::of(&bytes),
        size: bytes.len() as u64,
    };
    let signature = if let Some(object) = state.spool.lookup(signature_identity) {
        object
    } else {
        let reservation = state
            .spool
            .reserve_class(signature_identity.size, ReservationClass::Metadata)?;
        let mut writer = state
            .spool
            .begin_write(reservation, signature_identity)
            .await?;
        writer.write(bytes.into()).await?;
        writer.commit().await?
    };
    verifier
        .verify_detached_owned(
            &keyring,
            package_object.path(),
            signature.path(),
            (
                scratch,
                package_object.clone(),
                signature.clone(),
                Arc::clone(package.proof()),
            ),
        )
        .await
        .map_err(|error| FillError::Corrupt(error.to_string()))?;
    let signature = state
        .catalog
        .register_package_signature(&package, &signature_path, signature_identity)
        .map_err(|error| FillError::Corrupt(error.to_string()))?;
    Ok(Some(signature))
}

fn fresh_view(state: &AppState, view: Option<&ActiveView>) -> bool {
    state.catalog.clock_valid()
        && view.is_some_and(|view| {
            state.catalog.suite_available(view) && view.is_fresh(Instant::now(), UnixTime::now())
        })
}

struct PackageRequest {
    identity: ObjectIdentity,
    path: RepositoryPath,
    client: Arc<UpstreamClient>,
    proof: Option<Arc<VerifiedCaptureProof>>,
    deadline: tokio::time::Instant,
}

fn reject(rejection: Rejection) -> Response<Body> {
    match rejection {
        Rejection::MethodNotAllowed => response::method_not_allowed(),
        Rejection::QueryString => response::error(StatusCode::BAD_REQUEST),
        Rejection::PathTooLong => response::error(StatusCode::URI_TOO_LONG),
        Rejection::InvalidPath => response::error(StatusCode::NOT_FOUND),
    }
}

/// Package path: verified hit, HEAD probe, or single-flight fill.
async fn serve_package(
    state: &Arc<AppState>,
    peer: IpAddr,
    valid: &ValidRequest,
    headers: &HeaderMap,
    slot: OwnedSemaphorePermit,
    request: &PackageRequest,
) -> Response<Body> {
    let identity = request.identity;
    let path = &request.path;
    if let Some(object) = state.spool.lookup(identity) {
        if valid.method != RequestMethod::Head
            && matches!(
                response::plan(
                    valid.method,
                    headers,
                    &Representation {
                        identity,
                        class: CacheClass::Package
                    }
                ),
                ResponsePlan::Full | ResponsePlan::Partial { .. }
            )
            && let Err(error) = retain_package_reference(state, request).await
        {
            return fill_error_response(&error);
        }
        return serve_verified(state, valid, headers, slot, &object, CacheClass::Package).await;
    }
    if let Some(error) = state.registry.replayed_failure(identity) {
        return fill_error_response(&error);
    }
    if let Some(store) = &state.s3 {
        if store.circuit_open() {
            return response::service_unavailable();
        }
        if store.is_quarantined(identity) {
            return response::error(StatusCode::BAD_GATEWAY);
        }
        if store.allowance_blocked() {
            return response::budget_unavailable();
        }
    }
    let representation = Representation {
        identity,
        class: CacheClass::Package,
    };
    // Preconditions are decided on the authenticated descriptor; a matching
    // conditional request never downloads a body (§3.4).
    let plan = response::plan(valid.method, headers, &representation);
    match plan {
        ResponsePlan::PreconditionFailed => {
            return response::error(StatusCode::PRECONDITION_FAILED);
        }
        ResponsePlan::NotModified => return response::not_modified(&representation),
        ResponsePlan::RangeNotSatisfiable | ResponsePlan::Full | ResponsePlan::Partial { .. } => {}
    }
    let Some(_cold_client) = ColdClient::acquire(state, peer) else {
        return response::service_unavailable();
    };
    if valid.method == RequestMethod::Head {
        return head_probe(state, &request.client, path, &representation).await;
    }
    let Some(active_body) = acquire_body_permit(state).await else {
        return response::service_unavailable();
    };
    let joined = match &request.proof {
        Some(proof) => {
            let Some(capture) = &state.capture else {
                return response::service_unavailable();
            };
            state
                .registry
                .join_authorized(
                    identity,
                    path,
                    Arc::clone(&request.client),
                    Arc::clone(capture),
                    Arc::clone(proof),
                )
                .await
        }
        None if state.catalog.is_fixture() => state.registry.join(identity, path).await,
        None => return response::service_unavailable(),
    };
    match joined {
        JoinOutcome::Verified(object) => {
            if let Err(error) = retain_package_reference(state, request).await {
                return fill_error_response(&error);
            }
            if plan == ResponsePlan::RangeNotSatisfiable {
                return response::range_not_satisfiable(identity.size);
            }
            let permits = BodyPermits {
                request_slot: slot,
                active_body,
            };
            send_body(state, &object, &representation, plan, permits)
        }
        JoinOutcome::Failed(error) => fill_error_response(&error),
        JoinOutcome::Timeout | JoinOutcome::TooManyWaiters => response::service_unavailable(),
    }
}

async fn retain_package_reference(
    state: &AppState,
    request: &PackageRequest,
) -> Result<(), FillError> {
    let Some(proof) = &request.proof else {
        return if state.catalog.is_fixture() {
            Ok(())
        } else {
            Err(FillError::Admission)
        };
    };
    let capture = state.capture.as_ref().ok_or(FillError::Admission)?;
    if capture.lookup(proof.repository(), proof.path())? == Some(request.identity) {
        return Ok(());
    }
    if capture.is_durable(request.identity)? {
        let deadline = tokio::time::Instant::now() + state.limits.producer_deadline;
        tokio::time::timeout_at(
            request.deadline,
            capture.capture_verified_hit(proof, deadline, &CancellationToken::new()),
        )
        .await
        .map_err(|_| FillError::Timeout)??;
    } else {
        // A deduplicated flight may have filled another repository's reference.
        // Register this path too; reserve enqueues an already installed object.
        let _reservation = capture.reserve(proof, UnixTime::now().as_secs())?;
    }
    Ok(())
}

async fn serve_derived(
    state: &Arc<AppState>,
    peer: IpAddr,
    valid: &ValidRequest,
    headers: &HeaderMap,
    slot: OwnedSemaphorePermit,
    descriptor: &DerivedDescriptor,
    class: CacheClass,
) -> Response<Body> {
    if let Some(object) = state.spool.lookup(descriptor.identity) {
        return serve_verified(state, valid, headers, slot, &object, class).await;
    }
    if let Some(error) = state.registry.replayed_failure(descriptor.identity) {
        return fill_error_response(&error);
    }
    let representation = Representation {
        identity: descriptor.identity,
        class,
    };
    let plan = response::plan(valid.method, headers, &representation);
    match plan {
        ResponsePlan::PreconditionFailed => {
            return response::error(StatusCode::PRECONDITION_FAILED);
        }
        ResponsePlan::NotModified => return response::not_modified(&representation),
        _ => {}
    }
    // HEAD and descriptor-only 304 never expand the pinned source.
    if valid.method == RequestMethod::Head {
        return response::representation(&representation, ResponsePlan::Full, Body::empty());
    }
    let Some(_cold_client) = ColdClient::acquire(state, peer) else {
        return response::service_unavailable();
    };
    let Some(active_body) = acquire_body_permit(state).await else {
        return response::service_unavailable();
    };
    match state.registry.join_derived(descriptor).await {
        JoinOutcome::Verified(object) => {
            if plan == ResponsePlan::RangeNotSatisfiable {
                return response::range_not_satisfiable(descriptor.identity.size);
            }
            send_body(
                state,
                &object,
                &representation,
                plan,
                BodyPermits {
                    request_slot: slot,
                    active_body,
                },
            )
        }
        JoinOutcome::Failed(error) => fill_error_response(&error),
        JoinOutcome::Timeout | JoinOutcome::TooManyWaiters => response::service_unavailable(),
    }
}

/// Cold HEAD: S3 HEAD first, with origin HEAD only after confirmed absence.
/// Authenticated length is mandatory; never enqueues a fill or promotes state.
async fn head_probe(
    state: &Arc<AppState>,
    client: &UpstreamClient,
    path: &RepositoryPath,
    representation: &Representation,
) -> Response<Body> {
    if let Some(store) = &state.s3 {
        match store
            .head(
                representation.identity,
                tokio::time::Instant::now() + state.limits.response_header_timeout,
                CancellationToken::new(),
            )
            .await
        {
            Ok(_) => {
                return response::representation(representation, ResponsePlan::Full, Body::empty());
            }
            Err(S3Error::NotFound) => {}
            Err(S3Error::Corrupt) => return response::error(StatusCode::BAD_GATEWAY),
            Err(S3Error::Budget | S3Error::AdmissionRefused) => {
                return response::budget_unavailable();
            }
            Err(_) => return response::service_unavailable(),
        }
    }
    match client.head(path, Some(representation.identity.size)).await {
        Ok(_) => response::representation(representation, ResponsePlan::Full, Body::empty()),
        Err(SourceError::NotFound) => response::error(StatusCode::NOT_FOUND),
        Err(SourceError::Corrupt(_)) => response::error(StatusCode::BAD_GATEWAY),
        Err(_) => response::service_unavailable(),
    }
}

/// Verified object (metadata, by-hash, warm package): preconditions, Range, body.
async fn serve_verified(
    state: &Arc<AppState>,
    valid: &ValidRequest,
    headers: &HeaderMap,
    slot: OwnedSemaphorePermit,
    object: &VerifiedObject,
    class: CacheClass,
) -> Response<Body> {
    let representation = Representation {
        identity: object.identity(),
        class,
    };
    let plan = response::plan(valid.method, headers, &representation);
    match plan {
        ResponsePlan::PreconditionFailed => response::error(StatusCode::PRECONDITION_FAILED),
        ResponsePlan::NotModified => response::not_modified(&representation),
        ResponsePlan::RangeNotSatisfiable => response::range_not_satisfiable(object.size()),
        ResponsePlan::Full | ResponsePlan::Partial { .. } => {
            if valid.method == RequestMethod::Head {
                return response::representation(&representation, plan, Body::empty());
            }
            let Some(active_body) = acquire_body_permit(state).await else {
                return response::service_unavailable();
            };
            let permits = BodyPermits {
                request_slot: slot,
                active_body,
            };
            send_body(state, object, &representation, plan, permits)
        }
    }
}

async fn acquire_request_slot(state: &AppState) -> Option<OwnedSemaphorePermit> {
    let acquire = Arc::clone(&state.request_slots).acquire_owned();
    tokio::time::timeout(state.limits.admission_wait, acquire)
        .await
        .ok()?
        .ok()
}

async fn acquire_body_permit(state: &AppState) -> Option<OwnedSemaphorePermit> {
    let acquire = Arc::clone(&state.active_bodies).acquire_owned();
    tokio::time::timeout(state.limits.admission_wait, acquire)
        .await
        .ok()?
        .ok()
}

fn send_body(
    state: &AppState,
    object: &VerifiedObject,
    representation: &Representation,
    plan: ResponsePlan,
    permits: BodyPermits,
) -> Response<Body> {
    let request_class = match representation.class {
        CacheClass::Mutable | CacheClass::Canonical => RequestClass::Metadata,
        CacheClass::ByHash => RequestClass::ByHash,
        CacheClass::Package => RequestClass::Package,
    };
    let size = object.size();
    if size == 0 {
        state
            .metrics
            .record_body_transfer(true, request_class, Duration::ZERO);
        return response::representation(representation, ResponsePlan::Full, Body::empty());
    }
    let (start, end) = match plan {
        ResponsePlan::Partial { start, end } => (start, end),
        _ => (0, size.saturating_sub(1)),
    };
    let stream = match object.stream_range(start, end) {
        Ok(stream) => stream,
        Err(error) => {
            tracing::error!(%error, "verified object range could not be opened");
            return response::error(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let expected_bytes = end.saturating_sub(start).saturating_add(1);
    let body = BodyStream::new(
        stream,
        permits,
        Arc::clone(&state.metrics),
        request_class,
        expected_bytes,
        state.limits.body_write_idle,
        state.limits.body_lifetime,
    );
    response::representation(representation, plan, Body::from_stream(body))
}

/// A terminal fill failure preserves the provider-budget retry contract.
fn fill_error_response(error: &FillError) -> Response<Body> {
    let status = match error {
        FillError::Budget => return response::budget_unavailable(),
        FillError::Admission => return response::service_unavailable(),
        FillError::NotFound => StatusCode::NOT_FOUND,
        FillError::Corrupt(_)
        | FillError::Forbidden
        | FillError::Unexpected(_)
        | FillError::Internal(_) => StatusCode::BAD_GATEWAY,
        FillError::BackendForbidden
        | FillError::Transient(_)
        | FillError::Timeout
        | FillError::Shutdown => StatusCode::SERVICE_UNAVAILABLE,
    };
    response::error(status)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::sync::view::{ByHashKey, HashAlgorithm, ViewParts};
    use axum::body::to_bytes;
    use ferrum_apt::digest::Sha256Digest;
    use ferrum_storage::checkpoint::SuiteKey;
    use ferrum_storage::{SpoolConfig, disk::ReservationClass};

    const SUITES: [(&str, &str); 6] = [
        ("debian", "trixie"),
        ("debian", "trixie-updates"),
        ("debian-security", "trixie-security"),
        ("ubuntu", "noble"),
        ("ubuntu", "noble-updates"),
        ("ubuntu-security", "noble-security"),
    ];

    fn spool(root: &std::path::Path) -> Spool {
        Spool::open_exclusive_fixture(SpoolConfig {
            root: root.join("spool"),
            managed_ceiling: 16 * 1024 * 1024,
            max_object_size: 1024 * 1024,
            io_workers: 2,
            read_chunk: 4096,
        })
        .expect("fixture spool")
    }

    async fn install(spool: &Spool, bytes: &[u8]) -> VerifiedObject {
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(bytes),
            size: bytes.len() as u64,
        };
        if let Some(object) = spool.lookup(identity) {
            return object;
        }
        let reservation = spool
            .reserve_class(identity.size, ReservationClass::Metadata)
            .expect("reserve");
        let mut writer = spool
            .begin_write(reservation, identity)
            .await
            .expect("writer");
        writer
            .write(bytes::Bytes::copy_from_slice(bytes))
            .await
            .expect("write");
        writer.commit().await.expect("commit")
    }

    fn state(spool: Spool, catalog: Catalog, limits: Limits) -> Arc<AppState> {
        let client = Arc::new(
            UpstreamClient::new(
                "http://127.0.0.1:9/fixture/".parse().expect("loopback"),
                &limits,
            )
            .expect("fixture client"),
        );
        let metrics = Arc::new(Metrics::default());
        let registry = FillRegistry::new(
            spool.clone(),
            Arc::clone(&client),
            None,
            limits,
            CancellationToken::new(),
            Arc::clone(&metrics),
        );
        Arc::new(AppState {
            catalog: Arc::new(catalog),
            spool,
            client,
            s3: None,
            capture: None,
            clients: Vec::new(),
            registry,
            metrics,
            limits,
            request_slots: Arc::new(Semaphore::new(limits.request_slots)),
            active_bodies: Arc::new(Semaphore::new(limits.active_bodies)),
            cold_clients: Default::default(),
            authority: "fixture.test".to_owned(),
            trust_proxy_ip: true,
            request_ids: AtomicU64::new(0),
            prefix: RepositoryPath::parse_decoded("fixture").expect("prefix"),
        })
    }

    async fn request(
        state: &Arc<AppState>,
        method: Method,
        path: &str,
        condition: Option<(&str, &str)>,
    ) -> Response<Body> {
        let mut headers = HeaderMap::new();
        headers.insert("host", "fixture.test".parse().expect("host"));
        if let Some((name, value)) = condition {
            headers.insert(
                axum::http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                value.parse().expect("header value"),
            );
        }
        pipeline(
            state,
            "127.0.0.1".parse().expect("peer"),
            &method,
            &path.parse().expect("URI"),
            &headers,
        )
        .await
        .2
    }

    fn metadata_view(
        repository: &str,
        suite: &str,
        object: VerifiedObject,
        lease: Duration,
    ) -> ActiveView {
        let canonical =
            RepositoryPath::parse_decoded(&format!("dists/{suite}/InRelease")).expect("path");
        let alias = ByHashKey {
            directory: "main/binary-amd64".to_owned(),
            algorithm: HashAlgorithm::Sha256,
            hex: object.sha256().to_hex(),
        };
        let mut view = ActiveView::from_parts(ViewParts {
            generation_id: object.sha256(),
            release_date: UnixTime::now(),
            content_sha256: object.sha256(),
            valid_until: None,
            confirmed_at: Instant::now(),
            confirmed_at_unix: UnixTime::now(),
            lease,
            metadata: HashMap::from([(canonical, (object.clone(), CacheClass::Mutable))]),
            by_hash: HashMap::from([(alias, object)]),
            packages: HashMap::new(),
        });
        view.repository = repository.to_owned();
        view.suite = suite.to_owned();
        view
    }

    #[tokio::test]
    async fn repository_metadata_routes_do_not_use_dists_or_by_hash() {
        let directory = tempfile::tempdir().expect("directory");
        let spool = spool(directory.path());
        let object = install(&spool, b"authenticated repository metadata").await;
        let cases = [
            ("archlinux", "core", "core/os/x86_64/core.db"),
            (
                "chaotic-aur",
                "chaotic-aur",
                "chaotic-aur/x86_64/chaotic-aur.db",
            ),
            ("cachyos", "cachyos", "x86_64/cachyos/cachyos.db"),
            ("cachyos", "cachyos-v3", "x86_64/cachyos-v3/cachyos-v3.db"),
            ("cachyos", "cachyos-v4", "x86_64/cachyos-v4/cachyos-v4.db"),
            (
                "archlinuxcn",
                "archlinuxcn",
                "archlinuxcn/x86_64/archlinuxcn.db",
            ),
            (
                "endeavouros",
                "endeavouros",
                "endeavouros/x86_64/endeavouros.db",
            ),
            (
                "almalinux",
                "9-baseos-aarch64",
                "9/BaseOS/aarch64/os/repodata/repomd.xml",
            ),
            (
                "rockylinux",
                "10-appstream-x86-64",
                "10/AppStream/x86_64/os/repodata/repomd.xml.asc",
            ),
        ];
        let views = cases
            .iter()
            .map(|(repository, suite, database)| {
                let canonical = RepositoryPath::parse_decoded(database).expect("metadata route");
                let mut view = ActiveView::from_parts(ViewParts {
                    generation_id: object.sha256(),
                    release_date: UnixTime::now(),
                    content_sha256: object.sha256(),
                    valid_until: None,
                    confirmed_at: Instant::now(),
                    confirmed_at_unix: UnixTime::now(),
                    lease: Duration::from_secs(60),
                    metadata: HashMap::from([(canonical, (object.clone(), CacheClass::Mutable))]),
                    by_hash: HashMap::new(),
                    packages: HashMap::new(),
                });
                view.repository = (*repository).to_owned();
                view.suite = (*suite).to_owned();
                (SuiteKey::new(repository, suite).expect("suite"), view)
            })
            .collect();
        let state = state(spool, Catalog::for_suite_tests(views), Limits::default());
        let etag = format!("\"sha256-{}\"", object.sha256());
        for (repository, suite, database) in cases {
            let canonical = format!("/{repository}/{database}");
            let reply = request(&state, Method::GET, &canonical, None).await;
            assert_eq!(reply.status(), StatusCode::OK);
            assert_eq!(
                to_bytes(reply.into_body(), 1024)
                    .await
                    .expect("database body")
                    .as_ref(),
                b"authenticated repository metadata"
            );
            let reply = request(
                &state,
                Method::GET,
                &canonical,
                Some(("if-none-match", etag.as_str())),
            )
            .await;
            assert_eq!(reply.status(), StatusCode::NOT_MODIFIED);
            let apt_route = format!("/{repository}/dists/{suite}/{database}");
            assert_eq!(
                request(&state, Method::GET, &apt_route, None)
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
            let (directory, _) = database.rsplit_once('/').expect("database directory");
            let by_hash = format!(
                "/{repository}/{directory}/by-hash/SHA256/{}",
                object.sha256()
            );
            assert_eq!(
                request(&state, Method::GET, &by_hash, None).await.status(),
                StatusCode::NOT_FOUND
            );
        }
        state.registry.shutdown().await;
    }

    #[tokio::test]
    async fn each_stale_suite_blocks_only_its_mutable_200_and_304() {
        let directory = tempfile::tempdir().expect("directory");
        let spool = spool(directory.path());
        let object = install(&spool, b"authenticated metadata").await;
        let etag = format!("\"sha256-{}\"", object.sha256());
        for stale in 0..SUITES.len() {
            let views = SUITES
                .iter()
                .enumerate()
                .map(|(index, (repository, suite))| {
                    (
                        SuiteKey::new(repository, suite).expect("suite"),
                        metadata_view(
                            repository,
                            suite,
                            object.clone(),
                            if index == stale {
                                Duration::ZERO
                            } else {
                                Duration::from_secs(60)
                            },
                        ),
                    )
                })
                .collect();
            let state = state(
                spool.clone(),
                Catalog::for_suite_tests(views),
                Limits::default(),
            );
            for (index, (repository, suite)) in SUITES.iter().enumerate() {
                let path = format!("/{repository}/dists/{suite}/InRelease");
                for condition in [None, Some(("if-none-match", etag.as_str()))] {
                    let reply = request(&state, Method::GET, &path, condition).await;
                    let expected = if index == stale {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else if condition.is_some() {
                        StatusCode::NOT_MODIFIED
                    } else {
                        StatusCode::OK
                    };
                    assert_eq!(reply.status(), expected, "{repository}/{suite}");
                    if index == stale {
                        assert_eq!(reply.headers()["cache-control"], "no-store");
                        assert!(
                            to_bytes(reply.into_body(), 1024)
                                .await
                                .expect("error body")
                                .is_empty()
                        );
                    }
                }
                let alias = format!(
                    "/{repository}/dists/{suite}/main/binary-amd64/by-hash/SHA256/{}",
                    object.sha256()
                );
                let reply = request(&state, Method::GET, &alias, None).await;
                assert_eq!(reply.status(), StatusCode::OK);
                assert_eq!(
                    to_bytes(reply.into_body(), 1024)
                        .await
                        .expect("immutable body")
                        .as_ref(),
                    b"authenticated metadata"
                );
            }
            state.registry.shutdown().await;
        }
    }

    #[tokio::test]
    async fn request_body_retains_exact_generation_after_catalog_drops() {
        let directory = tempfile::tempdir().expect("directory");
        let spool = spool(directory.path());
        let object = install(&spool, b"generation A").await;
        let key = SuiteKey::new("ubuntu", "noble-updates").expect("key");
        let catalog = Catalog::for_suite_tests(vec![(
            key.clone(),
            metadata_view("ubuntu", "noble-updates", object, Duration::from_secs(60)),
        )]);
        let weak = Arc::downgrade(&catalog.load_suite(&key).expect("view"));
        let state = state(spool, catalog, Limits::default());
        let reply = request(
            &state,
            Method::GET,
            "/ubuntu/dists/noble-updates/InRelease",
            None,
        )
        .await;
        assert_eq!(reply.status(), StatusCode::OK);
        state.registry.shutdown().await;
        drop(state);
        assert!(weak.upgrade().is_some(), "body owns generation authority");
        assert_eq!(
            to_bytes(reply.into_body(), 1024)
                .await
                .expect("body")
                .as_ref(),
            b"generation A"
        );
        assert!(
            weak.upgrade().is_none(),
            "finished body releases generation"
        );
    }
    // Derived HTTP regressions live in tests/publication.rs: decoding requires
    // genuine activated durable metadata, not an unsigned in-memory view.
    #[tokio::test]
    async fn repository_and_suite_identity_reject_cross_pocket_and_disabled_paths() {
        let directory = tempfile::tempdir().expect("directory");
        let spool = spool(directory.path());
        let object = install(&spool, b"authorized metadata").await;
        let views = SUITES
            .iter()
            .map(|(repository, suite)| {
                (
                    SuiteKey::new(repository, suite).expect("key"),
                    metadata_view(repository, suite, object.clone(), Duration::from_secs(60)),
                )
            })
            .collect();
        let state = state(spool, Catalog::for_suite_tests(views), Limits::default());
        for path in [
            "/ubuntu/dists/noble-backports/InRelease",
            "/ubuntu-security/dists/noble/InRelease",
            "/debian-security/dists/trixie/InRelease",
            "/fixture/dists/ferrum-test/InRelease",
            "/debian/dists/trixie/main/binary-amd64/Packages.diff/Index",
        ] {
            let reply = request(&state, Method::GET, path, None).await;
            assert_eq!(reply.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(
                to_bytes(reply.into_body(), 16)
                    .await
                    .expect("unknown body")
                    .is_empty()
            );
        }
        assert_eq!(state.registry.active_flights(), 0);
        state.registry.shutdown().await;
    }

    #[tokio::test]
    async fn proxy_x_real_ip_canonicalizes_and_isolates_cold_admission_pools() {
        let directory = tempfile::tempdir().expect("directory");
        let spool = spool(directory.path());
        let catalog = Catalog::new();
        let digest = ferrum_apt::digest::Sha256Digest::of(b"cold package");
        catalog.publish(ActiveView::from_parts(ViewParts {
            generation_id: digest,
            release_date: UnixTime::now(),
            content_sha256: digest,
            valid_until: None,
            confirmed_at: Instant::now(),
            confirmed_at_unix: UnixTime::now(),
            lease: Duration::from_secs(60),
            metadata: HashMap::new(),
            by_hash: HashMap::new(),
            packages: HashMap::from([(
                RepositoryPath::parse_decoded("pool/main/p/package/package_1_all.deb")
                    .expect("package path"),
                ObjectIdentity {
                    sha256: digest,
                    size: 12,
                },
            )]),
        }));
        let state = state(spool, catalog, Limits::default());
        let loopback: IpAddr = "127.0.0.1".parse().expect("loopback");

        let mut headers_v4 = HeaderMap::new();
        headers_v4.insert("x-real-ip", "198.51.100.10".parse().expect("ip"));
        let mut headers_mapped = HeaderMap::new();
        headers_mapped.insert("x-real-ip", "::ffff:198.51.100.10".parse().expect("mapped"));
        let mut headers_other = HeaderMap::new();
        headers_other.insert("x-real-ip", "198.51.100.11".parse().expect("other"));

        let ip_a = resolve_client_ip(&state, loopback, &headers_v4).expect("v4");
        let ip_mapped = resolve_client_ip(&state, loopback, &headers_mapped).expect("mapped");
        let ip_b = resolve_client_ip(&state, loopback, &headers_other).expect("other");
        assert_eq!(
            ip_a, ip_mapped,
            "IPv4-mapped IPv6 must share the IPv4 cold pool"
        );
        assert_ne!(
            ip_a, ip_b,
            "distinct proxied clients must have distinct pools"
        );

        let mut guards_a = Vec::new();
        for _ in 0..16 {
            guards_a.push(ColdClient::acquire(&state, ip_a).expect("admitted"));
        }
        assert!(ColdClient::acquire(&state, ip_mapped).is_none());
        let reply = request(
            &state,
            Method::GET,
            "/fixture/pool/main/p/package/package_1_all.deb",
            Some(("x-real-ip", "::ffff:198.51.100.10")),
        )
        .await;
        assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            reply.headers().get("retry-after").expect("retry header"),
            "5"
        );
        let signature_reply = fill_error_response(&FillError::Admission);
        assert_eq!(signature_reply.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            signature_reply
                .headers()
                .get("retry-after")
                .expect("signature retry header"),
            "5"
        );
        let _guard_b =
            ColdClient::acquire(&state, ip_b).expect("second client unaffected by first IP cap");
        drop(guards_a);
        assert!(ColdClient::acquire(&state, ip_a).is_some());

        let mut bad = HeaderMap::new();
        bad.insert("x-real-ip", "not-an-ip".parse().expect("header"));
        assert!(resolve_client_ip(&state, loopback, &bad).is_err());

        let mut duplicate = HeaderMap::new();
        duplicate.append("x-real-ip", "198.51.100.10".parse().expect("first"));
        duplicate.append("x-real-ip", "198.51.100.11".parse().expect("second"));
        assert!(resolve_client_ip(&state, loopback, &duplicate).is_err());
        state.registry.shutdown().await;
    }
}
