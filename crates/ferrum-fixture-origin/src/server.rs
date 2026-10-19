//! Loopback static-file data server with injectable faults.
//!
//! Serves `GET`/`HEAD` of regular files under the configured root at
//! `<prefix><relative>`. Bodies are streamed in bounded chunks; the whole file is
//! never buffered, not even for the `corrupt` fault (the byte is flipped inside the
//! chunk that covers its offset).

use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use http::{HeaderMap, Method, StatusCode, Uri, header};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::faults::{FaultKind, FaultTable, PendingEntry, RequestLog};

/// Largest single read issued against a served file.
pub const READ_CHUNK: usize = 64 * 1024;

const READ_CHUNK_U64: u64 = READ_CHUNK as u64;

/// Listener addresses the fixture origin refuses or cannot bind.
#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    #[error("refusing to bind non-loopback address {0}: the fixture origin is loopback-only")]
    NotLoopback(SocketAddr),
    #[error("failed to bind {address}: {source}")]
    Bind {
        address: SocketAddr,
        #[source]
        source: io::Error,
    },
}

/// Reject any address whose IP is not loopback (`127.0.0.0/8` or `::1`).
pub fn require_loopback(address: SocketAddr) -> Result<(), ListenError> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(ListenError::NotLoopback(address))
    }
}

/// Bind a TCP listener after [`require_loopback`]; port `0` picks an ephemeral port.
pub async fn bind_loopback(address: SocketAddr) -> Result<TcpListener, ListenError> {
    require_loopback(address)?;
    TcpListener::bind(address)
        .await
        .map_err(|source| ListenError::Bind { address, source })
}

/// Configuration problems detected when creating an origin or swapping its root.
#[derive(Debug, thiserror::Error)]
pub enum OriginError {
    #[error("prefix {0:?} must start and end with '/'")]
    InvalidPrefix(String),
    #[error("root {0} is not a directory")]
    RootNotDirectory(PathBuf),
    #[error("cannot resolve root {path}: {source}")]
    RootIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Why a request target or fault path was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("path is empty")]
    Empty,
    #[error("malformed percent-encoding")]
    MalformedEncoding,
    #[error("percent-encoded path separator")]
    EncodedSeparator,
    #[error("forbidden byte 0x{0:02x}")]
    ForbiddenByte(u8),
    #[error("empty path segment")]
    EmptySegment,
    #[error("'.' or '..' segment")]
    DotSegment,
    #[error("trailing separator")]
    TrailingSeparator,
    #[error("path is not valid UTF-8")]
    InvalidUtf8,
}

/// Percent-decode a request target remainder exactly once and validate it as a
/// relative repository path.
///
/// Rejects malformed `%XX`, encoded `/` and `\`, control bytes, backslash, empty
/// segments, `.`/`..` segments and a trailing separator.
pub fn decode_request_path(raw: &str) -> Result<String, PathError> {
    if raw.is_empty() {
        return Err(PathError::Empty);
    }
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let high = bytes
            .next()
            .and_then(hex_value)
            .ok_or(PathError::MalformedEncoding)?;
        let low = bytes
            .next()
            .and_then(hex_value)
            .ok_or(PathError::MalformedEncoding)?;
        let value = (high << 4) | low;
        if value == b'/' || value == b'\\' {
            return Err(PathError::EncodedSeparator);
        }
        decoded.push(value);
    }
    let text = String::from_utf8(decoded).map_err(|_| PathError::InvalidUtf8)?;
    validate_relative_path(&text)?;
    Ok(text)
}

/// Validate an already decoded relative path (also used for control-API fault keys).
pub fn validate_relative_path(text: &str) -> Result<(), PathError> {
    if text.is_empty() {
        return Err(PathError::Empty);
    }
    if let Some(byte) = text
        .bytes()
        .find(|byte| *byte < 0x20 || *byte == 0x7f || *byte == b'\\')
    {
        return Err(PathError::ForbiddenByte(byte));
    }
    if text.ends_with('/') {
        return Err(PathError::TrailingSeparator);
    }
    for segment in text.split('/') {
        if segment.is_empty() {
            return Err(PathError::EmptySegment);
        }
        if segment == "." || segment == ".." {
            return Err(PathError::DotSegment);
        }
    }
    Ok(())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Shared origin state: served root, fault table, request log and settings.
///
/// Cloning is cheap; all clones observe the same state.
#[derive(Clone)]
pub struct Origin {
    inner: Arc<OriginInner>,
}

struct OriginInner {
    prefix: String,
    root: RwLock<Arc<PathBuf>>,
    faults: FaultTable,
    log: RequestLog,
    head_enabled: AtomicBool,
    started: Instant,
}

impl Origin {
    /// Create an origin serving `root` (must be an existing directory) under `prefix`
    /// (must start and end with `/`).
    ///
    /// # Errors
    /// [`OriginError::InvalidPrefix`], [`OriginError::RootNotDirectory`] or
    /// [`OriginError::RootIo`] when the root cannot be canonicalised.
    pub async fn new(root: PathBuf, prefix: String) -> Result<Self, OriginError> {
        if !prefix.starts_with('/') || !prefix.ends_with('/') {
            return Err(OriginError::InvalidPrefix(prefix));
        }
        let root = canonical_directory(root).await?;
        Ok(Self {
            inner: Arc::new(OriginInner {
                prefix,
                root: RwLock::new(Arc::new(root)),
                faults: FaultTable::default(),
                log: RequestLog::default(),
                head_enabled: AtomicBool::new(true),
                started: Instant::now(),
            }),
        })
    }

    pub fn prefix(&self) -> &str {
        &self.inner.prefix
    }

    pub fn faults(&self) -> &FaultTable {
        &self.inner.faults
    }

    pub fn log(&self) -> &RequestLog {
        &self.inner.log
    }

    /// Canonical directory currently served.
    pub fn root(&self) -> Arc<PathBuf> {
        Arc::clone(&self.read_root())
    }

    /// Swap the served tree after verifying `root` is an existing directory.
    ///
    /// # Errors
    /// [`OriginError::RootNotDirectory`] or [`OriginError::RootIo`].
    pub async fn set_root(&self, root: PathBuf) -> Result<(), OriginError> {
        let root = Arc::new(canonical_directory(root).await?);
        let mut guard = self
            .inner
            .root
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = root;
        Ok(())
    }

    pub fn head_enabled(&self) -> bool {
        self.inner.head_enabled.load(Ordering::Relaxed)
    }

    pub fn set_head_enabled(&self, enabled: bool) {
        self.inner.head_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Router for the data listener: every path is handled by the file server.
    pub fn data_router(&self) -> Router {
        Router::new().fallback(serve_file).with_state(self.clone())
    }

    /// Router for the control listener.
    pub fn control_router(&self) -> Router {
        crate::control::router(self.clone())
    }

    fn read_root(&self) -> std::sync::RwLockReadGuard<'_, Arc<PathBuf>> {
        self.inner
            .root
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn elapsed(&self) -> Duration {
        self.inner.started.elapsed()
    }
}

async fn canonical_directory(path: PathBuf) -> Result<PathBuf, OriginError> {
    let canonical = tokio::fs::canonicalize(&path)
        .await
        .map_err(|source| OriginError::RootIo {
            path: path.clone(),
            source,
        })?;
    let metadata = tokio::fs::metadata(&canonical)
        .await
        .map_err(|source| OriginError::RootIo {
            path: path.clone(),
            source,
        })?;
    if !metadata.is_dir() {
        return Err(OriginError::RootNotDirectory(path));
    }
    Ok(canonical)
}

struct ResolvedFile {
    path: PathBuf,
    size: u64,
    metadata_validator: Option<String>,
}

/// Resolve `relative` under `root`, following symlinks, and accept only regular files
/// whose canonical path stays inside the canonical root.
async fn resolve_file(root: &Path, relative: &str) -> Option<ResolvedFile> {
    let canonical = tokio::fs::canonicalize(root.join(relative)).await.ok()?;
    if !canonical.starts_with(root) {
        return None;
    }
    let metadata = tokio::fs::metadata(&canonical).await.ok()?;
    if !metadata.is_file() {
        return None;
    }
    // Generated signed metadata is immutable within one generation directory.
    // Include the canonical generation path so changing the served root cannot
    // accidentally reuse a validator for an equally-sized successor.
    let metadata_validator = if relative.ends_with("/InRelease") {
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        canonical.hash(&mut hash);
        metadata.len().hash(&mut hash);
        metadata.modified().ok()?.hash(&mut hash);
        Some(format!("\"fixture-{:016x}\"", hash.finish()))
    } else {
        None
    };
    Some(ResolvedFile {
        path: canonical,
        size: metadata.len(),
        metadata_validator,
    })
}

async fn serve_file(
    State(origin): State<Origin>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let mut pending = PendingEntry {
        at: origin.elapsed(),
        method: method.to_string(),
        path: uri.path().to_owned(),
        status: 0,
        range: headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        fault: None,
    };

    let is_head = method == Method::HEAD;
    if method != Method::GET && !is_head {
        return finish_headers_only(&origin, pending, method_not_allowed("GET, HEAD"));
    }
    if is_head && !origin.head_enabled() {
        return finish_headers_only(&origin, pending, method_not_allowed("GET"));
    }

    let relative = uri
        .path()
        .strip_prefix(origin.prefix())
        .ok_or(PathError::Empty)
        .and_then(decode_request_path);
    let relative = match relative {
        Ok(relative) => relative,
        Err(error) => {
            tracing::debug!(path = uri.path(), %error, "rejected request path");
            return finish_headers_only(&origin, pending, not_found());
        }
    };
    pending.path = relative;

    let root = origin.root();
    let Some(file) = resolve_file(&root, &pending.path).await else {
        return finish_headers_only(&origin, pending, not_found());
    };

    let fault = origin.faults().take_for(&pending.path);
    pending.fault = fault;
    match fault {
        Some(FaultKind::Delete) => return finish_headers_only(&origin, pending, not_found()),
        Some(FaultKind::Delay { ms }) => tokio::time::sleep(Duration::from_millis(ms)).await,
        _ => {}
    }
    if fault.is_none()
        && let Some(validator) = &file.metadata_validator
        && headers
            .get(header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok())
            == Some(validator.as_str())
    {
        return finish_headers_only(
            &origin,
            pending,
            Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, validator)
                .body(Body::empty()),
        );
    }

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_LENGTH, file.size)
        .header(header::CONTENT_TYPE, "application/octet-stream");
    if let Some(validator) = &file.metadata_validator {
        response = response.header(header::ETAG, validator);
    }
    if is_head {
        return finish_headers_only(&origin, pending, response.body(Body::empty()));
    }

    let opened = match File::open(&file.path).await {
        Ok(opened) => opened,
        Err(error) => {
            tracing::debug!(path = %file.path.display(), %error, "file vanished before open");
            return finish_headers_only(&origin, pending, not_found());
        }
    };
    let mode = BodyMode::from_fault(fault);
    let stream = LoggedStream::new(file_stream(opened, file.size, mode), origin, pending);
    let response = response.body(Body::from_stream(stream));
    match response {
        Ok(response) => response,
        Err(error) => internal_error(&error),
    }
}

fn not_found() -> http::Result<Response> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_LENGTH, 0)
        .body(Body::empty())
}

fn method_not_allowed(allow: &'static str) -> http::Result<Response> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::ALLOW, allow)
        .header(header::CONTENT_LENGTH, 0)
        .body(Body::empty())
}

fn internal_error(error: &http::Error) -> Response {
    tracing::error!(%error, "failed to build response");
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

/// Record a request whose body carries no bytes (HEAD, 404, 405) and return it.
fn finish_headers_only(
    origin: &Origin,
    mut pending: PendingEntry,
    response: http::Result<Response>,
) -> Response {
    let response = match response {
        Ok(response) => response,
        Err(error) => internal_error(&error),
    };
    pending.status = response.status().as_u16();
    origin.log().record(pending, 0);
    response
}

#[derive(Clone, Copy, Debug)]
enum BodyMode {
    Plain,
    Truncate { at: u64 },
    Pace { chunk: u64, interval: Duration },
    Corrupt { offset: u64 },
}

impl BodyMode {
    fn from_fault(fault: Option<FaultKind>) -> Self {
        match fault {
            Some(FaultKind::Truncate { at }) => BodyMode::Truncate { at },
            Some(FaultKind::Pace { chunk, interval_ms }) => BodyMode::Pace {
                chunk,
                interval: Duration::from_millis(interval_ms),
            },
            Some(FaultKind::Corrupt { offset }) => BodyMode::Corrupt { offset },
            Some(FaultKind::Delay { .. } | FaultKind::Delete) | None => BodyMode::Plain,
        }
    }
}

struct StreamState {
    file: File,
    mode: BodyMode,
    /// Bytes yielded so far.
    position: u64,
    /// Bytes this stream will yield (the file size, or `at` for truncation).
    length: u64,
    /// Bytes left in the current pacing chunk before the next interval sleep.
    pace_left: u64,
    finished: bool,
}

/// Stream the first `length` bytes of `file` in reads of at most [`READ_CHUNK`].
///
/// `Truncate` yields an error after its bytes so hyper aborts the connection instead of
/// finishing the declared `Content-Length` cleanly. A short or failed read is an error
/// too; the declared length is never padded.
fn file_stream(
    file: File,
    size: u64,
    mode: BodyMode,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    let length = match mode {
        BodyMode::Truncate { at } => at.min(size),
        _ => size,
    };
    let state = StreamState {
        file,
        mode,
        position: 0,
        length,
        pace_left: 0,
        finished: false,
    };
    futures_util::stream::unfold(state, |mut state| async move {
        if state.finished {
            return None;
        }
        match next_chunk(&mut state).await {
            Ok(Some(chunk)) => Some((Ok(chunk), state)),
            Ok(None) => None,
            Err(error) => {
                state.finished = true;
                Some((Err(error), state))
            }
        }
    })
}

async fn next_chunk(state: &mut StreamState) -> Result<Option<Bytes>, io::Error> {
    if state.position >= state.length {
        if let BodyMode::Truncate { .. } = state.mode {
            // Let hyper flush the bytes already queued before the error tears the
            // connection down; a synchronous error here would drop them unflushed.
            tokio::task::yield_now().await;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "truncate fault: aborting after declared bytes",
            ));
        }
        return Ok(None);
    }

    let mut want = READ_CHUNK_U64.min(state.length.saturating_sub(state.position));
    if let BodyMode::Pace { chunk, interval } = state.mode {
        if state.pace_left == 0 {
            if state.position > 0 {
                tokio::time::sleep(interval).await;
            }
            state.pace_left = chunk;
        }
        want = want.min(state.pace_left);
    }
    let capacity = usize::try_from(want).map_err(|_| io::Error::other("chunk exceeds usize"))?;

    // `read_buf` reads at most the spare capacity, so a chunk never exceeds `want`.
    let mut buffer = BytesMut::with_capacity(capacity);
    let read = state.file.read_buf(&mut buffer).await?;
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "file shrank below its declared length",
        ));
    }
    let read_len = u64::try_from(read).map_err(|_| io::Error::other("read length overflow"))?;

    if let BodyMode::Corrupt { offset } = state.mode {
        let in_chunk = offset
            .checked_sub(state.position)
            .filter(|index| *index < read_len)
            .and_then(|index| usize::try_from(index).ok());
        if let Some(byte) = in_chunk.and_then(|index| buffer.get_mut(index)) {
            *byte ^= 0xFF;
        }
    }

    state.position = state
        .position
        .checked_add(read_len)
        .ok_or_else(|| io::Error::other("position overflow"))?;
    state.pace_left = state.pace_left.saturating_sub(read_len);
    Ok(Some(buffer.freeze()))
}

/// Counts body bytes handed to the transport and records the request-log entry when
/// the body completes or the client disconnects (the stream is dropped either way).
struct LoggedStream<S> {
    inner: Pin<Box<S>>,
    origin: Origin,
    pending: Option<PendingEntry>,
    bytes_sent: u64,
}

impl<S> LoggedStream<S> {
    fn new(inner: S, origin: Origin, mut pending: PendingEntry) -> Self {
        pending.status = StatusCode::OK.as_u16();
        Self {
            inner: Box::pin(inner),
            origin,
            pending: Some(pending),
            bytes_sent: 0,
        }
    }
}

impl<S> Stream for LoggedStream<S>
where
    S: Stream<Item = Result<Bytes, io::Error>>,
{
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let polled = this.inner.as_mut().poll_next(cx);
        if let Poll::Ready(Some(Ok(chunk))) = &polled {
            let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            this.bytes_sent = this.bytes_sent.saturating_add(chunk_len);
        }
        polled
    }
}

impl<S> Drop for LoggedStream<S> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.origin.log().record(pending, self.bytes_sent);
        }
    }
}
