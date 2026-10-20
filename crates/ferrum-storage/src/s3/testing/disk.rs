//! Ephemeral, local-only S3 protocol transport. Not a persistent provider emulator.
//!
//! Files are immutable after publication. Reservations include unfinished writes,
//! multipart parts, completion copies and replaced/deleted objects with live readers.
//! Payload I/O is synchronous in at most 256 KiB chunks, outside the catalog lock;
//! writes yield between chunks. This avoids detached filesystem work surviving a
//! cancelled request. This test-only implementation is not a performance benchmark.
//!
//! Supported operations: PUT/GET/HEAD/DELETE, conditional create/replace,
//! ListObjectsV2, and multipart initiate/upload/list-parts/complete/abort/list-uploads.
//! LIST pages contain at most 64 entries; completion XML is capped at 64 KiB and
//! response XML at 1 MiB. Keys are owned ASCII paths of at most 4096 bytes.
//! GET supports one closed, open-ended or suffix byte range; unsatisfiable or
//! malformed ranges return 416. HEAD ignores Range. If-None-Match supports `*`;
//! If-Match supports an opaque ETag or `*`. Other conditional forms are rejected.
//! No versioning, ACLs, alternate endpoints, aws-chunked encoding or general S3
//! emulation is provided. The private parent directory must remain caller-owned;
//! concurrent hostile filesystem mutation is outside this local fixture's model.
//! Cleanup failures retain reservations and files, never recursively erase them.
use super::*;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use ferrum_apt::digest::Sha256Hasher;
use http_body::{Body, Frame, SizeHint};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CHUNK: usize = 256 * 1024;
const MAX_OBJECT: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL: u64 = 16 * MAX_OBJECT;
const MAX_PART: u64 = 16 * 1024 * 1024;
const MAX_PARTS: usize = 64;
const MAX_OBJECTS: usize = 20_000;
const MAX_UPLOADS: usize = 128;
const MAX_FILES: usize = 30_000;
const MAX_REQUESTS: usize = 100_000;
const MAX_CONTROL: usize = 64 * 1024;
const MAX_LIST: usize = 1024 * 1024;
const PAGE: usize = 64;

/// Local disk transport for the real production SDK and its existing ledger.
/// Clones share state; dropping the last store, handle and response removes only
/// files it created and then its empty root. No existing root is ever adopted.
#[derive(Clone)]
pub struct DiskBackedRemote {
    state: Arc<Mutex<State>>,
    root: Arc<Root>,
    slots: Arc<Semaphore>,
    endpoint: Arc<str>,
    host: Arc<str>,
    bucket: Arc<str>,
    prefixes: Arc<[String; 2]>,
}

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Arc<Object>>,
    uploads: BTreeMap<String, Upload>,
    requests: Vec<(String, String)>,
}
struct Root {
    path: PathBuf,
    maximum: u64,
    bytes: AtomicU64,
    files: AtomicUsize,
    sequence: AtomicU64,
}
struct Object {
    file: OwnedFile,
    etag: String,
    owner: Option<String>,
}
struct Upload {
    key: String,
    owner: Option<String>,
    initiated: String,
    revision: u64,
    parts: BTreeMap<u32, Arc<Object>>,
}
// The file handle must close before its reservation can unlink the file (Windows).
struct PendingFile {
    file: File,
    owned: OwnedFile,
}
struct OwnedFile {
    path: PathBuf,
    size: u64,
    root: Arc<Root>,
}

impl Drop for Root {
    fn drop(&mut self) {
        // Never recursively remove a directory, including on error. A crash or
        // external interference leaves an explicit, unadoptable test directory.
        if let Err(error) = std::fs::remove_dir(&self.path) {
            tracing::warn!(%error, "local S3 root cleanup failed; directory retained");
        }
    }
}
impl Drop for OwnedFile {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                self.root.bytes.fetch_sub(self.size, Ordering::AcqRel);
                self.root.files.fetch_sub(1, Ordering::AcqRel);
            }
            Err(error) => {
                // A failed unlink is not free capacity. Do not permit another
                // write to reuse this reservation even if the caller drops it.
                tracing::error!(%error, "local S3 file cleanup failed; reservation retained");
            }
        }
    }
}
impl Root {
    fn sequence(&self) -> Result<u64, ConnectorError> {
        self.sequence
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| remote_error("local identifier ceiling"))
    }
    fn reserve(self: &Arc<Self>, size: u64) -> Result<PendingFile, ConnectorError> {
        self.files
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_FILES).then_some(count + 1)
            })
            .map_err(|_| remote_error("local file count ceiling"))?;
        if self
            .bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |bytes| {
                bytes
                    .checked_add(size)
                    .filter(|total| *total <= self.maximum)
            })
            .is_err()
        {
            self.files.fetch_sub(1, Ordering::AcqRel);
            return Err(remote_error("local aggregate storage ceiling"));
        }
        let result = (|| {
            let path = self.path.join(format!("{:016x}.body", self.sequence()?));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(&path).map_err(io_error)?;
            Ok(PendingFile {
                file,
                owned: OwnedFile {
                    path,
                    size,
                    root: self.clone(),
                },
            })
        })();
        if result.is_err() {
            self.bytes.fetch_sub(size, Ordering::AcqRel);
            self.files.fetch_sub(1, Ordering::AcqRel);
        }
        result
    }
}

impl fmt::Debug for DiskBackedRemote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalDiskS3Transport")
    }
}
impl DiskBackedRemote {
    fn new(
        root: PathBuf,
        maximum: u64,
        endpoint: &str,
        bucket: &str,
        prefixes: [String; 2],
    ) -> Result<Self, S3Error> {
        if maximum == 0 || maximum > MAX_TOTAL || !config::valid_bucket(bucket) {
            return Err(S3Error::Boundary);
        }
        let host = config::valid_endpoint_and_host(endpoint)?;
        let canonical_endpoint = url::Url::parse(endpoint)
            .map_err(|_| S3Error::Boundary)?
            .to_string();
        let root = config::no_symlink_ancestors(&root)?;
        let parent = root.parent().ok_or(S3Error::Boundary)?;
        if !parent.is_dir() || root.file_name().is_none() {
            return Err(S3Error::Boundary);
        }
        let mut directory = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(&root).map_err(|_| S3Error::Boundary)?;
        Ok(Self {
            state: Arc::new(Mutex::new(State::default())),
            root: Arc::new(Root {
                path: root,
                maximum,
                bytes: AtomicU64::new(0),
                files: AtomicUsize::new(0),
                sequence: AtomicU64::new(1),
            }),
            slots: Arc::new(Semaphore::new(32)),
            endpoint: canonical_endpoint.into(),
            host: host.into(),
            bucket: bucket.into(),
            prefixes: Arc::new(prefixes),
        })
    }
    /// Includes all reserved physical bytes, including parts and reader leases.
    pub fn reserved_bytes(&self) -> u64 {
        self.root.bytes.load(Ordering::Acquire)
    }
    /// Bounded trace of accepted operation targets, without credentials or bodies.
    pub fn requests(&self) -> Result<Vec<(String, String)>, S3Error> {
        self.state
            .lock()
            .map(|state| state.requests.clone())
            .map_err(|_| S3Error::Unavailable)
    }
    fn owned_key(&self, key: &str) -> bool {
        remote_key(key)
            && key.split('/').all(|part| !part.is_empty())
            && self
                .prefixes
                .iter()
                .any(|prefix| key.starts_with(prefix) && key.len() > prefix.len())
    }
    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>, ConnectorError> {
        self.state
            .lock()
            .map_err(|_| remote_error("local state poisoned"))
    }
}
impl S3Store {
    /// Constructs a fresh local-only transport using the caller's existing ledger.
    /// `root` must not exist, its parent must exist and no ancestor may be a symlink.
    /// `maximum_bytes` is 1..=16 GiB, counting reservations and leased old versions.
    /// Objects are capped at 1 GiB, parts at 16 MiB, 64 parts/upload, 128 uploads,
    /// 20,000 objects, 30,000 physical files and 32 active requests/read bodies.
    /// No credential file is read. This uses the unchanged production SDK settings
    /// and metering wrapper with dummy credentials, not a socket or HTTP server.
    pub fn disk_backed_production(
        config: super::super::S3Config,
        ledger: crate::budget::BudgetLedger,
        root: PathBuf,
        maximum_bytes: u64,
    ) -> Result<(Self, DiskBackedRemote), S3Error> {
        let identity = Self::scripted_provider(&config, &ledger)?;
        let remote = DiskBackedRemote::new(
            root,
            maximum_bytes,
            &identity.endpoint,
            &identity.bucket,
            [identity.package_prefix, identity.checkpoint_prefix],
        )?;
        let store = Self::scripted(config, ledger, SharedHttpClient::new(remote.clone()))?;
        Ok((store, remote))
    }
}
impl HttpClient for DiskBackedRemote {
    fn http_connector(
        &self,
        _: &HttpConnectorSettings,
        _: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}
impl HttpConnector for DiskBackedRemote {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let remote = self.clone();
        HttpConnectorFuture::new(async move {
            let slot = remote
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| remote_error("local request ceiling"))?;
            remote.execute(request, slot).await
        })
    }
}
fn io_error(error: std::io::Error) -> ConnectorError {
    ConnectorError::user(error.into())
}
fn response(status: u16, body: SdkBody, length: u64) -> Result<Response<SdkBody>, ConnectorError> {
    let mut output = Response::new(
        StatusCode::try_from(status).map_err(|_| remote_error("invalid local status"))?,
        body,
    );
    output
        .headers_mut()
        .insert("content-length", length.to_string());
    Ok(output)
}
fn xml(status: u16, text: String) -> Result<Response<SdkBody>, ConnectorError> {
    if text.len() > MAX_LIST {
        return Err(remote_error("local XML response ceiling"));
    }
    let length = text.len() as u64;
    let mut output = response(status, SdkBody::from(text), length)?;
    output
        .headers_mut()
        .insert("content-type", "application/xml");
    Ok(output)
}
fn failure(status: u16, code: &str) -> Result<Response<SdkBody>, ConnectorError> {
    xml(status, format!("<Error><Code>{code}</Code></Error>"))
}
fn quoted(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Default)]
struct Conditions {
    none: bool,
    matched: Option<String>,
}
impl Conditions {
    fn parse(request: &HttpRequest) -> Result<Self, ConnectorError> {
        let none = request.headers().get("if-none-match");
        let matched = request.headers().get("if-match");
        if none.is_some_and(|value| value != "*")
            || none.is_some() && matched.is_some()
            || matched.is_some_and(|value| value.len() > 128 || value.is_empty())
        {
            return Err(remote_error("unsupported local condition"));
        }
        Ok(Self {
            none: none.is_some(),
            matched: matched.map(str::to_owned),
        })
    }
    fn passes(&self, object: Option<&Arc<Object>>) -> bool {
        (!self.none || object.is_none())
            && self.matched.as_ref().is_none_or(|expected| {
                object.is_some_and(|object| expected == "*" || &object.etag == expected)
            })
    }
}

struct Target {
    key: String,
    query: BTreeMap<String, String>,
    operation: &'static str,
}
impl DiskBackedRemote {
    fn target(&self, request: &HttpRequest) -> Result<Target, ConnectorError> {
        if request.uri().len() > 16 * 1024 {
            return Err(remote_error("local URI ceiling"));
        }
        // URL parsing normalizes dot segments and explicit default ports. Refuse
        // those alternate spellings before parsing; keys never need URL escapes.
        let raw_path = request.uri().split('?').next().unwrap_or_default();
        if !raw_path.starts_with(self.endpoint.as_ref())
            || raw_path.contains('%')
            || raw_path.contains('\\')
            || raw_path.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(remote_error("noncanonical local target"));
        }
        let url = url::Url::parse(request.uri()).map_err(|_| remote_error("invalid local URI"))?;
        if url.scheme() != "https"
            || url.host_str() != Some(self.host.as_ref())
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(remote_error("local transport refuses arbitrary endpoint"));
        }
        let bucket_root = format!("/{}", self.bucket);
        let bucket_slash = format!("/{}/", self.bucket);
        let key = if url.path() == bucket_root || url.path() == bucket_slash {
            String::new()
        } else {
            let key = url
                .path()
                .strip_prefix(&bucket_slash)
                .filter(|key| self.owned_key(key))
                .ok_or_else(|| remote_error("local transport refuses unowned key"))?;
            key.to_owned()
        };
        let mut query = BTreeMap::new();
        for (name, value) in url.query_pairs() {
            if name.len() > 32
                || value.len() > 8192
                || query.len() >= 8
                || query
                    .insert(name.into_owned(), value.into_owned())
                    .is_some()
            {
                return Err(remote_error("invalid local query"));
            }
        }
        let (operation, allowed): (&str, &[&str]) = match (request.method(), key.is_empty()) {
            ("GET", true) if query.get("list-type").is_some_and(|value| value == "2") => (
                "ListObjectsV2",
                &["list-type", "prefix", "max-keys", "continuation-token"],
            ),
            ("GET", true) if query.contains_key("uploads") => (
                "ListMultipartUploads",
                &[
                    "uploads",
                    "prefix",
                    "max-uploads",
                    "key-marker",
                    "upload-id-marker",
                ],
            ),
            ("POST", false) if query.contains_key("uploads") => {
                ("CreateMultipartUpload", &["uploads"])
            }
            ("PUT", false) if query.contains_key("uploadId") => {
                ("UploadPart", &["uploadId", "partNumber"])
            }
            ("POST", false) if query.contains_key("uploadId") => {
                ("CompleteMultipartUpload", &["uploadId"])
            }
            ("GET", false) if query.contains_key("uploadId") => (
                "ListParts",
                &["uploadId", "part-number-marker", "max-parts"],
            ),
            ("DELETE", false) if query.contains_key("uploadId") => {
                ("AbortMultipartUpload", &["uploadId"])
            }
            ("PUT", false) => ("PutObject", &[]),
            ("GET", false) => ("GetObject", &[]),
            ("HEAD", false) => ("HeadObject", &[]),
            ("DELETE", false) => ("DeleteObject", &[]),
            _ => return Err(remote_error("unsupported local operation")),
        };
        if query.iter().any(|(name, value)| {
            if name == "x-id" {
                value != operation
            } else {
                !allowed.contains(&name.as_str())
            }
        }) || query.get("uploads").is_some_and(|value| !value.is_empty())
        {
            return Err(remote_error("unsupported local query parameter"));
        }
        if key.is_empty()
            && query
                .get("prefix")
                .is_none_or(|prefix| !self.prefixes.contains(prefix))
        {
            return Err(remote_error("local listing requires exact owned prefix"));
        }
        if query
            .get("uploadId")
            .is_some_and(|id| id.len() != 16 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(remote_error("invalid local upload ID"));
        }
        Ok(Target {
            key,
            query,
            operation,
        })
    }

    async fn execute(
        &self,
        mut request: HttpRequest,
        slot: OwnedSemaphorePermit,
    ) -> Result<Response<SdkBody>, ConnectorError> {
        let target = self.target(&request)?;
        let conditions = Conditions::parse(&request)?;
        let owner = request
            .headers()
            .get("x-amz-meta-ferrum-owner")
            .map(str::to_owned);
        if owner
            .as_ref()
            .is_some_and(|owner| owner.len() > 256 || !owner.is_ascii())
            || request.headers().get("content-encoding").is_some()
            || request.headers().get("x-amz-trailer").is_some()
        {
            return Err(remote_error("unsupported local body encoding or metadata"));
        }
        if (conditions.none || conditions.matched.is_some())
            && !matches!(
                target.operation,
                "PutObject"
                    | "GetObject"
                    | "HeadObject"
                    | "DeleteObject"
                    | "CompleteMultipartUpload"
            )
        {
            return Err(remote_error("unsupported local operation condition"));
        }
        if !matches!(
            target.operation,
            "PutObject" | "UploadPart" | "CompleteMultipartUpload"
        ) && request.body().content_length() != Some(0)
        {
            return Err(remote_error("unexpected local control body"));
        }
        {
            let mut state = self.state()?;
            if state.requests.len() >= MAX_REQUESTS {
                return Err(remote_error("local trace ceiling"));
            }
            state.requests.push((
                request.method().to_owned(),
                if target.key.is_empty() {
                    target.query.get("prefix").cloned().unwrap_or_default()
                } else {
                    target.key.clone()
                },
            ));
        }
        match target.operation {
            "PutObject" | "UploadPart" => {
                let part = if target.operation == "UploadPart" {
                    Some(number(&target.query, "partNumber", None, MAX_PARTS as u32)?)
                } else {
                    None
                };
                let id = target.query.get("uploadId");
                if let Some(id) = id {
                    let state = self.state()?;
                    if state
                        .uploads
                        .get(id)
                        .is_none_or(|upload| upload.key != target.key)
                    {
                        return failure(404, "NoSuchUpload");
                    }
                }
                let length = request
                    .headers()
                    .get("content-length")
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|length| *length <= if part.is_some() { MAX_PART } else { MAX_OBJECT })
                    .ok_or_else(|| remote_error("missing or excessive local content length"))?;
                let object = Arc::new(self.receive(request.take_body(), length, owner).await?);
                let etag = object.etag.clone();
                let previous = {
                    let mut state = self.state()?;
                    if let (Some(id), Some(part)) = (id, part) {
                        let Some(upload) = state
                            .uploads
                            .get_mut(id)
                            .filter(|upload| upload.key == target.key)
                        else {
                            return failure(404, "NoSuchUpload");
                        };
                        upload.revision = upload
                            .revision
                            .checked_add(1)
                            .ok_or_else(|| remote_error("local revision ceiling"))?;
                        upload.parts.insert(part, object)
                    } else {
                        if !conditions.passes(state.objects.get(&target.key)) {
                            return failure(412, "PreconditionFailed");
                        }
                        if !state.objects.contains_key(&target.key)
                            && state.objects.len() >= MAX_OBJECTS
                        {
                            return Err(remote_error("local object count ceiling"));
                        }
                        state.objects.insert(target.key, object)
                    }
                };
                drop(previous);
                let mut output = response(200, SdkBody::empty(), 0)?;
                output.headers_mut().insert("etag", etag);
                Ok(output)
            }
            "GetObject" | "HeadObject" => {
                let object = self.state()?.objects.get(&target.key).cloned();
                let Some(object) = object else {
                    return if target.operation == "HeadObject" {
                        response(404, SdkBody::empty(), 0)
                    } else {
                        failure(404, "NoSuchKey")
                    };
                };
                if !conditions.passes(Some(&object)) {
                    return if conditions.none {
                        response(304, SdkBody::empty(), 0)
                    } else {
                        failure(412, "PreconditionFailed")
                    };
                }
                let size = object.file.size;
                let range = if target.operation == "GetObject" {
                    match request.headers().get("range") {
                        Some(value) => match byte_range(value, size) {
                            Some(range) => Some(range),
                            None => {
                                let mut output = failure(416, "InvalidRange")?;
                                output
                                    .headers_mut()
                                    .insert("content-range", format!("bytes */{size}"));
                                return Ok(output);
                            }
                        },
                        None => None,
                    }
                } else {
                    None
                };
                let (offset, length) = range.unwrap_or((0, size));
                let body = if target.operation == "HeadObject" {
                    SdkBody::empty()
                } else {
                    let mut file = File::open(&object.file.path).map_err(io_error)?;
                    file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
                    SdkBody::from_body_1_x(FileBody {
                        file,
                        _object: object.clone(),
                        remaining: length,
                        _slot: slot,
                    })
                };
                let mut output = response(if range.is_some() { 206 } else { 200 }, body, length)?;
                output.headers_mut().insert("etag", object.etag.clone());
                output.headers_mut().insert("accept-ranges", "bytes");
                if let Some(owner) = &object.owner {
                    output
                        .headers_mut()
                        .insert("x-amz-meta-ferrum-owner", owner.clone());
                }
                if range.is_some() {
                    output.headers_mut().insert(
                        "content-range",
                        format!("bytes {offset}-{}/{size}", offset + length - 1),
                    );
                }
                Ok(output)
            }
            "DeleteObject" => {
                let previous = {
                    let mut state = self.state()?;
                    if !conditions.passes(state.objects.get(&target.key)) {
                        return failure(412, "PreconditionFailed");
                    }
                    state.objects.remove(&target.key)
                };
                drop(previous);
                response(204, SdkBody::empty(), 0)
            }
            "CreateMultipartUpload" => {
                let id = format!("{:016x}", self.root.sequence()?);
                let now = crate::s3::production_now()
                    .map_err(|_| remote_error("local clock outside timestamp bounds"))?;
                let initiated = aws_smithy_types::DateTime::from_secs(now)
                    .fmt(aws_smithy_types::date_time::Format::DateTime)
                    .map_err(|_| remote_error("local clock outside timestamp bounds"))?;
                {
                    let mut state = self.state()?;
                    if state.uploads.len() >= MAX_UPLOADS {
                        return Err(remote_error("local upload count ceiling"));
                    }
                    state.uploads.insert(
                        id.clone(),
                        Upload {
                            key: target.key.clone(),
                            owner,
                            initiated,
                            revision: 0,
                            parts: BTreeMap::new(),
                        },
                    );
                }
                xml(
                    200,
                    format!(
                        "<InitiateMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>",
                        quoted(&self.bucket),
                        quoted(&target.key)
                    ),
                )
            }
            "AbortMultipartUpload" => {
                let id = target
                    .query
                    .get("uploadId")
                    .ok_or_else(|| remote_error("missing upload ID"))?;
                let previous = {
                    let mut state = self.state()?;
                    if state
                        .uploads
                        .get(id)
                        .is_none_or(|upload| upload.key != target.key)
                    {
                        return failure(404, "NoSuchUpload");
                    }
                    state.uploads.remove(id)
                };
                drop(previous);
                response(204, SdkBody::empty(), 0)
            }
            "CompleteMultipartUpload" => {
                self.complete(target, request.take_body(), conditions).await
            }
            "ListObjectsV2" => self.list_objects(&target.query),
            "ListMultipartUploads" => self.list_uploads(&target.query),
            "ListParts" => self.list_parts(&target),
            _ => Err(remote_error("unsupported local operation")),
        }
    }

    async fn receive(
        &self,
        mut body: SdkBody,
        length: u64,
        owner: Option<String>,
    ) -> Result<Object, ConnectorError> {
        let mut pending = self.root.reserve(length)?;
        let mut written = 0u64;
        let mut hash = Sha256Hasher::new();
        while let Some(frame) =
            std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
        {
            let frame = frame.map_err(|_| remote_error("local SDK body failed"))?;
            let data = frame
                .into_data()
                .map_err(|_| remote_error("unexpected local body trailers"))?;
            if data.len() as u64 > length - written {
                return Err(remote_error("local body exceeded content length"));
            }
            for chunk in data.chunks(CHUNK) {
                pending.file.write_all(chunk).map_err(io_error)?;
                hash.update(chunk);
                written += chunk.len() as u64;
                tokio::task::yield_now().await;
            }
        }
        if written != length {
            return Err(remote_error("truncated local request body"));
        }
        pending.file.flush().map_err(io_error)?;
        let PendingFile { file, owned } = pending;
        drop(file);
        Ok(Object {
            file: owned,
            etag: format!("\"{}\"", hash.finalize()),
            owner,
        })
    }
}

struct FileBody {
    file: File,
    _object: Arc<Object>,
    remaining: u64,
    _slot: OwnedSemaphorePermit,
}
impl Body for FileBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let mut bytes = vec![0u8; self.remaining.min(CHUNK as u64) as usize];
        match self.file.read(&mut bytes) {
            Ok(0) => {
                self.remaining = 0;
                Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated local object",
                ))))
            }
            Ok(length) => {
                bytes.truncate(length);
                self.remaining -= length as u64;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(bytes)))))
            }
            Err(error) => {
                self.remaining = 0;
                Poll::Ready(Some(Err(error)))
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}
fn byte_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    if size == 0 {
        return None;
    }
    let decimal = |value: &str| {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            None
        } else {
            value.parse::<u64>().ok()
        }
    };
    if start.is_empty() {
        let length = decimal(end)?.min(size);
        return (length > 0).then_some((size - length, length));
    }
    let start = decimal(start)?;
    let end = if end.is_empty() {
        size - 1
    } else {
        decimal(end)?.min(size - 1)
    };
    if start > end {
        None
    } else {
        Some((start, end - start + 1))
    }
}
fn number(
    query: &BTreeMap<String, String>,
    name: &str,
    default: Option<u32>,
    maximum: u32,
) -> Result<u32, ConnectorError> {
    let value = match query.get(name) {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse::<u32>().ok()
        }
        Some(_) => None,
        None => default,
    };
    value
        .filter(|value| *value > 0 && *value <= maximum)
        .ok_or_else(|| remote_error("invalid local numeric parameter"))
}

impl DiskBackedRemote {
    fn list_objects(
        &self,
        query: &BTreeMap<String, String>,
    ) -> Result<Response<SdkBody>, ConnectorError> {
        let prefix = query
            .get("prefix")
            .ok_or_else(|| remote_error("missing local prefix"))?;
        let limit = number(query, "max-keys", Some(PAGE as u32), PAGE as u32)? as usize;
        let after = query.get("continuation-token");
        if after.is_some_and(|key| !self.owned_key(key) || !key.starts_with(prefix)) {
            return Err(remote_error("invalid local continuation"));
        }
        let state = self.state()?;
        let mut entries = state
            .objects
            .iter()
            .filter(|(key, _)| key.starts_with(prefix) && after.is_none_or(|after| *key > after));
        let mut text = format!(
            "<ListBucketResult><Name>{}</Name><Prefix>{}</Prefix><MaxKeys>{limit}</MaxKeys>",
            quoted(&self.bucket),
            quoted(prefix)
        );
        let mut count = 0;
        let mut last = None;
        for (key, object) in entries.by_ref().take(limit) {
            text.push_str(&format!(
                "<Contents><Key>{}</Key><Size>{}</Size><ETag>{}</ETag><StorageClass>STANDARD</StorageClass></Contents>",
                quoted(key),
                object.file.size,
                quoted(&object.etag)
            ));
            last = Some(key);
            count += 1;
        }
        let more = entries.next().is_some();
        text.push_str(&format!(
            "<KeyCount>{count}</KeyCount><IsTruncated>{more}</IsTruncated>"
        ));
        if more && let Some(last) = last {
            text.push_str(&format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                quoted(last)
            ));
        }
        text.push_str("</ListBucketResult>");
        xml(200, text)
    }

    fn list_uploads(
        &self,
        query: &BTreeMap<String, String>,
    ) -> Result<Response<SdkBody>, ConnectorError> {
        let prefix = query
            .get("prefix")
            .ok_or_else(|| remote_error("missing local prefix"))?;
        let limit = number(query, "max-uploads", Some(PAGE as u32), PAGE as u32)? as usize;
        let key_marker = query.get("key-marker");
        let id_marker = query.get("upload-id-marker");
        if key_marker.is_some_and(|key| !self.owned_key(key) || !key.starts_with(prefix))
            || id_marker.is_some_and(|id| {
                key_marker.is_none()
                    || id.len() != 16
                    || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(remote_error("invalid local upload marker"));
        }
        let state = self.state()?;
        // At most 128 references; the wire page and its XML are separately bounded.
        let mut uploads: Vec<_> = state
            .uploads
            .iter()
            .filter(|(id, upload)| {
                upload.key.starts_with(prefix)
                    && key_marker.is_none_or(|marker| {
                        &upload.key > marker
                            || &upload.key == marker && id_marker.is_some_and(|marker| *id > marker)
                    })
            })
            .collect();
        uploads.sort_unstable_by(|(left_id, left), (right_id, right)| {
            (&left.key, left_id).cmp(&(&right.key, right_id))
        });
        let more = uploads.len() > limit;
        let mut text = format!(
            "<ListMultipartUploadsResult><Bucket>{}</Bucket><Prefix>{}</Prefix><MaxUploads>{limit}</MaxUploads><IsTruncated>{more}</IsTruncated>",
            quoted(&self.bucket),
            quoted(prefix)
        );
        for (id, upload) in uploads.iter().take(limit) {
            text.push_str(&format!(
                "<Upload><Key>{}</Key><UploadId>{id}</UploadId><Initiated>{}</Initiated><StorageClass>STANDARD</StorageClass></Upload>",
                quoted(&upload.key),
                upload.initiated
            ));
        }
        if more {
            let (id, upload) = uploads[limit - 1];
            text.push_str(&format!(
                "<NextKeyMarker>{}</NextKeyMarker><NextUploadIdMarker>{id}</NextUploadIdMarker>",
                quoted(&upload.key)
            ));
        }
        text.push_str("</ListMultipartUploadsResult>");
        xml(200, text)
    }

    fn list_parts(&self, target: &Target) -> Result<Response<SdkBody>, ConnectorError> {
        let id = target
            .query
            .get("uploadId")
            .ok_or_else(|| remote_error("missing local upload ID"))?;
        let limit = number(&target.query, "max-parts", Some(PAGE as u32), PAGE as u32)? as usize;
        let after = match target.query.get("part-number-marker") {
            Some(value) if value == "0" => 0,
            Some(_) => number(&target.query, "part-number-marker", None, MAX_PARTS as u32)?,
            None => 0,
        };
        let state = self.state()?;
        let Some(upload) = state
            .uploads
            .get(id)
            .filter(|upload| upload.key == target.key)
        else {
            return failure(404, "NoSuchUpload");
        };
        let mut parts = upload.parts.iter().filter(|(number, _)| **number > after);
        let mut text = format!(
            "<ListPartsResult><Bucket>{}</Bucket><Key>{}</Key><UploadId>{id}</UploadId><PartNumberMarker>{after}</PartNumberMarker><MaxParts>{limit}</MaxParts>",
            quoted(&self.bucket),
            quoted(&target.key)
        );
        let mut last = after;
        for (number, part) in parts.by_ref().take(limit) {
            text.push_str(&format!(
                "<Part><PartNumber>{number}</PartNumber><ETag>{}</ETag><Size>{}</Size></Part>",
                quoted(&part.etag),
                part.file.size
            ));
            last = *number;
        }
        let more = parts.next().is_some();
        text.push_str(&format!(
            "<IsTruncated>{more}</IsTruncated><NextPartNumberMarker>{last}</NextPartNumberMarker></ListPartsResult>"
        ));
        xml(200, text)
    }

    async fn complete(
        &self,
        target: Target,
        body: SdkBody,
        conditions: Conditions,
    ) -> Result<Response<SdkBody>, ConnectorError> {
        let requested = match completed_parts(body).await {
            Ok(parts) => parts,
            Err(_) => return failure(400, "MalformedXML"),
        };
        let id = target
            .query
            .get("uploadId")
            .ok_or_else(|| remote_error("missing local upload ID"))?;
        let (parts, owner, revision) = {
            let state = self.state()?;
            let Some(upload) = state
                .uploads
                .get(id)
                .filter(|upload| upload.key == target.key)
            else {
                return failure(404, "NoSuchUpload");
            };
            let mut parts = Vec::with_capacity(requested.len());
            for (index, (number, etag)) in requested.iter().enumerate() {
                let Some(part) = upload.parts.get(number).filter(|part| &part.etag == etag) else {
                    return failure(400, "InvalidPart");
                };
                if index + 1 < requested.len() && part.file.size < 5 * 1024 * 1024 {
                    return failure(400, "EntityTooSmall");
                }
                parts.push(part.clone());
            }
            (parts, upload.owner.clone(), upload.revision)
        };
        let length = parts
            .iter()
            .try_fold(0u64, |size, part| size.checked_add(part.file.size))
            .filter(|size| *size <= MAX_OBJECT)
            .ok_or_else(|| remote_error("local completed object ceiling"))?;
        // Parts stay reserved until the new immutable object has been installed.
        let mut pending = self.root.reserve(length)?;
        let mut buffer = vec![0u8; CHUNK];
        let mut hash = Sha256Hasher::new();
        for part in &parts {
            let mut file = File::open(&part.file.path).map_err(io_error)?;
            let mut remaining = part.file.size;
            while remaining != 0 {
                let count = remaining.min(CHUNK as u64) as usize;
                file.read_exact(&mut buffer[..count]).map_err(io_error)?;
                pending.file.write_all(&buffer[..count]).map_err(io_error)?;
                hash.update(&buffer[..count]);
                remaining -= count as u64;
                tokio::task::yield_now().await;
            }
        }
        pending.file.flush().map_err(io_error)?;
        let PendingFile { file, owned } = pending;
        drop(file);
        let etag = format!("\"{}-{}\"", hash.finalize(), parts.len());
        let object = Arc::new(Object {
            file: owned,
            etag: etag.clone(),
            owner,
        });
        let (previous, upload) = {
            let mut state = self.state()?;
            let Some(upload) = state
                .uploads
                .get(id)
                .filter(|upload| upload.key == target.key)
            else {
                return failure(404, "NoSuchUpload");
            };
            if upload.revision != revision {
                return failure(409, "ConditionalRequestConflict");
            }
            if !conditions.passes(state.objects.get(&target.key)) {
                return failure(412, "PreconditionFailed");
            }
            if !state.objects.contains_key(&target.key) && state.objects.len() >= MAX_OBJECTS {
                return Err(remote_error("local object count ceiling"));
            }
            let previous = state.objects.insert(target.key.clone(), object);
            (previous, state.uploads.remove(id))
        };
        drop(previous);
        drop(upload);
        xml(
            200,
            format!(
                "<CompleteMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>",
                quoted(&self.bucket),
                quoted(&target.key),
                quoted(&etag)
            ),
        )
    }
}

async fn completed_parts(mut body: SdkBody) -> Result<Vec<(u32, String)>, ConnectorError> {
    let mut bytes = Vec::new();
    while let Some(frame) =
        std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
    {
        let data = frame
            .map_err(|_| remote_error("local completion body failed"))?
            .into_data()
            .map_err(|_| remote_error("local completion trailers refused"))?;
        if data.len() > MAX_CONTROL - bytes.len() {
            return Err(remote_error("local completion XML ceiling"));
        }
        bytes.extend_from_slice(&data);
    }
    parse_parts(std::str::from_utf8(&bytes).map_err(|_| remote_error("non UTF-8 completion"))?)
}

fn parse_parts(text: &str) -> Result<Vec<(u32, String)>, ConnectorError> {
    use xmlparser::{ElementEnd, Token, Tokenizer};
    let invalid = || remote_error("invalid local completion XML");
    let mut stack = Vec::new();
    let mut parts = Vec::new();
    let mut number = None;
    let mut etag = None;
    let mut value = String::new();
    let mut opened = false;
    let mut closed = false;
    for token in Tokenizer::from(text) {
        match token.map_err(|_| invalid())? {
            Token::Declaration { .. } if !opened => {}
            Token::ElementStart { prefix, local, .. } if prefix.as_str().is_empty() && !closed => {
                let name = local.as_str();
                let valid = match stack.as_slice() {
                    [] => name == "CompleteMultipartUpload" && !opened,
                    ["CompleteMultipartUpload"] => name == "Part" && parts.len() < MAX_PARTS,
                    ["CompleteMultipartUpload", "Part"] => matches!(name, "PartNumber" | "ETag"),
                    _ => false,
                };
                if !valid {
                    return Err(invalid());
                }
                opened = true;
                value.clear();
                stack.push(name);
            }
            Token::Attribute {
                prefix,
                local,
                value,
                ..
            } if stack.as_slice() == ["CompleteMultipartUpload"]
                && prefix.as_str().is_empty()
                && local.as_str() == "xmlns"
                && value.as_str() == "http://s3.amazonaws.com/doc/2006-03-01/" => {}
            Token::ElementEnd {
                end: ElementEnd::Open,
                ..
            } => {}
            Token::Text { text } => {
                if stack.len() == 3 {
                    if value.len() + text.as_str().len() > 256 {
                        return Err(invalid());
                    }
                    value.push_str(text.as_str());
                } else if !text.as_str().trim().is_empty() {
                    return Err(invalid());
                }
            }
            Token::ElementEnd {
                end: ElementEnd::Close(prefix, name),
                ..
            } => {
                if !prefix.as_str().is_empty() || stack.pop() != Some(name.as_str()) {
                    return Err(invalid());
                }
                match name.as_str() {
                    "PartNumber" => {
                        if number.is_some()
                            || value.is_empty()
                            || !value.bytes().all(|byte| byte.is_ascii_digit())
                        {
                            return Err(invalid());
                        }
                        number = value
                            .parse::<u32>()
                            .ok()
                            .filter(|number| *number > 0 && *number <= MAX_PARTS as u32);
                        if number.is_none() {
                            return Err(invalid());
                        }
                    }
                    "ETag" => {
                        if etag.is_some() {
                            return Err(invalid());
                        }
                        // The SDK XML serializer escapes quotes. No general XML
                        // entity expansion, DTD, namespaces or nested values.
                        let decoded = value.replace("&quot;", "\"");
                        if decoded.contains('&') || decoded.len() > 128 || decoded.is_empty() {
                            return Err(invalid());
                        }
                        etag = Some(decoded);
                    }
                    "Part" => {
                        let number = number.take().ok_or_else(invalid)?;
                        if parts
                            .last()
                            .is_some_and(|(previous, _)| *previous >= number)
                        {
                            return Err(invalid());
                        }
                        parts.push((number, etag.take().ok_or_else(invalid)?));
                    }
                    "CompleteMultipartUpload" => closed = true,
                    _ => return Err(invalid()),
                }
                value.clear();
            }
            _ => return Err(invalid()),
        }
    }
    if !closed || !stack.is_empty() || parts.is_empty() {
        return Err(invalid());
    }
    Ok(parts)
}

#[cfg(test)]
mod tests;
