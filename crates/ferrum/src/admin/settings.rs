//! Revisioned, allowlisted restart-only settings. Source TOML stays in bounded
//! process memory; API previews and durable proposals contain only permitted edits.
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path as FsPath, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use ferrum_apt::digest::Sha256Digest;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use toml_edit::{DocumentMut, Item, Table, value};

use super::{
    AdminStore,
    inventory::config_projection,
    model::{AuthContext, Permission, StoreError},
    password,
    routes::{authenticate, error_reply, store_error},
    store::{actor, audit, check_file, create_private, sync_directory},
};
use crate::{
    config::{Config, DurableTrust},
    health::HealthState,
};

const MAX_CONFIG: usize = 1024 * 1024;
const MAX_BODY: usize = 64 * 1024;
// One gateway, one startup configuration. Locks never protect a public-path operation.
static BASELINE: Mutex<Option<Baseline>> = Mutex::const_new(None);
static SAVE_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Copy)]
struct Field {
    wire: &'static str,
    toml: &'static str,
    min: u64,
    max: u64,
}
const FIELDS: [Field; 17] = [
    Field {
        wire: "concurrentFills",
        toml: "concurrent_fills",
        min: 1,
        max: 64,
    },
    Field {
        wire: "waitersPerObject",
        toml: "waiters_per_object",
        min: 1,
        max: 64,
    },
    Field {
        wire: "activeBodies",
        toml: "active_bodies",
        min: 1,
        max: 256,
    },
    Field {
        wire: "requestSlots",
        toml: "request_slots",
        min: 1,
        max: 1024,
    },
    Field {
        wire: "readerBufferBytes",
        toml: "reader_buffer_bytes",
        min: 4096,
        max: 262144,
    },
    Field {
        wire: "sourceAttempts",
        toml: "source_attempts",
        min: 1,
        max: 2,
    },
    Field {
        wire: "failureMapEntries",
        toml: "failure_map_entries",
        min: 1,
        max: 10000,
    },
    Field {
        wire: "waiterTimeoutSeconds",
        toml: "waiter_timeout_seconds",
        min: 1,
        max: 30,
    },
    Field {
        wire: "producerDeadlineSeconds",
        toml: "producer_deadline_seconds",
        min: 1,
        max: 600,
    },
    Field {
        wire: "connectTimeoutSeconds",
        toml: "connect_timeout_seconds",
        min: 1,
        max: 3,
    },
    Field {
        wire: "responseHeaderTimeoutSeconds",
        toml: "response_header_timeout_seconds",
        min: 1,
        max: 10,
    },
    Field {
        wire: "readIdleTimeoutSeconds",
        toml: "read_idle_timeout_seconds",
        min: 1,
        max: 30,
    },
    Field {
        wire: "admissionWaitSeconds",
        toml: "admission_wait_seconds",
        min: 1,
        max: 2,
    },
    Field {
        wire: "failureBackoffSeconds",
        toml: "failure_backoff_seconds",
        min: 1,
        max: 30,
    },
    Field {
        wire: "bodyWriteIdleSeconds",
        toml: "body_write_idle_seconds",
        min: 1,
        max: 30,
    },
    Field {
        wire: "bodyLifetimeSeconds",
        toml: "body_lifetime_seconds",
        min: 1,
        max: 900,
    },
    Field {
        wire: "timeoutSeconds",
        toml: "timeout_seconds",
        min: 1,
        max: 30,
    },
];
#[derive(Clone)]
struct Baseline {
    identity: String,
    running_revision: String,
    base_revision: String,
    config: Config,
    text: Option<String>,
    file_hash: Option<String>,
}
#[derive(Debug)]
enum SettingsError {
    Store(StoreError),
    InvalidPatch,
    Revision,
    ManagedDisabled,
    ExternalEdit,
    NotFound,
    Unavailable,
}
impl From<StoreError> for SettingsError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
impl SettingsError {
    fn response(self) -> Response {
        match self {
            Self::Store(error) => store_error(error),
            Self::InvalidPatch => error_reply(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_config_patch",
                "Only the listed concurrency and timeout fields, within their bounds, may be proposed.",
            ),
            Self::Revision => error_reply(
                StatusCode::CONFLICT,
                "revision_conflict",
                "Configuration revision changed; refresh before proposing or saving.",
            ),
            Self::ManagedDisabled => error_reply(
                StatusCode::CONFLICT,
                "managed_config_disabled",
                "Managed configuration is not enabled at a safe writable startup path. The proposal remains available for offline operator apply.",
            ),
            Self::ExternalEdit => error_reply(
                StatusCode::CONFLICT,
                "external_config_change",
                "The source configuration was edited externally; restart with the reviewed file before proposing changes.",
            ),
            Self::NotFound => error_reply(
                StatusCode::NOT_FOUND,
                "not_found",
                "Configuration proposal not found.",
            ),
            Self::Unavailable => error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "config_unavailable",
                "Configuration source or durable recording is unavailable.",
            ),
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigRequest {
    pub expected_revision: String,
    pub patch: Value,
    pub reason: Option<String>,
}
pub type ConfigPayload = Result<Json<ConfigRequest>, JsonRejection>;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Diff {
    field: String,
    before: Value,
    after: Value,
    restart_required: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProposalBody {
    patch: Value,
    reason: String,
    proposed_revision: String,
    diffs: Vec<Diff>,
    base_file_hash: Option<String>,
    proposed_file_hash: Option<String>,
}
#[derive(Clone)]
struct Proposal {
    id: String,
    actor: String,
    base_revision: String,
    state: String,
    body: ProposalBody,
    created_at: i64,
}
impl Proposal {
    fn view(&self) -> Value {
        json!({"id":self.id,"actor":self.actor,"baseRevision":self.base_revision,"proposedRevision":self.body.proposed_revision,
            "state":self.state,"status":if self.state=="saved" {"saved_restart_required"} else {self.state.as_str()},
            "patch":self.body.patch,"diffs":self.body.diffs,"reason":self.body.reason,"createdAt":self.created_at})
    }
}
struct Prepared {
    config: Config,
    text: Option<String>,
    patch: Value,
    revision: String,
    diffs: Vec<Diff>,
    toml_preview: String,
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
        .unwrap_or(0)
}
fn digest(text: &str) -> String {
    Sha256Digest::of(text.as_bytes()).to_hex()
}
fn revision(config: &Config) -> Result<String, SettingsError> {
    Ok(Sha256Digest::of(
        &serde_json::to_vec(&config_projection(config)).map_err(|_| SettingsError::Unavailable)?,
    )
    .to_hex())
}
fn identity(config: &Config) -> Result<String, SettingsError> {
    Ok(format!(
        "{}\0{}\0{}",
        config
            .source_path()
            .map_or_else(String::new, |p| p.to_string_lossy().into_owned()),
        config.base_dir().display(),
        revision(config)?
    ))
}
fn numeric(value: &Value) -> Option<u64> {
    match value {
        Value::String(text)
            if !text.is_empty() && text.len() <= 20 && text.bytes().all(|b| b.is_ascii_digit()) =>
        {
            text.parse().ok()
        }
        _ => value.as_u64(),
    }
}
fn set(
    document: &mut DocumentMut,
    section: &str,
    key: &str,
    number: u64,
) -> Result<(), SettingsError> {
    if document.get(section).is_none() {
        document.insert(section, Item::Table(Table::new()));
    }
    let table = document
        .get_mut(section)
        .and_then(Item::as_table_like_mut)
        .ok_or(SettingsError::InvalidPatch)?;
    let number = i64::try_from(number).map_err(|_| SettingsError::InvalidPatch)?;
    // Keep an existing value's decoration, including inline comments.
    let mut replacement = value(number);
    if let Some(decoration) = table.get(key).and_then(Item::as_value).map(|v| v.decor())
        && let Some(v) = replacement.as_value_mut()
    {
        *v.decor_mut() = decoration.clone();
    }
    table.insert(key, replacement);
    Ok(())
}
fn field_value(projection: &Value, field: Field) -> Value {
    let section = if field.wire == "timeoutSeconds" {
        "verifier"
    } else {
        "limits"
    };
    projection[section][field.wire].clone()
}
fn patch_entries(patch: &Value) -> Result<Vec<(Field, u64)>, SettingsError> {
    let object = patch.as_object().ok_or(SettingsError::InvalidPatch)?;
    let mut entries = Vec::new();
    for (section, values) in object {
        match section.as_str() {
            "limits" => {
                let values = values.as_object().ok_or(SettingsError::InvalidPatch)?;
                for (key, value) in values {
                    let field = FIELDS
                        .iter()
                        .find(|f| f.wire == key && f.wire != "timeoutSeconds")
                        .copied()
                        .ok_or(SettingsError::InvalidPatch)?;
                    // Only the byte field accepts decimal strings; numeric settings are integers.
                    let number = if field.wire == "readerBufferBytes" {
                        numeric(value)
                    } else {
                        value.as_u64()
                    }
                    .ok_or(SettingsError::InvalidPatch)?;
                    if number < field.min || number > field.max {
                        return Err(SettingsError::InvalidPatch);
                    }
                    entries.push((field, number));
                }
            }
            "verifierTimeoutSeconds" => {
                let field = FIELDS[16];
                let number = values.as_u64().ok_or(SettingsError::InvalidPatch)?;
                if number < field.min || number > field.max {
                    return Err(SettingsError::InvalidPatch);
                }
                entries.push((field, number));
            }
            _ => return Err(SettingsError::InvalidPatch),
        }
    }
    if entries.is_empty() {
        return Err(SettingsError::InvalidPatch);
    }
    Ok(entries)
}
fn copy_editable(target: &mut Config, source: &Config) {
    let t = &mut target.limits;
    let s = &source.limits;
    t.concurrent_fills = s.concurrent_fills;
    t.waiters_per_object = s.waiters_per_object;
    t.active_bodies = s.active_bodies;
    t.request_slots = s.request_slots;
    t.reader_buffer_bytes = s.reader_buffer_bytes;
    t.source_attempts = s.source_attempts;
    t.failure_map_entries = s.failure_map_entries;
    t.waiter_timeout = s.waiter_timeout;
    t.producer_deadline = s.producer_deadline;
    t.connect_timeout = s.connect_timeout;
    t.response_header_timeout = s.response_header_timeout;
    t.read_idle_timeout = s.read_idle_timeout;
    t.admission_wait = s.admission_wait;
    t.failure_backoff = s.failure_backoff;
    t.body_write_idle = s.body_write_idle;
    t.body_lifetime = s.body_lifetime;
    target.verifier.timeout = source.verifier.timeout;
}
fn prepare(base: &Baseline, expected: &str, patch: &Value) -> Result<Prepared, SettingsError> {
    if expected != base.base_revision {
        return Err(SettingsError::Revision);
    }
    let entries = patch_entries(patch)?;
    let projection = config_projection(&base.config);
    let mut document = match &base.text {
        Some(text) => text
            .parse::<DocumentMut>()
            .map_err(|_| SettingsError::Unavailable)?,
        None => {
            // In-memory Config::parse fixtures have no source document. Validate
            // their editable subset with the SAME Config parser, not a second validator.
            let mut document = "mode='private-fixture'\n[listen]\npublic='127.0.0.1:8080'\nadmin='127.0.0.1:9090'\n[fixture]\nkeyring='key.gpg'\nwork_dir='settings-validation'\n[verifier]\n".parse::<DocumentMut>().map_err(|_|SettingsError::Unavailable)?;
            for field in FIELDS {
                let number =
                    numeric(&field_value(&projection, field)).ok_or(SettingsError::Unavailable)?;
                set(
                    &mut document,
                    if field.wire == "timeoutSeconds" {
                        "verifier"
                    } else {
                        "limits"
                    },
                    field.toml,
                    number,
                )?;
            }
            document
        }
    };
    let mut fragment = DocumentMut::new();
    let mut normalized = serde_json::Map::new();
    let mut normalized_limits = serde_json::Map::new();
    let mut diffs = Vec::new();
    for (field, number) in entries {
        let section = if field.wire == "timeoutSeconds" {
            "verifier"
        } else {
            "limits"
        };
        set(&mut document, section, field.toml, number)?;
        set(&mut fragment, section, field.toml, number)?;
        let after = if field.wire == "readerBufferBytes" {
            json!(number.to_string())
        } else {
            json!(number)
        };
        let before = field_value(&projection, field);
        if before != after {
            diffs.push(Diff {
                field: format!("{section}.{}", field.wire),
                before,
                after: after.clone(),
                restart_required: true,
            });
        }
        if section == "verifier" {
            normalized.insert("verifierTimeoutSeconds".into(), after);
        } else {
            normalized_limits.insert(field.wire.into(), after);
        }
    }
    if !normalized_limits.is_empty() {
        normalized.insert("limits".into(), Value::Object(normalized_limits));
    }
    let text = document.to_string();
    let validated =
        Config::parse(&text, base.config.base_dir()).map_err(|_| SettingsError::InvalidPatch)?;
    let mut config = base.config.clone();
    copy_editable(&mut config, &validated);
    let proposed_revision = revision(&config)?;
    Ok(Prepared {
        config,
        text: base.text.as_ref().map(|_| text),
        patch: Value::Object(normalized),
        revision: proposed_revision,
        diffs,
        toml_preview: fragment.to_string(),
    })
}
fn clean_absolute(path: &FsPath) -> Result<PathBuf, SettingsError> {
    let absolute = std::path::absolute(path).map_err(|_| SettingsError::Unavailable)?;
    let mut clean = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if !clean.pop() {
                    return Err(SettingsError::Unavailable);
                }
            }
            _ => clean.push(part.as_os_str()),
        }
    }
    Ok(clean)
}
fn no_symlink_ancestors(path: &FsPath) -> Result<(), SettingsError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(SettingsError::Unavailable);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(SettingsError::Unavailable),
        }
    }
    Ok(())
}
fn read_source(path: &FsPath) -> Result<String, SettingsError> {
    no_symlink_ancestors(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let mut file = options.open(path).map_err(|_| SettingsError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| SettingsError::Unavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG as u64 {
        return Err(SettingsError::Unavailable);
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take((MAX_CONFIG + 1) as u64)
        .read_to_string(&mut text)
        .map_err(|_| SettingsError::Unavailable)?;
    if text.len() > MAX_CONFIG {
        return Err(SettingsError::Unavailable);
    }
    Ok(text)
}
fn initial_baseline(config: &Config) -> Result<Baseline, SettingsError> {
    let running_revision = revision(config)?;
    let text = config.source_path().map(read_source).transpose()?;
    if let Some(text) = &text {
        let disk =
            Config::parse(text, config.base_dir()).map_err(|_| SettingsError::Unavailable)?;
        if revision(&disk)? != running_revision {
            return Err(SettingsError::ExternalEdit);
        }
    }
    Ok(Baseline {
        identity: identity(config)?,
        running_revision: running_revision.clone(),
        base_revision: running_revision,
        config: config.clone(),
        file_hash: text.as_ref().map(|text| digest(text)),
        text,
    })
}
async fn baseline(config: &Config) -> Result<Baseline, SettingsError> {
    let key = identity(config)?;
    if let Some(base) = BASELINE
        .lock()
        .await
        .as_ref()
        .filter(|base| base.identity == key)
    {
        return Ok(base.clone());
    }
    // A source-backed runtime must be initialized by startup reconciliation,
    // never silently adopt an external file in a POST preview/save request.
    if config.source_path().is_some() {
        return Err(SettingsError::Unavailable);
    }
    initial_baseline(config)
}
fn managed_path(config: &Config) -> Result<PathBuf, SettingsError> {
    if !config.admin.managed_config {
        return Err(SettingsError::ManagedDisabled);
    }
    let path = clean_absolute(config.source_path().ok_or(SettingsError::ManagedDisabled)?)?;
    for reserved in [
        config.spool_dir(),
        config.scratch_dir(),
        config.admin.state_dir.clone(),
    ] {
        let reserved = clean_absolute(&reserved)?;
        if path.starts_with(&reserved) || reserved.starts_with(&path) {
            return Err(SettingsError::ManagedDisabled);
        }
    }
    no_symlink_ancestors(&path).map_err(|_| SettingsError::ManagedDisabled)?;
    check_file(&path, false).map_err(|_| SettingsError::ManagedDisabled)?;
    secure_parent(&path).map_err(|_| SettingsError::ManagedDisabled)?;
    Ok(path)
}
fn secure_parent(path: &FsPath) -> Result<(), SettingsError> {
    let parent = path.parent().ok_or(SettingsError::Unavailable)?;
    no_symlink_ancestors(parent)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| SettingsError::Unavailable)?;
    if !metadata.is_dir() {
        return Err(SettingsError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(SettingsError::Unavailable);
        }
    }
    Ok(())
}
fn temporary_path(path: &FsPath, id: &str) -> Result<PathBuf, SettingsError> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SettingsError::Unavailable);
    }
    let mut name = path
        .file_name()
        .ok_or(SettingsError::Unavailable)?
        .to_os_string();
    name.push(format!(".tmp-{id}"));
    Ok(path.with_file_name(name))
}
fn atomic_write(
    path: &FsPath,
    text: &str,
    id: &str,
    expected_hash: Option<&str>,
) -> Result<(), SettingsError> {
    secure_parent(path)?;
    let temporary = temporary_path(path, id)?;
    let mut created = false;
    let result = (|| {
        let mut file = create_private(&temporary)?;
        created = true;
        file.write_all(text.as_bytes())
            .map_err(|_| SettingsError::Unavailable)?;
        file.sync_all().map_err(|_| SettingsError::Unavailable)?;
        if let Some(expected) = expected_hash {
            check_file(path, false)?;
            if digest(&read_source(path)?) != expected {
                return Err(SettingsError::ExternalEdit);
            }
            fs::rename(&temporary, path).map_err(|_| SettingsError::Unavailable)?;
        } else {
            // Publish a new offline output without clobbering an existing path.
            fs::hard_link(&temporary, path).map_err(|_| SettingsError::Unavailable)?;
            fs::remove_file(&temporary).map_err(|_| SettingsError::Unavailable)?;
        }
        sync_directory(path.parent().ok_or(SettingsError::Unavailable)?)?;
        Ok(())
    })();
    if result.is_err() && created && check_file(&temporary, false).is_ok() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
fn load_proposal(connection: &Connection, id: &str) -> Result<Option<Proposal>, StoreError> {
    let row: Option<(String, String, String, String, String, i64)> = connection
        .query_row(
            "SELECT id,actor,base_revision,state,body,created_at FROM config_proposals WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?;
    row.map(|(id, actor, base_revision, state, body, created_at)| {
        let body = serde_json::from_str(&body).map_err(|_| StoreError::Unavailable)?;
        Ok(Proposal {
            id,
            actor,
            base_revision,
            state,
            body,
            created_at,
        })
    })
    .transpose()
}
fn encode_body(body: &ProposalBody) -> Result<String, StoreError> {
    let text = serde_json::to_string(body).map_err(|_| StoreError::Invalid)?;
    if text.len() > MAX_BODY {
        return Err(StoreError::Invalid);
    }
    Ok(text)
}
fn decode(payload: ConfigPayload) -> Result<ConfigRequest, Response> {
    let Json(request) = payload.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            error_reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Configuration request exceeds 64 KiB.",
            )
        } else {
            SettingsError::InvalidPatch.response()
        }
    })?;
    if request.expected_revision.len() != 64
        || !request
            .expected_revision
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
        || serde_json::to_vec(&request.patch).map_or(true, |v| v.len() > MAX_BODY)
    {
        return Err(SettingsError::InvalidPatch.response());
    }
    Ok(request)
}
fn reason(request: &ConfigRequest) -> Result<String, SettingsError> {
    if request
        .reason
        .as_ref()
        .is_some_and(|value| value.len() > 1024)
    {
        return Err(SettingsError::Store(StoreError::Invalid));
    }
    let reason = request.reason.as_deref().map_or("", str::trim);
    if reason.is_empty() || reason.len() > 1024 || reason.chars().any(char::is_control) {
        return Err(SettingsError::Store(StoreError::Invalid));
    }
    Ok(reason.to_owned())
}
fn field_capabilities(config: &Config) -> Vec<Value> {
    let projection = config_projection(config);
    let mut fields=FIELDS.iter().map(|field| {
        let section=if field.wire=="timeoutSeconds" {"verifier"}else{"limits"};
        json!({"field":format!("{section}.{}",field.wire),"value":field_value(&projection,*field),"editable":true,"restartRequired":true,
            "min":field.min,"max":field.max,"reason":"Validated restart-only host setting; a proposal does not change the running process."})
    }).collect::<Vec<_>>();
    for (field, reason) in [
        (
            "mode",
            "Storage and authority mode is fixed at process startup.",
        ),
        ("listen.public", "Host-only listener configuration."),
        (
            "listen.admin",
            "Loopback administration boundary is host-only.",
        ),
        ("listen.publicHost", "Host-only public authority."),
        ("admin.origin", "Exact authentication origin is host-only."),
        (
            "admin.stateDir",
            "Exclusive administration state ownership is host-only.",
        ),
        (
            "admin.managedConfig",
            "Managed writes require explicit offline host opt-in.",
        ),
        (
            "durable.provider",
            "Provider identity, prefixes, and credential paths are offline-only; secret contents are never returned.",
        ),
        (
            "durable.budget",
            "Offline allowance ceilings; configuration edits cannot reset balances, periods, reservations, or certainty.",
        ),
        (
            "durable.suites",
            "Offline serving selection; move retained identities to retired_suites to retire them, or back here to reactivate. Adding a candidate does not authorize bootstrap.",
        ),
        (
            "durable.retiredSuites",
            "Offline retained trust selection. Retirement stops routes and synchronization after restart but preserves keyrings, checkpoints, capture authority and reservations.",
        ),
        (
            "limits.managedCeilingBytes",
            "Spool authority ceiling and current usage require offline validation.",
        ),
        (
            "limits.maxObjectBytes",
            "Spool object authority bound is offline-only.",
        ),
        (
            "limits.syncIntervalSeconds",
            "Durable observation cadence is fixed.",
        ),
        (
            "limits.activeLeaseHours",
            "Publication trust lease policy is offline-only.",
        ),
        (
            "fixture.keyring",
            "Host-only trust root path; contents and paths are redacted.",
        ),
        (
            "fixture.workDir",
            "Exclusive spool/scratch ownership is host-only.",
        ),
        (
            "durable.stateDir",
            "Exclusive durable authority ownership is host-only.",
        ),
        (
            "durable.keyrings",
            "Trust root paths and contents are redacted; offline-only.",
        ),
        ("verifier.binary", "Host-only verifier executable path."),
        (
            "s3",
            "Fixture provider configuration, transfer journals, and credentials are offline-only.",
        ),
    ] {
        fields.push(json!({"field":field,"editable":false,"restartRequired":true,"reason":reason}));
    }
    fields
}

pub async fn get_config(State(state): State<Arc<HealthState>>, headers: HeaderMap) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if auth.machine {
        return store_error(StoreError::Forbidden);
    }
    let base = match baseline(&state.config).await {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    let proposals = match state
        .admin
        .read(move |connection| {
            actor(connection, &auth, Some(Permission::ViewStatus))?;
            let mut statement = connection.prepare(
                "SELECT id FROM config_proposals ORDER BY created_at DESC,id DESC LIMIT 50",
            )?;
            let ids = statement
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids.into_iter()
                .map(|id| {
                    load_proposal(connection, &id)?
                        .map(|p| p.view())
                        .ok_or(StoreError::Unavailable)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .await
    {
        Ok(value) => value,
        Err(error) => return store_error(error),
    };
    let config = state.config.clone();
    let saved = tokio::task::spawn_blocking(move || {
        let Some(path) = config.source_path() else {
            return (None, "no_source", false, false);
        };
        let Ok(text) = read_source(path) else {
            return (None, "unavailable", false, false);
        };
        let changed = base.file_hash.as_deref() != Some(digest(&text).as_str());
        let Ok(saved) = Config::parse(&text, config.base_dir()) else {
            return (None, "invalid", true, false);
        };
        let Ok(saved_revision) = revision(&saved) else {
            return (None, "unavailable", changed, false);
        };
        let restart = saved_revision != base.running_revision;
        (
            Some(saved_revision),
            if changed {
                "external_change"
            } else if restart {
                "saved_restart_required"
            } else {
                "running"
            },
            changed,
            restart,
        )
    })
    .await;
    let (saved_revision, status, external, restart) = match saved {
        Ok(value) => value,
        Err(_) => return SettingsError::Unavailable.response(),
    };
    let running_revision = match revision(&state.config) {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    Json(json!({"running":config_projection(&state.config),"runningRevision":running_revision,"savedRevision":saved_revision,
        "savedRevisionStatus":status,"restartRequired":restart,"externalChangeDetected":external,
        "managedConfigEnabled":state.config.admin.managed_config,"fields":field_capabilities(&state.config),"proposals":proposals})).into_response()
}
pub async fn post_config_preview(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    payload: ConfigPayload,
) -> Response {
    if let Err(response) =
        authenticate(&state, &headers, true, Some(Permission::ManageConfig)).await
    {
        return response;
    }
    let request = match decode(payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let base = match baseline(&state.config).await {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    match prepare(&base,&request.expected_revision,&request.patch) {
        Ok(prepared)=>Json(json!({"valid":true,"baseRevision":base.base_revision,"proposedRevision":prepared.revision,"diffs":prepared.diffs,
            "tomlPreview":prepared.toml_preview,"managedConfigEnabled":state.config.admin.managed_config})).into_response(),
        Err(error)=>error.response(),
    }
}
pub async fn post_config_proposal(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    payload: ConfigPayload,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ManageConfig)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let request = match decode(payload) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let reason = match reason(&request) {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    let _serial = match SAVE_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(_) => return store_error(StoreError::Busy),
    };
    let base = match baseline(&state.config).await {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    let prepared = match prepare(&base, &request.expected_revision, &request.patch) {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    let body = ProposalBody {
        patch: prepared.patch,
        reason,
        proposed_revision: prepared.revision,
        diffs: prepared.diffs,
        base_file_hash: base.file_hash,
        proposed_file_hash: prepared.text.as_deref().map(digest),
    };
    let result=state.admin.write(move |tx| {
        let user=actor(tx,&auth,Some(Permission::ManageConfig))?;
        // Keep reconciliation and history bounded without deleting unsaved intent.
        if tx.query_row("SELECT count(*) FROM config_proposals",[],|r|r.get::<_,i64>(0))?>=1000 {
            tx.execute("DELETE FROM config_proposals WHERE id IN(SELECT id FROM config_proposals WHERE state IN('applied','conflict') ORDER BY created_at,id LIMIT 100)",[])?;
            if tx.query_row("SELECT count(*) FROM config_proposals",[],|r|r.get::<_,i64>(0))?>=1000 {return Err(StoreError::Busy);}
        }
        let proposal=Proposal {id:password::random_token(),actor:user.id,base_revision:base.base_revision,state:"proposed".into(),body,created_at:now()};
        tx.execute("INSERT INTO config_proposals(id,actor,base_revision,state,body,created_at) VALUES(?1,?2,?3,'proposed',?4,?5)",params![proposal.id,proposal.actor,proposal.base_revision,encode_body(&proposal.body)?,proposal.created_at])?;
        audit(tx,&proposal.actor,"config.propose",&proposal.id,"proposed",&proposal.body.reason)?;
        Ok(proposal.view())
    }).await;
    match result {
        Ok(proposal) => (StatusCode::CREATED, Json(json!({"proposal":proposal}))).into_response(),
        Err(error) => store_error(error),
    }
}
async fn save_proposal(
    admin: AdminStore,
    config: Arc<Config>,
    auth: AuthContext,
    id: String,
) -> Result<Value, SettingsError> {
    let _serial = SAVE_LOCK
        .try_lock()
        .map_err(|_| SettingsError::Store(StoreError::Busy))?;
    let base = baseline(&config).await?;
    let check_config = config.clone();
    let path = tokio::task::spawn_blocking(move || managed_path(&check_config))
        .await
        .map_err(|_| SettingsError::Unavailable)??;
    let lookup = id.clone();
    let read_auth = auth.clone();
    let mut proposal = admin
        .read(move |connection| {
            actor(connection, &read_auth, Some(Permission::ManageConfig))?;
            load_proposal(connection, &lookup)?.ok_or(StoreError::Invalid)
        })
        .await
        .map_err(|e| {
            if e == StoreError::Invalid {
                SettingsError::NotFound
            } else {
                e.into()
            }
        })?;
    if proposal.state != "proposed" {
        return Err(SettingsError::Revision);
    }
    if proposal.base_revision != base.base_revision {
        return Err(SettingsError::Revision);
    }
    let prepared = prepare(&base, &proposal.base_revision, &proposal.body.patch)?;
    let text = prepared.text.ok_or(SettingsError::ManagedDisabled)?;
    let expected_hash = proposal
        .body
        .base_file_hash
        .clone()
        .ok_or(SettingsError::ManagedDisabled)?;
    if base.file_hash.as_deref() != Some(expected_hash.as_str()) {
        return Err(SettingsError::ExternalEdit);
    }
    let check_path = path.clone();
    let check_hash = expected_hash.clone();
    tokio::task::spawn_blocking(move || {
        if digest(&read_source(&check_path)?) != check_hash {
            return Err(SettingsError::ExternalEdit);
        }
        Ok(())
    })
    .await
    .map_err(|_| SettingsError::Unavailable)??;
    proposal.body.proposed_file_hash = Some(digest(&text));
    proposal.body.proposed_revision = prepared.revision.clone();
    let intent = proposal.clone();
    admin.write(move |tx| {
        let user=actor(tx,&auth,Some(Permission::ManageConfig))?;
        let changed=tx.execute("UPDATE config_proposals SET state='saving',body=?1 WHERE id=?2 AND state='proposed' AND base_revision=?3",params![encode_body(&intent.body)?,intent.id,intent.base_revision])?;
        if changed!=1 {return Err(StoreError::Conflict);}
        // Bind the intent to the actual saving operator, not necessarily the proposer.
        audit(tx,&user.id,"config.save",&intent.id,"intent",&intent.body.reason)?;
        Ok(())
    }).await?;
    let write_path = path.clone();
    let write_id = proposal.id.clone();
    let write_text = text.clone();
    let written = tokio::task::spawn_blocking(move || {
        atomic_write(&write_path, &write_text, &write_id, Some(&expected_hash))
    })
    .await
    .map_err(|_| SettingsError::Unavailable)?;
    if let Err(error) = written {
        let failed = proposal.clone();
        admin
            .write(move |tx| {
                // A failed directory fsync may follow a successful rename. Keep the
                // intent unresolved rather than falsely claiming the file is unchanged.
                complete_save_audit(tx, &failed.id, "failed", &failed.body.reason)
            })
            .await?;
        return Err(error);
    }
    // The file is now saved even if completion recording fails. Pin its new base
    // and leave the durable saving intent for conservative startup reconciliation.
    let mut next = base;
    next.config = prepared.config;
    next.base_revision = prepared.revision;
    next.file_hash = Some(digest(&text));
    next.text = Some(text);
    *BASELINE.lock().await = Some(next);
    proposal.state = "saved".into();
    let saved = proposal.clone();
    admin
        .write(move |tx| {
            tx.execute(
                "UPDATE config_proposals SET state='saved',body=?1 WHERE id=?2 AND state='saving'",
                params![encode_body(&saved.body)?, saved.id],
            )?;
            complete_save_audit(tx, &saved.id, "saved", &saved.body.reason)
        })
        .await?;
    Ok(proposal.view())
}
fn complete_save_audit(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    outcome: &str,
    reason: &str,
) -> Result<(), StoreError> {
    let principal:String=tx.query_row("SELECT actor FROM audit_events WHERE action='config.save' AND target=?1 AND outcome='intent' ORDER BY id DESC LIMIT 1",[id],|r|r.get(0))?;
    audit(tx, &principal, "config.save", id, outcome, reason)
}
pub async fn post_config_save(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ManageConfig)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    // Detached ownership preserves intent -> file -> completion through client cancellation.
    match tokio::spawn(save_proposal(
        (*state.admin).clone(),
        state.config.clone(),
        auth,
        id,
    ))
    .await
    {
        Ok(Ok(proposal)) => Json(json!({"proposal":proposal})).into_response(),
        Ok(Err(error)) => error.response(),
        Err(_) => SettingsError::Unavailable.response(),
    }
}

/// Initialize the exact startup source and reconcile durable save intents. Call
/// before accepting administration requests; no provider/core-catalog work occurs.
pub async fn reconcile_config_proposals(
    admin: &AdminStore,
    config: &Config,
) -> Result<(), StoreError> {
    let _serial = SAVE_LOCK.lock().await;
    let config = config.clone();
    let base = tokio::task::spawn_blocking(move || initial_baseline(&config))
        .await
        .map_err(|_| StoreError::Unavailable)?
        .map_err(|_| StoreError::Unavailable)?;
    let pending=admin.read(|connection| {
        let mut statement=connection.prepare("SELECT id FROM config_proposals WHERE state='saving' ORDER BY created_at,id LIMIT 1000")?;
        let ids=statement.query_map([],|row|row.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
        Ok(ids)
    }).await?;
    if !pending.is_empty() && base.config.admin.managed_config {
        let config = base.config.clone();
        tokio::task::spawn_blocking(move || -> Result<(), SettingsError> {
            let path = managed_path(&config)?;
            for id in pending {
                let temporary = temporary_path(&path, &id)?;
                match fs::symlink_metadata(&temporary) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => return Err(SettingsError::Unavailable),
                    Ok(_) => {}
                }
                // Only a durable intent's exact, privately owned staging path
                // is removable, including a crash during a partial write.
                check_file(&temporary, false)?;
                fs::remove_file(&temporary).map_err(|_| SettingsError::Unavailable)?;
            }
            sync_directory(path.parent().ok_or(SettingsError::Unavailable)?)?;
            Ok(())
        })
        .await
        .map_err(|_| StoreError::Unavailable)?
        .map_err(|_| StoreError::Unavailable)?;
    }
    let observed_hash = base.file_hash.clone();
    let running = base.running_revision.clone();
    admin.write(move |tx| {
        let mut statement=tx.prepare("SELECT id FROM config_proposals WHERE state IN('saving','saved') ORDER BY created_at,id LIMIT 1000")?;
        let ids=statement.query_map([],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
        drop(statement);
        for id in ids {
            let proposal=load_proposal(tx,&id)?.ok_or(StoreError::Unavailable)?;
            let state=if proposal.body.proposed_file_hash.is_some() && proposal.body.proposed_file_hash==observed_hash && proposal.body.proposed_revision==running {"applied"}
                else if proposal.state=="saving" && proposal.body.base_file_hash==observed_hash {"proposed"}
                else if proposal.state=="saving" {"conflict"} else {continue;};
            tx.execute("UPDATE config_proposals SET state=?1 WHERE id=?2",params![state,id])?;
            if proposal.state=="saving" {complete_save_audit(tx,&id,if state=="applied" {"applied"}else if state=="proposed" {"interrupted"}else{"external_change"},&proposal.body.reason)?;}
            else {audit(tx,"system:startup","config.apply",&id,"applied",&proposal.body.reason)?;}
        }
        Ok(())
    }).await?;
    *BASELINE.lock().await = Some(base);
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptConfigReport {
    pub source_path: PathBuf,
    pub output_path: PathBuf,
    pub revision: String,
    pub restart_required: bool,
}
fn set_path(
    document: &mut DocumentMut,
    section: &[&str],
    key: &str,
    path: &FsPath,
) -> Result<(), String> {
    let text = path
        .to_str()
        .ok_or_else(|| "Configuration path is not UTF-8.".to_owned())?;
    let mut item = document.as_item_mut();
    for part in section {
        let table = item
            .as_table_like_mut()
            .ok_or_else(|| "Invalid configuration table.".to_owned())?;
        if !table.contains_key(part) {
            table.insert(part, Item::Table(Table::new()));
        }
        item = table
            .get_mut(part)
            .ok_or_else(|| "Invalid configuration table.".to_owned())?;
    }
    let table = item
        .as_table_like_mut()
        .ok_or_else(|| "Invalid configuration table.".to_owned())?;
    let mut replacement = value(text);
    if let Some(decoration) = table.get(key).and_then(Item::as_value).map(|v| v.decor())
        && let Some(v) = replacement.as_value_mut()
    {
        *v.decor_mut() = decoration.clone();
    }
    table.insert(key, replacement);
    Ok(())
}
/// Offline adoption never modifies the input and never replaces an existing
/// destination. All resolved authority paths keep their original meaning.
pub fn adopt_managed_config(
    source_path: &FsPath,
    output_path: &FsPath,
) -> Result<AdoptConfigReport, String> {
    let source = clean_absolute(source_path)
        .map_err(|_| "Cannot resolve source configuration.".to_owned())?;
    let output = clean_absolute(output_path)
        .map_err(|_| "Cannot resolve output configuration.".to_owned())?;
    if source == output || fs::symlink_metadata(&output).is_ok() {
        return Err("Output must be a new path, distinct from the source configuration.".into());
    }
    no_symlink_ancestors(&source)
        .map_err(|_| "Source configuration cannot contain symlinks.".to_owned())?;
    let config = Config::load(&source)
        .map_err(|_| "Source configuration is invalid or unavailable.".to_owned())?;
    for reserved in [
        config.spool_dir(),
        config.scratch_dir(),
        config.admin.state_dir.clone(),
    ] {
        let reserved = clean_absolute(&reserved)
            .map_err(|_| "Cannot resolve reserved state path.".to_owned())?;
        if output.starts_with(&reserved) || reserved.starts_with(&output) {
            return Err(
                "Managed configuration must be outside spool, scratch, and admin state.".into(),
            );
        }
    }
    let text =
        read_source(&source).map_err(|_| "Cannot read source configuration safely.".to_owned())?;
    let mut document = text
        .parse::<DocumentMut>()
        .map_err(|_| "Invalid configuration TOML.".to_owned())?;
    if config.durable().is_none() {
        set_path(
            &mut document,
            &["fixture"],
            "keyring",
            &config.fixture.keyring,
        )?;
        set_path(
            &mut document,
            &["fixture"],
            "work_dir",
            &config.fixture.work_dir,
        )?;
    }
    if let Some(durable) = config.durable() {
        set_path(&mut document, &["durable"], "state_dir", &durable.state_dir)?;
        set_path(
            &mut document,
            &["durable", "provider"],
            "credentials_file",
            &durable.provider.credentials_file,
        )?;
        match &durable.trust {
            DurableTrust::Fixture { keyring } => {
                set_path(&mut document, &["durable"], "fixture_keyring", keyring)?
            }
            DurableTrust::Distributions(keyrings) => {
                for (name, path) in [
                    ("debian", &keyrings.debian),
                    ("ubuntu", &keyrings.ubuntu),
                    ("kali", &keyrings.kali),
                    ("parrot", &keyrings.parrot),
                    ("trisquel", &keyrings.trisquel),
                    ("raspberrypi", &keyrings.raspberrypi),
                    ("proxmox", &keyrings.proxmox),
                    ("archlinux", &keyrings.archlinux),
                    ("chaoticaur", &keyrings.chaoticaur),
                    ("docker", &keyrings.docker),
                    ("tailscale", &keyrings.tailscale),
                    ("postgresql", &keyrings.postgresql),
                    ("grafana", &keyrings.grafana),
                    ("cachyos", &keyrings.cachyos),
                    ("archlinuxcn", &keyrings.archlinuxcn),
                    ("endeavouros", &keyrings.endeavouros),
                    ("almalinux", &keyrings.almalinux),
                    ("rockylinux", &keyrings.rockylinux),
                ] {
                    set_path(&mut document, &["durable", "keyrings"], name, path)?;
                }
            }
        }
    }
    set_path(
        &mut document,
        &["admin"],
        "state_dir",
        &config.admin.state_dir,
    )?;
    if document.get("admin").is_none() {
        document.insert("admin", Item::Table(Table::new()));
    }
    document["admin"]["managed_config"] = value(true);
    // A bare verifier command retains PATH lookup; relative executable paths
    // containing a separator retain their original process-cwd interpretation.
    if config.verifier.binary.is_relative() && config.verifier.binary.components().count() > 1 {
        let binary = std::path::absolute(&config.verifier.binary)
            .map_err(|_| "Cannot resolve verifier executable.".to_owned())?;
        set_path(&mut document, &["verifier"], "binary", &binary)?;
    }
    let output_text = document.to_string();
    let parent = output
        .parent()
        .ok_or_else(|| "Output must have a parent directory.".to_owned())?;
    let validated = Config::parse(&output_text, parent)
        .map_err(|_| "Adopted configuration did not validate.".to_owned())?;
    atomic_write(&output,&output_text,&password::random_token(),None).map_err(|_|"Cannot atomically create protected output; use an owned, non-symlink, non-writable-by-others parent and a new output path.".to_owned())?;
    Ok(AdoptConfigReport {
        source_path: source,
        output_path: output,
        revision: revision(&validated)
            .map_err(|_| "Cannot calculate configuration revision.".to_owned())?,
        restart_required: true,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn source(root: &FsPath, managed: bool) -> (PathBuf, Config) {
        let path = root.join("gateway.toml");
        let text = format!(
            "# Keep this operator comment.\nmode='private-fixture'\n[listen]\npublic='127.0.0.1:8080'\nadmin='127.0.0.1:9090'\n[fixture]\nkeyring='keys/fixture.gpg'\nwork_dir='run'\n[verifier]\ntimeout_seconds=30 # verifier comment\n[limits]\nconcurrent_fills=8 # concurrency comment\n[admin]\nmanaged_config={managed}\n"
        );
        let mut file = create_private(&path).unwrap();
        file.write_all(text.as_bytes()).unwrap();
        file.sync_all().unwrap();
        let config = Config::load(&path).unwrap();
        (path, config)
    }
    async fn owner(admin: &AdminStore, root: &FsPath) -> AuthContext {
        admin
            .setup(
                super::super::store::read_bootstrap_token(root).unwrap(),
                "owner".into(),
                "Owner".into(),
                "owner settings password".into(),
            )
            .await
            .unwrap()
            .auth
    }
    async fn proposal(
        admin: &AdminStore,
        auth: &AuthContext,
        base: &Baseline,
        patch: Value,
    ) -> Proposal {
        let prepared = prepare(base, &base.base_revision, &patch).unwrap();
        let proposal = Proposal {
            id: password::random_token(),
            actor: auth.user.id.clone(),
            base_revision: base.base_revision.clone(),
            state: "proposed".into(),
            created_at: now(),
            body: ProposalBody {
                patch: prepared.patch,
                reason: "Reduce fixture concurrency".into(),
                proposed_revision: prepared.revision,
                diffs: prepared.diffs,
                base_file_hash: base.file_hash.clone(),
                proposed_file_hash: prepared.text.as_deref().map(digest),
            },
        };
        let row = proposal.clone();
        let auth = auth.clone();
        admin
            .write(move |tx| {
                actor(tx, &auth, Some(Permission::ManageConfig))?;
                tx.execute(
                    "INSERT INTO config_proposals VALUES(?1,?2,?3,'proposed',?4,?5)",
                    params![
                        row.id,
                        row.actor,
                        row.base_revision,
                        encode_body(&row.body)?,
                        row.created_at
                    ],
                )?;
                audit(
                    tx,
                    &row.actor,
                    "config.propose",
                    &row.id,
                    "proposed",
                    &row.body.reason,
                )
            })
            .await
            .unwrap();
        proposal
    }
    #[test]
    fn patch_validation_uses_allowlists_bounds_and_original_config_parser() {
        let root = tempfile::tempdir().unwrap();
        let (path, config) = source(root.path(), false);
        let base = initial_baseline(&config).unwrap();
        let patch = json!({"limits":{"concurrentFills":4,"readerBufferBytes":"65536","admissionWaitSeconds":2},"verifierTimeoutSeconds":10});
        let prepared = prepare(&base, &base.base_revision, &patch).unwrap();
        assert_eq!(prepared.config.limits.concurrent_fills, 4);
        assert_eq!(prepared.config.limits.reader_buffer_bytes, 65536);
        assert_eq!(prepared.config.verifier.timeout.as_secs(), 10);
        assert_eq!(prepared.diffs.len(), 3); // admission wait already defaults to 2s.
        assert_ne!(prepared.revision, base.base_revision);
        assert!(
            prepared
                .text
                .as_ref()
                .unwrap()
                .contains("# concurrency comment")
        );
        assert!(
            prepared
                .text
                .as_ref()
                .unwrap()
                .contains("# Keep this operator comment.")
        );
        assert!(!prepared.toml_preview.contains("keyring"));
        assert!(!prepared.toml_preview.contains("127.0.0.1"));
        assert!(matches!(
            prepare(&base, "stale", &patch),
            Err(SettingsError::Revision)
        ));
        for invalid in [
            json!({}),
            json!({"limits":{}}),
            json!({"limits":{"concurrentFills":0}}),
            json!({"limits":{"concurrentFills":65}}),
            json!({"limits":{"readerBufferBytes":"4095"}}),
            json!({"limits":{"sourceAttempts":3}}),
            json!({"limits":{"admissionWaitSeconds":3}}),
            json!({"limits":{"connectTimeoutSeconds":4}}),
            json!({"limits":{"managedCeilingBytes":"9999"}}),
            json!({"limits":{"syncIntervalSeconds":1}}),
            json!({"limits":{"requestSlots":"100"}}),
            json!({"verifierTimeoutSeconds":31}),
            json!({"durable":{"suites":[]}}),
            json!({"admin":{"managedConfig":true}}),
            json!({"verifier":{"binary":"shell"}}),
        ] {
            assert!(
                matches!(
                    prepare(&base, &base.base_revision, &invalid),
                    Err(SettingsError::InvalidPatch)
                ),
                "{invalid}"
            );
        }
        // Preview has all it needs in memory and does not reopen the disk file.
        fs::remove_file(path).unwrap();
        assert!(prepare(&base, &base.base_revision, &patch).is_ok());
        assert_eq!(
            field_capabilities(&config)
                .iter()
                .filter(|field| field["editable"] == true)
                .count(),
            17
        );
    }
    #[test]
    fn adoption_preserves_source_comments_and_resolved_authority_paths() {
        let root = tempfile::tempdir().unwrap();
        let (source, original) = source(root.path(), false);
        let before = fs::read(&source).unwrap();
        let destination = root.path().join("managed");
        fs::create_dir(&destination).unwrap();
        let output = destination.join("gateway.toml");
        let report = adopt_managed_config(&source, &output).unwrap();
        assert_eq!(fs::read(&source).unwrap(), before);
        assert_eq!(report.output_path, output);
        let adopted = Config::load(&output).unwrap();
        assert!(adopted.admin.managed_config);
        assert_eq!(adopted.fixture.work_dir, original.fixture.work_dir);
        assert_eq!(adopted.fixture.keyring, original.fixture.keyring);
        assert_eq!(adopted.admin.state_dir, original.admin.state_dir);
        assert!(
            fs::read_to_string(&output)
                .unwrap()
                .contains("# Keep this operator comment.")
        );
        assert!(adopt_managed_config(&source, &source).is_err());
        assert!(adopt_managed_config(&source, &output).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn durable_adoption_resolves_implicit_keyrings_as_well_as_explicit_paths() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("durable.toml");
        let text = "mode='private-durable'\n[listen]\npublic='127.0.0.1:8080'\nadmin='127.0.0.1:9090'\n[durable]\nstate_dir='state'\n[durable.provider]\nendpoint='https://s3.example.org'\nregion='us-east-1'\nbucket='ferrum'\npackage_prefix='linux-packages/'\ncheckpoint_prefix='linux-checkpoints/'\nshared_nonisolated=true\ncredentials_file='provider.toml'\n[durable.keyrings]\ndebian='keyrings/debian.gpg'\nubuntu='keyrings/ubuntu.gpg'\n[durable.budget]\nmode='existing'\n[verifier]\n";
        fs::write(&source, text).unwrap();
        let original = Config::load(&source).unwrap();
        let destination = root.path().join("managed");
        fs::create_dir(&destination).unwrap();
        let output = destination.join("gateway.toml");
        adopt_managed_config(&source, &output).unwrap();
        let adopted = Config::load(&output).unwrap();
        let original = original.durable().unwrap();
        let adopted = adopted.durable().unwrap();
        assert_eq!(original.state_dir, adopted.state_dir);
        assert_eq!(
            original.provider.credentials_file,
            adopted.provider.credentials_file
        );
        match (&original.trust, &adopted.trust) {
            (DurableTrust::Distributions(a), DurableTrust::Distributions(b)) => {
                assert_eq!(a.ubuntu, b.ubuntu);
                assert_eq!(a.kali, b.kali);
                assert_eq!(a.rockylinux, b.rockylinux);
            }
            _ => panic!("distribution trust changed"),
        }
    }
    #[tokio::test]
    async fn readonly_installations_keep_proposals_and_external_edits_never_get_overwritten() {
        let _serial = password::TEST_LOCK.lock().await;
        let root = tempfile::tempdir().unwrap();
        let (path, config) = source(root.path(), false);
        let admin_root = root.path().join("admin");
        let admin = AdminStore::open(&admin_root).unwrap();
        let auth = owner(&admin, &admin_root).await;
        reconcile_config_proposals(&admin, &config).await.unwrap();
        let base = baseline(&config).await.unwrap();
        let p = proposal(
            &admin,
            &auth,
            &base,
            json!({"limits":{"concurrentFills":4}}),
        )
        .await;
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            save_proposal(admin.clone(), Arc::new(config), auth.clone(), p.id.clone()).await,
            Err(SettingsError::ManagedDisabled)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            admin
                .read(move |c| Ok(load_proposal(c, &p.id)?.unwrap().state))
                .await
                .unwrap(),
            "proposed"
        );
        let adopted_path = root.path().join("managed.toml");
        adopt_managed_config(&path, &adopted_path).unwrap();
        let managed = Config::load(&adopted_path).unwrap();
        reconcile_config_proposals(&admin, &managed).await.unwrap();
        let base = baseline(&managed).await.unwrap();
        let p = proposal(
            &admin,
            &auth,
            &base,
            json!({"limits":{"concurrentFills":4}}),
        )
        .await;
        let edited = format!(
            "{}\\n# External host edit.\\n",
            fs::read_to_string(&adopted_path).unwrap()
        );
        fs::write(&adopted_path, &edited).unwrap();
        assert!(matches!(
            save_proposal(admin.clone(), Arc::new(managed), auth, p.id.clone()).await,
            Err(SettingsError::ExternalEdit)
        ));
        assert_eq!(fs::read_to_string(adopted_path).unwrap(), edited);
        let row = admin
            .read(move |c| Ok(load_proposal(c, &p.id)?.unwrap().state))
            .await
            .unwrap();
        assert_eq!(row, "proposed");
        assert_eq!(
            admin
                .read(|c| Ok(c.query_row(
                    "SELECT count(*) FROM audit_events WHERE action='config.save'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?))
                .await
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn managed_save_commits_intent_then_file_then_completion_and_applies_only_on_restart() {
        let _serial = password::TEST_LOCK.lock().await;
        let root = tempfile::tempdir().unwrap();
        let (path, config) = source(root.path(), true);
        let admin_root = root.path().join("admin");
        let admin = AdminStore::open(&admin_root).unwrap();
        let auth = owner(&admin, &admin_root).await;
        reconcile_config_proposals(&admin, &config).await.unwrap();
        let base = baseline(&config).await.unwrap();
        let p = proposal(
            &admin,
            &auth,
            &base,
            json!({"limits":{"concurrentFills":4},"verifierTimeoutSeconds":12}),
        )
        .await;
        let saved = save_proposal(admin.clone(), Arc::new(config.clone()), auth, p.id.clone())
            .await
            .unwrap();
        assert_eq!(saved["state"], "saved");
        assert_eq!(saved["status"], "saved_restart_required");
        assert_eq!(config.limits.concurrent_fills, 8);
        let disk = Config::load(&path).unwrap();
        assert_eq!(disk.limits.concurrent_fills, 4);
        assert_ne!(revision(&config).unwrap(), revision(&disk).unwrap());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("# concurrency comment"));
        assert!(text.contains("# verifier comment"));
        let outcomes = admin
            .read(|c| {
                let mut statement = c.prepare(
                    "SELECT outcome FROM audit_events WHERE action='config.save' ORDER BY id",
                )?;
                Ok(statement
                    .query_map([], |r| r.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?)
            })
            .await
            .unwrap();
        assert_eq!(outcomes, vec!["intent", "saved"]);
        reconcile_config_proposals(&admin, &disk).await.unwrap();
        assert_eq!(
            admin
                .read(move |c| Ok(load_proposal(c, &p.id)?.unwrap().state))
                .await
                .unwrap(),
            "applied"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[tokio::test]
    async fn interrupted_save_reconciliation_uses_exact_disk_evidence_and_removes_only_owned_stage()
    {
        let _serial = password::TEST_LOCK.lock().await;
        let root = tempfile::tempdir().unwrap();
        let (path, config) = source(root.path(), true);
        let admin_root = root.path().join("admin");
        let admin = AdminStore::open(&admin_root).unwrap();
        let auth = owner(&admin, &admin_root).await;
        reconcile_config_proposals(&admin, &config).await.unwrap();
        let base = baseline(&config).await.unwrap();
        let p = proposal(
            &admin,
            &auth,
            &base,
            json!({"limits":{"concurrentFills":3}}),
        )
        .await;
        let prepared = prepare(&base, &base.base_revision, &p.body.patch).unwrap();
        let row = p.clone();
        admin
            .write(move |tx| {
                tx.execute(
                    "UPDATE config_proposals SET state='saving' WHERE id=?1",
                    [&row.id],
                )?;
                audit(
                    tx,
                    &row.actor,
                    "config.save",
                    &row.id,
                    "intent",
                    &row.body.reason,
                )
            })
            .await
            .unwrap();
        let stage = temporary_path(&path, &p.id).unwrap();
        let mut file = create_private(&stage).unwrap();
        file.write_all(b"interrupted partial write").unwrap();
        drop(file);
        // First interruption did not replace the file: return to proposed.
        reconcile_config_proposals(&admin, &config).await.unwrap();
        assert!(!stage.exists());
        let lookup = p.id.clone();
        assert_eq!(
            admin
                .read(move |c| Ok(load_proposal(c, &lookup)?.unwrap().state))
                .await
                .unwrap(),
            "proposed"
        );
        let row = p.clone();
        admin
            .write(move |tx| {
                tx.execute(
                    "UPDATE config_proposals SET state='saving' WHERE id=?1",
                    [&row.id],
                )?;
                audit(
                    tx,
                    &row.actor,
                    "config.save",
                    &row.id,
                    "intent",
                    &row.body.reason,
                )
            })
            .await
            .unwrap();
        fs::write(&path, prepared.text.unwrap()).unwrap();
        let restarted = Config::load(&path).unwrap();
        reconcile_config_proposals(&admin, &restarted)
            .await
            .unwrap();
        assert_eq!(
            admin
                .read(move |c| Ok(load_proposal(c, &p.id)?.unwrap().state))
                .await
                .unwrap(),
            "applied"
        );
    }
    #[cfg(unix)]
    #[test]
    fn managed_saves_reject_symlink_sources_and_unprotected_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        let (path, config) = source(root.path(), true);
        assert!(managed_path(&config).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(managed_path(&config).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = root.path().join("alias.toml");
        symlink(&path, &alias).unwrap();
        let mut aliased = config.clone();
        aliased.set_source_path(alias);
        assert!(managed_path(&aliased).is_err());
        let mut inside = config.clone();
        inside.set_source_path(config.spool_dir().join("config.toml"));
        assert!(matches!(
            managed_path(&inside),
            Err(SettingsError::ManagedDisabled)
        ));
    }
}
