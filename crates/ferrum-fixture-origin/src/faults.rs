//! Fault model and bounded request log shared by the data and control servers.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Key under which a fault applies to every relative path.
pub const WILDCARD_PATH: &str = "*";

/// Maximum number of retained request-log entries; older entries are dropped first.
pub const LOG_CAPACITY: usize = 10_000;

/// Maximum number of distinct fault paths held at once.
pub const FAULT_CAPACITY: usize = 1_024;

/// Maximum byte length of a fault path.
pub const MAX_FAULT_PATH_LEN: usize = 4_096;

/// One injected behaviour for matching requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum FaultKind {
    /// Sleep for `ms` milliseconds before sending response headers.
    Delay { ms: u64 },
    /// Send headers immediately, then `chunk` body bytes every `interval_ms` milliseconds.
    Pace { chunk: u64, interval_ms: u64 },
    /// Declare the full `Content-Length`, send `at` bytes, then abort the connection.
    Truncate { at: u64 },
    /// XOR the byte at `offset` with `0xFF`; the length is unchanged.
    Corrupt { offset: u64 },
    /// Respond 404 as if the file were absent.
    Delete,
}

impl FaultKind {
    /// Stable lowercase name recorded in the request log.
    pub fn name(self) -> &'static str {
        match self {
            FaultKind::Delay { .. } => "delay",
            FaultKind::Pace { .. } => "pace",
            FaultKind::Truncate { .. } => "truncate",
            FaultKind::Corrupt { .. } => "corrupt",
            FaultKind::Delete => "delete",
        }
    }

    pub(crate) fn validate(self) -> Result<(), FaultError> {
        match self {
            FaultKind::Pace { chunk: 0, .. } => Err(FaultError::ZeroChunk),
            _ => Ok(()),
        }
    }
}

/// A fault plus its optional application budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fault {
    #[serde(flatten)]
    pub kind: FaultKind,
    /// Apply to this many further matching requests, then auto-clear; `None` is persistent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<u64>,
}

impl Fault {
    pub(crate) fn validate(self) -> Result<(), FaultError> {
        if self.remaining == Some(0) {
            return Err(FaultError::ZeroRemaining);
        }
        self.kind.validate()
    }
}

/// Rejected fault definitions and table limits.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FaultError {
    #[error("pace chunk must be greater than zero")]
    ZeroChunk,
    #[error("remaining must be greater than zero (omit it for a persistent fault)")]
    ZeroRemaining,
    #[error("fault path exceeds {MAX_FAULT_PATH_LEN} bytes")]
    PathTooLong,
    #[error("fault table full")]
    TableFull,
}

/// Faults keyed by exact relative path or [`WILDCARD_PATH`].
#[derive(Default)]
pub struct FaultTable {
    entries: Mutex<BTreeMap<String, Fault>>,
}

impl FaultTable {
    /// Replace the fault registered for `path`.
    ///
    /// Replacing an existing path never consumes table budget; a new path beyond
    /// [`FAULT_CAPACITY`] is rejected with [`FaultError::TableFull`] and a path longer
    /// than [`MAX_FAULT_PATH_LEN`] bytes with [`FaultError::PathTooLong`].
    pub fn set(&self, path: String, fault: Fault) -> Result<(), FaultError> {
        fault.validate()?;
        if path.len() > MAX_FAULT_PATH_LEN {
            return Err(FaultError::PathTooLong);
        }
        let mut entries = self.lock();
        if entries.len() >= FAULT_CAPACITY && !entries.contains_key(&path) {
            return Err(FaultError::TableFull);
        }
        entries.insert(path, fault);
        Ok(())
    }

    /// Remove the fault for `path`; returns whether one existed.
    pub fn remove(&self, path: &str) -> bool {
        self.lock().remove(path).is_some()
    }

    pub fn clear(&self) {
        self.lock().clear();
    }

    pub fn snapshot(&self) -> BTreeMap<String, Fault> {
        self.lock().clone()
    }

    /// Find the fault for `path` (exact match wins over the wildcard), consuming one
    /// application from its budget and auto-clearing it when the budget reaches zero.
    pub fn take_for(&self, path: &str) -> Option<FaultKind> {
        let mut entries = self.lock();
        let key = if entries.contains_key(path) {
            path
        } else if entries.contains_key(WILDCARD_PATH) {
            WILDCARD_PATH
        } else {
            return None;
        };
        let fault = entries.get_mut(key)?;
        let kind = fault.kind;
        match fault.remaining {
            Some(budget) if budget <= 1 => {
                entries.remove(key);
            }
            Some(budget) => fault.remaining = Some(budget.saturating_sub(1)),
            None => {}
        }
        Some(kind)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Fault>> {
        // A poisoned fault table only means a panicking holder; the map itself stays valid.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One served request as reported by `GET /log`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    /// Milliseconds since origin start at which the request arrived.
    pub at_ms: u64,
    pub method: String,
    /// Relative path for requests inside the prefix; the raw request path otherwise.
    pub path: String,
    pub status: u16,
    /// Body bytes handed to the transport; a truncated response records its `at`.
    pub bytes_sent: u64,
    pub range: Option<String>,
    pub fault: Option<String>,
}

/// Log entry under construction while a response is streaming.
#[derive(Clone, Debug)]
pub struct PendingEntry {
    pub at: Duration,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub range: Option<String>,
    pub fault: Option<FaultKind>,
}

/// Bounded ring of the most recent [`LOG_CAPACITY`] requests.
#[derive(Default)]
pub struct RequestLog {
    inner: Mutex<LogRing>,
}

#[derive(Default)]
struct LogRing {
    next_seq: u64,
    entries: VecDeque<LogEntry>,
}

impl RequestLog {
    /// Append a finished request and emit its one-line tracing record.
    pub fn record(&self, pending: PendingEntry, bytes_sent: u64) {
        let fault = pending.fault.map(FaultKind::name);
        tracing::info!(
            method = %pending.method,
            path = %pending.path,
            status = pending.status,
            bytes_sent,
            range = pending.range.as_deref().unwrap_or("-"),
            fault = fault.unwrap_or("-"),
            "request"
        );
        let mut ring = self.lock();
        let seq = ring.next_seq;
        ring.next_seq = seq.saturating_add(1);
        if ring.entries.len() >= LOG_CAPACITY {
            ring.entries.pop_front();
        }
        ring.entries.push_back(LogEntry {
            seq,
            at_ms: u64::try_from(pending.at.as_millis()).unwrap_or(u64::MAX),
            method: pending.method,
            path: pending.path,
            status: pending.status,
            bytes_sent,
            range: pending.range,
            fault: fault.map(str::to_owned),
        });
    }

    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.lock().entries.iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.lock().entries.clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LogRing> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
