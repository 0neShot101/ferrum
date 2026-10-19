//! Private, local-only comparison through the durable Spool safety owner.
//! Bodies are generated deterministically at trace sizes; source tiers are a
//! model, not network traffic or evidence of package authenticity/durability.

mod runner;

use std::io::{self, Read};
use std::path::Path;

pub use crate::eviction::{PolicyKind, PolicyStats};
pub use runner::{RunReport, run};

pub const MAX_TRACE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_EVENTS: usize = 100_000;
pub const MAX_OBJECTS: usize = 4096;
pub const MAX_CACHE_BYTES: u64 = 448 * 1024 * 1024;
pub const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("invalid replay: {0}")]
    Invalid(&'static str),
    #[error("replay deadline exceeded")]
    Deadline,
    #[error("replay worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Spool(#[from] crate::disk::SpoolError),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    pub schema_version: u32,
    pub synthetic: bool,
    pub dataset: String,
    pub seed: u64,
    /// Package residency byte ceiling; SQL/temporary headroom is separate.
    pub cache_bytes: u64,
    pub objects: Vec<TraceObject>,
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceObject {
    /// Actual size for representative traces, explicitly chosen size for synthetic traces.
    pub size: u64,
    /// Generates a bounded repeating payload, not the original package bytes.
    pub content_seed: u64,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Upstream,
    E2,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pin {
    Reader,
    Fill,
    Upload,
    Generation,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Request {
        object: usize,
        source: Source,
    },
    /// One pin per slot. Reader pins use the normal synchronized owner lease pin,
    /// not a demand lookup. Slot identities must match at Unpin.
    Pin {
        object: usize,
        slot: usize,
        kind: Pin,
    },
    Unpin {
        slot: usize,
    },
    /// Eligibility oracle ONLY inside this fresh owned scratch replay. No SQL
    /// receipt is fabricated and no production durability is asserted.
    Outbox {
        object: usize,
        pending: bool,
    },
    Reclaim {
        bytes: u64,
    },
}

impl Trace {
    /// Reads at most 8 MiB plus one detection byte; rejects unknown schema/fields.
    pub fn read(path: &Path) -> Result<Self, ReplayError> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(MAX_TRACE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_TRACE_BYTES {
            return Err(ReplayError::Invalid("trace exceeds 8 MiB"));
        }
        let trace: Self = serde_json::from_slice(&bytes)?;
        trace.validate()?;
        Ok(trace)
    }

    pub fn validate(&self) -> Result<(), ReplayError> {
        if self.schema_version != 1
            || self.dataset.is_empty()
            || self.dataset.len() > 256
            || self.cache_bytes == 0
            || self.cache_bytes > MAX_CACHE_BYTES
            || self.objects.is_empty()
            || self.objects.len() > MAX_OBJECTS
            || self.events.len() > MAX_EVENTS
        {
            return Err(ReplayError::Invalid("schema, label, count or cache bound"));
        }
        if self
            .objects
            .iter()
            .any(|object| object.size > MAX_OBJECT_BYTES)
        {
            return Err(ReplayError::Invalid("object exceeds 64 MiB"));
        }
        let object_bytes = self
            .objects
            .iter()
            .try_fold(0u64, |bytes, object| bytes.checked_add(object.size))
            .ok_or(ReplayError::Invalid("object byte overflow"))?;
        if object_bytes > MAX_REQUEST_BYTES {
            return Err(ReplayError::Invalid(
                "object identity hashing exceeds 2 GiB",
            ));
        }
        let mut request_bytes = 0u64;
        let mut requests = 0;
        let mut pins = [false; MAX_OBJECTS];
        for event in &self.events {
            let object = match *event {
                Event::Request { object, .. }
                | Event::Pin { object, .. }
                | Event::Outbox { object, .. } => Some(object),
                _ => None,
            };
            if object.is_some_and(|object| object >= self.objects.len()) {
                return Err(ReplayError::Invalid("unknown object index"));
            }
            match *event {
                Event::Request { object, .. } => {
                    requests += 1;
                    request_bytes = request_bytes
                        .checked_add(self.objects[object].size)
                        .ok_or(ReplayError::Invalid("request byte overflow"))?;
                }
                Event::Pin { slot, .. } => {
                    if slot >= MAX_OBJECTS || pins[slot] {
                        return Err(ReplayError::Invalid("pin slot reused or out of bounds"));
                    }
                    pins[slot] = true;
                }
                Event::Unpin { slot } => {
                    if slot >= MAX_OBJECTS || !pins[slot] {
                        return Err(ReplayError::Invalid("unknown pin slot"));
                    }
                    pins[slot] = false;
                }
                Event::Reclaim { bytes } if bytes > MAX_CACHE_BYTES => {
                    return Err(ReplayError::Invalid("reclaim bound"));
                }
                _ => {}
            }
        }
        if requests == 0 || request_bytes > MAX_REQUEST_BYTES {
            return Err(ReplayError::Invalid(
                "empty requests or more than 2 GiB requested",
            ));
        }
        Ok(())
    }

    /// Synthetic hot reuse, one-pass scan, mixed sizes and pin/outbox pressure.
    /// 682 and 1,065,152 are fixture sizes, NOT an archive size distribution.
    pub fn synthetic() -> Self {
        let objects = (0..24)
            .map(|index| TraceObject {
                size: if index % 3 == 0 { 682 } else { 1_065_152 },
                content_seed: index + 1,
            })
            .collect();
        let mut events = Vec::new();
        for object in 0..4 {
            events.push(Event::Request {
                object,
                source: Source::Upstream,
            });
        }
        events.push(Event::Pin {
            object: 0,
            slot: 0,
            kind: Pin::Generation,
        });
        events.push(Event::Pin {
            object: 1,
            slot: 1,
            kind: Pin::Reader,
        });
        events.push(Event::Outbox {
            object: 2,
            pending: true,
        });
        for _ in 0..3 {
            for object in 0..4 {
                events.push(Event::Request {
                    object,
                    source: Source::E2,
                });
            }
        }
        for object in 4..24 {
            events.push(Event::Request {
                object,
                source: Source::Upstream,
            });
        }
        events.push(Event::Reclaim {
            bytes: 2 * 1024 * 1024,
        });
        events.push(Event::Unpin { slot: 0 });
        events.push(Event::Unpin { slot: 1 });
        events.push(Event::Outbox {
            object: 2,
            pending: false,
        });
        for _ in 0..3 {
            for object in 0..4 {
                events.push(Event::Request {
                    object,
                    source: Source::E2,
                });
            }
        }
        Self {
            schema_version: 1,
            synthetic: true,
            dataset: "synthetic-fixture-size-choices-not-representative".into(),
            seed: 1,
            cache_bytes: 6 * 1024 * 1024,
            objects,
            events,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validates_trace_bounds_and_pin_lifetimes() {
        let mut trace = Trace::synthetic();
        trace.validate().expect("synthetic trace");
        trace.schema_version = 2;
        assert!(trace.validate().is_err());
        trace.schema_version = 1;
        trace.events.push(Event::Unpin { slot: MAX_OBJECTS });
        assert!(trace.validate().is_err());
    }

    #[test]
    fn rejects_oversized_objects_work_and_unknown_events() {
        let mut trace = Trace::synthetic();
        trace.objects[0].size = MAX_OBJECT_BYTES + 1;
        assert!(trace.validate().is_err());
        trace = Trace::synthetic();
        trace.cache_bytes = MAX_CACHE_BYTES + 1;
        assert!(trace.validate().is_err());
        trace = Trace::synthetic();
        trace.events = vec![
            Event::Request {
                object: 0,
                source: Source::Upstream
            };
            MAX_EVENTS + 1
        ];
        assert!(trace.validate().is_err());
        assert!(
            serde_json::from_str::<Event>(
                r#"{"event":"request","object":0,"source":"e2","durable":true}"#
            )
            .is_err()
        );
    }
}
