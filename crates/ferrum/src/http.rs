//! HTTP protocol pieces shared by the public listener: request validation
//! ([`request`]), Range evaluation ([`range`]), response construction
//! ([`response`]) and the permit-holding body stream below.

pub mod range;
pub mod request;
pub mod response;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ferrum_storage::{ObjectStream, SpoolError};
use futures_util::Stream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Sleep;

use crate::health::{Metrics, RequestClass};

/// Permits a response body holds for its lifetime: the request slot and the
/// active-body permit. Dropping the body (completion, disconnect, timeout)
/// releases both.
pub struct BodyPermits {
    pub request_slot: OwnedSemaphorePermit,
    pub active_body: OwnedSemaphorePermit,
}

/// A verified-object range stream bounded by a per-chunk idle timer and a
/// total lifetime. Either bound ends the stream with an error so the
/// connection is reset; nothing is ever appended.
pub struct BodyStream {
    inner: ObjectStream,
    _permits: BodyPermits,
    metrics: Arc<Metrics>,
    class: RequestClass,
    started: Instant,
    remaining: u64,
    completed: bool,
    idle: Duration,
    idle_timer: Pin<Box<Sleep>>,
    deadline: Instant,
}

impl BodyStream {
    pub fn new(
        inner: ObjectStream,
        permits: BodyPermits,
        metrics: Arc<Metrics>,
        class: RequestClass,
        expected_bytes: u64,
        idle: Duration,
        lifetime: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            inner,
            _permits: permits,
            metrics,
            class,
            started: now,
            remaining: expected_bytes,
            completed: expected_bytes == 0,
            idle,
            idle_timer: Box::pin(tokio::time::sleep(idle)),
            deadline: now + lifetime,
        }
    }
}

impl Drop for BodyStream {
    fn drop(&mut self) {
        if !self.completed {
            self.metrics
                .record_body_transfer(false, self.class, self.started.elapsed());
        }
    }
}

impl Stream for BodyStream {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response body lifetime exceeded",
            ))));
        }
        if self.idle_timer.as_mut().poll(context).is_ready() {
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response body idle timeout",
            ))));
        }
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(Ok(chunk))) => {
                let idle = self.idle;
                self.idle_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle);
                let len = chunk.len() as u64;
                self.metrics.record_body_bytes(self.class, len);
                self.remaining = self.remaining.saturating_sub(len);
                if self.remaining == 0 && !self.completed {
                    self.completed = true;
                    self.metrics
                        .record_body_transfer(true, self.class, self.started.elapsed());
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(spool_io(error)))),
            Poll::Ready(None) => {
                if self.remaining == 0 && !self.completed {
                    self.completed = true;
                    self.metrics
                        .record_body_transfer(true, self.class, self.started.elapsed());
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn spool_io(error: SpoolError) -> io::Error {
    match error {
        SpoolError::Io(error) => error,
        other => io::Error::other(other),
    }
}
