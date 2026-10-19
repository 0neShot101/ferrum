//! Installed, immutable objects and bounded positional range streams.
//!
//! Every handle and detached read is a lease. The registry's sole reference can
//! be evicted only while holding the same owner lock used to clone a lease.
//! Per-stream offsets use the spool's owned, bounded filesystem worker pool.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use futures_util::stream::{Stream, StreamExt};
use tokio::sync::Semaphore;

use super::{SpoolError, SpoolInner, SpoolLifetime};

struct ObjectInner {
    identity: ObjectIdentity,
    path: PathBuf,
    file: File,
    /// Keeps the ledger and directory lock alive until this descriptor closes.
    _lifetime: Arc<SpoolLifetime>,
    #[cfg(test)]
    hook: Arc<std::sync::Mutex<Option<super::tests::Hook>>>,
    read_chunk: usize,
    io_permits: Arc<Semaphore>,
    io: Arc<super::io::IoPool>,
}

/// Immutable installed object whose length and SHA-256 were verified at
/// commit time.
#[derive(Clone)]
pub struct VerifiedObject(Arc<ObjectInner>);

impl std::fmt::Debug for VerifiedObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedObject")
            .field("identity", &self.0.identity)
            .field("path", &self.0.path)
            .finish()
    }
}

impl VerifiedObject {
    pub(crate) fn belongs_to(&self, spool: &super::Spool) -> bool {
        Arc::ptr_eq(&self.0._lifetime, &spool.0.lifetime)
    }
    /// Opens the installed file read-only (blocking; call from the I/O pool).
    pub(crate) fn open(
        spool: &SpoolInner,
        identity: ObjectIdentity,
        path: PathBuf,
    ) -> io::Result<Self> {
        let file = File::open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != identity.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed object has an unexpected type or size",
            ));
        }
        Ok(Self(Arc::new(ObjectInner {
            identity,
            path,
            file,
            _lifetime: Arc::clone(&spool.lifetime),
            #[cfg(test)]
            hook: Arc::clone(&spool.hook),
            read_chunk: spool.read_chunk(),
            io_permits: Arc::clone(spool.io_permits()),
            io: Arc::clone(&spool.io),
        })))
    }

    /// Called only under the disk-owner registry lock.
    pub(super) fn exclusive_to_owner(&self) -> bool {
        Arc::strong_count(&self.0) == 1
    }

    /// Verified identity (digest and length).
    pub fn identity(&self) -> ObjectIdentity {
        self.0.identity
    }

    /// Verified length in bytes.
    pub fn size(&self) -> u64 {
        self.0.identity.size
    }

    /// Verified SHA-256 digest.
    pub fn sha256(&self) -> Sha256Digest {
        self.0.identity.sha256
    }

    /// Installed digest path.
    pub fn path(&self) -> &Path {
        &self.0.path
    }

    /// Streams bytes `start..=end_inclusive` in chunks of at most the
    /// configured read chunk. Each stream owns its own offset.
    ///
    /// # Errors
    ///
    /// [`SpoolError::InvalidRange`] unless `start <= end_inclusive < size`.
    /// Read failures surface as [`SpoolError::Io`] items, after which the
    /// stream ends.
    ///
    /// Dropping the stream stops further reads; a chunk already handed to the
    /// blocking pool completes (bounded by one chunk) and is discarded.
    pub fn stream_range(&self, start: u64, end_inclusive: u64) -> Result<ObjectStream, SpoolError> {
        if start > end_inclusive || end_inclusive >= self.size() {
            return Err(SpoolError::InvalidRange);
        }
        let end = end_inclusive
            .checked_add(1)
            .ok_or(SpoolError::InvalidRange)?;
        let cursor = RangeCursor {
            object: Arc::clone(&self.0),
            offset: start,
            end,
        };
        let stream = futures_util::stream::unfold(cursor, |mut cursor| async move {
            if cursor.offset >= cursor.end {
                return None;
            }
            match cursor.read_next().await {
                Ok(chunk) => {
                    cursor.offset = cursor.offset.saturating_add(chunk.len() as u64);
                    Some((Ok(chunk), cursor))
                }
                Err(error) => {
                    cursor.end = cursor.offset;
                    Some((Err(error), cursor))
                }
            }
        });
        Ok(ObjectStream {
            inner: Box::pin(stream.fuse()),
        })
    }

    /// Reads the whole object into memory when it is at most `max` bytes;
    /// intended for metadata only.
    ///
    /// # Errors
    ///
    /// [`SpoolError::TooLarge`] when the object exceeds `max`; otherwise the
    /// errors of [`VerifiedObject::stream_range`].
    pub async fn read_bounded(&self, max: usize) -> Result<Vec<u8>, SpoolError> {
        let size = self.size();
        let capacity = usize::try_from(size)
            .ok()
            .filter(|&capacity| capacity <= max)
            .ok_or(SpoolError::TooLarge)?;
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = Vec::with_capacity(capacity);
        let mut stream = self.stream_range(0, size.saturating_sub(1))?;
        while let Some(chunk) = stream.next().await {
            buffer.extend_from_slice(&chunk?);
        }
        Ok(buffer)
    }
}

struct RangeCursor {
    object: Arc<ObjectInner>,
    offset: u64,
    end: u64,
}

impl RangeCursor {
    async fn read_next(&self) -> Result<Bytes, SpoolError> {
        let remaining = self.end.saturating_sub(self.offset);
        let length = usize::try_from(remaining).map_or(self.object.read_chunk, |remaining| {
            remaining.min(self.object.read_chunk)
        });
        let permit = Arc::clone(&self.object.io_permits)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("spool I/O pool closed"))?;
        let object = Arc::clone(&self.object);
        let offset = self.offset;
        self.object
            .io
            .run(permit, move || {
                let lease = object;
                #[cfg(test)]
                super::tests::pause(&lease.hook, "read");
                read_chunk_at(&lease.file, offset, length)
            })
            .await?
    }
}

fn read_chunk_at(file: &File, offset: u64, length: usize) -> Result<Bytes, SpoolError> {
    let mut buffer = vec![0u8; length];
    file.read_exact_at(&mut buffer, offset)?;
    Ok(Bytes::from(buffer))
}

/// Bounded chunk stream over one byte range of a [`VerifiedObject`].
pub struct ObjectStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, SpoolError>> + Send + 'static>>,
}

impl Stream for ObjectStream {
    type Item = Result<Bytes, SpoolError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}
