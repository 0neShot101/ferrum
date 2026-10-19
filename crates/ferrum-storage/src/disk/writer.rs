//! Bounded shared hash/write pipeline. A detached operation retains the exact
//! temporary owner, reservation and file guard until its bounded work finishes.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use ferrum_apt::digest::{ObjectIdentity, Sha256Hasher};
use tokio::sync::{Mutex, OwnedSemaphorePermit};

use super::{
    Entry, Reservation, ReservationClass, Spool, SpoolError, SpoolInner, VerifiedObject,
    lock_unpoisoned,
};

const TEMPORARY_NAME_ATTEMPTS: u32 = 16;

struct TemporaryFile {
    path: Option<PathBuf>,
    published: Option<PathBuf>,
    file: Option<File>,
    reservation: Reservation,
}

impl TemporaryFile {
    fn create(
        directory: &Path,
        reservation: Reservation,
        expected: Option<ObjectIdentity>,
    ) -> Result<Self, SpoolError> {
        for _ in 0..TEMPORARY_NAME_ATTEMPTS {
            let name = format!("{:032x}.part", rand::random::<u128>());
            if let (Some(catalog), Some(id), Some(expected)) =
                (reservation.spool.catalog(), &reservation.id, expected)
            {
                catalog.bind(id.clone(), expected, name.clone())?;
            }
            let path = directory.join(name);
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(Self {
                        path: Some(path),
                        published: None,
                        file: Some(file),
                        reservation,
                    });
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "could not allocate unique temporary name",
        )
        .into())
    }

    fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("temporary already closed"))
    }

    fn remove_temporary(&mut self) -> io::Result<()> {
        let result = self
            .reservation
            .spool
            .failpoint("temporary-unlink")
            .and_then(|()| remove_name(&mut self.path, self.reservation.spool.catalog().is_some()));
        if result.is_err() {
            self.reservation.retain();
        }
        result
    }

    fn cleanup(&mut self) -> io::Result<()> {
        let durable = self.reservation.spool.catalog().is_some();
        let published = remove_name(&mut self.published, durable);
        let temporary = self.remove_temporary();
        drop(self.file.take());
        let result = published.and(temporary);
        if result.is_err() {
            self.reservation.retain();
        }
        result
    }

    fn preserve_orphan(&mut self) {
        // A failed post-rename fsync/SQL leaves a reservation-backed orphan.
        // Do not turn an uncertain SQL outcome into an unaccounted unlink.
        self.published = None;
        self.reservation.retain();
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::error!(%error, "spool cleanup failed; charge retained and admission closed");
        }
    }
}

fn remove_name(path: &mut Option<PathBuf>, durable: bool) -> io::Result<()> {
    if let Some(name) = path.as_ref() {
        match fs::remove_file(name) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if durable {
            fsync_directory(
                name.parent()
                    .ok_or_else(|| io::Error::other("temporary has no parent"))?,
            )?;
        }
        *path = None;
    }
    Ok(())
}

/// Only an exclusively created spool temporary can become a snapshot. No caller
/// can adopt an arbitrary path, and publication uses the normal writer install.
pub(crate) struct SnapshotFile {
    temporary: TemporaryFile,
    // SQLite can copy one 64-page step before noticing an over-cap source.
    _step_allowance: Reservation,
    spool: Spool,
}

impl SnapshotFile {
    pub(crate) async fn create(spool: &Spool, maximum: u64) -> Result<Self, SpoolError> {
        let reservation = spool.reserve_class(maximum, ReservationClass::Metadata)?;
        let step_allowance = spool.reserve_class(256 * 1024, ReservationClass::Metadata)?;
        let permit = acquire_permit(&spool.0).await?;
        let spool = spool.clone();
        let owner = spool.clone();
        spool
            .0
            .io
            .run(permit, move || {
                owner.0.ensure_admission()?;
                let temporary = TemporaryFile::create(&owner.0.temporary_dir(), reservation, None)?;
                Ok(Self {
                    temporary,
                    _step_allowance: step_allowance,
                    spool: owner,
                })
            })
            .await?
    }

    pub(crate) fn path(&self) -> Result<&Path, SpoolError> {
        self.temporary
            .path
            .as_deref()
            .ok_or_else(|| io::Error::other("snapshot temporary name missing").into())
    }
    /// Hash the exclusively owned SQLite output once, then adopt its inode.
    /// Conservatively overlap raw and exact reservations without changing ledger
    /// semantics; peak staging is at most twice the cap plus one SQLite step.
    pub(crate) async fn install(
        self,
        deadline: std::time::Instant,
    ) -> Result<SnapshotObject, SpoolError> {
        let permit = acquire_permit(&self.spool.0).await?;
        let owner = self.spool.clone();
        owner
            .0
            .io
            .run(permit, move || {
                let mut snapshot = self;
                #[cfg(test)]
                snapshot.spool.0.pause("snapshot-hash");
                let file = snapshot.temporary.file()?;
                let size = file.metadata()?.len();
                let maximum = snapshot.temporary.reservation.size;
                if size > maximum {
                    return Err(SpoolError::ObjectTooLarge { size, max: maximum });
                }
                let mut hasher = Sha256Hasher::new();
                let mut offset = 0;
                let mut buffer = vec![0; super::MAX_READ_CHUNK];
                while offset < size {
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            ErrorKind::TimedOut,
                            "snapshot hashing deadline exceeded",
                        )
                        .into());
                    }
                    let length = (size - offset).min(buffer.len() as u64) as usize;
                    file.read_exact_at(&mut buffer[..length], offset)?;
                    hasher.update(&buffer[..length]);
                    offset += length as u64;
                }
                let identity = ObjectIdentity {
                    sha256: hasher.finalize(),
                    size,
                };
                let reservation = snapshot
                    .spool
                    .reserve_class(size, ReservationClass::Metadata)?;
                if let (Some(catalog), Some(id)) = (snapshot.spool.0.catalog(), &reservation.id) {
                    let name = snapshot
                        .path()?
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| io::Error::other("invalid snapshot temporary name"))?;
                    catalog.bind(id.clone(), identity, name.to_owned())?;
                }
                // The exact reservation owns the same file before either raw
                // charge is released. No uncharged I/O or additional copy.
                drop(std::mem::replace(
                    &mut snapshot.temporary.reservation,
                    reservation,
                ));
                drop(snapshot._step_allowance);
                #[cfg(test)]
                snapshot.spool.0.pause("snapshot-install");
                let object = install(&snapshot.spool.0, &mut snapshot.temporary, identity)?;
                Ok(SnapshotObject {
                    spool: snapshot.spool,
                    object: Some(object),
                })
            })
            .await?
    }
}

/// Owns local cleanup even if an installed result loses its async receiver.
pub(crate) struct SnapshotObject {
    spool: Spool,
    object: Option<VerifiedObject>,
}

impl SnapshotObject {
    pub(crate) fn object(&self) -> Result<&VerifiedObject, SpoolError> {
        self.object.as_ref().ok_or(SpoolError::ReservationMismatch)
    }

    pub(crate) fn into_object(mut self) -> Result<VerifiedObject, SpoolError> {
        self.object.take().ok_or(SpoolError::ReservationMismatch)
    }

    pub(crate) fn cleanup(mut self) -> Result<(), SpoolError> {
        self.remove()
    }

    fn remove(&mut self) -> Result<(), SpoolError> {
        if let Some(object) = self.object.take() {
            let identity = object.identity();
            drop(object);
            self.spool.discard_unreferenced_metadata(identity)?;
        }
        Ok(())
    }
}

impl Drop for SnapshotObject {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::error!(%error, "snapshot cleanup failed; installed charge retained");
        }
    }
}

pub struct SpoolWriter {
    spool: Arc<SpoolInner>,
    expected: ObjectIdentity,
    temporary: Arc<Mutex<TemporaryFile>>,
    hasher: Option<Sha256Hasher>,
    written: u64,
}

impl SpoolWriter {
    pub(crate) async fn create(
        spool: Arc<SpoolInner>,
        reservation: Reservation,
        expected: ObjectIdentity,
    ) -> Result<Self, SpoolError> {
        let directory = spool.temporary_dir();
        let permit = acquire_permit(&spool).await?;
        let owner = Arc::clone(&spool);
        let temporary = spool
            .io
            .run(permit, move || {
                owner.ensure_admission()?;
                let temporary = TemporaryFile::create(&directory, reservation, Some(expected))?;
                #[cfg(test)]
                owner.pause("create");
                Ok::<_, SpoolError>(Arc::new(Mutex::new(temporary)))
            })
            .await??;
        Ok(Self {
            spool,
            expected,
            temporary,
            hasher: Some(Sha256Hasher::new()),
            written: 0,
        })
    }

    /// Writes a bounded owned chunk without copying its payload. Cancellation
    /// poisons hashing until `reset` serializes behind the detached operation.
    pub async fn write(&mut self, mut chunk: Bytes) -> Result<(), SpoolError> {
        u64::try_from(chunk.len())
            .ok()
            .and_then(|length| self.written.checked_add(length))
            .filter(|&next| next <= self.expected.size)
            .ok_or(SpoolError::Overflow {
                expected: self.expected.size,
            })?;
        while chunk.len() > super::MAX_READ_CHUNK {
            self.write_chunk(chunk.split_to(super::MAX_READ_CHUNK))
                .await?;
        }
        self.write_chunk(chunk).await
    }

    async fn write_chunk(&mut self, chunk: Bytes) -> Result<(), SpoolError> {
        let next_written =
            self.written
                .checked_add(chunk.len() as u64)
                .ok_or(SpoolError::Overflow {
                    expected: self.expected.size,
                })?;
        let hasher = self.hasher.take().ok_or_else(poisoned)?;
        let temporary = Arc::clone(&self.temporary).lock_owned().await;
        let permit = acquire_permit(&self.spool).await?;
        let offset = self.written;
        let hasher = self
            .spool
            .io
            .run(permit, move || {
                let guard = temporary;
                #[cfg(test)]
                guard.reservation.spool.pause("write");
                let mut hasher = hasher;
                guard.file()?.write_all_at(&chunk, offset)?;
                hasher.update(&chunk);
                Ok::<_, io::Error>(hasher)
            })
            .await??;
        self.hasher = Some(hasher);
        self.written = next_written;
        Ok(())
    }

    pub async fn reset(&mut self) -> Result<(), SpoolError> {
        self.hasher = None;
        let temporary = Arc::clone(&self.temporary).lock_owned().await;
        let permit = acquire_permit(&self.spool).await?;
        self.spool
            .io
            .run(permit, move || {
                let guard = temporary;
                #[cfg(test)]
                guard.reservation.spool.pause("reset");
                guard.file()?.set_len(0)
            })
            .await??;
        self.hasher = Some(Sha256Hasher::new());
        self.written = 0;
        Ok(())
    }

    pub fn written(&self) -> u64 {
        self.written
    }
    pub fn expected(&self) -> ObjectIdentity {
        self.expected
    }

    /// Exact length/digest, file fsync, no-replace install, durable parent
    /// directories, then SQL residency. Nothing is readable before all succeed.
    /// Cancellation does not undo a commit already admitted to the I/O pool.
    pub async fn commit(self) -> Result<VerifiedObject, SpoolError> {
        let Self {
            spool,
            expected,
            temporary,
            hasher,
            written,
        } = self;
        let actual_sha256 = hasher.ok_or_else(poisoned)?.finalize();
        if written != expected.size || actual_sha256 != expected.sha256 {
            remove_blocking(temporary, &spool).await;
            return Err(SpoolError::Mismatch {
                expected,
                actual_size: written,
                actual_sha256,
            });
        }
        let temporary = temporary.lock_owned().await;
        let permit = acquire_permit(&spool).await?;
        let owner = Arc::clone(&spool);
        spool
            .io
            .run(permit, move || {
                let mut temporary = temporary;
                #[cfg(test)]
                owner.pause("commit");
                install(&owner, &mut temporary, expected)
            })
            .await?
    }

    pub async fn abort(self) {
        remove_blocking(self.temporary, &self.spool).await;
    }
}

async fn acquire_permit(spool: &SpoolInner) -> Result<OwnedSemaphorePermit, SpoolError> {
    Arc::clone(spool.io_permits())
        .acquire_owned()
        .await
        .map_err(|_| SpoolError::Io(io::Error::other("spool I/O pool closed")))
}
fn poisoned() -> SpoolError {
    SpoolError::Io(io::Error::other(
        "spool writer poisoned by an earlier failure or cancellation; reset before writing",
    ))
}

async fn remove_blocking(temporary: Arc<Mutex<TemporaryFile>>, spool: &SpoolInner) {
    let temporary = temporary.lock_owned().await;
    let permit = match acquire_permit(spool).await {
        Ok(permit) => permit,
        Err(error) => {
            tracing::error!(%error, "spool cleanup pool closed");
            return;
        }
    };
    if let Err(error) = spool
        .io
        .run(permit, move || {
            drop(temporary);
        })
        .await
    {
        tracing::error!(%error, "spool cleanup task failed");
    }
}

fn install(
    spool: &SpoolInner,
    temporary: &mut TemporaryFile,
    expected: ObjectIdentity,
) -> Result<VerifiedObject, SpoolError> {
    let mut registry = lock_unpoisoned(&spool.installed);
    let mut transaction = InstallGuard {
        spool,
        complete: false,
    };
    let result = (|| {
        spool.ensure_admission()?;
        if temporary.reservation.size != expected.size {
            return Err(SpoolError::ReservationMismatch);
        }
        if let Some(existing) = registry.entries.get_mut(&expected) {
            if existing.evicting {
                return Err(SpoolError::AdmissionClosed);
            }
            temporary.cleanup()?;
            if !temporary.reservation.class.metadata()
                && existing.class.metadata()
                && let Some(catalog) = spool.catalog()
            {
                if let Err(error) = catalog.require_package_retention(expected) {
                    spool.close_admission();
                    return Err(error.into());
                }
                lock_unpoisoned(&spool.lifetime.ledger).require_package_retention(expected.size)?;
                existing.class = super::ReservationClass::Package;
            }
            if let Some(catalog) = spool.catalog() {
                catalog.enqueue_installed_capture(expected)?;
            }
            return Ok(existing.object.clone());
        }
        spool.failpoint("file-fsync")?;
        temporary.file()?.sync_all()?;
        let destination = spool.object_path(&expected.sha256);
        let parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("object path has no parent"))?;
        let grandparent = parent
            .parent()
            .ok_or_else(|| io::Error::other("object path has no grandparent"))?;
        create_dir_durably(grandparent)?;
        create_dir_durably(parent)?;
        let source = temporary
            .path
            .as_ref()
            .ok_or_else(|| io::Error::other("temporary name missing"))?;
        if spool.catalog().is_some() {
            match rustix::fs::renameat_with(
                rustix::fs::CWD,
                source,
                rustix::fs::CWD,
                &destination,
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {
                    temporary.path = None;
                    temporary.published = Some(destination.clone());
                }
                Err(error) => {
                    if error == rustix::io::Errno::EXIST {
                        temporary.reservation.retain();
                    }
                    return Err(io::Error::from(error).into());
                }
            }
        } else {
            match fs::hard_link(source, &destination) {
                Ok(()) => temporary.published = Some(destination.clone()),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    temporary.reservation.retain();
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        #[cfg(test)]
        spool.pause("linked");
        spool.failpoint("directory-fsync")?;
        fsync_directory(parent)?;
        if spool.catalog().is_some() {
            fsync_directory(&spool.temporary_dir())?;
        }
        let object = VerifiedObject::open(spool, expected, destination)?;
        temporary.remove_temporary()?;
        let mut class = temporary.reservation.class;
        let mut durable = false;
        let mut generation_references = 0;
        let mut reconstructible = false;
        if let (Some(catalog), Some(id)) = (spool.catalog(), &temporary.reservation.id) {
            spool.failpoint("sql-install")?;
            catalog.install(id.clone(), expected, class.sql())?;
            let row = catalog
                .object(expected)?
                .ok_or(crate::catalog::CatalogError::InvalidState)?;
            class = super::ReservationClass::from_sql(row.class)?;
            durable = row.durable;
            generation_references = row.generation_references;
            reconstructible = row.reconstructible;
        }
        drop(temporary.file.take());
        temporary.reservation.install(class)?;
        registry.policy.insert(expected);
        registry.entries.insert(
            expected,
            Entry {
                object: object.clone(),
                class,
                durable,
                reconstructible,
                generation_references,
                pins: [0; 3],
                evicting: false,
            },
        );
        temporary.published = None;
        Ok(object)
    })();
    if result.is_err() {
        if spool.catalog().is_some() && temporary.published.is_some() {
            temporary.preserve_orphan();
        }
        if let Err(error) = temporary.cleanup() {
            return Err(error.into());
        }
    }
    transaction.complete = true;
    result
}

struct InstallGuard<'a> {
    spool: &'a SpoolInner,
    complete: bool,
}
impl Drop for InstallGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.spool.close_admission();
        }
    }
}

fn create_dir_durably(directory: &Path) -> io::Result<()> {
    match fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(directory)?.is_dir() {
                return Err(io::Error::other("object parent is not a directory"));
            }
        }
        Err(error) => return Err(error),
    }
    fsync_directory(directory)?;
    if let Some(parent) = directory.parent() {
        fsync_directory(parent)?;
    }
    Ok(())
}
pub(super) fn fsync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}
