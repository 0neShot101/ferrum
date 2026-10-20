//! One immutable file store with two explicit startup contracts: private
//! fixture cleanup, or persistent SQLite-authoritative production recovery.
//! The disk owner serializes lease acquisition and Evicting transitions; the
//! private replacement policy can propose identities but cannot delete them.

mod accounting;
mod derived;
mod io;
mod lifetime;
mod object;
mod recovery;
mod startup;
mod writer;

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use rusqlite::OptionalExtension;
use tokio::sync::Semaphore;

pub use self::accounting::Accounting;
use self::accounting::Ledger;
pub use self::object::{ObjectStream, VerifiedObject};
pub use self::writer::SpoolWriter;
pub(crate) use self::writer::{SnapshotFile, SnapshotObject};
use crate::catalog::Catalog;
use crate::eviction::Policy;

pub const MAX_READ_CHUNK: usize = 262_144;
const GIB: u64 = 1024 * 1024 * 1024;
// Per admitted writer, including its bind/install/release transactions. Eight
// reference updates per transaction, 4 KiB pages and the 1 GiB catalog cap keep
// B-tree splits plus WAL/checkpoint growth inside this conservative allowance.
const SQL_OPERATION_RESERVE: u64 = 2 * 1024 * 1024;
const CATALOG_FIXED_MEMORY: u64 = 16 * 1024 * 1024;
const ENTRY_MEMORY_BOUND: u64 = 4096;

/// Private fixture limits; this shape remains shared by existing callers.
#[derive(Clone, Debug)]
pub struct SpoolConfig {
    pub root: PathBuf,
    pub managed_ceiling: u64,
    pub max_object_size: u64,
    pub io_workers: usize,
    pub read_chunk: usize,
}

/// Durable mode limits. All partitions are sublimits of `spool.managed_ceiling`.
#[derive(Clone, Debug)]
pub struct DurableSpoolConfig {
    pub spool: SpoolConfig,
    pub free_space_floor: u64,
    pub temporary_ceiling: u64,
    /// Temporary bytes unavailable to package admissions.
    pub metadata_temporary_reserve: u64,
    pub metadata_ceiling: u64,
    /// SQLite database, WAL and SHM combined; at most 8 GiB. Growth stops admission.
    pub catalog_ceiling: u64,
    pub catalog_memory_budget: u64,
    /// Resident entries plus concurrent reservations, including zero-byte ones.
    pub max_entries: usize,
    /// Pending requests per database worker, not an unbounded task queue.
    pub database_queue: usize,
    pub eviction_high_watermark: u64,
    pub eviction_low_watermark: u64,
}

impl DurableSpoolConfig {
    pub fn new(root: PathBuf) -> Self {
        Self {
            spool: SpoolConfig {
                root,
                managed_ceiling: 200 * GIB,
                max_object_size: 8 * GIB,
                io_workers: 8,
                read_chunk: MAX_READ_CHUNK,
            },
            free_space_floor: 15 * GIB,
            temporary_ceiling: 20 * GIB,
            metadata_temporary_reserve: 2 * GIB,
            metadata_ceiling: 25 * GIB,
            catalog_ceiling: 8 * GIB,
            catalog_memory_budget: 256 * 1024 * 1024,
            max_entries: 60_000,
            database_queue: 64,
            eviction_high_watermark: 180 * GIB,
            eviction_low_watermark: 160 * GIB,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationClass {
    Package,
    Metadata,
}

impl ReservationClass {
    fn metadata(self) -> bool {
        self == Self::Metadata
    }
    fn sql(self) -> i64 {
        i64::from(self.metadata())
    }
    fn from_sql(value: i64) -> Result<Self, SpoolError> {
        match value {
            0 => Ok(Self::Package),
            1 => Ok(Self::Metadata),
            _ => Err(crate::catalog::CatalogError::InvalidState.into()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("spool capacity exhausted: requested {requested} bytes, {available} available")]
    CapacityExhausted { requested: u64, available: u64 },
    #[error("object of {size} bytes exceeds the {max} byte maximum")]
    ObjectTooLarge { size: u64, max: u64 },
    #[error("write exceeds the expected object size of {expected} bytes")]
    Overflow { expected: u64 },
    #[error(
        "object mismatch: expected {expected:?}, got {actual_size} bytes with sha256 {actual_sha256}"
    )]
    Mismatch {
        expected: ObjectIdentity,
        actual_size: u64,
        actual_sha256: Sha256Digest,
    },
    #[error("spool admission closed after an accounting or cleanup failure")]
    AdmissionClosed,
    #[error("reservation does not match the expected object or spool")]
    ReservationMismatch,
    #[error("invalid byte range")]
    InvalidRange,
    #[error("object too large for a bounded read")]
    TooLarge,
    #[error("spool directory is not exclusively owned: {0}")]
    NotExclusive(String),
    #[error("refusing to use directory: {0}")]
    UnsafeDirectory(String),
    #[error("spool I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Catalog(#[from] crate::catalog::CatalogError),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CacheProtection {
    pub objects: u64,
    pub bytes: u64,
}
impl CacheProtection {
    fn include(&mut self, size: u64) {
        self.objects = self.objects.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
    }
}

/// Protected categories are disjoint, in metadata/pinned/staged/reader order.
#[derive(Clone, Copy, Debug, Default)]
pub struct CachePreview {
    pub eligible: CacheProtection,
    pub pinned: CacheProtection,
    pub metadata: CacheProtection,
    pub staged: CacheProtection,
    pub live_reader: CacheProtection,
    pub evicting: CacheProtection,
    pub sampled_at: i64,
}

/// Catalog connections close before the process lock is released. Every live
/// file/stream retains this owner even if the last Spool handle is dropped.
pub(crate) struct SpoolLifetime {
    catalog: Option<Catalog>,
    _lock: Option<fd_lock::RwLock<File>>,
    ledger: Mutex<Ledger>,
}

struct Entry {
    object: VerifiedObject,
    class: ReservationClass,
    durable: bool,
    reconstructible: bool,
    generation_references: u64,
    pins: [u32; 3],
    evicting: bool,
}

impl Entry {
    fn evictable(&self) -> bool {
        !self.evicting
            && self.object.exclusive_to_owner()
            && self.pins == [0; 3]
            && self.generation_references == 0
            && (self.class.metadata() || self.durable || self.reconstructible)
    }
}

struct Registry {
    entries: HashMap<ObjectIdentity, Entry>,
    policy: Policy,
}

pub(crate) struct SpoolInner {
    root: PathBuf,
    max_object_size: u64,
    read_chunk: usize,
    lifetime: Arc<SpoolLifetime>,
    installed: Mutex<Registry>,
    io_permits: Arc<Semaphore>,
    io: Arc<io::IoPool>,
    durable: Option<DurableSpoolConfig>,
    #[cfg(test)]
    hook: Arc<Mutex<Option<tests::Hook>>>,
    #[cfg(test)]
    failure: Mutex<Option<&'static str>>,
}

impl SpoolInner {
    fn temporary_dir(&self) -> PathBuf {
        self.root.join(startup::TEMPORARY_DIR)
    }
    fn object_path(&self, digest: &Sha256Digest) -> PathBuf {
        let hex = digest.to_hex();
        self.root
            .join(startup::OBJECTS_DIR)
            .join("sha256")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(&hex)
    }
    fn read_chunk(&self) -> usize {
        self.read_chunk
    }
    fn io_permits(&self) -> &Arc<Semaphore> {
        &self.io_permits
    }
    fn catalog(&self) -> Option<&Catalog> {
        self.lifetime.catalog.as_ref()
    }
    fn close_admission(&self) {
        lock_unpoisoned(&self.lifetime.ledger).close();
    }
    fn ensure_admission(&self) -> Result<(), SpoolError> {
        lock_unpoisoned(&self.lifetime.ledger).ensure_open()
    }
    #[cfg(test)]
    fn pause(&self, operation: &'static str) {
        tests::pause(&self.hook, operation);
    }
    fn failpoint(&self, _operation: &'static str) -> std::io::Result<()> {
        #[cfg(test)]
        {
            let mut failure = lock_unpoisoned(&self.failure);
            if *failure == Some(_operation) {
                *failure = None;
                return Err(std::io::Error::other("injected storage transition failure"));
            }
        }
        Ok(())
    }
    fn lookup(&self, identity: ObjectIdentity) -> Option<VerifiedObject> {
        let mut registry = lock_unpoisoned(&self.installed);
        let entry = registry.entries.get(&identity)?;
        if entry.evicting {
            return None;
        }
        let object = entry.object.clone();
        registry.policy.hit(&identity);
        Some(object)
    }
    fn metadata_bytes(&self) -> Result<u64, SpoolError> {
        if self.catalog().is_none() {
            return Ok(0);
        }
        recovery::catalog_bytes(&self.root)
    }
    fn check_catalog_operation(&self, additional: u64) -> Result<(), SpoolError> {
        let config = self.durable.as_ref().ok_or(SpoolError::AdmissionClosed)?;
        let ledger = lock_unpoisoned(&self.lifetime.ledger);
        ledger.ensure_open()?;
        let snapshot = ledger.snapshot();
        let headroom = (ledger.reservation_count() as u64)
            .checked_mul(SQL_OPERATION_RESERVE)
            .and_then(|bytes| bytes.checked_add(additional))
            .ok_or(SpoolError::AdmissionClosed)?;
        let metadata = self.metadata_bytes()?;
        let total = snapshot
            .installed
            .checked_add(snapshot.reserved)
            .and_then(|bytes| bytes.checked_add(metadata))
            .and_then(|bytes| bytes.checked_add(headroom))
            .ok_or(SpoolError::AdmissionClosed)?;
        if total > snapshot.ceiling || metadata.saturating_add(headroom) > config.catalog_ceiling {
            return Err(SpoolError::CapacityExhausted {
                requested: additional,
                available: snapshot
                    .ceiling
                    .saturating_sub(total.saturating_sub(additional))
                    .min(config.catalog_ceiling.saturating_sub(metadata)),
            });
        }
        accounting::check_physical(
            available_bytes(&self.root)?.saturating_sub(config.free_space_floor),
            snapshot.reserved,
            headroom,
        )
    }
}

pub(crate) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(Clone)]
pub struct Spool(Arc<SpoolInner>);

/// Aggregate logical charges. SQLite bytes are sampled from the actual files,
/// not estimated from database row count; uncommitted/uncertain charges remain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageUsage {
    pub objects: Accounting,
    pub metadata_installed_bytes: u64,
    pub metadata_reserved_bytes: u64,
    pub catalog_bytes: u64,
    pub catalog_reserved_bytes: u64,
    pub managed_bytes: u64,
    pub filesystem_available: u64,
    pub resident_entries: usize,
    pub reservations: usize,
    pub admission_open: bool,
}

impl Spool {
    /// Exclusive fixture-only cleanup. Persistent production directories are
    /// intentionally rejected rather than wiped.
    pub fn open_exclusive_fixture(config: SpoolConfig) -> Result<Self, SpoolError> {
        validate_spool_config(&config)?;
        let lock = startup::take_ownership(&config.root)?;
        Self::from_parts(config, lock, None, None)
    }

    /// Locks, opens SQLite, and completes reconciliation before admitting any
    /// write. Unknown files are reclaimed, never authenticated by their names.
    /// Incomplete cleanup, malformed state, or exceeded bounds fail startup.
    pub fn open_durable(mut config: DurableSpoolConfig) -> Result<Self, SpoolError> {
        validate_durable_config(&config)?;
        let (lock, fresh) = startup::take_durable_ownership(&config.spool.root)?;
        let stats = rustix::fs::statvfs(&config.spool.root).map_err(std::io::Error::from)?;
        let capacity = stats
            .f_blocks
            .checked_mul(stats.f_frsize)
            .ok_or_else(|| invalid_input("filesystem capacity overflow"))?;
        // Leave the RFC's 25 GiB physical headroom on the production defaults;
        // smaller explicitly bounded private qualifications retain their own floor.
        let physical_limit = capacity.saturating_sub(
            config
                .free_space_floor
                .saturating_add(config.spool.managed_ceiling / 20),
        );
        config.spool.managed_ceiling = config.spool.managed_ceiling.min(physical_limit);
        config.eviction_high_watermark = config
            .eviction_high_watermark
            .min(config.spool.managed_ceiling.saturating_mul(9) / 10);
        config.eviction_low_watermark = config
            .eviction_low_watermark
            .min(config.spool.managed_ceiling.saturating_mul(4) / 5);
        let catalog = Catalog::open(&config.spool.root, config.database_queue, fresh)?;
        writer::fsync_directory(&config.spool.root)?;
        let spool = Self::from_parts(config.spool.clone(), lock, Some(catalog), Some(config))?;
        recovery::reconcile(&spool.0)?;
        crate::capture::lifecycle::reconcile_startup(&spool)?;
        crate::gc::reconcile_collected(&spool)?;
        Ok(spool)
    }

    fn from_parts(
        config: SpoolConfig,
        lock: fd_lock::RwLock<File>,
        catalog: Option<Catalog>,
        durable: Option<DurableSpoolConfig>,
    ) -> Result<Self, SpoolError> {
        let io = Arc::new(io::IoPool::new(config.io_workers)?);
        Ok(Self(Arc::new(SpoolInner {
            root: config.root,
            max_object_size: config.max_object_size,
            read_chunk: config.read_chunk,
            lifetime: Arc::new(SpoolLifetime {
                catalog,
                _lock: Some(lock),
                ledger: Mutex::new(Ledger::new(config.managed_ceiling)),
            }),
            installed: Mutex::new(Registry {
                entries: HashMap::new(),
                policy: Policy::clock(),
            }),
            io_permits: Arc::new(Semaphore::new(config.io_workers)),
            io,
            durable,
            #[cfg(test)]
            hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            failure: Mutex::new(None),
        })))
    }

    pub fn accounting(&self) -> Accounting {
        lock_unpoisoned(&self.0.lifetime.ledger).snapshot()
    }

    pub fn usage(&self) -> Result<StorageUsage, SpoolError> {
        let registry = lock_unpoisoned(&self.0.installed);
        let ledger = lock_unpoisoned(&self.0.lifetime.ledger);
        let catalog_bytes = self.0.metadata_bytes()?;
        let objects = ledger.snapshot();
        let catalog_reserved_bytes = if self.0.catalog().is_some() {
            (ledger.reservation_count() as u64)
                .checked_mul(SQL_OPERATION_RESERVE)
                .ok_or(SpoolError::AdmissionClosed)?
        } else {
            0
        };
        let managed_bytes = objects
            .installed
            .checked_add(objects.reserved)
            .and_then(|bytes| bytes.checked_add(catalog_bytes))
            .and_then(|bytes| bytes.checked_add(catalog_reserved_bytes))
            .ok_or(SpoolError::AdmissionClosed)?;
        Ok(StorageUsage {
            objects,
            metadata_installed_bytes: ledger.metadata_installed(),
            metadata_reserved_bytes: ledger.metadata_reserved(),
            catalog_bytes,
            catalog_reserved_bytes,
            managed_bytes,
            filesystem_available: available_bytes(&self.0.root)?,
            resident_entries: registry.entries.len(),
            reservations: ledger.reservation_count(),
            admission_open: ledger.ensure_open().is_ok(),
        })
    }

    /// Reserves package bytes; never evicts unreceipted package data.
    pub fn reserve(&self, size: u64) -> Result<Reservation, SpoolError> {
        self.reserve_class(size, ReservationClass::Package)
    }

    /// Metadata admissions can use reserved staging headroom. Only the disk
    /// owner may reclaim eligible bytes, with bounded CLOCK scan work.
    pub fn reserve_class(
        &self,
        size: u64,
        class: ReservationClass,
    ) -> Result<Reservation, SpoolError> {
        if size > self.0.max_object_size {
            return Err(SpoolError::ObjectTooLarge {
                size,
                max: self.0.max_object_size,
            });
        }
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.ensure_admission()?;
        if let Some(config) = &self.0.durable {
            let snapshot = self.accounting();
            let metadata = self.0.metadata_bytes()?;
            let used = snapshot
                .installed
                .saturating_add(snapshot.reserved)
                .saturating_add(metadata);
            if used
                .saturating_add(size)
                .saturating_add(SQL_OPERATION_RESERVE)
                > config.eviction_high_watermark
            {
                let target = used
                    .saturating_add(size)
                    .saturating_add(SQL_OPERATION_RESERVE)
                    .saturating_sub(config.eviction_low_watermark);
                reclaim_locked(&self.0, &mut registry, target)?;
            } else if class.metadata() {
                let metadata_used = {
                    let ledger = lock_unpoisoned(&self.0.lifetime.ledger);
                    ledger
                        .metadata_installed()
                        .saturating_add(ledger.metadata_reserved())
                };
                if metadata_used.saturating_add(size) > config.metadata_ceiling {
                    let target = metadata_used
                        .saturating_add(size)
                        .saturating_sub(config.metadata_ceiling);
                    reclaim_locked(&self.0, &mut registry, target)?;
                }
            }
        }
        let mut ledger = lock_unpoisoned(&self.0.lifetime.ledger);
        ledger.ensure_open()?;
        let snapshot = ledger.snapshot();
        let metadata = self.0.metadata_bytes()?;
        let mut available = snapshot
            .ceiling
            .saturating_sub(snapshot.reserved)
            .saturating_sub(snapshot.installed)
            .saturating_sub(metadata);
        let mut physical = available_bytes(&self.0.root)?;
        if let Some(config) = &self.0.durable {
            let sql_headroom = (ledger.reservation_count() as u64)
                .checked_add(1)
                .and_then(|count| count.checked_mul(SQL_OPERATION_RESERVE))
                .ok_or(SpoolError::AdmissionClosed)?;
            let required = snapshot
                .installed
                .checked_add(snapshot.reserved)
                .and_then(|bytes| bytes.checked_add(metadata))
                .and_then(|bytes| bytes.checked_add(sql_headroom))
                .and_then(|bytes| bytes.checked_add(size))
                .ok_or(SpoolError::AdmissionClosed)?;
            if required > snapshot.ceiling {
                return Err(SpoolError::CapacityExhausted {
                    requested: size.saturating_add(sql_headroom),
                    available,
                });
            }
            available -= sql_headroom;
            let entries = registry
                .entries
                .len()
                .checked_add(ledger.reservation_count())
                .ok_or(SpoolError::AdmissionClosed)?;
            if entries >= config.max_entries {
                return Err(SpoolError::CapacityExhausted {
                    requested: 1,
                    available: 0,
                });
            }
            available = available.min(config.temporary_ceiling.saturating_sub(snapshot.reserved));
            if !class.metadata() {
                available = available.min(
                    config
                        .temporary_ceiling
                        .saturating_sub(config.metadata_temporary_reserve)
                        .saturating_sub(
                            snapshot.reserved.saturating_sub(ledger.metadata_reserved()),
                        ),
                );
            } else {
                available = available.min(
                    config
                        .metadata_ceiling
                        .saturating_sub(ledger.metadata_installed())
                        .saturating_sub(ledger.metadata_reserved()),
                );
            }
            if metadata.saturating_add(sql_headroom) > config.catalog_ceiling {
                return Err(SpoolError::CapacityExhausted {
                    requested: sql_headroom,
                    available: config.catalog_ceiling.saturating_sub(metadata),
                });
            }
            physical = physical
                .checked_sub(config.free_space_floor)
                .and_then(|bytes| bytes.checked_sub(sql_headroom))
                .ok_or(SpoolError::CapacityExhausted {
                    requested: size.saturating_add(sql_headroom),
                    available: physical.saturating_sub(config.free_space_floor),
                })?;
        }
        if size > available {
            return Err(SpoolError::CapacityExhausted {
                requested: size,
                available,
            });
        }
        accounting::check_physical(physical, snapshot.reserved, size)?;
        let id = self
            .0
            .catalog()
            .map(|_| format!("{:032x}", rand::random::<u128>()));
        ledger.reserve_class(size, class.metadata())?;
        // No reservation escapes before SQL commit. An ambiguous SQL failure
        // keeps its conservative charge and closes admission until recovery.
        if let (Some(catalog), Some(id)) = (self.0.catalog(), &id)
            && let Err(error) = catalog.reserve(id.clone(), size, class.sql())
        {
            ledger.close();
            return Err(error.into());
        }
        Ok(Reservation {
            spool: Arc::clone(&self.0),
            size,
            class,
            id,
            held: true,
        })
    }

    pub fn lookup(&self, identity: ObjectIdentity) -> Option<VerifiedObject> {
        self.0.lookup(identity)
    }

    pub async fn begin_write(
        &self,
        reservation: Reservation,
        expected: ObjectIdentity,
    ) -> Result<SpoolWriter, SpoolError> {
        if reservation.size != expected.size || !Arc::ptr_eq(&reservation.spool, &self.0) {
            return Err(SpoolError::ReservationMismatch);
        }
        SpoolWriter::create(Arc::clone(&self.0), reservation, expected).await
    }

    pub fn root(&self) -> &Path {
        &self.0.root
    }

    pub fn durable_limits(&self) -> Option<DurableSpoolConfig> {
        self.0.durable.clone()
    }

    pub fn preview_evictable_cache(&self) -> Result<CachePreview, SpoolError> {
        let registry = lock_unpoisoned(&self.0.installed);
        let mut preview = CachePreview {
            sampled_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|v| i64::try_from(v.as_secs()).ok())
                .ok_or_else(|| invalid_input("clock before epoch"))?,
            ..CachePreview::default()
        };
        for (identity, entry) in &registry.entries {
            let category = if entry.class.metadata() {
                &mut preview.metadata
            } else if entry.evicting {
                &mut preview.evicting
            } else if entry.pins != [0; 3] || entry.generation_references != 0 {
                &mut preview.pinned
            } else if self.0.catalog().is_some() && !entry.durable && !entry.reconstructible {
                &mut preview.staged
            } else if !entry.object.exclusive_to_owner() {
                &mut preview.live_reader
            } else {
                &mut preview.eligible
            };
            category.include(identity.size);
        }
        Ok(preview)
    }

    pub(crate) fn durable_catalog(&self) -> Result<&Catalog, SpoolError> {
        self.0.catalog().ok_or(SpoolError::AdmissionClosed)
    }

    pub(crate) fn catalog_write<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T, crate::catalog::CatalogError>
        + Send
        + 'static,
    ) -> Result<T, SpoolError> {
        self.catalog_write_reserved(SQL_OPERATION_RESERVE, operation)
    }

    pub(crate) fn catalog_write_reserved<T: Send + 'static>(
        &self,
        bytes: u64,
        operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T, crate::catalog::CatalogError>
        + Send
        + 'static,
    ) -> Result<T, SpoolError> {
        let _owner = lock_unpoisoned(&self.0.installed);
        self.0.check_catalog_operation(bytes)?;
        Ok(self.durable_catalog()?.write(operation)?)
    }
    pub(crate) fn catalog_admission(&self, bytes: u64) -> Result<impl Drop + '_, SpoolError> {
        let owner = lock_unpoisoned(&self.0.installed);
        self.0.check_catalog_operation(bytes)?;
        Ok(owner)
    }
    pub(crate) fn close_capture_admission(&self) {
        self.0.close_admission();
    }

    pub(crate) async fn catalog_work_async<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T, crate::catalog::CatalogError>
        + Send
        + 'static,
    ) -> Result<T, SpoolError> {
        let owner = self.clone();
        let job = tokio::spawn(async move {
            Ok::<T, SpoolError>(owner.durable_catalog()?.work_async(operation).await?)
        });
        job.await
            .map_err(|error| SpoolError::Io(std::io::Error::other(error.to_string())))?
    }

    pub(crate) fn discard_unreferenced_metadata(
        &self,
        identity: ObjectIdentity,
    ) -> Result<bool, SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.ensure_admission()?;
        if registry
            .entries
            .get(&identity)
            .is_none_or(|entry| !entry.class.metadata())
        {
            return Ok(false);
        }
        evict_identity_locked(&self.0, &mut registry, identity, false)
    }

    /// Evicts all unpinned, unreferenced cached package objects from the local
    /// spool. Active generations, pinned fills/uploads, metadata, and objects
    /// with live readers are never removed. Returns `(evicted_objects, freed_bytes)`.
    pub fn clear_evictable_cache(&self) -> Result<(u64, u64), SpoolError> {
        let has_catalog = self.0.catalog().is_some();
        // Freeze the starting set once: newly arriving cache entries are not
        // chased indefinitely. Only identities are retained, never object leases.
        let candidates: Vec<ObjectIdentity> = {
            let registry = lock_unpoisoned(&self.0.installed);
            self.0.ensure_admission()?;
            registry
                .entries
                .iter()
                .filter(|(_, entry)| {
                    !entry.class.metadata()
                        && if has_catalog {
                            entry.evictable()
                        } else {
                            !entry.evicting
                                && entry.object.exclusive_to_owner()
                                && entry.pins == [0; 3]
                                && entry.generation_references == 0
                        }
                })
                .map(|(identity, _)| *identity)
                .collect()
        };
        let mut evicted = 0u64;
        let mut freed = 0u64;
        for batch in candidates.chunks(32) {
            let mut registry = lock_unpoisoned(&self.0.installed);
            self.0.ensure_admission()?;
            for &identity in batch {
                if has_catalog {
                    if evict_identity_locked(&self.0, &mut registry, identity, false)? {
                        evicted += 1;
                        freed = freed.saturating_add(identity.size);
                    }
                } else {
                    let eligible = registry.entries.get(&identity).is_some_and(|entry| {
                        !entry.evicting
                            && entry.object.exclusive_to_owner()
                            && entry.pins == [0; 3]
                            && entry.generation_references == 0
                            && !entry.class.metadata()
                    });
                    if !eligible {
                        continue;
                    }
                    if let Some(entry) = registry.entries.get(&identity) {
                        let path = entry.object.path();
                        fs::remove_file(path)?;
                        writer::fsync_directory(
                            path.parent()
                                .ok_or_else(|| invalid_input("object has no parent"))?,
                        )?;
                    }
                    let Some(entry) = registry.entries.remove(&identity) else {
                        continue;
                    };
                    let metadata = entry.class.metadata();
                    drop(entry);
                    lock_unpoisoned(&self.0.lifetime.ledger)
                        .remove_installed(identity.size, metadata)?;
                    registry.policy.remove(&identity);
                    evicted += 1;
                    freed = freed.saturating_add(identity.size);
                }
            }
        }
        Ok((evicted, freed))
    }

    /// One bounded local maintenance batch, reporting actual removals. A
    /// shortfall is not an error: protected objects stay resident. Durable
    /// mode uses the existing CLOCK eligibility and catalog eviction path.
    pub fn evict_cache_batch(
        &self,
        max_objects: usize,
        remaining_target_bytes: Option<u64>,
    ) -> Result<(u64, u64, bool), SpoolError> {
        let maximum = max_objects.min(32);
        let target = remaining_target_bytes.unwrap_or(u64::MAX);
        if target == 0 || maximum == 0 {
            return Ok((0, 0, false));
        }
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.ensure_admission()?;
        let mut evicted = 0u64;
        let mut freed = 0u64;
        if self.0.catalog().is_some() {
            let eligible = registry
                .entries
                .values()
                .filter(|entry| entry.evictable())
                .fold(0u64, |bytes, entry| {
                    bytes.saturating_add(entry.object.size())
                });
            let mut scan = registry.policy.begin_scan(target, eligible);
            while evicted < maximum as u64 && freed < target {
                let Some(identity) = registry.policy.next_candidate(&mut scan) else {
                    return Ok((evicted, freed, false));
                };
                if evict_identity_locked(&self.0, &mut registry, identity, false)? {
                    evicted += 1;
                    freed = freed.saturating_add(identity.size);
                } else {
                    registry.policy.skipped(&identity);
                }
            }
        } else {
            // Fixture files have no durable receipt. Their existing clear-cache
            // contract still requires exclusive readers and no metadata/pins.
            let candidates: Vec<_> = registry
                .entries
                .iter()
                .filter(|(_, entry)| {
                    !entry.evicting
                        && entry.object.exclusive_to_owner()
                        && entry.pins == [0; 3]
                        && entry.generation_references == 0
                        && !entry.class.metadata()
                })
                .take(maximum)
                .map(|(identity, _)| *identity)
                .collect();
            for identity in candidates {
                if freed >= target {
                    break;
                }
                if let Some(entry) = registry.entries.get(&identity) {
                    let path = entry.object.path();
                    fs::remove_file(path)?;
                    writer::fsync_directory(
                        path.parent()
                            .ok_or_else(|| invalid_input("object has no parent"))?,
                    )?;
                }
                if let Some(entry) = registry.entries.remove(&identity) {
                    drop(entry);
                    lock_unpoisoned(&self.0.lifetime.ledger)
                        .remove_installed(identity.size, false)?;
                    registry.policy.remove(&identity);
                    evicted += 1;
                    freed = freed.saturating_add(identity.size);
                }
            }
        }
        Ok((evicted, freed, evicted == maximum as u64 && freed < target))
    }

    pub(crate) fn discard_collected_package(
        &self,
        identity: ObjectIdentity,
    ) -> Result<(), SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        let authorized = self.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_blobs b WHERE b.digest=?1 AND b.size=?2 AND b.gc_pending=1 AND NOT EXISTS(SELECT 1 FROM capture_paths WHERE digest=b.digest) AND NOT EXISTS(SELECT 1 FROM capture_generation_refs WHERE digest=b.digest) AND NOT EXISTS(SELECT 1 FROM capture_outbox WHERE digest=b.digest) AND NOT EXISTS(SELECT 1 FROM capture_admissions WHERE digest=b.digest))",
                rusqlite::params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if !authorized {
            return Err(crate::catalog::CatalogError::InvalidState.into());
        }
        if !registry.entries.contains_key(&identity) {
            return Ok(());
        }
        if !evict_identity_locked(&self.0, &mut registry, identity, true)? {
            self.0.close_admission();
            return Err(SpoolError::AdmissionClosed);
        }
        Ok(())
    }

    pub(crate) fn capture_write<T: Send + 'static>(
        &self,
        identity: ObjectIdentity,
        operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T, crate::catalog::CatalogError>
        + Send
        + 'static,
    ) -> Result<T, SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.check_catalog_operation(8 * 1024 * 1024)?;
        if let Some(entry) = registry.entries.get_mut(&identity) {
            entry.reconstructible = false;
        }
        let result = self.durable_catalog()?.write(operation)?;
        if let Some(entry) = registry.entries.get_mut(&identity) {
            let refresh = (|| {
                let row = self
                    .durable_catalog()?
                    .object(identity)?
                    .ok_or(crate::catalog::CatalogError::InvalidState)?;
                let class = ReservationClass::from_sql(row.class)?;
                if entry.class.metadata() && !class.metadata() {
                    lock_unpoisoned(&self.0.lifetime.ledger)
                        .require_package_retention(identity.size)?;
                }
                entry.class = class;
                entry.durable = row.durable;
                entry.reconstructible = row.reconstructible;
                Ok::<_, SpoolError>(())
            })();
            if let Err(error) = refresh {
                entry.durable = false;
                self.0.close_admission();
                return Err(error);
            }
        }
        Ok(result)
    }
    pub(crate) fn quarantine_remote_key(&self, key: &str) -> Result<(), SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        let result = (|| {
            self.0.check_catalog_operation(SQL_OPERATION_RESERVE)?;
            let key = key.to_owned();
            let digest = key
                .rsplit_once("/v1/objects/sha256/")
                .and_then(|(_, digest)| Sha256Digest::from_hex(digest).ok());
            // Receipt authority belongs to exactly this repository/path/digest,
            // not to every origin which happens to advertise the same blob.
            let receipt = key.rsplit_once("/v1/captures/").and_then(|(_, suffix)| {
                let mut parts = suffix.split('/');
                let repository = parts.next()?;
                let path_hash = parts.next()?;
                let digest = parts.next()?.strip_suffix(".json")?;
                if parts.next().is_some()
                    || repository.is_empty()
                    || !repository
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    return None;
                }
                Some((
                    repository.to_owned(),
                    Sha256Digest::from_hex(path_hash).ok()?.to_hex(),
                    Sha256Digest::from_hex(digest).ok()?,
                ))
            });
            self.durable_catalog()?
                .write(move |connection| {
                    let transaction = connection.transaction()?;
                    transaction.execute(
                        "INSERT OR IGNORE INTO remote_quarantine(key) VALUES(?1)",
                        [key],
                    )?;
                    let affected = if let Some(digest) = digest {
                        transaction.execute(
                            "UPDATE capture_blobs SET readback_verified=0 WHERE digest=?1",
                            [digest.to_hex()],
                        )?;
                        Some(digest)
                    } else if let Some((repository, path_hash, digest)) = receipt {
                        let changed = transaction.execute(
                            "UPDATE capture_paths SET receipt_verified=0 WHERE repository=?1 AND path_hash=?2 AND digest=?3",
                            rusqlite::params![repository, path_hash, digest.to_hex()],
                        )?;
                        (changed > 0).then_some(digest)
                    } else {
                        None
                    };
                    let identity = if let Some(digest) = affected {
                        transaction.execute(
                            "UPDATE objects SET upload_state=0 WHERE digest=?1",
                            [digest.to_hex()],
                        )?;
                        let size = transaction
                            .query_row(
                                "SELECT size FROM capture_blobs WHERE digest=?1",
                                [digest.to_hex()],
                                |row| crate::catalog::read_unsigned(row, 0),
                            )
                            .optional()?;
                        size.map(|size| ObjectIdentity {
                            sha256: digest,
                            size,
                        })
                    } else {
                        None
                    };
                    transaction.commit()?;
                    Ok(identity)
                })
                .map_err(SpoolError::from)
        })();
        match result {
            Ok(Some(identity)) => {
                if let Some(entry) = registry.entries.get_mut(&identity) {
                    entry.durable = false;
                }
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) => {
                for entry in registry.entries.values_mut() {
                    entry.durable = false;
                }
                self.0.close_admission();
                Err(error)
            }
        }
    }
    pub(crate) fn reset_capture_verification(&self) -> Result<(), SpoolError> {
        loop {
            let mut registry = lock_unpoisoned(&self.0.installed);
            self.0.check_catalog_operation(8 * 1024 * 1024)?;
            let result = self.durable_catalog()?.write(|connection| {
                let transaction = connection.transaction()?;
                let identities = {
                    let mut statement = transaction.prepare("SELECT b.digest,b.size FROM capture_blobs b LEFT JOIN objects o ON o.digest=b.digest WHERE b.readback_verified=1 OR o.upload_state=1 LIMIT 128")?;
                    let rows = statement.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            crate::catalog::read_unsigned(row, 1)?,
                        ))
                    })?;
                    rows.collect::<Result<Vec<_>, _>>()?
                };
                let mut values = Vec::with_capacity(identities.len());
                for (digest, size) in identities {
                    transaction.execute(
                        "UPDATE capture_blobs SET readback_verified=0 WHERE digest=?1",
                        [&digest],
                    )?;
                    transaction.execute(
                        "UPDATE objects SET upload_state=0 WHERE digest=?1",
                        [&digest],
                    )?;
                    values.push(ObjectIdentity {
                        sha256: Sha256Digest::from_hex(&digest).map_err(|_| crate::catalog::CatalogError::InvalidState)?,
                        size,
                    });
                }
                transaction.commit()?;
                Ok(values)
            });
            let values = match result {
                Ok(values) => values,
                Err(error) => {
                    for entry in registry.entries.values_mut() {
                        entry.durable = false;
                    }
                    self.0.close_admission();
                    return Err(error.into());
                }
            };
            if values.is_empty() {
                return Ok(());
            }
            for identity in values {
                if let Some(entry) = registry.entries.get_mut(&identity) {
                    entry.durable = false;
                }
            }
        }
    }
    pub(crate) fn discard_unused_capture_proof(&self, generation: &str) -> Result<(), SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.check_catalog_operation(8 * 1024 * 1024)?;
        let bound = generation.to_owned();
        let unused = self.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_proofs WHERE generation=?1 AND durable=0 AND NOT EXISTS(SELECT 1 FROM capture_paths WHERE generation=?1))",
                [bound],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if !unused {
            return Ok(());
        }
        let pin = crate::capture::lifecycle::proof_pin(generation);
        loop {
            self.0.check_catalog_operation(SQL_OPERATION_RESERVE)?;
            let identities = match self.durable_catalog()?.release_generation_batch(pin) {
                Ok(values) => values,
                Err(error) => {
                    self.0.close_admission();
                    return Err(error.into());
                }
            };
            if identities.is_empty() {
                break;
            }
            for identity in identities {
                if let Some(entry) = registry.entries.get_mut(&identity) {
                    let Some(references) = entry.generation_references.checked_sub(1) else {
                        self.0.close_admission();
                        return Err(SpoolError::AdmissionClosed);
                    };
                    entry.generation_references = references;
                }
            }
        }
        let generation = generation.to_owned();
        self.durable_catalog()?.write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "DELETE FROM capture_artifacts WHERE generation=?1 AND EXISTS(SELECT 1 FROM capture_proofs WHERE generation=?1 AND durable=0 AND was_public=0)",
                [&generation],
            )?;
            transaction.execute(
                "DELETE FROM capture_proofs WHERE generation=?1 AND durable=0 AND was_public=0",
                [generation],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }

    pub(crate) fn promote_capture(&self, identity: ObjectIdentity) -> Result<bool, SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.check_catalog_operation(SQL_OPERATION_RESERVE)?;
        let promoted = self.durable_catalog()?.write(move |connection| {
            let transaction = connection.transaction()?;
            let pending: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_paths WHERE digest=?1 AND receipt_verified=0)",
                [identity.sha256.to_hex()],
                |row| row.get(0),
            )?;
            let verified: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_blobs WHERE digest=?1 AND readback_verified=1)",
                [identity.sha256.to_hex()],
                |row| row.get(0),
            )?;
            if pending {
                return Ok(false);
            }
            if !verified {
                return Err(crate::catalog::CatalogError::InvalidState);
            }
            transaction.execute(
                "UPDATE objects SET upload_state=1 WHERE digest=?1 AND size=?2",
                rusqlite::params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
            )?;
            transaction.execute(
                "DELETE FROM capture_outbox WHERE digest=?1",
                [identity.sha256.to_hex()],
            )?;
            transaction.commit()?;
            Ok(true)
        })?;
        if !promoted {
            return Ok(false);
        }
        if let Some(entry) = registry.entries.get_mut(&identity) {
            if entry.evicting {
                self.0.close_admission();
                return Err(SpoolError::AdmissionClosed);
            }
            entry.durable = true;
        }
        Ok(true)
    }
    /// Reclaims at most one bounded policy scan. A shortfall is explicit;
    /// candidates rejected for pins or durability remain resident/accounted.
    pub fn reclaim(&self, bytes: u64) -> Result<u64, SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.ensure_admission()?;
        reclaim_locked(&self.0, &mut registry, bytes)
    }

    pub(crate) fn check_publication_capacity(
        &self,
        manifest: &crate::recovery::GenerationManifest,
    ) -> Result<(), SpoolError> {
        let _owner = lock_unpoisoned(&self.0.installed);
        let headroom = self.durable_catalog()?.publication_headroom(manifest)?;
        self.0.check_catalog_operation(headroom)
    }

    pub(crate) fn activate_publication(
        &self,
        activation: crate::catalog::publication::Activation,
    ) -> Result<(), SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.ensure_admission()?;
        let headroom = self
            .durable_catalog()?
            .publication_headroom(&activation.manifest)?;
        self.0.check_catalog_operation(headroom)?;
        for artifact in &activation.manifest.artifacts {
            let identity = artifact
                .identity()
                .map_err(|_| crate::catalog::CatalogError::InvalidState)?;
            if registry
                .entries
                .get(&identity)
                .is_none_or(|entry| entry.evicting)
            {
                return Err(SpoolError::ReservationMismatch);
            }
        }
        // The writer returns absolute counts from the committed transaction, so
        // no fallible SQL/readback remains between commit and owner visibility.
        let counts = self.durable_catalog()?.publication_activate(activation)?;
        for (identity, references) in counts {
            if let Some(entry) = registry.entries.get_mut(&identity) {
                entry.generation_references = references;
            }
        }
        Ok(())
    }

    /// Flushes committed WAL pages without changing any authority or counters.
    /// Call after stopping publishers and draining owned background workers.
    pub fn checkpoint(&self) -> Result<(), SpoolError> {
        self.durable_catalog()?.write(|connection| {
            let (busy, frames, checkpointed) =
                connection.query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?;
            if busy != 0 || frames != checkpointed {
                return Err(crate::catalog::CatalogError::Busy);
            }
            Ok(())
        })?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn replay_select_policy(
        &self,
        kind: crate::eviction::PolicyKind,
    ) -> Result<(), SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        if !registry.entries.is_empty() {
            return Err(SpoolError::ReservationMismatch);
        }
        registry.policy = crate::eviction::Policy::new(kind);
        Ok(())
    }
    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn replay_policy_stats(&self) -> crate::eviction::PolicyStats {
        lock_unpoisoned(&self.0.installed).policy.stats()
    }
    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn replay_set_eligible(
        &self,
        identity: ObjectIdentity,
        eligible: bool,
    ) -> Result<(), SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        let Some(entry) = registry.entries.get_mut(&identity) else {
            return Ok(());
        };
        if entry.evicting {
            return Err(SpoolError::ReservationMismatch);
        }
        entry.durable = eligible;
        Ok(())
    }
    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn replay_lease(&self, identity: ObjectIdentity) -> Option<VerifiedObject> {
        lock_unpoisoned(&self.0.installed)
            .entries
            .get(&identity)
            .filter(|entry| !entry.evicting)
            .map(|entry| entry.object.clone())
    }

    /// Persist up to eight authenticated closure objects per short transaction.
    /// Call repeatedly before publishing a generation; duplicate references are
    /// idempotent. Unlike transient `pin`, these pins survive process restart.
    pub(crate) fn retain_generation(
        &self,
        generation: Sha256Digest,
        objects: &[ObjectIdentity],
    ) -> Result<(), SpoolError> {
        if objects.is_empty() || objects.len() > 8 {
            return Err(invalid_input(
                "generation pin batch must contain 1..=8 objects",
            ));
        }
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.ensure_admission()?;
        let catalog = self
            .0
            .catalog()
            .ok_or_else(|| invalid_input("persistent references require durable mode"))?;
        for identity in objects {
            if registry
                .entries
                .get(identity)
                .is_none_or(|entry| entry.evicting)
            {
                return Err(SpoolError::ReservationMismatch);
            }
        }
        self.0.check_catalog_operation(SQL_OPERATION_RESERVE)?;
        let result = (|| {
            catalog.retain_generation(generation, objects.to_vec())?;
            for identity in objects {
                let row = catalog
                    .object(*identity)?
                    .ok_or(crate::catalog::CatalogError::InvalidState)?;
                registry
                    .entries
                    .get_mut(identity)
                    .ok_or(SpoolError::AdmissionClosed)?
                    .generation_references = row.generation_references;
            }
            Ok::<_, SpoolError>(())
        })();
        if result.is_err() {
            self.0.close_admission();
        }
        result
    }

    /// Releases only this generation's durable references in bounded batches.
    /// The publication owner is responsible for the RFC retention deadline.
    pub(crate) fn release_generation(&self, generation: Sha256Digest) -> Result<(), SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        self.0.ensure_admission()?;
        let catalog = self
            .0
            .catalog()
            .ok_or_else(|| invalid_input("persistent references require durable mode"))?;
        loop {
            // Refusal before SQL is a known no-op, including between already
            // committed retirement batches. It must not poison admission.
            self.0.check_catalog_operation(SQL_OPERATION_RESERVE)?;
            let objects = match catalog.release_generation_batch(generation) {
                Ok(objects) => objects,
                Err(error) => {
                    self.0.close_admission();
                    return Err(error.into());
                }
            };
            if objects.is_empty() {
                return Ok(());
            }
            for identity in objects {
                if let Some(entry) = registry.entries.get_mut(&identity) {
                    let Some(references) = entry.generation_references.checked_sub(1) else {
                        self.0.close_admission();
                        return Err(SpoolError::AdmissionClosed);
                    };
                    entry.generation_references = references;
                }
            }
        }
    }

    /// Acquires an owner-synchronized non-reader pin. The returned guard keeps
    /// the process lock alive and releases only its own pin on drop.
    pub fn pin(
        &self,
        identity: ObjectIdentity,
        kind: PinKind,
    ) -> Result<Option<ObjectPin>, SpoolError> {
        let mut registry = lock_unpoisoned(&self.0.installed);
        let Some(entry) = registry.entries.get_mut(&identity) else {
            return Ok(None);
        };
        if entry.evicting {
            return Ok(None);
        }
        let count = &mut entry.pins[kind.index()];
        *count = count.checked_add(1).ok_or(SpoolError::AdmissionClosed)?;
        Ok(Some(ObjectPin {
            spool: self.clone(),
            identity,
            kind,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PinKind {
    Fill,
    Upload,
    Generation,
}
impl PinKind {
    fn index(self) -> usize {
        match self {
            Self::Fill => 0,
            Self::Upload => 1,
            Self::Generation => 2,
        }
    }
}

pub struct ObjectPin {
    spool: Spool,
    identity: ObjectIdentity,
    kind: PinKind,
}
impl Drop for ObjectPin {
    fn drop(&mut self) {
        let mut registry = lock_unpoisoned(&self.spool.0.installed);
        if let Some(entry) = registry.entries.get_mut(&self.identity) {
            let count = &mut entry.pins[self.kind.index()];
            if let Some(next) = count.checked_sub(1) {
                *count = next;
            } else {
                self.spool.0.close_admission();
            }
        } else {
            self.spool.0.close_admission();
        }
    }
}

fn reclaim_locked(
    spool: &SpoolInner,
    registry: &mut Registry,
    requested: u64,
) -> Result<u64, SpoolError> {
    let Some(_) = spool.catalog() else {
        return Ok(0);
    };
    let eligible = registry
        .entries
        .values()
        .filter(|entry| entry.evictable())
        .fold(0u64, |total, entry| {
            total.saturating_add(entry.object.size())
        });
    let mut scan = registry.policy.begin_scan(requested, eligible);
    let mut reclaimed = 0u64;
    while reclaimed < requested {
        let Some(identity) = registry.policy.next_candidate(&mut scan) else {
            break;
        };
        if !evict_identity_locked(spool, registry, identity, false)? {
            registry.policy.skipped(&identity);
            continue;
        }
        reclaimed = reclaimed
            .checked_add(identity.size)
            .ok_or(SpoolError::AdmissionClosed)?;
    }
    Ok(reclaimed)
}

fn evict_identity_locked(
    spool: &SpoolInner,
    registry: &mut Registry,
    identity: ObjectIdentity,
    retention_released: bool,
) -> Result<bool, SpoolError> {
    let Some(entry) = registry.entries.get_mut(&identity) else {
        return Ok(false);
    };
    let eligible = if retention_released {
        !entry.evicting
            && entry.object.exclusive_to_owner()
            && entry.pins == [0; 3]
            && entry.generation_references == 0
    } else {
        entry.evictable()
    };
    if !eligible {
        return Ok(false);
    }
    let catalog = spool.catalog().ok_or(SpoolError::AdmissionClosed)?;
    spool.check_catalog_operation(256 * 1024)?;
    entry.evicting = true;
    #[cfg(test)]
    spool.pause("evicting");
    if let Err(error) = catalog.set_residency(identity, 2) {
        entry.evicting = false;
        spool.close_admission();
        return Err(error.into());
    }
    let path = entry.object.path();
    let removed = (|| {
        spool.failpoint("unlink")?;
        fs::remove_file(path)?;
        writer::fsync_directory(
            path.parent()
                .ok_or_else(|| invalid_input("object has no parent"))?,
        )?;
        spool.failpoint("eviction-sql")?;
        catalog.set_residency(identity, 0)?;
        Ok::<_, SpoolError>(())
    })();
    if let Err(error) = removed {
        spool.close_admission();
        return Err(error);
    }
    let entry = registry
        .entries
        .remove(&identity)
        .ok_or(SpoolError::AdmissionClosed)?;
    let metadata = entry.class.metadata();
    drop(entry);
    lock_unpoisoned(&spool.lifetime.ledger).remove_installed(identity.size, metadata)?;
    registry.policy.remove(&identity);
    Ok(true)
}

pub struct Reservation {
    spool: Arc<SpoolInner>,
    size: u64,
    class: ReservationClass,
    id: Option<String>,
    held: bool,
}

impl Reservation {
    pub fn size(&self) -> u64 {
        self.size
    }
    fn install(&mut self, installed_class: ReservationClass) -> Result<(), SpoolError> {
        lock_unpoisoned(&self.spool.lifetime.ledger).install_as(
            self.size,
            self.class.metadata(),
            installed_class.metadata(),
        )?;
        self.held = false;
        Ok(())
    }
    fn retain(&mut self) {
        self.spool.close_admission();
        self.held = false;
    }
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Reservation")
            .field("size", &self.size)
            .field("class", &self.class)
            .finish()
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.held {
            return;
        }
        if let (Some(catalog), Some(id)) = (self.spool.catalog(), &self.id)
            && let Err(error) = catalog.release(id.clone())
        {
            self.spool.close_admission();
            tracing::error!(%error, "reservation release uncertain; charge retained");
            return;
        }
        lock_unpoisoned(&self.spool.lifetime.ledger)
            .release_class(self.size, self.class.metadata());
    }
}

fn available_bytes(root: &Path) -> Result<u64, SpoolError> {
    let stats = rustix::fs::statvfs(root).map_err(std::io::Error::from)?;
    stats
        .f_bavail
        .checked_mul(stats.f_frsize)
        .ok_or_else(|| invalid_input("filesystem available-byte count overflow"))
}
fn validate_spool_config(config: &SpoolConfig) -> Result<(), SpoolError> {
    if config.io_workers == 0 || config.io_workers > 32 {
        return Err(invalid_input("io_workers must be within 1..=32"));
    }
    if config.read_chunk == 0 || config.read_chunk > MAX_READ_CHUNK {
        return Err(invalid_input("read_chunk must be within 1..=262144"));
    }
    Ok(())
}
fn validate_durable_config(config: &DurableSpoolConfig) -> Result<(), SpoolError> {
    validate_spool_config(&config.spool)?;
    let queue_memory = (config.database_queue as u64).checked_mul(5 * (128 * 64 + 1024));
    let memory = u64::try_from(config.max_entries)
        .ok()
        .and_then(|entries| entries.checked_mul(ENTRY_MEMORY_BOUND))
        .and_then(|bytes| bytes.checked_add(CATALOG_FIXED_MEMORY))
        .and_then(|bytes| queue_memory.and_then(|queue| bytes.checked_add(queue)));
    if config.max_entries == 0
        || memory.is_none_or(|bytes| bytes > config.catalog_memory_budget)
        || config.database_queue == 0
        || config.database_queue > 1024
        || config.spool.root.as_os_str().is_empty()
        || config.spool.root.as_os_str().len() > 1024
        || config.metadata_temporary_reserve > config.temporary_ceiling
        || config.temporary_ceiling > config.spool.managed_ceiling
        || config.metadata_ceiling > config.spool.managed_ceiling
        || config.catalog_ceiling < SQL_OPERATION_RESERVE
        || config.catalog_ceiling > config.spool.managed_ceiling
        || config.catalog_ceiling > 8 * GIB
        || config.eviction_low_watermark > config.eviction_high_watermark
        || config.eviction_high_watermark > config.spool.managed_ceiling
        || config.spool.max_object_size > i64::MAX as u64
    {
        return Err(invalid_input(
            "invalid durable spool accounting, queue, or memory limits",
        ));
    }
    Ok(())
}
fn invalid_input(message: &'static str) -> SpoolError {
    SpoolError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

#[cfg(test)]
mod durable_tests;
#[cfg(test)]
mod tests;
impl Spool {
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn capture_is_durable(&self, identity: ObjectIdentity) -> Result<bool, SpoolError> {
        let registry = lock_unpoisoned(&self.0.installed);
        self.0.ensure_admission()?;
        if registry
            .entries
            .get(&identity)
            .is_some_and(|entry| !entry.durable)
        {
            return Ok(false);
        }
        Ok(self.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_blobs b JOIN objects o ON o.digest=b.digest WHERE b.digest=?1 AND b.size=?2 AND b.readback_verified=1 AND o.upload_state=1 AND EXISTS(SELECT 1 FROM capture_paths WHERE digest=b.digest AND receipt_verified=1) AND NOT EXISTS(SELECT 1 FROM capture_paths WHERE digest=b.digest AND receipt_verified=0))",
                rusqlite::params![
                    identity.sha256.to_hex(),
                    crate::catalog::signed(identity.size)?
                ],
                |row| row.get::<_, bool>(0),
            )?)
        })?)
    }
}
