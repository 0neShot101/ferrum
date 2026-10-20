//! SQLite authority shared by local residency, capture, budgets and publication.

pub(crate) mod checkpoint;
#[cfg(test)]
mod migration;
pub(crate) mod publication;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

const PAGE: i64 = 128;
const APPLICATION_ID: u32 = 0x4645_5252;
const SCHEMA_VERSION: u32 = 5;
const SCHEMA: [(&str, &str); 3] = [
    (
        "objects",
        "CREATE TABLE objects (
       digest TEXT PRIMARY KEY CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),
       size INTEGER NOT NULL CHECK(size>=0),
       class INTEGER NOT NULL CHECK(class IN (0,1)),
       resident INTEGER NOT NULL CHECK(resident IN (0,1,2)),
       upload_state INTEGER NOT NULL DEFAULT 0 CHECK(upload_state IN (0,1)),
       generation_references INTEGER NOT NULL DEFAULT 0 CHECK(generation_references>=0)
     ) STRICT",
    ),
    (
        "reservations",
        "CREATE TABLE reservations (
       id TEXT PRIMARY KEY CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
       size INTEGER NOT NULL CHECK(size>=0),
       class INTEGER NOT NULL CHECK(class IN (0,1)),
       digest TEXT CHECK(digest IS NULL OR (length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*')),
       temporary_name TEXT
     ) STRICT",
    ),
    (
        "generation_pins",
        "CREATE TABLE generation_pins (
       generation TEXT NOT NULL CHECK(length(generation)=64 AND generation NOT GLOB '*[^0-9a-f]*'),
       digest TEXT NOT NULL REFERENCES objects(digest),
       PRIMARY KEY(generation,digest)
     ) STRICT",
    ),
];

fn extended_schema() -> impl Iterator<Item = (&'static str, &'static str)> {
    crate::budget::SCHEMA
        .iter()
        .copied()
        .chain(crate::capture::SCHEMA.iter().copied())
        .chain(checkpoint::SCHEMA.iter().copied())
}
fn auxiliary_schema() -> impl Iterator<Item = (&'static str, &'static str)> {
    crate::capture::AUX_SCHEMA
        .iter()
        .copied()
        .chain(crate::budget::AUX_SCHEMA.iter().copied())
}
type Job = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("SQLite catalog error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("catalog worker I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("catalog worker queue full")]
    Busy,
    #[error("catalog worker stopped")]
    Closed,
    #[error("invalid or conflicting persisted catalog identity")]
    InvalidState,
}

struct Worker {
    sender: Option<SyncSender<Job>>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    fn start(path: PathBuf, writer: bool, queue: usize, fresh: bool) -> Result<Self, CatalogError> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(queue);
        let (ready, opened) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(
                if writer {
                    "ferrum-sql-writer"
                } else {
                    "ferrum-sql-reader"
                }
                .into(),
            )
            .spawn(move || {
                let connection = open_connection(&path, writer, fresh);
                match connection {
                    Ok(mut connection) => {
                        if ready.send(Ok(())).is_err() {
                            return;
                        }
                        while let Ok(job) = receiver.recv() {
                            job(&mut connection);
                        }
                        if writer
                            && let Err(error) =
                                connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                        {
                            tracing::error!(%error, "catalog shutdown checkpoint failed");
                        }
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                    }
                }
            })?;
        let worker = Self {
            sender: Some(sender),
            thread: Some(thread),
        };
        opened.recv().map_err(|_| CatalogError::Closed)??;
        Ok(worker)
    }

    fn call<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, CatalogError> + Send + 'static,
    ) -> Result<T, CatalogError> {
        let (reply, result) = mpsc::sync_channel(1);
        let job: Job = Box::new(move |connection| {
            // Losing a caller does not cancel a transaction already admitted.
            let _ = reply.send(operation(connection));
        });
        self.sender
            .as_ref()
            .ok_or(CatalogError::Closed)?
            .try_send(job)
            .map_err(|error| match error {
                TrySendError::Full(_) => CatalogError::Busy,
                TrySendError::Disconnected(_) => CatalogError::Closed,
            })?;
        result.recv().map_err(|_| CatalogError::Closed)?
    }

    async fn call_async<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, CatalogError> + Send + 'static,
    ) -> Result<T, CatalogError> {
        let (reply, result) = tokio::sync::oneshot::channel();
        let job: Job = Box::new(move |connection| {
            // Accepted work belongs to this worker, even if its caller disconnects.
            let _ = reply.send(operation(connection));
        });

        self.sender
            .as_ref()
            .ok_or(CatalogError::Closed)?
            .try_send(job)
            .map_err(|error| match error {
                TrySendError::Full(_) => CatalogError::Busy,
                TrySendError::Disconnected(_) => CatalogError::Closed,
            })?;

        result.await.map_err(|_| CatalogError::Closed)?
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("catalog worker panicked");
        }
    }
}

fn open_connection(path: &Path, writer: bool, fresh: bool) -> Result<Connection, CatalogError> {
    let flags = if writer {
        if fresh {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        }
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    if writer {
        match std::fs::symlink_metadata(path) {
            Ok(_) if fresh => return Err(CatalogError::InvalidState),
            Ok(metadata) if !metadata.is_file() || metadata.len() == 0 => {
                return Err(CatalogError::InvalidState);
            }
            Ok(_) => {}
            Err(error) if fresh && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut connection =
        Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA cache_size=-2048; PRAGMA temp_store=FILE; PRAGMA mmap_size=0;")?;
    if writer {
        let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if (fresh && version != 0) || version > SCHEMA_VERSION || (!fresh && version == 0) {
            return Err(CatalogError::InvalidState);
        }
        if fresh {
            connection.execute_batch(
                "PRAGMA page_size=4096; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
            )?;
            let transaction = connection.transaction()?;
            for (_, sql) in SCHEMA {
                transaction.execute_batch(sql)?;
            }
            for (_, sql) in extended_schema() {
                transaction.execute_batch(sql)?;
            }
            for (_, sql) in auxiliary_schema() {
                transaction.execute_batch(sql)?;
            }
            for (_, sql) in crate::budget::provider::SCHEMA {
                transaction.execute_batch(sql)?;
            }
            for (_, sql) in publication::SCHEMA.iter().chain(publication::AUX_SCHEMA) {
                transaction.execute_batch(sql)?;
            }
            for (_, sql) in crate::capture::PACKAGE_SIGNATURE_SCHEMA {
                transaction.execute_batch(sql)?;
            }
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }
        // Validate every known old table, index, trigger and invariant before
        // opening the exclusive migration transaction. No counter, reservation,
        // receipt or checkpoint is reconstructed or reset by this migration.
        validate_catalog(&connection, if fresh { SCHEMA_VERSION } else { version })?;
        if !fresh && version < SCHEMA_VERSION {
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
            if version == 1 {
                for (_, sql) in extended_schema().chain(auxiliary_schema()) {
                    transaction.execute_batch(sql)?;
                }
            }
            if version < 3 {
                for (_, sql) in publication::SCHEMA.iter().chain(publication::AUX_SCHEMA) {
                    transaction.execute_batch(sql)?;
                }
                transaction.execute(
                    "INSERT INTO suite_publication(repository,suite) SELECT repository,suite FROM suite_checkpoints",
                    [],
                )?;
                // An old active pointer is not authenticated B09 reference authority.
                // Recovery must authenticate the trusted floor before reopening it.
                transaction.execute(
                    "UPDATE suite_checkpoints SET blocked=1,recovery_ready=0",
                    [],
                )?;
            }
            if version < 4 {
                // Ownership is deliberately unknown after an upgrade. Only explicit
                // initialization or audited fixed-provider adoption can grant it.
                for (_, sql) in crate::budget::provider::SCHEMA {
                    transaction.execute_batch(sql)?;
                }
            }
            for (_, sql) in crate::capture::PACKAGE_SIGNATURE_SCHEMA {
                transaction.execute_batch(sql)?;
            }
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            validate_catalog(&transaction, SCHEMA_VERSION)?;
            transaction.commit()?;
            validate_catalog(&connection, SCHEMA_VERSION)?;
        }
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=16; PRAGMA journal_size_limit=65536; PRAGMA max_page_count=2097152;")?;
    } else {
        connection.execute_batch("PRAGMA query_only=ON;")?;
    }
    Ok(connection)
}

fn validate_catalog(connection: &Connection, version: u32) -> Result<(), CatalogError> {
    let application_id: u32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != APPLICATION_ID {
        return Err(CatalogError::InvalidState);
    }
    let mut tables: Vec<_> = SCHEMA.into_iter().collect();
    let mut auxiliary = Vec::new();
    if version >= 2 {
        tables.extend(extended_schema());
        auxiliary.extend(auxiliary_schema());
    }
    if version >= 3 {
        tables.extend(publication::SCHEMA.iter().copied());
        auxiliary.extend(publication::AUX_SCHEMA.iter().copied());
    }
    if version >= 4 {
        tables.extend(crate::budget::provider::SCHEMA.iter().copied());
    }
    if version >= 5 {
        tables.extend(crate::capture::PACKAGE_SIGNATURE_SCHEMA.iter().copied());
    }
    for (name, expected) in tables.iter().chain(&auxiliary) {
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1",
            [name],
            |row| row.get(0),
        )?;
        if !actual.split_whitespace().eq(expected.split_whitespace()) {
            return Err(CatalogError::InvalidState);
        }
    }
    let mut schema = connection.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema")?;
    let mut rows = schema.query([])?;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > 128 {
            return Err(CatalogError::InvalidState);
        }
        let kind: String = row.get(0)?;
        let name: String = row.get(1)?;
        let table: String = row.get(2)?;
        let sql: Option<String> = row.get(3)?;
        let known_table = tables.iter().any(|(expected, _)| *expected == name);
        let known_auxiliary = auxiliary.iter().any(|(expected, _)| *expected == name);
        let automatic = kind == "index"
            && sql.is_none()
            && name.starts_with("sqlite_autoindex_")
            && tables.iter().any(|(expected, _)| *expected == table);
        let statistics = kind == "table"
            && matches!(
                (name.as_str(), sql.as_deref()),
                (
                    "sqlite_stat1",
                    Some("CREATE TABLE sqlite_stat1(tbl,idx,stat)")
                ) | (
                    "sqlite_stat4",
                    Some("CREATE TABLE sqlite_stat4(tbl,idx,neq,nlt,ndlt,sample)")
                )
            );
        if !(kind == "table" && known_table
            || (kind == "index" || kind == "trigger") && known_auxiliary
            || automatic
            || statistics)
        {
            return Err(CatalogError::InvalidState);
        }
    }
    let page_size: u32 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let integrity: String =
        connection.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
    let invalid_references: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM objects WHERE generation_references<>(SELECT COUNT(*) FROM generation_pins WHERE generation_pins.digest=objects.digest))",
        [],
        |row| row.get(0),
    )?;
    let invalid_foreign_key = connection.prepare("PRAGMA foreign_key_check")?.exists([])?;
    let invalid_budget = if version >= 2 {
        connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM remote_storage_totals t WHERE t.total<>(SELECT COALESCE(SUM(size),0) FROM remote_storage) OR t.data<>(SELECT COALESCE(SUM(size),0) FROM remote_storage WHERE class=0)) OR (EXISTS(SELECT 1 FROM remote_storage) AND NOT EXISTS(SELECT 1 FROM remote_storage_totals WHERE id=1)) OR EXISTS(SELECT 1 FROM remote_budget WHERE data_used>used) OR EXISTS(SELECT 1 FROM qualification_budget WHERE uploaded>upload_limit OR downloaded>download_limit)",
            [],
            |row| row.get::<_, bool>(0),
        )?
    } else {
        false
    };
    if page_size != 4096
        || integrity != "ok"
        || invalid_references
        || invalid_foreign_key
        || invalid_budget
    {
        return Err(CatalogError::InvalidState);
    }
    Ok(())
}

pub(crate) struct Catalog {
    // Readers close before the writer's shutdown checkpoint and process lock.
    readers: [Worker; 4],
    writer: Worker,
    next_reader: AtomicUsize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Resident {
    pub identity: ObjectIdentity,
    pub class: i64,
    pub state: i64,
    pub durable: bool,
    pub generation_references: u64,
    /// Local deletion eligibility only: derived metadata, uncaptured provisional
    /// bytes, or exact remotely verified receipt staging. Never serving authority.
    pub reconstructible: bool,
}

#[derive(Debug)]
pub(crate) struct PendingReservation {
    pub id: String,
    pub size: u64,
    pub class: i64,
}

pub(crate) fn signed(size: u64) -> Result<i64, CatalogError> {
    i64::try_from(size).map_err(|_| CatalogError::InvalidState)
}

pub(crate) fn read_unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn resident_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Resident> {
    let digest: String = row.get(0)?;
    let digest = Sha256Digest::from_hex(&digest).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(Resident {
        identity: ObjectIdentity {
            sha256: digest,
            size: read_unsigned(row, 1)?,
        },
        class: row.get(2)?,
        state: row.get(3)?,
        durable: row.get(4)?,
        generation_references: read_unsigned(row, 5)?,
        reconstructible: row.get(6)?,
    })
}

impl Catalog {
    pub(crate) fn open(root: &Path, queue: usize, fresh: bool) -> Result<Self, CatalogError> {
        let path = root.join("state.sqlite");
        let writer = Worker::start(path.clone(), true, queue, fresh)?;
        let readers = [
            Worker::start(path.clone(), false, queue, false)?,
            Worker::start(path.clone(), false, queue, false)?,
            Worker::start(path.clone(), false, queue, false)?,
            Worker::start(path, false, queue, false)?,
        ];
        Ok(Self {
            readers,
            writer,
            next_reader: AtomicUsize::new(0),
        })
    }
    pub(crate) fn on_worker_thread(&self) -> bool {
        let current = thread::current().id();
        self.readers
            .iter()
            .chain(std::iter::once(&self.writer))
            .any(|worker| {
                worker
                    .thread
                    .as_ref()
                    .is_some_and(|worker| worker.thread().id() == current)
            })
    }

    pub(crate) fn write<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, CatalogError> + Send + 'static,
    ) -> Result<T, CatalogError> {
        self.writer.call(operation)
    }

    pub(crate) fn read<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, CatalogError> + Send + 'static,
    ) -> Result<T, CatalogError> {
        self.reader().call(operation)
    }

    /// Short reads share the three bounded reader queues with synchronous callers.
    /// Cancellation drops only the reply; admitted work finishes on its owner.
    pub(crate) async fn read_async<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, CatalogError> + Send + 'static,
    ) -> Result<T, CatalogError> {
        self.reader().call_async(operation).await
    }

    pub(crate) async fn work_async<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, CatalogError> + Send + 'static,
    ) -> Result<T, CatalogError> {
        self.readers[3].call_async(operation).await
    }

    fn reader(&self) -> &Worker {
        &self.readers[self.next_reader.fetch_add(1, Ordering::Relaxed) % 3]
    }

    pub(crate) fn object(
        &self,
        identity: ObjectIdentity,
    ) -> Result<Option<Resident>, CatalogError> {
        self.reader().call(move |connection| {
            let object = connection
                .query_row(
                    "SELECT digest,size,class,resident,upload_state,generation_references,EXISTS(SELECT 1 FROM derived_residency d WHERE d.digest=objects.digest) AND (NOT EXISTS(SELECT 1 FROM capture_blobs b WHERE b.digest=objects.digest) OR EXISTS(SELECT 1 FROM capture_paths p WHERE p.digest=objects.digest AND p.receipt_verified=1)) FROM objects WHERE digest=?1",
                    [identity.sha256.to_hex()],
                    resident_row,
                )
                .optional()?;
            if object
                .as_ref()
                .is_some_and(|object| object.identity != identity)
            {
                return Err(CatalogError::InvalidState);
            }
            Ok(object)
        })
    }

    pub(crate) fn residents(&self, after: Option<String>) -> Result<Vec<Resident>, CatalogError> {
        self.reader().call(move |connection| {
            let mut statement = connection.prepare("SELECT digest,size,class,resident,upload_state,generation_references,EXISTS(SELECT 1 FROM derived_residency d WHERE d.digest=objects.digest) AND (NOT EXISTS(SELECT 1 FROM capture_blobs b WHERE b.digest=objects.digest) OR EXISTS(SELECT 1 FROM capture_paths p WHERE p.digest=objects.digest AND p.receipt_verified=1)) FROM objects WHERE resident<>0 AND digest>?1 ORDER BY digest LIMIT ?2")?;
            let rows = statement.query_map(params![after.unwrap_or_default(), PAGE], resident_row)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(CatalogError::from)
        })
    }

    pub(crate) fn reservations(
        &self,
        after: Option<String>,
    ) -> Result<Vec<PendingReservation>, CatalogError> {
        self.reader().call(move |connection| {
            let mut statement = connection.prepare(
                "SELECT id,size,class FROM reservations WHERE id>?1 ORDER BY id LIMIT ?2",
            )?;
            let rows = statement.query_map(params![after.unwrap_or_default(), PAGE], |row| {
                Ok(PendingReservation {
                    id: row.get(0)?,
                    size: read_unsigned(row, 1)?,
                    class: row.get(2)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(CatalogError::from)
        })
    }

    pub(crate) fn reserve(&self, id: String, size: u64, class: i64) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO reservations(id,size,class) VALUES(?1,?2,?3)",
                params![id, signed(size)?, class],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub(crate) fn bind(
        &self,
        id: String,
        identity: ObjectIdentity,
        name: String,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            let existing: Option<u64> = transaction
                .query_row(
                    "SELECT size FROM objects WHERE digest=?1",
                    [identity.sha256.to_hex()],
                    |row| read_unsigned(row, 0),
                )
                .optional()?;
            if existing.is_some_and(|size| size != identity.size) {
                return Err(CatalogError::InvalidState);
            }
            let changed = transaction.execute(
                "UPDATE reservations SET digest=?1,temporary_name=?2 WHERE id=?3 AND size=?4",
                params![identity.sha256.to_hex(), name, id, signed(identity.size)?],
            )?;
            if changed != 1 {
                return Err(CatalogError::InvalidState);
            }
            transaction.commit()?;
            Ok(())
        })
    }

    pub(crate) fn release(&self, id: String) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            let digest: Option<String> = transaction
                .query_row(
                    "SELECT digest FROM reservations WHERE id=?1",
                    [&id],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            transaction.execute("DELETE FROM reservations WHERE id=?1", [id])?;
            if let Some(digest) = digest {
                crate::capture::lifecycle::abandon_transaction(&transaction, &digest)?;
            }
            transaction.commit()?;
            Ok(())
        })
    }

    pub(crate) fn install(
        &self,
        id: String,
        identity: ObjectIdentity,
        class: i64,
        candidate: bool,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            let existing: Option<(u64, i64)> = transaction
                .query_row(
                    "SELECT size,resident FROM objects WHERE digest=?1",
                    [identity.sha256.to_hex()],
                    |row| Ok((read_unsigned(row, 0)?, row.get(1)?)),
                )
                .optional()?;
            if existing.is_some_and(|(size, _)| size != identity.size) {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "INSERT INTO objects(digest,size,class,resident) VALUES(?1,?2,?3,1) ON CONFLICT(digest) DO UPDATE SET resident=1, class=MIN(objects.class,excluded.class)",
                params![identity.sha256.to_hex(), signed(identity.size)?, class],
            )?;
            // Only newly installed, uncaptured bytes receive provisional
            // deletion eligibility. This marker grants no serving/reconstruction
            // authority and cannot downgrade a deduplicated trusted object.
            if candidate && existing.is_none_or(|(_, resident)| resident == 0) && class == 0 {
                transaction.execute(
                    "INSERT OR IGNORE INTO derived_residency(digest) SELECT ?1 WHERE NOT EXISTS(SELECT 1 FROM capture_blobs WHERE digest=?1)",
                    [identity.sha256.to_hex()],
                )?;
            }
            let changed = transaction.execute(
                "DELETE FROM reservations WHERE id=?1 AND digest=?2 AND size=?3",
                params![id, identity.sha256.to_hex(), signed(identity.size)?],
            )?;
            if changed != 1 {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "UPDATE capture_blobs SET first_capture=CAST(strftime('%s','now') AS INTEGER),retain_until=MAX(retain_until,CAST(strftime('%s','now') AS INTEGER)+2592000) WHERE digest=?1 AND first_capture=0",
                [identity.sha256.to_hex()],
            )?;
            transaction.execute(
                "INSERT OR IGNORE INTO capture_outbox(digest,size,queued_at) SELECT a.digest,a.size,b.first_capture FROM capture_admissions a JOIN capture_blobs b ON b.digest=a.digest WHERE a.digest=?1",
                [identity.sha256.to_hex()],
            )?;
            transaction.execute(
                "DELETE FROM capture_admissions WHERE digest=?1",
                [identity.sha256.to_hex()],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub(crate) fn enqueue_installed_capture(
        &self,
        identity: ObjectIdentity,
    ) -> Result<(), CatalogError> {
        self.write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "UPDATE capture_blobs SET first_capture=CAST(strftime('%s','now') AS INTEGER),retain_until=MAX(retain_until,CAST(strftime('%s','now') AS INTEGER)+2592000) WHERE digest=?1 AND first_capture=0 AND EXISTS(SELECT 1 FROM objects WHERE digest=?1 AND resident=1)",
                [identity.sha256.to_hex()],
            )?;
            transaction.execute(
                "INSERT OR IGNORE INTO capture_outbox(digest,size,queued_at) SELECT a.digest,a.size,b.first_capture FROM capture_admissions a JOIN capture_blobs b ON b.digest=a.digest JOIN objects o ON o.digest=a.digest WHERE a.digest=?1 AND o.resident=1",
                [identity.sha256.to_hex()],
            )?;
            transaction.execute(
                "DELETE FROM capture_admissions WHERE digest=?1 AND EXISTS(SELECT 1 FROM capture_outbox WHERE digest=?1)",
                [identity.sha256.to_hex()],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub(crate) fn require_package_retention(
        &self,
        identity: ObjectIdentity,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            let changed = transaction.execute(
                "UPDATE objects SET class=0 WHERE digest=?1 AND size=?2 AND resident=1",
                params![identity.sha256.to_hex(), signed(identity.size)?],
            )?;
            if changed != 1 {
                return Err(CatalogError::InvalidState);
            }
            transaction.commit()?;
            Ok(())
        })
    }

    pub(crate) fn retain_generation(
        &self,
        generation: Sha256Digest,
        objects: Vec<ObjectIdentity>,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            for identity in objects {
                let resident: Option<(u64, i64)> = transaction
                    .query_row(
                        "SELECT size,resident FROM objects WHERE digest=?1",
                        [identity.sha256.to_hex()],
                        |row| Ok((read_unsigned(row, 0)?, row.get(1)?)),
                    )
                    .optional()?;
                if resident != Some((identity.size, 1)) {
                    return Err(CatalogError::InvalidState);
                }
                let changed = transaction.execute(
                    "INSERT INTO generation_pins(generation,digest) VALUES(?1,?2) ON CONFLICT DO NOTHING",
                    params![generation.to_hex(), identity.sha256.to_hex()],
                )?;
                if changed == 1 {
                    transaction.execute(
                        "UPDATE objects SET generation_references=generation_references+1 WHERE digest=?1",
                        [identity.sha256.to_hex()],
                    )?;
                }
            }
            transaction.commit()?;
            Ok(())
        })
    }

    pub(crate) fn release_generation_batch(
        &self,
        generation: Sha256Digest,
    ) -> Result<Vec<ObjectIdentity>, CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            let identities = {
                let mut statement = transaction.prepare("SELECT objects.digest,objects.size,objects.class,objects.resident,objects.upload_state,objects.generation_references,EXISTS(SELECT 1 FROM derived_residency d WHERE d.digest=objects.digest) AND (NOT EXISTS(SELECT 1 FROM capture_blobs b WHERE b.digest=objects.digest) OR EXISTS(SELECT 1 FROM capture_paths p WHERE p.digest=objects.digest AND p.receipt_verified=1)) FROM objects JOIN generation_pins USING(digest) WHERE generation=?1 ORDER BY digest LIMIT 8")?;
                let rows = statement.query_map([generation.to_hex()], resident_row)?;
                rows.map(|row| row.map(|row| row.identity))
                    .collect::<Result<Vec<_>, _>>()?
            };
            for identity in &identities {
                transaction.execute(
                    "DELETE FROM generation_pins WHERE generation=?1 AND digest=?2",
                    params![generation.to_hex(), identity.sha256.to_hex()],
                )?;
                let changed = transaction.execute(
                    "UPDATE objects SET generation_references=generation_references-1 WHERE digest=?1 AND generation_references>0",
                    [identity.sha256.to_hex()],
                )?;
                if changed != 1 {
                    return Err(CatalogError::InvalidState);
                }
            }
            transaction.commit()?;
            Ok(identities)
        })
    }

    pub(crate) fn set_residency(
        &self,
        identity: ObjectIdentity,
        state: i64,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            let changed = transaction.execute(
                "UPDATE objects SET resident=?1 WHERE digest=?2 AND size=?3",
                params![state, identity.sha256.to_hex(), signed(identity.size)?],
            )?;
            if changed != 1 {
                return Err(CatalogError::InvalidState);
            }
            transaction.commit()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod scheduling;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{Connection, read_unsigned, signed};

    #[test]
    fn sqlite_unsigned_boundaries_reject_negative_and_unrepresentable_values() {
        let connection = Connection::open_in_memory().expect("in-memory SQLite");
        assert_eq!(
            connection
                .query_row("SELECT 0", [], |row| read_unsigned(row, 0))
                .expect("zero"),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT 9223372036854775807", [], |row| read_unsigned(
                    row, 0
                ))
                .expect("largest SQLite integer"),
            u64::try_from(i64::MAX).expect("nonnegative i64 maximum")
        );
        assert!(
            connection
                .query_row("SELECT -1", [], |row| read_unsigned(row, 0))
                .is_err()
        );
        assert!(
            connection
                .query_row("SELECT 9223372036854775808", [], |row| read_unsigned(
                    row, 0
                ))
                .is_err()
        );
        assert!(signed(u64::MAX).is_err());
    }
}
