//! Short worker-owned checkpoint transactions; no connection crosses network I/O.
use super::{Catalog, CatalogError};
use crate::checkpoint::{PublicationIntent, SuiteKey, SuiteState};
use rusqlite::{OptionalExtension, params};

pub(super) const SCHEMA: &[(&str, &str)] = &[
    (
        "suite_checkpoints",
        "CREATE TABLE suite_checkpoints (
 repository TEXT NOT NULL, suite TEXT NOT NULL,
 observed_date INTEGER, observed_content TEXT,
 floor TEXT, active TEXT, pending TEXT,
 blocked INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN (0,1)),
 bootstrap_authorized INTEGER NOT NULL DEFAULT 0 CHECK(bootstrap_authorized IN (0,1)),
 recovery_ready INTEGER NOT NULL DEFAULT 0 CHECK(recovery_ready IN (0,1)),
 PRIMARY KEY(repository,suite)
) STRICT",
    ),
    (
        "bootstrap_audit",
        "CREATE TABLE bootstrap_audit (
 id INTEGER PRIMARY KEY, repository TEXT NOT NULL, suite TEXT NOT NULL,
 recorded_at INTEGER NOT NULL, operator TEXT NOT NULL, reason TEXT NOT NULL,
 previous_floor TEXT, disclosure TEXT NOT NULL
) STRICT",
    ),
    (
        "catalog_backups",
        "CREATE TABLE catalog_backups (
 hour INTEGER PRIMARY KEY, object_key TEXT NOT NULL, digest TEXT NOT NULL,
 size INTEGER NOT NULL CHECK(size>=0), descriptor TEXT NOT NULL
) STRICT",
    ),
];
fn decode(value: Option<String>) -> Result<Option<PublicationIntent>, CatalogError> {
    value
        .map(|text| {
            PublicationIntent::decode(text.as_bytes()).map_err(|_| CatalogError::InvalidState)
        })
        .transpose()
}
fn encode(intent: &PublicationIntent) -> Result<String, CatalogError> {
    intent.encode().map_err(|_| CatalogError::InvalidState)
}

fn load_checkpoint(
    connection: &rusqlite::Connection,
    key: &SuiteKey,
) -> Result<SuiteState, CatalogError> {
    let row = connection
        .prepare_cached(
            "SELECT observed_date,observed_content,floor,active,pending,blocked,bootstrap_authorized,recovery_ready FROM suite_checkpoints WHERE repository=?1 AND suite=?2",
        )?
        .query_row(
            params![key.repository(), key.suite()],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, bool>(6)?,
                    row.get::<_, bool>(7)?,
                ))
            },
        )
        .optional()?;
    let state = match row {
        None => SuiteState::default(),
        Some((date, content, floor, active, pending, blocked, bootstrap, recovery_ready)) => {
            SuiteState {
                observed_date: date,
                observed_content: content,
                floor: decode(floor)?,
                active: decode(active)?,
                pending: decode(pending)?,
                blocked,
                bootstrap_authorized: bootstrap,
                recovery_ready,
                ..SuiteState::default()
            }
        }
    };

    Ok(state)
}

pub(super) fn load(
    connection: &rusqlite::Connection,
    key: &SuiteKey,
) -> Result<SuiteState, CatalogError> {
    let mut state = load_checkpoint(connection, key)?;

    let publication = connection
        .query_row(
            "SELECT candidate_generation,observed_at,confirmed_at,successor_seen_at,last_error,next_check_at FROM suite_publication WHERE repository=?1 AND suite=?2",
            params![key.repository(), key.suite()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            },
        )
        .optional()?;
    if let Some((candidate, observed, confirmed, successor, error, next)) = publication {
        state.candidate_generation = candidate;
        state.observed_at = observed;
        state.confirmed_at = confirmed;
        state.successor_seen_at = successor;
        state.last_error = error;
        state.next_check_at = next;
    }
    Ok(state)
}
pub(super) fn ensure(
    connection: &rusqlite::Connection,
    key: &SuiteKey,
) -> Result<(), CatalogError> {
    let (exists, count): (bool, i64) = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM suite_checkpoints WHERE repository=?1 AND suite=?2), \
         (SELECT COUNT(*) FROM suite_checkpoints)",
        params![key.repository(), key.suite()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if !exists && count >= crate::checkpoint::MAX_SUITES as i64 {
        return Err(CatalogError::InvalidState);
    }
    connection.execute(
        "INSERT INTO suite_checkpoints(repository,suite) VALUES(?1,?2) ON CONFLICT DO NOTHING",
        params![key.repository(), key.suite()],
    )?;
    Ok(())
}
impl Catalog {
    pub(crate) fn checkpoint_state(&self, key: SuiteKey) -> Result<SuiteState, CatalogError> {
        self.reader().call(move |connection| load(connection, &key))
    }

    pub(crate) async fn checkpoint_state_async(
        &self,
        key: SuiteKey,
    ) -> Result<SuiteState, CatalogError> {
        self.read_async(move |connection| load(connection, &key))
            .await
    }

    pub(crate) async fn checkpoint_available_generation(
        &self,
        key: SuiteKey,
    ) -> Result<Option<String>, CatalogError> {
        self.read_async(move |connection| {
            let state = load_checkpoint(connection, &key)?;

            if state.blocked || state.pending.is_some() {
                return Ok(None);
            }

            Ok(state.active.map(|active| active.generation_id))
        })
        .await
    }

    pub(crate) fn checkpoint_prepare(&self, intent: PublicationIntent) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let key = intent.key().map_err(|_| CatalogError::InvalidState)?;
            let transaction = connection.transaction()?;
            ensure(&transaction, &key)?;
            let state = load(&transaction, &key)?;
            if (state.blocked && !state.recovery_ready)
                || state.pending.is_some()
                || state
                    .floor
                    .as_ref()
                    .map_or(1, |floor| floor.sequence.saturating_add(1))
                    != intent.sequence
                || (state.floor.is_none() && !state.bootstrap_authorized)
            {
                return Err(CatalogError::InvalidState);
            }
            if !key.uses_transport_candidate_metadata() && state
                .floor
                .as_ref()
                .is_some_and(|floor| intent.release_date < floor.release_date || (intent.release_date == floor.release_date && intent.release_content_sha256 != floor.release_content_sha256))
            {
                return Err(CatalogError::InvalidState);
            }
            if !key.uses_transport_candidate_metadata() && state
                .observed_date
                .is_some_and(|date| intent.release_date < date || (intent.release_date == date && state.observed_content.as_ref() != Some(&intent.release_content_sha256)))
            {
                return Err(CatalogError::InvalidState);
            }
            let scope = crate::recovery::generation_scope(key.repository(), key.suite(), &intent.generation_id).to_hex();
            super::publication::check_conflicts(&transaction, &key, &scope)?;
            transaction.execute(
                "INSERT INTO publication_candidates(generation,repository,suite) VALUES(?1,?2,?3)",
                params![scope, key.repository(), key.suite()],
            )?;
            transaction.execute(
                "UPDATE suite_checkpoints SET pending=?3,blocked=1,recovery_ready=0 WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite(), encode(&intent)?],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
    pub(crate) fn checkpoint_accept(&self, intent: PublicationIntent) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let key = intent.key().map_err(|_| CatalogError::InvalidState)?;
            let transaction = connection.transaction()?;
            ensure(&transaction, &key)?;
            let state = load(&transaction, &key)?;
            if state
                .floor
                .as_ref()
                .is_some_and(|floor| floor.sequence > intent.sequence || (floor.sequence == intent.sequence && *floor != intent))
            {
                return Err(CatalogError::InvalidState);
            }
            if state
                .pending
                .as_ref()
                .is_some_and(|pending| *pending != intent)
            {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "UPDATE suite_checkpoints SET floor=?3,pending=?3,blocked=1,bootstrap_authorized=0,recovery_ready=0 WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite(), encode(&intent)?],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
    pub(crate) fn checkpoint_block(&self, key: SuiteKey) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            ensure(connection, &key)?;
            connection.execute(
                "UPDATE suite_checkpoints SET blocked=1,recovery_ready=0 WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite()],
            )?;
            Ok(())
        })
    }
    pub(crate) fn checkpoint_cancel_unwritten(
        &self,
        key: SuiteKey,
        remote: Option<PublicationIntent>,
        blocked: bool,
        recovery_ready: bool,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            let state = load(&transaction, &key)?;
            if state.floor != remote {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "UPDATE suite_checkpoints SET pending=NULL,blocked=?3,recovery_ready=?4 WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite(), blocked, recovery_ready],
            )?;
            transaction.execute(
                "DELETE FROM publication_candidates WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite()],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
    pub(crate) fn checkpoint_bootstrap(
        &self,
        key: SuiteKey,
        now: i64,
        operator: String,
        reason: String,
        disclosure: String,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            ensure(&transaction, &key)?;
            let state = load(&transaction, &key)?;
            transaction.execute(
                "INSERT INTO bootstrap_audit(repository,suite,recorded_at,operator,reason,previous_floor,disclosure) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    key.repository(),
                    key.suite(),
                    now,
                    operator,
                    reason,
                    state.floor.as_ref().map(encode).transpose()?,
                    disclosure
                ],
            )?;
            transaction.execute(
                "UPDATE suite_checkpoints SET floor=NULL,active=NULL,pending=NULL,blocked=1,bootstrap_authorized=1,recovery_ready=0,observed_date=NULL,observed_content=NULL WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite()],
            )?;
            transaction.execute(
                "DELETE FROM publication_candidates WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite()],
            )?;
            transaction.execute(
                "DELETE FROM suite_publication WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite()],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
    pub(crate) fn checkpoint_prepare_bootstrap(
        &self,
        intent: PublicationIntent,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let key = intent.key().map_err(|_| CatalogError::InvalidState)?;
            let transaction = connection.transaction()?;
            let state = load(&transaction, &key)?;
            if !state.bootstrap_authorized || state.pending.is_some() {
                return Err(CatalogError::InvalidState);
            }
            let scope = crate::recovery::generation_scope(
                key.repository(),
                key.suite(),
                &intent.generation_id,
            )
            .to_hex();
            super::publication::check_conflicts(&transaction, &key, &scope)?;
            transaction.execute(
                "INSERT INTO publication_candidates(generation,repository,suite) VALUES(?1,?2,?3)",
                params![scope, key.repository(), key.suite()],
            )?;
            transaction.execute(
                "UPDATE suite_checkpoints SET pending=?3 WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite(), encode(&intent)?],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
}

impl crate::Spool {
    /// SQLite online backup runs on one of the four bounded read workers. Each
    /// step copies at most 64 pages; WAL readers/writer remain live.
    pub(crate) async fn online_backup<G: Send + 'static>(
        &self,
        path: std::path::PathBuf,
        maximum: u64,
        deadline: std::time::Instant,
        guard: G,
    ) -> Result<G, crate::SpoolError> {
        let cancel = tokio_util::sync::CancellationToken::new();
        let _cancel = cancel.clone().drop_guard();
        self.catalog_work_async(move |source| {
            let mut destination = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            destination.busy_timeout(std::time::Duration::from_millis(100))?;
            // This private scratch is unpublished until a complete fsynced backup
            // is installed; disabling its rollback journal avoids unowned sidecars.
            destination.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=FULL;")?;
            let validation_cancel = cancel.clone();
            destination.progress_handler(
                4096,
                Some(move || {
                    validation_cancel.is_cancelled() || std::time::Instant::now() >= deadline
                }),
            )?;
            {
                let backup = rusqlite::backup::Backup::new(source, &mut destination)?;
                loop {
                    if cancel.is_cancelled() {
                        return Err(CatalogError::Closed);
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(CatalogError::Busy);
                    }
                    let result = backup.step(64)?;
                    let pages = u64::try_from(backup.progress().pagecount)
                        .map_err(|_| CatalogError::InvalidState)?;
                    if pages.checked_mul(4096).is_none_or(|size| size > maximum) {
                        return Err(CatalogError::InvalidState);
                    }
                    match result {
                        rusqlite::backup::StepResult::Done => break,
                        rusqlite::backup::StepResult::More => {}
                        rusqlite::backup::StepResult::Busy
                        | rusqlite::backup::StepResult::Locked => {
                            std::thread::sleep(std::time::Duration::from_millis(10))
                        }
                        _ => return Err(CatalogError::InvalidState),
                    }
                }
            }
            destination.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
            let integrity: String =
                destination.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
            if integrity != "ok" {
                return Err(CatalogError::InvalidState);
            }
            destination
                .close()
                .map_err(|(_, error)| CatalogError::Sql(error))?;
            std::fs::File::open(&path)?.sync_all()?;
            Ok(guard)
        })
        .await
    }
}
impl Catalog {
    pub(crate) fn backup_last_hour(&self) -> Result<Option<i64>, CatalogError> {
        self.reader().call(|connection| {
            Ok(
                connection.query_row("SELECT MAX(hour) FROM catalog_backups", [], |row| {
                    row.get(0)
                })?,
            )
        })
    }
    pub(crate) fn backup_record(
        &self,
        hour: i64,
        key: String,
        digest: String,
        size: u64,
        descriptor: String,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let transaction = connection.transaction()?;
            let previous: Option<String> = transaction
                .query_row(
                    "SELECT descriptor FROM catalog_backups WHERE hour=?1",
                    [hour],
                    |row| row.get(0),
                )
                .optional()?;
            if previous.as_ref().is_some_and(|old| old != &descriptor) {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "INSERT INTO catalog_backups(hour,object_key,digest,size,descriptor) VALUES(?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING",
                params![hour, key, digest, super::signed(size)?, descriptor],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
}

impl crate::Spool {
    pub(crate) async fn validate_backup(
        &self,
        object: crate::VerifiedObject,
    ) -> Result<(), crate::SpoolError> {
        let cancel = tokio_util::sync::CancellationToken::new();
        let _cancel = cancel.clone().drop_guard();
        self.catalog_work_async(move |_| {
            let connection = rusqlite::Connection::open_with_flags(
                object.path(),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; PRAGMA cache_size=-2048; PRAGMA mmap_size=0;")?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            connection.progress_handler(
                4096,
                Some(move || cancel.is_cancelled() || std::time::Instant::now() >= deadline),
            )?;
            let integrity: String = connection.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
            let app: u32 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
            let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            if integrity != "ok" || app != super::APPLICATION_ID || !(2..=super::SCHEMA_VERSION).contains(&version) {
                return Err(CatalogError::InvalidState);
            }
            super::validate_catalog(&connection, version)?;
            Ok(())
        })
        .await
    }
}

impl crate::Spool {
    pub(crate) async fn verify_derived(
        &self,
        source: crate::VerifiedObject,
        source_name: String,
        entry: ferrum_apt::release::ReleaseEntry,
        authentication: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<ferrum_apt::digest::ObjectIdentity, crate::SpoolError> {
        let cancel = tokio_util::sync::CancellationToken::new();
        let _cancel = cancel.clone().drop_guard();
        self.catalog_work_async(move |_| {
            let _authentication = authentication;
            use ferrum_apt::digest::{Sha256Hasher, Sha512Hasher};
            use std::io::Read;
            if entry.size > 8 * 1024 * 1024 * 1024 {
                return Err(CatalogError::InvalidState);
            }
            let file = std::fs::File::open(source.path())?;
            let mut decoder = crate::recovery::proof_reader(file, &source_name, cancel)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            let mut buffer = vec![0u8; 256 * 1024];
            let mut size = 0u64;
            let mut sha256 = Sha256Hasher::new();
            let mut sha512 = Sha512Hasher::new();
            loop {
                if std::time::Instant::now() >= deadline {
                    return Err(CatalogError::Busy);
                }
                let maximum = usize::try_from(entry.size.saturating_sub(size).saturating_add(1))
                    .unwrap_or(buffer.len())
                    .min(buffer.len());
                let count = decoder.read(&mut buffer[..maximum])?;
                if count == 0 {
                    break;
                }
                size = size
                    .checked_add(count as u64)
                    .ok_or(CatalogError::InvalidState)?;
                if size > entry.size {
                    return Err(CatalogError::InvalidState);
                }
                sha256.update(&buffer[..count]);
                if entry.sha512.is_some() {
                    sha512.update(&buffer[..count]);
                }
            }
            let digest = sha256.finalize();
            if size != entry.size
                || entry.sha256.is_some_and(|expected| expected != digest)
                || entry
                    .sha512
                    .is_some_and(|expected| expected != sha512.finalize())
            {
                return Err(CatalogError::InvalidState);
            }
            Ok(ferrum_apt::digest::ObjectIdentity {
                sha256: digest,
                size,
            })
        })
        .await
    }
}

#[cfg(test)]
impl Catalog {
    /// Checkpoint protocol fixtures deliberately have no signed Packages body.
    /// These helpers are not compiled into the library or private harness.
    pub(crate) fn stage_protocol_indexes(
        &self,
        intent: &PublicationIntent,
    ) -> Result<(), CatalogError> {
        let scope = crate::recovery::generation_scope(
            &intent.repository,
            &intent.suite,
            &intent.generation_id,
        )
        .to_hex();
        self.write(move |connection| {
            connection.execute(
                "INSERT OR IGNORE INTO capture_index_generations(generation,path_set,verified) VALUES(?1,'protocol-fixture',1)",
                [scope],
            )?;
            Ok(())
        })
    }
    pub(crate) fn checkpoint_prepare_protocol(
        &self,
        intent: PublicationIntent,
    ) -> Result<(), CatalogError> {
        self.stage_protocol_indexes(&intent)?;
        self.checkpoint_prepare(intent)
    }
    pub(crate) fn checkpoint_bootstrap_protocol(
        &self,
        intent: PublicationIntent,
    ) -> Result<(), CatalogError> {
        self.stage_protocol_indexes(&intent)?;
        self.checkpoint_prepare_bootstrap(intent)
    }
    pub(crate) fn checkpoint_activate(
        &self,
        intent: PublicationIntent,
    ) -> Result<(), CatalogError> {
        self.write(move |connection| {
            let key = intent.key().map_err(|_| CatalogError::InvalidState)?;
            let transaction = connection.transaction()?;
            let state = load(&transaction, &key)?;
            if state.floor.as_ref() != Some(&intent) || state.pending.as_ref() != Some(&intent) {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "UPDATE suite_checkpoints SET active=?3,pending=NULL,blocked=0,recovery_ready=0 WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite(), encode(&intent)?],
            )?;
            transaction.execute(
                "DELETE FROM publication_candidates WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite()],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
    pub(crate) fn checkpoint_complete_unconfirmed(
        &self,
        intent: PublicationIntent,
    ) -> Result<(), CatalogError> {
        self.writer.call(move |connection| {
            let key = intent.key().map_err(|_| CatalogError::InvalidState)?;
            let transaction = connection.transaction()?;
            let state = load(&transaction, &key)?;
            if state.floor.as_ref() != Some(&intent) || state.pending.as_ref() != Some(&intent) {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "UPDATE suite_checkpoints SET active=?3,pending=NULL,blocked=1,recovery_ready=1 WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite(), encode(&intent)?],
            )?;
            transaction.execute(
                "DELETE FROM publication_candidates WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite()],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;
    fn intent(suite: &str, sequence: u64) -> PublicationIntent {
        PublicationIntent {
            schema_version: 1,
            repository: "debian".into(),
            suite: suite.into(),
            sequence,
            generation_id: format!("{sequence:064x}"),
            manifest_sha256: "a".repeat(64),
            release_content_sha256: format!("{sequence:064x}"),
            release_date: sequence as i64,
        }
    }
    fn bootstrap(catalog: &Catalog, value: PublicationIntent) {
        let key = value.key().unwrap();
        catalog
            .checkpoint_bootstrap(
                key,
                1,
                "test operator".into(),
                "ordinary loss".into(),
                "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED".into(),
            )
            .unwrap();
        catalog
            .checkpoint_bootstrap_protocol(value.clone())
            .unwrap();
        catalog.checkpoint_accept(value.clone()).unwrap();
        catalog.checkpoint_activate(value).unwrap();
    }
    #[test]
    fn checkpoint_inventory_accepts_shared_ceiling_and_rejects_additional_identity() {
        let directory = TempDir::new().unwrap();
        let catalog = Catalog::open(directory.path(), 4, true).unwrap();
        for index in 0..crate::checkpoint::MAX_SUITES {
            let key = SuiteKey::new("debian", &format!("suite-{index}")).unwrap();
            catalog.checkpoint_block(key).unwrap();
        }
        let extra = SuiteKey::new("debian", "overflow").unwrap();
        assert!(catalog.checkpoint_block(extra).is_err());
        let existing = SuiteKey::new("debian", "suite-0").unwrap();
        catalog.checkpoint_block(existing.clone()).unwrap();
        assert!(catalog.checkpoint_state(existing).unwrap().blocked);
    }

    #[test]
    fn crash_matrix_separates_observed_intent_floor_and_active() {
        let directory = TempDir::new().unwrap();
        let catalog = Catalog::open(directory.path(), 4, true).unwrap();
        let first = intent("trixie", 1);
        let second = intent("trixie", 2);
        let key = first.key().unwrap();
        bootstrap(&catalog, first.clone());
        catalog
            .publication_observe(
                key.clone(),
                second.generation_id.clone(),
                2,
                second.release_content_sha256.clone(),
                2,
            )
            .unwrap();
        assert_eq!(
            catalog.checkpoint_state(key.clone()).unwrap().floor,
            Some(first.clone())
        );
        catalog.checkpoint_prepare_protocol(second.clone()).unwrap();
        let state = catalog.checkpoint_state(key.clone()).unwrap();
        assert!(state.blocked);
        assert_eq!(state.active, Some(first.clone()));
        assert_eq!(state.pending, Some(second.clone()));
        assert!(catalog.checkpoint_activate(second.clone()).is_err());
        drop(catalog);
        let catalog = Catalog::open(directory.path(), 4, false).unwrap();
        // Direct unchanged trusted remote floor reconciles a crash before CAS.
        catalog
            .checkpoint_cancel_unwritten(key.clone(), Some(first.clone()), false, false)
            .unwrap();
        catalog.checkpoint_prepare_protocol(second.clone()).unwrap();
        // Lost ACK is accepted only after exact readback of the same intent.
        catalog.checkpoint_accept(second.clone()).unwrap();
        drop(catalog);
        let catalog = Catalog::open(directory.path(), 4, false).unwrap();
        let state = catalog.checkpoint_state(key.clone()).unwrap();
        assert_eq!(state.floor, Some(second.clone()));
        assert_eq!(state.active, Some(first.clone()));
        assert!(state.blocked);
        assert!(catalog.checkpoint_activate(first).is_err());
        catalog.checkpoint_activate(second.clone()).unwrap();
        assert_eq!(catalog.checkpoint_state(key).unwrap().active, Some(second));
    }
    #[test]
    fn conflicting_local_writers_and_suite_failure_are_independent() {
        let directory = TempDir::new().unwrap();
        let catalog = Catalog::open(directory.path(), 4, true).unwrap();
        bootstrap(&catalog, intent("trixie", 1));
        bootstrap(&catalog, intent("trixie-updates", 1));
        let pending = intent("trixie", 2);
        catalog
            .checkpoint_prepare_protocol(pending.clone())
            .unwrap();
        assert!(
            catalog
                .checkpoint_prepare_protocol(pending.clone())
                .is_err()
        );
        let mut conflicting = pending;
        conflicting.manifest_sha256 = "b".repeat(64);
        assert!(catalog.checkpoint_accept(conflicting).is_err());
        let healthy = catalog
            .checkpoint_state(SuiteKey::new("debian", "trixie-updates").unwrap())
            .unwrap();
        assert!(!healthy.blocked);
        assert!(healthy.active.is_some());
    }
    #[tokio::test]
    async fn online_backup_includes_wal_and_old_snapshot_never_implies_new_floor() {
        let directory = TempDir::new().unwrap();
        let spool = crate::recovery::test_support::open_spool(&directory.path().join("state"));
        let catalog = spool.durable_catalog().unwrap();
        let first = intent("trixie", 1);
        bootstrap(catalog, first.clone());
        let backup = directory.path().join("snapshot.sqlite");
        std::fs::File::create(&backup).unwrap();
        spool
            .online_backup(
                backup.clone(),
                16 * 1024 * 1024,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
                (),
            )
            .await
            .unwrap();
        let second = intent("trixie", 2);
        catalog.checkpoint_prepare_protocol(second.clone()).unwrap();
        catalog.checkpoint_accept(second.clone()).unwrap();
        catalog.checkpoint_activate(second.clone()).unwrap();
        let restored = rusqlite::Connection::open_with_flags(
            &backup,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let old = load(&restored, &first.key().unwrap()).unwrap();
        assert_eq!(old.active, Some(first));
        assert_ne!(old.floor, Some(second));
        let integrity: String = restored
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }
    #[test]
    fn recovered_historical_floor_remains_closed_until_current_successor_intent() {
        let directory = TempDir::new().unwrap();
        let catalog = Catalog::open(directory.path(), 4, true).unwrap();
        let first = intent("trixie", 1);
        let second = intent("trixie", 2);
        let key = first.key().unwrap();
        bootstrap(&catalog, first.clone());
        catalog.checkpoint_prepare_protocol(second.clone()).unwrap();
        // Recovery before an accepted intent cannot reopen an older backup.
        catalog
            .checkpoint_cancel_unwritten(key.clone(), Some(first), true, false)
            .unwrap();
        assert!(catalog.checkpoint_state(key.clone()).unwrap().blocked);
        catalog.checkpoint_accept(second.clone()).unwrap();
        catalog
            .checkpoint_complete_unconfirmed(second.clone())
            .unwrap();
        let state = catalog.checkpoint_state(key.clone()).unwrap();
        assert!(state.blocked);
        assert!(state.recovery_ready);
        assert_eq!(state.active, Some(second));
        let mut rollback = intent("trixie", 3);
        rollback.release_date = 1;
        assert!(catalog.checkpoint_prepare_protocol(rollback).is_err());
        let current = intent("trixie", 3);
        catalog
            .checkpoint_prepare_protocol(current.clone())
            .unwrap();
        catalog.checkpoint_accept(current.clone()).unwrap();
        catalog.checkpoint_activate(current.clone()).unwrap();
        let state = catalog.checkpoint_state(key).unwrap();
        assert!(!state.blocked);
        assert!(!state.recovery_ready);
        assert_eq!(state.active, Some(current));
    }
    #[test]
    fn candidate_highwater_does_not_move_publication_floor() {
        let directory = TempDir::new().unwrap();
        let catalog = Catalog::open(directory.path(), 4, true).unwrap();
        let first = intent("trixie", 1);
        bootstrap(&catalog, first.clone());
        let key = first.key().unwrap();
        catalog
            .publication_observe(key.clone(), "b".repeat(64), 10, "b".repeat(64), 10)
            .unwrap();
        assert!(
            catalog
                .publication_observe(key.clone(), "c".repeat(64), 9, "c".repeat(64), 11)
                .is_err()
        );
        assert!(
            catalog
                .publication_observe(key.clone(), "c".repeat(64), 10, "c".repeat(64), 12)
                .is_err()
        );
        assert_eq!(catalog.checkpoint_state(key).unwrap().floor, Some(first));
    }
}
