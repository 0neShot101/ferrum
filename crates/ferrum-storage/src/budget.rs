//! Shared single-bucket logical-storage and UTC download admission.
//! Reservations are committed before connector dispatch; unfinished attempts are
//! charged in full after restart. Initial allowance is an explicit operator action.
//! Wall time is sampled only on the serialized catalog writer, never by callers
//! before queueing. Any backwards writer sample still permanently refuses admission;
//! queue order cannot turn an older operation's start time into a clock rollback.
pub mod provider;

pub use provider::{LegacyProviderAdoption, ProviderIdentity};

use crate::catalog::CatalogError;
use crate::{Spool, SpoolError};
use rusqlite::{OptionalExtension, params};

pub(crate) const SCHEMA: &[(&str, &str)] = &[
    (
        "remote_budget",
        "CREATE TABLE remote_budget (id INTEGER PRIMARY KEY CHECK(id=1), period INTEGER NOT NULL, high_time INTEGER NOT NULL, used INTEGER NOT NULL CHECK(used>=0), data_used INTEGER NOT NULL CHECK(data_used>=0), certain INTEGER NOT NULL CHECK(certain IN (0,1))) STRICT",
    ),
    (
        "download_reservations",
        "CREATE TABLE download_reservations (id TEXT PRIMARY KEY, amount INTEGER NOT NULL CHECK(amount>=0), class INTEGER NOT NULL CHECK(class IN (0,1)), period INTEGER NOT NULL) STRICT",
    ),
    (
        "readback_escrow",
        "CREATE TABLE readback_escrow (id TEXT PRIMARY KEY REFERENCES download_reservations(id) ON DELETE CASCADE, key TEXT NOT NULL) STRICT",
    ),
    (
        "qualification_ownership",
        "CREATE TABLE qualification_ownership (key TEXT PRIMARY KEY, token TEXT NOT NULL, etag TEXT, deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)), cleanup_upload INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_upload>=0), cleanup_download INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_download>=0), creates INTEGER NOT NULL DEFAULT 0 CHECK(creates BETWEEN 0 AND 2)) STRICT",
    ),
    (
        "qualification_budget",
        "CREATE TABLE qualification_budget (id INTEGER PRIMARY KEY CHECK(id=1), run TEXT, upload_limit INTEGER NOT NULL CHECK(upload_limit>0), download_limit INTEGER NOT NULL CHECK(download_limit>0), storage_limit INTEGER NOT NULL CHECK(storage_limit>0), uploaded INTEGER NOT NULL DEFAULT 0 CHECK(uploaded>=0), downloaded INTEGER NOT NULL DEFAULT 0 CHECK(downloaded>=0), cleanup_upload INTEGER NOT NULL CHECK(cleanup_upload>=0), cleanup_download INTEGER NOT NULL CHECK(cleanup_download>=0), general_upload INTEGER NOT NULL CHECK(general_upload>=0), general_download INTEGER NOT NULL CHECK(general_download>=0)) STRICT",
    ),
    (
        "remote_storage",
        "CREATE TABLE remote_storage (key TEXT PRIMARY KEY, size INTEGER NOT NULL CHECK(size>=0), class INTEGER NOT NULL CHECK(class IN (0,1)), committed INTEGER NOT NULL DEFAULT 0 CHECK(committed IN (0,1)), mutation_intent INTEGER NOT NULL DEFAULT 0 CHECK(mutation_intent IN (0,1)), intent_at INTEGER NOT NULL DEFAULT 0, gc_owned INTEGER NOT NULL DEFAULT 0 CHECK(gc_owned IN (0,1))) STRICT",
    ),
    (
        "remote_quarantine",
        "CREATE TABLE remote_quarantine (key TEXT PRIMARY KEY) STRICT",
    ),
    (
        "multipart_uploads",
        "CREATE TABLE multipart_uploads (key TEXT PRIMARY KEY, upload_id TEXT NOT NULL, started INTEGER NOT NULL, size INTEGER NOT NULL CHECK(size>=0), completing INTEGER NOT NULL CHECK(completing IN (0,1)), uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_bytes>=0 AND uploaded_bytes<=size), discovered INTEGER NOT NULL DEFAULT 0 CHECK(discovered IN (0,1))) STRICT",
    ),
    (
        "remote_health",
        "CREATE TABLE remote_health (id INTEGER PRIMARY KEY CHECK(id=1), forbidden INTEGER NOT NULL CHECK(forbidden IN (0,1))) STRICT",
    ),
    (
        "remote_storage_totals",
        "CREATE TABLE remote_storage_totals (id INTEGER PRIMARY KEY CHECK(id=1), total INTEGER NOT NULL CHECK(total>=0), data INTEGER NOT NULL CHECK(data>=0 AND data<=total)) STRICT",
    ),
];
pub(crate) const AUX_SCHEMA: &[(&str, &str)] = &[
    (
        "remote_storage_unstarted",
        "CREATE INDEX remote_storage_unstarted ON remote_storage(committed,mutation_intent,class,key)",
    ),
    (
        "remote_storage_add",
        "CREATE TRIGGER remote_storage_add AFTER INSERT ON remote_storage BEGIN INSERT OR IGNORE INTO remote_storage_totals(id,total,data) VALUES(1,0,0); UPDATE remote_storage_totals SET total=total+NEW.size,data=data+CASE WHEN NEW.class=0 THEN NEW.size ELSE 0 END WHERE id=1; END",
    ),
    (
        "remote_storage_change",
        "CREATE TRIGGER remote_storage_change AFTER UPDATE OF size,class ON remote_storage BEGIN UPDATE remote_storage_totals SET total=total-OLD.size+NEW.size,data=data-CASE WHEN OLD.class=0 THEN OLD.size ELSE 0 END+CASE WHEN NEW.class=0 THEN NEW.size ELSE 0 END WHERE id=1; END",
    ),
    (
        "remote_storage_remove",
        "CREATE TRIGGER remote_storage_remove AFTER DELETE ON remote_storage BEGIN UPDATE remote_storage_totals SET total=total-OLD.size,data=data-CASE WHEN OLD.class=0 THEN OLD.size ELSE 0 END WHERE id=1; END",
    ),
];
const TIB: u64 = 1024 * 1024 * 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetClass {
    Package,
    Control,
}
impl BudgetClass {
    pub(crate) fn sql(self) -> i64 {
        i64::from(self == Self::Control)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct BudgetLimits {
    pub storage: u64,
    pub storage_control: u64,
    pub monthly_download: u64,
    pub download_control: u64,
}
impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            storage: TIB,
            storage_control: 100 * GIB,
            monthly_download: TIB,
            download_control: 100 * GIB,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct QualificationLimits {
    pub upload: u64,
    pub download: u64,
    pub storage: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct QualificationUsage {
    pub uploaded: u64,
    pub downloaded: u64,
    pub cleanup_upload: u64,
    pub cleanup_download: u64,
    pub limits: QualificationLimits,
}
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("remote budget exhausted or usage/clock reconciliation required")]
    Refused,
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error(transparent)]
    Spool(#[from] SpoolError),
}
#[derive(Clone)]
pub struct BudgetLedger {
    spool: Spool,
    limits: BudgetLimits,
    clock: LedgerClock,
}
#[derive(Debug)]
pub struct DownloadReservation {
    id: String,
    maximum: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct BudgetUsage {
    pub download: u64,
    pub package_download: u64,
    pub storage: u64,
    pub certain: bool,
}

/// A single read-only ledger snapshot. Reservations are reported, never settled.
#[derive(Clone, Debug)]
pub struct BudgetDiagnostics {
    pub period: i64,
    pub high_time: i64,
    pub download: u64,
    pub package_download: u64,
    pub certain: bool,
    pub storage: u64,
    pub package_storage: u64,
    pub reservation_count: u64,
    pub reserved_download: u64,
    pub reserved_package_download: u64,
    pub escrow_count: u64,
    pub escrow_bytes: u64,
    pub forbidden: bool,
    pub provider: Option<ProviderIdentity>,
}

#[derive(Clone, Default)]
struct LedgerClock {
    #[cfg(test)]
    injected: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
}

impl LedgerClock {
    fn now(&self) -> Result<i64, CatalogError> {
        #[cfg(test)]
        if let Some(clock) = &self.injected {
            return Ok(clock.load(std::sync::atomic::Ordering::SeqCst));
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
            .ok_or(CatalogError::InvalidState)
    }
}

fn number(value: u64) -> Result<i64, CatalogError> {
    i64::try_from(value).map_err(|_| CatalogError::InvalidState)
}
// Gregorian civil month from UTC epoch seconds, with no local timezone dependency.
fn month(seconds: i64) -> Result<i64, CatalogError> {
    if seconds < 0 {
        return Err(CatalogError::InvalidState);
    }
    let z = seconds / 86_400 + 719_468;
    let era = z / 146_097;
    let day = z - era * 146_097;
    let year = (day - day / 1460 + day / 36_524 - day / 146_096) / 365;
    let ordinal = day - (365 * year + year / 4 - year / 100);
    let part = (5 * ordinal + 2) / 153;
    let calendar_month = part + if part < 10 { 3 } else { -9 };
    Ok((year + era * 400 + i64::from(calendar_month <= 2)) * 12 + calendar_month - 1)
}

fn authorize_namespace(connection: &rusqlite::Connection, key: &str) -> Result<(), CatalogError> {
    let prefixes: Option<(String, String)> = connection
        .query_row(
            "SELECT package_prefix,checkpoint_prefix FROM remote_provider WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (pkg, chk) =
        prefixes
            .as_ref()
            .map_or(("linux-packages/", "linux-checkpoints/"), |(p, c)| {
                (
                    p.split_once("_ferrum-b07/").map_or(p.as_str(), |(b, _)| b),
                    c.split_once("_ferrum-b07/").map_or(c.as_str(), |(b, _)| b),
                )
            });
    let suffix = key
        .strip_prefix(pkg)
        .or_else(|| key.strip_prefix(chk))
        .ok_or(CatalogError::InvalidState)?;
    let binding: Option<Option<String>> = connection
        .query_row(
            "SELECT run FROM qualification_budget WHERE id=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let allowed = match binding {
        None => suffix.is_empty() || suffix.starts_with("v1/"),
        Some(None) => false,
        Some(Some(run)) => {
            run.len() == 32
                && run
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && suffix
                    .strip_prefix("_ferrum-b07/")
                    .and_then(|scoped| scoped.split_once('/'))
                    .is_some_and(|(actual, tail)| {
                        actual == run && (tail.is_empty() || tail.starts_with("v1/"))
                    })
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(CatalogError::InvalidState)
    }
}
impl BudgetLedger {
    /// A fresh explicit private-batch allocation; INSERT never resets prior usage.
    pub fn initialize_qualification(&self, limits: QualificationLimits) -> Result<(), BudgetError> {
        if limits.upload == 0
            || limits.download == 0
            || limits.storage == 0
            || limits.upload > 8 * GIB
            || limits.download > 16 * GIB
            || limits.storage > 8 * GIB
            || limits.download > self.limits.monthly_download
            || limits.storage > self.limits.storage
        {
            return Err(BudgetError::Refused);
        }
        self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            let populated: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM remote_storage UNION ALL SELECT 1 FROM capture_state UNION ALL SELECT 1 FROM capture_blobs UNION ALL SELECT 1 FROM capture_proofs UNION ALL SELECT 1 FROM suite_checkpoints WHERE floor IS NOT NULL OR active IS NOT NULL OR pending IS NOT NULL UNION ALL SELECT 1 FROM remote_budget WHERE used<>0 OR data_used<>0 OR certain=0 UNION ALL SELECT 1 FROM download_reservations)",
                [],
                |row| row.get(0),
            )?;
            if populated {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "INSERT INTO qualification_budget(id,upload_limit,download_limit,storage_limit,cleanup_upload,cleanup_download,general_upload,general_download) VALUES(1,?1,?2,?3,?4,?5,?4,?5)",
                params![
                    number(limits.upload)?,
                    number(limits.download)?,
                    number(limits.storage)?,
                    number(limits.upload / 16)?,
                    number(limits.download / 16)?
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }
    pub fn qualification_usage(&self) -> Result<QualificationUsage, BudgetError> {
        Ok(self.spool.durable_catalog()?.read(|connection| {
            Ok(connection.query_row(
                "SELECT uploaded,downloaded,upload_limit,download_limit,storage_limit,cleanup_upload,cleanup_download FROM qualification_budget WHERE id=1",
                [],
                |row| {
                    Ok(QualificationUsage {
                        uploaded: crate::catalog::read_unsigned(row, 0)?,
                        downloaded: crate::catalog::read_unsigned(row, 1)?,
                        cleanup_upload: crate::catalog::read_unsigned(row, 5)?,
                        cleanup_download: crate::catalog::read_unsigned(row, 6)?,
                        limits: QualificationLimits {
                            upload: crate::catalog::read_unsigned(row, 2)?,
                            download: crate::catalog::read_unsigned(row, 3)?,
                            storage: crate::catalog::read_unsigned(row, 4)?,
                        },
                    })
                },
            )?)
        })?)
    }
    pub(crate) fn bind_qualification(&self, run: &str) -> Result<(), BudgetError> {
        let run = run.to_owned();
        self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            let previous: Option<String> = transaction.query_row(
                "SELECT run FROM qualification_budget WHERE id=1",
                [],
                |row| row.get(0),
            )?;
            if previous.as_ref().is_some_and(|previous| previous != &run) {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute("UPDATE qualification_budget SET run=?1 WHERE id=1", [run])?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }
    pub(crate) fn reserve_qualification(
        &self,
        upload: u64,
        download: u64,
        cleanup: bool,
        key: Option<&str>,
    ) -> Result<(), BudgetError> {
        let key = key.map(str::to_owned);
        let admitted = self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            let changed = if !cleanup {
                transaction.execute(
                    "UPDATE qualification_budget SET uploaded=uploaded+?1,downloaded=downloaded+?2 WHERE id=1 AND run IS NOT NULL AND uploaded<=upload_limit-cleanup_upload-?1 AND downloaded<=download_limit-cleanup_download-?2",
                    params![number(upload)?, number(download)?],
                )?
            } else {
                let allowed = if let Some(key) = &key {
                    transaction.execute(
                        "UPDATE qualification_ownership SET cleanup_upload=cleanup_upload-?1,cleanup_download=cleanup_download-?2 WHERE key=?3 AND deleted=0 AND cleanup_upload>=?1 AND cleanup_download>=?2",
                        params![number(upload)?, number(download)?, key],
                    )?
                } else {
                    transaction.execute(
                        "UPDATE qualification_budget SET general_upload=general_upload-?1,general_download=general_download-?2 WHERE id=1 AND general_upload>=?1 AND general_download>=?2",
                        params![number(upload)?, number(download)?],
                    )?
                };
                if allowed == 1 {
                    transaction.execute(
                        "UPDATE qualification_budget SET uploaded=uploaded+?1,downloaded=downloaded+?2,cleanup_upload=cleanup_upload-?1,cleanup_download=cleanup_download-?2 WHERE id=1",
                        params![number(upload)?, number(download)?],
                    )?
                } else {
                    0
                }
            };
            transaction.commit()?;
            Ok(changed == 1)
        })?;
        if admitted {
            Ok(())
        } else {
            Err(BudgetError::Refused)
        }
    }
    pub(crate) fn qualification_bound(&self) -> Result<bool, BudgetError> {
        Ok(self.spool.durable_catalog()?.read(|connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM qualification_budget WHERE id=1)",
                [],
                |row| row.get(0),
            )?)
        })?)
    }
    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn qualification_run(&self) -> Result<Option<Option<String>>, BudgetError> {
        Ok(self.spool.durable_catalog()?.read(|connection| {
            Ok(connection
                .query_row(
                    "SELECT run FROM qualification_budget WHERE id=1",
                    [],
                    |row| row.get(0),
                )
                .optional()?)
        })?)
    }
    pub(crate) fn monthly_download_limit(&self) -> u64 {
        self.limits.monthly_download
    }
    fn validate(limits: BudgetLimits) -> Result<(), BudgetError> {
        if limits.storage == 0
            || limits.monthly_download == 0
            || limits.storage_control > limits.storage
            || limits.download_control > limits.monthly_download
            || limits.storage > i64::MAX as u64
            || limits.monthly_download > i64::MAX as u64
        {
            return Err(BudgetError::Refused);
        }
        Ok(())
    }
    /// Initializes unused accounting only. A one-use fresh marker permits the
    /// first provider open to bind it; configured initialization should bind now.
    pub fn initialize(spool: Spool, limits: BudgetLimits) -> Result<Self, BudgetError> {
        Self::initialize_with_provider_and_clock(spool, limits, LedgerClock::default(), None)
    }
    /// Initialize allowance and its configured destination in one transaction.
    pub fn initialize_for_provider(
        spool: Spool,
        limits: BudgetLimits,
        provider: &ProviderIdentity,
    ) -> Result<Self, BudgetError> {
        Self::initialize_with_provider_and_clock(
            spool,
            limits,
            LedgerClock::default(),
            Some(provider.clone()),
        )
    }
    #[cfg(test)]
    fn initialize_with_clock(
        spool: Spool,
        limits: BudgetLimits,
        clock: LedgerClock,
    ) -> Result<Self, BudgetError> {
        Self::initialize_with_provider_and_clock(spool, limits, clock, None)
    }
    fn initialize_with_provider_and_clock(
        spool: Spool,
        limits: BudgetLimits,
        clock: LedgerClock,
        provider: Option<ProviderIdentity>,
    ) -> Result<Self, BudgetError> {
        Self::validate(limits)?;
        let ledger = Self {
            spool,
            limits,
            clock: clock.clone(),
        };
        ledger.spool.catalog_write(move |connection| {
            let now = clock.now()?;
            let period = month(now)?;
            let transaction = connection.transaction()?;
            if !provider::unused(&transaction)? {
                return Err(CatalogError::InvalidState);
            }
            transaction.execute(
                "INSERT INTO remote_budget(id,period,high_time,used,data_used,certain) VALUES(1,?1,?2,0,0,1)",
                params![period, now],
            )?;
            transaction.execute("INSERT INTO remote_health(id,forbidden) VALUES(1,0)", [])?;
            transaction.execute(
                "INSERT INTO remote_storage_totals(id,total,data) VALUES(1,0,0)",
                [],
            )?;
            if let Some(provider) = provider {
                provider.insert(&transaction)?;
            } else {
                transaction.execute(
                    "INSERT INTO remote_provider_initialization(id) VALUES(1)",
                    [],
                )?;
            }
            transaction.commit()?;
            Ok(())
        })?;
        Ok(ledger)
    }
    /// Reopens known usage. An absent ledger never means zero usage.
    pub fn open(spool: Spool, limits: BudgetLimits) -> Result<Self, BudgetError> {
        Self::open_with_provider_and_clock(spool, limits, LedgerClock::default(), None)
    }
    /// Check destination ownership before changing periods or settling reservations.
    pub fn open_for_provider(
        spool: Spool,
        limits: BudgetLimits,
        provider: &ProviderIdentity,
    ) -> Result<Self, BudgetError> {
        Self::open_with_provider_and_clock(
            spool,
            limits,
            LedgerClock::default(),
            Some(provider.clone()),
        )
    }
    #[cfg(test)]
    fn open_with_clock(
        spool: Spool,
        limits: BudgetLimits,
        clock: LedgerClock,
    ) -> Result<Self, BudgetError> {
        Self::open_with_provider_and_clock(spool, limits, clock, None)
    }
    fn open_with_provider_and_clock(
        spool: Spool,
        limits: BudgetLimits,
        clock: LedgerClock,
        provider: Option<ProviderIdentity>,
    ) -> Result<Self, BudgetError> {
        Self::validate(limits)?;
        let ledger = Self {
            spool,
            limits,
            clock: clock.clone(),
        };
        ledger.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM remote_budget WHERE id=1)",
                [],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(CatalogError::InvalidState);
            }
            if let Some(provider) = provider {
                provider::bind(&transaction, &provider)?;
            }
            transaction.execute(
                "INSERT INTO remote_storage_totals(id,total,data) SELECT 1,COALESCE(SUM(size),0),COALESCE(SUM(CASE WHEN class=0 THEN size ELSE 0 END),0) FROM remote_storage WHERE true ON CONFLICT(id) DO UPDATE SET total=excluded.total,data=excluded.data",
                [],
            )?;
            roll(&transaction, clock.now()?)?;
            // The reservation was charged at admission. Never refund an interrupted attempt.
            transaction.execute("DELETE FROM readback_escrow", [])?;
            transaction.execute("DELETE FROM download_reservations", [])?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(ledger)
    }
    pub fn reserve_download(
        &self,
        maximum: u64,
        class: BudgetClass,
    ) -> Result<DownloadReservation, BudgetError> {
        self.reserve_download_inner(maximum, class, false, None)
    }
    fn reserve_download_inner(
        &self,
        maximum: u64,
        class: BudgetClass,
        cleanup: bool,
        scope: Option<(String, bool)>,
    ) -> Result<DownloadReservation, BudgetError> {
        let limits = self.limits;
        let clock = self.clock.clone();
        let reservation = self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            if let Some((key, _)) = &scope {
                authorize_namespace(&transaction, key)?;
            }
            roll(&transaction, clock.now()?)?;
            let (period, used, data, certain): (i64, u64, u64, bool) = transaction.query_row(
                "SELECT period,used,data_used,certain FROM remote_budget WHERE id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                        crate::catalog::read_unsigned(row, 2)?,
                        row.get(3)?,
                    ))
                },
            )?;
            if certain
                && class == BudgetClass::Package
                && let Some((key, true)) = &scope
            {
                let credit = transaction
                    .query_row(
                        "SELECT r.id,r.amount FROM readback_escrow e JOIN download_reservations r ON r.id=e.id WHERE e.key=?1 AND r.amount>=?2 ORDER BY r.id LIMIT 1",
                        params![key, number(maximum)?],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                crate::catalog::read_unsigned(row, 1)?,
                            ))
                        },
                    )
                    .optional()?;
                if let Some((id, maximum)) = credit {
                    transaction.execute("DELETE FROM readback_escrow WHERE id=?1", [&id])?;
                    transaction.commit()?;
                    return Ok(Some(DownloadReservation {
                        id,
                        maximum,
                    }));
                }
            }
            let next = used.checked_add(maximum);
            let next_data = data.checked_add(if class == BudgetClass::Package {
                maximum
            } else {
                0
            });
            let cleanup_headroom = transaction
                .query_row(
                    "SELECT cleanup_download FROM qualification_budget WHERE id=1",
                    [],
                    |row| crate::catalog::read_unsigned(row, 0),
                )
                .optional()?
                .unwrap_or(0);
            let limit = limits.monthly_download.saturating_sub(if cleanup {
                0
            } else {
                cleanup_headroom
            });
            let allowed = certain && next.is_some_and(|value| value <= limit) && next_data.is_some_and(|value| value <= limits.monthly_download - limits.download_control);
            if !allowed {
                transaction.commit()?;
                return Ok(None);
            }
            let id = format!("{:032x}", rand::random::<u128>());
            transaction.execute(
                "UPDATE remote_budget SET used=?1,data_used=?2 WHERE id=1",
                params![
                    number(next.ok_or(CatalogError::InvalidState)?)?,
                    number(next_data.ok_or(CatalogError::InvalidState)?)?
                ],
            )?;
            transaction.execute(
                "INSERT INTO download_reservations(id,amount,class,period) VALUES(?1,?2,?3,?4)",
                params![id, number(maximum)?, class.sql(), period],
            )?;
            transaction.commit()?;
            Ok(Some(DownloadReservation {
                id,
                maximum,
            }))
        })?;
        reservation.ok_or(BudgetError::Refused)
    }

    pub(crate) fn fund_capture(&self, key: &str, maximum: u64) -> Result<(), BudgetError> {
        let key = key.to_owned();
        let limits = self.limits;
        let clock = self.clock.clone();
        let admitted = self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            authorize_namespace(&transaction, &key)?;
            roll(&transaction, clock.now()?)?;
            let (period, used, data, certain): (i64, u64, u64, bool) = transaction.query_row(
                "SELECT period,used,data_used,certain FROM remote_budget WHERE id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                        crate::catalog::read_unsigned(row, 2)?,
                        row.get(3)?,
                    ))
                },
            )?;
            let existing: u64 = transaction.query_row(
                "SELECT COUNT(*) FROM readback_escrow WHERE key=?1",
                [&key],
                |row| crate::catalog::read_unsigned(row, 0),
            )?;
            let needed = 2u64.saturating_sub(existing);
            let extra = maximum
                .checked_mul(needed)
                .ok_or(CatalogError::InvalidState)?;
            let cleanup: u64 = transaction
                .query_row(
                    "SELECT cleanup_download FROM qualification_budget WHERE id=1",
                    [],
                    |row| crate::catalog::read_unsigned(row, 0),
                )
                .optional()?
                .unwrap_or(0);
            let allowed = certain
                && used
                    .checked_add(extra)
                    .is_some_and(|n| n <= limits.monthly_download.saturating_sub(cleanup))
                && data
                    .checked_add(extra)
                    .is_some_and(|n| n <= limits.monthly_download - limits.download_control);
            if allowed {
                transaction.execute(
                    "UPDATE remote_budget SET used=used+?1,data_used=data_used+?1 WHERE id=1",
                    [number(extra)?],
                )?;
                for _ in 0..needed {
                    let id = format!("{:032x}", rand::random::<u128>());
                    transaction.execute(
                        "INSERT INTO download_reservations(id,amount,class,period) VALUES(?1,?2,0,?3)",
                        params![id, number(maximum)?, period],
                    )?;
                    transaction.execute(
                        "INSERT INTO readback_escrow(id,key) VALUES(?1,?2)",
                        params![id, key],
                    )?;
                }
            }
            transaction.commit()?;
            Ok(allowed)
        })?;
        if admitted {
            Ok(())
        } else {
            Err(BudgetError::Refused)
        }
    }

    pub(crate) fn reserve_transfer(
        &self,
        key: &str,
        maximum: u64,
        class: BudgetClass,
        use_credit: bool,
        cleanup: bool,
    ) -> Result<DownloadReservation, BudgetError> {
        self.reserve_download_inner(maximum, class, cleanup, Some((key.to_owned(), use_credit)))
    }

    pub(crate) fn release_capture_credit(&self, key: &str) -> Result<(), BudgetError> {
        let key = key.to_owned();
        let clock = self.clock.clone();
        self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            roll(&transaction, clock.now()?)?;
            let amount: i64 = transaction.query_row(
                "SELECT COALESCE(SUM(r.amount),0) FROM readback_escrow e JOIN download_reservations r ON r.id=e.id WHERE e.key=?1",
                [&key],
                |row| row.get(0),
            )?;
            transaction.execute(
                "UPDATE remote_budget SET used=used-?1,data_used=data_used-?1 WHERE id=1",
                [amount],
            )?;
            transaction.execute(
                "DELETE FROM download_reservations WHERE id IN (SELECT id FROM readback_escrow WHERE key=?1)",
                [&key],
            )?;
            transaction.execute("DELETE FROM readback_escrow WHERE key=?1", [key])?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }
    /// Call only after a bounded response reached EOF. Dropped/failed responses retain full charge.
    pub fn settle_download(
        &self,
        reservation: DownloadReservation,
        actual: u64,
    ) -> Result<(), BudgetError> {
        if actual > reservation.maximum {
            return Err(BudgetError::Refused);
        }
        let clock = self.clock.clone();
        self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            roll(&transaction, clock.now()?)?;
            let (amount, class): (u64, i64) = transaction.query_row(
                "SELECT amount,class FROM download_reservations WHERE id=?1",
                [&reservation.id],
                |row| Ok((crate::catalog::read_unsigned(row, 0)?, row.get(1)?)),
            )?;
            let refund = amount
                .checked_sub(actual)
                .ok_or(CatalogError::InvalidState)?;
            transaction.execute(
                "UPDATE remote_budget SET used=used-?1,data_used=data_used-?2 WHERE id=1",
                params![
                    number(refund)?,
                    if class == 0 { number(refund)? } else { 0 }
                ],
            )?;
            transaction.execute(
                "DELETE FROM download_reservations WHERE id=?1",
                [reservation.id],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }
    /// Persistent unique-key reservation. Mutable controls keep their largest known size.
    pub fn reserve_storage(
        &self,
        key: &str,
        size: u64,
        class: BudgetClass,
    ) -> Result<(), BudgetError> {
        let key = key.to_owned();
        let limits = self.limits;
        let admitted = self.spool.catalog_write(move |connection| {
            let transaction = connection.transaction()?;
            let certain: bool = transaction.query_row("SELECT certain FROM remote_budget WHERE id=1", [], |row| {
                row.get(0)
            })?;
            let (total, data): (u64, u64) = transaction.query_row(
                "SELECT total,data FROM remote_storage_totals WHERE id=1",
                [],
                |row| {
                    Ok((
                        crate::catalog::read_unsigned(row, 0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                    ))
                },
            )?;
            let old: Option<(u64, i64)> = transaction
                .query_row(
                    "SELECT size,class FROM remote_storage WHERE key=?1",
                    [&key],
                    |row| Ok((crate::catalog::read_unsigned(row, 0)?, row.get(1)?)),
                )
                .optional()?;
            let increment = size.saturating_sub(old.map_or(0, |(size, _)| size));
            let final_class = old.map_or(class.sql(), |(_, old_class)| old_class.min(class.sql()));
            let data_increment = if final_class == 0 {
                size.max(old.map_or(0, |(size, _)| size)).saturating_sub(
                    old.filter(|(_, class)| *class == 0)
                        .map_or(0, |(size, _)| size),
                )
            } else {
                0
            };
            let qualification: Option<u64> = transaction
                .query_row(
                    "SELECT storage_limit FROM qualification_budget WHERE id=1",
                    [],
                    |row| crate::catalog::read_unsigned(row, 0),
                )
                .optional()?;
            let allowed = certain
                && total
                    .checked_add(increment)
                    .is_some_and(|n| n <= limits.storage.min(qualification.unwrap_or(limits.storage)))
                && data
                    .checked_add(data_increment)
                    .is_some_and(|n| n <= limits.storage - limits.storage_control);
            if allowed {
                transaction.execute(
                    "INSERT INTO remote_storage(key,size,class) VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET size=MAX(size,excluded.size),class=MIN(class,excluded.class)",
                    params![key, number(size)?, final_class],
                )?;
            }
            transaction.commit()?;
            Ok(allowed)
        })?;
        if admitted {
            Ok(())
        } else {
            Err(BudgetError::Refused)
        }
    }
    /// Records existing confirmed bytes even over the cap; new reservations still
    /// refuse. Reconciliation must not hide real usage to fit an admission limit.
    pub(crate) fn record_existing_storage(
        &self,
        key: &str,
        size: u64,
        class: BudgetClass,
    ) -> Result<(), BudgetError> {
        let key = key.to_owned();
        let size = number(size)?;
        self.spool.catalog_write(move |connection| {
            connection.execute(
                "INSERT INTO remote_storage(key,size,class,committed) VALUES(?1,?2,?3,1) ON CONFLICT(key) DO UPDATE SET size=MAX(size,excluded.size),class=MIN(class,excluded.class),committed=1",
                params![key, size, class.sql()],
            )?;
            Ok(())
        })?;
        Ok(())
    }
    pub fn usage(&self) -> Result<BudgetUsage, BudgetError> {
        Self::inspect(&self.spool)
    }
    /// Read-only diagnostic: never advances wall-clock high water, UTC period,
    /// settles unfinished reservations, or initializes missing consumption.
    pub fn inspect(spool: &Spool) -> Result<BudgetUsage, BudgetError> {
        Ok(spool.durable_catalog()?.read(|connection| {
            Ok(connection.query_row(
                "SELECT used,data_used,certain,(SELECT total FROM remote_storage_totals WHERE id=1) FROM remote_budget WHERE id=1",
                [],
                |row| {
                    Ok(BudgetUsage {
                        download: crate::catalog::read_unsigned(row, 0)?,
                        package_download: crate::catalog::read_unsigned(row, 1)?,
                        certain: row.get(2)?,
                        storage: crate::catalog::read_unsigned(row, 3)?,
                    })
                },
            )?)
        })?)
    }
    /// Does not initialize, roll periods, advance time, or reconcile reservations.
    pub fn inspect_detailed(spool: &Spool) -> Result<BudgetDiagnostics, BudgetError> {
        Ok(spool.durable_catalog()?.read(|connection| {
            let transaction = connection.unchecked_transaction()?;
            let mut snapshot = transaction.query_row(
                "SELECT period,high_time,used,data_used,certain,
                 COALESCE((SELECT total FROM remote_storage_totals WHERE id=1),0),
                 COALESCE((SELECT data FROM remote_storage_totals WHERE id=1),0),
                 COALESCE((SELECT forbidden FROM remote_health WHERE id=1),0)
                 FROM remote_budget WHERE id=1", [], |row| Ok(BudgetDiagnostics {
                    period: row.get(0)?, high_time: row.get(1)?,
                    download: crate::catalog::read_unsigned(row, 2)?,
                    package_download: crate::catalog::read_unsigned(row, 3)?,
                    certain: row.get(4)?,
                    storage: crate::catalog::read_unsigned(row, 5)?,
                    package_storage: crate::catalog::read_unsigned(row, 6)?,
                    forbidden: row.get(7)?,
                    reservation_count: 0, reserved_download: 0,
                    reserved_package_download: 0, escrow_count: 0, escrow_bytes: 0,
                    provider: None,
                }),
            )?;
            (snapshot.reservation_count, snapshot.reserved_download, snapshot.reserved_package_download) =
                transaction.query_row(
                    "SELECT COUNT(*),COALESCE(SUM(amount),0),COALESCE(SUM(CASE WHEN class=0 THEN amount ELSE 0 END),0) FROM download_reservations",
                    [], |row| Ok((
                        crate::catalog::read_unsigned(row, 0)?,
                        crate::catalog::read_unsigned(row, 1)?,
                        crate::catalog::read_unsigned(row, 2)?,
                    )))?;
            (snapshot.escrow_count, snapshot.escrow_bytes) = transaction.query_row(
                "SELECT COUNT(*),COALESCE(SUM(r.amount),0) FROM readback_escrow e JOIN download_reservations r ON r.id=e.id",
                [], |row| Ok((
                    crate::catalog::read_unsigned(row, 0)?,
                    crate::catalog::read_unsigned(row, 1)?,
                )))?;
            snapshot.provider = ProviderIdentity::read(&transaction)?;
            transaction.commit()?;
            Ok(snapshot)
        })?)
    }
    pub(crate) fn spool(&self) -> &Spool {
        &self.spool
    }
}
fn roll(transaction: &rusqlite::Transaction<'_>, now: i64) -> Result<(), CatalogError> {
    let (period, high): (i64, i64) = transaction.query_row(
        "SELECT period,high_time FROM remote_budget WHERE id=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if now < high {
        transaction.execute("UPDATE remote_budget SET certain=0 WHERE id=1", [])?;
        return Ok(());
    }
    let next = month(now)?;
    if next > period {
        let (outstanding, data): (i64, i64) = transaction.query_row(
            "SELECT COALESCE(SUM(amount),0),COALESCE(SUM(CASE WHEN class=0 THEN amount ELSE 0 END),0) FROM download_reservations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        transaction.execute(
            "UPDATE remote_budget SET period=?1,used=?2,data_used=?3 WHERE id=1",
            params![next, outstanding, data],
        )?;
        transaction.execute("UPDATE download_reservations SET period=?1", [next])?;
    }
    transaction.execute("UPDATE remote_budget SET high_time=?1 WHERE id=1", [now])?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::DurableSpoolConfig;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    impl LedgerClock {
        fn at(now: i64) -> Self {
            Self {
                injected: Some(Arc::new(AtomicI64::new(now))),
            }
        }

        fn set(&self, now: i64) {
            self.injected
                .as_ref()
                .expect("injected clock")
                .store(now, Ordering::SeqCst);
        }
    }

    fn spool(root: &std::path::Path) -> Spool {
        let mut config = DurableSpoolConfig::new(root.to_owned());
        config.spool.managed_ceiling = 64 * 1024 * 1024;
        config.spool.max_object_size = 1024;
        config.free_space_floor = 0;
        config.temporary_ceiling = 1024 * 1024;
        config.metadata_temporary_reserve = 0;
        config.metadata_ceiling = 1024 * 1024;
        config.catalog_ceiling = 16 * 1024 * 1024;
        config.max_entries = 100;
        config.eviction_high_watermark = 48 * 1024 * 1024;
        config.eviction_low_watermark = 32 * 1024 * 1024;
        Spool::open_durable(config).expect("open")
    }

    #[test]
    fn clock_rollback_preserves_capture_accounting_and_refuses_after_reopen() {
        let root = tempfile::tempdir().expect("root");
        let spool = spool(&root.path().join("state"));
        let limits = BudgetLimits {
            storage: 1000,
            storage_control: 100,
            monthly_download: 1000,
            download_control: 100,
        };
        let start = 1_735_689_600;
        let clock = LedgerClock::at(start);
        let ledger = BudgetLedger::initialize_with_clock(spool.clone(), limits, clock.clone())
            .expect("initialize");
        let key = "linux-packages/v1/objects/sha256/package";
        clock.set(start + 1);
        let control = ledger
            .reserve_download(100, BudgetClass::Control)
            .expect("reserve control transfer");
        ledger.fund_capture(key, 100).expect("fund capture");
        let credit = ledger
            .reserve_transfer(key, 100, BudgetClass::Package, true, false)
            .expect("consume funded credit");
        ledger.settle_download(credit, 25).expect("settle readback");
        ledger
            .release_capture_credit(key)
            .expect("refund unused credit");
        ledger
            .settle_download(control, 20)
            .expect("settle control transfer");
        let usage = ledger.usage().expect("usage before clock rollback");
        assert!(usage.certain);
        assert_eq!((usage.download, usage.package_download), (45, 25));
        ledger
            .reserve_storage(key, 100, BudgetClass::Package)
            .expect("capture admission remains available");

        // Even a single second backwards at the writer is a real rollback, not
        // queue skew. Refusal persists after time catches up and after reopening.
        clock.set(start);
        assert!(matches!(
            ledger.reserve_download(1, BudgetClass::Control),
            Err(BudgetError::Refused)
        ));
        assert!(!ledger.usage().expect("rollback state").certain);
        assert!(matches!(
            ledger.fund_capture(key, 100),
            Err(BudgetError::Refused)
        ));
        assert!(matches!(
            ledger.reserve_storage("new", 1, BudgetClass::Control),
            Err(BudgetError::Refused)
        ));
        clock.set(start + 2);
        assert!(matches!(
            ledger.reserve_download(1, BudgetClass::Control),
            Err(BudgetError::Refused)
        ));
        drop(ledger);
        let reopened = BudgetLedger::open_with_clock(spool, limits, clock).expect("reopen");
        let usage = reopened.usage().expect("persistent refusal");
        assert!(!usage.certain);
        assert_eq!(
            (usage.download, usage.package_download, usage.storage),
            (45, 25, 100)
        );
        assert!(matches!(
            reopened.reserve_download(1, BudgetClass::Control),
            Err(BudgetError::Refused)
        ));
    }
    #[test]
    fn reservations_survive_restart_rollover_and_clock_rollback() {
        let root = tempfile::tempdir().expect("root");
        let spool = spool(&root.path().join("state"));
        let limits = BudgetLimits {
            storage: 1000,
            storage_control: 100,
            monthly_download: 1000,
            download_control: 100,
        };
        let january = 1_735_689_600;
        let february = 1_738_368_000;
        let clock = LedgerClock::at(january);
        let ledger = BudgetLedger::initialize_with_clock(spool.clone(), limits, clock.clone())
            .expect("initialize");
        let old = ledger
            .reserve_download(800, BudgetClass::Package)
            .expect("reserve");
        assert!(ledger.reserve_download(101, BudgetClass::Package).is_err());
        clock.set(february);
        let control = ledger
            .reserve_download(100, BudgetClass::Control)
            .expect("roll preserves 800 outstanding");
        ledger.settle_download(control, 10).expect("settle");
        assert_eq!(ledger.usage().expect("usage").download, 810);
        drop(old);
        drop(ledger);
        let reopened =
            BudgetLedger::open_with_clock(spool, limits, clock.clone()).expect("restart");
        assert_eq!(reopened.usage().expect("usage").download, 810);
        clock.set(january);
        assert!(reopened.reserve_download(1, BudgetClass::Control).is_err());
        assert!(!reopened.usage().expect("usage").certain);
    }
    #[test]
    fn settling_first_operation_after_utc_rollover_carries_the_crossing_transfer() {
        let root = tempfile::tempdir().expect("root");
        let spool = spool(&root.path().join("state"));
        let limits = BudgetLimits {
            storage: 1000,
            storage_control: 100,
            monthly_download: 1000,
            download_control: 100,
        };
        let january = 1_735_689_600;
        let february = 1_738_368_000;
        let clock = LedgerClock::at(january);
        let ledger =
            BudgetLedger::initialize_with_clock(spool, limits, clock.clone()).expect("initialize");
        let crossing = ledger
            .reserve_download(800, BudgetClass::Package)
            .expect("crossing");
        clock.set(february);
        ledger
            .settle_download(crossing, 700)
            .expect("settle after month boundary");
        assert_eq!(ledger.usage().expect("usage").download, 700);
        assert!(ledger.reserve_download(201, BudgetClass::Package).is_err());
    }
    #[test]
    fn inspection_is_read_only_and_never_initializes_or_settles_reservations() {
        let root = tempfile::tempdir().expect("root");
        let spool = spool(&root.path().join("state"));
        assert!(BudgetLedger::inspect(&spool).is_err());
        let now = 1_735_689_600;
        let limits = BudgetLimits {
            storage: 1000,
            storage_control: 100,
            monthly_download: 1000,
            download_control: 100,
        };
        let ledger =
            BudgetLedger::initialize_with_clock(spool.clone(), limits, LedgerClock::at(now))
                .expect("initialize");
        let _pending = ledger
            .reserve_download(100, BudgetClass::Control)
            .expect("pending");
        let before = spool
            .durable_catalog()
            .expect("catalog")
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT period,high_time,(SELECT COUNT(*) FROM download_reservations) FROM remote_budget",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?)
            })
            .expect("before");
        assert_eq!(
            BudgetLedger::inspect(&spool).expect("inspect").download,
            100
        );
        let after = spool
            .durable_catalog()
            .expect("catalog")
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT period,high_time,(SELECT COUNT(*) FROM download_reservations) FROM remote_budget",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?)
            })
            .expect("after");
        assert_eq!(before, after);
        assert_eq!(after.2, 1);
    }
    #[test]
    fn qualification_caps_cleanup_headroom_and_consumption_survive_restart_and_month() {
        let root = tempfile::tempdir().expect("root");
        let spool = spool(&root.path().join("state"));
        let january = 1_735_689_600;
        let february = 1_738_368_000;
        let limits = BudgetLimits {
            storage: 2_000_000,
            storage_control: 200_000,
            monthly_download: 2_000_000,
            download_control: 200_000,
        };
        let clock = LedgerClock::at(january);
        let ledger = BudgetLedger::initialize_with_clock(spool.clone(), limits, clock.clone())
            .expect("initialize");
        let allocation = QualificationLimits {
            upload: 1_000_000,
            download: 1_000_000,
            storage: 1_000_000,
        };
        ledger
            .initialize_qualification(allocation)
            .expect("allocation");
        ledger
            .bind_qualification("0123456789abcdef0123456789abcdef")
            .expect("run");
        assert!(
            ledger
                .bind_qualification("ffffffffffffffffffffffffffffffff")
                .is_err()
        );
        ledger
            .reserve_qualification(937_500, 937_500, false, None)
            .expect("ordinary cap");
        assert!(ledger.reserve_qualification(1, 0, false, None).is_err());
        assert!(ledger.reserve_qualification(0, 1, false, None).is_err());
        ledger
            .reserve_qualification(1000, 1000, true, None)
            .expect("reserved cleanup");
        assert!(ledger.initialize_qualification(allocation).is_err());
        drop(ledger);
        clock.set(february);
        let reopened =
            BudgetLedger::open_with_clock(spool, limits, clock).expect("restart next UTC month");
        let usage = reopened.qualification_usage().expect("usage");
        assert_eq!((usage.uploaded, usage.downloaded), (938_500, 938_500));
        assert!(reopened.reserve_qualification(1, 0, false, None).is_err());
        assert!(reopened.initialize_qualification(allocation).is_err());
    }
    #[test]
    fn existing_over_cap_objects_remain_accounted_and_refuse_new_admission() {
        let root = tempfile::tempdir().expect("root");
        let spool = spool(&root.path().join("state"));
        let ledger = BudgetLedger::initialize_with_clock(
            spool,
            BudgetLimits {
                storage: 1000,
                storage_control: 100,
                monthly_download: 1000,
                download_control: 100,
            },
            LedgerClock::at(1_735_689_600),
        )
        .expect("initialize");
        ledger
            .record_existing_storage("owned-existing", 1200, BudgetClass::Package)
            .expect("reconcile actual bytes");
        assert_eq!(ledger.usage().expect("usage").storage, 1200);
        assert!(
            ledger
                .reserve_storage("new", 1, BudgetClass::Control)
                .is_err()
        );
        ledger
            .record_existing_storage("owned-existing", 1200, BudgetClass::Control)
            .expect("idempotent no double charge");
        assert_eq!(ledger.usage().expect("usage").storage, 1200);
    }
    #[test]
    fn qualification_namespace_is_enforced_for_ordinary_and_escrow_admission() {
        let root = tempfile::tempdir().expect("root");
        let now = 1_735_689_600;
        let ledger = BudgetLedger::initialize_with_clock(
            spool(&root.path().join("state")),
            BudgetLimits::default(),
            LedgerClock::at(now),
        )
        .expect("ledger");
        let run = "0123456789abcdef0123456789abcdef";
        let key = format!(
            "linux-packages/_ferrum-b07/{run}/v1/objects/sha256/{}",
            "a".repeat(64)
        );
        assert!(
            ledger
                .reserve_transfer(&key, 100, BudgetClass::Package, false, false)
                .is_err()
        );
        ledger
            .initialize_qualification(QualificationLimits {
                upload: 1_000_000,
                download: 1_000_000,
                storage: 1_000_000,
            })
            .expect("fresh allocation");
        assert!(
            ledger
                .reserve_transfer(
                    "linux-packages/v1/objects/sha256/object",
                    100,
                    BudgetClass::Package,
                    false,
                    false
                )
                .is_err()
        );
        assert!(
            ledger
                .reserve_transfer(&key, 100, BudgetClass::Package, true, false)
                .is_err()
        );
        ledger.bind_qualification(run).expect("bind");
        ledger
            .fund_capture(&key, 100)
            .expect("two readback credits");
        for invalid in [
            "linux-packages/v1/objects/sha256/object",
            "linux-checkpoints/_ferrum-b07/ffffffffffffffffffffffffffffffff/v1/checkpoints/debian/trixie.json",
            "linux-packages/_ferrum-b07/0123456789abcdef0123456789abcdef0/v1/objects/sha256/object",
        ] {
            for credit in [false, true] {
                assert!(
                    ledger
                        .reserve_transfer(invalid, 100, BudgetClass::Package, credit, false)
                        .is_err()
                );
            }
        }
        assert_eq!(ledger.usage().expect("unchanged charge").download, 200);
        let token = ledger
            .reserve_transfer(&key, 100, BudgetClass::Package, true, false)
            .expect("owned credit");
        assert_eq!(ledger.usage().expect("no duplicate charge").download, 200);
        ledger.settle_download(token, 50).expect("settle");
        assert_eq!(
            ledger
                .usage()
                .expect("remaining credit plus actual")
                .download,
            150
        );
    }
    #[test]
    fn allocation_and_canonical_admission_cannot_both_win() {
        let root = tempfile::tempdir().expect("root");
        let now = 1_735_689_600;
        let ledger = BudgetLedger::initialize_with_clock(
            spool(&root.path().join("state")),
            BudgetLimits::default(),
            LedgerClock::at(now),
        )
        .expect("ledger");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let other_ledger = ledger.clone();
        let other_barrier = barrier.clone();
        let allocation = std::thread::spawn(move || {
            other_barrier.wait();
            other_ledger.initialize_qualification(QualificationLimits {
                upload: 1_000_000,
                download: 1_000_000,
                storage: 1_000_000,
            })
        });
        barrier.wait();
        let transfer = ledger.reserve_transfer(
            "linux-packages/v1/objects/sha256/object",
            100,
            BudgetClass::Control,
            false,
            false,
        );
        let allocated = allocation.join().expect("allocation thread").is_ok();
        assert_ne!(allocated, transfer.is_ok());
        assert_eq!(
            ledger.usage().expect("charged only admitted work").download,
            if allocated { 0 } else { 100 }
        );
    }
}
