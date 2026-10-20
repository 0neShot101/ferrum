//! Bounded, query-only captured-package projections. No provider client or ledger
//! mutation is reachable from this module; remote state is recorded evidence only.
use crate::catalog::CatalogError;
use crate::{Spool, SpoolError};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryFilter {
    pub repository: Option<String>,
    pub suite: Option<String>,
    pub digest_prefix: Option<String>,
    pub path_prefix: Option<String>,
    pub cache_status: Option<String>,
    pub remote_status: Option<String>,
}
impl InventoryFilter {
    pub fn validate(&self) -> bool {
        self.repository.as_ref().is_none_or(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }) && self
            .suite
            .as_ref()
            .is_none_or(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
            && self.digest_prefix.as_ref().is_none_or(|s| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            && self
                .path_prefix
                .as_ref()
                .is_none_or(|s| s.len() <= 8192 && !s.chars().any(char::is_control))
            && self
                .cache_status
                .as_ref()
                .is_none_or(|s| CACHE_STATES.contains(&s.as_str()))
            && self
                .remote_status
                .as_ref()
                .is_none_or(|s| REMOTE_STATES.contains(&s.as_str()))
    }
}
const CACHE_STATES: &[&str] = &[
    "resident_pinned",
    "resident_cached",
    "resident_staged",
    "evicting",
    "remote_only",
];
const REMOTE_STATES: &[&str] = &[
    "quarantined",
    "gc_pending",
    "admitted_filling",
    "outbox_uploading",
    "outbox_backoff",
    "outbox_queued",
    "verified_durable",
    "pending_verification",
    "recorded_unverified",
];

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedPackage {
    pub repository: String,
    pub path: String,
    pub path_hash: String,
    pub digest: String,
    pub size: String,
    pub generation: String,
    pub recorded_suite: Option<String>,
    pub proof_durable: bool,
    pub receipt_verified: bool,
    pub referenced: bool,
    pub first_capture: i64,
    pub retain_until: i64,
    pub cache_status: String,
    pub remote_status: String,
    pub derived_residency: bool,
}
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventorySummary {
    pub paths: String,
    pub blobs: String,
    pub blob_bytes: String,
    pub resident_blobs: String,
    pub resident_bytes: String,
    pub verified_blobs: String,
    pub verified_bytes: String,
}
#[derive(Debug)]
pub struct InventoryPage {
    pub items: Vec<CapturedPackage>,
    pub has_more: bool,
}

// A reader connection is reused by the catalog worker. Always remove our hook,
// including error/unwind paths, before handing it back to unrelated operations.
struct Deadline<'a>(&'a Connection);
impl Drop for Deadline<'_> {
    fn drop(&mut self) {
        let _ = self.0.progress_handler(0, None::<fn() -> bool>);
    }
}
fn bounded<T>(
    connection: &Connection,
    operation: impl FnOnce(&Connection) -> Result<T, CatalogError>,
) -> Result<T, CatalogError> {
    let deadline = Instant::now() + Duration::from_millis(250);
    let _ = connection.progress_handler(1000, Some(move || Instant::now() >= deadline));
    let _guard = Deadline(connection);
    let result = operation(connection);
    if matches!(&result, Err(CatalogError::Sql(rusqlite::Error::SqliteFailure(code, _)))
        if code.code == rusqlite::ErrorCode::OperationInterrupted)
    {
        Err(CatalogError::Busy)
    } else {
        result
    }
}
fn like_prefix(value: Option<&str>) -> Option<String> {
    value.map(|s| {
        let mut result = String::with_capacity(s.len() + 1);
        for c in s.chars() {
            if matches!(c, '%' | '_' | '\\') {
                result.push('\\');
            }
            result.push(c);
        }
        result.push('%');
        result
    })
}
// The only suite association claimed here is that of the recorded proof. A
// capture path is not a complete historical package-to-suite index.
const PROJECTION: &str = "SELECT p.repository,p.path,p.digest,b.size,p.generation,
    COALESCE(g.suite,json_extract(f.manifest,'$.suite')),f.durable,p.receipt_verified,p.referenced,b.first_capture,p.retain_until,
    CASE WHEN o.resident=2 THEN 'evicting'
         WHEN COALESCE(o.resident,0)=0 THEN 'remote_only'
         WHEN o.generation_references>0 THEN 'resident_pinned'
         WHEN o.upload_state=0 AND d.digest IS NULL THEN 'resident_staged'
         ELSE 'resident_cached' END AS cache_status,
    CASE WHEN q.key IS NOT NULL OR COALESCE(x.quarantined,0)=1 THEN 'quarantined'
         WHEN b.gc_pending=1 THEN 'gc_pending'
         WHEN a.digest IS NOT NULL THEN 'admitted_filling'
         WHEN m.key IS NOT NULL THEN 'outbox_uploading'
         WHEN x.next_attempt>unixepoch() THEN 'outbox_backoff'
         WHEN x.digest IS NOT NULL THEN 'outbox_queued'
         WHEN b.verify_after>0 THEN 'pending_verification'
         WHEN b.readback_verified=1 AND p.receipt_verified=1 AND f.durable=1 AND COALESCE(r.committed,0)=1 AND r.size=b.size THEN 'verified_durable'
         WHEN p.receipt_verified=0 THEN 'pending_verification'
         ELSE 'recorded_unverified' END AS remote_status,
    d.digest IS NOT NULL,p.path_hash
    FROM capture_paths p JOIN capture_blobs b ON b.digest=p.digest
    JOIN capture_proofs f ON f.generation=p.generation
    LEFT JOIN public_generations g ON g.generation=p.generation AND g.repository=p.repository
    LEFT JOIN objects o ON o.digest=p.digest AND o.size=b.size
    LEFT JOIN derived_residency d ON d.digest=p.digest
    LEFT JOIN capture_admissions a ON a.digest=p.digest
    LEFT JOIN capture_outbox x ON x.digest=p.digest
    LEFT JOIN remote_provider provider ON provider.id=1
    LEFT JOIN remote_storage r ON r.key=provider.package_prefix || 'v1/objects/sha256/' || p.digest
    LEFT JOIN remote_quarantine q ON q.key=provider.package_prefix || 'v1/objects/sha256/' || p.digest
    LEFT JOIN multipart_uploads m ON m.key=provider.package_prefix || 'v1/objects/sha256/' || p.digest";
fn package(row: &rusqlite::Row<'_>) -> rusqlite::Result<CapturedPackage> {
    let size: i64 = row.get(3)?;
    let size =
        u64::try_from(size).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, size))?;
    Ok(CapturedPackage {
        repository: row.get(0)?,
        path: row.get(1)?,
        digest: row.get(2)?,
        size: size.to_string(),
        generation: row.get(4)?,
        recorded_suite: row.get(5)?,
        proof_durable: row.get(6)?,
        receipt_verified: row.get(7)?,
        referenced: row.get(8)?,
        first_capture: row.get(9)?,
        retain_until: row.get(10)?,
        cache_status: row.get(11)?,
        remote_status: row.get(12)?,
        derived_residency: row.get(13)?,
        path_hash: row.get(14)?,
    })
}
fn prefix_end(prefix: &str) -> Option<String> {
    let mut end = prefix.to_owned();
    while let Some(last) = end.pop() {
        let next = u32::from(last).checked_add(1)?;
        let next = if next == 0xd800 { 0xe000 } else { next };
        if let Some(next) = char::from_u32(next) {
            end.push(next);
            return Some(end);
        }
    }
    None
}
fn page(
    connection: &Connection,
    filter: &InventoryFilter,
    after: Option<(&str, &str)>,
    limit: usize,
) -> Result<InventoryPage, CatalogError> {
    let (repository, path) = after.unwrap_or(("", ""));
    // Mandatory tuple range drives the primary key even when optional filters
    // are highly selective. The progress deadline also bounds rejected rows.
    let repository_clause = if filter.repository.is_some() {
        "p.repository=?3"
    } else {
        "?3 IS NULL"
    };
    let path_end = filter.path_prefix.as_deref().and_then(prefix_end);
    let path_end_clause = if path_end.is_some() {
        "p.path<?11"
    } else {
        "?11 IS NULL"
    };
    let sql = format!("{PROJECTION} WHERE (p.repository,p.path)>(?1,?2)
        AND {repository_clause} AND (?4 IS NULL OR COALESCE(g.suite,json_extract(f.manifest,'$.suite'))=?4)
        AND (?5 IS NULL OR p.digest LIKE ?5 ESCAPE '\\')
        AND (?6 IS NULL OR p.path LIKE ?6 ESCAPE '\\')
        AND (?7 IS NULL OR cache_status=?7) AND (?8 IS NULL OR remote_status=?8)
        AND p.path>=?10 AND {path_end_clause}
        ORDER BY p.repository,p.path LIMIT ?9");
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(params![
        repository,
        path,
        filter.repository,
        filter.suite,
        like_prefix(filter.digest_prefix.as_deref()),
        like_prefix(filter.path_prefix.as_deref()),
        filter.cache_status,
        filter.remote_status,
        (limit + 1) as i64,
        filter.path_prefix.as_deref().unwrap_or(""),
        path_end
    ])?;
    let mut items = Vec::with_capacity(limit);
    let mut bytes = 0;
    let mut has_more = false;
    while let Some(row) = rows.next()? {
        if items.len() == limit {
            has_more = true;
            break;
        }
        let item = package(row)?;
        // Conservative JSON bound (six bytes per UTF-8 byte), avoiding a
        // throwaway serialization/allocation per row. HTTP may duplicate the
        // filename for display, so keep additional envelope headroom.
        let text_bytes = item.repository.len()
            + item.path.len()
            + item.path_hash.len()
            + item.digest.len()
            + item.size.len()
            + item.generation.len()
            + item.recorded_suite.as_ref().map_or(0, String::len)
            + item.cache_status.len()
            + item.remote_status.len();
        let size = text_bytes.saturating_mul(6).saturating_add(1024);
        if bytes + size > 512 * 1024 {
            has_more = true;
            break;
        }
        bytes += size;
        items.push(item);
    }
    Ok(InventoryPage { items, has_more })
}
fn summary(connection: &Connection) -> Result<InventorySummary, CatalogError> {
    Ok(connection.query_row("WITH blobs AS (
        SELECT b.size,COALESCE(o.resident,0) AS resident,
          b.readback_verified=1 AND b.gc_pending=0 AND b.verify_after=0
          AND EXISTS(SELECT 1 FROM capture_paths p JOIN capture_proofs f ON f.generation=p.generation
              WHERE p.digest=b.digest AND p.receipt_verified=1 AND f.durable=1)
          AND EXISTS(SELECT 1 FROM remote_storage r JOIN remote_provider v ON v.id=1
              WHERE r.key=v.package_prefix || 'v1/objects/sha256/' || b.digest AND r.committed=1 AND r.size=b.size)
          AND NOT EXISTS(SELECT 1 FROM remote_quarantine q JOIN remote_provider v ON v.id=1
              WHERE q.key=v.package_prefix || 'v1/objects/sha256/' || b.digest)
          AND NOT EXISTS(SELECT 1 FROM capture_outbox x WHERE x.digest=b.digest)
          AND NOT EXISTS(SELECT 1 FROM capture_admissions a WHERE a.digest=b.digest)
          AND NOT EXISTS(SELECT 1 FROM multipart_uploads m JOIN remote_provider v ON v.id=1
              WHERE m.key=v.package_prefix || 'v1/objects/sha256/' || b.digest) AS verified
        FROM capture_blobs b LEFT JOIN objects o ON o.digest=b.digest AND o.size=b.size)
        SELECT (SELECT COUNT(*) FROM capture_paths),COUNT(*),COALESCE(SUM(size),0),
          COALESCE(SUM(CASE WHEN resident=1 THEN 1 ELSE 0 END),0),
          COALESCE(SUM(CASE WHEN resident=1 THEN size ELSE 0 END),0),
          COALESCE(SUM(CASE WHEN verified THEN 1 ELSE 0 END),0),
          COALESCE(SUM(CASE WHEN verified THEN size ELSE 0 END),0)
        FROM blobs", [], |row| {
            let col = |idx| -> rusqlite::Result<String> {
                let v: i64 = row.get(idx)?;
                u64::try_from(v).map(|u| u.to_string()).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(idx, v))
            };
            Ok(InventorySummary {
                paths: col(0)?, blobs: col(1)?,
                blob_bytes: col(2)?, resident_blobs: col(3)?,
                resident_bytes: col(4)?, verified_blobs: col(5)?,
                verified_bytes: col(6)?,
            })
        })?)
}
impl Spool {
    pub fn captured_packages(
        &self,
        filter: InventoryFilter,
        after: Option<(String, String)>,
        limit: usize,
    ) -> Result<InventoryPage, SpoolError> {
        if !filter.validate() || !(1..=100).contains(&limit) {
            return Err(CatalogError::InvalidState.into());
        }
        Ok(self.durable_catalog()?.read(move |connection| {
            bounded(connection, |connection| {
                page(
                    connection,
                    &filter,
                    after.as_ref().map(|(r, p)| (r.as_str(), p.as_str())),
                    limit,
                )
            })
        })?)
    }
    pub fn captured_package(
        &self,
        repository: String,
        path: String,
    ) -> Result<Option<CapturedPackage>, SpoolError> {
        if repository.len() > 64 || path.len() > 8192 {
            return Err(CatalogError::InvalidState.into());
        }
        Ok(self.durable_catalog()?.read(move |connection| {
            bounded(connection, |connection| {
                Ok(connection
                    .query_row(
                        &format!("{PROJECTION} WHERE p.repository=?1 AND p.path=?2"),
                        params![repository, path],
                        package,
                    )
                    .optional()?)
            })
        })?)
    }
    /// Indexed opaque-ID lookup; a hash collision is an error, never an alias.
    pub fn captured_package_by_hash(
        &self,
        repository: String,
        path_hash: String,
    ) -> Result<Option<CapturedPackage>, SpoolError> {
        let filter = InventoryFilter {
            repository: Some(repository.clone()),
            digest_prefix: Some(path_hash.clone()),
            ..InventoryFilter::default()
        };
        if path_hash.len() != 64 || !filter.validate() {
            return Err(CatalogError::InvalidState.into());
        }
        Ok(self.durable_catalog()?.read(move |connection| bounded(connection, |connection| {
            let transaction = connection.unchecked_transaction()?;
            let paths = {
                let mut statement = transaction.prepare("SELECT path FROM capture_paths WHERE repository=?1 AND path_hash=?2 LIMIT 2")?;
                statement.query_map(params![repository,path_hash], |row| row.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?
            };
            let result = match paths.as_slice() {
                [] => None,
                [path] => Some(transaction.query_row(&format!("{PROJECTION} WHERE p.repository=?1 AND p.path=?2"), params![repository,path], package)?),
                _ => return Err(CatalogError::InvalidState),
            };
            transaction.commit()?;
            Ok(result)
        }))?)
    }
    pub fn captured_summary(&self) -> Result<InventorySummary, SpoolError> {
        Ok(self
            .durable_catalog()?
            .read(|connection| bounded(connection, summary))?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    fn database() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE objects(digest TEXT PRIMARY KEY,size INTEGER,resident INTEGER,upload_state INTEGER,generation_references INTEGER);
            CREATE TABLE derived_residency(digest TEXT PRIMARY KEY);
            CREATE TABLE public_generations(generation TEXT PRIMARY KEY,repository TEXT,suite TEXT);").unwrap();
        for (_, sql) in super::super::SCHEMA
            .iter()
            .chain(crate::budget::SCHEMA)
            .chain(crate::budget::provider::SCHEMA)
        {
            connection.execute_batch(sql).unwrap();
        }
        connection
            .execute(
                "INSERT INTO capture_proofs(generation,manifest,durable) VALUES('g','{}',1)",
                [],
            )
            .unwrap();
        connection
            .execute("INSERT INTO capture_blobs VALUES('a',7,1,100,0,0,0)", [])
            .unwrap();
        for path in ["pool/a%_", "pool/b"] {
            connection
                .execute(
                    "INSERT INTO capture_paths VALUES('debian',?1,?2,'a','g',0,1,100)",
                    params![path, "0".repeat(64)],
                )
                .unwrap();
        }
        connection
            .execute("INSERT INTO remote_budget VALUES(1,1,2,3,3,1)", [])
            .unwrap();
        connection
    }
    #[test]
    fn catalog_only_reads_deduplicate_and_do_not_mutate_ledger() {
        // No S3Store/client is constructed or passed: query-only SQLite suffices.
        let connection = database();
        connection.execute_batch("PRAGMA query_only=ON").unwrap();
        let changes = connection.total_changes();
        let totals = bounded(&connection, summary).unwrap();
        assert_eq!(
            (
                totals.paths.as_str(),
                totals.blobs.as_str(),
                totals.blob_bytes.as_str()
            ),
            ("2", "1", "7")
        );
        assert_eq!(totals.verified_blobs, "0");
        let first = bounded(&connection, |c| {
            page(c, &InventoryFilter::default(), None, 1)
        })
        .unwrap();
        assert!(first.has_more);
        let next = bounded(&connection, |c| {
            page(
                c,
                &InventoryFilter::default(),
                Some(("debian", &first.items[0].path)),
                1,
            )
        })
        .unwrap();
        assert_eq!(next.items[0].path, "pool/b");
        assert!(!next.has_more);
        let filter = InventoryFilter {
            path_prefix: Some("pool/a%_".into()),
            ..InventoryFilter::default()
        };
        assert_eq!(
            bounded(&connection, |c| page(c, &filter, None, 50))
                .unwrap()
                .items
                .len(),
            1
        );
        assert_eq!(changes, connection.total_changes());
        assert_eq!(
            connection
                .query_row("SELECT period,high_time,used FROM remote_budget", [], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .unwrap(),
            (1, 2, 3)
        );
    }
    #[test]
    fn deadline_interrupts_work_and_is_cleared_after_error() {
        let connection = database();
        let result = bounded(&connection, |connection| {
            Ok(connection.query_row("WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<1000000000) SELECT SUM(v) FROM n",[],|r| r.get::<_,i64>(0))?)
        });
        assert!(matches!(result, Err(CatalogError::Busy)));
        // The interrupted deadline has expired. A leaked hook would interrupt
        // this independent statement once it crosses the instruction interval.
        assert_eq!(connection.query_row("WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<10000) SELECT SUM(v) FROM n",[],|r| r.get::<_,i64>(0)).unwrap(),50005000);
        assert!(
            !InventoryFilter {
                digest_prefix: Some("%".into()),
                ..InventoryFilter::default()
            }
            .validate()
        );
    }
}
