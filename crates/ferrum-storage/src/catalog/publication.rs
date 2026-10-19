//! The single activation/reference/retirement transaction. Network work is finished
//! before the disk owner enters this module under its residency mutex.
//! Capture insertions consult the same retained/candidate path claims. Retirement
//! uses activation wall time; freshness retains the original origin confirmation.
use super::{Catalog, CatalogError};
use crate::{
    checkpoint::{PublicationIntent, SuiteKey},
    recovery::GenerationManifest,
};
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use rusqlite::{OptionalExtension, params};

pub(super) const SCHEMA: &[(&str, &str)] = &[
    (
        "suite_publication",
        "CREATE TABLE suite_publication (repository TEXT NOT NULL, suite TEXT NOT NULL, candidate_generation TEXT, observed_at INTEGER, confirmed_at INTEGER, successor_seen_at INTEGER, last_error TEXT CHECK(last_error IS NULL OR length(last_error)<=64), next_check_at INTEGER, PRIMARY KEY(repository,suite), FOREIGN KEY(repository,suite) REFERENCES suite_checkpoints(repository,suite)) STRICT",
    ),
    (
        "public_generations",
        "CREATE TABLE public_generations (generation TEXT PRIMARY KEY, repository TEXT NOT NULL, suite TEXT NOT NULL, raw_generation TEXT NOT NULL, release_content TEXT NOT NULL, release_date INTEGER NOT NULL, valid_until INTEGER, activated_at INTEGER NOT NULL, retired_at INTEGER, intent TEXT NOT NULL, manifest TEXT NOT NULL, FOREIGN KEY(repository,suite) REFERENCES suite_checkpoints(repository,suite)) STRICT",
    ),
    (
        "publication_artifacts",
        "CREATE TABLE publication_artifacts (key TEXT PRIMARY KEY REFERENCES remote_storage(key) ON DELETE CASCADE, digest TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0)) STRICT",
    ),
    (
        "publication_candidates",
        "CREATE TABLE publication_candidates (generation TEXT PRIMARY KEY, repository TEXT NOT NULL, suite TEXT NOT NULL, UNIQUE(repository,suite), FOREIGN KEY(repository,suite) REFERENCES suite_checkpoints(repository,suite)) STRICT",
    ),
    (
        "publication_metadata",
        "CREATE TABLE publication_metadata (generation TEXT NOT NULL REFERENCES public_generations(generation) ON DELETE CASCADE, path TEXT NOT NULL, directory TEXT NOT NULL, digest TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0), sha256_alias INTEGER NOT NULL CHECK(sha256_alias IN (0,1)), sha512 TEXT, source_path TEXT NOT NULL, PRIMARY KEY(generation,path)) STRICT",
    ),
    (
        "derived_residency",
        "CREATE TABLE derived_residency (digest TEXT PRIMARY KEY REFERENCES objects(digest) ON DELETE CASCADE) STRICT",
    ),
];
pub(super) const AUX_SCHEMA: &[(&str, &str)] = &[
    (
        "public_suite_history",
        "CREATE INDEX public_suite_history ON public_generations(repository,suite,activated_at DESC,generation)",
    ),
    (
        "public_repository",
        "CREATE INDEX public_repository ON public_generations(repository,generation)",
    ),
    (
        "publication_metadata_sha256",
        "CREATE INDEX publication_metadata_sha256 ON publication_metadata(directory,digest,generation)",
    ),
    (
        "publication_metadata_sha512",
        "CREATE INDEX publication_metadata_sha512 ON publication_metadata(directory,sha512,generation)",
    ),
];
const METADATA_GRACE: i64 = 7 * 24 * 60 * 60;

pub(super) fn check_conflicts(
    connection: &rusqlite::Connection,
    key: &SuiteKey,
    scope: &str,
) -> Result<(), CatalogError> {
    let staged: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM capture_index_generations WHERE generation=?1 AND verified=1)",
        [scope],
        |row| row.get(0),
    )?;
    if !staged {
        return Err(CatalogError::InvalidState);
    }
    let conflict: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM capture_proof_indexes n JOIN capture_index_entries e ON e.index_id=n.index_id JOIN capture_index_entries o ON o.path=e.path JOIN capture_proof_indexes m ON m.index_id=o.index_id WHERE n.generation=?1 AND (EXISTS(SELECT 1 FROM public_generations g WHERE g.generation=m.generation AND g.repository=?2) OR EXISTS(SELECT 1 FROM publication_candidates c WHERE c.generation=m.generation AND c.repository=?2)) AND (e.digest<>o.digest OR e.size<>o.size)) OR EXISTS(SELECT 1 FROM capture_proof_indexes n JOIN capture_index_entries e ON e.index_id=n.index_id JOIN capture_paths p ON p.path=e.path JOIN capture_blobs b ON b.digest=p.digest WHERE n.generation=?1 AND p.repository=?2 AND (e.digest<>p.digest OR e.size<>b.size))",
        params![scope, key.repository()],
        |row| row.get(0),
    )?;
    if conflict {
        return Err(CatalogError::InvalidState);
    }
    Ok(())
}

/// Check one origin-scoped path under the caller's insertion transaction. The
/// path index bounds this lookup without materializing a per-package claim map.
pub(crate) fn capture_path_conflicts(
    connection: &rusqlite::Connection,
    repository: &str,
    path: &str,
    identity: ObjectIdentity,
) -> Result<bool, CatalogError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_paths p JOIN capture_blobs b ON b.digest=p.digest WHERE p.repository=?1 AND p.path=?2 AND (p.digest<>?3 OR b.size<>?4))
         OR EXISTS(SELECT 1 FROM capture_index_entries e JOIN capture_proof_indexes m ON m.index_id=e.index_id WHERE e.path=?2 AND (e.digest<>?3 OR e.size<>?4) AND
           (EXISTS(SELECT 1 FROM public_generations g WHERE g.generation=m.generation AND g.repository=?1)
            OR EXISTS(SELECT 1 FROM publication_candidates c WHERE c.generation=m.generation AND c.repository=?1)))",
            params![
                repository,
                path,
                identity.sha256.to_hex(),
                super::signed(identity.size)?
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}
const CAPTURE_GRACE: i64 = 30 * 24 * 60 * 60;

pub(crate) struct MetadataRecord {
    pub path: String,
    pub directory: String,
    pub identity: ObjectIdentity,
    pub sha256_alias: bool,
    pub sha512: Option<String>,
    pub source_path: String,
}

pub(crate) struct Activation {
    pub intent: PublicationIntent,
    pub manifest: GenerationManifest,
    pub valid_until: Option<i64>,
    pub now: i64,
    pub confirmed_at: Option<i64>,
    pub metadata: Vec<MetadataRecord>,
}
impl Catalog {
    pub(crate) fn publication_headroom(
        &self,
        manifest: &GenerationManifest,
    ) -> Result<u64, CatalogError> {
        let repository = manifest.repository.clone();
        let suite = manifest.suite.clone();
        let scope = manifest.scope_id().to_hex();
        let manifest_bytes = manifest
            .encode()
            .map_err(|_| CatalogError::InvalidState)?
            .len() as u64;
        let metadata_rows = u64::try_from(manifest.artifacts.len() + manifest.derived.len())
            .map_err(|_| CatalogError::InvalidState)?;
        self.read(move |connection| {
            let references = connection.query_row(
                "SELECT (SELECT COUNT(*) FROM generation_pins p JOIN public_generations g ON g.generation=p.generation WHERE g.repository=?1 AND g.suite=?2)+(SELECT COUNT(*) FROM capture_generation_refs r JOIN public_generations g ON g.generation=r.generation WHERE g.repository=?1 AND g.suite=?2)+(SELECT COUNT(*) FROM capture_paths WHERE repository=?1)+(SELECT COUNT(*) FROM capture_blobs b WHERE EXISTS(SELECT 1 FROM capture_index_entries e JOIN capture_proof_indexes m ON m.index_id=e.index_id WHERE m.generation=?3 AND e.digest=b.digest AND e.size=b.size))",
                params![repository, suite, scope],
                |row| super::read_unsigned(row, 0),
            )?;
            // Account complete B-tree/WAL page rewrites, not just inserted row
            // payload. Atomic retirement is refused rather than split when this
            // conservative headroom cannot fit the existing catalog ceiling.
            let rows = references
                .checked_add(metadata_rows)
                .ok_or(CatalogError::InvalidState)?;
            rows.checked_mul(32 * 1024)
                .and_then(|bytes| bytes.checked_add(manifest_bytes.checked_mul(16)?))
                .and_then(|bytes| bytes.checked_add(8 * 1024 * 1024))
                .ok_or(CatalogError::InvalidState)
        })
    }
    pub(crate) fn publication_observe(
        &self,
        key: SuiteKey,
        generation: String,
        date: i64,
        content: String,
        now: i64,
    ) -> Result<(), CatalogError> {
        self.write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT OR IGNORE INTO suite_checkpoints(repository,suite) VALUES(?1,?2)",
                params![key.repository(), key.suite()],
            )?;
            let state = super::checkpoint::load(&transaction, &key)?;
            if now < 0
                || state.observed_at.is_some_and(|old| now < old)
                || state
                    .observed_date
                    .is_some_and(|old| date < old || (date == old && state.observed_content.as_ref() != Some(&content)))
            {
                return Err(CatalogError::InvalidState);
            }
            let same_content = state
                .active
                .as_ref()
                .is_some_and(|intent| intent.release_content_sha256 == content);
            let active = same_content
                && state
                    .active
                    .as_ref()
                    .is_some_and(|intent| intent.generation_id == generation);
            let confirm = active && state.successor_seen_at.is_none() && !state.blocked;
            transaction.execute(
                "UPDATE suite_checkpoints SET observed_date=?3,observed_content=?4 WHERE repository=?1 AND suite=?2",
                params![key.repository(), key.suite(), date, content],
            )?;
            transaction.execute(
                "INSERT INTO suite_publication(repository,suite,candidate_generation,observed_at,confirmed_at,successor_seen_at) VALUES(?1,?2,?3,?4,CASE WHEN ?5 THEN ?4 END,CASE WHEN ?6 THEN ?4 END) ON CONFLICT(repository,suite) DO UPDATE SET candidate_generation=excluded.candidate_generation,observed_at=excluded.observed_at,confirmed_at=CASE WHEN ?5 THEN ?4 ELSE suite_publication.confirmed_at END,successor_seen_at=CASE WHEN ?6 THEN COALESCE(suite_publication.successor_seen_at,?4) ELSE suite_publication.successor_seen_at END,last_error=NULL",
                params![
                    key.repository(),
                    key.suite(),
                    if active {
                        None
                    } else {
                        Some(generation)
                    },
                    now,
                    confirm,
                    !same_content && state.active.is_some()
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
    pub(crate) fn publication_schedule(
        &self,
        key: SuiteKey,
        error: Option<String>,
        next: i64,
    ) -> Result<(), CatalogError> {
        self.write(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT OR IGNORE INTO suite_checkpoints(repository,suite) VALUES(?1,?2)",
                params![key.repository(), key.suite()],
            )?;
            transaction.execute(
                "INSERT INTO suite_publication(repository,suite,last_error,next_check_at) VALUES(?1,?2,?3,?4) ON CONFLICT(repository,suite) DO UPDATE SET last_error=excluded.last_error,next_check_at=excluded.next_check_at",
                params![key.repository(), key.suite(), error, next],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
    pub(crate) fn publication_activate(
        &self,
        activation: Activation,
    ) -> Result<Vec<(ObjectIdentity, u64)>, CatalogError> {
        self.write(move |connection| activate(connection, activation))
    }
    pub(crate) fn publication_manifests(
        &self,
        key: SuiteKey,
    ) -> Result<Vec<GenerationManifest>, CatalogError> {
        self.read(move |connection| {
            let mut statement = connection.prepare("SELECT manifest FROM public_generations WHERE repository=?1 AND suite=?2 ORDER BY activated_at DESC,generation")?;
            let rows = statement.query_map(params![key.repository(), key.suite()], |row| {
                row.get::<_, String>(0)
            })?;
            let mut manifests = Vec::new();
            for row in rows {
                let manifest: GenerationManifest = serde_json::from_str(&row?).map_err(|_| CatalogError::InvalidState)?;
                manifest
                    .validate()
                    .map_err(|_| CatalogError::InvalidState)?;
                manifests.push(manifest);
            }
            Ok(manifests)
        })
    }
}
fn activate(
    connection: &mut rusqlite::Connection,
    activation: Activation,
) -> Result<Vec<(ObjectIdentity, u64)>, CatalogError> {
    let Activation {
        intent,
        manifest,
        valid_until,
        now,
        confirmed_at,
        metadata,
    } = activation;
    let key = intent.key().map_err(|_| CatalogError::InvalidState)?;
    let scope = manifest.scope_id().to_hex();
    let encoded = String::from_utf8(manifest.encode().map_err(|_| CatalogError::InvalidState)?)
        .map_err(|_| CatalogError::InvalidState)?;
    let transaction = connection.transaction()?;
    let state = super::checkpoint::load(&transaction, &key)?;
    if state.floor.as_ref() != Some(&intent)
        || state.pending.as_ref() != Some(&intent)
        || manifest.key().map_err(|_| CatalogError::InvalidState)? != key
        || manifest.generation_id != intent.generation_id
        || manifest.release_content_sha256 != intent.release_content_sha256
        || manifest.release_date != intent.release_date
        || Sha256Digest::of(encoded.as_bytes()).to_hex() != intent.manifest_sha256
        || now < 0
    {
        return Err(CatalogError::InvalidState);
    }
    if confirmed_at.is_some_and(|confirmation| {
        confirmation < 0
            || confirmation > now
            || state.observed_date.is_some_and(|date| {
                intent.release_date < date
                    || (intent.release_date == date
                        && state.observed_content.as_ref() != Some(&intent.release_content_sha256))
            })
            || state.observed_at.is_some_and(|old| confirmation < old)
    }) {
        return Err(CatalogError::InvalidState);
    }
    check_conflicts(&transaction, &key, &scope)?;
    let previous: Option<String> = transaction
        .query_row(
            "SELECT manifest FROM public_generations WHERE generation=?1",
            [&scope],
            |row| row.get(0),
        )
        .optional()?;
    if previous.is_some_and(|previous| previous != encoded) {
        return Err(CatalogError::InvalidState);
    }
    let proof_manifest: Option<String> = transaction
        .query_row(
            "SELECT manifest FROM capture_proofs WHERE generation=?1",
            [&scope],
            |row| row.get(0),
        )
        .optional()?;
    if proof_manifest.is_some_and(|previous| previous != encoded) {
        return Err(CatalogError::InvalidState);
    }
    transaction.execute(
        "UPDATE public_generations SET retired_at=COALESCE(retired_at,?3) WHERE repository=?1 AND suite=?2 AND generation<>?4 AND retired_at IS NULL",
        params![key.repository(), key.suite(), now, scope],
    )?;
    transaction.execute(
        "INSERT INTO public_generations(generation,repository,suite,raw_generation,release_content,release_date,valid_until,activated_at,retired_at,intent,manifest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,?9,?10) ON CONFLICT(generation) DO UPDATE SET retired_at=NULL,intent=excluded.intent",
        params![
            scope,
            key.repository(),
            key.suite(),
            manifest.generation_id,
            manifest.release_content_sha256,
            manifest.release_date,
            valid_until,
            now,
            intent.encode().map_err(|_| CatalogError::InvalidState)?,
            encoded
        ],
    )?;
    transaction.execute(
        "INSERT INTO capture_proofs(generation,manifest,durable,reconciled,was_public) VALUES(?1,?2,1,1,1) ON CONFLICT(generation) DO UPDATE SET durable=1,reconciled=1,was_public=1,public_retired_at=NULL",
        params![scope, encoded],
    )?;
    for record in metadata {
        transaction.execute(
            "INSERT INTO publication_metadata(generation,path,directory,digest,size,sha256_alias,sha512,source_path) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(generation,path) DO NOTHING",
            params![
                scope,
                record.path,
                record.directory,
                record.identity.sha256.to_hex(),
                super::signed(record.identity.size)?,
                record.sha256_alias,
                record.sha512,
                record.source_path
            ],
        )?;
        let conflict: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM publication_metadata WHERE generation=?1 AND path=?2 AND (digest<>?3 OR size<>?4 OR source_path<>?5 OR sha256_alias<>?6 OR sha512 IS NOT ?7))",
            params![
                scope,
                record.path,
                record.identity.sha256.to_hex(),
                super::signed(record.identity.size)?,
                record.source_path,
                record.sha256_alias,
                record.sha512
            ],
            |row| row.get(0),
        )?;
        if conflict {
            return Err(CatalogError::InvalidState);
        }
    }
    let mut touched = std::collections::BTreeSet::new();
    for artifact in &manifest.artifacts {
        let identity = artifact
            .identity()
            .map_err(|_| CatalogError::InvalidState)?;
        let size = super::signed(identity.size)?;
        let valid: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM objects WHERE digest=?1 AND size=?2 AND resident=1)",
            params![artifact.sha256, size],
            |row| row.get(0),
        )?;
        if !valid {
            return Err(CatalogError::InvalidState);
        }
        transaction.execute(
            "INSERT OR IGNORE INTO generation_pins(generation,digest) VALUES(?1,?2)",
            params![scope, artifact.sha256],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO capture_artifacts(generation,digest,size) VALUES(?1,?2,?3)",
            params![scope, artifact.sha256, size],
        )?;
        touched.insert(artifact.sha256.clone());
    }
    transaction.execute(
        "INSERT INTO capture_generation_refs(generation,digest) SELECT DISTINCT ?1,b.digest FROM capture_blobs b JOIN capture_index_entries e ON e.digest=b.digest AND e.size=b.size JOIN capture_proof_indexes m ON m.index_id=e.index_id WHERE m.generation=?1 ON CONFLICT(generation,digest) DO UPDATE SET retain_until=9223372036854775807",
        [&scope],
    )?;
    transaction.execute(
        "UPDATE capture_paths SET referenced=1 WHERE repository=?1 AND EXISTS(SELECT 1 FROM capture_proof_indexes m JOIN capture_index_entries e ON e.index_id=m.index_id WHERE m.generation=?2 AND e.path=capture_paths.path AND e.digest=capture_paths.digest)",
        params![key.repository(), scope],
    )?;
    let expired = {
        let mut statement = transaction.prepare("SELECT generation FROM public_generations WHERE repository=?1 AND suite=?2 AND retired_at IS NOT NULL ORDER BY activated_at DESC,generation DESC")?;
        let rows = statement.query_map(params![key.repository(), key.suite()], |row| {
            row.get::<_, String>(0)
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let grace = now
        .checked_add(CAPTURE_GRACE)
        .ok_or(CatalogError::InvalidState)?;
    for retired in expired.into_iter().skip(2) {
        let eligible: bool = transaction.query_row(
            "SELECT retired_at<=?2 AND (valid_until IS NULL OR valid_until<=?3) FROM public_generations WHERE generation=?1",
            params![
                retired,
                now.checked_sub(METADATA_GRACE)
                    .ok_or(CatalogError::InvalidState)?,
                now
            ],
            |row| row.get(0),
        )?;
        if !eligible {
            continue;
        }
        {
            let mut statement =
                transaction.prepare("SELECT digest FROM generation_pins WHERE generation=?1")?;
            for row in statement.query_map([&retired], |row| row.get::<_, String>(0))? {
                touched.insert(row?);
            }
        }
        transaction.execute(
            "DELETE FROM generation_pins WHERE generation=?1",
            [&retired],
        )?;
        transaction.execute(
            "UPDATE capture_blobs SET retain_until=MAX(retain_until,?2) WHERE digest IN (SELECT digest FROM capture_generation_refs WHERE generation=?1)",
            params![retired, grace],
        )?;
        transaction.execute(
            "UPDATE capture_proofs SET public_retired_at=COALESCE(public_retired_at,?2),recovery_retention=MAX(recovery_retention,?3) WHERE generation=?1",
            params![retired, now, grace],
        )?;
        transaction.execute(
            "DELETE FROM capture_generation_refs WHERE generation=?1",
            [&retired],
        )?;
        transaction.execute(
            "DELETE FROM public_generations WHERE generation=?1",
            [&retired],
        )?;
    }
    transaction.execute(
        "UPDATE capture_paths SET referenced=0,retain_until=MAX(retain_until,?2) WHERE repository=?1 AND referenced=1 AND NOT EXISTS(SELECT 1 FROM capture_generation_refs r WHERE r.digest=capture_paths.digest AND r.retain_until=9223372036854775807)",
        params![key.repository(), grace],
    )?;
    let mut counts = Vec::with_capacity(touched.len());
    for digest in touched {
        transaction.execute(
            "UPDATE objects SET generation_references=(SELECT COUNT(*) FROM generation_pins WHERE digest=?1) WHERE digest=?1",
            [&digest],
        )?;
        let (size, count) = transaction.query_row(
            "SELECT size,generation_references FROM objects WHERE digest=?1",
            [&digest],
            |row| Ok((super::read_unsigned(row, 0)?, super::read_unsigned(row, 1)?)),
        )?;
        counts.push((
            ObjectIdentity {
                sha256: Sha256Digest::from_hex(&digest).map_err(|_| CatalogError::InvalidState)?,
                size,
            },
            count,
        ));
    }
    transaction.execute(
        "UPDATE suite_checkpoints SET active=?3,pending=NULL,blocked=?4,recovery_ready=?5 WHERE repository=?1 AND suite=?2",
        params![
            key.repository(),
            key.suite(),
            intent.encode().map_err(|_| CatalogError::InvalidState)?,
            confirmed_at.is_none(),
            confirmed_at.is_none()
        ],
    )?;
    transaction.execute(
        "DELETE FROM publication_candidates WHERE generation=?1",
        [&scope],
    )?;
    if let Some(confirmation) = confirmed_at {
        transaction.execute(
            "INSERT INTO suite_publication(repository,suite,observed_at,confirmed_at) VALUES(?1,?2,?3,?3) ON CONFLICT(repository,suite) DO UPDATE SET candidate_generation=NULL,observed_at=?3,confirmed_at=?3,successor_seen_at=NULL,last_error=NULL",
            params![key.repository(), key.suite(), confirmation],
        )?;
    } else {
        transaction.execute(
            "INSERT INTO suite_publication(repository,suite) VALUES(?1,?2) ON CONFLICT(repository,suite) DO UPDATE SET confirmed_at=NULL",
            params![key.repository(), key.suite()],
        )?;
    }
    transaction.commit()?;
    Ok(counts)
}

#[cfg(test)]
mod tests;
