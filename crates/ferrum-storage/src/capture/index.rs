//! Signed-index authority shared by capture, recovery and generation publishers.
//! Only hash-checked complete streams promote staging rows into lookup authority.
use super::CaptureError;
use crate::{
    Spool, VerifiedObject,
    catalog::CatalogError,
    recovery::{PROOF_CPU, VerifiedHistoricalProof},
};
use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest},
    index::{IndexError, PackageRecord, parse_packages},
    path::RepositoryPath,
    release::{ParseLimits, ReleaseEntry},
};
use rusqlite::{OptionalExtension, params};
use std::{
    collections::HashMap,
    io::{BufReader, Read},
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex, Weak},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
type IndexGateMap = HashMap<(PathBuf, String), Weak<Semaphore>>;
static INDEX_GATES: LazyLock<Mutex<IndexGateMap>> = LazyLock::new(|| Mutex::new(HashMap::new()));
// Producers own one slot through source verification and generation promotion.
// Reset owns all slots; nested source staging shares its producer's slot.
pub(super) const INDEX_OWNERS: u32 = 32;
type ReconciliationGateMap = HashMap<PathBuf, Weak<Semaphore>>;
static RECONCILIATION_GATES: LazyLock<Mutex<ReconciliationGateMap>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn reconciliation_gate(spool: &Spool) -> Result<Arc<Semaphore>, CaptureError> {
    let mut gates = RECONCILIATION_GATES
        .lock()
        .map_err(|_| CaptureError::Admission)?;
    gates.retain(|_, gate| gate.strong_count() > 0);
    if let Some(gate) = gates.get(spool.root()).and_then(Weak::upgrade) {
        return Ok(gate);
    }
    if gates.len() >= 32 {
        return Err(CaptureError::Admission);
    }
    let gate = Arc::new(Semaphore::new(INDEX_OWNERS as usize));
    gates.insert(spool.root().to_owned(), Arc::downgrade(&gate));
    Ok(gate)
}

async fn index_owner(
    spool: &Spool,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<Arc<OwnedSemaphorePermit>, CaptureError> {
    let gate = reconciliation_gate(spool)?;
    let owner = tokio::select! {
        () = cancel.cancelled() => return Err(CaptureError::Admission),
        owner = tokio::time::timeout_at(deadline, gate.acquire_owned()) =>
            owner.map_err(|_| CaptureError::Admission)?.map_err(|_| CaptureError::Admission)?,
    };
    Ok(Arc::new(owner))
}
#[derive(Clone)]
pub struct AuthenticatedPackageIndex {
    spool: Spool,
    pub(crate) id: String,
    proof: Arc<VerifiedHistoricalProof>,
    logical_path: String,
}
impl AuthenticatedPackageIndex {
    pub(crate) fn bound(
        spool: Spool,
        id: String,
        proof: Arc<VerifiedHistoricalProof>,
        logical_path: String,
    ) -> Result<Self, CaptureError> {
        if !spool.same_owner(&proof.owner) || proof.packages_source(&logical_path).is_none() {
            return Err(CaptureError::Proof);
        }
        Ok(Self {
            spool,
            id,
            proof,
            logical_path,
        })
    }
    pub fn generation_id(&self) -> &str {
        &self.proof.manifest().generation_id
    }
    pub fn repository(&self) -> &str {
        &self.proof.manifest().repository
    }
    /// Reuse this handle on the request path: no reparse, signature subprocess,
    /// or whole-generation allocation is required for an indexed lookup.
    pub fn authorize(
        &self,
        proof: Arc<VerifiedHistoricalProof>,
        path: RepositoryPath,
    ) -> Result<Option<super::VerifiedCaptureProof>, CaptureError> {
        if proof.manifest().scope_id() != self.proof.manifest().scope_id()
            || !self.spool.same_owner(&proof.owner)
            || proof.packages_source(&self.logical_path).is_none()
            || !super::is_package_path(path.as_str())
        {
            return Err(CaptureError::Proof);
        }
        Ok(self
            .lookup(&path)?
            .map(|identity| super::VerifiedCaptureProof {
                proof,
                path,
                identity,
            }))
    }
    pub fn lookup(&self, path: &RepositoryPath) -> Result<Option<ObjectIdentity>, CaptureError> {
        let id = self.id.clone();
        let path = path.as_str().to_owned();
        Ok(self.spool.durable_catalog()?.read(move |connection| {
            let ready: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_indexes WHERE id=?1 AND verified=1)",
                [&id],
                |row| row.get(0),
            )?;
            if !ready {
                return Err(CatalogError::InvalidState);
            }
            let row: Option<(String, u64)> = connection
                .query_row(
                    "SELECT digest,size FROM capture_index_entries WHERE index_id=?1 AND path=?2",
                    params![id, path],
                    |row| Ok((row.get(0)?, crate::catalog::read_unsigned(row, 1)?)),
                )
                .optional()?;
            row.map(|(digest, size)| {
                Ok(ObjectIdentity {
                    sha256: Sha256Digest::from_hex(&digest)
                        .map_err(|_| CatalogError::InvalidState)?,
                    size,
                })
            })
            .transpose()
        })?)
    }
}
pub async fn stage_package_index(
    spool: &Spool,
    proof: Arc<VerifiedHistoricalProof>,
    index_path: &str,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<AuthenticatedPackageIndex, CaptureError> {
    if !spool.same_owner(&proof.owner) {
        return Err(CaptureError::Proof);
    }
    if !super::is_index_path(index_path) || proof.packages_source(index_path).is_none() {
        return Err(CaptureError::Proof);
    }
    let owner = index_owner(spool, deadline, cancel).await?;
    let generation = proof.manifest().scope_id().to_hex();
    let mut paths = proof
        .manifest()
        .artifacts
        .iter()
        .map(|artifact| &artifact.path)
        .chain(proof.manifest().derived.iter().map(|derived| &derived.path))
        .filter(|path| super::is_index_path(path))
        .cloned()
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    let path_set = Sha256Digest::of(paths.join("\n").as_bytes()).to_hex();
    let bound = generation.clone();
    let selected = path_set.clone();
    let ready = spool.durable_catalog()?.read(move |connection| {
        Ok(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_index_generations WHERE generation=?1 AND path_set=?2 AND verified=1)",
            params![bound, selected],
            |row| row.get::<_, bool>(0),
        )?)
    })?;
    if !ready {
        let key = (spool.root().to_owned(), format!("generation:{generation}"));
        let gate = {
            let mut gates = INDEX_GATES.lock().map_err(|_| CaptureError::Admission)?;
            gates.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = gates.get(&key).and_then(Weak::upgrade) {
                gate
            } else {
                if gates.len() >= 32 {
                    return Err(CaptureError::Admission);
                }
                let gate = Arc::new(Semaphore::new(1));
                gates.insert(key, Arc::downgrade(&gate));
                gate
            }
        };
        let _generation = tokio::select! {()=cancel.cancelled()=>return Err(CaptureError::Admission),slot=tokio::time::timeout_at(deadline,gate.acquire_owned())=>slot.map_err(|_|CaptureError::Admission)?.map_err(|_|CaptureError::Admission)?};
        let bound = generation.clone();
        let selected = path_set.clone();
        let already = spool.durable_catalog()?.read(move |connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM capture_index_generations WHERE generation=?1 AND path_set=?2 AND verified=1)",
                params![bound, selected],
                |row| row.get::<_, bool>(0),
            )?)
        })?;
        if !already {
            for path in paths {
                let (source, entry) = proof.packages_source(&path).ok_or(CaptureError::Proof)?;
                let name = proof
                    .manifest()
                    .derived
                    .iter()
                    .find(|derived| derived.path == path)
                    .map_or(path.as_str(), |derived| derived.source_path.as_str())
                    .to_owned();
                let id = stage_source(
                    spool,
                    source.clone(),
                    name,
                    entry.clone(),
                    deadline,
                    cancel,
                    owner.clone(),
                )
                .await?;
                let bound = generation.clone();
                let candidate = id.clone();
                let child = cancel.child_token();
                let _cancel_on_drop = child.clone().drop_guard();
                let conflict = spool
                    .catalog_work_async(move |connection| {
                        connection.progress_handler(
                            10_000,
                            Some(move || child.is_cancelled() || Instant::now() >= deadline),
                        )?;
                        let result = connection
                            .query_row(
                                "SELECT EXISTS(SELECT 1 FROM capture_index_entries n JOIN capture_index_entries o ON o.path=n.path JOIN capture_proof_indexes m ON m.index_id=o.index_id WHERE n.index_id=?1 AND m.generation=?2 AND (n.digest<>o.digest OR n.size<>o.size))",
                                params![candidate, bound],
                                |row| row.get::<_, bool>(0),
                            )
                            .map_err(CatalogError::from);
                        connection.progress_handler(0, None::<fn() -> bool>)?;
                        result
                    })
                    .await?;
                if conflict {
                    return Err(CaptureError::Proof);
                }
                let bound = generation.clone();
                spool.catalog_write(move |connection| {
                    connection.execute(
                        "INSERT OR IGNORE INTO capture_proof_indexes(generation,path,index_id) VALUES(?1,?2,?3)",
                        params![bound, path, id],
                    )?;
                    let changed: bool = connection.query_row(
                        "SELECT index_id<>?3 FROM capture_proof_indexes WHERE generation=?1 AND path=?2",
                        params![bound, path, id],
                        |row| row.get(0),
                    )?;
                    if changed {
                        return Err(CatalogError::InvalidState);
                    }
                    Ok(())
                })?;
            }
            let bound = generation.clone();
            spool.catalog_write(move |connection| {
                connection.execute(
                    "INSERT INTO capture_index_generations(generation,path_set,verified) VALUES(?1,?2,1) ON CONFLICT(generation,path_set) DO UPDATE SET verified=1",
                    params![bound, path_set],
                )?;
                Ok(())
            })?;
        }
    }
    let bound = generation.clone();
    let path = index_path.to_owned();
    let id = spool.durable_catalog()?.read(move |connection| {
        Ok(connection.query_row(
            "SELECT m.index_id FROM capture_proof_indexes m JOIN capture_indexes i ON i.id=m.index_id AND i.verified=1 WHERE m.generation=?1 AND m.path=?2",
            params![bound, path],
            |row| row.get::<_, String>(0),
        )?)
    })?;
    Ok(AuthenticatedPackageIndex {
        spool: spool.clone(),
        id,
        proof,
        logical_path: index_path.to_owned(),
    })
}
/// Internal only: caller has authenticated the Release entry and source artifact.
/// Historical proof validation calls this instead of a separate derived hash pass.
pub(crate) async fn stage_authenticated_source(
    spool: &Spool,
    source: VerifiedObject,
    name: String,
    entry: ReleaseEntry,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<String, CaptureError> {
    let owner = index_owner(spool, deadline, cancel).await?;
    stage_source(spool, source, name, entry, deadline, cancel, owner).await
}

async fn stage_source(
    spool: &Spool,
    source: VerifiedObject,
    name: String,
    entry: ReleaseEntry,
    deadline: Instant,
    cancel: &CancellationToken,
    owner: Arc<OwnedSemaphorePermit>,
) -> Result<String, CaptureError> {
    // Suite-relative package paths must not share authority across index names.
    let identity_key = if let Some(prefix) = ferrum_apt::pacman::pacman_package_prefix(&name) {
        format!(
            "ferrum-pacman-index-v1:{prefix}:{}:{:?}:{:?}",
            entry.size, entry.sha256, entry.sha512
        )
    } else if ferrum_apt::rpm::is_rpm_primary_index_path(&name) {
        format!(
            "ferrum-rpm-index-v1:{name}:{}:{:?}:{:?}",
            entry.size, entry.sha256, entry.sha512
        )
    } else {
        format!(
            "ferrum-index-v1:{}:{:?}:{:?}",
            entry.size, entry.sha256, entry.sha512
        )
    };
    let id = Sha256Digest::of(identity_key.as_bytes()).to_hex();
    let gate = {
        let mut gates = INDEX_GATES.lock().map_err(|_| CaptureError::Admission)?;
        gates.retain(|_, gate| gate.strong_count() > 0);
        let key = (spool.root().to_owned(), id.clone());
        if let Some(gate) = gates.get(&key).and_then(Weak::upgrade) {
            gate
        } else {
            if gates.len() >= 32 {
                return Err(CaptureError::Admission);
            }
            let gate = Arc::new(Semaphore::new(1));
            gates.insert(key, Arc::downgrade(&gate));
            gate
        }
    };
    let slot = tokio::select! {()=cancel.cancelled()=>return Err(CaptureError::Admission),slot=tokio::time::timeout_at(deadline,gate.acquire_owned())=>slot.map_err(|_|CaptureError::Admission)?.map_err(|_|CaptureError::Admission)?};
    let identity = source.identity();
    let saved = id.clone();
    if super::is_index_path(&name)
        && (identity.size != entry.size
            || entry.sha256.is_some_and(|digest| digest != identity.sha256))
    {
        return Err(CaptureError::Proof);
    }
    let (ready, attested) = spool.durable_catalog()?.read(move |connection| {
        let ready = connection
            .query_row(
                "SELECT verified FROM capture_indexes WHERE id=?1",
                [&saved],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false);
        let attested = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_index_sources WHERE index_id=?1 AND digest=?2 AND size=?3)",
            params![
                saved,
                identity.sha256.to_hex(),
                crate::catalog::signed(identity.size)?
            ],
            |row| row.get::<_, bool>(0),
        )?;
        Ok((ready, attested))
    })?;
    if ready && attested {
        return Ok(id);
    }
    if !ready {
        let saved = id.clone();
        spool.catalog_write(move |connection| {
            connection.execute(
                "INSERT OR IGNORE INTO capture_indexes(id,verified) VALUES(?1,0)",
                [saved],
            )?;
            Ok(())
        })?;
        loop {
            let saved = id.clone();
            let changed = spool.catalog_write_reserved(8 * 1024 * 1024, move |connection| {
                Ok(connection.execute(
                    "DELETE FROM capture_index_entries WHERE rowid IN (SELECT rowid FROM capture_index_entries WHERE index_id=?1 LIMIT 128)",
                    [saved],
                )?)
            })?;
            if changed == 0 {
                break;
            }
        }
    }
    let permit = tokio::select! {()=cancel.cancelled()=>return Err(CaptureError::Admission),permit=tokio::time::timeout_at(deadline,PROOF_CPU.clone().acquire_owned())=>permit.map_err(|_|CaptureError::Admission)?.map_err(|_|CaptureError::Admission)?};
    let worker_spool = spool.clone();
    let worker_id = id.clone();
    let child = cancel.child_token();
    let _cancel_on_drop = child.clone().drop_guard();
    spool
        .catalog_work_async(move |_| {
            // Blocking work can outlive its awaiting future. Keep reset ownership
            // until its last write, including after cancellation.
            let _owner = owner;
            let _slot = slot;
            let _permit = permit;
            let identity = source.identity();
            let file = std::fs::File::open(source.path())?;
            let checked = super::proof::checked_reader(file, &name, entry, child, deadline)?;
            let mut reader = BufReader::with_capacity(256 * 1024, checked);
            if !ready {
                let mut pending = Vec::with_capacity(128);
                let mut sink = |record: PackageRecord| {
                    if matches!(
                        record.architecture.as_str(),
                        "amd64"
                            | "arm64"
                            | "all"
                            | "x86_64"
                            | "x86_64_v3"
                            | "x86_64_v4"
                            | "aarch64"
                            | "noarch"
                            | "any"
                    ) {
                        pending.push((record.filename, record.sha256, record.size));
                        if pending.len() == 128 {
                            flush(&worker_spool, &worker_id, &mut pending)
                                .map_err(|error| IndexError::Sink(error.to_string()))?;
                        }
                    }
                    Ok(())
                };
                if ferrum_apt::pacman::pacman_package_prefix(&name).is_some() {
                    ferrum_apt::pacman::parse_pacman_db(
                        &mut reader,
                        &name,
                        &ParseLimits::default(),
                        &mut sink,
                    )
                } else if ferrum_apt::rpm::is_rpm_primary_index_path(&name) {
                    ferrum_apt::rpm::parse_rpm_primary_xml(
                        &mut reader,
                        &name,
                        &ParseLimits::default(),
                        &mut sink,
                    )
                } else {
                    parse_packages(&mut reader, &ParseLimits::default(), &mut sink)
                }
                .map_err(|_| CatalogError::InvalidState)?;
                flush(&worker_spool, &worker_id, &mut pending)?;
            } else {
                let mut buffer = vec![0; 256 * 1024];
                while reader.read(&mut buffer)? != 0 {}
            }
            if !reader.get_ref().verified() {
                return Err(CatalogError::InvalidState);
            }
            worker_spool
                .catalog_write(move |connection| {
                    let transaction = connection.transaction()?;
                    transaction.execute(
                        "INSERT OR IGNORE INTO capture_index_sources(index_id,digest,size) VALUES(?1,?2,?3)",
                        params![
                            worker_id,
                            identity.sha256.to_hex(),
                            crate::catalog::signed(identity.size)?
                        ],
                    )?;
                    transaction.execute(
                        "UPDATE capture_indexes SET verified=1 WHERE id=?1",
                        [worker_id],
                    )?;
                    transaction.commit()?;
                    Ok(())
                })
                .map_err(|error| CatalogError::Io(std::io::Error::other(error.to_string())))?;
            Ok(())
        })
        .await?;
    Ok(id)
}
fn flush(
    spool: &Spool,
    id: &str,
    pending: &mut Vec<(RepositoryPath, Sha256Digest, u64)>,
) -> Result<(), CatalogError> {
    if pending.is_empty() {
        return Ok(());
    }
    let mut values = std::mem::take(pending);
    let id = id.to_owned();
    *pending = spool
        .catalog_write_reserved(8 * 1024 * 1024, move |connection| {
            let transaction = connection.transaction()?;
            {
                let mut insert = transaction.prepare_cached("INSERT OR IGNORE INTO capture_index_entries(index_id,path,digest,size) VALUES(?1,?2,?3,?4)")?;
                let mut check = transaction.prepare_cached("SELECT digest<>?3 OR size<>?4 FROM capture_index_entries WHERE index_id=?1 AND path=?2")?;
                for (path, digest, size) in &values {
                    let hex = digest.to_hex();
                    let size = crate::catalog::signed(*size)?;
                    insert.execute(params![&id, path.as_str(), &hex, size])?;
                    let conflict: bool = check.query_row(params![&id, path.as_str(), &hex, size], |row| row.get(0))?;
                    if conflict {
                        return Err(CatalogError::InvalidState);
                    }
                }
            }
            transaction.commit()?;
            values.clear();
            Ok(values)
        })
        .map_err(|error| CatalogError::Io(std::io::Error::other(error.to_string())))?;
    #[cfg(test)]
    test_support::at(spool, test_support::Point::Flush);
    Ok(())
}

#[cfg(test)]
pub(super) mod test_support {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::sync::{
        MutexGuard,
        mpsc::{self, Receiver, SyncSender},
    };
    use tokio::sync::oneshot;
    use tokio::time::Duration;

    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) enum Point {
        Flush,
        Reset,
    }

    struct Waiter {
        reached: oneshot::Sender<()>,
        resume: Receiver<()>,
    }

    type PauseMap = HashMap<(PathBuf, Point), Waiter>;
    static PAUSES: LazyLock<Mutex<PauseMap>> = LazyLock::new(|| Mutex::new(HashMap::new()));

    fn pauses() -> MutexGuard<'static, PauseMap> {
        match PAUSES.lock() {
            Ok(pauses) => pauses,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) struct Pause {
        key: (PathBuf, Point),
        reached: oneshot::Receiver<()>,
        resume: SyncSender<()>,
    }

    impl Pause {
        pub(crate) fn new(spool: &Spool, point: Point) -> Self {
            let key = (spool.root().to_owned(), point);
            let (reached, receiver) = oneshot::channel();
            let (resume, waiter) = mpsc::sync_channel(1);
            assert!(
                pauses()
                    .insert(
                        key.clone(),
                        Waiter {
                            reached,
                            resume: waiter,
                        },
                    )
                    .is_none()
            );
            Self {
                key,
                reached: receiver,
                resume,
            }
        }

        pub(crate) async fn reached(&mut self) {
            tokio::time::timeout(Duration::from_secs(10), &mut self.reached)
                .await
                .expect("index operation must reach the test boundary")
                .expect("index operation must retain the test boundary");
        }

        pub(crate) fn resume(&self) {
            self.resume.send(()).unwrap();
        }
    }

    impl Drop for Pause {
        fn drop(&mut self) {
            pauses().remove(&self.key);
            let _ = self.resume.try_send(());
        }
    }

    pub(crate) fn at(spool: &Spool, point: Point) {
        let waiter = pauses().remove(&(spool.root().to_owned(), point));
        if let Some(waiter) = waiter {
            let _ = waiter.reached.send(());
            waiter
                .resume
                .recv_timeout(Duration::from_secs(10))
                .expect("test must release the paused index operation");
        }
    }
}
