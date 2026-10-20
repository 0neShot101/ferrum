//! Durable operation truth, attached to real synchronizer passes rather than HTTP
//! triggers. A request made after observation starts belongs to the next pass.
//! Registry bookkeeping never changes publication authority or aborts active work.
//! Persistence failures after admission leave live truth visible with an explicit
//! recording gap; restart interrupts unfinished requests instead of replaying them.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::Json;
use axum::body::to_bytes;
use axum::extract::{Path, Request, State, rejection::JsonRejection};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use ferrum_storage::checkpoint::SuiteKey;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::model::{AuthContext, Permission, StoreError};
use super::password;
use super::routes::{authenticate, error_reply, store_error};
use super::store::{AdminStore, actor, audit, now};
use crate::health::HealthState;

const RESTART_REASON: &str = "Gateway restarted before operation completed";
const MAX_TARGETS: usize = 128;
const MAX_ACTIVE: usize = 32;
const LIVE_TERMINAL: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobTarget {
    pub repository: String,
    pub suite: String,
    pub state: String,
    pub disposition: String,
    pub phase: String,
    pub pass_id: Option<String>,
    pub generation_id: Option<String>,
    pub completed_artifacts: Option<u64>,
    pub total_artifacts: Option<u64>,
    pub current_path: Option<String>,
    pub error: Option<String>,
    pub cancellable: bool,
    #[serde(default)]
    pub superseded_generation_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobView {
    pub id: String,
    pub kind: String,
    pub state: String,
    pub actor: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub reason: String,
    pub targets: Vec<JobTarget>,
    pub recording_incomplete: bool,
    pub cancellable: bool,
    pub evicted_objects: Option<String>,
    pub freed_bytes: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuiteJobState {
    pub repository: String,
    pub suite: String,
    pub phase: String,
    pub generation_id: Option<String>,
    pub completed_artifacts: Option<u64>,
    pub total_artifacts: Option<u64>,
    pub current_path: Option<String>,
    pub active_pass_id: Option<String>,
    pub queued_pass_id: Option<String>,
    pub recheck_after_current: bool,
    pub last_outcome: Option<String>,
    pub last_error: Option<String>,
    pub recording_incomplete: bool,
    #[serde(skip)]
    observation_started: bool,
}
impl SuiteJobState {
    fn new(key: &SuiteKey) -> Self {
        Self {
            repository: key.repository().into(),
            suite: key.suite().into(),
            phase: "idle".into(),
            generation_id: None,
            completed_artifacts: None,
            total_artifacts: None,
            current_path: None,
            active_pass_id: None,
            queued_pass_id: None,
            recheck_after_current: false,
            last_outcome: None,
            last_error: None,
            recording_incomplete: false,
            observation_started: false,
        }
    }
    fn attachment(&mut self) -> (String, &'static str) {
        if !self.observation_started
            && let Some(pass) = &self.active_pass_id
        {
            return (pass.clone(), "queued");
        }
        let pass = self
            .queued_pass_id
            .get_or_insert_with(password::random_token)
            .clone();
        if self.observation_started {
            self.recheck_after_current = true;
            (pass, "queued_recheck")
        } else {
            self.phase = "queued".into();
            (pass, "queued")
        }
    }
}

#[derive(Default)]
struct RegistryState {
    suites: BTreeMap<(String, String), SuiteJobState>,
    jobs: BTreeMap<String, JobView>,
}
impl RegistryState {
    fn suite(&mut self, key: &SuiteKey) -> &mut SuiteJobState {
        self.suites
            .entry((key.repository().into(), key.suite().into()))
            .or_insert_with(|| SuiteJobState::new(key))
    }
    fn prune(&mut self) {
        let mut terminal: Vec<_> = self
            .jobs
            .values()
            .filter(|job| !nonterminal(&job.state))
            .map(|job| (job.recording_incomplete, job.updated_at, job.id.clone()))
            .collect();
        terminal.sort();
        let remove = terminal.len().saturating_sub(LIVE_TERMINAL);
        for (_, _, id) in terminal.into_iter().take(remove) {
            self.jobs.remove(&id);
        }
    }
}

pub struct JobRegistry {
    admin: AdminStore,
    // Admission, cancellation and actor transitions share this gate. No SQLite
    // call runs on the async worker; AdminStore owns its bounded writer thread.
    inner: Mutex<RegistryState>,
}
impl JobRegistry {
    pub fn new(admin: AdminStore) -> Self {
        Self {
            admin,
            inner: Mutex::new(RegistryState::default()),
        }
    }

    pub async fn reconcile_startup(admin: &AdminStore) -> Result<(), StoreError> {
        admin.write(|tx| {
            let mut statement = tx.prepare("SELECT id FROM operation_requests WHERE state IN('queued','running') ORDER BY created_at,id LIMIT 32")?;
            let ids = statement.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            for id in ids {
                let mut job = load_job(tx, &id)?.ok_or(StoreError::Unavailable)?;
                for target in &mut job.targets {
                    if nonterminal(&target.state) {
                        target.state = "interrupted".into(); target.phase = "interrupted".into();
                        target.error = Some(RESTART_REASON.into()); target.cancellable = false;
                    }
                }
                job.state = "interrupted".into(); job.updated_at = now(); job.error = Some(RESTART_REASON.into()); job.cancellable = false;
                persist_job(tx, &job)?;
                audit(tx, &job.actor, "operation.interrupted", &job.id, "interrupted", RESTART_REASON)?;
            }
            Ok(())
        }).await
    }

    pub async fn snapshot(&self) -> Vec<SuiteJobState> {
        self.inner.lock().await.suites.values().cloned().collect()
    }

    async fn admit_sync(
        &self,
        auth: AuthContext,
        targets: Vec<SuiteKey>,
        key: String,
        hash: String,
        reason: String,
    ) -> Result<(JobView, bool), StoreError> {
        let mut inner = self.inner.lock().await;
        // Prepare on a copy: a failed transaction must not consume pass IDs or
        // leave phantom queued references in the live scheduler projection.
        let mut slots: Vec<_> = targets
            .iter()
            .map(|target| {
                inner
                    .suites
                    .get(&(target.repository().into(), target.suite().into()))
                    .cloned()
                    .unwrap_or_else(|| SuiteJobState::new(target))
            })
            .collect();
        let job_targets = slots
            .iter_mut()
            .map(|slot| {
                let (pass, disposition) = slot.attachment();
                JobTarget {
                    repository: slot.repository.clone(),
                    suite: slot.suite.clone(),
                    state: "queued".into(),
                    disposition: disposition.into(),
                    phase: "queued".into(),
                    pass_id: Some(pass),
                    generation_id: None,
                    completed_artifacts: None,
                    total_artifacts: None,
                    current_path: None,
                    error: None,
                    cancellable: true,
                    superseded_generation_ids: Vec::new(),
                }
            })
            .collect();
        let job = new_job("sync", &auth, reason, job_targets);
        let (job, replay) = self
            .insert_intent(auth, Permission::TriggerSync, key, hash, job)
            .await?;
        if !replay {
            for slot in slots {
                inner
                    .suites
                    .insert((slot.repository.clone(), slot.suite.clone()), slot);
            }
            inner.jobs.insert(job.id.clone(), job.clone());
            inner.prune();
        }
        Ok((job, replay))
    }

    async fn insert_intent(
        &self,
        auth: AuthContext,
        permission: Permission,
        key: String,
        hash: String,
        job: JobView,
    ) -> Result<(JobView, bool), StoreError> {
        self.admin.write(move |tx| {
            let user = actor(tx, &auth, Some(permission))?;
            if let Some(id) = replay_id(tx, &user.id, &key, &hash)? {
                return Ok((load_job(tx, &id)?.ok_or(StoreError::Unavailable)?, true));
            }
            let active: i64 = tx.query_row("SELECT count(*) FROM operation_requests WHERE state IN('queued','running')", [], |row| row.get(0))?;
            if active >= MAX_ACTIVE as i64 { return Err(StoreError::Busy); }
            let mut body = job.clone(); body.targets.clear();
            tx.execute("INSERT INTO operation_requests(id,actor,idempotency_key,request_hash,kind,state,created_at,updated_at,body) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![job.id, user.id, key, hash, job.kind, job.state, job.created_at, job.updated_at, encode(&body)?])?;
            for target in &job.targets {
                tx.execute("INSERT INTO operation_targets(request_id,repository,suite,pass_id,state,body) VALUES(?1,?2,?3,?4,?5,?6)", params![job.id, target.repository, target.suite, target.pass_id, target.state, encode(target)?])?;
            }
            audit(tx, &user.id, if job.kind == "sync" { "sync.request" } else { "cache.clear" }, &job.id, "intent", &job.reason)?;
            Ok((job, false))
        }).await
    }

    pub async fn pass_started(&self, key: &SuiteKey, phase: &str) {
        let mut inner = self.inner.lock().await;
        let slot = inner.suite(key);
        if slot.active_pass_id.is_none() {
            slot.active_pass_id = Some(
                slot.queued_pass_id
                    .take()
                    .unwrap_or_else(password::random_token),
            );
            slot.generation_id = None;
            slot.completed_artifacts = None;
            slot.total_artifacts = None;
            slot.current_path = None;
            slot.observation_started = false;
            slot.recheck_after_current = false;
            slot.recording_incomplete = false;
        }
        slot.phase = phase.into();
        if phase == "observing" {
            slot.observation_started = true;
        }
        let snapshot = slot.clone();
        let changed = update_targets(&mut inner, &snapshot, false);
        self.record(&mut inner, key, changed).await;
    }

    pub async fn phase_changed(
        &self,
        key: &SuiteKey,
        phase: &str,
        generation: Option<String>,
        completed: Option<u64>,
        total: Option<u64>,
        path: Option<String>,
    ) {
        let mut inner = self.inner.lock().await;
        let slot = inner.suite(key);
        if slot.active_pass_id.is_none() {
            return;
        }
        slot.phase = phase.into();
        if generation.is_some() {
            slot.generation_id = generation;
        }
        slot.completed_artifacts = completed;
        slot.total_artifacts = total;
        slot.current_path = path.map(|path| bounded_text(&path, 4096));
        let snapshot = slot.clone();
        let changed = update_targets(&mut inner, &snapshot, false);
        self.record(&mut inner, key, changed).await;
    }

    /// Returns whether the actor must schedule the single queued recheck. A
    /// late result for a superseded generation cannot finish its replacement.
    pub async fn pass_completed(
        &self,
        key: &SuiteKey,
        outcome: &str,
        generation: Option<String>,
        error: Option<String>,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        let slot = inner.suite(key);
        if slot.active_pass_id.is_none() {
            return false;
        }
        if generation.is_some() && slot.generation_id.is_some() && generation != slot.generation_id
        {
            return false;
        }
        slot.phase = outcome.into();
        if generation.is_some() {
            slot.generation_id = generation;
        }
        slot.last_outcome = Some(outcome.into());
        slot.last_error = error.map(|error| bounded_text(&error, 256));
        slot.current_path = None;
        let snapshot = slot.clone();
        let changed = update_targets(&mut inner, &snapshot, true);
        let recheck = slot_recheck(&mut inner, key);
        self.record(&mut inner, key, changed).await;
        inner.prune();
        recheck
    }

    async fn record(&self, inner: &mut RegistryState, key: &SuiteKey, jobs: Vec<JobView>) {
        if jobs.is_empty() {
            return;
        }
        let ids: Vec<_> = jobs.iter().map(|job| job.id.clone()).collect();
        let result = self
            .admin
            .write(move |tx| {
                for job in jobs {
                    let previous: String = tx.query_row(
                        "SELECT state FROM operation_requests WHERE id=?1",
                        [&job.id],
                        |row| row.get(0),
                    )?;
                    persist_job(tx, &job)?;
                    if nonterminal(&previous) && !nonterminal(&job.state) {
                        audit(
                            tx,
                            &job.actor,
                            "sync.outcome",
                            &job.id,
                            &job.state,
                            &job.reason,
                        )?;
                    }
                }
                Ok(())
            })
            .await;
        if result.is_err() {
            inner.suite(key).recording_incomplete = true;
            for id in ids {
                if let Some(job) = inner.jobs.get_mut(&id) {
                    job.recording_incomplete = true;
                }
            }
            tracing::warn!(
                repository = key.repository(),
                suite = key.suite(),
                "operation result recording incomplete; publication is unaffected"
            );
        }
    }

    async fn cancel(&self, auth: AuthContext, id: String) -> Result<Option<JobView>, StoreError> {
        let mut inner = self.inner.lock().await;
        let live = inner.jobs.get(&id).cloned();
        let changed = self
            .admin
            .write(move |tx| {
                let user = actor(tx, &auth, Some(Permission::TriggerSync))?;
                let Some(mut job) = live.or(load_job(tx, &id)?) else {
                    return Ok(None);
                };
                if job.kind != "sync" {
                    return Err(StoreError::Forbidden);
                }
                for target in &mut job.targets {
                    if target.state == "queued" && target.cancellable {
                        target.state = "cancelled".into();
                        target.phase = "cancelled".into();
                        target.cancellable = false;
                    }
                }
                rollup(&mut job);
                persist_job(tx, &job)?;
                audit(
                    tx,
                    &user.id,
                    "sync.cancel",
                    &job.id,
                    &job.state,
                    "Queued references only; active publication is not cancelled",
                )?;
                Ok(Some(job))
            })
            .await?;
        if let Some(job) = &changed {
            inner.jobs.insert(job.id.clone(), job.clone());
        }
        // Drop empty queued references, but never stop a scheduled/system pass.
        let queued: BTreeSet<_> = inner
            .jobs
            .values()
            .flat_map(|job| job.targets.iter())
            .filter(|target| target.state == "queued")
            .filter_map(|target| target.pass_id.clone())
            .collect();
        for slot in inner.suites.values_mut() {
            if slot
                .queued_pass_id
                .as_ref()
                .is_some_and(|pass| !queued.contains(pass))
            {
                slot.queued_pass_id = None;
                slot.recheck_after_current = false;
            }
        }
        Ok(changed)
    }

    async fn overlay(&self, mut job: JobView) -> JobView {
        if let Some(live) = self.inner.lock().await.jobs.get(&job.id) {
            job = live.clone();
        }
        job
    }
}

fn slot_recheck(inner: &mut RegistryState, key: &SuiteKey) -> bool {
    let slot = inner.suite(key);
    slot.active_pass_id = None;
    slot.observation_started = false;
    let recheck = slot.recheck_after_current && slot.queued_pass_id.is_some();
    slot.recheck_after_current = false;
    recheck
}
fn update_targets(inner: &mut RegistryState, slot: &SuiteJobState, terminal: bool) -> Vec<JobView> {
    let mut changed = Vec::new();
    for job in inner
        .jobs
        .values_mut()
        .filter(|job| nonterminal(&job.state))
    {
        let mut touched = false;
        for target in &mut job.targets {
            if target.repository != slot.repository
                || target.suite != slot.suite
                || target.pass_id != slot.active_pass_id
                || !nonterminal(&target.state)
            {
                continue;
            }
            if let Some(old) = &target.generation_id
                && Some(old) != slot.generation_id.as_ref()
                && slot.generation_id.is_some()
            {
                if target.superseded_generation_ids.len() == 16 {
                    target.superseded_generation_ids.remove(0);
                }
                target.superseded_generation_ids.push(old.clone());
            }
            target.phase = slot.phase.clone();
            target.state = if terminal {
                slot.phase.clone()
            } else if slot.observation_started {
                "running".into()
            } else {
                "queued".into()
            };
            target.generation_id = slot.generation_id.clone();
            target.completed_artifacts = slot.completed_artifacts;
            target.total_artifacts = slot.total_artifacts;
            target.current_path = slot.current_path.clone();
            target.error = if terminal {
                slot.last_error.clone()
            } else {
                None
            };
            target.cancellable = !terminal && !slot.observation_started;
            touched = true;
        }
        if touched {
            rollup(job);
            changed.push(job.clone());
        }
    }
    changed
}
fn nonterminal(state: &str) -> bool {
    matches!(state, "queued" | "running")
}
fn successful(state: &str) -> bool {
    matches!(state, "published" | "renewed")
}
fn rollup(job: &mut JobView) {
    if job.targets.is_empty() {
        return;
    }
    job.state = if job.targets.iter().any(|target| nonterminal(&target.state)) {
        if job.targets.iter().any(|target| target.state == "running") {
            "running"
        } else {
            "queued"
        }
    } else if job.targets.iter().all(|target| successful(&target.state)) {
        "succeeded"
    } else if job.targets.iter().all(|target| target.state == "cancelled") {
        "cancelled"
    } else if job.targets.iter().any(|target| successful(&target.state)) {
        "partial"
    } else {
        "failed"
    }
    .into();
    job.cancellable = job
        .targets
        .iter()
        .any(|target| target.state == "queued" && target.cancellable);
    job.updated_at = now();
}
fn new_job(kind: &str, auth: &AuthContext, reason: String, targets: Vec<JobTarget>) -> JobView {
    JobView {
        id: password::random_token(),
        kind: kind.into(),
        state: "queued".into(),
        actor: auth.user.id.clone(),
        created_at: now(),
        updated_at: now(),
        reason,
        cancellable: !targets.is_empty(),
        targets,
        recording_incomplete: false,
        evicted_objects: None,
        freed_bytes: None,
        error: None,
    }
}
fn encode<T: Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| StoreError::Unavailable)
}
fn replay_id(
    c: &Connection,
    actor_id: &str,
    key: &str,
    hash: &str,
) -> Result<Option<String>, StoreError> {
    let found: Option<(String, String)> = c
        .query_row(
            "SELECT id,request_hash FROM operation_requests WHERE actor=?1 AND idempotency_key=?2",
            params![actor_id, key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match found {
        Some((id, recorded)) if recorded == hash => Ok(Some(id)),
        Some(_) => Err(StoreError::Conflict),
        None => Ok(None),
    }
}
fn load_job(c: &Connection, id: &str) -> Result<Option<JobView>, StoreError> {
    let raw: Option<(String, String, i64)> = c
        .query_row(
            "SELECT body,state,updated_at FROM operation_requests WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((body, state, updated)) = raw else {
        return Ok(None);
    };
    let mut job: JobView = serde_json::from_str(&body).map_err(|_| StoreError::Unavailable)?;
    job.state = state;
    job.updated_at = updated;
    let mut statement = c.prepare("SELECT body,state FROM operation_targets WHERE request_id=?1 ORDER BY repository,suite LIMIT 128")?;
    let rows = statement
        .query_map([id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    job.targets = rows
        .into_iter()
        .map(|(body, state)| {
            let mut target: JobTarget =
                serde_json::from_str(&body).map_err(|_| StoreError::Unavailable)?;
            target.state = state;
            Ok(target)
        })
        .collect::<Result<_, StoreError>>()?;
    Ok(Some(job))
}
fn persist_job(tx: &Transaction<'_>, job: &JobView) -> Result<(), StoreError> {
    // Keep the request row below 64 KiB even for 128 targets: target truth has
    // its own bounded rows and is joined only when projecting a response.
    let mut body = job.clone();
    body.targets.clear();
    tx.execute(
        "UPDATE operation_requests SET state=?1,updated_at=?2,body=?3 WHERE id=?4",
        params![job.state, job.updated_at, encode(&body)?, job.id],
    )?;
    for target in &job.targets {
        tx.execute("UPDATE operation_targets SET pass_id=?1,state=?2,body=?3 WHERE request_id=?4 AND repository=?5 AND suite=?6", params![target.pass_id, target.state, encode(target)?, job.id, target.repository, target.suite])?;
    }
    Ok(())
}
fn bounded_text(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .scan(0usize, |len, ch| {
            *len += ch.len_utf8();
            (*len <= max).then_some(ch)
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncRequest {
    pub repository: Option<String>,
    pub suite: Option<String>,
    pub targets: Option<Vec<SyncTarget>>,
    pub idempotency_key: Option<String>,
    pub reason: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncTarget {
    pub repository: String,
    pub suite: String,
}
fn reason(value: Option<String>, default: &str) -> Result<String, StoreError> {
    let reason = value.unwrap_or_else(|| default.into());
    if reason.trim().is_empty() || reason.len() > 1024 || reason.chars().any(char::is_control) {
        return Err(StoreError::Invalid);
    }
    Ok(reason)
}
fn idempotency(headers: &HeaderMap, body: Option<String>) -> Result<String, StoreError> {
    let mut values = headers.get_all("x-ferrum-idempotency").iter();
    let header = values
        .next()
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| StoreError::Invalid)?;
    if values.next().is_some() || (body.is_some() && header.is_some() && body != header) {
        return Err(StoreError::Invalid);
    }
    let key = body.or(header).unwrap_or_else(password::random_token);
    if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
        return Err(StoreError::Invalid);
    }
    Ok(key)
}
fn request_hash(
    kind: &str,
    targets: &[SuiteKey],
    reason: &str,
    bytes: Option<u64>,
) -> Result<String, StoreError> {
    let targets: Vec<_> = targets
        .iter()
        .map(|key| (key.repository(), key.suite()))
        .collect();
    Ok(password::digest(
        encode(&(kind, targets, reason, bytes))?.as_bytes(),
    ))
}
fn configured_targets(
    trigger: &crate::sync::SyncTrigger,
    payload: &SyncRequest,
) -> Result<Vec<SuiteKey>, StoreError> {
    let mut targets = BTreeMap::new();
    if let Some(selected) = &payload.targets {
        if payload.repository.is_some()
            || payload.suite.is_some()
            || selected.is_empty()
            || selected.len() > MAX_TARGETS
        {
            return Err(StoreError::Invalid);
        }
        for selected in selected {
            if selected.repository.len() > 64 || selected.suite.len() > 128 {
                return Err(StoreError::Invalid);
            }
            let found = trigger
                .matching(Some(&selected.repository), Some(&selected.suite))
                .ok_or(StoreError::Invalid)?;
            for key in found {
                targets.insert((key.repository().to_owned(), key.suite().to_owned()), key);
            }
        }
    } else {
        if payload
            .repository
            .as_ref()
            .is_some_and(|value| value.len() > 64)
            || payload
                .suite
                .as_ref()
                .is_some_and(|value| value.len() > 128)
        {
            return Err(StoreError::Invalid);
        }
        for key in trigger
            .matching(payload.repository.as_deref(), payload.suite.as_deref())
            .ok_or(StoreError::Invalid)?
        {
            targets.insert((key.repository().to_owned(), key.suite().to_owned()), key);
        }
    }
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(StoreError::Invalid);
    }
    Ok(targets.into_values().collect())
}

pub async fn post_sync(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    payload: Result<Json<SyncRequest>, JsonRejection>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::TriggerSync)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let Json(payload) = match payload {
        Ok(payload) => payload,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return error_reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Request body exceeds its limit.",
            );
        }
        Err(_) => return store_error(StoreError::Invalid),
    };
    let Some(trigger) = state.sync_trigger.clone() else {
        return error_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "sync_unavailable",
            "Synchronizer unavailable.",
        );
    };
    let prepared = (|| {
        let targets = configured_targets(&trigger, &payload)?;
        let reason = reason(payload.reason, "Manual metadata synchronization")?;
        let key = idempotency(&headers, payload.idempotency_key)?;
        let hash = request_hash("sync", &targets, &reason, None)?;
        Ok::<_, StoreError>((targets, reason, key, hash))
    })();
    let (targets, reason, key, hash) = match prepared {
        Ok(value) => value,
        Err(error) => return store_error(error),
    };
    // Own the admitted mutation independently of HTTP cancellation.
    tokio::spawn(async move {
        let triggered: Vec<_> = targets
            .iter()
            .map(|key| format!("{}/{}", key.repository(), key.suite()))
            .collect();
        let (job, replay) = match state
            .jobs
            .admit_sync(auth, targets, key, hash, reason)
            .await
        {
            Ok(value) => value,
            Err(error) => return store_error(error),
        };
        if !replay {
            for target in &job.targets {
                if target.disposition == "queued" {
                    let _ = trigger.trigger(Some(&target.repository), Some(&target.suite));
                }
            }
        }
        let job = state.jobs.overlay(job).await;
        (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"job":job,"triggered":triggered})),
        )
            .into_response()
    })
    .await
    .unwrap_or_else(|_| store_error(StoreError::Unavailable))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClearRequest {
    target_bytes: Option<BytesInput>,
    reason: Option<String>,
    idempotency_key: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum BytesInput {
    Text(String),
    Number(u64),
}
impl BytesInput {
    fn value(self) -> Result<u64, StoreError> {
        match self {
            Self::Number(value) => Ok(value),
            Self::Text(value)
                if !value.is_empty()
                    && value.len() <= 20
                    && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                value.parse().map_err(|_| StoreError::Invalid)
            }
            _ => Err(StoreError::Invalid),
        }
    }
}

pub async fn post_clear_cache(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::ManageCache)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let body = match to_bytes(request.into_body(), 64 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            return error_reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Request body exceeds its limit.",
            );
        }
    };
    let payload: ClearRequest = if body.is_empty() {
        ClearRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(_) => return store_error(StoreError::Invalid),
        }
    };
    let prepared = (|| {
        let target = payload.target_bytes.map(BytesInput::value).transpose()?;
        let reason = reason(payload.reason, "Manual local cache clear")?;
        let key = idempotency(&headers, payload.idempotency_key)?;
        let hash = request_hash("cache_clear", &[], &reason, target)?;
        Ok::<_, StoreError>((target, reason, key, hash))
    })();
    let (target, reason, key, hash) = match prepared {
        Ok(value) => value,
        Err(error) => return store_error(error),
    };
    tokio::spawn(async move {
        let permit = match state.admin_http.cache_operation.clone().try_acquire_owned() { Ok(permit) => permit, Err(_) => return store_error(StoreError::Busy) };
        let _permit = permit;
        let job = new_job("cache_clear", &auth, reason, Vec::new());
        let (mut job, replay) = match state.jobs.insert_intent(auth, Permission::ManageCache, key, hash, job).await { Ok(value) => value, Err(error) => return store_error(error) };
        if !replay {
            job.state = "running".into(); job.updated_at = now();
            let running = job.clone();
            if let Err(error) = state.admin.write(move |tx| persist_job(tx, &running)).await {
                job.state = "failed".into(); job.updated_at = now();
                job.error = Some("Local cache operation could not be durably started; no objects were removed".into());
                let failed = job.clone();
                job.recording_incomplete = state.admin.write(move |tx| {
                    persist_job(tx, &failed)?;
                    audit(tx, &failed.actor, "cache.clear", &failed.id, "failed", &failed.reason)
                }).await.is_err();
                let mut inner = state.jobs.inner.lock().await;
                inner.jobs.insert(job.id.clone(), job); inner.prune();
                return store_error(error);
            }
            let spool = state.spool.clone();
            let result = tokio::task::spawn_blocking(move || {
                let Some(target) = target else { return spool.clear_evictable_cache(); };
                let starting = spool.preview_evictable_cache()?.eligible.objects;
                let mut objects = 0u64; let mut bytes = 0u64;
                while objects < starting && bytes < target {
                    let maximum = (starting - objects).min(32) as usize;
                    let (removed, freed, more) = spool.evict_cache_batch(maximum, Some(target - bytes))?;
                    objects = objects.saturating_add(removed); bytes = bytes.saturating_add(freed);
                    if !more || removed == 0 { break; }
                }
                Ok((objects, bytes))
            }).await;
            job.updated_at = now();
            match result {
                Ok(Ok((objects, bytes))) => { job.state = "succeeded".into(); job.evicted_objects = Some(objects.to_string()); job.freed_bytes = Some(bytes.to_string()); }
                _ => { job.state = "failed".into(); job.error = Some("Local cache reclamation failed; some eligible objects may already have been removed".into()); }
            }
            let completed = job.clone();
            if state.admin.write(move |tx| { persist_job(tx, &completed)?; audit(tx, &completed.actor, "cache.clear", &completed.id, if completed.state == "succeeded" { "completed" } else { "failed" }, &completed.reason) }).await.is_err() { job.recording_incomplete = true; }
            let mut inner = state.jobs.inner.lock().await; inner.jobs.insert(job.id.clone(), job.clone()); inner.prune();
        } else { job = state.jobs.overlay(job).await; }
        let snapshot_state = state.clone();
        let spool = match tokio::task::spawn_blocking(move || super::overview::build_spool_overview(&snapshot_state)).await { Ok(spool) => spool, Err(_) => return store_error(StoreError::Unavailable) };
        let status = if job.state == "failed" { StatusCode::SERVICE_UNAVAILABLE } else if nonterminal(&job.state) { StatusCode::ACCEPTED } else { StatusCode::OK };
        let evicted_objects = job.evicted_objects.as_deref().and_then(|value| value.parse::<u64>().ok());
        let freed_bytes = job.freed_bytes.as_deref().and_then(|value| value.parse::<u64>().ok());
        (status, Json(serde_json::json!({"evictedObjects":evicted_objects,"freedBytes":freed_bytes,"spool":spool,"job":job}))).into_response()
    }).await.unwrap_or_else(|_| store_error(StoreError::Unavailable))
}

pub async fn get_job_detail(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if id.len() > 64 {
        return store_error(StoreError::Invalid);
    }
    match state
        .admin
        .read(move |c| {
            actor(c, &auth, Some(Permission::ViewStatus))?;
            load_job(c, &id)
        })
        .await
    {
        Ok(Some(job)) => {
            Json(serde_json::json!({"job":state.jobs.overlay(job).await})).into_response()
        }
        Ok(None) => error_reply(
            StatusCode::NOT_FOUND,
            "job_not_found",
            "Operation not found.",
        ),
        Err(error) => store_error(error),
    }
}

pub async fn get_jobs(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let auth = match authenticate(&state, &headers, false, Some(Permission::ViewStatus)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let mut limit = 50usize;
    let mut kind = None;
    let mut filter = None;
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    if uri.query().is_some_and(|query| query.len() > 1024) {
        return store_error(StoreError::Invalid);
    }
    for (key, value) in url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()) {
        if !seen.insert(key.to_string()) {
            return store_error(StoreError::Invalid);
        }
        match key.as_ref() {
            "limit" => match value.parse::<usize>() {
                Ok(value) if (1..=100).contains(&value) => limit = value,
                _ => return store_error(StoreError::Invalid),
            },
            "kind" if matches!(value.as_ref(), "sync" | "cache_clear") => {
                kind = Some(value.into_owned())
            }
            "state"
                if matches!(
                    value.as_ref(),
                    "queued"
                        | "running"
                        | "succeeded"
                        | "partial"
                        | "failed"
                        | "cancelled"
                        | "interrupted"
                ) =>
            {
                filter = Some(value.into_owned())
            }
            "cursor" if value.len() <= 128 => cursor = Some(value.into_owned()),
            _ => return store_error(StoreError::Invalid),
        }
    }
    let before = if let Some(cursor) = cursor {
        match cursor.split_once(':') {
            Some((time, id))
                if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
            {
                match time.parse::<i64>() {
                    Ok(time) => Some((time, id.to_owned())),
                    Err(_) => return store_error(StoreError::Invalid),
                }
            }
            _ => return store_error(StoreError::Invalid),
        }
    } else {
        None
    };
    let result = state.admin.read(move |c| {
        actor(c, &auth, Some(Permission::ViewStatus))?;
        let (at, id) = before.unwrap_or((i64::MAX, "~".into()));
        let mut statement = c.prepare("SELECT id FROM operation_requests WHERE (?1 IS NULL OR kind=?1) AND (?2 IS NULL OR state=?2) AND (created_at,id)<(?3,?4) ORDER BY created_at DESC,id DESC LIMIT ?5")?;
        let ids = statement.query_map(params![kind, filter, at, id, limit as i64 + 1], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
        let more = ids.len() > limit;
        let jobs = ids.into_iter().take(limit).map(|id| load_job(c, &id)?.ok_or(StoreError::Unavailable)).collect::<Result<Vec<_>, _>>()?;
        Ok((jobs, more))
    }).await;
    match result {
        Ok((jobs, more)) => {
            let cursor = if more {
                jobs.last()
                    .map(|job| format!("{}:{}", job.created_at, job.id))
            } else {
                None
            };
            let mut projected = Vec::with_capacity(jobs.len());
            for job in jobs {
                projected.push(state.jobs.overlay(job).await);
            }
            Json(serde_json::json!({"jobs":projected,"nextCursor":cursor,"hasMore":more,"activeSuites":state.jobs.snapshot().await})).into_response()
        }
        Err(error) => store_error(error),
    }
}

pub async fn post_cancel_job(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let auth = match authenticate(&state, &headers, true, Some(Permission::TriggerSync)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    if id.len() > 64 {
        return store_error(StoreError::Invalid);
    }
    tokio::spawn(async move {
        match state.jobs.cancel(auth, id).await {
            Ok(Some(job)) => Json(serde_json::json!({"job":job})).into_response(),
            Ok(None) => error_reply(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "Operation not found.",
            ),
            Err(error) => store_error(error),
        }
    })
    .await
    .unwrap_or_else(|_| store_error(StoreError::Unavailable))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    async fn fixture() -> (
        tempfile::TempDir,
        AdminStore,
        JobRegistry,
        AuthContext,
        SuiteKey,
    ) {
        let root = tempfile::tempdir().unwrap();
        let admin = AdminStore::open(&root.path().join("admin")).unwrap();
        let token = std::fs::read_to_string(root.path().join("admin/control.token")).unwrap();
        let auth = admin
            .authenticate_control(token.trim().into())
            .await
            .unwrap();
        let registry = JobRegistry::new(admin.clone());
        (
            root,
            admin,
            registry,
            auth,
            SuiteKey::new("debian", "trixie").unwrap(),
        )
    }
    async fn submit(
        registry: &JobRegistry,
        auth: &AuthContext,
        targets: Vec<SuiteKey>,
        key: &str,
    ) -> (JobView, bool) {
        let reason = "Operator requested metadata refresh".to_owned();
        let hash = request_hash("sync", &targets, &reason, None).unwrap();
        registry
            .admit_sync(auth.clone(), targets, key.into(), hash, reason)
            .await
            .unwrap()
    }
    async fn stored(admin: &AdminStore, id: &str) -> JobView {
        let id = id.to_owned();
        admin
            .read(move |c| load_job(c, &id)?.ok_or(StoreError::Unavailable))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn idempotency_replays_one_intent_and_conflicting_reuse_is_rejected() {
        let (_root, admin, registry, auth, key) = fixture().await;
        let (first, replay) = submit(&registry, &auth, vec![key.clone()], "retry").await;
        assert!(!replay);
        let (same, replay) = submit(&registry, &auth, vec![key.clone()], "retry").await;
        assert!(replay);
        assert_eq!(first.id, same.id);
        assert_eq!(first.targets[0].pass_id, same.targets[0].pass_id);
        let conflict = registry
            .admit_sync(
                auth,
                vec![key],
                "retry".into(),
                "a".repeat(64),
                "Changed request".into(),
            )
            .await;
        assert_eq!(conflict.err(), Some(StoreError::Conflict));
        let (requests, intents) = admin.read(|c| Ok((
            c.query_row("SELECT count(*) FROM operation_requests", [], |row| row.get::<_, i64>(0))?,
            c.query_row("SELECT count(*) FROM audit_events WHERE action='sync.request' AND outcome='intent'", [], |row| row.get::<_, i64>(0))?,
        ))).await.unwrap();
        assert_eq!((requests, intents), (1, 1));
    }

    #[tokio::test]
    async fn requests_before_observation_share_a_pass_and_later_requests_share_one_recheck() {
        let (_root, admin, registry, auth, key) = fixture().await;
        let (first, _) = submit(&registry, &auth, vec![key.clone()], "first").await;
        registry.pass_started(&key, "recovering").await;
        let (before, _) = submit(&registry, &auth, vec![key.clone()], "before").await;
        assert_eq!(first.targets[0].pass_id, before.targets[0].pass_id);
        assert_eq!(before.targets[0].disposition, "queued");
        registry.pass_started(&key, "observing").await;
        let (after, _) = submit(&registry, &auth, vec![key.clone()], "after").await;
        let (another, _) = submit(&registry, &auth, vec![key.clone()], "another").await;
        assert_ne!(first.targets[0].pass_id, after.targets[0].pass_id);
        assert_eq!(after.targets[0].pass_id, another.targets[0].pass_id);
        assert_eq!(after.targets[0].disposition, "queued_recheck");
        assert!(registry.snapshot().await[0].recheck_after_current);
        assert!(
            registry
                .pass_completed(&key, "renewed", Some("a".repeat(64)), None)
                .await
        );
        assert_eq!(stored(&admin, &first.id).await.state, "succeeded");
        assert_eq!(stored(&admin, &after.id).await.state, "queued");
        registry.pass_started(&key, "observing").await;
        assert!(
            !registry
                .pass_completed(&key, "published", Some("b".repeat(64)), None)
                .await
        );
        assert_eq!(stored(&admin, &after.id).await.state, "succeeded");
        assert_eq!(stored(&admin, &another.id).await.state, "succeeded");
    }

    #[tokio::test]
    async fn cancellation_only_removes_references_that_have_not_started_observation() {
        let (_root, admin, registry, auth, key) = fixture().await;
        let (active, _) = submit(&registry, &auth, vec![key.clone()], "active").await;
        registry.pass_started(&key, "observing").await;
        let (queued, _) = submit(&registry, &auth, vec![key.clone()], "queued").await;
        let retained = registry
            .cancel(auth.clone(), active.id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.state, "running");
        assert!(!retained.cancellable);
        let cancelled = registry
            .cancel(auth, queued.id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cancelled.state, "cancelled");
        assert!(!registry.snapshot().await[0].recheck_after_current);
        assert!(!registry.pass_completed(&key, "published", None, None).await);
        assert_eq!(stored(&admin, &active.id).await.state, "succeeded");
        assert_eq!(stored(&admin, &queued.id).await.state, "cancelled");
    }

    #[tokio::test]
    async fn recovering_targets_are_still_cancellable_before_observation() {
        let (_root, _admin, registry, auth, key) = fixture().await;
        let (job, _) = submit(&registry, &auth, vec![key.clone()], "recover").await;
        registry.pass_started(&key, "recovering").await;
        let cancelled = registry.cancel(auth, job.id).await.unwrap().unwrap();
        assert_eq!(cancelled.targets[0].state, "cancelled");
        assert!(registry.snapshot().await[0].active_pass_id.is_some());
    }

    #[tokio::test]
    async fn superseded_generation_results_cannot_finish_the_replacement() {
        let (_root, admin, registry, auth, key) = fixture().await;
        let (job, _) = submit(&registry, &auth, vec![key.clone()], "supersede").await;
        registry.pass_started(&key, "observing").await;
        registry
            .phase_changed(
                &key,
                "staging",
                Some("a".repeat(64)),
                Some(1),
                Some(7),
                None,
            )
            .await;
        registry
            .phase_changed(
                &key,
                "staging",
                Some("b".repeat(64)),
                Some(1),
                Some(9),
                None,
            )
            .await;
        assert!(
            !registry
                .pass_completed(&key, "published", Some("a".repeat(64)), None)
                .await
        );
        assert_eq!(stored(&admin, &job.id).await.state, "running");
        registry
            .pass_completed(&key, "published", Some("b".repeat(64)), None)
            .await;
        let completed = stored(&admin, &job.id).await;
        assert_eq!(completed.state, "succeeded");
        assert_eq!(completed.targets[0].generation_id, Some("b".repeat(64)));
        assert_eq!(
            completed.targets[0].superseded_generation_ids,
            vec!["a".repeat(64)]
        );
    }

    #[tokio::test]
    async fn parent_states_distinguish_success_partial_and_failure() {
        let (_root, admin, registry, auth, first_key) = fixture().await;
        let second_key = SuiteKey::new("debian", "trixie-updates").unwrap();
        for (id, outcomes, expected) in [
            ("all-good", ["published", "renewed"], "succeeded"),
            ("mixed", ["published", "rejected"], "partial"),
            ("all-bad", ["failed", "rejected"], "failed"),
        ] {
            let (job, _) = submit(
                &registry,
                &auth,
                vec![first_key.clone(), second_key.clone()],
                id,
            )
            .await;
            registry.pass_started(&first_key, "observing").await;
            registry.pass_started(&second_key, "observing").await;
            registry
                .pass_completed(&first_key, outcomes[0], None, None)
                .await;
            assert_eq!(stored(&admin, &job.id).await.state, "running");
            registry
                .pass_completed(&second_key, outcomes[1], None, None)
                .await;
            assert_eq!(stored(&admin, &job.id).await.state, expected);
        }
    }

    #[tokio::test]
    async fn startup_interrupts_unfinished_rows_without_replaying_or_changing_finished_targets() {
        let (_root, admin, registry, auth, first_key) = fixture().await;
        let second_key = SuiteKey::new("debian", "trixie-updates").unwrap();
        let (job, _) = submit(
            &registry,
            &auth,
            vec![first_key.clone(), second_key],
            "restart",
        )
        .await;
        registry.pass_started(&first_key, "observing").await;
        registry
            .pass_completed(&first_key, "published", None, None)
            .await;
        JobRegistry::reconcile_startup(&admin).await.unwrap();
        JobRegistry::reconcile_startup(&admin).await.unwrap();
        let interrupted = stored(&admin, &job.id).await;
        assert_eq!(interrupted.state, "interrupted");
        assert_eq!(interrupted.error.as_deref(), Some(RESTART_REASON));
        assert_eq!(interrupted.targets[0].state, "published");
        assert_eq!(interrupted.targets[1].state, "interrupted");
        assert_eq!(
            interrupted.targets[1].error.as_deref(),
            Some(RESTART_REASON)
        );
        let fresh_registry = JobRegistry::new(admin);
        assert!(fresh_registry.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn recording_failure_does_not_erase_live_terminal_truth() {
        let (_root, _admin, registry, auth, key) = fixture().await;
        let (job, _) = submit(&registry, &auth, vec![key.clone()], "recording").await;
        registry.pass_started(&key, "observing").await;
        let broken = JobRegistry {
            admin: AdminStore::unavailable(),
            inner: registry.inner,
        };
        broken.pass_completed(&key, "published", None, None).await;
        let live = broken.overlay(job).await;
        assert_eq!(live.state, "succeeded");
        assert!(live.recording_incomplete);
        assert!(broken.snapshot().await[0].recording_incomplete);
    }
}
