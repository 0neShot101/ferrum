//! Explicit operator prewarming through the authenticated package pipeline.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::extract::{State, rejection::JsonRejection};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::admin::jobs::{JobRegistry, JobView};
use crate::admin::{Permission, StoreError};
use crate::health::HealthState;
use crate::server::{AppState, PreparedWarm, prepare_warm, warm_package};

const MAX_OBJECTS: usize = 128;
const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_SECONDS: u64 = 3600;
const MAX_CONCURRENCY: usize = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrewarmRequest {
    pub paths: Vec<String>,
    pub max_bytes: u64,
    pub max_objects: usize,
    pub timeout_seconds: u64,
    pub concurrency: usize,
    pub reason: Option<String>,
    pub idempotency_key: Option<String>,
}

impl PrewarmRequest {
    fn validate(&self) -> Result<(), StoreError> {
        if self.paths.is_empty()
            || self.paths.len() > MAX_OBJECTS
            || !(1..=MAX_OBJECTS).contains(&self.max_objects)
            || self.paths.len() > self.max_objects
            || !(1..=MAX_BYTES).contains(&self.max_bytes)
            || !(1..=MAX_SECONDS).contains(&self.timeout_seconds)
            || !(1..=MAX_CONCURRENCY).contains(&self.concurrency)
            || self
                .paths
                .iter()
                .any(|path| path.is_empty() || path.len() > 4096)
        {
            return Err(StoreError::Invalid);
        }
        let mut paths = BTreeSet::new();
        if self
            .paths
            .iter()
            .any(|path| !paths.insert(path.trim_start_matches('/')))
        {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }

    fn charge(
        &self,
        bytes: &mut u64,
        objects: &mut usize,
        additional_bytes: u64,
        additional_objects: usize,
    ) -> Result<(), StoreError> {
        let next_bytes = bytes
            .checked_add(additional_bytes)
            .ok_or(StoreError::Invalid)?;
        let next_objects = objects
            .checked_add(additional_objects)
            .ok_or(StoreError::Invalid)?;
        if next_bytes > self.max_bytes || next_objects > self.max_objects {
            return Err(StoreError::Invalid);
        }
        *bytes = next_bytes;
        *objects = next_objects;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrewarmItem {
    pub path: String,
    pub bytes: u64,
    pub objects: usize,
    pub state: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrewarmProgress {
    pub items: Vec<PrewarmItem>,
    pub byte_scope: String,
    pub planned_bytes: u64,
    pub charged_bytes: u64,
    pub planned_objects: usize,
    pub cache_hits: usize,
    pub filled: usize,
    pub failed: usize,
}

impl PrewarmProgress {
    fn prepare(packages: &[PreparedWarm], request: &PrewarmRequest) -> Result<Self, StoreError> {
        let mut bytes = 0u64;
        let mut objects = 0usize;
        let mut paths = BTreeSet::new();
        let mut items = Vec::with_capacity(packages.len());
        for package in packages {
            request.charge(&mut bytes, &mut objects, package.size, package.objects)?;
            if !paths.insert(package.path.as_str()) {
                return Err(StoreError::Invalid);
            }
            items.push(PrewarmItem {
                path: package.path.clone(),
                bytes: package.size,
                objects: package.objects,
                state: "queued".into(),
                error: None,
            });
        }
        let progress = Self {
            items,
            byte_scope: "Authenticated package/signature admission bytes, not wire bytes; durable transfer allowances apply independently".into(),
            planned_bytes: bytes,
            charged_bytes: 0,
            planned_objects: objects,
            cache_hits: 0,
            filled: 0,
            failed: 0,
        };
        // Leave room in the existing 64 KiB durable job row for bounded error
        // messages and terminal states without introducing a second journal.
        if serde_json::to_vec(&progress)
            .map_err(|_| StoreError::Invalid)?
            .len()
            > 24 * 1024
        {
            return Err(StoreError::Invalid);
        }
        Ok(progress)
    }
}

pub struct Prewarm {
    state: Arc<AppState>,
    admission: Arc<Semaphore>,
    cancel: CancellationToken,
    active: Mutex<Option<(String, CancellationToken)>>,
    tasks: Mutex<JoinSet<()>>,
}

impl Prewarm {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            admission: Arc::new(Semaphore::new(1)),
            cancel: CancellationToken::new(),
            active: Mutex::new(None),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub(crate) fn cancel(&self, id: &str) {
        let active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some((active_id, cancel)) = active.as_ref()
            && active_id == id
        {
            cancel.cancel();
        }
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let mut tasks = {
            let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
            std::mem::take(&mut *tasks)
        };
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                tracing::error!(%error, "prewarm task failed during shutdown");
            }
        }
    }

    async fn start(
        self: &Arc<Self>,
        jobs: Arc<JobRegistry>,
        auth: crate::admin::AuthContext,
        request: PrewarmRequest,
        key: String,
        hash: String,
        reason: String,
    ) -> Result<JobView, StoreError> {
        request.validate()?;
        if let Some(job) = jobs
            .replay_prewarm(auth.clone(), key.clone(), hash.clone())
            .await?
        {
            return Ok(job);
        }
        let permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| StoreError::Busy)?;
        if self.cancel.is_cancelled()
            || self.state.registry.max_fill_slots() < 2
            || request.concurrency > self.state.registry.max_fill_slots() - 1
        {
            return Err(StoreError::Busy);
        }

        let deadline = Instant::now() + Duration::from_secs(request.timeout_seconds);
        let prepare = async {
            let mut packages = Vec::with_capacity(request.paths.len());
            for path in &request.paths {
                packages.push(prepare_warm(&self.state, path).await.map_err(|error| {
                    tracing::debug!(%error, "prewarm admission refused");
                    StoreError::Invalid
                })?);
            }
            Ok::<_, StoreError>(packages)
        };
        let packages = tokio::select! {
            () = self.cancel.cancelled() => return Err(StoreError::Unavailable),
            result = tokio::time::timeout_at(deadline, prepare) => {
                result.map_err(|_| StoreError::Busy)??
            }
        };
        let progress = PrewarmProgress::prepare(&packages, &request)?;
        let (job, replay) = jobs
            .admit_prewarm(auth, key, hash, reason, progress.clone())
            .await?;
        if replay {
            return Ok(job);
        }
        let cancel = self.cancel.child_token();
        *self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some((job.id.clone(), cancel.clone()));
        let controller = Arc::clone(self);
        let id = job.id.clone();
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            let _permit = permit;
            controller
                .run(
                    &jobs,
                    &id,
                    packages,
                    progress,
                    request.concurrency,
                    (deadline, cancel),
                )
                .await;
            *controller
                .active
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = None;
        });
        Ok(job)
    }

    async fn run(
        &self,
        jobs: &JobRegistry,
        id: &str,
        packages: Vec<PreparedWarm>,
        mut progress: PrewarmProgress,
        concurrency: usize,
        (deadline, cancel): (Instant, CancellationToken),
    ) {
        let mut queue: VecDeque<_> = packages.into_iter().enumerate().collect();
        let mut running = JoinSet::new();
        let mut pending = Vec::with_capacity(concurrency);
        let mut worker_failed = false;
        let mut stopped = false;
        loop {
            while !stopped && running.len() + pending.len() < concurrency {
                if cancel.is_cancelled() || Instant::now() >= deadline {
                    stopped = true;
                    cancel.cancel();
                    break;
                }
                let Some((index, package)) = queue.pop_front() else {
                    break;
                };
                progress.items[index].state = "running".into();
                // Reserve the complete authenticated charge before dispatch.
                // Cancellation and failed transfers never refund this job budget.
                progress.charged_bytes += package.size;
                pending.push((index, package));
            }
            match jobs.record_prewarm(id, progress.clone(), false).await {
                Ok(true) => {}
                Ok(false) => {
                    stopped = true;
                    cancel.cancel();
                }
                Err(error) => {
                    tracing::warn!(%error, "prewarm progress recording failed; stopping admission");
                    stopped = true;
                    cancel.cancel();
                }
            }
            for (index, package) in pending.drain(..) {
                if stopped {
                    progress.items[index].state = "cancelled".into();
                    continue;
                }
                let state = Arc::clone(&self.state);
                let cancel = cancel.clone();
                running.spawn(async move {
                    let result = warm_package(&state, &package, deadline, cancel).await;
                    (index, result)
                });
            }
            if running.is_empty() {
                break;
            }
            match running.join_next().await {
                Some(Ok((index, result))) => {
                    let item = &mut progress.items[index];
                    match result {
                        Ok(true) => {
                            item.state = "cache_hit".into();
                            progress.cache_hits += 1;
                        }
                        Ok(false) => {
                            item.state = "filled".into();
                            progress.filled += 1;
                        }
                        Err(error) => {
                            item.state = if cancel.is_cancelled() {
                                "cancelled"
                            } else {
                                "failed"
                            }
                            .into();
                            item.error = Some(bounded_error(&error));
                            progress.failed += usize::from(!cancel.is_cancelled());
                        }
                    }
                }
                Some(Err(error)) => {
                    tracing::error!(%error, "prewarm worker failed");
                    worker_failed = true;
                    stopped = true;
                    cancel.cancel();
                }
                None => break,
            }
        }
        for item in &mut progress.items {
            if item.state == "running" && worker_failed {
                item.state = "failed".into();
                item.error = Some("Prewarm worker failed".into());
                progress.failed += 1;
            } else if matches!(item.state.as_str(), "queued" | "running") {
                item.state = "cancelled".into();
                item.error = Some(
                    "Admission stopped or deadline expired; shared foreground fills may continue"
                        .into(),
                );
            }
        }
        if let Err(error) = jobs.record_prewarm(id, progress, true).await {
            tracing::error!(%error, "prewarm terminal result recording failed");
        }
    }
}

pub(crate) async fn post_prewarm(
    State(state): State<Arc<HealthState>>,
    headers: HeaderMap,
    payload: Result<Json<PrewarmRequest>, JsonRejection>,
) -> Response {
    use crate::admin::routes::{authenticate, error_reply, store_error};

    let auth = match authenticate(&state, &headers, true, Some(Permission::TriggerSync)).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let request = match payload {
        Ok(Json(request)) => request,
        Err(error) if error.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return error_reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "Request body exceeds its limit.",
            );
        }
        Err(_) => return store_error(StoreError::Invalid),
    };
    let Some(prewarm) = state.prewarm.as_ref().map(Arc::clone) else {
        return store_error(StoreError::Unavailable);
    };
    let prepared = (|| {
        request.validate()?;
        let reason =
            crate::admin::jobs::reason(request.reason.clone(), "Operator package prewarm")?;
        let key = crate::admin::jobs::idempotency(&headers, request.idempotency_key.clone())?;
        let hash = crate::admin::password::digest(
            serde_json::to_string(&(
                "prewarm",
                &request.paths,
                request.max_bytes,
                request.max_objects,
                request.timeout_seconds,
                request.concurrency,
                &reason,
            ))
            .map_err(|_| StoreError::Invalid)?
            .as_bytes(),
        );
        Ok::<_, StoreError>((reason, key, hash))
    })();
    let (reason, key, hash) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return store_error(error),
    };
    // Admission and persistence survive an HTTP disconnect, like sync jobs.
    tokio::spawn(async move {
        match prewarm
            .start(Arc::clone(&state.jobs), auth, request, key, hash, reason)
            .await
        {
            Ok(job) => {
                (StatusCode::ACCEPTED, Json(serde_json::json!({"job": job}))).into_response()
            }
            Err(error) => store_error(error),
        }
    })
    .await
    .unwrap_or_else(|_| store_error(StoreError::Unavailable))
}

fn bounded_error(error: &str) -> String {
    let mut length = 0;
    error
        .chars()
        .filter(|character| !character.is_control())
        .take_while(|character| {
            length += character.len_utf8();
            length <= 96
        })
        .collect()
}

pub enum PrewarmCommand {
    Run(PrewarmRequest),
    Status(String),
    Cancel(String),
}

/// Contact only the configured private listener, with the protected control
/// token. No offline or unsigned fallback exists.
pub async fn execute(
    config: &crate::config::Config,
    command: PrewarmCommand,
) -> anyhow::Result<serde_json::Value> {
    use anyhow::Context;

    let token = crate::admin::migration::read_control_token(&config.admin.state_dir)
        .context("read protected local admin control token")?;
    let origin = url::Url::parse(&config.admin.origin).context("configured admin origin")?;
    let authority = &origin[url::Position::BeforeHost..url::Position::AfterPort];
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .context("admin HTTP client")?;
    let base = format!("http://{}/api/admin", config.listen.admin);
    let request = match command {
        PrewarmCommand::Run(request) => {
            request.validate().map_err(anyhow::Error::msg)?;
            client
                .post(format!("{base}/prewarm"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&request)?)
        }
        PrewarmCommand::Status(id) | PrewarmCommand::Cancel(id)
            if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            anyhow::bail!("invalid prewarm job identifier");
        }
        PrewarmCommand::Status(id) => client.get(format!("{base}/jobs/{id}")),
        PrewarmCommand::Cancel(id) => client.post(format!("{base}/jobs/{id}/cancel")),
    };
    let mut response = request
        .header(reqwest::header::HOST, authority)
        .bearer_auth(token)
        .send()
        .await
        .context("private gateway administration listener unreachable")?;
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("admin response body")? {
        anyhow::ensure!(
            body.len().saturating_add(chunk.len()) <= 128 * 1024,
            "admin response too large"
        );
        body.extend_from_slice(&chunk);
    }
    anyhow::ensure!(
        status.is_success(),
        "prewarm command refused ({status}): {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).context("invalid admin job response")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> PrewarmRequest {
        PrewarmRequest {
            paths: vec!["debian/pool/package.deb".into()],
            max_bytes: 1024,
            max_objects: 2,
            timeout_seconds: 30,
            concurrency: 1,
            reason: None,
            idempotency_key: None,
        }
    }

    #[test]
    fn operator_budgets_and_explicit_unique_paths_are_required() {
        let valid = request();
        assert_eq!(valid.validate(), Ok(()));
        let mut invalid = valid.clone();
        invalid.max_bytes = 0;
        assert_eq!(invalid.validate(), Err(StoreError::Invalid));
        invalid = valid.clone();
        invalid.timeout_seconds = MAX_SECONDS + 1;
        assert_eq!(invalid.validate(), Err(StoreError::Invalid));
        invalid = valid.clone();
        invalid.concurrency = MAX_CONCURRENCY + 1;
        assert_eq!(invalid.validate(), Err(StoreError::Invalid));
        invalid = valid;
        invalid.paths.push("/debian/pool/package.deb".into());
        assert_eq!(invalid.validate(), Err(StoreError::Invalid));
    }

    #[test]
    fn full_batch_and_signature_charges_refuse_before_dispatch() {
        let request = request();
        let (mut bytes, mut objects) = (0, 0);
        assert_eq!(request.charge(&mut bytes, &mut objects, 600, 1), Ok(()));
        assert_eq!(
            request.charge(&mut bytes, &mut objects, 500, 1),
            Err(StoreError::Invalid)
        );
        assert_eq!((bytes, objects), (600, 1));
        assert_eq!(
            request.charge(&mut bytes, &mut objects, 1, 2),
            Err(StoreError::Invalid)
        );
        assert_eq!((bytes, objects), (600, 1));
        bytes = u64::MAX;
        assert_eq!(
            request.charge(&mut bytes, &mut objects, 1, 1),
            Err(StoreError::Invalid)
        );
    }

    #[test]
    fn retained_failure_text_is_byte_bounded_and_printable() {
        let error = bounded_error(&format!("{}\n\u{0000}", "\u{00e9}".repeat(200)));
        assert!(error.len() <= 96);
        assert!(!error.chars().any(char::is_control));
    }
}
