//! JSON control API: fault table, settings, request log and root swapping.

use std::collections::BTreeMap;
use std::path::PathBuf;

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::faults::{Fault, FaultError, LogEntry, WILDCARD_PATH};
use crate::server::{Origin, OriginError, PathError, validate_relative_path};

/// Build the control router over `origin`.
pub(crate) fn router(origin: Origin) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/faults", get(list_faults).delete(clear_faults))
        .route("/faults/{*path}", put(set_fault).delete(remove_fault))
        .route("/settings", put(update_settings))
        .route("/log", get(read_log).delete(clear_log))
        .route("/root", put(set_root))
        .with_state(origin)
}

/// Control-API failures, rendered as `{"error": "..."}` with a 4xx/5xx status.
#[derive(Debug, thiserror::Error)]
enum ControlError {
    #[error("invalid fault path: {0}")]
    Path(#[from] PathError),
    #[error(transparent)]
    Fault(#[from] FaultError),
    #[error("no fault registered for {0:?}")]
    UnknownFault(String),
    #[error(transparent)]
    Root(#[from] OriginError),
}

impl ControlError {
    fn status(&self) -> StatusCode {
        match self {
            ControlError::Fault(FaultError::TableFull) => StatusCode::INSUFFICIENT_STORAGE,
            ControlError::Path(_) | ControlError::Fault(_) => StatusCode::BAD_REQUEST,
            ControlError::UnknownFault(_) => StatusCode::NOT_FOUND,
            ControlError::Root(OriginError::RootIo { .. }) => StatusCode::NOT_FOUND,
            ControlError::Root(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for ControlError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.to_string() });
        (self.status(), Json(body)).into_response()
    }
}

#[derive(Serialize)]
struct Status {
    status: &'static str,
}

async fn healthz() -> Json<Status> {
    Json(Status { status: "ok" })
}

async fn list_faults(State(origin): State<Origin>) -> Json<BTreeMap<String, Fault>> {
    Json(origin.faults().snapshot())
}

async fn clear_faults(State(origin): State<Origin>) -> StatusCode {
    origin.faults().clear();
    StatusCode::NO_CONTENT
}

fn fault_key(path: String) -> Result<String, ControlError> {
    if path != WILDCARD_PATH {
        validate_relative_path(&path)?;
    }
    Ok(path)
}

async fn set_fault(
    State(origin): State<Origin>,
    Path(path): Path<String>,
    Json(fault): Json<Fault>,
) -> Result<StatusCode, ControlError> {
    let key = fault_key(path)?;
    tracing::info!(path = %key, ?fault, "fault set");
    origin.faults().set(key, fault)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_fault(
    State(origin): State<Origin>,
    Path(path): Path<String>,
) -> Result<StatusCode, ControlError> {
    let key = fault_key(path)?;
    if !origin.faults().remove(&key) {
        return Err(ControlError::UnknownFault(key));
    }
    tracing::info!(path = %key, "fault removed");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct Settings {
    head_enabled: Option<bool>,
}

#[derive(Serialize)]
struct EffectiveSettings {
    head_enabled: bool,
}

async fn update_settings(
    State(origin): State<Origin>,
    Json(settings): Json<Settings>,
) -> Json<EffectiveSettings> {
    if let Some(enabled) = settings.head_enabled {
        origin.set_head_enabled(enabled);
        tracing::info!(head_enabled = enabled, "settings updated");
    }
    Json(EffectiveSettings {
        head_enabled: origin.head_enabled(),
    })
}

async fn read_log(State(origin): State<Origin>) -> Json<Vec<LogEntry>> {
    Json(origin.log().snapshot())
}

async fn clear_log(State(origin): State<Origin>) -> StatusCode {
    origin.log().clear();
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
struct RootRequest {
    root: PathBuf,
}

#[derive(Serialize)]
struct RootResponse {
    root: PathBuf,
}

async fn set_root(
    State(origin): State<Origin>,
    Json(request): Json<RootRequest>,
) -> Result<Json<RootResponse>, ControlError> {
    origin.set_root(request.root).await?;
    let root = origin.root();
    tracing::info!(root = %root.display(), "root swapped");
    Ok(Json(RootResponse {
        root: root.as_ref().clone(),
    }))
}
