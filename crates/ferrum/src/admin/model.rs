//! Token-free administration DTOs and classified boundary failures.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ViewStatus,
    TriggerSync,
    ManageCache,
    ManageUsers,
    ViewInventory,
    ViewAudit,
    ManageConfig,
    AcknowledgeAlerts,
}
impl Permission {
    const VALUES: [Self; 8] = [
        Self::ViewStatus,
        Self::TriggerSync,
        Self::ManageCache,
        Self::ManageUsers,
        Self::ViewInventory,
        Self::ViewAudit,
        Self::ManageConfig,
        Self::AcknowledgeAlerts,
    ];
    pub fn all() -> BTreeSet<Self> {
        BTreeSet::from(Self::VALUES)
    }
    pub(crate) fn mask(self) -> i64 {
        1 << self as u8
    }
    pub(crate) fn from_mask(mask: i64) -> Vec<Self> {
        Self::VALUES
            .into_iter()
            .filter(|p| mask & p.mask() != 0)
            .collect()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub permissions: Vec<Permission>,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    pub disabled: bool,
}
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user: UserView,
    pub session_id: String,
    pub csrf_token: String,
    pub machine: bool,
}
pub struct SessionGrant {
    pub token: String,
    pub auth: AuthContext,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    pub id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
    pub current: bool,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditView {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub reason: String,
    pub created_at: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("Authentication required")]
    Unauthorized,
    #[error("Operation not permitted")]
    Forbidden,
    #[error("State conflict")]
    Conflict,
    #[error("Invalid administration values")]
    Invalid,
    #[error("Administration capacity temporarily exhausted")]
    Busy,
    #[error("Administration state unavailable")]
    Unavailable,
}
impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        match value.sqlite_error_code() {
            Some(
                rusqlite::ErrorCode::DatabaseBusy
                | rusqlite::ErrorCode::DatabaseLocked
                | rusqlite::ErrorCode::OperationInterrupted
                | rusqlite::ErrorCode::DiskFull,
            ) => Self::Busy,
            Some(rusqlite::ErrorCode::ConstraintViolation) => Self::Conflict,
            _ => Self::Unavailable,
        }
    }
}
impl From<std::io::Error> for StoreError {
    fn from(_: std::io::Error) -> Self {
        Self::Unavailable
    }
}
