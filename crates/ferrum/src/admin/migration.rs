//! Explicit offline import; never opens or modifies the core catalog.
use super::{
    model::{Permission, StoreError, UserView},
    password, store,
};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    path::{Component, Path, PathBuf},
};
pub use store::{read_bootstrap_token, read_control_token};
const MAX_SOURCE: u64 = 2 * 1024 * 1024;
#[derive(Debug)]
pub struct MigrationReport {
    pub users: usize,
    pub already_migrated: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDocument {
    schema_version: u32,
    users: Vec<LegacyUser>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyUser {
    id: String,
    username: String,
    display_name: String,
    salt_hex: String,
    password_hash_hex: String,
    permissions: BTreeSet<Permission>,
    created_at: i64,
    last_login_at: Option<i64>,
}

pub fn legacy_present(spool_root: &Path) -> Result<bool, StoreError> {
    for name in ["admin-users.json.tmp", "admin-users.tmp"] {
        match fs::symlink_metadata(spool_root.join(name)) {
            Ok(_) => return Err(StoreError::Conflict),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    match fs::symlink_metadata(spool_root.join("admin-users.json")) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(StoreError::Unavailable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn read_source(path: &Path) -> Result<Vec<u8>, StoreError> {
    store::check_file(path, false)?;
    if fs::metadata(path)?.len() > MAX_SOURCE {
        return Err(StoreError::Invalid);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let mut bytes = Vec::new();
    options
        .open(path)?
        .take(MAX_SOURCE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SOURCE {
        return Err(StoreError::Invalid);
    }
    Ok(bytes)
}
fn hex(value: &str) -> bool {
    matches!(value.len(), 32 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode(bytes: &[u8]) -> Result<Vec<(UserView, String)>, StoreError> {
    let document: LegacyDocument =
        serde_json::from_slice(bytes).map_err(|_| StoreError::Invalid)?;
    if document.schema_version != 1 || document.users.is_empty() || document.users.len() > 128 {
        return Err(StoreError::Invalid);
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut rows = Vec::with_capacity(document.users.len());
    for user in document.users {
        if !hex(&user.id)
            || !hex(&user.salt_hex)
            || user.password_hash_hex.len() != 64
            || !hex(&user.password_hash_hex)
            || !ids.insert(user.id.clone())
            || !names.insert(user.username.clone())
            || user.permissions.iter().any(|p| {
                !matches!(
                    p,
                    Permission::ViewStatus
                        | Permission::TriggerSync
                        | Permission::ManageCache
                        | Permission::ManageUsers
                )
            })
        {
            return Err(StoreError::Invalid);
        }
        let permissions: Vec<Permission> = if user.permissions.len() == 4 {
            Permission::all().into_iter().collect()
        } else {
            user.permissions.into_iter().collect()
        };
        store::permission_mask(&permissions)?;
        let view = UserView {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            permissions,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
            disabled: false,
        };
        rows.push((
            view,
            format!("legacy:{}:{}", user.salt_hex, user.password_hash_hex),
        ));
    }
    Ok(rows)
}
fn absolute_normal(path: &Path) -> Result<PathBuf, StoreError> {
    let path = std::path::absolute(path)?;
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                if !result.pop() {
                    return Err(StoreError::Invalid);
                }
            }
            Component::CurDir => {}
            _ => result.push(part.as_os_str()),
        }
    }
    Ok(result)
}
fn validate_spool(root: &Path) -> Result<(), StoreError> {
    for ancestor in root.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let m = fs::symlink_metadata(ancestor)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(StoreError::Unavailable);
        }
    }
    let m = fs::metadata(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != rustix::process::geteuid().as_raw() {
            return Err(StoreError::Unavailable);
        }
    }
    #[cfg(not(unix))]
    let _ = m;
    Ok(())
}
fn spool_lock(root: &Path) -> Result<fd_lock::RwLock<std::fs::File>, StoreError> {
    let path = root.join("lock");
    let m = fs::symlink_metadata(&path)?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err(StoreError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != rustix::process::geteuid().as_raw() || m.nlink() != 1 {
            return Err(StoreError::Unavailable);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let mut lock = fd_lock::RwLock::new(options.open(path)?);
    match lock.try_write() {
        Ok(g) => std::mem::forget(g),
        Err(_) => return Err(StoreError::Busy),
    }
    Ok(lock)
}

pub fn migrate(spool_root: &Path, admin_root: &Path) -> Result<MigrationReport, StoreError> {
    let spool = absolute_normal(spool_root)?;
    let admin = absolute_normal(admin_root)?;
    if admin.starts_with(&spool) || spool.starts_with(&admin) {
        return Err(StoreError::Invalid);
    }
    validate_spool(&spool)?;
    let _spool_lock = spool_lock(&spool)?;
    let present = legacy_present(&spool)?;
    let source = spool.join("admin-users.json");
    let backup = admin.join("legacy-users.backup.json");
    if !present && !backup.exists() {
        return Err(StoreError::Invalid);
    }
    let bytes = if present {
        read_source(&source)?
    } else {
        read_source(&backup)?
    };
    let rows = decode(&bytes)?;
    let source_hash = password::digest(&bytes);
    for (user, _) in &rows {
        store::validate_identity(&user.username, &user.display_name)?;
    }
    let (mut connection, _admin_lock) = store::open_offline(&admin)?;
    let receipt: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key='migration_source_sha256'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if receipt
        .as_ref()
        .is_some_and(|receipt| receipt != &source_hash)
    {
        return Err(StoreError::Conflict);
    }
    let source_identity = password::digest(spool.to_string_lossy().as_bytes());
    if receipt.is_some() {
        let recorded: String = connection.query_row(
            "SELECT value FROM metadata WHERE key='migration_source_path_hash'",
            [],
            |r| r.get(0),
        )?;
        if recorded != source_identity {
            return Err(StoreError::Conflict);
        }
    }
    if receipt.is_none() {
        let count: i64 = connection.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?;
        let state: String = connection.query_row(
            "SELECT value FROM metadata WHERE key='bootstrap_state'",
            [],
            |r| r.get(0),
        )?;
        if count != 0 || state != "pending" {
            return Err(StoreError::Conflict);
        }
    } else if !backup.exists() {
        return Err(StoreError::Unavailable);
    }
    let pending: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key='migration_pending_sha256'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let stage = admin.join("legacy-users.backup.stage");
    if let Some(pending) = &pending {
        let path_hash: String = connection.query_row(
            "SELECT value FROM metadata WHERE key='migration_pending_path_hash'",
            [],
            |r| r.get(0),
        )?;
        if pending != &source_hash || path_hash != source_identity {
            return Err(StoreError::Conflict);
        }
    } else {
        if fs::symlink_metadata(&stage).is_ok() {
            return Err(StoreError::Conflict);
        }
        let tx = connection.transaction()?;
        tx.execute(
            "INSERT INTO metadata VALUES('migration_pending_sha256',?1)",
            [&source_hash],
        )?;
        tx.execute(
            "INSERT INTO metadata VALUES('migration_pending_path_hash',?1)",
            [&source_identity],
        )?;
        store::audit(
            &tx,
            "machine:offline-migration",
            "legacy.intent",
            "users",
            "accepted",
            "",
        )?;
        tx.commit()?;
    }
    if backup.exists() {
        if read_source(&backup)? != bytes {
            return Err(StoreError::Conflict);
        }
        if stage.exists() {
            return Err(StoreError::Conflict);
        }
    } else {
        if stage.exists() {
            // Only a recorded, matching intent owns this exact staging filename.
            store::check_file(&stage, false)?;
            fs::remove_file(&stage)?;
            store::sync_directory(&admin)?;
        }
        store::write_private(&stage, &bytes)?;
        fs::rename(&stage, &backup)?;
        store::sync_directory(&admin)?;
    }
    if receipt.is_none() {
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?;
        let state: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='bootstrap_state'",
            [],
            |r| r.get(0),
        )?;
        if count != 0 || state != "pending" {
            return Err(StoreError::Conflict);
        }
        for (user, hash) in &rows {
            store::insert_user(&tx, user, hash)?;
        }
        tx.execute(
            "UPDATE metadata SET value='consumed' WHERE key='bootstrap_state'",
            [],
        )?;
        tx.execute(
            "INSERT INTO metadata VALUES('migration_source_sha256',?1)",
            [&source_hash],
        )?;
        tx.execute(
            "INSERT INTO metadata VALUES('migration_source_path_hash',?1)",
            [source_identity],
        )?;
        store::audit(
            &tx,
            "machine:offline-migration",
            "legacy.import",
            "users",
            "success",
            "",
        )?;
        tx.commit()?;
    }
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    store::sync_directory(&admin)?;
    if present {
        // Re-read after commit: never remove a source that changed during the import.
        if password::digest(&read_source(&source)?) != source_hash {
            return Err(StoreError::Conflict);
        }
        fs::remove_file(&source)?;
        store::sync_directory(&spool)?;
    }
    let tx = connection.transaction()?;
    tx.execute("DELETE FROM metadata WHERE key IN('migration_pending_sha256','migration_pending_path_hash')",[])?;
    store::audit(
        &tx,
        "machine:offline-migration",
        "legacy.complete",
        "users",
        "success",
        "",
    )?;
    tx.commit()?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    store::sync_directory(&admin)?;
    Ok(MigrationReport {
        users: rows.len(),
        already_migrated: receipt.is_some(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let spool = tmp.path().join("spool");
        fs::create_dir(&spool).unwrap();
        fs::write(spool.join("lock"), b"").unwrap();
        fs::write(spool.join("state.sqlite"), b"core state sentinel").unwrap();
        let admin = tmp.path().join("spool.admin");
        (tmp, spool, admin)
    }
    fn legacy() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"schema_version":1,"users":[{"id":"a".repeat(64),"username":"operator","display_name":"Operator","salt_hex":"b".repeat(64),"password_hash_hex":password::legacy_hash(&"b".repeat(64),"old password"),"permissions":["view_status","trigger_sync","manage_cache","manage_users"],"created_at":1,"last_login_at":null}]})).unwrap()
    }
    #[test]
    fn import_retry_and_core_untouched() {
        let (_tmp, spool, admin) = fixture();
        store::write_private(&spool.join("admin-users.json"), &legacy()).unwrap();
        let result = migrate(&spool, &admin).unwrap();
        assert_eq!(result.users, 1);
        assert!(!result.already_migrated);
        assert!(!spool.join("admin-users.json").exists());
        assert_eq!(
            fs::read(spool.join("state.sqlite")).unwrap(),
            b"core state sentinel"
        );
        assert!(migrate(&spool, &admin).unwrap().already_migrated);
        let (db, _lock) = store::open_offline(&admin).unwrap();
        let permissions: i64 = db
            .query_row("SELECT permissions FROM users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(permissions, 255);
    }
    #[test]
    fn mismatched_retry_preserves_source() {
        let (_tmp, spool, admin) = fixture();
        store::write_private(&spool.join("admin-users.json"), &legacy()).unwrap();
        migrate(&spool, &admin).unwrap();
        let other = String::from_utf8(legacy())
            .unwrap()
            .replace("Operator", "Changed");
        store::write_private(&spool.join("admin-users.json"), other.as_bytes()).unwrap();
        assert_eq!(migrate(&spool, &admin).unwrap_err(), StoreError::Conflict);
        assert!(spool.join("admin-users.json").exists());
    }
    #[test]
    fn staging_and_overlap_refused() {
        let (_tmp, spool, admin) = fixture();
        fs::write(spool.join("admin-users.json.tmp"), b"bad").unwrap();
        assert_eq!(legacy_present(&spool), Err(StoreError::Conflict));
        assert_eq!(
            migrate(&spool, &spool.join("admin")).unwrap_err(),
            StoreError::Invalid
        );
        assert!(!admin.exists());
    }
    #[test]
    fn interrupted_backup_resumes_only_matching_owned_intent() {
        let (_tmp, spool, admin) = fixture();
        let source = legacy();
        store::write_private(&spool.join("admin-users.json"), &source).unwrap();
        let (db, lock) = store::open_offline(&admin).unwrap();
        db.execute(
            "INSERT INTO metadata VALUES('migration_pending_sha256',?1)",
            [password::digest(&source)],
        )
        .unwrap();
        db.execute(
            "INSERT INTO metadata VALUES('migration_pending_path_hash',?1)",
            [password::digest(
                absolute_normal(&spool)
                    .unwrap()
                    .to_string_lossy()
                    .as_bytes(),
            )],
        )
        .unwrap();
        store::write_private(
            &admin.join("legacy-users.backup.stage"),
            b"interrupted copy",
        )
        .unwrap();
        drop(db);
        drop(lock);
        assert!(matches!(
            store::AdminStore::open(&admin),
            Err(StoreError::Unavailable)
        ));
        assert_eq!(migrate(&spool, &admin).unwrap().users, 1);
        assert!(!admin.join("legacy-users.backup.stage").exists());
        assert_eq!(
            read_source(&admin.join("legacy-users.backup.json")).unwrap(),
            source
        );
    }
    #[test]
    fn committed_import_retry_finishes_source_removal() {
        let (_tmp, spool, admin) = fixture();
        let source = legacy();
        store::write_private(&spool.join("admin-users.json"), &source).unwrap();
        migrate(&spool, &admin).unwrap();
        // Reconstruct the durable state immediately after import commit but before unlink.
        store::write_private(&spool.join("admin-users.json"), &source).unwrap();
        let (db, lock) = store::open_offline(&admin).unwrap();
        db.execute(
            "INSERT INTO metadata VALUES('migration_pending_sha256',?1)",
            [password::digest(&source)],
        )
        .unwrap();
        db.execute(
            "INSERT INTO metadata VALUES('migration_pending_path_hash',?1)",
            [password::digest(
                absolute_normal(&spool)
                    .unwrap()
                    .to_string_lossy()
                    .as_bytes(),
            )],
        )
        .unwrap();
        drop(db);
        drop(lock);
        assert!(matches!(
            store::AdminStore::open(&admin),
            Err(StoreError::Unavailable)
        ));
        assert!(migrate(&spool, &admin).unwrap().already_migrated);
        assert!(!spool.join("admin-users.json").exists());
        let (db, _lock) = store::open_offline(&admin).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM users", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn legacy_login_rehashes_once_without_expanding_custom_grants() {
        let _serial = password::TEST_LOCK.lock().await;
        let (_tmp, spool, admin) = fixture();
        let mut source: serde_json::Value = serde_json::from_slice(&legacy()).unwrap();
        source["users"][0]["permissions"] = serde_json::json!(["view_status", "manage_users"]);
        store::write_private(
            &spool.join("admin-users.json"),
            &serde_json::to_vec(&source).unwrap(),
        )
        .unwrap();
        migrate(&spool, &admin).unwrap();
        let db = store::AdminStore::open(&admin).unwrap();
        let session = db
            .login("operator".into(), "old password".into())
            .await
            .unwrap();
        assert_eq!(session.auth.user.id, "a".repeat(64));
        assert_eq!(
            session.auth.user.permissions,
            vec![Permission::ViewStatus, Permission::ManageUsers]
        );
        let hash = db
            .read(|c| Ok(c.query_row("SELECT password FROM users", [], |r| r.get::<_, String>(0))?))
            .await
            .unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(matches!(
            db.update_user(
                session.auth.clone(),
                session.auth.user.id.clone(),
                None,
                None,
                vec![
                    Permission::ViewStatus,
                    Permission::ManageUsers,
                    Permission::ViewInventory
                ],
                None
            )
            .await,
            Err(StoreError::Forbidden)
        ));
        assert_eq!(
            db.delete_user(session.auth.clone(), session.auth.user.id.clone())
                .await,
            Err(StoreError::Conflict)
        );
        db.login("operator".into(), "old password".into())
            .await
            .unwrap();
        let after = db
            .read(|c| Ok(c.query_row("SELECT password FROM users", [], |r| r.get::<_, String>(0))?))
            .await
            .unwrap();
        assert_eq!(hash, after);
    }
}
