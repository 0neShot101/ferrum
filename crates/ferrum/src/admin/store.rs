//! Separate, exclusively owned administration database. No core catalog access.
use super::{model::*, password};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{
    Arc,
    mpsc::{self, SyncSender, TrySendError},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

const APPLICATION_ID: i64 = 0x4641_444d;
const DATABASE_MAX: u64 = 224 * 1024 * 1024;
const WAL_MAX: u64 = 32 * 1024 * 1024;
const TRANSACTION_RESERVE: u64 = 4 * 1024 * 1024;
const SCHEMA: &str = "
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL CHECK(length(value)<=1024)) STRICT;
CREATE TABLE users(id TEXT PRIMARY KEY CHECK(length(id)<=64),username TEXT NOT NULL UNIQUE CHECK(length(username)<=64),display_name TEXT NOT NULL CHECK(length(display_name)<=128),password TEXT NOT NULL CHECK(length(password)<=1024),permissions INTEGER NOT NULL CHECK(permissions BETWEEN 0 AND 255),disabled INTEGER NOT NULL CHECK(disabled IN(0,1)),created_at INTEGER NOT NULL,last_login_at INTEGER) STRICT;
CREATE TABLE sessions(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64),user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL CHECK(length(csrf)=64),created_at INTEGER NOT NULL,last_seen_at INTEGER NOT NULL,expires_at INTEGER NOT NULL) STRICT;
CREATE INDEX sessions_user ON sessions(user_id,created_at,id);
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL CHECK(length(actor)<=128),action TEXT NOT NULL CHECK(length(action)<=128),target TEXT NOT NULL CHECK(length(target)<=256),outcome TEXT NOT NULL CHECK(length(outcome)<=128),reason TEXT NOT NULL CHECK(length(reason)<=1024),created_at INTEGER NOT NULL) STRICT;
CREATE INDEX audit_time ON audit_events(created_at,id);
CREATE INDEX audit_intents ON audit_events(actor,action,target,outcome,id);
CREATE TABLE workspaces(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL CHECK(length(name)<=128),schema_version INTEGER NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL CHECK(length(CAST(body AS BLOB))<=65536),is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN(0,1))) STRICT;
CREATE INDEX workspace_owner ON workspaces(user_id,id);
CREATE UNIQUE INDEX workspace_default ON workspaces(user_id) WHERE is_default=1;
CREATE TABLE operation_requests(id TEXT PRIMARY KEY,actor TEXT NOT NULL,idempotency_key TEXT NOT NULL CHECK(length(idempotency_key)<=128),request_hash TEXT NOT NULL CHECK(length(request_hash)=64),kind TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('queued','running','succeeded','partial','failed','cancelled','interrupted')),created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,body TEXT NOT NULL CHECK(length(CAST(body AS BLOB))<=65536),UNIQUE(actor,idempotency_key)) STRICT;
CREATE INDEX operation_history ON operation_requests(created_at,id);
CREATE TABLE operation_targets(request_id TEXT NOT NULL REFERENCES operation_requests(id) ON DELETE CASCADE,repository TEXT NOT NULL,suite TEXT NOT NULL,pass_id TEXT,state TEXT NOT NULL,body TEXT NOT NULL CHECK(length(CAST(body AS BLOB))<=16384),PRIMARY KEY(request_id,repository,suite)) STRICT;
CREATE TABLE config_proposals(id TEXT PRIMARY KEY,actor TEXT NOT NULL,base_revision TEXT NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL CHECK(length(CAST(body AS BLOB))<=65536),created_at INTEGER NOT NULL) STRICT;
CREATE TABLE alert_acknowledgments(condition_id TEXT NOT NULL,actor TEXT NOT NULL,note TEXT NOT NULL CHECK(length(note)<=1024),created_at INTEGER NOT NULL,PRIMARY KEY(condition_id,created_at,actor)) STRICT;
CREATE TABLE metric_rollups(minute INTEGER PRIMARY KEY,boot_id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)<=65536)) STRICT;
CREATE TRIGGER user_bound BEFORE INSERT ON users WHEN (SELECT count(*) FROM users)>=128 BEGIN SELECT RAISE(ABORT,'user bound'); END;
CREATE TRIGGER session_bound BEFORE INSERT ON sessions WHEN (SELECT count(*) FROM sessions)>=256 OR (SELECT count(*) FROM sessions WHERE user_id=NEW.user_id)>=8 BEGIN SELECT RAISE(ABORT,'session bound'); END;
CREATE TRIGGER workspace_bound BEFORE INSERT ON workspaces WHEN (SELECT count(*) FROM workspaces WHERE user_id=NEW.user_id)>=16 BEGIN SELECT RAISE(ABORT,'workspace bound'); END;
CREATE TRIGGER operation_bound BEFORE INSERT ON operation_requests WHEN NEW.state IN('queued','running') AND (SELECT count(*) FROM operation_requests WHERE state IN('queued','running'))>=32 BEGIN SELECT RAISE(ABORT,'operation bound'); END;
CREATE TRIGGER operation_update_bound BEFORE UPDATE OF state ON operation_requests WHEN OLD.state NOT IN('queued','running') AND NEW.state IN('queued','running') AND (SELECT count(*) FROM operation_requests WHERE state IN('queued','running'))>=32 BEGIN SELECT RAISE(ABORT,'operation bound'); END;
CREATE TRIGGER target_bound BEFORE INSERT ON operation_targets WHEN (SELECT count(*) FROM operation_targets WHERE request_id=NEW.request_id)>=128 BEGIN SELECT RAISE(ABORT,'target bound'); END;
CREATE TRIGGER audit_retention AFTER INSERT ON audit_events BEGIN DELETE FROM audit_events WHERE id<=COALESCE((SELECT id FROM audit_events ORDER BY id DESC LIMIT 1 OFFSET 50000),-1); END;
CREATE TRIGGER metric_bound AFTER INSERT ON metric_rollups BEGIN DELETE FROM metric_rollups WHERE minute<COALESCE((SELECT minute FROM metric_rollups ORDER BY minute DESC LIMIT 1 OFFSET 10079),-9223372036854775808); END;
CREATE TRIGGER terminal_insert_retention AFTER INSERT ON operation_requests WHEN NEW.state NOT IN('queued','running') BEGIN DELETE FROM operation_requests WHERE id IN(SELECT id FROM operation_requests WHERE state NOT IN('queued','running') ORDER BY created_at DESC,id DESC LIMIT 1 OFFSET 1000); END;
CREATE TRIGGER terminal_update_retention AFTER UPDATE OF state ON operation_requests WHEN NEW.state NOT IN('queued','running') BEGIN DELETE FROM operation_requests WHERE id IN(SELECT id FROM operation_requests WHERE state NOT IN('queued','running') ORDER BY created_at DESC,id DESC LIMIT 1 OFFSET 1000); END;
";

type Job = Box<dyn FnOnce(&mut Connection) + Send + 'static>;
struct Worker {
    sender: SyncSender<Job>,
    alive: Arc<AtomicBool>,
}
struct Liveness(Arc<AtomicBool>);
impl Drop for Liveness {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Worker {
    fn start(
        mut connection: Connection,
        root: PathBuf,
        writer: bool,
        lock: Option<Arc<fd_lock::RwLock<File>>>,
    ) -> Result<Self, StoreError> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(64);
        let alive = Arc::new(AtomicBool::new(true));
        let liveness = Liveness(alive.clone());
        thread::Builder::new()
            .name(
                if writer {
                    "ferrum-admin-writer"
                } else {
                    "ferrum-admin-reader"
                }
                .into(),
            )
            .spawn(move || {
                let _lock = lock;
                let _liveness = liveness;
                while let Ok(job) = receiver.recv() {
                    let deadline = Instant::now()
                        + if writer {
                            Duration::from_secs(2)
                        } else {
                            Duration::from_millis(250)
                        };
                    let _ =
                        connection.progress_handler(1000, Some(move || Instant::now() > deadline));
                    job(&mut connection);
                    let _ = connection.progress_handler(0, None::<fn() -> bool>);
                    if writer {
                        let _ = connection.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
                    }
                }
                if writer {
                    let _ = connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
                    let _ = sync_directory(&root);
                }
                drop(connection);
            })?;
        Ok(Self { sender, alive })
    }
    async fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(StoreError::Unavailable);
        }
        let (send, receive) = oneshot::channel();
        self.sender
            .try_send(Box::new(move |connection| {
                let _ = send.send(f(connection));
            }))
            .map_err(|e| match e {
                TrySendError::Full(_) => StoreError::Busy,
                TrySendError::Disconnected(_) => StoreError::Unavailable,
            })?;
        let result = receive.await.map_err(|_| StoreError::Unavailable)?;
        if !self.alive.load(Ordering::Acquire) {
            return Err(StoreError::Unavailable);
        }
        result
    }
}
struct Inner {
    writer: Worker,
    reader: Worker,
    root: PathBuf,
}
#[derive(Clone)]
pub struct AdminStore {
    inner: Option<Arc<Inner>>,
}
impl AdminStore {
    pub fn unavailable() -> Self {
        Self { inner: None }
    }
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        let (connection, lock) = open_offline(root)?;
        if connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='migration_pending_sha256')",
            [],
            |r| r.get::<_, bool>(0),
        )? || root.join("legacy-users.backup.stage").exists()
        {
            return Err(StoreError::Unavailable);
        }
        if root.join("legacy-users.backup.json").exists()
            && !connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='migration_source_sha256')",
                [],
                |r| r.get::<_, bool>(0),
            )?
        {
            return Err(StoreError::Unavailable);
        }
        let reader = connect(&root.join("admin.sqlite"), false)?;
        let lock = Arc::new(lock);
        let writer = Worker::start(connection, root.into(), true, Some(lock.clone()))?;
        let reader = Worker::start(reader, root.into(), false, Some(lock))?;
        Ok(Self {
            inner: Some(Arc::new(Inner {
                writer,
                reader,
                root: root.into(),
            })),
        })
    }
    pub(crate) async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let inner = self.inner.as_ref().ok_or(StoreError::Unavailable)?;
        if !inner.writer.alive.load(Ordering::Acquire) {
            return Err(StoreError::Unavailable);
        }
        let result = inner
            .reader
            .call(move |c| {
                // Authorization and its projection share one bounded, query-only snapshot.
                let tx = c.transaction()?;
                let value = f(&tx)?;
                tx.commit()?;
                Ok(value)
            })
            .await;
        if !inner.writer.alive.load(Ordering::Acquire) {
            return Err(StoreError::Unavailable);
        }
        result
    }
    /// Privileged callers must commit their audit event in this same transaction.
    pub(crate) async fn write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let inner = self.inner.as_ref().ok_or(StoreError::Unavailable)?;
        if !inner.reader.alive.load(Ordering::Acquire) {
            return Err(StoreError::Unavailable);
        }
        let root = inner.root.clone();
        inner
            .writer
            .call(move |c| {
                write_admission(c, &root)?;
                let deadline = Instant::now() + Duration::from_secs(2);
                let wal = root.join("admin.sqlite-wal");
                let _ = c.progress_handler(
                    100,
                    Some(move || {
                        Instant::now() > deadline
                            || fs::metadata(&wal)
                                .is_ok_and(|m| m.len() >= WAL_MAX - TRANSACTION_RESERVE)
                    }),
                );
                let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                retention(&tx)?;
                let value = f(&tx)?;
                tx.commit().map_err(|error| {
                    if fs::metadata(root.join("admin.sqlite-wal"))
                        .is_ok_and(|m| m.len() >= WAL_MAX - TRANSACTION_RESERVE)
                    {
                        StoreError::Busy
                    } else {
                        error.into()
                    }
                })?;
                Ok(value)
            })
            .await
    }
    pub async fn setup_required(&self) -> Result<bool, StoreError> {
        self.read(|c| {
            Ok(c.query_row(
                "SELECT value='pending' FROM metadata WHERE key='bootstrap_state'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
    }
    pub async fn setup(
        &self,
        bootstrap_token: String,
        username: String,
        display_name: String,
        password: String,
    ) -> Result<SessionGrant, StoreError> {
        validate_identity(&username, &display_name)?;
        if bootstrap_token.len() != 64 {
            return Err(StoreError::Forbidden);
        }
        if !self.setup_required().await? {
            return Err(StoreError::Conflict);
        }
        let token_hash = password::digest(bootstrap_token.as_bytes());
        let expected: String = self
            .read(|c| {
                Ok(c.query_row(
                    "SELECT value FROM metadata WHERE key='bootstrap_hash'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await?;
        if !password::constant_eq(&token_hash, &expected) {
            return Err(StoreError::Forbidden);
        }
        let hash = password::hash(password).await?;
        self.write(move |tx| {
            let state: String = tx.query_row(
                "SELECT value FROM metadata WHERE key='bootstrap_state'",
                [],
                |r| r.get(0),
            )?;
            if state != "pending"
                || tx.query_row("SELECT count(*) FROM users", [], |r| r.get::<_, i64>(0))? != 0
            {
                return Err(StoreError::Conflict);
            }
            let user = UserView {
                id: password::random_token(),
                username,
                display_name,
                permissions: Permission::all().into_iter().collect(),
                created_at: now(),
                last_login_at: None,
                disabled: false,
            };
            insert_user(tx, &user, &hash)?;
            tx.execute(
                "UPDATE metadata SET value='consumed' WHERE key='bootstrap_state'",
                [],
            )?;
            audit(tx, &user.id, "setup", &user.id, "success", "")?;
            grant(tx, user)
        })
        .await
    }
    pub async fn login(
        &self,
        username: String,
        password: String,
    ) -> Result<SessionGrant, StoreError> {
        if username.len() > 64 || password.len() > 1024 {
            return Err(StoreError::Unauthorized);
        }
        let username = username.trim().to_ascii_lowercase();
        let found = self
            .read(move |c| {
                let user = c
                    .query_row("SELECT id FROM users WHERE username=?1", [username], |r| {
                        r.get::<_, String>(0)
                    })
                    .optional()?;
                user.map(|id| load_credentials(c, &id)).transpose()
            })
            .await?;
        let Some((user, original_hash)) = found else {
            let result = password::dummy(password).await;
            if result == Err(StoreError::Unauthorized) {
                self.write(|tx| audit(tx, "anonymous", "login", "", "denied", ""))
                    .await?;
            }
            return result.and(Err(StoreError::Unauthorized));
        };
        let replacement = match password::verify(password, original_hash.clone()).await {
            Ok(hash) => hash,
            Err(StoreError::Unauthorized) => {
                let id = user.id;
                self.write(move |tx| audit(tx, &id, "login", &id, "denied", ""))
                    .await?;
                return Err(StoreError::Unauthorized);
            }
            Err(error) => return Err(error),
        };
        self.write(move |tx| {
            let (current, hash) = load_credentials(tx, &user.id)?;
            if current.disabled || !password::constant_eq(&hash, &original_hash) {
                audit(tx, &user.id, "login", &user.id, "denied", "")?;
                return Ok(None);
            }
            if let Some(hash) = replacement {
                tx.execute(
                    "UPDATE users SET password=?1 WHERE id=?2",
                    params![hash, current.id],
                )?;
            }
            audit(tx, &current.id, "login", &current.id, "success", "")?;
            grant(tx, current).map(Some)
        })
        .await?
        .ok_or(StoreError::Unauthorized)
    }
    pub async fn authenticate(&self, token: String) -> Result<AuthContext, StoreError> {
        if token.len() != 64 {
            return Err(StoreError::Unauthorized);
        }
        let hash = password::digest(token.as_bytes());
        let (auth, last_seen) = self.read(move |c| session_by_hash(c, &hash)).await?;
        // At most one durable touch per five minutes, while every request rechecks revocation.
        if last_seen <= now() - 300 {
            let id = auth.session_id.clone();
            self.write(move |tx| {
                let changed=tx.execute("UPDATE sessions SET last_seen_at=?1 WHERE id=?2 AND last_seen_at>?3 AND expires_at>?1",params![now(),id,now()-1800])?;
                if changed==0{return Err(StoreError::Unauthorized);}
                Ok(())
            }).await?;
        }
        Ok(auth)
    }
    pub async fn authenticate_control(&self, token: String) -> Result<AuthContext, StoreError> {
        if token.len() != 64 {
            return Err(StoreError::Unauthorized);
        }
        let expected: String = self
            .read(|c| {
                Ok(c.query_row(
                    "SELECT value FROM metadata WHERE key='control_hash'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await?;
        if !password::constant_eq(&expected, &password::digest(token.as_bytes())) {
            return Err(StoreError::Unauthorized);
        }
        Ok(machine_context())
    }
    pub async fn logout(&self, auth: AuthContext) -> Result<(), StoreError> {
        self.write(move |tx| {
            actor(tx, &auth, None)?;
            tx.execute("DELETE FROM sessions WHERE id=?1", [&auth.session_id])?;
            audit(tx, &auth.user.id, "logout", &auth.session_id, "success", "")
        })
        .await
    }
    pub async fn list_users(&self, auth: AuthContext) -> Result<Vec<UserView>, StoreError> {
        self.read(move |c| {
            actor(c,&auth,Some(Permission::ManageUsers))?;
            let mut stmt=c.prepare("SELECT id,username,display_name,permissions,created_at,last_login_at,disabled FROM users ORDER BY username,id LIMIT 128")?;
            let users=stmt.query_map([],user_row)?.collect::<Result<Vec<_>,_>>()?;
            Ok(users)
        }).await
    }
    pub async fn create_user(
        &self,
        auth: AuthContext,
        username: String,
        display_name: String,
        password: String,
        permissions: Vec<Permission>,
    ) -> Result<UserView, StoreError> {
        validate_identity(&username, &display_name)?;
        let mask = permission_mask(&permissions)?;
        let current = self
            .check_actor(auth.clone(), Some(Permission::ManageUsers))
            .await?;
        grant_subset(&current, mask)?;
        let hash = password::hash(password).await?;
        self.write(move |tx| {
            let current = actor(tx, &auth, Some(Permission::ManageUsers))?;
            grant_subset(&current, mask)?;
            let user = UserView {
                id: password::random_token(),
                username,
                display_name,
                permissions: Permission::from_mask(mask),
                created_at: now(),
                last_login_at: None,
                disabled: false,
            };
            insert_user(tx, &user, &hash)?;
            audit(tx, &current.id, "user.create", &user.id, "success", "")?;
            Ok(user)
        })
        .await
    }
    pub async fn update_user(
        &self,
        auth: AuthContext,
        id: String,
        display_name: Option<String>,
        password: Option<String>,
        permissions: Vec<Permission>,
        disabled: Option<bool>,
    ) -> Result<UserView, StoreError> {
        let mask = permission_mask(&permissions)?;
        let current = self
            .check_actor(auth.clone(), Some(Permission::ManageUsers))
            .await?;
        grant_subset(&current, mask)?;
        let hash = match password {
            Some(p) => Some(password::hash(p).await?),
            None => None,
        };
        self.write(move |tx| {
            let current=actor(tx,&auth,Some(Permission::ManageUsers))?; grant_subset(&current,mask)?; let mut user=load_user(tx,&id)?;
            let disabled=disabled.unwrap_or(user.disabled);
            if let Some(name)=display_name {validate_identity(&user.username,&name)?;user.display_name=name;}
            protect_last_admin(tx,&user,mask,disabled)?;
            let revoke = permission_mask(&user.permissions)?!=mask || user.disabled!=disabled || hash.is_some();
            tx.execute("UPDATE users SET display_name=?1,permissions=?2,disabled=?3,password=COALESCE(?4,password) WHERE id=?5",params![user.display_name,mask,disabled,hash,id])?;
            if revoke {tx.execute("DELETE FROM sessions WHERE user_id=?1",[&id])?;}
            audit(tx,&current.id,"user.update",&id,"success","")?; load_user(tx,&id)
        }).await
    }
    pub async fn delete_user(&self, auth: AuthContext, id: String) -> Result<(), StoreError> {
        self.write(move |tx| {
            let current = actor(tx, &auth, Some(Permission::ManageUsers))?;
            let user = load_user(tx, &id)?;
            grant_subset(&current, permission_mask(&user.permissions)?)?;
            protect_last_admin(tx, &user, 0, true)?;
            tx.execute("DELETE FROM users WHERE id=?1", [&id])?;
            audit(tx, &current.id, "user.delete", &id, "success", "")
        })
        .await
    }
    pub async fn update_account(
        &self,
        auth: AuthContext,
        username: Option<String>,
        display_name: Option<String>,
        current_password: Option<String>,
        new_password: Option<String>,
    ) -> Result<UserView, StoreError> {
        self.check_actor(auth.clone(), None).await?;
        let id = auth.user.id.clone();
        let (existing, old_hash) = self.read(move |c| load_credentials(c, &id)).await?;
        let credential_change = username
            .as_ref()
            .is_some_and(|name| name != &existing.username)
            || new_password.is_some();
        let username = username.unwrap_or(existing.username);
        let display_name = display_name.unwrap_or(existing.display_name);
        validate_identity(&username, &display_name)?;
        if credential_change {
            password::verify(
                current_password.ok_or(StoreError::Forbidden)?,
                old_hash.clone(),
            )
            .await?;
        }
        let new_hash = match new_password {
            Some(p) => Some(password::hash(p).await?),
            None => None,
        };
        self.write(move |tx| {
            let current=actor(tx,&auth,None)?;
            let (_,hash)=load_credentials(tx,&current.id)?;
            if hash!=old_hash{return Err(StoreError::Conflict);}
            tx.execute("UPDATE users SET username=?1,display_name=?2,password=COALESCE(?3,password) WHERE id=?4",params![username,display_name,new_hash,current.id])?;
            tx.execute("DELETE FROM sessions WHERE user_id=?1",[&current.id])?;
            audit(tx,&current.id,"account.update",&current.id,"success","")?;
            load_user(tx,&current.id)
        }).await
    }
    async fn check_actor(
        &self,
        auth: AuthContext,
        permission: Option<Permission>,
    ) -> Result<UserView, StoreError> {
        self.read(move |c| actor(c, &auth, permission)).await
    }
    pub async fn list_sessions(
        &self,
        auth: AuthContext,
        user_id: Option<String>,
    ) -> Result<Vec<SessionView>, StoreError> {
        self.read(move|c|{let current=actor(c,&auth,None)?;let id=user_id.unwrap_or(current.id.clone());if id!=current.id&&!current.permissions.contains(&Permission::ManageUsers){return Err(StoreError::Forbidden);}let mut stmt=c.prepare("SELECT id,created_at,last_seen_at,expires_at FROM sessions WHERE user_id=?1 AND expires_at>?2 AND last_seen_at>?3 ORDER BY created_at,id LIMIT 8")?;let rows=stmt.query_map(params![id,now(),now()-1800],|r|{let id:String=r.get(0)?;Ok(SessionView{current:id==auth.session_id,id,created_at:r.get(1)?,last_seen_at:r.get(2)?,expires_at:r.get(3)?})})?.collect::<Result<Vec<_>,_>>()?;Ok(rows)}).await
    }
    pub async fn revoke_session(&self, auth: AuthContext, id: String) -> Result<(), StoreError> {
        self.write(move |tx| {
            let current = actor(tx, &auth, None)?;
            let owner: String = tx
                .query_row("SELECT user_id FROM sessions WHERE id=?1", [&id], |r| {
                    r.get(0)
                })
                .optional()?
                .ok_or(StoreError::Invalid)?;
            if owner != current.id && !current.permissions.contains(&Permission::ManageUsers) {
                return Err(StoreError::Forbidden);
            }
            tx.execute("DELETE FROM sessions WHERE id=?1", [&id])?;
            audit(tx, &current.id, "session.revoke", &id, "success", "")
        })
        .await
    }
    pub async fn audit_operation(
        &self,
        auth: AuthContext,
        action: String,
        target: String,
        outcome: String,
        reason: String,
    ) -> Result<(), StoreError> {
        let permission = match action.as_str() {
            "sync.request" => Permission::TriggerSync,
            "cache.clear" => Permission::ManageCache,
            _ => return Err(StoreError::Invalid),
        };
        self.write(move|tx|{
            let principal=if auth.machine{"machine:local-control"}else{&auth.user.id};
            if outcome=="intent"{
                actor(tx,&auth,Some(permission))?;
            }else{
                // Effects already authorized by intent must remain auditable after revocation.
                let intent:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM audit_events WHERE actor=?1 AND action=?2 AND target=?3 AND outcome='intent')",params![principal,action,target],|r|r.get(0))?;
                if !intent{return Err(StoreError::Conflict);}
                if auth.machine&&permission!=Permission::TriggerSync{return Err(StoreError::Forbidden);}
            }
            audit(tx,principal,&action,&target,&outcome,&reason)
        }).await
    }
    pub async fn list_audit(
        &self,
        auth: AuthContext,
        before: Option<i64>,
        limit: usize,
    ) -> Result<Vec<AuditView>, StoreError> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError::Invalid);
        }
        self.read(move|c|{actor(c,&auth,Some(Permission::ViewAudit))?;let mut stmt=c.prepare("SELECT id,actor,action,target,outcome,reason,created_at FROM audit_events WHERE id<?1 ORDER BY id DESC LIMIT ?2")?;let rows=stmt.query_map(params![before.unwrap_or(i64::MAX),limit as i64],|r|Ok(AuditView{id:r.get(0)?,actor:r.get(1)?,action:r.get(2)?,target:r.get(3)?,outcome:r.get(4)?,reason:r.get(5)?,created_at:r.get(6)?}))?.collect::<Result<Vec<_>,_>>()?;Ok(rows)}).await
    }
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(i64::MAX as u64) as i64)
}
pub(crate) fn validate_identity(username: &str, display: &str) -> Result<(), StoreError> {
    if username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        || display.trim().is_empty()
        || display.len() > 128
        || display.chars().any(char::is_control)
    {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}
pub(crate) fn permission_mask(permissions: &[Permission]) -> Result<i64, StoreError> {
    let mut mask = 0;
    for p in permissions {
        mask |= p.mask();
    }
    if mask & Permission::ViewStatus.mask() == 0 {
        return Err(StoreError::Invalid);
    }
    Ok(mask)
}
fn grant_subset(actor: &UserView, mask: i64) -> Result<(), StoreError> {
    if mask & !permission_mask(&actor.permissions)? != 0 {
        Err(StoreError::Forbidden)
    } else {
        Ok(())
    }
}
fn protect_last_admin(
    c: &Connection,
    user: &UserView,
    mask: i64,
    disabled: bool,
) -> Result<(), StoreError> {
    if user.disabled {
        return Ok(());
    }
    let original = permission_mask(&user.permissions)?;
    let full: i64 = c.query_row(
        "SELECT count(*) FROM users WHERE disabled=0 AND permissions=255",
        [],
        |r| r.get(0),
    )?;
    if original == 255 && (disabled || mask != 255) && full <= 1 {
        return Err(StoreError::Conflict);
    }
    // Imported custom grants are not expanded; preserve their last user manager.
    let manager = Permission::ManageUsers.mask();
    if full == 0
        && original & manager != 0
        && (disabled || mask & manager == 0)
        && c.query_row(
            "SELECT count(*) FROM users WHERE disabled=0 AND (permissions & ?1)!=0",
            [manager],
            |r| r.get::<_, i64>(0),
        )? <= 1
    {
        return Err(StoreError::Conflict);
    }
    if c.query_row("SELECT count(*) FROM users WHERE disabled=0", [], |r| {
        r.get::<_, i64>(0)
    })? <= 1
        && disabled
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}
fn user_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<UserView> {
    Ok(UserView {
        id: r.get(0)?,
        username: r.get(1)?,
        display_name: r.get(2)?,
        permissions: Permission::from_mask(r.get(3)?),
        created_at: r.get(4)?,
        last_login_at: r.get(5)?,
        disabled: r.get(6)?,
    })
}
pub(crate) fn load_user(c: &Connection, id: &str) -> Result<UserView, StoreError> {
    c.query_row("SELECT id,username,display_name,permissions,created_at,last_login_at,disabled FROM users WHERE id=?1",[id],user_row).optional()?.ok_or(StoreError::Unauthorized)
}
fn load_credentials(c: &Connection, id: &str) -> Result<(UserView, String), StoreError> {
    c.query_row("SELECT id,username,display_name,permissions,created_at,last_login_at,disabled,password FROM users WHERE id=?1",[id],|r|Ok((user_row(r)?,r.get(7)?))).optional()?.ok_or(StoreError::Unauthorized)
}
pub(crate) fn insert_user(
    tx: &Transaction<'_>,
    user: &UserView,
    hash: &str,
) -> Result<(), StoreError> {
    validate_identity(&user.username, &user.display_name)?;
    if tx.query_row("SELECT count(*) FROM users", [], |r| r.get::<_, i64>(0))? >= 128 {
        return Err(StoreError::Busy);
    }
    tx.execute("INSERT INTO users(id,username,display_name,password,permissions,disabled,created_at,last_login_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![user.id,user.username,user.display_name,hash,permission_mask(&user.permissions)?,user.disabled,user.created_at,user.last_login_at])?;
    Ok(())
}
fn grant(tx: &Transaction<'_>, mut user: UserView) -> Result<SessionGrant, StoreError> {
    let time = now();
    let token = password::random_token();
    let id = password::random_token();
    let csrf = password::random_token();
    tx.execute(
        "DELETE FROM sessions WHERE expires_at<=?1 OR last_seen_at<=?2",
        params![time, time - 1800],
    )?;
    if tx.query_row(
        "SELECT count(*) FROM sessions WHERE user_id=?1",
        [&user.id],
        |r| r.get::<_, i64>(0),
    )? >= 8
    {
        tx.execute("DELETE FROM sessions WHERE id=(SELECT id FROM sessions WHERE user_id=?1 ORDER BY created_at,id LIMIT 1)",[&user.id])?;
    }
    if tx.query_row("SELECT count(*) FROM sessions", [], |r| r.get::<_, i64>(0))? >= 256 {
        return Err(StoreError::Busy);
    }
    tx.execute(
        "INSERT INTO sessions VALUES(?1,?2,?3,?4,?5,?5,?6)",
        params![
            id,
            password::digest(token.as_bytes()),
            user.id,
            csrf,
            time,
            time + 28800
        ],
    )?;
    tx.execute(
        "UPDATE users SET last_login_at=?1 WHERE id=?2",
        params![time, user.id],
    )?;
    user.last_login_at = Some(time);
    Ok(SessionGrant {
        token,
        auth: AuthContext {
            user,
            session_id: id,
            csrf_token: csrf,
            machine: false,
        },
    })
}
fn session_by_hash(c: &Connection, hash: &str) -> Result<(AuthContext, i64), StoreError> {
    let row=c.query_row("SELECT id,user_id,csrf,last_seen_at FROM sessions WHERE token_hash=?1 AND expires_at>?2 AND last_seen_at>?3",params![hash,now(),now()-1800],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?))).optional()?.ok_or(StoreError::Unauthorized)?;
    let user = load_user(c, &row.1)?;
    if user.disabled {
        return Err(StoreError::Unauthorized);
    }
    Ok((
        AuthContext {
            user,
            session_id: row.0,
            csrf_token: row.2,
            machine: false,
        },
        row.3,
    ))
}
fn machine_context() -> AuthContext {
    AuthContext {
        user: UserView {
            id: "machine:local-control".into(),
            username: "local-control".into(),
            display_name: "Local control".into(),
            permissions: vec![Permission::ViewStatus, Permission::TriggerSync],
            created_at: 0,
            last_login_at: None,
            disabled: false,
        },
        session_id: String::new(),
        csrf_token: String::new(),
        machine: true,
    }
}
/// Recheck a principal and its current grants inside the caller's transaction.
pub(crate) fn actor(
    c: &Connection,
    auth: &AuthContext,
    permission: Option<Permission>,
) -> Result<UserView, StoreError> {
    let user = if auth.machine {
        machine_context().user
    } else {
        let user_id: String = c
            .query_row(
                "SELECT user_id FROM sessions WHERE id=?1 AND expires_at>?2 AND last_seen_at>?3",
                params![auth.session_id, now(), now() - 1800],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StoreError::Unauthorized)?;
        if user_id != auth.user.id {
            return Err(StoreError::Unauthorized);
        }
        let user = load_user(c, &user_id)?;
        if user.disabled {
            return Err(StoreError::Unauthorized);
        }
        user
    };
    if permission.is_some_and(|p| !user.permissions.contains(&p)) {
        return Err(StoreError::Forbidden);
    }
    Ok(user)
}
pub(crate) fn audit(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    target: &str,
    outcome: &str,
    reason: &str,
) -> Result<(), StoreError> {
    for (v, max) in [
        (actor, 128),
        (action, 128),
        (target, 256),
        (outcome, 128),
        (reason, 1024),
    ] {
        if v.len() > max || v.chars().any(char::is_control) {
            return Err(StoreError::Invalid);
        }
    }
    tx.execute("INSERT INTO audit_events(actor,action,target,outcome,reason,created_at) VALUES(?1,?2,?3,?4,?5,?6)",params![actor,action,target,outcome,reason,now()])?;
    Ok(())
}
fn retention(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.execute(
        "DELETE FROM sessions WHERE expires_at<=?1 OR last_seen_at<=?2",
        params![now(), now() - 1800],
    )?;
    tx.execute("DELETE FROM metric_rollups WHERE minute IN (SELECT minute FROM metric_rollups WHERE minute<?1 ORDER BY minute LIMIT 256)",[now()/60-10080])?;
    Ok(())
}

pub(crate) fn connect(path: &Path, writer: bool) -> Result<Connection, StoreError> {
    let flags = if writer {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let c = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    c.busy_timeout(Duration::from_millis(100))?;
    c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA mmap_size=0; PRAGMA cache_size=-1024; PRAGMA temp_store=FILE;")?;
    if writer {
        c.execute_batch("PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=128; PRAGMA journal_size_limit=33554432; PRAGMA max_page_count=57344;")?;
        let wal = path.with_file_name("admin.sqlite-wal");
        let _ = c.commit_hook(Some(move || {
            fs::metadata(&wal).is_ok_and(|m| m.len() >= WAL_MAX - TRANSACTION_RESERVE)
        }));
    } else {
        c.execute_batch("PRAGMA query_only=ON;")?;
    }
    Ok(c)
}
pub(crate) fn open_offline(root: &Path) -> Result<(Connection, fd_lock::RwLock<File>), StoreError> {
    secure_root(root)?;
    let mut fresh = true;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        fresh = false;
        let name = entry.file_name();
        let name = name.to_str().ok_or(StoreError::Unavailable)?;
        if ![
            "lock",
            ".initializing",
            "admin.sqlite",
            "admin.sqlite-wal",
            "admin.sqlite-shm",
            "admin.sqlite-journal",
            "bootstrap.token",
            "control.token",
            "legacy-users.backup.json",
            "legacy-users.backup.stage",
        ]
        .contains(&name)
        {
            return Err(StoreError::Unavailable);
        }
        check_file(&entry.path(), false)?;
    }
    let marker = root.join(".initializing");
    if fresh {
        // Atomic, empty-file intent: no accounts can be exposed until its durable removal.
        create_private(&marker)?.sync_all()?;
        sync_directory(root)?;
    }
    let lock = exclusive_lock(&root.join("lock"), fresh || marker.exists())?;
    let path = root.join("admin.sqlite");
    let initializing = marker.exists();
    if initializing {
        check_file(&marker, false)?;
        if fs::metadata(&marker)?.len() != 0
            || root.join("legacy-users.backup.json").exists()
            || root.join("legacy-users.backup.stage").exists()
        {
            return Err(StoreError::Unavailable);
        }
        if path.exists() && fs::metadata(&path)?.len() > 0 {
            if fs::metadata(&path)?.len() > DATABASE_MAX {
                return Err(StoreError::Unavailable);
            }
            if let Ok(probe) = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            ) {
                // Even an unexpected marker can never authorize deleting existing accounts/history.
                for sql in [
                    "SELECT count(*) FROM users",
                    "SELECT count(*) FROM audit_events",
                    "SELECT count(*) FROM metadata WHERE key LIKE 'migration_%'",
                ] {
                    if probe
                        .query_row(sql, [], |r| r.get::<_, i64>(0))
                        .is_ok_and(|count| count > 0)
                    {
                        return Err(StoreError::Unavailable);
                    }
                }
            }
        }
        // Only initialization-owned files may be recreated, while holding the same lock inode.
        for name in [
            "admin.sqlite",
            "admin.sqlite-wal",
            "admin.sqlite-shm",
            "admin.sqlite-journal",
            "bootstrap.token",
            "control.token",
        ] {
            let file = root.join(name);
            if file.exists() {
                check_file(&file, false)?;
                fs::remove_file(file)?;
            }
        }
        sync_directory(root)?;
        let f = create_private(&path)?;
        f.sync_all()?;
        let c = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        c.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let bootstrap = password::random_token();
        let control = password::random_token();
        write_private(&root.join("bootstrap.token"), bootstrap.as_bytes())?;
        write_private(&root.join("control.token"), control.as_bytes())?;
        let tx = c.unchecked_transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", 1)?;
        for (key, value) in [
            ("bootstrap_state", "pending".to_string()),
            ("bootstrap_hash", password::digest(bootstrap.as_bytes())),
            ("control_hash", password::digest(control.as_bytes())),
        ] {
            tx.execute("INSERT INTO metadata VALUES(?1,?2)", params![key, value])?;
        }
        tx.commit()?;
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        sync_directory(root)?;
    } else {
        check_file(&path, false)?;
        if fs::metadata(&path)?.len() == 0 || root.join("admin.sqlite-journal").exists() {
            return Err(StoreError::Unavailable);
        }
    }
    if fs::metadata(&path)?.len() > DATABASE_MAX
        || fs::metadata(root.join("admin.sqlite-wal")).is_ok_and(|m| m.len() > WAL_MAX)
    {
        return Err(StoreError::Unavailable);
    }
    let c = connect(&path, true)?;
    validate_schema(&c)?;
    for name in ["admin.sqlite", "admin.sqlite-wal", "admin.sqlite-shm"] {
        if root.join(name).exists() {
            protect_file(&root.join(name))?;
        }
    }
    // A token missing from initialized state is never silently rotated or regenerated.
    for (name, key) in [
        ("bootstrap.token", "bootstrap_hash"),
        ("control.token", "control_hash"),
    ] {
        let token = read_token(&root.join(name))?;
        let expected: String =
            c.query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
                r.get(0)
            })?;
        if !password::constant_eq(&expected, &password::digest(token.as_bytes())) {
            return Err(StoreError::Unavailable);
        }
    }
    if initializing {
        fs::remove_file(&marker)?;
        sync_directory(root)?;
    }
    Ok((c, lock))
}
fn validate_schema(c: &Connection) -> Result<(), StoreError> {
    let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if app != APPLICATION_ID || version != 1 {
        return Err(StoreError::Unavailable);
    }
    let page_size: i64 = c.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let journal: String = c.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    if page_size != 4096 || journal != "wal" {
        return Err(StoreError::Unavailable);
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA)?;
    let definitions =
        |connection: &Connection| -> Result<Vec<(String, String, String)>, StoreError> {
            let mut stmt=connection.prepare("SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        };
    if definitions(c)? != definitions(&reference)? {
        return Err(StoreError::Unavailable);
    }
    let check: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if check != "ok" || c.prepare("PRAGMA foreign_key_check")?.exists([])? {
        return Err(StoreError::Unavailable);
    }
    let state: String = c.query_row(
        "SELECT value FROM metadata WHERE key='bootstrap_state'",
        [],
        |r| r.get(0),
    )?;
    let users: i64 = c.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?;
    let imported: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='migration_source_sha256')",
        [],
        |r| r.get(0),
    )?;
    let full: i64 = c.query_row(
        "SELECT count(*) FROM users WHERE disabled=0 AND permissions=255",
        [],
        |r| r.get(0),
    )?;
    if !["pending", "consumed"].contains(&state.as_str())
        || users > 128
        || (state == "pending" && users != 0)
        || (state == "consumed" && (users == 0 || (!imported && full == 0)))
    {
        return Err(StoreError::Unavailable);
    }
    for sql in [
        "SELECT count(*)>256 FROM sessions",
        "SELECT EXISTS(SELECT user_id FROM sessions GROUP BY user_id HAVING count(*)>8)",
        "SELECT count(*)>50000 FROM audit_events",
        "SELECT count(*)>10080 FROM metric_rollups",
        "SELECT EXISTS(SELECT user_id FROM workspaces GROUP BY user_id HAVING count(*)>16)",
        "SELECT count(*)>32 FROM operation_requests WHERE state IN('queued','running')",
        "SELECT count(*)>1000 FROM operation_requests WHERE state NOT IN('queued','running')",
    ] {
        if c.query_row(sql, [], |r| r.get::<_, bool>(0))? {
            return Err(StoreError::Unavailable);
        }
    }
    let mut stmt = c.prepare("SELECT id,password FROM users")?;
    let records = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for record in records {
        let (id, hash) = record?;
        let user = load_user(c, &id)?;
        validate_identity(&user.username, &user.display_name)
            .map_err(|_| StoreError::Unavailable)?;
        permission_mask(&user.permissions).map_err(|_| StoreError::Unavailable)?;
        if let Some(stripped) = hash.strip_prefix("legacy:") {
            if !imported {
                return Err(StoreError::Unavailable);
            }
            let Some((salt, digest)) = stripped.split_once(':') else {
                return Err(StoreError::Unavailable);
            };
            if !matches!(salt.len(), 32 | 64)
                || digest.len() != 64
                || !salt
                    .bytes()
                    .chain(digest.bytes())
                    .all(|b| b.is_ascii_hexdigit())
            {
                return Err(StoreError::Unavailable);
            }
        } else if !hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$") {
            return Err(StoreError::Unavailable);
        }
    }
    Ok(())
}
fn write_admission(c: &Connection, root: &Path) -> Result<(), StoreError> {
    let wal = root.join("admin.sqlite-wal");
    if fs::metadata(&wal).map_or(0, |m| m.len()) >= WAL_MAX - TRANSACTION_RESERVE {
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        if fs::metadata(&wal).map_or(0, |m| m.len()) >= WAL_MAX - TRANSACTION_RESERVE {
            return Err(StoreError::Busy);
        }
    }
    let used = |c: &Connection| -> Result<u64, StoreError> {
        let pages: i64 = c.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let free: i64 = c.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        Ok((pages - free).max(0) as u64 * 4096)
    };
    if used(c)? > DATABASE_MAX - TRANSACTION_RESERVE {
        // Optional history is expendable; auth state is never reset to make space.
        // Start this bounded reclamation with a clean WAL, including when a reader pins it.
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        if fs::metadata(&wal).is_ok_and(|m| m.len() != 0) {
            return Err(StoreError::Busy);
        }
        let tx = c.unchecked_transaction()?;
        let mut removed=tx.execute("DELETE FROM metric_rollups WHERE minute IN (SELECT minute FROM metric_rollups ORDER BY minute LIMIT 64)",[])?;
        if used(&tx)? > DATABASE_MAX - TRANSACTION_RESERVE {
            removed+=tx.execute("DELETE FROM operation_requests WHERE id IN (SELECT id FROM operation_requests WHERE state NOT IN('queued','running') ORDER BY created_at,id LIMIT 1)",[])?;
        }
        if used(&tx)? > DATABASE_MAX - TRANSACTION_RESERVE {
            let audits=tx.execute("DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE id<COALESCE((SELECT id FROM audit_events ORDER BY id DESC LIMIT 1 OFFSET 999),-1) ORDER BY id LIMIT 256)",[])?;
            if audits > 0 {
                tx.execute("INSERT INTO metadata(key,value) VALUES('audit_gap_at',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[now().to_string()])?;
            }
            removed += audits;
        }
        if removed > 0 {
            tx.execute("INSERT INTO metadata(key,value) VALUES('history_gap_at',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[now().to_string()])?;
        }
        tx.commit()?;
        if used(c)? > DATABASE_MAX - TRANSACTION_RESERVE {
            return Err(StoreError::Busy);
        }
    }
    #[cfg(unix)]
    {
        let v = rustix::fs::statvfs(root).map_err(|_| StoreError::Unavailable)?;
        if v.f_bavail.saturating_mul(v.f_frsize as u64) < WAL_MAX + TRANSACTION_RESERVE {
            return Err(StoreError::Busy);
        }
    }
    Ok(())
}

pub(crate) fn secure_root(root: &Path) -> Result<(), StoreError> {
    for ancestor in root.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(m) if m.file_type().is_symlink() => return Err(StoreError::Unavailable),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if !root.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(root)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(root)?;
        // Persist every newly created ancestor before a migration can unlink its source.
        for ancestor in root.ancestors() {
            if let Some(parent) = ancestor.parent() {
                sync_directory(if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                })?;
            }
        }
    }
    let m = fs::symlink_metadata(root)?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(StoreError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
            return Err(StoreError::Unavailable);
        }
    }
    Ok(())
}
pub(crate) fn check_file(path: &Path, allow_missing: bool) -> Result<(), StoreError> {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if allow_missing && e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if !m.is_file() || m.file_type().is_symlink() {
        return Err(StoreError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 || m.nlink() != 1
        {
            return Err(StoreError::Unavailable);
        }
    }
    Ok(())
}
fn private_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    o
}
pub(crate) fn create_private(path: &Path) -> Result<File, StoreError> {
    Ok(private_options().write(true).create_new(true).open(path)?)
}
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut f = create_private(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
pub(crate) fn exclusive_lock(
    path: &Path,
    create: bool,
) -> Result<fd_lock::RwLock<File>, StoreError> {
    check_file(path, create)?;
    let file = private_options()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .open(path)?;
    let mut lock = fd_lock::RwLock::new(file);
    match lock.try_write() {
        Ok(guard) => std::mem::forget(guard),
        Err(_) => return Err(StoreError::Busy),
    }
    Ok(lock)
}
fn protect_file(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    check_file(path, false)
}
pub(crate) fn sync_directory(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn read_token(path: &Path) -> Result<String, StoreError> {
    check_file(path, false)?;
    let mut f = private_options().read(true).open(path)?;
    let mut token = String::new();
    Read::by_ref(&mut f).take(65).read_to_string(&mut token)?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(StoreError::Unavailable);
    }
    Ok(token)
}
pub fn read_bootstrap_token(root: &Path) -> Result<String, StoreError> {
    secure_existing_root(root)?;
    read_token(&root.join("bootstrap.token"))
}
pub fn read_control_token(root: &Path) -> Result<String, StoreError> {
    secure_existing_root(root)?;
    read_token(&root.join("control.token"))
}
fn secure_existing_root(root: &Path) -> Result<(), StoreError> {
    if !root.exists() || root.join(".initializing").exists() {
        return Err(StoreError::Unavailable);
    }
    secure_root(root)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, AdminStore) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state.admin");
        let store = AdminStore::open(&root).unwrap();
        (temp, root, store)
    }
    async fn owner(store: &AdminStore, root: &Path) -> SessionGrant {
        store
            .setup(
                read_bootstrap_token(root).unwrap(),
                "owner".into(),
                "Owner".into(),
                "owner password secure".into(),
            )
            .await
            .unwrap()
    }
    async fn reopen(root: &Path) -> AdminStore {
        for _ in 0..100 {
            match AdminStore::open(root) {
                Ok(store) => return store,
                Err(StoreError::Busy) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => panic!("reopen failed: {error}"),
            }
        }
        panic!("admin ownership did not release")
    }
    #[tokio::test]
    async fn setup_is_one_time_and_sessions_survive_restart() {
        let _serial = password::TEST_LOCK.lock().await;
        let (_temp, root, store) = fixture();
        assert!(store.setup_required().await.unwrap());
        let token = read_bootstrap_token(&root).unwrap();
        let (a, b) = tokio::join!(
            store.setup(
                token.clone(),
                "owner".into(),
                "Owner".into(),
                "owner password secure".into()
            ),
            store.setup(
                token,
                "other".into(),
                "Other".into(),
                "other password secure".into()
            )
        );
        assert_ne!(a.is_ok(), b.is_ok());
        let grant = a.or(b).unwrap();
        assert!(!store.setup_required().await.unwrap());
        drop(store);
        let store = reopen(&root).await;
        let auth = store.authenticate(grant.token.clone()).await.unwrap();
        assert_eq!(auth.user.id, grant.auth.user.id);
        assert_eq!(store.list_users(auth.clone()).await.unwrap().len(), 1);
        store.logout(auth).await.unwrap();
        assert!(matches!(
            store.authenticate(grant.token).await,
            Err(StoreError::Unauthorized)
        ));
    }
    #[tokio::test]
    async fn grants_last_admin_and_revocation_are_transactional() {
        let _serial = password::TEST_LOCK.lock().await;
        let (_temp, root, store) = fixture();
        let owner = owner(&store, &root).await;
        assert_eq!(
            store
                .delete_user(owner.auth.clone(), owner.auth.user.id.clone())
                .await,
            Err(StoreError::Conflict)
        );
        assert!(matches!(
            store
                .update_user(
                    owner.auth.clone(),
                    owner.auth.user.id.clone(),
                    None,
                    None,
                    vec![Permission::ViewStatus],
                    None
                )
                .await,
            Err(StoreError::Conflict)
        ));
        let viewer = store
            .create_user(
                owner.auth.clone(),
                "viewer".into(),
                "Viewer".into(),
                "viewer secure password".into(),
                vec![Permission::ViewStatus, Permission::TriggerSync],
            )
            .await
            .unwrap();
        let session = store
            .login("viewer".into(), "viewer secure password".into())
            .await
            .unwrap();
        assert!(matches!(
            store.list_users(session.auth.clone()).await,
            Err(StoreError::Forbidden)
        ));
        assert!(matches!(
            store
                .list_sessions(session.auth.clone(), Some(owner.auth.user.id.clone()))
                .await,
            Err(StoreError::Forbidden)
        ));
        store
            .update_user(
                owner.auth.clone(),
                viewer.id.clone(),
                None,
                None,
                vec![Permission::ViewStatus],
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .audit_operation(
                    session.auth.clone(),
                    "sync.request".into(),
                    "configured".into(),
                    "intent".into(),
                    "".into()
                )
                .await,
            Err(StoreError::Unauthorized)
        ));
        store
            .update_user(
                owner.auth.clone(),
                viewer.id.clone(),
                None,
                None,
                vec![Permission::ViewStatus],
                Some(true),
            )
            .await
            .unwrap();
        let updated = store
            .update_user(
                owner.auth.clone(),
                viewer.id,
                None,
                None,
                vec![Permission::ViewStatus],
                None,
            )
            .await
            .unwrap();
        assert!(updated.disabled);
        assert!(matches!(
            store.authenticate(session.token).await,
            Err(StoreError::Unauthorized)
        ));
        assert!(matches!(
            store
                .login("viewer".into(), "viewer secure password".into())
                .await,
            Err(StoreError::Unauthorized)
        ));
        let audit = store.list_audit(owner.auth, None, 100).await.unwrap();
        assert!(audit.iter().any(|event| event.action == "user.update"));
        assert!(
            audit
                .iter()
                .any(|event| event.action == "login" && event.outcome == "denied")
        );
    }
    #[tokio::test]
    async fn account_changes_require_credentials_and_revoke_every_session() {
        let _serial = password::TEST_LOCK.lock().await;
        let (_temp, root, store) = fixture();
        let owner = owner(&store, &root).await;
        let second = store
            .login("owner".into(), "owner password secure".into())
            .await
            .unwrap();
        assert!(matches!(
            store
                .update_account(owner.auth.clone(), Some("renamed".into()), None, None, None)
                .await,
            Err(StoreError::Forbidden)
        ));
        store
            .audit_operation(
                owner.auth.clone(),
                "sync.request".into(),
                "configured".into(),
                "intent".into(),
                "".into(),
            )
            .await
            .unwrap();
        store
            .update_account(
                owner.auth.clone(),
                None,
                Some("New display".into()),
                None,
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            store.authenticate(owner.token).await,
            Err(StoreError::Unauthorized)
        ));
        assert!(matches!(
            store.authenticate(second.token).await,
            Err(StoreError::Unauthorized)
        ));
        store
            .audit_operation(
                owner.auth,
                "sync.request".into(),
                "configured".into(),
                "accepted".into(),
                "".into(),
            )
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn failed_transaction_leaves_no_user_or_audit() {
        let (_temp, _root, store) = fixture();
        let result: Result<(), StoreError> = store
            .write(|tx| {
                let user = UserView {
                    id: "test".into(),
                    username: "test".into(),
                    display_name: "Test".into(),
                    permissions: vec![Permission::ViewStatus],
                    created_at: now(),
                    last_login_at: None,
                    disabled: false,
                };
                insert_user(tx, &user, "not committed")?;
                audit(tx, "test", "user.create", "test", "success", "")?;
                Err(StoreError::Unavailable)
            })
            .await;
        assert_eq!(result, Err(StoreError::Unavailable));
        assert_eq!(
            store
                .read(
                    |c| Ok(c.query_row("SELECT count(*) FROM users", [], |r| r.get::<_, i64>(0))?)
                )
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .read(
                    |c| Ok(c.query_row("SELECT count(*) FROM audit_events", [], |r| r
                        .get::<_, i64>(0))?)
                )
                .await
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn sessions_are_hashed_bounded_and_idle_expiring() {
        let _serial = password::TEST_LOCK.lock().await;
        let (_temp, root, store) = fixture();
        let owner = owner(&store, &root).await;
        let mut newest = owner;
        for _ in 0..9 {
            newest = store
                .write({
                    let user = newest.auth.user.clone();
                    move |tx| grant(tx, user)
                })
                .await
                .unwrap();
        }
        assert_eq!(
            store
                .list_sessions(newest.auth.clone(), None)
                .await
                .unwrap()
                .len(),
            8
        );
        let token = newest.token.clone();
        let stored = store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM sessions WHERE token_hash=?1 OR csrf=?1",
                    [token],
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(stored, 0);
        store
            .write(|tx| {
                tx.execute("UPDATE sessions SET last_seen_at=?1", [now() - 1801])?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            store.authenticate(newest.token).await,
            Err(StoreError::Unauthorized)
        ));
    }
    #[tokio::test]
    async fn control_token_has_only_machine_scope() {
        let (_temp, root, store) = fixture();
        let auth = store
            .authenticate_control(read_control_token(&root).unwrap())
            .await
            .unwrap();
        assert!(auth.machine);
        assert_eq!(
            auth.user.permissions,
            vec![Permission::ViewStatus, Permission::TriggerSync]
        );
        assert!(matches!(
            store.list_users(auth.clone()).await,
            Err(StoreError::Forbidden)
        ));
        store
            .audit_operation(
                auth,
                "sync.request".into(),
                "configured".into(),
                "intent".into(),
                "".into(),
            )
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn reader_deadline_and_queue_bound_are_real() {
        let connection = Connection::open_in_memory().unwrap();
        let worker = Worker::start(connection, PathBuf::new(), false, None).unwrap();
        let (started, wait_started) = mpsc::sync_channel(1);
        let (release, blocked) = mpsc::sync_channel(1);
        worker
            .sender
            .try_send(Box::new(move |_| {
                started.send(()).unwrap();
                blocked.recv().unwrap();
            }))
            .unwrap();
        wait_started.recv().unwrap();
        for _ in 0..64 {
            worker.sender.try_send(Box::new(|_| {})).unwrap();
        }
        assert_eq!(worker.call(|_| Ok(())).await, Err(StoreError::Busy));
        release.send(()).unwrap();
        let (_temp, _root, store) = fixture();
        let result=store.read(|c|Ok(c.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT sum(x) FROM n",[],|r|r.get::<_,i64>(0))?)).await;
        assert_eq!(result, Err(StoreError::Busy));
    }
    #[test]
    fn persisted_schema_identity_and_missing_state_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("admin");
        let (db, lock) = open_offline(&root).unwrap();
        db.pragma_update(None, "application_id", 1).unwrap();
        drop(db);
        drop(lock);
        assert!(matches!(
            AdminStore::open(&root),
            Err(StoreError::Unavailable)
        ));
        fs::remove_file(root.join("admin.sqlite")).unwrap();
        assert!(matches!(
            AdminStore::open(&root),
            Err(StoreError::Unavailable)
        ));
    }
    #[test]
    fn user_and_global_session_caps_are_enforced_by_database() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("admin");
        let (mut db, _lock) = open_offline(&root).unwrap();
        let tx = db.transaction().unwrap();
        for n in 0..128 {
            let user = UserView {
                id: format!("u{n}"),
                username: format!("u{n}"),
                display_name: "User".into(),
                permissions: vec![Permission::ViewStatus],
                created_at: now(),
                last_login_at: None,
                disabled: false,
            };
            insert_user(&tx, &user, "test hash").unwrap();
        }
        let extra = UserView {
            id: "extra".into(),
            username: "extra".into(),
            display_name: "Extra".into(),
            permissions: vec![Permission::ViewStatus],
            created_at: now(),
            last_login_at: None,
            disabled: false,
        };
        assert_eq!(insert_user(&tx, &extra, "test hash"), Err(StoreError::Busy));
        for n in 0..256 {
            tx.execute(
                "INSERT INTO sessions VALUES(?1,?2,?3,?4,?5,?5,?6)",
                params![
                    format!("s{n}"),
                    format!("{n:064x}"),
                    format!("u{}", n / 8),
                    password::random_token(),
                    now(),
                    now() + 28800
                ],
            )
            .unwrap();
        }
        assert!(
            tx.execute(
                "INSERT INTO sessions VALUES('overflow',?1,'u50',?2,?3,?3,?4)",
                params![
                    password::random_token(),
                    password::random_token(),
                    now(),
                    now() + 28800
                ]
            )
            .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn symlink_and_public_token_permissions_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("admin");
        let (db, lock) = open_offline(&root).unwrap();
        drop(db);
        drop(lock);
        fs::set_permissions(
            root.join("control.token"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(read_control_token(&root), Err(StoreError::Unavailable));
        let alias = temp.path().join("alias");
        symlink(&root, &alias).unwrap();
        assert!(matches!(
            AdminStore::open(&alias),
            Err(StoreError::Unavailable)
        ));
    }
    #[test]
    fn database_and_wal_limits_cannot_silently_expand() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("admin");
        let (db, lock) = open_offline(&root).unwrap();
        assert_eq!(
            u64::try_from(
                db.pragma_query_value(None, "max_page_count", |r| r.get::<_, i64>(0))
                    .unwrap()
            )
            .unwrap()
                * 4096,
            DATABASE_MAX
        );
        drop(db);
        drop(lock);
        let wal = create_private(&root.join("admin.sqlite-wal")).unwrap();
        wal.set_len(WAL_MAX + 1).unwrap();
        wal.sync_all().unwrap();
        drop(wal);
        assert!(matches!(
            AdminStore::open(&root),
            Err(StoreError::Unavailable)
        ));
    }
    #[test]
    fn interrupted_unexposed_initialization_can_resume_but_history_never_resets() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("admin");
        secure_root(&root).unwrap();
        create_private(&root.join(".initializing")).unwrap();
        create_private(&root.join("admin.sqlite")).unwrap();
        write_private(&root.join("bootstrap.token"), b"partial").unwrap();
        assert_eq!(read_bootstrap_token(&root), Err(StoreError::Unavailable));
        let (mut db, lock) = open_offline(&root).unwrap();
        assert!(!root.join(".initializing").exists());
        let tx = db.transaction().unwrap();
        audit(&tx, "anonymous", "login", "", "denied", "").unwrap();
        tx.commit().unwrap();
        drop(db);
        drop(lock);
        create_private(&root.join(".initializing")).unwrap();
        assert!(matches!(
            AdminStore::open(&root),
            Err(StoreError::Unavailable)
        ));
        let db = connect(&root.join("admin.sqlite"), false).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM audit_events", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
