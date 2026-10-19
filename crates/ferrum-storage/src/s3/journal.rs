//! A private-test allowance, not the production monthly transfer ledger.
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{CONTROL, ObjectIdentity, PrivateS3Config, S3Error};

pub(crate) type SharedJournal = Arc<Mutex<Journal>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferStatus {
    pub schema: u32,
    pub prefix: String,
    pub upload_limit: u64,
    pub download_limit: u64,
    pub upload_reserved: u64,
    pub download_reserved: u64,
    pub upload_observed: u64,
    pub download_observed: u64,
    pub attempts: u64,
    pub forbidden: bool,
    /// Observed body framing exceeded a guard. Counts remain exact; ordinary traffic stops.
    pub overrun: bool,
    pub objects: BTreeMap<String, ObjectRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRecord {
    pub size: u64,
    pub mutation_intent: bool,
    pub etag: Option<String>,
    pub deleted: bool,
    pub quarantined: bool,
    /// Pending conditional replacement token survives a lost response.
    pub replacement: Option<ReplacementIntent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementIntent {
    pub prior_etag: String,
    pub token: String,
}

pub(crate) struct Journal {
    directory: PathBuf,
    state: TransferStatus,
    // Lock is held by a platform file lock, not a borrowed fd-lock guard.
    _lock: File,
    poisoned: bool,
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn io(error: std::io::Error) -> S3Error {
    S3Error::Journal(error.to_string())
}

fn protect(path: &Path, directory: bool) -> Result<(), S3Error> {
    let metadata = std::fs::symlink_metadata(path).map_err(io)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(S3Error::Journal(
            "journal path is not a regular owned path".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let expected = if directory { 0o700 } else { 0o600 };
        if metadata.permissions().mode() & 0o777 != expected {
            return Err(S3Error::Journal(
                "journal paths must have mode 700/600".into(),
            ));
        }
    }
    Ok(())
}

impl Journal {
    pub(crate) fn initialize(config: &PrivateS3Config) -> Result<(), S3Error> {
        config.validate()?;
        // create_dir is intentional: existing, empty, or partially initialized means unknown usage.
        std::fs::create_dir(&config.transfer_journal).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &config.transfer_journal,
                std::fs::Permissions::from_mode(0o700),
            )
            .map_err(io)?;
        }
        let lock = private_options()
            .open(config.transfer_journal.join("lock"))
            .map_err(io)?;
        lock.sync_all().map_err(io)?;
        let mut journal = Self {
            directory: config.transfer_journal.clone(),
            state: TransferStatus {
                schema: 2,
                prefix: config.package_prefix.clone(),
                upload_limit: 8 * 1024 * 1024,
                download_limit: 16 * 1024 * 1024,
                upload_reserved: 0,
                download_reserved: 0,
                upload_observed: 0,
                download_observed: 0,
                attempts: 0,
                forbidden: false,
                overrun: false,
                objects: BTreeMap::new(),
            },
            _lock: lock,
            poisoned: false,
        };
        journal.persist()?;
        if let Some(parent) = journal.directory.parent() {
            File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(io)?;
        }
        Ok(())
    }

    pub(crate) fn reopen(config: &PrivateS3Config) -> Result<SharedJournal, S3Error> {
        protect(&config.transfer_journal, true)?;
        protect(&config.transfer_journal.join("state.json"), false)?;
        protect(&config.transfer_journal.join("lock"), false)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(config.transfer_journal.join("lock"))
            .map_err(io)?;
        lock.try_lock()
            .map_err(|_| S3Error::Journal("journal is already open".into()))?;
        let data = std::fs::read(config.transfer_journal.join("state.json")).map_err(io)?;
        if data.len() > 1024 * 1024 {
            return Err(S3Error::Journal("oversized journal".into()));
        }
        let state: TransferStatus = serde_json::from_slice(&data)
            .map_err(|_| S3Error::Journal("invalid or unknown journal usage".into()))?;
        if state.schema != 2
            || state.prefix != config.package_prefix
            || state.upload_limit != 8 * 1024 * 1024
            || state.download_limit != 16 * 1024 * 1024
            || state.upload_reserved > state.upload_limit
            || state.download_reserved > state.download_limit
            || (!state.overrun
                && (state.upload_observed > state.upload_reserved
                    || state.download_observed > state.download_reserved))
        {
            return Err(S3Error::Journal(
                "journal identity, usage or allowance differs".into(),
            ));
        }
        for (key, record) in &state.objects {
            config.validate_key(key)?;
            if record.size >= super::SINGLE_PUT_LIMIT {
                return Err(S3Error::Journal("invalid recorded object size".into()));
            }
        }
        // A stale temporary is never used to reconstruct or reset usage. The committed file is authority.
        Ok(Arc::new(Mutex::new(Self {
            directory: config.transfer_journal.clone(),
            state,
            _lock: lock,
            poisoned: false,
        })))
    }

    fn persist(&mut self) -> Result<(), S3Error> {
        if self.poisoned {
            return Err(S3Error::Journal(
                "journal failed previously; restart required".into(),
            ));
        }
        let result = (|| {
            let temporary = self.directory.join("state.next");
            if temporary.try_exists().map_err(io)? {
                protect(&temporary, false)?;
                std::fs::remove_file(&temporary).map_err(io)?;
            }
            let bytes = serde_json::to_vec_pretty(&self.state)
                .map_err(|error| S3Error::Journal(error.to_string()))?;
            let mut file = private_options().open(&temporary).map_err(io)?;
            file.write_all(&bytes).map_err(io)?;
            file.sync_all().map_err(io)?;
            std::fs::rename(temporary, self.directory.join("state.json")).map_err(io)?;
            File::open(&self.directory)
                .and_then(|file| file.sync_all())
                .map_err(io)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn status(&self) -> TransferStatus {
        self.state.clone()
    }

    pub(crate) fn is_forbidden(&self) -> bool {
        self.state.forbidden
    }
    pub(crate) fn has_overrun(&self) -> bool {
        self.state.overrun
    }

    pub(crate) fn authorize(&mut self, key: &str, identity: ObjectIdentity) -> Result<(), S3Error> {
        if let Some(record) = self.state.objects.get(key) {
            if record.size != identity.size {
                return Err(S3Error::Corrupt);
            }
            return Ok(());
        }
        if self.state.objects.len() >= 32 {
            return Err(S3Error::Budget);
        }
        self.state.objects.insert(
            key.into(),
            ObjectRecord {
                size: identity.size,
                mutation_intent: false,
                etag: None,
                deleted: false,
                quarantined: false,
                replacement: None,
            },
        );
        self.persist()
    }

    pub(crate) fn object(&self, key: &str) -> Result<&ObjectRecord, S3Error> {
        self.state.objects.get(key).ok_or(S3Error::Boundary)
    }

    pub(crate) fn intent(&mut self, key: &str) -> Result<(), S3Error> {
        let record = self.state.objects.get_mut(key).ok_or(S3Error::Boundary)?;
        if record.mutation_intent {
            return Err(S3Error::Conflict);
        }
        record.mutation_intent = true;
        self.persist()
    }

    pub(crate) fn owned(&mut self, key: &str, etag: String) -> Result<(), S3Error> {
        let record = self.state.objects.get_mut(key).ok_or(S3Error::Boundary)?;
        if !record.mutation_intent {
            return Err(S3Error::Boundary);
        }
        record.etag = Some(etag);
        record.replacement = None;
        record.deleted = false;
        self.persist()
    }

    pub(crate) fn replace_intent(&mut self, key: &str, token: String) -> Result<String, S3Error> {
        let record = self.state.objects.get_mut(key).ok_or(S3Error::Boundary)?;
        if !record.mutation_intent || record.deleted || record.replacement.is_some() {
            return Err(S3Error::Conflict);
        }
        let prior_etag = record.etag.clone().ok_or(S3Error::Boundary)?;
        record.replacement = Some(ReplacementIntent {
            prior_etag: prior_etag.clone(),
            token,
        });
        self.persist()?;
        Ok(prior_etag)
    }

    pub(crate) fn deleted(&mut self, key: &str) -> Result<(), S3Error> {
        self.state
            .objects
            .get_mut(key)
            .ok_or(S3Error::Boundary)?
            .deleted = true;
        self.persist()
    }

    pub(crate) fn quarantine(&mut self, key: &str) -> Result<(), S3Error> {
        self.state
            .objects
            .get_mut(key)
            .ok_or(S3Error::Boundary)?
            .quarantined = true;
        self.persist()
    }

    pub(crate) fn forbidden(&mut self) -> Result<(), S3Error> {
        self.state.forbidden = true;
        self.persist()
    }

    pub(crate) fn reserve(
        &mut self,
        upload: u64,
        download: u64,
        cleanup: bool,
    ) -> Result<(), S3Error> {
        if self.state.overrun && !cleanup {
            return Err(S3Error::Budget);
        }
        let upload = self
            .state
            .upload_reserved
            .max(self.state.upload_observed)
            .checked_add(upload)
            .ok_or(S3Error::Budget)?;
        let download = self
            .state
            .download_reserved
            .max(self.state.download_observed)
            .checked_add(download)
            .ok_or(S3Error::Budget)?;
        // Retain eight bounded control attempts for owned-key reconciliation and cleanup.
        let upload_reserve = if cleanup { 0 } else { 8 * CONTROL };
        let download_reserve = if cleanup {
            0
        } else {
            8 * (CONTROL + super::PROTOCOL_BUFFER)
        };
        if upload > self.state.upload_limit.saturating_sub(upload_reserve)
            || download > self.state.download_limit.saturating_sub(download_reserve)
        {
            return Err(S3Error::Budget);
        }
        self.state.upload_reserved = upload;
        self.state.download_reserved = download;
        self.state.attempts = self.state.attempts.checked_add(1).ok_or(S3Error::Budget)?;
        self.persist()
    }

    pub(crate) fn observe(
        &mut self,
        upload: bool,
        bytes: u64,
        overrun: bool,
    ) -> Result<(), S3Error> {
        let counter = if upload {
            &mut self.state.upload_observed
        } else {
            &mut self.state.download_observed
        };
        *counter = counter.checked_add(bytes).ok_or(S3Error::Budget)?;
        self.state.overrun |= overrun
            || self.state.upload_observed > self.state.upload_reserved
            || self.state.download_observed > self.state.download_reserved;
        self.persist()
    }
}

pub(crate) fn lock(journal: &SharedJournal) -> Result<std::sync::MutexGuard<'_, Journal>, S3Error> {
    journal
        .lock()
        .map_err(|_| S3Error::Journal("journal lock poisoned".into()))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn reservations_survive_restart_and_cannot_reset() {
        let root = tempfile::tempdir().expect("tempdir");
        let config = PrivateS3Config::test_config(root.path().join("journal"));
        Journal::initialize(&config).expect("explicit fresh init");
        assert!(Journal::initialize(&config).is_err());
        let shared = Journal::reopen(&config).expect("reopen");
        lock(&shared)
            .expect("lock")
            .reserve(7 * 1024 * 1024, 0, false)
            .expect("reserve");
        drop(shared);
        let shared = Journal::reopen(&config).expect("restart");
        assert_eq!(
            lock(&shared).expect("lock").status().upload_reserved,
            7 * 1024 * 1024
        );
        assert!(
            lock(&shared)
                .expect("lock")
                .reserve(1024 * 1024, 0, false)
                .is_err()
        );
        assert!(
            lock(&shared)
                .expect("lock")
                .reserve(0, 17 * 1024 * 1024, true)
                .is_err()
        );
    }
    #[test]
    fn absent_or_unknown_ledger_never_opens() {
        let root = tempfile::tempdir().expect("tempdir");
        let config = PrivateS3Config::test_config(root.path().join("journal"));
        assert!(Journal::reopen(&config).is_err());
        std::fs::create_dir(&config.transfer_journal).expect("mkdir");
        assert!(Journal::initialize(&config).is_err());
        assert!(Journal::reopen(&config).is_err());
    }

    #[test]
    fn corrupted_usage_and_concurrent_open_are_refused_without_reinitializing() {
        let root = tempfile::tempdir().expect("tempdir");
        let config = PrivateS3Config::test_config(root.path().join("journal"));
        Journal::initialize(&config).expect("init");
        let shared = Journal::reopen(&config).expect("open");
        assert!(Journal::reopen(&config).is_err());
        drop(shared);
        std::fs::write(config.transfer_journal.join("state.json"), b"{}").expect("damage journal");
        assert!(Journal::reopen(&config).is_err());
        assert!(Journal::initialize(&config).is_err());
    }
}
