use crate::config::{self, BudgetProfile};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) type SharedJournal = Arc<Mutex<Journal>>;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Candidate {
    pub(crate) size: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Object {
    pub(crate) owned: bool,
    pub(crate) clean: bool,
    pub(crate) size: u64,
    pub(crate) sha256: String,
    #[serde(default)]
    pub(crate) candidates: Vec<Candidate>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Upload {
    pub(crate) key: String,
    pub(crate) id: String,
    pub(crate) resolved: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) schema_version: u32,
    pub(crate) prefix: String,
    #[serde(default)]
    pub(crate) budget_profile: BudgetProfile,
    #[serde(default)]
    pub(crate) checkpoint_prefix: Option<String>,
    #[serde(default)]
    pub(crate) faults: BTreeMap<String, String>,
    pub(crate) bucket: String,
    pub(crate) upload_reserved: u64,
    pub(crate) download_reserved: u64,
    pub(crate) objects: BTreeMap<String, Object>,
    pub(crate) uploads: Vec<Upload>,
    pub(crate) pending_creates: Vec<String>,
    pub(crate) events: u64,
    pub(crate) outcome: String,
    pub(crate) capabilities: BTreeMap<String, Value>,
}

pub(crate) struct Journal {
    pub(crate) manifest: Manifest,
    directory: PathBuf,
    evidence: File,
}

pub(crate) fn lock(journal: &SharedJournal) -> Result<MutexGuard<'_, Journal>> {
    journal
        .lock()
        .map_err(|_| anyhow::anyhow!("probe journal lock poisoned"))
}

fn private_file(path: &Path, append: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true);
    if append {
        options.append(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

pub(crate) fn sync_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

impl Journal {
    pub(crate) fn create(
        directory: &Path,
        prefix: String,
        profile: BudgetProfile,
        target: &config::ProbeTarget,
    ) -> Result<SharedJournal> {
        config::validate_prefix(&prefix)?;
        std::fs::create_dir(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let evidence = private_file(&directory.join("evidence.jsonl"), false)?;
        let mut journal = Self {
            manifest: Manifest {
                schema_version: if profile == BudgetProfile::Qualification {
                    2
                } else {
                    1
                },
                checkpoint_prefix: if profile == BudgetProfile::Qualification {
                    Some(config::checkpoint_prefix(&prefix)?)
                } else {
                    None
                },
                budget_profile: profile,
                faults: BTreeMap::new(),
                prefix,
                bucket: target.bucket.clone(),
                upload_reserved: 0,
                download_reserved: 0,
                objects: BTreeMap::new(),
                uploads: Vec::new(),
                pending_creates: Vec::new(),
                events: 0,
                outcome: "running".to_owned(),
                capabilities: BTreeMap::new(),
            },
            directory: directory.to_owned(),
            evidence,
        };
        journal.save()?;
        let (upload_limit, download_limit, cleanup_reserve) = profile.limits();
        journal.event(json!({"kind":"contract", "sdk":"aws-sdk-s3=1.152.0", "rust":"1.99.1", "endpoint":target.endpoint, "region":target.region, "bucket":target.bucket, "prefix":journal.manifest.prefix, "checkpoint_prefix":journal.manifest.checkpoint_prefix, "budget_profile":profile, "credential_profile":"shared_NONISOLATED", "permission_isolation_claim":false, "path_style":true, "behavior_version":"2026-01-12", "request_checksum":"WhenRequired", "response_checksum":"WhenRequired", "sdk_max_attempts":1, "application_retries":0, "upload_limit":upload_limit, "download_limit":download_limit, "cleanup_reserve":cleanup_reserve, "accounting":"full body ceilings plus 64KiB allowance per direction per request; reservations never refunded, even on timeout or cleanup restart; not a provider billing meter"}))?;
        Ok(Arc::new(Mutex::new(journal)))
    }

    pub(crate) fn open(directory: &Path, target: &config::ProbeTarget) -> Result<SharedJournal> {
        let metadata = std::fs::symlink_metadata(directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "run directory must not be a symlink"
        );
        let path = directory.join("manifest.json");
        ensure!(
            std::fs::symlink_metadata(&path)?.is_file(),
            "manifest must be a regular file"
        );
        ensure!(
            std::fs::metadata(&path)?.len() <= 1024 * 1024,
            "manifest too large"
        );
        let manifest: Manifest = serde_json::from_reader(File::open(path)?)?;
        ensure!(
            manifest.bucket == target.bucket,
            "manifest bucket mismatch"
        );
        match (manifest.schema_version, manifest.budget_profile) {
            (1, BudgetProfile::LegacyBlob) => {
                ensure!(
                    manifest.checkpoint_prefix.is_none(),
                    "legacy checkpoint scope forbidden"
                );
            }
            (2, BudgetProfile::Qualification) => {
                ensure!(
                    manifest.checkpoint_prefix.as_deref()
                        == Some(config::checkpoint_prefix(&manifest.prefix)?.as_str()),
                    "checkpoint scope mismatch"
                );
            }
            _ => anyhow::bail!(
                "incompatible manifest schema/profile; no automatic allowance migration"
            ),
        }
        config::validate_prefix(&manifest.prefix)?;
        ensure!(
            manifest.objects.len() <= 9
                && manifest.uploads.len() <= 8
                && manifest.pending_creates.len() <= 2,
            "manifest entry ceiling"
        );
        for key in manifest
            .objects
            .keys()
            .chain(manifest.pending_creates.iter())
        {
            config::validate_owned_key(
                &manifest.prefix,
                manifest.checkpoint_prefix.as_deref(),
                key,
            )?;
        }
        for upload in &manifest.uploads {
            config::validate_key(&manifest.prefix, &upload.key)?;
            ensure!(
                !upload.id.is_empty() && upload.id.len() <= 2048,
                "invalid retained upload ID"
            );
        }
        let (upload_limit, download_limit, _) = manifest.budget_profile.limits();
        ensure!(
            manifest.upload_reserved <= upload_limit
                && manifest.download_reserved <= download_limit,
            "retained budget invalid"
        );
        for object in manifest.objects.values() {
            ensure!(object.candidates.len() <= 8, "candidate ceiling exceeded");
            for candidate in &object.candidates {
                ensure!(
                    candidate.size <= config::CHECKPOINT_MAX && candidate.sha256.len() == 64,
                    "invalid checkpoint candidate"
                );
            }
        }
        let journal = Self {
            manifest,
            directory: directory.to_owned(),
            evidence: private_file(&directory.join("evidence.jsonl"), true)?,
        };
        Ok(Arc::new(Mutex::new(journal)))
    }

    pub(crate) fn save(&self) -> Result<()> {
        // Never truncate the authoritative manifest. A crash leaves the previous durable snapshot.
        let temporary = self.directory.join("manifest.next");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        serde_json::to_writer_pretty(&mut file, &self.manifest)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(temporary, self.directory.join("manifest.json"))?;
        sync_directory(&self.directory)
    }

    pub(crate) fn event(&mut self, mut value: Value) -> Result<()> {
        if value["kind"] == "capability" {
            let operation = value["operation"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("capability operation missing"))?;
            self.manifest
                .capabilities
                .insert(operation.to_owned(), value.clone());
        }
        self.manifest.events = self
            .manifest
            .events
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("event overflow"))?;
        value["event"] = json!(self.manifest.events);
        value["unix_ms"] = json!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis());
        serde_json::to_writer(&mut self.evidence, &value)?;
        self.evidence.write_all(b"\n")?;
        self.evidence.sync_all()?;
        self.save()
    }

    pub(crate) fn reserve(&mut self, upload: u64, download: u64, cleanup: bool) -> Result<()> {
        let upload = upload
            .checked_add(config::CONTROL)
            .ok_or_else(|| anyhow::anyhow!("upload reservation overflow"))?;
        let download = download
            .checked_add(config::CONTROL)
            .ok_or_else(|| anyhow::anyhow!("download reservation overflow"))?;
        let next_upload = self
            .manifest
            .upload_reserved
            .checked_add(upload)
            .ok_or_else(|| anyhow::anyhow!("upload budget overflow"))?;
        let next_download = self
            .manifest
            .download_reserved
            .checked_add(download)
            .ok_or_else(|| anyhow::anyhow!("download budget overflow"))?;
        let (upload_limit, download_limit, cleanup_reserve) = self.manifest.budget_profile.limits();
        let reserve = if cleanup { 0 } else { cleanup_reserve };
        ensure!(
            next_upload <= upload_limit - reserve && next_download <= download_limit - reserve,
            "approved transfer budget exhausted"
        );
        self.manifest.upload_reserved = next_upload;
        self.manifest.download_reserved = next_download;
        self.event(json!({"kind":"reservation", "upload":upload, "download":download, "cleanup":cleanup, "upload_total":next_upload, "download_total":next_download}))
    }

    pub(crate) fn intent(&mut self, key: &str, size: u64, sha256: &str) -> Result<()> {
        config::validate_owned_key(
            &self.manifest.prefix,
            self.manifest.checkpoint_prefix.as_deref(),
            key,
        )?;
        ensure!(
            !self.manifest.objects.contains_key(key),
            "object intent already exists"
        );
        self.manifest.objects.insert(
            key.to_owned(),
            Object {
                owned: false,
                clean: false,
                size,
                sha256: sha256.to_owned(),
                candidates: Vec::new(),
            },
        );
        self.event(json!({"kind":"object_intent", "key":key, "size":size, "sha256":sha256}))
    }

    pub(crate) fn own(&mut self, key: &str) -> Result<()> {
        self.manifest
            .objects
            .get_mut(key)
            .ok_or_else(|| anyhow::anyhow!("object intent missing"))?
            .owned = true;
        self.event(json!({"kind":"object_owned", "key":key}))
    }

    pub(crate) fn candidate(&mut self, key: &str, size: u64, sha256: &str) -> Result<()> {
        config::validate_owned_key(
            &self.manifest.prefix,
            self.manifest.checkpoint_prefix.as_deref(),
            key,
        )?;
        ensure!(
            self.manifest
                .checkpoint_prefix
                .as_deref()
                .is_some_and(|prefix| key.starts_with(prefix)),
            "candidate is not in checkpoint adapter scope"
        );
        ensure!(
            size <= config::CHECKPOINT_MAX,
            "checkpoint candidate too large"
        );
        let object = self
            .manifest
            .objects
            .get_mut(key)
            .ok_or_else(|| anyhow::anyhow!("checkpoint intent missing"))?;
        ensure!(object.candidates.len() < 8, "checkpoint candidate ceiling");
        object.candidates.push(Candidate {
            size,
            sha256: sha256.to_owned(),
        });
        self.event(json!({"kind":"checkpoint_candidate", "key":key, "size":size, "sha256":sha256}))
    }

    pub(crate) fn fault(&mut self, operation: &str, state: &str) -> Result<()> {
        ensure!(
            self.manifest.budget_profile == BudgetProfile::Qualification,
            "legacy run cannot inject faults"
        );
        let previous = self.manifest.faults.get(operation).map(String::as_str);
        ensure!(
            matches!(
                (previous, state),
                (None, "armed")
                    | (Some("armed"), "delivered_locally_without_provider_request")
                    | (
                        Some("armed"),
                        "provider_success_body_settled_acknowledgment_suppressed"
                    )
                    | (
                        Some("provider_success_body_settled_acknowledgment_suppressed"),
                        "reconciled_by_owned_head_size_full_sha256"
                    )
            ),
            "invalid or repeated injected fault transition"
        );
        self.manifest
            .faults
            .insert(operation.to_owned(), state.to_owned());
        self.event(json!({"kind":"injected_fault_state", "source":"INJECTED", "operation":operation, "state":state}))
    }

    pub(crate) fn add_upload(&mut self, key: &str, id: &str) -> Result<()> {
        config::validate_key(&self.manifest.prefix, key)?;
        ensure!(
            self.manifest.objects.contains_key(key),
            "multipart key lacks intent"
        );
        ensure!(!id.is_empty() && id.len() <= 2048, "invalid upload ID");
        self.manifest.uploads.push(Upload {
            key: key.to_owned(),
            id: id.to_owned(),
            resolved: false,
        });
        self.manifest
            .pending_creates
            .retain(|pending| pending != key);
        self.event(json!({"kind":"multipart_created", "key":key, "upload_id":id}))
    }

    pub(crate) fn resolve_upload(&mut self, id: &str) -> Result<()> {
        for upload in &mut self.manifest.uploads {
            if upload.id == id {
                upload.resolved = true;
            }
        }
        self.event(json!({"kind":"multipart_resolved", "upload_id":id}))
    }

    pub(crate) fn unrun(&mut self, operation: &str, reason: &str) -> Result<()> {
        self.event(
            json!({"kind":"capability", "operation":operation, "outcome":"unrun", "reason":reason}),
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::config::MIB;

    fn default_target() -> config::ProbeTarget {
        config::ProbeTarget {
            endpoint: config::ENDPOINT.to_owned(),
            host: "s3.us-east-1.amazonaws.com".to_owned(),
            region: config::REGION.to_owned(),
            bucket: config::BUCKET.to_owned(),
        }
    }

    #[test]
    fn cleanup_keeps_reserved_headroom_and_restart_never_resets_usage() -> Result<()> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ferrum-e2-budget-test-{}-{unique}",
            std::process::id()
        ));
        let prefix = format!("{}0123456789abcdef0123456789abcdef/", config::ROOT);
        let target = default_target();
        let journal = Journal::create(&directory, prefix, BudgetProfile::LegacyBlob, &target)?;
        {
            let mut journal = lock(&journal)?;
            journal.reserve(90 * MIB, 0, false)?;
            assert!(journal.reserve(6 * MIB, 0, false).is_err());
            journal.reserve(6 * MIB, 0, true)?;
            journal.unrun("checkpoint", "separate credential absent")?;
        }
        let total = lock(&journal)?.manifest.upload_reserved;
        drop(journal);
        let manifest_path = directory.join("manifest.json");
        let mut old: Value = serde_json::from_reader(File::open(&manifest_path)?)?;
        let fields = old
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("manifest is not an object"))?;
        for field in ["budget_profile", "checkpoint_prefix", "faults"] {
            fields.remove(field);
        }
        std::fs::write(&manifest_path, serde_json::to_vec(&old)?)?;
        let journal = Journal::open(&directory, &target)?;
        {
            let mut journal = lock(&journal)?;
            assert_eq!(journal.manifest.upload_reserved, total);
            assert_eq!(journal.manifest.budget_profile, BudgetProfile::LegacyBlob);
            assert!(journal.manifest.checkpoint_prefix.is_none());
            assert!(journal.fault("injected_timeout", "armed").is_err());
            assert!(journal.reserve(4 * MIB, 0, true).is_err());
            assert_eq!(journal.manifest.upload_reserved, total);
            assert_eq!(
                journal.manifest.capabilities["checkpoint"]["outcome"],
                "unrun"
            );
        }
        drop(journal);
        // This path was exclusively created above for this test; never an operator directory.
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn qualification_budget_candidates_and_fault_state_survive_restart() -> Result<()> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ferrum-e2-qualification-test-{}-{unique}",
            std::process::id()
        ));
        let prefix = format!("{}0123456789abcdef0123456789abcdef/", config::ROOT);
        let checkpoint = format!("{}state", config::checkpoint_prefix(&prefix)?);
        let target = default_target();
        let journal = Journal::create(&directory, prefix, BudgetProfile::Qualification, &target)?;
        {
            let mut journal = lock(&journal)?;
            journal.reserve(239 * MIB, 495 * MIB, false)?;
            assert!(journal.reserve(MIB, MIB, false).is_err());
            journal.reserve(MIB, MIB, true)?;
            journal.intent(&checkpoint, 2, &"a".repeat(64))?;
            journal.candidate(&checkpoint, 2, &"a".repeat(64))?;
            assert!(
                journal
                    .candidate(&checkpoint, config::CHECKPOINT_MAX + 1, &"a".repeat(64))
                    .is_err()
            );
            assert!(
                journal
                    .fault(
                        "multipart_complete_lost_response",
                        "provider_success_body_settled_acknowledgment_suppressed"
                    )
                    .is_err()
            );
            journal.fault("multipart_complete_lost_response", "armed")?;
            journal.fault(
                "multipart_complete_lost_response",
                "provider_success_body_settled_acknowledgment_suppressed",
            )?;
        }
        let total = lock(&journal)?.manifest.upload_reserved;
        drop(journal);
        let journal = Journal::open(&directory, &target)?;
        {
            let mut journal = lock(&journal)?;
            assert_eq!(
                journal.manifest.budget_profile,
                BudgetProfile::Qualification
            );
            assert_eq!(journal.manifest.upload_reserved, total);
            assert_eq!(journal.manifest.objects[&checkpoint].candidates.len(), 1);
            journal.fault(
                "multipart_complete_lost_response",
                "reconciled_by_owned_head_size_full_sha256",
            )?;
            assert!(
                journal
                    .fault("multipart_complete_lost_response", "armed")
                    .is_err()
            );
        }
        drop(journal);
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }
}
