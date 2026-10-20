use super::*;
use rusqlite::{OptionalExtension, params};
impl Production {
    pub(super) fn mutation_marker(&self, key: &str, create: bool) -> Result<String, S3Error> {
        let timestamp = now()?;
        let owned = key.to_owned();
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                let changed = connection.execute(
                    "UPDATE remote_storage SET mutation_intent=1,intent_at=CASE WHEN mutation_intent=0 THEN ?2 ELSE intent_at END WHERE key=?1",
                    params![owned, timestamp],
                )?;
                if changed != 1 {
                    return Err(crate::catalog::CatalogError::InvalidState);
                }
                Ok(())
            })
            .map_err(database)?;
        if !self.config.package_prefix.contains("/_ferrum-b07/") {
            return Ok("ferrum-v1".into());
        }
        let key = key.to_owned();
        let monthly = self.transport.ledger.monthly_download_limit();
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                let transaction = connection.transaction()?;
                let existing: Option<String> = transaction
                    .query_row(
                        "SELECT token FROM qualification_ownership WHERE key=?1 AND deleted=0",
                        [&key],
                        |row| row.get(0),
                    )
                    .optional()?;
                let token = match existing {
                    Some(token) => token,
                    None if create => {
                        let upload = crate::catalog::signed(10 * CONTROL)?;
                        let download = crate::catalog::signed(10 * (CONTROL + super::super::PROTOCOL_BUFFER))?;
                        let reserved = transaction.execute(
                            "UPDATE qualification_budget SET cleanup_upload=cleanup_upload+?1,cleanup_download=cleanup_download+?2 WHERE id=1 AND uploaded<=upload_limit-cleanup_upload-?1 AND downloaded<=download_limit-cleanup_download-?2 AND (SELECT used FROM remote_budget WHERE id=1)<=?3-cleanup_download-?2",
                            params![upload, download, crate::catalog::signed(monthly)?],
                        )?;
                        if reserved != 1 {
                            return Err(crate::catalog::CatalogError::Busy);
                        }
                        let token = format!("{:032x}", rand::random::<u128>());
                        transaction.execute(
                            "INSERT INTO qualification_ownership(key,token,deleted,cleanup_upload,cleanup_download) VALUES(?1,?2,0,?3,?4) ON CONFLICT(key) DO UPDATE SET token=excluded.token,etag=NULL,deleted=0,cleanup_upload=excluded.cleanup_upload,cleanup_download=excluded.cleanup_download",
                            params![key, token, upload, download],
                        )?;
                        token
                    }
                    None => return Err(crate::catalog::CatalogError::InvalidState),
                };
                transaction.execute(
                    "UPDATE qualification_ownership SET etag=NULL WHERE key=?1",
                    [&key],
                )?;
                transaction.commit()?;
                Ok(token)
            })
            .map_err(database)
    }
    pub(super) fn mutation_accepted(&self, key: &str, etag: Option<&str>) -> Result<(), S3Error> {
        let key = key.to_owned();
        let etag = etag.map(str::to_owned);
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                let transaction = connection.transaction()?;
                transaction.execute(
                    "UPDATE remote_storage SET committed=1,gc_owned=1 WHERE key=?1",
                    [&key],
                )?;
                transaction.execute(
                    "UPDATE qualification_ownership SET etag=?2 WHERE key=?1 AND deleted=0",
                    params![key, etag],
                )?;
                transaction.commit()?;
                Ok(())
            })
            .map_err(database)
    }
}
impl S3Store {
    /// Explicit private-operation identity: only recorded intents inside this
    /// exact correlated disposable run may be deleted. Canonical instances have
    /// no such operation. No LIST result grants cleanup authority.
    pub async fn cleanup_qualification(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<u64, S3Error> {
        let store = self.production()?;
        if !store.config.package_prefix.contains("/_ferrum-b07/")
            || !store.config.checkpoint_prefix.contains("/_ferrum-b07/")
        {
            return Err(S3Error::Boundary);
        }
        store
            .transport
            .ledger
            .spool()
            .catalog_write(|connection| {
                connection.execute(
                    "UPDATE capture_state SET coverage=0,gc_resume=0 WHERE id=1",
                    [],
                )?;
                Ok(())
            })
            .map_err(database)?;
        store
            .transport
            .ledger
            .spool()
            .reset_capture_verification()
            .map_err(database)?;
        self.reap_uploads(now()?, true, deadline, cancel).await?;
        let mut after = String::new();
        let mut deleted = 0;
        loop {
            let cursor = after.clone();
            let rows = store
                .transport
                .ledger
                .spool()
                .durable_catalog()
                .map_err(database)?
                .read(move |connection| {
                    let mut statement = connection.prepare("SELECT key,token,etag FROM qualification_ownership WHERE deleted=0 AND key>?1 ORDER BY key LIMIT 64")?;
                    let rows = statement.query_map([cursor], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    })?;
                    Ok(rows.collect::<Result<Vec<_>, _>>()?)
                })
                .map_err(database)?;
            if rows.is_empty() {
                break;
            }
            for (key, token, recorded_etag) in rows {
                after = key.clone();
                let pending = key.clone();
                let unresolved = store
                    .transport
                    .ledger
                    .spool()
                    .durable_catalog()
                    .map_err(database)?
                    .read(move |connection| {
                        Ok(connection.query_row(
                            "SELECT creates>0 OR EXISTS(SELECT 1 FROM multipart_uploads WHERE key=?1) FROM qualification_ownership WHERE key=?1",
                            [pending],
                            |row| row.get::<_, bool>(0),
                        )?)
                    })
                    .map_err(database)?;
                if unresolved {
                    return Err(S3Error::Unavailable);
                }
                if !(key.starts_with(store.config.package_prefix.as_ref())
                    || key.starts_with(store.config.checkpoint_prefix.as_ref()))
                {
                    return Err(S3Error::Boundary);
                }
                let client = store.client(
                    OperationIdentity::PrivateQualificationCleanup,
                    &key,
                    CONTROL,
                    BudgetClass::Control,
                )?;
                let head = {
                    let _slots = store.slot(true, deadline, cancel).await?;
                    bounded(deadline, cancel, async {
                        client
                            .head_object()
                            .bucket(&store.config.bucket)
                            .key(&key)
                            .send()
                            .await
                            .map_err(|error| classify_sdk(error, true))
                    })
                    .await
                };
                let head = match head {
                    Ok(head) => Some(head),
                    Err(S3Error::NotFound) => {
                        if !self
                            .confirm_absent(
                                OperationIdentity::PrivateQualificationCleanup,
                                &key,
                                deadline,
                                cancel,
                            )
                            .await?
                        {
                            return Err(S3Error::Unavailable);
                        }
                        None
                    }
                    Err(error) => return Err(error),
                };
                if let Some(head) = head {
                    if head.version_id().is_some_and(|version| version != "null")
                        || head
                            .metadata()
                            .and_then(|metadata| metadata.get("ferrum-owner"))
                            .map(String::as_str)
                            != Some(token.as_str())
                    {
                        continue;
                    }
                    let etag = head.e_tag().ok_or(S3Error::Corrupt)?.to_owned();
                    if recorded_etag
                        .as_deref()
                        .is_some_and(|recorded| recorded != etag)
                    {
                        return Err(S3Error::Conflict);
                    }
                    let known = key.clone();
                    let observed = etag.clone();
                    store
                        .transport
                        .ledger
                        .spool()
                        .catalog_write(move |connection| {
                            connection.execute(
                                "UPDATE qualification_ownership SET etag=?2 WHERE key=?1",
                                params![known, observed],
                            )?;
                            Ok(())
                        })
                        .map_err(database)?;
                    let _slots = store.slot(true, deadline, cancel).await?;
                    let deletion = bounded(deadline, cancel, async {
                        client
                            .delete_object()
                            .bucket(&store.config.bucket)
                            .key(&key)
                            .if_match(etag)
                            .send()
                            .await
                            .map_err(|error| classify_sdk(error, false))
                    })
                    .await?;
                    if deletion
                        .version_id()
                        .is_some_and(|version| version != "null")
                        || deletion.delete_marker() == Some(true)
                    {
                        return Err(S3Error::Unsupported);
                    }
                }
                let known = key.clone();
                store
                    .transport
                    .ledger
                    .spool()
                    .catalog_write(move |connection| {
                        let transaction = connection.transaction()?;
                        let (up, down): (i64, i64) = transaction.query_row(
                            "SELECT cleanup_upload,cleanup_download FROM qualification_ownership WHERE key=?1",
                            [&known],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )?;
                        if up < 0 || down < 0 {
                            return Err(crate::catalog::CatalogError::InvalidState);
                        }
                        transaction.execute(
                            "UPDATE qualification_budget SET cleanup_upload=cleanup_upload-?1,cleanup_download=cleanup_download-?2 WHERE id=1",
                            params![up, down],
                        )?;
                        transaction.execute(
                            "UPDATE qualification_ownership SET deleted=1,cleanup_upload=0,cleanup_download=0 WHERE key=?1",
                            [&known],
                        )?;
                        transaction.execute("DELETE FROM remote_storage WHERE key=?1", [known])?;
                        transaction.commit()?;
                        Ok(())
                    })
                    .map_err(database)?;
                deleted += 1;
            }
        }
        Ok(deleted)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::budget::{BudgetLimits, QualificationLimits};
    use crate::s3::testing::ScriptedResponse;
    use crate::{DurableSpoolConfig, Spool};

    fn response(method: &'static str, status: u16, body: &[u8]) -> ScriptedResponse {
        ScriptedResponse {
            method,
            status,
            content_length: body.len() as u64,
            body: body.to_vec(),
            delay: Duration::ZERO,
            headers: Vec::new(),
            lose_ack: false,
        }
    }

    fn setup(mut responses: Vec<ScriptedResponse>) -> (tempfile::TempDir, S3Store, String) {
        let directory = tempfile::tempdir().unwrap();
        let mut disk = DurableSpoolConfig::new(directory.path().join("state"));
        disk.spool.managed_ceiling = 64 * 1024 * 1024;
        disk.spool.max_object_size = 16 * 1024 * 1024;
        disk.free_space_floor = 0;
        disk.temporary_ceiling = 32 * 1024 * 1024;
        disk.metadata_temporary_reserve = 8 * 1024 * 1024;
        disk.metadata_ceiling = 16 * 1024 * 1024;
        disk.catalog_ceiling = 16 * 1024 * 1024;
        disk.eviction_high_watermark = 56 * 1024 * 1024;
        disk.eviction_low_watermark = 48 * 1024 * 1024;
        let spool = Spool::open_durable(disk).unwrap();
        let ledger = BudgetLedger::initialize(spool, BudgetLimits::default()).unwrap();
        let allowance = 64 * 1024 * 1024;
        ledger
            .initialize_qualification(QualificationLimits {
                upload: allowance,
                download: allowance,
                storage: allowance,
            })
            .unwrap();
        let run = "0123456789abcdef0123456789abcdef";
        ledger.bind_qualification(run).unwrap();
        responses.insert(
            0,
            response(
                "GET",
                200,
                b"<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>",
            ),
        );
        let config = S3Config {
            endpoint: config::DEFAULT_ENDPOINT.into(),
            region: config::DEFAULT_REGION.into(),
            bucket: config::DEFAULT_BUCKET.into(),
            package_prefix: "linux-packages/".into(),
            checkpoint_prefix: "linux-checkpoints/".into(),
            credentials_file: directory.path().join("unused-test-credentials"),
            shared_nonisolated: true,
        };
        let (store, _) = S3Store::scripted_production(config, ledger, responses).unwrap();
        let Mode::Production(production) = &store.mode else {
            unreachable!()
        };
        let key = production.object_key(ObjectIdentity {
            sha256: Sha256Digest::of(b"package"),
            size: 7,
        });
        production
            .transport
            .ledger
            .reserve_storage(&key, 7, BudgetClass::Package)
            .unwrap();
        production.mutation_marker(&key, true).unwrap();
        production
            .mutation_accepted(&key, Some("\"private-scripted-etag\""))
            .unwrap();
        (directory, store, key)
    }

    fn ownership(store: &S3Store, key: &str) -> (bool, u64) {
        let production = store.production().unwrap();
        let key = key.to_owned();
        let deleted = production
            .transport
            .ledger
            .spool()
            .durable_catalog()
            .unwrap()
            .read(move |connection| {
                Ok(connection.query_row(
                    "SELECT deleted FROM qualification_ownership WHERE key=?1",
                    [key],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        (
            deleted,
            production.transport.ledger.usage().unwrap().storage,
        )
    }

    #[test]
    fn upload_size_sql_boundary_preserves_create_accounting() {
        let (_directory, store, key) = setup(Vec::new());
        let production = store.production().unwrap();
        production.before_create(&key).unwrap();
        let state = || {
            let key = key.clone();
            production
                .transport
                .ledger
                .spool()
                .durable_catalog()
                .unwrap()
                .read(move |connection| {
                    Ok(connection.query_row(
                        "SELECT creates,cleanup_upload,cleanup_download,(SELECT COUNT(*) FROM multipart_uploads WHERE key=?1) FROM qualification_ownership WHERE key=?1",
                        [key],
                        |row| {
                            Ok((
                                crate::catalog::read_unsigned(row, 0)?,
                                crate::catalog::read_unsigned(row, 1)?,
                                crate::catalog::read_unsigned(row, 2)?,
                                crate::catalog::read_unsigned(row, 3)?,
                            ))
                        },
                    )?)
                })
                .unwrap()
        };
        let before = state();
        assert_eq!((before.0, before.3), (1, 0));
        let maximum = u64::try_from(i64::MAX).unwrap();
        for size in [maximum + 1, u64::MAX] {
            assert!(matches!(
                production.record_upload(&key, "upload", 1, size, false),
                Err(S3Error::Journal(_))
            ));
            assert_eq!(state(), before);
        }
        production
            .record_upload(&key, "upload", 1, maximum, false)
            .unwrap();
        assert_eq!(state(), (0, before.1, before.2, 1));
        let saved = production
            .transport
            .ledger
            .spool()
            .durable_catalog()
            .unwrap()
            .read(move |connection| {
                Ok(connection.query_row(
                    "SELECT size FROM multipart_uploads WHERE key=?1",
                    [key],
                    |row| crate::catalog::read_unsigned(row, 0),
                )?)
            })
            .unwrap();
        assert_eq!(saved, maximum);
    }

    #[tokio::test]
    async fn ambiguous_head_absence_preserves_ownership_and_storage() {
        for probe in [
            response("GET", 206, b"p"),
            response("GET", 404, b"<html>proxy not found</html>"),
        ] {
            let (_directory, store, key) = setup(vec![response("HEAD", 404, b""), probe]);
            let store = Arc::new(store);
            let manager = crate::capture::CaptureManager::new(
                store.production().unwrap().transport.ledger.spool().clone(),
                store.clone(),
            )
            .unwrap();
            manager.initialize(now().unwrap()).unwrap();
            let path =
                ferrum_apt::path::RepositoryPath::parse_decoded("pool/main/p/package.deb").unwrap();
            assert_eq!(manager.lookup("fixture", &path).unwrap(), None);
            let result = store
                .cleanup_qualification(
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new(),
                )
                .await;
            assert!(result.is_err());
            assert_eq!(ownership(&store, &key), (false, 7));
            assert!(!store.production().unwrap().quarantined(&key).unwrap());
            assert!(matches!(
                manager.lookup("fixture", &path),
                Err(crate::capture::CaptureError::Admission)
            ));
        }
    }

    #[tokio::test]
    async fn genuine_object_absence_releases_owned_storage() {
        let (_directory, store, key) = setup(vec![
            response("HEAD", 404, b""),
            response("GET", 404, b"<Error><Code>NoSuchKey</Code></Error>"),
        ]);
        let deleted = store
            .cleanup_qualification(
                Instant::now() + Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(ownership(&store, &key), (true, 0));
    }

    #[tokio::test]
    async fn versioned_absence_does_not_release_retained_storage() {
        let mut head = response("HEAD", 404, b"");
        head.headers
            .push(("x-amz-delete-marker".into(), "true".into()));
        head.headers
            .push(("x-amz-version-id".into(), "retained-version".into()));
        let (_directory, store, key) = setup(vec![head]);
        let result = store
            .cleanup_qualification(
                Instant::now() + Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await;
        assert!(matches!(result, Err(S3Error::Unsupported)));
        assert_eq!(ownership(&store, &key), (false, 7));
    }
}
