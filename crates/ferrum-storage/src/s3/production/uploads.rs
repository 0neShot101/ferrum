use super::*;
use aws_sdk_s3::error::ProvideErrorMetadata;
use rusqlite::{OptionalExtension, params};
impl Production {
    pub(super) fn before_create(&self, key: &str) -> Result<(), S3Error> {
        if !self.config.package_prefix.contains("/_ferrum-b07/") {
            return Ok(());
        }
        let key = key.to_owned();
        let admitted = self
            .transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                Ok(connection.execute(
                    "UPDATE qualification_ownership SET creates=creates+1 WHERE key=?1 AND deleted=0 AND creates<2",
                    [key],
                )? == 1)
            })
            .map_err(database)?;
        if admitted {
            Ok(())
        } else {
            Err(S3Error::AdmissionRefused)
        }
    }
    pub(super) fn create_not_sent(&self, key: &str) -> Result<(), S3Error> {
        let key = key.to_owned();
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                connection.execute(
                    "UPDATE qualification_ownership SET creates=MAX(0,creates-1) WHERE key=?1",
                    [key],
                )?;
                Ok(())
            })
            .map_err(database)
    }
    pub(super) fn record_upload(
        &self,
        key: &str,
        id: &str,
        started: i64,
        size: u64,
        discovered: bool,
    ) -> Result<(), S3Error> {
        let key = key.to_owned();
        let id = id.to_owned();
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                let transaction = connection.transaction()?;
                transaction.execute(
                    "INSERT INTO multipart_uploads(key,upload_id,started,size,completing,discovered) VALUES(?1,?2,?3,?4,0,?5)",
                    params![key, id, started, crate::catalog::signed(size)?, discovered],
                )?;
                if !discovered {
                    transaction.execute(
                        "UPDATE qualification_ownership SET creates=MAX(0,creates-1) WHERE key=?1",
                        [key],
                    )?;
                }
                transaction.commit()?;
                Ok(())
            })
            .map_err(database)
    }
    pub(super) async fn abort_owned(
        &self,
        identity: OperationIdentity,
        key: &str,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), S3Error> {
        let suffix = key
            .strip_prefix(self.config.package_prefix.as_ref())
            .ok_or(S3Error::Boundary)?;
        validate_suffix(OperationIdentity::Object, suffix)?;
        if id.is_empty() || id.len() > 4096 {
            return Err(S3Error::Boundary);
        }
        let owned = key.to_owned();
        let upload = id.to_owned();
        let recorded = self
            .transport
            .ledger
            .spool()
            .durable_catalog()
            .map_err(database)?
            .read(move |connection| {
                Ok(connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM multipart_uploads WHERE key=?1 AND upload_id=?2)",
                    params![owned, upload],
                    |row| row.get::<_, bool>(0),
                )?)
            })
            .map_err(database)?;
        if !recorded {
            return Err(S3Error::Boundary);
        }
        let _slots = self.slot(true, deadline, cancel).await?;
        let client = self.client(identity, key, CONTROL, BudgetClass::Control)?;
        let result = bounded(deadline, cancel, async {
            client
                .abort_multipart_upload()
                .bucket(&self.config.bucket)
                .key(key)
                .upload_id(id)
                .send()
                .await
                .map_err(|error| {
                    if error
                        .raw_response()
                        .is_some_and(|response| response.status().as_u16() == 404)
                        && error
                            .as_service_error()
                            .is_some_and(|error| error.code() == Some("NoSuchUpload"))
                    {
                        S3Error::NotFound
                    } else {
                        classify_sdk(error, false)
                    }
                })
        })
        .await;
        self.outcome(&result)?;
        if let Err(error) = result
            && error != S3Error::NotFound
        {
            return Err(error);
        }
        let key = key.to_owned();
        let id = id.to_owned();
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                let transaction = connection.transaction()?;
                let discovered: bool = transaction.query_row(
                    "SELECT discovered FROM multipart_uploads WHERE key=?1 AND upload_id=?2",
                    params![key, id],
                    |row| row.get(0),
                )?;
                if discovered {
                    transaction.execute(
                        "UPDATE qualification_ownership SET creates=MAX(0,creates-1) WHERE key=?1",
                        [&key],
                    )?;
                }
                transaction.execute(
                    "DELETE FROM multipart_uploads WHERE key=?1 AND upload_id=?2",
                    params![key, id],
                )?;
                transaction.commit()?;
                Ok(())
            })
            .map_err(database)
    }
}
impl S3Store {
    pub(crate) async fn reap_uploads(
        &self,
        now: i64,
        private: bool,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<u64, S3Error> {
        let store = self.production()?;
        if private && !store.config.package_prefix.contains("/_ferrum-b07/") {
            return Err(S3Error::Boundary);
        }
        let identity = if private {
            OperationIdentity::PrivateQualificationCleanup
        } else {
            OperationIdentity::OfflineMaintenance
        };
        let mut reaped = 0;
        let mut after = String::new();
        loop {
            let cursor = after.clone();
            let rows = store
                .transport
                .ledger
                .spool()
                .durable_catalog()
                .map_err(database)?
                .read(move |connection| {
                    let mut statement = connection.prepare("SELECT key,upload_id,started FROM multipart_uploads WHERE key>?1 ORDER BY key LIMIT 64")?;
                    let rows = statement.query_map([cursor], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })?;
                    Ok(rows.collect::<Result<Vec<_>, _>>()?)
                })
                .map_err(database)?;
            if rows.is_empty() {
                break;
            }
            for (key, id, started) in rows {
                after = key.clone();
                let suffix = key
                    .strip_prefix(store.config.package_prefix.as_ref())
                    .ok_or(S3Error::Boundary)?;
                validate_suffix(OperationIdentity::Object, suffix)?;
                if !private && now.checked_sub(started).is_none_or(|age| age < 86400) {
                    continue;
                }
                store
                    .abort_owned(identity, &key, &id, deadline, cancel)
                    .await?;
                reaped += 1;
            }
        }
        let mut key_marker = None;
        let mut id_marker = None;
        loop {
            let output = {
                let _slots = store.slot(true, deadline, cancel).await?;
                let wire = if private {
                    store
                        .transport
                        .private_listing(store.config.package_prefix.to_string(), 1024 * 1024)
                } else {
                    store
                        .transport
                        .listing(store.config.package_prefix.to_string(), 1024 * 1024)
                        .with_circuit(Some(store.circuit.clone()))
                };
                let client = aws_sdk_s3::Client::from_conf(
                    store.client.config().to_builder().http_client(wire).build(),
                );
                let result = bounded(deadline, cancel, async {
                    client
                        .list_multipart_uploads()
                        .bucket(&store.config.bucket)
                        .prefix(store.config.package_prefix.as_ref())
                        .max_uploads(64)
                        .set_key_marker(key_marker.clone())
                        .set_upload_id_marker(id_marker.clone())
                        .send()
                        .await
                        .map_err(|error| classify_sdk(error, false))
                })
                .await;
                store.outcome(&result)?;
                result?
            };
            if output.uploads().len() > 64 {
                return Err(S3Error::Boundary);
            }
            for upload in output.uploads() {
                let key = upload.key().ok_or(S3Error::Boundary)?;
                let id = upload
                    .upload_id()
                    .filter(|id| !id.is_empty() && id.len() <= 4096)
                    .ok_or(S3Error::Boundary)?;
                let suffix = key
                    .strip_prefix(store.config.package_prefix.as_ref())
                    .ok_or(S3Error::Boundary)?;
                if validate_suffix(OperationIdentity::Object, suffix).is_err() {
                    continue;
                }
                let started = upload.initiated().ok_or(S3Error::Boundary)?.secs();
                if !private && now.checked_sub(started).is_none_or(|age| age < 86400) {
                    continue;
                }
                let owned = key.to_owned();
                let association = store
                    .transport
                    .ledger
                    .spool()
                    .durable_catalog()
                    .map_err(database)?
                    .read(move |connection| {
                        let storage: Option<(u64, i64)> = connection
                            .query_row(
                                "SELECT size,intent_at FROM remote_storage WHERE key=?1 AND mutation_intent=1",
                                [&owned],
                                |row| Ok((crate::catalog::read_unsigned(row, 0)?, row.get(1)?)),
                            )
                            .optional()?;
                        let existing: bool = connection.query_row(
                            "SELECT EXISTS(SELECT 1 FROM multipart_uploads WHERE key=?1)",
                            [&owned],
                            |row| row.get(0),
                        )?;
                        let unknown: Option<u64> = connection
                            .query_row(
                                "SELECT creates FROM qualification_ownership WHERE key=?1 AND deleted=0",
                                [owned],
                                |row| crate::catalog::read_unsigned(row, 0),
                            )
                            .optional()?;
                        Ok(if existing {
                            None
                        } else {
                            storage.filter(|(_, intent)| started >= *intent && (private && unknown.is_some_and(|count| count > 0) || !private && now.checked_sub(*intent).is_some_and(|age| age >= 86400)))
                        })
                    })
                    .map_err(database)?;
                let Some((size, _)) = association else {
                    continue;
                };
                store.record_upload(key, id, started, size, true)?;
                store
                    .abort_owned(identity, key, id, deadline, cancel)
                    .await?;
                reaped += 1;
            }
            if output.is_truncated() != Some(true) {
                break;
            }
            let next_key = output
                .next_key_marker()
                .filter(|value| !value.is_empty() && value.len() <= 8192)
                .ok_or(S3Error::Boundary)?
                .to_owned();
            let next_id = output
                .next_upload_id_marker()
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .ok_or(S3Error::Boundary)?
                .to_owned();
            if key_marker.as_ref() == Some(&next_key) && id_marker.as_ref() == Some(&next_id) {
                return Err(S3Error::Boundary);
            }
            key_marker = Some(next_key);
            id_marker = Some(next_id);
        }
        Ok(reaped)
    }
}
