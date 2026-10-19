use super::*;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use rusqlite::{OptionalExtension, params};
const PART: u64 = 16 * 1024 * 1024;
struct UploadPart<'a> {
    key: &'a str,
    upload_id: &'a str,
    number: i32,
}
impl Production {
    async fn upload_part(
        &self,
        object: &UploadFile<'_>,
        part: UploadPart<'_>,
        class: BudgetClass,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<CompletedPart, S3Error> {
        let UploadPart {
            key,
            upload_id: id,
            number,
        } = part;
        let offset = (number as u64 - 1) * PART;
        let size = (object.identity().size - offset).min(PART);
        let owned = key.to_owned();
        let upload = id.to_owned();
        let reserved = offset + size;
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                let changed = connection.execute(
                    "UPDATE multipart_uploads SET uploaded_bytes=MAX(uploaded_bytes,?3) WHERE key=?1 AND upload_id=?2",
                    params![owned, upload, crate::catalog::signed(reserved)?],
                )?;
                if changed != 1 {
                    return Err(crate::catalog::CatalogError::InvalidState);
                }
                Ok(())
            })
            .map_err(database)?;
        let body = ByteStream::read_from()
            .path(object.path())
            .offset(offset)
            .length(Length::Exact(size))
            .buffer_size(CHUNK)
            .build()
            .await
            .map_err(|_| S3Error::Unavailable)?;
        let _slots = self
            .slot(class == BudgetClass::Control, deadline, cancel)
            .await?;
        let client = self.client(OperationIdentity::Object, key, CONTROL, class)?;
        let result = bounded(deadline, cancel, async {
            client
                .upload_part()
                .bucket(&self.config.bucket)
                .key(key)
                .upload_id(id)
                .part_number(number)
                .content_length(size as i64)
                .body(body)
                .send()
                .await
                .map_err(|e| classify_sdk(e, false))
        })
        .await;
        self.outcome(&result)?;
        let output = result?;
        Ok(CompletedPart::builder()
            .part_number(number)
            .e_tag(output.e_tag().ok_or(S3Error::Corrupt)?)
            .build())
    }
    async fn abort(
        &self,
        key: &str,
        id: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), S3Error> {
        self.abort_owned(OperationIdentity::Object, key, id, deadline, cancel)
            .await
    }
    fn forget_upload(&self, key: &str, id: &str) -> Result<(), S3Error> {
        let key = key.to_owned();
        let id = id.to_owned();
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                connection.execute(
                    "DELETE FROM multipart_uploads WHERE key=?1 AND upload_id=?2",
                    params![key, id],
                )?;
                Ok(())
            })
            .map_err(database)
    }
    pub(super) async fn multipart(
        &self,
        object: &UploadFile<'_>,
        key: &str,
        class: BudgetClass,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<String, S3Error> {
        let owned = key.to_owned();
        let recorded: Option<(String, bool)> = self
            .transport
            .ledger
            .spool()
            .durable_catalog()
            .map_err(database)?
            .read(move |connection| {
                Ok(connection
                    .query_row(
                        "SELECT upload_id,completing FROM multipart_uploads WHERE key=?1",
                        [owned],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?)
            })
            .map_err(database)?;
        if let Some((id, completing)) = recorded {
            // An ambiguous completion is not absence and never implies durability.
            if completing {
                match self
                    .get_metered(
                        OperationIdentity::Object,
                        key,
                        object.identity().size,
                        GetMode::reconciliation(class),
                        deadline,
                        cancel,
                    )
                    .await
                {
                    Ok(response) => {
                        let etag = response.etag.clone().ok_or(S3Error::Corrupt)?;
                        if let Err(error) = verify_response(response, object.identity()).await {
                            if error == S3Error::Corrupt {
                                self.quarantine(key)?;
                            }
                            return Err(error);
                        }
                        self.mutation_accepted(key, Some(&etag))?;
                        self.abort(key, &id, deadline, cancel).await?;
                        return Ok(etag);
                    }
                    Err(S3Error::NotFound) => {}
                    Err(error) => return Err(error),
                }
            }
            self.abort(key, &id, deadline, cancel).await?;
        }
        // A new local intent does not prove remote absence. A preexisting object
        // must be fully verified before creating separately billed multipart
        // parts, including after catalog restoration or an unknown prior ACK.
        match self
            .get_metered(
                OperationIdentity::Object,
                key,
                object.identity().size,
                GetMode::reconciliation(class),
                deadline,
                cancel,
            )
            .await
        {
            Ok(response) => {
                let etag = response.etag.clone().ok_or(S3Error::Corrupt)?;
                if let Err(error) = verify_response(response, object.identity()).await {
                    if error == S3Error::Corrupt {
                        self.quarantine(key)?;
                    }
                    return Err(error);
                }
                self.transport
                    .ledger
                    .record_existing_storage(key, object.identity().size, class)
                    .map_err(database)?;
                return Ok(etag);
            }
            Err(S3Error::NotFound) => {
                let owned = key.to_owned();
                self.transport
                    .ledger
                    .spool()
                    .catalog_write(move |connection| {
                        connection.execute(
                            "UPDATE remote_storage SET committed=0 WHERE key=?1",
                            [owned],
                        )?;
                        Ok(())
                    })
                    .map_err(database)?;
            }
            Err(error) => return Err(error),
        }
        let marker = self.mutation_marker(key, true)?;
        let created = {
            let _slots = self
                .slot(class == BudgetClass::Control, deadline, cancel)
                .await?;
            let client = self.client(OperationIdentity::Object, key, CONTROL, class)?;
            self.before_create(key)?;
            let result = bounded(deadline, cancel, async {
                client
                    .create_multipart_upload()
                    .bucket(&self.config.bucket)
                    .key(key)
                    .metadata("ferrum-owner", marker)
                    .send()
                    .await
                    .map_err(|e| classify_sdk(e, false))
            })
            .await;
            self.outcome(&result)?;
            match result {
                Ok(created) => created,
                Err(error) => {
                    if matches!(
                        error,
                        S3Error::AdmissionRefused
                            | S3Error::Forbidden
                            | S3Error::Conflict
                            | S3Error::Boundary
                    ) {
                        self.create_not_sent(key)?;
                    }
                    return Err(error);
                }
            }
        };
        let id = created
            .upload_id()
            .filter(|id| !id.is_empty() && id.len() <= 4096)
            .ok_or(S3Error::Corrupt)?
            .to_owned();
        // No part may be sent until the ID and exact key association are durable.
        self.record_upload(key, &id, now()?, object.identity().size, false)?;
        let count = object.identity().size.div_ceil(PART) as i32;
        let mut parts = Vec::with_capacity(count as usize);
        let mut number = 1;
        while number <= count {
            let result = if number < count {
                let (first, second) = tokio::join!(
                    self.upload_part(
                        object,
                        UploadPart {
                            key,
                            upload_id: &id,
                            number
                        },
                        class,
                        deadline,
                        cancel
                    ),
                    self.upload_part(
                        object,
                        UploadPart {
                            key,
                            upload_id: &id,
                            number: number + 1
                        },
                        class,
                        deadline,
                        cancel
                    )
                );
                match (first, second) {
                    (Ok(first), Ok(second)) => {
                        parts.push(first);
                        parts.push(second);
                        Ok(())
                    }
                    (Err(error), _) | (_, Err(error)) => Err(error),
                }
            } else {
                self.upload_part(
                    object,
                    UploadPart {
                        key,
                        upload_id: &id,
                        number,
                    },
                    class,
                    deadline,
                    cancel,
                )
                .await
                .map(|part| parts.push(part))
            };
            if let Err(error) = result {
                if matches!(
                    error,
                    S3Error::Forbidden
                        | S3Error::Corrupt
                        | S3Error::Unsupported
                        | S3Error::Boundary
                ) && let Err(abort) = self.abort(key, &id, deadline, cancel).await
                {
                    tracing::error!(%abort,"multipart abort deferred to recorded-ID reconciliation");
                }
                return Err(error);
            }
            number += 2;
        }
        let owned = key.to_owned();
        self.transport
            .ledger
            .spool()
            .catalog_write(move |connection| {
                connection.execute(
                    "UPDATE multipart_uploads SET completing=1 WHERE key=?1",
                    [owned],
                )?;
                Ok(())
            })
            .map_err(database)?;
        let completed = {
            let _slots = self
                .slot(class == BudgetClass::Control, deadline, cancel)
                .await?;
            let client = self.client(OperationIdentity::Object, key, CONTROL, class)?;
            let result = bounded(deadline, cancel, async {
                client
                    .complete_multipart_upload()
                    .bucket(&self.config.bucket)
                    .key(key)
                    .upload_id(&id)
                    .if_none_match("*")
                    .multipart_upload(
                        CompletedMultipartUpload::builder()
                            .set_parts(Some(parts))
                            .build(),
                    )
                    .send()
                    .await
                    .map_err(|e| classify_sdk(e, false))
            })
            .await;
            self.outcome(&result)?;
            result
        };
        if let Err(error) = &completed
            && !matches!(
                error,
                S3Error::Timeout | S3Error::Unavailable | S3Error::Conflict
            )
        {
            if matches!(
                error,
                S3Error::Forbidden | S3Error::Unsupported | S3Error::Boundary | S3Error::Corrupt
            ) && let Err(abort) = self.abort(key, &id, deadline, cancel).await
            {
                tracing::error!(%abort,"permanent completion rejection retains recorded abort intent");
            }
            return Err(error.clone());
        }
        // Successful complete and lost ACK both require a full authenticated GET.
        let response = self
            .get_metered(
                OperationIdentity::Object,
                key,
                object.identity().size,
                GetMode::reconciliation(class),
                deadline,
                cancel,
            )
            .await?;
        let etag = response.etag.clone().ok_or(S3Error::Corrupt)?;
        if let Err(error) = verify_response(response, object.identity()).await {
            if error == S3Error::Corrupt {
                self.quarantine(key)?;
            }
            return Err(error);
        }
        self.mutation_accepted(key, Some(&etag))?;
        if completed.is_err() {
            self.abort(key, &id, deadline, cancel).await?;
        } else {
            self.forget_upload(key, &id)?;
        }
        Ok(etag)
    }
}
