use super::*;
pub(crate) struct OwnedPage {
    pub keys: Vec<String>,
    pub continuation: Option<String>,
}
impl S3Store {
    /// A HEAD404 is never absence authority. This bounded Range GET passes
    /// through the concrete connector's genuine XML NoSuchKey classifier.
    pub(crate) async fn confirm_absent(
        &self,
        identity: OperationIdentity,
        key: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<bool, S3Error> {
        let store = self.production()?;
        match identity {
            OperationIdentity::PrivateQualificationCleanup
                if store
                    .config
                    .package_prefix
                    .starts_with("linux-packages/_ferrum-b07/")
                    && (key.starts_with(store.config.package_prefix.as_ref())
                        || key.starts_with(store.config.checkpoint_prefix.as_ref())) =>
            {
                let suffix = namespace_suffix(identity, key)?;
                validate_suffix(identity, suffix)?;
            }
            OperationIdentity::OfflineMaintenance => {
                let suffix = key
                    .strip_prefix(store.config.package_prefix.as_ref())
                    .ok_or(S3Error::Boundary)?;
                validate_suffix(identity, suffix)?;
            }
            _ => return Err(S3Error::Boundary),
        }
        let _slots = store.slot(true, deadline, cancel).await?;
        let client = store.client(identity, key, CONTROL, BudgetClass::Control)?;
        let result = bounded(deadline, cancel, async {
            client
                .get_object()
                .bucket(&store.config.bucket)
                .key(key)
                .range("bytes=0-0")
                .send()
                .await
                .map_err(|error| classify_sdk(error, false))
        })
        .await;
        store.outcome(&result)?;
        match result {
            Err(S3Error::NotFound) => Ok(true),
            Err(error) => Err(error),
            Ok(output) => {
                let mut body = output.body;
                let mut size = 0usize;
                while let Some(bytes) = bounded(deadline, cancel, async {
                    body.next().await.transpose().map_err(classify_body_error)
                })
                .await?
                {
                    size = size.checked_add(bytes.len()).ok_or(S3Error::Budget)?;
                    if size > CONTROL as usize {
                        return Err(S3Error::Budget);
                    }
                }
                Ok(false)
            }
        }
    }
    pub(crate) async fn observe_owned(
        &self,
        key: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<S3ObjectMeta, S3Error> {
        let store = self.production()?;
        let suffix = key
            .strip_prefix(store.config.package_prefix.as_ref())
            .ok_or(S3Error::Boundary)?;
        validate_suffix(OperationIdentity::OfflineMaintenance, suffix)?;
        store.check(key)?;
        let _slots = store.slot(true, deadline, cancel).await?;
        let client = store.client(
            OperationIdentity::OfflineMaintenance,
            key,
            CONTROL,
            BudgetClass::Control,
        )?;
        let result = bounded(deadline, cancel, async {
            client
                .head_object()
                .bucket(&store.config.bucket)
                .key(key)
                .send()
                .await
                .map_err(|error| classify_sdk(error, true))
        })
        .await;
        store.outcome(&result)?;
        let output = result?;
        if output.version_id().is_some_and(|version| version != "null") {
            return Err(S3Error::Unsupported);
        }
        Ok(S3ObjectMeta {
            content_length: output
                .content_length()
                .and_then(|size| u64::try_from(size).ok())
                .ok_or(S3Error::Corrupt)?,
            etag: output.e_tag().map(str::to_owned),
            version_id: output.version_id().map(str::to_owned),
        })
    }
    pub(crate) fn account_observed(
        &self,
        identity: OperationIdentity,
        suffix: &str,
        size: u64,
        class: BudgetClass,
    ) -> Result<(), S3Error> {
        let store = self.production()?;
        let key = store.key(identity, suffix)?;
        store
            .transport
            .ledger
            .record_existing_storage(&key, size, class)
            .map_err(database)
    }
    pub(crate) async fn maintenance_list(
        &self,
        continuation: Option<String>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<OwnedPage, S3Error> {
        let store = self.production()?;
        let prefix = store.config.package_prefix.as_ref();
        let _slots = store.slot(true, deadline, cancel).await?;
        let wire = store
            .transport
            .listing(prefix.to_owned(), 1024 * 1024)
            .with_circuit(Some(store.circuit.clone()));
        let client = aws_sdk_s3::Client::from_conf(
            store.client.config().to_builder().http_client(wire).build(),
        );
        let result = bounded(deadline, cancel, async {
            client
                .list_objects_v2()
                .bucket(&store.config.bucket)
                .prefix(prefix)
                .max_keys(64)
                .set_continuation_token(continuation)
                .send()
                .await
                .map_err(|e| classify_sdk(e, false))
        })
        .await;
        store.outcome(&result)?;
        let output = result?;
        if output.contents().len() > 64 {
            return Err(S3Error::Boundary);
        }
        let mut keys = Vec::with_capacity(output.contents().len());
        for item in output.contents() {
            let key = item.key().ok_or(S3Error::Boundary)?;
            if !key.starts_with(prefix) || key.len() > 8192 {
                return Err(S3Error::Boundary);
            }
            keys.push(key.to_owned());
        }
        let continuation = if output.is_truncated() == Some(true) {
            Some(
                output
                    .next_continuation_token()
                    .filter(|value| !value.is_empty() && value.len() <= 8192)
                    .ok_or(S3Error::Boundary)?
                    .to_owned(),
            )
        } else {
            None
        };
        Ok(OwnedPage { keys, continuation })
    }
    pub(crate) async fn maintenance_delete(
        &self,
        key: &str,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), S3Error> {
        let store = self.production()?;
        let suffix = key
            .strip_prefix(store.config.package_prefix.as_ref())
            .ok_or(S3Error::Boundary)?;
        validate_suffix(OperationIdentity::OfflineMaintenance, suffix)?;
        let _slots = store.slot(true, deadline, cancel).await?;
        let client = store.client(
            OperationIdentity::OfflineMaintenance,
            key,
            CONTROL,
            BudgetClass::Control,
        )?;
        let head = bounded(deadline, cancel, async {
            client
                .head_object()
                .bucket(&store.config.bucket)
                .key(key)
                .send()
                .await
                .map_err(|e| classify_sdk(e, true))
        })
        .await;
        store.outcome(&head)?;
        let head = match head {
            Err(S3Error::NotFound) => {
                drop(_slots);
                return if self
                    .confirm_absent(OperationIdentity::OfflineMaintenance, key, deadline, cancel)
                    .await?
                {
                    Ok(())
                } else {
                    Err(S3Error::Conflict)
                };
            }
            other => other?,
        };
        if head.version_id().is_some_and(|v| v != "null") {
            return Err(S3Error::Unsupported);
        }
        let etag = head
            .e_tag()
            .filter(|etag| !etag.is_empty())
            .ok_or(S3Error::Corrupt)?;
        let result = bounded(deadline, cancel, async {
            client
                .delete_object()
                .bucket(&store.config.bucket)
                .key(key)
                .if_match(etag)
                .send()
                .await
                .map_err(|e| classify_sdk(e, false))
        })
        .await;
        store.outcome(&result)?;
        let output = result?;
        if output.delete_marker() == Some(true)
            || output.version_id().is_some_and(|version| version != "null")
        {
            return Err(S3Error::Unsupported);
        }
        Ok(())
    }
    /// Paginated owned-prefix orphan cleanup. A listed upload is eligible only
    /// when its exact key has a persisted storage intent; unknown keys survive.
    pub(crate) async fn maintenance_multipart(
        &self,
        now: i64,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<u64, S3Error> {
        self.reap_uploads(now, false, deadline, cancel).await
    }
}
