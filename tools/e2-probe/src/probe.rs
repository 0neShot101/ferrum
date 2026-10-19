mod inspection;

use crate::{
    config::{self, BUCKET, BudgetProfile, CHECKPOINT_MAX, CONTROL, LARGE, MIB, PART},
    journal::{self, SharedJournal},
    wire::Wire,
};
use anyhow::{Result, bail, ensure};
use aws_sdk_s3::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
};
use aws_smithy_types::byte_stream::Length;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt,
    future::Future,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;

#[derive(Debug)]
struct Failure {
    class: &'static str,
    status: Option<u16>,
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.class)
    }
}

impl std::error::Error for Failure {}

pub(crate) struct Probe {
    client: Client,
    wire: Wire,
    journal: SharedJournal,
    prefix: String,
    payload: PathBuf,
    checkpoint_prefix: Option<String>,
    qualification: bool,
}

fn classification(status: Option<u16>, code: Option<&str>, timeout: bool) -> &'static str {
    match (status, code) {
        (Some(404), Some("NoSuchLifecycleConfiguration")) => "NoLifecycleConfiguration",
        (Some(404), Some("NoSuchKey" | "NotFound")) => "NotFound",
        (Some(404), Some("NoSuchUpload")) => "MissingUpload",
        (Some(403), _) => "Forbidden",
        (Some(409 | 412), _) => "Conflict",
        (Some(429), _) => "Throttled",
        (_, Some("SlowDown" | "Throttling")) => "Throttled",
        (Some(501), _) | (_, Some("NotImplemented" | "UnsupportedOperation")) => "Unsupported",
        (Some(500..=599), _) => "Unavailable",
        _ if timeout => "Timeout",
        _ => "UnknownFailure",
    }
}

fn safe_code(code: Option<&str>) -> Option<&str> {
    code.filter(|code| {
        !code.is_empty()
            && code.len() <= 128
            && code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    })
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRecord {
    schema_version: u32,
    run: String,
    sequence: u64,
    writer: String,
}

impl Probe {
    pub(crate) fn new(
        client: Client,
        wire: Wire,
        journal: SharedJournal,
        directory: &Path,
    ) -> Result<Self> {
        let prefix = journal::lock(&journal)?.manifest.prefix.clone();
        let checkpoint_prefix = journal::lock(&journal)?.manifest.checkpoint_prefix.clone();
        let qualification =
            journal::lock(&journal)?.manifest.budget_profile == BudgetProfile::Qualification;
        config::validate_prefix(&prefix)?;
        Ok(Self {
            client,
            wire,
            journal,
            prefix,
            checkpoint_prefix,
            qualification,
            payload: directory.join("payload.bin"),
        })
    }

    fn key(&self, name: &str) -> Result<String> {
        let key = format!("{}{name}", self.prefix);
        config::validate_key(&self.prefix, &key)?;
        Ok(key)
    }

    fn marker(&self) -> &str {
        &self.prefix[config::ROOT.len()..self.prefix.len() - 1]
    }

    async fn send<T, E, F>(
        &self,
        operation: &'static str,
        upload: u64,
        download: u64,
        cleanup: bool,
        future: F,
    ) -> Result<T>
    where
        E: ProvideErrorMetadata,
        F: Future<Output = std::result::Result<T, SdkError<E>>>,
    {
        self.wire.permit(operation, upload, download, cleanup)?;
        let result = self.send_reserved(operation, future).await;
        self.wire.clear_permits()?;
        result
    }

    // Only the two same-target, same-size checkpoint CAS attempts call this concurrently.
    // Their identical one-use permits are both durably reserved before either future is polled.
    async fn send_reserved<T, E, F>(&self, operation: &'static str, future: F) -> Result<T>
    where
        E: ProvideErrorMetadata,
        F: Future<Output = std::result::Result<T, SdkError<E>>>,
    {
        let started = Instant::now();
        let concurrent = operation == "checkpoint_concurrent_update";
        let before = (!concurrent).then(|| self.wire.totals());
        let result = future.await;
        let injected_completion = operation == "multipart_complete_lost_response"
            && journal::lock(&self.journal)?
                .manifest
                .faults
                .get(operation)
                .is_some_and(|state| {
                    state == "provider_success_body_settled_acknowledgment_suppressed"
                });
        let source = if operation.starts_with("injected_") || injected_completion {
            "INJECTED"
        } else {
            "provider_sdk"
        };
        let after = self.wire.totals();
        let uploaded = before.map(|before| after.0.saturating_sub(before.0));
        let downloaded = before.map(|before| after.1.saturating_sub(before.1));
        let byte_scope = if concurrent {
            "unavailable_per_attempt_see_concurrent_pair_aggregate"
        } else {
            "sequential_operation_interval"
        };
        match result {
            Ok(output) => {
                journal::lock(&self.journal)?.event(json!({"kind":"operation", "source":source, "operation":operation, "outcome":"sdk_success", "elapsed_ms":started.elapsed().as_millis(), "upload_body_bytes":uploaded, "download_body_bytes":downloaded, "byte_measurement_scope":byte_scope}))?;
                Ok(output)
            }
            Err(error) => {
                let status = error
                    .raw_response()
                    .map(|response| response.status().as_u16());
                let code = error.as_service_error().and_then(|error| error.code());
                let timeout = matches!(&error, SdkError::TimeoutError(_))
                    || matches!(&error, SdkError::DispatchFailure(error) if error.is_timeout());
                let class = classification(status, code, timeout);
                journal::lock(&self.journal)?.event(json!({"kind":"operation", "source":source, "operation":operation, "outcome":"error", "class":class, "status":status, "code":safe_code(code), "elapsed_ms":started.elapsed().as_millis(), "upload_body_bytes":uploaded, "download_body_bytes":downloaded, "byte_measurement_scope":byte_scope}))?;
                Err(Failure { class, status }.into())
            }
        }
    }

    async fn body(&self, offset: u64, size: u64) -> Result<ByteStream> {
        ensure!(
            offset.checked_add(size).is_some_and(|end| end <= LARGE),
            "file body outside deterministic payload"
        );
        Ok(ByteStream::read_from()
            .path(&self.payload)
            .offset(offset)
            .length(Length::Exact(size))
            .buffer_size(256 * 1024)
            .build()
            .await?)
    }

    async fn prepare(&self) -> Result<String> {
        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&self.payload).await?;
        let mut buffer = vec![0u8; 256 * 1024];
        let mut hash = Sha256::new();
        let mut offset = 0;
        while offset < LARGE {
            fill(&mut buffer, offset);
            hash.update(&buffer);
            file.write_all(&buffer).await?;
            offset += buffer.len() as u64;
        }
        file.sync_all().await?;
        let digest = finish_digest(hash);
        journal::lock(&self.journal)?.event(json!({"kind":"payload", "size":LARGE, "sha256":digest, "pattern":"absolute byte offset modulo 251", "buffer_bytes":buffer.len()}))?;
        Ok(digest)
    }

    async fn head(
        &self,
        key: &str,
        cleanup: bool,
    ) -> Result<Option<aws_sdk_s3::operation::head_object::HeadObjectOutput>> {
        config::validate_owned_key(&self.prefix, self.checkpoint_prefix.as_deref(), key)?;
        match self
            .send(
                if self
                    .checkpoint_prefix
                    .as_deref()
                    .is_some_and(|prefix| key.starts_with(prefix))
                {
                    if cleanup {
                        "checkpoint_cleanup_head"
                    } else {
                        "checkpoint_head"
                    }
                } else if cleanup {
                    "cleanup_head"
                } else {
                    "head"
                },
                0,
                CONTROL,
                cleanup,
                self.client.head_object().bucket(BUCKET).key(key).send(),
            )
            .await
        {
            Ok(output) => {
                if output.version_id().is_some_and(|version| version != "null") {
                    journal::lock(&self.journal)?.event(json!({"kind":"versioning", "key":key, "version_id":output.version_id(), "outcome":"unsupported_retained_no_version_deletion_approval"}))?;
                    bail!("versioned bucket cleanup is not authorized");
                }
                journal::lock(&self.journal)?.event(json!({"kind":"head", "key":key, "returned_length":output.content_length(), "ownership_marker_matches":output.metadata().and_then(|metadata| metadata.get("ferrum-probe-run")).map(String::as_str) == Some(self.marker())}))?;
                Ok(Some(output))
            }
            Err(error) if is_class(&error, "NotFound") => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn absent(&self, key: &str) -> Result<()> {
        ensure!(
            self.head(key, false).await?.is_none(),
            "preexisting object found; refusing mutation"
        );
        Ok(())
    }

    async fn verify(
        &self,
        key: &str,
        size: u64,
        digest: &str,
        range: Option<(u64, u64)>,
        cleanup: bool,
    ) -> Result<()> {
        config::validate_owned_key(&self.prefix, self.checkpoint_prefix.as_deref(), key)?;
        let started = Instant::now();
        let mut request = self.client.get_object().bucket(BUCKET).key(key);
        if let Some((start, end)) = range {
            request = request.range(format!("bytes={start}-{end}"));
        }
        let operation = if range.is_some() {
            "get_range"
        } else {
            "get_full"
        };
        let mut output = self
            .send(operation, 0, size, cleanup, request.send())
            .await?;
        if output.version_id().is_some_and(|version| version != "null") {
            journal::lock(&self.journal)?.event(json!({"kind":"versioning", "key":key, "version_id":output.version_id(), "outcome":"unsupported_retained_no_version_deletion_approval"}))?;
            bail!("versioned bucket cleanup is not authorized");
        }
        let mut valid = output.content_length() == Some(i64::try_from(size)?);
        if let Some((start, end)) = range {
            let full = journal::lock(&self.journal)?
                .manifest
                .objects
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("range descriptor missing"))?
                .size;
            valid &= output.content_range() == Some(format!("bytes {start}-{end}/{full}").as_str());
        } else {
            valid &= output
                .metadata()
                .and_then(|metadata| metadata.get("ferrum-probe-run"))
                .map(String::as_str)
                == Some(self.marker());
        }
        journal::lock(&self.journal)?.event(json!({"kind":"readback_headers", "operation":operation, "key":key, "returned_length":output.content_length(), "expected_length":size, "outcome":if valid { "valid" } else { "error" }, "class":if valid { None } else { Some("Corrupt") }}))?;
        ensure!(valid, "GET length/range/ownership metadata mismatch");
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let transfer = async {
            loop {
                let next = tokio::time::timeout(Duration::from_secs(30), output.body.next())
                    .await
                    .map_err(|_| Failure {
                        class: "Timeout",
                        status: None,
                    })?;
                let Some(chunk) = next else { break };
                let chunk = chunk.map_err(|_| Failure {
                    class: "Unavailable",
                    status: None,
                })?;
                count = count.checked_add(chunk.len() as u64).ok_or(Failure {
                    class: "Corrupt",
                    status: None,
                })?;
                if count > size {
                    return Err(Failure {
                        class: "Corrupt",
                        status: None,
                    });
                }
                hash.update(&chunk);
            }
            Ok::<(), Failure>(())
        };
        let transfer = match tokio::time::timeout(Duration::from_secs(120), transfer).await {
            Ok(result) => result,
            Err(_) => Err(Failure {
                class: "Timeout",
                status: None,
            }),
        };
        let actual = finish_digest(hash);
        let matches = transfer.is_ok() && count == size && actual == digest;
        let class = transfer
            .as_ref()
            .err()
            .map(|failure| failure.class)
            .or(if matches { None } else { Some("Corrupt") });
        journal::lock(&self.journal)?.event(json!({"kind":"readback", "operation":operation, "key":key, "outcome":if matches { "pass" } else { "error" }, "class":class, "returned_length":count, "sha256":actual, "expected_sha256":digest, "elapsed_ms":started.elapsed().as_millis()}))?;
        transfer?;
        ensure!(matches, "GET digest or length mismatch");
        Ok(())
    }

    async fn put(&self, name: &str, size: u64) -> Result<()> {
        let key = self.key(name)?;
        self.absent(&key).await?;
        let digest = expected(0, size);
        journal::lock(&self.journal)?.intent(&key, size, &digest)?;
        let body = self.body(0, size).await?;
        let result = self
            .send(
                "put_create",
                size,
                CONTROL,
                false,
                self.client
                    .put_object()
                    .bucket(BUCKET)
                    .key(&key)
                    .metadata("ferrum-probe-run", self.marker())
                    .if_none_match("*")
                    .content_length(i64::try_from(size)?)
                    .body(body)
                    .send(),
            )
            .await;
        match result {
            Ok(_) => journal::lock(&self.journal)?.own(&key)?,
            Err(error) => {
                // A conditional-create response can be lost after the object was accepted. Only
                // our unpredictable marker plus full exact readback can establish ownership.
                self.reconcile_object(&key, false).await?;
                return Err(error);
            }
        }
        let head = self
            .head(&key, false)
            .await?
            .ok_or_else(|| anyhow::anyhow!("new object not visible to HEAD"))?;
        ensure!(
            head.content_length() == Some(i64::try_from(size)?),
            "HEAD size mismatch"
        );
        self.verify(&key, size, &digest, None, false).await
    }

    async fn conditional(&self) -> Result<()> {
        self.put("conditional", 4097).await?;
        let key = self.key("conditional")?;
        let body = self.body(0, 8193).await?;
        let rejected = self
            .send(
                "put_duplicate_create",
                8193,
                CONTROL,
                false,
                self.client
                    .put_object()
                    .bucket(BUCKET)
                    .key(&key)
                    .if_none_match("*")
                    .metadata("ferrum-probe-run", self.marker())
                    .body(body)
                    .send(),
            )
            .await;
        ensure!(
            matches!(&rejected, Err(error) if error.downcast_ref::<Failure>().is_some_and(|failure| failure.class == "Conflict" && failure.status == Some(412))),
            "conditional duplicate must reject with412"
        );
        self.verify(&key, 4097, &expected(0, 4097), None, false)
            .await?;
        let head = self
            .head(&key, false)
            .await?
            .ok_or_else(|| anyhow::anyhow!("conditional object missing"))?;
        let token = head
            .e_tag()
            .ok_or_else(|| anyhow::anyhow!("HEAD ETag missing"))?
            .to_owned();
        let body = self.body(0, 8193).await?;
        self.send(
            "put_if_match_overwrite",
            8193,
            CONTROL,
            false,
            self.client
                .put_object()
                .bucket(BUCKET)
                .key(&key)
                .if_match(&token)
                .metadata("ferrum-probe-run", self.marker())
                .body(body)
                .send(),
        )
        .await?;
        {
            let mut journal = journal::lock(&self.journal)?;
            let object = journal
                .manifest
                .objects
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("conditional object intent missing"))?;
            object.size = 8193;
            object.sha256 = expected(0, 8193);
            journal.save()?;
        }
        self.verify(&key, 8193, &expected(0, 8193), None, false)
            .await?;
        let body = self.body(0, 4097).await?;
        let stale = self
            .send(
                "put_stale_if_match",
                4097,
                CONTROL,
                false,
                self.client
                    .put_object()
                    .bucket(BUCKET)
                    .key(&key)
                    .if_match(token)
                    .metadata("ferrum-probe-run", self.marker())
                    .body(body)
                    .send(),
            )
            .await;
        ensure!(
            matches!(&stale, Err(error) if error.downcast_ref::<Failure>().is_some_and(|failure| failure.class == "Conflict" && failure.status == Some(412))),
            "stale ETag overwrite must reject with412"
        );
        self.verify(&key, 8193, &expected(0, 8193), None, false)
            .await?;
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"blob_conditions_and_overwrite", "outcome":"pass"}))
    }

    async fn missing(&self) -> Result<()> {
        let key = self.key("missing")?;
        let result = self
            .send(
                "get_missing",
                0,
                CONTROL,
                false,
                self.client.get_object().bucket(BUCKET).key(key).send(),
            )
            .await;
        ensure!(
            matches!(&result, Err(error) if is_class(error, "NotFound")),
            "missing GET did not produce genuine object-not-found"
        );
        journal::lock(&self.journal)?
            .event(json!({"kind":"capability", "operation":"missing_get_404", "outcome":"pass"}))
    }

    async fn create_upload(&self, key: &str, size: u64, digest: &str) -> Result<String> {
        self.absent(key).await?;
        {
            let mut journal = journal::lock(&self.journal)?;
            journal.intent(key, size, digest)?;
            journal.manifest.pending_creates.push(key.to_owned());
            journal.save()?;
        }
        let output = self
            .send(
                "multipart_create",
                0,
                CONTROL,
                false,
                self.client
                    .create_multipart_upload()
                    .bucket(BUCKET)
                    .key(key)
                    .metadata("ferrum-probe-run", self.marker())
                    .send(),
            )
            .await?;
        let id = output
            .upload_id()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "multipart create missing ID; retained intent requires reconciliation"
                )
            })?
            .to_owned();
        journal::lock(&self.journal)?.add_upload(key, &id)?;
        Ok(id)
    }

    async fn part(&self, key: &str, id: &str, number: i32, size: u64) -> Result<CompletedPart> {
        let offset = u64::try_from(number - 1)?
            .checked_mul(PART)
            .ok_or_else(|| anyhow::anyhow!("part offset overflow"))?;
        let body = self.body(offset, size).await?;
        let output = self
            .send(
                "upload_part",
                size,
                CONTROL,
                false,
                self.client
                    .upload_part()
                    .bucket(BUCKET)
                    .key(key)
                    .upload_id(id)
                    .part_number(number)
                    .content_length(i64::try_from(size)?)
                    .body(body)
                    .send(),
            )
            .await?;
        let token = output
            .e_tag()
            .ok_or_else(|| anyhow::anyhow!("part ETag missing"))?;
        journal::lock(&self.journal)?.event(json!({"kind":"part_uploaded", "key":key, "upload_id":id, "part_number":number, "size":size, "sha256":expected(offset, size)}))?;
        Ok(CompletedPart::builder()
            .part_number(number)
            .e_tag(token)
            .build())
    }

    async fn list_parts(&self, key: &str, id: &str, count: usize, cleanup: bool) -> Result<()> {
        let mut marker: Option<String> = None;
        let mut parts = BTreeSet::new();
        let mut pages = 0;
        loop {
            pages += 1;
            ensure!(pages <= 8, "list-parts page ceiling exceeded");
            let previous = marker.as_deref().unwrap_or("0").parse::<u32>()?;
            let output = self
                .send(
                    "list_parts",
                    0,
                    CONTROL,
                    cleanup,
                    self.client
                        .list_parts()
                        .bucket(BUCKET)
                        .key(key)
                        .upload_id(id)
                        .max_parts(2)
                        .set_part_number_marker(marker)
                        .send(),
                )
                .await?;
            for part in output.parts() {
                let number = part
                    .part_number()
                    .ok_or_else(|| anyhow::anyhow!("listed part number missing"))?;
                ensure!(parts.insert(number), "duplicate listed part");
                let expected_size = if key.ends_with("/abort") {
                    5 * MIB
                } else {
                    PART
                };
                ensure!(
                    part.size() == Some(i64::try_from(expected_size)?),
                    "listed part size mismatch"
                );
            }
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            let next = output
                .next_part_number_marker()
                .ok_or_else(|| anyhow::anyhow!("list-parts continuation missing"))?
                .to_owned();
            ensure!(
                next.parse::<u32>()? > previous,
                "list-parts continuation did not advance"
            );
            marker = Some(next);
        }
        ensure!(
            parts == (1..=i32::try_from(count)?).collect::<BTreeSet<_>>(),
            "multipart list differs from uploaded parts"
        );
        ensure!(
            count <= 2 || pages >= 2,
            "provider did not paginate ListParts at the requested maximum"
        );
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":if count > 2 { "list_parts_paginated" } else { "list_parts_single" }, "key":key, "pages":pages, "parts":parts, "outcome":"pass"}))
    }

    async fn multipart(&self, digest: &str) -> Result<()> {
        let key = self.key("multipart")?;
        let id = self.create_upload(&key, LARGE, digest).await?;
        let mut parts = Vec::with_capacity(5);
        // Sequential parts use less than the production maximum of two, with one file-backed
        // 256KiB body buffer. This probe measures compatibility, not production throughput.
        for number in 1..=5 {
            parts.push(self.part(&key, &id, number, PART).await?);
        }
        self.list_parts(&key, &id, 5, false).await?;
        if self.qualification {
            journal::lock(&self.journal)?.fault("multipart_complete_lost_response", "armed")?;
        }
        let result = self
            .send(
                if self.qualification {
                    "multipart_complete_lost_response"
                } else {
                    "multipart_complete"
                },
                CONTROL,
                CONTROL,
                false,
                self.client
                    .complete_multipart_upload()
                    .bucket(BUCKET)
                    .key(&key)
                    .upload_id(&id)
                    .if_none_match("*")
                    .multipart_upload(
                        CompletedMultipartUpload::builder()
                            .set_parts(Some(parts))
                            .build(),
                    )
                    .send(),
            )
            .await;
        match result {
            Ok(_) => {
                journal::lock(&self.journal)?.own(&key)?;
                self.verify(&key, LARGE, digest, None, false).await?;
                journal::lock(&self.journal)?.resolve_upload(&id)?;
                if self.qualification {
                    bail!(
                        "qualification required an injected lost Complete acknowledgment; provider success was not suppressed"
                    );
                }
                journal::lock(&self.journal)?.unrun(
                    "ambiguous_completion_injection",
                    "legacy subset does not inject response loss",
                )?;
            }
            Err(error) => {
                journal::lock(&self.journal)?
                    .event(json!({"kind":"completion_unknown", "key":key, "upload_id":id}))?;
                // Never repeat Complete or re-upload on an ambiguous outcome. Direct HEAD plus
                // marker/length/digest readback can confirm success; otherwise retain and abort ID.
                if self.reconcile_object(&key, false).await? {
                    let injected = journal::lock(&self.journal)?
                        .manifest
                        .faults
                        .get("multipart_complete_lost_response")
                        .is_some_and(|state| {
                            state == "provider_success_body_settled_acknowledgment_suppressed"
                        });
                    ensure!(
                        !self.qualification || injected,
                        "completion reconciled but required post-acceptance injection did not occur"
                    );
                    journal::lock(&self.journal)?.resolve_upload(&id)?;
                    if injected {
                        journal::lock(&self.journal)?.fault(
                            "multipart_complete_lost_response",
                            "reconciled_by_owned_head_size_full_sha256",
                        )?;
                    }
                    journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"ambiguous_completion_reconciliation", "source":if injected { "INJECTED_response_loss_real_provider_reconciliation" } else { "provider_sdk" }, "outcome":"pass", "resubmitted_complete":false, "resubmitted_parts":false}))?;
                } else {
                    return Err(error);
                }
            }
        }
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"multipart_complete_and_readback", "outcome":"pass", "size":LARGE, "sha256":digest}))
    }

    async fn abort(&self, key: &str, id: &str, cleanup: bool) -> Result<()> {
        let result = self
            .send(
                "multipart_abort",
                0,
                CONTROL,
                cleanup,
                self.client
                    .abort_multipart_upload()
                    .bucket(BUCKET)
                    .key(key)
                    .upload_id(id)
                    .send(),
            )
            .await;
        if let Err(error) = result
            && !is_class(&error, "MissingUpload")
        {
            return Err(error);
        }
        let result = self
            .send(
                "list_parts_after_abort",
                0,
                CONTROL,
                cleanup,
                self.client
                    .list_parts()
                    .bucket(BUCKET)
                    .key(key)
                    .upload_id(id)
                    .max_parts(1)
                    .send(),
            )
            .await;
        ensure!(
            matches!(&result, Err(error) if is_class(error, "MissingUpload")),
            "aborted multipart still exists or cannot be reconciled"
        );
        journal::lock(&self.journal)?.resolve_upload(id)
    }

    async fn abort_probe(&self) -> Result<()> {
        let key = self.key("abort")?;
        let id = self
            .create_upload(&key, 5 * MIB, &expected(0, 5 * MIB))
            .await?;
        self.part(&key, &id, 1, 5 * MIB).await?;
        self.list_parts(&key, &id, 1, false).await?;
        let seen = self.list_uploads(false).await?;
        ensure!(
            seen.contains(&(key.clone(), id.clone())),
            "created multipart absent from scoped orphan discovery"
        );
        self.abort(&key, &id, false).await?;
        ensure!(
            !self.list_uploads(false).await?.contains(&(key.clone(), id)),
            "aborted multipart still listed"
        );
        ensure!(
            self.head(&key, false).await?.is_none(),
            "aborted multipart created an object"
        );
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"multipart_abort_and_reconciliation", "outcome":"pass"}))
    }

    async fn list_uploads(&self, cleanup: bool) -> Result<BTreeSet<(String, String)>> {
        let mut uploads = BTreeSet::new();
        let mut key_marker = None;
        let mut upload_marker = None;
        for _ in 0..8 {
            let output = self
                .send(
                    "list_multipart_uploads",
                    0,
                    CONTROL,
                    cleanup,
                    self.client
                        .list_multipart_uploads()
                        .bucket(BUCKET)
                        .prefix(&self.prefix)
                        .max_uploads(2)
                        .set_key_marker(key_marker.clone())
                        .set_upload_id_marker(upload_marker.clone())
                        .send(),
                )
                .await?;
            for upload in output.uploads() {
                let key = upload
                    .key()
                    .ok_or_else(|| anyhow::anyhow!("listed upload key missing"))?;
                config::validate_key(&self.prefix, key)?;
                let id = upload
                    .upload_id()
                    .ok_or_else(|| anyhow::anyhow!("listed upload ID missing"))?;
                ensure!(
                    uploads.insert((key.to_owned(), id.to_owned())),
                    "duplicate multipart listing"
                );
            }
            if !output.is_truncated().unwrap_or(false) {
                journal::lock(&self.journal)?.event(json!({"kind":"multipart_discovery", "count":uploads.len(), "outcome":"observed", "deletion_authority":false}))?;
                return Ok(uploads);
            }
            let next_key = output.next_key_marker().map(str::to_owned);
            let next_upload = output.next_upload_id_marker().map(str::to_owned);
            ensure!(
                next_key.is_some() && (next_key != key_marker || next_upload != upload_marker),
                "multipart continuation missing or repeated"
            );
            key_marker = next_key;
            upload_marker = next_upload;
        }
        bail!("multipart listing page ceiling exceeded")
    }

    async fn list_objects(&self) -> Result<()> {
        let expected: BTreeSet<String> = journal::lock(&self.journal)?
            .manifest
            .objects
            .iter()
            .filter(|(key, object)| key.starts_with(&self.prefix) && object.owned && !object.clean)
            .map(|(key, _)| key.clone())
            .collect();
        let mut keys = BTreeSet::new();
        let mut continuation = None;
        let mut pages = 0;
        loop {
            pages += 1;
            ensure!(pages <= 8, "ListV2 page ceiling exceeded");
            let output = self
                .send(
                    "list_objects_v2",
                    0,
                    CONTROL,
                    false,
                    self.client
                        .list_objects_v2()
                        .bucket(BUCKET)
                        .prefix(&self.prefix)
                        .max_keys(2)
                        .set_continuation_token(continuation.clone())
                        .send(),
                )
                .await?;
            for object in output.contents() {
                let key = object
                    .key()
                    .ok_or_else(|| anyhow::anyhow!("listed object key missing"))?;
                config::validate_key(&self.prefix, key)?;
                ensure!(keys.insert(key.to_owned()), "duplicate ListV2 object");
            }
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            let next = output
                .next_continuation_token()
                .ok_or_else(|| anyhow::anyhow!("ListV2 continuation missing"))?
                .to_owned();
            ensure!(
                continuation.as_ref() != Some(&next),
                "ListV2 continuation repeated"
            );
            continuation = Some(next);
        }
        ensure!(
            pages >= 2 && keys == expected,
            "paginated ListV2 did not discover exact created set"
        );
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"list_v2_paginated", "pages":pages, "count":keys.len(), "outcome":"pass", "consistency_guarantee":false, "deletion_authority":false}))
    }

    async fn reconcile_object(&self, key: &str, cleanup: bool) -> Result<bool> {
        let Some(head) = self.head(key, cleanup).await? else {
            return Ok(false);
        };
        ensure!(
            head.metadata()
                .and_then(|metadata| metadata.get("ferrum-probe-run"))
                .map(String::as_str)
                == Some(self.marker()),
            "unowned object found; never delete or overwrite it"
        );
        if self
            .checkpoint_prefix
            .as_deref()
            .is_some_and(|prefix| key.starts_with(prefix))
        {
            self.read_checkpoint(key, cleanup).await?;
            journal::lock(&self.journal)?.own(key)?;
            return Ok(true);
        }
        let object = journal::lock(&self.journal)?
            .manifest
            .objects
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("reconciliation intent missing"))?
            .clone();
        ensure!(
            head.content_length() == Some(i64::try_from(object.size)?),
            "reconciliation HEAD size mismatch"
        );
        self.verify(key, object.size, &object.sha256, None, cleanup)
            .await?;
        journal::lock(&self.journal)?.own(key)?;
        Ok(true)
    }

    fn checkpoint_key(&self, name: &str) -> Result<String> {
        let prefix = self
            .checkpoint_prefix
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("qualification checkpoint scope missing"))?;
        let key = format!("{prefix}{name}");
        config::validate_owned_key(&self.prefix, Some(prefix), &key)?;
        Ok(key)
    }

    fn record(&self, sequence: u64, writer: &str) -> CheckpointRecord {
        CheckpointRecord {
            schema_version: 1,
            run: self.marker().to_owned(),
            sequence,
            writer: writer.to_owned(),
        }
    }

    fn stage_checkpoint(&self, key: &str, record: &CheckpointRecord) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(record)?;
        ensure!(
            bytes.len() as u64 <= CHECKPOINT_MAX && record.run == self.marker(),
            "checkpoint bound/ownership mismatch"
        );
        let digest = digest_bytes(&bytes);
        let mut journal = journal::lock(&self.journal)?;
        if !journal.manifest.objects.contains_key(key) {
            journal.intent(key, bytes.len() as u64, &digest)?;
        }
        journal.candidate(key, bytes.len() as u64, &digest)?;
        Ok(bytes)
    }

    fn checkpoint_request(
        &self,
        key: &str,
        bytes: Vec<u8>,
        token: Option<&str>,
    ) -> aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder {
        let request = self
            .client
            .put_object()
            .bucket(BUCKET)
            .key(key)
            .metadata("ferrum-probe-run", self.marker())
            .content_length(bytes.len() as i64)
            .body(ByteStream::from(bytes));
        if let Some(token) = token {
            request.if_match(token)
        } else {
            request.if_none_match("*")
        }
    }

    async fn write_checkpoint(
        &self,
        operation: &'static str,
        key: &str,
        bytes: Vec<u8>,
        token: Option<&str>,
    ) -> Result<()> {
        self.send(
            operation,
            bytes.len() as u64,
            CONTROL,
            false,
            self.checkpoint_request(key, bytes, token).send(),
        )
        .await?;
        Ok(())
    }

    async fn read_checkpoint(
        &self,
        key: &str,
        cleanup: bool,
    ) -> Result<(CheckpointRecord, String)> {
        config::validate_owned_key(&self.prefix, self.checkpoint_prefix.as_deref(), key)?;
        ensure!(
            self.checkpoint_prefix
                .as_deref()
                .is_some_and(|prefix| key.starts_with(prefix)),
            "checkpoint read escaped adapter"
        );
        let mut output = self
            .send(
                "checkpoint_get",
                0,
                CHECKPOINT_MAX,
                cleanup,
                self.client.get_object().bucket(BUCKET).key(key).send(),
            )
            .await?;
        ensure!(
            output.version_id().is_none_or(|version| version == "null"),
            "checkpoint version deletion is not approved"
        );
        ensure!(
            output
                .metadata()
                .and_then(|metadata| metadata.get("ferrum-probe-run"))
                .map(String::as_str)
                == Some(self.marker()),
            "checkpoint ownership mismatch"
        );
        let length = output
            .content_length()
            .ok_or_else(|| anyhow::anyhow!("checkpoint length missing"))?;
        ensure!(
            (0..=CHECKPOINT_MAX as i64).contains(&length),
            "checkpoint response too large"
        );
        let etag = output
            .e_tag()
            .ok_or_else(|| anyhow::anyhow!("checkpoint ETag missing"))?
            .to_owned();
        let transfer = async {
            let mut bytes = Vec::with_capacity(length as usize);
            loop {
                let next = tokio::time::timeout(Duration::from_secs(30), output.body.next())
                    .await
                    .map_err(|_| anyhow::anyhow!("checkpoint body idle timeout"))?;
                let Some(chunk) = next else { break };
                let chunk = chunk.map_err(|_| anyhow::anyhow!("checkpoint body failed"))?;
                ensure!(
                    bytes.len() + chunk.len() <= CHECKPOINT_MAX as usize,
                    "checkpoint body exceeded bound"
                );
                bytes.extend_from_slice(&chunk);
            }
            Ok::<_, anyhow::Error>(bytes)
        };
        let bytes = tokio::time::timeout(Duration::from_secs(120), transfer)
            .await
            .map_err(|_| anyhow::anyhow!("checkpoint body deadline"))??;
        ensure!(
            bytes.len() == length as usize,
            "checkpoint body length mismatch"
        );
        let digest = digest_bytes(&bytes);
        {
            let journal = journal::lock(&self.journal)?;
            let object = journal
                .manifest
                .objects
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("checkpoint intent missing"))?;
            ensure!(
                object
                    .candidates
                    .iter()
                    .any(|candidate| candidate.size == bytes.len() as u64
                        && candidate.sha256 == digest),
                "checkpoint bytes are not a durable candidate"
            );
        }
        let record: CheckpointRecord = serde_json::from_slice(&bytes)?;
        ensure!(
            record.schema_version == 1 && record.run == self.marker(),
            "checkpoint content ownership mismatch"
        );
        journal::lock(&self.journal)?.event(json!({"kind":"checkpoint_readback", "key":key, "outcome":"pass", "returned_length":bytes.len(), "sha256":digest, "sequence":record.sequence, "writer":record.writer}))?;
        Ok((record, etag))
    }

    async fn checkpoint_create(&self, key: &str, record: &CheckpointRecord) -> Result<String> {
        self.absent(key).await?;
        let bytes = self.stage_checkpoint(key, record)?;
        self.write_checkpoint("checkpoint_create", key, bytes, None)
            .await?;
        let (actual, token) = self.read_checkpoint(key, false).await?;
        ensure!(&actual == record, "checkpoint create readback mismatch");
        journal::lock(&self.journal)?.own(key)?;
        Ok(token)
    }

    async fn checkpoints(&self) -> Result<()> {
        let key = self.checkpoint_key("state")?;
        let independent_key = self.checkpoint_key("independent")?;
        let initial = self.record(1, "initial");
        let independent = self.record(1, "independent");
        let token = self.checkpoint_create(&key, &initial).await?;
        self.checkpoint_create(&independent_key, &independent)
            .await?;
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"checkpoint_conditional_create", "outcome":"pass"}))?;
        let duplicate = self.stage_checkpoint(&key, &self.record(99, "duplicate"))?;
        let rejected = self
            .write_checkpoint("checkpoint_duplicate", &key, duplicate, None)
            .await;
        ensure!(
            is_412(&rejected),
            "checkpoint duplicate create must return412"
        );
        ensure!(
            self.read_checkpoint(&key, false).await?.0 == initial,
            "duplicate create changed checkpoint"
        );
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"checkpoint_duplicate_412_unchanged", "outcome":"pass"}))?;
        let next = self.record(2, "matching");
        let bytes = self.stage_checkpoint(&key, &next)?;
        self.write_checkpoint("checkpoint_match", &key, bytes, Some(&token))
            .await?;
        let (actual, race_token) = self.read_checkpoint(&key, false).await?;
        ensure!(
            actual == next && race_token != token,
            "matching checkpoint update mismatch"
        );
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"checkpoint_matching_if_match", "outcome":"pass"}))?;
        let stale = self.stage_checkpoint(&key, &self.record(98, "stale"))?;
        let rejected = self
            .write_checkpoint("checkpoint_stale", &key, stale, Some(&token))
            .await;
        ensure!(is_412(&rejected), "stale checkpoint CAS must return412");
        ensure!(
            self.read_checkpoint(&key, false).await?.0 == next,
            "stale CAS changed checkpoint"
        );
        journal::lock(&self.journal)?.event(
            json!({"kind":"capability", "operation":"checkpoint_stale_if_match", "outcome":"pass"}),
        )?;
        let left = self.record(3, "race-a");
        let right = self.record(3, "race-b");
        let left_bytes = self.stage_checkpoint(&key, &left)?;
        let right_bytes = self.stage_checkpoint(&key, &right)?;
        ensure!(
            left_bytes.len() == right_bytes.len(),
            "concurrent permit bounds must be identical"
        );
        // Both reservations are fsynced before either SDK future may reach the connector.
        self.wire.permit(
            "checkpoint_concurrent_update",
            left_bytes.len() as u64,
            CONTROL,
            false,
        )?;
        self.wire.permit(
            "checkpoint_concurrent_update",
            right_bytes.len() as u64,
            CONTROL,
            false,
        )?;
        let left_request = self.checkpoint_request(&key, left_bytes, Some(&race_token));
        let right_request = self.checkpoint_request(&key, right_bytes, Some(&race_token));
        let before = self.wire.totals();
        let (left_result, right_result) = tokio::join!(
            self.send_reserved("checkpoint_concurrent_update", left_request.send()),
            self.send_reserved("checkpoint_concurrent_update", right_request.send()),
        );
        let after = self.wire.totals();
        journal::lock(&self.journal)?.event(json!({"kind":"concurrent_pair_aggregate", "operation":"checkpoint_concurrent_update", "attempts":2, "upload_body_bytes":after.0.saturating_sub(before.0), "download_body_bytes":after.1.saturating_sub(before.1), "per_attempt_byte_attribution":false}))?;
        self.wire.clear_permits()?;
        let winner = cas_winner(&left_result.map(|_| ()), &right_result.map(|_| ()))?;
        let winner_record = if winner == 0 { &left } else { &right };
        let (actual, _) = self.read_checkpoint(&key, false).await?;
        ensure!(
            &actual == winner_record,
            "checkpoint readback does not match sole CAS winner"
        );
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"checkpoint_concurrent_same_token", "outcome":"pass", "successful_updates":1, "rejected_412_updates":1, "winner":winner_record.writer, "sequence":actual.sequence, "credential_profile":"shared_NONISOLATED"}))?;
        ensure!(
            self.read_checkpoint(&independent_key, false).await?.0 == independent,
            "independent checkpoint key changed"
        );
        self.verify(&self.key("small")?, 4097, &expected(0, 4097), None, false)
            .await?;
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"checkpoint_prefix_and_key_logical_independence", "outcome":"pass", "permission_isolation_claim":false}))
    }

    async fn invalid_credential_403(&self) -> Result<()> {
        let key = self.key("small")?;
        self.verify(&key, 4097, &expected(0, 4097), None, false)
            .await?;
        let invalid = config::invalid_client(&self.client);
        let result = self
            .send(
                "get_invalid_sentinel",
                0,
                4097,
                false,
                invalid.get_object().bucket(BUCKET).key(&key).send(),
            )
            .await;
        ensure!(
            matches!(&result, Err(error) if error.downcast_ref::<Failure>().is_some_and(|failure| failure.class == "Forbidden" && failure.status == Some(403))),
            "invalid sentinel did not produce genuine provider403"
        );
        self.verify(&key, 4097, &expected(0, 4097), None, false)
            .await?;
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"denied_credential_403", "outcome":"pass", "source":"provider_sdk", "identity":"invalid-sentinel-authentication-probe", "access_key_id":"FERRUMINTENTIONALLYINVALID", "class":"AuthenticationRejected403", "provider_code_evidence_operation":"get_invalid_sentinel", "existing_owned_target":key, "criterion":"denied-credential authentication403 only", "valid_scoped_credential_authorization_denial":false, "permission_isolation_claim":false}))
    }

    async fn local_faults(&self) -> Result<()> {
        let key = self.key("small")?;
        for (operation, class) in [
            ("injected_timeout", "Timeout"),
            ("injected_429", "Throttled"),
            ("injected_503", "Unavailable"),
        ] {
            journal::lock(&self.journal)?.fault(operation, "armed")?;
            let result = self
                .send(
                    operation,
                    0,
                    4097,
                    false,
                    self.client.get_object().bucket(BUCKET).key(&key).send(),
                )
                .await;
            ensure!(
                matches!(&result, Err(error) if is_class(error, class)),
                "injected transport fault classification mismatch"
            );
            journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":operation, "outcome":"pass", "source":"INJECTED_local_transport", "class":class, "provider_error_observed":false, "sdk_retries":0}))?;
        }
        Ok(())
    }

    pub(crate) async fn run(&self) -> Result<()> {
        {
            let mut journal = journal::lock(&self.journal)?;
            for operation in [
                "zero_put_head_get",
                "small_put_head_get",
                "range",
                "blob_conditions_and_overwrite",
                "missing_get_404",
                "multipart_complete_and_readback",
                "list_parts_paginated",
                "multipart_abort_and_reconciliation",
                "list_v2_paginated",
                "ambiguous_completion_reconciliation",
                "single_put_exact_64MiB",
                "checkpoint_conditional_create",
                "checkpoint_duplicate_412_unchanged",
                "checkpoint_matching_if_match",
                "checkpoint_stale_if_match",
                "checkpoint_concurrent_same_token",
                "checkpoint_prefix_and_key_logical_independence",
                "denied_credential_403",
                "injected_timeout",
                "injected_429",
                "injected_503",
            ] {
                journal.unrun(
                    operation,
                    if self.qualification {
                        "not reached; pass requires actual selected-profile operation and readback, or explicitly labelled injection"
                    } else {
                        "legacy100/200 profile only; new qualification requires explicit qualify command in a fresh artifact directory"
                    },
                )?;
            }
            journal.event(json!({"kind":"credential_profile", "profile":"shared_NONISOLATED", "same_static_credential_for_package_and_checkpoint_adapters":true, "permission_isolation_claim":false, "cross_prefix_denials":"not_applicable_to_selected_nonisolated_profile", "administrative_permissions":"unverified_not_probed", "recovery_guarantee":"ordinary_VM_loss_only_while_off_VM_checkpoint_and_artifacts_remain_intact_and_trusted", "credential_compromise_rollback_protection":false, "deployment_authorization":false}))?;
            journal.unrun(
                "provider_timeout_429_5xx_natural",
                "no naturally observed provider failure is claimed; separate local transport injections exercise error classification without abuse traffic",
            )?;
            journal.unrun(
                "checksum_alternate_encodings",
                "only locked WhenRequired checksum settings are selected; alternate encodings are not a qualification requirement or inferred compatible",
            )?;
            journal.unrun(
                "multipart_two_part_concurrency",
                "sequential file-backed parts remain within production maximum of two; no throughput claim",
            )?;
        }
        let digest = self.prepare().await?;
        self.missing().await?;
        self.put("zero", 0).await?;
        journal::lock(&self.journal)?.event(
            json!({"kind":"capability", "operation":"zero_put_head_get", "outcome":"pass"}),
        )?;
        self.put("small", 4097).await?;
        journal::lock(&self.journal)?.event(
            json!({"kind":"capability", "operation":"small_put_head_get", "outcome":"pass"}),
        )?;
        self.verify(
            &self.key("small")?,
            1000,
            &expected(100, 1000),
            Some((100, 1099)),
            false,
        )
        .await?;
        journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"range", "outcome":"pass", "returned_length":1000}))?;
        self.conditional().await?;
        if self.qualification {
            self.put("threshold", 64 * MIB).await?;
            journal::lock(&self.journal)?.event(json!({"kind":"capability", "operation":"single_put_exact_64MiB", "outcome":"pass", "size":64 * MIB}))?;
            self.invalid_credential_403().await?;
            self.checkpoints().await?;
            self.local_faults().await?;
        }
        self.multipart(&digest).await?;
        self.abort_probe().await?;
        self.list_objects().await?;
        journal::lock(&self.journal)?.event(json!({"kind":"selected_matrix", "outcome":"pass", "budget_profile":if self.qualification { "qualification256_512" } else { "legacy100_200" }, "credential_profile":"shared_NONISOLATED", "full_b02":"requires_report_review", "denied_credential_interpretation":"invalid sentinel genuine authentication403 is the general denied-credential failure-class test, never scoped authorization/isolation evidence"}))
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        self.wire.clear_permits()?;
        let uploads = journal::lock(&self.journal)?.manifest.uploads.clone();
        let mut failed = false;
        for upload in uploads.iter().filter(|upload| !upload.resolved) {
            if self.abort(&upload.key, &upload.id, true).await.is_err() {
                failed = true;
                journal::lock(&self.journal)?.event(json!({"kind":"cleanup", "operation":"abort", "key":upload.key, "upload_id":upload.id, "outcome":"unresolved"}))?;
            }
        }
        let objects: Vec<_> = journal::lock(&self.journal)?
            .manifest
            .objects
            .iter()
            .filter(|(_, object)| !object.clean)
            .map(|(key, object)| (key.clone(), object.clone()))
            .collect();
        for (key, object) in objects {
            let result = async {
                let Some(head) = self.head(&key, true).await? else {
                    let mut journal = journal::lock(&self.journal)?;
                    journal
                        .manifest
                        .objects
                        .get_mut(&key)
                        .ok_or_else(|| anyhow::anyhow!("object intent missing"))?
                        .clean = true;
                    return journal.event(json!({"kind":"cleanup", "operation":"head", "key":key, "outcome":"absent"}));
                };
                ensure!(
                    head.metadata()
                        .and_then(|metadata| metadata.get("ferrum-probe-run"))
                        .map(String::as_str)
                        == Some(self.marker()),
                    "cleanup refuses unowned object"
                );
                let checkpoint = self
                    .checkpoint_prefix
                    .as_deref()
                    .is_some_and(|prefix| key.starts_with(prefix));
                if checkpoint {
                    self.read_checkpoint(&key, true).await?;
                }
                if !object.owned {
                    // A lost create response is reconciled by complete exact readback first.
                    ensure!(
                        self.reconcile_object(&key, true).await?,
                        "unknown object outcome"
                    );
                }
                let token = head
                    .e_tag()
                    .ok_or_else(|| anyhow::anyhow!("cleanup requires an object validator"))?;
                self.send(
                    if checkpoint {
                        "checkpoint_cleanup_delete"
                    } else {
                        "cleanup_delete"
                    },
                    0,
                    CONTROL,
                    true,
                    self.client
                        .delete_object()
                        .bucket(BUCKET)
                        .key(&key)
                        .if_match(token)
                        .send(),
                )
                .await?;
                ensure!(
                    self.head(&key, true).await?.is_none(),
                    "object still visible after cleanup"
                );
                let mut journal = journal::lock(&self.journal)?;
                journal
                    .manifest
                    .objects
                    .get_mut(&key)
                    .ok_or_else(|| anyhow::anyhow!("object intent missing"))?
                    .clean = true;
                journal.event(json!({"kind":"cleanup", "operation":"delete", "key":key, "outcome":"confirmed_absent"}))
            }
            .await;
            if result.is_err() {
                failed = true;
                journal::lock(&self.journal)?.event(json!({"kind":"cleanup", "operation":"delete", "key":key, "outcome":"unresolved"}))?;
            }
        }
        // Discovery never grants deletion authority. A lost Create response or unknown listed ID
        // remains an operator-visible unresolved record, rather than aborting an arbitrary upload.
        match self.list_uploads(true).await {
            Ok(discovered) => {
                let mut journal = journal::lock(&self.journal)?;
                for (key, id) in &discovered {
                    if !journal
                        .manifest
                        .uploads
                        .iter()
                        .any(|upload| upload.key == *key && upload.id == *id)
                    {
                        journal.event(json!({"kind":"cleanup", "operation":"unknown_upload", "key":key, "upload_id":id, "outcome":"retained_not_authorized_for_deletion"}))?;
                    }
                }
                if !discovered.is_empty() || !journal.manifest.pending_creates.is_empty() {
                    failed = true;
                }
            }
            Err(_) => failed = true,
        }
        let journal = journal::lock(&self.journal)?;
        ensure!(
            !failed
                && journal.manifest.pending_creates.is_empty()
                && journal
                    .manifest
                    .uploads
                    .iter()
                    .all(|upload| upload.resolved)
                && journal.manifest.objects.values().all(|object| object.clean),
            "cleanup incomplete; retain manifest and IDs for bounded cleanup retry"
        );
        Ok(())
    }
}

fn is_class(error: &anyhow::Error, class: &str) -> bool {
    error
        .downcast_ref::<Failure>()
        .is_some_and(|failure| failure.class == class)
}

fn is_412<T>(result: &Result<T>) -> bool {
    matches!(result, Err(error) if error.downcast_ref::<Failure>().is_some_and(|failure| failure.class == "Conflict" && failure.status == Some(412)))
}

fn cas_winner(left: &Result<()>, right: &Result<()>) -> Result<usize> {
    match (left.is_ok(), right.is_ok(), is_412(left), is_412(right)) {
        (true, false, false, true) => Ok(0),
        (false, true, true, false) => Ok(1),
        _ => bail!("same-token concurrent CAS requires exactly one success and one actual412"),
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    finish_digest(hash)
}

fn fill(buffer: &mut [u8], offset: u64) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = ((offset + index as u64) % 251) as u8;
    }
}

fn finish_digest(hash: Sha256) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in hash.finalize() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

fn expected(offset: u64, size: u64) -> String {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 256 * 1024];
    let mut consumed = 0;
    while consumed < size {
        let length = (size - consumed).min(buffer.len() as u64) as usize;
        fill(&mut buffer[..length], offset + consumed);
        hash.update(&buffer[..length]);
        consumed += length as u64;
    }
    finish_digest(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bucket_or_forbidden_never_becomes_object_absence() {
        assert_eq!(
            classification(Some(404), Some("NoSuchBucket"), false),
            "UnknownFailure"
        );
        assert_eq!(
            classification(Some(403), Some("AccessDenied"), false),
            "Forbidden"
        );
        assert_eq!(
            classification(Some(404), Some("NoSuchKey"), false),
            "NotFound"
        );
        assert_eq!(
            classification(Some(412), Some("PreconditionFailed"), false),
            "Conflict"
        );
    }

    #[test]
    fn known_empty_digest_and_pattern_are_stable() {
        assert_eq!(
            expected(0, 0),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut bytes = [0u8; 4];
        fill(&mut bytes, 249);
        assert_eq!(bytes, [249, 250, 0, 1]);
    }

    #[test]
    fn concurrent_cas_accepts_only_one_success_and_one_real_412() -> Result<()> {
        let conflict = || {
            Err(Failure {
                class: "Conflict",
                status: Some(412),
            }
            .into())
        };
        assert_eq!(cas_winner(&Ok(()), &conflict())?, 0);
        assert_eq!(cas_winner(&conflict(), &Ok(()))?, 1);
        assert!(cas_winner(&Ok(()), &Ok(())).is_err());
        assert!(cas_winner(&conflict(), &conflict()).is_err());
        assert!(
            cas_winner(
                &Ok(()),
                &Err(Failure {
                    class: "Conflict",
                    status: Some(409)
                }
                .into())
            )
            .is_err()
        );
        assert!(
            cas_winner(
                &Ok(()),
                &Err(Failure {
                    class: "Timeout",
                    status: None
                }
                .into())
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn checkpoint_winner_content_is_distinct_and_bounded() -> Result<()> {
        let left = CheckpointRecord {
            schema_version: 1,
            run: "0123456789abcdef0123456789abcdef".to_owned(),
            sequence: 3,
            writer: "race-a".to_owned(),
        };
        let right = CheckpointRecord {
            writer: "race-b".to_owned(),
            ..left.clone()
        };
        let left_bytes = serde_json::to_vec(&left)?;
        let right_bytes = serde_json::to_vec(&right)?;
        assert_eq!(left_bytes.len(), right_bytes.len());
        assert!(left_bytes.len() as u64 <= CHECKPOINT_MAX);
        assert_ne!(digest_bytes(&left_bytes), digest_bytes(&right_bytes));
        assert_eq!(
            serde_json::from_slice::<CheckpointRecord>(&left_bytes)?,
            left
        );
        Ok(())
    }
}
