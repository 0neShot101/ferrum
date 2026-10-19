use super::{BUCKET, CONTROL, Failure, Probe, Result, journal, json};

impl Probe {
    /// Two read-only controls using the existing durable allowance, never a new probe batch.
    pub(crate) async fn inspect_configuration(&self) -> Result<()> {
        let versioning = self
            .send(
                "inspect_versioning",
                0,
                CONTROL,
                false,
                self.client.get_bucket_versioning().bucket(BUCKET).send(),
            )
            .await;
        match versioning {
            Ok(output) => {
                let status = match output.status().map(|status| status.as_str()) {
                    None => "unset",
                    Some("Enabled") => "enabled",
                    Some("Suspended") => "suspended",
                    Some(_) => "unknown",
                };
                journal::lock(&self.journal)?.event(json!({
                    "kind":"bucket_configuration", "control":"versioning", "status":status,
                    "source":"actual_provider", "mutation":false,
                    "limitation":"Current configuration only; suspended does not prove historical versions absent or billed usage reconciled"
                }))?;
            }
            Err(error) => self.record_configuration_failure("versioning", &error)?,
        }
        let lifecycle = self
            .send(
                "inspect_lifecycle",
                0,
                CONTROL,
                false,
                self.client
                    .get_bucket_lifecycle_configuration()
                    .bucket(BUCKET)
                    .send(),
            )
            .await;
        match lifecycle {
            Ok(output) => {
                let enabled = output
                    .rules()
                    .iter()
                    .filter(|rule| rule.status().as_str() == "Enabled")
                    .count();
                journal::lock(&self.journal)?.event(json!({
                    "kind":"bucket_configuration", "control":"lifecycle",
                    "status":"configuration_present", "rule_count":output.rules().len(),
                    "enabled_rule_count":enabled, "source":"actual_provider", "mutation":false,
                    "scope_review_required":enabled != 0,
                    "limitation":"Enabled rules require explicit prefix/action review; counts do not establish that either Ferrum namespace is safe. Rule names, tags and unrelated key prefixes are not logged"
                }))?;
            }
            Err(error) => self.record_configuration_failure("lifecycle", &error)?,
        }
        let (uploaded, downloaded) = self.wire.totals();
        journal::lock(&self.journal)?.event(json!({
            "kind":"configuration_inspection_complete", "upload_body_bytes":uploaded,
            "download_body_bytes":downloaded, "mutation":false,
            "deployment_authorization":false, "credential_profile":"shared_NONISOLATED"
        }))?;
        Ok(())
    }

    fn record_configuration_failure(&self, control: &str, error: &anyhow::Error) -> Result<()> {
        let failure = error.downcast_ref::<Failure>();
        let absent = control == "lifecycle"
            && failure.is_some_and(|failure| failure.class == "NoLifecycleConfiguration");
        journal::lock(&self.journal)?.event(json!({
            "kind":"bucket_configuration", "control":control,
            "status":if absent { "no_configuration" } else { "unknown" },
            "class":failure.map(|failure| failure.class),
            "http_status":failure.and_then(|failure| failure.status),
            "source":"actual_provider_or_transport_failure", "mutation":false,
            "operator_inspection_required":!absent
        }))?;
        Ok(())
    }
}
