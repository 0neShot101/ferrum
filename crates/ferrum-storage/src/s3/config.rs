use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
    retry::RetryConfig, timeout::TimeoutConfig,
};
use serde::Deserialize;

use super::{S3Error, wire::Wire};

pub const ENDPOINT: &str = "https://s3.us-central-1.idrivee2.com";
pub const REGION: &str = "us-central-1";
pub const BUCKET: &str = "s3-andrew";
pub const ROOT: &str = "linux-packages/_ferrum-b05/";

/// Explicitly private configuration. There is no default provider/credential chain.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateS3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub package_prefix: String,
    pub credentials_file: PathBuf,
    pub transfer_journal: PathBuf,
}

impl PrivateS3Config {
    pub fn validate(&self) -> Result<(), S3Error> {
        if self.endpoint != ENDPOINT || self.region != REGION || self.bucket != BUCKET {
            return Err(S3Error::Boundary);
        }
        let suffix = self
            .package_prefix
            .strip_prefix(ROOT)
            .ok_or(S3Error::Boundary)?;
        if suffix.len() != 33
            || !suffix.ends_with('/')
            || !suffix.as_bytes()[..32]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            || !self.credentials_file.is_absolute()
            || !self.transfer_journal.is_absolute()
        {
            return Err(S3Error::Boundary);
        }
        no_symlink_ancestors(&self.credentials_file)?;
        no_symlink_ancestors(&self.transfer_journal)?;
        Ok(())
    }

    /// Called before any fixture startup cleanup or explicit ledger initialization.
    pub fn validate_separation(&self, spool: &Path, scratch: &Path) -> Result<(), S3Error> {
        self.validate()?;
        let journal = no_symlink_ancestors(&self.transfer_journal)?;
        for cleaned in [spool, scratch] {
            let cleaned = no_symlink_ancestors(cleaned)?;
            if journal.starts_with(&cleaned) || cleaned.starts_with(&journal) {
                return Err(S3Error::Boundary);
            }
        }
        Ok(())
    }

    pub(crate) fn validate_key(&self, key: &str) -> Result<(), S3Error> {
        let digest = key
            .strip_prefix(&format!("{}v1/objects/sha256/", self.package_prefix))
            .ok_or(S3Error::Boundary)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(S3Error::Boundary);
        }
        Ok(())
    }

    pub(crate) fn marker(&self) -> &str {
        &self.package_prefix[ROOT.len()..self.package_prefix.len() - 1]
    }

    #[cfg(test)]
    pub(crate) fn test_config(journal: PathBuf) -> Self {
        Self {
            endpoint: ENDPOINT.into(),
            region: REGION.into(),
            bucket: BUCKET.into(),
            package_prefix: format!("{ROOT}0123456789abcdef0123456789abcdef/"),
            credentials_file: journal.with_file_name("provider.env"),
            transfer_journal: journal,
        }
    }
}

pub(super) fn no_symlink_ancestors(path: &Path) -> Result<PathBuf, S3Error> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(S3Error::Boundary);
    }
    let absolute = std::path::absolute(path).map_err(|_| S3Error::Boundary)?;
    if absolute
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(S3Error::Boundary);
    }
    let mut ancestor = PathBuf::new();
    for component in absolute.components() {
        ancestor.push(component.as_os_str());
        match std::fs::symlink_metadata(&ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(S3Error::Boundary),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(S3Error::Boundary),
        }
    }
    Ok(absolute)
}

pub(crate) fn client(config: &PrivateS3Config, wire: Wire) -> Result<aws_sdk_s3::Client, S3Error> {
    client_for_credentials(&config.credentials_file, ENDPOINT, REGION, BUCKET, wire)
}

pub(crate) fn client_for_credentials(
    credentials_file: &Path,
    endpoint: &str,
    region: &str,
    bucket: &str,
    http: impl aws_smithy_runtime_api::client::http::HttpClient + 'static,
) -> Result<aws_sdk_s3::Client, S3Error> {
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        if std::env::var_os(name).is_some() {
            return Err(S3Error::Credentials);
        }
    }
    let metadata = std::fs::symlink_metadata(credentials_file).map_err(|_| S3Error::Credentials)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16 * 1024 {
        return Err(S3Error::Credentials);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let parent = credentials_file.parent().ok_or(S3Error::Credentials)?;
        let parent = std::fs::symlink_metadata(parent).map_err(|_| S3Error::Credentials)?;
        if !parent.is_dir()
            || parent.file_type().is_symlink()
            || metadata.permissions().mode() & 0o777 != 0o600
            || parent.permissions().mode() & 0o777 != 0o700
            || parent.uid() != metadata.uid()
        {
            return Err(S3Error::Credentials);
        }
    }
    let text = std::fs::read_to_string(credentials_file).map_err(|_| S3Error::Credentials)?;
    let mut values = parse_credentials(&text)?;
    let access = values
        .remove("AWS_ACCESS_KEY_ID")
        .filter(|value| !value.is_empty())
        .ok_or(S3Error::Credentials)?;
    let secret = values
        .remove("AWS_SECRET_ACCESS_KEY")
        .filter(|value| !value.is_empty())
        .ok_or(S3Error::Credentials)?;
    for (name, expected) in [
        ("AWS_ENDPOINT_URL_S3", endpoint),
        ("AWS_REGION", region),
        ("FERRUM_S3_BUCKET", bucket),
        ("FERRUM_S3_PREFIX", "linux-packages/"),
    ] {
        if values.get(name).map(String::as_str) != Some(expected) {
            return Err(S3Error::Credentials);
        }
    }
    if values.contains_key("AWS_SESSION_TOKEN") {
        return Err(S3Error::Credentials);
    }
    let sdk = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::v2026_01_12())
        .region(Region::new(region.to_owned()))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .disable_multi_region_access_points(true)
        .disable_s3_express_session_auth(true)
        .credentials_provider(Credentials::new(
            access,
            secret,
            None,
            None,
            "explicit-protected-file",
        ))
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
        .retry_config(RetryConfig::disabled())
        .timeout_config(
            TimeoutConfig::builder()
                .connect_timeout(Duration::from_secs(3))
                .read_timeout(Duration::from_secs(10))
                .operation_timeout(Duration::from_secs(120))
                .operation_attempt_timeout(Duration::from_secs(120))
                .build(),
        )
        .http_client(http)
        .build();
    Ok(aws_sdk_s3::Client::from_conf(sdk))
}

fn parse_credentials(text: &str) -> Result<BTreeMap<String, String>, S3Error> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line.split_once('=').ok_or(S3Error::Credentials)?;
        let name = name.trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(S3Error::Credentials);
        }
        let value = value.trim();
        let value = if (value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"'))
        {
            value
                .get(1..value.len().saturating_sub(1))
                .ok_or(S3Error::Credentials)?
        } else {
            value
        };
        if value.contains(['\n', '\r', '\0']) || values.insert(name.into(), value.into()).is_some()
        {
            return Err(S3Error::Credentials);
        }
    }
    Ok(values)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn journal_and_cleaned_roots_cannot_overlap_in_either_direction() {
        let root = tempfile::tempdir().expect("root");
        let spool = root.path().join("work/spool");
        let scratch = root.path().join("work/scratch");
        let separate = PrivateS3Config::test_config(root.path().join("journal"));
        separate
            .validate_separation(&spool, &scratch)
            .expect("separate paths");
        for journal in [
            root.path().join("work"),
            spool.clone(),
            spool.join("objects/journal"),
            scratch.join("journal"),
        ] {
            let config = PrivateS3Config::test_config(journal);
            assert!(config.validate_separation(&spool, &scratch).is_err());
        }
        let traversal = root.path().join("work/../work/spool");
        assert!(separate.validate_separation(&traversal, &scratch).is_err());
    }
}
