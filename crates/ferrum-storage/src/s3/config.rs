use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
    retry::RetryConfig, timeout::TimeoutConfig,
};
use serde::Deserialize;

use super::{S3Error, wire::Wire};

#[cfg(test)]
pub const DEFAULT_ENDPOINT: &str = "https://s3.us-east-1.amazonaws.com";
pub const DEFAULT_REGION: &str = "us-east-1";
#[cfg(test)]
pub const DEFAULT_BUCKET: &str = "ferrum";
pub const DEFAULT_PACKAGE_PREFIX: &str = "linux-packages/";
pub const DEFAULT_CHECKPOINT_PREFIX: &str = "linux-checkpoints/";
#[cfg(test)]
pub const ENDPOINT: &str = DEFAULT_ENDPOINT;
#[cfg(test)]
pub const REGION: &str = DEFAULT_REGION;
#[cfg(test)]
pub const BUCKET: &str = DEFAULT_BUCKET;
#[cfg(test)]
pub const ROOT: &str = "linux-packages/_ferrum-b05/";
pub(crate) fn default_aws_endpoint(region: &str) -> String {
    format!("https://s3.{region}.amazonaws.com")
}

pub(crate) fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn valid_endpoint_and_host(endpoint: &str) -> Result<String, S3Error> {
    let parsed = url::Url::parse(endpoint).map_err(|_| S3Error::Boundary)?;
    let domain = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain,
        _ => return Err(S3Error::Boundary),
    };
    if parsed.scheme() != "https"
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !domain.contains('.')
        || !domain.split('.').all(valid_label)
    {
        return Err(S3Error::Boundary);
    }
    Ok(domain.to_owned())
}

pub(crate) fn valid_region(region: &str) -> bool {
    region.len() <= 63 && valid_label(region)
}

pub(crate) fn valid_bucket(bucket: &str) -> bool {
    (3..=63).contains(&bucket.len())
        && bucket.parse::<std::net::IpAddr>().is_err()
        && bucket.split('.').all(valid_label)
}

pub(crate) fn valid_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.len() <= 256
        && !prefix.starts_with('/')
        && prefix.ends_with('/')
        && !prefix.contains("//")
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        && prefix[..prefix.len() - 1].split('/').all(|part| {
            !part.is_empty() && !matches!(part, "." | ".." | "_ferrum-b05" | "_ferrum-b07")
        })
}

pub(crate) fn prefixes_overlap(left: &str, right: &str) -> bool {
    left.starts_with(right) || right.starts_with(left)
}
fn infer_region_from_endpoint(endpoint: &str) -> Option<String> {
    let parsed = url::Url::parse(endpoint).ok()?;
    let host = parsed.host_str()?;
    if host.ends_with(".r2.cloudflarestorage.com") {
        return Some("auto".into());
    }
    let rest = host.strip_prefix("s3.")?;
    let (region, domain) = rest.split_once('.')?;
    if valid_region(region) && domain.contains('.') {
        Some(region.to_owned())
    } else {
        None
    }
}

pub(crate) fn resolve_provider_fields(
    provider: Option<&str>,
    account_id: Option<&str>,
    endpoint: Option<String>,
    region: Option<String>,
) -> (String, String) {
    let kind = match provider {
        None => {
            if account_id.is_some()
                || endpoint
                    .as_deref()
                    .is_some_and(|ep| ep.contains(".r2.cloudflarestorage.com"))
            {
                "cloudflare-r2"
            } else if endpoint
                .as_deref()
                .is_some_and(|ep| ep.contains(".idrivee2.com"))
            {
                "idrive-e2"
            } else {
                "s3"
            }
        }
        Some("cloudflare" | "cloudflare-r2" | "r2") => "cloudflare-r2",
        Some("idrive" | "idrive-e2" | "e2") => "idrive-e2",
        Some("aws" | "s3" | "custom") => "s3",
        Some(_) => return (String::new(), String::new()),
    };
    match kind {
        "cloudflare-r2" => {
            let region = region.unwrap_or_else(|| "auto".into());
            let endpoint = match (endpoint, account_id) {
                (Some(ep), None) => ep,
                (None, Some(account)) if valid_label(account) => {
                    format!("https://{account}.r2.cloudflarestorage.com")
                }
                _ => String::new(),
            };
            (endpoint, region)
        }
        "idrive-e2" => {
            if account_id.is_some() {
                return (String::new(), String::new());
            }
            let region = region
                .or_else(|| endpoint.as_deref().and_then(infer_region_from_endpoint))
                .unwrap_or_default();
            let endpoint = endpoint.unwrap_or_else(|| {
                if region.is_empty() {
                    String::new()
                } else {
                    format!("https://s3.{region}.idrivee2.com")
                }
            });
            (endpoint, region)
        }
        _ => {
            if account_id.is_some() {
                return (String::new(), String::new());
            }
            let region = region
                .or_else(|| endpoint.as_deref().and_then(infer_region_from_endpoint))
                .unwrap_or_else(|| {
                    if endpoint.is_some() {
                        DEFAULT_REGION.into()
                    } else {
                        String::new()
                    }
                });
            let endpoint = endpoint.unwrap_or_else(|| {
                if region.is_empty() {
                    String::new()
                } else {
                    default_aws_endpoint(&region)
                }
            });
            (endpoint, region)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrivateS3Config {
    provider: Option<String>,
    account_id: Option<String>,
    endpoint: Option<String>,
    region: Option<String>,
    bucket: String,
    package_prefix: String,
    credentials_file: PathBuf,
    transfer_journal: PathBuf,
}

/// Explicitly private configuration. There is no default provider/credential chain.
#[derive(Clone, Debug, Deserialize)]
#[serde(from = "RawPrivateS3Config")]
pub struct PrivateS3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub package_prefix: String,
    pub credentials_file: PathBuf,
    pub transfer_journal: PathBuf,
}

impl From<RawPrivateS3Config> for PrivateS3Config {
    fn from(raw: RawPrivateS3Config) -> Self {
        let (endpoint, region) = resolve_provider_fields(
            raw.provider.as_deref(),
            raw.account_id.as_deref(),
            raw.endpoint,
            raw.region,
        );
        Self {
            endpoint,
            region,
            bucket: raw.bucket,
            package_prefix: raw.package_prefix,
            credentials_file: raw.credentials_file,
            transfer_journal: raw.transfer_journal,
        }
    }
}
impl PrivateS3Config {
    pub fn validate(&self) -> Result<(), S3Error> {
        let _ = valid_endpoint_and_host(&self.endpoint)?;
        if !valid_region(&self.region) || !valid_bucket(&self.bucket) {
            return Err(S3Error::Boundary);
        }
        let (base, suffix) = self
            .package_prefix
            .split_once("_ferrum-b05/")
            .ok_or(S3Error::Boundary)?;
        if !(base.is_empty() || valid_prefix(base))
            || suffix.len() != 33
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
        &self.package_prefix[self.package_prefix.len() - 33..self.package_prefix.len() - 1]
    }

    #[cfg(test)]
    pub(crate) fn test_config(journal: PathBuf) -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.into(),
            region: DEFAULT_REGION.into(),
            bucket: DEFAULT_BUCKET.into(),
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
    client_for_credentials(
        &config.credentials_file,
        &config.endpoint,
        &config.region,
        &config.bucket,
        &config.package_prefix,
        wire,
    )
}

pub(crate) fn client_for_credentials(
    credentials_file: &Path,
    endpoint: &str,
    region: &str,
    bucket: &str,
    package_prefix: &str,
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
    if values.contains_key("AWS_SESSION_TOKEN") {
        return Err(S3Error::Credentials);
    }
    let base_prefix = package_prefix
        .split_once("_ferrum-b05/")
        .or_else(|| package_prefix.split_once("_ferrum-b07/"))
        .map_or(package_prefix, |(base, _)| base);
    if let Some(configured_endpoint) = values.remove("AWS_ENDPOINT_URL_S3") {
        let actual = url::Url::parse(&configured_endpoint).map_err(|_| S3Error::Credentials)?;
        let expected = url::Url::parse(endpoint).map_err(|_| S3Error::Credentials)?;
        if actual != expected {
            return Err(S3Error::Credentials);
        }
    }
    if let Some(configured_region) = values.remove("AWS_REGION")
        && configured_region != region
    {
        return Err(S3Error::Credentials);
    }
    if let Some(configured_bucket) = values.remove("FERRUM_S3_BUCKET")
        && configured_bucket != bucket
    {
        return Err(S3Error::Credentials);
    }
    if let Some(configured_prefix) = values.remove("FERRUM_S3_PREFIX")
        && configured_prefix != package_prefix
        && configured_prefix != base_prefix
    {
        return Err(S3Error::Credentials);
    }
    if !values.is_empty() {
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

    #[test]
    fn private_config_and_credentials_support_general_s3_providers() {
        let root = tempfile::tempdir().expect("root");
        let private_dir = root.path().join("private");
        std::fs::create_dir(&private_dir).expect("mkdir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod 700");
        }
        let creds = private_dir.join("provider.env");
        std::fs::write(
            &creds,
            "AWS_ACCESS_KEY_ID=AKIAEXAMPLE\nAWS_SECRET_ACCESS_KEY=secret-value\n",
        )
        .expect("write minimal credentials");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }
        let mut config = PrivateS3Config::test_config(root.path().join("journal"));
        config.endpoint = "https://s3.eu-central-1.example.com".into();
        config.region = "eu-central-1".into();
        config.bucket = "custom-bucket-01".into();
        config.package_prefix =
            "custom-packages/_ferrum-b05/0123456789abcdef0123456789abcdef/".into();
        config.credentials_file = creds.clone();
        config.validate().expect("custom private S3 config");
        assert_eq!(config.marker(), "0123456789abcdef0123456789abcdef");

        let resolver = super::super::production::dns::PublicResolver::new(
            "s3.eu-central-1.example.com".into(),
        );
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
            ))
            .build_with_resolver(resolver);
        client_for_credentials(
            &creds,
            &config.endpoint,
            &config.region,
            &config.bucket,
            "custom-packages/",
            http.clone(),
        )
        .expect("minimal two-field credentials file accepted");

        for bad in [
            "AWS_ACCESS_KEY_ID=a\nAWS_SECRET_ACCESS_KEY=b\nFERRUM_S3_BUCKET=wrong-bucket\n",
            "AWS_ACCESS_KEY_ID=a\nAWS_SECRET_ACCESS_KEY=b\nAWS_REGION=wrong-region\n",
            "AWS_ACCESS_KEY_ID=a\nAWS_SECRET_ACCESS_KEY=b\nAWS_ENDPOINT_URL_S3=https://wrong.example.com\n",
            "AWS_ACCESS_KEY_ID=a\nAWS_SECRET_ACCESS_KEY=b\nFERRUM_S3_PREFIX=wrong-prefix/\n",
            "AWS_ACCESS_KEY_ID=a\nAWS_SECRET_ACCESS_KEY=b\nUNKNOWN_VAR=1\n",
        ] {
            std::fs::write(&creds, bad).expect("write invalid credentials");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod 600");
            }
            assert!(
                client_for_credentials(
                    &creds,
                    &config.endpoint,
                    &config.region,
                    &config.bucket,
                    "custom-packages/",
                    http.clone(),
                )
                .is_err()
            );
        }
    }
}
