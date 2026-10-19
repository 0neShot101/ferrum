use anyhow::{Result, bail, ensure};
use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
    retry::RetryConfig, timeout::TimeoutConfig,
};
use std::{collections::BTreeMap, path::Path, time::Duration};

pub(crate) const ENDPOINT: &str = "https://s3.us-central-1.idrivee2.com";
pub(crate) const REGION: &str = "us-central-1";
pub(crate) const BUCKET: &str = "s3-andrew";
pub(crate) const ROOT: &str = "linux-packages/_ferrum-probe/";
pub(crate) const CHECKPOINT_ROOT: &str = "linux-checkpoints/_ferrum-probe/";
pub(crate) const MIB: u64 = 1024 * 1024;
pub(crate) const PART: u64 = 16 * MIB;
pub(crate) const LARGE: u64 = 5 * PART;
pub(crate) const CONTROL: u64 = 64 * 1024;
pub(crate) const UPLOAD_LIMIT: u64 = 100 * MIB;
pub(crate) const DOWNLOAD_LIMIT: u64 = 200 * MIB;
pub(crate) const CLEANUP_RESERVE: u64 = 4 * MIB;
pub(crate) const QUALIFICATION_CLEANUP_RESERVE: u64 = 16 * MIB;
pub(crate) const CHECKPOINT_MAX: u64 = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetProfile {
    #[default]
    #[serde(rename = "legacy_blob100_200")]
    LegacyBlob,
    #[serde(rename = "qualification256_512")]
    Qualification,
}

impl BudgetProfile {
    pub(crate) fn limits(self) -> (u64, u64, u64) {
        match self {
            Self::LegacyBlob => (UPLOAD_LIMIT, DOWNLOAD_LIMIT, CLEANUP_RESERVE),
            Self::Qualification => (256 * MIB, 512 * MIB, QUALIFICATION_CLEANUP_RESERVE),
        }
    }
}

// This is deliberately not a dotenv shell: no expansion, execution or environment mutation.
fn parse(content: &str) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid credential file syntax"))?;
        let name = name.trim();
        ensure!(
            name.bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit()),
            "invalid credential field name"
        );
        let value = value.trim();
        let value = if (value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"'))
        {
            ensure!(value.len() >= 2, "invalid credential quoting");
            &value[1..value.len() - 1]
        } else {
            value
        };
        ensure!(
            !value.contains(['\n', '\r', '\0']),
            "invalid credential value"
        );
        ensure!(
            values.insert(name.to_owned(), value.to_owned()).is_none(),
            "duplicate credential field"
        );
    }
    Ok(values)
}

pub(crate) fn client(path: &Path, wire: crate::wire::Wire) -> Result<aws_sdk_s3::Client> {
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        ensure!(
            std::env::var_os(name).is_none(),
            "proxy environment must be absent"
        );
    }
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "credential file must be a regular non-symlink file"
    );
    ensure!(metadata.len() <= 16 * 1024, "credential file is too large");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o777 == 0o600,
            "credential file must have mode 600"
        );
        let parent = std::fs::metadata(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("credential parent missing"))?,
        )?;
        ensure!(
            parent.permissions().mode() & 0o777 == 0o700 && parent.uid() == metadata.uid(),
            "credential parent must have mode 700 and matching owner"
        );
    }
    let mut values = parse(&std::fs::read_to_string(path)?)?;
    let access = values
        .remove("AWS_ACCESS_KEY_ID")
        .ok_or_else(|| anyhow::anyhow!("required credential field missing"))?;
    let secret = values
        .remove("AWS_SECRET_ACCESS_KEY")
        .ok_or_else(|| anyhow::anyhow!("required credential field missing"))?;
    ensure!(
        !access.is_empty() && !secret.is_empty(),
        "empty credential field"
    );
    let get = |name: &str| -> Result<&str> {
        let value = values
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("required provider field missing"))?;
        ensure!(!value.is_empty(), "empty provider field");
        Ok(value.as_str())
    };
    for (name, approved) in [
        ("AWS_ENDPOINT_URL_S3", ENDPOINT),
        ("AWS_REGION", REGION),
        ("FERRUM_S3_BUCKET", BUCKET),
        ("FERRUM_S3_PREFIX", "linux-packages/"),
    ] {
        ensure!(
            get(name)? == approved,
            "provider configuration differs from approved boundary"
        );
    }
    if values.contains_key("AWS_SESSION_TOKEN") {
        bail!("session credentials are outside the approved static credential contract");
    }
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::v2026_01_12())
        .region(Region::new(REGION))
        .endpoint_url(ENDPOINT)
        .force_path_style(true)
        .disable_multi_region_access_points(true)
        .disable_s3_express_session_auth(true)
        .credentials_provider(Credentials::new(
            access,
            secret,
            None,
            None,
            "explicit-probe-file",
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
        .http_client(wire)
        .build();
    Ok(aws_sdk_s3::Client::from_conf(config))
}

pub(crate) fn checkpoint_prefix(prefix: &str) -> Result<String> {
    validate_prefix(prefix)?;
    Ok(format!("{CHECKPOINT_ROOT}{}", &prefix[ROOT.len()..]))
}

pub(crate) fn validate_prefix(prefix: &str) -> Result<()> {
    validate_namespace(prefix, ROOT)
}

fn validate_namespace(prefix: &str, root: &str) -> Result<()> {
    let suffix = prefix
        .strip_prefix(root)
        .ok_or_else(|| anyhow::anyhow!("prefix outside approved boundary"))?;
    ensure!(
        suffix.len() == 33
            && suffix.ends_with('/')
            && suffix.as_bytes()[..32]
                .iter()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid run prefix"
    );
    Ok(())
}

pub(crate) fn validate_key(prefix: &str, key: &str) -> Result<()> {
    validate_prefix(prefix)?;
    let names = [
        "zero",
        "small",
        "conditional",
        "threshold",
        "multipart",
        "abort",
        "missing",
    ];
    ensure!(
        key.strip_prefix(prefix)
            .is_some_and(|name| names.contains(&name)),
        "key is not a fixed package probe key"
    );
    Ok(())
}

pub(crate) fn validate_owned_key(prefix: &str, checkpoint: Option<&str>, key: &str) -> Result<()> {
    if validate_key(prefix, key).is_ok() {
        return Ok(());
    }
    let checkpoint = checkpoint.ok_or_else(|| anyhow::anyhow!("checkpoint scope not approved"))?;
    ensure!(
        checkpoint == checkpoint_prefix(prefix)?,
        "checkpoint run correlation mismatch"
    );
    ensure!(
        key.strip_prefix(checkpoint)
            .is_some_and(|name| ["state", "independent"].contains(&name)),
        "key is not a fixed checkpoint probe key"
    );
    Ok(())
}

pub(crate) fn invalid_client(client: &aws_sdk_s3::Client) -> aws_sdk_s3::Client {
    aws_sdk_s3::Client::from_conf(
        client
            .config()
            .to_builder()
            .identity_cache(aws_sdk_s3::config::IdentityCache::no_cache())
            .credentials_provider(Credentials::new(
                "FERRUMINTENTIONALLYINVALID",
                "ferrum-intentionally-invalid-sentinel-not-a-secret",
                None,
                None,
                "invalid-sentinel-authentication-probe",
            ))
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_reject_arbitrary_prefixes_and_keys() {
        let prefix = format!("{ROOT}0123456789abcdef0123456789abcdef/");
        assert!(validate_key(&prefix, &format!("{prefix}small")).is_ok());
        assert!(validate_key(&prefix, &format!("{prefix}../other")).is_err());
        assert!(validate_prefix(ROOT).is_err());
        assert!(validate_prefix("linux-packages/").is_err());
    }

    #[test]
    fn credential_parser_never_executes_shell() -> Result<()> {
        let values = parse("AWS_ACCESS_KEY_ID='$(touch ignored)'\n")?;
        assert_eq!(values["AWS_ACCESS_KEY_ID"], "$(touch ignored)");
        assert!(parse("AWS_ACCESS_KEY_ID=a\nAWS_ACCESS_KEY_ID=b").is_err());
        Ok(())
    }

    #[test]
    fn checkpoint_scope_requires_correlated_sibling_and_fixed_keys() -> Result<()> {
        let package = format!("{ROOT}0123456789abcdef0123456789abcdef/");
        let checkpoint = checkpoint_prefix(&package)?;
        assert!(
            validate_owned_key(&package, Some(&checkpoint), &format!("{checkpoint}state")).is_ok()
        );
        assert!(validate_owned_key(&package, None, &format!("{checkpoint}state")).is_err());
        let foreign = format!("{CHECKPOINT_ROOT}1123456789abcdef0123456789abcdef/");
        assert!(validate_owned_key(&package, Some(&foreign), &format!("{foreign}state")).is_err());
        assert!(
            validate_owned_key(
                &package,
                Some(&checkpoint),
                &format!("{checkpoint}../state")
            )
            .is_err()
        );
        assert!(
            validate_owned_key(&package, Some(&checkpoint), "linux-checkpoints/live/state")
                .is_err()
        );
        assert_eq!(
            BudgetProfile::LegacyBlob.limits(),
            (100 * MIB, 200 * MIB, 4 * MIB)
        );
        assert_eq!(
            BudgetProfile::Qualification.limits(),
            (256 * MIB, 512 * MIB, 16 * MIB)
        );
        Ok(())
    }
}
