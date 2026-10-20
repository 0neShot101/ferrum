//! Administration lives outside both the spool and disposable sync scratch.

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use url::{Host, Url};

use super::{ConfigError, invalid};

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub state_dir: PathBuf,
    pub origin: String,
    pub managed_config: bool,
    explicit_origin: bool,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawAdmin {
    state_dir: Option<PathBuf>,
    origin: Option<String>,
    #[serde(default)]
    managed_config: bool,
}

impl AdminConfig {
    pub(super) fn resolve(
        raw: RawAdmin,
        base: &Path,
        spool: &Path,
        scratch: &Path,
        listen: SocketAddr,
    ) -> Result<Self, ConfigError> {
        let state_dir = match raw.state_dir {
            Some(path) => base.join(path),
            None => {
                let mut name = spool
                    .file_name()
                    .ok_or_else(|| invalid("admin.state_dir", "spool must have a directory name"))?
                    .to_os_string();
                name.push(".admin");
                spool.with_file_name(name)
            }
        };
        let explicit_origin = raw.origin.is_some();
        let origin = raw.origin.unwrap_or_else(|| format!("http://{listen}"));
        let config = Self {
            state_dir: absolute_clean(&state_dir)?,
            origin: validate_origin(&origin)?,
            managed_config: raw.managed_config,
            explicit_origin,
        };
        config.validate_separation(spool, scratch, false)?;
        Ok(config)
    }

    /// Ephemeral listeners use their actual bound port, not the configured zero.
    pub fn origin_for_listener(&self, bound: SocketAddr) -> String {
        if self.explicit_origin {
            self.origin.clone()
        } else {
            format!("http://{bound}")
        }
    }

    pub(super) fn validate_separation(
        &self,
        spool: &Path,
        scratch: &Path,
        inspect_filesystem: bool,
    ) -> Result<(), ConfigError> {
        validate_origin(&self.origin)?;
        let admin = absolute_clean(&self.state_dir)?;
        for reserved in [spool, scratch] {
            let reserved = absolute_clean(reserved)?;
            if admin.starts_with(&reserved) || reserved.starts_with(&admin) {
                return Err(invalid(
                    "admin.state_dir",
                    "must be separate from spool and scratch",
                ));
            }
            if inspect_filesystem {
                reject_symlinks(&reserved)?;
            }
        }
        if inspect_filesystem {
            reject_symlinks(&admin)?;
        }
        Ok(())
    }
}

fn absolute_clean(path: &Path) -> Result<PathBuf, ConfigError> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid("admin.state_dir", "parent traversal is forbidden"));
    }
    let path = std::path::absolute(path)
        .map_err(|_| invalid("admin.state_dir", "cannot resolve absolute path"))?;
    Ok(path
        .components()
        .filter(|part| !matches!(part, Component::CurDir))
        .collect())
}

fn reject_symlinks(path: &Path) -> Result<(), ConfigError> {
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component.as_os_str());
        match std::fs::symlink_metadata(&ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid(
                    "admin.state_dir",
                    "symlink ancestors are forbidden",
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(invalid("admin.state_dir", "ancestor must be a directory"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {
                return Err(invalid(
                    "admin.state_dir",
                    "cannot inspect directory ownership",
                ));
            }
        }
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<String, ConfigError> {
    let url = Url::parse(origin).map_err(|_| invalid("admin.origin", "must be an HTTP origin"))?;
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain("localhost")) => true,
        _ => false,
    };
    if !matches!(url.scheme(), "http" | "https")
        || (url.scheme() == "http" && !loopback)
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "admin.origin",
            "requires HTTPS, or loopback HTTP, with no credentials, path, query or fragment",
        ));
    }
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn origin_rejects_insecure_remote_and_non_origin_urls() {
        for bad in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com/admin",
            "https://example.com/?key=x",
            "https://example.com/#x",
        ] {
            assert!(validate_origin(bad).is_err());
        }
        assert_eq!(
            validate_origin("https://example.com:443/").expect("origin"),
            "https://example.com"
        );
        assert_eq!(
            validate_origin("http://[::1]:9090").expect("loopback"),
            "http://[::1]:9090"
        );
    }

    #[test]
    fn admin_state_cannot_overlap_spool_or_scratch() {
        let root = tempfile::tempdir().expect("root");
        let spool = root.path().join("spool");
        let scratch = root.path().join("scratch");
        for path in [
            spool.clone(),
            spool.join("admin"),
            root.path().to_path_buf(),
            scratch.join("admin"),
        ] {
            let raw = RawAdmin {
                state_dir: Some(path),
                ..RawAdmin::default()
            };
            assert!(
                AdminConfig::resolve(
                    raw,
                    root.path(),
                    &spool,
                    &scratch,
                    "127.0.0.1:0".parse().expect("listen")
                )
                .is_err()
            );
        }
        let config = AdminConfig::resolve(
            RawAdmin::default(),
            root.path(),
            &spool,
            &scratch,
            "127.0.0.1:0".parse().expect("listen"),
        )
        .expect("separate");
        assert_eq!(config.state_dir, root.path().join("spool.admin"));
        assert_eq!(
            config.origin_for_listener("127.0.0.1:12345".parse().expect("bound")),
            "http://127.0.0.1:12345"
        );
    }
}
