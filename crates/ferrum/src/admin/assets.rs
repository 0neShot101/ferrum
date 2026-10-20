//! Immutable, bounded UI bundle loaded before accepting HTTP requests.
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ferrum_apt::digest::Sha256Hasher;

pub(super) struct Assets {
    files: BTreeMap<String, Asset>,
    pub(super) csp: String,
}
struct Asset {
    bytes: Bytes,
    content_type: &'static str,
}
impl Assets {
    pub(super) fn load() -> Result<Self, String> {
        let mut assets = Self {
            files: BTreeMap::new(),
            csp: "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; script-src 'self'; style-src 'self'".into(),
        };
        let Some(root) = locate_bundle() else {
            return Ok(assets);
        };
        let mut remaining = 64 * 1024 * 1024;
        let mut entries = 1024;
        assets.read_directory(&root, &root, 0, &mut remaining, &mut entries)?;
        if let Some(index) = assets.files.get("index.html") {
            let html = std::str::from_utf8(&index.bytes).map_err(|_| "Admin index is not UTF-8")?;
            let scripts = inline_hashes(html, "script")?;
            let styles = inline_hashes(html, "style")?;
            assets.csp = format!(
                "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; script-src 'self'{scripts}; style-src 'self'{styles}"
            );
        }
        Ok(assets)
    }
    fn read_directory(
        &mut self,
        root: &Path,
        directory: &Path,
        depth: usize,
        remaining: &mut usize,
        entries: &mut usize,
    ) -> Result<(), String> {
        if depth > 16
            || std::fs::symlink_metadata(directory)
                .map_err(|_| "Cannot inspect admin bundle")?
                .file_type()
                .is_symlink()
        {
            return Err("Unsafe admin bundle directory".into());
        }
        for entry in std::fs::read_dir(directory).map_err(|_| "Cannot read admin bundle")? {
            let entry = entry.map_err(|_| "Cannot read admin bundle entry")?;
            *entries = entries
                .checked_sub(1)
                .ok_or("Admin bundle exceeds entry limit")?;
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|_| "Cannot inspect admin asset")?;
            if metadata.file_type().is_symlink() {
                return Err("Symlink in admin bundle".into());
            }
            if metadata.is_dir() {
                self.read_directory(root, &entry.path(), depth + 1, remaining, entries)?;
                continue;
            }
            if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 || self.files.len() >= 512 {
                return Err("Admin bundle exceeds file limits".into());
            }
            let size = usize::try_from(metadata.len()).map_err(|_| "Admin asset too large")?;
            *remaining = remaining
                .checked_sub(size)
                .ok_or("Admin bundle exceeds memory limit")?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "Invalid admin asset path")?;
            let name = relative
                .to_str()
                .ok_or("Invalid admin asset name")?
                .replace('\\', "/");
            // The directory is host-owned and only read at startup. Never resolve a browser path here.
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            let file = options.open(&path).map_err(|_| "Cannot open admin asset")?;
            let mut bytes = Vec::with_capacity(size);
            file.take(size as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Cannot load admin asset")?;
            if bytes.len() != size {
                return Err("Admin asset changed during loading".into());
            }
            self.files.insert(
                name,
                Asset {
                    bytes: Bytes::from(bytes),
                    content_type: content_type(&path),
                },
            );
        }
        Ok(())
    }
    pub(super) fn serve(&self, path: &str) -> Response {
        let name = path.trim_start_matches('/');
        if name.starts_with("api/") || name == "api" || name == "sync" || name.starts_with("sync/")
        {
            return super::routes::error_reply(
                StatusCode::NOT_FOUND,
                "not_found",
                "Unknown endpoint.",
            );
        }
        if name.contains(['\\', '%', '\0'])
            || (!name.is_empty()
                && Path::new(name)
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_))))
        {
            return super::routes::error_reply(
                StatusCode::BAD_REQUEST,
                "invalid_path",
                "Invalid asset path.",
            );
        }
        let asset = self
            .files
            .get(if name.is_empty() { "index.html" } else { name })
            .or_else(|| {
                if !name.contains('.') {
                    self.files.get("index.html")
                } else {
                    None
                }
            });
        match asset {
            Some(asset) => (
                [(header::CONTENT_TYPE, asset.content_type)],
                asset.bytes.clone(),
            )
                .into_response(),
            None if self.files.is_empty() => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Admin UI bundle unavailable; build ui/ before startup.",
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }
}
fn locate_bundle() -> Option<PathBuf> {
    if let Some(custom) = std::env::var_os("FERRUM_UI_DIR") {
        return Some(custom.into());
    }
    let cwd = PathBuf::from("ui/build");
    if cwd.join("index.html").is_file() {
        return Some(cwd);
    }
    let exe = std::env::current_exe().ok()?;
    exe.ancestors()
        .take(5)
        .map(|ancestor| ancestor.join("ui/build"))
        .find(|path| path.join("index.html").is_file())
}
fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}
fn inline_hashes(html: &str, tag: &str) -> Result<String, String> {
    let mut result = String::new();
    let opener = format!("<{tag}");
    let closer = format!("</{tag}>");
    let mut rest = html;
    let mut count = 0;
    while let Some(start) = rest.find(&opener) {
        count += 1;
        if count > 64 {
            return Err("Too many inline blocks in admin HTML".into());
        }
        rest = &rest[start + opener.len()..];
        let end = rest.find('>').ok_or("Malformed admin HTML")?;
        rest = &rest[end + 1..];
        let close = rest.find(&closer).ok_or("Malformed admin HTML")?;
        let contents = &rest[..close];
        if !contents.is_empty() {
            let mut hash = Sha256Hasher::new();
            hash.update(contents.as_bytes());
            result.push_str(" 'sha256-");
            result.push_str(&base64(hash.finalize().as_bytes()));
            result.push('\'');
        }
        rest = &rest[close + closer.len()..];
    }
    Ok(result)
}
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        result.push(ALPHABET[((bits >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((bits >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 {
            ALPHABET[((bits >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            ALPHABET[(bits & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn inline_csp_hashes_match_browser_encoding() {
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(
            inline_hashes("<script>abc</script>", "script").unwrap(),
            " 'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0='"
        );
    }
}
