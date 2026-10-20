//! Authenticated PDiff closure parsing. The caller must authenticate Index bytes
//! against Release before using these descriptors. Only gzip patch downloads are
//! admitted; unsupported or incomplete histories must use the full index instead.

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader, Read};

use crate::digest::{ObjectIdentity, Sha256Digest, Sha256Hasher};

pub const MAX_INDEX_BYTES: usize = 1024 * 1024;
pub const MAX_INDEXES: usize = 32;
pub const MAX_PATCHES: usize = 64;
pub const MAX_DOWNLOAD_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PATCH_BYTES: u64 = 64 * 1024 * 1024;
// Include expanded bytes to bound decompression work, not just network traffic.
pub const MAX_CLOSURE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SUITE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PdiffError {
    #[error("invalid or unsupported PDiff Index")]
    Invalid,
    #[error("PDiff exceeds bounded resource limits")]
    Limit,
    #[error("PDiff patch checksum or size mismatch")]
    Checksum,
    #[error("invalid reversed restricted ed patch")]
    Patch,
    #[error("reading PDiff patch: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct Patch {
    pub name: String,
    pub history: ObjectIdentity,
    pub expanded: ObjectIdentity,
    pub download: ObjectIdentity,
}

#[derive(Debug)]
pub struct Index {
    pub current: ObjectIdentity,
    pub patches: Vec<Patch>,
}

fn identity<'a>(words: &mut impl Iterator<Item = &'a str>) -> Result<ObjectIdentity, PdiffError> {
    let digest = words.next().ok_or(PdiffError::Invalid)?;
    let size = words.next().ok_or(PdiffError::Invalid)?;
    if size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PdiffError::Invalid);
    }
    Ok(ObjectIdentity {
        sha256: Sha256Digest::from_hex(digest).map_err(|_| PdiffError::Invalid)?,
        size: size.parse().map_err(|_| PdiffError::Limit)?,
    })
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && !name.contains("..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

/// Recognizes syntax only, never grants authority. Serving still requires a
/// generation proof rooted in the signed Release and the exact Index closure.
pub fn is_patch_path(path: &str) -> bool {
    path.rsplit_once(".diff/")
        .is_some_and(|(_, name)| name.strip_suffix(".gz").is_some_and(safe_name))
}

impl Index {
    /// Parse one authenticated control stanza, bound its complete patch closure,
    /// and require its final expanded identity to match the signed full index.
    pub fn parse(bytes: &[u8], expected: ObjectIdentity) -> Result<Self, PdiffError> {
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(PdiffError::Limit);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| PdiffError::Invalid)?;
        if text.bytes().any(|byte| byte == 0 || byte == b'\r') {
            return Err(PdiffError::Invalid);
        }
        let mut fields = BTreeMap::<String, String>::new();
        let mut field = None;
        let mut ended = false;
        for line in text.lines() {
            if line.len() > MAX_LINE_BYTES {
                return Err(PdiffError::Limit);
            }
            if line.is_empty() {
                ended = true;
                continue;
            }
            if ended {
                return Err(PdiffError::Invalid);
            }
            if line.starts_with([' ', '\t']) {
                let key = field.as_ref().ok_or(PdiffError::Invalid)?;
                let value = fields.get_mut(key).ok_or(PdiffError::Invalid)?;
                value.push('\n');
                value.push_str(line.trim());
            } else {
                let (name, value) = line.split_once(':').ok_or(PdiffError::Invalid)?;
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                {
                    return Err(PdiffError::Invalid);
                }
                let name = name.to_ascii_lowercase();
                if fields
                    .insert(name.clone(), value.trim().to_owned())
                    .is_some()
                {
                    return Err(PdiffError::Invalid);
                }
                field = Some(name);
            }
        }
        let get = |name: &str| {
            fields
                .get(name)
                .map(String::as_str)
                .ok_or(PdiffError::Invalid)
        };
        let mut words = get("sha256-current")?.split_ascii_whitespace();
        let current = identity(&mut words)?;
        if words.next().is_some() || current != expected {
            return Err(PdiffError::Checksum);
        }
        if fields
            .get("x-patch-precedence")
            .is_some_and(|value| value != "merged")
        {
            return Err(PdiffError::Invalid);
        }
        let table = |name: &str, limit: u64, gzip: bool| {
            let mut entries = BTreeMap::new();
            let mut order = Vec::new();
            for line in get(name)?.lines().filter(|line| !line.is_empty()) {
                let mut words = line.split_ascii_whitespace();
                let value = identity(&mut words)?;
                let file = words.next().ok_or(PdiffError::Invalid)?;
                let base = if gzip {
                    file.strip_suffix(".gz").ok_or(PdiffError::Invalid)?
                } else {
                    file
                };
                if words.next().is_some() || !safe_name(base) {
                    return Err(PdiffError::Invalid);
                }
                if value.size > limit || entries.len() >= MAX_PATCHES {
                    return Err(PdiffError::Limit);
                }
                if entries.insert(base.to_owned(), value).is_some() {
                    return Err(PdiffError::Invalid);
                }
                order.push(base.to_owned());
            }
            Ok::<_, PdiffError>((entries, order))
        };
        let (history, order) = table("sha256-history", u64::MAX, false)?;
        let (expanded, _) = table("sha256-patches", MAX_PATCH_BYTES, false)?;
        let (downloads, _) = table("sha256-download", MAX_DOWNLOAD_BYTES, true)?;
        if history.len() != expanded.len() || history.len() != downloads.len() {
            return Err(PdiffError::Invalid);
        }
        let mut patches = Vec::with_capacity(history.len());
        let mut total = 0u64;
        let mut states = HashSet::new();
        for name in order {
            let history = *history.get(&name).ok_or(PdiffError::Invalid)?;
            if !states.insert(history) {
                return Err(PdiffError::Invalid);
            }
            let expanded = *expanded.get(&name).ok_or(PdiffError::Invalid)?;
            let download = *downloads.get(&name).ok_or(PdiffError::Invalid)?;
            total = total
                .checked_add(download.size)
                .and_then(|size| size.checked_add(expanded.size))
                .ok_or(PdiffError::Limit)?;
            if total > MAX_CLOSURE_BYTES {
                return Err(PdiffError::Limit);
            }
            patches.push(Patch {
                name,
                history,
                expanded,
                download,
            });
        }
        Ok(Self { current, patches })
    }
}

/// Authenticate expanded bytes while validating rred's descending a/c/d grammar.
/// Does not apply patches: stock APT checks application against SHA256-Current.
/// A line buffer and a decoder supplied by the caller are the only payload memory.
pub fn verify_patch(reader: impl Read, expected: ObjectIdentity) -> Result<(), PdiffError> {
    if expected.size > MAX_PATCH_BYTES {
        return Err(PdiffError::Limit);
    }
    let mut reader = BufReader::new(reader);
    let mut hash = Sha256Hasher::new();
    let mut size = 0u64;
    let mut line = Vec::new();
    let mut body = false;
    let mut previous = u64::MAX;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        let count = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |i| i + 1);
        size = size.checked_add(count as u64).ok_or(PdiffError::Limit)?;
        if size > expected.size || line.len() + count > MAX_LINE_BYTES {
            return Err(PdiffError::Limit);
        }
        hash.update(&buffer[..count]);
        line.extend_from_slice(&buffer[..count]);
        let complete = line.last() == Some(&b'\n');
        reader.consume(count);
        if !complete {
            continue;
        }
        if line.contains(&0) {
            return Err(PdiffError::Patch);
        }
        if body {
            if line == b".\n" {
                body = false;
            }
        } else {
            let command =
                std::str::from_utf8(&line[..line.len() - 1]).map_err(|_| PdiffError::Patch)?;
            if !command.is_ascii() {
                return Err(PdiffError::Patch);
            }
            let (numbers, operation) =
                command.split_at(command.len().checked_sub(1).ok_or(PdiffError::Patch)?);
            let number = |text: &str| -> Result<u64, PdiffError> {
                if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(PdiffError::Patch);
                }
                text.parse().map_err(|_| PdiffError::Patch)
            };
            let (start, end) = match numbers.split_once(',') {
                Some((start, end)) => (number(start)?, number(end)?),
                None => {
                    let value = number(numbers)?;
                    (value, value)
                }
            };
            if end < start || start > previous || (start == 0 && operation != "a") {
                return Err(PdiffError::Patch);
            }
            previous = if operation == "a" { start } else { start - 1 };
            body = match operation {
                "a" | "c" => true,
                "d" => false,
                _ => return Err(PdiffError::Patch),
            };
        }
        line.clear();
    }
    if body || !line.is_empty() {
        return Err(PdiffError::Patch);
    }
    if size != expected.size || hash.finalize() != expected.sha256 {
        return Err(PdiffError::Checksum);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn identity(bytes: &[u8]) -> ObjectIdentity {
        ObjectIdentity {
            sha256: Sha256Digest::of(bytes),
            size: bytes.len() as u64,
        }
    }

    fn index(name: &str) -> String {
        let current = identity(b"new\n");
        let old = identity(b"old\n");
        let patch = identity(b"1c\nnew\n.\n");
        format!(
            "SHA256-Current: {} {}\nSHA256-History:\n {} {} {name}\nSHA256-Patches:\n {} {} {name}\nSHA256-Download:\n {} {} {name}.gz\n",
            current.sha256,
            current.size,
            old.sha256,
            old.size,
            patch.sha256,
            patch.size,
            patch.sha256,
            patch.size
        )
    }

    #[test]
    fn authenticated_closure_requires_exact_current_and_safe_complete_names() {
        assert_eq!(
            Index::parse(index("2026-01").as_bytes(), identity(b"new\n"))
                .expect("complete authenticated patch closure")
                .patches
                .len(),
            1
        );
        for name in ["../escape", "a/b", "%2f", "a..b", "", "a\\b"] {
            assert!(
                Index::parse(index(name).as_bytes(), identity(b"new\n")).is_err(),
                "{name}"
            );
        }
        assert!(Index::parse(index("p").as_bytes(), identity(b"other\n")).is_err());
        let incomplete = index("p").replace("p.gz", "different.gz");
        assert!(Index::parse(incomplete.as_bytes(), identity(b"new\n")).is_err());
        let duplicate = format!(
            "{}SHA256-Current: {} 4\n",
            index("p"),
            identity(b"new\n").sha256
        );
        assert!(Index::parse(duplicate.as_bytes(), identity(b"new\n")).is_err());
    }

    #[test]
    fn rred_accepts_reversed_commands_but_not_malformed_or_mismatched_bytes() {
        for patch in [
            b"1c\nnew\n.\n".as_slice(),
            b"9d\n3,4c\nx\n.\n0a\nfirst\n.\n",
            b"",
        ] {
            verify_patch(patch, identity(patch)).expect("valid reverse-ordered patch");
        }
        for patch in [
            b"1c\nnew\n".as_slice(),
            b"0d\n",
            b"1d\n2d\n",
            b"1w\n",
            b"1d",
            b"9,2d\n",
        ] {
            assert!(verify_patch(patch, identity(patch)).is_err());
        }
        assert!(verify_patch(b"1d\n".as_slice(), identity(b"2d\n")).is_err());
    }

    #[test]
    fn bounded_inputs_and_unsupported_representations_fail_closed() {
        let current = identity(b"new\n");
        let oversized = vec![b' '; MAX_INDEX_BYTES + 1];
        assert!(matches!(
            Index::parse(&oversized, current),
            Err(PdiffError::Limit)
        ));
        let unsupported = index("p").replace("p.gz", "p.xz");
        assert!(Index::parse(unsupported.as_bytes(), current).is_err());
        let oversized_download =
            index("p").replace(" 9 p.gz", &format!(" {} p.gz", MAX_DOWNLOAD_BYTES + 1));
        assert!(Index::parse(oversized_download.as_bytes(), current).is_err());
        let unicode = "1\u{00e9}\n".as_bytes();
        assert!(verify_patch(unicode, identity(unicode)).is_err());
        let long_line = vec![b'1'; MAX_LINE_BYTES + 1];
        assert!(verify_patch(long_line.as_slice(), identity(&long_line)).is_err());
    }
}
