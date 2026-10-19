//! Validated relative repository paths (RFC-0001 §3.2).
//!
//! A [`RepositoryPath`] is stored decoded, uses `/` as the only separator and never
//! has a leading or trailing separator, empty segment, `.`/`..` segment, backslash
//! or control byte. Untrusted request targets are decoded exactly once; encoded
//! separators are rejected rather than decoded so that an encoded `/` can never
//! change the segment structure. The same rules validate `Filename` fields and
//! Release table paths, so every path that reaches storage or URL building has
//! passed through one parser.

use std::fmt;

use percent_encoding::percent_decode_str;
use thiserror::Error;

/// Maximum accepted length in bytes, both for the raw request target and for the
/// decoded path (§3.1: longer paths answer 414).
pub const MAX_PATH_BYTES: usize = 8 * 1024;

/// Why a path was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PathError {
    #[error("path is empty")]
    Empty,
    #[error("path contains malformed percent-encoding")]
    MalformedEncoding,
    #[error("path contains a percent-encoded separator")]
    EncodedSeparator,
    #[error("path contains forbidden byte 0x{0:02x}")]
    ForbiddenByte(u8),
    #[error("path contains an empty segment")]
    EmptySegment,
    #[error("path contains a '.' or '..' segment")]
    DotSegment,
    #[error("path ends with a separator")]
    TrailingSeparator,
    #[error("path exceeds {MAX_PATH_BYTES} bytes")]
    TooLong,
}

/// A validated relative repository path such as `dists/ferrum-test/InRelease`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepositoryPath(String);

impl RepositoryPath {
    /// Validates an already-decoded path (Packages `Filename`, Release table
    /// entries, configuration).
    ///
    /// # Errors
    /// Any [`PathError`] except the encoding variants.
    pub fn parse_decoded(text: &str) -> Result<Self, PathError> {
        validate_decoded(text)?;
        Ok(Self(text.to_owned()))
    }

    /// Validates a raw percent-encoded request target without its leading `/`.
    ///
    /// Decodes exactly once. Malformed `%XX`, encoded `/` or `\`, invalid UTF-8
    /// after decoding and every decoded-form rule are rejected.
    ///
    /// # Errors
    /// Any [`PathError`].
    pub fn parse_request_target(raw: &str) -> Result<Self, PathError> {
        if raw.is_empty() {
            return Err(PathError::Empty);
        }
        if raw.len() > MAX_PATH_BYTES {
            return Err(PathError::TooLong);
        }
        check_percent_escapes(raw.as_bytes())?;
        let decoded = percent_decode_str(raw)
            .decode_utf8()
            .map_err(|_| PathError::MalformedEncoding)?;
        validate_decoded(&decoded)?;
        Ok(Self(decoded.into_owned()))
    }

    /// The decoded path text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Path segments in order; never empty and never containing an empty segment.
    pub fn segments(&self) -> std::str::Split<'_, char> {
        self.0.split('/')
    }

    /// The remainder after `<prefix>/`, or `None` when `prefix` is not a proper
    /// segment-aligned ancestor of this path.
    pub fn strip_prefix(&self, prefix: &RepositoryPath) -> Option<&str> {
        self.0
            .strip_prefix(prefix.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
    }

    /// Appends `child` (validated with [`Self::parse_decoded`] rules) below this path.
    ///
    /// # Errors
    /// Any [`PathError`] from validating `child`, or [`PathError::TooLong`] when the
    /// combined path exceeds [`MAX_PATH_BYTES`].
    pub fn join(&self, child: &str) -> Result<Self, PathError> {
        validate_decoded(child)?;
        let length = self
            .0
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(child.len()))
            .ok_or(PathError::TooLong)?;
        if length > MAX_PATH_BYTES {
            return Err(PathError::TooLong);
        }
        let mut joined = String::with_capacity(length);
        joined.push_str(&self.0);
        joined.push('/');
        joined.push_str(child);
        Ok(Self(joined))
    }

    /// Splits into `(parent, file name)`; the parent is `None` for a single segment.
    pub fn split_last(&self) -> (Option<&str>, &str) {
        match self.0.rsplit_once('/') {
            Some((parent, name)) => (Some(parent), name),
            None => (None, &self.0),
        }
    }
}

impl fmt::Display for RepositoryPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for RepositoryPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RepositoryPath({:?})", self.0)
    }
}

impl AsRef<str> for RepositoryPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Every `%` must introduce two hex digits, and the encoded byte must not be a
/// separator: decoding `%2F` would silently add a segment boundary.
fn check_percent_escapes(raw: &[u8]) -> Result<(), PathError> {
    let mut index = 0;
    while index < raw.len() {
        if raw[index] != b'%' {
            index = index.checked_add(1).ok_or(PathError::TooLong)?;
            continue;
        }
        let high = raw.get(index.wrapping_add(1)).copied();
        let low = raw.get(index.wrapping_add(2)).copied();
        let (Some(high), Some(low)) = (high, low) else {
            return Err(PathError::MalformedEncoding);
        };
        let (Some(high), Some(low)) = (hex_value(high), hex_value(low)) else {
            return Err(PathError::MalformedEncoding);
        };
        let byte = (high << 4) | low;
        if byte == b'/' || byte == b'\\' {
            return Err(PathError::EncodedSeparator);
        }
        index = index.checked_add(3).ok_or(PathError::TooLong)?;
    }
    Ok(())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn validate_decoded(text: &str) -> Result<(), PathError> {
    if text.is_empty() {
        return Err(PathError::Empty);
    }
    if text.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    for byte in text.bytes() {
        if byte < 0x20 || byte == 0x7F || byte == b'\\' {
            return Err(PathError::ForbiddenByte(byte));
        }
    }
    if text.ends_with('/') {
        return Err(PathError::TrailingSeparator);
    }
    for segment in text.split('/') {
        match segment {
            "" => return Err(PathError::EmptySegment),
            "." | ".." => return Err(PathError::DotSegment),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn request_targets_are_decoded_once_and_validated() {
        let accepted = [
            ("dists/ferrum-test/InRelease", "dists/ferrum-test/InRelease"),
            (
                "pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb",
                "pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb",
            ),
            ("a/b%20c", "a/b c"),
            ("a/%25", "a/%"),
            ("a/%2525", "a/%25"),
            ("a/caf%C3%A9", "a/café"),
            ("a/...", "a/..."),
            ("a/.hidden", "a/.hidden"),
            ("by-hash/SHA256/%41", "by-hash/SHA256/A"),
        ];
        for (raw, decoded) in accepted {
            let path = RepositoryPath::parse_request_target(raw).expect(raw);
            assert_eq!(path.as_str(), decoded, "{raw}");
        }

        let rejected = [
            ("", PathError::Empty),
            ("a%2Fb", PathError::EncodedSeparator),
            ("a%2fb", PathError::EncodedSeparator),
            ("a%5Cb", PathError::EncodedSeparator),
            ("a%5cb", PathError::EncodedSeparator),
            ("a%2", PathError::MalformedEncoding),
            ("a%", PathError::MalformedEncoding),
            ("a%zzb", PathError::MalformedEncoding),
            ("a%C3%28", PathError::MalformedEncoding),
            ("a/../b", PathError::DotSegment),
            ("../a", PathError::DotSegment),
            ("a/..", PathError::DotSegment),
            ("a/./b", PathError::DotSegment),
            (".", PathError::DotSegment),
            ("a/%2e%2e/b", PathError::DotSegment),
            ("a//b", PathError::EmptySegment),
            ("/a", PathError::EmptySegment),
            ("a/", PathError::TrailingSeparator),
            ("/", PathError::TrailingSeparator),
            ("a/b\\c", PathError::ForbiddenByte(b'\\')),
            ("a/b%00c", PathError::ForbiddenByte(0)),
            ("a/b%7fc", PathError::ForbiddenByte(0x7F)),
            ("a/b%1fc", PathError::ForbiddenByte(0x1F)),
            ("a/b\tc", PathError::ForbiddenByte(b'\t')),
            ("a\nb", PathError::ForbiddenByte(b'\n')),
        ];
        for (raw, error) in rejected {
            assert_eq!(
                RepositoryPath::parse_request_target(raw),
                Err(error),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn overlong_paths_are_rejected_before_decoding() {
        let longest = "a".repeat(MAX_PATH_BYTES);
        assert!(RepositoryPath::parse_request_target(&longest).is_ok());
        let overlong = "a".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(
            RepositoryPath::parse_request_target(&overlong),
            Err(PathError::TooLong)
        );
        assert_eq!(
            RepositoryPath::parse_decoded(&overlong),
            Err(PathError::TooLong)
        );
        let encoded_overlong = "%41".repeat(MAX_PATH_BYTES / 3 + 1);
        assert_eq!(
            RepositoryPath::parse_request_target(&encoded_overlong),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn decoded_paths_keep_percent_literal() {
        let path = RepositoryPath::parse_decoded("a/%2F").expect("literal percent is a plain byte");
        assert_eq!(path.as_str(), "a/%2F");
        assert_eq!(
            RepositoryPath::parse_decoded("a/b/"),
            Err(PathError::TrailingSeparator)
        );
        assert_eq!(
            RepositoryPath::parse_decoded("a\\b"),
            Err(PathError::ForbiddenByte(b'\\'))
        );
        assert_eq!(RepositoryPath::parse_decoded(""), Err(PathError::Empty));
    }

    #[test]
    fn prefix_join_and_split_follow_segment_boundaries() {
        let base = RepositoryPath::parse_decoded("dists/ferrum-test").expect("base");
        let child = base.join("main/binary-amd64/Packages").expect("join");
        assert_eq!(
            child.as_str(),
            "dists/ferrum-test/main/binary-amd64/Packages"
        );
        assert_eq!(
            child.strip_prefix(&base),
            Some("main/binary-amd64/Packages")
        );
        let sibling = RepositoryPath::parse_decoded("dists/ferrum-tests/x").expect("sibling");
        assert_eq!(sibling.strip_prefix(&base), None);
        assert_eq!(base.strip_prefix(&base), None);
        assert_eq!(
            child.split_last(),
            (Some("dists/ferrum-test/main/binary-amd64"), "Packages")
        );
        let single = RepositoryPath::parse_decoded("InRelease").expect("single");
        assert_eq!(single.split_last(), (None, "InRelease"));
        assert_eq!(base.join("../x"), Err(PathError::DotSegment));
        assert_eq!(base.join("/x"), Err(PathError::EmptySegment));
        assert_eq!(base.join(""), Err(PathError::Empty));
        let filler = "b".repeat(MAX_PATH_BYTES - base.as_str().len());
        assert_eq!(base.join(&filler), Err(PathError::TooLong));
        assert_eq!(
            child.segments().collect::<Vec<_>>(),
            ["dists", "ferrum-test", "main", "binary-amd64", "Packages"]
        );
    }
}
