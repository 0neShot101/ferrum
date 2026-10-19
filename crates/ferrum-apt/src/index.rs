//! Streaming `Packages` index parsing (RFC-0001 §2).
//!
//! The index is framed stanza by stanza on blank lines with hard byte limits, and
//! each stanza is handed to `deb822-fast`'s borrowed parser. Only the owned fields
//! the catalog needs survive a stanza; the whole index is never resident in memory.

use std::io::BufRead;

use thiserror::Error;

use crate::digest::{DigestError, Sha256Digest};
use crate::path::{PathError, RepositoryPath};
use crate::release::{ParseLimits, reject_duplicate_fields};

/// Why a Packages index was rejected. Any error aborts the whole index: an
/// unparseable stanza is an inventory violation, never a silently dropped package.
#[derive(Debug, Error)]
pub enum IndexError {
    #[error("Packages stanza {stanza} exceeds the configured line or stanza limit")]
    TooLarge { stanza: usize },
    #[error("Packages stanza is not valid deb822: {0}")]
    Deb822(String),
    #[error("Packages stanza lacks required field {0}")]
    MissingField(&'static str),
    #[error("Packages stanza repeats security-relevant field {0}")]
    DuplicateField(String),
    #[error("Packages stanza has invalid Size: {0}")]
    InvalidSize(String),
    #[error("Packages Filename rejected: {0}")]
    Path(#[from] PathError),
    #[error("Packages SHA256 rejected: {0}")]
    Digest(#[from] DigestError),
    #[error("Packages index read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Packages consumer rejected a record: {0}")]
    Sink(String),
}

/// The fields of one binary package stanza that the catalog retains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRecord {
    pub package: String,
    pub version: String,
    pub architecture: String,
    /// Relative to the repository root, e.g.
    /// `pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb`.
    pub filename: RepositoryPath,
    pub size: u64,
    pub sha256: Sha256Digest,
}

const REQUIRED_FIELDS: [&str; 6] = [
    "Package",
    "Version",
    "Architecture",
    "Filename",
    "Size",
    "SHA256",
];

/// Parses a Packages index one stanza at a time, handing each record to `sink`.
///
/// Returns the number of records delivered. A line longer than `limits.max_line` or
/// a stanza longer than `limits.max_stanza` aborts with [`IndexError::TooLarge`];
/// a sink error aborts with that error unchanged.
///
/// # Errors
/// See [`IndexError`]. Missing `Package`/`Version`/`Architecture`/`Filename`/`Size`/
/// `SHA256`, or a case-insensitive repeat of one of them, rejects the stanza.
pub fn parse_packages<R: BufRead>(
    mut reader: R,
    limits: &ParseLimits,
    sink: &mut dyn FnMut(PackageRecord) -> Result<(), IndexError>,
) -> Result<usize, IndexError> {
    let mut stanza: Vec<u8> = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    let mut records: usize = 0;
    let mut stanzas: usize = 0;
    loop {
        line.clear();
        let reached_end = !read_line_bounded(&mut reader, &mut line, limits.max_line).map_err(
            |error| match error {
                LineError::TooLong => IndexError::TooLarge { stanza: stanzas },
                LineError::Io(error) => IndexError::Io(error),
            },
        )?;
        let separator = line.iter().all(u8::is_ascii_whitespace);
        if !separator {
            let next_length = stanza
                .len()
                .checked_add(line.len())
                .ok_or(IndexError::TooLarge { stanza: stanzas })?;
            if next_length > limits.max_stanza {
                return Err(IndexError::TooLarge { stanza: stanzas });
            }
            stanza.extend_from_slice(&line);
        }
        if (separator || reached_end) && !stanza.is_empty() {
            if let Some(record) = parse_stanza(&stanza)? {
                sink(record)?;
                records = records
                    .checked_add(1)
                    .ok_or(IndexError::Sink("record count overflow".to_owned()))?;
            }
            stanzas = stanzas
                .checked_add(1)
                .ok_or(IndexError::Sink("stanza count overflow".to_owned()))?;
            stanza.clear();
        }
        if reached_end {
            return Ok(records);
        }
    }
}

enum LineError {
    TooLong,
    Io(std::io::Error),
}

/// Appends one line (including its `\n`, if any) to `line`. Returns `false` at end of
/// input when nothing more was read. Never buffers more than `max_line` bytes.
fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max_line: usize,
) -> Result<bool, LineError> {
    loop {
        let available = reader.fill_buf().map_err(LineError::Io)?;
        if available.is_empty() {
            return Ok(!line.is_empty());
        }
        let (take, complete) = match available.iter().position(|&byte| byte == b'\n') {
            Some(position) => (position.checked_add(1).ok_or(LineError::TooLong)?, true),
            None => (available.len(), false),
        };
        let next_length = line.len().checked_add(take).ok_or(LineError::TooLong)?;
        if next_length > max_line {
            return Err(LineError::TooLong);
        }
        line.extend_from_slice(available.get(..take).unwrap_or(available));
        reader.consume(take);
        if complete {
            return Ok(true);
        }
    }
}

/// Parses one framed stanza; `None` when deb822 sees only comments or whitespace.
fn parse_stanza(stanza: &[u8]) -> Result<Option<PackageRecord>, IndexError> {
    let text = std::str::from_utf8(stanza)
        .map_err(|error| IndexError::Deb822(format!("invalid UTF-8: {error}")))?;
    let mut paragraphs = deb822_fast::borrowed::iter_paragraphs_borrowed(text);
    let Some(paragraph) = paragraphs.next() else {
        return Ok(None);
    };
    let paragraph = paragraph.map_err(|error| IndexError::Deb822(error.to_string()))?;
    if paragraphs.next().is_some() {
        return Err(IndexError::Deb822(
            "framed stanza produced more than one paragraph".to_owned(),
        ));
    }
    reject_duplicate_fields(&paragraph, &REQUIRED_FIELDS)
        .map_err(|name| IndexError::DuplicateField(name.to_owned()))?;

    let size_text = required(&paragraph, "Size")?;
    let size: u64 = size_text
        .parse()
        .map_err(|_| IndexError::InvalidSize(size_text.to_owned()))?;
    Ok(Some(PackageRecord {
        package: required(&paragraph, "Package")?.to_owned(),
        version: required(&paragraph, "Version")?.to_owned(),
        architecture: required(&paragraph, "Architecture")?.to_owned(),
        filename: RepositoryPath::parse_decoded(required(&paragraph, "Filename")?)?,
        size,
        sha256: Sha256Digest::from_hex(required(&paragraph, "SHA256")?)?,
    }))
}

fn required<'a>(
    paragraph: &deb822_fast::borrowed::BorrowedParagraph<'a>,
    name: &'static str,
) -> Result<&'a str, IndexError> {
    let field = paragraph
        .get_field(name)
        .ok_or(IndexError::MissingField(name))?;
    let value = field
        .as_single_line()
        .ok_or_else(|| IndexError::Deb822(format!("{name} must be a single line")))?
        .trim();
    if value.is_empty() {
        return Err(IndexError::MissingField(name));
    }
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const FIXTURE_PACKAGES: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/Packages"));

    const SHA256_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn stanza(extra: &str) -> String {
        format!(
            "Package: ferrum-fixture\nVersion: 1.0\nArchitecture: all\n\
             Filename: pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb\nSize: 1234\n\
             SHA256: {SHA256_A}\n{extra}"
        )
    }

    fn collect(input: &[u8], limits: &ParseLimits) -> Result<Vec<PackageRecord>, IndexError> {
        let mut records = Vec::new();
        parse_packages(input, limits, &mut |record| {
            records.push(record);
            Ok(())
        })?;
        Ok(records)
    }

    #[test]
    fn streams_fixture_index_with_two_stanzas() {
        let records = collect(FIXTURE_PACKAGES, &ParseLimits::default()).expect("fixture");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].package, "ferrum-fixture");
        assert_eq!(records[0].version, "1.0");
        assert_eq!(records[0].architecture, "all");
        assert_eq!(
            records[0].filename.as_str(),
            "pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb"
        );
        assert!(records[0].size > 0);
        assert_eq!(records[1].package, "ferrum-pacer");
        assert_eq!(
            records[1].filename.as_str(),
            "pool/main/f/ferrum-pacer/ferrum-pacer_1.0_all.deb"
        );
    }

    #[test]
    fn delivers_records_in_order_and_tolerates_blank_runs_and_missing_final_newline() {
        let input = format!(
            "\n\n{}\n\n\n{}",
            stanza("Description: first\n multi\n line\n"),
            stanza("")
                .replace("ferrum-fixture", "other-package")
                .trim_end()
        );
        let records = collect(input.as_bytes(), &ParseLimits::default()).expect("parse");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].package, "ferrum-fixture");
        assert_eq!(records[1].package, "other-package");
        assert_eq!(records[1].size, 1234);
        assert_eq!(
            records[1].sha256,
            Sha256Digest::from_hex(SHA256_A).expect("hex")
        );
    }

    #[test]
    fn returns_zero_for_empty_input() {
        let count = parse_packages(&b""[..], &ParseLimits::default(), &mut |_| Ok(()))
            .expect("empty index");
        assert_eq!(count, 0);
        let count = parse_packages(&b"\n\n"[..], &ParseLimits::default(), &mut |_| Ok(()))
            .expect("blank index");
        assert_eq!(count, 0);
    }

    #[test]
    fn rejects_missing_sha256() {
        let input = stanza("").replace(&format!("SHA256: {SHA256_A}\n"), "");
        assert!(matches!(
            collect(input.as_bytes(), &ParseLimits::default()),
            Err(IndexError::MissingField("SHA256"))
        ));
    }

    #[test]
    fn rejects_lowercase_duplicate_sha256() {
        let input = stanza(&format!("sha256: {SHA256_A}\n"));
        assert!(matches!(
            collect(input.as_bytes(), &ParseLimits::default()),
            Err(IndexError::DuplicateField(name)) if name == "SHA256"
        ));
    }

    #[test]
    fn rejects_bad_size_filename_and_digest() {
        let input = stanza("").replace("Size: 1234", "Size: 18446744073709551616");
        assert!(matches!(
            collect(input.as_bytes(), &ParseLimits::default()),
            Err(IndexError::InvalidSize(_))
        ));
        let input = stanza("").replace("Size: 1234", "Size: -1");
        assert!(matches!(
            collect(input.as_bytes(), &ParseLimits::default()),
            Err(IndexError::InvalidSize(_))
        ));
        let input = stanza("").replace("pool/main", "../pool/main");
        assert!(matches!(
            collect(input.as_bytes(), &ParseLimits::default()),
            Err(IndexError::Path(PathError::DotSegment))
        ));
        let input = stanza("").replace(SHA256_A, "abc");
        assert!(matches!(
            collect(input.as_bytes(), &ParseLimits::default()),
            Err(IndexError::Digest(DigestError::InvalidLength { .. }))
        ));
    }

    #[test]
    fn rejects_oversized_stanza_and_line_without_dropping_earlier_records() {
        let limits = ParseLimits {
            max_line: 256,
            max_stanza: 512,
            max_release: 1024,
        };
        // Two 210-byte lines stay under max_line but push the stanza past max_stanza.
        let big_stanza = stanza(&format!(
            "X-Long-A: {}\nX-Long-B: {}\n",
            "x".repeat(200),
            "x".repeat(200)
        ));
        let input = format!("{}\n{}\n{}", stanza(""), big_stanza, stanza(""));
        let mut delivered = 0usize;
        let error = parse_packages(input.as_bytes(), &limits, &mut |_| {
            delivered += 1;
            Ok(())
        })
        .expect_err("second stanza exceeds the limit");
        assert!(
            matches!(error, IndexError::TooLarge { stanza: 1 }),
            "{error}"
        );
        assert_eq!(delivered, 1);

        let long_line = stanza(&format!("Description: {}\n", "y".repeat(300)));
        let error = collect(long_line.as_bytes(), &limits).expect_err("line exceeds the limit");
        assert!(
            matches!(error, IndexError::TooLarge { stanza: 0 }),
            "{error}"
        );
    }

    #[test]
    fn sink_errors_abort_the_index() {
        let input = format!("{}\n{}", stanza(""), stanza(""));
        let error = parse_packages(input.as_bytes(), &ParseLimits::default(), &mut |_| {
            Err(IndexError::Sink("full".to_owned()))
        })
        .expect_err("sink refused");
        assert!(matches!(error, IndexError::Sink(message) if message == "full"));
    }
}
