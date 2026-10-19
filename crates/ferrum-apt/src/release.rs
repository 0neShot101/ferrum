//! Authenticated `Release` descriptor parsing (RFC-0001 §2, §6).
//!
//! The input is the exact byte sequence that the signature verifier returned; the
//! parser never sees unverified bytes. deb822 framing comes from `deb822-fast`;
//! this module only interprets the fields the trust chain depends on.

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::digest::{DigestError, Sha256Digest, Sha512Digest};
use crate::path::{PathError, RepositoryPath};

/// Byte limits for control-file parsing (§2: 1 MiB line, 8 MiB stanza, 32 MiB Release).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    /// Longest accepted single line of a Packages index.
    pub max_line: usize,
    /// Largest accepted Packages stanza including its blank-line terminator.
    pub max_stanza: usize,
    /// Largest accepted authenticated Release document.
    pub max_release: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_line: 1024 * 1024,
            max_stanza: 8 * 1024 * 1024,
            max_release: 32 * 1024 * 1024,
        }
    }
}

/// Why a Release document was rejected.
#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("Release exceeds the configured size limit")]
    TooLarge,
    #[error("Release is not valid deb822: {0}")]
    Deb822(String),
    #[error("Release lacks required field {0}")]
    MissingField(&'static str),
    #[error("Release repeats security-relevant field {0}")]
    DuplicateField(String),
    #[error("Release date is invalid: {0}")]
    InvalidDate(String),
    #[error("Release hash entry is invalid: {0}")]
    InvalidEntry(String),
    #[error("Release lists conflicting sizes for {0}")]
    SizeConflict(String),
    #[error("Release entry path rejected: {0}")]
    Path(#[from] PathError),
    #[error("Release digest rejected: {0}")]
    Digest(#[from] DigestError),
    #[error("Release must be exactly one deb822 paragraph")]
    NotSingleParagraph,
}

/// Seconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(i64);

/// Longest `Date`/`Valid-Until` value the tokenizer will inspect.
const MAX_DATE_BYTES: usize = 64;

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const ZONES: [&str; 6] = ["UTC", "GMT", "UT", "Z", "+0000", "-0000"];

impl UnixTime {
    /// The current system time.
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => Self(i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)),
            Err(before_epoch) => Self(
                i64::try_from(before_epoch.duration().as_secs())
                    .map(|seconds| seconds.checked_neg().unwrap_or(i64::MIN))
                    .unwrap_or(i64::MIN),
            ),
        }
    }

    /// Wraps a raw second count.
    pub fn from_secs(seconds: i64) -> Self {
        Self(seconds)
    }

    /// Parses the RFC 1123 form APT writes: `Sat, 17 Oct 2026 12:00:00 UTC`.
    ///
    /// The weekday is optional; day may have one or two digits; the zone must be
    /// `UTC`, `GMT`, `UT`, `Z`, `+0000` or `-0000`. Calendar validity is enforced.
    ///
    /// # Errors
    /// [`ReleaseError::InvalidDate`] with the offending text.
    pub fn parse_release_date(text: &str) -> Result<Self, ReleaseError> {
        parse_release_date(text).ok_or_else(|| ReleaseError::InvalidDate(text.to_owned()))
    }

    /// Seconds since the epoch.
    pub fn as_secs(&self) -> i64 {
        self.0
    }

    /// Formats as `Sat, 17 Oct 2026 12:00:00 UTC`.
    pub fn to_rfc1123(&self) -> String {
        let days = self.0.div_euclid(86_400);
        let second_of_day = self.0.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        // 1970-01-01 was a Thursday; index 3 in WEEKDAYS (Monday-based).
        let weekday_index = (days.checked_add(3).unwrap_or(3)).rem_euclid(7);
        let weekday = WEEKDAYS
            .get(usize::try_from(weekday_index).unwrap_or(0))
            .copied()
            .unwrap_or("Thu");
        let month_name = MONTHS
            .get(usize::try_from(month.saturating_sub(1)).unwrap_or(0))
            .copied()
            .unwrap_or("Jan");
        format!(
            "{weekday}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} UTC",
            second_of_day / 3600,
            (second_of_day / 60) % 60,
            second_of_day % 60
        )
    }
}

impl fmt::Display for UnixTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_rfc1123())
    }
}

fn parse_release_date(text: &str) -> Option<UnixTime> {
    if text.len() > MAX_DATE_BYTES {
        return None;
    }
    let mut tokens = text.split_ascii_whitespace();
    let mut token = tokens.next()?;
    if let Some(weekday) = token.strip_suffix(',') {
        if !WEEKDAYS
            .iter()
            .any(|name| name.eq_ignore_ascii_case(weekday))
        {
            return None;
        }
        token = tokens.next()?;
    }
    let day = parse_number(token, 1, 2)?;
    let month_name = tokens.next()?;
    let month_index = MONTHS
        .iter()
        .position(|name| name.eq_ignore_ascii_case(month_name))?;
    let month = i64::try_from(month_index).ok()?.checked_add(1)?;
    let year = parse_number(tokens.next()?, 4, 4)?;
    let mut clock = tokens.next()?.split(':');
    let hour = parse_number(clock.next()?, 1, 2)?;
    let minute = parse_number(clock.next()?, 2, 2)?;
    let second = parse_number(clock.next()?, 2, 2)?;
    if clock.next().is_some() {
        return None;
    }
    let zone = tokens.next()?;
    if !ZONES.iter().any(|name| name.eq_ignore_ascii_case(zone)) {
        return None;
    }
    if tokens.next().is_some() {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 || day < 1 || day > days_in_month(year, month)? {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    Some(UnixTime(seconds))
}

fn parse_number(token: &str, min_digits: usize, max_digits: usize) -> Option<i64> {
    if token.len() < min_digits || token.len() > max_digits {
        return None;
    }
    if !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> Option<i64> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = if month > 2 {
        month.checked_sub(3)?
    } else {
        month.checked_add(9)?
    };
    let day_of_year = shifted_month
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?
        .checked_add(day_of_year)?;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

/// Inverse of [`days_from_civil`]; saturates instead of overflowing for absurd inputs.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days.saturating_add(719_468);
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(month <= 2));
    (year, month, day)
}

/// One file listed in the Release hash tables; `path` is relative to `dists/<suite>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseEntry {
    /// Canonical advertised path, including paths listed only with weak hashes.
    pub path: RepositoryPath,
    pub size: u64,
    /// Only SHA-2 digests are retained; weak-only advertisements have neither.
    pub sha256: Option<Sha256Digest>,
    pub sha512: Option<Sha512Digest>,
}

/// Authenticated Release descriptor.
#[derive(Debug, Clone)]
pub struct Release {
    pub origin: String,
    pub suite: String,
    pub codename: String,
    pub label: Option<String>,
    pub version: Option<String>,
    pub architectures: Vec<String>,
    pub components: Vec<String>,
    pub date: UnixTime,
    pub valid_until: Option<UnixTime>,
    pub acquire_by_hash: bool,
    pub no_support_for_architecture_all: bool,
    entries: Vec<ReleaseEntry>,
    entry_index: HashMap<RepositoryPath, usize>,
    content_sha256: Sha256Digest,
}

/// Fields whose repetition would let a second copy override the first in a lenient
/// consumer; the parser refuses rather than guessing which copy wins.
const SECURITY_RELEVANT_FIELDS: [&str; 14] = [
    "Origin",
    "Label",
    "Suite",
    "Codename",
    "Date",
    "Valid-Until",
    "Architectures",
    "Components",
    "Acquire-By-Hash",
    "SHA256",
    "SHA512",
    "SHA1",
    "MD5Sum",
    "No-Support-for-Architecture-all",
];

impl Release {
    /// Parses the authenticated Release bytes as a single deb822 paragraph.
    ///
    /// All hash tables are merged by canonical path and signed size. SHA1 and
    /// MD5Sum advertise targets but their digests are never retained or trusted.
    /// Selected targets must have SHA256; weak-only entries cannot disappear
    /// from closure selection merely because they lack a serving digest.
    /// Field order is not assumed (noble places `Acquire-By-Hash` last).
    ///
    /// # Errors
    /// [`ReleaseError::TooLarge`] before any parsing when the input exceeds
    /// `limits.max_release` or a line (including its newline) exceeds `limits.max_line`;
    /// [`ReleaseError::NotSingleParagraph`] for multi-paragraph input;
    /// [`ReleaseError::DuplicateField`] for repeated security-relevant fields
    /// (case-insensitive); [`ReleaseError::SizeConflict`] when tables list
    /// different sizes for one path; other variants as documented on [`ReleaseError`].
    pub fn parse(authenticated: &[u8], limits: &ParseLimits) -> Result<Self, ReleaseError> {
        if authenticated.len() > limits.max_release
            || authenticated
                .split_inclusive(|byte| *byte == b'\n')
                .any(|line| line.len() > limits.max_line)
        {
            return Err(ReleaseError::TooLarge);
        }
        let content_sha256 = Sha256Digest::of(authenticated);
        let text = std::str::from_utf8(authenticated)
            .map_err(|error| ReleaseError::Deb822(format!("invalid UTF-8: {error}")))?;

        let mut paragraphs = deb822_fast::borrowed::iter_paragraphs_borrowed(text);
        let paragraph = paragraphs
            .next()
            .ok_or_else(|| ReleaseError::Deb822("no paragraph".to_owned()))?
            .map_err(|error| ReleaseError::Deb822(error.to_string()))?;
        if paragraphs.next().is_some() {
            return Err(ReleaseError::NotSingleParagraph);
        }
        reject_duplicate_fields(&paragraph, &SECURITY_RELEVANT_FIELDS)
            .map_err(|name| ReleaseError::DuplicateField(name.to_owned()))?;

        let origin = required_scalar(&paragraph, "Origin")?;
        let suite = required_scalar(&paragraph, "Suite")?;
        let codename = required_scalar(&paragraph, "Codename")?;
        let label = optional_scalar(&paragraph, "Label")?;
        let version = optional_scalar(&paragraph, "Version")?;
        let architectures = required_list(&paragraph, "Architectures")?;
        let components = required_list(&paragraph, "Components")?;
        let date = UnixTime::parse_release_date(&required_scalar(&paragraph, "Date")?)?;
        let valid_until = optional_scalar(&paragraph, "Valid-Until")?
            .map(|text| UnixTime::parse_release_date(&text))
            .transpose()?;
        let acquire_by_hash = match optional_scalar(&paragraph, "Acquire-By-Hash")?.as_deref() {
            None | Some("no") => false,
            Some("yes") => true,
            Some(other) => {
                return Err(ReleaseError::Deb822(format!(
                    "Acquire-By-Hash has unexpected value {other:?}"
                )));
            }
        };
        let no_support_for_architecture_all =
            optional_scalar(&paragraph, "No-Support-for-Architecture-all")?.is_some();

        let mut entries: Vec<ReleaseEntry> = Vec::new();
        let mut entry_index: HashMap<RepositoryPath, usize> = HashMap::new();
        let sha256_lines = paragraph
            .get("SHA256")
            .ok_or(ReleaseError::MissingField("SHA256"))?;
        for line in table_lines(sha256_lines) {
            let (digest, size, path) = parse_table_line(line, Sha256Digest::from_hex)?;
            merge_entry(
                &mut entries,
                &mut entry_index,
                path,
                size,
                |entry| match entry.sha256 {
                    Some(existing) if existing != digest => Err(conflicting(&entry.path, "SHA256")),
                    _ => {
                        entry.sha256 = Some(digest);
                        Ok(())
                    }
                },
            )?;
        }
        for line in table_lines(paragraph.get("SHA512").unwrap_or_default()) {
            let (digest, size, path) = parse_table_line(line, Sha512Digest::from_hex)?;
            merge_entry(
                &mut entries,
                &mut entry_index,
                path,
                size,
                |entry| match entry.sha512 {
                    Some(existing) if existing != digest => Err(conflicting(&entry.path, "SHA512")),
                    _ => {
                        entry.sha512 = Some(digest);
                        Ok(())
                    }
                },
            )?;
        }
        for (field, hex_length) in [("SHA1", 40), ("MD5Sum", 32)] {
            for line in table_lines(paragraph.get(field).unwrap_or_default()) {
                let ((), size, path) = parse_table_line(line, |hex| {
                    if hex.len() != hex_length {
                        return Err(DigestError::InvalidLength {
                            expected: hex_length,
                            actual: hex.len(),
                        });
                    }
                    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return Err(DigestError::InvalidHex);
                    }
                    Ok(())
                })?;
                merge_entry(&mut entries, &mut entry_index, path, size, |_| Ok(()))?;
            }
        }

        Ok(Self {
            origin,
            suite,
            codename,
            label,
            version,
            architectures,
            components,
            date,
            valid_until,
            acquire_by_hash,
            no_support_for_architecture_all,
            entries,
            entry_index,
            content_sha256,
        })
    }

    /// Constructs an authenticated descriptor for a verified Pacman suite database.
    pub fn for_pacman(
        origin: impl Into<String>,
        suite: impl Into<String>,
        date: UnixTime,
        content_sha256: Sha256Digest,
        entries: Vec<ReleaseEntry>,
    ) -> Result<Self, ReleaseError> {
        let suite = suite.into();
        let mut entry_index = HashMap::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            if entry.sha256.is_none() {
                return Err(ReleaseError::InvalidEntry(entry.path.as_str().to_owned()));
            }
            if entry_index.insert(entry.path.clone(), index).is_some() {
                return Err(ReleaseError::DuplicateField(entry.path.as_str().to_owned()));
            }
        }
        Ok(Self {
            origin: origin.into(),
            codename: suite.clone(),
            suite,
            label: None,
            version: None,
            architectures: vec!["x86_64".into(), "aarch64".into()],
            components: vec!["os".into()],
            date,
            valid_until: None,
            acquire_by_hash: false,
            no_support_for_architecture_all: false,
            entries,
            entry_index,
            content_sha256,
        })
    }

    /// Every advertised file: SHA256 first, then SHA512-, SHA1- and MD5Sum-only
    /// paths. Weak-only entries carry no digest and cannot authorize serving.
    pub fn entries(&self) -> &[ReleaseEntry] {
        &self.entries
    }

    /// Looks up one listed file by its path relative to `dists/<suite>/`.
    pub fn entry(&self, path: &RepositoryPath) -> Option<&ReleaseEntry> {
        self.entry_index
            .get(path)
            .and_then(|&index| self.entries.get(index))
    }

    /// SHA-256 of the exact authenticated bytes given to [`Release::parse`].
    pub fn content_sha256(&self) -> Sha256Digest {
        self.content_sha256
    }
}

type Paragraph<'a> = deb822_fast::borrowed::BorrowedParagraph<'a>;

/// Shared by Release and Packages parsing: refuses a case-insensitive repeat of any
/// listed field name and reports the canonical spelling. `relevant` holds at most 64
/// names; the bitmask is the stanza-rate bookkeeping, so no allocation per stanza.
pub(crate) fn reject_duplicate_fields(
    paragraph: &Paragraph<'_>,
    relevant: &[&'static str],
) -> Result<(), &'static str> {
    let mut seen: u64 = 0;
    for field in paragraph.iter() {
        let Some(position) = relevant
            .iter()
            .position(|name| name.eq_ignore_ascii_case(field.name()))
        else {
            continue;
        };
        let canonical = relevant.get(position).copied().unwrap_or("");
        let bit = u32::try_from(position)
            .ok()
            .and_then(|shift| 1u64.checked_shl(shift))
            .ok_or(canonical)?;
        if seen & bit != 0 {
            return Err(canonical);
        }
        seen |= bit;
    }
    Ok(())
}

fn scalar<'a>(
    paragraph: &Paragraph<'a>,
    name: &'static str,
) -> Result<Option<&'a str>, ReleaseError> {
    let Some(field) = paragraph.get_field(name) else {
        return Ok(None);
    };
    field
        .as_single_line()
        .map(|value| Some(value.trim()))
        .ok_or_else(|| ReleaseError::Deb822(format!("{name} must be a single line")))
}

fn required_scalar(paragraph: &Paragraph<'_>, name: &'static str) -> Result<String, ReleaseError> {
    match scalar(paragraph, name)? {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        _ => Err(ReleaseError::MissingField(name)),
    }
}

fn optional_scalar(
    paragraph: &Paragraph<'_>,
    name: &'static str,
) -> Result<Option<String>, ReleaseError> {
    Ok(scalar(paragraph, name)?
        .filter(|value| !value.is_empty())
        .map(str::to_owned))
}

fn required_list(
    paragraph: &Paragraph<'_>,
    name: &'static str,
) -> Result<Vec<String>, ReleaseError> {
    let lines = paragraph
        .get(name)
        .ok_or(ReleaseError::MissingField(name))?;
    let items: Vec<String> = lines
        .iter()
        .flat_map(|line| line.split_ascii_whitespace())
        .map(str::to_owned)
        .collect();
    if items.is_empty() {
        return Err(ReleaseError::MissingField(name));
    }
    Ok(items)
}

/// Table fields start with an empty first line (`SHA256:` followed by a newline);
/// skip that and any other blank continuation line.
fn table_lines<'a>(lines: &'a [&'a str]) -> impl Iterator<Item = &'a str> + 'a {
    lines.iter().copied().filter(|line| !line.trim().is_empty())
}

/// Parses one `<hex> <size> <path>` table line.
fn parse_table_line<D>(
    line: &str,
    parse_digest: impl FnOnce(&str) -> Result<D, DigestError>,
) -> Result<(D, u64, RepositoryPath), ReleaseError> {
    let mut tokens = line.split_ascii_whitespace();
    let (Some(hex), Some(size), Some(path), None) =
        (tokens.next(), tokens.next(), tokens.next(), tokens.next())
    else {
        return Err(ReleaseError::InvalidEntry(line.to_owned()));
    };
    let digest = parse_digest(hex)?;
    let size: u64 = size
        .parse()
        .map_err(|_| ReleaseError::InvalidEntry(line.to_owned()))?;
    let path = RepositoryPath::parse_decoded(path)?;
    Ok((digest, size, path))
}

fn merge_entry(
    entries: &mut Vec<ReleaseEntry>,
    entry_index: &mut HashMap<RepositoryPath, usize>,
    path: RepositoryPath,
    size: u64,
    record: impl FnOnce(&mut ReleaseEntry) -> Result<(), ReleaseError>,
) -> Result<(), ReleaseError> {
    if let Some(&index) = entry_index.get(&path) {
        let entry = entries
            .get_mut(index)
            .ok_or_else(|| ReleaseError::InvalidEntry(path.to_string()))?;
        if entry.size != size {
            return Err(ReleaseError::SizeConflict(path.to_string()));
        }
        return record(entry);
    }
    let mut entry = ReleaseEntry {
        path: path.clone(),
        size,
        sha256: None,
        sha512: None,
    };
    record(&mut entry)?;
    entry_index.insert(path, entries.len());
    entries.push(entry);
    Ok(())
}

fn conflicting(path: &RepositoryPath, table: &str) -> ReleaseError {
    ReleaseError::InvalidEntry(format!(
        "{path} listed twice in {table} with different digests"
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const FIXTURE_RELEASE: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/Release"));

    const SHA256_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA256_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sha512_hex(fill: char) -> String {
        std::iter::repeat_n(fill, 128).collect()
    }

    fn minimal(extra: &str) -> Vec<u8> {
        format!(
            "Origin: FerrumTest\nSuite: ferrum-test\nCodename: ferrum-test\n\
             Date: Sat, 17 Oct 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\n\
             SHA256:\n {SHA256_A} 10 main/binary-amd64/Packages\n{extra}"
        )
        .into_bytes()
    }

    fn path(text: &str) -> RepositoryPath {
        RepositoryPath::parse_decoded(text).expect("test path")
    }

    #[test]
    fn parses_fixture_release_with_trailing_acquire_by_hash() {
        let release = Release::parse(FIXTURE_RELEASE, &ParseLimits::default()).expect("fixture");
        assert_eq!(release.origin, "FerrumTest");
        assert_eq!(release.suite, "ferrum-test");
        assert_eq!(release.codename, "ferrum-test");
        assert_eq!(release.label.as_deref(), Some("FerrumTest"));
        assert_eq!(release.architectures, ["amd64"]);
        assert_eq!(release.components, ["main"]);
        assert!(release.acquire_by_hash);
        assert!(!release.no_support_for_architecture_all);
        assert!(release.valid_until.expect("Valid-Until present") > release.date);
        assert_eq!(release.content_sha256(), Sha256Digest::of(FIXTURE_RELEASE));
        assert_eq!(release.entries().len(), 3);
        for name in ["Packages", "Packages.gz", "Release"] {
            let entry = release
                .entry(&path(&format!("main/binary-amd64/{name}")))
                .unwrap_or_else(|| panic!("entry {name}"));
            assert!(entry.sha256.is_some(), "{name} sha256");
            assert!(entry.sha512.is_some(), "{name} sha512");
            assert!(entry.size > 0, "{name} size");
        }
        assert!(release.entry(&path("main/binary-amd64/Sources")).is_none());
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let limits = ParseLimits {
            max_release: FIXTURE_RELEASE.len() - 1,
            ..ParseLimits::default()
        };
        assert!(matches!(
            Release::parse(FIXTURE_RELEASE, &limits),
            Err(ReleaseError::TooLarge)
        ));
    }

    #[test]
    fn rejects_oversized_release_line_at_boundary() {
        let limits = ParseLimits {
            max_line: 256,
            ..ParseLimits::default()
        };
        let bounded = minimal(&format!("Description: {}\n", "x".repeat(242)));
        assert!(Release::parse(&bounded, &limits).is_ok());
        let oversized = minimal(&format!("Description: {}\n", "x".repeat(243)));
        assert!(matches!(
            Release::parse(&oversized, &limits),
            Err(ReleaseError::TooLarge)
        ));
    }

    #[test]
    fn rejects_multi_paragraph_input() {
        let mut text = minimal("");
        text.extend_from_slice(b"\nOrigin: Second\n");
        assert!(matches!(
            Release::parse(&text, &ParseLimits::default()),
            Err(ReleaseError::NotSingleParagraph)
        ));
    }

    #[test]
    fn rejects_case_insensitive_duplicate_security_fields() {
        for (field, value) in [
            ("origin", "Other"),
            ("SUITE", "other"),
            ("Codename", "other"),
            ("date", "Sat, 17 Oct 2026 12:00:00 UTC"),
            ("ARCHITECTURES", "arm64"),
            ("sha256", ""),
        ] {
            let text = minimal(&format!("{field}: {value}\n"));
            let error = Release::parse(&text, &ParseLimits::default())
                .err()
                .unwrap_or_else(|| panic!("duplicate {field} must be rejected"));
            assert!(
                matches!(&error, ReleaseError::DuplicateField(name) if name.eq_ignore_ascii_case(field)),
                "{field}: {error}"
            );
        }
        let text = minimal("Acquire-By-Hash: yes\nacquire-by-hash: no\n");
        assert!(matches!(
            Release::parse(&text, &ParseLimits::default()),
            Err(ReleaseError::DuplicateField(name)) if name == "Acquire-By-Hash"
        ));
        let text = minimal("Description: twice\nDescription: is fine\n");
        assert!(Release::parse(&text, &ParseLimits::default()).is_ok());
    }

    #[test]
    fn rejects_size_conflicts_across_tables_and_merges_matching_sizes() {
        let conflicting = minimal(&format!(
            "SHA512:\n {} 11 main/binary-amd64/Packages\n",
            sha512_hex('c')
        ));
        assert!(matches!(
            Release::parse(&conflicting, &ParseLimits::default()),
            Err(ReleaseError::SizeConflict(path)) if path == "main/binary-amd64/Packages"
        ));

        let merged = minimal(&format!(
            "SHA512:\n {} 10 main/binary-amd64/Packages\n {} 7 main/binary-amd64/Release\n",
            sha512_hex('c'),
            sha512_hex('d')
        ));
        let release = Release::parse(&merged, &ParseLimits::default()).expect("merged");
        assert_eq!(release.entries().len(), 2);
        let packages = release
            .entry(&path("main/binary-amd64/Packages"))
            .expect("Packages entry");
        assert_eq!(packages.size, 10);
        assert_eq!(
            packages.sha256,
            Some(Sha256Digest::from_hex(SHA256_A).expect("hex"))
        );
        assert_eq!(
            packages.sha512,
            Some(Sha512Digest::from_hex(&sha512_hex('c')).expect("hex"))
        );
        let component = release
            .entry(&path("main/binary-amd64/Release"))
            .expect("Release entry");
        assert_eq!(component.sha256, None);
        assert_eq!(component.size, 7);
    }

    #[test]
    fn retains_weak_only_advertisements_without_retaining_weak_digests() {
        let text = minimal(&format!(
            concat!(
                "SHA1:\n {} 10 main/binary-amd64/Packages\n {} 7 main/Contents-amd64.gz\n",
                "MD5Sum:\n {} 10 main/binary-amd64/Packages\n {} 7 main/Contents-amd64.gz\n",
                " {} 3 main/i18n/Translation-en.gz\n",
            ),
            "c".repeat(40),
            "d".repeat(40),
            "e".repeat(32),
            "f".repeat(32),
            "a".repeat(32)
        ));
        let release = Release::parse(&text, &ParseLimits::default()).expect("advertisements");
        assert_eq!(release.entries().len(), 3);
        let packages = release
            .entry(&path("main/binary-amd64/Packages"))
            .expect("Packages");
        assert_eq!(
            packages.sha256,
            Some(Sha256Digest::from_hex(SHA256_A).expect("hex"))
        );
        for (name, size) in [
            ("main/Contents-amd64.gz", 7),
            ("main/i18n/Translation-en.gz", 3),
        ] {
            let entry = release.entry(&path(name)).expect("weak-only advertisement");
            assert_eq!(entry.size, size);
            assert_eq!(entry.sha256, None);
            assert_eq!(entry.sha512, None);
        }
    }

    #[test]
    fn weak_advertisements_obey_duplicate_path_size_and_input_bounds() {
        for (field, length) in [("SHA1", 40), ("MD5Sum", 32)] {
            let digest = "a".repeat(length);
            let duplicate = minimal(&format!("{field}:\n{field}:\n"));
            assert!(matches!(
                Release::parse(&duplicate, &ParseLimits::default()),
                Err(ReleaseError::DuplicateField(name)) if name == field
            ));
            let conflicting = minimal(&format!(
                "{field}:\n {digest} 11 main/binary-amd64/Packages\n"
            ));
            assert!(matches!(
                Release::parse(&conflicting, &ParseLimits::default()),
                Err(ReleaseError::SizeConflict(_))
            ));
            let bad_path = minimal(&format!("{field}:\n {digest} 1 ../escape\n"));
            assert!(matches!(
                Release::parse(&bad_path, &ParseLimits::default()),
                Err(ReleaseError::Path(PathError::DotSegment))
            ));
            for bad_digest in ["a".repeat(length - 1), "z".repeat(length)] {
                let invalid = minimal(&format!(
                    "{field}:\n {bad_digest} 1 main/Contents-amd64.gz\n"
                ));
                assert!(matches!(
                    Release::parse(&invalid, &ParseLimits::default()),
                    Err(ReleaseError::Digest(_))
                ));
            }
            let bounded = minimal(&format!("{field}:\n {digest} 1 main/{}\n", "x".repeat(200)));
            let limits = ParseLimits {
                max_line: 200,
                ..ParseLimits::default()
            };
            assert!(matches!(
                Release::parse(&bounded, &limits),
                Err(ReleaseError::TooLarge)
            ));
        }
    }

    #[test]
    fn rejects_conflicting_digests_for_one_path_in_one_table() {
        let text = minimal(&format!(" {SHA256_B} 10 main/binary-amd64/Packages\n"));
        assert!(matches!(
            Release::parse(&text, &ParseLimits::default()),
            Err(ReleaseError::InvalidEntry(_))
        ));
    }

    #[test]
    fn rejects_malformed_table_entries() {
        let bad_path = minimal(&format!(" {SHA256_B} 10 ../escape\n"));
        assert!(matches!(
            Release::parse(&bad_path, &ParseLimits::default()),
            Err(ReleaseError::Path(PathError::DotSegment))
        ));
        let bad_digest = minimal(" abcd 10 main/x\n");
        assert!(matches!(
            Release::parse(&bad_digest, &ParseLimits::default()),
            Err(ReleaseError::Digest(DigestError::InvalidLength { .. }))
        ));
        let bad_size = minimal(&format!(" {SHA256_B} -1 main/x\n"));
        assert!(matches!(
            Release::parse(&bad_size, &ParseLimits::default()),
            Err(ReleaseError::InvalidEntry(_))
        ));
        let extra_token = minimal(&format!(" {SHA256_B} 1 main/x extra\n"));
        assert!(matches!(
            Release::parse(&extra_token, &ParseLimits::default()),
            Err(ReleaseError::InvalidEntry(_))
        ));
    }

    #[test]
    fn rejects_missing_required_fields() {
        let text = b"Origin: FerrumTest\nSuite: s\nCodename: c\nArchitectures: amd64\n\
                     Components: main\nSHA256:\n";
        assert!(matches!(
            Release::parse(text, &ParseLimits::default()),
            Err(ReleaseError::MissingField("Date"))
        ));
        let text = b"Origin: FerrumTest\nSuite: s\nCodename: c\nArchitectures: amd64\n\
                     Components: main\nDate: Sat, 17 Oct 2026 12:00:00 UTC\n";
        assert!(matches!(
            Release::parse(text, &ParseLimits::default()),
            Err(ReleaseError::MissingField("SHA256"))
        ));
        let text = minimal("Valid-Until: yesterday\n");
        assert!(matches!(
            Release::parse(&text, &ParseLimits::default()),
            Err(ReleaseError::InvalidDate(value)) if value == "yesterday"
        ));
    }

    #[test]
    fn parses_rfc1123_dates_in_accepted_zones() {
        let expected = UnixTime::from_secs(1_792_238_400);
        for text in [
            "Sat, 17 Oct 2026 12:00:00 UTC",
            "Sat, 17 Oct 2026 12:00:00 GMT",
            "Sat, 17 Oct 2026 12:00:00 +0000",
            "Sat, 17 Oct 2026 12:00:00 -0000",
            "Sat, 17 Oct 2026 12:00:00 UT",
            "Sat, 17 Oct 2026 12:00:00 Z",
            "17 Oct 2026 12:00:00 UTC",
            "  Sat,  17 Oct 2026 12:00:00 UTC  ",
        ] {
            assert_eq!(
                UnixTime::parse_release_date(text).expect(text),
                expected,
                "{text}"
            );
        }
        assert_eq!(
            UnixTime::parse_release_date("Thu, 01 Jan 1970 00:00:00 UTC").expect("epoch"),
            UnixTime::from_secs(0)
        );
        assert_eq!(
            UnixTime::parse_release_date("Sat, 29 Feb 2020 23:59:59 GMT")
                .expect("leap day")
                .as_secs(),
            1_583_020_799
        );
        assert_eq!(
            UnixTime::parse_release_date("Sun, 18 Oct 2026  5:50:44 UTC")
                .expect("space-padded single-digit hour")
                .as_secs(),
            1_792_302_644
        );
        assert_eq!(expected.to_rfc1123(), "Sat, 17 Oct 2026 12:00:00 UTC");
        assert_eq!(
            UnixTime::from_secs(0).to_rfc1123(),
            "Thu, 01 Jan 1970 00:00:00 UTC"
        );
        assert_eq!(
            UnixTime::from_secs(-86_400).to_rfc1123(),
            "Wed, 31 Dec 1969 00:00:00 UTC"
        );
    }

    #[test]
    fn rejects_malformed_dates() {
        for text in [
            "",
            "Sat, 17 Oct 2026 12:00:00",
            "Sat, 17 Oct 2026 12:00:00 CET",
            "Sat, 17 Oct 2026 12:00:00 +0100",
            "Sat, 17 Oct 2026 12:00 UTC",
            "Sat, 17 Oct 2026 24:00:00 UTC",
            "Sat, 17 Oct 2026 12:60:00 UTC",
            "Sat, 32 Oct 2026 12:00:00 UTC",
            "Sat, 29 Feb 2026 12:00:00 UTC",
            "Sat, 17 Foo 2026 12:00:00 UTC",
            "Xyz, 17 Oct 2026 12:00:00 UTC",
            "Sat, 17 Oct 26 12:00:00 UTC",
            "Sat, 17 Oct 2026 12:00:00 UTC extra",
            "2026-10-17T12:00:00Z",
            "Sat, 17 Oct 2026 12:00:00 UTC                                              ",
        ] {
            assert!(
                UnixTime::parse_release_date(text).is_err(),
                "{text:?} must be rejected"
            );
        }
    }
}
