//! Bounded Pacman `.db` tar archive and `%FIELD%` `desc` parsing.
//!
//! Official Arch Linux (`core`, `extra`, `multilib`) and Chaotic-AUR (`chaotic-aur`)
//! distribute repository indexes as compressed UStar/POSIX tar archives containing
//! `<pkgname>-<pkgver>-<pkgrel>/desc` files. This module streams and validates those
//! archives without filesystem extraction or unbounded memory allocation.

use std::collections::HashSet;
use std::io::{self, BufReader, Chain, Cursor, Read};

use base64::Engine as _;

use crate::digest::{ObjectIdentity, Sha256Digest, Sha256Hasher};
use crate::index::{IndexError, PackageRecord};
use crate::path::RepositoryPath;
use crate::release::{ParseLimits, UnixTime};

pub(crate) mod zstd;

use zstd::{MultiZstdDecoder, is_zstd_magic};

/// Maximum uncompressed tar stream size accepted for a Pacman `.db` archive.
const MAX_DECOMPRESSED_DB_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum detached OpenPGP signature size accepted from `%PGPSIG%` or `.sig`.
pub const MAX_PACMAN_SIG_BYTES: usize = 16 * 1024;
/// Maximum package size eligible as a deterministic metadata verification canary.
const MAX_CANARY_PACKAGE_BYTES: u64 = 32 * 1024 * 1024;
/// XZ decoder memory cap matching `ferrum-storage` proof decoding.
const XZ_DECODER_MEMORY_LIMIT: u64 = 65 * 1024 * 1024;

/// Fixed architecture directory for each CachyOS repository suite.
pub fn cachyos_suite_arch(suite: &str) -> Option<&'static str> {
    match suite {
        "cachyos" => Some("x86_64"),
        "cachyos-v3" => Some("x86_64_v3"),
        "cachyos-v4" => Some("x86_64_v4"),
        _ => None,
    }
}

/// Splits a CachyOS repository-relative request using its exact architecture root.
pub fn split_cachyos_suite_path(path: &str) -> Option<(&str, &str)> {
    let (architecture, rest) = path.split_once('/')?;
    let (suite, relative) = rest.split_once('/')?;
    (cachyos_suite_arch(suite)? == architecture).then_some((suite, relative))
}

/// Maps a suite-relative Pacman index path (`os/x86_64/<suite>.db` or
/// `x86_64/chaotic-aur.db`) to its repository-relative package directory prefix
/// (`<suite>/os/x86_64` or `chaotic-aur/x86_64`).
pub fn pacman_package_prefix(index_path: &str) -> Option<String> {
    let (directory, file) = index_path.rsplit_once('/')?;
    let suite = file.strip_suffix(".db")?;
    if !valid_suite_segment(suite) {
        return None;
    }
    match directory {
        "os/x86_64" | "os/aarch64" => Some(format!("{suite}/{directory}")),
        "x86_64" | "aarch64" if matches!(suite, "chaotic-aur" | "endeavouros" | "archlinuxcn") => {
            Some(format!("{suite}/{directory}"))
        }
        _ if cachyos_suite_arch(suite) == Some(directory) => Some(format!("{directory}/{suite}")),
        _ => None,
    }
}

/// Returns whether a repository-relative path is a Pacman binary package or
/// detached package signature.
pub fn is_pacman_package_path(path: &str) -> bool {
    let Some((prefix, file)) = path.rsplit_once('/') else {
        return false;
    };
    if file.is_empty() || file.contains('/') {
        return false;
    }
    let valid_prefix = if let Some(suite) = prefix
        .strip_suffix("/os/x86_64")
        .or_else(|| prefix.strip_suffix("/os/aarch64"))
    {
        valid_suite_segment(suite)
    } else {
        matches!(
            prefix,
            "chaotic-aur/x86_64"
                | "chaotic-aur/aarch64"
                | "endeavouros/x86_64"
                | "endeavouros/aarch64"
                | "archlinuxcn/x86_64"
                | "archlinuxcn/aarch64"
                | "x86_64/cachyos"
                | "x86_64_v3/cachyos-v3"
                | "x86_64_v4/cachyos-v4"
        )
    };
    if !valid_prefix {
        return false;
    }
    let base = file.strip_suffix(".sig").unwrap_or(file);
    is_pacman_archive_filename(base)
}

fn is_pacman_archive_filename(name: &str) -> bool {
    (name.ends_with(".pkg.tar.zst")
        || name.ends_with(".pkg.tar.xz")
        || name.ends_with(".pkg.tar.gz"))
        && name.len() > ".pkg.tar.gz".len()
        && !name.contains('/')
}

fn valid_suite_segment(suite: &str) -> bool {
    !suite.is_empty()
        && suite.len() <= 64
        && suite
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Deterministic canary package selected from a Pacman `.db` to anchor detached
/// OpenPGP signature verification against the suite keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacmanCanary {
    /// Suite-relative package path, e.g. `os/x86_64/base-devel-1-2-any.pkg.tar.zst`.
    pub path: RepositoryPath,
    pub identity: ObjectIdentity,
    /// Suite-relative detached signature path (`<path>.sig`).
    pub sig_path: RepositoryPath,
    /// Raw detached OpenPGP signature bytes when `%PGPSIG%` is embedded in `desc`.
    pub embedded_sig: Option<Vec<u8>>,
}

/// Summary extracted when validating a Pacman `.db` archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacmanDbSummary {
    /// Suite-relative `.db` path, e.g. `os/x86_64/core.db` or `x86_64/chaotic-aur.db`.
    pub db_path: RepositoryPath,
    pub db_identity: ObjectIdentity,
    /// SHA-256 of the uncompressed tar stream inside the `.db` archive.
    pub content_sha256: Sha256Digest,
    /// Maximum `%BUILDDATE%` across all selected `desc` entries.
    pub max_build_date: UnixTime,
    pub canary: PacmanCanary,
    pub package_count: usize,
}

struct ParsedDesc {
    filename: String,
    name: String,
    version: String,
    architecture: String,
    size: u64,
    sha256: Sha256Digest,
    build_date: Option<i64>,
    pgpsig: Option<Vec<u8>>,
}

/// Validates a complete `.db` archive in memory and extracts its canonical summary
/// and deterministic canary package.
pub fn summarize_pacman_db(
    db_bytes: &[u8],
    db_subpath: &str,
    limits: &ParseLimits,
) -> Result<PacmanDbSummary, IndexError> {
    let Some(repo_prefix) = pacman_package_prefix(db_subpath) else {
        return Err(IndexError::Deb822(format!(
            "unsupported Pacman db path {db_subpath}"
        )));
    };
    let (directory, _) = db_subpath
        .rsplit_once('/')
        .ok_or_else(|| IndexError::Deb822("missing Pacman db directory".into()))?;
    let db_path = RepositoryPath::parse_decoded(db_subpath)?;
    let db_identity = ObjectIdentity {
        sha256: Sha256Digest::of(db_bytes),
        size: db_bytes.len() as u64,
    };
    let mut cursor = Cursor::new(db_bytes);
    let mut max_build_date: Option<i64> = None;
    let mut canary: Option<(String, PacmanCanary)> = None;
    let mut package_count = 0usize;
    let mut seen_filenames = HashSet::new();
    let content_sha256 = scan_pacman_tar(&mut cursor, limits, &mut |stanza, desc| {
        if !seen_filenames.insert(desc.filename.clone()) {
            return Err(IndexError::DuplicateField(format!(
                "duplicate Pacman %FILENAME% {}",
                desc.filename
            )));
        }
        if !matches!(
            desc.architecture.as_str(),
            "x86_64" | "x86_64_v3" | "x86_64_v4" | "aarch64" | "any"
        ) {
            return Ok(());
        }
        let _ = repo_prefix.as_str();
        package_count = package_count.saturating_add(1);
        if let Some(build_date) = desc.build_date {
            max_build_date = Some(max_build_date.map_or(build_date, |prev| prev.max(build_date)));
        }
        if desc.size > 0 && desc.size <= MAX_CANARY_PACKAGE_BYTES {
            let replace = match &canary {
                None => true,
                Some((best_name, best)) => {
                    desc.size < best.identity.size
                        || (desc.size == best.identity.size && desc.filename < *best_name)
                }
            };
            if replace {
                let rel_pkg =
                    RepositoryPath::parse_decoded(&format!("{directory}/{}", desc.filename))?;
                let rel_sig =
                    RepositoryPath::parse_decoded(&format!("{directory}/{}.sig", desc.filename))?;
                canary = Some((
                    desc.filename,
                    PacmanCanary {
                        path: rel_pkg,
                        identity: ObjectIdentity {
                            sha256: desc.sha256,
                            size: desc.size,
                        },
                        sig_path: rel_sig,
                        embedded_sig: desc.pgpsig,
                    },
                ));
            }
        }
        let _ = stanza;
        Ok(())
    })?;
    let Some((_, canary)) = canary else {
        return Err(IndexError::MissingField("%FILENAME%"));
    };
    let max_build_date = UnixTime::from_secs(max_build_date.unwrap_or(0));
    Ok(PacmanDbSummary {
        db_path,
        db_identity,
        content_sha256,
        max_build_date,
        canary,
        package_count,
    })
}

/// Streams a Pacman `.db` archive and emits [`PackageRecord`] entries for every
/// `x86_64` and `any` package (plus `<filename>.sig` when `%PGPSIG%` is embedded).
pub fn parse_pacman_db<R, S>(
    reader: &mut R,
    index_path: &str,
    limits: &ParseLimits,
    sink: &mut S,
) -> Result<usize, IndexError>
where
    R: Read,
    S: FnMut(PackageRecord) -> Result<(), IndexError>,
{
    let Some(prefix) = pacman_package_prefix(index_path) else {
        return Err(IndexError::Deb822(format!(
            "unsupported Pacman index path {index_path}"
        )));
    };
    let mut delivered = 0usize;
    let mut seen_filenames = HashSet::new();
    let _content_sha256 = scan_pacman_tar(reader, limits, &mut |_stanza, desc| {
        if !seen_filenames.insert(desc.filename.clone()) {
            return Err(IndexError::DuplicateField(format!(
                "duplicate Pacman %FILENAME% {}",
                desc.filename
            )));
        }
        if !matches!(
            desc.architecture.as_str(),
            "x86_64" | "x86_64_v3" | "x86_64_v4" | "aarch64" | "any"
        ) {
            return Ok(());
        }
        let pkg_path = RepositoryPath::parse_decoded(&format!("{prefix}/{}", desc.filename))?;
        sink(PackageRecord {
            package: desc.name.clone(),
            version: desc.version.clone(),
            architecture: desc.architecture.clone(),
            filename: pkg_path,
            size: desc.size,
            sha256: desc.sha256,
        })?;
        delivered = delivered.saturating_add(1);
        if let Some(sig_bytes) = desc.pgpsig {
            let sig_path =
                RepositoryPath::parse_decoded(&format!("{prefix}/{}.sig", desc.filename))?;
            sink(PackageRecord {
                package: desc.name,
                version: desc.version,
                architecture: desc.architecture,
                filename: sig_path,
                size: sig_bytes.len() as u64,
                sha256: Sha256Digest::of(&sig_bytes),
            })?;
            delivered = delivered.saturating_add(1);
        }
        Ok(())
    })?;
    Ok(delivered)
}

/// Returns the embedded signature for one exact repository-relative package path.
///
/// The entire bounded database is validated before returning; malformed archives
/// and duplicate package filenames are errors, including after the matched entry.
pub fn package_embedded_signature(
    bytes: &[u8],
    db_path: &str,
    package_path: &RepositoryPath,
    limits: &ParseLimits,
) -> Result<Option<Vec<u8>>, IndexError> {
    package_embedded_signature_reader(&mut Cursor::new(bytes), db_path, package_path, limits)
}

/// Reader form used by bounded, cancellation-aware repository workers.
pub fn package_embedded_signature_reader<R: Read>(
    reader: &mut R,
    db_path: &str,
    package_path: &RepositoryPath,
    limits: &ParseLimits,
) -> Result<Option<Vec<u8>>, IndexError> {
    let prefix = pacman_package_prefix(db_path)
        .ok_or_else(|| IndexError::Deb822("unsupported Pacman database path".into()))?;
    let mut signature = None;
    let mut seen_filenames = HashSet::new();
    scan_pacman_tar(reader, limits, &mut |_, desc| {
        if !seen_filenames.insert(desc.filename.clone()) {
            return Err(IndexError::DuplicateField(desc.filename));
        }
        if package_path
            .as_str()
            .strip_prefix(&prefix)
            .and_then(|tail| tail.strip_prefix('/'))
            == Some(desc.filename.as_str())
        {
            signature = desc.pgpsig;
        }
        Ok(())
    })?;
    Ok(signature)
}

fn scan_pacman_tar<R, F>(
    reader: &mut R,
    limits: &ParseLimits,
    on_desc: &mut F,
) -> Result<Sha256Digest, IndexError>
where
    R: Read,
    F: FnMut(usize, ParsedDesc) -> Result<(), IndexError>,
{
    let mut magic = [0u8; 6];
    let mut magic_len = 0usize;
    while magic_len < magic.len() {
        let count = reader.read(&mut magic[magic_len..])?;
        if count == 0 {
            break;
        }
        magic_len += count;
    }
    let content_sha256 = {
        let prefix = Cursor::new(&magic[..magic_len]);
        let chained: Chain<Cursor<&[u8]>, &mut R> = prefix.chain(&mut *reader);
        let decoder: Box<dyn Read + '_> = if magic_len >= 2 && magic[..2] == [0x1f, 0x8b] {
            Box::new(flate2::read::MultiGzDecoder::new(BufReader::new(chained)))
        } else if is_zstd_magic(&magic[..magic_len]) {
            Box::new(MultiZstdDecoder::new(chained))
        } else if magic_len >= 6 && magic == [0xfd, b'7', b'z', b'X', b'Z', 0x00] {
            let stream = xz2::stream::Stream::new_stream_decoder(
                XZ_DECODER_MEMORY_LIMIT,
                xz2::stream::CONCATENATED,
            )
            .map_err(|error| IndexError::Deb822(format!("xz init failed: {error}")))?;
            Box::new(xz2::read::XzDecoder::new_stream(
                BufReader::new(chained),
                stream,
            ))
        } else if magic_len >= 3 && &magic[..3] == b"BZh" {
            Box::new(bzip2::read::MultiBzDecoder::new(BufReader::new(chained)))
        } else {
            Box::new(chained)
        };

        let mut hashed = HashingBoundedReader {
            inner: decoder,
            total: 0,
            hasher: Sha256Hasher::new(),
        };
        let mut header = [0u8; 512];
        let mut zero_blocks = 0u8;
        let mut stanza = 0usize;
        let mut pax_path: Option<String> = None;

        loop {
            if !read_exact_or_eof(&mut hashed, &mut header)? {
                return Err(IndexError::Deb822(
                    "missing tar end-of-archive blocks".into(),
                ));
            }
            if header.iter().all(|&byte| byte == 0) {
                zero_blocks = zero_blocks.saturating_add(1);
                if zero_blocks >= 2 {
                    if pax_path.is_some() {
                        return Err(IndexError::Deb822("dangling tar path extension".into()));
                    }
                    while read_exact_or_eof(&mut hashed, &mut header)? {
                        if header.iter().any(|&byte| byte != 0) {
                            return Err(IndexError::Deb822(
                                "nonzero data after tar terminator".into(),
                            ));
                        }
                    }
                    break;
                }
                continue;
            }
            validate_tar_checksum(&header)?;
            if zero_blocks != 0 {
                return Err(IndexError::Deb822("incomplete tar terminator".into()));
            }
            let size = parse_tar_octal(&header[124..136])
                .ok_or_else(|| IndexError::InvalidSize("invalid tar octal size".into()))?;
            let typeflag = header[156];
            let raw_name = pax_path.take().unwrap_or_else(|| parse_tar_path(&header));
            let padded = next_512_multiple(size)
                .ok_or_else(|| IndexError::InvalidSize("tar entry size overflow".into()))?;
            let padding = padded - size;

            if matches!(typeflag, b'x' | b'L') {
                if size > limits.max_line as u64 {
                    return Err(IndexError::TooLarge {
                        stanza: stanza.saturating_add(1),
                    });
                }
                let mut buf = vec![0u8; size as usize];
                hashed.read_exact(&mut buf)?;
                skip_exact(&mut hashed, padding)?;
                if typeflag == b'L' {
                    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                    if let Ok(long_name) = std::str::from_utf8(&buf[..end]) {
                        pax_path = Some(long_name.to_owned());
                    }
                } else if let Some(path) = parse_pax_path(&buf) {
                    pax_path = Some(path);
                }
                continue;
            }

            let is_regular = typeflag == 0 || typeflag == b'0';
            if is_regular && is_desc_entry_path(&raw_name) {
                stanza = stanza.saturating_add(1);
                if size == 0 || size > limits.max_stanza as u64 {
                    return Err(IndexError::TooLarge { stanza });
                }
                let mut body = vec![0u8; size as usize];
                hashed.read_exact(&mut body)?;
                skip_exact(&mut hashed, padding)?;
                let text = std::str::from_utf8(&body)
                    .map_err(|error| IndexError::Deb822(format!("desc UTF-8 error: {error}")))?;
                let parsed = parse_desc_stanza(text, stanza, limits)?;
                on_desc(stanza, parsed)?;
            } else {
                skip_exact(&mut hashed, padded)?;
            }
        }

        hashed.hasher.finalize()
    };
    // All decoder output, frame trailers and compressed input have reached EOF.
    Ok(content_sha256)
}

fn validate_tar_checksum(header: &[u8; 512]) -> Result<(), IndexError> {
    let field = &header[148..156];
    let text = std::str::from_utf8(field)
        .map_err(|_| IndexError::Deb822("invalid tar checksum encoding".into()))?
        .trim_matches([' ', '\0']);
    if text.is_empty() || !text.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(IndexError::Deb822("invalid tar checksum field".into()));
    }
    let expected = u64::from_str_radix(text, 8)
        .map_err(|_| IndexError::Deb822("invalid tar checksum octal".into()))?;
    let mut unsigned_sum = 0u64;
    let mut signed_sum = 0i64;
    for (offset, &byte) in header.iter().enumerate() {
        let byte = if (148..156).contains(&offset) {
            b' '
        } else {
            byte
        };
        unsigned_sum += u64::from(byte);
        signed_sum += i64::from(byte as i8);
    }
    if expected != unsigned_sum && i64::try_from(expected).ok() != Some(signed_sum) {
        return Err(IndexError::Deb822("tar header checksum mismatch".into()));
    }
    Ok(())
}

struct HashingBoundedReader<R> {
    inner: R,
    total: u64,
    hasher: Sha256Hasher,
}

impl<R: Read> Read for HashingBoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        self.total = self
            .total
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("decompressed Pacman db overflow"))?;
        if self.total > MAX_DECOMPRESSED_DB_BYTES {
            return Err(io::Error::other("decompressed Pacman db exceeds 256 MiB"));
        }
        if count > 0 {
            self.hasher.update(&buf[..count]);
        }
        Ok(count)
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let count = reader.read(&mut buf[offset..])?;
        if count == 0 {
            if offset == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated tar block",
            ));
        }
        offset += count;
    }
    Ok(true)
}

fn skip_exact<R: Read>(reader: &mut R, mut remaining: u64) -> io::Result<()> {
    let mut scratch = [0u8; 8192];
    while remaining > 0 {
        let chunk = scratch.len().min(remaining as usize);
        let count = reader.read(&mut scratch[..chunk])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated tar entry body",
            ));
        }
        remaining -= count as u64;
    }
    Ok(())
}

fn next_512_multiple(size: u64) -> Option<u64> {
    let rem = size % 512;
    if rem == 0 {
        Some(size)
    } else {
        size.checked_add(512 - rem)
    }
}

fn parse_tar_octal(field: &[u8]) -> Option<u64> {
    if field.first().copied() == Some(0x80) {
        let mut value = 0u64;
        for &byte in &field[field.len().saturating_sub(8)..] {
            value = (value << 8) | u64::from(byte);
        }
        return Some(value);
    }
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let text = std::str::from_utf8(&field[..end]).ok()?.trim();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

fn parse_tar_path(header: &[u8; 512]) -> String {
    let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
    let name = String::from_utf8_lossy(&header[..name_end]);
    let is_ustar = &header[257..262] == b"ustar";
    if is_ustar {
        let prefix_end = header[345..500].iter().position(|&b| b == 0).unwrap_or(155);
        if prefix_end > 0 {
            let prefix = String::from_utf8_lossy(&header[345..345 + prefix_end]);
            return format!("{prefix}/{name}");
        }
    }
    name.into_owned()
}

fn parse_pax_path(pax: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(pax).ok()?;
    for line in text.split('\n') {
        if let Some((_len, rest)) = line.split_once(' ')
            && let Some(path) = rest.strip_prefix("path=")
        {
            return Some(path.to_owned());
        }
    }
    None
}

fn is_desc_entry_path(path: &str) -> bool {
    let trimmed = path.strip_prefix("./").unwrap_or(path);
    let Some((dir, file)) = trimmed.split_once('/') else {
        return false;
    };
    file == "desc" && !dir.is_empty() && dir != "." && dir != ".." && !dir.contains('/')
}

fn parse_desc_stanza(
    text: &str,
    stanza: usize,
    limits: &ParseLimits,
) -> Result<ParsedDesc, IndexError> {
    let mut filename: Option<String> = None;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut architecture: Option<String> = None;
    let mut size: Option<u64> = None;
    let mut sha256: Option<Sha256Digest> = None;
    let mut build_date: Option<i64> = None;
    let mut pgpsig: Option<Vec<u8>> = None;

    let mut seen_fields = HashSet::new();
    let mut lines = text.lines();
    while let Some(raw_line) = lines.next() {
        if raw_line.len() > limits.max_line {
            return Err(IndexError::TooLarge { stanza });
        }
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if !(line.starts_with('%') && line.ends_with('%') && line.len() > 2) {
            return Err(IndexError::Deb822(format!(
                "expected Pacman %FIELD% header in stanza {stanza}, got {line:?}"
            )));
        }
        let field = &line[1..line.len() - 1];
        if matches!(
            field,
            "FILENAME"
                | "NAME"
                | "VERSION"
                | "ARCH"
                | "CSIZE"
                | "SHA256SUM"
                | "BUILDDATE"
                | "PGPSIG"
        ) && !seen_fields.insert(field.to_owned())
        {
            return Err(IndexError::DuplicateField(field.to_owned()));
        }
        let mut values = Vec::new();
        for value_raw in lines.by_ref() {
            if value_raw.len() > limits.max_line {
                return Err(IndexError::TooLarge { stanza });
            }
            let value_line = value_raw.trim_end_matches('\r');
            if value_line.is_empty() {
                break;
            }
            values.push(value_line);
        }
        match field {
            "FILENAME" => {
                if values.len() != 1 || !is_pacman_archive_filename(values[0]) {
                    return Err(IndexError::Deb822(
                        "invalid %FILENAME% in Pacman desc".into(),
                    ));
                }
                RepositoryPath::parse_decoded(values[0])?;
                filename = Some(values[0].to_owned());
            }
            "NAME" => {
                if values.len() != 1 || values[0].is_empty() {
                    return Err(IndexError::MissingField("%NAME%"));
                }
                name = Some(values[0].to_owned());
            }
            "VERSION" => {
                if values.len() != 1 || values[0].is_empty() {
                    return Err(IndexError::MissingField("%VERSION%"));
                }
                version = Some(values[0].to_owned());
            }
            "ARCH" => {
                if values.len() != 1 || values[0].is_empty() {
                    return Err(IndexError::MissingField("%ARCH%"));
                }
                architecture = Some(values[0].to_owned());
            }
            "CSIZE" => {
                if values.len() != 1 {
                    return Err(IndexError::InvalidSize("missing %CSIZE%".into()));
                }
                let parsed: u64 = values[0]
                    .parse()
                    .map_err(|_| IndexError::InvalidSize(values[0].to_owned()))?;
                if parsed == 0 {
                    return Err(IndexError::InvalidSize("zero %CSIZE%".into()));
                }
                size = Some(parsed);
            }
            "SHA256SUM" => {
                if values.len() != 1 {
                    return Err(IndexError::MissingField("%SHA256SUM%"));
                }
                sha256 = Some(Sha256Digest::from_hex(values[0])?);
            }
            "BUILDDATE" => {
                if values.len() != 1 {
                    return Err(IndexError::Deb822("invalid %BUILDDATE%".into()));
                }
                let parsed: i64 = values[0]
                    .parse()
                    .map_err(|_| IndexError::Deb822("invalid %BUILDDATE% integer".into()))?;
                if parsed < 0 {
                    return Err(IndexError::Deb822("negative %BUILDDATE%".into()));
                }
                build_date = Some(parsed);
            }
            "PGPSIG" => {
                if values.len() != 1 || values[0].is_empty() {
                    return Err(IndexError::Deb822("empty %PGPSIG%".into()));
                }
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(values[0])
                    .map_err(|error| IndexError::Deb822(format!("invalid %PGPSIG%: {error}")))?;
                if decoded.is_empty() || decoded.len() > MAX_PACMAN_SIG_BYTES {
                    return Err(IndexError::Deb822("out-of-bounds %PGPSIG%".into()));
                }
                pgpsig = Some(decoded);
            }
            _ => {}
        }
    }

    Ok(ParsedDesc {
        filename: filename.ok_or(IndexError::MissingField("%FILENAME%"))?,
        name: name.ok_or(IndexError::MissingField("%NAME%"))?,
        version: version.ok_or(IndexError::MissingField("%VERSION%"))?,
        architecture: architecture.ok_or(IndexError::MissingField("%ARCH%"))?,
        size: size.ok_or(IndexError::MissingField("%CSIZE%"))?,
        sha256: sha256.ok_or(IndexError::MissingField("%SHA256SUM%"))?,
        build_date,
        pgpsig,
    })
}

#[cfg(test)]
mod regression;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    pub(super) fn tar_entry(path: &str, body: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        header[100..107].copy_from_slice(b"0000644");
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");
        let size_octal = format!("{:011o}\0", body.len());
        header[124..136].copy_from_slice(size_octal.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        let chk_octal = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(chk_octal.as_bytes());

        let mut out = header.to_vec();
        out.extend_from_slice(body);
        let pad = (512 - (body.len() % 512)) % 512;
        out.resize(out.len() + pad, 0);
        out
    }

    pub(super) fn sample_tar(with_pgpsig: bool) -> Vec<u8> {
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(b"sample-openpgp-sig");
        let pgpsig_block = if with_pgpsig {
            format!("%PGPSIG%\n{sig_b64}\n\n")
        } else {
            String::new()
        };
        let desc1 = format!(
            "%FILENAME%\nferrum-small-1:1.0-1-any.pkg.tar.zst\n\n%NAME%\nferrum-small\n\n%VERSION%\n1:1.0-1\n\n%CSIZE%\n512\n\n%SHA256SUM%\n{}\n\n{pgpsig_block}%ARCH%\nany\n\n%BUILDDATE%\n1700000100\n\n",
            "a".repeat(64)
        );
        let desc2 = format!(
            "%FILENAME%\nferrum-large-2.0-1-x86_64.pkg.tar.zst\n\n%NAME%\nferrum-large\n\n%VERSION%\n2.0-1\n\n%CSIZE%\n4096\n\n%SHA256SUM%\n{}\n\n{pgpsig_block}%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000500\n\n",
            "b".repeat(64)
        );
        let mut tar = Vec::new();
        tar.extend_from_slice(&tar_entry("ferrum-large-2.0-1/desc", desc2.as_bytes()));
        tar.extend_from_slice(&tar_entry("ferrum-small-1:1.0-1/desc", desc1.as_bytes()));
        tar.resize(tar.len() + 1024, 0);
        tar
    }

    #[test]
    fn summarizes_and_streams_gzip_pacman_db_with_embedded_signatures() {
        let raw_tar = sample_tar(true);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&raw_tar).unwrap();
        let gz_db = encoder.finish().unwrap();

        let summary =
            summarize_pacman_db(&gz_db, "os/x86_64/core.db", &ParseLimits::default()).unwrap();
        assert_eq!(summary.package_count, 2);
        assert_eq!(summary.max_build_date.as_secs(), 1_700_000_500);
        assert_eq!(summary.content_sha256, Sha256Digest::of(&raw_tar));
        assert_eq!(
            summary.canary.path.as_str(),
            "os/x86_64/ferrum-small-1:1.0-1-any.pkg.tar.zst"
        );
        assert_eq!(summary.canary.identity.size, 512);
        assert_eq!(
            summary.canary.embedded_sig.as_deref(),
            Some(b"sample-openpgp-sig".as_slice())
        );

        let mut records = Vec::new();
        let count = parse_pacman_db(
            &mut Cursor::new(&gz_db),
            "os/x86_64/core.db",
            &ParseLimits::default(),
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count, 4);
        assert_eq!(
            records[0].filename.as_str(),
            "core/os/x86_64/ferrum-large-2.0-1-x86_64.pkg.tar.zst"
        );
        assert_eq!(
            records[1].filename.as_str(),
            "core/os/x86_64/ferrum-large-2.0-1-x86_64.pkg.tar.zst.sig"
        );
        assert!(is_pacman_package_path(records[0].filename.as_str()));
        assert!(is_pacman_package_path(records[1].filename.as_str()));
    }

    #[test]
    fn summarizes_and_streams_chaotic_aur_without_embedded_signatures() {
        let raw_tar = sample_tar(false);
        let summary =
            summarize_pacman_db(&raw_tar, "x86_64/chaotic-aur.db", &ParseLimits::default())
                .unwrap();
        assert_eq!(summary.package_count, 2);
        assert_eq!(
            summary.canary.path.as_str(),
            "x86_64/ferrum-small-1:1.0-1-any.pkg.tar.zst"
        );
        assert!(summary.canary.embedded_sig.is_none());

        let mut records = Vec::new();
        let count = parse_pacman_db(
            &mut Cursor::new(&raw_tar),
            "x86_64/chaotic-aur.db",
            &ParseLimits::default(),
            &mut |record| {
                records.push(record);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            records[0].filename.as_str(),
            "chaotic-aur/x86_64/ferrum-large-2.0-1-x86_64.pkg.tar.zst"
        );
        assert!(is_pacman_package_path(records[0].filename.as_str()));
        assert!(!is_pacman_package_path("chaotic-aur/x86_64/chaotic-aur.db"));
    }
}
