//! Bounded RPM `repomd.xml` and streaming `primary.xml.{gz,zst,xz,bz2}` parsing.
//!
//! RPM repositories (`almalinux`, `rockylinux`) publish a signed `repodata/repomd.xml`
//! (with detached OpenPGP signature `repodata/repomd.xml.asc`) listing `<data>` blobs
//! including `primary.xml.{gz,zst,xz,bz2}`, which in turn lists `<package type="rpm">`
//! stanzas with `<location href="Packages/...rpm"/>`, `<size package="..."/>`, and
//! `<checksum type="sha256">`.

use std::collections::HashSet;
use std::io::{self, BufReader, Chain, Cursor, Read};

use xmlparser::{ElementEnd, Token, Tokenizer};

use crate::digest::{ObjectIdentity, Sha256Digest};
use crate::index::{IndexError, PackageRecord};
use crate::path::RepositoryPath;
use crate::release::{ParseLimits, UnixTime};

/// Maximum uncompressed `primary.xml` stream size accepted (512 MiB).
const MAX_DECOMPRESSED_PRIMARY_XML_BYTES: u64 = 512 * 1024 * 1024;
/// XZ decoder memory cap matching `ferrum-storage` proof decoding.
const XZ_DECODER_MEMORY_LIMIT: u64 = 65 * 1024 * 1024;

/// Fixed mapping from an RPM `suite` identifier to its repository-relative root directory.
pub fn rpm_suite_root(suite: &str) -> Option<&'static str> {
    match suite {
        "9-baseos-x86-64" => Some("9/BaseOS/x86_64/os"),
        "9-appstream-x86-64" => Some("9/AppStream/x86_64/os"),
        "9-extras-x86-64" => Some("9/extras/x86_64/os"),
        "9-baseos-aarch64" => Some("9/BaseOS/aarch64/os"),
        "9-appstream-aarch64" => Some("9/AppStream/aarch64/os"),
        "10-baseos-x86-64" => Some("10/BaseOS/x86_64/os"),
        "10-appstream-x86-64" => Some("10/AppStream/x86_64/os"),
        "10-extras-x86-64" => Some("10/extras/x86_64/os"),
        "10-baseos-aarch64" => Some("10/BaseOS/aarch64/os"),
        "10-appstream-aarch64" => Some("10/AppStream/aarch64/os"),
        _ => None,
    }
}

/// All known RPM suite roots and their corresponding `SuiteKey` suite names.
pub const RPM_SUITE_ROOTS: &[(&str, &str)] = &[
    ("9-baseos-x86-64", "9/BaseOS/x86_64/os"),
    ("9-appstream-x86-64", "9/AppStream/x86_64/os"),
    ("9-extras-x86-64", "9/extras/x86_64/os"),
    ("9-baseos-aarch64", "9/BaseOS/aarch64/os"),
    ("9-appstream-aarch64", "9/AppStream/aarch64/os"),
    ("10-baseos-x86-64", "10/BaseOS/x86_64/os"),
    ("10-appstream-x86-64", "10/AppStream/x86_64/os"),
    ("10-extras-x86-64", "10/extras/x86_64/os"),
    ("10-baseos-aarch64", "10/BaseOS/aarch64/os"),
    ("10-appstream-aarch64", "10/AppStream/aarch64/os"),
];

/// Splits a repository-relative RPM metadata path (`<suite_root>/<relative>`) into
/// `(suite_name, relative_path_under_suite_root)`.
pub fn split_rpm_suite_path(rest: &str) -> Option<(&'static str, &str)> {
    for &(suite, root) in RPM_SUITE_ROOTS {
        if let Some(tail) = rest.strip_prefix(root)
            && let Some(relative) = tail.strip_prefix('/')
            && !relative.is_empty()
        {
            return Some((suite, relative));
        }
    }
    None
}

/// Maps an RPM `primary.xml` index path (`<suite_root>/repodata/*primary.xml*` or
/// `repodata/*primary.xml*`) to its package directory prefix.
pub fn rpm_package_prefix(index_path: &str) -> Option<String> {
    if let Some((prefix, file)) = index_path.rsplit_once("/repodata/")
        && RPM_SUITE_ROOTS.iter().any(|&(_, root)| root == prefix)
        && is_primary_xml_filename(file)
    {
        return Some(prefix.to_owned());
    }
    None
}

/// Returns whether `path` is an RPM `primary.xml` index path.
pub fn is_rpm_primary_index_path(path: &str) -> bool {
    rpm_package_prefix(path).is_some()
}

fn is_primary_xml_filename(file: &str) -> bool {
    !file.contains('/')
        && (file.ends_with("primary.xml.gz")
            || file.ends_with("primary.xml.zst")
            || file.ends_with("primary.xml.xz")
            || file.ends_with("primary.xml.bz2")
            || file.ends_with("primary.xml"))
}

/// Returns whether a repository-relative path is a binary `.rpm` package under a
/// known RPM suite root.
pub fn is_rpm_package_path(path: &str) -> bool {
    let Some((_, relative)) = split_rpm_suite_path(path) else {
        return false;
    };
    relative.starts_with("Packages/")
        && relative.ends_with(".rpm")
        && !relative.ends_with(".src.rpm")
}

/// One `<data>` record parsed from `repomd.xml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepomdDataRecord {
    pub data_type: String,
    /// Repository-relative path (`<suite_root>/repodata/<file>`).
    pub path: RepositoryPath,
    pub identity: ObjectIdentity,
    pub timestamp: Option<i64>,
}

/// Validated `repomd.xml` summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepomdSummary {
    /// Repository-relative path (`<suite_root>/repodata/repomd.xml`).
    pub repomd_path: RepositoryPath,
    /// Repository-relative detached signature path (`<suite_root>/repodata/repomd.xml.asc`).
    pub repomd_asc_path: RepositoryPath,
    pub repomd_identity: ObjectIdentity,
    pub max_timestamp: UnixTime,
    /// Repository-relative `primary.xml.*` path.
    pub primary_path: RepositoryPath,
    pub data: Vec<RepomdDataRecord>,
}

/// Parses and validates `repomd.xml` bytes for the given `suite_root`.
pub fn parse_repomd_xml(
    xml_bytes: &[u8],
    suite_root: &str,
    limits: &ParseLimits,
) -> Result<RepomdSummary, IndexError> {
    if xml_bytes.is_empty() || xml_bytes.len() > limits.max_release {
        return Err(IndexError::TooLarge { stanza: 0 });
    }
    if !RPM_SUITE_ROOTS.iter().any(|&(_, root)| root == suite_root) {
        return Err(IndexError::Deb822(format!(
            "unsupported RPM suite root {suite_root}"
        )));
    }
    let text = std::str::from_utf8(xml_bytes)
        .map_err(|error| IndexError::Deb822(format!("repomd.xml UTF-8 error: {error}")))?;
    let repomd_path = RepositoryPath::parse_decoded(&format!("{suite_root}/repodata/repomd.xml"))?;
    let repomd_asc_path =
        RepositoryPath::parse_decoded(&format!("{suite_root}/repodata/repomd.xml.asc"))?;
    let repomd_identity = ObjectIdentity {
        sha256: Sha256Digest::of(xml_bytes),
        size: xml_bytes.len() as u64,
    };

    let mut data_records = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut primary_path: Option<RepositoryPath> = None;
    let mut max_timestamp: Option<i64> = None;

    let mut current_data_type: Option<String> = None;
    let mut current_tag: Option<String> = None;
    let mut current_checksum_is_sha256 = false;
    let mut data_sha256: Option<Sha256Digest> = None;
    let mut data_location: Option<String> = None;
    let mut data_size: Option<u64> = None;
    let mut data_timestamp: Option<i64> = None;

    for token in Tokenizer::from(text) {
        let token =
            token.map_err(|error| IndexError::Deb822(format!("repomd XML error: {error}")))?;
        match token {
            Token::ElementStart { local, .. } => {
                let name = local.as_str();
                if name == "data" {
                    current_data_type = None;
                    data_sha256 = None;
                    data_location = None;
                    data_size = None;
                    data_timestamp = None;
                } else if current_data_type.is_some() {
                    current_tag = Some(name.to_owned());
                    current_checksum_is_sha256 = false;
                }
            }
            Token::Attribute { local, value, .. } => {
                if current_tag.is_none() && local.as_str() == "type" && current_data_type.is_none()
                {
                    current_data_type = Some(value.as_str().to_owned());
                } else if let Some(tag) = current_tag.as_deref() {
                    if tag == "checksum" && local.as_str() == "type" && value.as_str() == "sha256" {
                        current_checksum_is_sha256 = true;
                    } else if tag == "location" && local.as_str() == "href" {
                        data_location = Some(value.as_str().to_owned());
                    }
                }
            }
            Token::Text { text } => {
                if let Some(tag) = current_tag.as_deref() {
                    let trimmed = text.as_str().trim();
                    if !trimmed.is_empty() {
                        match tag {
                            "checksum" if current_checksum_is_sha256 => {
                                data_sha256 = Some(Sha256Digest::from_hex(trimmed)?);
                            }
                            "size" => {
                                let parsed: u64 = trimmed
                                    .parse()
                                    .map_err(|_| IndexError::InvalidSize(trimmed.to_owned()))?;
                                if parsed == 0 {
                                    return Err(IndexError::InvalidSize("zero repomd size".into()));
                                }
                                data_size = Some(parsed);
                            }
                            "timestamp" => {
                                if let Ok(ts) = trimmed.parse::<f64>()
                                    && ts >= 0.0
                                {
                                    data_timestamp = Some(ts as i64);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Token::ElementEnd { end, .. } => match end {
                ElementEnd::Close(_, local) if local.as_str() == "data" => {
                    if let Some(dtype) = current_data_type.take() {
                        if dtype == "primary" {
                            let href = data_location
                                .take()
                                .ok_or(IndexError::MissingField("repomd primary location"))?;
                            let file = href.strip_prefix("repodata/").ok_or_else(|| {
                                IndexError::Deb822("repomd primary must be under repodata/".into())
                            })?;
                            if !is_primary_xml_filename(file) {
                                return Err(IndexError::Deb822(format!(
                                    "unsupported repomd primary filename {file}"
                                )));
                            }
                            let sha256 = data_sha256
                                .take()
                                .ok_or(IndexError::MissingField("repomd primary sha256"))?;
                            let size = data_size
                                .take()
                                .ok_or(IndexError::MissingField("repomd primary size"))?;
                            let full_path =
                                RepositoryPath::parse_decoded(&format!("{suite_root}/{href}"))?;
                            if let Some(ts) = data_timestamp {
                                max_timestamp = Some(max_timestamp.map_or(ts, |prev| prev.max(ts)));
                            }
                            if seen_paths.insert(full_path.clone()) {
                                primary_path = Some(full_path.clone());
                                data_records.push(RepomdDataRecord {
                                    data_type: dtype,
                                    path: full_path,
                                    identity: ObjectIdentity { sha256, size },
                                    timestamp: data_timestamp,
                                });
                            }
                        } else if let (Some(href), Some(sha256), Some(size)) =
                            (data_location.take(), data_sha256.take(), data_size.take())
                            && let Some(file) = href.strip_prefix("repodata/")
                            && !file.is_empty()
                            && !file.contains('/')
                        {
                            let full_path =
                                RepositoryPath::parse_decoded(&format!("{suite_root}/{href}"))?;
                            if let Some(ts) = data_timestamp {
                                max_timestamp = Some(max_timestamp.map_or(ts, |prev| prev.max(ts)));
                            }
                            if seen_paths.insert(full_path.clone()) {
                                data_records.push(RepomdDataRecord {
                                    data_type: dtype,
                                    path: full_path,
                                    identity: ObjectIdentity { sha256, size },
                                    timestamp: data_timestamp,
                                });
                            }
                        }
                    }
                    current_tag = None;
                }
                ElementEnd::Close(_, _) | ElementEnd::Empty => {
                    current_tag = None;
                }
                ElementEnd::Open => {}
            },
            _ => {}
        }
    }

    let Some(primary_path) = primary_path else {
        return Err(IndexError::MissingField("repomd primary data"));
    };
    Ok(RepomdSummary {
        repomd_path,
        repomd_asc_path,
        repomd_identity,
        max_timestamp: UnixTime::from_secs(max_timestamp.unwrap_or(0)),
        primary_path,
        data: data_records,
    })
}

/// Streams a compressed or uncompressed `primary.xml` and emits [`PackageRecord`]s
/// for every `x86_64`, `aarch64`, and `noarch` RPM package.
pub fn parse_rpm_primary_xml<R, S>(
    reader: &mut R,
    index_path: &str,
    limits: &ParseLimits,
    sink: &mut S,
) -> Result<usize, IndexError>
where
    R: Read,
    S: FnMut(PackageRecord) -> Result<(), IndexError>,
{
    let Some(suite_root) = rpm_package_prefix(index_path) else {
        return Err(IndexError::Deb822(format!(
            "unsupported RPM primary index path {index_path}"
        )));
    };
    let mut magic = [0u8; 6];
    let mut magic_len = 0usize;
    while magic_len < magic.len() {
        let count = reader.read(&mut magic[magic_len..])?;
        if count == 0 {
            break;
        }
        magic_len += count;
    }
    let delivered = {
        let prefix = Cursor::new(magic[..magic_len].to_vec());
        let chained: Chain<Cursor<Vec<u8>>, &mut R> = prefix.chain(&mut *reader);
        let decoder: Box<dyn Read + '_> = if magic_len >= 2 && magic[..2] == [0x1f, 0x8b] {
            Box::new(flate2::read::MultiGzDecoder::new(BufReader::new(chained)))
        } else if magic_len >= 4 && magic[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
            let stream = ruzstd::decoding::StreamingDecoder::new(BufReader::new(chained))
                .map_err(|error| IndexError::Deb822(format!("zstd init failed: {error}")))?;
            Box::new(stream)
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

        let mut total_decompressed = 0u64;
        let mut buffer = Vec::with_capacity(64 * 1024);
        let mut chunk = [0u8; 32 * 1024];
        let mut stanza = 0usize;
        let mut count = 0usize;
        let mut seen_paths = HashSet::new();
        let mut reader_inner = decoder;

        loop {
            let read_bytes = reader_inner.read(&mut chunk)?;
            if read_bytes > 0 {
                total_decompressed = total_decompressed
                    .checked_add(read_bytes as u64)
                    .ok_or_else(|| io::Error::other("primary.xml size overflow"))?;
                if total_decompressed > MAX_DECOMPRESSED_PRIMARY_XML_BYTES {
                    return Err(IndexError::TooLarge {
                        stanza: stanza.saturating_add(1),
                    });
                }
                buffer.extend_from_slice(&chunk[..read_bytes]);
            }

            while let Some(end_pos) = find_subslice(&buffer, b"</package>") {
                let close_end = end_pos + b"</package>".len();
                let Some(start_pos) = find_subslice(&buffer[..close_end], b"<package") else {
                    return Err(IndexError::Deb822(
                        "closing </package> without <package".into(),
                    ));
                };
                stanza = stanza.saturating_add(1);
                let stanza_bytes = &buffer[start_pos..close_end];
                if stanza_bytes.len() > limits.max_stanza {
                    return Err(IndexError::TooLarge { stanza });
                }
                let stanza_text = std::str::from_utf8(stanza_bytes)
                    .map_err(|error| IndexError::Deb822(format!("primary.xml UTF-8: {error}")))?;
                if let Some(record) = parse_rpm_package_stanza(stanza_text, &suite_root)? {
                    if !seen_paths.insert(record.filename.clone()) {
                        return Err(IndexError::DuplicateField(
                            record.filename.as_str().to_owned(),
                        ));
                    }
                    sink(record)?;
                    count = count.saturating_add(1);
                }
                buffer.drain(..close_end);
            }

            if buffer.len() > limits.max_stanza {
                return Err(IndexError::TooLarge {
                    stanza: stanza.saturating_add(1),
                });
            }
            if read_bytes == 0 {
                break;
            }
        }
        count
    };
    let mut tail = [0u8; 4096];
    while reader.read(&mut tail)? != 0 {}
    Ok(delivered)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_rpm_package_stanza(
    stanza_xml: &str,
    suite_root: &str,
) -> Result<Option<PackageRecord>, IndexError> {
    let mut name: Option<String> = None;
    let mut arch: Option<String> = None;
    let mut version: Option<String> = None;
    let mut sha256: Option<Sha256Digest> = None;
    let mut size: Option<u64> = None;
    let mut location: Option<String> = None;

    let mut depth = 0usize;
    let mut current_top_tag: Option<String> = None;
    let mut checksum_is_sha256 = false;
    let mut ver_epoch: Option<String> = None;
    let mut ver_ver: Option<String> = None;
    let mut ver_rel: Option<String> = None;

    for token in Tokenizer::from(stanza_xml) {
        let token =
            token.map_err(|error| IndexError::Deb822(format!("primary.xml error: {error}")))?;
        match token {
            Token::ElementStart { local, .. } => {
                depth = depth.saturating_add(1);
                if depth == 2 {
                    current_top_tag = Some(local.as_str().to_owned());
                    checksum_is_sha256 = false;
                    if local.as_str() == "version" {
                        ver_epoch = None;
                        ver_ver = None;
                        ver_rel = None;
                    }
                }
            }
            Token::Attribute { local, value, .. } if depth == 2 => {
                if let Some(tag) = current_top_tag.as_deref() {
                    match (tag, local.as_str()) {
                        ("version", "epoch") => ver_epoch = Some(value.as_str().to_owned()),
                        ("version", "ver") => ver_ver = Some(value.as_str().to_owned()),
                        ("version", "rel") => ver_rel = Some(value.as_str().to_owned()),
                        ("checksum", "type") if value.as_str() == "sha256" => {
                            checksum_is_sha256 = true;
                        }
                        ("size", "package") => {
                            let parsed: u64 = value
                                .as_str()
                                .parse()
                                .map_err(|_| IndexError::InvalidSize(value.as_str().to_owned()))?;
                            if parsed == 0 {
                                return Err(IndexError::InvalidSize(
                                    "zero RPM package size".into(),
                                ));
                            }
                            size = Some(parsed);
                        }
                        ("location", "href") => {
                            location = Some(value.as_str().to_owned());
                        }
                        _ => {}
                    }
                }
            }
            Token::Text { text } if depth == 2 => {
                if let Some(tag) = current_top_tag.as_deref() {
                    let trimmed = text.as_str().trim();
                    if !trimmed.is_empty() {
                        match tag {
                            "name" => name = Some(trimmed.to_owned()),
                            "arch" => arch = Some(trimmed.to_owned()),
                            "checksum" if checksum_is_sha256 => {
                                sha256 = Some(Sha256Digest::from_hex(trimmed)?);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Token::ElementEnd { end, .. } => {
                if depth == 2
                    && current_top_tag.as_deref() == Some("version")
                    && let (Some(v), Some(r)) = (ver_ver.take(), ver_rel.take())
                {
                    let epoch = ver_epoch.take().unwrap_or_else(|| "0".into());
                    version = Some(if epoch == "0" || epoch.is_empty() {
                        format!("{v}-{r}")
                    } else {
                        format!("{epoch}:{v}-{r}")
                    });
                }
                match end {
                    ElementEnd::Close(_, _) | ElementEnd::Empty => {
                        if depth == 2 {
                            current_top_tag = None;
                        }
                        depth = depth.saturating_sub(1);
                    }
                    ElementEnd::Open => {}
                }
            }
            _ => {}
        }
    }

    let name = name.ok_or(IndexError::MissingField("rpm <name>"))?;
    let arch = arch.ok_or(IndexError::MissingField("rpm <arch>"))?;
    let version = version.ok_or(IndexError::MissingField("rpm <version>"))?;
    let sha256 = sha256.ok_or(IndexError::MissingField("rpm <checksum type=sha256>"))?;
    let size = size.ok_or(IndexError::MissingField("rpm <size package>"))?;
    let href = location.ok_or(IndexError::MissingField("rpm <location href>"))?;

    if !matches!(arch.as_str(), "x86_64" | "aarch64" | "noarch") {
        return Ok(None);
    }
    let full_path = format!("{suite_root}/{href}");
    if !is_rpm_package_path(&full_path) {
        return Err(IndexError::Deb822(format!("invalid RPM href {href}")));
    }
    let filename = RepositoryPath::parse_decoded(&full_path)?;
    Ok(Some(PackageRecord {
        package: name,
        version,
        architecture: arch,
        filename,
        size,
        sha256,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn parses_repomd_and_streams_primary_xml_gz() {
        let primary_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">
<package type="rpm">
  <name>bash</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="5.2.15" rel="2.el9"/>
  <checksum type="sha256" pkgid="YES">{}</checksum>
  <size package="1820412" installed="7000000" archive="7100000"/>
  <location href="Packages/bash-5.2.15-2.el9.x86_64.rpm"/>
</package>
<package type="rpm">
  <name>setup</name>
  <arch>noarch</arch>
  <version epoch="1" ver="2.13.7" rel="10.el9"/>
  <checksum type="sha256" pkgid="YES">{}</checksum>
  <size package="150200" installed="500000" archive="510000"/>
  <location href="Packages/s/setup-2.13.7-10.el9.noarch.rpm"/>
</package>
</metadata>"#,
            "a".repeat(64),
            "b".repeat(64)
        );
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(primary_xml.as_bytes()).unwrap();
        let primary_gz = gz.finish().unwrap();
        let primary_sha = Sha256Digest::of(&primary_gz).to_hex();
        let primary_size = primary_gz.len();

        let repomd_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1792142769</revision>
  <data type="primary">
    <checksum type="sha256">{primary_sha}</checksum>
    <location href="repodata/{primary_sha}-primary.xml.gz"/>
    <timestamp>1792142749</timestamp>
    <size>{primary_size}</size>
  </data>
</repomd>"#
        );

        let summary = parse_repomd_xml(
            repomd_xml.as_bytes(),
            "9/BaseOS/x86_64/os",
            &ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            summary.repomd_path.as_str(),
            "9/BaseOS/x86_64/os/repodata/repomd.xml"
        );
        assert_eq!(
            summary.primary_path.as_str(),
            format!("9/BaseOS/x86_64/os/repodata/{primary_sha}-primary.xml.gz")
        );
        assert_eq!(summary.max_timestamp.as_secs(), 1_792_142_749);

        let mut records = Vec::new();
        let count = parse_rpm_primary_xml(
            &mut Cursor::new(&primary_gz),
            summary.primary_path.as_str(),
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
            "9/BaseOS/x86_64/os/Packages/bash-5.2.15-2.el9.x86_64.rpm"
        );
        assert_eq!(records[1].version, "1:2.13.7-10.el9");
        assert!(is_rpm_package_path(records[0].filename.as_str()));
        assert!(is_rpm_package_path(records[1].filename.as_str()));
    }
}
