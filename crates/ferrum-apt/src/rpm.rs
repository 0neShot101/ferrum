//! Bounded RPM `repomd.xml` and streaming `primary.xml.{gz,zst,xz,bz2}` parsing.
//!
//! RPM repositories (`almalinux`, `rockylinux`) publish a signed `repodata/repomd.xml`
//! (with detached OpenPGP signature `repodata/repomd.xml.asc`) listing `<data>` blobs
//! including `primary.xml.{gz,zst,xz,bz2}`, which in turn lists `<package type="rpm">`
//! stanzas with `<location href="Packages/...rpm"/>`, `<size package="..."/>`, and
//! `<checksum type="sha256">`.

use std::collections::HashSet;
use std::io::{BufReader, Chain, Cursor, Read};

mod xml;

use crate::pacman::zstd::{MultiZstdDecoder, is_zstd_magic};
use xml::Element;

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

    xml::document(
        Cursor::new(text.as_bytes()),
        "repomd",
        "http://linux.duke.edu/metadata/repo",
        limits,
        limits.max_release as u64,
        |data| {
            if data.name != "data" || !data.in_document_namespace() {
                return Ok(());
            }
            let dtype = data
                .attribute("type")
                .ok_or(IndexError::MissingField("repomd data type"))?;
            let checksum = data.field("checksum")?;
            let location = data.field("location")?;
            let size = data.field("size")?;
            let timestamp = data.field("timestamp")?;
            if let Some(location) = location
                && !location.scalar()?.is_empty()
            {
                return Err(IndexError::Deb822("repomd location must be empty".into()));
            }
            let sha256 = match checksum {
                Some(checksum) if checksum.attribute("type") == Some("sha256") => {
                    Some(Sha256Digest::from_hex(checksum.scalar()?)?)
                }
                _ => None,
            };
            let size = size
                .map(|size| parse_positive_size(size.scalar()?))
                .transpose()?;
            let timestamp = timestamp
                .map(|timestamp| {
                    let text = timestamp.scalar()?;
                    let value = text
                        .parse::<i64>()
                        .map_err(|_| IndexError::Deb822("invalid repomd timestamp".into()))?;
                    if value < 0 {
                        return Err(IndexError::Deb822("negative repomd timestamp".into()));
                    }
                    Ok(value)
                })
                .transpose()?;
            let href = location.and_then(|location| location.attribute("href"));
            let (Some(href), Some(sha256), Some(size)) = (href, sha256, size) else {
                if dtype == "primary" {
                    return Err(IndexError::MissingField(
                        "repomd primary location/sha256/size",
                    ));
                }
                return Ok(());
            };
            let file = href
                .strip_prefix("repodata/")
                .filter(|file| !file.is_empty() && !file.contains('/'))
                .ok_or_else(|| IndexError::Deb822("repomd data must be under repodata/".into()))?;
            if dtype == "primary" && !is_primary_xml_filename(file) {
                return Err(IndexError::Deb822(format!(
                    "unsupported repomd primary filename {file}"
                )));
            }
            let full_path = RepositoryPath::parse_decoded(&format!("{suite_root}/{href}"))?;
            if !seen_paths.insert(full_path.clone()) {
                return Err(IndexError::DuplicateField(full_path.as_str().to_owned()));
            }
            if dtype == "primary" && primary_path.replace(full_path.clone()).is_some() {
                return Err(IndexError::DuplicateField("repomd primary data".into()));
            }
            if let Some(timestamp) = timestamp {
                max_timestamp =
                    Some(max_timestamp.map_or(timestamp, |previous| previous.max(timestamp)));
            }
            data_records.push(RepomdDataRecord {
                data_type: dtype.to_owned(),
                path: full_path,
                identity: ObjectIdentity { sha256, size },
                timestamp,
            });
            Ok(())
        },
    )?;

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

        let mut count = 0usize;
        let mut seen_paths = HashSet::new();
        xml::document(
            decoder,
            "metadata",
            "http://linux.duke.edu/metadata/common",
            limits,
            MAX_DECOMPRESSED_PRIMARY_XML_BYTES,
            |package| {
                if package.name != "package" || !package.in_document_namespace() {
                    return Err(IndexError::Deb822("unexpected primary XML child".into()));
                }
                if let Some(record) = parse_rpm_package(&package, &suite_root)? {
                    if !seen_paths.insert(record.filename.clone()) {
                        return Err(IndexError::DuplicateField(
                            record.filename.as_str().to_owned(),
                        ));
                    }
                    sink(record)?;
                    count = count.saturating_add(1);
                }
                Ok(())
            },
        )?;
        count
    };
    Ok(delivered)
}

fn parse_positive_size(text: &str) -> Result<u64, IndexError> {
    let value = text
        .parse::<u64>()
        .map_err(|_| IndexError::InvalidSize(text.to_owned()))?;
    if value == 0 {
        return Err(IndexError::InvalidSize("zero RPM size".into()));
    }
    Ok(value)
}

fn required_field<'a>(element: &'a Element, name: &'static str) -> Result<&'a Element, IndexError> {
    element.field(name)?.ok_or(IndexError::MissingField(name))
}

fn required_attribute<'a>(element: &'a Element, name: &'static str) -> Result<&'a str, IndexError> {
    element
        .attribute(name)
        .filter(|value| !value.is_empty())
        .ok_or(IndexError::MissingField(name))
}

fn parse_rpm_package(
    package: &Element,
    suite_root: &str,
) -> Result<Option<PackageRecord>, IndexError> {
    if package.attribute("type") != Some("rpm") {
        return Err(IndexError::Deb822(
            "primary package type must be rpm".into(),
        ));
    }
    let name = required_field(package, "name")?.scalar()?;
    let arch = required_field(package, "arch")?.scalar()?;
    let version = required_field(package, "version")?;
    let checksum = required_field(package, "checksum")?;
    let size = required_field(package, "size")?;
    let location = required_field(package, "location")?;
    if !version.scalar()?.is_empty() || !size.scalar()?.is_empty() || !location.scalar()?.is_empty()
    {
        return Err(IndexError::Deb822(
            "RPM version/size/location must be empty".into(),
        ));
    }
    if name.is_empty() || arch.is_empty() {
        return Err(IndexError::MissingField("RPM name/arch"));
    }
    if checksum.attribute("type") != Some("sha256") {
        return Err(IndexError::MissingField("rpm <checksum type=sha256>"));
    }
    let sha256 = Sha256Digest::from_hex(checksum.scalar()?)?;
    let size = parse_positive_size(required_attribute(size, "package")?)?;
    let href = required_attribute(location, "href")?;
    let ver = required_attribute(version, "ver")?;
    let rel = required_attribute(version, "rel")?;
    let epoch = version.attribute("epoch").unwrap_or("0");
    let version = if epoch == "0" || epoch.is_empty() {
        format!("{ver}-{rel}")
    } else {
        format!("{epoch}:{ver}-{rel}")
    };
    if !matches!(arch, "x86_64" | "aarch64" | "noarch") {
        return Ok(None);
    }
    let full_path = format!("{suite_root}/{href}");
    if !is_rpm_package_path(&full_path) {
        return Err(IndexError::Deb822(format!("invalid RPM href {href}")));
    }
    let filename = RepositoryPath::parse_decoded(&full_path)?;
    Ok(Some(PackageRecord {
        package: name.to_owned(),
        version,
        architecture: arch.to_owned(),
        filename,
        size,
        sha256,
    }))
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
