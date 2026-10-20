//! The selected binary-client closure, shared by publication, recovery and inventory.
use crate::release::{Release, ReleaseEntry};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    #[error("unsupported compression or representation for required target {0}")]
    Unsupported(String),
    #[error("missing selected {0}/binary-amd64/Packages")]
    MissingPackages(String),
    #[error("selected target lacks the authenticated SHA256 required for bounded staging: {0}")]
    MissingSha256(String),
    #[error("selected target disappeared from authenticated Release: {0}")]
    MissingTarget(String),
}
#[derive(Clone, Debug)]
pub struct Target {
    pub path: String,
    pub logical: String,
    pub category: &'static str,
    pub compression: Option<&'static str>,
    pub signed_size: u64,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub pinned: bool,
    pub derived_from: Option<String>,
}
#[derive(Clone, Debug)]
pub struct Excluded {
    pub path: String,
    pub reason: &'static str,
    pub signed_size: u64,
}
pub fn representation(path: &str) -> (&str, Option<&'static str>) {
    for (suffix, compression) in [(".xz", "xz"), (".gz", "gzip"), (".bz2", "bzip2")] {
        if let Some(logical) = path.strip_suffix(suffix) {
            return (logical, Some(compression));
        }
    }
    (path, None)
}
struct Selected<'a> {
    logical: &'a str,
    category: &'static str,
    compression: Option<&'static str>,
}
fn category<'a>(
    path: &'a str,
    components: &[&str],
    ubuntu: bool,
    architectures: &[&str],
) -> Result<Result<Selected<'a>, &'static str>, SelectionError> {
    if path.split('/').any(|part| part.ends_with(".diff")) {
        return Ok(Err("PDiff acquired through optional authenticated closure"));
    }
    if path
        .split('/')
        .any(|part| part == "source" || part == "Sources")
    {
        return Ok(Err("source packages excluded"));
    }
    if path.contains("debian-installer") || path.contains("installer-") {
        return Ok(Err("installer and udeb metadata excluded"));
    }
    let (logical, compression) = representation(path);
    let (relative, component) = match logical.split_once('/') {
        Some((component, relative)) if components.contains(&component) => (relative, true),
        None => (logical, false),
        _ => return Ok(Err("unconfigured component or target")),
    };
    let unsupported = || SelectionError::Unsupported(path.to_owned());
    let category = match relative.split_once('/') {
        Some((arch_dir, file))
            if component
                && (arch_dir == "binary-all"
                    || arch_dir
                        .strip_prefix("binary-")
                        .is_some_and(|arch| architectures.contains(&arch))) =>
        {
            match file {
                "Packages" => Some("Packages"),
                "Release" => Some("component Release"),
                _ if file.starts_with("Packages.") || file.starts_with("Release.") => {
                    return Err(unsupported());
                }
                _ => None,
            }
        }
        Some(("i18n", file)) if component && file.starts_with("Translation-") => {
            let language = file.strip_prefix("Translation-").unwrap_or("");
            if language.is_empty()
                || !language
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'@' | b'-'))
            {
                return Err(unsupported());
            }
            Some("Translation")
        }
        Some(("i18n", "Index")) if component => Some("Translation index"),
        Some(("dep11", file)) if component => {
            if file == "Components-all.yml"
                || architectures
                    .iter()
                    .any(|arch| file == format!("Components-{arch}.yml"))
            {
                Some("DEP11/icons")
            } else if file.starts_with("Components-all.yml.")
                || architectures
                    .iter()
                    .any(|arch| file.starts_with(&format!("Components-{arch}.yml.")))
            {
                return Err(unsupported());
            } else if file.starts_with("icons-") {
                if !file.ends_with(".tar") || file.contains('/') {
                    return Err(unsupported());
                }
                Some("DEP11/icons")
            } else {
                None
            }
        }
        Some(("cnf", file)) if component => {
            if architectures
                .iter()
                .any(|arch| file == format!("Commands-{arch}"))
            {
                Some("command-not-found")
            } else if architectures
                .iter()
                .any(|arch| file.starts_with(&format!("Commands-{arch}.")))
            {
                return Err(unsupported());
            } else {
                None
            }
        }
        None if component && relative == "Release" => Some("component Release"),
        None if component && relative.starts_with("Release.") => return Err(unsupported()),
        None if component || ubuntu => {
            if relative == "Contents-all"
                || architectures
                    .iter()
                    .any(|arch| relative == format!("Contents-{arch}"))
            {
                Some("Contents")
            } else if relative.starts_with("Contents-all.")
                || architectures
                    .iter()
                    .any(|arch| relative.starts_with(&format!("Contents-{arch}.")))
            {
                return Err(unsupported());
            } else {
                None
            }
        }
        _ => None,
    };
    Ok(match category {
        Some(category) => Ok(Selected {
            logical,
            category,
            compression,
        }),
        None => Err("foreign architecture or non-profile target"),
    })
}
/// All advertised selected representations are mandatory, including paths listed
/// only with weak hashes: missing SHA256 refuses the entire candidate. Header
/// Components need not spell acquisition prefixes; configured components are
/// authorized only by their authenticated required binary-amd64 Packages paths.
/// `binary-all` is selected whenever advertised, even when
/// No-Support-for-Architecture-all places all stanzas in binary-amd64; its absence
/// never creates an invented target requirement.
pub fn select(
    release: &Release,
    components: &[&str],
    ubuntu: bool,
) -> Result<(Vec<Target>, Vec<Excluded>), SelectionError> {
    select_for_architectures(release, components, ubuntu, &["amd64"])
}

/// Selects binary metadata targets for the requested client architectures
/// (e.g. `&["amd64"]`, `&["arm64"]`, or `&["amd64", "arm64"]`) plus `all`.
pub fn select_for_architectures(
    release: &Release,
    components: &[&str],
    ubuntu: bool,
    architectures: &[&str],
) -> Result<(Vec<Target>, Vec<Excluded>), SelectionError> {
    let mut selected = Vec::new();
    let mut excluded = Vec::new();
    for entry in release.entries() {
        let path = entry.path.as_str();
        match category(path, components, ubuntu, architectures)? {
            Ok(Selected {
                logical,
                category,
                compression,
            }) => {
                if entry.sha256.is_none() {
                    return Err(SelectionError::MissingSha256(path.to_owned()));
                }
                selected.push(Target {
                    path: path.to_owned(),
                    logical: logical.to_owned(),
                    category,
                    compression,
                    signed_size: entry.size,
                    sha256: entry.sha256.map(|digest| digest.to_hex()),
                    sha512: entry.sha512.map(|digest| digest.to_hex()),
                    pinned: true,
                    derived_from: None,
                });
            }
            Err(reason) => excluded.push(Excluded {
                path: path.to_owned(),
                reason,
                signed_size: entry.size,
            }),
        }
    }
    let rank = |compression| match compression {
        Some("xz") => 0,
        Some("gzip") => 1,
        Some("bzip2") => 2,
        _ => 3,
    };
    let mut sources: BTreeMap<&str, &Target> = BTreeMap::new();
    for target in &selected {
        if target.compression.is_some() {
            sources
                .entry(&target.logical)
                .and_modify(|current| {
                    if rank(target.compression) < rank(current.compression) {
                        *current = target;
                    }
                })
                .or_insert(target);
        }
    }
    let sources: BTreeMap<String, String> = sources
        .into_iter()
        .map(|(logical, target)| (logical.to_owned(), target.path.clone()))
        .collect();
    for target in &mut selected {
        if target.compression.is_none()
            && let Some(source) = sources.get(&target.logical)
        {
            target.pinned = false;
            target.derived_from = Some(source.clone());
        }
    }
    for component in components {
        let has_packages = architectures.iter().any(|arch| {
            selected.iter().any(|target| {
                target.category == "Packages"
                    && target.logical == format!("{component}/binary-{arch}/Packages")
            })
        });
        if !has_packages {
            return Err(SelectionError::MissingPackages((*component).to_owned()));
        }
    }
    Ok((selected, excluded))
}
/// One preferred representation per logical Packages index for inventory scans.
pub fn packages<'a>(
    release: &'a Release,
    targets: &[Target],
) -> Result<Vec<&'a ReleaseEntry>, SelectionError> {
    let mut chosen: BTreeMap<&str, &Target> = BTreeMap::new();
    let rank = |target: &Target| match target.compression {
        Some("xz") => 0,
        Some("gzip") => 1,
        Some("bzip2") => 2,
        _ => 3,
    };
    for target in targets
        .iter()
        .filter(|target| target.category == "Packages")
    {
        chosen
            .entry(&target.logical)
            .and_modify(|current| {
                if rank(target) < rank(current) {
                    *current = target;
                }
            })
            .or_insert(target);
    }
    chosen
        .values()
        .map(|target| {
            release
                .entries()
                .iter()
                .find(|entry| entry.path.as_str() == target.path)
                .ok_or_else(|| SelectionError::MissingTarget(target.path.clone()))
        })
        .collect()
}

/// Optional PDiff roots for selected full indexes. Patch names are never
/// selected from Release or guessed from suffixes: only the authenticated
/// Index may authorize their exact closure. Unsupported roots use full indexes.
pub fn pdiffs<'a>(release: &'a Release, targets: &[Target]) -> Vec<&'a ReleaseEntry> {
    let roots: Vec<_> = release
        .entries()
        .iter()
        .filter(|entry| {
            let Some(base) = entry.path.as_str().strip_suffix(".diff/Index") else {
                return false;
            };
            entry.sha256.is_some()
                && entry.size <= crate::pdiff::MAX_INDEX_BYTES as u64
                && targets.iter().any(|target| target.logical == base)
                && release
                    .entries()
                    .iter()
                    .any(|full| full.path.as_str() == base && full.sha256.is_some())
        })
        .collect();
    if roots.len() > crate::pdiff::MAX_INDEXES {
        Vec::new()
    } else {
        roots
    }
}
#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    #[test]
    fn required_unknown_codecs_fail_closed() {
        for path in [
            "main/binary-amd64/Packages.zst",
            "main/Contents-all.lz4",
            "main/i18n/Translation-en.zst",
            "main/dep11/icons-48x48.tar.zst",
            "main/cnf/Commands-amd64.zst",
        ] {
            assert!(
                category(path, &["main"], false, &["amd64"]).is_err(),
                "{path}"
            );
        }
        assert!(matches!(
            category("main/binary-all/Packages.xz", &["main"], false, &["amd64"]),
            Ok(Ok(_))
        ));
        assert!(matches!(
            category("Contents-amd64.gz", &["main"], false, &["amd64"]),
            Ok(Err(_))
        ));
        assert!(matches!(
            category("Contents-amd64.gz", &["main"], true, &["amd64"]),
            Ok(Ok(_))
        ));
    }
    fn release_text(paths: &[&str], hash: &str) -> String {
        let mut text = String::from(
            "Origin: Debian\nSuite: trixie\nCodename: trixie\nArchitectures: amd64 all\nComponents: main\nNo-Support-for-Architecture-all: Packages\nDate: Thu, 01 Jan 1970 00:00:00 UTC\nAcquire-By-Hash: yes\n",
        );
        if hash != "SHA256" {
            let path = "main/binary-amd64/Packages";
            let digest = crate::digest::Sha256Digest::of(path.as_bytes()).to_hex();
            text.push_str(&format!("SHA256:\n {digest} 1 {path}\n"));
        }
        text.push_str(&format!("{hash}:\n"));
        for path in paths {
            let digest = match hash {
                "SHA256" => crate::digest::Sha256Digest::of(path.as_bytes()).to_hex(),
                "SHA512" => "a".repeat(128),
                "SHA1" => "a".repeat(40),
                "MD5Sum" => "a".repeat(32),
                _ => panic!("unknown fixture hash"),
            };
            text.push_str(&format!(" {digest} 1 {path}\n"));
        }
        text
    }
    fn release(paths: &[&str], hash: &str) -> Release {
        Release::parse(
            release_text(paths, hash).as_bytes(),
            &crate::release::ParseLimits::default(),
        )
        .expect("Release fixture")
    }
    #[test]
    fn complete_binary_profile_preserves_variants_and_derives_expanded_siblings() {
        let paths = [
            "main/binary-amd64/Packages",
            "main/binary-amd64/Packages.gz",
            "main/binary-amd64/Packages.xz",
            "main/binary-amd64/Packages.bz2",
            "main/binary-all/Packages",
            "main/binary-all/Packages.gz",
            "main/binary-amd64/Release",
            "main/Release",
            "main/i18n/Translation-en",
            "main/i18n/Translation-en.gz",
            "main/i18n/Translation-pt_BR.bz2",
            "main/i18n/Index",
            "main/dep11/Components-amd64.yml",
            "main/dep11/Components-amd64.yml.xz",
            "main/dep11/Components-all.yml.gz",
            "main/dep11/icons-128x128@2.tar.gz",
            "main/cnf/Commands-amd64",
            "main/cnf/Commands-amd64.xz",
            "main/Contents-amd64",
            "main/Contents-amd64.gz",
            "main/Contents-all.xz",
            "Contents-amd64.gz",
            "main/binary-arm64/Packages.xz",
            "main/i18n/Translation-en.diff/Index",
            "main/source/Sources.xz",
        ];
        let release = release(&paths, "SHA256");
        let (selected, excluded) =
            select(&release, &["main"], false).expect("complete Debian profile");
        assert_eq!(selected.len(), 21);
        assert_eq!(excluded.len(), 4);
        let packages = selected
            .iter()
            .find(|target| target.path == "main/binary-amd64/Packages")
            .expect("expanded Packages");
        assert!(!packages.pinned);
        assert_eq!(
            packages.derived_from.as_deref(),
            Some("main/binary-amd64/Packages.xz")
        );
        assert!(
            selected
                .iter()
                .filter(|target| target.compression.is_some())
                .all(|target| target.pinned)
        );
        assert!(
            selected
                .iter()
                .any(|target| target.logical == "main/binary-all/Packages")
        );
        let (ubuntu, _) = select(&release, &["main"], true).expect("Ubuntu suite-root Contents");
        assert!(
            ubuntu
                .iter()
                .any(|target| target.path == "Contents-amd64.gz")
        );
        assert!(select(&release, &["main", "contrib"], false).is_err());
    }
    #[test]
    fn unsupported_selected_digest_or_codec_refuses_the_whole_candidate() {
        let missing = release(&["main/binary-amd64/Packages.xz"], "SHA512");
        assert!(
            matches!(select(&missing,&["main"],false),Err(SelectionError::MissingSha256(path)) if path == "main/binary-amd64/Packages.xz")
        );
        let unsupported = release(
            &["main/binary-amd64/Packages.xz", "main/Contents-all.zst"],
            "SHA256",
        );
        assert!(matches!(
            select(&unsupported, &["main"], false),
            Err(SelectionError::Unsupported(_))
        ));
    }
    #[test]
    fn selected_weak_only_advertisements_refuse_complete_closure() {
        for hash in ["SHA1", "MD5Sum"] {
            for path in [
                "main/binary-amd64/Packages.xz",
                "main/binary-all/Packages.xz",
                "main/binary-all/Release",
                "main/binary-amd64/Release",
                "main/Release",
                "main/Contents-amd64.gz",
                "main/Contents-all.xz",
                "main/i18n/Translation-en.bz2",
                "main/i18n/Index",
                "main/dep11/Components-amd64.yml.xz",
                "main/dep11/icons-48x48.tar.gz",
                "main/cnf/Commands-amd64.xz",
            ] {
                let release = release(&[path], hash);
                assert!(
                    matches!(
                        select(&release, &["main"], false),
                        Err(SelectionError::MissingSha256(missing)) if missing == path
                    ),
                    "{hash}: {path}"
                );
            }
            // A strong compressed source does not excuse an advertised expanded
            // sibling without its own SHA256, even if it could be derived.
            let mut text = release_text(
                &["main/binary-amd64/Packages.xz", "main/Contents-amd64.gz"],
                "SHA256",
            );
            let digest = "a".repeat(if hash == "SHA1" { 40 } else { 32 });
            text.push_str(&format!("{hash}:\n {digest} 1 main/Contents-amd64\n"));
            let sibling = Release::parse(text.as_bytes(), &crate::release::ParseLimits::default())
                .expect("weak expanded sibling");
            assert!(matches!(
                select(&sibling, &["main"], false),
                Err(SelectionError::MissingSha256(path)) if path == "main/Contents-amd64"
            ));
            let release = release(&["Contents-amd64.gz"], hash);
            assert!(matches!(
                select(&release, &["main"], true),
                Err(SelectionError::MissingSha256(path)) if path == "Contents-amd64.gz"
            ));
        }
    }

    #[test]
    fn weak_only_unselected_advertisements_do_not_expand_client_scope() {
        let paths = [
            "contrib/binary-amd64/Packages.xz",
            "main/binary-arm64/Packages.xz",
            "main/source/Sources.xz",
            "main/debian-installer/binary-amd64/Packages.xz",
            "main/i18n/Translation-en.diff/Index",
            "Contents-amd64.gz",
            "arbitrary-root/Contents-amd64.gz",
        ];
        for hash in ["SHA1", "MD5Sum"] {
            let release = release(&paths, hash);
            let (selected, excluded) = select(&release, &["main"], false).expect("bounded scope");
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].path, "main/binary-amd64/Packages");
            assert_eq!(excluded.len(), paths.len());
            assert!(
                paths
                    .iter()
                    .all(|path| excluded.iter().any(|entry| entry.path == *path))
            );
            assert!(matches!(
                select(&release, &["main", "non-free"], false),
                Err(SelectionError::MissingPackages(component)) if component == "non-free"
            ));
        }
    }

    #[test]
    fn advertised_binary_all_is_required_independently_of_header_flags() {
        for advertised in [false, true] {
            for no_support in [false, true] {
                let mut paths = vec!["main/binary-amd64/Packages.xz"];
                if advertised {
                    paths.push("main/binary-all/Packages.xz");
                }
                let mut text = release_text(&paths, "SHA256").replace("amd64 all", "amd64");
                if !no_support {
                    text = text.replace("No-Support-for-Architecture-all: Packages\n", "");
                }
                let release =
                    Release::parse(text.as_bytes(), &crate::release::ParseLimits::default())
                        .expect("binary-all fixture");
                assert_eq!(release.no_support_for_architecture_all, no_support);
                let (selected, _) = select(&release, &["main"], false).expect("advertised closure");
                assert_eq!(
                    selected
                        .iter()
                        .any(|target| target.path == "main/binary-all/Packages.xz"),
                    advertised
                );
                let scanned = packages(&release, &selected).expect("Packages acquisition");
                assert_eq!(scanned.len(), if advertised { 2 } else { 1 });
            }
        }
    }
}
