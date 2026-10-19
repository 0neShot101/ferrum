use anyhow::Result;
use ferrum_apt::release::{Release, ReleaseEntry};
use serde::Serialize;

pub(crate) const DEBIAN_COMPONENTS: &[&str] = &["main", "contrib", "non-free", "non-free-firmware"];
pub(crate) const BULLSEYE_COMPONENTS: &[&str] = &["main", "contrib", "non-free"];
pub(crate) const UBUNTU_COMPONENTS: &[&str] = &["main", "restricted", "universe", "multiverse"];
pub(crate) struct Suite {
    pub(crate) repository: &'static str,
    pub(crate) root: &'static str,
    pub(crate) name: &'static str,
    pub(crate) ubuntu: bool,
}

impl Suite {
    pub(crate) fn components(&self) -> &'static [&'static str] {
        if self.ubuntu {
            UBUNTU_COMPONENTS
        } else if self.name.starts_with("bullseye") {
            BULLSEYE_COMPONENTS
        } else {
            DEBIAN_COMPONENTS
        }
    }
}

pub(crate) const SUITES: [Suite; 6] = [
    Suite {
        repository: "debian",
        root: "https://deb.debian.org/debian/",
        name: "trixie",
        ubuntu: false,
    },
    Suite {
        repository: "debian",
        root: "https://deb.debian.org/debian/",
        name: "trixie-updates",
        ubuntu: false,
    },
    Suite {
        repository: "debian-security",
        root: "https://deb.debian.org/debian-security/",
        name: "trixie-security",
        ubuntu: false,
    },
    Suite {
        repository: "ubuntu",
        root: "https://archive.ubuntu.com/ubuntu/",
        name: "noble",
        ubuntu: true,
    },
    Suite {
        repository: "ubuntu",
        root: "https://archive.ubuntu.com/ubuntu/",
        name: "noble-updates",
        ubuntu: true,
    },
    Suite {
        repository: "ubuntu-security",
        root: "https://security.ubuntu.com/ubuntu/",
        name: "noble-security",
        ubuntu: true,
    },
];

pub(crate) use ferrum_apt::selection::{Excluded, Target, representation};

pub(crate) fn select(release: &Release, suite: &Suite) -> Result<(Vec<Target>, Vec<Excluded>)> {
    Ok(ferrum_apt::selection::select(
        release,
        suite.components(),
        suite.ubuntu,
    )?)
}

pub(crate) fn packages<'a>(
    release: &'a Release,
    targets: &[Target],
) -> Result<Vec<&'a ReleaseEntry>> {
    Ok(ferrum_apt::selection::packages(release, targets)?)
}

#[derive(Serialize)]
struct TargetRecord<'a> {
    path: &'a str,
    logical: &'a str,
    category: &'static str,
    compression: Option<&'static str>,
    signed_size: u64,
    sha256: Option<&'a str>,
    sha512: Option<&'a str>,
    pinned: bool,
    derived_from: Option<&'a str>,
}
#[derive(Serialize)]
struct ExcludedRecord<'a> {
    path: &'a str,
    reason: &'static str,
    signed_size: u64,
}
pub(crate) fn serialize_targets<S: serde::Serializer>(
    targets: &[Target],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_seq(targets.iter().map(|target| TargetRecord {
        path: &target.path,
        logical: &target.logical,
        category: target.category,
        compression: target.compression,
        signed_size: target.signed_size,
        sha256: target.sha256.as_deref(),
        sha512: target.sha512.as_deref(),
        pinned: target.pinned,
        derived_from: target.derived_from.as_deref(),
    }))
}
pub(crate) fn serialize_excluded<S: serde::Serializer>(
    excluded: &[Excluded],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_seq(excluded.iter().map(|entry| ExcludedRecord {
        path: &entry.path,
        reason: entry.reason,
        signed_size: entry.signed_size,
    }))
}
