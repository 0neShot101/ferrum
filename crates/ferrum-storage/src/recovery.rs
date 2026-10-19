//! Signed generation proof and profile-aware recovery. Historical proof authenticity
//! and permission to activate fresh mutable metadata are deliberately separate.
mod publication;
use crate::{
    Spool, VerifiedObject,
    checkpoint::{
        CheckpointError, CheckpointPublisher, FloorTrust, MANIFEST_LIMIT, PublicationIntent,
        RecoveryProfile, SuiteKey, canonical_digest,
    },
    disk::ReservationClass,
    s3::{OperationIdentity, S3Error},
};
use ferrum_apt::{
    digest::{ObjectIdentity, Sha256Digest, Sha256Hasher, Sha512Hasher},
    path::RepositoryPath,
    release::{ParseLimits, Release, ReleaseEntry, UnixTime},
    signature::SignatureVerifier,
};
use futures_util::StreamExt;
pub use publication::materialize_derived;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestArtifact {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}
impl ManifestArtifact {
    pub fn identity(&self) -> Result<ObjectIdentity, CheckpointError> {
        Ok(ObjectIdentity {
            sha256: canonical_digest(&self.sha256)?,
            size: self.size,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedArtifact {
    pub path: String,
    pub source_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationManifest {
    pub schema_version: u32,
    pub repository: String,
    pub suite: String,
    pub generation_id: String,
    pub release_content_sha256: String,
    pub release_date: i64,
    pub artifacts: Vec<ManifestArtifact>,
    #[serde(default)]
    pub derived: Vec<DerivedArtifact>,
}
/// Local ownership identity, distinct from the RFC's raw InRelease generation.
/// Identical signed Release bytes served by separate repositories/suites never
/// share retirement, proof closure, or generation-pin ownership.
pub fn generation_scope(repository: &str, suite: &str, generation: &str) -> Sha256Digest {
    let mut hash = ferrum_apt::digest::Sha256Hasher::new();
    hash.update(b"ferrum-generation-v1\0");
    hash.update(repository.as_bytes());
    hash.update(b"\0");
    hash.update(suite.as_bytes());
    hash.update(b"\0");
    hash.update(generation.as_bytes());
    hash.finalize()
}
impl GenerationManifest {
    pub fn scope_id(&self) -> Sha256Digest {
        generation_scope(&self.repository, &self.suite, &self.generation_id)
    }
    pub fn key(&self) -> Result<SuiteKey, CheckpointError> {
        SuiteKey::new(&self.repository, &self.suite)
    }
    pub fn suffix(&self) -> String {
        format!(
            "v1/generations/{}/{}/{}/manifest.json",
            self.repository, self.suite, self.generation_id
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() as u64 > MANIFEST_LIMIT {
            return Err(CheckpointError::Invalid);
        }
        Ok(bytes)
    }
    pub fn validate(&self) -> Result<(), CheckpointError> {
        self.key()?;
        canonical_digest(&self.generation_id)?;
        canonical_digest(&self.release_content_sha256)?;
        if self.schema_version != 1 || self.artifacts.len() < 3 || self.artifacts.len() > 8192 {
            return Err(CheckpointError::Invalid);
        }
        let mut paths = HashSet::with_capacity(self.artifacts.len());
        for artifact in &self.artifacts {
            RepositoryPath::parse_decoded(&artifact.path).map_err(|_| CheckpointError::Invalid)?;
            artifact.identity()?;
            if !paths.insert(&artifact.path) {
                return Err(CheckpointError::Invalid);
            }
        }
        if self.derived.len() > 8192 {
            return Err(CheckpointError::Invalid);
        }
        for derived in &self.derived {
            RepositoryPath::parse_decoded(&derived.path).map_err(|_| CheckpointError::Invalid)?;
            if !paths.insert(&derived.path)
                || !self
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.path == derived.source_path)
                || ![".gz", ".xz", ".bz2"]
                    .iter()
                    .any(|extension| derived.source_path == format!("{}{extension}", derived.path))
            {
                return Err(CheckpointError::Invalid);
            }
        }
        if matches!(
            self.repository.as_str(),
            "archlinux" | "chaotic-aur" | "cachyos" | "archlinuxcn" | "endeavouros"
        ) {
            if !self.derived.is_empty()
                || self.artifacts.len() != 3
                || ferrum_apt::pacman::pacman_package_prefix(&self.artifacts[0].path).is_none()
                || self.artifacts[2].path != format!("{}.sig", self.artifacts[1].path)
                || !ferrum_apt::pacman::is_pacman_package_path(&format!(
                    "{}/{}",
                    self.suite, self.artifacts[1].path
                ))
            {
                return Err(CheckpointError::Proof);
            }
        } else if matches!(self.repository.as_str(), "almalinux" | "rockylinux") {
            let root =
                ferrum_apt::rpm::rpm_suite_root(&self.suite).ok_or(CheckpointError::Invalid)?;
            if !self.derived.is_empty()
                || self.artifacts[0].path != format!("{root}/repodata/repomd.xml")
                || self.artifacts[1].path != format!("{root}/repodata/repomd.xml.asc")
                || !self.artifacts[2..]
                    .iter()
                    .any(|artifact| ferrum_apt::rpm::is_rpm_primary_index_path(&artifact.path))
            {
                return Err(CheckpointError::Proof);
            }
        } else {
            for name in ["InRelease", "Release", "Release.gpg"] {
                if !self.artifacts.iter().any(|artifact| artifact.path == name) {
                    return Err(CheckpointError::Proof);
                }
            }
        }
        Ok(())
    }
}

/// Operator-owned keyrings only. Production origins and identity rules are fixed.
#[derive(Clone, Debug)]
pub enum TrustPolicy {
    Debian { keyring: PathBuf },
    Ubuntu { keyring: PathBuf },
    Kali { keyring: PathBuf },
    Parrot { keyring: PathBuf },
    Trisquel { keyring: PathBuf },
    RaspberryPi { keyring: PathBuf },
    ProxmoxPve { keyring: PathBuf },
    ProxmoxPbs { keyring: PathBuf },
    ArchLinux { keyring: PathBuf },
    ChaoticAur { keyring: PathBuf },
    UbuntuPorts { keyring: PathBuf },
    DockerDebian { keyring: PathBuf },
    DockerUbuntu { keyring: PathBuf },
    TailscaleDebian { keyring: PathBuf },
    TailscaleUbuntu { keyring: PathBuf },
    PostgresqlApt { keyring: PathBuf },
    GrafanaApt { keyring: PathBuf },
    CachyOs { keyring: PathBuf },
    ArchLinuxCn { keyring: PathBuf },
    EndeavourOs { keyring: PathBuf },
    AlmaLinux { keyring: PathBuf },
    RockyLinux { keyring: PathBuf },
    LoopbackFixture { keyring: PathBuf },
}
impl TrustPolicy {
    pub fn is_pacman(&self) -> bool {
        matches!(
            self,
            Self::ArchLinux { .. }
                | Self::ChaoticAur { .. }
                | Self::CachyOs { .. }
                | Self::ArchLinuxCn { .. }
                | Self::EndeavourOs { .. }
        )
    }
    pub fn is_rpm(&self) -> bool {
        matches!(self, Self::AlmaLinux { .. } | Self::RockyLinux { .. })
    }
    pub fn architectures(&self) -> &'static [&'static str] {
        match self {
            Self::UbuntuPorts { .. } => &["arm64"],
            Self::DockerDebian { .. }
            | Self::DockerUbuntu { .. }
            | Self::TailscaleDebian { .. }
            | Self::TailscaleUbuntu { .. }
            | Self::PostgresqlApt { .. }
            | Self::GrafanaApt { .. }
            | Self::RaspberryPi { .. } => &["amd64", "arm64"],
            policy if policy.is_pacman() || policy.is_rpm() => &["x86_64", "aarch64"],
            _ => &["amd64"],
        }
    }
    /// Returns the fixed RPM suite root, rejecting unrelated repositories or suites.
    pub fn rpm_suite_root(&self, key: &SuiteKey) -> Result<&'static str, CheckpointError> {
        if !matches!(
            (self, key.repository()),
            (Self::AlmaLinux { .. }, "almalinux") | (Self::RockyLinux { .. }, "rockylinux")
        ) {
            return Err(CheckpointError::Proof);
        }
        ferrum_apt::rpm::rpm_suite_root(key.suite()).ok_or(CheckpointError::Proof)
    }
    /// Returns the database path within the fixed suite origin.
    pub fn pacman_db_subpath(&self, key: &SuiteKey) -> Result<String, CheckpointError> {
        match (self, key.repository(), key.suite()) {
            (Self::ArchLinux { .. }, "archlinux", "core" | "extra" | "multilib") => {
                Ok(format!("os/x86_64/{}.db", key.suite()))
            }
            (Self::ChaoticAur { .. }, "chaotic-aur", "chaotic-aur") => {
                Ok("x86_64/chaotic-aur.db".into())
            }
            (Self::CachyOs { .. }, "cachyos", "cachyos" | "cachyos-v3" | "cachyos-v4") => {
                Ok(format!("x86_64/{}.db", key.suite()))
            }
            (Self::ArchLinuxCn { .. }, "archlinuxcn", "archlinuxcn") => {
                Ok("x86_64/archlinuxcn.db".into())
            }
            (Self::EndeavourOs { .. }, "endeavouros", "endeavouros") => {
                Ok("x86_64/endeavouros.db".into())
            }
            _ => Err(CheckpointError::Proof),
        }
    }
    pub fn keyring(&self) -> &std::path::Path {
        match self {
            Self::Debian { keyring }
            | Self::Ubuntu { keyring }
            | Self::Kali { keyring }
            | Self::Parrot { keyring }
            | Self::Trisquel { keyring }
            | Self::RaspberryPi { keyring }
            | Self::ProxmoxPve { keyring }
            | Self::ProxmoxPbs { keyring }
            | Self::ArchLinux { keyring }
            | Self::ChaoticAur { keyring }
            | Self::UbuntuPorts { keyring }
            | Self::DockerDebian { keyring }
            | Self::DockerUbuntu { keyring }
            | Self::TailscaleDebian { keyring }
            | Self::TailscaleUbuntu { keyring }
            | Self::PostgresqlApt { keyring }
            | Self::GrafanaApt { keyring }
            | Self::CachyOs { keyring }
            | Self::ArchLinuxCn { keyring }
            | Self::EndeavourOs { keyring }
            | Self::AlmaLinux { keyring }
            | Self::RockyLinux { keyring }
            | Self::LoopbackFixture { keyring } => keyring,
        }
    }
    pub fn components(&self) -> &'static [&'static str] {
        match self {
            Self::Debian { .. } | Self::Kali { .. } | Self::Parrot { .. } => {
                &["main", "contrib", "non-free", "non-free-firmware"]
            }
            Self::Ubuntu { .. } | Self::UbuntuPorts { .. } => {
                &["main", "restricted", "universe", "multiverse"]
            }
            Self::DockerDebian { .. } | Self::DockerUbuntu { .. } => &["stable"],
            Self::ProxmoxPve { .. } => &["pve-no-subscription"],
            Self::ProxmoxPbs { .. } => &["pbs-no-subscription"],
            Self::ArchLinux { .. }
            | Self::ChaoticAur { .. }
            | Self::CachyOs { .. }
            | Self::ArchLinuxCn { .. }
            | Self::EndeavourOs { .. }
            | Self::AlmaLinux { .. }
            | Self::RockyLinux { .. } => &["os"],
            Self::Trisquel { .. }
            | Self::RaspberryPi { .. }
            | Self::TailscaleDebian { .. }
            | Self::TailscaleUbuntu { .. }
            | Self::PostgresqlApt { .. }
            | Self::GrafanaApt { .. }
            | Self::LoopbackFixture { .. } => &["main"],
        }
    }
    pub fn components_for_suite(&self, suite: &str) -> &'static [&'static str] {
        match self {
            Self::Debian { .. } if suite.starts_with("bullseye") => {
                &["main", "contrib", "non-free"]
            }
            _ => self.components(),
        }
    }
    pub fn identity(&self, key: &SuiteKey, release: &Release) -> Result<(), CheckpointError> {
        let valid = match self {
            Self::Debian { .. } => {
                let is_backports = matches!(
                    (key.repository(), key.suite()),
                    (
                        "debian",
                        "bookworm-backports" | "trixie-backports" | "forky-backports"
                    )
                );
                let is_standard = matches!(
                    (key.repository(), key.suite()),
                    (
                        "debian",
                        "bullseye"
                            | "bullseye-updates"
                            | "bookworm"
                            | "bookworm-updates"
                            | "trixie"
                            | "trixie-updates"
                            | "forky"
                            | "forky-updates"
                    ) | (
                        "debian-security",
                        "bullseye-security"
                            | "bookworm-security"
                            | "trixie-security"
                            | "forky-security"
                    )
                );
                let origin_ok = if is_backports {
                    matches!(release.origin.as_str(), "Debian" | "Debian Backports")
                } else {
                    is_standard && release.origin == "Debian"
                };
                origin_ok && release.codename == key.suite()
            }
            Self::Ubuntu { .. } => {
                let codename = match (key.repository(), key.suite()) {
                    ("ubuntu", "focal" | "focal-updates" | "focal-backports")
                    | ("ubuntu-security", "focal-security") => Some("focal"),
                    ("ubuntu", "jammy" | "jammy-updates" | "jammy-backports")
                    | ("ubuntu-security", "jammy-security") => Some("jammy"),
                    ("ubuntu", "noble" | "noble-updates" | "noble-backports")
                    | ("ubuntu-security", "noble-security") => Some("noble"),
                    ("ubuntu", "plucky" | "plucky-updates" | "plucky-backports")
                    | ("ubuntu-security", "plucky-security") => Some("plucky"),
                    ("ubuntu", "questing" | "questing-updates" | "questing-backports")
                    | ("ubuntu-security", "questing-security") => Some("questing"),
                    ("ubuntu", "resolute" | "resolute-updates" | "resolute-backports")
                    | ("ubuntu-security", "resolute-security") => Some("resolute"),
                    _ => None,
                };
                codename.is_some_and(|expected| {
                    release.origin == "Ubuntu"
                        && release.codename == expected
                        && release.suite == key.suite()
                })
            }
            Self::UbuntuPorts { .. } => {
                key.repository() == "ubuntu-ports"
                    && matches!(
                        key.suite(),
                        "jammy"
                            | "jammy-updates"
                            | "jammy-backports"
                            | "jammy-security"
                            | "noble"
                            | "noble-updates"
                            | "noble-backports"
                            | "noble-security"
                    )
                    && release.origin == "Ubuntu"
                    && release.suite == key.suite()
            }
            Self::DockerDebian { .. } => {
                key.repository() == "docker-debian"
                    && matches!(key.suite(), "bookworm" | "trixie")
                    && release.origin == "Docker"
            }
            Self::DockerUbuntu { .. } => {
                key.repository() == "docker-ubuntu"
                    && matches!(key.suite(), "jammy" | "noble")
                    && release.origin == "Docker"
            }
            Self::TailscaleDebian { .. } => {
                key.repository() == "tailscale-debian"
                    && matches!(key.suite(), "bookworm" | "trixie")
                    && release.origin == "Tailscale"
            }
            Self::TailscaleUbuntu { .. } => {
                key.repository() == "tailscale-ubuntu"
                    && matches!(key.suite(), "jammy" | "noble")
                    && release.origin == "Tailscale"
            }
            Self::PostgresqlApt { .. } => {
                key.repository() == "postgresql-apt"
                    && matches!(
                        key.suite(),
                        "bookworm-pgdg" | "trixie-pgdg" | "jammy-pgdg" | "noble-pgdg"
                    )
                    && release.origin == "apt.postgresql.org"
            }
            Self::GrafanaApt { .. } => {
                key.repository() == "grafana-apt"
                    && key.suite() == "stable"
                    && release.origin == ". stable"
            }
            Self::Kali { .. } => {
                key.repository() == "kali"
                    && matches!(key.suite(), "kali-rolling" | "kali-last-snapshot")
                    && release.origin == "Kali"
                    && release.suite == key.suite()
                    && release.codename == key.suite()
            }
            Self::Parrot { .. } => {
                key.repository() == "parrot"
                    && matches!(key.suite(), "lory" | "lory-security" | "lory-backports")
                    && release.origin == "Parrot"
                    && release.codename == key.suite()
            }
            Self::Trisquel { .. } => {
                key.repository() == "trisquel"
                    && matches!(
                        key.suite(),
                        "aramo"
                            | "aramo-updates"
                            | "aramo-security"
                            | "ecne"
                            | "ecne-updates"
                            | "ecne-security"
                    )
                    && release.origin == "Trisquel"
                    && release.suite == key.suite()
                    && release.codename == key.suite()
            }
            Self::RaspberryPi { .. } => {
                key.repository() == "raspberrypi"
                    && matches!(key.suite(), "bookworm" | "trixie")
                    && release.origin == "Raspberry Pi Foundation"
                    && release.codename == key.suite()
            }
            Self::ProxmoxPve { .. } => {
                key.repository() == "proxmox-pve"
                    && matches!(key.suite(), "bookworm" | "trixie")
                    && release.origin == "Proxmox"
                    && release.codename == key.suite()
            }
            Self::ProxmoxPbs { .. } => {
                key.repository() == "proxmox-pbs"
                    && matches!(key.suite(), "bookworm" | "trixie")
                    && release.origin == "Proxmox"
                    && release.codename == key.suite()
            }
            Self::ArchLinux { .. } => {
                key.repository() == "archlinux"
                    && matches!(key.suite(), "core" | "extra" | "multilib")
                    && release.origin == "ArchLinux"
                    && release.suite == key.suite()
                    && release.codename == key.suite()
            }
            Self::ChaoticAur { .. } => {
                key.repository() == "chaotic-aur"
                    && key.suite() == "chaotic-aur"
                    && release.origin == "ChaoticAUR"
                    && release.suite == key.suite()
                    && release.codename == key.suite()
            }
            Self::CachyOs { .. } => {
                key.repository() == "cachyos"
                    && matches!(key.suite(), "cachyos" | "cachyos-v3" | "cachyos-v4")
                    && release.origin == "CachyOS"
                    && release.suite == key.suite()
            }
            Self::ArchLinuxCn { .. } => {
                key.repository() == "archlinuxcn"
                    && key.suite() == "archlinuxcn"
                    && release.origin == "ArchLinuxCN"
                    && release.suite == "archlinuxcn"
            }
            Self::EndeavourOs { .. } => {
                key.repository() == "endeavouros"
                    && key.suite() == "endeavouros"
                    && release.origin == "EndeavourOS"
                    && release.suite == "endeavouros"
            }
            Self::AlmaLinux { .. } => {
                key.repository() == "almalinux"
                    && ferrum_apt::rpm::rpm_suite_root(key.suite()).is_some()
                    && release.origin == "AlmaLinux"
                    && release.suite == key.suite()
            }
            Self::RockyLinux { .. } => {
                key.repository() == "rockylinux"
                    && ferrum_apt::rpm::rpm_suite_root(key.suite()).is_some()
                    && release.origin == "RockyLinux"
                    && release.suite == key.suite()
            }
            Self::LoopbackFixture { .. } => {
                key.repository() == "fixture"
                    && key.suite() == "ferrum-test"
                    && release.origin == "FerrumTest"
                    && release.suite == "ferrum-test"
                    && release.codename == "ferrum-test"
            }
        };
        let requires_by_hash = matches!(
            self,
            Self::Debian { .. } | Self::Ubuntu { .. } | Self::LoopbackFixture { .. }
        );
        if !valid
            || (requires_by_hash && !release.acquire_by_hash)
            || !release
                .architectures
                .iter()
                .any(|architecture| self.architectures().contains(&architecture.as_str()))
        {
            return Err(CheckpointError::Proof);
        }
        // Signed header names are not acquisition prefixes: Debian security
        // lists updates/main but authenticates main/binary-amd64/Packages.
        // The shared selector requires signed Packages paths for every fixed
        // client component; neither the header nor an arbitrary root expands it.
        Ok(())
    }
    pub fn origin(&self, key: &SuiteKey) -> Result<String, CheckpointError> {
        let base = match (self, key.repository(), key.suite()) {
            (Self::ArchLinux { .. }, "archlinux", "core" | "extra" | "multilib") => {
                return Ok(format!(
                    "https://geo.mirror.pkgbuild.com/{}/os/x86_64/{}.db",
                    key.suite(),
                    key.suite()
                ));
            }
            (Self::ChaoticAur { .. }, "chaotic-aur", "chaotic-aur") => {
                return Ok(
                    "https://builds.garudalinux.org/repos/chaotic-aur/x86_64/chaotic-aur.db".into(),
                );
            }
            (Self::CachyOs { .. }, "cachyos", "cachyos" | "cachyos-v3" | "cachyos-v4") => {
                return Ok(format!(
                    "https://mirror.cachyos.org/repo/x86_64/{}/{}.db",
                    key.suite(),
                    key.suite()
                ));
            }
            (Self::ArchLinuxCn { .. }, "archlinuxcn", "archlinuxcn") => {
                return Ok(
                    "https://mirrors.tuna.tsinghua.edu.cn/archlinuxcn/x86_64/archlinuxcn.db".into(),
                );
            }
            (Self::EndeavourOs { .. }, "endeavouros", "endeavouros") => {
                return Ok("https://mirrors.tuna.tsinghua.edu.cn/endeavouros/repo/endeavouros/x86_64/endeavouros.db".into());
            }
            (Self::AlmaLinux { .. }, "almalinux", _) => {
                return Ok(format!(
                    "https://repo.almalinux.org/almalinux/{}/repodata/repomd.xml",
                    self.rpm_suite_root(key)?
                ));
            }
            (Self::RockyLinux { .. }, "rockylinux", _) => {
                return Ok(format!(
                    "https://dl.rockylinux.org/pub/rocky/{}/repodata/repomd.xml",
                    self.rpm_suite_root(key)?
                ));
            }
            (
                Self::UbuntuPorts { .. },
                "ubuntu-ports",
                "jammy" | "jammy-updates" | "jammy-backports" | "jammy-security" | "noble"
                | "noble-updates" | "noble-backports" | "noble-security",
            ) => "https://ports.ubuntu.com/ubuntu-ports",
            (Self::DockerDebian { .. }, "docker-debian", "bookworm" | "trixie") => {
                "https://download.docker.com/linux/debian"
            }
            (Self::DockerUbuntu { .. }, "docker-ubuntu", "jammy" | "noble") => {
                "https://download.docker.com/linux/ubuntu"
            }
            (Self::TailscaleDebian { .. }, "tailscale-debian", "bookworm" | "trixie") => {
                "https://pkgs.tailscale.com/stable/debian"
            }
            (Self::TailscaleUbuntu { .. }, "tailscale-ubuntu", "jammy" | "noble") => {
                "https://pkgs.tailscale.com/stable/ubuntu"
            }
            (
                Self::PostgresqlApt { .. },
                "postgresql-apt",
                "bookworm-pgdg" | "trixie-pgdg" | "jammy-pgdg" | "noble-pgdg",
            ) => "https://apt.postgresql.org/pub/repos/apt",
            (Self::GrafanaApt { .. }, "grafana-apt", "stable") => "https://apt.grafana.com",
            (
                Self::Debian { .. },
                "debian",
                "bullseye" | "bullseye-updates" | "bookworm" | "bookworm-updates"
                | "bookworm-backports" | "trixie" | "trixie-updates" | "trixie-backports" | "forky"
                | "forky-updates" | "forky-backports",
            ) => "https://deb.debian.org/debian",
            (
                Self::Debian { .. },
                "debian-security",
                "bullseye-security" | "bookworm-security" | "trixie-security" | "forky-security",
            ) => "https://deb.debian.org/debian-security",
            (
                Self::Ubuntu { .. },
                "ubuntu",
                "focal" | "focal-updates" | "focal-backports" | "jammy" | "jammy-updates"
                | "jammy-backports" | "noble" | "noble-updates" | "noble-backports" | "plucky"
                | "plucky-updates" | "plucky-backports" | "questing" | "questing-updates"
                | "questing-backports" | "resolute" | "resolute-updates" | "resolute-backports",
            ) => "https://archive.ubuntu.com/ubuntu",
            (
                Self::Ubuntu { .. },
                "ubuntu-security",
                "focal-security" | "jammy-security" | "noble-security" | "plucky-security"
                | "questing-security" | "resolute-security",
            ) => "https://security.ubuntu.com/ubuntu",
            (Self::Kali { .. }, "kali", "kali-rolling" | "kali-last-snapshot") => {
                "https://kali.download/kali"
            }
            (Self::Parrot { .. }, "parrot", "lory" | "lory-security" | "lory-backports") => {
                "https://deb.parrot.sh/direct/parrot"
            }
            (
                Self::Trisquel { .. },
                "trisquel",
                "aramo" | "aramo-updates" | "aramo-security" | "ecne" | "ecne-updates"
                | "ecne-security",
            ) => "https://mirrors.ocf.berkeley.edu/trisquel",
            (Self::RaspberryPi { .. }, "raspberrypi", "bookworm" | "trixie") => {
                "https://archive.raspberrypi.com/debian"
            }
            (Self::ProxmoxPve { .. }, "proxmox-pve", "bookworm" | "trixie") => {
                "https://mirrors.ustc.edu.cn/proxmox/debian/pve"
            }
            (Self::ProxmoxPbs { .. }, "proxmox-pbs", "bookworm" | "trixie") => {
                "https://mirrors.ustc.edu.cn/proxmox/debian/pbs"
            }
            (Self::LoopbackFixture { .. }, "fixture", "ferrum-test") => {
                "http://127.0.0.1:18080/fixture"
            }
            _ => return Err(CheckpointError::Proof),
        };
        Ok(format!("{base}/dists/{}/InRelease", key.suite()))
    }
}

/// Uses exactly the same required-target/compression policy as the live publisher.
pub fn selected_metadata_paths<'a>(
    release: &'a Release,
    policy: &TrustPolicy,
) -> Result<Vec<&'a RepositoryPath>, CheckpointError> {
    let (targets, _) = ferrum_apt::selection::select_for_architectures(
        release,
        policy.components_for_suite(&release.codename),
        matches!(
            policy,
            TrustPolicy::Ubuntu { .. } | TrustPolicy::UbuntuPorts { .. }
        ),
        policy.architectures(),
    )
    .map_err(|_| CheckpointError::Proof)?;
    targets
        .iter()
        .map(|target| {
            release
                .entries()
                .iter()
                .find(|entry| entry.path.as_str() == target.path)
                .map(|entry| &entry.path)
                .ok_or(CheckpointError::Proof)
        })
        .collect()
}

pub(crate) static PROOF_CPU: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(ferrum_apt::signature::cpu_gate);

// liblzma's memory cap includes decoder state, not just the dictionary. Ubuntu
// CNF indexes use a 64 MiB dictionary and need another 66,200 bytes. One MiB of
// overhead admits those indexes while still refusing the next 96 MiB dictionary.
const XZ_DECODER_MEMORY_LIMIT: u64 = 65 * 1024 * 1024;

/// One decoder convention for capture and selected metadata verification. XZ has
/// a hard total memory limit; multi-member decoders reject invalid trailing data.
pub(crate) fn proof_reader(
    file: std::fs::File,
    source_name: &str,
    cancel: CancellationToken,
) -> Result<Box<dyn std::io::Read>, crate::catalog::CatalogError> {
    use crate::catalog::CatalogError;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let input = DeadlineReader {
        reader: Box::new(file),
        deadline,
        cancel: cancel.clone(),
    };
    let reader: Box<dyn std::io::Read> = if ferrum_apt::rpm::is_rpm_primary_index_path(source_name)
    {
        Box::new(input)
    } else if source_name.ends_with(".gz") {
        Box::new(flate2::read::MultiGzDecoder::new(input))
    } else if source_name.ends_with(".xz") {
        let stream = xz2::stream::Stream::new_stream_decoder(
            XZ_DECODER_MEMORY_LIMIT,
            xz2::stream::CONCATENATED,
        )
        .map_err(|_| CatalogError::InvalidState)?;
        Box::new(xz2::read::XzDecoder::new_stream(input, stream))
    } else if source_name.ends_with(".bz2") {
        Box::new(bzip2::read::MultiBzDecoder::new(input))
    } else {
        Box::new(input)
    };
    Ok(Box::new(DeadlineReader {
        reader,
        deadline,
        cancel,
    }))
}
struct DeadlineReader {
    reader: Box<dyn std::io::Read>,
    deadline: std::time::Instant,
    cancel: CancellationToken,
}
impl std::io::Read for DeadlineReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "proof decode cancelled",
            ));
        }
        if std::time::Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "proof decode deadline",
            ));
        }
        let maximum = buffer.len().min(256 * 1024);
        self.reader.read(&mut buffer[..maximum])
    }
}

#[derive(Clone)]
pub struct VerifiedHistoricalProof {
    manifest: GenerationManifest,
    release: Release,
    artifacts: Vec<VerifiedObject>,
    pub(crate) owner: Spool,
    derived_identities: Vec<(String, ObjectIdentity)>,
}
impl VerifiedHistoricalProof {
    pub fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }
    pub fn release(&self) -> &Release {
        &self.release
    }
    /// Rechecks stored signatures and their content binding under current policy.
    /// Pacman canaries and RPM detached metadata signatures retain their bindings.
    pub(crate) async fn revalidate(
        &self,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
    ) -> Result<(), CheckpointError> {
        policy.identity(&self.manifest.key()?, &self.release)?;
        if policy.is_pacman() {
            let [database, package, signature] = self.artifacts.as_slice() else {
                return Err(CheckpointError::Proof);
            };
            let release = authenticate_pacman(
                &self.owner,
                &self.manifest.key()?,
                policy,
                verifier,
                database,
                package,
                signature,
            )
            .await?;
            if release.content_sha256() != self.release.content_sha256() {
                return Err(CheckpointError::Proof);
            }
            return Ok(());
        }
        if policy.is_rpm() {
            let metadata = self.artifacts.first().ok_or(CheckpointError::Proof)?;
            let signature = self.artifacts.get(1).ok_or(CheckpointError::Proof)?;
            let scratch = self
                .owner
                .reserve_class(32 * 1024 * 1024, ReservationClass::Metadata)?;
            verifier
                .verify_detached_owned(
                    policy.keyring(),
                    metadata.path(),
                    signature.path(),
                    (scratch, metadata.clone(), signature.clone()),
                )
                .await?;
            return Ok(());
        }
        let authenticated = verify_signatures(
            &self.owner,
            policy,
            verifier,
            self.artifact("InRelease").ok_or(CheckpointError::Proof)?,
            self.artifact("Release").ok_or(CheckpointError::Proof)?,
            self.artifact("Release.gpg").ok_or(CheckpointError::Proof)?,
        )
        .await?;
        if Sha256Digest::of(&authenticated) != self.release.content_sha256() {
            return Err(CheckpointError::Proof);
        }
        Ok(())
    }
    pub fn artifact(&self, path: &str) -> Option<&VerifiedObject> {
        self.manifest
            .artifacts
            .iter()
            .position(|artifact| artifact.path == path)
            .and_then(|index| self.artifacts.get(index))
    }
    pub fn identity(&self, path: &str) -> Option<ObjectIdentity> {
        self.artifact(path)
            .map(VerifiedObject::identity)
            .or_else(|| {
                self.derived_identities
                    .iter()
                    .find(|(name, _)| name == path)
                    .map(|(_, identity)| *identity)
            })
    }
    pub(crate) fn metadata_records(
        &self,
    ) -> Result<Vec<crate::catalog::publication::MetadataRecord>, CheckpointError> {
        self.manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .chain(
                self.manifest
                    .derived
                    .iter()
                    .map(|derived| derived.path.as_str()),
            )
            .map(|path| {
                let parsed =
                    RepositoryPath::parse_decoded(path).map_err(|_| CheckpointError::Proof)?;
                let entry = self.release.entry(&parsed);
                Ok(crate::catalog::publication::MetadataRecord {
                    path: path.to_owned(),
                    directory: path
                        .rsplit_once('/')
                        .map_or("", |(directory, _)| directory)
                        .to_owned(),
                    identity: self.identity(path).ok_or(CheckpointError::Proof)?,
                    sha256_alias: entry.is_some_and(|entry| entry.sha256.is_some()),
                    sha512: entry
                        .and_then(|entry| entry.sha512)
                        .map(|digest| digest.to_hex()),
                    source_path: self
                        .manifest
                        .derived
                        .iter()
                        .find(|derived| derived.path == path)
                        .map_or(path, |derived| derived.source_path.as_str())
                        .to_owned(),
                })
            })
            .collect()
    }
    /// Resolves an authenticated expanded Packages path without retaining a
    /// redundant expanded file. Caller streams the indicated compressed source.
    pub fn packages_source(
        &self,
        index_path: &str,
    ) -> Option<(&VerifiedObject, &ferrum_apt::release::ReleaseEntry)> {
        let path = RepositoryPath::parse_decoded(index_path).ok()?;
        let entry = self.release.entry(&path)?;
        let source = self
            .manifest
            .derived
            .iter()
            .find(|derived| derived.path == index_path)
            .map_or(index_path, |derived| derived.source_path.as_str());
        Some((self.artifact(source)?, entry))
    }
}
fn pacman_entry(path: RepositoryPath, identity: ObjectIdentity) -> ReleaseEntry {
    ReleaseEntry {
        path,
        size: identity.size,
        sha256: Some(identity.sha256),
        sha512: None,
    }
}

fn rpm_release(
    key: &SuiteKey,
    policy: &TrustPolicy,
    summary: &ferrum_apt::rpm::RepomdSummary,
    signature: ObjectIdentity,
) -> Result<Release, CheckpointError> {
    let origin = match policy {
        TrustPolicy::AlmaLinux { .. } => "AlmaLinux",
        TrustPolicy::RockyLinux { .. } => "RockyLinux",
        _ => return Err(CheckpointError::Proof),
    };
    let mut entries = Vec::with_capacity(summary.data.len() + 2);
    entries.push(pacman_entry(
        summary.repomd_path.clone(),
        summary.repomd_identity,
    ));
    entries.push(pacman_entry(summary.repomd_asc_path.clone(), signature));
    entries.extend(
        summary
            .data
            .iter()
            .map(|record| pacman_entry(record.path.clone(), record.identity)),
    );
    let release = Release::for_pacman(
        origin,
        key.suite(),
        summary.max_timestamp,
        summary.repomd_identity.sha256,
        entries,
    )?;
    policy.identity(key, &release)?;
    Ok(release)
}

async fn authenticate_pacman(
    spool: &Spool,
    key: &SuiteKey,
    policy: &TrustPolicy,
    verifier: &SignatureVerifier,
    database: &VerifiedObject,
    package: &VerifiedObject,
    signature: &VerifiedObject,
) -> Result<Release, CheckpointError> {
    let bytes = database.read_bounded(32 * 1024 * 1024).await?;
    let summary = ferrum_apt::pacman::summarize_pacman_db(
        &bytes,
        &policy.pacman_db_subpath(key)?,
        &ParseLimits::default(),
    )
    .map_err(|_| CheckpointError::Proof)?;
    if summary.db_identity != database.identity() {
        return Err(CheckpointError::Proof);
    }
    verify_pacman_canary(spool, key, policy, verifier, &summary, package, signature).await
}

async fn verify_pacman_canary(
    spool: &Spool,
    key: &SuiteKey,
    policy: &TrustPolicy,
    verifier: &SignatureVerifier,
    summary: &ferrum_apt::pacman::PacmanDbSummary,
    package: &VerifiedObject,
    signature: &VerifiedObject,
) -> Result<Release, CheckpointError> {
    if package.identity() != summary.canary.identity
        || signature.size() > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64
        || summary.canary.embedded_sig.as_ref().is_some_and(|bytes| {
            signature.identity()
                != (ObjectIdentity {
                    sha256: Sha256Digest::of(bytes),
                    size: bytes.len() as u64,
                })
        })
    {
        return Err(CheckpointError::Proof);
    }
    let scratch = spool.reserve_class(32 * 1024 * 1024, ReservationClass::Metadata)?;
    verifier
        .verify_detached_owned(
            policy.keyring(),
            package.path(),
            signature.path(),
            (scratch, package.clone(), signature.clone()),
        )
        .await?;
    let origin = match policy {
        TrustPolicy::ArchLinux { .. } => "ArchLinux",
        TrustPolicy::ChaoticAur { .. } => "ChaoticAUR",
        TrustPolicy::CachyOs { .. } => "CachyOS",
        TrustPolicy::ArchLinuxCn { .. } => "ArchLinuxCN",
        TrustPolicy::EndeavourOs { .. } => "EndeavourOS",
        _ => return Err(CheckpointError::Proof),
    };
    let release = Release::for_pacman(
        origin,
        key.suite(),
        summary.max_build_date,
        summary.content_sha256,
        vec![
            pacman_entry(summary.db_path.clone(), summary.db_identity),
            pacman_entry(summary.canary.path.clone(), package.identity()),
            pacman_entry(summary.canary.sig_path.clone(), signature.identity()),
        ],
    )?;
    policy.identity(key, &release)?;
    Ok(release)
}

async fn verify_signatures(
    spool: &Spool,
    policy: &TrustPolicy,
    verifier: &SignatureVerifier,
    inrelease: &VerifiedObject,
    release_file: &VerifiedObject,
    signature: &VerifiedObject,
) -> Result<Vec<u8>, CheckpointError> {
    let reservation = spool.reserve_class(32 * 1024 * 1024, ReservationClass::Metadata)?;
    let authenticated = verifier
        .verify_cleartext_owned(
            policy.keyring(),
            inrelease.path(),
            &spool.root().join("temporary"),
            32 * 1024 * 1024,
            (reservation, inrelease.clone()),
        )
        .await?;
    verifier
        .verify_detached_owned(
            policy.keyring(),
            release_file.path(),
            signature.path(),
            (release_file.clone(), signature.clone()),
        )
        .await?;
    let detached = release_file.read_bounded(32 * 1024 * 1024).await?;
    // Cleartext signatures exclude the final line break, which the helper omits.
    // Release.gpg still authenticates every original detached byte independently.
    if detached != authenticated && detached.strip_suffix(b"\n") != Some(authenticated.as_slice()) {
        return Err(CheckpointError::Proof);
    }
    Ok(authenticated)
}

/// Verifies retained proof under current key policy, but does not reject an old
/// Valid-Until: expired signed checksums can still authenticate captured packages.
pub async fn verify_historical_proof(
    spool: &Spool,
    manifest: &GenerationManifest,
    policy: &TrustPolicy,
    verifier: &SignatureVerifier,
) -> Result<VerifiedHistoricalProof, CheckpointError> {
    manifest.validate()?;
    let proof_deadline = Instant::now() + Duration::from_secs(600);
    let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
    for descriptor in &manifest.artifacts {
        artifacts.push(
            spool
                .lookup(descriptor.identity()?)
                .ok_or(CheckpointError::Proof)?,
        );
    }
    let find = |name: &str| -> Result<&VerifiedObject, CheckpointError> {
        let index = manifest
            .artifacts
            .iter()
            .position(|artifact| artifact.path == name)
            .ok_or(CheckpointError::Proof)?;
        artifacts.get(index).ok_or(CheckpointError::Proof)
    };
    if policy.is_pacman() {
        let [database, package, signature] = artifacts.as_slice() else {
            return Err(CheckpointError::Proof);
        };
        let release = authenticate_pacman(
            spool,
            &manifest.key()?,
            policy,
            verifier,
            database,
            package,
            signature,
        )
        .await?;
        if database.sha256().to_hex() != manifest.generation_id
            || release.content_sha256().to_hex() != manifest.release_content_sha256
            || release.date.as_secs() != manifest.release_date
            || manifest
                .artifacts
                .iter()
                .zip(release.entries())
                .any(|(artifact, entry)| {
                    artifact.path != entry.path.as_str()
                        || artifact.size != entry.size
                        || entry.sha256.map(|digest| digest.to_hex()).as_deref()
                            != Some(artifact.sha256.as_str())
                })
        {
            return Err(CheckpointError::Proof);
        }
        let path = &manifest.artifacts[0].path;
        let entry = release.entries().first().ok_or(CheckpointError::Proof)?;
        crate::capture::index::stage_authenticated_source(
            spool,
            database.clone(),
            path.clone(),
            entry.clone(),
            proof_deadline,
            &CancellationToken::new(),
        )
        .await
        .map_err(|_| CheckpointError::Proof)?;
        let proof = Arc::new(VerifiedHistoricalProof {
            manifest: manifest.clone(),
            release,
            artifacts,
            owner: spool.clone(),
            derived_identities: Vec::new(),
        });
        crate::capture::stage_package_index(
            spool,
            proof.clone(),
            path,
            proof_deadline,
            &CancellationToken::new(),
        )
        .await
        .map_err(|_| CheckpointError::Proof)?;
        return Arc::try_unwrap(proof).map_err(|_| CheckpointError::Proof);
    }
    if policy.is_rpm() {
        let metadata = artifacts.first().ok_or(CheckpointError::Proof)?;
        let signature = artifacts.get(1).ok_or(CheckpointError::Proof)?;
        if metadata.sha256().to_hex() != manifest.generation_id
            || signature.size() > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64
        {
            return Err(CheckpointError::Proof);
        }
        let key = manifest.key()?;
        let bytes = metadata.read_bounded(32 * 1024 * 1024).await?;
        let summary = ferrum_apt::rpm::parse_repomd_xml(
            &bytes,
            policy.rpm_suite_root(&key)?,
            &ParseLimits::default(),
        )
        .map_err(|_| CheckpointError::Proof)?;
        if summary.repomd_identity != metadata.identity()
            || manifest.artifacts.len() != summary.data.len() + 2
            || manifest.artifacts[2..]
                .iter()
                .zip(&summary.data)
                .any(|(artifact, record)| {
                    artifact.path != record.path.as_str()
                        || artifact.identity().ok() != Some(record.identity)
                })
        {
            return Err(CheckpointError::Proof);
        }
        let scratch = spool.reserve_class(32 * 1024 * 1024, ReservationClass::Metadata)?;
        verifier
            .verify_detached_owned(
                policy.keyring(),
                metadata.path(),
                signature.path(),
                (scratch, metadata.clone(), signature.clone()),
            )
            .await?;
        let release = rpm_release(&key, policy, &summary, signature.identity())?;
        if release.content_sha256().to_hex() != manifest.release_content_sha256
            || release.date.as_secs() != manifest.release_date
        {
            return Err(CheckpointError::Proof);
        }
        let path = summary.primary_path.as_str();
        let entry = release
            .entry(&summary.primary_path)
            .ok_or(CheckpointError::Proof)?;
        crate::capture::index::stage_authenticated_source(
            spool,
            find(path)?.clone(),
            path.to_owned(),
            entry.clone(),
            proof_deadline,
            &CancellationToken::new(),
        )
        .await
        .map_err(|_| CheckpointError::Proof)?;
        let proof = Arc::new(VerifiedHistoricalProof {
            manifest: manifest.clone(),
            release,
            artifacts,
            owner: spool.clone(),
            derived_identities: Vec::new(),
        });
        crate::capture::stage_package_index(
            spool,
            proof.clone(),
            path,
            proof_deadline,
            &CancellationToken::new(),
        )
        .await
        .map_err(|_| CheckpointError::Proof)?;
        return Arc::try_unwrap(proof).map_err(|_| CheckpointError::Proof);
    }
    let inrelease = find("InRelease")?;
    let release_file = find("Release")?;
    let signature = find("Release.gpg")?;
    if inrelease.sha256().to_hex() != manifest.generation_id {
        return Err(CheckpointError::Proof);
    }
    let authenticated =
        verify_signatures(spool, policy, verifier, inrelease, release_file, signature).await?;
    let release = Release::parse(&authenticated, &ParseLimits::default())?;
    policy.identity(&manifest.key()?, &release)?;
    if release.content_sha256().to_hex() != manifest.release_content_sha256
        || release.date.as_secs() != manifest.release_date
    {
        return Err(CheckpointError::Proof);
    }
    let (selected, _) = ferrum_apt::selection::select_for_architectures(
        &release,
        policy.components_for_suite(&release.codename),
        matches!(
            policy,
            TrustPolicy::Ubuntu { .. } | TrustPolicy::UbuntuPorts { .. }
        ),
        policy.architectures(),
    )
    .map_err(|_| CheckpointError::Proof)?;
    let selected_by_path: std::collections::HashMap<_, _> = selected
        .iter()
        .map(|target| (target.path.as_str(), target))
        .collect();
    let pinned = selected.iter().filter(|target| target.pinned).count();
    if manifest.artifacts.len() != pinned + 3 || manifest.derived.len() != selected.len() - pinned {
        return Err(CheckpointError::Proof);
    }
    for artifact in &manifest.artifacts {
        if !matches!(
            artifact.path.as_str(),
            "InRelease" | "Release" | "Release.gpg"
        ) && selected_by_path
            .get(artifact.path.as_str())
            .is_none_or(|target| !target.pinned)
        {
            return Err(CheckpointError::Proof);
        }
    }
    for derived in &manifest.derived {
        if selected_by_path
            .get(derived.path.as_str())
            .is_none_or(|target| {
                target.derived_from.as_deref() != Some(derived.source_path.as_str())
            })
        {
            return Err(CheckpointError::Proof);
        }
    }
    for (descriptor, object) in manifest.artifacts.iter().zip(&artifacts) {
        if Instant::now() >= proof_deadline {
            return Err(CheckpointError::Proof);
        }
        let expected = if matches!(
            descriptor.path.as_str(),
            "InRelease" | "Release" | "Release.gpg"
        ) {
            None
        } else {
            let path = RepositoryPath::parse_decoded(&descriptor.path)
                .map_err(|_| CheckpointError::Proof)?;
            let entry = release.entry(&path).ok_or(CheckpointError::Proof)?;
            if entry.size != descriptor.size {
                return Err(CheckpointError::Proof);
            }
            if crate::capture::is_index_path(&descriptor.path) {
                crate::capture::index::stage_authenticated_source(
                    spool,
                    object.clone(),
                    descriptor.path.clone(),
                    entry.clone(),
                    proof_deadline,
                    &CancellationToken::new(),
                )
                .await
                .map_err(|_| CheckpointError::Proof)?;
                continue;
            }
            Some(entry)
        };
        let mut sha256 = Sha256Hasher::new();
        let mut sha512 = Sha512Hasher::new();
        if object.size() > 0 {
            let mut stream = object.stream_range(0, object.size() - 1)?;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                sha256.update(&chunk);
                if expected.is_some_and(|entry| entry.sha512.is_some()) {
                    sha512.update(&chunk)
                }
            }
        }
        let digest = sha256.finalize();
        if digest != object.sha256()
            || expected.is_some_and(|entry| entry.sha256.is_some_and(|expected| expected != digest))
        {
            return Err(CheckpointError::Proof);
        }
        if expected.is_some_and(|entry| {
            entry
                .sha512
                .is_some_and(|expected| expected != sha512.finalize())
        }) {
            return Err(CheckpointError::Proof);
        }
        if let Some(base) = [".gz", ".xz", ".bz2"]
            .iter()
            .find_map(|extension| descriptor.path.strip_suffix(extension))
            && crate::capture::is_index_path(base)
        {
            let path = RepositoryPath::parse_decoded(base).map_err(|_| CheckpointError::Proof)?;
            let entry = release.entry(&path).ok_or(CheckpointError::Proof)?;
            crate::capture::index::stage_authenticated_source(
                spool,
                object.clone(),
                descriptor.path.clone(),
                entry.clone(),
                proof_deadline,
                &CancellationToken::new(),
            )
            .await
            .map_err(|_| CheckpointError::Proof)?;
        }
    }
    let mut derived_identities = Vec::with_capacity(manifest.derived.len());
    for derived in &manifest.derived {
        if Instant::now() >= proof_deadline {
            return Err(CheckpointError::Proof);
        }
        let path =
            RepositoryPath::parse_decoded(&derived.path).map_err(|_| CheckpointError::Proof)?;
        let entry = release.entry(&path).ok_or(CheckpointError::Proof)?;
        let source = find(&derived.source_path)?;
        if crate::capture::is_index_path(&derived.path) {
            crate::capture::index::stage_authenticated_source(
                spool,
                source.clone(),
                derived.source_path.clone(),
                entry.clone(),
                proof_deadline,
                &CancellationToken::new(),
            )
            .await
            .map_err(|_| CheckpointError::Proof)?;
            if let Some(sha256) = entry.sha256 {
                derived_identities.push((
                    derived.path.clone(),
                    ObjectIdentity {
                        sha256,
                        size: entry.size,
                    },
                ));
                continue;
            }
        }
        {
            let authentication = PROOF_CPU
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| CheckpointError::Proof)?;
            let identity = spool
                .verify_derived(
                    source.clone(),
                    derived.source_path.clone(),
                    entry.clone(),
                    authentication,
                )
                .await?;
            derived_identities.push((derived.path.clone(), identity));
        }
    }
    let proof = std::sync::Arc::new(VerifiedHistoricalProof {
        manifest: manifest.clone(),
        release,
        artifacts,
        owner: spool.clone(),
        derived_identities,
    });
    if let Some(path) = manifest
        .artifacts
        .iter()
        .map(|artifact| &artifact.path)
        .chain(manifest.derived.iter().map(|derived| &derived.path))
        .find(|path| crate::capture::is_index_path(path))
    {
        crate::capture::stage_package_index(
            spool,
            proof.clone(),
            path,
            proof_deadline,
            &CancellationToken::new(),
        )
        .await
        .map_err(|_| CheckpointError::Proof)?;
    }
    std::sync::Arc::try_unwrap(proof).map_err(|_| CheckpointError::Proof)
}

/// Cannot be constructed by callbacks, receipt JSON, or an unchecked manifest.
pub struct VerifiedGeneration {
    pub(crate) proof: Arc<VerifiedHistoricalProof>,
    manifest_sha256: String,
    confirmed_at: i64,
    proof_key: SuiteKey,
    verified_at: Instant,
    issuing_store: Arc<crate::s3::S3Store>,
}
impl VerifiedGeneration {
    pub fn key(&self) -> &SuiteKey {
        &self.proof_key
    }
    pub fn manifest(&self) -> &GenerationManifest {
        &self.proof.manifest
    }
    pub fn confirmed_at(&self) -> i64 {
        self.confirmed_at
    }
    pub fn release(&self) -> &Release {
        self.proof.release()
    }
    pub fn artifact(&self, path: &str) -> Option<&VerifiedObject> {
        self.proof.artifact(path)
    }
    pub fn proof(&self) -> Arc<VerifiedHistoricalProof> {
        self.proof.clone()
    }
    pub(crate) fn ensure_current(
        &self,
        store: &Arc<crate::s3::S3Store>,
    ) -> Result<(), CheckpointError> {
        if !Arc::ptr_eq(&self.issuing_store, store) {
            return Err(CheckpointError::Proof);
        }
        let now = UnixTime::now().as_secs();
        if self.verified_at.elapsed() > Duration::from_secs(600)
            || now < self.confirmed_at.saturating_sub(600)
            || self.proof.release.date.as_secs() > now.saturating_add(600)
            || self
                .proof
                .release
                .valid_until
                .is_some_and(|until| until.as_secs() <= now)
        {
            return Err(CheckpointError::Origin);
        }
        Ok(())
    }
    pub(crate) fn intent(&self, sequence: u64) -> PublicationIntent {
        let manifest = &self.proof.manifest;
        PublicationIntent {
            schema_version: 1,
            repository: manifest.repository.clone(),
            suite: manifest.suite.clone(),
            sequence,
            generation_id: manifest.generation_id.clone(),
            manifest_sha256: self.manifest_sha256.clone(),
            release_content_sha256: manifest.release_content_sha256.clone(),
            release_date: manifest.release_date,
        }
    }
}

/// Resolver used by the actual HTTP connector: all answers must be globally
/// routable before any address is returned. Redirects/proxies are disabled.
#[derive(Debug)]
pub struct PublicResolver;
impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            if addresses.is_empty() || addresses.iter().any(|address| !public_ip(address.ip())) {
                return Err(
                    Box::new(std::io::Error::other("non-global origin DNS answer"))
                        as Box<dyn std::error::Error + Send + Sync>,
                );
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
pub(crate) fn public_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !matches!(a, 0 | 10 | 127 | 224..=255)
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..=31).contains(&b))
                && !(a == 192
                    && (b == 0
                        || b == 168
                        || b == 2
                        || b == 88 && c == 99
                        || b == 31 && c == 196
                        || b == 52 && c == 193
                        || b == 175 && c == 48))
                && !(a == 198 && (b == 18 || b == 19 || b == 51 && c == 100))
                && !(a == 203 && b == 0 && c == 113)
        }
        std::net::IpAddr::V6(ip) => {
            // Restrict to allocated global-unicast 2000::/3; exclude transition,
            // benchmarking, documentation and special-purpose 2001::/23.
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2000
                && s[0] != 0x3ffe
                && !(s[0] == 0x2001 && s[1] < 0x0200)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
                && !(s[0] == 0x2620 && s[1] == 0x004f && s[2] == 0x8000)
                && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0)
        }
    }
}

/// One reusable production/fixture origin verifier for B09. Fixed roots, bounded
/// body, connector-level DNS policy and the same verifier/parser as retained proofs.
pub struct OriginVerifier {
    client: reqwest::Client,
    #[cfg(any(test, feature = "test-harness"))]
    loopback: Option<String>,
}
pub struct AuthenticatedObservation {
    release: Release,
    inrelease: VerifiedObject,
    observed_at: i64,
}
impl AuthenticatedObservation {
    pub fn release(&self) -> &Release {
        &self.release
    }
    pub fn inrelease(&self) -> &VerifiedObject {
        &self.inrelease
    }
    pub fn observed_at(&self) -> i64 {
        self.observed_at
    }
}
impl OriginVerifier {
    pub fn new() -> Result<Self, CheckpointError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(30))
            .dns_resolver(Arc::new(PublicResolver))
            .build()
            .map_err(|_| CheckpointError::Origin)?;
        Ok(Self {
            client,
            #[cfg(any(test, feature = "test-harness"))]
            loopback: None,
        })
    }
    #[cfg(any(test, feature = "test-harness"))]
    pub fn loopback_for_tests(base: &str) -> Result<Self, CheckpointError> {
        let url = reqwest::Url::parse(base).map_err(|_| CheckpointError::Origin)?;
        if url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().ends_with('/')
            || url.path().contains('%')
        {
            return Err(CheckpointError::Origin);
        }
        let path = url.path().trim_matches('/');
        if !path.is_empty() {
            RepositoryPath::parse_decoded(path).map_err(|_| CheckpointError::Origin)?;
        }
        let mut verifier = Self::new()?;
        verifier.loopback = Some(url.to_string());
        Ok(verifier)
    }
    /// Authenticates fixed-origin APT, Pacman, or RPM repository metadata.
    /// Advances observed highwater, not an active pointer or checkpoint floor.
    pub async fn observe(
        &self,
        spool: &Spool,
        key: &SuiteKey,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        now: i64,
    ) -> Result<AuthenticatedObservation, CheckpointError> {
        Ok(self
            .observe_conditional(spool, key, policy, verifier, None, now)
            .await?
            .0)
    }
    /// A validator belongs to the exact saved signed representation. A 304
    /// repeats signature/key/time/high-water verification before any renewal.
    pub async fn observe_conditional(
        &self,
        spool: &Spool,
        key: &SuiteKey,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        saved: Option<(&VerifiedObject, &str)>,
        now: i64,
    ) -> Result<(AuthenticatedObservation, Option<String>), CheckpointError> {
        let url = policy.origin(key)?;
        #[cfg(any(test, feature = "test-harness"))]
        let url = if let Some(base) = &self.loopback {
            if policy.is_pacman() {
                format!(
                    "{base}{}/{}/{}",
                    key.repository(),
                    key.suite(),
                    policy.pacman_db_subpath(key)?
                )
            } else if policy.is_rpm() {
                format!(
                    "{base}{}/{}/repodata/repomd.xml",
                    key.repository(),
                    policy.rpm_suite_root(key)?
                )
            } else {
                format!("{base}{}/dists/{}/InRelease", key.repository(), key.suite())
            }
        } else {
            url
        };
        let reservation = spool.reserve_class(32 * 1024 * 1024, ReservationClass::Metadata)?;
        let mut request = self.client.get(url);
        if let Some((object, validator)) = saved {
            if !object.belongs_to(spool) || validator.len() > 1024 {
                return Err(CheckpointError::Proof);
            }
            request = request.header(reqwest::header::IF_NONE_MATCH, validator);
        }
        let response = request.send().await.map_err(|_| CheckpointError::Origin)?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            let (object, validator) = saved.ok_or(CheckpointError::Origin)?;
            drop(reservation);
            return Ok((
                self.revalidate(spool, key, policy, verifier, object, now)
                    .await?,
                Some(validator.to_owned()),
            ));
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(CheckpointError::Origin);
        }
        let validator = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= 1024)
            .map(str::to_owned);
        // Re-signing identical content is legitimate; Date/content highwater is
        // separate from the exact upstream signature-byte object identity.
        let declared = response.content_length();
        if declared.is_some_and(|size| size > 32 * 1024 * 1024) {
            return Err(CheckpointError::Origin);
        }
        // A bounded metadata document may use chunked transfer coding. Unknown
        // package lengths remain forbidden by the package capture API.
        let mut bytes = Vec::with_capacity(
            usize::try_from(declared.unwrap_or(64 * 1024)).map_err(|_| CheckpointError::Origin)?,
        );
        let mut sha256 = Sha256Hasher::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| CheckpointError::Origin)?;
            if (bytes.len() as u64).saturating_add(chunk.len() as u64) > 32 * 1024 * 1024 {
                return Err(CheckpointError::Origin);
            }
            sha256.update(&chunk);
            bytes.extend_from_slice(&chunk);
        }
        let size = bytes.len() as u64;
        if declared.is_some_and(|declared| declared != size) {
            return Err(CheckpointError::Origin);
        }
        let identity = ObjectIdentity {
            sha256: sha256.finalize(),
            size,
        };
        let reservation = if reservation.size() == size {
            reservation
        } else {
            drop(reservation);
            spool.reserve_class(size, ReservationClass::Metadata)?
        };
        let mut writer = spool.begin_write(reservation, identity).await?;
        writer.write(bytes.into()).await?;
        let object = writer.commit().await?;
        Ok((
            self.revalidate(spool, key, policy, verifier, &object, now)
                .await?,
            validator,
        ))
    }
    pub async fn revalidate(
        &self,
        spool: &Spool,
        key: &SuiteKey,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        object: &VerifiedObject,
        now: i64,
    ) -> Result<AuthenticatedObservation, CheckpointError> {
        if !object.belongs_to(spool) || object.size() > 32 * 1024 * 1024 {
            return Err(CheckpointError::Proof);
        }
        let release = if policy.is_pacman() {
            self.revalidate_pacman(spool, key, policy, verifier, object)
                .await?
        } else if policy.is_rpm() {
            self.revalidate_rpm(spool, key, policy, verifier, object)
                .await?
        } else {
            let scratch = spool.reserve_class(32 * 1024 * 1024, ReservationClass::Metadata)?;
            let authenticated = verifier
                .verify_cleartext_owned(
                    policy.keyring(),
                    object.path(),
                    &spool.root().join("temporary"),
                    32 * 1024 * 1024,
                    (scratch, object.clone()),
                )
                .await?;
            Release::parse(&authenticated, &ParseLimits::default())?
        };
        policy.identity(key, &release)?;
        if release.date.as_secs() > now.saturating_add(600)
            || release
                .valid_until
                .is_some_and(|until| until.as_secs() <= now)
        {
            return Err(CheckpointError::Origin);
        }
        crate::checkpoint::catalog_update(spool, |catalog| {
            catalog.publication_observe(
                key.clone(),
                object.sha256().to_hex(),
                release.date.as_secs(),
                release.content_sha256().to_hex(),
                now,
            )
        })?;
        Ok(AuthenticatedObservation {
            release,
            inrelease: object.clone(),
            observed_at: now,
        })
    }
    async fn revalidate_rpm(
        &self,
        spool: &Spool,
        key: &SuiteKey,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        metadata: &VerifiedObject,
    ) -> Result<Release, CheckpointError> {
        let bytes = metadata.read_bounded(32 * 1024 * 1024).await?;
        let root = policy.rpm_suite_root(key)?;
        let summary = ferrum_apt::rpm::parse_repomd_xml(&bytes, root, &ParseLimits::default())
            .map_err(|_| CheckpointError::Proof)?;
        if summary.repomd_identity != metadata.identity() {
            return Err(CheckpointError::Proof);
        }
        let url = policy.origin(key)?;
        #[cfg(any(test, feature = "test-harness"))]
        let url = self.loopback.as_ref().map_or(url, |base| {
            format!("{base}{}/{root}/repodata/repomd.xml", key.repository())
        });
        let response = self
            .client
            .get(format!("{url}.asc"))
            .send()
            .await
            .map_err(|_| CheckpointError::Origin)?;
        let declared = response.content_length();
        if response.status() != reqwest::StatusCode::OK
            || declared.is_some_and(|size| size > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64)
        {
            return Err(CheckpointError::Origin);
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| CheckpointError::Origin)?;
            if bytes.len().saturating_add(chunk.len()) > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES {
                return Err(CheckpointError::Origin);
            }
            bytes.extend_from_slice(&chunk);
        }
        if declared.is_some_and(|size| size != bytes.len() as u64) {
            return Err(CheckpointError::Origin);
        }
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(&bytes),
            size: bytes.len() as u64,
        };
        let signature = if let Some(object) = spool.lookup(identity) {
            object
        } else {
            let reservation = spool.reserve_class(identity.size, ReservationClass::Metadata)?;
            let mut writer = spool.begin_write(reservation, identity).await?;
            writer.write(bytes.into()).await?;
            writer.commit().await?
        };
        let scratch = spool.reserve_class(32 * 1024 * 1024, ReservationClass::Metadata)?;
        verifier
            .verify_detached_owned(
                policy.keyring(),
                metadata.path(),
                signature.path(),
                (scratch, metadata.clone(), signature.clone()),
            )
            .await?;
        rpm_release(key, policy, &summary, signature.identity())
    }
    async fn revalidate_pacman(
        &self,
        spool: &Spool,
        key: &SuiteKey,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        database: &VerifiedObject,
    ) -> Result<Release, CheckpointError> {
        let subpath = policy.pacman_db_subpath(key)?;
        let bytes = database.read_bounded(32 * 1024 * 1024).await?;
        let summary =
            ferrum_apt::pacman::summarize_pacman_db(&bytes, &subpath, &ParseLimits::default())
                .map_err(|_| CheckpointError::Proof)?;
        if summary.db_identity != database.identity() {
            return Err(CheckpointError::Proof);
        }
        let url = policy.origin(key)?;
        #[cfg(any(test, feature = "test-harness"))]
        let url = self.loopback.as_ref().map_or(url, |base| {
            format!("{base}{}/{}/{subpath}", key.repository(), key.suite())
        });
        let (directory, filename) = subpath.rsplit_once('/').ok_or(CheckpointError::Origin)?;
        let root = url.strip_suffix(filename).ok_or(CheckpointError::Origin)?;
        let package_path = summary
            .canary
            .path
            .as_str()
            .strip_prefix(directory)
            .and_then(|path| path.strip_prefix('/'))
            .ok_or(CheckpointError::Proof)?;
        let signature_path = summary
            .canary
            .sig_path
            .as_str()
            .strip_prefix(directory)
            .and_then(|path| path.strip_prefix('/'))
            .ok_or(CheckpointError::Proof)?;
        let package = if let Some(object) = spool.lookup(summary.canary.identity) {
            object
        } else {
            self.download_pacman_package(
                spool,
                &format!("{root}{package_path}"),
                summary.canary.identity,
            )
            .await?
        };
        let signature_bytes = if let Some(bytes) = &summary.canary.embedded_sig {
            bytes.clone()
        } else {
            let response = self
                .client
                .get(format!("{root}{signature_path}"))
                .send()
                .await
                .map_err(|_| CheckpointError::Origin)?;
            if response.status() != reqwest::StatusCode::OK
                || response
                    .content_length()
                    .is_some_and(|size| size > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64)
            {
                return Err(CheckpointError::Origin);
            }
            let declared = response.content_length();
            let mut bytes = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| CheckpointError::Origin)?;
                if bytes.len().saturating_add(chunk.len())
                    > ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES
                {
                    return Err(CheckpointError::Origin);
                }
                bytes.extend_from_slice(&chunk);
            }
            if declared.is_some_and(|size| size != bytes.len() as u64) {
                return Err(CheckpointError::Origin);
            }
            bytes
        };
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(&signature_bytes),
            size: signature_bytes.len() as u64,
        };
        let signature = if let Some(object) = spool.lookup(identity) {
            object
        } else {
            let reservation = spool.reserve_class(identity.size, ReservationClass::Metadata)?;
            let mut writer = spool.begin_write(reservation, identity).await?;
            writer.write(signature_bytes.into()).await?;
            writer.commit().await?
        };
        verify_pacman_canary(spool, key, policy, verifier, &summary, &package, &signature).await
    }

    async fn download_pacman_package(
        &self,
        spool: &Spool,
        url: &str,
        identity: ObjectIdentity,
    ) -> Result<VerifiedObject, CheckpointError> {
        let reservation = spool.reserve_class(identity.size, ReservationClass::Metadata)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| CheckpointError::Origin)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|size| size != identity.size)
        {
            return Err(CheckpointError::Origin);
        }
        let mut writer = spool.begin_write(reservation, identity).await?;
        let mut received = 0u64;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| CheckpointError::Origin)?;
            received = received
                .checked_add(chunk.len() as u64)
                .ok_or(CheckpointError::Origin)?;
            if received > identity.size {
                return Err(CheckpointError::Origin);
            }
            writer.write(chunk).await?;
        }
        if received != identity.size {
            return Err(CheckpointError::Origin);
        }
        Ok(writer.commit().await?)
    }
    async fn confirm(
        &self,
        spool: &Spool,
        proof: &VerifiedHistoricalProof,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        not_before: i64,
    ) -> Result<i64, CheckpointError> {
        let now = UnixTime::now().as_secs();
        if now < not_before {
            return Err(CheckpointError::Origin);
        }
        let observed = self
            .observe(spool, &proof.manifest.key()?, policy, verifier, now)
            .await?;
        if observed.release.content_sha256() != proof.release.content_sha256() {
            return Err(CheckpointError::Origin);
        }
        Ok(observed.observed_at())
    }
}

/// Borrowed trust and current-origin inputs shared by publication and recovery.
/// This context grants no authority: each operation still authenticates the
/// durable proof, then samples time for current-origin reconfirmation.
pub struct PublicationVerification<'a> {
    pub policy: &'a TrustPolicy,
    pub verifier: &'a SignatureVerifier,
    pub origin: &'a OriginVerifier,
}

impl CheckpointPublisher {
    /// Directly restores each exact manifest artifact through the shared verified
    /// spool, preserving reservations and transport accounting.
    pub(crate) async fn restore_artifacts(
        &self,
        manifest: &GenerationManifest,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<HashSet<Sha256Digest>, CheckpointError> {
        manifest.validate()?;
        let mut restored = HashSet::new();
        for artifact in &manifest.artifacts {
            let identity = artifact.identity()?;
            if self.spool.lookup(identity).is_some() {
                continue;
            }
            let reservation = self
                .spool
                .reserve_class(identity.size, ReservationClass::Metadata)?;
            let suffix = format!("v1/objects/sha256/{}", identity.sha256);
            let response = self
                .store
                .control_get_stream(
                    OperationIdentity::Object,
                    &suffix,
                    identity,
                    deadline,
                    cancel,
                )
                .await
                .map_err(|error| self.artifact_failure(identity, error))?;
            let mut writer = self.spool.begin_write(reservation, identity).await?;
            let mut stream = response.into_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| self.artifact_failure(identity, error))?;
                if let Err(error) = writer.write(chunk).await {
                    if matches!(
                        &error,
                        crate::SpoolError::Mismatch { .. } | crate::SpoolError::Overflow { .. }
                    ) {
                        self.store.quarantine(identity)?;
                    }
                    return Err(error.into());
                }
            }
            if let Err(error) = writer.commit().await {
                if matches!(
                    &error,
                    crate::SpoolError::Mismatch { .. } | crate::SpoolError::Overflow { .. }
                ) {
                    self.store.quarantine(identity)?;
                }
                return Err(error.into());
            }
            restored.insert(identity.sha256);
        }
        Ok(restored)
    }
    async fn verify_durable_proof(
        &self,
        manifest: &GenerationManifest,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        deadline: Instant,
        cancel: &CancellationToken,
        reuse: bool,
    ) -> Result<(Arc<VerifiedHistoricalProof>, String), CheckpointError> {
        let expected = manifest.encode()?;
        let manifest_identity = ObjectIdentity {
            sha256: Sha256Digest::of(&expected),
            size: expected.len() as u64,
        };
        if !reuse || !self.artifact_attested(&manifest.suffix(), manifest_identity)? {
            let remote = self
                .store
                .control_get(
                    OperationIdentity::Object,
                    &manifest.suffix(),
                    MANIFEST_LIMIT,
                    deadline,
                    cancel,
                )
                .await?;
            if remote.bytes != expected {
                return Err(CheckpointError::Proof);
            }
            self.attest_artifact(&manifest.suffix(), manifest_identity)?;
        }
        let restored = self.restore_artifacts(manifest, deadline, cancel).await?;
        // Full direct readback also checks already-local artifacts; local residency
        // alone is not evidence that a durable remote reconstruction closure exists.
        for artifact in &manifest.artifacts {
            let identity = artifact.identity()?;
            let suffix = format!("v1/objects/sha256/{}", identity.sha256);
            if restored.contains(&identity.sha256) {
                self.attest_artifact(&suffix, identity)?;
                continue;
            }
            if reuse && self.artifact_attested(&suffix, identity)? {
                continue;
            }
            let response = self
                .store
                .control_get_stream(
                    OperationIdentity::Object,
                    &suffix,
                    identity,
                    deadline,
                    cancel,
                )
                .await
                .map_err(|error| self.artifact_failure(identity, error))?;
            let mut stream = response.into_stream();
            let mut hasher = Sha256Hasher::new();
            let mut size = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| self.artifact_failure(identity, error))?;
                size = size
                    .checked_add(chunk.len() as u64)
                    .ok_or(CheckpointError::Proof)?;
                if size > identity.size {
                    self.store.quarantine(identity)?;
                    return Err(S3Error::Corrupt.into());
                }
                hasher.update(&chunk);
            }
            if size != identity.size || hasher.finalize() != identity.sha256 {
                self.store.quarantine(identity)?;
                return Err(S3Error::Corrupt.into());
            }
            self.attest_artifact(&suffix, identity)?;
        }
        if reuse
            && let Some(cached) = self
                .revalidate_cached(&manifest.scope_id().to_hex(), policy, verifier, deadline)
                .await?
        {
            return Ok((cached, Sha256Digest::of(&expected).to_hex()));
        }
        Ok((
            Arc::new(verify_historical_proof(&self.spool, manifest, policy, verifier).await?),
            Sha256Digest::of(&expected).to_hex(),
        ))
    }
    /// B09 entrypoint: no caller-supplied boolean/callback can claim durability.
    pub async fn verify_durable_generation(
        &self,
        manifest: &GenerationManifest,
        verification: &PublicationVerification<'_>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<VerifiedGeneration, CheckpointError> {
        let started_at = UnixTime::now().as_secs();
        let (proof, manifest_sha256) = self
            .verify_durable_proof(
                manifest,
                verification.policy,
                verification.verifier,
                deadline,
                cancel,
                true,
            )
            .await?;
        let confirmed_at = verification
            .origin
            .confirm(
                &self.spool,
                &proof,
                verification.policy,
                verification.verifier,
                started_at,
            )
            .await?;
        Ok(VerifiedGeneration {
            proof,
            manifest_sha256,
            confirmed_at,
            proof_key: manifest.key()?,
            verified_at: Instant::now(),
            issuing_store: self.store.clone(),
        })
    }
    /// Completes a durable intent locally without issuing mutable serving authority.
    /// This permits a healthy newer origin to be published above an expired floor.
    pub async fn recover_floor_artifacts(
        &self,
        key: &SuiteKey,
        trust: FloorTrust,
        policy: &TrustPolicy,
        verifier: &SignatureVerifier,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<RecoveredFloor, CheckpointError> {
        let (floor, _) = self.recovery_floor(key, trust, deadline, cancel).await?;
        let local = self.state(key)?;
        if local.floor.as_ref().is_some_and(|old| {
            old.sequence > floor.sequence || old.sequence == floor.sequence && *old != floor
        }) {
            return Err(CheckpointError::UntrustedFloor);
        }
        if let Some(pending) = local.pending.as_ref()
            && pending != &floor
        {
            if local.floor.as_ref() == Some(&floor) {
                // Crash before CAS: the unchanged trusted floor proves that
                // the prepared successor never established a recovery floor.
                crate::checkpoint::catalog_update(&self.spool, |catalog| {
                    catalog.checkpoint_cancel_unwritten(
                        key.clone(),
                        Some(floor.clone()),
                        true,
                        false,
                    )
                })?;
            } else {
                return Err(CheckpointError::Conflict);
            }
        }
        let suffix = format!(
            "v1/generations/{}/{}/{}/manifest.json",
            key.repository(),
            key.suite(),
            floor.generation_id
        );
        let object = self
            .store
            .control_get(
                OperationIdentity::Object,
                &suffix,
                MANIFEST_LIMIT,
                deadline,
                cancel,
            )
            .await?;
        if Sha256Digest::of(&object.bytes).to_hex() != floor.manifest_sha256 {
            return Err(CheckpointError::Proof);
        }
        let manifest: GenerationManifest = serde_json::from_slice(&object.bytes)?;
        manifest.validate()?;
        let reuse = local.floor.as_ref() == Some(&floor);
        let (proof, manifest_sha256) = self
            .verify_durable_proof(&manifest, policy, verifier, deadline, cancel, reuse)
            .await?;
        if manifest.key()? != *key
            || manifest.generation_id != floor.generation_id
            || manifest_sha256 != floor.manifest_sha256
            || manifest.release_content_sha256 != floor.release_content_sha256
            || manifest.release_date != floor.release_date
        {
            return Err(CheckpointError::Proof);
        }
        crate::checkpoint::catalog_update(&self.spool, |catalog| {
            catalog.checkpoint_accept(floor.clone())
        })?;
        self.spool
            .activate_publication(crate::catalog::publication::Activation {
                intent: floor.clone(),
                manifest: manifest.clone(),
                valid_until: proof.release().valid_until.map(|until| until.as_secs()),
                now: UnixTime::now().as_secs(),
                confirmed_at: None,
                metadata: proof.metadata_records()?,
            })?;
        self.cache_proof(proof.clone())?;
        Ok(RecoveredFloor {
            intent: floor,
            proof,
        })
    }
    /// Exact-floor recovery still reconfirms the authenticated current origin.
    pub async fn recover_suite(
        &self,
        key: &SuiteKey,
        trust: FloorTrust,
        verification: &PublicationVerification<'_>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<VerifiedGeneration, CheckpointError> {
        let started_at = UnixTime::now().as_secs();
        let recovered = self
            .recover_floor_artifacts(
                key,
                trust,
                verification.policy,
                verification.verifier,
                deadline,
                cancel,
            )
            .await?;
        let confirmed_at = verification
            .origin
            .confirm(
                &self.spool,
                &recovered.proof,
                verification.policy,
                verification.verifier,
                started_at,
            )
            .await?;
        let generation = VerifiedGeneration {
            proof: recovered.proof,
            manifest_sha256: recovered.intent.manifest_sha256.clone(),
            confirmed_at,
            proof_key: key.clone(),
            verified_at: Instant::now(),
            issuing_store: self.store.clone(),
        };
        crate::checkpoint::catalog_update(&self.spool, |catalog| {
            catalog.checkpoint_accept(recovered.intent.clone())
        })?;
        self.activate(&generation, &recovered.intent)?;
        Ok(generation)
    }
    /// Restores the trusted floor, then publishes a fully current successor with
    /// the next CAS sequence. No historical rollback reset is involved.
    pub async fn recover_and_publish(
        &self,
        manifest: &GenerationManifest,
        trust: FloorTrust,
        verification: &PublicationVerification<'_>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<VerifiedGeneration, CheckpointError> {
        self.recover_floor_artifacts(
            &manifest.key()?,
            trust,
            verification.policy,
            verification.verifier,
            deadline,
            cancel,
        )
        .await?;
        let generation = self
            .verify_durable_generation(manifest, verification, deadline, cancel)
            .await?;
        let intent = self.publish(&generation, deadline, cancel).await?;
        self.activate(&generation, &intent)?;
        Ok(generation)
    }
}

pub struct RecoveredFloor {
    intent: PublicationIntent,
    proof: Arc<VerifiedHistoricalProof>,
}
impl RecoveredFloor {
    pub fn intent(&self) -> &PublicationIntent {
        &self.intent
    }
    pub fn proof(&self) -> &VerifiedHistoricalProof {
        &self.proof
    }
}

/// Bootstrap is a deliberate reset, not recovery of a compromised/missing sequence.
pub struct BootstrapAudit {
    operator: String,
    reason: String,
    recorded_at: i64,
}
impl BootstrapAudit {
    pub fn acknowledge_reset(
        operator: &str,
        reason: &str,
        recorded_at: i64,
        disclosure: &str,
    ) -> Result<Self, CheckpointError> {
        if operator.trim().is_empty()
            || operator.len() > 128
            || reason.trim().is_empty()
            || reason.len() > 2048
            || disclosure != "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED"
        {
            return Err(CheckpointError::BootstrapAudit);
        }
        Ok(Self {
            operator: operator.into(),
            reason: reason.into(),
            recorded_at,
        })
    }
}
impl CheckpointPublisher {
    /// The operator audit is committed before any reset; current-origin proof is
    /// still mandatory. Existing remote records are replaced only with their CAS.
    pub async fn bootstrap(
        &self,
        generation: &VerifiedGeneration,
        audit: BootstrapAudit,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<PublicationIntent, CheckpointError> {
        generation.ensure_current(&self.store)?;
        let key = generation.key();
        self.record_bootstrap(key, audit)?;
        self.bootstrap_verified(generation, deadline, cancel).await
    }
    /// Records the reset before disregarding possibly untrusted local highwater.
    /// Failure during current-origin verification leaves the suite closed.
    pub async fn bootstrap_current(
        &self,
        manifest: &GenerationManifest,
        verification: &PublicationVerification<'_>,
        audit: BootstrapAudit,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(VerifiedGeneration, PublicationIntent), CheckpointError> {
        manifest.validate()?;
        self.record_bootstrap(&manifest.key()?, audit)?;
        let generation = self
            .verify_durable_generation(manifest, verification, deadline, cancel)
            .await?;
        let intent = self
            .bootstrap_verified(&generation, deadline, cancel)
            .await?;
        Ok((generation, intent))
    }
    /// Records an explicit operator bootstrap audit in the offline durable catalog.
    pub fn authorize_bootstrap(
        spool: &Spool,
        profile: RecoveryProfile,
        key: &SuiteKey,
        audit: BootstrapAudit,
    ) -> Result<(), CheckpointError> {
        profile.validate()?;
        crate::checkpoint::catalog_update(spool, |catalog| {
            catalog.checkpoint_bootstrap(
                key.clone(),
                audit.recorded_at,
                audit.operator,
                audit.reason,
                format!(
                    "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED. {}",
                    profile.disclosure()
                ),
            )
        })?;
        Ok(())
    }
    /// Completes a previously operator-authorized bootstrap after durable closure
    /// verification and current-origin reconfirmation.
    pub async fn complete_authorized_bootstrap(
        &self,
        generation: &VerifiedGeneration,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<PublicationIntent, CheckpointError> {
        self.bootstrap_verified(generation, deadline, cancel).await
    }
    fn record_bootstrap(
        &self,
        key: &SuiteKey,
        audit: BootstrapAudit,
    ) -> Result<(), CheckpointError> {
        Self::authorize_bootstrap(&self.spool, self.profile(), key, audit)
    }
    async fn bootstrap_verified(
        &self,
        generation: &VerifiedGeneration,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<PublicationIntent, CheckpointError> {
        generation.ensure_current(&self.store)?;
        self.spool
            .check_publication_capacity(generation.manifest())?;
        let key = generation.key();
        let remote = self
            .store
            .control_get(
                OperationIdentity::Checkpoint,
                &key.suffix(),
                crate::checkpoint::CHECKPOINT_LIMIT,
                deadline,
                cancel,
            )
            .await;
        let (sequence, condition) = match remote {
            Ok(object) => {
                let sequence = PublicationIntent::decode(&object.bytes)
                    .ok()
                    .and_then(|intent| intent.sequence.checked_add(1))
                    .filter(|sequence| *sequence <= i64::MAX as u64)
                    .unwrap_or(1);
                (sequence, crate::s3::ControlCondition::Match(object.etag))
            }
            Err(S3Error::NotFound) => (1, crate::s3::ControlCondition::Create),
            Err(error) => return Err(error.into()),
        };
        let intent = generation.intent(sequence);
        let encoded = intent.encode()?;
        crate::checkpoint::catalog_update(&self.spool, |catalog| {
            catalog.checkpoint_prepare_bootstrap(intent.clone())
        })?;
        let outcome = self
            .store
            .control_put(
                OperationIdentity::Checkpoint,
                &key.suffix(),
                encoded.as_bytes(),
                condition,
                deadline,
                cancel,
            )
            .await;
        let (actual, _) = self
            .read_floor(key, FloorTrust::IntactTrusted, deadline, cancel)
            .await?;
        if actual != intent {
            return Err(CheckpointError::Conflict);
        }
        if matches!(outcome, Err(S3Error::Unsupported)) {
            return Err(S3Error::Unsupported.into());
        }
        crate::checkpoint::catalog_update(&self.spool, |catalog| {
            catalog.checkpoint_accept(intent.clone())
        })?;
        self.activate(generation, &intent)?;
        Ok(intent)
    }
}

impl CheckpointPublisher {
    fn artifact_failure(&self, identity: ObjectIdentity, error: S3Error) -> CheckpointError {
        if error == S3Error::Corrupt
            && let Err(quarantine) = self.store.quarantine(identity)
        {
            return quarantine.into();
        }
        error.into()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn pacman_policies_bind_fixed_suites_and_architectures() {
        for (policy, repository, suite, origin, path) in [
            (
                TrustPolicy::ArchLinux {
                    keyring: PathBuf::new(),
                },
                "archlinux",
                "core",
                "ArchLinux",
                "os/x86_64/core.db",
            ),
            (
                TrustPolicy::ArchLinux {
                    keyring: PathBuf::new(),
                },
                "archlinux",
                "extra",
                "ArchLinux",
                "os/x86_64/extra.db",
            ),
            (
                TrustPolicy::ArchLinux {
                    keyring: PathBuf::new(),
                },
                "archlinux",
                "multilib",
                "ArchLinux",
                "os/x86_64/multilib.db",
            ),
            (
                TrustPolicy::ChaoticAur {
                    keyring: PathBuf::new(),
                },
                "chaotic-aur",
                "chaotic-aur",
                "ChaoticAUR",
                "x86_64/chaotic-aur.db",
            ),
            (
                TrustPolicy::CachyOs {
                    keyring: PathBuf::new(),
                },
                "cachyos",
                "cachyos-v3",
                "CachyOS",
                "x86_64/cachyos-v3.db",
            ),
            (
                TrustPolicy::ArchLinuxCn {
                    keyring: PathBuf::new(),
                },
                "archlinuxcn",
                "archlinuxcn",
                "ArchLinuxCN",
                "x86_64/archlinuxcn.db",
            ),
            (
                TrustPolicy::EndeavourOs {
                    keyring: PathBuf::new(),
                },
                "endeavouros",
                "endeavouros",
                "EndeavourOS",
                "x86_64/endeavouros.db",
            ),
        ] {
            let key = SuiteKey::new(repository, suite).unwrap();
            assert!(policy.is_pacman());
            assert_eq!(policy.components(), &["os"]);
            assert_eq!(policy.pacman_db_subpath(&key).unwrap(), path);
            if !matches!(policy, TrustPolicy::CachyOs { .. }) {
                assert!(policy.origin(&key).unwrap().ends_with(path));
            } else {
                assert_eq!(
                    policy.origin(&key).unwrap(),
                    "https://mirror.cachyos.org/repo/x86_64/cachyos-v3/cachyos-v3.db"
                );
            }
            let mut release = Release::for_pacman(
                origin,
                suite,
                UnixTime::from_secs(1),
                Sha256Digest::of(b"db"),
                Vec::new(),
            )
            .unwrap();
            policy.identity(&key, &release).unwrap();
            release.architectures = vec!["aarch64".into()];
            policy.identity(&key, &release).unwrap();
            release.architectures = vec!["amd64".into()];
            assert!(policy.identity(&key, &release).is_err());
            let wrong_key = SuiteKey::new(repository, "unsupported").unwrap();
            assert!(policy.pacman_db_subpath(&wrong_key).is_err());
            assert!(policy.origin(&wrong_key).is_err());
        }
    }

    #[test]
    fn pacman_manifest_requires_exact_database_canary_closure() {
        let digest = Sha256Digest::of(b"proof").to_hex();
        let mut manifest = GenerationManifest {
            schema_version: 1,
            repository: "archlinux".into(),
            suite: "core".into(),
            generation_id: digest.clone(),
            release_content_sha256: digest.clone(),
            release_date: 1,
            artifacts: [
                "os/x86_64/core.db",
                "os/x86_64/sample-1-1-any.pkg.tar.zst",
                "os/x86_64/sample-1-1-any.pkg.tar.zst.sig",
            ]
            .into_iter()
            .map(|path| ManifestArtifact {
                path: path.into(),
                sha256: digest.clone(),
                size: 1,
            })
            .collect(),
            derived: Vec::new(),
        };
        manifest.validate().unwrap();
        manifest.artifacts[2].path = "os/x86_64/other-1-1-any.pkg.tar.zst.sig".into();
        assert!(manifest.validate().is_err());
        manifest.artifacts[2].path = format!("{}.sig", manifest.artifacts[1].path);
        manifest.derived.push(DerivedArtifact {
            path: "os/x86_64/Packages".into(),
            source_path: "os/x86_64/core.db".into(),
        });
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn rpm_policies_and_manifests_bind_suite_roots() {
        for (policy, repository, origin) in [
            (
                TrustPolicy::AlmaLinux {
                    keyring: PathBuf::new(),
                },
                "almalinux",
                "AlmaLinux",
            ),
            (
                TrustPolicy::RockyLinux {
                    keyring: PathBuf::new(),
                },
                "rockylinux",
                "RockyLinux",
            ),
        ] {
            let key = SuiteKey::new(repository, "9-baseos-aarch64").unwrap();
            assert!(policy.is_rpm());
            assert!(!policy.is_pacman());
            assert_eq!(policy.rpm_suite_root(&key).unwrap(), "9/BaseOS/aarch64/os");
            assert!(
                policy
                    .origin(&key)
                    .unwrap()
                    .ends_with("/9/BaseOS/aarch64/os/repodata/repomd.xml")
            );
            let digest = Sha256Digest::of(b"metadata").to_hex();
            let mut manifest = GenerationManifest {
                schema_version: 1,
                repository: repository.into(),
                suite: key.suite().into(),
                generation_id: digest.clone(),
                release_content_sha256: digest.clone(),
                release_date: 1,
                artifacts: [
                    "9/BaseOS/aarch64/os/repodata/repomd.xml",
                    "9/BaseOS/aarch64/os/repodata/repomd.xml.asc",
                    "9/BaseOS/aarch64/os/repodata/primary.xml.gz",
                ]
                .into_iter()
                .map(|path| ManifestArtifact {
                    path: path.into(),
                    sha256: digest.clone(),
                    size: 1,
                })
                .collect(),
                derived: Vec::new(),
            };
            manifest.validate().unwrap();
            manifest.artifacts.swap(0, 1);
            assert!(manifest.validate().is_err());
            manifest.artifacts.swap(0, 1);
            manifest.artifacts[2].path = "9/BaseOS/aarch64/os/repodata/filelists.xml.gz".into();
            assert!(manifest.validate().is_err());
            let mut release = Release::for_pacman(
                origin,
                key.suite(),
                UnixTime::from_secs(1),
                Sha256Digest::of(b"metadata"),
                Vec::new(),
            )
            .unwrap();
            release.architectures = vec!["aarch64".into()];
            policy.identity(&key, &release).unwrap();
            release.architectures = vec!["amd64".into()];
            assert!(policy.identity(&key, &release).is_err());
            assert!(
                policy
                    .rpm_suite_root(&SuiteKey::new(repository, "unsupported").unwrap())
                    .is_err()
            );
        }
    }

    #[test]
    fn vendor_apt_policies_accept_arm64_and_keep_origin_authority() {
        for (policy, repository, suite, origin, component) in [
            (
                TrustPolicy::UbuntuPorts {
                    keyring: PathBuf::new(),
                },
                "ubuntu-ports",
                "noble-security",
                "Ubuntu",
                "main",
            ),
            (
                TrustPolicy::DockerDebian {
                    keyring: PathBuf::new(),
                },
                "docker-debian",
                "bookworm",
                "Docker",
                "stable",
            ),
            (
                TrustPolicy::DockerUbuntu {
                    keyring: PathBuf::new(),
                },
                "docker-ubuntu",
                "noble",
                "Docker",
                "stable",
            ),
            (
                TrustPolicy::TailscaleDebian {
                    keyring: PathBuf::new(),
                },
                "tailscale-debian",
                "trixie",
                "Tailscale",
                "main",
            ),
            (
                TrustPolicy::TailscaleUbuntu {
                    keyring: PathBuf::new(),
                },
                "tailscale-ubuntu",
                "jammy",
                "Tailscale",
                "main",
            ),
            (
                TrustPolicy::PostgresqlApt {
                    keyring: PathBuf::new(),
                },
                "postgresql-apt",
                "noble-pgdg",
                "apt.postgresql.org",
                "main",
            ),
            (
                TrustPolicy::GrafanaApt {
                    keyring: PathBuf::new(),
                },
                "grafana-apt",
                "stable",
                ". stable",
                "main",
            ),
        ] {
            let key = SuiteKey::new(repository, suite).unwrap();
            let text = format!(
                "Origin: {origin}\nSuite: {suite}\nCodename: {suite}\nDate: Sat, 17 Oct 2026 15:37:43 UTC\nArchitectures: arm64\nComponents: {component}\nSHA256:\n {} 1 {component}/binary-arm64/Packages\n",
                Sha256Digest::of(b"x").to_hex()
            );
            let mut release = Release::parse(text.as_bytes(), &ParseLimits::default()).unwrap();
            policy.identity(&key, &release).unwrap();
            assert!(policy.architectures().contains(&"arm64"));
            assert!(policy.components().contains(&component));
            assert!(
                policy
                    .origin(&key)
                    .unwrap()
                    .ends_with(&format!("/dists/{suite}/InRelease"))
            );
            release.origin = "Untrusted".into();
            assert!(policy.identity(&key, &release).is_err());
            assert!(
                policy
                    .origin(&SuiteKey::new(repository, "unsupported").unwrap())
                    .is_err()
            );
        }
    }
    // Header and acquisition-entry subset copied verbatim from retained
    // fixture/run/inventory-20261017/snapshot-2/debian-security-trixie-security/
    // authenticated-Release. This parser/policy regression does not claim to
    // authenticate this reduced document or require gitignored inventory files.
    const SECURITY_RELEASE: &str = concat!(
        "Origin: Debian\nLabel: Debian-Security\nSuite: stable-security\nVersion: 13\n",
        "Codename: trixie-security\nDate: Sat, 17 Oct 2026 15:37:43 UTC\n",
        "Valid-Until: Sat, 24 Oct 2026 15:37:43 UTC\nAcquire-By-Hash: yes\n",
        "Architectures: amd64 arm64 armel armhf i386 ppc64el riscv64 s390x\n",
        "Components: updates/main updates/contrib updates/non-free-firmware updates/non-free\n",
        "Description: Debian 13 - Security Updates\nSHA256:\n",
        " 7fd8b35aa5c8c61e6918820be8410cccb855f11afd24842c6e07b6dd0219c4b0    12938 contrib/binary-amd64/Packages\n",
        " 016f6d630d8536cdaf061ca623fbce587a8f624fa1fa93c4eb29a2c747bb5a8d   776961 main/binary-all/Packages\n",
        " f5e75cbf6c654c461f16b2296daccf05cf905eb597258aea8953bea0c064fdef  1853032 main/binary-amd64/Packages\n",
        " 365a16864bdd378f61fed57e03b2e5bca7384f28f20889e19d81ea2d27cacc86      693 non-free-firmware/binary-amd64/Packages\n",
        " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/binary-amd64/Packages\n",
    );

    #[test]
    fn debian_security_uses_authenticated_acquisition_paths_not_header_prefixes() {
        let policy = TrustPolicy::Debian {
            keyring: PathBuf::new(),
        };
        let key = SuiteKey::new("debian-security", "trixie-security").unwrap();
        let release = Release::parse(SECURITY_RELEASE.as_bytes(), &ParseLimits::default()).unwrap();
        policy.identity(&key, &release).unwrap();
        let paths = selected_metadata_paths(&release, &policy).unwrap();
        assert_eq!(paths.len(), 5);
        for component in policy.components() {
            assert!(
                paths
                    .iter()
                    .any(|path| path.as_str() == format!("{component}/binary-amd64/Packages"))
            );
        }
        assert!(
            paths
                .iter()
                .any(|path| path.as_str() == "main/binary-all/Packages")
        );
        assert_eq!(
            policy.origin(&key).unwrap(),
            "https://deb.debian.org/debian-security/dists/trixie-security/InRelease"
        );

        // A signed header cannot substitute updates/main (or any other root)
        // for a required client acquisition path.
        for prefix in ["updates/main", "arbitrary-root"] {
            let text = SECURITY_RELEASE.replace(
                "main/binary-amd64/Packages",
                &format!("{prefix}/binary-amd64/Packages"),
            );
            let release = Release::parse(text.as_bytes(), &ParseLimits::default()).unwrap();
            assert!(
                selected_metadata_paths(&release, &policy).is_err(),
                "{prefix}"
            );
        }
    }

    #[test]
    fn distribution_identity_and_component_authority_remain_fixed() {
        let policy = TrustPolicy::Debian {
            keyring: PathBuf::new(),
        };
        let key = SuiteKey::new("debian-security", "trixie-security").unwrap();
        let release = Release::parse(SECURITY_RELEASE.as_bytes(), &ParseLimits::default()).unwrap();
        for (repository, suite) in [
            ("arbitrary-root", "trixie-security"),
            ("debian", "trixie-security"),
        ] {
            let other = SuiteKey::new(repository, suite).unwrap();
            assert!(policy.identity(&other, &release).is_err());
            assert!(policy.origin(&other).is_err());
        }
        for (from, to) in [
            ("Origin: Debian", "Origin: Ubuntu"),
            ("Codename: trixie-security", "Codename: trixie"),
            ("Architectures: amd64 ", "Architectures: "),
            ("Acquire-By-Hash: yes", "Acquire-By-Hash: no"),
        ] {
            let text = SECURITY_RELEASE.replace(from, to);
            let release = Release::parse(text.as_bytes(), &ParseLimits::default()).unwrap();
            assert!(policy.identity(&key, &release).is_err(), "{to}");
        }
    }

    #[test]
    fn all_six_suite_policies_require_their_fixed_client_component_paths() {
        for (repository, suite, ubuntu, codename, origin) in [
            ("debian", "bullseye", false, "bullseye", "Debian"),
            (
                "debian",
                "bullseye-updates",
                false,
                "bullseye-updates",
                "Debian",
            ),
            (
                "debian-security",
                "bullseye-security",
                false,
                "bullseye-security",
                "Debian",
            ),
            ("debian", "bookworm", false, "bookworm", "Debian"),
            (
                "debian",
                "bookworm-updates",
                false,
                "bookworm-updates",
                "Debian",
            ),
            (
                "debian",
                "bookworm-backports",
                false,
                "bookworm-backports",
                "Debian Backports",
            ),
            (
                "debian-security",
                "bookworm-security",
                false,
                "bookworm-security",
                "Debian",
            ),
            ("debian", "trixie", false, "trixie", "Debian"),
            (
                "debian",
                "trixie-updates",
                false,
                "trixie-updates",
                "Debian",
            ),
            (
                "debian",
                "trixie-backports",
                false,
                "trixie-backports",
                "Debian Backports",
            ),
            (
                "debian-security",
                "trixie-security",
                false,
                "trixie-security",
                "Debian",
            ),
            ("debian", "forky", false, "forky", "Debian"),
            ("debian", "forky-updates", false, "forky-updates", "Debian"),
            (
                "debian",
                "forky-backports",
                false,
                "forky-backports",
                "Debian Backports",
            ),
            (
                "debian-security",
                "forky-security",
                false,
                "forky-security",
                "Debian",
            ),
            ("ubuntu", "focal", true, "focal", "Ubuntu"),
            ("ubuntu", "focal-updates", true, "focal", "Ubuntu"),
            ("ubuntu", "focal-backports", true, "focal", "Ubuntu"),
            ("ubuntu-security", "focal-security", true, "focal", "Ubuntu"),
            ("ubuntu", "jammy", true, "jammy", "Ubuntu"),
            ("ubuntu", "jammy-updates", true, "jammy", "Ubuntu"),
            ("ubuntu", "jammy-backports", true, "jammy", "Ubuntu"),
            ("ubuntu-security", "jammy-security", true, "jammy", "Ubuntu"),
            ("ubuntu", "noble", true, "noble", "Ubuntu"),
            ("ubuntu", "noble-updates", true, "noble", "Ubuntu"),
            ("ubuntu", "noble-backports", true, "noble", "Ubuntu"),
            ("ubuntu-security", "noble-security", true, "noble", "Ubuntu"),
            ("ubuntu", "plucky", true, "plucky", "Ubuntu"),
            ("ubuntu", "plucky-updates", true, "plucky", "Ubuntu"),
            ("ubuntu", "plucky-backports", true, "plucky", "Ubuntu"),
            (
                "ubuntu-security",
                "plucky-security",
                true,
                "plucky",
                "Ubuntu",
            ),
            ("ubuntu", "questing", true, "questing", "Ubuntu"),
            ("ubuntu", "questing-updates", true, "questing", "Ubuntu"),
            ("ubuntu", "questing-backports", true, "questing", "Ubuntu"),
            (
                "ubuntu-security",
                "questing-security",
                true,
                "questing",
                "Ubuntu",
            ),
            ("ubuntu", "resolute", true, "resolute", "Ubuntu"),
            ("ubuntu", "resolute-updates", true, "resolute", "Ubuntu"),
            ("ubuntu", "resolute-backports", true, "resolute", "Ubuntu"),
            (
                "ubuntu-security",
                "resolute-security",
                true,
                "resolute",
                "Ubuntu",
            ),
        ] {
            let policy = if ubuntu {
                TrustPolicy::Ubuntu {
                    keyring: PathBuf::new(),
                }
            } else {
                TrustPolicy::Debian {
                    keyring: PathBuf::new(),
                }
            };
            let key = SuiteKey::new(repository, suite).unwrap();
            let components = policy.components_for_suite(codename);
            let header_components = if repository == "debian-security" {
                components
                    .iter()
                    .map(|component| format!("updates/{component}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                components.join(" ")
            };
            let mut text = format!(
                "Origin: {origin}\nSuite: {suite}\nCodename: {codename}\nArchitectures: amd64\nComponents: {header_components}\n\
                 Date: Sat, 17 Oct 2026 15:37:43 UTC\nAcquire-By-Hash: yes\nSHA256:\n",
            );
            for component in components.iter().chain(std::iter::once(&"arbitrary-root")) {
                text.push_str(&format!(
                    " {} 0 {component}/binary-amd64/Packages.xz\n",
                    "a".repeat(64)
                ));
            }
            let release = Release::parse(text.as_bytes(), &ParseLimits::default()).unwrap();
            policy.identity(&key, &release).unwrap();
            let paths = selected_metadata_paths(&release, &policy).unwrap();
            assert_eq!(paths.len(), components.len(), "{suite}");
            assert!(
                !paths
                    .iter()
                    .any(|path| path.as_str().starts_with("arbitrary-root/"))
            );
            for component in components {
                let missing = text.replace(
                    &format!("{component}/binary-amd64/Packages.xz"),
                    &format!("{component}/binary-arm64/Packages.xz"),
                );
                let release = Release::parse(missing.as_bytes(), &ParseLimits::default()).unwrap();
                assert!(
                    selected_metadata_paths(&release, &policy).is_err(),
                    "{suite}/{component}"
                );
            }
        }
    }
    #[test]
    fn connector_rejects_mapped_and_special_addresses() {
        for text in [
            "127.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "::ffff:8.8.8.8",
            "fc00::1",
            "2001:db8::1",
            "2002:808:808::1",
        ] {
            assert!(!public_ip(text.parse().unwrap()), "{text}")
        }
        for text in ["8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_ip(text.parse().unwrap()), "{text}")
        }
    }
    #[test]
    fn bootstrap_requires_reset_disclosure() {
        assert!(
            BootstrapAudit::acknowledge_reset("operator", "lost VM", 1, "recovered securely")
                .is_err()
        );
    }
}

#[cfg(all(test, feature = "test-harness"))]
mod transport_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::{
        budget::{BudgetLedger, BudgetLimits},
        checkpoint::RecoveryProfile,
        disk::DurableSpoolConfig,
        s3::{S3Config, S3Store, testing::ScriptedResponse},
    };
    fn response(
        method: &'static str,
        status: u16,
        body: Vec<u8>,
        lose_ack: bool,
    ) -> ScriptedResponse {
        ScriptedResponse {
            method,
            status,
            content_length: body.len() as u64,
            body,
            delay: Duration::ZERO,
            headers: Vec::new(),
            lose_ack,
        }
    }
    const PROTOCOL_RELEASE: &str = concat!(
        "Origin: Debian\nSuite: trixie\nCodename: trixie\nArchitectures: amd64\n",
        "Components: main contrib non-free non-free-firmware\n",
        "Date: Thu, 01 Jan 1970 00:00:00 UTC\nAcquire-By-Hash: yes\nSHA256:\n ",
        "0000000000000000000000000000000000000000000000000000000000000000",
        " 0 main/binary-amd64/Packages\n",
    );
    fn protocol_manifest() -> GenerationManifest {
        GenerationManifest {
            schema_version: 1,
            repository: "debian".into(),
            suite: "trixie".into(),
            generation_id: "b".repeat(64),
            release_content_sha256: Sha256Digest::of(PROTOCOL_RELEASE.as_bytes()).to_hex(),
            release_date: 0,
            artifacts: ["InRelease", "Release", "Release.gpg"]
                .into_iter()
                .map(|path| ManifestArtifact {
                    path: path.into(),
                    sha256: Sha256Digest::of(b"").to_hex(),
                    size: 0,
                })
                .collect(),
            derived: Vec::new(),
        }
    }
    fn intent(sequence: u64) -> PublicationIntent {
        PublicationIntent {
            schema_version: 1,
            repository: "debian".into(),
            suite: "trixie".into(),
            sequence,
            generation_id: "b".repeat(64),
            manifest_sha256: Sha256Digest::of(&protocol_manifest().encode().unwrap()).to_hex(),
            release_content_sha256: Sha256Digest::of(PROTOCOL_RELEASE.as_bytes()).to_hex(),
            release_date: 0,
        }
    }
    async fn generation(publisher: &CheckpointPublisher) -> VerifiedGeneration {
        let release = Release::parse(PROTOCOL_RELEASE.as_bytes(), &ParseLimits::default()).unwrap();
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(b""),
            size: 0,
        };
        let reservation = publisher
            .spool
            .reserve_class(0, ReservationClass::Metadata)
            .unwrap();
        let object = publisher
            .spool
            .begin_write(reservation, identity)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let manifest = protocol_manifest();
        let manifest_sha256 = Sha256Digest::of(&manifest.encode().unwrap()).to_hex();
        // Protocol-unit fixture only: signature/closure authenticity is exercised separately.
        let generation = VerifiedGeneration {
            proof: Arc::new(VerifiedHistoricalProof {
                manifest,
                release,
                artifacts: vec![object.clone(), object.clone(), object],
                owner: publisher.spool.clone(),
                derived_identities: Vec::new(),
            }),
            manifest_sha256,
            confirmed_at: UnixTime::now().as_secs(),
            proof_key: SuiteKey::new("debian", "trixie").unwrap(),
            verified_at: Instant::now(),
            issuing_store: publisher.store.clone(),
        };
        publisher
            .spool
            .durable_catalog()
            .unwrap()
            .stage_protocol_indexes(&generation.intent(1))
            .unwrap();
        generation
    }
    fn setup(
        responses: Vec<ScriptedResponse>,
    ) -> (
        tempfile::TempDir,
        CheckpointPublisher,
        crate::s3::testing::ScriptedRequests,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let mut config = DurableSpoolConfig::new(directory.path().join("state"));
        config.spool.managed_ceiling = 512 * 1024 * 1024;
        config.free_space_floor = 1024 * 1024;
        config.temporary_ceiling = 256 * 1024 * 1024;
        config.metadata_temporary_reserve = 128 * 1024 * 1024;
        config.metadata_ceiling = 256 * 1024 * 1024;
        config.catalog_ceiling = 32 * 1024 * 1024;
        config.eviction_high_watermark = 448 * 1024 * 1024;
        config.eviction_low_watermark = 384 * 1024 * 1024;
        let spool = Spool::open_durable(config).unwrap();
        let (publisher, requests) = setup_spool(spool, responses);
        (directory, publisher, requests)
    }
    fn setup_spool(
        spool: Spool,
        responses: Vec<ScriptedResponse>,
    ) -> (CheckpointPublisher, crate::s3::testing::ScriptedRequests) {
        let ledger = BudgetLedger::initialize(spool.clone(), BudgetLimits::default()).unwrap();
        let config = S3Config {
            endpoint: "https://s3.us-central-1.idrivee2.com".into(),
            region: "us-central-1".into(),
            bucket: "s3-andrew".into(),
            package_prefix: "linux-packages/".into(),
            checkpoint_prefix: "linux-checkpoints/".into(),
            credentials_file: spool
                .root()
                .parent()
                .unwrap()
                .join("unused-scripted-credentials"),
            shared_nonisolated: true,
        };
        let (store, requests) = S3Store::scripted_production(config, ledger, responses).unwrap();
        (
            CheckpointPublisher::new(spool, Arc::new(store), RecoveryProfile::SharedNonisolated)
                .unwrap(),
            requests,
        )
    }
    fn seed(publisher: &CheckpointPublisher, intent: &PublicationIntent) {
        let catalog = publisher.spool.durable_catalog().unwrap();
        let key = intent.key().unwrap();
        catalog
            .checkpoint_bootstrap(
                key,
                UnixTime::now().as_secs(),
                "operator".into(),
                "test reset".into(),
                "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED".into(),
            )
            .unwrap();
        catalog
            .checkpoint_bootstrap_protocol(intent.clone())
            .unwrap();
        catalog.checkpoint_accept(intent.clone()).unwrap();
        catalog.checkpoint_activate(intent.clone()).unwrap();
    }
    async fn warm_publisher(
        root: &std::path::Path,
        recoveries: usize,
    ) -> (
        test_support::SignedFixture,
        CheckpointPublisher,
        crate::s3::testing::ScriptedRequests,
        Arc<VerifiedHistoricalProof>,
    ) {
        let mut fixture = test_support::signed_fixture(&root.join("state")).await;
        let keyring = root.join("keyring.gpg");
        std::fs::copy(fixture.policy.keyring(), &keyring).unwrap();
        fixture.policy = TrustPolicy::LoopbackFixture { keyring };
        let manifest = fixture.manifest.encode().unwrap();
        let floor = PublicationIntent {
            schema_version: 1,
            repository: fixture.manifest.repository.clone(),
            suite: fixture.manifest.suite.clone(),
            sequence: 1,
            generation_id: fixture.manifest.generation_id.clone(),
            manifest_sha256: Sha256Digest::of(&manifest).to_hex(),
            release_content_sha256: fixture.manifest.release_content_sha256.clone(),
            release_date: fixture.manifest.release_date,
        };
        let floor = floor.encode().unwrap().into_bytes();
        let mut responses = vec![
            response("GET", 200, floor.clone(), false),
            response("GET", 200, manifest.clone(), false),
            response("GET", 200, manifest.clone(), false),
        ];
        for artifact in &fixture.manifest.artifacts {
            let bytes = fixture
                .spool
                .lookup(artifact.identity().unwrap())
                .unwrap()
                .read_bounded(32 * 1024 * 1024)
                .await
                .unwrap();
            responses.push(response("GET", 200, bytes, false));
        }
        for _ in 0..recoveries {
            responses.push(response("GET", 200, floor.clone(), false));
            responses.push(response("GET", 200, manifest.clone(), false));
        }
        let (publisher, requests) = setup_spool(fixture.spool.clone(), responses);
        let recovered = publisher
            .recover_floor_artifacts(
                &fixture.manifest.key().unwrap(),
                FloorTrust::IntactTrusted,
                &fixture.policy,
                &fixture.verifier,
                Instant::now() + Duration::from_secs(60),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        (fixture, publisher, requests, recovered.proof)
    }
    fn remove_signer(policy: &TrustPolicy) {
        // This is a valid keyring for a different key, not a corrupt/empty file.
        let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ferrum-apt/tests/data");
        std::fs::copy(data.join("keyring-revoked.gpg"), policy.keyring()).unwrap();
    }
    fn assert_serving(
        publisher: &CheckpointPublisher,
        proof: &VerifiedHistoricalProof,
        authorized: bool,
    ) {
        let path =
            RepositoryPath::parse_decoded("pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb")
                .unwrap();
        let package = publisher.lookup_package("fixture", &path);
        let metadata = publisher.lookup_by_hash(
            &proof.manifest().key().unwrap(),
            "main/binary-amd64",
            crate::checkpoint::MetadataHash::Sha256(
                proof
                    .identity("main/binary-amd64/Packages.gz")
                    .unwrap()
                    .sha256,
            ),
        );
        if authorized {
            package.unwrap().unwrap().authorize().unwrap();
            assert!(metadata.unwrap().is_some());
        } else {
            assert!(matches!(package, Err(CheckpointError::Proof)));
            assert!(matches!(metadata, Err(CheckpointError::Proof)));
            assert!(
                publisher
                    .retained_proofs(&proof.manifest().key().unwrap())
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn cached_floor_recovery_rejects_removed_signer() {
        let directory = tempfile::tempdir().unwrap();
        let (fixture, publisher, requests, proof) = warm_publisher(directory.path(), 2).await;
        assert_serving(&publisher, &proof, true);
        let key = fixture.manifest.key().unwrap();
        let recovered = publisher
            .recover_floor_artifacts(
                &key,
                FloorTrust::IntactTrusted,
                &fixture.policy,
                &fixture.verifier,
                Instant::now() + Duration::from_secs(60),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&proof, &recovered.proof));
        remove_signer(&fixture.policy);
        assert!(matches!(
            publisher
                .recover_floor_artifacts(
                    &key,
                    FloorTrust::IntactTrusted,
                    &fixture.policy,
                    &fixture.verifier,
                    Instant::now() + Duration::from_secs(60),
                    &CancellationToken::new(),
                )
                .await,
            Err(CheckpointError::Signature(_))
        ));
        assert_serving(&publisher, &proof, false);
        assert_eq!(
            requests.snapshot().unwrap().len(),
            7 + fixture.manifest.artifacts.len()
        );
    }
    #[tokio::test]
    async fn cached_retained_restore_rejects_removed_signer() {
        let directory = tempfile::tempdir().unwrap();
        let (fixture, publisher, requests, proof) = warm_publisher(directory.path(), 0).await;
        let key = fixture.manifest.key().unwrap();
        let request_count = requests.snapshot().unwrap().len();
        publisher
            .restore_retained(
                &key,
                &fixture.policy,
                &fixture.verifier,
                Instant::now() + Duration::from_secs(60),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &proof,
            &publisher.retained_proofs(&key).unwrap()[0]
        ));
        assert_serving(&publisher, &proof, true);
        remove_signer(&fixture.policy);
        assert!(matches!(
            publisher
                .restore_retained(
                    &key,
                    &fixture.policy,
                    &fixture.verifier,
                    Instant::now() + Duration::from_secs(60),
                    &CancellationToken::new(),
                )
                .await,
            Err(CheckpointError::Signature(_))
        ));
        assert_serving(&publisher, &proof, false);
        assert_eq!(requests.snapshot().unwrap().len(), request_count);
    }
    #[tokio::test]
    async fn lost_ack_is_reconciled_only_by_exact_intent_readback() {
        let first = intent(1);
        let next = intent(2);
        let responses = vec![
            response("GET", 200, serde_json::to_vec(&first).unwrap(), false),
            response("PUT", 200, Vec::new(), true),
            response("GET", 200, serde_json::to_vec(&next).unwrap(), false),
        ];
        let (_directory, publisher, requests) = setup(responses);
        seed(&publisher, &first);
        let generation = generation(&publisher).await;
        let intent = publisher
            .publish(
                &generation,
                Instant::now() + Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        let state = publisher.state(generation.key()).unwrap();
        assert_eq!(state.floor, Some(next));
        assert_eq!(state.active, Some(first));
        assert!(state.blocked);
        publisher.activate(&generation, &intent).unwrap();
        assert!(!publisher.state(generation.key()).unwrap().blocked);
        assert_eq!(requests.snapshot().unwrap(), ["GET", "PUT", "GET"]);
    }
    #[tokio::test]
    async fn conflicting_cas_never_advances_or_unconditionally_overwrites() {
        let first = intent(1);
        let mut competitor = intent(2);
        competitor.manifest_sha256 = "d".repeat(64);
        let responses = vec![
            response("GET", 200, serde_json::to_vec(&first).unwrap(), false),
            response(
                "PUT",
                412,
                b"<Error><Code>PreconditionFailed</Code></Error>".to_vec(),
                false,
            ),
            response("GET", 200, serde_json::to_vec(&competitor).unwrap(), false),
        ];
        let (_directory, publisher, requests) = setup(responses);
        seed(&publisher, &first);
        let generation = generation(&publisher).await;
        assert!(matches!(
            publisher
                .publish(
                    &generation,
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new()
                )
                .await,
            Err(CheckpointError::Conflict)
        ));
        let state = publisher.state(generation.key()).unwrap();
        assert_eq!(state.floor, Some(first));
        assert!(state.blocked);
        assert_eq!(requests.snapshot().unwrap(), ["GET", "PUT", "GET"]);
    }
    #[tokio::test]
    async fn rejected_auth_mutation_preserves_old_active_without_network_readback() {
        let first = intent(1);
        let (_directory, publisher, requests) = setup(vec![
            response("GET", 200, serde_json::to_vec(&first).unwrap(), false),
            response(
                "PUT",
                403,
                b"<Error><Code>AccessDenied</Code></Error>".to_vec(),
                false,
            ),
        ]);
        seed(&publisher, &first);
        let generation = generation(&publisher).await;
        assert!(
            publisher
                .publish(
                    &generation,
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new()
                )
                .await
                .is_err()
        );
        let state = publisher.state(generation.key()).unwrap();
        assert_eq!(state.active, Some(first));
        assert!(!state.blocked);
        assert!(state.pending.is_none());
        assert_eq!(requests.snapshot().unwrap(), ["GET", "PUT"]);
    }
    #[tokio::test]
    async fn definitely_unwritten_admission_failure_restores_prior_checkpoint_state() {
        let first = intent(1);
        let body = serde_json::to_vec(&first).unwrap();
        let (_directory, publisher, requests) = setup(vec![
            response("GET", 200, body.clone(), false),
            response("GET", 200, body, false),
        ]);
        seed(&publisher, &first);
        let generation = generation(&publisher).await;
        publisher
            .store
            .ledger()
            .unwrap()
            .reserve_storage(
                &format!("linux-packages/v1/objects/sha256/{}", "e".repeat(64)),
                BudgetLimits::default().storage,
                crate::budget::BudgetClass::Control,
            )
            .unwrap();
        assert!(
            publisher
                .publish(
                    &generation,
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new()
                )
                .await
                .is_err()
        );
        let state = publisher.state(generation.key()).unwrap();
        assert_eq!(state.active, Some(first));
        assert!(!state.blocked);
        assert!(state.pending.is_none());
        assert_eq!(requests.snapshot().unwrap(), ["GET", "GET"]);
    }
    #[tokio::test]
    async fn activation_pins_more_than_one_owner_batch_before_advancing() {
        let (_directory, publisher, _) = setup(Vec::new());
        let mut generation = generation(&publisher).await;
        let first = generation.intent(1);
        seed(&publisher, &first);
        for index in 0u8..9 {
            let bytes = bytes::Bytes::from(vec![index]);
            let identity = ObjectIdentity {
                sha256: Sha256Digest::of(&bytes),
                size: 1,
            };
            let reservation = publisher
                .spool
                .reserve_class(1, ReservationClass::Metadata)
                .unwrap();
            let mut writer = publisher
                .spool
                .begin_write(reservation, identity)
                .await
                .unwrap();
            writer.write(bytes).await.unwrap();
            let object = writer.commit().await.unwrap();
            Arc::get_mut(&mut generation.proof)
                .unwrap()
                .manifest
                .artifacts
                .push(ManifestArtifact {
                    path: format!("artifact-{index}"),
                    sha256: identity.sha256.to_hex(),
                    size: 1,
                });
            Arc::get_mut(&mut generation.proof)
                .unwrap()
                .artifacts
                .push(object);
        }
        generation.manifest_sha256 =
            Sha256Digest::of(&generation.manifest().encode().unwrap()).to_hex();
        let next = generation.intent(2);
        let catalog = publisher.spool.durable_catalog().unwrap();
        catalog.checkpoint_prepare_protocol(next.clone()).unwrap();
        catalog.checkpoint_accept(next.clone()).unwrap();
        publisher.activate(&generation, &next).unwrap();
        let count: i64 = catalog
            .read(|connection| {
                Ok(connection
                    .query_row("SELECT COUNT(*) FROM generation_pins", [], |row| row.get(0))?)
            })
            .unwrap();
        assert_eq!(count, 10);
        assert_eq!(
            publisher.state(generation.key()).unwrap().active,
            Some(next)
        );
    }
    #[tokio::test]
    async fn activating_equal_raw_generations_in_two_scopes_keeps_independent_owner_pins() {
        let (_directory, publisher, _) = setup(Vec::new());
        let mut first = generation(&publisher).await;
        let mut second = generation(&publisher).await;
        Arc::get_mut(&mut second.proof).unwrap().manifest.repository = "mirror".into();
        second.proof_key = SuiteKey::new("mirror", "trixie").unwrap();
        let bytes = bytes::Bytes::from_static(b"shared metadata object");
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(&bytes),
            size: bytes.len() as u64,
        };
        let reservation = publisher
            .spool
            .reserve_class(identity.size, ReservationClass::Metadata)
            .unwrap();
        let mut writer = publisher
            .spool
            .begin_write(reservation, identity)
            .await
            .unwrap();
        writer.write(bytes).await.unwrap();
        let object = writer.commit().await.unwrap();
        for generation in [&mut first, &mut second] {
            Arc::get_mut(&mut generation.proof)
                .unwrap()
                .manifest
                .artifacts
                .push(ManifestArtifact {
                    path: "owned-artifact".into(),
                    sha256: identity.sha256.to_hex(),
                    size: identity.size,
                });
            Arc::get_mut(&mut generation.proof)
                .unwrap()
                .artifacts
                .push(object.clone());
            generation.manifest_sha256 =
                Sha256Digest::of(&generation.manifest().encode().unwrap()).to_hex();
            let old = generation.intent(1);
            seed(&publisher, &old);
            let next = generation.intent(2);
            let catalog = publisher.spool.durable_catalog().unwrap();
            catalog.checkpoint_prepare_protocol(next.clone()).unwrap();
            catalog.checkpoint_accept(next.clone()).unwrap();
            publisher.activate(generation, &next).unwrap();
        }
        assert_eq!(
            first.manifest().generation_id,
            second.manifest().generation_id
        );
        let first_scope = first.manifest().scope_id();
        let second_scope = second.manifest().scope_id();
        drop(first);
        drop(second);
        drop(object);
        publisher
            .proofs
            .lock()
            .expect("proof cache poisoned")
            .clear();
        publisher.spool.release_generation(first_scope).unwrap();
        assert_eq!(publisher.spool.reclaim(identity.size).unwrap(), 0);
        let resident = publisher
            .spool
            .lookup(identity)
            .expect("second scope still owns shared metadata");
        drop(resident);
        publisher.spool.release_generation(second_scope).unwrap();
        assert!(publisher.spool.reclaim(identity.size).unwrap() >= identity.size);
        assert!(publisher.spool.lookup(identity).is_none());
    }
    #[tokio::test]
    async fn definite_no_write_never_reopens_a_missing_or_malformed_floor() {
        for (status, body) in [
            (404, b"<Error><Code>NoSuchKey</Code></Error>".to_vec()),
            (200, b"not a checkpoint".to_vec()),
        ] {
            let first = intent(1);
            let (_directory, publisher, _) = setup(vec![
                response("GET", 200, serde_json::to_vec(&first).unwrap(), false),
                response("GET", status, body, false),
            ]);
            seed(&publisher, &first);
            let generation = generation(&publisher).await;
            publisher
                .store
                .ledger()
                .unwrap()
                .reserve_storage(
                    &format!("linux-packages/v1/objects/sha256/{}", "e".repeat(64)),
                    BudgetLimits::default().storage,
                    crate::budget::BudgetClass::Control,
                )
                .unwrap();
            assert!(
                publisher
                    .publish(
                        &generation,
                        Instant::now() + Duration::from_secs(5),
                        &CancellationToken::new()
                    )
                    .await
                    .is_err()
            );
            let state = publisher.state(generation.key()).unwrap();
            assert!(state.blocked);
            assert_eq!(state.active, Some(first));
        }
    }
    #[tokio::test]
    async fn unavailable_floor_preserves_intact_availability_but_blocks_promotion() {
        let first = intent(1);
        let (_directory, publisher, _requests) = setup(vec![response(
            "GET",
            503,
            b"<Error><Code>ServiceUnavailable</Code></Error>".to_vec(),
            false,
        )]);
        seed(&publisher, &first);
        let generation = generation(&publisher).await;
        assert!(
            publisher
                .publish(
                    &generation,
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new()
                )
                .await
                .is_err()
        );
        let state = publisher.state(generation.key()).unwrap();
        assert_eq!(state.active, Some(first));
        assert!(!state.blocked);
        assert!(state.pending.is_none());
    }
    #[tokio::test]
    async fn lost_state_missing_unavailable_and_untrusted_floor_close_only_selected_suite() {
        for status in [404, 503] {
            let code = if status == 404 {
                "NoSuchKey"
            } else {
                "ServiceUnavailable"
            };
            let (_directory, publisher, _) = setup(vec![response(
                "GET",
                status,
                format!("<Error><Code>{code}</Code></Error>").into_bytes(),
                false,
            )]);
            let key = SuiteKey::new("debian", "trixie").unwrap();
            assert!(
                publisher
                    .recovery_floor(
                        &key,
                        FloorTrust::IntactTrusted,
                        Instant::now() + Duration::from_secs(5),
                        &CancellationToken::new()
                    )
                    .await
                    .is_err()
            );
            assert!(publisher.state(&key).unwrap().blocked);
            assert!(
                !publisher
                    .state(&SuiteKey::new("ubuntu", "noble").unwrap())
                    .unwrap()
                    .blocked
            );
        }
        let (_directory, publisher, requests) = setup(Vec::new());
        let key = SuiteKey::new("debian", "trixie").unwrap();
        assert!(matches!(
            publisher
                .recovery_floor(
                    &key,
                    FloorTrust::MissingOrSuspectedCompromise,
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new()
                )
                .await,
            Err(CheckpointError::UntrustedFloor)
        ));
        assert!(requests.snapshot().unwrap().is_empty());
        assert!(publisher.state(&key).unwrap().blocked);
    }
    #[tokio::test]
    async fn bootstrap_persists_reset_audit_and_handles_lost_ack() {
        let first = intent(1);
        let (_directory, publisher, requests) = setup(vec![
            response(
                "GET",
                404,
                b"<Error><Code>NoSuchKey</Code></Error>".to_vec(),
                false,
            ),
            response("PUT", 200, Vec::new(), true),
            response("GET", 200, serde_json::to_vec(&first).unwrap(), false),
        ]);
        let generation = generation(&publisher).await;
        let audit = BootstrapAudit::acknowledge_reset(
            "operator",
            "catalog and historical floor lost",
            UnixTime::now().as_secs(),
            "HISTORICAL ROLLBACK PROTECTION RESET; NOT RECOVERED",
        )
        .unwrap();
        publisher
            .bootstrap(
                &generation,
                audit,
                Instant::now() + Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        let audit_count: u64 = publisher
            .spool
            .durable_catalog()
            .unwrap()
            .read(|connection| {
                Ok(connection.query_row(
                    "SELECT COUNT(*) FROM bootstrap_audit WHERE repository=?1 AND suite=?2 AND operator=?3 AND reason=?4",
                    [
                        "debian",
                        "trixie",
                        "operator",
                        "catalog and historical floor lost",
                    ],
                    |row| crate::catalog::read_unsigned(row, 0),
                )?)
            })
            .unwrap();
        assert_eq!(audit_count, 1);
        assert_eq!(requests.snapshot().unwrap(), ["GET", "PUT", "GET"]);
        assert_eq!(
            publisher.state(generation.key()).unwrap().active,
            Some(first)
        );
    }
    #[tokio::test]
    async fn foreign_store_authority_cannot_publish_activate_or_backup() {
        let (_first_directory, first, _) = setup(Vec::new());
        let (_second_directory, second, requests) = setup(Vec::new());
        let generation = generation(&first).await;
        let old = generation.intent(1);
        let next = generation.intent(2);
        seed(&second, &old);
        let catalog = second.spool.durable_catalog().unwrap();
        catalog.checkpoint_prepare_protocol(next.clone()).unwrap();
        catalog.checkpoint_accept(next.clone()).unwrap();
        assert!(matches!(
            second
                .publish(
                    &generation,
                    Instant::now() + Duration::from_secs(5),
                    &CancellationToken::new()
                )
                .await,
            Err(CheckpointError::Proof)
        ));
        assert!(matches!(
            second.activate(&generation, &next),
            Err(CheckpointError::Proof)
        ));
        assert_eq!(second.state(generation.key()).unwrap().active, Some(old));
        assert!(requests.snapshot().unwrap().is_empty());
        assert!(matches!(
            CheckpointPublisher::new(
                first.spool.clone(),
                second.store.clone(),
                RecoveryProfile::SharedNonisolated
            ),
            Err(CheckpointError::Proof)
        ));
        assert!(matches!(
            crate::backup::BackupService::new(
                first.spool.clone(),
                second.store.clone(),
                16 * 1024 * 1024
            ),
            Err(CheckpointError::Proof)
        ));
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    pub(crate) struct SignedFixture {
        pub spool: Spool,
        pub manifest: GenerationManifest,
        pub policy: TrustPolicy,
        pub verifier: SignatureVerifier,
    }
    pub(crate) fn open_spool(root: &std::path::Path) -> Spool {
        let mut config = crate::disk::DurableSpoolConfig::new(root.to_owned());
        config.spool.managed_ceiling = 512 * 1024 * 1024;
        config.spool.max_object_size = 128 * 1024 * 1024;
        config.free_space_floor = 1024 * 1024;
        config.temporary_ceiling = 256 * 1024 * 1024;
        config.metadata_temporary_reserve = 128 * 1024 * 1024;
        config.metadata_ceiling = 256 * 1024 * 1024;
        config.catalog_ceiling = 32 * 1024 * 1024;
        config.eviction_high_watermark = 448 * 1024 * 1024;
        config.eviction_low_watermark = 384 * 1024 * 1024;
        Spool::open_durable(config).unwrap()
    }
    pub(crate) async fn signed_fixture(root: &std::path::Path) -> SignedFixture {
        let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ferrum-apt/tests/data");
        let spool = open_spool(root);
        let compressed = std::process::Command::new("gzip")
            .args(["-9", "-n", "-c"])
            .arg(data.join("Packages"))
            .output()
            .expect("gzip static authenticated vector");
        assert!(compressed.status.success());
        let sources = vec![
            ("InRelease", std::fs::read(data.join("InRelease")).unwrap()),
            ("Release", std::fs::read(data.join("Release")).unwrap()),
            (
                "Release.gpg",
                std::fs::read(data.join("Release.gpg")).unwrap(),
            ),
            ("main/binary-amd64/Packages.gz", compressed.stdout),
            (
                "main/binary-amd64/Release",
                b"Archive: ferrum-test\nOrigin: FerrumTest\nLabel: FerrumTest\nComponent: main\nArchitecture: amd64\n".to_vec(),
            ),
        ];
        // Match the authenticated cleartext body, not the independently signed
        // detached representation whose final LF is outside the cleartext frame.
        let authenticated = sources[1]
            .1
            .strip_suffix(b"\n")
            .expect("Release fixture ends with LF");
        let release = Release::parse(authenticated, &ParseLimits::default()).unwrap();
        let mut artifacts = Vec::new();
        for (path, bytes) in sources {
            let identity = ObjectIdentity {
                sha256: Sha256Digest::of(&bytes),
                size: bytes.len() as u64,
            };
            let reservation = spool
                .reserve_class(identity.size, ReservationClass::Metadata)
                .unwrap();
            let mut writer = spool.begin_write(reservation, identity).await.unwrap();
            writer.write(bytes.into()).await.unwrap();
            writer.commit().await.unwrap();
            artifacts.push(ManifestArtifact {
                path: path.into(),
                sha256: identity.sha256.to_hex(),
                size: identity.size,
            });
        }
        let manifest = GenerationManifest {
            schema_version: 1,
            repository: "fixture".into(),
            suite: "ferrum-test".into(),
            generation_id: artifacts[0].sha256.clone(),
            release_content_sha256: release.content_sha256().to_hex(),
            release_date: release.date.as_secs(),
            artifacts,
            derived: vec![DerivedArtifact {
                path: "main/binary-amd64/Packages".into(),
                source_path: "main/binary-amd64/Packages.gz".into(),
            }],
        };
        let binary = std::env::var_os("FERRUM_VERIFIER")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("ferrum-verifier"));
        let verifier = SignatureVerifier::new(binary, Duration::from_secs(30))
            .await
            .expect("ferrum-verifier 0.1.0 required");
        SignedFixture {
            spool,
            manifest,
            policy: TrustPolicy::LoopbackFixture {
                keyring: data.join("keyring.gpg"),
            },
            verifier,
        }
    }
}

#[cfg(test)]
mod signed_proof_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[tokio::test]
    async fn actual_signed_compressed_closure_authenticates_without_retained_expanded_copy() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = test_support::signed_fixture(&directory.path().join("state")).await;
        let proof = verify_historical_proof(
            &fixture.spool,
            &fixture.manifest,
            &fixture.policy,
            &fixture.verifier,
        )
        .await
        .unwrap();
        let (source, entry) = proof.packages_source("main/binary-amd64/Packages").unwrap();
        assert_eq!(
            source.identity(),
            fixture
                .manifest
                .artifacts
                .iter()
                .find(|artifact| artifact.path.ends_with("Packages.gz"))
                .unwrap()
                .identity()
                .unwrap()
        );
        assert!(entry.sha256.is_some());
        assert!(proof.artifact("main/binary-amd64/Packages").is_none());
        let index = crate::capture::stage_package_index(
            &fixture.spool,
            Arc::new(proof),
            "main/binary-amd64/Packages",
            Instant::now() + Duration::from_secs(60),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        let path =
            RepositoryPath::parse_decoded("pool/main/f/ferrum-fixture/ferrum-fixture_1.0_all.deb")
                .unwrap();
        assert_eq!(
            index.lookup(&path).unwrap(),
            Some(ObjectIdentity {
                sha256: Sha256Digest::from_hex(
                    "bbf3d2c1ae800e53631d807f7818799a9de281f178f408658e392907a2036e62",
                )
                .unwrap(),
                size: 1234,
            })
        );
        let mut incomplete = fixture.manifest.clone();
        incomplete.derived.clear();
        assert!(
            verify_historical_proof(
                &fixture.spool,
                &incomplete,
                &fixture.policy,
                &fixture.verifier
            )
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn unsigned_wrong_identity_and_replayed_release_hash_do_not_authorize_proof() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = test_support::signed_fixture(&directory.path().join("state")).await;
        let mut forged = fixture.manifest.clone();
        forged.release_content_sha256 = "f".repeat(64);
        assert!(
            verify_historical_proof(&fixture.spool, &forged, &fixture.policy, &fixture.verifier)
                .await
                .is_err()
        );
        let mut detached_hash = fixture.manifest.clone();
        detached_hash.release_content_sha256 = detached_hash
            .artifacts
            .iter()
            .find(|artifact| artifact.path == "Release")
            .unwrap()
            .sha256
            .clone();
        assert_ne!(
            detached_hash.release_content_sha256,
            fixture.manifest.release_content_sha256
        );
        assert!(
            verify_historical_proof(
                &fixture.spool,
                &detached_hash,
                &fixture.policy,
                &fixture.verifier
            )
            .await
            .is_err()
        );
        let mut wrong_identity = fixture.manifest.clone();
        wrong_identity.repository = "debian".into();
        wrong_identity.suite = "trixie".into();
        assert!(
            verify_historical_proof(
                &fixture.spool,
                &wrong_identity,
                &fixture.policy,
                &fixture.verifier
            )
            .await
            .is_err()
        );
        let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ferrum-apt/tests/data");
        let bytes = std::fs::read(data.join("InRelease.unknown")).unwrap();
        let identity = ObjectIdentity {
            sha256: Sha256Digest::of(&bytes),
            size: bytes.len() as u64,
        };
        let reservation = fixture
            .spool
            .reserve_class(identity.size, ReservationClass::Metadata)
            .unwrap();
        let mut writer = fixture
            .spool
            .begin_write(reservation, identity)
            .await
            .unwrap();
        writer.write(bytes.into()).await.unwrap();
        writer.commit().await.unwrap();
        let mut forged = fixture.manifest.clone();
        forged.generation_id = identity.sha256.to_hex();
        forged.artifacts[0] = ManifestArtifact {
            path: "InRelease".into(),
            sha256: identity.sha256.to_hex(),
            size: identity.size,
        };
        assert!(
            verify_historical_proof(&fixture.spool, &forged, &fixture.policy, &fixture.verifier)
                .await
                .is_err()
        );
    }
    #[test]
    fn xz_accepts_archive_dictionary_overhead_but_rejects_larger_dictionaries() {
        use std::io::Read;
        // Generated with: xz --format=xz --lzma2=dict={64,96}MiB
        // --threads=1 --no-adjust --check=crc64, over the expected payload below.
        // Tiny fixed fixtures avoid allocating large encoder match-finder tables.
        let dictionary_64 = b"\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x1c\x00\x00\x00\x10\xcf\x58\xcc\x01\x00\x16\x78\x7a\x2d\x64\x69\x63\x74\x69\x6f\x6e\x61\x72\x79\x2d\x62\x6f\x75\x6e\x64\x61\x72\x79\x0a\x00\x00\x2c\x0c\xb5\xb6\x90\x6b\x68\xa3\x00\x01\x2f\x17\x81\x08\x49\xb1\x1f\xb6\xf3\x7d\x01\x00\x00\x00\x00\x04\x59\x5a";
        let dictionary_96 = b"\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x1d\x00\x00\x00\x75\xa8\xe4\x74\x01\x00\x16\x78\x7a\x2d\x64\x69\x63\x74\x69\x6f\x6e\x61\x72\x79\x2d\x62\x6f\x75\x6e\x64\x61\x72\x79\x0a\x00\x00\x2c\x0c\xb5\xb6\x90\x6b\x68\xa3\x00\x01\x2f\x17\x81\x08\x49\xb1\x1f\xb6\xf3\x7d\x01\x00\x00\x00\x00\x04\x59\x5a";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Commands-amd64.xz");
        for (encoded, accepted) in [(dictionary_64, true), (dictionary_96, false)] {
            std::fs::write(&path, encoded).unwrap();
            let mut reader = proof_reader(
                std::fs::File::open(&path).unwrap(),
                "Commands-amd64.xz",
                CancellationToken::new(),
            )
            .unwrap();
            let mut decoded = Vec::new();
            let result = reader.read_to_end(&mut decoded);
            if accepted {
                result.unwrap();
                assert_eq!(decoded, b"xz-dictionary-boundary\n");
            } else {
                assert!(result.is_err());
                assert!(decoded.is_empty());
            }
        }
    }

    #[test]
    fn shared_decoder_rejects_trailing_garbage_and_cancelled_empty_members() {
        use std::io::{Read, Write};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("compressed");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"payload").unwrap();
        let mut bytes = encoder.finish().unwrap();
        bytes.extend_from_slice(b"not another gzip member");
        std::fs::write(&path, bytes).unwrap();
        let mut reader = proof_reader(
            std::fs::File::open(&path).unwrap(),
            "Packages.gz",
            CancellationToken::new(),
        )
        .unwrap();
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
        let token = CancellationToken::new();
        let mut reader = proof_reader(
            std::fs::File::open(path).unwrap(),
            "Packages.gz",
            token.clone(),
        )
        .unwrap();
        token.cancel();
        assert!(reader.read(&mut [0; 1]).is_err());
    }
}
