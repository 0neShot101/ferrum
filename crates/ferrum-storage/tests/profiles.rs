#![allow(clippy::expect_used)]

use ferrum_apt::pacman::{is_pacman_package_path, pacman_package_prefix, split_cachyos_suite_path};
use ferrum_apt::release::{ParseLimits, Release};
use ferrum_storage::checkpoint::SuiteKey;
use ferrum_storage::recovery::{TrustPolicy, selected_metadata_paths};

// Header ordering, omitted Suite/Valid-Until/Acquire-By-Hash and selected entries
// from https://pkgs.tailscale.com/stable/debian/dists/trixie/Release.
const TAILSCALE_RELEASE: &str = "Date: Wed, 14 Oct 2026 00:59:08 UTC
Codename: trixie
Origin: Tailscale
Label: Tailscale
Architectures: all amd64 arm64 armhf i386 mips mips64 mips64el mips64le mipsel riscv64
Components: main
Description: Packages from Tailscale Inc. (https://www.tailscale.com)
SHA256:
 11a5c44499af3081da7724a5a1f17b9bea2d20b3c7fbd08edb25508f808d0e6d 351 main/binary-all/Packages.gz
 b614a8c19e7b33e518131e4c0ce7c9c0ee9131e7ac766d5655e18cf2955a8418 16252 main/binary-arm64/Packages.gz
 c3831fec9dbe6513ad45dd64d036280cf5ebb35ccfe7631b460ef4f5b89dfa8b 16494 main/binary-amd64/Packages.gz
";

#[test]
fn tailscale_real_layout_preserves_absent_suite_and_selects_client_indexes() {
    for (policy, repository, codename) in [
        (
            TrustPolicy::TailscaleDebian {
                keyring: "unused.gpg".into(),
            },
            "tailscale-debian",
            "trixie",
        ),
        (
            TrustPolicy::TailscaleUbuntu {
                keyring: "unused.gpg".into(),
            },
            "tailscale-ubuntu",
            "noble",
        ),
    ] {
        let text = TAILSCALE_RELEASE.replace("trixie", codename);
        let release =
            Release::parse(text.as_bytes(), &ParseLimits::default()).expect("Tailscale layout");
        assert_eq!(release.suite, None);
        let key = SuiteKey::new(repository, codename).expect("configured key");
        policy
            .identity(&key, &release)
            .expect("Origin and Codename authenticate identity without Suite");
        let paths = selected_metadata_paths(&release, &policy).expect("selected client indexes");
        assert!(
            paths
                .iter()
                .any(|path| path.as_str() == "main/binary-amd64/Packages.gz")
        );
        assert!(
            paths
                .iter()
                .any(|path| path.as_str() == "main/binary-arm64/Packages.gz")
        );
        for wrong in [
            text.replace("Origin: Tailscale", "Origin: Other"),
            text.replace(&format!("Codename: {codename}"), "Codename: other"),
            format!("Suite: other\n{text}"),
        ] {
            let release =
                Release::parse(wrong.as_bytes(), &ParseLimits::default()).expect("valid deb822");
            assert!(policy.identity(&key, &release).is_err());
        }
        let present = Release::parse(
            format!("Suite: {codename}\n{text}").as_bytes(),
            &ParseLimits::default(),
        )
        .expect("explicit matching Suite");
        policy.identity(&key, &present).expect("matching Suite");
    }
}

#[test]
fn debian_and_ubuntu_still_require_suite_and_ubuntu_rejects_wrong_pocket() {
    for (policy, repository, codename, origin) in [
        (
            TrustPolicy::Debian {
                keyring: "unused.gpg".into(),
            },
            "debian",
            "trixie",
            "Debian",
        ),
        (
            TrustPolicy::Ubuntu {
                keyring: "unused.gpg".into(),
            },
            "ubuntu",
            "noble",
            "Ubuntu",
        ),
    ] {
        let key = SuiteKey::new(repository, codename).expect("configured key");
        let text = TAILSCALE_RELEASE
            .replace("trixie", codename)
            .replace("Origin: Tailscale", &format!("Origin: {origin}"));
        let text = format!("Acquire-By-Hash: yes\n{text}");
        let absent = Release::parse(text.as_bytes(), &ParseLimits::default())
            .expect("optional parser field");
        assert!(policy.identity(&key, &absent).is_err());
        let present = Release::parse(
            format!("Suite: {codename}\n{text}").as_bytes(),
            &ParseLimits::default(),
        )
        .expect("matching Suite");
        policy
            .identity(&key, &present)
            .expect("strict existing identity");
        if repository == "ubuntu" {
            let wrong = Release::parse(
                format!("Suite: noble-updates\n{text}").as_bytes(),
                &ParseLimits::default(),
            )
            .expect("wrong pocket");
            assert!(policy.identity(&key, &wrong).is_err());
        }
    }
}

#[test]
fn cachyos_origins_metadata_and_package_requests_round_trip_exact_roots() {
    let policy = TrustPolicy::CachyOs {
        keyring: "unused.gpg".into(),
    };
    for (suite, architecture) in [
        ("cachyos", "x86_64"),
        ("cachyos-v3", "x86_64_v3"),
        ("cachyos-v4", "x86_64_v4"),
    ] {
        let key = SuiteKey::new("cachyos", suite).expect("suite key");
        let index = policy
            .pacman_db_subpath(&key)
            .expect("metadata descriptor path");
        assert_eq!(index, format!("{architecture}/{suite}.db"));
        let prefix = pacman_package_prefix(&index).expect("package index prefix");
        assert_eq!(prefix, format!("{architecture}/{suite}"));
        let request = format!("{prefix}/{suite}.db");
        let (requested_suite, relative) =
            split_cachyos_suite_path(&request).expect("request route");
        assert_eq!(requested_suite, suite);
        assert_eq!(format!("{architecture}/{relative}"), index);
        assert_eq!(
            policy.origin(&key).expect("fixed origin"),
            format!("https://mirror.cachyos.org/repo/{request}")
        );
        let package = format!("{prefix}/example-1-1-{architecture}.pkg.tar.zst");
        assert!(is_pacman_package_path(&package));
        assert!(is_pacman_package_path(&format!("{package}.sig")));
        if suite != "cachyos" {
            assert!(pacman_package_prefix(&format!("x86_64/{suite}.db")).is_none());
            assert!(split_cachyos_suite_path(&format!("x86_64/{suite}/{suite}.db")).is_none());
            assert!(!is_pacman_package_path(&format!(
                "x86_64/{suite}/example-1-1-x86_64.pkg.tar.zst"
            )));
        }
    }
}
