#![allow(clippy::expect_used)]

use super::tests::{sample_tar, tar_entry};
use super::zstd::{raw_frame, skippable_frame};
use super::*;
use std::io::Write;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("encode gzip fixture");
    encoder.finish().expect("finish gzip fixture")
}

fn assert_rejected(bytes: &[u8]) {
    let limits = ParseLimits::default();
    assert!(summarize_pacman_db(bytes, "os/x86_64/core.db", &limits).is_err());
    assert!(
        parse_pacman_db(
            &mut Cursor::new(bytes),
            "os/x86_64/core.db",
            &limits,
            &mut |_| Ok(())
        )
        .is_err()
    );
}

#[test]
fn pacman_validates_checksums_on_every_nonzero_header() {
    let valid = sample_tar(false);
    let summary = summarize_pacman_db(&valid, "os/x86_64/core.db", &ParseLimits::default())
        .expect("valid checksum control");
    assert_eq!(summary.package_count, 2);
    let mut zero_checksum = valid.clone();
    zero_checksum[148..156].copy_from_slice(b"000000\0 ");
    let mut blank_checksum = valid.clone();
    blank_checksum[148..156].fill(b' ');
    let mut changed_path = valid.clone();
    changed_path[0] ^= 1;
    let mut changed_size = valid.clone();
    changed_size[124] = b'1';
    let mut invalid_checksum = valid.clone();
    invalid_checksum[148] = b'9';
    let mut ignored = tar_entry("ignored/not-desc", b"body");
    ignored[156] = b'5'; // Even ignored entry types must have a valid checksum.
    ignored.extend_from_slice(&valid);
    let mut after_records = valid[..valid.len() - 1024].to_vec();
    let mut corrupt_tail_header = tar_entry("ignored/after-desc", b"");
    corrupt_tail_header[148..156].copy_from_slice(b"000000\0 ");
    after_records.extend(corrupt_tail_header);
    after_records.resize(after_records.len() + 1024, 0);
    for invalid in [
        zero_checksum,
        blank_checksum,
        changed_path,
        changed_size,
        invalid_checksum,
        ignored,
        after_records,
    ] {
        for bytes in [invalid.clone(), gzip(&invalid), raw_frame(&invalid)] {
            assert_rejected(&bytes);
        }
    }
}

#[test]
fn pacman_requires_complete_terminal_blocks_and_zero_only_aligned_tail() {
    let valid = sample_tar(false);
    for removed in [1, 511, 512, 513, 1024] {
        let invalid = &valid[..valid.len() - removed];
        for bytes in [invalid.to_vec(), gzip(invalid), raw_frame(invalid)] {
            assert_rejected(&bytes);
        }
    }
    assert_rejected(&valid[..513]); // Complete header, incomplete description body.
    let mut partial_padding = valid.clone();
    partial_padding.push(0);
    assert_rejected(&partial_padding);
    let mut nonzero_tail = valid.clone();
    nonzero_tail.extend_from_slice(&tar_entry("hidden/desc", b"hidden"));
    assert_rejected(&nonzero_tail);
    let mut single_zero = valid[..valid.len() - 512].to_vec();
    single_zero.extend_from_slice(&tar_entry("after/one-zero", b""));
    single_zero.resize(single_zero.len() + 1024, 0);
    assert_rejected(&single_zero);
    let mut padded_valid = valid.clone();
    padded_valid.resize(padded_valid.len() + 20 * 512, 0);
    let summary = summarize_pacman_db(&padded_valid, "os/x86_64/core.db", &ParseLimits::default())
        .expect("tar record padding is legal");
    assert_eq!(summary.package_count, 2);
    assert_eq!(summary.content_sha256, Sha256Digest::of(&padded_valid));
}

struct ShortReads<'a>(&'a [u8]);

impl Read for ShortReads<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(1).min(self.0.len());
        output[..count].copy_from_slice(&self.0[..count]);
        self.0 = &self.0[count..];
        Ok(count)
    }
}

#[test]
fn pacman_decodes_concatenated_and_skippable_zstd_frames_with_short_input_reads() {
    let tar = sample_tar(false);
    // The frame boundary cuts through a tar header, not just between records.
    let split = 113;
    let mut bytes = skippable_frame(b"leading");
    bytes.extend(raw_frame(&tar[..split]));
    bytes.extend(skippable_frame(b"between"));
    bytes.extend(raw_frame(&tar[split..]));
    bytes.extend(skippable_frame(b"trailing"));
    let summary = summarize_pacman_db(&bytes, "os/x86_64/core.db", &ParseLimits::default())
        .expect("all Zstandard frames decoded");
    assert_eq!(summary.package_count, 2);
    assert_eq!(summary.content_sha256, Sha256Digest::of(&tar));
    let mut records = Vec::new();
    let count = parse_pacman_db(
        &mut ShortReads(&bytes),
        "os/x86_64/core.db",
        &ParseLimits::default(),
        &mut |record| {
            records.push(record);
            Ok(())
        },
    )
    .expect("preserves input buffered across frames and short reads");
    assert_eq!(count, 2);
    assert_eq!(records[1].package, "ferrum-small");
    for removed in [1, 4, 12] {
        assert_rejected(&bytes[..bytes.len() - removed]);
    }
    bytes.extend_from_slice(b"garbage after last frame");
    assert_rejected(&bytes);
}

#[test]
fn pacman_rejects_compressed_stream_truncation_after_valid_records() {
    let tar = sample_tar(false);
    let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
    xz.write_all(&tar).expect("encode xz");
    let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    bz.write_all(&tar).expect("encode bzip2");
    for bytes in [
        gzip(&tar),
        raw_frame(&tar),
        xz.finish().expect("finish xz"),
        bz.finish().expect("finish bzip2"),
    ] {
        assert_eq!(
            summarize_pacman_db(&bytes, "os/x86_64/core.db", &ParseLimits::default())
                .expect("valid compression control")
                .package_count,
            2
        );
        assert_rejected(&bytes[..bytes.len() - 1]);
    }
}

#[test]
fn embedded_signature_lookup_is_exact_and_validates_the_archive_tail() {
    let tar = sample_tar(true);
    let path = RepositoryPath::parse_decoded("core/os/x86_64/ferrum-small-1:1.0-1-any.pkg.tar.zst")
        .expect("valid package path");
    assert_eq!(
        package_embedded_signature(&tar, "os/x86_64/core.db", &path, &ParseLimits::default())
            .expect("signature lookup"),
        Some(b"sample-openpgp-sig".to_vec())
    );
    let wrong_suite =
        RepositoryPath::parse_decoded("extra/os/x86_64/ferrum-small-1:1.0-1-any.pkg.tar.zst")
            .expect("valid different suite path");
    assert!(
        package_embedded_signature(
            &tar,
            "os/x86_64/core.db",
            &wrong_suite,
            &ParseLimits::default()
        )
        .expect("different suite does not match")
        .is_none()
    );
    assert!(
        package_embedded_signature(
            &tar[..tar.len() - 512],
            "os/x86_64/core.db",
            &path,
            &ParseLimits::default()
        )
        .is_err()
    );
    let unsigned = sample_tar(false);
    assert!(
        package_embedded_signature(
            &unsigned,
            "os/x86_64/core.db",
            &path,
            &ParseLimits::default()
        )
        .expect("absent signature remains absent")
        .is_none()
    );
}
