use std::io::{self, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use ferrum_apt::digest::{Sha256Hasher, Sha512Hasher};
use ferrum_apt::index::{IndexError, parse_packages};
use ferrum_apt::release::{ParseLimits, ReleaseEntry};
use serde::Serialize;

use crate::transfer;

const EXPANDED_CAP: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const PACKAGE_CAP: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Default, Serialize)]
pub(crate) struct PackageSummary {
    pub(crate) records: u64,
    pub(crate) amd64: u64,
    pub(crate) all: u64,
    pub(crate) advertised_bytes_with_duplicates: u64,
    pub(crate) over_8_gib: u64,
    pub(crate) largest: Option<Largest>,
    pub(crate) expanded_bytes: u64,
    pub(crate) expanded_sha256: String,
    pub(crate) expanded_sha512: String,
    pub(crate) signed_expanded_verified: bool,
    pub(crate) max_line_bytes: u64,
    pub(crate) max_stanza_bytes: u64,
    pub(crate) line_1_mib_violations: u64,
    pub(crate) stanza_8_mib_violations: u64,
}

#[derive(Serialize)]
pub(crate) struct Largest {
    package: String,
    version: String,
    architecture: String,
    filename: String,
    sha256: String,
    pub(crate) bytes: u64,
}

struct Measured<R> {
    reader: R,
    bytes: u64,
    cap: u64,
    sha256: Sha256Hasher,
    sha512: Sha512Hasher,
    line: u64,
    stanza: u64,
    whitespace: bool,
    max_line: u64,
    max_stanza: u64,
}

impl<R: Read> Read for Measured<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.cap.saturating_sub(self.bytes).saturating_add(1);
        let length = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let count = self.reader.read(&mut buffer[..length])?;
        let chunk = &buffer[..count];
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("expanded byte counter overflow"))?;
        if self.bytes > self.cap {
            return Err(io::Error::other(
                "expanded Packages exceeds bounded signed size/2 GiB decode cap",
            ));
        }
        self.sha256.update(chunk);
        self.sha512.update(chunk);
        for &byte in chunk {
            self.line += 1;
            self.whitespace &= byte.is_ascii_whitespace();
            if byte == b'\n' {
                self.max_line = self.max_line.max(self.line);
                if self.whitespace {
                    self.stanza = 0;
                } else {
                    self.stanza += self.line;
                    self.max_stanza = self.max_stanza.max(self.stanza);
                }
                self.line = 0;
                self.whitespace = true;
            }
        }
        Ok(count)
    }
}

pub(crate) fn inspect(
    path: &Path,
    compression: &str,
    expanded: Option<&ReleaseEntry>,
) -> Result<PackageSummary> {
    let binary = match compression {
        "xz" => "/usr/bin/xz",
        "gzip" => "/usr/bin/gzip",
        "bzip2" => "/usr/bin/bzip2",
        _ => anyhow::bail!("unsupported Packages compression {compression}"),
    };
    let cap = expanded.map_or(EXPANDED_CAP, |entry| entry.size.min(EXPANDED_CAP));
    if let Some(entry) = expanded {
        ensure!(
            entry.size <= EXPANDED_CAP,
            "{} exceeds 2 GiB bounded decode cap",
            entry.path
        );
    }
    let mut child = Command::new("/usr/bin/timeout")
        .args([
            "--foreground",
            "--signal=KILL",
            "180",
            "/usr/bin/prlimit",
            "--cpu=120",
            "--as=1073741824",
            "--",
            binary,
            "--decompress",
            "--stdout",
            "--",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("launching bounded {binary}; timeout and prlimit are required"))?;
    let result = (|| {
        let stdout = child.stdout.take().context("decoder stdout missing")?;
        let measured = Measured {
            reader: stdout,
            bytes: 0,
            cap,
            sha256: Sha256Hasher::new(),
            sha512: Sha512Hasher::new(),
            line: 0,
            stanza: 0,
            whitespace: true,
            max_line: 0,
            max_stanza: 0,
        };
        let mut reader = BufReader::with_capacity(64 * 1024, measured);
        let mut summary = PackageSummary::default();
        let parsed = parse_packages(&mut reader, &ParseLimits::default(), &mut |record| {
            match record.architecture.as_str() {
                "amd64" => summary.amd64 += 1,
                "all" => summary.all += 1,
                architecture => {
                    return Err(IndexError::Sink(format!(
                        "foreign architecture {architecture} in selected Packages"
                    )));
                }
            }
            summary.records += 1;
            summary.advertised_bytes_with_duplicates = summary
                .advertised_bytes_with_duplicates
                .checked_add(record.size)
                .ok_or_else(|| IndexError::Sink("package size total overflow".to_owned()))?;
            if record.size > PACKAGE_CAP {
                summary.over_8_gib += 1;
            }
            if summary
                .largest
                .as_ref()
                .is_none_or(|largest| record.size > largest.bytes)
            {
                summary.largest = Some(Largest {
                    package: record.package,
                    version: record.version,
                    architecture: record.architecture,
                    filename: record.filename.as_str().to_owned(),
                    sha256: record.sha256.to_hex(),
                    bytes: record.size,
                });
            }
            Ok(())
        });
        if let Err(error) = parsed {
            let measured = reader.get_ref();
            let line = measured.max_line.max(measured.line);
            let stanza = measured.max_stanza.max(
                measured.stanza
                    + if measured.whitespace {
                        0
                    } else {
                        measured.line
                    },
            );
            return Err(anyhow::Error::new(error).context(format!(
                "Packages rejected; observed_line_1_mib_violation={}, observed_stanza_8_mib_violation={}; observed maxima {line}/{stanza} bytes; scan aborted, remaining violations unmeasured",
                line > 1024 * 1024,
                stanza > 8 * 1024 * 1024
            )));
        }
        let measured = reader.into_inner();
        summary.expanded_bytes = measured.bytes;
        summary.expanded_sha256 = measured.sha256.finalize().to_hex();
        summary.expanded_sha512 = measured.sha512.finalize().to_hex();
        summary.max_line_bytes = measured.max_line.max(measured.line);
        summary.max_stanza_bytes = measured.max_stanza.max(
            measured.stanza
                + if measured.whitespace {
                    0
                } else {
                    measured.line
                },
        );
        if let Some(entry) = expanded {
            transfer::verify(
                entry,
                summary.expanded_bytes,
                &summary.expanded_sha256,
                &summary.expanded_sha512,
            )?;
            summary.signed_expanded_verified = true;
        }
        Ok(summary)
    })();
    // Closing the read pipe on a parse error makes the decoder exit on SIGPIPE.
    // Let timeout reap it; killing only the timeout wrapper would orphan its child.
    let status = child.wait().context("reaping decoder")?;
    ensure!(
        status.success() || result.is_err(),
        "decoder failed or exceeded 180 seconds: {status}"
    );
    result
}
