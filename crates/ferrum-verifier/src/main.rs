use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Parser, error::ErrorKind};
use sequoia_openpgp::parse::{
    Parse,
    stream::{DetachedVerifierBuilder, VerifierBuilder},
};
use sequoia_openpgp::types::SignatureType;
use sequoia_policy_config::ConfiguredStandardPolicy;

mod trust;

const MAX_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "ferrum-verifier",
    version,
    about = "Verify repository metadata using current trusted signing keys"
)]
struct Arguments {
    #[arg(long)]
    keyring: PathBuf,
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u8).range(1..=1))]
    signatures: u8,
    #[arg(long, conflicts_with = "signature_file", requires = "output")]
    cleartext: bool,
    #[arg(long, required_unless_present = "cleartext", conflicts_with = "output")]
    signature_file: Option<PathBuf>,
    #[arg(long, requires = "cleartext")]
    output: Option<PathBuf>,
    input: PathBuf,
}

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("input: expected a readable regular file of at most 32 MiB")]
    Input,
    #[error("keyring: malformed, secret, empty, or excessive trusted public-key material")]
    Keyring,
    #[error("policy: unable to load the system cryptographic policy")]
    Policy,
    #[error("mode: expected a cleartext signed message")]
    Mode,
    #[error("output: unable to create or write a new private output file")]
    Output,
    #[error("verification: malformed artifact or no currently valid trusted signature")]
    Verification,
}

fn main() -> ExitCode {
    // One reference time governs policy, certificate, key, and document validity.
    let now = SystemTime::now();
    let arguments = match Arguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error) => {
            match error.kind() {
                ErrorKind::DisplayVersion => {
                    println!("ferrum-verifier {}", env!("CARGO_PKG_VERSION"))
                }
                ErrorKind::DisplayHelp => print!("{}", error),
                _ => {
                    // Never echo hostile arguments, paths, packet text, or crypto errors.
                    eprintln!(
                        "ferrum-verifier: arguments: use --help for supported invocation forms"
                    );
                    return ExitCode::from(2);
                }
            }
            return ExitCode::SUCCESS;
        }
    };
    match verify(arguments, now) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ferrum-verifier: {error}");
            ExitCode::FAILURE
        }
    }
}

fn verify(arguments: Arguments, now: SystemTime) -> Result<(), Failure> {
    let mut configured = ConfiguredStandardPolicy::at(now);
    // Unlike parse_default_config, this never consults SEQUOIA_CRYPTO_POLICY.
    configured
        .parse_config_file(ConfiguredStandardPolicy::CONFIG_FILE)
        .map_err(|_| Failure::Policy)?;
    let policy = configured.build();
    let certs = trust::load(open_input(&arguments.keyring)?)?;
    let signature_type = if arguments.cleartext {
        SignatureType::Text
    } else {
        SignatureType::Binary
    };
    let helper = trust::Helper::new(certs, &policy, now, signature_type);
    let mut input = open_input(&arguments.input)?;

    if let Some(signature_path) = arguments.signature_file {
        let signature = open_input(&signature_path)?;
        let mut verifier = DetachedVerifierBuilder::from_reader(signature)
            .map_err(|_| Failure::Verification)?
            .with_policy(&policy, Some(now), helper)
            .map_err(|_| Failure::Verification)?;
        verifier
            .verify_reader(input)
            .map_err(|_| Failure::Verification)?;
        return Ok(());
    }

    // Reject opaque/inline/compressed OpenPGP messages, even when signed.  The
    // OpenPGP library, not this format discriminator, parses and authenticates
    // the cleartext framework, dash escaping, and canonical line endings.
    let mut prefix = [0; 35];
    input.read_exact(&mut prefix).map_err(|_| Failure::Mode)?;
    if &prefix[..34] != b"-----BEGIN PGP SIGNED MESSAGE-----"
        || !matches!(prefix[34], b'\n' | b'\r')
    {
        return Err(Failure::Mode);
    }
    if prefix[34] == b'\r' {
        let mut newline = [0];
        input.read_exact(&mut newline).map_err(|_| Failure::Mode)?;
        if newline != *b"\n" {
            return Err(Failure::Mode);
        }
    }
    input.inner.rewind().map_err(|_| Failure::Input)?;
    input.remaining = MAX_BYTES;
    let output_path = arguments.output.ok_or(Failure::Mode)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&output_path).map_err(|_| Failure::Output)?;
    // Bytes are provisional until verification finishes.  The caller only
    // trusts exit zero; remove partial output on every ordinary failure.
    let result = (|| {
        let mut verifier = VerifierBuilder::from_reader(input)
            .map_err(|_| Failure::Verification)?
            .with_policy(&policy, Some(now), helper)
            .map_err(|_| Failure::Verification)?;
        let mut buffer = [0; 16 * 1024];
        let mut written = 0u64;
        loop {
            let count = verifier
                .read(&mut buffer)
                .map_err(|_| Failure::Verification)?;
            if count == 0 {
                break;
            }
            written += count as u64;
            if written > MAX_BYTES {
                return Err(Failure::Output);
            }
            output
                .write_all(&buffer[..count])
                .map_err(|_| Failure::Output)?;
        }
        output.flush().map_err(|_| Failure::Output)
    })();
    drop(output);
    if result.is_err() {
        fs::remove_file(output_path).map_err(|_| Failure::Output)?;
    }
    result
}

fn open_input(path: &Path) -> Result<LimitedReader<File>, Failure> {
    // Check before open as well: opening a FIFO could otherwise block before
    // the post-open check. Follow normal operator-owned keyring symlinks (as
    // installed by Debian); private caller-owned artifact paths prevent mutation.
    let metadata = fs::metadata(path).map_err(|_| Failure::Input)?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err(Failure::Input);
    }
    let file = File::open(path).map_err(|_| Failure::Input)?;
    let metadata = file.metadata().map_err(|_| Failure::Input)?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err(Failure::Input);
    }
    Ok(LimitedReader {
        inner: file,
        remaining: MAX_BYTES,
    })
}

struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut overflow = [0];
            return match self.inner.read(&mut overflow)? {
                0 => Ok(0),
                _ => Err(io::Error::other("input exceeds 32 MiB")),
            };
        }
        let limit = buffer.len().min(self.remaining as usize);
        let count = self.inner.read(&mut buffer[..limit])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}
