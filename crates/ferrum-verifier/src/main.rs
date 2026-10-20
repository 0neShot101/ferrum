use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Parser, error::ErrorKind};
use sequoia_openpgp::parse::{
    Parse,
    stream::{DetachedVerifierBuilder, VerifierBuilder},
};
use sequoia_openpgp::types::SignatureType;
use sequoia_policy_config::ConfiguredStandardPolicy;

mod input;
mod trust;

use input::{METADATA_CAP, PACKAGE_CAP};

#[derive(Parser)]
#[command(
    name = "ferrum-verifier",
    version,
    about = "Verify repository metadata and packages using current trusted signing keys"
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
    #[arg(long, requires_all = ["signature_file", "expected_size"], conflicts_with = "cleartext")]
    package: bool,
    #[arg(long, requires = "package", value_parser = clap::value_parser!(u64).range(..=PACKAGE_CAP))]
    expected_size: Option<u64>,
    input: PathBuf,
}

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("input: expected a readable regular file of at most 32 MiB")]
    Input,
    #[error(
        "package input: expected a readable regular file matching --expected-size within 8 GiB"
    )]
    PackageInput,
    #[error("input changed during verification")]
    InputChanged,
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
    let mut keyring = input::open_metadata(&arguments.keyring)?;
    let certs = trust::load(&mut keyring)?;
    keyring.verify_unchanged()?;
    let signature_type = if arguments.cleartext {
        SignatureType::Text
    } else {
        SignatureType::Binary
    };
    let helper = trust::Helper::new(certs, &policy, now, signature_type);
    let mut input = if arguments.package {
        input::open_package(
            &arguments.input,
            arguments.expected_size.ok_or(Failure::Mode)?,
        )?
    } else {
        input::open_metadata(&arguments.input)?
    };

    if let Some(signature_path) = arguments.signature_file {
        let mut signature = input::open_metadata(&signature_path)?;
        let mut verifier = DetachedVerifierBuilder::from_reader(&mut signature)
            .map_err(|_| Failure::Verification)?
            .with_policy(&policy, Some(now), helper)
            .map_err(|_| Failure::Verification)?;
        verifier
            .verify_reader(&mut input)
            .map_err(|_| Failure::Verification)?;
        drop(verifier);
        input.finish()?;
        signature.verify_unchanged()?;
        keyring.verify_unchanged()?;
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
    input.rewind()?;
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
        let mut verifier = VerifierBuilder::from_reader(&mut input)
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
            written = written
                .checked_add(u64::try_from(count).map_err(|_| Failure::Output)?)
                .ok_or(Failure::Output)?;
            if written > METADATA_CAP {
                return Err(Failure::Output);
            }
            output
                .write_all(&buffer[..count])
                .map_err(|_| Failure::Output)?;
        }
        drop(verifier);
        input.finish()?;
        keyring.verify_unchanged()?;
        output.flush().map_err(|_| Failure::Output)
    })();
    drop(output);
    if result.is_err() {
        fs::remove_file(output_path).map_err(|_| Failure::Output)?;
    }
    result
}
