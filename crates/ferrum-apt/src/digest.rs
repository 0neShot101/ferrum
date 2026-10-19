//! SHA-2 digests and incremental hashers used across the trust chain.
//!
//! Internal object identity is always `(SHA-256, size)`; SHA-512 only appears in
//! authenticated Release tables and by-hash aliases.

use std::fmt;
use std::str::FromStr;

use sha2::Digest as _;
use thiserror::Error;

/// Failure to interpret a hexadecimal digest string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DigestError {
    /// The hex string encodes the wrong number of bytes.
    #[error("digest has {actual} hex characters, expected {expected}")]
    InvalidLength { expected: usize, actual: usize },
    /// The string contains characters outside `[0-9a-fA-F]`.
    #[error("digest contains non-hexadecimal characters")]
    InvalidHex,
}

macro_rules! digest_type {
    ($(#[$meta:meta])* $name:ident, $hasher:ident, $algorithm:ty, $bytes:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $bytes]);

        impl $name {
            /// Number of raw digest bytes.
            pub const LEN: usize = $bytes;

            /// Parses a lowercase or uppercase hex string of exactly `2 * LEN` characters.
            ///
            /// # Errors
            /// [`DigestError::InvalidLength`] when the character count is wrong,
            /// [`DigestError::InvalidHex`] when a character is not hexadecimal.
            pub fn from_hex(text: &str) -> Result<Self, DigestError> {
                if text.len() != Self::LEN * 2 {
                    return Err(DigestError::InvalidLength {
                        expected: Self::LEN * 2,
                        actual: text.len(),
                    });
                }
                let mut bytes = [0u8; $bytes];
                hex::decode_to_slice(text, &mut bytes).map_err(|_| DigestError::InvalidHex)?;
                Ok(Self(bytes))
            }

            /// Lowercase hexadecimal representation.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Raw digest bytes.
            pub fn as_bytes(&self) -> &[u8; $bytes] {
                &self.0
            }

            /// Digest of a complete in-memory buffer.
            pub fn of(data: &[u8]) -> Self {
                Self(<$algorithm>::digest(data).into())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({self})", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = DigestError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::from_hex(text)
            }
        }

        #[doc = concat!("Incremental hasher producing a [`", stringify!($name), "`].")]
        #[derive(Clone, Default)]
        pub struct $hasher($algorithm);

        impl $hasher {
            /// Fresh hasher state.
            pub fn new() -> Self {
                Self(<$algorithm>::new())
            }

            /// Feeds one chunk.
            pub fn update(&mut self, chunk: &[u8]) {
                self.0.update(chunk);
            }

            /// Consumes the state and returns the digest.
            pub fn finalize(self) -> $name {
                $name(self.0.finalize().into())
            }
        }

        impl fmt::Debug for $hasher {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(stringify!($hasher))
            }
        }
    };
}

digest_type!(
    /// A SHA-256 digest.
    Sha256Digest,
    Sha256Hasher,
    sha2::Sha256,
    32
);

digest_type!(
    /// A SHA-512 digest.
    Sha512Digest,
    Sha512Hasher,
    sha2::Sha512,
    64
);

/// Identity of a verified object: its SHA-256 and exact byte length.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ObjectIdentity {
    pub sha256: Sha256Digest,
    pub size: u64,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_hex_round_trip() {
        let digest = Sha256Digest::from_hex(EMPTY_SHA256).expect("valid hex");
        assert_eq!(digest.to_hex(), EMPTY_SHA256);
        assert_eq!(digest.to_string(), EMPTY_SHA256);
        assert_eq!(digest, Sha256Digest::of(b""));
        assert_eq!(
            EMPTY_SHA256.parse::<Sha256Digest>().expect("FromStr"),
            digest
        );
        let upper = EMPTY_SHA256.to_ascii_uppercase();
        assert_eq!(
            Sha256Digest::from_hex(&upper).expect("uppercase hex"),
            digest
        );
    }

    #[test]
    fn sha256_rejects_bad_length_and_bad_characters() {
        assert_eq!(
            Sha256Digest::from_hex(&EMPTY_SHA256[..63]),
            Err(DigestError::InvalidLength {
                expected: 64,
                actual: 63
            })
        );
        let too_long = format!("{EMPTY_SHA256}00");
        assert_eq!(
            Sha256Digest::from_hex(&too_long),
            Err(DigestError::InvalidLength {
                expected: 64,
                actual: 66
            })
        );
        let bad = format!("g{}", &EMPTY_SHA256[1..]);
        assert_eq!(Sha256Digest::from_hex(&bad), Err(DigestError::InvalidHex));
        assert_eq!(
            Sha256Digest::from_hex(""),
            Err(DigestError::InvalidLength {
                expected: 64,
                actual: 0
            })
        );
    }

    #[test]
    fn sha512_hex_round_trip_and_length() {
        let digest = Sha512Digest::of(b"ferrum");
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 128);
        assert_eq!(Sha512Digest::from_hex(&hex).expect("valid hex"), digest);
        assert_eq!(
            Sha512Digest::from_hex(EMPTY_SHA256),
            Err(DigestError::InvalidLength {
                expected: 128,
                actual: 64
            })
        );
    }

    #[test]
    fn incremental_hasher_matches_one_shot() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"fer");
        hasher.update(b"rum");
        assert_eq!(hasher.finalize(), Sha256Digest::of(b"ferrum"));
        let mut hasher = Sha512Hasher::new();
        hasher.update(b"fer");
        hasher.update(b"rum");
        assert_eq!(hasher.finalize(), Sha512Digest::of(b"ferrum"));
    }
}
