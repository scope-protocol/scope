//! Versioned, checksummed encoding of the recipient's public keys.

use std::fmt;

use crate::{KeyError, RecipientPublicKeys};

const PREFIX: &str = "scope:";
const VERSION: u8 = 1;
const PAYLOAD_LEN: usize = 65;
const CHECKSUM_LEN: usize = 4;
// A 69-byte Base58Check value needs at most 95 characters.
const MAX_ENCODED_LEN: usize = 95;

/// A malformed, unsupported, or invalid recipient meta-address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaAddressError {
    InvalidEncoding,
    InvalidChecksum,
    UnsupportedVersion(u8),
    InvalidKeys(KeyError),
}

impl fmt::Display for MetaAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => {
                f.write_str("invalid meta-address prefix, encoding, or length")
            }
            Self::InvalidChecksum => f.write_str("invalid meta-address checksum"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported meta-address version {version}")
            }
            Self::InvalidKeys(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for MetaAddressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidKeys(error) => Some(error),
            _ => None,
        }
    }
}

impl RecipientPublicKeys {
    /// Encode as scope:Base58Check(version || spend || scan), version 1.
    pub fn to_meta_address(&self) -> String {
        let mut keys = [0; 64];
        keys[..32].copy_from_slice(&self.spend_public_key_bytes());
        keys[32..].copy_from_slice(&self.scan_public_key_bytes());
        format!(
            "{PREFIX}{}",
            bs58::encode(keys).with_check_version(VERSION).into_string()
        )
    }

    /// Decode a version-1 meta-address and validate both recipient public keys.
    pub fn from_meta_address(address: &str) -> Result<Self, MetaAddressError> {
        let encoded = address
            .strip_prefix(PREFIX)
            .ok_or(MetaAddressError::InvalidEncoding)?;
        if encoded.len() > MAX_ENCODED_LEN {
            return Err(MetaAddressError::InvalidEncoding);
        }
        let mut bytes = [0; PAYLOAD_LEN + CHECKSUM_LEN];
        let length = bs58::decode(encoded)
            .with_check(None)
            .onto(&mut bytes[..])
            .map_err(|error| match error {
                bs58::decode::Error::InvalidChecksum { .. } => MetaAddressError::InvalidChecksum,
                _ => MetaAddressError::InvalidEncoding,
            })?;
        if length != PAYLOAD_LEN {
            return Err(MetaAddressError::InvalidEncoding);
        }
        if bytes[0] != VERSION {
            return Err(MetaAddressError::UnsupportedVersion(bytes[0]));
        }
        let mut spend = [0; 32];
        let mut scan = [0; 32];
        spend.copy_from_slice(&bytes[1..33]);
        scan.copy_from_slice(&bytes[33..65]);
        Self::from_bytes(spend, scan).map_err(MetaAddressError::InvalidKeys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::vector;
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};

    fn public() -> RecipientPublicKeys {
        RecipientPublicKeys::from_bytes(vector("spend_public"), vector("scan_public")).unwrap()
    }

    fn encode(version: u8, keys: &[u8]) -> String {
        format!(
            "{PREFIX}{}",
            bs58::encode(keys).with_check_version(version).into_string()
        )
    }

    #[test]
    fn meta_address_matches_independent_vector() {
        let expected = include_str!("../tests/fixtures/meta_address.txt").trim();
        assert_eq!(public().to_meta_address(), expected);
        assert_eq!(
            RecipientPublicKeys::from_meta_address(expected).unwrap(),
            public()
        );
    }

    #[test]
    fn meta_address_rejects_malformed_input_and_bad_checksum() {
        let valid = public().to_meta_address();
        for malformed in [
            String::new(),
            PREFIX.to_owned(),
            valid[PREFIX.len()..].to_owned(),
            valid.replacen("scope:", "SCOPE:", 1),
            format!(" {valid}"),
            format!("{valid} "),
            format!("{PREFIX}{}", "1".repeat(10_000)),
            format!("{PREFIX}0"),
            format!("{PREFIX}é"),
            valid[..valid.len() - 1].to_owned(),
        ] {
            assert!(RecipientPublicKeys::from_meta_address(&malformed).is_err());
        }
        let mut corrupted = valid.into_bytes();
        let last = corrupted.last_mut().unwrap();
        *last = if *last == b'1' { b'2' } else { b'1' };
        assert_eq!(
            RecipientPublicKeys::from_meta_address(&String::from_utf8(corrupted).unwrap()),
            Err(MetaAddressError::InvalidChecksum)
        );
    }

    #[test]
    fn meta_address_rejects_unknown_versions_and_wrong_payload_lengths() {
        let keys = [vector::<32>("spend_public"), vector("scan_public")].concat();
        assert_eq!(
            RecipientPublicKeys::from_meta_address(&encode(2, &keys)),
            Err(MetaAddressError::UnsupportedVersion(2))
        );
        for length in [0, 32, 63, 65] {
            assert_eq!(
                RecipientPublicKeys::from_meta_address(&encode(VERSION, &vec![1; length])),
                Err(MetaAddressError::InvalidEncoding)
            );
        }
    }

    #[test]
    fn meta_address_checksum_does_not_bypass_key_validation() {
        let scan = vector::<32>("scan_public");
        for spend in [
            [0xff; 32],
            EIGHT_TORSION[0].compress().to_bytes(),
            EIGHT_TORSION[1].compress().to_bytes(),
            (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
                .compress()
                .to_bytes(),
        ] {
            assert_eq!(
                RecipientPublicKeys::from_meta_address(&encode(VERSION, &[spend, scan].concat())),
                Err(MetaAddressError::InvalidKeys(
                    KeyError::InvalidSpendPublicKey
                ))
            );
        }
        let spend = vector::<32>("spend_public");
        assert_eq!(
            RecipientPublicKeys::from_meta_address(&encode(VERSION, &[spend, [0; 32]].concat())),
            Err(MetaAddressError::InvalidKeys(
                KeyError::InvalidScanPublicKey
            ))
        );
    }
}
