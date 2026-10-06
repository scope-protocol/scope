//! Convert account-scoped stealth material into Token-2022 encryption keys.

use solana_address::Address;
use solana_zk_sdk::{
    encryption::{
        auth_encryption::AeKey, derivation::derive_confidential_keys_from_ikm,
        elgamal::ElGamalKeypair,
    },
    errors::ElGamalError,
};
use stealth_keygen::{ConfidentialContext, ConfidentialKeyMaterial};

/// The protocol context shared by the payer and recipient on this cluster.
pub fn context(chain_id: [u8; 32], mint: &Address, token_account: &Address) -> ConfidentialContext {
    ConfidentialContext {
        chain_id,
        program_id: scope_interface::ID,
        mint: mint.to_bytes(),
        token_account: token_account.to_bytes(),
    }
}

/// Derive the account's ElGamal keypair and symmetric balance key with the SDK.
/// A receipt verifier must check the derived public key against the referenced
/// transaction. A decrypted balance hint must be checked against ElGamal state.
pub fn derive_confidential_keys(
    material: &ConfidentialKeyMaterial,
) -> Result<(ElGamalKeypair, AeKey), ElGamalError> {
    derive_confidential_keys_from_ikm(material.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector<const N: usize>(key: &str) -> [u8; N] {
        let value = include_str!("../../stealth-keygen/tests/fixtures/hkdf.txt")
            .lines()
            .filter_map(|line| line.split_once('='))
            .find(|(name, _)| *name == key)
            .expect("fixture field")
            .1;
        assert_eq!(value.len(), N * 2);
        std::array::from_fn(|i| {
            u8::from_str_radix(&value[2 * i..2 * i + 2], 16).expect("hex fixture")
        })
    }

    #[test]
    fn sdk_keys_match_independent_hkdf_sha512_vectors() {
        let material = ConfidentialKeyMaterial::from_bytes(vector("ct_ikm"));
        let (elgamal, ae) = derive_confidential_keys(&material).expect("SDK derivation");
        assert_eq!(elgamal.secret().as_bytes(), &vector::<32>("elgamal_scalar"));
        assert_eq!(ae, AeKey::from(vector::<16>("balance_key")));
        let (again, again_ae) = derive_confidential_keys(&material).expect("SDK derivation");
        assert_eq!(elgamal, again);
        assert_eq!(ae, again_ae);
    }
}
