//! Recipient-only derivation of the per-payment sweep owner.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::{DeriveError, RecipientSecretKeys};

const DESTINATION_SALT: &[u8] = b"stealth-dest/v1";
const DESTINATION_INFO: &[u8] = b"d-owner";

/// Standard Ed25519 seed for D_owner, ready for the client's keypair constructor.
/// Cleared on drop; intentionally does not implement Debug, Clone, or Copy.
pub struct SweepDestinationSeed(Zeroizing<[u8; 32]>);

impl SweepDestinationSeed {
    /// Borrow secret seed bytes. Any copies must be protected separately.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl RecipientSecretKeys {
    /// Derive D_owner's seed from the canonical spend scalar, B_spend, the exact R bytes
    /// and the payment's token account T. Binding T keeps two announcements that reuse
    /// one R (a payer who knows r can make a second) on different destinations.
    /// Repeating the same inputs reconstructs the same sweep owner after a crash.
    /// Derive only for a payment whose receiving authority has been verified.
    pub fn derive_sweep_destination(
        &self,
        ephemeral_public_key: &[u8; 32],
        token_account: &[u8; 32],
    ) -> Result<SweepDestinationSeed, DeriveError> {
        let spend_public_key = self.derive_public_keys().spend_public_key_bytes();
        let (mut prk, hkdf) =
            Hkdf::<Sha512>::extract(Some(DESTINATION_SALT), self.spend_private_key().as_bytes());
        prk[..].zeroize();
        let mut seed = Zeroizing::new([0; 32]);
        hkdf.expand_multi_info(
            &[
                DESTINATION_INFO,
                &spend_public_key,
                ephemeral_public_key,
                token_account,
            ],
            &mut seed[..],
        )
        .map_err(|_| DeriveError::InvalidKdfOutputLength)?;
        Ok(SweepDestinationSeed(seed))
    }
}
