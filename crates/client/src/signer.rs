//! Solana signatures from a recovered stealth payment scalar.

use solana_address::Address;
use solana_signature::Signature;
use solana_signer::{Signer, SignerError};
use stealth_keygen::RecoveredPayment;

pub struct PaymentSigner<'a>(&'a RecoveredPayment);

impl<'a> PaymentSigner<'a> {
    pub fn new(payment: &'a RecoveredPayment) -> Self {
        Self(payment)
    }
}

impl Signer for PaymentSigner<'_> {
    fn try_pubkey(&self) -> Result<Address, SignerError> {
        Ok(Address::new_from_array(self.0.payment_public_key))
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        Ok(Signature::from(self.0.sign(message)))
    }

    fn is_interactive(&self) -> bool {
        false
    }
}
