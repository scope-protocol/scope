//! The payer's per-run secret (docs/crypto.md, Run secret and amount openings). It is derived from the
//! payer's Ed25519 signature over a fixed message, and Ed25519 signing is
//! deterministic, so the payer keypair alone rebuilds every stealth row's R and every
//! row's amount openings. Nothing secret is stored.

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha256;
use solana_signer::{Signer, SignerError};
use solana_zk_sdk::encryption::pedersen::PedersenOpening;
use stealth_keygen::EphemeralSecret;
use zeroize::Zeroizing;

const SECRET_LABEL: &[u8] = b"scope-run-secret/v1";
const EPHEMERAL_LABEL: &[u8] = b"scope-ephemeral/v1";
const OPENING_LABEL: &[u8] = b"scope-opening/v1";

pub struct RunSecret(Zeroizing<[u8; 32]>);

/// Pedersen openings for the low 16 and high 32 bits of one row's transfer amount.
pub struct AmountOpenings {
    pub lo: PedersenOpening,
    pub hi: PedersenOpening,
}

impl RunSecret {
    /// `HKDF-SHA256(salt = label, ikm = payer's signature over label || run_id, info = run_id)`.
    pub fn derive(payer: &dyn Signer, run_id: &str) -> Result<Self, SignerError> {
        let message = [SECRET_LABEL, run_id.as_bytes()].concat();
        let signature = payer.try_sign_message(&message)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(SECRET_LABEL), signature.as_ref())
            .expand(run_id.as_bytes(), secret.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        Ok(Self(secret))
    }

    fn expand<const N: usize>(
        &self,
        label: &[u8],
        run_id: &str,
        row: usize,
        part: &[u8],
    ) -> Zeroizing<[u8; N]> {
        let info = [label, run_id.as_bytes(), &(row as u64).to_le_bytes(), part].concat();
        let mut out = Zeroizing::new([0u8; N]);
        Hkdf::<Sha256>::new(Some(label), self.0.as_ref())
            .expand(&info, out.as_mut())
            .expect("32 and 64 bytes are valid HKDF-SHA256 lengths");
        out
    }

    /// r_i for stealth row `row`, an X25519 secret.
    pub fn ephemeral(&self, run_id: &str, row: usize) -> EphemeralSecret {
        EphemeralSecret::from_bytes(*self.expand::<32>(EPHEMERAL_LABEL, run_id, row, b""))
    }

    /// The openings of row `row`'s amount ciphertexts. Every attempt for a row moves the
    /// same amount, so reusing them across attempts reveals nothing new.
    pub fn openings(&self, run_id: &str, row: usize) -> AmountOpenings {
        let scalar = |part: &[u8]| {
            Scalar::from_bytes_mod_order_wide(&self.expand::<64>(OPENING_LABEL, run_id, row, part))
        };
        AmountOpenings {
            lo: PedersenOpening::new(scalar(b"lo")),
            hi: PedersenOpening::new(scalar(b"hi")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_keypair::Keypair;

    fn r(secret: &RunSecret, row: usize) -> [u8; 32] {
        *secret.expand::<32>(EPHEMERAL_LABEL, "run", row, b"")
    }

    #[test]
    fn the_payer_key_alone_rebuilds_the_same_material() {
        let payer = Keypair::new();
        let a = RunSecret::derive(&payer, "run").expect("derive");
        let b = RunSecret::derive(&payer, "run").expect("derive");
        assert_eq!(*a.0, *b.0);
        assert_eq!(r(&a, 3), r(&b, 3));
        assert_eq!(
            a.openings("run", 3).lo.as_bytes(),
            b.openings("run", 3).lo.as_bytes()
        );
    }

    #[test]
    fn runs_rows_and_parts_are_separated() {
        let payer = Keypair::new();
        let secret = RunSecret::derive(&payer, "run").expect("derive");
        let other_run = RunSecret::derive(&payer, "run2").expect("derive");
        let other_payer = RunSecret::derive(&Keypair::new(), "run").expect("derive");
        assert_ne!(*secret.0, *other_run.0);
        assert_ne!(*secret.0, *other_payer.0);
        assert_ne!(r(&secret, 0), r(&secret, 1));
        let openings = secret.openings("run", 0);
        assert_ne!(openings.lo.as_bytes(), openings.hi.as_bytes());
        assert_ne!(
            openings.lo.as_bytes(),
            secret.openings("run", 1).lo.as_bytes()
        );
    }
}
