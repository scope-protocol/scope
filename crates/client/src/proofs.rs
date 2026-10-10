//! Transfer proofs with the amount's Pedersen openings supplied by the caller, so the
//! payer can later prove a payment's amount by disclosing them (docs/audit.md).
//! Same builders, inputs and order as `transfer_split_proof_data` in
//! spl-token-confidential-transfer-proof-generation 0.6.1 (`src/transfer.rs` 79-253);
//! only where the two amount openings come from differs, and the verifier never sees it.

use crate::run_secret::AmountOpenings;
use solana_zk_sdk::{
    encryption::{
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
        grouped_elgamal::GroupedElGamal,
        pedersen::Pedersen,
    },
    zk_elgamal_proof_program::{
        build_batched_grouped_ciphertext_3_handles_validity_proof_data,
        build_batched_range_proof_u128_data, build_ciphertext_commitment_equality_proof_data,
    },
};
use spl_token_confidential_transfer_proof_generation::{
    CiphertextValidityProofWithAuditorCiphertext, REMAINING_BALANCE_BIT_LENGTH,
    TRANSFER_AMOUNT_HI_BITS, TRANSFER_AMOUNT_LO_BITS, transfer::TransferProofData,
    try_combine_lo_hi_ciphertexts, try_split_u64,
};

/// The range proof's bit lengths must sum to 128; a commitment to 0 pads 112 to 128.
const RANGE_PROOF_PADDING_BIT_LENGTH: usize = 16;

/// Proofs for moving `amount` out of a source whose available ciphertext is `current`
/// and whose verified balance is `balance`.
pub fn transfer_proofs(
    current: &ElGamalCiphertext,
    balance: u64,
    amount: u64,
    source: &ElGamalKeypair,
    destination: &ElGamalPubkey,
    auditor: Option<&ElGamalPubkey>,
    openings: &AmountOpenings,
) -> Result<TransferProofData, String> {
    let no_auditor = ElGamalPubkey::default();
    let auditor = auditor.unwrap_or(&no_auditor);
    // try_split_u64 does not bound the high part, so the 48-bit limit is checked here.
    if amount >> 48 != 0 {
        return Err("amount exceeds 48 bits".into());
    }
    let (lo, hi) =
        try_split_u64(amount, TRANSFER_AMOUNT_LO_BITS).ok_or("amount exceeds 48 bits")?;
    let keys = [source.pubkey(), destination, auditor];
    let grouped_lo = GroupedElGamal::<3>::encrypt_with(keys, lo, &openings.lo);
    let grouped_hi = GroupedElGamal::<3>::encrypt_with(keys, hi, &openings.hi);

    let remaining = balance.checked_sub(amount).ok_or("not enough funds")?;
    let (remaining_commitment, remaining_opening) = Pedersen::new(remaining);
    let source_part =
        |g: &solana_zk_sdk::encryption::grouped_elgamal::GroupedElGamalCiphertext<3>| {
            g.to_elgamal_ciphertext(0)
                .map_err(|e| format!("source ciphertext: {e}"))
        };
    let moved = try_combine_lo_hi_ciphertexts(
        &source_part(&grouped_lo)?,
        &source_part(&grouped_hi)?,
        TRANSFER_AMOUNT_LO_BITS,
    )
    .ok_or("amount ciphertexts do not combine")?;
    let new_available = current - moved;

    let equality = build_ciphertext_commitment_equality_proof_data(
        source,
        &new_available,
        &remaining_commitment,
        &remaining_opening,
        remaining,
    )
    .map_err(|e| format!("equality proof: {e}"))?;
    let validity = build_batched_grouped_ciphertext_3_handles_validity_proof_data(
        source.pubkey(),
        destination,
        auditor,
        &grouped_lo,
        &grouped_hi,
        lo,
        hi,
        &openings.lo,
        &openings.hi,
    )
    .map_err(|e| format!("validity proof: {e}"))?;
    let auditor_part = |hi: bool| {
        let grouped = if hi {
            &validity.context.grouped_ciphertext_hi
        } else {
            &validity.context.grouped_ciphertext_lo
        };
        grouped
            .try_extract_ciphertext(2)
            .map_err(|e| format!("auditor ciphertext: {e}"))
    };
    let (auditor_lo, auditor_hi) = (auditor_part(false)?, auditor_part(true)?);
    let (padding_commitment, padding_opening) = Pedersen::new(0_u64);
    let range = build_batched_range_proof_u128_data(
        vec![
            &remaining_commitment,
            &grouped_lo.commitment,
            &grouped_hi.commitment,
            &padding_commitment,
        ],
        vec![remaining, lo, hi, 0],
        vec![
            REMAINING_BALANCE_BIT_LENGTH,
            TRANSFER_AMOUNT_LO_BITS,
            TRANSFER_AMOUNT_HI_BITS,
            RANGE_PROOF_PADDING_BIT_LENGTH,
        ],
        vec![
            &remaining_opening,
            &openings.lo,
            &openings.hi,
            &padding_opening,
        ],
    )
    .map_err(|e| format!("range proof: {e}"))?;
    Ok(TransferProofData {
        equality_proof_data: equality,
        ciphertext_validity_proof_data_with_ciphertext:
            CiphertextValidityProofWithAuditorCiphertext {
                proof_data: validity,
                ciphertext_lo: auditor_lo,
                ciphertext_hi: auditor_hi,
            },
        range_proof_data: range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_zk_sdk::{
        encryption::pedersen::PedersenOpening, zk_elgamal_proof_program::VerifyZkProof,
    };

    #[test]
    fn proofs_verify_and_commit_to_the_amount_under_the_given_openings() {
        let source = ElGamalKeypair::new_rand();
        let destination = ElGamalKeypair::new_rand();
        let auditor = ElGamalKeypair::new_rand();
        let balance = 10_000_000_u64;
        let current = source.pubkey().encrypt(balance);
        let openings = AmountOpenings {
            lo: PedersenOpening::new_rand(),
            hi: PedersenOpening::new_rand(),
        };
        let amount = (77 << 16) + 4_321;
        let proofs = transfer_proofs(
            &current,
            balance,
            amount,
            &source,
            destination.pubkey(),
            Some(auditor.pubkey()),
            &openings,
        )
        .expect("proofs");
        let validity = &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .proof_data;
        proofs.equality_proof_data.verify_proof().expect("equality");
        validity.verify_proof().expect("validity");
        proofs.range_proof_data.verify_proof().expect("range");
        let commitment = |grouped: &[u8]| grouped[..32].to_vec();
        assert_eq!(
            commitment(&validity.context.grouped_ciphertext_lo.0),
            Pedersen::with(4_321_u64, &openings.lo).to_bytes()
        );
        assert_eq!(
            commitment(&validity.context.grouped_ciphertext_hi.0),
            Pedersen::with(77_u64, &openings.hi).to_bytes()
        );
        assert!(
            transfer_proofs(
                &current,
                balance,
                balance + 1,
                &source,
                destination.pubkey(),
                None,
                &openings
            )
            .is_err()
        );
    }

    fn proofs_for(amount: u64, openings: &AmountOpenings) -> Result<TransferProofData, String> {
        let source = ElGamalKeypair::new_rand();
        let destination = ElGamalKeypair::new_rand();
        let balance = 1u64 << 49;
        let current = source.pubkey().encrypt(balance);
        transfer_proofs(
            &current,
            balance,
            amount,
            &source,
            destination.pubkey(),
            None,
            openings,
        )
    }

    #[test]
    fn the_48_bit_limit_is_exact_and_every_split_boundary_verifies() {
        let secret = crate::run_secret::RunSecret::derive(
            &solana_keypair::Keypair::new(),
            "00ff00ff00ff00ff",
        )
        .expect("derive");
        let openings = secret.openings("00ff00ff00ff00ff", 0);
        for amount in [0, 1, 0xFFFF, 0x1_0000, 0x1_FFFF, (1u64 << 48) - 1] {
            let proofs = proofs_for(amount, &openings).unwrap_or_else(|e| panic!("{amount}: {e}"));
            proofs.range_proof_data.verify_proof().expect("range");
            proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .proof_data
                .verify_proof()
                .expect("validity");
        }
        for amount in [1u64 << 48, (1u64 << 48) + 1, 1 << 63, u64::MAX] {
            assert!(proofs_for(amount, &openings).is_err(), "{amount}");
        }
    }
}
