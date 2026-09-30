use core::num::NonZeroI8;
use curve25519_dalek::scalar::Scalar;
use scope_client::{address::token_2022, ix::reclaim, testkit::*, tx::v1_transaction};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_zk_sdk::{
    encryption::{
        auth_encryption::AeKey,
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    zk_elgamal_proof_program::zero_ciphertext::build_zero_ciphertext_proof_data,
};
use spl_token_2022_interface::extension::{
    BaseStateWithExtensions, StateWithExtensions,
    confidential_transfer::{ConfidentialTransferAccount, instruction as ct},
};
use spl_token_2022_interface::state::Account;
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;

pub(crate) const AMOUNT: u64 = 250_000;

fn off(n: i8) -> NonZeroI8 {
    NonZeroI8::new(n).expect("nonzero")
}

/// Payer side: setup + Transfer from the source, one transaction.
pub(crate) fn payer_ixs(h: &Harness, case: &StealthCase) -> Vec<Instruction> {
    let t22 = token_2022();
    let source = h.svm.get_account(&h.source).expect("source");
    let state = StateWithExtensions::<Account>::unpack(&source.data).expect("unpack");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    let available: ElGamalCiphertext = ext.available_balance.try_into().expect("ct");
    let proofs = transfer_split_proof_data(
        &available,
        &ext.decryptable_available_balance.try_into().expect("ae"),
        AMOUNT,
        &h.source_elgamal,
        &h.source_ae,
        case.elgamal.pubkey(),
        None,
    )
    .expect("proofs");
    let new_decryptable = h.source_ae.encrypt(h.source_balance - AMOUNT);
    let mut ixs = case.setup.clone();
    ixs.extend(
        ct::transfer(
            &t22,
            &h.source,
            &h.mint,
            &case.token_account,
            &new_decryptable.into(),
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_lo,
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_hi,
            &h.payer.pubkey(),
            &[],
            ProofLocation::InstructionOffset(off(1), &proofs.equality_proof_data),
            ProofLocation::InstructionOffset(
                off(2),
                &proofs
                    .ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
            ),
            ProofLocation::InstructionOffset(off(3), &proofs.range_proof_data),
        )
        .expect("transfer"),
    );
    ixs
}

/// Sends the payer transaction and books the amount off the source.
pub(crate) fn pay(h: &mut Harness, case: &StealthCase) {
    let ixs = payer_ixs(h, case);
    let meta = h.send(&ixs, &[]).expect("payer transaction lands");
    println!("payer tx: {} CU", meta.compute_units_consumed);
    h.source_balance -= AMOUNT;
}

/// A plain confidential account the recipient sweeps into, owned by `owner`.
fn destination(h: &mut Harness, owner: &Keypair, keys: &ElGamalKeypair, ae: &AeKey) -> Address {
    // Same steps as the harness source account, owner = `owner`, max credits 65_536.
    h.plain_confidential_account(owner, keys, ae)
}

/// Recipient side: apply, transfer everything to `d`, empty, reclaim; the one-time
/// owner pays. Reads the one-time account, so the payer transaction must have landed.
pub(crate) fn recipient_ixs(
    h: &Harness,
    case: &StealthCase,
    d: &Address,
    d_elgamal: &ElGamalPubkey,
) -> Vec<Instruction> {
    // Reads the one-time account and precomputes every ciphertext.
    let t22 = token_2022();
    let acct = h
        .svm
        .get_account(&case.token_account)
        .expect("one-time account");
    let state = StateWithExtensions::<Account>::unpack(&acct.data).expect("unpack");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    let available: ElGamalCiphertext = ext.available_balance.try_into().expect("ct");
    let lo: ElGamalCiphertext = ext.pending_balance_lo.try_into().expect("lo");
    let hi: ElGamalCiphertext = ext.pending_balance_hi.try_into().expect("hi");
    let after_apply = available + lo + hi * Scalar::from(1u64 << 16);
    let applied_ae = case.ae.encrypt(AMOUNT);

    let proofs = transfer_split_proof_data(
        &after_apply,
        &applied_ae,
        AMOUNT,
        &case.elgamal,
        &case.ae,
        d_elgamal,
        None,
    )
    .expect("sweep proofs");
    let after_transfer: ElGamalCiphertext = proofs
        .equality_proof_data
        .context
        .ciphertext
        .try_into()
        .expect("new source ct");
    let zero =
        build_zero_ciphertext_proof_data(&case.elgamal, &after_transfer).expect("zero proof");

    let p = &case.one_time_owner;
    let mut ixs = vec![
        ct::apply_pending_balance(
            &t22,
            &case.token_account,
            1,
            &applied_ae.into(),
            &p.pubkey(),
            &[],
        )
        .expect("apply"),
    ];
    ixs.extend(
        ct::transfer(
            &t22,
            &case.token_account,
            &h.mint,
            d,
            &case.ae.encrypt(0).into(),
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_lo,
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_hi,
            &p.pubkey(),
            &[],
            ProofLocation::InstructionOffset(off(1), &proofs.equality_proof_data),
            ProofLocation::InstructionOffset(
                off(2),
                &proofs
                    .ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
            ),
            ProofLocation::InstructionOffset(off(3), &proofs.range_proof_data),
        )
        .expect("transfer out"),
    );
    ixs.extend(
        ct::empty_account(
            &t22,
            &case.token_account,
            &p.pubkey(),
            &[],
            ProofLocation::InstructionOffset(off(1), &zero),
        )
        .expect("empty"),
    );
    ixs.push(reclaim(
        &case.announcement,
        &case.token_account,
        &h.payer.pubkey(),
    ));
    ixs
}

#[test]
fn s3_payment_then_sweep_in_one_recipient_transaction() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    pay(&mut h, &case);

    let d_owner = Keypair::new();
    let (d_keys, d_ae) = (ElGamalKeypair::new_rand(), AeKey::new_rand());
    let d = destination(&mut h, &d_owner, &d_keys, &d_ae);

    let ixs = recipient_ixs(&h, &case, &d, d_keys.pubkey());
    let lamports = |h: &Harness, a: &Address| h.svm.get_account(a).map_or(0, |a| a.lamports);
    let payer_before = lamports(&h, &h.payer.pubkey());
    let (account_rent, announcement_rent) = (
        lamports(&h, &case.token_account),
        lamports(&h, &case.announcement),
    );
    assert!(
        account_rent > 0 && announcement_rent > 0,
        "both accounts hold rent"
    );
    let rent = account_rent + announcement_rent;
    let tx = v1_transaction(&case.one_time_owner, &[], &ixs, h.svm.latest_blockhash());
    let meta = h
        .svm
        .send_transaction(tx)
        .unwrap_or_else(|e| panic!("sweep failed: {:?}\n{:#?}", e.err, e.meta.logs));
    println!("recipient tx: {} CU", meta.compute_units_consumed);

    assert!(
        h.svm
            .get_account(&case.token_account)
            .is_none_or(|a| a.lamports == 0),
        "one-time account closed"
    );
    assert!(
        h.svm
            .get_account(&case.announcement)
            .is_none_or(|a| a.lamports == 0),
        "announcement closed"
    );
    let d_state = h.svm.get_account(&d).expect("d");
    let d_ext = StateWithExtensions::<Account>::unpack(&d_state.data).expect("unpack");
    assert_eq!(
        d_ext
            .get_extension::<ConfidentialTransferAccount>()
            .expect("ct")
            .pending_balance_credit_counter,
        1u64.into()
    );

    assert_eq!(
        lamports(&h, &h.payer.pubkey()),
        payer_before + rent,
        "payer gets back exactly the rent of both accounts"
    );
    let d_ct = d_ext
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    let d_lo: ElGamalCiphertext = d_ct.pending_balance_lo.try_into().expect("lo");
    let d_hi: ElGamalCiphertext = d_ct.pending_balance_hi.try_into().expect("hi");
    let d_lo = d_keys.secret().decrypt_u32(&d_lo).expect("decrypt lo");
    let d_hi = d_keys.secret().decrypt_u32(&d_hi).expect("decrypt hi");
    assert_eq!(d_lo + (d_hi << 16), AMOUNT, "D holds the swept amount");
}
