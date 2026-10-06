//! Token-2022 behaviour the design relies on, tried against a real announced account:
//! after the handover only P can move funds, public credits are refused, the credit
//! cap admits one credit, and the mint is enforced.

use crate::s3_sweep::{AMOUNT, pay, recipient_ixs};
use litesvm::types::TransactionResult;
use scope_client::{address::token_2022, testkit::*};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
};
use spl_token_2022_interface::{
    error::TokenError,
    extension::{
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        confidential_transfer::{ConfidentialTransferAccount, instruction as ct},
    },
    instruction as t22,
    state::{Account, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;

/// The harness mint's decimals; mints made here use the same.
const DECIMALS: u8 = 6;

fn assert_token_error(result: TransactionResult, index: u8, expected: TokenError) {
    match result {
        Err(failed) => assert_eq!(
            failed.err,
            TransactionError::InstructionError(index, InstructionError::Custom(expected as u32)),
            "logs: {:#?}",
            failed.meta.logs
        ),
        Ok(_) => panic!("expected {expected:?}, transaction succeeded"),
    }
}

/// A confidential Transfer of `AMOUNT` from a payer-owned source, with its three proofs.
#[allow(clippy::too_many_arguments)]
fn transfer_ixs(
    h: &Harness,
    source: &Address,
    keys: &ElGamalKeypair,
    ae: &AeKey,
    balance: u64,
    mint: &Address,
    to: &Address,
    to_key: &ElGamalPubkey,
) -> Vec<Instruction> {
    let account = h.svm.get_account(source).expect("source");
    let state = StateWithExtensions::<Account>::unpack(&account.data).expect("unpack");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    let available: ElGamalCiphertext = ext.available_balance.try_into().expect("ct");
    let proofs = transfer_split_proof_data(
        &available,
        &ext.decryptable_available_balance.try_into().expect("ae"),
        AMOUNT,
        keys,
        ae,
        to_key,
        None,
    )
    .expect("proofs");
    let validity = &proofs.ciphertext_validity_proof_data_with_ciphertext;
    let offset = |n| core::num::NonZeroI8::new(n).expect("nonzero");
    ct::transfer(
        &token_2022(),
        source,
        mint,
        to,
        &ae.encrypt(balance - AMOUNT).into(),
        &validity.ciphertext_lo,
        &validity.ciphertext_hi,
        &h.payer.pubkey(),
        &[],
        ProofLocation::InstructionOffset(offset(1), &proofs.equality_proof_data),
        ProofLocation::InstructionOffset(offset(2), &validity.proof_data),
        ProofLocation::InstructionOffset(offset(3), &proofs.range_proof_data),
    )
    .expect("transfer")
}

/// A second mint with the confidential extension, authorities held by the harness.
fn confidential_mint(h: &mut Harness, auto_approve: bool) -> Address {
    let mint = Keypair::new();
    let t22 = token_2022();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])
    .expect("len");
    let authority = h.mint_authority.pubkey();
    let ixs = [
        solana_system_interface::instruction::create_account(
            &h.payer.pubkey(),
            &mint.pubkey(),
            h.svm.minimum_balance_for_rent_exemption(space),
            space as u64,
            &t22,
        ),
        ct::initialize_mint(&t22, &mint.pubkey(), Some(authority), auto_approve, None)
            .expect("ct mint"),
        t22::initialize_mint2(&t22, &mint.pubkey(), &authority, None, DECIMALS).expect("mint"),
    ];
    h.send(&ixs, &[&mint]).expect("create mint");
    mint.pubkey()
}

/// Announces a stealth account on `mint` instead of the harness mint.
fn announced_on(h: &mut Harness, mint: Address) -> StealthCase {
    let harness_mint = std::mem::replace(&mut h.mint, mint);
    let case = h.stealth_case();
    h.mint = harness_mint;
    h.send(&case.setup, &[]).expect("setup and announce");
    case
}

/// Replaces P with the payer, the account's owner before the handover.
fn signed_by_payer(h: &Harness, case: &StealthCase, ix: &Instruction) -> Instruction {
    let mut ix = ix.clone();
    for meta in &mut ix.accounts {
        if meta.pubkey == case.one_time_owner.pubkey() {
            meta.pubkey = h.payer.pubkey();
        }
    }
    ix
}

#[test]
fn only_p_can_apply_transfer_or_empty_after_the_handover() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    pay(&mut h, &case);
    let d_keys = ElGamalKeypair::new_rand();
    let d = h.plain_confidential_account(&Keypair::new(), &d_keys, &AeKey::new_rand());
    // [apply, transfer + 3 proofs, empty + zero proof, reclaim]
    let ixs = recipient_ixs(&h, &case, &d, d_keys.pubkey());
    for (name, op) in [("apply", 0..1), ("transfer", 1..5), ("empty", 5..7)] {
        let target = op.start;
        let mut tx = ixs[..target].to_vec();
        tx.push(signed_by_payer(&h, &case, &ixs[target]));
        tx.extend_from_slice(&ixs[target + 1..op.end]);
        let p = case.one_time_owner.insecure_clone();
        let extra: &[&Keypair] = if target == 0 { &[] } else { &[&p] };
        println!("{name} signed by the payer");
        assert_token_error(h.send(&tx, extra), target as u8, TokenError::OwnerMismatch);
    }
}

#[test]
fn public_credits_are_refused_but_mint_to_lands() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    pay(&mut h, &case);
    let t22 = token_2022();
    let public = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Account>(&[]).expect("len");
    let create = [
        solana_system_interface::instruction::create_account(
            &h.payer.pubkey(),
            &public.pubkey(),
            h.svm.minimum_balance_for_rent_exemption(space),
            space as u64,
            &t22,
        ),
        t22::initialize_account3(&t22, &public.pubkey(), &h.mint, &h.payer.pubkey()).expect("init"),
    ];
    h.send(&create, &[&public]).expect("public account");
    let authority = h.mint_authority.insecure_clone();
    let fund = t22::mint_to(
        &t22,
        &h.mint,
        &public.pubkey(),
        &authority.pubkey(),
        &[],
        10,
    )
    .expect("mint_to");
    h.send(&[fund], &[&authority]).expect("fund public account");

    let credit = t22::transfer_checked(
        &t22,
        &public.pubkey(),
        &h.mint,
        &case.token_account,
        &h.payer.pubkey(),
        &[],
        1,
        DECIMALS,
    )
    .expect("transfer_checked");
    assert_token_error(
        h.send(&[credit], &[]),
        0,
        TokenError::NonConfidentialTransfersDisabled,
    );

    // The flag binds Transfer only (V6): a mint authority can still mint public dust in,
    // which is why the sweep burns it.
    let dust = t22::mint_to(
        &t22,
        &h.mint,
        &case.token_account,
        &authority.pubkey(),
        &[],
        1,
    )
    .expect("mint_to");
    h.send(&[dust], &[&authority])
        .expect("MintTo ignores the flag");
    let account = h.svm.get_account(&case.token_account).expect("account");
    let state = StateWithExtensions::<Account>::unpack(&account.data).expect("unpack");
    assert_eq!(state.base.amount, 1);
}

#[test]
fn the_credit_cap_admits_only_the_payers_credit() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    pay(&mut h, &case);
    let ixs = transfer_ixs(
        &h,
        &h.source,
        &h.source_elgamal,
        &h.source_ae,
        h.source_balance,
        &h.mint,
        &case.token_account,
        case.elgamal.pubkey(),
    );
    assert_token_error(
        h.send(&ixs, &[]),
        0,
        TokenError::MaximumPendingBalanceCreditCounterExceeded,
    );
}

#[test]
fn a_credit_in_another_mint_is_refused() {
    let mut h = Harness::new();
    let other = confidential_mint(&mut h, true);
    let case = announced_on(&mut h, other);
    let ixs = transfer_ixs(
        &h,
        &h.source,
        &h.source_elgamal,
        &h.source_ae,
        h.source_balance,
        &h.mint,
        &case.token_account,
        case.elgamal.pubkey(),
    );
    assert_token_error(h.send(&ixs, &[]), 0, TokenError::MintMismatch);
}

#[test]
fn a_mint_without_auto_approve_leaves_the_account_unpayable() {
    let mut h = Harness::new();
    let t22 = token_2022();
    let mint = confidential_mint(&mut h, false);
    let authority = h.mint_authority.insecure_clone();

    // A funded source on that mint, approved by the mint's confidential authority.
    let (keys, ae) = (ElGamalKeypair::new_rand(), AeKey::new_rand());
    let payer = h.payer.insecure_clone();
    let harness_mint = std::mem::replace(&mut h.mint, mint);
    let source = h.plain_confidential_account(&payer, &keys, &ae);
    h.mint = harness_mint;
    let approve =
        ct::approve_account(&t22, &source, &mint, &authority.pubkey(), &[]).expect("approve");
    let fund =
        t22::mint_to(&t22, &mint, &source, &authority.pubkey(), &[], AMOUNT).expect("mint_to");
    h.send(&[approve, fund], &[&authority])
        .expect("approve and fund");
    let deposit =
        ct::deposit(&t22, &source, &mint, AMOUNT, DECIMALS, &payer.pubkey(), &[]).expect("deposit");
    let apply = ct::apply_pending_balance(
        &t22,
        &source,
        1,
        &ae.encrypt(AMOUNT).into(),
        &payer.pubkey(),
        &[],
    )
    .expect("apply");
    h.send(&[deposit, apply], &[]).expect("shield");

    // `announce` does not check approval, so the setup lands; the payment cannot.
    let case = announced_on(&mut h, mint);
    let ixs = transfer_ixs(
        &h,
        &source,
        &keys,
        &ae,
        AMOUNT,
        &mint,
        &case.token_account,
        case.elgamal.pubkey(),
    );
    assert_token_error(
        h.send(&ixs, &[]),
        0,
        TokenError::ConfidentialTransferAccountNotApproved,
    );
}
