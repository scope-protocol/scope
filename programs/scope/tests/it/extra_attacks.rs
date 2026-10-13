//! Extra adversarial tests: each one tries to break the program or prove invariants.
//! Predictions were written in comments before running each test.

use crate::s3_sweep::{AMOUNT, pay, recipient_ixs};
use litesvm::types::TransactionResult;
use scope_client::{
    address::{program_id, token_2022},
    ix::reclaim,
    testkit::*,
};
use scope_interface::{
    ScopeError,
    token_account::{STATE_INITIALIZED, read_token_account},
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};
use spl_token_2022_interface::{
    error::TokenError,
    extension::{
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        cpi_guard::instruction::enable_cpi_guard, permanent_delegate::PermanentDelegate,
    },
    instruction::{
        AuthorityType, burn_checked, close_account, reallocate, set_authority, transfer_checked,
    },
    state::Mint,
};

const DECIMALS: u8 = 6;

fn assert_token_error(result: TransactionResult, index: u8, expected: TokenError) {
    match result {
        Err(failed) => assert_eq!(
            failed.err,
            TransactionError::InstructionError(index, InstructionError::Custom(expected as u32)),
            "logs: {:#?}",
            failed.meta.logs
        ),
        Ok(_) => panic!("expected {expected:?}, but the transaction succeeded"),
    }
}

// T1. PREDICTION: an unknown tag and empty data both fail with `InvalidInstruction`,
// never a panic or a silent success.
#[test]
fn unknown_tag_and_empty_data_are_invalid_instructions() {
    let mut h = Harness::new();
    for data in [vec![255u8], vec![]] {
        let ix = Instruction {
            program_id: program_id(),
            accounts: vec![],
            data,
        };
        assert_scope_error(h.send(&[ix], &[]), ScopeError::InvalidInstruction);
    }
}

// T2. PREDICTION:
// - (a) Initial prediction: `MissingAccount` (due to deprecation of `NotEnoughAccountKeys`).
//       Actual runtime result: `NotEnoughAccountKeys`.
// - (b) Prediction & result: `PayerMismatch`.
// - (c) Prediction & result: `AnnouncementAddressMismatch`.
#[test]
#[allow(deprecated)]
fn reclaim_with_too_few_accounts_fails() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("announce");
    let mut ix = reclaim(&case.announcement, &case.token_account, &h.payer.pubkey());
    ix.accounts.truncate(2);
    let failed = h.send(&[ix], &[]).expect_err("must fail");
    assert_eq!(
        failed.err,
        TransactionError::InstructionError(0, InstructionError::NotEnoughAccountKeys)
    );
}

#[test]
fn reclaim_with_the_announcement_as_payer_fails() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("announce");
    let ix = reclaim(&case.announcement, &case.token_account, &case.announcement);
    assert_scope_error(h.send(&[ix], &[]), ScopeError::PayerMismatch);
}

#[test]
fn announce_with_the_token_account_in_the_announcement_slot_fails() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    let mut setup = case.setup.clone();
    let n = setup.len();
    setup[n - 2].accounts[2] = AccountMeta::new(case.token_account, false);
    assert_scope_error(h.send(&setup, &[]), ScopeError::AnnouncementAddressMismatch);
}

// T3. PREDICTION: announce ACCEPTS an owner handed to the announcement PDA, because
// `setup::check` only requires `owner != payer`. Severity LOW (defense in depth): it
// only harms the payer, and the official client never builds it.
// Explicit verification: we verify via `read_token_account` that the post-announce owner is
// indeed the announcement PDA.
#[test]
fn announce_accepts_owner_handed_to_the_announcement() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    let payer = h.payer.pubkey();
    let mut setup = case.setup.clone();
    let n = setup.len();
    setup[n - 3] = set_authority(
        &token_2022(),
        &case.token_account,
        Some(&case.announcement),
        AuthorityType::AccountOwner,
        &payer,
        &[],
    )
    .expect("set_authority");
    h.send(&setup, &[]).expect("accepted today (finding)");

    // Proves that the token account was initialized and handed over to the announcement PDA.
    let data = h
        .svm
        .get_account(&case.token_account)
        .expect("account")
        .data;
    let view = read_token_account(&data).expect("read_token_account");
    assert_eq!(view.state, STATE_INITIALIZED);
    assert_eq!(view.owner, case.announcement.to_bytes());
}

// T4. PREDICTION: P turns CpiGuard on after the announce; reclaim's CPI CloseAccount is
// then blocked by Token-2022 (`CpiGuardCloseAccountBlocked`), so nothing moves.
// Explicit verification: we verify via `read_token_account` that `cpi_guard_locked == true`
// before attempting reclaim.
#[test]
fn cpi_guard_enabled_after_announce_blocks_reclaim() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("announce");
    let t22 = token_2022();
    let p = case.one_time_owner.insecure_clone();
    let ixs = [
        reallocate(
            &t22,
            &case.token_account,
            &h.payer.pubkey(),
            &p.pubkey(),
            &[],
            &[ExtensionType::CpiGuard],
        )
        .expect("reallocate"),
        enable_cpi_guard(&t22, &case.token_account, &p.pubkey(), &[]).expect("enable"),
    ];
    h.send(&ixs, &[&p]).expect("P enables CpiGuard");

    // Proves that CpiGuard is locked on the account before reclaim is called.
    let data = h
        .svm
        .get_account(&case.token_account)
        .expect("account")
        .data;
    let view = read_token_account(&data).expect("read_token_account");
    assert!(view.cpi_guard_locked, "cpi_guard_locked must be true");

    let payer = h.payer.pubkey();
    let before = (
        h.svm.get_balance(&payer).expect("payer"),
        h.svm.get_balance(&case.token_account).expect("ta"),
        h.svm.get_balance(&case.announcement).expect("ann"),
    );
    let result = h.send(
        &[reclaim(&case.announcement, &case.token_account, &payer)],
        &[],
    );
    assert_token_error(result, 0, TokenError::CpiGuardCloseAccountBlocked);
    assert_eq!(h.svm.get_balance(&case.token_account), Some(before.1));
    assert_eq!(h.svm.get_balance(&case.announcement), Some(before.2));
    assert!(h.svm.get_balance(&payer).expect("payer") <= before.0);
}

// T5. PREDICTION:
// - (a) The permanent delegate attempts confidential instructions (apply, transfer, empty).
//   Token-2022 rejects all with `OwnerMismatch`.
// - (b) The permanent delegate attempts public `transfer_checked` or `burn_checked`.
//   Result: fails with `InsufficientFunds` because the account holds encrypted confidential
//   balance rather than plaintext balance.
// Together, (a) and (b) prove that the permanent delegate has authority over public balance,
// but cannot access or drain confidential funds.
#[test]
fn permanent_delegate_cannot_apply_transfer_empty_or_drain_publicly() {
    const PERMANENT_DELEGATE: u16 = 12;
    let mut h = Harness::new();
    let delegate = Keypair::new();
    let mut mint = h.svm.get_account(&h.mint).expect("mint");
    mint.data.extend(PERMANENT_DELEGATE.to_le_bytes());
    mint.data.extend(32u16.to_le_bytes());
    mint.data.extend(delegate.pubkey().to_bytes());
    h.svm.set_account(h.mint, mint).expect("set mint");

    // The extension must really be there, otherwise the test proves nothing.
    let data = h.svm.get_account(&h.mint).expect("mint").data;
    let state = StateWithExtensions::<Mint>::unpack(&data).expect("unpack");
    let ext = state.get_extension::<PermanentDelegate>().expect("ext");
    assert_eq!(
        Option::<Address>::from(ext.delegate),
        Some(delegate.pubkey())
    );

    let case = h.stealth_case();
    pay(&mut h, &case);

    // T5a: confidential instructions
    let d_keys = ElGamalKeypair::new_rand();
    let d = h.plain_confidential_account(&Keypair::new(), &d_keys, &AeKey::new_rand());
    let ixs = recipient_ixs(&h, &case, &d, d_keys.pubkey());
    for (name, op) in [("apply", 0..1), ("transfer", 1..5), ("empty", 5..7)] {
        let target = op.start;
        let mut signed = ixs[target].clone();
        for meta in &mut signed.accounts {
            if meta.pubkey == case.one_time_owner.pubkey() {
                meta.pubkey = delegate.pubkey();
            }
        }
        let mut tx = ixs[..target].to_vec();
        tx.push(signed);
        tx.extend_from_slice(&ixs[target + 1..op.end]);
        let p = case.one_time_owner.insecure_clone();
        let d_signer = delegate.insecure_clone();
        let extra: Vec<&Keypair> = if target == 0 {
            vec![&d_signer]
        } else {
            vec![&p, &d_signer]
        };
        println!("{name} signed by the permanent delegate");
        assert_token_error(h.send(&tx, &extra), target as u8, TokenError::OwnerMismatch);
    }

    // T5b: public transfer_checked and burn_checked attempts by the permanent delegate
    let t22 = token_2022();
    let d_signer = delegate.insecure_clone();

    // Public transfer_checked attempt
    let transfer_ix = transfer_checked(
        &t22,
        &case.token_account,
        &h.mint,
        &d,
        &delegate.pubkey(),
        &[],
        AMOUNT,
        DECIMALS,
    )
    .expect("transfer_checked");
    assert_token_error(
        h.send(&[transfer_ix], &[&d_signer]),
        0,
        TokenError::InsufficientFunds,
    );

    // Public burn_checked attempt
    let burn_ix = burn_checked(
        &t22,
        &case.token_account,
        &h.mint,
        &delegate.pubkey(),
        &[],
        AMOUNT,
        DECIMALS,
    )
    .expect("burn_checked");
    assert_token_error(
        h.send(&[burn_ix], &[&d_signer]),
        0,
        TokenError::InsufficientFunds,
    );
}

// T6. PREDICTION: The recipient P (who is the AccountOwner) attempts to steal payer rent:
// - (a) P attempts to replace the close authority with themselves via `set_authority(CloseAccount)`.
//       Prediction: fails (`TokenError::OwnerMismatch`), because once close_authority is set (to the PDA),
//       only the existing close authority can change it.
// - (b) P attempts to close the token account directly via `close_account` directing lamports to themselves.
//       Prediction: fails (`TokenError::OwnerMismatch`), because only the close authority can close the account.
// Proves that "rent can only return to the stored payer" (REQ04, REQ11, REQ12) holds against the recipient.
#[test]
fn recipient_cannot_steal_payer_rent_via_token_2022() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("announce");

    let t22 = token_2022();
    let p = case.one_time_owner.insecure_clone();

    let ta_balance_before = h.svm.get_balance(&case.token_account).expect("ta balance");
    let ann_balance_before = h.svm.get_balance(&case.announcement).expect("ann balance");

    // (a) P attempts to change close authority to themselves
    let change_close_auth = set_authority(
        &t22,
        &case.token_account,
        Some(&p.pubkey()),
        AuthorityType::CloseAccount,
        &p.pubkey(),
        &[],
    )
    .expect("set_authority");
    assert_token_error(
        h.send(&[change_close_auth], &[&p]),
        0,
        TokenError::OwnerMismatch,
    );

    // (b) P attempts to directly close the token account to siphon lamports
    let steal_close = close_account(&t22, &case.token_account, &p.pubkey(), &p.pubkey(), &[])
        .expect("close_account");
    assert_token_error(h.send(&[steal_close], &[&p]), 0, TokenError::OwnerMismatch);

    // Verify neither the token account nor the announcement lost any lamports
    assert_eq!(
        h.svm.get_balance(&case.token_account),
        Some(ta_balance_before)
    );
    assert_eq!(
        h.svm.get_balance(&case.announcement),
        Some(ann_balance_before)
    );
}

// T7. PREDICTION: After announce and ownership handover to P, the payer attempts to reclaim
// account ownership by calling `set_authority(AccountOwner, new = payer)` signed by the payer.
// Prediction: fails with `TokenError::OwnerMismatch`, as ownership has already transferred to P.
#[test]
fn payer_cannot_reclaim_account_ownership_after_announce() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("announce");

    let t22 = token_2022();
    let payer = h.payer.pubkey();

    let steal_back = set_authority(
        &t22,
        &case.token_account,
        Some(&payer),
        AuthorityType::AccountOwner,
        &payer,
        &[],
    )
    .expect("set_authority");

    // Signed by the payer (h.send automatically signs with payer)
    assert_token_error(h.send(&[steal_back], &[]), 0, TokenError::OwnerMismatch);
}

// T8. PREDICTION: The payer completes announce, then reclaim (closing both token account and announcement).
// The payer then resends the exact same `case.setup` (reusing ephemeral key R).
// Prediction: the program accepts successfully (finding). There is no on-chain defense against reusing R
// after account closure; uniqueness of R relies on the client journal off-chain.
#[test]
fn reusing_ephemeral_key_after_reclaim_succeeds() {
    let mut h = Harness::new();
    let case = h.stealth_case();

    // 1st cycle: announce and reclaim
    h.send(&case.setup, &[]).expect("1st announce");
    h.send(
        &[reclaim(
            &case.announcement,
            &case.token_account,
            &h.payer.pubkey(),
        )],
        &[],
    )
    .expect("reclaim");

    // Both accounts are closed
    assert_eq!(h.svm.get_balance(&case.token_account), None);
    assert_eq!(h.svm.get_balance(&case.announcement), None);

    // 2nd cycle: resend the identical setup with the reused R
    h.send(&case.setup, &[])
        .expect("2nd announce with reused R succeeds (finding)");

    // Verify the account and announcement exist again
    assert!(h.svm.get_account(&case.token_account).is_some());
    assert!(h.svm.get_account(&case.announcement).is_some());
}
