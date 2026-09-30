use scope_client::{ix::reclaim, testkit::*};
use scope_interface::ScopeError;
use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_signer::Signer;

fn announced() -> (Harness, StealthCase) {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("announce");
    (h, case)
}

#[test]
fn rejects_data_after_the_discriminator() {
    let (mut h, case) = announced();
    let mut ix = reclaim(&case.announcement, &case.token_account, &h.payer.pubkey());
    ix.data.push(0);
    assert_scope_error(h.send(&[ix], &[]), ScopeError::InvalidInstructionData);
}

#[test]
fn rejects_program_owned_account_that_is_not_an_announcement() {
    let (mut h, case) = announced();
    let real = h.svm.get_account(&case.announcement).expect("ann");
    let zeroed = vec![0u8; 68];
    let truncated = real.data[..67].to_vec();
    for data in [zeroed, truncated] {
        let mut fake = real.clone();
        fake.data = data;
        let fake_address = Address::new_unique();
        h.svm.set_account(fake_address, fake).expect("set");
        let ix = reclaim(&fake_address, &case.token_account, &h.payer.pubkey());
        assert_scope_error(h.send(&[ix], &[]), ScopeError::NotAnnouncement);
    }
}

#[test]
fn rejects_wrong_token_program() {
    let (mut h, case) = announced();
    let mut ix = reclaim(&case.announcement, &case.token_account, &h.payer.pubkey());
    ix.accounts[3] = AccountMeta::new_readonly(Address::default(), false);
    assert_scope_error(h.send(&[ix], &[]), ScopeError::WrongTokenProgram);
}

#[test]
fn refuses_while_confidential_balance_is_pending() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    crate::s3_sweep::pay(&mut h, &case);
    let ix = reclaim(&case.announcement, &case.token_account, &h.payer.pubkey());
    let failed = h.send(&[ix], &[]).expect_err("Token-2022 refuses to close");
    let code =
        spl_token_2022_interface::error::TokenError::ConfidentialTransferAccountHasBalance as u32;
    // Match on the debug text so the test needs no extra error crates.
    assert!(
        format!("{:?}", failed.err).contains(&format!("Custom({code})")),
        "expected ConfidentialTransferAccountHasBalance, got {:?}",
        failed.err
    );
    assert!(
        h.svm
            .get_account(&case.announcement)
            .is_some_and(|a| a.lamports > 0)
    );
    assert!(
        h.svm
            .get_account(&case.token_account)
            .is_some_and(|a| a.lamports > 0)
    );
}

#[test]
fn second_reclaim_fails() {
    let (mut h, case) = announced();
    let ix = reclaim(&case.announcement, &case.token_account, &h.payer.pubkey());
    h.send(std::slice::from_ref(&ix), &[])
        .expect("first reclaim");
    assert_scope_error(h.send(&[ix], &[]), ScopeError::NotAnnouncement);
    assert!(
        h.svm
            .get_account(&case.announcement)
            .is_none_or(|a| a.lamports == 0)
    );
    assert!(
        h.svm
            .get_account(&case.token_account)
            .is_none_or(|a| a.lamports == 0)
    );
}
