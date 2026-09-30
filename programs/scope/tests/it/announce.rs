use scope_client::{address::token_2022, testkit::*};
use scope_interface::{ScopeError, state::Announcement};
use solana_signer::Signer;
use spl_token_2022_interface::instruction::{AuthorityType, set_authority};

#[test]
fn announce_writes_the_record() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("setup and announce land");
    let account = h
        .svm
        .get_account(&case.announcement)
        .expect("announcement exists");
    let record = Announcement::from_bytes(&account.data).expect("well formed");
    assert_eq!(record.payer, h.payer.pubkey().to_bytes());
    assert_eq!(record.ephemeral, case.ephemeral);
    assert_eq!(record.view_tag, case.view_tag);
    assert_eq!(account.owner, scope_client::address::program_id());
    assert_eq!(
        account.lamports,
        h.svm
            .minimum_balance_for_rent_exemption(scope_interface::state::ANNOUNCEMENT_LEN)
    );
}

#[test]
fn announce_succeeds_when_announcement_prefunded() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    // Below the 68-byte minimum so announce tops up; a smaller tip would leave a
    // new rent-paying account, which the runtime rejects.
    let lamports = h.svm.minimum_balance_for_rent_exemption(0);
    let tip = solana_system_interface::instruction::transfer(
        &h.payer.pubkey(),
        &case.announcement,
        lamports,
    );
    h.send(&[tip], &[]).expect("prefund");
    h.send(&case.setup, &[]).expect("announce still lands");
}

#[test]
fn announce_twice_fails() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("first");
    let again = scope_client::ix::announce(&h.payer.pubkey(), &case.ephemeral, case.view_tag);
    assert_scope_error(h.send(&[again], &[]), ScopeError::AnnouncementInUse);
}

#[test]
fn announce_rejects_owner_still_payer() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    // Drop SetAuthority AccountOwner (the instruction before `announce`).
    let announce_at = case.setup.len() - 2;
    case.setup.remove(announce_at - 1);
    assert_scope_error(h.send(&case.setup, &[]), ScopeError::OwnerNotHandedOver);
}

#[test]
fn announce_rejects_other_close_authority() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let payer = h.payer.pubkey();
    let close_at = case.setup.len() - 4;
    case.setup[close_at] = set_authority(
        &token_2022(),
        &case.token_account,
        Some(&payer),
        AuthorityType::CloseAccount,
        &payer,
        &[],
    )
    .expect("ix");
    assert_scope_error(h.send(&case.setup, &[]), ScopeError::CloseAuthorityMismatch);
}

#[test]
fn announce_rejects_public_credits_enabled() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    // Drop DisableNonConfidentialCredits (five before the end).
    let disable_at = case.setup.len() - 5;
    case.setup.remove(disable_at);
    assert_scope_error(h.send(&case.setup, &[]), ScopeError::PublicCreditsEnabled);
}

#[test]
fn announce_rejects_wrong_ephemeral() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let at = case.setup.len() - 2;
    case.setup[at].data[1] ^= 1;
    assert_scope_error(
        h.send(&case.setup, &[]),
        ScopeError::TokenAccountAddressMismatch,
    );
}
