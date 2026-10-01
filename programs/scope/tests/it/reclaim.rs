use scope_client::{address::token_2022, ix::reclaim, testkit::*};
use scope_interface::ScopeError;
use solana_keypair::Keypair;
use solana_signer::Signer;
use spl_token_2022_interface::{
    extension::ExtensionType,
    instruction::{AuthorityType, initialize_account3, set_authority},
    state::Account,
};

/// Announce, then have P close nothing: the token account is empty, so reclaim can run.
fn announced() -> (Harness, StealthCase) {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("announce");
    (h, case)
}

#[test]
fn reclaim_returns_both_rents_to_payer() {
    let (mut h, case) = announced();
    let before = h.svm.get_balance(&h.payer.pubkey()).expect("payer");
    let ta_rent = h.svm.get_balance(&case.token_account).expect("ta");
    let ann_rent = h.svm.get_balance(&case.announcement).expect("ann");
    let stranger = Keypair::new();
    h.svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .expect("airdrop");
    let ix = reclaim(&case.announcement, &case.token_account, &h.payer.pubkey());
    let tx = scope_client::tx::v1_transaction(&stranger, &[], &[ix], h.svm.latest_blockhash());
    h.svm.send_transaction(tx).expect("anyone can reclaim");
    assert!(
        h.svm
            .get_account(&case.token_account)
            .is_none_or(|a| a.lamports == 0)
    );
    assert!(
        h.svm
            .get_account(&case.announcement)
            .is_none_or(|a| a.lamports == 0)
    );
    assert_eq!(
        h.svm.get_balance(&h.payer.pubkey()).expect("payer"),
        before + ta_rent + ann_rent
    );
}

#[test]
fn reclaim_fails_while_balance_remains() {
    let (mut h, case) = announced();
    // Mint public dust straight into the one-time account (MintTo ignores the disabled flag).
    let dust = spl_token_2022_interface::instruction::mint_to(
        &token_2022(),
        &h.mint,
        &case.token_account,
        &h.mint_authority.pubkey(),
        &[],
        1,
    )
    .expect("mint_to");
    let authority = h.mint_authority.insecure_clone();
    h.send(&[dust], &[&authority]).expect("dust");
    let ta_before = h.svm.get_account(&case.token_account).expect("ta");
    let ix = reclaim(&case.announcement, &case.token_account, &h.payer.pubkey());
    assert!(h.send(&[ix], &[]).is_err());
    assert!(
        h.svm
            .get_account(&case.announcement)
            .is_some_and(|a| a.lamports > 0)
    );
    let ta_after = h.svm.get_account(&case.token_account).expect("ta");
    assert_eq!(ta_after.lamports, ta_before.lamports);
    assert_eq!(ta_after.data, ta_before.data);
}

#[test]
fn reclaim_rejects_decoy_token_account() {
    let (mut h, case) = announced();
    // An attacker's own empty token account, close authority pointed at the victim's announcement.
    let attacker = Keypair::new();
    h.svm
        .airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("airdrop");
    let decoy = Keypair::new();
    let t22 = token_2022();
    let space = ExtensionType::try_calculate_account_len::<Account>(&[]).expect("len");
    let ixs = [
        solana_system_interface::instruction::create_account(
            &attacker.pubkey(),
            &decoy.pubkey(),
            h.svm.minimum_balance_for_rent_exemption(space),
            space as u64,
            &t22,
        ),
        initialize_account3(&t22, &decoy.pubkey(), &h.mint, &attacker.pubkey()).expect("init"),
        set_authority(
            &t22,
            &decoy.pubkey(),
            Some(&case.announcement),
            AuthorityType::CloseAccount,
            &attacker.pubkey(),
            &[],
        )
        .expect("auth"),
    ];
    let tx = scope_client::tx::v1_transaction(&attacker, &[&decoy], &ixs, h.svm.latest_blockhash());
    h.svm.send_transaction(tx).expect("decoy");
    h.svm.expire_blockhash();
    let ix = reclaim(&case.announcement, &decoy.pubkey(), &h.payer.pubkey());
    assert_scope_error(h.send(&[ix], &[]), ScopeError::AnnouncementAddressMismatch);
    assert!(
        h.svm
            .get_account(&case.announcement)
            .is_some_and(|a| a.lamports > 0)
    );
}

#[test]
fn reclaim_rejects_wrong_payer() {
    let (mut h, case) = announced();
    let ix = reclaim(
        &case.announcement,
        &case.token_account,
        &Keypair::new().pubkey(),
    );
    assert_scope_error(h.send(&[ix], &[]), ScopeError::PayerMismatch);
}

#[test]
fn reclaim_rejects_non_announcement() {
    let (mut h, case) = announced();
    let ix = reclaim(&h.mint, &case.token_account, &h.payer.pubkey());
    assert_scope_error(h.send(&[ix], &[]), ScopeError::NotAnnouncement);
}
