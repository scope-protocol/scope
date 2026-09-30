use scope_client::{
    address::{announcement_address, program_id, token_2022},
    testkit::*,
};
use scope_interface::{ScopeError, seeds::ANNOUNCEMENT_SEED};
use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_signer::Signer;

/// `announce` sits second to last in the setup, before the lamports for P.
fn announce_at(case: &StealthCase) -> usize {
    case.setup.len() - 2
}

/// Land the setup without `announce`, returning the `announce` instruction.
fn setup_without_announce(
    h: &mut Harness,
    case: &mut StealthCase,
) -> solana_instruction::Instruction {
    let announce = case.setup.remove(announce_at(case));
    h.send(&case.setup, &[]).expect("setup lands");
    announce
}

/// Rewrite the token account's bytes in place.
fn patch_token_account(h: &mut Harness, case: &StealthCase, patch: impl FnOnce(&mut Vec<u8>)) {
    let mut account = h
        .svm
        .get_account(&case.token_account)
        .expect("token account");
    patch(&mut account.data);
    h.svm.set_account(case.token_account, account).expect("set");
}

#[test]
fn rejects_short_and_long_data() {
    for len in [32usize, 34] {
        let mut h = Harness::new();
        let mut case = h.stealth_case();
        let at = announce_at(&case);
        case.setup[at].data.resize(1 + len, 0);
        assert_scope_error(h.send(&case.setup, &[]), ScopeError::InvalidInstructionData);
    }
}

#[test]
fn rejects_stranger_announcing_the_payers_account() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let mut announce = setup_without_announce(&mut h, &mut case);
    let stranger = Keypair::new();
    h.svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .expect("airdrop");
    announce.accounts[0] = AccountMeta::new(stranger.pubkey(), true);
    assert_scope_error(
        h.send(&[announce], &[&stranger]),
        ScopeError::TokenAccountAddressMismatch,
    );
}

#[test]
fn rejects_payer_that_did_not_sign() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let at = announce_at(&case);
    // The fee payer signs the whole message, so use a key that signs nothing.
    case.setup[at].accounts[0] = AccountMeta::new(Keypair::new().pubkey(), false);
    assert_scope_error(h.send(&case.setup, &[]), ScopeError::PayerNotSigner);
}

#[test]
fn rejects_wrong_system_program() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let at = announce_at(&case);
    case.setup[at].accounts[3] = AccountMeta::new_readonly(token_2022(), false);
    assert_scope_error(h.send(&case.setup, &[]), ScopeError::WrongSystemProgram);
}

#[test]
fn rejects_token_account_not_owned_by_token_2022() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let announce = setup_without_announce(&mut h, &mut case);
    let mut account = h.svm.get_account(&case.token_account).expect("ta");
    account.owner = Address::default();
    h.svm.set_account(case.token_account, account).expect("set");
    assert_scope_error(h.send(&[announce], &[]), ScopeError::NotTokenAccount);
}

#[test]
fn rejects_wrong_account_type() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let announce = setup_without_announce(&mut h, &mut case);
    // Byte 165 is the account type; 1 means mint.
    patch_token_account(&mut h, &case, |d| d[165] = 1);
    assert_scope_error(h.send(&[announce], &[]), ScopeError::NotTokenAccount);
}

#[test]
fn rejects_uninitialized_token_account() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let announce = setup_without_announce(&mut h, &mut case);
    patch_token_account(&mut h, &case, |d| d[108] = 0);
    assert_scope_error(
        h.send(&[announce], &[]),
        ScopeError::TokenAccountNotInitialized,
    );
}

#[test]
fn rejects_delegate() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let announce = setup_without_announce(&mut h, &mut case);
    patch_token_account(&mut h, &case, |d| {
        d[72..76].copy_from_slice(&[1, 0, 0, 0]);
        d[76..108].fill(7);
    });
    assert_scope_error(h.send(&[announce], &[]), ScopeError::DelegateSet);
}

#[test]
fn rejects_missing_confidential_extension() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let announce = setup_without_announce(&mut h, &mut case);
    // The confidential extension is the only TLV entry; type 0 ends the list.
    patch_token_account(&mut h, &case, |d| d[166..168].copy_from_slice(&[0, 0]));
    assert_scope_error(
        h.send(&[announce], &[]),
        ScopeError::MissingConfidentialExtension,
    );
}

#[test]
fn rejects_credit_cap_above_one() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let announce = setup_without_announce(&mut h, &mut case);
    // Extension value starts at 170; the cap is at offset 271 within it.
    patch_token_account(&mut h, &case, |d| {
        d[170 + 271..170 + 279].copy_from_slice(&2u64.to_le_bytes());
    });
    assert_scope_error(h.send(&[announce], &[]), ScopeError::CreditCapNotOne);
}

#[test]
fn rejects_non_canonical_announcement_address() {
    let mut h = Harness::new();
    let mut case = h.stealth_case();
    let (canonical, bump) = announcement_address(&case.token_account);
    let other = (0..bump)
        .rev()
        .find_map(|b| {
            Address::create_program_address(
                &[ANNOUNCEMENT_SEED, case.token_account.as_ref(), &[b]],
                &program_id(),
            )
            .ok()
        })
        .expect("a lower valid bump");
    assert_ne!(other, canonical);
    let at = announce_at(&case);
    case.setup[at].accounts[2] = AccountMeta::new(other, false);
    assert_scope_error(
        h.send(&case.setup, &[]),
        ScopeError::AnnouncementAddressMismatch,
    );
}

#[test]
fn rejects_announcement_with_data() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    // Clone an existing System account so the test never names the account type.
    let mut occupied = h.svm.get_account(&h.payer.pubkey()).expect("payer");
    occupied.lamports = h.svm.minimum_balance_for_rent_exemption(68);
    occupied.data = vec![0; 68];
    h.svm.set_account(case.announcement, occupied).expect("set");
    assert_scope_error(h.send(&case.setup, &[]), ScopeError::AnnouncementInUse);
}
