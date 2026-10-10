//! `register` and `deregister`, and S7: B_spend must have prime order.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as B,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use scope_client::{
    address::{meta_entry_address, program_id},
    testkit::*,
};
use scope_interface::{
    ScopeError,
    instruction::{RegisterData, deregister_data},
    state::{META_SCHEME_V1, MetaAddressEntry},
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;

fn valid_spend() -> [u8; 32] {
    (B * Scalar::from(11u64)).compress().to_bytes()
}

fn data(spend: [u8; 32]) -> RegisterData {
    RegisterData {
        scheme_id: META_SCHEME_V1,
        version: 1,
        spend,
        scan: [9; 32],
        flags: 0,
    }
}

fn register_ix(registrant: &Address, entry: &Address, data: &[u8]) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*registrant, true),
            AccountMeta::new(*entry, false),
            AccountMeta::new_readonly(Address::default(), false),
        ],
        data: data.to_vec(),
    }
}

// Returns litesvm's own result type so tests can match on its metadata.
#[allow(clippy::result_large_err)]
fn register(h: &mut Harness, d: RegisterData) -> litesvm::types::TransactionResult {
    let registrant = h.payer.pubkey();
    let (entry, _) = meta_entry_address(&registrant);
    h.send(&[register_ix(&registrant, &entry, &d.to_bytes())], &[])
}

fn deregister_ix(registrant: &Address, entry: &Address, data: &[u8]) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*registrant, true),
            AccountMeta::new(*entry, false),
        ],
        data: data.to_vec(),
    }
}

fn lamports(h: &Harness, a: &Address) -> u64 {
    h.svm.get_account(a).map_or(0, |a| a.lamports)
}

#[test]
fn registers_in_srfc_42_layout_and_deregisters_with_the_rent_back() {
    let mut h = Harness::new();
    let registrant = h.payer.pubkey();
    let (entry, bump) = meta_entry_address(&registrant);
    let meta = register(&mut h, data(valid_spend())).expect("register");
    println!("register: {} CU", meta.compute_units_consumed);
    let account = h.svm.get_account(&entry).expect("entry");
    assert_eq!(account.owner, program_id());
    assert_eq!(
        MetaAddressEntry::from_bytes(&account.data),
        Ok(MetaAddressEntry {
            registrant: registrant.to_bytes(),
            scheme_id: META_SCHEME_V1,
            bump,
            version: 1,
            spend: valid_spend(),
            scan: [9; 32],
            flags: 0,
        })
    );
    let rent = account.lamports;
    let before = lamports(&h, &registrant);
    h.send(
        &[deregister_ix(
            &registrant,
            &entry,
            &deregister_data(META_SCHEME_V1),
        )],
        &[],
    )
    .expect("deregister");
    assert_eq!(lamports(&h, &entry), 0);
    assert_eq!(
        lamports(&h, &registrant),
        before + rent - scope_client::fees::LAMPORTS_PER_SIGNATURE
    );
}

#[test]
fn registers_again_after_deregistering() {
    let mut h = Harness::new();
    let registrant = h.payer.pubkey();
    let (entry, _) = meta_entry_address(&registrant);
    register(&mut h, data(valid_spend())).expect("register");
    let deregister = deregister_ix(&registrant, &entry, &deregister_data(META_SCHEME_V1));
    h.send(std::slice::from_ref(&deregister), &[])
        .expect("deregister");
    assert_scope_error(h.send(&[deregister], &[]), ScopeError::NotMetaAddressEntry);
    let other_spend = (B * Scalar::from(13u64)).compress().to_bytes();
    register(&mut h, data(other_spend)).expect("register again");
    let account = h.svm.get_account(&entry).expect("entry");
    assert_eq!(
        MetaAddressEntry::from_bytes(&account.data).map(|e| e.spend),
        Ok(other_spend)
    );
}

#[test]
fn deregister_refuses_an_announcement_in_place_of_an_entry() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.send(&case.setup, &[]).expect("setup and announce");
    let registrant = h.payer.pubkey();
    assert_scope_error(
        h.send(
            &[deregister_ix(
                &registrant,
                &case.announcement,
                &deregister_data(META_SCHEME_V1),
            )],
            &[],
        ),
        ScopeError::NotMetaAddressEntry,
    );
}

#[test]
fn a_prefunded_entry_address_still_registers() {
    let mut h = Harness::new();
    let (entry, _) = meta_entry_address(&h.payer.pubkey());
    h.svm.airdrop(&entry, 1_000_000).expect("prefund");
    register(&mut h, data(valid_spend())).expect("register");
}

#[test]
fn rejects_bad_data_scheme_version_and_flags() {
    let mut h = Harness::new();
    let registrant = h.payer.pubkey();
    let (entry, _) = meta_entry_address(&registrant);
    let full = data(valid_spend()).to_bytes();
    assert_scope_error(
        h.send(&[register_ix(&registrant, &entry, &full[..68])], &[]),
        ScopeError::InvalidInstructionData,
    );
    for bad in [
        RegisterData {
            scheme_id: 2,
            ..data(valid_spend())
        },
        RegisterData {
            version: 2,
            ..data(valid_spend())
        },
        RegisterData {
            flags: 1,
            ..data(valid_spend())
        },
    ] {
        assert_scope_error(register(&mut h, bad), ScopeError::UnsupportedMetaAddress);
    }
}

#[test]
fn rejects_a_registrant_that_did_not_sign() {
    let mut h = Harness::new();
    let victim = Keypair::new().pubkey();
    let (entry, _) = meta_entry_address(&victim);
    let mut ix = register_ix(&victim, &entry, &data(valid_spend()).to_bytes());
    ix.accounts[0].is_signer = false;
    assert_scope_error(h.send(&[ix], &[]), ScopeError::RegistrantNotSigner);
}

#[test]
fn rejects_wrong_system_program() {
    let mut h = Harness::new();
    let registrant = h.payer.pubkey();
    let (entry, _) = meta_entry_address(&registrant);
    let mut ix = register_ix(&registrant, &entry, &data(valid_spend()).to_bytes());
    ix.accounts[2] = AccountMeta::new_readonly(Keypair::new().pubkey(), false);
    assert_scope_error(h.send(&[ix], &[]), ScopeError::WrongSystemProgram);
}

#[test]
fn rejects_an_entry_that_is_not_the_canonical_pda() {
    let mut h = Harness::new();
    let registrant = h.payer.pubkey();
    let other = Keypair::new().pubkey();
    let ix = register_ix(&registrant, &other, &data(valid_spend()).to_bytes());
    assert_scope_error(h.send(&[ix], &[]), ScopeError::MetaAddressMismatch);
}

#[test]
fn rejects_registering_twice() {
    let mut h = Harness::new();
    register(&mut h, data(valid_spend())).expect("first");
    assert_scope_error(
        register(&mut h, data(valid_spend())),
        ScopeError::MetaAddressInUse,
    );
}

#[test]
fn s7_rejects_identity_small_order_mixed_order_and_non_canonical_spend_keys() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let small_order = [0u8; 32];
    let small = CompressedEdwardsY(small_order)
        .decompress()
        .expect("on curve");
    let mixed: EdwardsPoint = B * Scalar::from(11u64) + small;
    let mut noncanonical_identity = [0xff; 32];
    noncanonical_identity[0] = 0xee;
    noncanonical_identity[31] = 0x7f;
    let off_curve = (2u8..)
        .map(|y| {
            let mut b = [0u8; 32];
            b[0] = y;
            b
        })
        .find(|b| CompressedEdwardsY(*b).decompress().is_none())
        .expect("some small y is off the curve");
    let mut vectors = vec![
        ("identity".to_string(), identity),
        ("small order".into(), small_order),
        ("mixed order".into(), mixed.compress().to_bytes()),
        ("non-canonical identity".into(), noncanonical_identity),
        ("off the curve".into(), off_curve),
    ];
    for (i, t) in curve25519_dalek::constants::EIGHT_TORSION
        .iter()
        .enumerate()
        .skip(1)
    {
        vectors.push((format!("torsion {i}"), t.compress().to_bytes()));
        let with_b = B * Scalar::from(11u64) + t;
        vectors.push((format!("torsion {i} + 11B"), with_b.compress().to_bytes()));
    }
    for (name, spend) in vectors {
        let mut h = Harness::new();
        println!("{name}");
        assert_scope_error(register(&mut h, data(spend)), ScopeError::InvalidSpendKey);
    }
}

#[test]
fn deregister_rejects_bad_data_a_missing_signature_a_stranger_and_a_wrong_scheme() {
    let mut h = Harness::new();
    // Not the fee payer, so its signature is only there when it signs.
    let owner = Keypair::new();
    h.svm.airdrop(&owner.pubkey(), 1_000_000_000).expect("fund");
    let registrant = owner.pubkey();
    let (entry, _) = meta_entry_address(&registrant);
    h.send(
        &[register_ix(
            &registrant,
            &entry,
            &data(valid_spend()).to_bytes(),
        )],
        &[&owner],
    )
    .expect("register");

    let ok = deregister_data(META_SCHEME_V1);
    assert_scope_error(
        h.send(&[deregister_ix(&registrant, &entry, &ok[..2])], &[&owner]),
        ScopeError::InvalidInstructionData,
    );
    let mut unsigned = deregister_ix(&registrant, &entry, &ok);
    unsigned.accounts[0].is_signer = false;
    assert_scope_error(h.send(&[unsigned], &[]), ScopeError::RegistrantNotSigner);

    let stranger = Keypair::new();
    h.svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .expect("fund");
    assert_scope_error(
        h.send(
            &[deregister_ix(&stranger.pubkey(), &entry, &ok)],
            &[&stranger],
        ),
        ScopeError::RegistrantMismatch,
    );
    assert_scope_error(
        h.send(
            &[deregister_ix(&registrant, &entry, &deregister_data(2))],
            &[&owner],
        ),
        ScopeError::MetaAddressMismatch,
    );
    let (not_an_entry, _) = meta_entry_address(&stranger.pubkey());
    h.svm
        .airdrop(&not_an_entry, 1_000_000)
        .expect("system account");
    assert_scope_error(
        h.send(&[deregister_ix(&registrant, &not_an_entry, &ok)], &[&owner]),
        ScopeError::NotMetaAddressEntry,
    );
    assert!(
        h.svm.get_account(&entry).is_some_and(|a| a.lamports > 0),
        "every refused call left the entry in place"
    );
}

#[test]
fn rejects_an_entry_address_that_holds_data() {
    let mut h = Harness::new();
    let (entry, _) = meta_entry_address(&h.payer.pubkey());
    let mut occupied = h.svm.get_account(&h.payer.pubkey()).expect("payer");
    occupied.lamports = h.svm.minimum_balance_for_rent_exemption(109);
    occupied.data = vec![0; 109];
    h.svm.set_account(entry, occupied).expect("set");
    assert_scope_error(
        register(&mut h, data(valid_spend())),
        ScopeError::MetaAddressInUse,
    );
}

#[test]
fn rejects_an_entry_address_owned_by_another_program() {
    let mut h = Harness::new();
    let (entry, _) = meta_entry_address(&h.payer.pubkey());
    let mut claimed = h.svm.get_account(&h.payer.pubkey()).expect("payer");
    claimed.lamports = h.svm.minimum_balance_for_rent_exemption(0);
    claimed.owner = scope_client::address::token_2022();
    h.svm.set_account(entry, claimed).expect("set");
    assert_scope_error(
        register(&mut h, data(valid_spend())),
        ScopeError::MetaAddressInUse,
    );
}

#[test]
fn a_legacy_transaction_registers_and_deregisters() {
    let mut h = Harness::new();
    let registrant = h.payer.pubkey();
    let (entry, _) = meta_entry_address(&registrant);
    let register_ix = register_ix(&registrant, &entry, &data(valid_spend()).to_bytes());
    let tx =
        scope_client::tx::legacy_transaction(&h.payer, &[register_ix], h.svm.latest_blockhash());
    h.svm.send_transaction(tx).expect("legacy register lands");
    assert!(lamports(&h, &entry) > 0);
    h.svm.expire_blockhash();
    let tx = scope_client::tx::legacy_transaction(
        &h.payer,
        &[deregister_ix(
            &registrant,
            &entry,
            &deregister_data(META_SCHEME_V1),
        )],
        h.svm.latest_blockhash(),
    );
    h.svm.send_transaction(tx).expect("legacy deregister lands");
    assert_eq!(lamports(&h, &entry), 0);
}
