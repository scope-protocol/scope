//! Real stealth discovery and recipient transactions against LiteSVM.

use core::num::NonZeroI8;
use scope_client::{
    address::{announcement_address, token_2022, token_account_address},
    confidential::{context, derive_confidential_keys},
    ix::{StealthSetup, stealth_setup},
    scan::{self, ScanError},
    testkit::{Harness, SvmChain},
};
use solana_address::Address;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, BaseStateWithExtensionsMut, ExtensionType, StateWithExtensions,
        StateWithExtensionsMut,
        confidential_transfer::{ConfidentialTransferAccount, instruction as ct},
    },
    state::Account,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;
use stealth_keygen::{EphemeralSecret, RecipientSecretKeys, derive_payment_with_ephemeral};

const AMOUNT: u64 = 250_000;

fn recipient(spend: u8) -> RecipientSecretKeys {
    let mut bytes = [2; 64];
    bytes[..32].fill(0);
    bytes[0] = spend;
    RecipientSecretKeys::from_bytes(bytes).expect("public test secrets")
}

fn offset(n: i8) -> NonZeroI8 {
    NonZeroI8::new(n).expect("nonzero")
}

fn fund(h: &mut Harness, recipient: &RecipientSecretKeys, r: u8) -> (Address, Address, AeKey) {
    let sent = derive_payment_with_ephemeral(
        &recipient.derive_public_keys(),
        &EphemeralSecret::from_bytes([r; 32]),
    )
    .expect("payment");
    let payer = h.payer.pubkey();
    let ephemeral = sent.announcement.ephemeral_public_key;
    let account = token_account_address(&payer, &ephemeral);
    let (announcement, _) = announcement_address(&account);
    let material = sent
        .derive_ct_ikm(&context([42; 32], &h.mint, &account))
        .expect("context");
    let (keys, ae) = derive_confidential_keys(&material).expect("keys");
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])
    .expect("space");
    let mut ixs = stealth_setup(&StealthSetup {
        payer,
        mint: h.mint,
        ephemeral,
        view_tag: sent.announcement.discovery_tag,
        one_time_owner: Address::new_from_array(sent.payment_public_key),
        elgamal: &keys,
        ae: &ae,
        rent_lamports: h.svm.minimum_balance_for_rent_exemption(space),
        space: space as u64,
        lamports_for_owner: 5_000_000,
    })
    .expect("setup");
    let source = h.svm.get_account(&h.source).expect("source");
    let state = StateWithExtensions::<Account>::unpack(&source.data).expect("unpack");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("confidential");
    let available: ElGamalCiphertext = ext.available_balance.try_into().expect("ciphertext");
    let proofs = transfer_split_proof_data(
        &available,
        &ext.decryptable_available_balance.try_into().expect("hint"),
        AMOUNT,
        &h.source_elgamal,
        &h.source_ae,
        keys.pubkey(),
        None,
    )
    .expect("proofs");
    ixs.extend(
        ct::transfer(
            &token_2022(),
            &h.source,
            &h.mint,
            &account,
            &h.source_ae.encrypt(h.source_balance - AMOUNT).into(),
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_lo,
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_hi,
            &payer,
            &[],
            ProofLocation::InstructionOffset(offset(1), &proofs.equality_proof_data),
            ProofLocation::InstructionOffset(
                offset(2),
                &proofs
                    .ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
            ),
            ProofLocation::InstructionOffset(offset(3), &proofs.range_proof_data),
        )
        .expect("transfer"),
    );
    h.send(&ixs, &[]).expect("payer transaction");
    h.source_balance -= AMOUNT;
    (announcement, account, ae)
}

fn edit_source(
    h: &mut Harness,
    address: Address,
    edit: impl FnOnce(&mut ConfidentialTransferAccount),
) {
    let mut account = h.svm.get_account(&address).expect("account");
    let mut state = StateWithExtensionsMut::<Account>::unpack(&mut account.data).expect("unpack");
    edit(
        state
            .get_extension_mut::<ConfidentialTransferAccount>()
            .expect("extension"),
    );
    h.svm.set_account(address, account).expect("set");
}

#[test]
fn scan_recovers_backed_up_recipient_and_ignores_other_payments() {
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, account, _) = fund(&mut h, &alice, 3);
    fund(&mut h, &recipient(7), 4);
    let restored = RecipientSecretKeys::from_bytes(*alice.export().as_bytes()).expect("restore");
    let chain = SvmChain::new(&mut h.svm);
    let found = scan::scan(&chain, &restored, None).expect("scan");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].announcement, announcement);
    assert_eq!(found[0].token_account, account);
    assert_eq!(found[0].amount, AMOUNT);
    assert!(
        scan::scan(&chain, &restored, Some(&Address::default()))
            .expect("filter")
            .is_empty()
    );
}

#[test]
fn scan_rejects_forged_balance_hints_and_elgamal_keys() {
    let mut h = Harness::new();
    let alice = recipient(1);
    let (_, account, ae) = fund(&mut h, &alice, 3);
    edit_source(&mut h, account, |ext| {
        ext.decryptable_available_balance = ae.encrypt(7).into()
    });
    let error = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect_err("forged hint");
    assert!(matches!(error, ScanError::Invalid { why, .. } if why.contains("disagrees")));
    edit_source(&mut h, account, |ext| {
        ext.decryptable_available_balance = ae.encrypt(0).into();
        ext.elgamal_pubkey = (*ElGamalKeypair::new_rand().pubkey()).into();
    });
    let error = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect_err("wrong keys");
    assert!(matches!(error, ScanError::Invalid { why, .. } if why.contains("ElGamal")));
}

#[test]
fn scan_ignores_wrong_announcement_bumps_and_invalid_ephemeral_keys() {
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let mut account = h.svm.get_account(&announcement).expect("announcement");
    account.data[3] ^= 1;
    h.svm
        .set_account(announcement, account.clone())
        .expect("set");
    assert!(
        scan::scan(&SvmChain::new(&mut h.svm), &alice, None)
            .expect("scan")
            .is_empty()
    );
    account.data[3] ^= 1;
    account.data[4..36].fill(0);
    h.svm.set_account(announcement, account).expect("set");
    assert!(
        scan::scan(&SvmChain::new(&mut h.svm), &alice, None)
            .expect("scan")
            .is_empty()
    );
}
