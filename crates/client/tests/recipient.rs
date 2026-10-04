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
    state::{Account, Mint},
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
        lamports_for_owner: 8_000_000,
    })
    .expect("setup");
    let source = h.svm.get_account(&h.source).expect("source");
    let state = StateWithExtensions::<Account>::unpack(&source.data).expect("unpack");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("confidential");
    let available: ElGamalCiphertext = ext.available_balance.try_into().expect("ciphertext");
    let mint_account = h.svm.get_account(&h.mint).expect("mint");
    let mint = StateWithExtensions::<Mint>::unpack(&mint_account.data).expect("mint state");
    let auditor = mint.get_extension::<spl_token_2022_interface::extension::confidential_transfer::ConfidentialTransferMint>().expect("mint extension").auditor_elgamal_pubkey.get().map(|key| solana_zk_sdk::encryption::elgamal::ElGamalPubkey::try_from(key.0.as_slice()).expect("auditor"));
    let proofs = transfer_split_proof_data(
        &available,
        &ext.decryptable_available_balance.try_into().expect("hint"),
        AMOUNT,
        &h.source_elgamal,
        &h.source_ae,
        keys.pubkey(),
        auditor.as_ref(),
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

#[test]
fn sweep_moves_the_whole_balance_closes_accounts_and_refunds_rent() {
    use scope_client::{
        chain::Chain,
        sweep::{self, SweepOptions},
    };
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, account, _) = fund(&mut h, &alice, 3);
    let payer_before = h
        .svm
        .get_account(&h.payer.pubkey())
        .expect("payer")
        .lamports;
    let rent = h
        .svm
        .get_account(&announcement)
        .expect("announcement")
        .lamports
        + h.svm.get_account(&account).expect("source").lamports;
    let mut chain = SvmChain::new(&mut h.svm);
    chain.drop_sends = 1;
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let report = sweep::sweep(&mut chain, &alice, &announcement, &opts).expect("sweep");
    assert!(report.reclaimed);
    assert_eq!(report.amount, AMOUNT);
    assert!(
        chain
            .account(&account, scope_client::chain::Commitment::Confirmed)
            .expect("source")
            .is_none()
    );
    assert!(
        chain
            .account(&announcement, scope_client::chain::Commitment::Confirmed)
            .expect("announcement")
            .is_none()
    );
    assert!(sweep::sweep(&mut chain, &alice, &announcement, &opts).is_err());
    assert_eq!(
        h.svm
            .get_account(&h.payer.pubkey())
            .expect("payer")
            .lamports,
        payer_before + rent
    );
    let seed = alice
        .derive_sweep_destination(&report.ephemeral)
        .expect("seed");
    let owner = solana_keypair::Keypair::new_from_array(*seed.as_bytes());
    let (keys, _) = solana_zk_sdk::encryption::derivation::derive_confidential_keys(&owner, b"")
        .expect("destination keys");
    let destination = h.svm.get_account(&report.destination).expect("destination");
    let state = StateWithExtensions::<Account>::unpack(&destination.data).expect("account");
    assert_eq!(state.base.owner, report.destination_owner);
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("extension");
    let lo: ElGamalCiphertext = ext.pending_balance_lo.try_into().expect("lo");
    let hi: ElGamalCiphertext = ext.pending_balance_hi.try_into().expect("hi");
    assert_eq!(
        keys.secret().decrypt_u32(&lo).expect("lo")
            + (keys.secret().decrypt_u32(&hi).expect("hi") << 16),
        AMOUNT
    );
    assert_eq!(u64::from(ext.pending_balance_credit_counter), 1);
    assert!(
        h.svm
            .get_account(&report.destination_owner)
            .expect("drained funds")
            .lamports
            > 0
    );
}

#[test]
fn sweep_dry_run_and_underfunding_leave_the_payment_untouched() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, account, _) = fund(&mut h, &alice, 3);
    let opts = SweepOptions {
        dry_run: true,
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let report = sweep::sweep(&mut SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect("dry run");
    assert!(report.dry_run);
    assert!(h.svm.get_account(&report.destination).is_none());
    assert!(h.svm.get_account(&account).is_some());
    let public = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect("scan");
    let note = stealth_keygen::PaymentAnnouncement {
        ephemeral_public_key: public[0].ephemeral,
        discovery_tag: h.svm.get_account(&announcement).expect("announcement").data[2],
    };
    let p = Address::new_from_array(
        stealth_keygen::recover_payment(&alice, &note)
            .expect("recover")
            .expect("ours")
            .payment_public_key,
    );
    let mut funding = h.svm.get_account(&p).expect("authority");
    funding.lamports = 1;
    h.svm.set_account(p, funding).expect("set");
    let error = sweep::sweep(
        &mut SvmChain::new(&mut h.svm),
        &alice,
        &announcement,
        &SweepOptions::default(),
    )
    .expect_err("underfunded");
    assert!(matches!(error, SweepError::Underfunded { short, .. } if short > 0));
    assert!(h.svm.get_account(&account).is_some());
}

#[test]
fn sweep_burns_public_dust_and_handles_a_prefunded_destination() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, account, _) = fund(&mut h, &alice, 3);
    let r = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect("scan")[0].ephemeral;
    let seed = alice.derive_sweep_destination(&r).expect("seed");
    let owner = solana_keypair::Keypair::new_from_array(*seed.as_bytes());
    let d = sweep::destination_address(&owner.pubkey());
    let mint_to = spl_token_2022_interface::instruction::mint_to(
        &token_2022(),
        &h.mint,
        &account,
        &h.mint_authority.pubkey(),
        &[],
        17,
    )
    .expect("dust");
    let authority = h.mint_authority.insecure_clone();
    let prefund = h.svm.minimum_balance_for_rent_exemption(0);
    h.send(
        &[
            mint_to,
            solana_system_interface::instruction::transfer(&h.payer.pubkey(), &d, prefund),
        ],
        &[&authority],
    )
    .expect("dust and prefund");
    let mut chain = SvmChain::new(&mut h.svm);
    chain.finalized_missing_until_send = Some(account);
    let report = sweep::sweep(
        &mut chain,
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("sweep");
    assert_eq!(report.destination, d);
    assert!(report.reclaimed);
    assert!(h.svm.get_account(&account).is_none_or(|a| a.lamports == 0));
}

#[test]
fn sweep_can_finish_when_cpi_guard_blocks_reclaim() {
    use scope_client::sweep::{self, SweepOptions};
    use spl_token_2022_interface::extension::cpi_guard::CpiGuard;
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, account, _) = fund(&mut h, &alice, 3);
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
        ExtensionType::CpiGuard,
    ])
    .expect("space");
    let mut source = h.svm.get_account(&account).expect("source");
    source.data.resize(space, 0);
    source.lamports = h.svm.minimum_balance_for_rent_exemption(space);
    StateWithExtensionsMut::<Account>::unpack(&mut source.data)
        .expect("unpack")
        .init_extension::<CpiGuard>(true)
        .expect("guard")
        .lock_cpi = true.into();
    h.svm.set_account(account, source).expect("set");
    let report = sweep::sweep(
        &mut SvmChain::new(&mut h.svm),
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("fallback sweep");
    assert!(!report.reclaimed);
    assert!(h.svm.get_account(&announcement).is_some());
    let source = h.svm.get_account(&account).expect("source remains");
    let state = StateWithExtensions::<Account>::unpack(&source.data).expect("unpack");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    assert_eq!(ext.available_balance.0, [0; 64]);
    assert_eq!(ext.pending_balance_lo.0, [0; 64]);
    assert_eq!(ext.pending_balance_hi.0, [0; 64]);
}

#[test]
fn sweep_builds_proofs_for_the_mint_auditor() {
    use scope_client::sweep::{self, SweepOptions};
    let auditor = ElGamalKeypair::new_rand();
    let mut h = Harness::with_auditor(Some(auditor.pubkey()));
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let report = sweep::sweep(
        &mut SvmChain::new(&mut h.svm),
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("audited sweep");
    assert_eq!(report.amount, AMOUNT);
    assert!(report.reclaimed);
}
