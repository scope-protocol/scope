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
    fund_amount(h, recipient, r, AMOUNT)
}

fn fund_amount(
    h: &mut Harness,
    recipient: &RecipientSecretKeys,
    r: u8,
    amount: u64,
) -> (Address, Address, AeKey) {
    let (ixs, announcement, account, ae) = payment_instructions(h, recipient, r, amount);
    h.send(&ixs, &[]).expect("payer transaction");
    h.source_balance -= amount;
    (announcement, account, ae)
}

fn payment_instructions(
    h: &Harness,
    recipient: &RecipientSecretKeys,
    r: u8,
    amount: u64,
) -> (
    Vec<solana_instruction::Instruction>,
    Address,
    Address,
    AeKey,
) {
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
    ixs.extend(transfer(h, account, keys.pubkey(), amount));
    (ixs, announcement, account, ae)
}

fn transfer(
    h: &Harness,
    destination: Address,
    elgamal: &solana_zk_sdk::encryption::elgamal::ElGamalPubkey,
    amount: u64,
) -> Vec<solana_instruction::Instruction> {
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
        amount,
        &h.source_elgamal,
        &h.source_ae,
        elgamal,
        auditor.as_ref(),
    )
    .expect("proofs");
    ct::transfer(
        &token_2022(),
        &h.source,
        &h.mint,
        &destination,
        &h.source_ae.encrypt(h.source_balance - amount).into(),
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
        &h.payer.pubkey(),
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
    .expect("transfer")
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

fn enable_cpi_guard(h: &mut Harness, address: Address) {
    use spl_token_2022_interface::extension::cpi_guard::CpiGuard;
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
        ExtensionType::CpiGuard,
    ])
    .expect("space");
    let mut source = h.svm.get_account(&address).expect("source");
    source.data.resize(space, 0);
    source.lamports = h.svm.minimum_balance_for_rent_exemption(space);
    StateWithExtensionsMut::<Account>::unpack(&mut source.data)
        .expect("unpack")
        .init_extension::<CpiGuard>(true)
        .expect("guard")
        .lock_cpi = true.into();
    h.svm.set_account(address, source).expect("set");
}

/// Asserts that `destination` holds `amount` as an applied, available balance and no pending credit.
fn assert_available(
    svm: &litesvm::LiteSVM,
    destination: &Address,
    owner: &solana_keypair::Keypair,
    amount: u64,
) {
    let (keys, ae) = solana_zk_sdk::encryption::derivation::derive_confidential_keys(owner, b"")
        .expect("destination keys");
    let account = svm.get_account(destination).expect("destination");
    let state = StateWithExtensions::<Account>::unpack(&account.data).expect("account");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("extension");
    let available: ElGamalCiphertext = ext.available_balance.try_into().expect("available");
    assert_eq!(
        keys.secret().decrypt(&available).target,
        solana_zk_sdk::encryption::pedersen::G * curve25519_dalek::scalar::Scalar::from(amount)
    );
    assert_eq!(
        ae.decrypt(&ext.decryptable_available_balance.try_into().expect("hint")),
        Some(amount)
    );
    assert_eq!(ext.pending_balance_lo.0, [0; 64]);
    assert_eq!(ext.pending_balance_hi.0, [0; 64]);
    assert_eq!(u64::from(ext.pending_balance_credit_counter), 0);
}

#[test]
fn scan_recovers_backed_up_recipient_and_ignores_other_payments() {
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, account, _) = fund(&mut h, &alice, 3);
    fund(&mut h, &recipient(7), 4);
    let restored = RecipientSecretKeys::from_bytes(*alice.export().as_bytes()).expect("restore");
    let chain = SvmChain::new(&mut h.svm);
    let report = scan::scan(&chain, &restored, None).expect("scan");
    assert!(report.skipped.is_empty());
    let found = report.payments;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].announcement, announcement);
    assert_eq!(found[0].token_account, account);
    assert_eq!(found[0].amount, AMOUNT);
    assert!(
        scan::scan(&chain, &restored, Some(&Address::default()))
            .expect("filter")
            .payments
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
    let report = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect("scan");
    assert!(report.payments.is_empty());
    assert!(
        matches!(report.skipped.as_slice(), [ScanError::Invalid { why, .. }] if why.contains("disagrees"))
    );
    edit_source(&mut h, account, |ext| {
        ext.decryptable_available_balance = ae.encrypt(0).into();
        ext.elgamal_pubkey = (*ElGamalKeypair::new_rand().pubkey()).into();
    });
    let report = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect("scan");
    assert!(report.payments.is_empty());
    assert!(
        matches!(report.skipped.as_slice(), [ScanError::Invalid { why, .. }] if why.contains("ElGamal"))
    );
}

#[test]
fn scan_skips_mismatched_elgamal_keys_without_blocking_valid_payments() {
    let mut h = Harness::new();
    let alice = recipient(1);
    let (first, _, _) = fund(&mut h, &alice, 3);
    let attacker = solana_keypair::Keypair::new();
    h.svm
        .airdrop(&attacker.pubkey(), 1_000_000_000)
        .expect("airdrop");
    let sent = derive_payment_with_ephemeral(
        &alice.derive_public_keys(),
        &EphemeralSecret::from_bytes([5; 32]),
    )
    .expect("payment");
    let ephemeral = sent.announcement.ephemeral_public_key;
    let account = token_account_address(&attacker.pubkey(), &ephemeral);
    let (announcement, _) = announcement_address(&account);
    let keys = ElGamalKeypair::new_rand();
    let ae = AeKey::new_rand();
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])
    .expect("space");
    let ixs = stealth_setup(&StealthSetup {
        payer: attacker.pubkey(),
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
    let tx = scope_client::tx::v1_transaction(&attacker, &[], &ixs, h.svm.latest_blockhash());
    assert_eq!(tx.signatures.len(), 1);
    h.svm.send_transaction(tx).expect("attacker announcement");
    h.svm.expire_blockhash();
    let (second, _, _) = fund(&mut h, &alice, 4);
    let mut expected = vec![first, second];
    expected.sort_unstable();
    let mut chain = SvmChain::new(&mut h.svm);
    for mint in [None, Some(h.mint)] {
        let report = scan::scan(&chain, &alice, mint.as_ref()).expect("scan");
        assert_eq!(
            report
                .payments
                .iter()
                .map(|p| p.announcement)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(report.payments.iter().all(|p| p.amount == AMOUNT));
        assert!(
            matches!(report.skipped.as_slice(), [ScanError::Invalid { account: a, why }]
            if *a == account && why.contains("ElGamal"))
        );
    }
    let error = scope_client::sweep::sweep(
        &mut chain,
        &alice,
        &announcement,
        &scope_client::sweep::SweepOptions::default(),
    )
    .expect_err("invalid payment cannot be swept");
    assert!(matches!(
        error,
        scope_client::sweep::SweepError::Scan(ScanError::Invalid { .. })
    ));
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
            .payments
            .is_empty()
    );
    account.data[3] ^= 1;
    account.data[4..36].fill(0);
    h.svm.set_account(announcement, account).expect("set");
    assert!(
        scan::scan(&SvmChain::new(&mut h.svm), &alice, None)
            .expect("scan")
            .payments
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
    assert_eq!(report.reclaimed, Some(true));
    assert_eq!(report.amount, AMOUNT);
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
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
        .derive_sweep_destination(&report.ephemeral, &report.token_account.to_bytes())
        .expect("seed");
    let owner = solana_keypair::Keypair::new_from_array(*seed.as_bytes());
    let destination = h.svm.get_account(&report.destination).expect("destination");
    let state = StateWithExtensions::<Account>::unpack(&destination.data).expect("account");
    assert_eq!(state.base.owner, report.destination_owner);
    assert_available(&h.svm, &report.destination, &owner, AMOUNT);
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
    let prepared = sweep::prepare(
        &SvmChain::new(&mut h.svm),
        &alice,
        &announcement,
        &SweepOptions::default(),
    )
    .expect("prepare without sending");
    let report = sweep::submit(&mut SvmChain::new(&mut h.svm), prepared, &opts)
        .expect("submission honors dry run");
    assert!(report.dry_run);
    assert!(h.svm.get_account(&report.destination).is_none());
    let public = scan::scan(&SvmChain::new(&mut h.svm), &alice, None)
        .expect("scan")
        .payments;
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
    let found = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect("scan");
    let r = found.payments[0].ephemeral;
    let seed = alice
        .derive_sweep_destination(&r, &found.payments[0].token_account.to_bytes())
        .expect("seed");
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
    assert_eq!(report.reclaimed, Some(true));
    assert!(h.svm.get_account(&account).is_none_or(|a| a.lamports == 0));
}

#[test]
fn sweep_can_finish_when_cpi_guard_blocks_reclaim() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, account, _) = fund(&mut h, &alice, 3);
    enable_cpi_guard(&mut h, account);
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
    assert_eq!(report.reclaimed, Some(false));
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
    assert_eq!(report.reclaimed, Some(true));
}

#[test]
fn sweep_preserves_recovery_details_when_rpc_fails_after_send() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, account, _) = fund(&mut h, &alice, 3);
    let mut chain = SvmChain::new(&mut h.svm);
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    let recovery = prepared.report().clone();
    assert!(chain.svm.get_account(&recovery.destination).is_none());
    assert!(chain.svm.get_account(&account).is_some());
    chain.fail_status_after_send = true;
    let error = sweep::submit(&mut chain, prepared, &opts).expect_err("RPC failure");
    assert!(
        error
            .to_string()
            .contains(&Address::new_from_array(recovery.ephemeral).to_string())
    );
    let SweepError::Interrupted { report, .. } = error else {
        panic!("missing recovery report")
    };
    assert_eq!(report.destination, recovery.destination);
    assert_eq!(report.destination_owner, recovery.destination_owner);
    assert_eq!(report.ephemeral, recovery.ephemeral);
    assert_eq!(report.attempt_signature, recovery.attempt_signature);
    assert!(chain.svm.get_account(&announcement).is_none());
    assert!(chain.svm.get_account(&report.destination).is_some());
    let seed = alice
        .derive_sweep_destination(&report.ephemeral, &report.token_account.to_bytes())
        .expect("seed");
    assert_eq!(
        solana_keypair::Keypair::new_from_array(*seed.as_bytes()).pubkey(),
        report.destination_owner
    );
    assert!(
        matches!(sweep::sweep(&mut chain, &alice, &announcement, &opts),
        Err(SweepError::Invalid(why)) if why.contains("not found"))
    );
}

#[test]
fn sweep_timeout_preserves_recovery_details_after_execution() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let mut chain = SvmChain::new(&mut h.svm);
    chain.lag_finalized_reads = true;
    chain.lag_finalized_status = true;
    let error = sweep::sweep(
        &mut chain,
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect_err("pending");
    let SweepError::Pending { report } = error else {
        panic!("missing recovery report")
    };
    assert!(!report.attempt_signature.is_empty());
    assert!(chain.svm.get_account(&announcement).is_none());
    assert!(chain.svm.get_account(&report.destination).is_some());
    let seed = alice
        .derive_sweep_destination(&report.ephemeral, &report.token_account.to_bytes())
        .expect("seed");
    assert_eq!(
        solana_keypair::Keypair::new_from_array(*seed.as_bytes()).pubkey(),
        report.destination_owner
    );
}

#[test]
fn sweep_survives_a_credit_to_the_authority_after_simulation() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let minimum = h.svm.minimum_balance_for_rent_exemption(0);
    let sender = h.payer.insecure_clone();
    let mut chain = SvmChain::new(&mut h.svm);
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    let credit = solana_system_interface::instruction::transfer(
        &sender.pubkey(),
        &prepared.report().payment_authority,
        1,
    );
    chain.before_send = Some(scope_client::tx::v1_transaction(
        &sender,
        &[],
        &[credit],
        chain.svm.latest_blockhash(),
    ));
    let report = sweep::submit(&mut chain, prepared, &opts).expect("sweep after credit");
    assert_eq!(report.reclaimed, Some(true));
    assert_eq!(report.amount, AMOUNT);
    assert_eq!(report.retained_lamports, Some(minimum + 1));
}

fn sweep_requirement(h: &Harness) -> u64 {
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])
    .expect("space");
    h.svm.minimum_balance_for_rent_exemption(space)
        + 10_000
        + h.svm.minimum_balance_for_rent_exemption(0)
}

fn set_funding(h: &mut Harness, authority: Address, amount: u64) {
    let mut account = h.svm.get_account(&authority).expect("authority");
    account.lamports = amount;
    h.svm.set_account(authority, account).expect("funding");
}

#[test]
fn sweep_funding_boundaries_include_the_reserve_and_quote_exact_shortages() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let authority = sweep::prepare(&SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect("prepare")
        .report()
        .payment_authority;
    let need = sweep_requirement(&h);
    let minimum = h.svm.minimum_balance_for_rent_exemption(0);
    set_funding(&mut h, authority, need - 1);
    let error = sweep::prepare(&SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect_err("one lamport short");
    assert!(
        matches!(error, SweepError::Underfunded { need: quoted, short: 1, .. } if quoted == need)
    );
    for surplus in [0, 1, minimum - 1, minimum] {
        set_funding(&mut h, authority, need + surplus);
        let prepared = sweep::prepare(&SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
            .expect("simulation at funding boundary");
        let retained = if surplus < minimum {
            minimum + surplus
        } else {
            minimum
        };
        assert_eq!(prepared.report().retained_lamports, Some(retained));
        assert!(h.svm.get_account(&prepared.report().destination).is_none());
    }
    set_funding(&mut h, authority, need);
    let report = sweep::sweep(&mut SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect("exact funding succeeds");
    assert_eq!(report.retained_lamports, Some(minimum));
    assert_eq!(report.reclaimed, Some(true));
}

#[test]
fn sweep_transfers_a_small_surplus_to_an_already_funded_owner() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let recovery = sweep::prepare(&SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect("prepare")
        .report()
        .clone();
    let minimum = h.svm.minimum_balance_for_rent_exemption(0);
    h.svm
        .airdrop(&recovery.destination_owner, minimum)
        .expect("fund owner");
    let need = sweep_requirement(&h);
    set_funding(&mut h, recovery.payment_authority, need + 1);
    let report = sweep::sweep(&mut SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect("small surplus");
    assert_eq!(report.retained_lamports, Some(minimum));
    assert_eq!(
        h.svm
            .get_account(&report.destination_owner)
            .expect("owner")
            .lamports,
        minimum + 1
    );
}

#[test]
fn sweep_moves_confidential_funds_when_permissioned_burning_blocks_cleanup() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::with_permissioned_burn();
    let alice = recipient(1);
    let (announcement, source, _) = fund(&mut h, &alice, 3);
    let issuer = h.mint_authority.insecure_clone();
    let dust = spl_token_2022_interface::instruction::mint_to(
        &token_2022(),
        &h.mint,
        &source,
        &issuer.pubkey(),
        &[],
        17,
    )
    .expect("dust");
    h.send(&[dust], &[&issuer]).expect("mint dust");
    let report = sweep::sweep(
        &mut SvmChain::new(&mut h.svm),
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("transfer-only fallback");
    assert_eq!(report.reclaimed, Some(false));
    assert_eq!(report.burned_public_amount, Some(0));
    assert_eq!(report.public_amount_remaining, Some(17));
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
    let source_account = h.svm.get_account(&source).expect("source remains");
    let state = StateWithExtensions::<Account>::unpack(&source_account.data).expect("source state");
    assert_eq!(state.base.amount, 17);
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("extension");
    assert_eq!(ext.available_balance.0, [0; 64]);
    assert_eq!(ext.pending_balance_lo.0, [0; 64]);
    assert_eq!(ext.pending_balance_hi.0, [0; 64]);
    assert!(!bool::from(ext.allow_confidential_credits));
    let elgamal = ext.elgamal_pubkey.try_into().expect("key");
    let second_credit = transfer(&h, source, &elgamal, 42);
    let failed = h
        .send(&second_credit, &[])
        .expect_err("retired source rejects credits");
    assert!(matches!(
        failed.err,
        solana_transaction_error::TransactionError::InstructionError(
            _, solana_instruction_error::InstructionError::Custom(code)
        ) if code == spl_token_2022_interface::error::TokenError::ConfidentialTransferDepositsAndTransfersDisabled as u32
    ));
    let seed = alice
        .derive_sweep_destination(&report.ephemeral, &report.token_account.to_bytes())
        .expect("seed");
    let owner = solana_keypair::Keypair::new_from_array(*seed.as_bytes());
    assert_available(&h.svm, &report.destination, &owner, AMOUNT);
}

#[test]
fn concurrent_sweep_completion_does_not_claim_an_unexecuted_signature() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let mut chain = SvmChain::new(&mut h.svm);
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let first = sweep::prepare(&chain, &alice, &announcement, &opts).expect("first attempt");
    let winner = first.transaction().clone();
    chain.before_send = Some(winner.clone());
    let second = sweep::prepare(&chain, &alice, &announcement, &opts).expect("second attempt");
    let attempted = second.report().attempt_signature.clone();
    assert_ne!(attempted, first.report().attempt_signature);
    let report = sweep::submit(&mut chain, second, &opts).expect("observes completed payment");
    assert_eq!(report.reclaimed, Some(true));
    assert_eq!(report.attempt_signature, attempted);
    assert_eq!(report.finalized_signature, None);
    assert_eq!(report.burned_public_amount, None);
    assert!(
        chain
            .svm
            .get_transaction(&winner.signatures[0])
            .expect("winner history")
            .is_ok()
    );
}

fn mint_dust(h: &Harness, source: Address, amount: u64) -> solana_instruction::Instruction {
    spl_token_2022_interface::instruction::mint_to(
        &token_2022(),
        &h.mint,
        &source,
        &h.mint_authority.pubkey(),
        &[],
        amount,
    )
    .expect("dust")
}

#[test]
fn sweep_retries_without_cleanup_after_a_finalized_dust_failure() {
    use scope_client::sweep::{self, SweepOptions};
    for existing_dust in [0, 17] {
        let mut h = Harness::new();
        let alice = recipient(1);
        let (announcement, source, _) = fund(&mut h, &alice, 3);
        if existing_dust > 0 {
            h.send(
                &[mint_dust(&h, source, existing_dust)],
                &[&h.mint_authority.insecure_clone()],
            )
            .expect("initial dust");
        }
        let dust = scope_client::tx::v1_transaction(
            &h.payer,
            &[&h.mint_authority],
            &[mint_dust(&h, source, 17)],
            h.svm.latest_blockhash(),
        );
        let opts = SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        };
        let mut chain = SvmChain::new(&mut h.svm);
        let prepared =
            sweep::prepare(&chain, &alice, &announcement, &opts).expect("full simulation");
        assert_eq!(prepared.report().reclaimed, Some(true));
        let signature = prepared.transaction().signatures[0];
        let recovery = prepared.report().clone();
        chain.before_send = Some(dust);
        chain.failed_status_lag.set(1);
        let report = sweep::submit(&mut chain, prepared, &opts).expect("fallback after failure");
        assert_eq!(chain.sent_signatures.len(), 3);
        assert_eq!(chain.sent_signatures[..2], [signature; 2]);
        assert_ne!(chain.sent_signatures[2], signature);
        assert!(
            chain
                .svm
                .get_transaction(&signature)
                .expect("original")
                .is_err()
        );
        assert_eq!(
            report.finalized_signature.as_ref(),
            Some(&report.attempt_signature)
        );
        assert_eq!(report.reclaimed, Some(false));
        assert_eq!(report.burned_public_amount, Some(0));
        assert_eq!(report.public_amount_remaining, Some(existing_dust + 17));
        assert_eq!(report.destination_owner, recovery.destination_owner);
        assert_eq!(report.ephemeral, recovery.ephemeral);
        assert!(chain.svm.get_account(&report.destination).is_some());
        let account = chain.svm.get_account(&source).expect("source remains");
        let state = StateWithExtensions::<Account>::unpack(&account.data).expect("state");
        let ext = state
            .get_extension::<ConfidentialTransferAccount>()
            .expect("ct");
        assert_eq!(ext.available_balance.0, [0; 64]);
        assert_eq!(ext.pending_balance_lo.0, [0; 64]);
        assert_eq!(ext.pending_balance_hi.0, [0; 64]);
        assert!(!bool::from(ext.allow_confidential_credits));
    }
}

#[test]
fn sweep_retries_without_cleanup_only_after_an_unknown_attempt_expires() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, source, _) = fund(&mut h, &alice, 3);
    let dust = scope_client::tx::v1_transaction(
        &h.payer,
        &[&h.mint_authority],
        &[mint_dust(&h, source, 17)],
        h.svm.latest_blockhash(),
    );
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let mut chain = SvmChain::new(&mut h.svm);
    chain.drop_sends = 3;
    chain.before_send = Some(dust);
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    let signature = prepared.transaction().signatures[0];
    let report = sweep::submit(&mut chain, prepared, &opts).expect("retry after expiry");
    assert_eq!(chain.sent_signatures.len(), 4);
    assert_eq!(chain.sent_signatures[..3], [signature; 3]);
    assert_ne!(chain.sent_signatures[3], signature);
    assert!(chain.svm.get_transaction(&signature).is_none());
    assert_eq!(report.reclaimed, Some(false));
    assert_eq!(report.public_amount_remaining, Some(17));
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
}

#[test]
fn sweep_retry_rechecks_funding_after_a_failed_attempt_charges_fees() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, source, _) = fund(&mut h, &alice, 3);
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let recovery = sweep::prepare(&SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect("prepare")
        .report()
        .clone();
    let need = sweep_requirement(&h);
    set_funding(&mut h, recovery.payment_authority, need);
    let dust = scope_client::tx::v1_transaction(
        &h.payer,
        &[&h.mint_authority],
        &[mint_dust(&h, source, 17)],
        h.svm.latest_blockhash(),
    );
    let mut chain = SvmChain::new(&mut h.svm);
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("exact funding");
    chain.before_send = Some(dust);
    let error = sweep::submit(&mut chain, prepared, &opts).expect_err("retry funding shortage");
    let SweepError::Interrupted {
        report,
        source: cause,
    } = error
    else {
        panic!("recovery missing")
    };
    assert!(matches!(
        *cause,
        SweepError::Underfunded { short: 10_000, .. }
    ));
    assert_eq!(report.ephemeral, recovery.ephemeral);
    assert_eq!(report.destination_owner, recovery.destination_owner);
    assert_eq!(chain.sent_signatures.len(), 1);
    assert!(chain.svm.get_account(&source).is_some());
    assert!(chain.svm.get_account(&report.destination).is_none());
}

#[test]
fn sweep_deadline_prevents_late_sends_and_caps_poll_sleeps() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    use std::time::{Duration, Instant};
    for (timeout, height_delay, sends) in [
        (Duration::ZERO, Duration::ZERO, 0),
        (Duration::from_millis(25), Duration::from_millis(150), 0),
        (Duration::from_millis(50), Duration::ZERO, 1),
    ] {
        let mut h = Harness::new();
        let alice = recipient(1);
        let (announcement, source, _) = fund(&mut h, &alice, 3);
        let opts = SweepOptions {
            timeout,
            poll: Duration::from_secs(10),
            ..Default::default()
        };
        let mut chain = SvmChain::new(&mut h.svm);
        let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
        let recovery = prepared.report().clone();
        chain.height_delay = height_delay;
        chain.drop_sends = usize::MAX;
        let start = Instant::now();
        let error = sweep::submit(&mut chain, prepared, &opts).expect_err("deadline");
        assert!(start.elapsed() < Duration::from_millis(500));
        let SweepError::Pending { report } = error else {
            panic!("recovery missing")
        };
        assert_eq!(report.destination_owner, recovery.destination_owner);
        assert_eq!(report.ephemeral, recovery.ephemeral);
        assert_eq!(chain.sent_signatures.len(), sends);
        assert!(chain.svm.get_account(&report.destination).is_none());
        assert!(chain.svm.get_account(&source).is_some());
    }
}

#[test]
fn finalized_sweep_proves_completion_despite_lagging_account_reads() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let mut chain = SvmChain::new(&mut h.svm);
    chain.lag_finalized_reads = true;
    let opts = SweepOptions {
        timeout: std::time::Duration::from_secs(2),
        poll: std::time::Duration::from_millis(5),
        ..Default::default()
    };
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    let signature = prepared.transaction().signatures[0];
    let report = sweep::submit(&mut chain, prepared, &opts)
        .expect("finalized transaction proves completion");
    assert_eq!(chain.sent_signatures, [signature]);
    assert_eq!(report.attempt_signature, signature.to_string());
    assert_eq!(report.finalized_signature, Some(signature.to_string()));
    assert!(
        chain
            .svm
            .get_transaction(&signature)
            .expect("finalized")
            .is_ok()
    );
    assert!(chain.svm.get_account(&report.destination).is_some());
}

#[test]
fn sweep_accepts_destination_prefunding_after_simulation() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let donor = h.payer.insecure_clone();
    let prefund = h.svm.minimum_balance_for_rent_exemption(0);
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let mut chain = SvmChain::new(&mut h.svm);
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    chain.before_send = Some(scope_client::tx::v1_transaction(
        &donor,
        &[],
        &[solana_system_interface::instruction::transfer(
            &donor.pubkey(),
            &prepared.report().destination,
            prefund,
        )],
        chain.svm.latest_blockhash(),
    ));
    let report = sweep::submit(&mut chain, prepared, &opts).expect("late prefund");
    assert_eq!(report.reclaimed, Some(true));
    assert_eq!(chain.sent_signatures.len(), 1);
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
}

#[test]
fn sweep_retry_refreshes_destination_rent_after_prefunding() {
    use scope_client::sweep::{self, SweepOptions};
    for fully_funded in [false, true] {
        let mut h = Harness::new();
        let alice = recipient(1);
        let (announcement, source, _) = fund(&mut h, &alice, 3);
        let donor = h.payer.insecure_clone();
        let issuer = h.mint_authority.insecure_clone();
        let space = ExtensionType::try_calculate_account_len::<Account>(&[
            ExtensionType::ConfidentialTransferAccount,
        ])
        .expect("space");
        let rent = h.svm.minimum_balance_for_rent_exemption(space);
        let prefund = if fully_funded {
            rent
        } else {
            h.svm.minimum_balance_for_rent_exemption(0)
        };
        let dust = mint_dust(&h, source, 17);
        let opts = SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        };
        let mut chain = SvmChain::new(&mut h.svm);
        let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
        chain.before_send = Some(scope_client::tx::v1_transaction(
            &donor,
            &[&issuer],
            &[
                dust,
                solana_system_interface::instruction::transfer(
                    &donor.pubkey(),
                    &prepared.report().destination,
                    prefund,
                ),
            ],
            chain.svm.latest_blockhash(),
        ));
        let report = sweep::submit(&mut chain, prepared, &opts).expect("fresh destination funding");
        assert_eq!(report.reclaimed, Some(false));
        assert_eq!(report.public_amount_remaining, Some(17));
        assert_eq!(chain.sent_signatures.len(), 2);
        assert_eq!(
            chain
                .svm
                .get_account(&report.destination)
                .expect("destination")
                .lamports,
            rent
        );
        assert_eq!(
            report.finalized_signature.as_ref(),
            Some(&report.attempt_signature)
        );
    }
}

#[test]
fn sweep_reports_success_when_closed_addresses_are_refunded() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, source, _) = fund(&mut h, &alice, 3);
    let donor = h.payer.insecure_clone();
    let rent = h.svm.minimum_balance_for_rent_exemption(0);
    let refund = scope_client::tx::v1_transaction(
        &donor,
        &[],
        &[
            solana_system_interface::instruction::transfer(&donor.pubkey(), &source, rent),
            solana_system_interface::instruction::transfer(&donor.pubkey(), &announcement, rent),
        ],
        h.svm.latest_blockhash(),
    );
    let mut chain = SvmChain::new(&mut h.svm);
    chain.after_send = Some(refund);
    let report = sweep::sweep(
        &mut chain,
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("refunded closed addresses");
    assert_eq!(report.reclaimed, Some(true));
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
    for address in [source, announcement] {
        let account = chain.svm.get_account(&address).expect("System placeholder");
        assert_eq!(account.owner, Address::default());
        assert!(account.data.is_empty());
        assert_eq!(account.lamports, rent);
    }
}

#[test]
fn recovery_is_checkpointed_for_each_attempt_and_flush_failure_stops_sends() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    for failed_checkpoint in [None, Some(1), Some(2)] {
        let mut h = Harness::new();
        let alice = recipient(1);
        let (announcement, source, _) = fund(&mut h, &alice, 3);
        let dust = scope_client::tx::v1_transaction(
            &h.payer,
            &[&h.mint_authority],
            &[mint_dust(&h, source, 17)],
            h.svm.latest_blockhash(),
        );
        let mut chain = SvmChain::new(&mut h.svm);
        chain.before_send = Some(dust);
        let opts = SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        };
        let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
        let recovery = prepared.report().clone();
        let mut checkpoints = Vec::new();
        let result = sweep::submit_with_recovery(&mut chain, prepared, &opts, |report| {
            assert_eq!(report.destination_owner, recovery.destination_owner);
            assert_eq!(report.ephemeral, recovery.ephemeral);
            checkpoints.push(report.attempt_signature.clone());
            if failed_checkpoint == Some(checkpoints.len()) {
                Err(std::io::Error::other("flush failed"))
            } else {
                Ok(())
            }
        });
        match failed_checkpoint {
            None => {
                let report = result.expect("sweep");
                assert_eq!(checkpoints.len(), 2);
                assert_ne!(checkpoints[0], checkpoints[1]);
                assert_eq!(checkpoints[1], report.attempt_signature);
                assert_eq!(report.finalized_signature.as_ref(), Some(&checkpoints[1]));
            }
            Some(n) => {
                let SweepError::RecoveryOutput { report, .. } = result.expect_err("output failed")
                else {
                    panic!("missing recovery")
                };
                assert_eq!(checkpoints.len(), n);
                assert_eq!(chain.sent_signatures.len(), n - 1);
                assert_eq!(report.attempt_signature, checkpoints[n - 1]);
                assert!(chain.svm.get_account(&report.destination).is_none());
            }
        }
        for (sent, checkpoint) in chain.sent_signatures.iter().zip(&checkpoints) {
            assert_eq!(sent.to_string(), *checkpoint);
        }
    }
}

#[test]
fn scan_and_sweep_support_large_pending_balances() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let maximum =
        spl_token_2022_interface::extension::confidential_transfer::MAXIMUM_DEPOSIT_TRANSFER_AMOUNT;
    let issuer = h.mint_authority.insecure_clone();
    let new_balance = h.source_balance + maximum;
    let mint = spl_token_2022_interface::instruction::mint_to(
        &token_2022(),
        &h.mint,
        &h.source,
        &issuer.pubkey(),
        &[],
        maximum,
    )
    .expect("mint");
    let deposit = ct::deposit(
        &token_2022(),
        &h.source,
        &h.mint,
        maximum,
        6,
        &h.payer.pubkey(),
        &[],
    )
    .expect("deposit");
    let apply = ct::apply_pending_balance(
        &token_2022(),
        &h.source,
        1,
        &h.source_ae.encrypt(new_balance).into(),
        &h.payer.pubkey(),
        &[],
    )
    .expect("apply");
    h.send(&[mint, deposit, apply], &[&issuer])
        .expect("fund large balance");
    h.source_balance = new_balance;
    for (r, amount) in [(3, (1 << 32) + 65_535), (4, maximum - (1 << 32) - 65_535)] {
        let (announcement, _, _) = fund_amount(&mut h, &alice, r, amount);
        let mut chain = SvmChain::new(&mut h.svm);
        let found = scan::scan(&chain, &alice, None).expect("scan").payments;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].amount, amount);
        let report = sweep::sweep(
            &mut chain,
            &alice,
            &announcement,
            &SweepOptions {
                poll: std::time::Duration::ZERO,
                ..Default::default()
            },
        )
        .expect("large sweep");
        assert_eq!(report.amount, amount);
        assert_eq!(report.reclaimed, Some(true));
        let seed = alice
            .derive_sweep_destination(&report.ephemeral, &report.token_account.to_bytes())
            .expect("seed");
        let owner = solana_keypair::Keypair::new_from_array(*seed.as_bytes());
        assert_available(chain.svm, &report.destination, &owner, amount);
    }
}

#[test]
fn scan_reports_each_batch_before_the_next_read() {
    let mut h = Harness::new();
    let alice = recipient(1);
    let (first, source, ae) = fund(&mut h, &alice, 3);
    let (second, _, _) = fund(&mut h, &alice, 4);
    edit_source(&mut h, source, |ext| {
        ext.decryptable_available_balance = ae.encrypt(42).into()
    });
    let chain = SvmChain::new(&mut h.svm);
    let mut valid = Vec::new();
    let mut skipped = Vec::new();
    let report = scan::scan_with_results(&chain, &alice, None, |result| {
        assert_eq!(chain.account_batches.get(), 1);
        match result {
            Ok(payment) => valid.push(payment.announcement),
            Err(ScanError::Invalid { account, .. }) => skipped.push(*account),
            Err(other) => panic!("unexpected event: {other}"),
        }
        Ok(())
    })
    .expect("scan");
    assert_eq!(valid, [second]);
    assert_eq!(skipped, [source]);
    assert_eq!(report.payments.len(), 1);
    assert_eq!(report.skipped.len(), 1);
    assert_ne!(first, second);
    chain.account_batches.set(0);
    let error = scan::scan_with_results(&chain, &alice, None, |_| {
        Err(std::io::Error::other("output closed"))
    })
    .expect_err("stop on output error");
    assert!(matches!(error, ScanError::Output(_)));
    assert_eq!(chain.account_batches.get(), 1);
}

#[test]
fn scan_handles_empty_retired_sources_without_changing_their_balances() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::with_permissioned_burn();
    let alice = recipient(1);
    let (announcement, source, _) = fund(&mut h, &alice, 3);
    h.send(
        &[mint_dust(&h, source, 17)],
        &[&h.mint_authority.insecure_clone()],
    )
    .expect("dust");
    let mut chain = SvmChain::new(&mut h.svm);
    sweep::sweep(
        &mut chain,
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("fallback");
    let before = chain.svm.get_account(&source).expect("source");
    let report = scan::scan(&chain, &alice, None).expect("retired source");
    assert_eq!(report.payments.len(), 1);
    assert_eq!(report.payments[0].amount, 0);
    assert_eq!(report.payments[0].public_amount, 17);
    assert_eq!(
        chain.svm.get_account(&source).expect("unchanged").data,
        before.data
    );
}

fn fund_applied(h: &mut Harness, recipient: &RecipientSecretKeys) -> (Address, Address) {
    use spl_token_2022_interface::instruction::{AuthorityType, TokenInstruction};
    let (mut setup, announcement, source, ae) = payment_instructions(h, recipient, 3, AMOUNT);
    let transfer_start = setup.len() - 4;
    let transfer = setup.split_off(transfer_start);
    let handover = setup
        .iter()
        .position(|ix| {
            ix.program_id == token_2022()
                && matches!(
                    TokenInstruction::unpack(&ix.data),
                    Ok(TokenInstruction::SetAuthority {
                        authority_type: AuthorityType::AccountOwner,
                        ..
                    })
                )
        })
        .expect("handover");
    let tail = setup.split_off(handover);
    setup.extend(transfer);
    setup.push(
        ct::apply_pending_balance(
            &token_2022(),
            &source,
            1,
            &ae.encrypt(AMOUNT).into(),
            &h.payer.pubkey(),
            &[],
        )
        .expect("apply before handover"),
    );
    setup.extend(tail);
    h.send(&setup, &[]).expect("applied payment");
    h.source_balance -= AMOUNT;
    (announcement, source)
}

#[test]
fn sweep_retry_refreshes_applied_balances_when_a_new_credit_arrives() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, source) = fund_applied(&mut h, &alice);
    let account = h.svm.get_account(&source).expect("source");
    let state = StateWithExtensions::<Account>::unpack(&account.data).expect("state");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    assert_eq!(u64::from(ext.pending_balance_credit_counter), 0);
    let key = ext.elgamal_pubkey.try_into().expect("key");
    let extra_credit = scope_client::tx::v1_transaction(
        &h.payer,
        &[],
        &transfer(&h, source, &key, 42),
        h.svm.latest_blockhash(),
    );
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let mut chain = SvmChain::new(&mut h.svm);
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    chain.before_send = Some(extra_credit);
    let report = sweep::submit(&mut chain, prepared, &opts).expect("refreshed source proofs");
    assert_eq!(report.amount, AMOUNT + 42);
    assert_eq!(chain.sent_signatures.len(), 2);
    assert_eq!(report.reclaimed, Some(false));
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
    let account = chain.svm.get_account(&source).expect("retired source");
    let state = StateWithExtensions::<Account>::unpack(&account.data).expect("state");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    assert!(!bool::from(ext.allow_confidential_credits));
    assert_eq!(ext.available_balance.0, [0; 64]);
    assert_eq!(ext.pending_balance_lo.0, [0; 64]);
    assert_eq!(ext.pending_balance_hi.0, [0; 64]);
}

#[test]
fn sweep_retry_refreshes_a_changed_mint_auditor() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let auditor = ElGamalKeypair::new_rand();
    let update = ct::update_mint(
        &token_2022(),
        &h.mint,
        &h.mint_authority.pubkey(),
        &[],
        true,
        Some((*auditor.pubkey()).into()),
    )
    .expect("update auditor");
    let update = scope_client::tx::v1_transaction(
        &h.payer,
        &[&h.mint_authority],
        &[update],
        h.svm.latest_blockhash(),
    );
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let mut chain = SvmChain::new(&mut h.svm);
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    chain.before_send = Some(update);
    let report = sweep::submit(&mut chain, prepared, &opts).expect("fresh auditor proofs");
    assert_eq!(report.amount, AMOUNT);
    assert_eq!(chain.sent_signatures.len(), 2);
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
}

#[test]
fn retry_decryption_respects_the_submission_deadline() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    use std::time::{Duration, Instant};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, source, _) = fund(&mut h, &alice, 3);
    let opts = SweepOptions {
        timeout: Duration::from_millis(100),
        poll: Duration::ZERO,
        ..Default::default()
    };
    let mut chain = SvmChain::new(&mut h.svm);
    chain.drop_sends = 3;
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    let signature = prepared.report().attempt_signature.clone();
    let start = Instant::now();
    let error =
        sweep::submit(&mut chain, prepared, &opts).expect_err("retry CPU work exceeds budget");
    assert!(start.elapsed() < Duration::from_secs(1));
    let SweepError::Pending { report } = error else {
        panic!("missing recovery")
    };
    assert_eq!(report.attempt_signature, signature);
    assert_eq!(chain.sent_signatures.len(), 3);
    assert!(chain.svm.get_account(&source).is_some());
    assert!(chain.svm.get_account(&report.destination).is_none());
}

#[test]
fn bounded_retries_cover_cleanup_and_subsequent_credit_races() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, source) = fund_applied(&mut h, &alice);
    let account = h.svm.get_account(&source).expect("source");
    let state = StateWithExtensions::<Account>::unpack(&account.data).expect("state");
    let key = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct")
        .elgamal_pubkey
        .try_into()
        .expect("key");
    let credit = transfer(&h, source, &key, 42);
    let dust = mint_dust(&h, source, 17);
    let donor = h.payer.insecure_clone();
    let issuer = h.mint_authority.insecure_clone();
    let mut calls = 0;
    let mut chain = SvmChain::new(&mut h.svm);
    chain.before_send_hook = Some(Box::new(move |svm, _| {
        calls += 1;
        let tx = match calls {
            1 => scope_client::tx::v1_transaction(
                &donor,
                &[&issuer],
                std::slice::from_ref(&dust),
                svm.latest_blockhash(),
            ),
            2 => scope_client::tx::v1_transaction(&donor, &[], &credit, svm.latest_blockhash()),
            _ => return,
        };
        svm.send_transaction(tx).expect("racing transaction");
    }));
    let report = sweep::sweep(
        &mut chain,
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("both races resolved");
    assert_eq!(chain.sent_signatures.len(), 3);
    assert_eq!(report.amount, AMOUNT + 42);
    assert_eq!(report.public_amount_remaining, Some(17));
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
    assert_eq!(report.reclaimed, Some(false));
}

#[test]
fn completed_sweep_remains_successful_if_the_payer_recreates_the_source() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, source, _) = fund(&mut h, &alice, 3);
    let (replay, replay_announcement, replay_source, _) = payment_instructions(&h, &alice, 3, 42);
    assert_eq!((replay_announcement, replay_source), (announcement, source));
    let replay = scope_client::tx::v1_transaction(&h.payer, &[], &replay, h.svm.latest_blockhash());
    let mut chain = SvmChain::new(&mut h.svm);
    chain.after_send = Some(replay);
    let report = sweep::sweep(
        &mut chain,
        &alice,
        &announcement,
        &SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("immutable finalized proof");
    assert_eq!(report.amount, AMOUNT);
    assert_eq!(report.reclaimed, Some(true));
    assert_eq!(
        report.finalized_signature.as_ref(),
        Some(&report.attempt_signature)
    );
    let payments = scan::scan(&chain, &alice, None)
        .expect("recreated payment")
        .payments;
    assert_eq!(payments[0].amount, 42);
    assert!(chain.svm.get_account(&announcement).is_some());
    assert!(chain.svm.get_account(&report.destination).is_some());
}

#[test]
fn sweep_refuses_a_mint_that_now_requires_destination_approval() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let issuer = h.mint_authority.insecure_clone();
    let update = ct::update_mint(&token_2022(), &h.mint, &issuer.pubkey(), &[], false, None)
        .expect("update policy");
    h.send(&[update], &[&issuer]).expect("require approval");
    let mut chain = SvmChain::new(&mut h.svm);
    let error = sweep::sweep(&mut chain, &alice, &announcement, &SweepOptions::default())
        .expect_err("unsupported mint");
    assert!(matches!(error, SweepError::Invalid(why) if why.contains("requires approval")));
    assert!(chain.sent_signatures.is_empty());
}

#[test]
fn full_recipient_transaction_fits_the_v1_wire_and_compute_budgets() {
    use scope_client::{
        sweep::{self, SweepOptions},
        tx::{SWEEP_CU_LIMIT, v1_wire_size},
    };
    let auditor = ElGamalKeypair::new_rand();
    let mut h = Harness::with_auditor(Some(auditor.pubkey()));
    let alice = recipient(1);
    let (announcement, source, _) = fund(&mut h, &alice, 3);
    h.send(
        &[mint_dust(&h, source, 17)],
        &[&h.mint_authority.insecure_clone()],
    )
    .expect("dust");
    let chain = SvmChain::new(&mut h.svm);
    let prepared =
        sweep::prepare(&chain, &alice, &announcement, &SweepOptions::default()).expect("prepare");
    assert_eq!(prepared.report().reclaimed, Some(true));
    let transaction = prepared.transaction();
    let bytes = wincode::serialize(transaction).expect("wire encoding");
    assert_eq!(bytes.len(), v1_wire_size(transaction));
    assert!(bytes.len() <= 4_096);
    for (signature, key) in transaction
        .signatures
        .iter()
        .zip(transaction.message.static_account_keys())
    {
        assert!(signature.verify(key.as_ref(), &transaction.message.serialize()));
    }
    let simulation = chain
        .svm
        .simulate_transaction(transaction.clone())
        .expect("simulate");
    let used = simulation.meta.compute_units_consumed;
    assert!(
        used * 10 <= u64::from(SWEEP_CU_LIMIT) * 9,
        "full sweep used {used} CU, over 90% of its {SWEEP_CU_LIMIT} limit"
    );
    println!(
        "full sweep with auditor and dust: {} bytes, {} CU",
        bytes.len(),
        simulation.meta.compute_units_consumed
    );
}

#[test]
fn the_sweep_requirement_is_exact_at_the_price_cap_and_the_payer_funds_retries_on_top() {
    use scope_client::{
        fees::{self, SWEEP_PRICE_CAP},
        sweep::{self, SweepError, SweepOptions},
    };
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let opts = SweepOptions {
        poll: std::time::Duration::ZERO,
        ..Default::default()
    };
    let authority = sweep::prepare(&SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect("prepare")
        .report()
        .payment_authority;
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])
    .expect("space");
    let (rent, reserve) = (
        h.svm.minimum_balance_for_rent_exemption(space),
        h.svm.minimum_balance_for_rent_exemption(0),
    );
    let funding = fees::sweep_requirement(rent, reserve, SWEEP_PRICE_CAP);
    assert_eq!(
        fees::sweep_funding(rent, reserve, SWEEP_PRICE_CAP),
        funding + 2 * fees::sweep_attempt_fee(SWEEP_PRICE_CAP),
        "the payer adds the fee of each rebuild"
    );

    set_funding(&mut h, authority, funding - 1);
    let mut chain = SvmChain::new(&mut h.svm);
    chain.price_samples = vec![vec![SWEEP_PRICE_CAP]];
    let error = sweep::prepare(&chain, &alice, &announcement, &opts).expect_err("one short");
    assert!(
        matches!(error, SweepError::Underfunded { short: 1, .. }),
        "{error}"
    );

    set_funding(&mut h, authority, funding);
    let mut chain = SvmChain::new(&mut h.svm);
    chain.price_samples = vec![vec![SWEEP_PRICE_CAP]];
    let report = sweep::sweep(&mut chain, &alice, &announcement, &opts)
        .expect("a P holding the requirement sweeps at the cap");
    assert_eq!(report.reclaimed, Some(true));
}

#[test]
fn finalized_sweeps_succeed_when_metadata_is_unavailable_or_times_out() {
    use scope_client::chain::Chain;
    use scope_client::sweep::{self, SweepOptions};
    use std::time::Duration;
    for (cleanup, delay, fail) in [
        (true, Duration::ZERO, true),
        (false, Duration::ZERO, true),
        (true, Duration::from_millis(30), false),
        (false, Duration::from_millis(30), true),
    ] {
        let mut h = Harness::new();
        let alice = recipient(1);
        let (announcement, source, _) = fund(&mut h, &alice, 3);
        if !cleanup {
            h.send(
                &[mint_dust(&h, source, 17)],
                &[&h.mint_authority.insecure_clone()],
            )
            .expect("dust");
            enable_cpi_guard(&mut h, source);
        }
        let opts = SweepOptions {
            timeout: Duration::from_millis(10),
            poll: Duration::ZERO,
            ..Default::default()
        };
        let mut chain = SvmChain::new(&mut h.svm);
        let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
        assert_eq!(prepared.report().reclaimed, Some(cleanup));
        let signature = prepared.transaction().signatures[0];
        chain
            .send(prepared.transaction())
            .expect("already finalized");
        chain.finalized_read_delay = delay;
        chain.fail_finalized_after_send = fail;
        let report =
            sweep::submit(&mut chain, prepared, &opts).expect("finalization is authoritative");
        assert_eq!(report.finalized_signature, Some(signature.to_string()));
        assert_eq!(report.reclaimed, Some(cleanup));
        assert_eq!(report.public_amount_remaining, cleanup.then_some(0));
        assert_eq!(report.retained_lamports.is_none(), fail || !cleanup);
        assert_eq!(chain.sent_signatures, [signature]);
    }
}

#[test]
fn sweep_reprices_only_rebuilt_attempts_and_rechecks_the_cap() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    use std::{cell::RefCell, rc::Rc};
    let fee =
        |price| scope_client::fees::priority_fee_lamports(price, scope_client::tx::SWEEP_CU_LIMIT);
    for retry_price in [20, 1_001] {
        let mut h = Harness::new();
        let alice = recipient(1);
        let (announcement, source, _) = fund(&mut h, &alice, 3);
        let dust = scope_client::tx::v1_transaction(
            &h.payer,
            &[&h.mint_authority],
            &[mint_dust(&h, source, 17)],
            h.svm.latest_blockhash(),
        );
        let priorities = Rc::new(RefCell::new(Vec::new()));
        let sent_priorities = Rc::clone(&priorities);
        let mut chain = SvmChain::new(&mut h.svm);
        chain.price_samples = vec![vec![10], vec![retry_price]];
        chain.before_send_hook = Some(Box::new(move |_, tx| {
            let solana_message::VersionedMessage::V1(message) = &tx.message else {
                panic!("expected v1");
            };
            sent_priorities
                .borrow_mut()
                .push(message.config.priority_fee.unwrap_or(0));
        }));
        let opts = SweepOptions {
            max_price_per_cu: 1_000,
            poll: std::time::Duration::ZERO,
            ..Default::default()
        };
        let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
        let initial = prepared.report().attempt_signature.clone();
        chain.before_send = Some(dust);
        chain.failed_status_lag.set(1);
        let result = sweep::submit(&mut chain, prepared, &opts);
        assert_eq!(chain.price_reads.get(), 2);
        if retry_price == 20 {
            let report = result.expect("repriced retry");
            assert_eq!(*priorities.borrow(), [fee(10), fee(10), fee(20)]);
            assert_eq!(
                report.finalized_signature.as_ref(),
                Some(&report.attempt_signature)
            );
            assert_ne!(report.attempt_signature, initial);
        } else {
            let SweepError::Interrupted { report, source } = result.expect_err("price exceeds cap")
            else {
                panic!("missing recovery");
            };
            assert_eq!(*priorities.borrow(), [fee(10), fee(10)]);
            assert_eq!(report.attempt_signature, initial);
            assert!(source.to_string().contains("1001 is above the cap 1000"));
        }
    }
}

#[test]
fn sweep_pending_preserves_send_errors_without_claiming_failure() {
    use scope_client::sweep::{self, SweepError, SweepOptions};
    use std::time::Duration;
    let mut h = Harness::new();
    let alice = recipient(1);
    let (announcement, _, _) = fund(&mut h, &alice, 3);
    let mut chain = SvmChain::new(&mut h.svm);
    let opts = SweepOptions {
        timeout: Duration::from_millis(25),
        poll: Duration::from_secs(1),
        ..Default::default()
    };
    let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
    chain.send_error = Some("RPC node rejects v1 transactions".into());
    let error = sweep::submit(&mut chain, prepared, &opts).expect_err("submission rejection");
    assert!(
        error
            .to_string()
            .contains("RPC node rejects v1 transactions")
    );
    let SweepError::Pending { report } = error else {
        panic!("unresolved status must remain pending");
    };
    assert_eq!(report.last_send_error, chain.send_error);
    assert_eq!(report.finalized_signature, None);
    assert_eq!(chain.sent_signatures.len(), 1);
    assert!(chain.svm.get_account(&announcement).is_some());
    assert!(chain.svm.get_account(&report.destination).is_none());
}

#[test]
fn observed_completion_survives_unavailable_cleanup_and_sol_metadata() {
    use scope_client::{
        chain::Chain,
        sweep::{self, SweepOptions},
    };
    for missing_cleanup in [true, false] {
        let mut h = Harness::new();
        let alice = recipient(1);
        let (announcement, _, _) = fund(&mut h, &alice, 3);
        let mut chain = SvmChain::new(&mut h.svm);
        let opts = SweepOptions {
            poll: std::time::Duration::ZERO,
            ..Default::default()
        };
        let prepared = sweep::prepare(&chain, &alice, &announcement, &opts).expect("prepare");
        chain.unavailable_finalized_account = Some(if missing_cleanup {
            announcement
        } else {
            prepared.report().payment_authority
        });
        chain.send(prepared.transaction()).expect("landed");
        chain.lag_finalized_status = true;
        let report = sweep::submit(&mut chain, prepared, &opts).expect("observed completion");
        assert_eq!(report.finalized_signature, None);
        assert_eq!(report.burned_public_amount, None);
        assert_eq!(report.public_amount_remaining, Some(0));
        assert_eq!(report.reclaimed, (!missing_cleanup).then_some(true));
        assert_eq!(report.retained_lamports.is_some(), missing_cleanup);
        assert_eq!(chain.sent_signatures.len(), 1);
    }
}

#[test]
fn restored_standard_owner_can_apply_and_spend_the_swept_balance() {
    use scope_client::sweep::{self, SweepOptions};
    use solana_keypair::{Keypair, read_keypair_file};
    use std::{fs, os::unix::fs::OpenOptionsExt};
    let mut h = Harness::new();
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
    .expect("sweep");
    let restored = RecipientSecretKeys::from_bytes(*alice.export().as_bytes()).expect("restore");
    let seed = restored
        .derive_sweep_destination(&report.ephemeral, &report.token_account.to_bytes())
        .expect("owner seed");
    let owner = Keypair::new_from_array(*seed.as_bytes());
    let path = std::env::temp_dir().join(format!(
        "scope-standard-owner-{}-{}.json",
        std::process::id(),
        h.payer.pubkey()
    ));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .expect("private keypair");
    serde_json::to_writer(file, owner.to_bytes().as_slice()).expect("standard JSON");
    let owner = read_keypair_file(&path).expect("standard import");
    fs::remove_file(path).expect("cleanup");
    assert_eq!(owner.pubkey(), report.destination_owner);
    let (keys, ae) = solana_zk_sdk::encryption::derivation::derive_confidential_keys(&owner, b"")
        .expect("wallet keys");
    let receiver = Keypair::new();
    let (receiver_keys, receiver_ae) =
        solana_zk_sdk::encryption::derivation::derive_confidential_keys(&receiver, b"")
            .expect("receiver keys");
    let destination = h.plain_confidential_account(&receiver, &receiver_keys, &receiver_ae);
    h.payer = owner;
    h.source = report.destination;
    h.source_elgamal = keys;
    h.source_ae = ae;
    h.source_balance = AMOUNT;
    assert_available(&h.svm, &report.destination, &h.payer, AMOUNT);
    h.send(
        &transfer(&h, destination, receiver_keys.pubkey(), AMOUNT),
        &[],
    )
    .expect("spend with restored standard owner");
    let received = h.svm.get_account(&destination).expect("receiver");
    let state = StateWithExtensions::<Account>::unpack(&received.data).expect("account");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("confidential extension");
    let lo: ElGamalCiphertext = ext.pending_balance_lo.try_into().expect("lo");
    let hi: ElGamalCiphertext = ext.pending_balance_hi.try_into().expect("hi");
    assert_eq!(
        receiver_keys.secret().decrypt_u32(&lo).expect("lo")
            + (receiver_keys.secret().decrypt_u32(&hi).expect("hi") << 16),
        AMOUNT
    );
    let spent = h
        .svm
        .get_account(&report.destination)
        .expect("spent account");
    let state = StateWithExtensions::<Account>::unpack(&spent.data).expect("account");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("confidential extension");
    assert_eq!(
        h.source_ae
            .decrypt(&ext.decryptable_available_balance.try_into().expect("hint")),
        Some(0)
    );
}

mod history {
    use super::*;
    use scope_client::{
        address::program_id,
        chain::ChainError,
        history::{
            self, DEFAULT_LIMIT, PAGE, RecoverOptions, SignatureEntry, SignatureHistory,
            SignatureQuery,
        },
        receipt::{ArchivedTransaction, TransactionArchive},
        sweep::{self, SweepOptions},
        tx::v1_transaction,
    };
    use solana_signature::Signature;
    use solana_transaction::versioned::VersionedTransaction;
    use std::cell::Cell;

    /// Transactions in the order they landed, answering like an archival node.
    #[derive(Default)]
    struct Archive {
        txs: Vec<(Signature, VersionedTransaction)>,
        listings: Cell<usize>,
    }

    impl Archive {
        fn push(&mut self, tx: VersionedTransaction) -> Signature {
            let signature = tx.signatures[0];
            self.txs.push((signature, tx));
            signature
        }
    }

    impl SignatureHistory for Archive {
        fn signatures_for_address(
            &self,
            address: &Address,
            query: &SignatureQuery<'_>,
        ) -> Result<Vec<SignatureEntry>, ChainError> {
            self.listings.set(self.listings.get() + 1);
            let newest_first = self
                .txs
                .iter()
                .enumerate()
                .rev()
                .filter(|(_, (_, tx))| tx.message.static_account_keys().contains(address))
                .map(|(slot, (signature, _))| (slot, *signature));
            let mut after_before =
                newest_first.skip_while(|(_, s)| query.before.is_some_and(|b| b != s));
            if query.before.is_some() {
                after_before.next();
            }
            Ok(after_before
                .take_while(|(_, s)| query.until != Some(s))
                .take(query.limit)
                .map(|(slot, signature)| SignatureEntry {
                    signature,
                    slot: slot as u64,
                    succeeded: true,
                })
                .collect())
        }
    }

    impl TransactionArchive for Archive {
        fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
            Ok([42; 32])
        }

        fn transaction(&self, signature: &Signature) -> Result<ArchivedTransaction, ChainError> {
            self.txs
                .iter()
                .find(|(s, _)| s == signature)
                .map(|(_, tx)| ArchivedTransaction {
                    transaction: tx.clone(),
                    succeeded: true,
                })
                .ok_or_else(|| ChainError(format!("{signature}: not found")))
        }
    }

    fn pay(
        h: &mut Harness,
        archive: &mut Archive,
        recipient: &RecipientSecretKeys,
        r: u8,
    ) -> (Signature, Address) {
        let (ixs, _, account, _) = payment_instructions(h, recipient, r, AMOUNT);
        let tx = v1_transaction(&h.payer, &[], &ixs, h.svm.latest_blockhash());
        h.svm.send_transaction(tx.clone()).expect("payment");
        h.svm.expire_blockhash();
        h.source_balance -= AMOUNT;
        (archive.push(tx), account)
    }

    /// A transaction that touches `address` and nothing else of interest.
    fn noise(h: &Harness, address: Address, lamports: u64) -> VersionedTransaction {
        v1_transaction(
            &h.payer,
            &[],
            &[solana_system_interface::instruction::transfer(
                &h.payer.pubkey(),
                &address,
                lamports,
            )],
            h.svm.latest_blockhash(),
        )
    }

    #[test]
    fn recover_finds_swept_and_unswept_payments_and_ignores_others() {
        let mut h = Harness::new();
        let (alice, bob) = (recipient(1), recipient(2));
        let mut archive = Archive::default();
        let (first, first_account) = pay(&mut h, &mut archive, &alice, 3);
        pay(&mut h, &mut archive, &bob, 4);
        let (third, third_account) = pay(&mut h, &mut archive, &alice, 5);
        let announcement = announcement_address(&first_account).0;
        let mut chain = SvmChain::new(&mut h.svm);
        let swept = sweep::sweep(
            &mut chain,
            &alice,
            &announcement,
            &SweepOptions {
                poll: std::time::Duration::ZERO,
                ..Default::default()
            },
        )
        .expect("sweep");
        assert!(
            scan::scan(&chain, &alice, None)
                .expect("scan")
                .payments
                .iter()
                .all(|p| p.token_account != first_account)
        );

        let report = history::recover(
            &chain,
            &archive,
            &alice,
            &RecoverOptions {
                limit: DEFAULT_LIMIT,
                since: None,
            },
        )
        .expect("recover");
        assert_eq!(report.examined, 3);
        assert_eq!(report.unavailable, 0);
        let signatures: Vec<_> = report.found.iter().map(|f| f.signature).collect();
        assert_eq!(
            signatures,
            [third, first],
            "newest first, Bob's payment absent"
        );
        let (open, closed) = (&report.found[0], &report.found[1]);
        assert_eq!(open.token_account, third_account);
        assert_eq!(open.payer, h.payer.pubkey());
        assert_eq!(open.mint, h.mint);
        assert!(open.destination_state.is_none());
        assert_eq!(closed.token_account, first_account);
        assert_eq!(closed.destination, swept.destination);
        assert_eq!(closed.destination_owner, swept.destination_owner);
        let state = closed.destination_state.as_ref().expect("D exists");
        assert_eq!(state.amount, Some(AMOUNT));
        assert!(state.lamports > 0);
        assert_eq!(
            history::payment_signature(&archive, &first_account).expect("lookup"),
            Some(first),
            "the signature is found after reclaim closed the one-time account"
        );
    }

    #[test]
    fn recover_honors_the_limit_and_since() {
        let mut h = Harness::new();
        let alice = recipient(1);
        let mut archive = Archive::default();
        let (first, _) = pay(&mut h, &mut archive, &alice, 3);
        let (second, _) = pay(&mut h, &mut archive, &alice, 4);
        let chain = SvmChain::new(&mut h.svm);
        let run = |limit, since| {
            history::recover(&chain, &archive, &alice, &RecoverOptions { limit, since })
                .expect("recover")
                .found
                .iter()
                .map(|f| f.signature)
                .collect::<Vec<_>>()
        };
        assert_eq!(run(1, None), [second]);
        assert_eq!(run(2, None), [second, first]);
        assert_eq!(run(10, Some(first)), [second]);
        assert!(run(0, None).is_empty());
    }

    #[test]
    fn recover_pages_through_long_histories() {
        let mut h = Harness::new();
        let alice = recipient(1);
        let mut archive = Archive::default();
        pay(&mut h, &mut archive, &alice, 3);
        for lamports in 1..=PAGE as u64 + 100 {
            archive.push(noise(&h, program_id(), lamports));
        }
        let chain = SvmChain::new(&mut h.svm);
        let find = |limit| {
            archive.listings.set(0);
            let report = history::recover(
                &chain,
                &archive,
                &alice,
                &RecoverOptions { limit, since: None },
            )
            .expect("recover");
            (report.found.len(), report.examined, archive.listings.get())
        };
        assert_eq!(find(PAGE), (0, PAGE, 1), "the limit ends the walk");
        assert_eq!(find(2 * PAGE), (1, PAGE + 101, 2));
    }

    #[test]
    fn payment_signature_skips_earlier_transfers_to_the_address_and_reads_every_page() {
        let mut h = Harness::new();
        let alice = recipient(1);
        let mut archive = Archive::default();
        let sent = derive_payment_with_ephemeral(
            &alice.derive_public_keys(),
            &EphemeralSecret::from_bytes([3; 32]),
        )
        .expect("payment");
        let account =
            token_account_address(&h.payer.pubkey(), &sent.announcement.ephemeral_public_key);
        archive.push(noise(&h, account, 1));
        let (signature, paid) = pay(&mut h, &mut archive, &alice, 3);
        assert_eq!(paid, account);
        for lamports in 2..=PAGE as u64 + 50 {
            archive.push(noise(&h, account, lamports));
        }
        assert_eq!(
            history::payment_signature(&archive, &account).expect("lookup"),
            Some(signature)
        );
        assert_eq!(archive.listings.get(), 2);
        let unrelated = Address::new_from_array([9; 32]);
        assert_eq!(
            history::payment_signature(&archive, &unrelated).expect("lookup"),
            None
        );
    }
}
