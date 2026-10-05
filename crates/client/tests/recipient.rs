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
    ixs.extend(transfer(h, account, keys.pubkey(), AMOUNT));
    h.send(&ixs, &[]).expect("payer transaction");
    h.source_balance -= AMOUNT;
    (announcement, account, ae)
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
    assert!(report.reclaimed);
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
    let r = scan::scan(&SvmChain::new(&mut h.svm), &alice, None)
        .expect("scan")
        .payments[0]
        .ephemeral;
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
    chain.fail_finalized_after_send = true;
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
        .derive_sweep_destination(&report.ephemeral)
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
        .derive_sweep_destination(&report.ephemeral)
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
    assert!(report.reclaimed);
    assert_eq!(report.amount, AMOUNT);
    assert_eq!(report.retained_lamports, minimum + 1);
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
        assert_eq!(prepared.report().retained_lamports, retained);
        assert!(h.svm.get_account(&prepared.report().destination).is_none());
    }
    set_funding(&mut h, authority, need);
    let report = sweep::sweep(&mut SvmChain::new(&mut h.svm), &alice, &announcement, &opts)
        .expect("exact funding succeeds");
    assert_eq!(report.retained_lamports, minimum);
    assert!(report.reclaimed);
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
    assert_eq!(report.retained_lamports, minimum);
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
    assert!(!report.reclaimed);
    assert_eq!(report.burned_public_amount, Some(0));
    assert_eq!(report.public_amount_remaining, 17);
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
        .derive_sweep_destination(&report.ephemeral)
        .expect("seed");
    let owner = solana_keypair::Keypair::new_from_array(*seed.as_bytes());
    let (keys, _) =
        solana_zk_sdk::encryption::derivation::derive_confidential_keys(&owner, b"").expect("keys");
    let destination = h.svm.get_account(&report.destination).expect("destination");
    let state =
        StateWithExtensions::<Account>::unpack(&destination.data).expect("destination state");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("extension");
    let lo: ElGamalCiphertext = ext.pending_balance_lo.try_into().expect("low");
    let hi: ElGamalCiphertext = ext.pending_balance_hi.try_into().expect("high");
    assert_eq!(
        keys.secret().decrypt_u32(&lo).expect("low")
            + (keys.secret().decrypt_u32(&hi).expect("high") << 16),
        AMOUNT
    );
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
    assert!(report.reclaimed);
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
