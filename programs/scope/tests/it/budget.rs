use crate::token_attacks::transfer_ixs;
use scope_client::{
    address::announcement_address,
    ix::reclaim,
    testkit::*,
    tx::{PLAIN_TRANSFER_CU_LIMIT, STEALTH_PAYMENT_CU_LIMIT},
};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};

/// Measured 2026-09-30 at bump 255: announce 6,373, reclaim 3,256 (bump 254: announce
/// 7,873). Ceilings about 20% above; raise only with a reason in the commit.
const ANNOUNCE_CU_MAX: u64 = 7_700;
const RECLAIM_CU_MAX: u64 = 4_000;

/// `announce` searches for the canonical bump, and each step below 255 costs about
/// 1,500 CU more, so a random case would make the ceiling flaky. Pin bump 255.
fn case_at_bump_255(h: &Harness) -> StealthCase {
    loop {
        let case = h.stealth_case();
        if announcement_address(&case.token_account).1 == 255 {
            return case;
        }
    }
}

#[test]
fn announce_stays_within_budget() {
    let mut h = Harness::new();
    let case = case_at_bump_255(&h);
    let meta = h.send(&case.setup, &[]).expect("announce");
    let used = program_compute_units(&meta.logs);
    println!("announce CU {used:?}");
    assert_eq!(used.len(), 1);
    assert!(used[0] <= ANNOUNCE_CU_MAX, "announce used {}", used[0]);
}

#[test]
fn reclaim_stays_within_budget() {
    let mut h = Harness::new();
    let case = case_at_bump_255(&h);
    h.send(&case.setup, &[]).expect("announce");
    let ix = reclaim(&case.announcement, &case.token_account, &h.payer.pubkey());
    let meta = h.send(&[ix], &[]).expect("reclaim");
    let used = program_compute_units(&meta.logs);
    println!("reclaim CU {used:?}");
    assert_eq!(used.len(), 1);
    assert!(used[0] <= RECLAIM_CU_MAX, "reclaim used {}", used[0]);
}

/// Fails when a shape uses more than 90% of its limit: headroom for Token-2022 drift,
/// without paying a priority fee on much more than the shape uses.
fn assert_headroom(shape: &str, used: u64, limit: u32) {
    println!("{shape}: {used} CU of {limit}");
    assert!(
        used * 10 <= u64::from(limit) * 9,
        "{shape} used {used} CU, over 90% of its {limit} limit"
    );
}

#[test]
fn plain_transfer_keeps_headroom_under_its_limit() {
    let auditor = ElGamalKeypair::new_rand();
    let mut h = Harness::with_auditor(Some(auditor.pubkey()));
    let keys = ElGamalKeypair::new_rand();
    let to = h.plain_confidential_account(&Keypair::new(), &keys, &AeKey::new_rand());
    let ixs = transfer_ixs(
        &h,
        &h.source,
        &h.source_elgamal,
        &h.source_ae,
        h.source_balance,
        &h.mint,
        &to,
        keys.pubkey(),
        Some(auditor.pubkey()),
    );
    let meta = h.send(&ixs, &[]).expect("plain transfer");
    assert_headroom(
        "plain transfer",
        meta.compute_units_consumed,
        PLAIN_TRANSFER_CU_LIMIT,
    );
}

/// At bump 255; each lower bump adds about 1,500 CU (V55), well inside the headroom.
#[test]
fn stealth_payment_keeps_headroom_under_its_limit() {
    let auditor = ElGamalKeypair::new_rand();
    let mut h = Harness::with_auditor(Some(auditor.pubkey()));
    let case = case_at_bump_255(&h);
    let mut ixs = case.setup.clone();
    ixs.extend(transfer_ixs(
        &h,
        &h.source,
        &h.source_elgamal,
        &h.source_ae,
        h.source_balance,
        &h.mint,
        &case.token_account,
        case.elgamal.pubkey(),
        Some(auditor.pubkey()),
    ));
    let meta = h.send(&ixs, &[]).expect("stealth payment");
    assert_headroom(
        "stealth payment",
        meta.compute_units_consumed,
        STEALTH_PAYMENT_CU_LIMIT,
    );
}
