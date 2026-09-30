use scope_client::{address::announcement_address, ix::reclaim, testkit::*};
use solana_signer::Signer;

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
