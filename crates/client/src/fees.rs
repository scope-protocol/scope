//! Priority fee sampling (docs/payer.md, How are fees priced?): the per-CU price landed non-vote
//! transactions actually paid, never `getRecentPrioritizationFees`.

use solana_address::Address;
use solana_message::VersionedMessage;
use solana_transaction_status_client_types::EncodedTransactionWithStatusMeta;

const COMPUTE_BUDGET_PROGRAM: Address =
    Address::from_str_const("ComputeBudget111111111111111111111111111111");
const VOTE_PROGRAM: Address =
    Address::from_str_const("Vote111111111111111111111111111111111111111");
const SET_COMPUTE_UNIT_PRICE_TAG: u8 = 3;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("priority price {price} is above the cap {cap}")]
pub struct FeeAboveCap {
    pub price: u64,
    pub cap: u64,
}

pub fn priority_price(mut prices: Vec<u64>, cap: u64) -> Result<u64, FeeAboveCap> {
    prices.sort_unstable();
    let price = if prices.is_empty() {
        0
    } else {
        percentile(&prices, 75)
    };
    if price > cap {
        return Err(FeeAboveCap { price, cap });
    }
    Ok(price)
}

/// Nearest-rank percentile of a sorted, non-empty slice.
pub fn percentile(sorted: &[u64], pct: usize) -> u64 {
    let n = sorted.len();
    let rank = (n * pct).div_ceil(100).max(1);
    sorted[(rank - 1).min(n - 1)]
}

/// Per-CU price in micro-lamports, or `None` for a vote transaction. Legacy and v0
/// read `SetComputeUnitPrice` (absent means 0); v1 divides the header's total
/// priority fee by its compute unit limit.
pub fn price_per_cu(message: &VersionedMessage) -> Option<u64> {
    let keys = message.static_account_keys();
    let program = |index: u8| keys.get(usize::from(index));
    if message
        .instructions()
        .iter()
        .any(|ix| program(ix.program_id_index) == Some(&VOTE_PROGRAM))
    {
        return None;
    }
    if let VersionedMessage::V1(v1) = message {
        let limit = v1.config.compute_unit_limit.filter(|l| *l > 0)?;
        let lamports = u128::from(v1.config.priority_fee.unwrap_or(0));
        return Some(u64::try_from(lamports * 1_000_000 / u128::from(limit)).unwrap_or(u64::MAX));
    }
    let mut price = 0;
    for ix in message.instructions() {
        if program(ix.program_id_index) == Some(&COMPUTE_BUDGET_PROGRAM)
            && ix.data.first() == Some(&SET_COMPUTE_UNIT_PRICE_TAG)
            && let Some(bytes) = ix.data.get(1..9)
        {
            price = u64::from_le_bytes(bytes.try_into().expect("slice of 8"));
        }
    }
    Some(price)
}

/// Prices paid by the block's landed non-vote transactions, sorted.
pub fn block_prices(transactions: Vec<EncodedTransactionWithStatusMeta>) -> Vec<u64> {
    let mut prices: Vec<u64> = transactions
        .into_iter()
        .filter(|tx| tx.meta.as_ref().is_some_and(|m| m.err.is_none()))
        .filter_map(|tx| tx.transaction.decode())
        .filter_map(|tx| price_per_cu(&tx.message))
        .collect();
    prices.sort_unstable();
    prices
}

/// Total v1 header priority fee in lamports for `price` micro-lamports per CU, rounded up.
pub fn priority_fee_lamports(price_per_cu: u64, compute_unit_limit: u32) -> u64 {
    (u128::from(price_per_cu) * u128::from(compute_unit_limit)).div_ceil(1_000_000) as u64
}

/// Agave's default base fee per signature (solana-fee-structure 4.1.0, `src/lib.rs` 125).
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;

/// The highest per-CU price, in micro-lamports, a payer funds P's sweep for, and the
/// sweep's default `--max-price`. The recipient may sweep weeks after the payment.
pub const SWEEP_PRICE_CAP: u64 = 1_000_000;

/// One sweep attempt's fee at `price`: two signatures and the priority fee at the sweep's
/// compute-unit limit.
pub fn sweep_attempt_fee(price: u64) -> u64 {
    2 * LAMPORTS_PER_SIGNATURE + priority_fee_lamports(price, crate::tx::SWEEP_CU_LIMIT)
}

/// What the sweep requires P to hold for one attempt at `price`: D's rent, the attempt's
/// fee, and the rent reserve the sweep leaves in P.
pub fn sweep_requirement(destination_rent: u64, reserve: u64, price: u64) -> u64 {
    destination_rent + sweep_attempt_fee(price) + reserve
}

/// What the payer funds P with: the requirement at `price_cap`, plus the fee of every
/// rebuild the sweep may make, since an attempt that lands and fails is still charged.
/// Whatever is left goes to D_owner with the sweep.
pub fn sweep_funding(destination_rent: u64, reserve: u64, price_cap: u64) -> u64 {
    sweep_requirement(destination_rent, reserve, price_cap)
        + crate::sweep::MAX_RETRIES as u64 * sweep_attempt_fee(price_cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::Instruction;
    use solana_message::{
        Hash,
        v1::{Message, TransactionConfig},
    };

    fn v1_message(program: Address, config: TransactionConfig) -> VersionedMessage {
        let ix = Instruction::new_with_bytes(program, &[], vec![]);
        let payer = Address::new_from_array([7; 32]);
        let message = Message::try_compile_with_config(&payer, &[ix], Hash::default(), config)
            .expect("message compiles");
        VersionedMessage::V1(message)
    }

    #[test]
    fn v1_vote_transaction_is_excluded() {
        let config = TransactionConfig::empty()
            .with_priority_fee(1_000_000)
            .with_compute_unit_limit(200_000);
        assert_eq!(price_per_cu(&v1_message(VOTE_PROGRAM, config)), None);
    }

    #[test]
    fn v1_price_comes_from_the_header() {
        let config = TransactionConfig::empty()
            .with_priority_fee(2_000_000)
            .with_compute_unit_limit(400_000);
        // 2,000,000 lamports * 1,000,000 / 400,000 CU.
        assert_eq!(
            price_per_cu(&v1_message(Address::new_from_array([9; 32]), config)),
            Some(5_000_000)
        );
    }

    #[test]
    fn percentile_is_nearest_rank() {
        let s = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile(&s, 50), 5);
        assert_eq!(percentile(&s, 75), 8);
        assert_eq!(percentile(&s, 95), 10);
        assert_eq!(percentile(&[42], 75), 42);
    }

    #[test]
    fn priority_fee_rounds_up() {
        assert_eq!(priority_fee_lamports(1, 600_000), 1);
        assert_eq!(priority_fee_lamports(1_000_000, 600_000), 600_000);
        assert_eq!(priority_fee_lamports(0, 600_000), 0);
    }

    #[test]
    fn priority_price_sorts_samples_and_enforces_the_cap() {
        assert_eq!(priority_price(Vec::new(), 0), Ok(0));
        assert_eq!(priority_price(vec![3, 0, 1, 2], 2), Ok(2));
        assert_eq!(
            priority_price(vec![3, 0, 1, 2], 1),
            Err(FeeAboveCap { price: 2, cap: 1 })
        );
    }
}
