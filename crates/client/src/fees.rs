//! Priority fee sampling (docs/client.md, Fees): the per-CU price landed non-vote
//! transactions actually paid, never `getRecentPrioritizationFees`.

use solana_address::Address;
use solana_message::VersionedMessage;
use solana_transaction_status_client_types::EncodedTransactionWithStatusMeta;

const COMPUTE_BUDGET_PROGRAM: Address =
    Address::from_str_const("ComputeBudget111111111111111111111111111111");
const VOTE_PROGRAM: Address =
    Address::from_str_const("Vote111111111111111111111111111111111111111");
const SET_COMPUTE_UNIT_PRICE_TAG: u8 = 3;

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
        return Some((lamports * 1_000_000 / u128::from(limit)) as u64);
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
}
