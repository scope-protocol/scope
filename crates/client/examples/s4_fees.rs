//! Spike S4: sample the per-CU priority fee actually paid by landed transactions.
//!
//! `cargo run -p scope-client --example s4_fees -- [RPC_URL] [CSV_PATH] [--once]`
//! Defaults: RPC_URL `https://api.mainnet-beta.solana.com`, CSV_PATH `fees.csv`.
//!
//! `getRecentPrioritizationFees` with no account filter returns, per slot, the
//! lowest per-CU fee among landed transactions, so its percentiles read ~0 by
//! construction and do not describe what anyone actually paid (review finding,
//! fix round 1). Instead this samples a confirmed block directly: `getSlot`
//! (confirmed), then `getBlock` for that slot, retrying a few earlier slots if
//! one was skipped. For each landed, non-vote transaction it reads the per-CU
//! price actually paid, from the ComputeBudget `SetComputeUnitPrice`
//! instruction (legacy and v0) or from the v1 header's `priority_fee` divided
//! by its compute unit limit. Every 10 minutes it appends
//! `unix_time,slot,n,p50,p75,p95` to the CSV and prints the running values.
//! `--once` takes a single sample and exits, for verification without a
//! multi-day run.

use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_message::VersionedMessage;
use solana_rpc_client::{api::config::RpcBlockConfig, rpc_client::RpcClient};
use solana_transaction_status_client_types::{TransactionDetails, UiTransactionEncoding};
use std::{
    error::Error,
    fs::OpenOptions,
    io::Write,
    path::Path,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Res<T> = Result<T, Box<dyn Error>>;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const SLOT_RETRIES: u64 = 5;
const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
const VOTE_PROGRAM: &str = "Vote111111111111111111111111111111111111111";
const SET_COMPUTE_UNIT_PRICE_TAG: u8 = 3;

/// Nearest-rank percentile: rank = ceil(pct/100 * n), one-based, clamped into range.
fn percentile(sorted: &[u64], pct: usize) -> u64 {
    let n = sorted.len();
    let rank = (n * pct).div_ceil(100).max(1);
    sorted[(rank - 1).min(n - 1)]
}

/// Per-CU price (micro-lamports) this instruction set paid, or `None` if it is
/// a vote transaction (checked first, across every message version). Legacy
/// and v0 then read the ComputeBudget instruction; v1 reads the header.
/// Non-vote transactions with no price instruction pay 0.
fn price_per_cu(
    message: &VersionedMessage,
    compute_budget: &Address,
    vote: &Address,
) -> Option<u64> {
    let keys = message.static_account_keys();
    for ix in message.instructions() {
        if keys.get(usize::from(ix.program_id_index)) == Some(vote) {
            return None;
        }
    }

    if let VersionedMessage::V1(v1) = message {
        let limit = v1.config.compute_unit_limit?;
        if limit == 0 {
            return None;
        }
        let lamports = u128::from(v1.config.priority_fee.unwrap_or(0));
        return Some((lamports * 1_000_000 / u128::from(limit)) as u64);
    }

    let mut price = 0u64;
    for ix in message.instructions() {
        let Some(program) = keys.get(usize::from(ix.program_id_index)) else {
            continue;
        };
        if program == compute_budget
            && ix.data.len() >= 9
            && ix.data[0] == SET_COMPUTE_UNIT_PRICE_TAG
        {
            price = u64::from_le_bytes(ix.data[1..9].try_into().expect("9 bytes sliced to 8"));
        }
    }
    Some(price)
}

fn sample(rpc: &RpcClient, csv_path: &str) -> Res<()> {
    let compute_budget: Address = COMPUTE_BUDGET_PROGRAM.parse()?;
    let vote: Address = VOTE_PROGRAM.parse()?;

    let mut slot = rpc.get_slot_with_commitment(CommitmentConfig::confirmed())?;
    let config = RpcBlockConfig {
        encoding: Some(UiTransactionEncoding::Base64),
        transaction_details: Some(TransactionDetails::Full),
        rewards: Some(false),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(1),
    };
    let block = 'block: {
        for attempt in 0..=SLOT_RETRIES {
            match rpc.get_block_with_config(slot, config) {
                Ok(block) => break 'block block,
                Err(err) if attempt < SLOT_RETRIES && slot > 0 => {
                    println!("slot {slot} unavailable ({err}), trying {}", slot - 1);
                    slot -= 1;
                }
                Err(err) => return Err(err.into()),
            }
        }
        return Err("no block found within the retry budget".into());
    };

    let mut prices: Vec<u64> = Vec::new();
    for tx in block.transactions.unwrap_or_default() {
        let Some(meta) = tx.meta else { continue };
        if meta.err.is_some() {
            continue;
        }
        let Some(decoded) = tx.transaction.decode() else {
            continue;
        };
        if let Some(price) = price_per_cu(&decoded.message, &compute_budget, &vote) {
            prices.push(price);
        }
    }

    if prices.is_empty() {
        println!("slot {slot}: no landed non-vote transactions in this sample");
        return Ok(());
    }
    prices.sort_unstable();
    let n = prices.len();
    let p50 = percentile(&prices, 50);
    let p75 = percentile(&prices, 75);
    let p95 = percentile(&prices, 95);
    let unix_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let is_new = !Path::new(csv_path).exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(csv_path)?;
    if is_new {
        writeln!(file, "unix_time,slot,n,p50,p75,p95")?;
    }
    writeln!(file, "{unix_time},{slot},{n},{p50},{p75},{p95}")?;

    println!("slot {slot}: n {n}, p50 {p50}, p75 {p75}, p95 {p95} micro-lamports per CU");
    Ok(())
}

fn main() -> Res<()> {
    let mut url: Option<String> = None;
    let mut csv_path: Option<String> = None;
    let mut once = false;
    for arg in std::env::args().skip(1) {
        if arg == "--once" {
            once = true;
        } else if url.is_none() {
            url = Some(arg);
        } else if csv_path.is_none() {
            csv_path = Some(arg);
        } else {
            return Err(format!("unexpected argument: {arg}").into());
        }
    }
    let url = url.unwrap_or_else(|| "https://api.mainnet-beta.solana.com".into());
    let csv_path = csv_path.unwrap_or_else(|| "fees.csv".into());

    let rpc = RpcClient::new(url.clone());
    println!("cluster {url}, csv {csv_path}");

    if once {
        return sample(&rpc, &csv_path);
    }

    loop {
        sample(&rpc, &csv_path)?;
        sleep(SAMPLE_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::Instruction;
    use solana_message::{
        Hash,
        v1::{Message, TransactionConfig},
    };

    fn payer() -> Address {
        Address::new_from_array([7u8; 32])
    }

    fn programs() -> (Address, Address) {
        (
            COMPUTE_BUDGET_PROGRAM.parse().expect("valid address"),
            VOTE_PROGRAM.parse().expect("valid address"),
        )
    }

    fn v1_message(program: Address, config: TransactionConfig) -> VersionedMessage {
        let ix = Instruction::new_with_bytes(program, &[], vec![]);
        let message = Message::try_compile_with_config(&payer(), &[ix], Hash::default(), config)
            .expect("message compiles");
        VersionedMessage::V1(message)
    }

    #[test]
    fn v1_vote_transaction_is_excluded() {
        let (compute_budget, vote) = programs();
        let config = TransactionConfig::empty()
            .with_priority_fee(1_000_000)
            .with_compute_unit_limit(200_000);
        let message = v1_message(vote, config);
        assert_eq!(price_per_cu(&message, &compute_budget, &vote), None);
    }

    #[test]
    fn v1_price_comes_from_the_header() {
        let (compute_budget, vote) = programs();
        let other = Address::new_from_array([9u8; 32]);
        let config = TransactionConfig::empty()
            .with_priority_fee(2_000_000)
            .with_compute_unit_limit(400_000);
        let message = v1_message(other, config);
        // 2_000_000 lamports * 1_000_000 / 400_000 CU = 5_000_000 micro-lamports/CU.
        assert_eq!(
            price_per_cu(&message, &compute_budget, &vote),
            Some(5_000_000)
        );
    }
}
