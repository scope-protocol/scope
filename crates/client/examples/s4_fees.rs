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

use scope_client::fees::{block_prices, percentile};
use solana_commitment_config::CommitmentConfig;
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

fn sample(rpc: &RpcClient, csv_path: &str) -> Res<()> {
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

    let prices = block_prices(block.transactions.unwrap_or_default());
    if prices.is_empty() {
        println!("slot {slot}: no landed non-vote transactions in this sample");
        return Ok(());
    }
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

    // A multi-day run outlives any one RPC error; a gap in the CSV is the record of it.
    loop {
        if let Err(err) = sample(&rpc, &csv_path) {
            eprintln!("sample failed: {err}");
        }
        sleep(SAMPLE_INTERVAL);
    }
}
