#![forbid(unsafe_code)]

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use scope_client::{
    chain::RpcChain,
    journal::{self, Record},
    pay::{self, PayOptions, SourceKeys},
};
use solana_address::Address;
use solana_keypair::read_keypair_file;
use solana_rpc_client::rpc_client::RpcClient;
use std::{path::PathBuf, time::Duration};

/// Confidential payouts on Solana: hidden amounts, optional one-time recipient accounts.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Publish a meta-address so payers can reach you with one-time accounts.
    Register,
    /// Pay a batch of plain and stealth recipients.
    Pay(PayArgs),
    /// Find payments addressed to you.
    Scan,
    /// Move a found payment into a fresh account of your own.
    Sweep,
    /// Produce a receipt that proves one payment's amount.
    Disclose,
    /// Check a receipt against the chain.
    Verify,
    /// Measure bytes, compute and cost per transaction.
    Bench,
}

#[derive(Debug, Args)]
struct PayArgs {
    /// `recipient,amount` rows; recipient is a configured confidential token account.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    input: Option<PathBuf>,
    /// Token-2022 mint with confidential transfers enabled.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    mint: Option<Address>,
    /// The payer's confidential token account to pay from; its keys derive from --keypair.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    source: Option<Address>,
    /// Continue an interrupted run.
    #[arg(long, value_name = "RUN_ID")]
    resume: Option<String>,
    /// Payer keypair: owns the source and pays every fee.
    #[arg(long, default_value = "~/.config/solana/id.json")]
    keypair: String,
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    url: String,
    /// Directory holding one journal per run.
    #[arg(long, default_value = "runs")]
    runs: PathBuf,
    /// Stop, resumable, when the sampled priority fee is above this, in micro-lamports per CU.
    #[arg(long, default_value_t = 1_000_000)]
    max_price: u64,
    /// Pay an input file that an earlier run already paid.
    #[arg(long)]
    again: bool,
}

fn expand_home(path: &str) -> anyhow::Result<PathBuf> {
    match path.strip_prefix("~/") {
        Some(rest) => Ok(std::env::home_dir()
            .context("no home directory")?
            .join(rest)),
        None => Ok(path.into()),
    }
}

fn run_pay(args: PayArgs) -> anyhow::Result<()> {
    let keypair_path = expand_home(&args.keypair)?;
    let payer = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", keypair_path.display()))?;
    let chain = RpcChain(RpcClient::new(args.url));
    let opts = PayOptions {
        runs_dir: args.runs,
        max_price_per_cu: args.max_price,
        poll: Duration::from_secs(2),
        again: args.again,
        log: |line| eprintln!("{line}"),
    };
    let report = match args.resume {
        Some(run_id) => {
            let Some(Record::Run { source, .. }) =
                journal::read_header(&opts.runs_dir.join(&run_id))?
            else {
                bail!("run {run_id} has no header");
            };
            let source: Address = source.parse().context("source in the journal")?;
            let keys = SourceKeys::from_signer(&payer, &source)?;
            pay::resume(chain, &payer, keys, &run_id, &opts)?
        }
        None => {
            let (input, mint, source) = (
                args.input.context("--input")?,
                args.mint.context("--mint")?,
                args.source.context("--source")?,
            );
            let bytes =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let keys = SourceKeys::from_signer(&payer, &source)?;
            pay::start(chain, &payer, keys, mint, source, &bytes, &opts)?
        }
    };
    println!("run {}: {} rows paid", report.run_id, report.paid.len());
    for p in &report.paid {
        println!("{}\t{}\t{}", p.row, p.recipient, p.signature);
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Pay(args) => run_pay(args),
        other => bail!("{other:?} is not implemented yet"),
    }
}
