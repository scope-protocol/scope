#![forbid(unsafe_code)]

use anyhow::bail;
use clap::{Parser, Subcommand};

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
    Pay,
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    bail!("{:?} is not implemented yet", cli.command)
}
