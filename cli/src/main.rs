#![forbid(unsafe_code)]

mod recipient_keys;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use scope_client::{
    chain::RpcChain,
    pay::{self, PayOptions, SourceKeys},
    receipt, scan, sweep,
};
use solana_address::Address;
use solana_keypair::read_keypair_file;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

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
    Register(RegisterArgs),
    /// Pay a batch of plain and stealth recipients.
    Pay(PayArgs),
    /// Publish your meta-address under a wallet in the on-chain registry, or remove it.
    Publish(PublishArgs),
    /// Print the meta-addresses wallets published, fetched in one query.
    Lookup(LookupArgs),
    /// Find payments addressed to you.
    Scan(ScanArgs),
    /// Move a found payment into a fresh account of your own.
    Sweep(SweepArgs),
    /// Produce a receipt that proves one payment's amount.
    Disclose(DiscloseArgs),
    /// Check a receipt against the chain.
    Verify(VerifyArgs),
    /// Measure bytes, compute and cost per transaction.
    Bench,
}

#[derive(Debug, Args)]
struct RecipientKeys {
    /// Recipient backup created by `scope register`.
    #[arg(long, default_value = "~/.config/scope/recipient.key")]
    recipient_key: String,
    /// Owner-only age identity file for an encrypted backup.
    #[arg(long)]
    identity: Option<String>,
}

impl RecipientKeys {
    fn load(&self) -> anyhow::Result<stealth_keygen::RecipientSecretKeys> {
        let path = expand_home(&self.recipient_key)?;
        let identity = self.identity.as_deref().map(expand_home).transpose()?;
        recipient_keys::load(&path, identity.as_deref())
    }
}

#[derive(Debug, Args)]
struct RegisterArgs {
    #[arg(long, default_value = "~/.config/scope/recipient.key")]
    recipient_key: String,
    /// Encrypt the new backup to this age public recipient (requires age).
    #[arg(long)]
    encrypt_to: Option<String>,
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[command(flatten)]
    keys: RecipientKeys,
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    url: String,
    /// Show payments for only this mint.
    #[arg(long)]
    mint: Option<Address>,
}

#[derive(Debug, Args)]
struct SweepArgs {
    #[command(flatten)]
    keys: RecipientKeys,
    /// Announcement address reported by `scope scan`.
    #[arg(long)]
    announcement: Address,
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    url: String,
    /// Highest priority price paid, micro-lamports per CU; the payer funds P for this cap.
    #[arg(long, default_value_t = scope_client::fees::SWEEP_PRICE_CAP)]
    max_price: u64,
    /// Maximum wait for finalization, in seconds.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
    /// Build and simulate the sweep without sending it.
    #[arg(long)]
    dry_run: bool,
}

fn recipient_chain(url: String) -> RpcChain {
    RpcChain::from(RpcClient::new_with_commitment(
        url,
        solana_commitment_config::CommitmentConfig::confirmed(),
    ))
}

fn run_scan(args: ScanArgs) -> anyhow::Result<()> {
    let recipient = args.keys.load()?;
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "announcement\ttoken_account\tmint\tamount_base_units\tpublic_amount_base_units\tephemeral"
    )?;
    scan::scan_with_results(
        &recipient_chain(args.url),
        &recipient,
        args.mint.as_ref(),
        |result| match result {
            Ok(p) => {
                writeln!(
                    output,
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    p.announcement,
                    p.token_account,
                    p.mint,
                    p.amount,
                    p.public_amount,
                    Address::new_from_array(p.ephemeral)
                )?;
                output.flush()
            }
            Err(error) => writeln!(io::stderr().lock(), "skipped {error}"),
        },
    )?;
    Ok(())
}

fn run_sweep(args: SweepArgs) -> anyhow::Result<()> {
    let recipient = args.keys.load()?;
    let mut chain = recipient_chain(args.url);
    let opts = sweep::SweepOptions {
        max_price_per_cu: args.max_price,
        timeout: Duration::from_secs(args.timeout),
        dry_run: args.dry_run,
        ..Default::default()
    };
    let prepared = sweep::prepare(&chain, &recipient, &args.announcement, &opts)?;
    let report = sweep::submit_with_recovery(&mut chain, prepared, &opts, |report| {
        write_recovery(&mut io::stdout().lock(), report)
    })?;
    println!(
        "{}: {} base units to {}",
        if report.dry_run {
            "simulated"
        } else if report.finalized_signature.is_some() {
            "swept"
        } else {
            "prepared amount"
        },
        report.amount,
        report.destination
    );
    println!(
        "SOL remaining\t{} lamports at {}",
        report.retained_lamports, report.payment_authority
    );
    if !report.dry_run {
        match &report.finalized_signature {
            Some(signature) => println!("finalized_signature\t{signature}"),
            None => println!("payment completed; this attempt's success was not verified"),
        }
    }
    if let Some(amount) = report.burned_public_amount.filter(|amount| *amount > 0) {
        println!(
            "public balance {}: {} base units",
            if report.dry_run { "to burn" } else { "burned" },
            amount
        );
    }
    if report.public_amount_remaining > 0 {
        println!(
            "public balance remaining\t{} base units",
            report.public_amount_remaining
        );
    }
    let rent_status = match (report.reclaimed, report.dry_run) {
        (true, true) => "reclaim simulated",
        (true, false) => "reclaimed",
        (false, true) => "reclaim unavailable; simulated sweep omits cleanup",
        (false, false) => "not reclaimed; funds swept without cleanup",
    };
    println!("rent {rent_status}");
    Ok(())
}

fn write_recovery(output: &mut impl Write, report: &sweep::SweepReport) -> io::Result<()> {
    writeln!(output, "{report}")?;
    output.flush()
}

#[derive(Debug, Args)]
struct PublishArgs {
    #[command(flatten)]
    keys: RecipientKeys,
    /// Wallet the entry is published under; it signs and pays the entry's rent.
    #[arg(long, default_value = "~/.config/solana/id.json")]
    keypair: String,
    /// Remove the wallet's entry and return its rent instead.
    #[arg(long)]
    remove: bool,
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    url: String,
}

#[derive(Debug, Args)]
struct LookupArgs {
    #[arg(required = true)]
    wallets: Vec<Address>,
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    url: String,
}

fn run_publish(args: PublishArgs) -> anyhow::Result<()> {
    let keypair_path = expand_home(&args.keypair)?;
    let wallet = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", keypair_path.display()))?;
    let ix = if args.remove {
        scope_client::ix::deregister(&wallet.pubkey())
    } else {
        scope_client::ix::register(&wallet.pubkey(), &args.keys.load()?.derive_public_keys())
    };
    let rpc = RpcClient::new_with_commitment(
        args.url,
        solana_commitment_config::CommitmentConfig::confirmed(),
    );
    let tx = scope_client::tx::v1_transaction(&wallet, &[], &[ix], rpc.get_latest_blockhash()?);
    let signature = rpc.send_and_confirm_transaction(&tx)?;
    let (entry, _) = scope_client::address::meta_entry_address(&wallet.pubkey());
    println!(
        "{}\t{entry}\t{signature}",
        if args.remove { "removed" } else { "published" }
    );
    Ok(())
}

fn run_lookup(args: LookupArgs) -> anyhow::Result<()> {
    for (wallet, keys) in scope_client::registry::lookup(&recipient_chain(args.url), &args.wallets)?
    {
        match keys {
            Some(keys) => println!("{wallet}\t{}", keys.to_meta_address()),
            None => println!("{wallet}\tnot published"),
        }
    }
    Ok(())
}

#[derive(Debug, Args)]
struct DiscloseArgs {
    /// As the payer: the run holding the payment, with --row.
    #[arg(
        long,
        value_name = "RUN_ID",
        requires = "row",
        conflicts_with = "signature"
    )]
    run: Option<String>,
    /// The row's position in the run's input file, from 0.
    #[arg(long)]
    row: Option<usize>,
    /// Payer keypair, with --run.
    #[arg(long, default_value = "~/.config/solana/id.json")]
    keypair: String,
    #[arg(long, default_value = "runs")]
    runs: PathBuf,
    /// As a stealth recipient: the payment transaction's signature.
    #[arg(long, required_unless_present = "run")]
    signature: Option<String>,
    #[command(flatten)]
    keys: RecipientKeys,
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    url: String,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Receipt file from `scope disclose`.
    receipt: PathBuf,
    /// An RPC node that keeps transaction history.
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    url: String,
}

fn run_disclose(args: DiscloseArgs) -> anyhow::Result<()> {
    let chain = recipient_chain(args.url);
    let receipt = match (args.run, args.signature) {
        (Some(run_id), _) => {
            let keypair_path = expand_home(&args.keypair)?;
            let payer = read_keypair_file(&keypair_path)
                .map_err(|e| anyhow::anyhow!("{}: {e}", keypair_path.display()))?;
            let opts = PayOptions {
                runs_dir: args.runs,
                max_price_per_cu: 0,
                poll: Duration::from_secs(2),
                again: false,
                log: |line| eprintln!("{line}"),
            };
            pay::disclose(&chain, &payer, &run_id, args.row.context("--row")?, &opts)?
        }
        (None, Some(signature)) => {
            let signature: solana_signature::Signature =
                signature.parse().context("--signature")?;
            receipt::disclose_as_recipient(&chain, &args.keys.load()?, &signature)?
        }
        (None, None) => bail!("--run or --signature"),
    };
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

fn run_verify(args: VerifyArgs) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&args.receipt)
        .with_context(|| format!("reading {}", args.receipt.display()))?;
    let receipt: receipt::Receipt = serde_json::from_str(&text).context("parsing the receipt")?;
    let verified = receipt::verify(&recipient_chain(args.url), &receipt)?;
    println!("verified\t{}", verified.signature);
    println!("amount_base_units\t{}", verified.amount);
    println!("payer\t{}", verified.payer);
    println!("source\t{}", verified.source);
    println!("destination\t{}", verified.destination);
    println!("mint\t{}", verified.mint);
    Ok(())
}

#[derive(Debug, Args)]
struct PayArgs {
    /// `recipient,amount` rows; recipient is a configured confidential token account (plain row)
    /// or a `scope:` meta-address (stealth row).
    #[arg(long, required_unless_present_any = ["resume", "status"], conflicts_with_all = ["resume", "status"])]
    input: Option<PathBuf>,
    /// Token-2022 mint with confidential transfers enabled.
    #[arg(long, required_unless_present_any = ["resume", "status"], conflicts_with_all = ["resume", "status"])]
    mint: Option<Address>,
    /// The payer's confidential token account to pay from, configured with the keys
    /// spl-token-cli derives from --keypair.
    #[arg(long, required_unless_present_any = ["resume", "status"], conflicts_with_all = ["resume", "status"])]
    source: Option<Address>,
    /// Continue an interrupted run.
    #[arg(long, value_name = "RUN_ID", conflicts_with = "status")]
    resume: Option<String>,
    /// Show where each stealth row of a run stands: unpaid, open, swept or reclaimed.
    #[arg(long, value_name = "RUN_ID")]
    status: Option<String>,
    /// With --status, return the rent of every swept stealth row to the payer.
    #[arg(long, requires = "status")]
    reclaim: bool,
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
    let chain = RpcChain::from(RpcClient::new(args.url));
    let opts = PayOptions {
        runs_dir: args.runs,
        max_price_per_cu: args.max_price,
        poll: Duration::from_secs(2),
        again: args.again,
        log: |line| eprintln!("{line}"),
    };
    if let Some(run_id) = args.status {
        let mut chain = chain;
        let rows = if args.reclaim {
            pay::reclaim(&mut chain, &payer, &run_id, &opts)?
        } else {
            pay::status(&chain, &payer, &run_id, &opts)?
        };
        println!("row\ttoken_account\tannouncement\tstate");
        for s in rows {
            let state = match s.state {
                pay::StealthState::Unpaid => "unpaid",
                pay::StealthState::Open => "open",
                pay::StealthState::Swept => "swept",
                pay::StealthState::Reclaimed => "reclaimed",
            };
            println!(
                "{}\t{}\t{}\t{state}",
                s.row, s.token_account, s.announcement
            );
        }
        return Ok(());
    }
    let report = match args.resume {
        Some(run_id) => {
            let keys = SourceKeys::from_signer(&payer)?;
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
            let keys = SourceKeys::from_signer(&payer)?;
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
        Command::Register(args) => {
            let path = expand_home(&args.recipient_key)?;
            let address = recipient_keys::create(&path, args.encrypt_to.as_deref())?;
            println!("{address}");
            eprintln!("recipient backup: {}", path.display());
            Ok(())
        }
        Command::Publish(args) => run_publish(args),
        Command::Lookup(args) => run_lookup(args),
        Command::Scan(args) => run_scan(args),
        Command::Sweep(args) => run_sweep(args),
        Command::Disclose(args) => run_disclose(args),
        Command::Verify(args) => run_verify(args),
        other => bail!("{other:?} is not implemented yet"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecoveryOutput {
        bytes: Vec<u8>,
        flushed: bool,
        fail_flush: bool,
    }

    impl Write for RecoveryOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                return Err(io::Error::other("flush failed"));
            }
            self.flushed = true;
            Ok(())
        }
    }

    #[test]
    fn recovery_output_must_be_flushed_before_submission() {
        let report = sweep::SweepReport {
            destination: Address::default(),
            destination_owner: Address::default(),
            payment_authority: Address::default(),
            retained_lamports: 0,
            ephemeral: [7; 32],
            amount: 1,
            burned_public_amount: Some(0),
            public_amount_remaining: 0,
            attempt_signature: "attempt".into(),
            finalized_signature: None,
            reclaimed: false,
            dry_run: false,
        };
        let mut output = RecoveryOutput::default();
        write_recovery(&mut output, &report).expect("recovery");
        assert!(output.flushed);
        let text = String::from_utf8(output.bytes).expect("text");
        assert!(text.contains(&Address::new_from_array(report.ephemeral).to_string()));
        assert!(text.contains("attempt_signature\tattempt"));
        let mut output = RecoveryOutput {
            fail_flush: true,
            ..Default::default()
        };
        assert!(write_recovery(&mut output, &report).is_err());
        assert!(!output.flushed);
    }

    #[test]
    fn recipient_commands_parse_and_sweep_requires_an_announcement() {
        assert!(matches!(
            Cli::try_parse_from(["scope", "register", "--encrypt-to", "age1example"])
                .expect("register")
                .command,
            Command::Register(_)
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "scope",
                "scan",
                "--recipient-key",
                "recipient.age",
                "--identity",
                "identity.txt"
            ])
            .expect("scan")
            .command,
            Command::Scan(_)
        ));
        assert!(Cli::try_parse_from(["scope", "sweep"]).is_err());
        let address = Address::default().to_string();
        assert!(matches!(
            Cli::try_parse_from(["scope", "sweep", "--announcement", &address, "--dry-run"])
                .expect("sweep")
                .command,
            Command::Sweep(SweepArgs { dry_run: true, .. })
        ));
        assert!(
            Cli::try_parse_from([
                "scope",
                "sweep",
                "--announcement",
                &address,
                "--timeout",
                "0"
            ])
            .is_err()
        );
    }
}
