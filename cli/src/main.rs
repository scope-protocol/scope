#![forbid(unsafe_code)]

mod private_files;
mod recipient_keys;
mod recovery;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use scope_client::{
    chain::{Chain, RpcChain},
    history,
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
    /// Create your recipient key backup and print the meta-address payers send to.
    Register(RegisterArgs),
    /// Pay a batch of plain and stealth recipients.
    Pay(PayArgs),
    /// Publish your meta-address under a wallet in the on-chain registry, or remove it.
    Publish(PublishArgs),
    /// Print the meta-addresses wallets published, fetched in one query.
    Lookup(LookupArgs),
    /// Print your meta-address from the key backup.
    MetaAddress(MetaAddressArgs),
    /// Find payments addressed to you.
    Scan(ScanArgs),
    /// List payments to you from transaction history, including swept ones.
    Recover(RecoverArgs),
    /// Move a found payment into a fresh account of your own.
    Sweep(SweepArgs),
    #[command(about = "Export one sweep's owner as a private Solana keypair file.")]
    ExportSweepKey(ExportSweepKeyArgs),
    /// Produce a receipt that proves one payment's amount.
    Disclose(DiscloseArgs),
    /// Check a receipt against the chain.
    Verify(VerifyArgs),
    /// Not implemented: will measure bytes, compute and cost per transaction.
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
    /// Age identity file; decrypts the new backup to check it can be read back.
    #[arg(long, requires = "encrypt_to")]
    verify_identity: Option<String>,
}

#[derive(Debug, Args)]
struct MetaAddressArgs {
    #[command(flatten)]
    keys: RecipientKeys,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    #[command(flatten)]
    keys: RecipientKeys,
    /// RPC node; defaults to $SCOPE_URL, else http://127.0.0.1:8899.
    #[arg(long)]
    url: Option<String>,
    /// Program transactions to examine, newest first.
    #[arg(long, default_value_t = history::DEFAULT_LIMIT)]
    limit: usize,
    /// Stop at this signature; earlier transactions are not examined.
    #[arg(long)]
    since: Option<solana_signature::Signature>,
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[command(flatten)]
    keys: RecipientKeys,
    /// RPC node; defaults to $SCOPE_URL, else http://127.0.0.1:8899.
    #[arg(long)]
    url: Option<String>,
    /// Show payments for only this mint.
    #[arg(long)]
    mint: Option<Address>,
    /// Hide payments below this many base units.
    #[arg(long, default_value_t = 0)]
    min_amount: u64,
    /// Hide payments from this payer; repeat for several.
    #[arg(long = "ignore-payer")]
    ignore_payer: Vec<Address>,
    /// Add each payment's signature, looked up in transaction history (one extra query each).
    #[arg(long)]
    with_signature: bool,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("target").required(true).args(["announcement", "all"])))]
struct SweepArgs {
    #[command(flatten)]
    keys: RecipientKeys,
    /// Announcement address reported by `scope scan`.
    #[arg(long)]
    announcement: Option<Address>,
    /// Sweep every payment `scan` finds, one transaction each, stopping at the first failure.
    #[arg(long)]
    all: bool,
    /// With --all: only this mint.
    #[arg(long, conflicts_with = "announcement")]
    mint: Option<Address>,
    /// With --all: skip payments below this many base units.
    #[arg(long, conflicts_with = "announcement", default_value_t = 1)]
    min_amount: u64,
    /// With --all: skip payments from this payer; repeat for several.
    #[arg(long = "ignore-payer", conflicts_with = "announcement")]
    ignore_payer: Vec<Address>,
    /// With --all: wait a random 0 to this many seconds between sweeps (30 to 300 suggested).
    #[arg(long, conflicts_with = "announcement", default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=86_400))]
    jitter_secs: u64,
    /// RPC node; defaults to $SCOPE_URL, else http://127.0.0.1:8899.
    #[arg(long)]
    url: Option<String>,
    /// Highest priority price paid, micro-lamports per CU; the payer funds P for this cap.
    #[arg(long, default_value_t = scope_client::fees::SWEEP_PRICE_CAP)]
    max_price: u64,
    /// Maximum wait for finalization, in seconds.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
    /// Build and simulate the sweep without sending it.
    #[arg(long)]
    dry_run: bool,
    #[arg(
        long,
        help = "Recovery journal path; defaults to <recipient-key>.sweeps.jsonl."
    )]
    recovery_file: Option<String>,
}

#[derive(Debug, Args)]
struct ExportSweepKeyArgs {
    #[command(flatten)]
    keys: RecipientKeys,
    #[arg(long, help = "Public R from scan, sweep, or the recovery journal.")]
    ephemeral: Address,
    #[arg(
        long,
        help = "The payment's token account T from scan, sweep, or the recovery journal."
    )]
    token_account: Address,
    #[arg(
        long,
        help = "New owner-only keypair file; existing files are never overwritten."
    )]
    output: String,
    /// Write the keypair JSON encrypted to this age public recipient (requires age).
    #[arg(long)]
    encrypt_to: Option<String>,
}

fn recipient_chain(url: String) -> RpcChain {
    RpcChain::from(RpcClient::new_with_commitment(
        url,
        solana_commitment_config::CommitmentConfig::confirmed(),
    ))
}

fn run_scan(args: ScanArgs) -> anyhow::Result<()> {
    let recipient = args.keys.load()?;
    let chain = recipient_chain(rpc_url(args.url));
    let filter = scan::PaymentFilter {
        min_amount: args.min_amount,
        ignore_payers: args.ignore_payer,
    };
    let mut output = io::stdout().lock();
    write!(
        output,
        "announcement\ttoken_account\tpayer\tmint\tamount_base_units\tpublic_amount_base_units\tephemeral"
    )?;
    writeln!(
        output,
        "{}",
        if args.with_signature {
            "\tsignature"
        } else {
            ""
        }
    )?;
    scan::scan_with_results(
        &chain,
        &recipient,
        args.mint.as_ref(),
        |result| match result {
            Ok(p) if !filter.accepts(p) => Ok(()),
            Ok(p) => {
                write!(
                    output,
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    p.announcement,
                    p.token_account,
                    p.payer,
                    p.mint,
                    p.amount,
                    p.public_amount,
                    Address::new_from_array(p.ephemeral)
                )?;
                if args.with_signature {
                    match history::payment_signature(&chain, &p.token_account) {
                        Ok(Some(signature)) => write!(output, "\t{signature}")?,
                        Ok(None) => write!(output, "\tunknown")?,
                        Err(error) => {
                            writeln!(
                                io::stderr().lock(),
                                "signature for {}: {error}",
                                p.token_account
                            )?;
                            write!(output, "\tunknown")?;
                        }
                    }
                }
                writeln!(output)?;
                output.flush()
            }
            Err(error) => writeln!(io::stderr().lock(), "skipped {error}"),
        },
    )?;
    Ok(())
}

fn run_meta_address(args: MetaAddressArgs) -> anyhow::Result<()> {
    println!(
        "{}",
        args.keys.load()?.derive_public_keys().to_meta_address()
    );
    Ok(())
}

fn run_recover(args: RecoverArgs) -> anyhow::Result<()> {
    let recipient = args.keys.load()?;
    let chain = recipient_chain(rpc_url(args.url));
    let report = history::recover(
        &chain,
        &chain,
        &recipient,
        &history::RecoverOptions {
            limit: args.limit,
            since: args.since,
        },
    )?;
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "payer\tmint\ttoken_account\tephemeral\tsignature\tdestination\tdestination_exists\tdestination_lamports\tdestination_base_units"
    )?;
    for p in &report.found {
        let (exists, lamports, amount) = match &p.destination_state {
            Some(d) => (
                "yes",
                d.lamports.to_string(),
                d.amount.map_or("unknown".into(), |a| a.to_string()),
            ),
            None => ("no", "-".into(), "-".into()),
        };
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}\t{}\t{exists}\t{lamports}\t{amount}",
            p.payer,
            p.mint,
            p.token_account,
            Address::new_from_array(p.ephemeral),
            p.signature,
            p.destination
        )?;
    }
    eprintln!(
        "examined {} transactions, found {} payments",
        report.examined,
        report.found.len()
    );
    if report.unavailable > 0 {
        eprintln!(
            "warning: the node would not return {} listed transactions; use an RPC that keeps history for the program",
            report.unavailable
        );
    }
    Ok(())
}

fn run_register(args: RegisterArgs) -> anyhow::Result<()> {
    let path = expand_home(&args.recipient_key)?;
    let address = recipient_keys::create(&path, args.encrypt_to.as_deref())?;
    println!("{address}");
    eprintln!("recipient backup: {}", path.display());
    match &args.verify_identity {
        Some(identity) => {
            recipient_keys::verify_readback(&path, &expand_home(identity)?, &address)
                .context("the new backup does not decrypt with that identity; do not rely on it")?;
            eprintln!("backup decrypted and matches the meta-address");
        }
        None if args.encrypt_to.is_some() => eprintln!(
            "warning: the encrypted backup was not read back; check it with `scope meta-address --identity <file>` or pass --verify-identity"
        ),
        None => eprintln!(
            "warning: the backup is a plaintext file; anyone who can read it can spend your payments (use --encrypt-to)"
        ),
    }
    Ok(())
}

fn run_sweep(args: SweepArgs) -> anyhow::Result<()> {
    let recipient = args.keys.load()?;
    let mut chain = recipient_chain(rpc_url(args.url));
    let opts = sweep::SweepOptions {
        max_price_per_cu: args.max_price,
        timeout: Duration::from_secs(args.timeout),
        dry_run: args.dry_run,
        ..Default::default()
    };
    let mut journal = if opts.dry_run {
        None
    } else {
        let path = match &args.recovery_file {
            Some(path) => expand_home(path)?,
            None => recovery::default_path(&expand_home(&args.keys.recipient_key)?),
        };
        Some(
            recovery::RecoveryJournal::open(&path)
                .with_context(|| format!("opening recovery journal {}", path.display()))?,
        )
    };
    let Some(announcement) = args.announcement else {
        let filter = scan::PaymentFilter {
            min_amount: args.min_amount,
            ignore_payers: args.ignore_payer,
        };
        let found =
            scan::scan_with_results(
                &chain,
                &recipient,
                args.mint.as_ref(),
                |result| match result {
                    Ok(_) => Ok(()),
                    Err(error) => writeln!(io::stderr().lock(), "skipped {error}"),
                },
            )?;
        let announcements: Vec<Address> = found
            .payments
            .iter()
            .filter(|p| filter.accepts(p))
            .map(|p| p.announcement)
            .collect();
        // A dry run sends nothing, so there is no timing to hide.
        let jitter = if opts.dry_run { 0 } else { args.jitter_secs };
        return sweep_all(
            &announcements,
            jitter,
            &mut random_up_to,
            &mut std::thread::sleep,
            &mut |announcement| {
                println!("announcement\t{announcement}");
                sweep_one(
                    &mut chain,
                    &recipient,
                    announcement,
                    &opts,
                    journal.as_mut(),
                )
            },
            &mut io::stdout().lock(),
        );
    };
    sweep_one(
        &mut chain,
        &recipient,
        &announcement,
        &opts,
        journal.as_mut(),
    )
}

/// A uniform-enough value in `0..=max`; the bias of a modulo over 64 bits is irrelevant for a delay.
fn random_up_to(max: u64) -> u64 {
    getrandom::u64().map_or(max, |value| value % (max + 1))
}

/// Sweeps each announcement in order, waiting a random 0 to `jitter_secs` between them, and
/// stops at the first failure after saying how far it got.
fn sweep_all(
    announcements: &[Address],
    jitter_secs: u64,
    random: &mut dyn FnMut(u64) -> u64,
    sleep: &mut dyn FnMut(Duration),
    sweep: &mut dyn FnMut(&Address) -> anyhow::Result<()>,
    output: &mut dyn Write,
) -> anyhow::Result<()> {
    let total = announcements.len();
    if total == 0 {
        writeln!(output, "no payments to sweep")?;
        return Ok(());
    }
    for (done, announcement) in announcements.iter().enumerate() {
        if done > 0 && jitter_secs > 0 {
            let wait = random(jitter_secs);
            writeln!(output, "waiting {wait}s before the next sweep")?;
            output.flush()?;
            sleep(Duration::from_secs(wait));
        }
        if let Err(error) = sweep(announcement) {
            writeln!(
                output,
                "stopped: {done} of {total} swept, {announcement} failed"
            )?;
            return Err(error.context(format!("sweeping {announcement}")));
        }
    }
    writeln!(output, "swept {total} of {total}")?;
    Ok(())
}

fn sweep_one(
    chain: &mut RpcChain,
    recipient: &stealth_keygen::RecipientSecretKeys,
    announcement: &Address,
    opts: &sweep::SweepOptions,
    mut journal: Option<&mut recovery::RecoveryJournal>,
) -> anyhow::Result<()> {
    let prepared = sweep::prepare(chain, recipient, announcement, opts)?;
    let report = sweep::submit_with_recovery(chain, prepared, opts, |report| {
        checkpoint(&mut io::stdout().lock(), journal.as_deref_mut(), report)
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
    match report.retained_lamports {
        Some(lamports) => println!(
            "SOL {}remaining\t{lamports} lamports at {}",
            if report.dry_run { "predicted " } else { "" },
            report.payment_authority
        ),
        None => println!("SOL remaining\tunknown at {}", report.payment_authority),
    }
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
    if let Some(amount) = report.public_amount_remaining.filter(|amount| *amount > 0) {
        println!("public balance remaining\t{amount} base units");
    } else if report.public_amount_remaining.is_none() {
        println!("public balance remaining\tunknown");
    }
    let rent_status = match (report.reclaimed, report.dry_run) {
        (Some(true), true) => "reclaim simulated",
        (Some(true), false) => "reclaimed",
        (Some(false), true) => "reclaim unavailable; simulated sweep omits cleanup",
        (Some(false), false) => "not reclaimed by this attempt; funds swept without cleanup",
        (None, _) => "reclaim status unknown",
    };
    println!("rent {rent_status}");
    Ok(())
}

fn run_export_sweep_key(args: ExportSweepKeyArgs) -> anyhow::Result<()> {
    let recipient = args.keys.load()?;
    let path = expand_home(&args.output)?;
    let owner = recipient_keys::export_owner(
        &path,
        &recipient,
        &args.ephemeral.to_bytes(),
        &args.token_account.to_bytes(),
        args.encrypt_to.as_deref(),
    )?;
    println!(
        "owner\t{}\ndestination\t{}",
        owner.pubkey(),
        sweep::destination_address(&owner.pubkey())
    );
    Ok(())
}

fn checkpoint(
    output: &mut impl Write,
    journal: Option<&mut recovery::RecoveryJournal>,
    report: &sweep::SweepReport,
) -> io::Result<()> {
    if !report.dry_run {
        journal
            .ok_or_else(|| io::Error::other("recovery journal is required before broadcast"))?
            .append(report)?;
    }
    write_recovery(output, report)
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
    /// RPC node; defaults to $SCOPE_URL, else http://127.0.0.1:8899.
    #[arg(long)]
    url: Option<String>,
}

#[derive(Debug, Args)]
struct LookupArgs {
    #[arg(required = true)]
    wallets: Vec<Address>,
    /// RPC node; defaults to $SCOPE_URL, else http://127.0.0.1:8899.
    #[arg(long)]
    url: Option<String>,
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
        rpc_url(args.url),
        solana_commitment_config::CommitmentConfig::confirmed(),
    );
    let tx = scope_client::tx::legacy_transaction(&wallet, &[ix], rpc.get_latest_blockhash()?);
    let signature = rpc.send_and_confirm_transaction(&tx)?;
    let (entry, _) = scope_client::address::meta_entry_address(&wallet.pubkey());
    println!(
        "{}\t{entry}\t{signature}",
        if args.remove { "removed" } else { "published" }
    );
    Ok(())
}

fn run_lookup(args: LookupArgs) -> anyhow::Result<()> {
    for (wallet, keys) in
        scope_client::registry::lookup(&recipient_chain(rpc_url(args.url)), &args.wallets)?
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
    #[arg(long, requires = "run")]
    row: Option<usize>,
    /// Payer keypair, with --run.
    #[arg(long, default_value = "~/.config/solana/id.json")]
    keypair: String,
    #[arg(long, default_value = DEFAULT_RUNS)]
    runs: String,
    /// As a stealth recipient: the payment transaction's signature.
    #[arg(long, required_unless_present_any = ["run", "token_account"])]
    signature: Option<String>,
    /// As a stealth recipient without the signature: the payment's token account from `scan`,
    /// `recover` or the recovery journal; the signature is found in transaction history.
    #[arg(long, conflicts_with_all = ["run", "signature"])]
    token_account: Option<Address>,
    #[command(flatten)]
    keys: RecipientKeys,
    /// Write the receipt to this new file, owner-only, instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
    /// RPC node; defaults to $SCOPE_URL, else http://127.0.0.1:8899.
    #[arg(long)]
    url: Option<String>,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Receipt file from `scope disclose`.
    receipt: PathBuf,
    /// An RPC node that keeps transaction history.
    /// RPC node; defaults to $SCOPE_URL, else http://127.0.0.1:8899.
    #[arg(long)]
    url: Option<String>,
}

fn run_disclose(args: DiscloseArgs) -> anyhow::Result<()> {
    let chain = recipient_chain(rpc_url(args.url));
    let receipt = match (args.run, args.signature) {
        (Some(run_id), _) => {
            let keypair_path = expand_home(&args.keypair)?;
            let payer = read_keypair_file(&keypair_path)
                .map_err(|e| anyhow::anyhow!("{}: {e}", keypair_path.display()))?;
            let opts = PayOptions {
                runs_dir: runs_dir(&args.runs)?,
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
        (None, None) => {
            let token_account = args
                .token_account
                .context("--run, --signature or --token-account")?;
            let signature = history::payment_signature(&chain, &token_account)?.with_context(|| {
                format!("no payment transaction for {token_account} in this node's history; pass --signature")
            })?;
            eprintln!("payment signature: {signature}");
            receipt::disclose_as_recipient(&chain, &args.keys.load()?, &signature)?
        }
    };
    receipt::verify(&chain, &receipt)
        .context("the receipt does not verify against the chain; nothing written")?;
    let text = serde_json::to_string_pretty(&receipt)?;
    match args.out {
        Some(path) => private_files::create(&path, |file| Ok(file.write_all(text.as_bytes())?))?,
        None => {
            if matches!(receipt, receipt::Receipt::AccountKey { .. }) {
                eprintln!(
                    "this receipt grants read access to the one-time account; --out writes it owner-only"
                );
            }
            println!("{text}");
        }
    }
    Ok(())
}

fn run_verify(args: VerifyArgs) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&args.receipt)
        .with_context(|| format!("reading {}", args.receipt.display()))?;
    let receipt: receipt::Receipt = serde_json::from_str(&text).context("parsing the receipt")?;
    let verified = receipt::verify(&recipient_chain(rpc_url(args.url)), &receipt)?;
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
    #[arg(long, required_unless_present_any = ["resume", "status", "reclaim_all"], conflicts_with_all = ["resume", "status", "reclaim_all"])]
    input: Option<PathBuf>,
    /// Token-2022 mint with confidential transfers enabled.
    #[arg(long, required_unless_present_any = ["resume", "status", "reclaim_all"], conflicts_with_all = ["resume", "status", "reclaim_all"])]
    mint: Option<Address>,
    /// The payer's confidential token account to pay from, configured with the keys
    /// spl-token-cli derives from --keypair.
    #[arg(long, required_unless_present_any = ["resume", "status", "reclaim_all"], conflicts_with_all = ["resume", "status", "reclaim_all"])]
    source: Option<Address>,
    /// Continue an interrupted run.
    #[arg(long, value_name = "RUN_ID", conflicts_with_all = ["status", "reclaim_all", "dry_run"])]
    resume: Option<String>,
    /// Show a run's rows landed and state, plain rows, and where each stealth row stands:
    /// unpaid, unresolved, open, swept or reclaimed.
    #[arg(long, value_name = "RUN_ID", conflicts_with_all = ["reclaim_all", "dry_run"])]
    status: Option<String>,
    /// With --status, return the rent of every swept stealth row to the payer.
    #[arg(long, requires = "status")]
    reclaim: bool,
    /// Return the rent of every swept one-time account this payer ever made, found on chain
    /// and without a run journal.
    #[arg(long, conflicts_with_all = ["dry_run", "yes"])]
    reclaim_all: bool,
    /// Run every preflight and print the plan and its cost; send nothing, write no journal.
    #[arg(long, conflicts_with_all = ["resume", "status", "reclaim_all"])]
    dry_run: bool,
    /// Confirm a real run on mainnet-beta.
    #[arg(long)]
    yes: bool,
    /// Payer keypair: owns the source and pays every fee.
    #[arg(long, default_value = "~/.config/solana/id.json")]
    keypair: String,
    /// RPC node; defaults to $SCOPE_URL, else http://127.0.0.1:8899.
    #[arg(long)]
    url: Option<String>,
    /// Directory holding one journal per run.
    #[arg(long, default_value = DEFAULT_RUNS)]
    runs: String,
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

const DEFAULT_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_RUNS: &str = "~/.local/share/scope/runs";

/// `--url`, else `SCOPE_URL`, else the local validator.
fn rpc_url(flag: Option<String>) -> String {
    pick_url(flag, std::env::var("SCOPE_URL").ok())
}

fn pick_url(flag: Option<String>, env: Option<String>) -> String {
    flag.or(env.filter(|url| !url.is_empty()))
        .unwrap_or_else(|| DEFAULT_URL.into())
}

/// The journal directory as an absolute path, so a run can be resumed from anywhere.
fn runs_dir(path: &str) -> anyhow::Result<PathBuf> {
    let path = expand_home(path)?;
    std::path::absolute(&path).with_context(|| format!("resolving {}", path.display()))
}

fn run_pay(args: PayArgs) -> anyhow::Result<()> {
    let keypair_path = expand_home(&args.keypair)?;
    let payer = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", keypair_path.display()))?;
    let chain = RpcChain::from(RpcClient::new(rpc_url(args.url)));
    let opts = PayOptions {
        runs_dir: runs_dir(&args.runs)?,
        max_price_per_cu: args.max_price,
        poll: Duration::from_secs(2),
        again: args.again,
        log: |line| eprintln!("{line}"),
    };
    if let Some(run_id) = args.status {
        let mut chain = chain;
        return print_status(&mut chain, &payer, &run_id, args.reclaim, &opts);
    }
    if args.reclaim_all {
        let mut chain = chain;
        println!("announcement\ttoken_account\toutcome");
        for r in pay::reclaim_all(&mut chain, &payer, &opts)? {
            let outcome = match r.outcome {
                pay::ReclaimOutcome::Reclaimed => "reclaimed".to_string(),
                pay::ReclaimOutcome::StillHolding => "still holds a balance".to_string(),
                pay::ReclaimOutcome::Failed(why) => format!("failed: {why}"),
            };
            println!("{}\t{}\t{outcome}", r.announcement, r.token_account);
        }
        return Ok(());
    }
    if args.dry_run {
        let (input, mint, source) = (
            args.input.context("--input")?,
            args.mint.context("--mint")?,
            args.source.context("--source")?,
        );
        let bytes =
            std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
        let keys = SourceKeys::from_signer(&payer)?;
        let plan = pay::dry_run(&chain, &payer, &keys, mint, source, &bytes, &opts)?;
        print_plan(&plan, opts.max_price_per_cu);
        if plan.payer_have < plan.payer_need {
            bail!(
                "the payer needs {} SOL and has {}",
                pay::sol(plan.payer_need),
                pay::sol(plan.payer_have)
            );
        }
        return Ok(());
    }
    pay::mainnet_gate(&chain.genesis_hash()?, args.yes).map_err(anyhow::Error::msg)?;
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

fn print_plan(plan: &pay::DryRun, max_price: u64) {
    let short = plan.payer_need.saturating_sub(plan.payer_have);
    println!("cluster\t{}", plan.cluster);
    println!(
        "rows\t{} ({} plain, {} stealth)",
        plan.rows, plan.plain_rows, plan.stealth_rows
    );
    println!(
        "total\t{} ({} base units)",
        pay::token_amount(plan.total, plan.decimals),
        plan.total
    );
    println!(
        "payer SOL\tneeds {}, has {}{}",
        pay::sol(plan.payer_need),
        pay::sol(plan.payer_have),
        if short > 0 {
            format!(", short by {}", pay::sol(short))
        } else {
            String::new()
        }
    );
    println!(
        "fee cap per row\t{} lamports plain, {} stealth, at {max_price} micro-lamports/CU",
        plan.fee_cap_plain, plan.fee_cap_stealth
    );
    println!("fee price now\t{} micro-lamports/CU", plan.price);
    println!("nothing sent, no journal written");
}

fn print_status(
    chain: &mut RpcChain,
    payer: &solana_keypair::Keypair,
    run_id: &str,
    reclaim: bool,
    opts: &PayOptions,
) -> anyhow::Result<()> {
    let stealth = if reclaim {
        pay::reclaim(chain, payer, run_id, opts)?
    } else {
        pay::status(chain, payer, run_id, opts)?
    };
    let summary = pay::summary(chain, payer, run_id, opts)?;
    let state = match &summary.state {
        pay::RunState::Done => "done".to_string(),
        pay::RunState::Halted(why) => format!("halted: {why}"),
        pay::RunState::Unfinished => format!("unfinished; scope pay --resume {run_id}"),
    };
    println!(
        "run {run_id}: {}/{} rows landed, {state}",
        summary.landed, summary.rows
    );
    println!(
        "journal: {}",
        opts.runs_dir
            .join(run_id)
            .join(scope_client::journal::JOURNAL)
            .display()
    );
    if !summary.plain.is_empty() {
        println!("row\trecipient\tstate\tsignature");
        for p in &summary.plain {
            let state = match p.state {
                pay::PlainState::Unpaid => "unpaid",
                pay::PlainState::Attempted => "unresolved, resume the run",
                pay::PlainState::Landed => "landed",
            };
            println!(
                "{}\t{}\t{state}\t{}",
                p.row,
                p.recipient,
                p.signature.as_deref().unwrap_or("")
            );
        }
    }
    if !stealth.is_empty() {
        println!("row\ttoken_account\tannouncement\tstate");
        for s in stealth {
            let state = match s.state {
                pay::StealthState::Unpaid => "unpaid",
                pay::StealthState::Unresolved => "unresolved, resume the run",
                pay::StealthState::Open => "open",
                pay::StealthState::Swept => "swept",
                pay::StealthState::Reclaimed => "reclaimed",
            };
            println!(
                "{}\t{}\t{}\t{state}",
                s.row, s.token_account, s.announcement
            );
        }
    }
    Ok(())
}

/// Exit codes: 0 done, 1 refused or failed before anything was sent, 2 bad arguments (clap),
/// 3 transient, retry or resume later, 4 stopped after sending, inspect then resume.
fn exit_code(error: &anyhow::Error) -> u8 {
    use scope_client::{chain::ChainError, pay::PayError};
    for cause in error.chain() {
        if let Some(pay) = cause.downcast_ref::<PayError>() {
            return match pay {
                PayError::FeeAboveCap { .. } | PayError::Chain(_) => 3,
                PayError::Halted(_) | PayError::Simulation { .. } => 4,
                _ => 1,
            };
        }
        if cause.downcast_ref::<ChainError>().is_some() {
            return 3;
        }
    }
    1
}

fn main() -> std::process::ExitCode {
    let result = match Cli::parse().command {
        Command::Pay(args) => run_pay(args),
        Command::Register(args) => run_register(args),
        Command::MetaAddress(args) => run_meta_address(args),
        Command::Recover(args) => run_recover(args),
        Command::Publish(args) => run_publish(args),
        Command::Lookup(args) => run_lookup(args),
        Command::Scan(args) => run_scan(args),
        Command::Sweep(args) => run_sweep(args),
        Command::Disclose(args) => run_disclose(args),
        Command::Verify(args) => run_verify(args),
        Command::ExportSweepKey(args) => run_export_sweep_key(args),
        other => Err(anyhow::anyhow!("{other:?} is not implemented yet")),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::from(exit_code(&error))
        }
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

    pub(super) fn report() -> sweep::SweepReport {
        sweep::SweepReport {
            genesis_hash: [42; 32],
            destination: Address::default(),
            destination_owner: Address::default(),
            payment_authority: Address::default(),
            retained_lamports: Some(0),
            ephemeral: [7; 32],
            token_account: Address::new_from_array([8; 32]),
            amount: 1,
            burned_public_amount: Some(0),
            public_amount_remaining: Some(0),
            attempt_signature: "attempt".into(),
            finalized_signature: None,
            last_send_error: None,
            reclaimed: Some(false),
            dry_run: false,
        }
    }

    #[test]
    fn recovery_output_must_be_flushed_before_submission() {
        let report = report();
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
    fn checkpoint_requires_durable_recovery_and_dry_runs_do_not_append() {
        use std::fs;
        let dir = private_files::test_directory();
        let path = dir.join("recovery.jsonl");
        let mut journal = recovery::RecoveryJournal::open(&path).expect("journal");
        let mut output = RecoveryOutput {
            fail_flush: true,
            ..Default::default()
        };
        let mut report = report();
        assert!(checkpoint(&mut output, Some(&mut journal), &report).is_err());
        let before = fs::read(&path).expect("durable record");
        let lines = String::from_utf8(before.clone()).expect("json");
        let saved: serde_json::Value =
            serde_json::from_str(lines.lines().nth(1).expect("record")).expect("record");
        assert_eq!(saved["attempt_signature"], report.attempt_signature);
        let mut output = Vec::new();
        assert!(checkpoint(&mut output, None, &report).is_err());
        assert!(output.is_empty());
        report.dry_run = true;
        checkpoint(&mut output, Some(&mut journal), &report).expect("dry run");
        assert_eq!(fs::read(&path).expect("unchanged"), before);
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn exit_codes_tell_retry_from_inspect_from_refused() {
        use scope_client::{chain::ChainError, pay::PayError};
        let code = |e: PayError| exit_code(&anyhow::Error::new(e));
        assert_eq!(code(PayError::FeeAboveCap { price: 2, cap: 1 }), 3);
        assert_eq!(code(PayError::Chain(ChainError("rpc".into()))), 3);
        assert_eq!(code(PayError::Halted("source moved".into())), 4);
        assert_eq!(code(PayError::Insufficient { have: 1, need: 2 }), 1);
        assert_eq!(exit_code(&anyhow::anyhow!("plain")), 1);
        let wrapped = anyhow::Error::new(PayError::Halted("x".into())).context("pay");
        assert_eq!(exit_code(&wrapped), 4);
    }

    #[test]
    fn export_requires_public_r_and_an_explicit_output_file() {
        let ephemeral = Address::new_from_array([3; 32]).to_string();
        assert!(matches!(
            Cli::try_parse_from([
                "scope",
                "export-sweep-key",
                "--ephemeral",
                &ephemeral,
                "--token-account",
                &ephemeral,
                "--output",
                "owner.json"
            ])
            .expect("export command")
            .command,
            Command::ExportSweepKey(_)
        ));
        assert!(
            Cli::try_parse_from([
                "scope",
                "export-sweep-key",
                "--ephemeral",
                &ephemeral,
                "--token-account",
                &ephemeral
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "scope",
                "export-sweep-key",
                "--token-account",
                &ephemeral,
                "--output",
                "owner.json"
            ])
            .is_err()
        );
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

    fn parse(args: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("scope").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn sweep_takes_one_announcement_or_all_and_all_only_flags_need_all() {
        let a = Address::new_unique().to_string();
        assert!(parse(&["sweep"]).is_err());
        assert!(parse(&["sweep", "--announcement", &a, "--all"]).is_err());
        assert!(parse(&["sweep", "--announcement", &a, "--jitter-secs", "30"]).is_err());
        assert!(parse(&["sweep", "--announcement", &a, "--min-amount", "5"]).is_err());
        assert!(parse(&["sweep", "--announcement", &a, "--ignore-payer", &a]).is_err());
        assert!(parse(&["sweep", "--announcement", &a, "--mint", &a]).is_err());
        assert!(parse(&["sweep", "--all", "--jitter-secs", "86401"]).is_err());
        let Command::Sweep(args) = parse(&[
            "sweep",
            "--all",
            "--jitter-secs",
            "120",
            "--min-amount",
            "1000",
            "--ignore-payer",
            &a,
            "--ignore-payer",
            &Address::default().to_string(),
            "--mint",
            &a,
        ])
        .expect("sweep --all") else {
            panic!("not a sweep");
        };
        assert!(args.all && args.announcement.is_none());
        assert_eq!((args.jitter_secs, args.min_amount), (120, 1000));
        assert_eq!(args.ignore_payer.len(), 2);
        let Command::Sweep(args) = parse(&["sweep", "--all"]).expect("defaults") else {
            panic!("not a sweep");
        };
        assert_eq!((args.jitter_secs, args.min_amount), (0, 1));
    }

    #[test]
    fn scan_filters_and_register_verification_parse() {
        let a = Address::new_unique().to_string();
        let Command::Scan(args) = parse(&[
            "scan",
            "--min-amount",
            "7",
            "--ignore-payer",
            &a,
            "--with-signature",
        ])
        .expect("scan") else {
            panic!("not a scan");
        };
        assert_eq!(
            (
                args.min_amount,
                args.ignore_payer.len(),
                args.with_signature
            ),
            (7, 1, true)
        );
        assert!(parse(&["register", "--verify-identity", "id.txt"]).is_err());
        assert!(
            parse(&[
                "register",
                "--encrypt-to",
                "age1x",
                "--verify-identity",
                "id.txt"
            ])
            .is_ok()
        );
        assert!(matches!(
            parse(&["meta-address", "--identity", "id.txt"]),
            Ok(Command::MetaAddress(_))
        ));
        assert!(matches!(
            parse(&["recover", "--limit", "50"]),
            Ok(Command::Recover(_))
        ));
    }

    #[test]
    fn disclose_needs_a_run_a_signature_or_a_token_account_and_only_one() {
        let a = Address::new_unique().to_string();
        let signature = solana_signature::Signature::default().to_string();
        assert!(parse(&["disclose"]).is_err());
        assert!(parse(&["disclose", "--token-account", &a]).is_ok());
        assert!(parse(&["disclose", "--signature", &signature]).is_ok());
        assert!(parse(&["disclose", "--signature", &signature, "--token-account", &a]).is_err());
        assert!(
            parse(&[
                "disclose",
                "--run",
                "r",
                "--row",
                "0",
                "--token-account",
                &a
            ])
            .is_err()
        );
    }

    fn addresses(n: usize) -> Vec<Address> {
        (0..n).map(|_| Address::new_unique()).collect()
    }

    #[test]
    fn sweep_all_waits_between_sweeps_with_the_drawn_delay() {
        let found = addresses(3);
        let mut waits = Vec::new();
        let mut swept = Vec::new();
        let mut draws = vec![17, 4].into_iter();
        let mut bounds = Vec::new();
        let mut output = Vec::new();
        sweep_all(
            &found,
            300,
            &mut |max| {
                bounds.push(max);
                draws.next().expect("draw")
            },
            &mut |d| waits.push(d),
            &mut |a| {
                swept.push(*a);
                Ok(())
            },
            &mut output,
        )
        .expect("all swept");
        assert_eq!(swept, found);
        assert_eq!(waits, [Duration::from_secs(17), Duration::from_secs(4)]);
        assert_eq!(bounds, [300, 300]);
        assert!(
            String::from_utf8(output)
                .expect("text")
                .ends_with("swept 3 of 3\n")
        );
    }

    #[test]
    fn sweep_all_without_jitter_never_sleeps_and_an_empty_list_is_fine() {
        let found = addresses(2);
        let mut output = Vec::new();
        sweep_all(
            &found,
            0,
            &mut |_| panic!("no draw without jitter"),
            &mut |_| panic!("no sleep without jitter"),
            &mut |_| Ok(()),
            &mut output,
        )
        .expect("swept");
        output.clear();
        sweep_all(
            &[],
            60,
            &mut |_| 0,
            &mut |_| panic!("sleep"),
            &mut |_| panic!("sweep"),
            &mut output,
        )
        .expect("nothing to do");
        assert_eq!(
            String::from_utf8(output).expect("text"),
            "no payments to sweep\n"
        );
    }

    #[test]
    fn sweep_all_stops_at_the_first_failure_and_says_how_far_it_got() {
        let found = addresses(4);
        let mut attempted = Vec::new();
        let mut output = Vec::new();
        let error = sweep_all(
            &found,
            10,
            &mut |_| 1,
            &mut |_| {},
            &mut |a| {
                attempted.push(*a);
                if attempted.len() == 3 {
                    anyhow::bail!("payment authority is not funded")
                }
                Ok(())
            },
            &mut output,
        )
        .expect_err("third sweep fails");
        assert_eq!(attempted, found[..3]);
        assert!(format!("{error:#}").contains("payment authority is not funded"));
        let text = String::from_utf8(output).expect("text");
        assert!(text.contains(&format!("stopped: 2 of 4 swept, {} failed", found[2])));
        assert!(!text.contains("swept 4 of 4"));
    }

    #[test]
    fn the_jitter_draw_stays_within_its_bound() {
        for max in [0, 1, 30, 300] {
            for _ in 0..200 {
                assert!(random_up_to(max) <= max);
            }
        }
    }

    fn parse_pay(args: &[&str]) -> Result<PayArgs, clap::Error> {
        let mut argv = vec!["scope", "pay"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).map(|cli| match cli.command {
            Command::Pay(args) => args,
            other => panic!("{other:?}"),
        })
    }

    #[test]
    fn pay_defaults_to_an_absolute_runs_directory_and_an_unset_url() {
        let args = parse_pay(&["--status", "ab"]).expect("status");
        assert_eq!(args.runs, "~/.local/share/scope/runs");
        assert!(args.url.is_none());
        let dir = runs_dir(&args.runs).expect("runs dir");
        assert!(dir.is_absolute());
        assert!(dir.ends_with(".local/share/scope/runs"));
        assert!(runs_dir("runs").expect("relative").is_absolute());
    }

    #[test]
    fn the_rpc_url_comes_from_the_flag_then_the_environment_then_localhost() {
        let own = Some("https://flag".to_string());
        let env = Some("https://env".to_string());
        assert_eq!(pick_url(own.clone(), env.clone()), "https://flag");
        assert_eq!(pick_url(None, env), "https://env");
        assert_eq!(pick_url(None, Some(String::new())), DEFAULT_URL);
        assert_eq!(pick_url(None, None), DEFAULT_URL);
        assert_eq!(pick_url(own, None), "https://flag",);
    }

    #[test]
    fn pay_flags_parse_and_conflict_where_they_must() {
        let mint = Address::new_unique().to_string();
        let source = Address::new_unique().to_string();
        let new_run = ["--input", "in.csv", "--mint", &mint, "--source", &source];
        let args = parse_pay(&new_run).expect("new run");
        assert!(!args.dry_run && !args.yes && !args.reclaim_all);
        let mut dry = new_run.to_vec();
        dry.push("--dry-run");
        assert!(parse_pay(&dry).expect("dry run").dry_run);
        let mut yes = new_run.to_vec();
        yes.push("--yes");
        assert!(parse_pay(&yes).expect("yes").yes);
        // A dry run needs the run's inputs, and excludes the other modes.
        assert!(parse_pay(&["--dry-run"]).is_err());
        assert!(parse_pay(&["--dry-run", "--resume", "ab"]).is_err());
        assert!(parse_pay(&["--dry-run", "--status", "ab"]).is_err());
        // Reclaim-all stands alone.
        assert!(
            parse_pay(&["--reclaim-all"])
                .expect("reclaim all")
                .reclaim_all
        );
        let mut both = new_run.to_vec();
        both.push("--reclaim-all");
        assert!(parse_pay(&both).is_err());
        assert!(parse_pay(&["--reclaim-all", "--resume", "ab"]).is_err());
        assert!(parse_pay(&["--reclaim-all", "--dry-run"]).is_err());
        assert!(
            parse_pay(&["--reclaim"]).is_err(),
            "--reclaim needs --status"
        );
    }
}
