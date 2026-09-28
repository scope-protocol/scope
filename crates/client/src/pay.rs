//! Payer engine, plain recipients (docs/client.md, Payer engine).
//!
//! One source account per run, one attempt in flight. Every attempt for a row is
//! built on the same source ciphertext, and Token-2022 applies a transfer only on
//! the exact ciphertext its equality proof was built on (verification: V8), so at
//! most one attempt per row can land. The source's available ciphertext tells which:
//! equal to the attempt's `post` means it landed, equal to `pre` means nothing did,
//! anything else halts. A row is rebuilt only once its attempt is provably dead:
//! the finalized block height is past the attempt's last valid block height and the
//! finalized source still shows `pre`.

use crate::{
    address::token_2022,
    chain::{Chain, ChainError, Commitment},
    fees,
    input::{self, InputError, Row},
    journal::{self, INPUT_COPY, Journal, JournalError, Record, hex, unhex},
    tx::{COMPUTE_UNIT_LIMIT, v1_transaction_with_fee},
};
use core::num::NonZeroI8;
use curve25519_dalek::scalar::Scalar;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    derivation::derive_confidential_keys,
    elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    pedersen::G,
};
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        confidential_transfer::{
            ConfidentialTransferAccount, ConfidentialTransferMint, instruction as ct,
        },
    },
    state::{Account, AccountState, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::Duration,
};

/// Mint extensions a plain confidential Transfer cannot go through.
const REFUSED_MINT_EXTENSIONS: [ExtensionType; 3] = [
    ExtensionType::NonTransferable,
    ExtensionType::TransferFeeConfig,
    ExtensionType::TransferHook,
];

pub struct SourceKeys {
    pub elgamal: ElGamalKeypair,
    pub ae: AeKey,
}

impl SourceKeys {
    /// Per-wallet keys from the owner's signature, as spl-token-cli 5.6.1 derives them
    /// (`derive_confidential_keys(owner, b"")`), so a source set up with that CLI works here.
    pub fn from_signer(owner: &dyn Signer) -> Result<Self, PayError> {
        let (elgamal, ae) =
            derive_confidential_keys(owner, b"").map_err(|e| PayError::Keys(e.to_string()))?;
        Ok(Self { elgamal, ae })
    }
}

pub struct PayOptions {
    pub runs_dir: PathBuf,
    /// Refuse to start above this per-CU price, in micro-lamports; the run stays resumable.
    pub max_price_per_cu: u64,
    /// Wait between polls of the source account.
    pub poll: Duration,
    /// Allow an input file whose hash matches an earlier run.
    pub again: bool,
    pub log: fn(&str),
}

#[derive(Debug, thiserror::Error)]
pub enum PayError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Input(#[from] InputError),
    #[error("source keys: {0}")]
    Keys(String),
    #[error("mint {mint}: {why}")]
    Mint { mint: Address, why: String },
    #[error("source {account}: {why}")]
    Source { account: Address, why: String },
    #[error("recipient {recipient}: {why}")]
    Recipient { recipient: Address, why: String },
    #[error("source holds {have}, the run needs {need} (base units)")]
    Insufficient { have: u64, need: u64 },
    #[error("this input was already run as {run_id}; pass --again to pay it twice")]
    DuplicateInput { run_id: String },
    #[error("priority fee {price} micro-lamports/CU is above the cap {cap}; resume later")]
    FeeAboveCap { price: u64, cap: u64 },
    #[error("proof generation: {0}")]
    Proof(String),
    #[error("row {row}: simulation failed, nothing sent: {logs}")]
    Simulation { row: usize, logs: String },
    #[error("halted: {0}; the journal is intact, inspect before resuming")]
    Halted(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Paid {
    pub row: usize,
    pub recipient: Address,
    pub signature: String,
}

#[derive(Debug)]
pub struct Report {
    pub run_id: String,
    pub paid: Vec<Paid>,
}

struct MintInfo {
    decimals: u8,
    auditor: Option<ElGamalPubkey>,
}

struct SourceState {
    available: [u8; 64],
    hint: AeCiphertext,
}

struct Attempt {
    row: usize,
    tx: VersionedTransaction,
    last_valid_block_height: u64,
    pre: [u8; 64],
    post: [u8; 64],
}

enum Outcome {
    Landed,
    Expired,
}

fn ciphertext(bytes: &str) -> Option<[u8; 64]> {
    unhex(bytes)?.try_into().ok()
}

fn mint_info<C: Chain>(chain: &C, mint: &Address) -> Result<MintInfo, PayError> {
    let bad = |why: &str| PayError::Mint {
        mint: *mint,
        why: why.into(),
    };
    let account = chain
        .account(mint, Commitment::Confirmed)?
        .ok_or(bad("not found"))?;
    if account.owner != token_2022() {
        return Err(bad("not a Token-2022 mint"));
    }
    let state =
        StateWithExtensions::<Mint>::unpack(&account.data).map_err(|_| bad("not a mint"))?;
    let types = state
        .get_extension_types()
        .map_err(|_| bad("bad extensions"))?;
    if let Some(t) = REFUSED_MINT_EXTENSIONS.iter().find(|t| types.contains(t)) {
        return Err(bad(&format!("{t:?} is not supported")));
    }
    let ext = state
        .get_extension::<ConfidentialTransferMint>()
        .map_err(|_| bad("confidential transfers not enabled"))?;
    let auditor = ext
        .auditor_elgamal_pubkey
        .get()
        .map(|key| ElGamalPubkey::try_from(key.0.as_slice()))
        .transpose()
        .map_err(|_| bad("bad auditor key"))?;
    Ok(MintInfo {
        decimals: state.base.decimals,
        auditor,
    })
}

/// The recipient's ElGamal key, once its account can take one more confidential credit.
fn preflight<C: Chain>(
    chain: &C,
    recipient: &Address,
    mint: &Address,
) -> Result<ElGamalPubkey, PayError> {
    let bad = |why: &str| PayError::Recipient {
        recipient: *recipient,
        why: why.into(),
    };
    let account = chain
        .account(recipient, Commitment::Confirmed)?
        .ok_or(bad("not found"))?;
    if account.owner != token_2022() {
        return Err(bad("not a Token-2022 account"));
    }
    let state = StateWithExtensions::<Account>::unpack(&account.data)
        .map_err(|_| bad("not a token account"))?;
    if &state.base.mint != mint {
        return Err(bad("wrong mint"));
    }
    if state.base.state != AccountState::Initialized {
        return Err(bad("frozen"));
    }
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| bad("not configured for confidential transfers"))?;
    if !bool::from(ext.approved) {
        return Err(bad("not approved"));
    }
    if !bool::from(ext.allow_confidential_credits) {
        return Err(bad("confidential credits disabled"));
    }
    if u64::from(ext.pending_balance_credit_counter)
        >= u64::from(ext.maximum_pending_balance_credit_counter)
    {
        return Err(bad("pending credit counter full"));
    }
    ElGamalPubkey::try_from(ext.elgamal_pubkey).map_err(|_| bad("bad ElGamal key"))
}

fn source_state<C: Chain>(
    chain: &C,
    source: &Address,
    mint: &Address,
    owner: &Address,
    keys: &SourceKeys,
    commitment: Commitment,
) -> Result<SourceState, PayError> {
    let bad = |why: &str| PayError::Source {
        account: *source,
        why: why.into(),
    };
    let account = chain.account(source, commitment)?.ok_or(bad("not found"))?;
    if account.owner != token_2022() {
        return Err(bad("not a Token-2022 account"));
    }
    let state = StateWithExtensions::<Account>::unpack(&account.data)
        .map_err(|_| bad("not a token account"))?;
    if &state.base.mint != mint || &state.base.owner != owner {
        return Err(bad("wrong mint or owner"));
    }
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| bad("not configured for confidential transfers"))?;
    if ext.elgamal_pubkey != (*keys.elgamal.pubkey()).into() {
        return Err(bad(
            "its ElGamal key is not the one derived from this keypair",
        ));
    }
    Ok(SourceState {
        available: ext.available_balance.0,
        hint: ext
            .decryptable_available_balance
            .try_into()
            .map_err(|_| bad("bad balance hint"))?,
    })
}

/// The balance the AE hint claims, confirmed against the ElGamal ciphertext (docs/crypto.md, Balance cache).
fn verified_balance(
    keys: &SourceKeys,
    state: &SourceState,
    source: &Address,
) -> Result<u64, PayError> {
    let bad = |why: &str| PayError::Source {
        account: *source,
        why: why.into(),
    };
    let claimed = keys
        .ae
        .decrypt(&state.hint)
        .ok_or(bad("balance hint does not decrypt"))?;
    let available =
        ElGamalCiphertext::from_bytes(&state.available).ok_or(bad("bad available ciphertext"))?;
    if keys.elgamal.secret().decrypt(&available).target != G * Scalar::from(claimed) {
        return Err(bad("balance hint disagrees with the available ciphertext"));
    }
    Ok(claimed)
}

/// Finds an earlier run of the same input, by the hash in each journal's first record.
fn earlier_run(runs_dir: &Path, input_sha256: &str) -> Result<Option<String>, PayError> {
    let Ok(entries) = std::fs::read_dir(runs_dir) else {
        return Ok(None);
    };
    for entry in entries.flatten() {
        if let Ok(Some(Record::Run {
            run_id,
            input_sha256: h,
            ..
        })) = journal::read_header(&entry.path())
            && h == input_sha256
        {
            return Ok(Some(run_id));
        }
    }
    Ok(None)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut out);
    out
}

/// Fisher-Yates with the OS generator.
fn shuffled(n: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let r = u64::from_le_bytes(random_bytes::<8>());
        order.swap(i, (r % (i as u64 + 1)) as usize);
    }
    order
}

struct Engine<'a, C: Chain> {
    chain: C,
    payer: &'a Keypair,
    keys: SourceKeys,
    mint: Address,
    source: Address,
    auditor: Option<ElGamalPubkey>,
    opts: &'a PayOptions,
    journal: Journal,
    rows: Vec<Row>,
    destinations: HashMap<usize, ElGamalPubkey>,
    current: [u8; 64],
    balance: u64,
    paid: Vec<Paid>,
    run_id: String,
}

/// Starts a new run over `input`, the raw bytes of the input file.
#[allow(clippy::too_many_arguments)]
pub fn start<C: Chain>(
    chain: C,
    payer: &Keypair,
    keys: SourceKeys,
    mint: Address,
    source: Address,
    input_bytes: &[u8],
    opts: &PayOptions,
) -> Result<Report, PayError> {
    let info = mint_info(&chain, &mint)?;
    let text = std::str::from_utf8(input_bytes).map_err(|_| InputError::Shape { line: 0 })?;
    let rows = input::parse(text, info.decimals)?;
    let input_sha256 = hex(&solana_sha256_hasher::hash(input_bytes).to_bytes());
    // Held from the duplicate check until the new journal exists, so two runs of one input cannot race.
    let _runs_lock = journal::lock_dir(&opts.runs_dir)?;
    if !opts.again
        && let Some(run_id) = earlier_run(&opts.runs_dir, &input_sha256)?
    {
        return Err(PayError::DuplicateInput { run_id });
    }
    let state = source_state(
        &chain,
        &source,
        &mint,
        &payer.pubkey(),
        &keys,
        Commitment::Confirmed,
    )?;
    let balance = verified_balance(&keys, &state, &source)?;
    let need = rows
        .iter()
        .try_fold(0u64, |sum, r| sum.checked_add(r.amount))
        .ok_or(PayError::Insufficient {
            have: balance,
            need: u64::MAX,
        })?;
    if need > balance {
        return Err(PayError::Insufficient {
            have: balance,
            need,
        });
    }
    let destinations = rows
        .iter()
        .enumerate()
        .map(|(i, r)| Ok((i, preflight(&chain, &r.recipient, &mint)?)))
        .collect::<Result<HashMap<_, _>, PayError>>()?;

    let run_id = hex(&random_bytes::<8>());
    let dir = opts.runs_dir.join(&run_id);
    let mut journal = Journal::create(&dir)?;
    journal::write_private(&dir.join(INPUT_COPY), input_bytes)?;
    let order = shuffled(rows.len());
    journal.append(&Record::Run {
        run_id: run_id.clone(),
        input_sha256,
        mint: mint.to_string(),
        source: source.to_string(),
        payer: payer.pubkey().to_string(),
        order: order.clone(),
    })?;
    (opts.log)(&format!("run {run_id}: {} rows", rows.len()));
    let mut engine = Engine {
        chain,
        payer,
        keys,
        mint,
        source,
        auditor: info.auditor,
        opts,
        journal,
        rows,
        destinations,
        current: state.available,
        balance,
        paid: Vec::new(),
        run_id,
    };
    engine.run(&order, &HashSet::new())
}

/// Continues run `run_id` from its journal and the chain.
pub fn resume<C: Chain>(
    chain: C,
    payer: &Keypair,
    keys: SourceKeys,
    run_id: &str,
    opts: &PayOptions,
) -> Result<Report, PayError> {
    let dir = opts.runs_dir.join(run_id);
    let (journal, records) = Journal::open(&dir)?;
    let corrupt = |why: &str| {
        PayError::Journal(JournalError::Corrupt {
            path: dir.join(journal::JOURNAL),
            line: 1,
            why: why.into(),
        })
    };
    let Some(Record::Run {
        input_sha256,
        mint,
        source,
        payer: journal_payer,
        order,
        ..
    }) = records.first().cloned()
    else {
        return Err(corrupt("no run header"));
    };
    if journal_payer != payer.pubkey().to_string() {
        return Err(corrupt("run belongs to another payer"));
    }
    let mint: Address = mint.parse().map_err(|_| corrupt("bad mint"))?;
    let source: Address = source.parse().map_err(|_| corrupt("bad source"))?;
    let input_bytes = std::fs::read(dir.join(INPUT_COPY))
        .map_err(|e| JournalError::Io(dir.join(INPUT_COPY), e))?;
    if hex(&solana_sha256_hasher::hash(&input_bytes).to_bytes()) != input_sha256 {
        return Err(corrupt("input copy does not match the run's hash"));
    }
    let info = mint_info(&chain, &mint)?;
    let text = std::str::from_utf8(&input_bytes).map_err(|_| InputError::Shape { line: 0 })?;
    let rows = input::parse(text, info.decimals)?;

    let mut landed = HashSet::new();
    let mut open: Option<Record> = None;
    let mut paid = Vec::new();
    let mut posts: HashMap<&str, &str> = HashMap::new();
    let mut last_post: Option<&str> = None;
    for r in &records[1..] {
        match r {
            Record::Attempt {
                signature, post, ..
            } => {
                posts.insert(signature, post);
                open = Some(r.clone());
            }
            Record::Landed { row, signature } => {
                last_post = Some(
                    posts
                        .get(signature.as_str())
                        .ok_or(corrupt("landed without an attempt"))?,
                );
                landed.insert(*row);
                paid.push(Paid {
                    row: *row,
                    recipient: rows[*row].recipient,
                    signature: signature.clone(),
                });
                open = None;
            }
            Record::Done => {
                return Ok(Report {
                    run_id: run_id.into(),
                    paid,
                });
            }
            Record::Run { .. } => return Err(corrupt("second run header")),
        }
    }
    let state = source_state(
        &chain,
        &source,
        &mint,
        &payer.pubkey(),
        &keys,
        Commitment::Confirmed,
    )?;
    let balance = verified_balance(&keys, &state, &source)?;
    let destinations = (0..rows.len())
        .filter(|i| !landed.contains(i))
        .map(|i| Ok((i, preflight(&chain, &rows[i].recipient, &mint)?)))
        .collect::<Result<HashMap<_, _>, PayError>>()?;
    let mut engine = Engine {
        chain,
        payer,
        keys,
        mint,
        source,
        auditor: info.auditor,
        opts,
        journal,
        rows,
        destinations,
        current: state.available,
        balance,
        paid,
        run_id: run_id.into(),
    };
    (opts.log)(&format!(
        "resuming run {run_id}: {} rows landed",
        landed.len()
    ));
    if let Some(Record::Attempt {
        row,
        last_valid_block_height,
        pre,
        post,
        tx,
        ..
    }) = open
    {
        let tx = unhex(&tx)
            .and_then(|b| wincode::deserialize::<VersionedTransaction>(&b).ok())
            .ok_or(corrupt("bad transaction bytes"))?;
        let attempt = Attempt {
            row,
            tx,
            last_valid_block_height,
            pre: ciphertext(&pre).ok_or(corrupt("bad ciphertext"))?,
            post: ciphertext(&post).ok_or(corrupt("bad ciphertext"))?,
        };
        if engine.current == attempt.post {
            engine.record_landed(&attempt)?;
            landed.insert(row);
        } else if engine.current == attempt.pre {
            if let Outcome::Landed = engine.drive(&attempt)? {
                engine.record_landed(&attempt)?;
                landed.insert(row);
            }
        } else {
            return Err(PayError::Halted(format!(
                "row {row}: source matches neither side of the open attempt"
            )));
        }
        // A landed attempt changed the balance; read it back verified rather than trusting arithmetic.
        let state = engine.source_state(Commitment::Confirmed)?;
        engine.balance = verified_balance(&engine.keys, &state, &engine.source)?;
        engine.current = state.available;
    } else if let Some(post) = last_post
        && Some(engine.current) != ciphertext(post)
    {
        // A `landed` record is written at confirmed; a fork that dropped it shows up here.
        return Err(PayError::Halted(
            "source is not where the last landed row left it".into(),
        ));
    }
    engine.run(&order, &landed)
}

impl<C: Chain> Engine<'_, C> {
    fn source_state(&self, commitment: Commitment) -> Result<SourceState, PayError> {
        source_state(
            &self.chain,
            &self.source,
            &self.mint,
            &self.payer.pubkey(),
            &self.keys,
            commitment,
        )
    }

    fn run(&mut self, order: &[usize], landed: &HashSet<usize>) -> Result<Report, PayError> {
        for &row in order.iter().filter(|r| !landed.contains(*r)) {
            self.pay_row(row)?;
        }
        self.await_finalized()?;
        self.journal.append(&Record::Done)?;
        (self.opts.log)(&format!("run {} done", self.run_id));
        Ok(Report {
            run_id: self.run_id.clone(),
            paid: std::mem::take(&mut self.paid),
        })
    }

    /// Rows land at confirmed. Each transfer is built on the previous one's ciphertext, so
    /// the finalized source showing the last one means every row of the run is final.
    fn await_finalized(&self) -> Result<(), PayError> {
        loop {
            if self.source_state(Commitment::Finalized)?.available == self.current {
                return Ok(());
            }
            if self.source_state(Commitment::Confirmed)?.available != self.current {
                return Err(PayError::Halted(
                    "a confirmed transfer was dropped before finalizing".into(),
                ));
            }
            std::thread::sleep(self.opts.poll);
        }
    }

    fn pay_row(&mut self, row: usize) -> Result<(), PayError> {
        loop {
            let attempt = self.build(row)?;
            if let Err(logs) = self.chain.simulate(&attempt.tx)? {
                return Err(PayError::Simulation { row, logs });
            }
            self.journal.append(&Record::Attempt {
                row,
                signature: attempt.tx.signatures[0].to_string(),
                last_valid_block_height: attempt.last_valid_block_height,
                pre: hex(&attempt.pre),
                post: hex(&attempt.post),
                tx: hex(&wincode::serialize(&attempt.tx).expect("transactions serialize")),
            })?;
            match self.drive(&attempt)? {
                Outcome::Landed => return self.record_landed(&attempt),
                Outcome::Expired => {
                    (self.opts.log)(&format!("row {row}: attempt expired, rebuilding"));
                }
            }
        }
    }

    fn record_landed(&mut self, attempt: &Attempt) -> Result<(), PayError> {
        let signature = attempt.tx.signatures[0].to_string();
        self.journal.append(&Record::Landed {
            row: attempt.row,
            signature: signature.clone(),
        })?;
        let row = &self.rows[attempt.row];
        self.balance -= row.amount;
        self.current = attempt.post;
        (self.opts.log)(&format!(
            "row {}: {} paid, {signature}",
            attempt.row, row.recipient
        ));
        self.paid.push(Paid {
            row: attempt.row,
            recipient: row.recipient,
            signature,
        });
        Ok(())
    }

    fn price(&self) -> Result<u64, PayError> {
        let prices = self.chain.recent_prices()?;
        let price = if prices.is_empty() {
            0
        } else {
            fees::percentile(&prices, 75)
        };
        if price > self.opts.max_price_per_cu {
            return Err(PayError::FeeAboveCap {
                price,
                cap: self.opts.max_price_per_cu,
            });
        }
        Ok(price)
    }

    fn build(&self, row: usize) -> Result<Attempt, PayError> {
        let r = &self.rows[row];
        let destination = &self.destinations[&row];
        let current = ElGamalCiphertext::from_bytes(&self.current)
            .ok_or(PayError::Proof("bad source ciphertext".into()))?;
        let proofs = transfer_split_proof_data(
            &current,
            &self.keys.ae.encrypt(self.balance),
            r.amount,
            &self.keys.elgamal,
            &self.keys.ae,
            destination,
            self.auditor.as_ref(),
        )
        .map_err(|e| PayError::Proof(e.to_string()))?;
        let validity = &proofs.ciphertext_validity_proof_data_with_ciphertext;
        let offset = |n| NonZeroI8::new(n).expect("nonzero");
        let ixs = ct::transfer(
            &token_2022(),
            &self.source,
            &self.mint,
            &r.recipient,
            &self.keys.ae.encrypt(self.balance - r.amount).into(),
            &validity.ciphertext_lo,
            &validity.ciphertext_hi,
            &self.payer.pubkey(),
            &[],
            ProofLocation::InstructionOffset(offset(1), &proofs.equality_proof_data),
            ProofLocation::InstructionOffset(offset(2), &validity.proof_data),
            ProofLocation::InstructionOffset(offset(3), &proofs.range_proof_data),
        )
        .map_err(|e| PayError::Proof(e.to_string()))?;
        let fee = fees::priority_fee_lamports(self.price()?, COMPUTE_UNIT_LIMIT);
        let (blockhash, last_valid_block_height) = self.chain.blockhash()?;
        Ok(Attempt {
            row,
            tx: v1_transaction_with_fee(self.payer, &[], &ixs, blockhash, fee),
            last_valid_block_height,
            pre: self.current,
            post: proofs.equality_proof_data.context.ciphertext.0,
        })
    }

    /// Sends and resends one signed attempt until the source shows it landed or it is provably dead.
    fn drive(&mut self, attempt: &Attempt) -> Result<Outcome, PayError> {
        loop {
            if let Err(e) = self.chain.send(&attempt.tx) {
                (self.opts.log)(&format!(
                    "row {}: send failed, will retry: {e}",
                    attempt.row
                ));
            }
            std::thread::sleep(self.opts.poll);
            let now = self.source_state(Commitment::Confirmed)?.available;
            if now == attempt.post {
                return Ok(Outcome::Landed);
            }
            if now != attempt.pre {
                return Err(PayError::Halted(format!(
                    "row {}: source changed outside this run",
                    attempt.row
                )));
            }
            if self.chain.finalized_block_height()? > attempt.last_valid_block_height {
                let finalized = self.source_state(Commitment::Finalized)?.available;
                if finalized == attempt.pre {
                    return Ok(Outcome::Expired);
                }
                if finalized == attempt.post {
                    return Ok(Outcome::Landed);
                }
                return Err(PayError::Halted(format!(
                    "row {}: finalized source matches neither side of the attempt",
                    attempt.row
                )));
            }
        }
    }
}
