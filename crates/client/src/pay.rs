//! Payer engine (docs/payer.md): plain rows pay a configured confidential
//! account; stealth rows create, hand over and announce a one-time account and pay it,
//! all in one transaction (docs/protocol.md, The picture).
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
    address::{
        announcement_address, program_id, token_2022, token_account_address, token_account_seed_str,
    },
    chain::{Chain, ChainError, Commitment},
    confidential, fees,
    input::{self, InputError, Recipient, Row},
    ix::{self, StealthSetup},
    journal::{self, INPUT_COPY, Journal, JournalError, Record, hex, unhex},
    mint_policy::{self, MintPolicy},
    proofs::transfer_proofs,
    run_secret::RunSecret,
    tx::{
        PLAIN_TRANSFER_CU_LIMIT, RECLAIM_CU_LIMIT, STEALTH_PAYMENT_CU_LIMIT,
        v1_transaction_with_fee,
    },
};
use core::num::NonZeroI8;
use curve25519_dalek::scalar::Scalar;
use solana_address::Address;
use solana_instruction::Instruction;
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
        BaseStateWithExtensions, StateWithExtensions,
        confidential_transfer::{ConfidentialTransferAccount, instruction as ct},
    },
    state::{Account, AccountState, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::Duration,
};
use stealth_keygen::{RecipientPublicKeys, derive_payment_with_ephemeral};

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
    /// Refuse any attempt above this per-CU price, in micro-lamports; the run stays resumable.
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
    #[error(
        "the payer needs {} SOL, has {} (rent {}, funding for one-time accounts {}, fees {})",
        sol(*need), sol(*have), sol(parts.rent), sol(parts.funding), sol(parts.fees)
    )]
    PayerFunds {
        have: u64,
        need: u64,
        parts: NeedParts,
    },
    #[error(
        "this input was already run as {run_id}; resume it if it did not finish, or pass --again to pay it twice"
    )]
    DuplicateInput { run_id: String },
    #[error("priority fee {price} micro-lamports/CU is above the cap {cap}; resume later")]
    FeeAboveCap { price: u64, cap: u64 },
    #[error(
        "run {run_id} paid on cluster {journal} (genesis hash), but this RPC node is on {node}; use the node the run started on"
    )]
    WrongCluster {
        run_id: String,
        journal: String,
        node: String,
    },
    #[error("proof generation: {0}")]
    Proof(String),
    #[error("row {row}: simulation failed, nothing sent: {logs}")]
    Simulation { row: usize, logs: String },
    #[error("halted: {0}; the journal is intact, inspect before resuming")]
    Halted(String),
}

impl From<fees::FeeAboveCap> for PayError {
    fn from(e: fees::FeeAboveCap) -> Self {
        Self::FeeAboveCap {
            price: e.price,
            cap: e.cap,
        }
    }
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
    /// The transaction landed and failed, so it can never land again; its error text.
    Failed(String),
}

fn ciphertext(bytes: &str) -> Option<[u8; 64]> {
    unhex(bytes)?.try_into().ok()
}

/// The mint's decimals only, to read back a run's input. Today's payment policy (auditor
/// key, approval, extensions) does not apply to rows already paid.
fn mint_decimals<C: Chain>(chain: &C, mint: &Address) -> Result<u8, PayError> {
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
    StateWithExtensions::<Mint>::unpack(&account.data)
        .map(|state| state.base.decimals)
        .map_err(|_| bad("not a mint"))
}

fn mint_info<C: Chain>(chain: &C, mint: &Address) -> Result<MintPolicy, PayError> {
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
    mint_policy::check(&account.data).map_err(|why| bad(&why))
}

/// One stealth row's one-time account, derived from the run secret (docs/crypto.md, Derivation tree).
struct Stealth {
    ephemeral: [u8; 32],
    view_tag: u8,
    one_time_owner: Address,
    token_account: Address,
    elgamal: ElGamalKeypair,
    ae: AeKey,
}

/// Derives every stealth row; reads only the genesis hash, and only if there is one.
fn stealth_rows<C: Chain>(
    chain: &C,
    rows: &[Row],
    secret: &RunSecret,
    run_id: &str,
    payer: &Address,
    mint: &Address,
) -> Result<HashMap<usize, Stealth>, PayError> {
    let stealth: Vec<(usize, &RecipientPublicKeys)> = rows
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match &r.recipient {
            Recipient::Stealth(keys) => Some((i, keys)),
            Recipient::Plain(_) => None,
        })
        .collect();
    if stealth.is_empty() {
        return Ok(HashMap::new());
    }
    let genesis = chain.genesis_hash()?;
    stealth
        .into_iter()
        .map(|(row, keys)| {
            let keys_error = |e: String| PayError::Keys(format!("row {row}: {e}"));
            let payment = derive_payment_with_ephemeral(keys, &secret.ephemeral(run_id, row))
                .map_err(|e| keys_error(format!("{e:?}")))?;
            let ephemeral = payment.announcement.ephemeral_public_key;
            let token_account = token_account_address(payer, &ephemeral);
            let material = payment
                .derive_ct_ikm(&confidential::context(genesis, mint, &token_account))
                .map_err(|e| keys_error(format!("{e:?}")))?;
            let (elgamal, ae) = confidential::derive_confidential_keys(&material)
                .map_err(|e| keys_error(e.to_string()))?;
            Ok((
                row,
                Stealth {
                    ephemeral,
                    view_tag: payment.announcement.discovery_tag,
                    one_time_owner: Address::new_from_array(payment.payment_public_key),
                    token_account,
                    elgamal,
                    ae,
                },
            ))
        })
        .collect()
}

/// Refuses stealth rows still to pay on a mint they cannot use.
fn check_stealth_mint<'a>(
    unpaid: impl IntoIterator<Item = &'a Row>,
    mint: &Address,
    info: &MintPolicy,
) -> Result<(), PayError> {
    let any = unpaid
        .into_iter()
        .any(|r| matches!(r.recipient, Recipient::Stealth(_)));
    match info.stealth_refusal {
        Some(why) if any => Err(PayError::Mint {
            mint: *mint,
            why: why.into(),
        }),
        _ => Ok(()),
    }
}

/// Lamports as SOL text, exact to the lamport.
pub fn sol(lamports: u64) -> String {
    format!(
        "{}.{:09}",
        lamports / 1_000_000_000,
        lamports % 1_000_000_000
    )
}

/// Rows in `rows` not in `skip` that credit the plain account `address`.
fn credits_to(rows: &[Row], skip: &HashSet<usize>, address: &Address) -> u64 {
    rows.iter()
        .enumerate()
        .filter(|(i, r)| !skip.contains(i) && r.recipient == Recipient::Plain(*address))
        .count() as u64
}

/// What the payer's wallet must hold, by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeedParts {
    /// The wallet's own rent reserve and, per stealth row, the one-time account's and the
    /// announcement's rent; the stealth rents come back on reclaim.
    pub rent: u64,
    /// P's funding for each stealth row, priced at the cap because the sweep may come weeks later.
    pub funding: u64,
    /// The payer's own transaction fees at the budgeted price.
    pub fees: u64,
}

impl NeedParts {
    pub fn total(&self) -> u64 {
        self.rent
            .saturating_add(self.funding)
            .saturating_add(self.fees)
    }
}

/// What the payer's wallet must hold for the rows not in `skip`. Rent and P's funding are
/// exact; the payer's own fees use `fees::budget_price` of the current sample, not the cap.
pub fn payer_need<C: Chain>(
    chain: &C,
    rows: &[Row],
    skip: &HashSet<usize>,
    rents: (u64, u64),
    max_price_per_cu: u64,
) -> Result<NeedParts, PayError> {
    let (rent, reserve) = rents;
    let price = fees::budget_price(chain.recent_prices()?, max_price_per_cu);
    let fee = |limit| fees::LAMPORTS_PER_SIGNATURE + fees::priority_fee_lamports(price, limit);
    let mut parts = NeedParts::default();
    let mut stealth_rows = 0u64;
    for (_, r) in rows.iter().enumerate().filter(|(i, _)| !skip.contains(i)) {
        parts.fees = parts.fees.saturating_add(match r.recipient {
            Recipient::Plain(_) => fee(PLAIN_TRANSFER_CU_LIMIT),
            Recipient::Stealth(_) => {
                stealth_rows += 1;
                fee(STEALTH_PAYMENT_CU_LIMIT)
            }
        });
    }
    if stealth_rows > 0 {
        let rents = rent.saturating_add(chain.rent(scope_interface::state::ANNOUNCEMENT_LEN)?);
        parts.rent = rents.saturating_mul(stealth_rows);
        parts.funding =
            fees::sweep_funding(rent, reserve, fees::SWEEP_PRICE_CAP).saturating_mul(stealth_rows);
    }
    parts.rent = parts.rent.saturating_add(chain.rent(0)?);
    Ok(parts)
}

/// Refuses a run whose lamport cost the payer's wallet cannot cover.
fn check_payer_funds<C: Chain>(
    chain: &C,
    payer: &Address,
    parts: NeedParts,
) -> Result<(), PayError> {
    let have = chain
        .account(payer, Commitment::Confirmed)?
        .map_or(0, |a| a.lamports);
    let need = parts.total();
    if have < need {
        return Err(PayError::PayerFunds { have, need, parts });
    }
    Ok(())
}

/// Preflights every plain row not in `skip` and returns its ElGamal key.
fn plain_rows<C: Chain>(
    chain: &C,
    rows: &[Row],
    skip: &HashSet<usize>,
    mint: &Address,
) -> Result<HashMap<usize, ElGamalPubkey>, PayError> {
    rows.iter()
        .enumerate()
        .filter(|(i, _)| !skip.contains(i))
        .filter_map(|(i, r)| match &r.recipient {
            Recipient::Plain(address) => Some((i, address)),
            Recipient::Stealth(_) => None,
        })
        .map(|(i, address)| {
            let credits = credits_to(rows, skip, address);
            Ok((i, preflight(chain, address, mint, credits)?))
        })
        .collect()
}

/// A run as its journal header and input copy describe it, checked against the payer and
/// the input hash.
struct LoadedRun {
    mint: Address,
    source: Address,
    order: Vec<usize>,
    derived_openings: bool,
    rows: Vec<Row>,
}

fn load_run<C: Chain>(
    chain: &C,
    payer: &Keypair,
    dir: &Path,
    records: &[Record],
) -> Result<LoadedRun, PayError> {
    let corrupt = |why: &str| {
        PayError::Journal(JournalError::Corrupt {
            path: dir.join(journal::JOURNAL),
            line: 1,
            why: why.into(),
        })
    };
    let Some(Record::Run {
        run_id,
        genesis,
        input_sha256,
        mint,
        source,
        payer: journal_payer,
        order,
        derived_openings,
        ..
    }) = records.first()
    else {
        return Err(corrupt("no run header"));
    };
    if *journal_payer != payer.pubkey().to_string() {
        return Err(corrupt("run belongs to another payer"));
    }
    // Runs that predate the field recorded no cluster.
    if !genesis.is_empty() {
        let node = hex(&chain.genesis_hash()?);
        if node != *genesis {
            return Err(PayError::WrongCluster {
                run_id: run_id.clone(),
                journal: genesis.clone(),
                node,
            });
        }
    }
    let mint: Address = mint.parse().map_err(|_| corrupt("bad mint"))?;
    let source: Address = source.parse().map_err(|_| corrupt("bad source"))?;
    let input_bytes = std::fs::read(dir.join(INPUT_COPY))
        .map_err(|e| JournalError::Io(dir.join(INPUT_COPY), e))?;
    if hex(&solana_sha256_hasher::hash(&input_bytes).to_bytes()) != *input_sha256 {
        return Err(corrupt("input copy does not match the run's hash"));
    }
    let text = std::str::from_utf8(&input_bytes).map_err(|_| InputError::Shape { line: 0 })?;
    let rows = input::parse(text, mint_decimals(chain, &mint)?)?;
    Ok(LoadedRun {
        mint,
        source,
        order: order.clone(),
        derived_openings: *derived_openings,
        rows,
    })
}

/// Rent of a stealth row's token account and of P's reserve, read once per run.
fn stealth_rents<C: Chain>(
    chain: &C,
    stealth: &HashMap<usize, Stealth>,
    space: usize,
) -> Result<(u64, u64), PayError> {
    rents_if(chain, !stealth.is_empty(), space)
}

fn rents_if<C: Chain>(chain: &C, any_stealth: bool, space: usize) -> Result<(u64, u64), PayError> {
    if !any_stealth {
        return Ok((0, 0));
    }
    Ok((chain.rent(space)?, chain.rent(0)?))
}

/// The account a row pays: the recipient's own for a plain row, the one-time one otherwise.
fn paid_to(rows: &[Row], stealth: &HashMap<usize, Stealth>, row: usize) -> Address {
    match &rows[row].recipient {
        Recipient::Plain(address) => *address,
        Recipient::Stealth(_) => stealth[&row].token_account,
    }
}

/// The recipient's ElGamal key, once its account can take `credits` more confidential
/// credits, one per row that pays it.
fn preflight<C: Chain>(
    chain: &C,
    recipient: &Address,
    mint: &Address,
    credits: u64,
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
    let room = u64::from(ext.maximum_pending_balance_credit_counter)
        .saturating_sub(u64::from(ext.pending_balance_credit_counter));
    if credits > room {
        return Err(bad(&format!(
            "pending credit counter: {credits} rows pay it, room for {room}"
        )));
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

/// What makes two inputs the same payout: the rows' recipients and base-unit amounts,
/// in any order, on one mint from one payer. Formatting, comments and row order do not
/// change it; a different mint does.
pub fn input_key(rows: &[Row], mint: &Address, payer: &Address) -> String {
    let mut lines: Vec<String> = rows
        .iter()
        .map(|r| match &r.recipient {
            Recipient::Plain(a) => format!("plain {a} {}", r.amount),
            Recipient::Stealth(k) => format!("stealth {} {}", k.to_meta_address(), r.amount),
        })
        .collect();
    lines.sort();
    let text = format!(
        "scope-input/v1\nmint {mint}\npayer {payer}\n{}",
        lines.join("\n")
    );
    hex(&solana_sha256_hasher::hash(text.as_bytes()).to_bytes())
}

/// Finds an earlier run of the same input: by `input_key` in each journal's first
/// record, or for a journal that predates it by the hash of the raw input bytes.
fn earlier_run(
    runs_dir: &Path,
    input_key: &str,
    input_sha256: &str,
) -> Result<Option<String>, PayError> {
    let io = |e| PayError::Journal(JournalError::Io(runs_dir.to_path_buf(), e));
    let entries = match std::fs::read_dir(runs_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    };
    for entry in entries {
        let dir = entry.map_err(io)?.path();
        if !dir.is_dir() {
            continue;
        }
        match journal::read_header(&dir) {
            Ok(Some(Record::Run {
                run_id,
                input_sha256: raw,
                input_key: key,
                ..
            })) if if key.is_empty() {
                raw == input_sha256
            } else {
                key == input_key
            } =>
            {
                return Ok(Some(run_id));
            }
            Ok(_) => {}
            // A crash between creating the directory and the journal leaves nothing to pay twice.
            Err(JournalError::Io(_, e))
                if e.kind() == std::io::ErrorKind::NotFound && !dir.join(INPUT_COPY).exists() => {}
            // Any other journal that cannot be read may be this input's; refuse rather than pay twice.
            Err(e) => return Err(e.into()),
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
    plain: HashMap<usize, ElGamalPubkey>,
    stealth: HashMap<usize, Stealth>,
    run_secret: RunSecret,
    /// Size of each stealth row's token account, from the mint.
    space: usize,
    /// Rent of that account and of P's reserve.
    rents: (u64, u64),
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
    let input_key = input_key(&rows, &mint, &payer.pubkey());
    // Held from the duplicate check until the new journal records its input hash, so two
    // runs of one input cannot race.
    let runs_lock = journal::lock_dir(&opts.runs_dir)?;
    if !opts.again
        && let Some(run_id) = earlier_run(&opts.runs_dir, &input_key, &input_sha256)?
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
    let run_id = hex(&random_bytes::<8>());
    let run_secret =
        RunSecret::derive(payer, &run_id).map_err(|e| PayError::Keys(e.to_string()))?;
    check_stealth_mint(&rows, &mint, &info)?;
    let stealth = stealth_rows(&chain, &rows, &run_secret, &run_id, &payer.pubkey(), &mint)?;
    let rents = stealth_rents(&chain, &stealth, info.space)?;
    let plain = plain_rows(&chain, &rows, &HashSet::new(), &mint)?;
    let need = payer_need(&chain, &rows, &HashSet::new(), rents, opts.max_price_per_cu)?;
    check_payer_funds(&chain, &payer.pubkey(), need)?;

    // Read before the directory exists, so an RPC failure leaves no header-less run.
    let genesis = hex(&chain.genesis_hash()?);
    let dir = opts.runs_dir.join(&run_id);
    let mut journal = Journal::create(&dir)?;
    journal::write_private(&dir.join(INPUT_COPY), input_bytes)?;
    let order = shuffled(rows.len());
    journal.append(&Record::Run {
        format: journal::FORMAT,
        genesis,
        run_id: run_id.clone(),
        input_sha256,
        input_key,
        mint: mint.to_string(),
        source: source.to_string(),
        payer: payer.pubkey().to_string(),
        order: order.clone(),
        derived_openings: true,
    })?;
    drop(runs_lock);
    (opts.log)(&format!(
        "run {run_id}: {} rows\njournal: {}",
        rows.len(),
        dir.join(journal::JOURNAL).display()
    ));
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
        plain,
        stealth,
        run_secret,
        space: info.space,
        rents,
        current: state.available,
        balance,
        paid: Vec::new(),
        run_id,
    };
    engine.run(&order, &HashSet::new())
}

/// What a real run would do and cost, from every preflight but without sending anything
/// or writing a journal.
#[derive(Debug)]
pub struct DryRun {
    pub genesis: [u8; 32],
    /// `cluster_name` of the genesis hash.
    pub cluster: String,
    pub rows: usize,
    pub plain_rows: usize,
    pub stealth_rows: usize,
    /// Sum of all rows, base units.
    pub total: u64,
    pub decimals: u8,
    pub payer_have: u64,
    pub payer_need: u64,
    /// The sampled per-CU price a row would pay now, micro-lamports.
    pub price: u64,
    /// Most one row's fee can be at `--max-price`, lamports.
    pub fee_cap_plain: u64,
    pub fee_cap_stealth: u64,
}

const KNOWN_CLUSTERS: [(&str, &str); 3] = [
    (
        "mainnet-beta",
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
    ),
    ("devnet", "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
    ("testnet", "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"),
];

/// The cluster a genesis hash belongs to, or `unknown cluster <hash>`.
pub fn cluster_name(genesis: &[u8; 32]) -> String {
    let hash = solana_message::Hash::new_from_array(*genesis).to_string();
    KNOWN_CLUSTERS
        .iter()
        .find(|(_, known)| *known == hash)
        .map_or_else(
            || format!("unknown cluster {hash}"),
            |(name, _)| (*name).into(),
        )
}

/// A real run on mainnet-beta needs `--yes`; anything else goes ahead.
pub fn mainnet_gate(genesis: &[u8; 32], yes: bool) -> Result<(), String> {
    if cluster_name(genesis) == "mainnet-beta" && !yes {
        return Err(
            "this node is on mainnet-beta; check the plan with --dry-run, then rerun with --yes"
                .into(),
        );
    }
    Ok(())
}

/// Token amount in base units as decimal text.
pub fn token_amount(base: u64, decimals: u8) -> String {
    let Some(scale) = 10u64
        .checked_pow(u32::from(decimals))
        .filter(|_| decimals > 0)
    else {
        return base.to_string();
    };
    format!(
        "{}.{:0width$}",
        base / scale,
        base % scale,
        width = usize::from(decimals)
    )
}

/// Runs the preflights of `start` that need no signature or write: the input, the mint's
/// policy, duplicate runs, the source and its balance, the plain recipients, the payer's
/// SOL and a fee sample.
pub fn dry_run<C: Chain>(
    chain: &C,
    payer: &Keypair,
    keys: &SourceKeys,
    mint: Address,
    source: Address,
    input_bytes: &[u8],
    opts: &PayOptions,
) -> Result<DryRun, PayError> {
    let info = mint_info(chain, &mint)?;
    let text = std::str::from_utf8(input_bytes).map_err(|_| InputError::Shape { line: 0 })?;
    let rows = input::parse(text, info.decimals)?;
    if !opts.again {
        let raw = hex(&solana_sha256_hasher::hash(input_bytes).to_bytes());
        let key = input_key(&rows, &mint, &payer.pubkey());
        if let Some(run_id) = earlier_run(&opts.runs_dir, &key, &raw)? {
            return Err(PayError::DuplicateInput { run_id });
        }
    }
    let state = source_state(
        chain,
        &source,
        &mint,
        &payer.pubkey(),
        keys,
        Commitment::Confirmed,
    )?;
    let balance = verified_balance(keys, &state, &source)?;
    let total = rows
        .iter()
        .try_fold(0u64, |sum, r| sum.checked_add(r.amount))
        .ok_or(PayError::Insufficient {
            have: balance,
            need: u64::MAX,
        })?;
    if total > balance {
        return Err(PayError::Insufficient {
            have: balance,
            need: total,
        });
    }
    check_stealth_mint(&rows, &mint, &info)?;
    plain_rows(chain, &rows, &HashSet::new(), &mint)?;
    let stealth_rows = rows
        .iter()
        .filter(|r| matches!(r.recipient, Recipient::Stealth(_)))
        .count();
    let rents = rents_if(chain, stealth_rows > 0, info.space)?;
    let payer_need = payer_need(chain, &rows, &HashSet::new(), rents, opts.max_price_per_cu)?;
    let price = fees::priority_price(chain.recent_prices()?, opts.max_price_per_cu)?;
    let fee_cap = |limit| {
        fees::LAMPORTS_PER_SIGNATURE + fees::priority_fee_lamports(opts.max_price_per_cu, limit)
    };
    let genesis = chain.genesis_hash()?;
    Ok(DryRun {
        genesis,
        cluster: cluster_name(&genesis),
        rows: rows.len(),
        plain_rows: rows.len() - stealth_rows,
        stealth_rows,
        total,
        decimals: info.decimals,
        payer_have: chain
            .account(&payer.pubkey(), Commitment::Confirmed)?
            .map_or(0, |a| a.lamports),
        payer_need: payer_need.total(),
        price,
        fee_cap_plain: fee_cap(PLAIN_TRANSFER_CU_LIMIT),
        fee_cap_stealth: fee_cap(STEALTH_PAYMENT_CU_LIMIT),
    })
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
    let LoadedRun {
        mint,
        source,
        order,
        rows,
        ..
    } = load_run(&chain, payer, &dir, &records)?;
    let run_secret = RunSecret::derive(payer, run_id).map_err(|e| PayError::Keys(e.to_string()))?;
    let stealth = stealth_rows(&chain, &rows, &run_secret, run_id, &payer.pubkey(), &mint)?;

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
                    recipient: paid_to(&rows, &stealth, *row),
                    signature: signature.clone(),
                });
                open = None;
            }
            Record::Halted { .. } => {}
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
    // Payment policy and the payer's SOL bind new payments only. They are checked once
    // outcomes are reconciled, and only if rows remain, so a paused mint or a short wallet
    // cannot block settling a row that already paid.
    let policy = mint_info(&chain, &mint);
    let mut engine = Engine {
        chain,
        payer,
        keys,
        mint,
        source,
        auditor: None,
        opts,
        journal,
        rows,
        plain: HashMap::new(),
        stealth,
        run_secret,
        space: 0,
        rents: (0, 0),
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
    if landed.len() < engine.rows.len() {
        let info = policy?;
        check_stealth_mint(
            engine
                .rows
                .iter()
                .enumerate()
                .filter(|(i, _)| !landed.contains(i))
                .map(|(_, r)| r),
            &engine.mint,
            &info,
        )?;
        engine.rents = stealth_rents(&engine.chain, &engine.stealth, info.space)?;
        engine.plain = plain_rows(&engine.chain, &engine.rows, &landed, &engine.mint)?;
        let need = payer_need(
            &engine.chain,
            &engine.rows,
            &landed,
            engine.rents,
            opts.max_price_per_cu,
        )?;
        check_payer_funds(&engine.chain, &payer.pubkey(), need)?;
        engine.auditor = info.auditor;
        engine.space = info.space;
    }
    engine.run(&order, &landed)
}

/// Attempts of one row that landed with an error before the run halts. An attempt that
/// passed simulation and still fails points at something a rebuild will not fix.
const FAILED_LIMIT: usize = 3;

/// Expired attempts of one row before the run halts. Congestion alone can expire attempts,
/// and every rebuild reprices and refuses a price above `--max-price`, so the limit is loose.
const EXPIRED_LIMIT: usize = 10;

/// Expired attempts per row before `reclaim` gives up; it is a backstop, safe to rerun.
const RECLAIM_ATTEMPTS: usize = 3;

/// Where one stealth row of a run stands, read from the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StealthState {
    /// The run has not paid this row.
    Unpaid,
    /// The run attempted this row and never recorded the outcome, and no announcement is
    /// open; resuming the run settles it from the source ciphertext.
    Unresolved,
    /// Paid and announced; the recipient has not swept it yet.
    Open,
    /// Swept: both balances are empty, so `reclaim` returns the rent to the payer.
    Swept,
    /// The announcement is closed and its rent is back with the payer.
    Reclaimed,
}

#[derive(Debug)]
pub struct StealthStatus {
    pub row: usize,
    pub token_account: Address,
    pub announcement: Address,
    pub state: StealthState,
}

/// Where a run as a whole stands, from its journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunState {
    Done,
    /// The last thing the run recorded was an error it stopped on.
    Halted(String),
    /// Neither done nor halted: running now, or killed; resume to find out.
    Unfinished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlainState {
    Unpaid,
    /// Attempted and not recorded as landed; resuming settles it.
    Attempted,
    Landed,
}

#[derive(Debug)]
pub struct PlainStatus {
    pub row: usize,
    pub recipient: Address,
    pub state: PlainState,
    pub signature: Option<String>,
}

#[derive(Debug)]
pub struct RunSummary {
    pub rows: usize,
    pub landed: usize,
    pub state: RunState,
    pub plain: Vec<PlainStatus>,
}

/// The run's row counts, its overall state and each plain row, read from the journal
/// without locking it.
pub fn summary<C: Chain>(
    chain: &C,
    payer: &Keypair,
    run_id: &str,
    opts: &PayOptions,
) -> Result<RunSummary, PayError> {
    let dir = opts.runs_dir.join(run_id);
    let records = journal::read_unlocked(&dir)?;
    let run = load_run(chain, payer, &dir, &records)?;
    let mut landed: HashMap<usize, String> = HashMap::new();
    let mut attempted = HashSet::new();
    for r in &records {
        match r {
            Record::Landed { row, signature } => {
                landed.insert(*row, signature.clone());
            }
            Record::Attempt { row, .. } => {
                attempted.insert(*row);
            }
            _ => {}
        }
    }
    let state = match records.last() {
        Some(Record::Done) => RunState::Done,
        Some(Record::Halted { reason }) => RunState::Halted(reason.clone()),
        _ => RunState::Unfinished,
    };
    let plain = run
        .rows
        .iter()
        .enumerate()
        .filter_map(|(row, r)| match &r.recipient {
            Recipient::Plain(recipient) => Some(PlainStatus {
                row,
                recipient: *recipient,
                state: if landed.contains_key(&row) {
                    PlainState::Landed
                } else if attempted.contains(&row) {
                    PlainState::Attempted
                } else {
                    PlainState::Unpaid
                },
                signature: landed.get(&row).cloned(),
            }),
            Recipient::Stealth(_) => None,
        })
        .collect();
    Ok(RunSummary {
        rows: run.rows.len(),
        landed: landed.len(),
        state,
        plain,
    })
}

/// Where each stealth row of run `run_id` stands. Reads the journal without locking it,
/// so it works while the run is live.
pub fn status<C: Chain>(
    chain: &C,
    payer: &Keypair,
    run_id: &str,
    opts: &PayOptions,
) -> Result<Vec<StealthStatus>, PayError> {
    let dir = opts.runs_dir.join(run_id);
    let records = journal::read_unlocked(&dir)?;
    let run = load_run(chain, payer, &dir, &records)?;
    let rows_with = |pick: fn(&Record) -> Option<usize>| -> HashSet<usize> {
        records.iter().filter_map(pick).collect()
    };
    let landed = rows_with(|r| match r {
        Record::Landed { row, .. } => Some(*row),
        _ => None,
    });
    let attempted = rows_with(|r| match r {
        Record::Attempt { row, .. } => Some(*row),
        _ => None,
    });
    let secret = RunSecret::derive(payer, run_id).map_err(|e| PayError::Keys(e.to_string()))?;
    let stealth = stealth_rows(
        chain,
        &run.rows,
        &secret,
        run_id,
        &payer.pubkey(),
        &run.mint,
    )?;
    let mut out = stealth
        .iter()
        .map(|(&row, s)| {
            let (announcement, _) = announcement_address(&s.token_account);
            let journaled = if landed.contains(&row) {
                Journaled::Landed
            } else if attempted.contains(&row) {
                Journaled::Attempted
            } else {
                Journaled::Nothing
            };
            Ok(StealthStatus {
                row,
                token_account: s.token_account,
                announcement,
                state: stealth_state(chain, journaled, s, &announcement)?,
            })
        })
        .collect::<Result<Vec<_>, PayError>>()?;
    out.sort_by_key(|s| s.row);
    Ok(out)
}

/// Whether the token account exists and every balance of it is empty.
fn token_account_empty<C: Chain>(chain: &C, token_account: &Address) -> Result<bool, PayError> {
    Ok(match chain.account(token_account, Commitment::Confirmed)? {
        Some(a) if a.owner == token_2022() => StateWithExtensions::<Account>::unpack(&a.data)
            .ok()
            .and_then(|state| {
                let ext = state.get_extension::<ConfidentialTransferAccount>().ok()?;
                Some(
                    state.base.amount == 0
                        && ext.available_balance.0 == [0; 64]
                        && ext.pending_balance_lo.0 == [0; 64]
                        && ext.pending_balance_hi.0 == [0; 64],
                )
            })
            .unwrap_or(false),
        _ => false,
    })
}

/// What the journal says about a row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Journaled {
    Nothing,
    Attempted,
    Landed,
}

/// An open announcement means paid, whatever the journal says: a run killed after a
/// send has no `landed` record for a row that landed. Without an announcement, a row the
/// run attempted but never recorded may have landed and been swept and reclaimed since.
fn stealth_state<C: Chain>(
    chain: &C,
    journaled: Journaled,
    s: &Stealth,
    announcement: &Address,
) -> Result<StealthState, PayError> {
    let open = chain
        .account(announcement, Commitment::Confirmed)?
        .is_some_and(|a| a.owner == program_id());
    if !open {
        return Ok(match journaled {
            Journaled::Landed => StealthState::Reclaimed,
            Journaled::Attempted => StealthState::Unresolved,
            Journaled::Nothing => StealthState::Unpaid,
        });
    }
    let empty = token_account_empty(chain, &s.token_account)?;
    // Every row pays a nonzero amount, so empty balances under an open announcement mean swept.
    Ok(if empty {
        StealthState::Swept
    } else {
        StealthState::Open
    })
}

/// Why one `reclaim` could not be completed.
enum ReclaimError {
    Simulation(String),
    GaveUp,
    Other(PayError),
}

impl<E: Into<PayError>> From<E> for ReclaimError {
    fn from(e: E) -> Self {
        Self::Other(e.into())
    }
}

/// Calls the permissionless `reclaim` until the announcement is closed. Anyone may call
/// it, so another caller can win the race; that is success too. Each attempt pays the
/// sampled priority price under `--max-price`.
fn reclaim_announcement<C: Chain>(
    chain: &mut C,
    payer: &Keypair,
    announcement: &Address,
    token_account: &Address,
    label: &str,
    opts: &PayOptions,
) -> Result<(), ReclaimError> {
    let ix = ix::reclaim(announcement, token_account, &payer.pubkey());
    let closed = |chain: &C| -> Result<bool, PayError> {
        Ok(chain
            .account(announcement, Commitment::Confirmed)?
            .is_none_or(|a| a.owner != program_id()))
    };
    let mut attempts = 0;
    'attempts: while !closed(chain)? {
        if attempts == RECLAIM_ATTEMPTS {
            return Err(ReclaimError::GaveUp);
        }
        attempts += 1;
        let price = fees::priority_price(chain.recent_prices()?, opts.max_price_per_cu)?;
        let (blockhash, last_valid_block_height) = chain.blockhash()?;
        let tx = v1_transaction_with_fee(
            payer,
            &[],
            std::slice::from_ref(&ix),
            blockhash,
            RECLAIM_CU_LIMIT,
            fees::priority_fee_lamports(price, RECLAIM_CU_LIMIT),
        );
        if let Err(logs) = chain.simulate(&tx)? {
            if closed(chain)? {
                break;
            }
            return Err(ReclaimError::Simulation(logs));
        }
        loop {
            if let Err(e) = chain.send(&tx) {
                (opts.log)(&format!("{label}: reclaim send failed, will retry: {e}"));
            }
            std::thread::sleep(opts.poll);
            if closed(chain)? {
                break 'attempts;
            }
            if chain.finalized_block_height()? > last_valid_block_height {
                continue 'attempts;
            }
        }
    }
    Ok(())
}

/// Calls `reclaim` for every swept stealth row of the run, then returns the new status.
/// Token-2022 refuses to close an account with any balance (verification: V4), so this
/// cannot touch funds. After `RECLAIM_ATTEMPTS` expired attempts for a row it stops and
/// says so.
pub fn reclaim<C: Chain>(
    chain: &mut C,
    payer: &Keypair,
    run_id: &str,
    opts: &PayOptions,
) -> Result<Vec<StealthStatus>, PayError> {
    let swept: Vec<StealthStatus> = status(chain, payer, run_id, opts)?
        .into_iter()
        .filter(|s| s.state == StealthState::Swept)
        .collect();
    for s in swept {
        let label = format!("row {}", s.row);
        match reclaim_announcement(
            chain,
            payer,
            &s.announcement,
            &s.token_account,
            &label,
            opts,
        ) {
            Ok(()) => {}
            Err(ReclaimError::Simulation(logs)) => {
                return Err(PayError::Simulation { row: s.row, logs });
            }
            Err(ReclaimError::GaveUp) => {
                return Err(PayError::Halted(format!(
                    "row {}: reclaim did not land in {RECLAIM_ATTEMPTS} attempts; try again later",
                    s.row
                )));
            }
            Err(ReclaimError::Other(e)) => return Err(e),
        }
        (opts.log)(&format!(
            "row {}: rent reclaimed from {}",
            s.row, s.token_account
        ));
    }
    status(chain, payer, run_id, opts)
}

/// What `reclaim_all` did with one announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReclaimOutcome {
    /// The announcement is closed and its rent is back with the payer.
    Reclaimed,
    /// The one-time account still holds a balance, so Token-2022 would refuse to close it.
    StillHolding,
    Failed(String),
}

#[derive(Debug)]
pub struct ReclaimReport {
    pub announcement: Address,
    pub token_account: Address,
    pub outcome: ReclaimOutcome,
}

/// Reclaims every announcement the payer made, found on chain, whose one-time account is
/// swept. It needs no journal, so it also covers runs whose journal is lost.
pub fn reclaim_all<C: Chain>(
    chain: &mut C,
    payer: &Keypair,
    opts: &PayOptions,
) -> Result<Vec<ReclaimReport>, PayError> {
    let mut found: Vec<(Address, Address)> = chain
        .announcements_by_payer(&payer.pubkey())?
        .into_iter()
        .filter(|(_, a)| a.owner == program_id())
        .filter_map(|(address, a)| {
            let announcement = scope_interface::state::Announcement::from_bytes(&a.data).ok()?;
            (announcement.payer == payer.pubkey().to_bytes()).then(|| {
                (
                    address,
                    token_account_address(&payer.pubkey(), &announcement.ephemeral),
                )
            })
        })
        .collect();
    found.sort();
    let mut report = Vec::new();
    for (announcement, token_account) in found {
        let outcome = if !token_account_empty(chain, &token_account)? {
            ReclaimOutcome::StillHolding
        } else {
            match reclaim_announcement(
                chain,
                payer,
                &announcement,
                &token_account,
                &announcement.to_string(),
                opts,
            ) {
                Ok(()) => ReclaimOutcome::Reclaimed,
                Err(ReclaimError::Simulation(logs)) => {
                    ReclaimOutcome::Failed(format!("simulation failed: {logs}"))
                }
                Err(ReclaimError::GaveUp) => ReclaimOutcome::Failed(format!(
                    "did not land in {RECLAIM_ATTEMPTS} attempts; try again later"
                )),
                Err(ReclaimError::Other(e)) => return Err(e),
            }
        };
        report.push(ReclaimReport {
            announcement,
            token_account,
            outcome,
        });
    }
    Ok(report)
}

/// The payer's receipt for one paid row: its amount and the two openings the run secret
/// derives for it. Works for plain and stealth rows (docs/audit.md).
pub fn disclose<C: Chain>(
    chain: &C,
    payer: &Keypair,
    run_id: &str,
    row: usize,
    opts: &PayOptions,
) -> Result<crate::receipt::Receipt, PayError> {
    let dir = opts.runs_dir.join(run_id);
    let records = journal::read_unlocked(&dir)?;
    let LoadedRun {
        rows,
        derived_openings,
        ..
    } = load_run(chain, payer, &dir, &records)?;
    if !derived_openings {
        return Err(PayError::Halted(format!(
            "run {run_id} predates derived amount openings; its receipts cannot be rebuilt"
        )));
    }
    let signature = records
        .iter()
        .find_map(|r| match r {
            Record::Landed {
                row: landed,
                signature,
            } if *landed == row => Some(signature.clone()),
            _ => None,
        })
        .ok_or_else(|| PayError::Halted(format!("row {row} has not landed in run {run_id}")))?;
    let amount = rows
        .get(row)
        .ok_or_else(|| PayError::Halted(format!("run {run_id} has no row {row}")))?
        .amount;
    let openings = RunSecret::derive(payer, run_id)
        .map_err(|e| PayError::Keys(e.to_string()))?
        .openings(run_id, row);
    Ok(crate::receipt::Receipt::Opening {
        version: crate::receipt::RECEIPT_VERSION,
        cluster: hex(&chain.genesis_hash()?),
        signature,
        amount,
        opening_lo: hex(openings.lo.as_bytes()),
        opening_hi: hex(openings.hi.as_bytes()),
    })
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

    /// Runs the rows; an error that stops the run is journaled and reported with the path
    /// and the command that resumes it.
    fn run(&mut self, order: &[usize], landed: &HashSet<usize>) -> Result<Report, PayError> {
        let result = self.run_rows(order, landed);
        if let Err(error) = &result {
            if let PayError::Halted(why) = error {
                let _ = self.journal.append(&Record::Halted {
                    reason: why.clone(),
                });
            }
            (self.opts.log)(&format!(
                "run {} stopped: {error}\njournal: {}\nresume with: scope pay --resume {}",
                self.run_id,
                self.opts
                    .runs_dir
                    .join(&self.run_id)
                    .join(journal::JOURNAL)
                    .display(),
                self.run_id
            ));
        }
        result
    }

    fn run_rows(&mut self, order: &[usize], landed: &HashSet<usize>) -> Result<Report, PayError> {
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
        let (mut expired, mut failed) = (0, 0);
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
                Outcome::Landed => {
                    // Resume reads the balance back from the chain instead.
                    self.balance -= self.rows[row].amount;
                    return self.record_landed(&attempt);
                }
                Outcome::Expired => {
                    expired += 1;
                    if expired == EXPIRED_LIMIT {
                        return Err(PayError::Halted(format!(
                            "row {row}: {EXPIRED_LIMIT} attempts expired without landing; resume to try again"
                        )));
                    }
                    (self.opts.log)(&format!("row {row}: attempt expired, rebuilding"));
                }
                Outcome::Failed(error) => {
                    failed += 1;
                    if failed == FAILED_LIMIT {
                        return Err(PayError::Halted(format!(
                            "row {row}: {FAILED_LIMIT} attempts landed with an error, the last: {error}"
                        )));
                    }
                    (self.opts.log)(&format!(
                        "row {row}: attempt landed with an error ({error}), rebuilding"
                    ));
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
        let recipient = paid_to(&self.rows, &self.stealth, attempt.row);
        self.current = attempt.post;
        (self.opts.log)(&format!(
            "row {}: {recipient} paid, {signature}",
            attempt.row
        ));
        self.paid.push(Paid {
            row: attempt.row,
            recipient,
            signature,
        });
        Ok(())
    }

    fn price(&self) -> Result<u64, PayError> {
        Ok(fees::priority_price(
            self.chain.recent_prices()?,
            self.opts.max_price_per_cu,
        )?)
    }

    /// The setup, handover and `announce` for a stealth row, in front of its transfer.
    fn stealth_setup(&self, row: usize, s: &Stealth) -> Result<Vec<Instruction>, PayError> {
        let existing = match self
            .chain
            .account(&s.token_account, Commitment::Confirmed)?
        {
            None => 0,
            Some(a) if a.owner == Address::default() && a.data.is_empty() => a.lamports,
            Some(_) => {
                return Err(PayError::Halted(format!(
                    "row {row}: an account already exists at its one-time address {}",
                    s.token_account
                )));
            }
        };
        let (rent, reserve) = self.rents;
        let payer = self.payer.pubkey();
        let mut ixs = ix::stealth_setup(&StealthSetup {
            payer,
            mint: self.mint,
            ephemeral: s.ephemeral,
            view_tag: s.view_tag,
            one_time_owner: s.one_time_owner,
            elgamal: &s.elgamal,
            ae: &s.ae,
            rent_lamports: rent,
            space: self.space as u64,
            // D is the same size as this account, so its rent is `rent` too.
            lamports_for_owner: fees::sweep_funding(rent, reserve, fees::SWEEP_PRICE_CAP),
        })
        .map_err(|e| PayError::Proof(e.to_string()))?;
        // An expired attempt made the address public; anyone may have sent it lamports since.
        if existing > 0 {
            ixs.splice(
                0..1,
                ix::create_prefunded_with_seed(
                    &payer,
                    &s.token_account,
                    &token_account_seed_str(&s.ephemeral),
                    rent,
                    existing,
                    self.space as u64,
                    &token_2022(),
                ),
            );
        }
        Ok(ixs)
    }

    fn build(&self, row: usize) -> Result<Attempt, PayError> {
        let r = &self.rows[row];
        let (to, to_key, mut ixs, compute_unit_limit) = match &r.recipient {
            Recipient::Plain(address) => (
                *address,
                self.plain[&row],
                Vec::new(),
                PLAIN_TRANSFER_CU_LIMIT,
            ),
            Recipient::Stealth(_) => {
                let s = &self.stealth[&row];
                (
                    s.token_account,
                    *s.elgamal.pubkey(),
                    self.stealth_setup(row, s)?,
                    STEALTH_PAYMENT_CU_LIMIT,
                )
            }
        };
        let current = ElGamalCiphertext::from_bytes(&self.current)
            .ok_or(PayError::Proof("bad source ciphertext".into()))?;
        let proofs = transfer_proofs(
            &current,
            self.balance,
            r.amount,
            &self.keys.elgamal,
            &to_key,
            self.auditor.as_ref(),
            &self.run_secret.openings(&self.run_id, row),
        )
        .map_err(PayError::Proof)?;
        let validity = &proofs.ciphertext_validity_proof_data_with_ciphertext;
        let offset = |n| NonZeroI8::new(n).expect("nonzero");
        ixs.extend(
            ct::transfer(
                &token_2022(),
                &self.source,
                &self.mint,
                &to,
                &self.keys.ae.encrypt(self.balance - r.amount).into(),
                &validity.ciphertext_lo,
                &validity.ciphertext_hi,
                &self.payer.pubkey(),
                &[],
                ProofLocation::InstructionOffset(offset(1), &proofs.equality_proof_data),
                ProofLocation::InstructionOffset(offset(2), &validity.proof_data),
                ProofLocation::InstructionOffset(offset(3), &proofs.range_proof_data),
            )
            .map_err(|e| PayError::Proof(e.to_string()))?,
        );
        let fee = fees::priority_fee_lamports(self.price()?, compute_unit_limit);
        let (blockhash, last_valid_block_height) = self.chain.blockhash()?;
        Ok(Attempt {
            row,
            tx: v1_transaction_with_fee(self.payer, &[], &ixs, blockhash, compute_unit_limit, fee),
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
            // A failed transaction cannot land again, and moved nothing; resending it is pointless.
            if let Some(error) = self.chain.landed_error(&attempt.tx.signatures[0])? {
                return Ok(Outcome::Failed(error));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn rows(amounts: &[u64]) -> Vec<Row> {
        amounts
            .iter()
            .map(|&amount| Row {
                recipient: Recipient::Plain(Address::new_from_array([amount as u8; 32])),
                amount,
            })
            .collect()
    }

    #[test]
    fn the_input_key_ignores_order_and_binds_mint_and_payer() {
        let (mint, other_mint) = (Address::new_unique(), Address::new_unique());
        let (payer, other_payer) = (Address::new_unique(), Address::new_unique());
        let mut shuffled = rows(&[1, 2, 3]);
        shuffled.reverse();
        let key = input_key(&rows(&[1, 2, 3]), &mint, &payer);
        assert_eq!(key, input_key(&shuffled, &mint, &payer));
        assert_ne!(key, input_key(&rows(&[1, 2, 3]), &other_mint, &payer));
        assert_ne!(key, input_key(&rows(&[1, 2, 3]), &mint, &other_payer));
        assert_ne!(key, input_key(&rows(&[1, 2, 4]), &mint, &payer));
        let twice = [rows(&[1]), rows(&[1]), rows(&[2, 3])].concat();
        assert_ne!(key, input_key(&twice, &mint, &payer));
    }

    #[test]
    fn a_journal_without_an_input_key_still_matches_on_the_raw_hash() {
        let runs = std::env::temp_dir().join(format!("scope-earlier-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&runs);
        let dir = runs.join("ab");
        std::fs::create_dir_all(&dir).expect("dir");
        let old = r#"{"t":"run","run_id":"ab","input_sha256":"beef","mint":"m","source":"s","payer":"p","order":[0]}"#;
        std::fs::write(dir.join(journal::JOURNAL), format!("{old}\n")).expect("journal");
        assert_eq!(
            earlier_run(&runs, "key", "beef").expect("read"),
            Some("ab".into())
        );
        assert_eq!(earlier_run(&runs, "key", "cafe").expect("read"), None);
    }

    #[test]
    fn known_clusters_are_named_and_others_show_their_hash() {
        let hash = |text: &str| -> [u8; 32] {
            solana_message::Hash::from_str(text)
                .expect("genesis hash")
                .to_bytes()
        };
        assert_eq!(
            cluster_name(&hash("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d")),
            "mainnet-beta"
        );
        assert_eq!(
            cluster_name(&hash("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG")),
            "devnet"
        );
        assert_eq!(
            cluster_name(&hash("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY")),
            "testnet"
        );
        let other = cluster_name(&[9; 32]);
        assert!(other.starts_with("unknown cluster "), "{other}");
        assert!(other.contains(&solana_message::Hash::new_from_array([9; 32]).to_string()));
    }

    #[test]
    fn token_amounts_print_with_the_mints_decimals() {
        assert_eq!(token_amount(1_250_500, 6), "1.250500");
        assert_eq!(token_amount(7, 0), "7");
        assert_eq!(token_amount(5, 9), "0.000000005");
    }

    #[test]
    fn mainnet_needs_an_explicit_yes() {
        let mainnet =
            solana_message::Hash::from_str("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d")
                .expect("genesis hash")
                .to_bytes();
        let refused = mainnet_gate(&mainnet, false).expect_err("no --yes");
        assert!(
            refused.contains("--dry-run") && refused.contains("--yes"),
            "{refused}"
        );
        mainnet_gate(&mainnet, true).expect("--yes");
        mainnet_gate(&[9; 32], false).expect("other clusters need no flag");
    }
}
