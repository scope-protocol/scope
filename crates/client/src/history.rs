//! Finding payments from transaction history (docs/recipient.md, docs/audit.md). A payment's
//! `announce` is in its own transaction, which stays on an archival node after `reclaim`
//! closes the announcement and the one-time account.

use crate::{
    address::{program_id, token_account_address},
    chain::{AccountData, Chain, ChainError, Commitment},
    receipt::{self, ReceiptError, TransactionArchive},
    sweep::destination_address,
};
use scope_interface::instruction::{AnnounceData, ScopeInstruction};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_zk_sdk::encryption::derivation::derive_confidential_keys;
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, StateWithExtensions,
        confidential_transfer::ConfidentialTransferAccount,
    },
    state::Account,
};
use stealth_keygen::{PaymentAnnouncement, RecipientSecretKeys};

/// Signatures per `getSignaturesForAddress` call, the RPC maximum.
pub const PAGE: usize = 1_000;
/// Transactions `recover` examines unless told otherwise.
pub const DEFAULT_LIMIT: usize = 1_000;
/// Pages `payment_signature` reads before it gives up on a busy account.
const MAX_PAYMENT_PAGES: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureEntry {
    pub signature: Signature,
    pub slot: u64,
    pub succeeded: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct SignatureQuery<'a> {
    /// Start after this signature, going back in time.
    pub before: Option<&'a Signature>,
    /// Stop at this signature, which is not returned.
    pub until: Option<&'a Signature>,
    pub limit: usize,
    pub commitment: Commitment,
}

/// `getSignaturesForAddress`: transactions that touch an address, newest first.
pub trait SignatureHistory {
    fn signatures_for_address(
        &self,
        address: &Address,
        query: &SignatureQuery<'_>,
    ) -> Result<Vec<SignatureEntry>, ChainError>;
}

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    /// Rows already reported are valid; the walk did not get further than `examined`.
    #[error("stopped after listing {listed} and examining {examined} transactions: {source}")]
    Stopped {
        listed: usize,
        examined: usize,
        #[source]
        source: ChainError,
    },
    #[error("writing recover results: {0}")]
    Output(#[source] std::io::Error),
    #[error("{0} has too many transactions to search; pass the payment signature instead")]
    Busy(Address),
}

/// An `announce` instruction as the payer's transaction carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Announce {
    pub payer: Address,
    pub token_account: Address,
    pub ephemeral: [u8; 32],
    pub view_tag: u8,
}

/// Every well-formed `announce` in `tx`: its accounts are the payer and the one-time account
/// that payer's R derives.
pub fn announces(tx: &VersionedTransaction) -> Vec<Announce> {
    let keys = tx.message.static_account_keys();
    let key = |index: Option<&u8>| index.and_then(|i| keys.get(usize::from(*i))).copied();
    tx.message
        .instructions()
        .iter()
        .filter(|ix| keys.get(usize::from(ix.program_id_index)) == Some(&program_id()))
        .filter_map(|ix| {
            let (&tag, rest) = ix.data.split_first()?;
            if ScopeInstruction::try_from(tag) != Ok(ScopeInstruction::Announce) {
                return None;
            }
            let data = AnnounceData::from_bytes(rest).ok()?;
            let payer = key(ix.accounts.first())?;
            let token_account = key(ix.accounts.get(1))?;
            (token_account_address(&payer, &data.ephemeral) == token_account).then_some(Announce {
                payer,
                token_account,
                ephemeral: data.ephemeral,
                view_tag: data.view_tag,
            })
        })
        .collect()
}

/// The signature of the transaction that announced a payment into `token_account`.
///
/// It is the oldest successful transaction touching the account that holds a matching
/// `announce`; anyone can send lamports to the address first, so oldest alone is not enough.
/// `None` when the node has no such transaction.
pub fn payment_signature<H: SignatureHistory + TransactionArchive>(
    history: &H,
    token_account: &Address,
) -> Result<Option<Signature>, HistoryError> {
    let mut entries: Vec<SignatureEntry> = Vec::new();
    for _ in 0..MAX_PAYMENT_PAGES {
        let page = history.signatures_for_address(
            token_account,
            &SignatureQuery {
                before: entries.last().map(|e| &e.signature),
                until: None,
                limit: PAGE,
                commitment: Commitment::Finalized,
            },
        )?;
        let last_page = page.len() < PAGE;
        entries.extend(page);
        if last_page {
            for entry in entries.iter().rev().filter(|e| e.succeeded) {
                let tx = receipt::fetch(history, &entry.signature)?;
                if announces(&tx)
                    .iter()
                    .any(|a| a.token_account == *token_account)
                {
                    return Ok(Some(entry.signature));
                }
            }
            return Ok(None);
        }
    }
    Err(HistoryError::Busy(*token_account))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationState {
    pub lamports: u64,
    /// D's applied balance, from the hint only D's owner key decrypts; `None` when D is not
    /// a confidential Token-2022 account.
    pub amount: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundPayment {
    pub signature: Signature,
    pub payer: Address,
    pub mint: Address,
    pub token_account: Address,
    pub ephemeral: [u8; 32],
    pub destination: Address,
    pub destination_owner: Address,
    /// `None` while D does not exist, so the payment has not been swept to this address.
    pub destination_state: Option<DestinationState>,
}

#[derive(Clone, Debug, Default)]
pub struct RecoverOptions {
    /// Program signatures to list, newest first. Failed transactions count against it.
    pub limit: usize,
    /// Stop at this signature, for an incremental run that only wants newer transactions.
    pub since: Option<Signature>,
    /// Start below this signature, to continue a run into older history.
    pub before: Option<Signature>,
}

#[derive(Debug)]
pub struct RecoverReport {
    pub found: Vec<FoundPayment>,
    /// Signatures the node listed, failed ones included.
    pub listed: usize,
    /// Successful transactions looked at.
    pub examined: usize,
    /// Transactions the node listed but does not have (pruned or not yet finalized).
    pub unavailable: usize,
    /// The oldest signature listed, where a later run can continue with `before`.
    pub last_signature: Option<Signature>,
    /// The limit ended the walk with older history still to list.
    pub truncated: bool,
}

/// Walks the program's transactions, newest first, and returns the payments addressed to
/// `recipient`. A payment counts only when its transaction's confidential transfer pays the
/// key the recipient derives for it.
pub fn recover<C: Chain, H: SignatureHistory + TransactionArchive>(
    chain: &C,
    history: &H,
    recipient: &RecipientSecretKeys,
    opts: &RecoverOptions,
) -> Result<RecoverReport, HistoryError> {
    recover_with(chain, history, recipient, opts, |_| Ok(()))
}

/// `recover`, handing each payment to `on_found` as soon as it is authenticated. A chain
/// error ends the walk with `HistoryError::Stopped`, and the payments already handed over
/// stay valid.
pub fn recover_with<C: Chain, H: SignatureHistory + TransactionArchive>(
    chain: &C,
    history: &H,
    recipient: &RecipientSecretKeys,
    opts: &RecoverOptions,
    mut on_found: impl FnMut(&FoundPayment) -> std::io::Result<()>,
) -> Result<RecoverReport, HistoryError> {
    let genesis = history.genesis_hash()?;
    let mut report = RecoverReport {
        found: Vec::new(),
        listed: 0,
        examined: 0,
        unavailable: 0,
        last_signature: None,
        truncated: false,
    };
    let mut before = opts.before;
    let mut last_page_full = false;
    while report.listed < opts.limit {
        let want = (opts.limit - report.listed).min(PAGE);
        let page = history
            .signatures_for_address(
                &program_id(),
                &SignatureQuery {
                    before: before.as_ref(),
                    until: opts.since.as_ref(),
                    limit: want,
                    commitment: Commitment::Finalized,
                },
            )
            .map_err(|source| stopped(&report, source))?;
        for entry in &page {
            report.listed += 1;
            report.last_signature = Some(entry.signature);
            if !entry.succeeded {
                continue;
            }
            report.examined += 1;
            let tx = match receipt::fetch(history, &entry.signature) {
                Ok(tx) => tx,
                Err(ReceiptError::Chain(e)) if e.is_not_found() => {
                    report.unavailable += 1;
                    continue;
                }
                Err(ReceiptError::Chain(source)) => return Err(stopped(&report, source)),
                Err(_) => {
                    report.unavailable += 1;
                    continue;
                }
            };
            for a in announces(&tx) {
                let found = authenticate(chain, recipient, genesis, &tx, &a, entry)
                    .map_err(|source| stopped(&report, source))?;
                if let Some(found) = found {
                    on_found(&found).map_err(HistoryError::Output)?;
                    report.found.push(found);
                }
            }
        }
        last_page_full = page.len() == want;
        match page.last() {
            Some(last) if last_page_full => before = Some(last.signature),
            _ => break,
        }
    }
    report.truncated = last_page_full && report.listed >= opts.limit;
    Ok(report)
}

fn stopped(report: &RecoverReport, source: ChainError) -> HistoryError {
    HistoryError::Stopped {
        listed: report.listed,
        examined: report.examined,
        source,
    }
}

fn authenticate<C: Chain>(
    chain: &C,
    recipient: &RecipientSecretKeys,
    genesis: [u8; 32],
    tx: &VersionedTransaction,
    a: &Announce,
    entry: &SignatureEntry,
) -> Result<Option<FoundPayment>, ChainError> {
    let note = PaymentAnnouncement {
        ephemeral_public_key: a.ephemeral,
        discovery_tag: a.view_tag,
    };
    let Ok(Some(payment)) = stealth_keygen::recover_payment(recipient, &note) else {
        return Ok(None);
    };
    // The setup transfers lamports to P, so P is in the payment's accounts.
    let owner = Address::new_from_array(payment.payment_public_key);
    if !tx.message.static_account_keys().contains(&owner) {
        return Ok(None);
    }
    let Ok(transfer) = receipt::find_transfer(tx) else {
        return Ok(None);
    };
    if transfer.destination != a.token_account
        || receipt::payment_key(&transfer, genesis, &payment).is_err()
    {
        return Ok(None);
    }
    let Ok(seed) = recipient.derive_sweep_destination(&a.ephemeral, &a.token_account.to_bytes())
    else {
        return Ok(None);
    };
    let owner = Keypair::new_from_array(*seed.as_bytes());
    let destination = destination_address(&owner.pubkey());
    let destination_state = chain
        .account(&destination, Commitment::Confirmed)?
        .map(|account| destination_state(&owner, &account));
    Ok(Some(FoundPayment {
        signature: entry.signature,
        payer: a.payer,
        mint: transfer.mint,
        token_account: a.token_account,
        ephemeral: a.ephemeral,
        destination,
        destination_owner: owner.pubkey(),
        destination_state,
    }))
}

fn destination_state(owner: &Keypair, account: &AccountData) -> DestinationState {
    let amount = StateWithExtensions::<Account>::unpack(&account.data)
        .ok()
        .and_then(|state| {
            let ext = *state.get_extension::<ConfidentialTransferAccount>().ok()?;
            let (_, ae) = derive_confidential_keys(owner, b"").ok()?;
            ae.decrypt(&ext.decryptable_available_balance.try_into().ok()?)
        });
    DestinationState {
        lamports: account.lamports,
        amount,
    }
}
