//! Discover and authenticate recipient payments before deriving their balances.

use crate::{
    address::{announcement_address, program_id, token_2022, token_account_address},
    chain::{AccountData, ChainError, Commitment, RecipientChain},
    confidential::{context, derive_confidential_keys},
};
use curve25519_dalek::scalar::Scalar;
use scope_interface::state::Announcement;
use solana_address::Address;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
    pedersen::G,
};
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, StateWithExtensions,
        confidential_transfer::ConfidentialTransferAccount,
    },
    state::{Account, AccountState},
};
use stealth_keygen::{PaymentAnnouncement, RecipientSecretKeys, RecoveredPayment, recover_payment};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentInfo {
    pub announcement: Address,
    pub token_account: Address,
    pub payer: Address,
    pub mint: Address,
    pub ephemeral: [u8; 32],
    pub amount: u64,
    pub public_amount: u64,
}

/// Which found payments a caller wants; the scan itself reads them all.
#[derive(Clone, Debug, Default)]
pub struct PaymentFilter {
    pub min_amount: u64,
    pub ignore_payers: Vec<Address>,
}

impl PaymentFilter {
    pub fn accepts(&self, payment: &PaymentInfo) -> bool {
        payment.amount >= self.min_amount && !self.ignore_payers.contains(&payment.payer)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error("payment {account}: {why}")]
    Invalid { account: Address, why: String },
    #[error("writing scan results: {0}")]
    Output(#[source] std::io::Error),
    /// Rows already reported are valid; the rest of the candidates were not read.
    #[error("scan stopped after reading {read} of {total} candidate accounts: {source}")]
    Incomplete {
        read: usize,
        total: usize,
        #[source]
        source: ChainError,
    },
}

/// Candidate token accounts per `getMultipleAccounts` call, the RPC maximum.
pub const ACCOUNT_BATCH: usize = 100;

#[derive(Debug)]
pub struct ScanReport {
    pub payments: Vec<PaymentInfo>,
    pub skipped: Vec<ScanError>,
}

pub(crate) struct OwnedPayment {
    pub info: PaymentInfo,
    pub payment: RecoveredPayment,
    pub elgamal: ElGamalKeypair,
    pub ae: AeKey,
    pub extension: ConfidentialTransferAccount,
}

/// Tags depend on each announcement's R, so filter locally before account reads.
pub fn scan<C: RecipientChain>(
    chain: &C,
    recipient: &RecipientSecretKeys,
    mint: Option<&Address>,
) -> Result<ScanReport, ScanError> {
    scan_with_results(chain, recipient, mint, |_| Ok(()))
}

pub fn scan_with_results<C: RecipientChain>(
    chain: &C,
    recipient: &RecipientSecretKeys,
    mint: Option<&Address>,
    mut on_result: impl FnMut(Result<&PaymentInfo, &ScanError>) -> std::io::Result<()>,
) -> Result<ScanReport, ScanError> {
    let genesis = chain.genesis_hash()?;
    let mut payments = Vec::new();
    let mut skipped = Vec::new();
    let candidates: Vec<Candidate> = chain
        .announcements()?
        .into_iter()
        .filter_map(|(address, account)| candidate(recipient, address, &account))
        .collect();
    let total = candidates.len();
    let mut pending = candidates.into_iter();
    let mut read = 0;
    loop {
        let batch: Vec<Candidate> = pending.by_ref().take(ACCOUNT_BATCH).collect();
        if batch.is_empty() {
            break;
        }
        let mut keys: Vec<Address> = Vec::with_capacity(batch.len());
        for c in &batch {
            if !keys.contains(&c.token_account) {
                keys.push(c.token_account);
            }
        }
        let sources = chain
            .accounts(&keys, Commitment::Confirmed)
            .map_err(|source| ScanError::Incomplete {
                read,
                total,
                source,
            })?;
        read += batch.len();
        for c in batch {
            let Some(source) = keys
                .iter()
                .position(|k| *k == c.token_account)
                .and_then(|i| sources.get(i))
                .cloned()
                .flatten()
            else {
                continue;
            };
            match decode_source(c.info(), c.payment, genesis, source, mint) {
                Ok(Some(payment)) => {
                    on_result(Ok(&payment.info)).map_err(ScanError::Output)?;
                    payments.push(payment.info);
                }
                Ok(None) => {}
                Err(error @ ScanError::Invalid { .. }) => {
                    on_result(Err(&error)).map_err(ScanError::Output)?;
                    skipped.push(error);
                }
                Err(error) => return Err(error),
            }
        }
    }
    payments.sort_by_key(|p| p.announcement);
    Ok(ScanReport { payments, skipped })
}

/// An announcement that is canonical and addressed to this recipient by its view tag; the
/// token account behind it is not read yet.
struct Candidate {
    announcement: Address,
    token_account: Address,
    payer: Address,
    ephemeral: [u8; 32],
    payment: RecoveredPayment,
}

impl Candidate {
    fn info(&self) -> PaymentInfo {
        PaymentInfo {
            announcement: self.announcement,
            token_account: self.token_account,
            payer: self.payer,
            mint: Address::default(),
            ephemeral: self.ephemeral,
            amount: 0,
            public_amount: 0,
        }
    }
}

fn candidate(
    recipient: &RecipientSecretKeys,
    address: Address,
    account: &AccountData,
) -> Option<Candidate> {
    if account.owner != program_id() || account.lamports == 0 {
        return None;
    }
    let announcement = Announcement::from_bytes(&account.data).ok()?;
    let payer = Address::new_from_array(announcement.payer);
    let token_account = token_account_address(&payer, &announcement.ephemeral);
    if announcement_address(&token_account) != (address, announcement.bump) {
        return None;
    }
    let note = PaymentAnnouncement {
        ephemeral_public_key: announcement.ephemeral,
        discovery_tag: announcement.view_tag,
    };
    let Ok(Some(payment)) = recover_payment(recipient, &note) else {
        return None;
    };
    Some(Candidate {
        announcement: address,
        token_account,
        payer,
        ephemeral: announcement.ephemeral,
        payment,
    })
}

pub(crate) fn inspect<C: RecipientChain>(
    chain: &C,
    recipient: &RecipientSecretKeys,
    genesis: [u8; 32],
    address: Address,
    account: &AccountData,
    mint: Option<&Address>,
) -> Result<Option<OwnedPayment>, ScanError> {
    let Some(c) = candidate(recipient, address, account) else {
        return Ok(None);
    };
    let Some(source) = chain.account(&c.token_account, Commitment::Confirmed)? else {
        return Ok(None);
    };
    decode_source(c.info(), c.payment, genesis, source, mint)
}

pub(crate) fn decode_source(
    info: PaymentInfo,
    payment: RecoveredPayment,
    genesis: [u8; 32],
    source: AccountData,
    mint: Option<&Address>,
) -> Result<Option<OwnedPayment>, ScanError> {
    if source.owner != token_2022() {
        return Ok(None);
    }
    let Ok(state) = StateWithExtensions::<Account>::unpack(&source.data) else {
        return Ok(None);
    };
    if mint.is_some_and(|m| *m != state.base.mint) {
        return Ok(None);
    }
    if state.base.owner.to_bytes() != payment.payment_public_key {
        return Ok(None);
    }
    let bad = |why: &str| ScanError::Invalid {
        account: info.token_account,
        why: why.into(),
    };
    if state.base.state != AccountState::Initialized {
        return Err(bad("account is frozen"));
    }
    if state.base.close_authority != Some(info.announcement).into() || state.base.delegate.is_some()
    {
        return Err(bad("unexpected close authority or delegate"));
    }
    let ext = *state
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| bad("missing confidential extension"))?;
    if !bool::from(ext.approved)
        || bool::from(ext.allow_non_confidential_credits)
        || u64::from(ext.maximum_pending_balance_credit_counter) != 1
        || u64::from(ext.pending_balance_credit_counter) > 1
    {
        return Err(bad("invalid confidential account policy"));
    }
    let material = payment
        .derive_ct_ikm(&context(genesis, &state.base.mint, &info.token_account))
        .map_err(|_| bad("key derivation failed"))?;
    let (elgamal, ae) = derive_confidential_keys(&material)
        .map_err(|_| bad("confidential key derivation failed"))?;
    if ext.elgamal_pubkey != (*elgamal.pubkey()).into() {
        return Err(bad("ElGamal key differs from the derived key"));
    }
    let hint = ext
        .decryptable_available_balance
        .try_into()
        .map_err(|_| bad("invalid balance hint"))?;
    let available: ElGamalCiphertext = ext
        .available_balance
        .try_into()
        .map_err(|_| bad("invalid available ciphertext"))?;
    let amount = ae
        .decrypt(&hint)
        .ok_or(bad("balance hint does not decrypt"))?;
    if elgamal.secret().decrypt(&available).target != G * Scalar::from(amount) {
        return Err(bad("balance hint disagrees with the ciphertext"));
    }
    let lo: ElGamalCiphertext = ext
        .pending_balance_lo
        .try_into()
        .map_err(|_| bad("invalid pending ciphertext"))?;
    let hi: ElGamalCiphertext = ext
        .pending_balance_hi
        .try_into()
        .map_err(|_| bad("invalid pending ciphertext"))?;
    let lo = if ext.pending_balance_lo.0 == [0; 64] {
        0
    } else {
        elgamal
            .secret()
            .decrypt_u32(&lo)
            .ok_or(bad("pending low balance does not decrypt"))?
    };
    let hi = if ext.pending_balance_hi.0 == [0; 64] {
        0
    } else {
        elgamal
            .secret()
            .decrypt_u32(&hi)
            .ok_or(bad("pending high balance does not decrypt"))?
    };
    if lo > u64::from(u16::MAX) || hi > u64::from(u32::MAX) {
        return Err(bad("pending balance exceeds the single-credit range"));
    }
    let pending = hi
        .checked_shl(16)
        .and_then(|h| h.checked_add(lo))
        .ok_or(bad("pending balance overflow"))?;
    let amount = amount.checked_add(pending).ok_or(bad("balance overflow"))?;
    Ok(Some(OwnedPayment {
        info: PaymentInfo {
            mint: state.base.mint,
            amount,
            public_amount: state.base.amount,
            ..info
        },
        payment,
        elgamal,
        ae,
        extension: ext,
    }))
}
