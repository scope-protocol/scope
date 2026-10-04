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

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error("payment {account}: {why}")]
    Invalid { account: Address, why: String },
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
) -> Result<Vec<PaymentInfo>, ScanError> {
    let genesis = chain.genesis_hash()?;
    let mut payments = Vec::new();
    for (address, account) in chain.announcements()? {
        if let Some(payment) = inspect(chain, recipient, genesis, address, &account)?
            && mint.is_none_or(|m| *m == payment.info.mint)
        {
            payments.push(payment.info);
        }
    }
    payments.sort_by_key(|p| p.announcement);
    Ok(payments)
}

pub(crate) fn inspect<C: RecipientChain>(
    chain: &C,
    recipient: &RecipientSecretKeys,
    genesis: [u8; 32],
    address: Address,
    account: &AccountData,
) -> Result<Option<OwnedPayment>, ScanError> {
    if account.owner != program_id() || account.lamports == 0 {
        return Ok(None);
    }
    let Ok(announcement) = Announcement::from_bytes(&account.data) else {
        return Ok(None);
    };
    let payer = Address::new_from_array(announcement.payer);
    let token_account = token_account_address(&payer, &announcement.ephemeral);
    if announcement_address(&token_account) != (address, announcement.bump) {
        return Ok(None);
    }
    let note = PaymentAnnouncement {
        ephemeral_public_key: announcement.ephemeral,
        discovery_tag: announcement.view_tag,
    };
    let Ok(Some(payment)) = recover_payment(recipient, &note) else {
        return Ok(None);
    };
    let Some(source) = chain.account(&token_account, Commitment::Confirmed)? else {
        return Ok(None);
    };
    if source.owner != token_2022() {
        return Ok(None);
    }
    let Ok(state) = StateWithExtensions::<Account>::unpack(&source.data) else {
        return Ok(None);
    };
    if state.base.owner.to_bytes() != payment.payment_public_key {
        return Ok(None);
    }
    let bad = |why: &str| ScanError::Invalid {
        account: token_account,
        why: why.into(),
    };
    if state.base.state != AccountState::Initialized {
        return Err(bad("account is frozen"));
    }
    if state.base.close_authority != Some(address).into() || state.base.delegate.is_some() {
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
        .derive_ct_ikm(&context(genesis, &state.base.mint, &token_account))
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
    let lo = elgamal
        .secret()
        .decrypt_u32(&lo)
        .ok_or(bad("pending low balance does not decrypt"))?;
    let hi = elgamal
        .secret()
        .decrypt_u32(&hi)
        .ok_or(bad("pending high balance does not decrypt"))?;
    let pending = hi
        .checked_shl(16)
        .and_then(|h| h.checked_add(lo))
        .ok_or(bad("pending balance overflow"))?;
    let amount = amount.checked_add(pending).ok_or(bad("balance overflow"))?;
    Ok(Some(OwnedPayment {
        info: PaymentInfo {
            announcement: address,
            token_account,
            payer,
            mint: state.base.mint,
            ephemeral: announcement.ephemeral,
            amount,
            public_amount: state.base.amount,
        },
        payment,
        elgamal,
        ae,
        extension: ext,
    }))
}
