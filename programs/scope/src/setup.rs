//! The Token-2022 settings every announced account must have (docs/design.md, announce).

use crate::{address::TOKEN_2022, err};
use pinocchio::{AccountView, Address, ProgramResult};
use scope_interface::{
    ScopeError,
    token_account::{STATE_INITIALIZED, read_token_account},
};

/// Checks 5 to 8: Token-2022 account, initialized, close authority is the
/// announcement, handed over with no delegate, credit cap 1, public credits off.
pub(crate) fn check(
    token_account: &AccountView,
    payer: &Address,
    announcement: &Address,
) -> ProgramResult {
    if !token_account.owned_by(&TOKEN_2022) {
        return Err(err(ScopeError::NotTokenAccount));
    }
    let data = token_account.try_borrow()?;
    let view = read_token_account(&data).map_err(err)?;
    if view.state != STATE_INITIALIZED {
        return Err(err(ScopeError::TokenAccountNotInitialized));
    }
    if view.close_authority != Some(announcement.to_bytes()) {
        return Err(err(ScopeError::CloseAuthorityMismatch));
    }
    if view.owner == payer.to_bytes() {
        return Err(err(ScopeError::OwnerNotHandedOver));
    }
    if view.delegate.is_some() {
        return Err(err(ScopeError::DelegateSet));
    }
    let ct = view
        .confidential
        .ok_or(err(ScopeError::MissingConfidentialExtension))?;
    if ct.maximum_pending_balance_credit_counter != 1 {
        return Err(err(ScopeError::CreditCapNotOne));
    }
    if ct.allow_non_confidential_credits {
        return Err(err(ScopeError::PublicCreditsEnabled));
    }
    Ok(())
}
