//! `announce`: check the payer's setup of a one-time token account and publish it.

use crate::{
    address::{SYSTEM, announcement_pda, announcement_seeds, token_account_address},
    err, pda, setup,
};
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};
use scope_interface::{
    ScopeError,
    instruction::AnnounceData,
    state::{ANNOUNCEMENT_LEN, Announcement},
};

/// Accounts, in order: payer (signer, writable), token account, announcement
/// (writable), System program.
pub(crate) struct AnnounceAccounts<'a> {
    pub(crate) payer: &'a AccountView,
    pub(crate) token_account: &'a AccountView,
    pub(crate) announcement: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for AnnounceAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let [payer, token_account, announcement, system, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if !payer.is_signer() {
            return Err(err(ScopeError::PayerNotSigner));
        }
        if system.address() != &SYSTEM {
            return Err(err(ScopeError::WrongSystemProgram));
        }
        Ok(Self {
            payer,
            token_account,
            announcement,
        })
    }
}

/// Checks in order: data, payer signed, System id, token account from (payer, R),
/// the setup rules in `setup`, announcement canonical and unused.
pub(crate) fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let data = AnnounceData::from_bytes(data).map_err(err)?;
    let AnnounceAccounts {
        payer,
        token_account,
        announcement,
    } = AnnounceAccounts::try_from(accounts)?;
    if token_account.address() != &token_account_address(payer.address(), &data.ephemeral)? {
        return Err(err(ScopeError::TokenAccountAddressMismatch));
    }
    let (expected, bump) = announcement_pda(token_account.address(), program_id);
    setup::check(token_account, payer.address(), &expected)?;
    if announcement.address() != &expected {
        return Err(err(ScopeError::AnnouncementAddressMismatch));
    }
    if !announcement.is_data_empty() || !announcement.owned_by(&SYSTEM) {
        return Err(err(ScopeError::AnnouncementInUse));
    }
    let bump_seed = [bump];
    pda::create(
        payer,
        announcement,
        program_id,
        ANNOUNCEMENT_LEN,
        &announcement_seeds(token_account.address(), &bump_seed),
    )?;
    let record = Announcement {
        view_tag: data.view_tag,
        bump,
        ephemeral: data.ephemeral,
        payer: payer.address().to_bytes(),
    };
    announcement
        .try_borrow_mut()?
        .copy_from_slice(&record.to_bytes());
    Ok(())
}
