//! `reclaim`: close an emptied one-time token account and its announcement, rent to the payer.

use crate::{
    address::{TOKEN_2022, announcement_address, announcement_seeds, token_account_address},
    err,
};
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Signer, invoke_signed},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
};
use scope_interface::{ScopeError, state::Announcement, token_account::CLOSE_ACCOUNT_INSTRUCTION};

/// Accounts, in order: announcement (writable), token account (writable), payer
/// (writable), Token-2022 program. No signer: anyone may call it.
pub(crate) struct ReclaimAccounts<'a> {
    pub(crate) announcement: &'a mut AccountView,
    pub(crate) token_account: &'a AccountView,
    pub(crate) payer: &'a mut AccountView,
}

impl<'a> TryFrom<&'a mut [AccountView]> for ReclaimAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let [announcement, token_account, payer, token_program, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
        if token_program.address() != &TOKEN_2022 {
            return Err(err(ScopeError::WrongTokenProgram));
        }
        Ok(Self {
            announcement,
            token_account,
            payer,
        })
    }
}

pub(crate) fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(err(ScopeError::InvalidInstructionData));
    }
    let ReclaimAccounts {
        announcement,
        token_account,
        payer,
    } = ReclaimAccounts::try_from(accounts)?;
    if !announcement.owned_by(program_id) {
        return Err(err(ScopeError::NotAnnouncement));
    }
    let record = Announcement::from_bytes(&announcement.try_borrow()?).map_err(err)?;
    let stored_payer = Address::new_from_array(record.payer);
    if token_account.address() != &token_account_address(&stored_payer, &record.ephemeral)? {
        return Err(err(ScopeError::TokenAccountAddressMismatch));
    }
    let expected = announcement_address(token_account.address(), record.bump, program_id);
    if announcement.address() != &expected {
        return Err(err(ScopeError::AnnouncementAddressMismatch));
    }
    if payer.address() != &stored_payer {
        return Err(err(ScopeError::PayerMismatch));
    }
    close_token_account(token_account, payer, announcement, record.bump)?;
    let lamports = announcement.lamports();
    payer.set_lamports(
        payer
            .lamports()
            .checked_add(lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    announcement.set_lamports(0);
    announcement.close()
}

/// Token-2022 CloseAccount signed by the announcement PDA; it refuses while any balance remains.
#[inline(never)]
fn close_token_account(
    token_account: &AccountView,
    payer: &AccountView,
    announcement: &AccountView,
    bump: u8,
) -> ProgramResult {
    let metas = [
        InstructionAccount::writable(token_account.address()),
        InstructionAccount::writable(payer.address()),
        InstructionAccount::readonly_signer(announcement.address()),
    ];
    let data = [CLOSE_ACCOUNT_INSTRUCTION];
    let ix = InstructionView {
        program_id: &TOKEN_2022,
        data: &data,
        accounts: &metas,
    };
    let bump = [bump];
    let seeds = announcement_seeds(token_account.address(), &bump);
    invoke_signed(
        &ix,
        &[token_account, payer, announcement],
        &[Signer::from(&seeds)],
    )
}
