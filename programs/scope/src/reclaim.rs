use crate::{
    checks::{TOKEN_2022, token_account_address},
    err,
};
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer, invoke_signed},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
};
use scope_interface::{
    ScopeError, seeds::ANNOUNCEMENT_SEED, state::Announcement,
    token_account::CLOSE_ACCOUNT_INSTRUCTION,
};

/// Anyone may call it. The token account must be the one the announcement's own
/// (payer, E, k) derive, so a decoy account cannot close someone else's announcement.
pub(crate) fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    if !data.is_empty() {
        return Err(err(ScopeError::InvalidInstructionData));
    }
    let [announcement, token_account, payer, token_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if token_program.address() != &TOKEN_2022 {
        return Err(err(ScopeError::WrongTokenProgram));
    }
    if !announcement.owned_by(program_id) {
        return Err(err(ScopeError::NotAnnouncement));
    }
    let record = Announcement::from_bytes(&announcement.try_borrow()?).map_err(err)?;
    let stored_payer = Address::new_from_array(record.payer);
    if token_account.address()
        != &token_account_address(&stored_payer, &record.ephemeral, record.k)?
    {
        return Err(err(ScopeError::TokenAccountAddressMismatch));
    }
    let derived = Address::derive_address(
        &[ANNOUNCEMENT_SEED, token_account.address().as_ref()],
        Some(record.bump),
        program_id,
    );
    if announcement.address() != &derived {
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
    let seeds = [
        Seed::from(ANNOUNCEMENT_SEED),
        Seed::from(token_account.address().as_ref()),
        Seed::from(&bump),
    ];
    invoke_signed(
        &ix,
        &[token_account, payer, announcement],
        &[Signer::from(&seeds)],
    )
}
