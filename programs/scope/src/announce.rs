use crate::{
    checks::{SYSTEM, TOKEN_2022, token_account_address},
    err,
};
use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};
use scope_interface::{
    ScopeError,
    instruction::AnnounceData,
    seeds::ANNOUNCEMENT_SEED,
    state::{ANNOUNCEMENT_LEN, Announcement},
    token_account::{STATE_INITIALIZED, read_token_account},
};

/// Checks, in order: data length, payer signed, System id, token account address
/// from (payer, E, k), Token-2022 owned and initialized, close authority is the
/// announcement, owner handed over and no delegate, credit cap 1 with public credits
/// off, announcement address canonical and unused.
pub(crate) fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let data = AnnounceData::from_bytes(data).map_err(err)?;
    let [payer, token_account, announcement, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() {
        return Err(err(ScopeError::PayerNotSigner));
    }
    if system.address() != &SYSTEM {
        return Err(err(ScopeError::WrongSystemProgram));
    }
    if token_account.address() != &token_account_address(payer.address(), &data.ephemeral, data.k)?
    {
        return Err(err(ScopeError::TokenAccountAddressMismatch));
    }
    if !token_account.owned_by(&TOKEN_2022) {
        return Err(err(ScopeError::NotTokenAccount));
    }
    let (expected, bump) = Address::find_program_address(
        &[ANNOUNCEMENT_SEED, token_account.address().as_ref()],
        program_id,
    );
    check_token_account(token_account, payer.address(), &expected)?;
    if announcement.address() != &expected {
        return Err(err(ScopeError::AnnouncementAddressMismatch));
    }
    if !announcement.is_data_empty() || !announcement.owned_by(&SYSTEM) {
        return Err(err(ScopeError::AnnouncementInUse));
    }
    create_announcement(
        payer,
        announcement,
        program_id,
        token_account.address(),
        bump,
    )?;
    let record = Announcement {
        view_tag: data.view_tag,
        k: data.k,
        bump,
        ephemeral: data.ephemeral,
        payer: payer.address().to_bytes(),
    };
    announcement
        .try_borrow_mut()?
        .copy_from_slice(&record.to_bytes());
    Ok(())
}

fn check_token_account(
    token_account: &AccountView,
    payer: &Address,
    announcement: &Address,
) -> ProgramResult {
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

/// Top up to rent exemption, then allocate and assign, so a pre-funded address still works.
#[inline(never)]
fn create_announcement(
    payer: &AccountView,
    announcement: &AccountView,
    program_id: &Address,
    token_account: &Address,
    bump: u8,
) -> ProgramResult {
    let required = Rent::get()?.try_minimum_balance(ANNOUNCEMENT_LEN)?;
    let deficit = required.saturating_sub(announcement.lamports());
    if deficit > 0 {
        Transfer {
            from: payer,
            to: announcement,
            lamports: deficit,
        }
        .invoke()?;
    }
    let bump = [bump];
    let seeds = [
        Seed::from(ANNOUNCEMENT_SEED),
        Seed::from(token_account.as_ref()),
        Seed::from(&bump),
    ];
    let signer = Signer::from(&seeds);
    Allocate {
        account: announcement,
        space: ANNOUNCEMENT_LEN as u64,
    }
    .invoke_signed(core::slice::from_ref(&signer))?;
    Assign {
        account: announcement,
        owner: program_id,
    }
    .invoke_signed(core::slice::from_ref(&signer))
}
