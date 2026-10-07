//! Creating a program account at a PDA.

use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};

/// Top up to rent exemption, then allocate and assign, so a pre-funded address still works.
#[inline(never)]
pub(crate) fn create(
    payer: &AccountView,
    account: &AccountView,
    program_id: &Address,
    space: usize,
    seeds: &[Seed],
) -> ProgramResult {
    let required = Rent::get()?.try_minimum_balance(space)?;
    let deficit = required.saturating_sub(account.lamports());
    if deficit > 0 {
        Transfer {
            from: payer,
            to: account,
            lamports: deficit,
        }
        .invoke()?;
    }
    let signer = Signer::from(seeds);
    Allocate {
        account,
        space: space as u64,
    }
    .invoke_signed(core::slice::from_ref(&signer))?;
    Assign {
        account,
        owner: program_id,
    }
    .invoke_signed(core::slice::from_ref(&signer))
}
