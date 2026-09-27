//! SCOPE on-chain program (docs/design.md): `announce` publishes a one-time token
//! account the payer set up and handed over; `reclaim` returns its rent to the payer.

#![no_std]

mod announce;
mod checks;
mod reclaim;

use pinocchio::{
    AccountView, Address, ProgramResult, error::ProgramError, no_allocator, nostd_panic_handler,
    program_entrypoint,
};
use scope_interface::{ScopeError, instruction::ScopeInstruction};

program_entrypoint!(process_instruction);
no_allocator!();
nostd_panic_handler!();

fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&tag, rest) = data
        .split_first()
        .ok_or(err(ScopeError::InvalidInstruction))?;
    match ScopeInstruction::try_from(tag).map_err(err)? {
        ScopeInstruction::Announce => announce::process(program_id, accounts, rest),
        ScopeInstruction::Reclaim => reclaim::process(program_id, accounts, rest),
    }
}

pub(crate) fn err(e: ScopeError) -> ProgramError {
    ProgramError::Custom(e.code())
}
