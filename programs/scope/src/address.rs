//! Addresses the program derives: the payer's token account and the announcement PDA.

use crate::err;
use pinocchio::{Address, cpi::Seed, error::ProgramError};
use scope_interface::{
    SYSTEM_PROGRAM_ID, ScopeError, TOKEN_2022_ID,
    seeds::{ANNOUNCEMENT_SEED, token_account_seed, token_account_seed_parts},
};

pub(crate) const TOKEN_2022: Address = Address::new_from_array(TOKEN_2022_ID);
pub(crate) const SYSTEM: Address = Address::new_from_array(SYSTEM_PROGRAM_ID);

/// `create_with_seed(payer, seed(R), Token-2022)`; see scope_interface::seeds.
pub(crate) fn token_account_address(
    payer: &Address,
    ephemeral: &[u8; 32],
) -> Result<Address, ProgramError> {
    let digest = solana_sha256_hasher::hashv(&token_account_seed_parts(ephemeral)).to_bytes();
    let seed = token_account_seed(&digest);
    let seed =
        core::str::from_utf8(&seed).map_err(|_| err(ScopeError::TokenAccountAddressMismatch))?;
    Address::create_with_seed(payer, seed, &TOKEN_2022)
        .map_err(|_| err(ScopeError::TokenAccountAddressMismatch))
}

/// Canonical announcement PDA for a token account.
pub(crate) fn announcement_pda(token_account: &Address, program_id: &Address) -> (Address, u8) {
    Address::find_program_address(&[ANNOUNCEMENT_SEED, token_account.as_ref()], program_id)
}

/// Announcement address from a stored bump, without the canonical search.
pub(crate) fn announcement_address(
    token_account: &Address,
    bump: u8,
    program_id: &Address,
) -> Address {
    Address::derive_address(
        &[ANNOUNCEMENT_SEED, token_account.as_ref()],
        Some(bump),
        program_id,
    )
}

/// Signer seeds for the announcement PDA.
pub(crate) fn announcement_seeds<'a>(
    token_account: &'a Address,
    bump: &'a [u8; 1],
) -> [Seed<'a>; 3] {
    [
        Seed::from(ANNOUNCEMENT_SEED),
        Seed::from(token_account.as_ref()),
        Seed::from(bump),
    ]
}
