use crate::err;
use pinocchio::{Address, error::ProgramError};
use scope_interface::{
    SYSTEM_PROGRAM_ID, ScopeError, TOKEN_2022_ID,
    seeds::{token_account_seed, token_account_seed_parts},
};

pub(crate) const TOKEN_2022: Address = Address::new_from_array(TOKEN_2022_ID);
pub(crate) const SYSTEM: Address = Address::new_from_array(SYSTEM_PROGRAM_ID);

/// `create_with_seed(payer, seed(E, k), Token-2022)`; see scope_interface::seeds.
pub(crate) fn token_account_address(
    payer: &Address,
    ephemeral: &[u8; 32],
    k: u8,
) -> Result<Address, ProgramError> {
    let k = [k];
    let digest = solana_sha256_hasher::hashv(&token_account_seed_parts(ephemeral, &k)).to_bytes();
    let seed = token_account_seed(&digest);
    let seed =
        core::str::from_utf8(&seed).map_err(|_| err(ScopeError::TokenAccountAddressMismatch))?;
    Address::create_with_seed(payer, seed, &TOKEN_2022)
        .map_err(|_| err(ScopeError::TokenAccountAddressMismatch))
}
