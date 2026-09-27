use scope_interface::seeds::{ANNOUNCEMENT_SEED, token_account_seed, token_account_seed_parts};
use solana_address::Address;

pub fn program_id() -> Address {
    Address::new_from_array(scope_interface::ID)
}

pub fn token_2022() -> Address {
    Address::new_from_array(scope_interface::TOKEN_2022_ID)
}

/// The `create_with_seed` seed for (E, k); always 32 ASCII hex characters.
pub fn token_account_seed_str(e: &[u8; 32], k: u8) -> String {
    let k = [k];
    let digest = solana_sha256_hasher::hashv(&token_account_seed_parts(e, &k)).to_bytes();
    token_account_seed(&digest)
        .iter()
        .map(|b| *b as char)
        .collect()
}

pub fn token_account_address(payer: &Address, e: &[u8; 32], k: u8) -> Address {
    Address::create_with_seed(payer, &token_account_seed_str(e, k), &token_2022())
        .expect("32-character seed and a non-PDA owner are always valid")
}

pub fn announcement_address(token_account: &Address) -> (Address, u8) {
    Address::find_program_address(&[ANNOUNCEMENT_SEED, token_account.as_ref()], &program_id())
}
