use crate::address::{
    announcement_address, meta_entry_address, program_id, token_2022, token_account_address,
    token_account_seed_str,
};
use core::num::NonZeroI8;
use scope_interface::{
    instruction::{AnnounceData, RECLAIM_DATA, RegisterData, deregister_data},
    state::{META_SCHEME_V1, META_VERSION},
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_zk_sdk::{
    encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use spl_token_2022_interface::{
    extension::confidential_transfer::instruction::{
        configure_account, disable_non_confidential_credits,
    },
    instruction::{AuthorityType, initialize_account3, set_authority},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use stealth_keygen::RecipientPublicKeys;

pub fn announce(payer: &Address, e: &[u8; 32], view_tag: u8) -> Instruction {
    let token_account = token_account_address(payer, e);
    let (announcement, _) = announcement_address(&token_account);
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(token_account, false),
            AccountMeta::new(announcement, false),
            AccountMeta::new_readonly(Address::default(), false),
        ],
        data: AnnounceData {
            ephemeral: *e,
            view_tag,
        }
        .to_bytes()
        .to_vec(),
    }
}

pub fn reclaim(announcement: &Address, token_account: &Address, payer: &Address) -> Instruction {
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*announcement, false),
            AccountMeta::new(*token_account, false),
            AccountMeta::new(*payer, false),
            AccountMeta::new_readonly(token_2022(), false),
        ],
        data: RECLAIM_DATA.to_vec(),
    }
}

/// Publishes `keys` under `registrant`; the registrant signs and pays the entry's rent.
pub fn register(registrant: &Address, keys: &RecipientPublicKeys) -> Instruction {
    let (entry, _) = meta_entry_address(registrant);
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*registrant, true),
            AccountMeta::new(entry, false),
            AccountMeta::new_readonly(Address::default(), false),
        ],
        data: RegisterData {
            scheme_id: META_SCHEME_V1,
            version: META_VERSION,
            spend: keys.spend_public_key_bytes(),
            scan: keys.scan_public_key_bytes(),
            flags: 0,
        }
        .to_bytes()
        .to_vec(),
    }
}

/// Closes the registrant's entry and returns its rent.
pub fn deregister(registrant: &Address) -> Instruction {
    let (entry, _) = meta_entry_address(registrant);
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*registrant, true),
            AccountMeta::new(entry, false),
        ],
        data: deregister_data(META_SCHEME_V1).to_vec(),
    }
}

/// Replaces CreateAccountWithSeed for an address someone already sent `existing`
/// lamports to, which CreateAccountWithSeed refuses: tops it up to `rent`, then
/// allocates and assigns it, both signed by `base`.
pub fn create_prefunded_with_seed(
    base: &Address,
    address: &Address,
    seed: &str,
    rent: u64,
    existing: u64,
    space: u64,
    owner: &Address,
) -> Vec<Instruction> {
    use solana_system_interface::instruction as system;
    let mut ixs = Vec::new();
    if rent > existing {
        ixs.push(system::transfer(base, address, rent - existing));
    }
    ixs.push(system::allocate_with_seed(
        address, base, seed, space, owner,
    ));
    ixs.push(system::assign_with_seed(address, base, seed, owner));
    ixs
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("proof generation failed: {0}")]
    Proof(String),
    #[error("token instruction rejected: {0}")]
    Token(String),
}

fn token<E: core::fmt::Display>(e: E) -> BuildError {
    BuildError::Token(e.to_string())
}

/// Everything the payer needs to set up one stealth account.
pub struct StealthSetup<'a> {
    pub payer: Address,
    pub mint: Address,
    pub ephemeral: [u8; 32],
    pub view_tag: u8,
    pub one_time_owner: Address,
    pub elgamal: &'a ElGamalKeypair,
    pub ae: &'a AeKey,
    pub rent_lamports: u64,
    pub space: u64,
    pub lamports_for_owner: u64,
}

const fn offset(n: i8) -> NonZeroI8 {
    match NonZeroI8::new(n) {
        Some(v) => v,
        None => panic!("proof offset must be nonzero"),
    }
}

/// The payer's setup sequence, in order, ending with `announce` and the lamports for P.
/// The confidential Transfer and its proofs are appended by the caller.
pub fn stealth_setup(s: &StealthSetup<'_>) -> Result<Vec<Instruction>, BuildError> {
    let t22 = token_2022();
    let ta = token_account_address(&s.payer, &s.ephemeral);
    let (announcement, _) = announcement_address(&ta);
    let seed = token_account_seed_str(&s.ephemeral);
    let proof = build_pubkey_validity_proof_data(s.elgamal)
        .map_err(|e| BuildError::Proof(e.to_string()))?;
    let mut ixs = vec![
        solana_system_interface::instruction::create_account_with_seed(
            &s.payer,
            &ta,
            &s.payer,
            &seed,
            s.rent_lamports,
            s.space,
            &t22,
        ),
        initialize_account3(&t22, &ta, &s.mint, &s.payer).map_err(token)?,
    ];
    ixs.extend(
        configure_account(
            &t22,
            &ta,
            &s.mint,
            &s.ae.encrypt(0).into(),
            1,
            &s.payer,
            &[],
            ProofLocation::InstructionOffset(offset(1), &proof),
        )
        .map_err(token)?,
    );
    ixs.push(disable_non_confidential_credits(&t22, &ta, &s.payer, &[]).map_err(token)?);
    ixs.push(
        set_authority(
            &t22,
            &ta,
            Some(&announcement),
            AuthorityType::CloseAccount,
            &s.payer,
            &[],
        )
        .map_err(token)?,
    );
    ixs.push(
        set_authority(
            &t22,
            &ta,
            Some(&s.one_time_owner),
            AuthorityType::AccountOwner,
            &s.payer,
            &[],
        )
        .map_err(token)?,
    );
    ixs.push(announce(&s.payer, &s.ephemeral, s.view_tag));
    ixs.push(solana_system_interface::instruction::transfer(
        &s.payer,
        &s.one_time_owner,
        s.lamports_for_owner,
    ));
    Ok(ixs)
}
