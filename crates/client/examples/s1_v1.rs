//! Spike S1: send the stealth payer transaction as a v1 transaction to a live cluster.
//!
//! `cargo run -p scope-client --example s1_v1 -- [RPC_URL]` (default http://127.0.0.1:8899).
//! The program must already be deployed at `scope_interface::ID`; the fee payer is
//! `~/.config/solana/id.json`.

use core::num::NonZeroI8;
use scope_client::{
    address::{announcement_address, token_2022, token_account_address},
    ix::{StealthSetup, stealth_setup},
    tx::{v1_transaction, v1_wire_size},
};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::{Keypair, read_keypair_file};
use solana_rpc_client::{
    api::config::RpcTransactionConfig, rpc_client::RpcClient, rpc_client::SerializableTransaction,
};
use solana_signer::Signer;
use solana_transaction_status_client_types::UiTransactionEncoding;
use solana_zk_sdk::{
    encryption::{
        auth_encryption::AeKey,
        elgamal::{ElGamalCiphertext, ElGamalKeypair},
    },
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        confidential_transfer::{ConfidentialTransferAccount, instruction as ct},
    },
    instruction as t22,
    state::{Account, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;
use std::error::Error;

type Res<T> = Result<T, Box<dyn Error>>;

const DECIMALS: u8 = 6;
const SOURCE_FUNDS: u64 = 1_000_000_000;
const AMOUNT: u64 = 250_000;

fn off(n: i8) -> NonZeroI8 {
    NonZeroI8::new(n).expect("nonzero")
}

struct Cluster {
    rpc: RpcClient,
    payer: Keypair,
}

impl Cluster {
    fn send(&self, ixs: &[Instruction], extra: &[&Keypair]) -> Res<()> {
        let tx = v1_transaction(&self.payer, extra, ixs, self.rpc.get_latest_blockhash()?);
        self.rpc.send_and_confirm_transaction(&tx)?;
        Ok(())
    }

    fn create_mint(&self) -> Res<Address> {
        let mint = Keypair::new();
        let t22 = token_2022();
        let space = ExtensionType::try_calculate_account_len::<Mint>(&[
            ExtensionType::ConfidentialTransferMint,
        ])?;
        let authority = self.payer.pubkey();
        self.send(
            &[
                solana_system_interface::instruction::create_account(
                    &authority,
                    &mint.pubkey(),
                    self.rpc.get_minimum_balance_for_rent_exemption(space)?,
                    space as u64,
                    &t22,
                ),
                ct::initialize_mint(&t22, &mint.pubkey(), Some(authority), true, None)?,
                t22::initialize_mint2(&t22, &mint.pubkey(), &authority, None, DECIMALS)?,
            ],
            &[&mint],
        )?;
        Ok(mint.pubkey())
    }

    /// Confidential account owned by the payer, funded and shielded like the harness source.
    fn create_funded_source(
        &self,
        mint: &Address,
        keys: &ElGamalKeypair,
        ae: &AeKey,
    ) -> Res<Address> {
        let account = Keypair::new();
        let t22 = token_2022();
        let owner = self.payer.pubkey();
        let space = ExtensionType::try_calculate_account_len::<Account>(&[
            ExtensionType::ConfidentialTransferAccount,
        ])?;
        let proof = build_pubkey_validity_proof_data(keys)?;
        let mut ixs = vec![
            solana_system_interface::instruction::create_account(
                &owner,
                &account.pubkey(),
                self.rpc.get_minimum_balance_for_rent_exemption(space)?,
                space as u64,
                &t22,
            ),
            t22::initialize_account3(&t22, &account.pubkey(), mint, &owner)?,
        ];
        ixs.extend(ct::configure_account(
            &t22,
            &account.pubkey(),
            mint,
            &ae.encrypt(0).into(),
            65_536,
            &owner,
            &[],
            ProofLocation::InstructionOffset(off(1), &proof),
        )?);
        self.send(&ixs, &[&account])?;
        let source = account.pubkey();
        self.send(
            &[
                t22::mint_to(&t22, mint, &source, &owner, &[], SOURCE_FUNDS)?,
                ct::deposit(&t22, &source, mint, SOURCE_FUNDS, DECIMALS, &owner, &[])?,
                ct::apply_pending_balance(
                    &t22,
                    &source,
                    1,
                    &ae.encrypt(SOURCE_FUNDS).into(),
                    &owner,
                    &[],
                )?,
            ],
            &[],
        )?;
        Ok(source)
    }
}

fn main() -> Res<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8899".into());
    let home = std::env::home_dir().ok_or("no home directory")?;
    let payer = read_keypair_file(home.join(".config/solana/id.json"))?;
    let c = Cluster {
        rpc: RpcClient::new(url.clone()),
        payer,
    };
    println!("cluster {url}, fee payer {}", c.payer.pubkey());

    let t22 = token_2022();
    let mint = c.create_mint()?;
    let (source_keys, source_ae) = (ElGamalKeypair::new_rand(), AeKey::new_rand());
    let source = c.create_funded_source(&mint, &source_keys, &source_ae)?;
    println!("mint {mint}, source {source}");

    // Payer side of one stealth payment: setup + announce + Transfer, one transaction.
    let one_time_owner = Keypair::new();
    let (elgamal, ae) = (ElGamalKeypair::new_rand(), AeKey::new_rand());
    let ephemeral = Keypair::new().pubkey().to_bytes();
    let payer = c.payer.pubkey();
    let token_account = token_account_address(&payer, &ephemeral, 0);
    let (announcement, _) = announcement_address(&token_account);
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])?;
    let mut ixs = stealth_setup(&StealthSetup {
        payer,
        mint,
        ephemeral,
        k: 0,
        view_tag: ephemeral[0],
        one_time_owner: one_time_owner.pubkey(),
        elgamal: &elgamal,
        ae: &ae,
        rent_lamports: c.rpc.get_minimum_balance_for_rent_exemption(space)?,
        space: space as u64,
        lamports_for_owner: 5_000_000,
    })?;

    let data = c.rpc.get_account_data(&source)?;
    let state = StateWithExtensions::<Account>::unpack(&data)?;
    let ext = state.get_extension::<ConfidentialTransferAccount>()?;
    let available: ElGamalCiphertext = ext.available_balance.try_into()?;
    let proofs = transfer_split_proof_data(
        &available,
        &ext.decryptable_available_balance.try_into()?,
        AMOUNT,
        &source_keys,
        &source_ae,
        elgamal.pubkey(),
        None,
    )?;
    let validity = &proofs.ciphertext_validity_proof_data_with_ciphertext;
    ixs.extend(ct::transfer(
        &t22,
        &source,
        &mint,
        &token_account,
        &source_ae.encrypt(SOURCE_FUNDS - AMOUNT).into(),
        &validity.ciphertext_lo,
        &validity.ciphertext_hi,
        &payer,
        &[],
        ProofLocation::InstructionOffset(off(1), &proofs.equality_proof_data),
        ProofLocation::InstructionOffset(off(2), &validity.proof_data),
        ProofLocation::InstructionOffset(off(3), &proofs.range_proof_data),
    )?);

    let tx = v1_transaction(&c.payer, &[], &ixs, c.rpc.get_latest_blockhash()?);
    println!(
        "payer tx: {} instructions, {} bytes built",
        ixs.len(),
        v1_wire_size(&tx)
    );
    let signature = c.rpc.send_and_confirm_transaction(&tx)?;
    println!("signature {signature}");
    assert_eq!(&signature, tx.get_signature());

    let landed = c.rpc.get_transaction_with_config(
        &signature,
        RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Base64),
            commitment: None,
            max_supported_transaction_version: Some(1),
        },
    )?;
    let meta = landed.transaction.meta.ok_or("no meta")?;
    let cu: Option<u64> = meta.compute_units_consumed.into();
    let fetched = landed
        .transaction
        .transaction
        .decode()
        .ok_or("transaction does not decode")?;
    println!(
        "slot {}, {} CU, {} bytes on chain, err {:?}",
        landed.slot,
        cu.ok_or("no CU in meta")?,
        v1_wire_size(&fetched),
        meta.err
    );
    println!("announcement {announcement}, one-time account {token_account}");
    Ok(())
}
