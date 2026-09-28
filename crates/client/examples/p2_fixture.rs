//! P2 fixture: a confidential mint, a funded source whose keys derive from the payer
//! keypair the way `scope pay` derives them, and N configured plain recipients.
//!
//! `cargo run -p scope-client --example p2_fixture -- RPC_URL KEYPAIR N INPUT_CSV`
//! writes `recipient,amount` rows to INPUT_CSV (row i pays i + 1 tokens) and prints
//! the mint and source for `scope pay`.

use core::num::NonZeroI8;
use scope_client::{address::token_2022, pay::SourceKeys, tx::v1_transaction};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::{Keypair, read_keypair_file};
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_zk_sdk::{
    encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use spl_token_2022_interface::{
    extension::{ExtensionType, confidential_transfer::instruction as ct},
    instruction as t22,
    state::{Account, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use std::{error::Error, fmt::Write};

type Res<T> = Result<T, Box<dyn Error>>;

const DECIMALS: u8 = 6;
const SOURCE_FUNDS: u64 = 1_000 * 1_000_000;

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

    /// A configured, empty confidential account for `owner` at a fresh address.
    fn confidential_account(
        &self,
        mint: &Address,
        owner: &Keypair,
        keys: impl FnOnce(&Address) -> Res<(ElGamalKeypair, AeKey)>,
    ) -> Res<Address> {
        let account = Keypair::new();
        let (elgamal, ae) = keys(&account.pubkey())?;
        let t22 = token_2022();
        let space = ExtensionType::try_calculate_account_len::<Account>(&[
            ExtensionType::ConfidentialTransferAccount,
        ])?;
        let proof = build_pubkey_validity_proof_data(&elgamal)?;
        let mut ixs = vec![
            solana_system_interface::instruction::create_account(
                &self.payer.pubkey(),
                &account.pubkey(),
                self.rpc.get_minimum_balance_for_rent_exemption(space)?,
                space as u64,
                &t22,
            ),
            t22::initialize_account3(&t22, &account.pubkey(), mint, &owner.pubkey())?,
        ];
        ixs.extend(ct::configure_account(
            &t22,
            &account.pubkey(),
            mint,
            &ae.encrypt(0).into(),
            65_536,
            &owner.pubkey(),
            &[],
            ProofLocation::InstructionOffset(NonZeroI8::new(1).expect("nonzero"), &proof),
        )?);
        if owner.pubkey() == self.payer.pubkey() {
            self.send(&ixs, &[&account])?;
        } else {
            self.send(&ixs, &[&account, owner])?;
        }
        Ok(account.pubkey())
    }
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [url, keypair, n, out] = args.as_slice() else {
        return Err("usage: p2_fixture RPC_URL KEYPAIR N INPUT_CSV".into());
    };
    let n: usize = n.parse()?;
    let c = Cluster {
        rpc: RpcClient::new(url.clone()),
        payer: read_keypair_file(keypair)?,
    };
    let owner = c.payer.insecure_clone();
    let mint = c.create_mint()?;
    let source = c.confidential_account(&mint, &owner, |address| {
        let k = SourceKeys::from_signer(&owner, address)?;
        Ok((k.elgamal, k.ae))
    })?;
    let keys = SourceKeys::from_signer(&owner, &source)?;
    let t22 = token_2022();
    let payer = owner.pubkey();
    c.send(
        &[
            t22::mint_to(&t22, &mint, &source, &payer, &[], SOURCE_FUNDS)?,
            ct::deposit(&t22, &source, &mint, SOURCE_FUNDS, DECIMALS, &payer, &[])?,
            ct::apply_pending_balance(
                &t22,
                &source,
                1,
                &keys.ae.encrypt(SOURCE_FUNDS).into(),
                &payer,
                &[],
            )?,
        ],
        &[],
    )?;
    let mut csv = String::from("recipient,amount\n");
    for i in 0..n {
        let recipient = c.confidential_account(&mint, &Keypair::new(), |_| {
            Ok((ElGamalKeypair::new_rand(), AeKey::new_rand()))
        })?;
        writeln!(csv, "{recipient},{}", i + 1)?;
    }
    std::fs::write(out, csv)?;
    println!("mint {mint}\nsource {source}\ninput {out}");
    Ok(())
}
