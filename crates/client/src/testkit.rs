//! LiteSVM harness shared by the program and client tests.

use crate::{address::*, ix::*, tx::v1_transaction};
use litesvm::{LiteSVM, types::TransactionResult};
use scope_interface::ScopeError;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;
use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};
use spl_token_2022_interface::{
    extension::{ExtensionType, confidential_transfer::instruction as ct},
    instruction as t22,
    state::{Account, Mint},
};
use std::path::PathBuf;

/// The built program; panics with the build command when missing or older than its sources.
pub fn program_elf() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let so = root.join("target/deploy/scope_program.so");
    let built = std::fs::metadata(&so)
        .and_then(|m| m.modified())
        .unwrap_or_else(|_| {
            panic!(
                "missing {}: run `cargo build-sbf --manifest-path programs/scope/Cargo.toml`",
                so.display()
            )
        });
    for dir in ["programs/scope/src", "crates/interface/src"] {
        for entry in std::fs::read_dir(root.join(dir)).expect("source dir") {
            let modified = entry
                .expect("entry")
                .metadata()
                .and_then(|m| m.modified())
                .expect("mtime");
            assert!(
                modified <= built,
                "stale {}: run `cargo build-sbf --manifest-path programs/scope/Cargo.toml`",
                so.display()
            );
        }
    }
    so
}

pub struct Harness {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub mint: Address,
    pub mint_authority: Keypair,
    pub source: Address,
    pub source_elgamal: ElGamalKeypair,
    pub source_ae: AeKey,
    pub source_balance: u64,
}

/// One set-up-but-not-yet-sent stealth payment.
pub struct StealthCase {
    pub ephemeral: [u8; 32],
    pub k: u8,
    pub view_tag: u8,
    pub one_time_owner: Keypair,
    pub elgamal: ElGamalKeypair,
    pub ae: AeKey,
    pub token_account: Address,
    pub announcement: Address,
    pub setup: Vec<Instruction>,
}

const ONE_SOL: u64 = 1_000_000_000;
const DECIMALS: u8 = 6;
pub const SOURCE_FUNDS: u64 = 1_000_000_000;

impl Harness {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(program_id(), program_elf())
            .expect("load program");
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100 * ONE_SOL)
            .expect("airdrop");
        let mut h = Self {
            svm,
            payer,
            mint: Address::default(),
            mint_authority: Keypair::new(),
            source: Address::default(),
            source_elgamal: ElGamalKeypair::new_rand(),
            source_ae: AeKey::new_rand(),
            source_balance: 0,
        };
        h.create_mint();
        h.create_funded_source();
        h
    }

    // Returns litesvm's own result type so tests can match on its metadata.
    #[allow(clippy::result_large_err)]
    pub fn send(&mut self, ixs: &[Instruction], extra: &[&Keypair]) -> TransactionResult {
        let tx = v1_transaction(&self.payer, extra, ixs, self.svm.latest_blockhash());
        let result = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        result
    }

    fn create_mint(&mut self) {
        let mint = Keypair::new();
        let t22 = token_2022();
        let space = ExtensionType::try_calculate_account_len::<Mint>(&[
            ExtensionType::ConfidentialTransferMint,
        ])
        .expect("len");
        let ixs = [
            solana_system_interface::instruction::create_account(
                &self.payer.pubkey(),
                &mint.pubkey(),
                self.svm.minimum_balance_for_rent_exemption(space),
                space as u64,
                &t22,
            ),
            ct::initialize_mint(
                &t22,
                &mint.pubkey(),
                Some(self.mint_authority.pubkey()),
                true,
                None,
            )
            .expect("ct mint"),
            t22::initialize_mint2(
                &t22,
                &mint.pubkey(),
                &self.mint_authority.pubkey(),
                None,
                DECIMALS,
            )
            .expect("mint"),
        ];
        self.send(&ixs, &[&mint]).expect("create mint");
        self.mint = mint.pubkey();
    }

    /// Creates and configures an empty confidential account for `owner`; the payer funds it.
    pub fn plain_confidential_account(
        &mut self,
        owner: &Keypair,
        keys: &ElGamalKeypair,
        ae: &AeKey,
    ) -> Address {
        let account = Keypair::new();
        let t22 = token_2022();
        let space = ExtensionType::try_calculate_account_len::<Account>(&[
            ExtensionType::ConfidentialTransferAccount,
        ])
        .expect("len");
        let proof = solana_zk_sdk::zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data(keys).expect("proof");
        let mut ixs = vec![
            solana_system_interface::instruction::create_account(
                &self.payer.pubkey(),
                &account.pubkey(),
                self.svm.minimum_balance_for_rent_exemption(space),
                space as u64,
                &t22,
            ),
            t22::initialize_account3(&t22, &account.pubkey(), &self.mint, &owner.pubkey())
                .expect("init"),
        ];
        ixs.extend(ct::configure_account(
            &t22, &account.pubkey(), &self.mint, &ae.encrypt(0).into(), 65_536, &owner.pubkey(), &[],
            spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation::InstructionOffset(
                core::num::NonZeroI8::new(1).expect("nonzero"), &proof,
            ),
        ).expect("configure"));
        let owner = owner.insecure_clone();
        let signers: &[&Keypair] = if owner.pubkey() == self.payer.pubkey() {
            &[&account]
        } else {
            &[&account, &owner]
        };
        self.send(&ixs, signers)
            .expect("create confidential account");
        account.pubkey()
    }

    fn create_funded_source(&mut self) {
        let t22 = token_2022();
        let owner = self.payer.pubkey();
        let payer = self.payer.insecure_clone();
        let (keys, ae) = (self.source_elgamal.clone(), self.source_ae.clone());
        self.source = self.plain_confidential_account(&payer, &keys, &ae);

        let mint_to = t22::mint_to(
            &t22,
            &self.mint,
            &self.source,
            &self.mint_authority.pubkey(),
            &[],
            SOURCE_FUNDS,
        )
        .expect("mint_to");
        let authority = self.mint_authority.insecure_clone();
        self.send(&[mint_to], &[&authority])
            .expect("mint to source");
        let deposit = ct::deposit(
            &t22,
            &self.source,
            &self.mint,
            SOURCE_FUNDS,
            DECIMALS,
            &owner,
            &[],
        )
        .expect("deposit");
        let apply = ct::apply_pending_balance(
            &t22,
            &self.source,
            1,
            &self.source_ae.encrypt(SOURCE_FUNDS).into(),
            &owner,
            &[],
        )
        .expect("apply");
        self.send(&[deposit, apply], &[]).expect("shield");
        self.source_balance = SOURCE_FUNDS;
    }

    /// Builds the payer's setup instructions for a fresh stealth payment.
    pub fn stealth_case(&self, k: u8) -> StealthCase {
        let one_time_owner = Keypair::new();
        let elgamal = ElGamalKeypair::new_rand();
        let ae = AeKey::new_rand();
        let ephemeral: [u8; 32] = Keypair::new().pubkey().to_bytes();
        let view_tag = ephemeral[0];
        let payer = self.payer.pubkey();
        let token_account = token_account_address(&payer, &ephemeral, k);
        let (announcement, _) = announcement_address(&token_account);
        let space = ExtensionType::try_calculate_account_len::<Account>(&[
            ExtensionType::ConfidentialTransferAccount,
        ])
        .expect("len");
        let setup = stealth_setup(&StealthSetup {
            payer,
            mint: self.mint,
            ephemeral,
            k,
            view_tag,
            one_time_owner: one_time_owner.pubkey(),
            elgamal: &elgamal,
            ae: &ae,
            rent_lamports: self.svm.minimum_balance_for_rent_exemption(space),
            space: space as u64,
            lamports_for_owner: 5_000_000,
        })
        .expect("setup");
        StealthCase {
            ephemeral,
            k,
            view_tag,
            one_time_owner,
            elgamal,
            ae,
            token_account,
            announcement,
            setup,
        }
    }
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

/// Asserts a transaction failed with our custom error code.
pub fn assert_scope_error(result: TransactionResult, expected: ScopeError) {
    match result {
        Err(failed) => assert!(
            matches!(failed.err, TransactionError::InstructionError(_, InstructionError::Custom(c)) if c == expected.code()),
            "expected {expected:?}, got {:?}\nlogs: {:#?}",
            failed.err,
            failed.meta.logs
        ),
        Ok(_) => panic!("expected {expected:?}, transaction succeeded"),
    }
}
