//! LiteSVM harness shared by the program and client tests.

use crate::{
    address::*,
    chain::{AccountData, Chain, ChainError, Commitment, FinalizedStatus, RecipientChain},
    ix::*,
    tx::v1_transaction,
};
use litesvm::{LiteSVM, types::TransactionResult};
use scope_interface::ScopeError;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Hash;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalKeypair, ElGamalPubkey},
};
use spl_token_2022_interface::{
    extension::{ExtensionType, confidential_transfer::instruction as ct},
    instruction as t22,
    state::{Account, Mint},
};
use std::cell::Cell;
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
        assert!(
            newest_mtime(&root.join(dir)) <= built,
            "stale {}: run `cargo build-sbf --manifest-path programs/scope/Cargo.toml`",
            so.display()
        );
    }
    so
}

/// Newest modification time of any file under `dir`, subdirectories included.
fn newest_mtime(dir: &std::path::Path) -> std::time::SystemTime {
    std::fs::read_dir(dir)
        .expect("source dir")
        .map(|entry| {
            let entry = entry.expect("entry");
            let meta = entry.metadata().expect("metadata");
            if meta.is_dir() {
                newest_mtime(&entry.path())
            } else {
                meta.modified().expect("mtime")
            }
        })
        .max()
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
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
        Self::with_auditor(None)
    }

    pub fn with_auditor(auditor: Option<&ElGamalPubkey>) -> Self {
        Self::with_mint_policy(auditor, false)
    }

    pub fn with_permissioned_burn() -> Self {
        Self::with_mint_policy(None, true)
    }

    fn with_mint_policy(auditor: Option<&ElGamalPubkey>, permissioned_burn: bool) -> Self {
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
        h.create_mint(auditor, permissioned_burn);
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

    fn create_mint(&mut self, auditor: Option<&ElGamalPubkey>, permissioned_burn: bool) {
        let mint = Keypair::new();
        let t22 = token_2022();
        let mut types = vec![ExtensionType::ConfidentialTransferMint];
        if permissioned_burn {
            types.push(ExtensionType::PermissionedBurn);
        }
        let space = ExtensionType::try_calculate_account_len::<Mint>(&types).expect("len");
        let mut ixs = vec![
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
                auditor.map(|a| (*a).into()),
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
        if permissioned_burn {
            ixs.insert(
                1,
                spl_token_2022_interface::extension::permissioned_burn::instruction::initialize(
                    &t22,
                    &mint.pubkey(),
                    &self.mint_authority.pubkey(),
                )
                .expect("permissioned burn"),
            );
        }
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
    pub fn stealth_case(&self) -> StealthCase {
        let one_time_owner = Keypair::new();
        let elgamal = ElGamalKeypair::new_rand();
        let ae = AeKey::new_rand();
        let ephemeral: [u8; 32] = Keypair::new().pubkey().to_bytes();
        let view_tag = ephemeral[0];
        let payer = self.payer.pubkey();
        let token_account = token_account_address(&payer, &ephemeral);
        let (announcement, _) = announcement_address(&token_account);
        let space = ExtensionType::try_calculate_account_len::<Account>(&[
            ExtensionType::ConfidentialTransferAccount,
        ])
        .expect("len");
        let setup = stealth_setup(&StealthSetup {
            payer,
            mint: self.mint,
            ephemeral,
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

pub type SendHook = Box<dyn FnMut(&mut LiteSVM, &VersionedTransaction)>;

/// [`Chain`] over LiteSVM. Every call to `finalized_block_height` advances the
/// height by `HEIGHT_STEP`, so a dropped transaction expires after a few polls.
pub struct SvmChain<'a> {
    pub svm: &'a mut LiteSVM,
    height: Cell<u64>,
    pub account_reads: Cell<usize>,
    /// Sends to swallow before executing any, to model lost transactions.
    pub drop_sends: usize,
    /// Model a source that has not appeared in finalized reads yet.
    pub finalized_missing_until_send: Option<Address>,
    pub fail_finalized_after_send: bool,
    pub lag_finalized_reads: bool,
    pub lag_finalized_status: bool,
    pub before_send: Option<VersionedTransaction>,
    pub before_send_hook: Option<SendHook>,
    pub after_send: Option<VersionedTransaction>,
    pub sent_signatures: Vec<solana_signature::Signature>,
    pub failed_status_lag: Cell<usize>,
    pub height_delay: std::time::Duration,
    /// What `recent_prices` returns; empty by default, as on an idle cluster.
    pub prices: Vec<u64>,
    sent: bool,
}

const HEIGHT_STEP: u64 = 40;
/// Blocks a blockhash stays valid for, as on a real cluster.
const BLOCKHASH_VALIDITY: u64 = 150;

impl<'a> SvmChain<'a> {
    pub fn new(svm: &'a mut LiteSVM) -> Self {
        Self {
            svm,
            height: Cell::new(0),
            account_reads: Cell::new(0),
            drop_sends: 0,
            finalized_missing_until_send: None,
            fail_finalized_after_send: false,
            lag_finalized_reads: false,
            lag_finalized_status: false,
            before_send: None,
            before_send_hook: None,
            after_send: None,
            sent_signatures: Vec::new(),
            failed_status_lag: Cell::new(0),
            height_delay: std::time::Duration::ZERO,
            prices: Vec::new(),
            sent: false,
        }
    }
}

impl Chain for SvmChain<'_> {
    fn account(
        &self,
        address: &Address,
        commitment: Commitment,
    ) -> Result<Option<AccountData>, ChainError> {
        self.account_reads.set(self.account_reads.get() + 1);
        if commitment == Commitment::Finalized {
            if self.fail_finalized_after_send && self.sent {
                return Err(ChainError("RPC disconnected after send".into()));
            }
            if self.lag_finalized_reads {
                return Ok(None);
            }
        }
        if commitment == Commitment::Finalized
            && self.finalized_missing_until_send == Some(*address)
        {
            return Ok(None);
        }
        Ok(self
            .svm
            .get_account(address)
            .filter(|a| a.lamports > 0)
            .map(|a| AccountData {
                owner: a.owner,
                lamports: a.lamports,
                data: a.data,
            }))
    }

    fn blockhash(&self) -> Result<(Hash, u64), ChainError> {
        Ok((
            self.svm.latest_blockhash(),
            self.height.get() + BLOCKHASH_VALIDITY,
        ))
    }

    fn finalized_block_height(&self) -> Result<u64, ChainError> {
        std::thread::sleep(self.height_delay);
        self.height.set(self.height.get() + HEIGHT_STEP);
        Ok(self.height.get())
    }

    fn simulate(&self, tx: &VersionedTransaction) -> Result<Result<(), String>, ChainError> {
        Ok(self
            .svm
            .simulate_transaction(tx.clone())
            .map(|_| ())
            .map_err(|failed| format!("{:?}\n{:#?}", failed.err, failed.meta.logs)))
    }

    fn send(&mut self, tx: &VersionedTransaction) -> Result<(), ChainError> {
        self.sent_signatures.push(tx.signatures[0]);
        if self.drop_sends > 0 {
            self.drop_sends -= 1;
            return Ok(());
        }
        if let Some(before) = self.before_send.take() {
            self.svm
                .send_transaction(before)
                .map_err(|failed| ChainError(format!("{:?}", failed.err)))?;
        }
        if let Some(hook) = &mut self.before_send_hook {
            hook(self.svm, tx);
        }
        let result = self.svm.send_transaction(tx.clone());
        if result.is_ok() {
            self.finalized_missing_until_send = None;
            self.sent = true;
            if let Some(after) = self.after_send.take() {
                self.svm
                    .send_transaction(after)
                    .map_err(|failed| ChainError(format!("{:?}", failed.err)))?;
            }
        }
        self.svm.expire_blockhash();
        result
            .map(|_| ())
            .map_err(|failed| ChainError(format!("{:?}", failed.err)))
    }

    fn recent_prices(&self) -> Result<Vec<u64>, ChainError> {
        Ok(self.prices.clone())
    }
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
        Ok([42; 32])
    }
    fn rent(&self, space: usize) -> Result<u64, ChainError> {
        Ok(self.svm.minimum_balance_for_rent_exemption(space))
    }
}

impl RecipientChain for SvmChain<'_> {
    fn set_deadline(&mut self, _deadline: Option<std::time::Instant>) {}

    fn finalized_status(
        &self,
        signature: &solana_signature::Signature,
    ) -> Result<FinalizedStatus, ChainError> {
        Ok(if self.lag_finalized_status {
            FinalizedStatus::Unknown
        } else {
            match self.svm.get_transaction(signature) {
                Some(Ok(_)) => FinalizedStatus::Succeeded,
                Some(Err(_)) if self.failed_status_lag.get() > 0 => {
                    self.failed_status_lag.set(self.failed_status_lag.get() - 1);
                    FinalizedStatus::Unknown
                }
                Some(Err(_)) => FinalizedStatus::Failed,
                None => FinalizedStatus::Unknown,
            }
        })
    }

    fn announcements(&self) -> Result<Vec<(Address, AccountData)>, ChainError> {
        Ok(self
            .svm
            .get_program_accounts(&program_id())
            .into_iter()
            .map(|(address, a)| {
                (
                    address,
                    AccountData {
                        owner: a.owner,
                        lamports: a.lamports,
                        data: a.data,
                    },
                )
            })
            .collect())
    }
    fn fee(&self, message: &solana_message::VersionedMessage) -> Result<u64, ChainError> {
        let priority = match message {
            solana_message::VersionedMessage::V1(m) => m.config.priority_fee.unwrap_or(0),
            _ => 0,
        };
        (u64::from(message.header().num_required_signatures) * crate::fees::LAMPORTS_PER_SIGNATURE)
            .checked_add(priority)
            .ok_or_else(|| ChainError("fee overflow".into()))
    }
}

/// Compute units our program consumed, one entry per invocation, from the runtime log.
pub fn program_compute_units(logs: &[String]) -> Vec<u64> {
    let prefix = format!("Program {} consumed ", program_id());
    logs.iter()
        .filter_map(|line| line.strip_prefix(&prefix))
        .filter_map(|rest| rest.split(' ').next()?.parse().ok())
        .collect()
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

#[cfg(test)]
mod elf_guard_tests {
    use super::newest_mtime;

    #[test]
    fn newest_mtime_walks_subdirectories() {
        let root = std::env::temp_dir().join(format!("scope-mtime-{}", std::process::id()));
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).expect("dirs");
        std::fs::write(root.join("top.rs"), "").expect("top");
        std::thread::sleep(std::time::Duration::from_millis(20));
        let deep = nested.join("deep.rs");
        std::fs::write(&deep, "").expect("deep");
        let deep_mtime = std::fs::metadata(&deep)
            .and_then(|m| m.modified())
            .expect("mtime");
        assert_eq!(newest_mtime(&root), deep_mtime);
        std::fs::remove_dir_all(&root).expect("cleanup");
    }
}

#[cfg(test)]
mod budget_tests {
    use super::program_compute_units;

    #[test]
    fn reads_only_our_program_lines() {
        let id = crate::address::program_id();
        let logs = vec![
            format!("Program {id} invoke [1]"),
            format!("Program {id} consumed 12345 of 600000 compute units"),
            "Program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb consumed 999 of 1 compute units"
                .into(),
        ];
        assert_eq!(program_compute_units(&logs), vec![12345]);
    }
}
