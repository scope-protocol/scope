//! Whole-balance recipient transfers, simulated before sending and safe to retry.

use crate::{
    address::token_2022,
    chain::{ChainError, Commitment, RecipientChain},
    fees, ix,
    scan::{self, OwnedPayment, ScanError},
    signer::PaymentSigner,
    tx::{COMPUTE_UNIT_LIMIT, signed_v1_transaction, v1_wire_size},
};
use core::num::NonZeroI8;
use curve25519_dalek::scalar::Scalar;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_zk_sdk::{
    encryption::{
        derivation::derive_confidential_keys,
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    zk_elgamal_proof_program::{
        build_pubkey_validity_proof_data, zero_ciphertext::build_zero_ciphertext_proof_data,
    },
};
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        confidential_transfer::{
            ConfidentialTransferAccount, ConfidentialTransferMint, instruction as ct,
        },
    },
    instruction as t22,
    state::{Account, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;
use std::{
    fmt,
    time::{Duration, Instant},
};
use stealth_keygen::RecipientSecretKeys;

const DESTINATION_SEED: &str = "scope-sweep/v1";

pub struct SweepOptions {
    pub max_price_per_cu: u64,
    pub poll: Duration,
    pub timeout: Duration,
    pub dry_run: bool,
}

impl Default for SweepOptions {
    fn default() -> Self {
        Self {
            max_price_per_cu: 1_000_000,
            poll: Duration::from_secs(2),
            timeout: Duration::from_secs(120),
            dry_run: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SweepReport {
    pub destination: Address,
    pub destination_owner: Address,
    pub payment_authority: Address,
    pub retained_lamports: u64,
    pub ephemeral: [u8; 32],
    pub amount: u64,
    pub burned_public_amount: u64,
    pub signature: String,
    pub reclaimed: bool,
    pub dry_run: bool,
}

impl fmt::Display for SweepReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "destination\t{}\nowner\t{}\npayment_authority\t{}\nephemeral\t{}\nattempt_signature\t{}",
            self.destination,
            self.destination_owner,
            self.payment_authority,
            Address::new_from_array(self.ephemeral),
            self.signature
        )
    }
}

#[derive(Debug)]
pub struct PreparedSweep {
    report: SweepReport,
    transaction: VersionedTransaction,
    announcement: Address,
    source: Address,
    mint: Address,
    elgamal: ElGamalPubkey,
    valid_until: u64,
}

impl PreparedSweep {
    pub fn report(&self) -> &SweepReport {
        &self.report
    }
    pub fn transaction(&self) -> &VersionedTransaction {
        &self.transaction
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error("{0}")]
    Invalid(String),
    #[error("payment authority holds {have} lamports, needs {need}; short by {short}")]
    Underfunded { have: u64, need: u64, short: u64 },
    #[error("simulation failed, nothing sent: {0}")]
    Simulation(String),
    #[error("sweep has not finalized; check chain state before retrying\n{report}")]
    Pending { report: Box<SweepReport> },
    #[error("sweep status is unavailable: {source}\n{report}")]
    Interrupted {
        report: Box<SweepReport>,
        #[source]
        source: Box<SweepError>,
    },
}

fn invalid(e: impl core::fmt::Display) -> SweepError {
    SweepError::Invalid(e.to_string())
}
fn offset(n: i8) -> NonZeroI8 {
    NonZeroI8::new(n).expect("nonzero proof offset")
}

pub fn destination_address(owner: &Address) -> Address {
    Address::create_with_seed(owner, DESTINATION_SEED, &token_2022())
        .expect("fixed seed and token program")
}

struct Destination {
    owner: Keypair,
    address: Address,
    keys: ElGamalKeypair,
    rent: u64,
    setup: Vec<Instruction>,
    auditor: Option<ElGamalPubkey>,
}

fn destination<C: RecipientChain>(
    chain: &C,
    recipient: &RecipientSecretKeys,
    payment: &OwnedPayment,
    authority: &Address,
) -> Result<Destination, SweepError> {
    let seed = recipient
        .derive_sweep_destination(&payment.info.ephemeral)
        .map_err(|e| invalid(format!("sweep key derivation: {e:?}")))?;
    let owner = Keypair::new_from_array(*seed.as_bytes());
    let (keys, ae) = derive_confidential_keys(&owner, b"").map_err(invalid)?;
    let address = destination_address(&owner.pubkey());
    let mint_account = chain
        .account(&payment.info.mint, Commitment::Confirmed)?
        .ok_or_else(|| invalid("mint not found"))?;
    if mint_account.owner != token_2022() {
        return Err(invalid("mint is not owned by Token-2022"));
    }
    let mint = StateWithExtensions::<Mint>::unpack(&mint_account.data).map_err(invalid)?;
    let types = mint.get_extension_types().map_err(invalid)?;
    for refused in [
        ExtensionType::NonTransferable,
        ExtensionType::TransferFeeConfig,
        ExtensionType::TransferHook,
    ] {
        if types.contains(&refused) {
            return Err(invalid(format!(
                "mint extension {refused:?} is not supported"
            )));
        }
    }
    let confidential = mint
        .get_extension::<ConfidentialTransferMint>()
        .map_err(invalid)?;
    if !bool::from(confidential.auto_approve_new_accounts) || mint.get_extension::<spl_token_2022_interface::extension::default_account_state::DefaultAccountState>().is_ok_and(|s| s.state == spl_token_2022_interface::state::AccountState::Frozen as u8) {
        return Err(invalid(
            "mint requires approval or freezes new destinations by default",
        ));
    }
    let auditor = confidential
        .auditor_elgamal_pubkey
        .get()
        .map(|p| ElGamalPubkey::try_from(p.0.as_slice()))
        .transpose()
        .map_err(invalid)?;
    let space =
        spl_token_2022_interface::extension::account_len::try_calculate_account_len_from_mint_data(
            &mint_account.data,
            &[ExtensionType::ConfidentialTransferAccount],
        )
        .map_err(invalid)?;
    let rent = chain.rent(space)?;
    let prefund = chain.account(&address, Commitment::Confirmed)?;
    if prefund
        .as_ref()
        .is_some_and(|a| a.owner != Address::default() || !a.data.is_empty())
    {
        return Err(invalid(
            "sweep destination already exists; refusing destination reuse",
        ));
    }
    let cost = rent.saturating_sub(prefund.as_ref().map_or(0, |a| a.lamports));
    let t22 = token_2022();
    let mut setup = if prefund.is_some() {
        let mut ixs = Vec::new();
        if cost > 0 {
            ixs.push(solana_system_interface::instruction::transfer(
                authority, &address, cost,
            ));
        }
        ixs.push(solana_system_interface::instruction::allocate_with_seed(
            &address,
            &owner.pubkey(),
            DESTINATION_SEED,
            space as u64,
            &t22,
        ));
        ixs.push(solana_system_interface::instruction::assign_with_seed(
            &address,
            &owner.pubkey(),
            DESTINATION_SEED,
            &t22,
        ));
        ixs
    } else {
        vec![
            solana_system_interface::instruction::create_account_with_seed(
                authority,
                &address,
                &owner.pubkey(),
                DESTINATION_SEED,
                rent,
                space as u64,
                &t22,
            ),
        ]
    };
    setup.push(
        t22::initialize_account3(&t22, &address, &payment.info.mint, &owner.pubkey())
            .map_err(invalid)?,
    );
    let proof = build_pubkey_validity_proof_data(&keys).map_err(invalid)?;
    setup.extend(
        ct::configure_account(
            &t22,
            &address,
            &payment.info.mint,
            &ae.encrypt(0).into(),
            65_536,
            &owner.pubkey(),
            &[],
            ProofLocation::InstructionOffset(offset(1), &proof),
        )
        .map_err(invalid)?,
    );
    setup.push(
        ct::disable_non_confidential_credits(&t22, &address, &owner.pubkey(), &[])
            .map_err(invalid)?,
    );
    Ok(Destination {
        owner,
        address,
        keys,
        rent: cost,
        setup,
        auditor,
    })
}

fn instructions(
    payment: &OwnedPayment,
    destination: &Destination,
    authority: &Address,
) -> Result<Vec<Instruction>, SweepError> {
    let ext = &payment.extension;
    let available: ElGamalCiphertext = ext.available_balance.try_into().map_err(invalid)?;
    let lo: ElGamalCiphertext = ext.pending_balance_lo.try_into().map_err(invalid)?;
    let hi: ElGamalCiphertext = ext.pending_balance_hi.try_into().map_err(invalid)?;
    let applied = available + lo + hi * Scalar::from(1u64 << 16);
    let hint = payment.ae.encrypt(payment.info.amount);
    let proofs = transfer_split_proof_data(
        &applied,
        &hint,
        payment.info.amount,
        &payment.elgamal,
        &payment.ae,
        destination.keys.pubkey(),
        destination.auditor.as_ref(),
    )
    .map_err(invalid)?;
    let post: ElGamalCiphertext = proofs
        .equality_proof_data
        .context
        .ciphertext
        .try_into()
        .map_err(invalid)?;
    let zero = build_zero_ciphertext_proof_data(&payment.elgamal, &post).map_err(invalid)?;
    let t22 = token_2022();
    let mut ixs = destination.setup.clone();
    ixs.push(
        ct::apply_pending_balance(
            &t22,
            &payment.info.token_account,
            u64::from(ext.pending_balance_credit_counter),
            &hint.into(),
            authority,
            &[],
        )
        .map_err(invalid)?,
    );
    ixs.extend(
        ct::transfer(
            &t22,
            &payment.info.token_account,
            &payment.info.mint,
            &destination.address,
            &payment.ae.encrypt(0).into(),
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_lo,
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_hi,
            authority,
            &[],
            ProofLocation::InstructionOffset(offset(1), &proofs.equality_proof_data),
            ProofLocation::InstructionOffset(
                offset(2),
                &proofs
                    .ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
            ),
            ProofLocation::InstructionOffset(offset(3), &proofs.range_proof_data),
        )
        .map_err(invalid)?,
    );
    ixs.extend(
        ct::empty_account(
            &t22,
            &payment.info.token_account,
            authority,
            &[],
            ProofLocation::InstructionOffset(offset(1), &zero),
        )
        .map_err(invalid)?,
    );
    if payment.info.public_amount > 0 {
        ixs.push(
            t22::burn(
                &t22,
                &payment.info.token_account,
                &payment.info.mint,
                authority,
                &[],
                payment.info.public_amount,
            )
            .map_err(invalid)?,
        );
    }
    Ok(ixs)
}

/// Sweep to a fresh deterministic destination, optionally simulating without sending.
pub fn sweep<C: RecipientChain>(
    chain: &mut C,
    recipient: &RecipientSecretKeys,
    announcement: &Address,
    opts: &SweepOptions,
) -> Result<SweepReport, SweepError> {
    let prepared = prepare(chain, recipient, announcement, opts)?;
    submit(chain, prepared, opts)
}

pub fn prepare<C: RecipientChain>(
    chain: &C,
    recipient: &RecipientSecretKeys,
    announcement: &Address,
    opts: &SweepOptions,
) -> Result<PreparedSweep, SweepError> {
    let account = chain
        .account(announcement, Commitment::Confirmed)?
        .ok_or_else(|| invalid("announcement not found; it may already have been reclaimed"))?;
    let payment = scan::inspect(
        chain,
        recipient,
        chain.genesis_hash()?,
        *announcement,
        &account,
        None,
    )?
    .ok_or_else(|| invalid("announcement is not an authenticated payment for this recipient"))?;
    if payment.info.amount == 0 {
        return Err(invalid("payment has no confidential balance to sweep"));
    }
    let signer = PaymentSigner::new(&payment.payment);
    let destination = destination(chain, recipient, &payment, &signer.pubkey())?;
    let base = instructions(&payment, &destination, &signer.pubkey())?;
    let mut prices = chain.recent_prices()?;
    prices.sort_unstable();
    let price = if prices.is_empty() {
        0
    } else {
        fees::percentile(&prices, 75)
    };
    if price > opts.max_price_per_cu {
        return Err(invalid(format!(
            "priority price {price} is above the cap {}",
            opts.max_price_per_cu
        )));
    }
    let priority = fees::priority_fee_lamports(price, COMPUTE_UNIT_LIMIT);
    let (blockhash, valid_until) = chain.blockhash()?;
    let balance = chain
        .account(&signer.pubkey(), Commitment::Confirmed)?
        .ok_or_else(|| invalid("payment authority is not funded"))?;
    if balance.owner != Address::default() || !balance.data.is_empty() {
        return Err(invalid("payment authority is not an empty system account"));
    }
    let minimum = chain.rent(0)?;
    let owner_account = chain.account(&destination.owner.pubkey(), Commitment::Confirmed)?;
    let owner_balance = owner_account.as_ref().map_or(0, |a| a.lamports);
    let owner_rent = match &owner_account {
        Some(a) if !a.data.is_empty() => chain.rent(a.data.len())?,
        _ => minimum,
    };
    let build = |reclaim: bool| -> Result<(VersionedTransaction, u64), SweepError> {
        let mut ixs = base.clone();
        if reclaim {
            ixs.push(ix::reclaim(
                announcement,
                &payment.info.token_account,
                &payment.info.payer,
            ));
        }
        ixs.push(solana_system_interface::instruction::transfer(
            &signer.pubkey(),
            &destination.owner.pubkey(),
            1,
        ));
        let provisional = signed_v1_transaction(
            &signer,
            &[&destination.owner],
            &ixs,
            blockhash,
            Some(priority),
        )
        .map_err(invalid)?;
        let fee = chain.fee(&provisional.message)?;
        let cost = fee
            .checked_add(destination.rent)
            .ok_or_else(|| invalid("fee and rent overflow"))?;
        let need = cost
            .checked_add(minimum)
            .ok_or_else(|| invalid("funding floor overflow"))?;
        let remainder = balance
            .lamports
            .checked_sub(need)
            .ok_or(SweepError::Underfunded {
                have: balance.lamports,
                need,
                short: need.saturating_sub(balance.lamports),
            })?;
        let transfer = if remainder >= owner_rent.saturating_sub(owner_balance) {
            remainder
        } else {
            0
        };
        ixs.pop();
        if transfer > 0 {
            ixs.push(solana_system_interface::instruction::transfer(
                &signer.pubkey(),
                &destination.owner.pubkey(),
                transfer,
            ));
        }
        let tx = signed_v1_transaction(
            &signer,
            &[&destination.owner],
            &ixs,
            blockhash,
            Some(priority),
        )
        .map_err(invalid)?;
        if v1_wire_size(&tx) > 4096 {
            return Err(invalid("sweep exceeds the v1 transaction size limit"));
        }
        Ok((tx, balance.lamports - cost - transfer))
    };
    let full = build(true)?;
    let (tx, retained_lamports, reclaimed) = match chain.simulate(&full.0)? {
        Ok(()) => (full.0, full.1, true),
        Err(full_logs) => {
            let fallback = build(false)?;
            match chain.simulate(&fallback.0)? {
                Ok(()) => (fallback.0, fallback.1, false),
                Err(_) => return Err(SweepError::Simulation(full_logs)),
            }
        }
    };
    let report = SweepReport {
        destination: destination.address,
        destination_owner: destination.owner.pubkey(),
        payment_authority: signer.pubkey(),
        retained_lamports,
        ephemeral: payment.info.ephemeral,
        amount: payment.info.amount,
        burned_public_amount: payment.info.public_amount,
        signature: tx.signatures[0].to_string(),
        reclaimed,
        dry_run: opts.dry_run,
    };
    Ok(PreparedSweep {
        report,
        transaction: tx,
        announcement: *announcement,
        source: payment.info.token_account,
        mint: payment.info.mint,
        elgamal: *destination.keys.pubkey(),
        valid_until,
    })
}

fn completed<C: RecipientChain>(chain: &C, prepared: &PreparedSweep) -> Result<bool, SweepError> {
    let source = chain.account(&prepared.source, Commitment::Finalized)?;
    let empty = match source {
        None => true,
        Some(a) => {
            let state = StateWithExtensions::<Account>::unpack(&a.data).map_err(invalid)?;
            let ext = state
                .get_extension::<ConfidentialTransferAccount>()
                .map_err(invalid)?;
            ext.available_balance.0 == [0; 64]
                && ext.pending_balance_lo.0 == [0; 64]
                && ext.pending_balance_hi.0 == [0; 64]
        }
    };
    if !empty {
        return Ok(false);
    }
    let destination_ready = match chain
        .account(&prepared.report.destination, Commitment::Finalized)?
    {
        Some(account) if account.owner == token_2022() => {
            let state = StateWithExtensions::<Account>::unpack(&account.data).map_err(invalid)?;
            let ext = state
                .get_extension::<ConfidentialTransferAccount>()
                .map_err(invalid)?;
            state.base.owner == prepared.report.destination_owner
                && state.base.mint == prepared.mint
                && ext.elgamal_pubkey == prepared.elgamal.into()
        }
        _ => false,
    };
    Ok(destination_ready)
}

pub fn submit<C: RecipientChain>(
    chain: &mut C,
    mut prepared: PreparedSweep,
    opts: &SweepOptions,
) -> Result<SweepReport, SweepError> {
    if prepared.report.dry_run {
        return Ok(prepared.report);
    }
    let started = Instant::now();
    loop {
        let interrupted = |source| SweepError::Interrupted {
            report: Box::new(prepared.report.clone()),
            source: Box::new(source),
        };
        if completed(chain, &prepared).map_err(interrupted)? {
            let reclaimed = chain
                .account(&prepared.announcement, Commitment::Finalized)
                .map_err(|e| interrupted(e.into()))?
                .is_none();
            let retained_lamports = chain
                .account(&prepared.report.payment_authority, Commitment::Finalized)
                .map_err(|e| interrupted(e.into()))?
                .map_or(0, |a| a.lamports);
            prepared.report.reclaimed = reclaimed;
            prepared.report.retained_lamports = retained_lamports;
            return Ok(prepared.report);
        }
        if started.elapsed() >= opts.timeout
            || chain
                .finalized_block_height()
                .map_err(|e| interrupted(e.into()))?
                > prepared.valid_until
        {
            return Err(SweepError::Pending {
                report: Box::new(prepared.report),
            });
        }
        // Resend the identical signed transaction; destination creation prevents a second sweep.
        let _ = chain.send(&prepared.transaction);
        std::thread::sleep(opts.poll);
    }
}
