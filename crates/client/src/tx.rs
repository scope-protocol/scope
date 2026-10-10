use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{
    VersionedMessage,
    v1::{Message, TransactionConfig},
};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

/// Compute-unit limit per transaction shape, each about 15% above its LiteSVM measurement
/// with a mint auditor (`programs/scope/tests/it/budget.rs` and the sweep test in
/// `crates/client/tests/recipient.rs`). The priority fee is price times the limit, so
/// headroom is paid for.
pub const PLAIN_TRANSFER_CU_LIMIT: u32 = 275_000; // measured 237,792
pub const STEALTH_PAYMENT_CU_LIMIT: u32 = 295_000; // measured 254,576 at bump 255
pub const SWEEP_CU_LIMIT: u32 = 310_000; // measured 268,049 with dust burn and reclaim
pub const RECLAIM_CU_LIMIT: u32 = 3_800; // measured 3,260
/// For transactions outside those shapes, which pay no priority fee: setup, tests, spikes.
pub const DEFAULT_CU_LIMIT: u32 = 600_000;

/// Loaded account data limit. Mainnet Token-2022 programdata alone is 1,382,061
/// bytes; v1 defaults this to 0, which fails the transaction.
pub const LOADED_ACCOUNTS_DATA_SIZE_LIMIT: u32 = 4 * 1024 * 1024;

/// A legacy transaction for the small registry instructions, which need no v1 header.
pub fn legacy_transaction(
    fee_payer: &Keypair,
    ixs: &[Instruction],
    blockhash: solana_message::Hash,
) -> solana_transaction::Transaction {
    solana_transaction::Transaction::new_signed_with_payer(
        ixs,
        Some(&fee_payer.pubkey()),
        &[fee_payer],
        blockhash,
    )
}

pub fn v1_transaction(
    fee_payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    blockhash: solana_message::Hash,
) -> VersionedTransaction {
    build(
        fee_payer,
        extra_signers,
        ixs,
        blockhash,
        DEFAULT_CU_LIMIT,
        None,
    )
}

/// As [`v1_transaction`], with the shape's compute-unit limit and a total priority fee
/// in lamports in the header.
pub fn v1_transaction_with_fee(
    fee_payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    blockhash: solana_message::Hash,
    compute_unit_limit: u32,
    priority_fee_lamports: u64,
) -> VersionedTransaction {
    build(
        fee_payer,
        extra_signers,
        ixs,
        blockhash,
        compute_unit_limit,
        Some(priority_fee_lamports),
    )
}

fn build(
    fee_payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    blockhash: solana_message::Hash,
    compute_unit_limit: u32,
    priority_fee: Option<u64>,
) -> VersionedTransaction {
    let signers: Vec<&dyn Signer> = extra_signers.iter().map(|s| *s as &dyn Signer).collect();
    signed_v1_transaction(
        fee_payer,
        &signers,
        ixs,
        blockhash,
        compute_unit_limit,
        priority_fee,
    )
    .expect("instructions compile and all signers are present")
}

/// Build a v1 transaction with standard keypairs or a recovered payment signer.
pub fn signed_v1_transaction(
    fee_payer: &dyn Signer,
    extra_signers: &[&dyn Signer],
    ixs: &[Instruction],
    blockhash: solana_message::Hash,
    compute_unit_limit: u32,
    priority_fee: Option<u64>,
) -> Result<VersionedTransaction, String> {
    let mut config = TransactionConfig::empty()
        .with_compute_unit_limit(compute_unit_limit)
        .with_loaded_accounts_data_size_limit(LOADED_ACCOUNTS_DATA_SIZE_LIMIT);
    if let Some(fee) = priority_fee.filter(|f| *f > 0) {
        config = config.with_priority_fee(fee);
    }
    let message = Message::try_compile_with_config(
        &fee_payer.try_pubkey().map_err(|e| e.to_string())?,
        ixs,
        blockhash,
        config,
    )
    .map_err(|e| e.to_string())?;
    let mut signers: Vec<&dyn Signer> = vec![fee_payer];
    signers.extend_from_slice(extra_signers);
    VersionedTransaction::try_new(VersionedMessage::V1(message), &signers)
        .map_err(|e| e.to_string())
}

/// Serialized size of a v1 transaction: version byte, signatures, message.
/// Nothing below the cluster checks it against `MAX_TRANSACTION_SIZE`, LiteSVM included.
pub fn v1_wire_size(tx: &VersionedTransaction) -> usize {
    match &tx.message {
        VersionedMessage::V1(message) => 1 + 64 * tx.signatures.len() + message.size(),
        _ => panic!("not a v1 transaction"),
    }
}
