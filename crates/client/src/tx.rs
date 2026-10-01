use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{
    VersionedMessage,
    v1::{Message, TransactionConfig},
};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

/// Compute budget for one stealth payment side: about 226k CU of proofs plus
/// Token-2022 work (docs/verification.md, V27). S5 replaces it
/// with a measured value plus 10%.
pub const COMPUTE_UNIT_LIMIT: u32 = 600_000;

/// Loaded account data limit. Mainnet Token-2022 programdata alone is 1,382,061
/// bytes; v1 defaults this to 0, which fails the transaction.
pub const LOADED_ACCOUNTS_DATA_SIZE_LIMIT: u32 = 4 * 1024 * 1024;

pub fn v1_transaction(
    fee_payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    blockhash: solana_message::Hash,
) -> VersionedTransaction {
    build(fee_payer, extra_signers, ixs, blockhash, None)
}

/// As [`v1_transaction`], with a total priority fee in lamports in the header.
pub fn v1_transaction_with_fee(
    fee_payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    blockhash: solana_message::Hash,
    priority_fee_lamports: u64,
) -> VersionedTransaction {
    build(
        fee_payer,
        extra_signers,
        ixs,
        blockhash,
        Some(priority_fee_lamports),
    )
}

fn build(
    fee_payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    blockhash: solana_message::Hash,
    priority_fee: Option<u64>,
) -> VersionedTransaction {
    let mut config = TransactionConfig::empty()
        .with_compute_unit_limit(COMPUTE_UNIT_LIMIT)
        .with_loaded_accounts_data_size_limit(LOADED_ACCOUNTS_DATA_SIZE_LIMIT);
    if let Some(fee) = priority_fee.filter(|f| *f > 0) {
        config = config.with_priority_fee(fee);
    }
    let message = Message::try_compile_with_config(&fee_payer.pubkey(), ixs, blockhash, config)
        .expect("instructions compile");
    let mut signers: Vec<&Keypair> = vec![fee_payer];
    signers.extend_from_slice(extra_signers);
    VersionedTransaction::try_new(VersionedMessage::V1(message), &signers)
        .expect("all signers present")
}

/// Serialized size of a v1 transaction: version byte, signatures, message.
/// Nothing below the cluster checks it against `MAX_TRANSACTION_SIZE`, LiteSVM included.
pub fn v1_wire_size(tx: &VersionedTransaction) -> usize {
    match &tx.message {
        VersionedMessage::V1(message) => 1 + 64 * tx.signatures.len() + message.size(),
        _ => panic!("not a v1 transaction"),
    }
}
