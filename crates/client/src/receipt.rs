//! Disclosure receipts (docs/client.md, Audit). A receipt names one finalized payment
//! transaction and proves the amount it moved, checked against that transaction's own
//! inline ciphertext-validity proof, which Token-2022 verified when it landed.
//!
//! - `Opening`: the payer's, for any row. The two Pedersen openings of the amount, which
//!   the payer re-derives from its run secret, open the transfer's amount commitments.
//! - `AccountKey`: a stealth payment's `ct_ikm`. It derives the one-time account's
//!   ElGamal key, which must be the transfer's destination key, and decrypts the amount.
//!   It grants read access to that one account, nothing else (docs/crypto.md).

use crate::{
    address::{program_id, token_2022, token_account_address},
    chain::ChainError,
    confidential,
    journal::{hex, unhex},
};
use scope_interface::instruction::{AnnounceData, ScopeInstruction};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_zk_elgamal_proof_interface::{
    instruction::ProofInstruction,
    proof_data::{
        BatchedGroupedCiphertext3HandlesValidityProofContext,
        BatchedGroupedCiphertext3HandlesValidityProofData,
    },
};
use solana_zk_sdk::encryption::{
    elgamal::ElGamalPubkey,
    grouped_elgamal::GroupedElGamalCiphertext,
    pedersen::{Pedersen, PedersenOpening},
};
use spl_token_2022_interface::{
    extension::confidential_transfer::instruction::{
        ConfidentialTransferInstruction, TransferInstructionData,
    },
    instruction::decode_instruction_data,
};
use stealth_keygen::{ConfidentialKeyMaterial, PaymentAnnouncement, RecipientSecretKeys};

pub const RECEIPT_VERSION: u8 = 1;

/// Token-2022's instruction tag for the confidential transfer extension
/// (spl-token-2022-interface 3.1.1, `src/instruction.rs` 1116).
const CONFIDENTIAL_TRANSFER_EXTENSION: u8 = 27;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Receipt {
    Opening {
        version: u8,
        /// Genesis hash of the cluster, hex.
        cluster: String,
        signature: String,
        amount: u64,
        /// Pedersen openings of the amount's low 16 and high 32 bits, hex.
        opening_lo: String,
        opening_hi: String,
    },
    AccountKey {
        version: u8,
        cluster: String,
        signature: String,
        /// The one-time account's confidential key material, hex.
        ct_ikm: String,
    },
}

/// Leaves out the openings and `ct_ikm`, so logs and panics do not carry them.
impl core::fmt::Debug for Receipt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Receipt::Opening {
                version,
                cluster,
                signature,
                amount,
                ..
            } => f
                .debug_struct("Opening")
                .field("version", version)
                .field("cluster", cluster)
                .field("signature", signature)
                .field("amount", amount)
                .finish_non_exhaustive(),
            Receipt::AccountKey {
                version,
                cluster,
                signature,
                ..
            } => f
                .debug_struct("AccountKey")
                .field("version", version)
                .field("cluster", cluster)
                .field("signature", signature)
                .finish_non_exhaustive(),
        }
    }
}

/// A payment transaction as an archival node returns it.
pub struct ArchivedTransaction {
    pub transaction: VersionedTransaction,
    pub succeeded: bool,
}

/// Finalized transactions by signature, from a node that keeps history.
pub trait TransactionArchive {
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError>;
    fn transaction(&self, signature: &Signature) -> Result<ArchivedTransaction, ChainError>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct Verified {
    pub signature: String,
    /// The transaction's fee payer, which signs every payer transaction.
    pub payer: Address,
    pub source: Address,
    pub destination: Address,
    pub mint: Address,
    pub amount: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error("receipt version {0} is not supported")]
    Version(u8),
    #[error("receipt field {0} is malformed")]
    Field(&'static str),
    #[error("the receipt is for another cluster")]
    Cluster,
    #[error("the transaction failed on chain")]
    Failed,
    #[error("the node returned a transaction that this signature does not sign")]
    Unauthenticated,
    #[error("the transaction holds no confidential transfer with an inline validity proof")]
    NoTransfer,
    #[error("the transaction holds no announcement for this recipient")]
    NotOurs,
    #[error("the openings do not open the transfer's amount commitments")]
    Opening,
    #[error("the key material does not match the transfer's destination key")]
    Key,
    #[error("the amount does not decrypt")]
    Decrypt,
}

/// The first confidential Transfer in `tx` and its validity proof's context; a payer
/// transaction holds exactly one.
struct Transfer {
    source: Address,
    mint: Address,
    destination: Address,
    context: BatchedGroupedCiphertext3HandlesValidityProofContext,
}

fn find_transfer(tx: &VersionedTransaction) -> Result<Transfer, ReceiptError> {
    let keys = tx.message.static_account_keys();
    let instructions = tx.message.instructions();
    let program = |index: u8| keys.get(usize::from(index));
    for (i, ix) in instructions.iter().enumerate() {
        if program(ix.program_id_index) != Some(&token_2022())
            || ix.data.first() != Some(&CONFIDENTIAL_TRANSFER_EXTENSION)
            || ix.data.get(1) != Some(&(ConfidentialTransferInstruction::Transfer as u8))
        {
            continue;
        }
        let data = decode_instruction_data::<TransferInstructionData>(&ix.data[1..])
            .map_err(|_| ReceiptError::NoTransfer)?;
        let at = i64::try_from(i).map_err(|_| ReceiptError::NoTransfer)?
            + i64::from(data.ciphertext_validity_proof_instruction_offset);
        let proof = usize::try_from(at)
            .ok()
            .and_then(|at| instructions.get(at))
            .filter(|p| {
                program(p.program_id_index) == Some(&solana_zk_elgamal_proof_interface::id())
            })
            .filter(|p| {
                ProofInstruction::instruction_type(&p.data)
                    == Some(ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity)
            })
            .ok_or(ReceiptError::NoTransfer)?;
        let proof = ProofInstruction::proof_data::<
            BatchedGroupedCiphertext3HandlesValidityProofData,
            BatchedGroupedCiphertext3HandlesValidityProofContext,
        >(&proof.data)
        .ok_or(ReceiptError::NoTransfer)?;
        let account = |n: usize| {
            ix.accounts
                .get(n)
                .and_then(|k| keys.get(usize::from(*k)))
                .copied()
                .ok_or(ReceiptError::NoTransfer)
        };
        return Ok(Transfer {
            source: account(0)?,
            mint: account(1)?,
            destination: account(2)?,
            context: proof.context,
        });
    }
    Err(ReceiptError::NoTransfer)
}

/// The successful transaction `signature` names. It must be signed by that signature and
/// all its others, so the node can misreport only whether it landed, not what it holds.
fn fetch<A: TransactionArchive>(
    archive: &A,
    signature: &Signature,
) -> Result<VersionedTransaction, ReceiptError> {
    let ArchivedTransaction {
        transaction,
        succeeded,
    } = archive.transaction(signature)?;
    let required = usize::from(transaction.message.header().num_required_signatures);
    if transaction.signatures.first() != Some(signature)
        || transaction.signatures.len() != required
        || !transaction.verify_with_results().into_iter().all(|ok| ok)
    {
        return Err(ReceiptError::Unauthenticated);
    }
    if !succeeded {
        return Err(ReceiptError::Failed);
    }
    Ok(transaction)
}

fn grouped<P: TryInto<GroupedElGamalCiphertext<3>>>(
    pod: P,
) -> Result<GroupedElGamalCiphertext<3>, ReceiptError> {
    pod.try_into().map_err(|_| ReceiptError::NoTransfer)
}

fn field<const N: usize>(value: &str, name: &'static str) -> Result<[u8; N], ReceiptError> {
    unhex(value)
        .and_then(|b| b.try_into().ok())
        .ok_or(ReceiptError::Field(name))
}

/// Checks `receipt` against the finalized transaction it names, on `archive`'s cluster.
pub fn verify<A: TransactionArchive>(
    archive: &A,
    receipt: &Receipt,
) -> Result<Verified, ReceiptError> {
    let (version, cluster, signature) = match receipt {
        Receipt::Opening {
            version,
            cluster,
            signature,
            ..
        }
        | Receipt::AccountKey {
            version,
            cluster,
            signature,
            ..
        } => (*version, cluster, signature),
    };
    if version != RECEIPT_VERSION {
        return Err(ReceiptError::Version(version));
    }
    if field::<32>(cluster, "cluster")? != archive.genesis_hash()? {
        return Err(ReceiptError::Cluster);
    }
    let sig: Signature = signature
        .parse()
        .map_err(|_| ReceiptError::Field("signature"))?;
    let transaction = fetch(archive, &sig)?;
    let transfer = find_transfer(&transaction)?;
    let (lo, hi) = (
        grouped(transfer.context.grouped_ciphertext_lo)?,
        grouped(transfer.context.grouped_ciphertext_hi)?,
    );
    let amount = match receipt {
        Receipt::Opening {
            amount,
            opening_lo,
            opening_hi,
            ..
        } => {
            let opening = |value: &str, name| {
                PedersenOpening::from_bytes(&field::<32>(value, name)?)
                    .ok_or(ReceiptError::Field(name))
            };
            let (a_lo, a_hi) = (amount & 0xffff, amount >> 16);
            if a_hi >> 32 != 0
                || Pedersen::with(a_lo, &opening(opening_lo, "opening_lo")?).to_bytes()
                    != lo.commitment.to_bytes()
                || Pedersen::with(a_hi, &opening(opening_hi, "opening_hi")?).to_bytes()
                    != hi.commitment.to_bytes()
            {
                return Err(ReceiptError::Opening);
            }
            *amount
        }
        Receipt::AccountKey { ct_ikm, .. } => {
            let material = ConfidentialKeyMaterial::from_bytes(field::<32>(ct_ikm, "ct_ikm")?);
            let (keys, _) =
                confidential::derive_confidential_keys(&material).map_err(|_| ReceiptError::Key)?;
            let destination_key: ElGamalPubkey = transfer
                .context
                .second_pubkey
                .try_into()
                .map_err(|_| ReceiptError::NoTransfer)?;
            if *keys.pubkey() != destination_key {
                return Err(ReceiptError::Key);
            }
            let part = |g: &GroupedElGamalCiphertext<3>| {
                let ciphertext = g
                    .to_elgamal_ciphertext(1)
                    .map_err(|_| ReceiptError::Decrypt)?;
                keys.secret()
                    .decrypt_u32(&ciphertext)
                    .ok_or(ReceiptError::Decrypt)
            };
            part(&lo)? + (part(&hi)? << 16)
        }
    };
    Ok(Verified {
        signature: signature.clone(),
        payer: *transaction
            .message
            .static_account_keys()
            .first()
            .ok_or(ReceiptError::NoTransfer)?,
        source: transfer.source,
        destination: transfer.destination,
        mint: transfer.mint,
        amount,
    })
}

/// The recipient's receipt for a stealth payment, from the payment transaction alone:
/// R and the view tag are in its `announce` data, the mint and one-time account in its
/// transfer.
pub fn disclose_as_recipient<A: TransactionArchive>(
    archive: &A,
    recipient: &RecipientSecretKeys,
    signature: &Signature,
) -> Result<Receipt, ReceiptError> {
    let tx = &fetch(archive, signature)?;
    let keys = tx.message.static_account_keys();
    let payer = *keys.first().ok_or(ReceiptError::NotOurs)?;
    let transfer = find_transfer(tx)?;
    let genesis = archive.genesis_hash()?;
    for ix in tx.message.instructions() {
        if keys.get(usize::from(ix.program_id_index)) != Some(&program_id()) {
            continue;
        }
        let Some((&tag, rest)) = ix.data.split_first() else {
            continue;
        };
        if ScopeInstruction::try_from(tag) != Ok(ScopeInstruction::Announce) {
            continue;
        }
        let Ok(data) = AnnounceData::from_bytes(rest) else {
            continue;
        };
        if token_account_address(&payer, &data.ephemeral) != transfer.destination {
            continue;
        }
        let note = PaymentAnnouncement {
            ephemeral_public_key: data.ephemeral,
            discovery_tag: data.view_tag,
        };
        let Ok(Some(payment)) = stealth_keygen::recover_payment(recipient, &note) else {
            return Err(ReceiptError::NotOurs);
        };
        let material = payment
            .derive_ct_ikm(&confidential::context(
                genesis,
                &transfer.mint,
                &transfer.destination,
            ))
            .map_err(|_| ReceiptError::Key)?;
        // A 1-in-256 view-tag match is not a payment to us; the derived key decides.
        let (keys, _) =
            confidential::derive_confidential_keys(&material).map_err(|_| ReceiptError::Key)?;
        let destination_key: ElGamalPubkey = transfer
            .context
            .second_pubkey
            .try_into()
            .map_err(|_| ReceiptError::NoTransfer)?;
        if *keys.pubkey() != destination_key {
            return Err(ReceiptError::NotOurs);
        }
        return Ok(Receipt::AccountKey {
            version: RECEIPT_VERSION,
            cluster: hex(&genesis),
            signature: signature.to_string(),
            ct_ikm: hex(material.as_bytes()),
        });
    }
    Err(ReceiptError::NotOurs)
}
