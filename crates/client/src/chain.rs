//! What the payer engine needs from a cluster. One trait, so the engine runs the same
//! against an RPC node and against LiteSVM (`testkit`), and tests can inject faults.

use crate::fees;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_message::Hash;
use solana_rpc_client::{
    api::config::{RpcBlockConfig, RpcSendTransactionConfig, RpcSimulateTransactionConfig},
    rpc_client::RpcClient,
};
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::{TransactionDetails, UiTransactionEncoding};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commitment {
    Confirmed,
    Finalized,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountData {
    pub owner: Address,
    pub lamports: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ChainError(pub String);

pub trait Chain {
    fn account(
        &self,
        address: &Address,
        commitment: Commitment,
    ) -> Result<Option<AccountData>, ChainError>;

    /// A recent blockhash and the last block height at which a transaction using it can land.
    fn blockhash(&self) -> Result<(Hash, u64), ChainError>;

    fn finalized_block_height(&self) -> Result<u64, ChainError>;

    /// `Ok(Err(logs))` when the transaction would fail.
    fn simulate(&self, tx: &VersionedTransaction) -> Result<Result<(), String>, ChainError>;

    /// Fire and forget: the engine learns the outcome from the source account, never from here.
    fn send(&mut self, tx: &VersionedTransaction) -> Result<(), ChainError>;

    /// Per-CU prices in micro-lamports paid by landed non-vote transactions in a recent block.
    fn recent_prices(&self) -> Result<Vec<u64>, ChainError>;
}

fn rpc_err<E: core::fmt::Display>(e: E) -> ChainError {
    ChainError(e.to_string())
}

fn config(c: Commitment) -> CommitmentConfig {
    match c {
        Commitment::Confirmed => CommitmentConfig::confirmed(),
        Commitment::Finalized => CommitmentConfig::finalized(),
    }
}

pub struct RpcChain(pub RpcClient);

impl Chain for RpcChain {
    fn account(
        &self,
        address: &Address,
        commitment: Commitment,
    ) -> Result<Option<AccountData>, ChainError> {
        let found = self
            .0
            .get_account_with_commitment(address, config(commitment))
            .map_err(rpc_err)?
            .value;
        Ok(found.map(|a| AccountData {
            owner: a.owner,
            lamports: a.lamports,
            data: a.data,
        }))
    }

    fn blockhash(&self) -> Result<(Hash, u64), ChainError> {
        self.0
            .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())
            .map_err(rpc_err)
    }

    fn finalized_block_height(&self) -> Result<u64, ChainError> {
        self.0
            .get_block_height_with_commitment(CommitmentConfig::finalized())
            .map_err(rpc_err)
    }

    fn simulate(&self, tx: &VersionedTransaction) -> Result<Result<(), String>, ChainError> {
        let result = self
            .0
            .simulate_transaction_with_config(
                tx,
                RpcSimulateTransactionConfig {
                    sig_verify: true,
                    commitment: Some(CommitmentConfig::confirmed()),
                    ..RpcSimulateTransactionConfig::default()
                },
            )
            .map_err(rpc_err)?
            .value;
        Ok(match result.err {
            None => Ok(()),
            Some(err) => Err(format!("{err:?}\n{:#?}", result.logs.unwrap_or_default())),
        })
    }

    fn send(&mut self, tx: &VersionedTransaction) -> Result<(), ChainError> {
        self.0
            .send_transaction_with_config(
                tx,
                RpcSendTransactionConfig {
                    skip_preflight: true,
                    max_retries: Some(0),
                    ..RpcSendTransactionConfig::default()
                },
            )
            .map(|_| ())
            .map_err(rpc_err)
    }

    fn recent_prices(&self) -> Result<Vec<u64>, ChainError> {
        let slot = self
            .0
            .get_slot_with_commitment(CommitmentConfig::confirmed())
            .map_err(rpc_err)?;
        let block = self
            .0
            .get_block_with_config(
                slot,
                RpcBlockConfig {
                    encoding: Some(UiTransactionEncoding::Base64),
                    transaction_details: Some(TransactionDetails::Full),
                    rewards: Some(false),
                    commitment: Some(CommitmentConfig::confirmed()),
                    max_supported_transaction_version: Some(1),
                },
            )
            .map_err(rpc_err)?;
        Ok(fees::block_prices(block.transactions.unwrap_or_default()))
    }
}
