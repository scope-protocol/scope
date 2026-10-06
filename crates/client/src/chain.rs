//! What the payer engine needs from a cluster. One trait, so the engine runs the same
//! against an RPC node and against LiteSVM (`testkit`), and tests can inject faults.

use crate::fees;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_message::Hash;
use solana_rpc_client::{
    api::{
        config::{
            RpcAccountInfoConfig, RpcBlockConfig, RpcProgramAccountsConfig,
            RpcSendTransactionConfig, RpcSimulateTransactionConfig, RpcTransactionConfig,
            UiAccountEncoding,
        },
        filter::{Memcmp, RpcFilterType},
    },
    rpc_client::RpcClient,
};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::{TransactionDetails, UiTransactionEncoding};
use std::{future::Future, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commitment {
    Confirmed,
    Finalized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizedStatus {
    Unknown,
    Succeeded,
    Failed,
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
    /// The cluster's genesis hash, which binds stealth confidential keys to one cluster.
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError>;
    fn rent(&self, space: usize) -> Result<u64, ChainError>;
}

/// Cluster reads needed by recipient discovery and sweeping.
pub trait RecipientChain: Chain {
    fn set_deadline(&mut self, deadline: Option<Instant>);
    fn announcements(&self) -> Result<Vec<(Address, AccountData)>, ChainError>;
    /// Every registry entry, in one query, so lookups are picked locally.
    fn registry_entries(&self) -> Result<Vec<(Address, AccountData)>, ChainError>;
    fn fee(&self, message: &solana_message::VersionedMessage) -> Result<u64, ChainError>;
    fn finalized_status(&self, signature: &Signature) -> Result<FinalizedStatus, ChainError>;
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

pub struct RpcChain {
    client: RpcClient,
    deadline: Option<Instant>,
}

impl From<RpcClient> for RpcChain {
    fn from(client: RpcClient) -> Self {
        Self {
            client,
            deadline: None,
        }
    }
}

impl RpcChain {
    fn rpc(&self) -> &solana_rpc_client::nonblocking::rpc_client::RpcClient {
        self.client.get_inner_client()
    }

    fn call<T>(
        &self,
        request: impl Future<Output = solana_rpc_client::api::client_error::Result<T>>,
    ) -> Result<T, ChainError> {
        tokio::task::block_in_place(|| {
            self.client.runtime().block_on(async {
                match self.deadline {
                    Some(deadline) => {
                        if Instant::now() >= deadline {
                            return Err(ChainError("sweep deadline exceeded".into()));
                        }
                        tokio::time::timeout_at(deadline.into(), request)
                            .await
                            .map_err(rpc_err)?
                            .map_err(rpc_err)
                    }
                    None => request.await.map_err(rpc_err),
                }
            })
        })
    }
}

impl Chain for RpcChain {
    fn account(
        &self,
        address: &Address,
        commitment: Commitment,
    ) -> Result<Option<AccountData>, ChainError> {
        let found = self
            .call(
                self.rpc()
                    .get_account_with_commitment(address, config(commitment)),
            )?
            .value;
        Ok(found.map(|a| AccountData {
            owner: a.owner,
            lamports: a.lamports,
            data: a.data,
        }))
    }

    fn blockhash(&self) -> Result<(Hash, u64), ChainError> {
        self.call(
            self.rpc()
                .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed()),
        )
    }

    fn finalized_block_height(&self) -> Result<u64, ChainError> {
        self.call(
            self.rpc()
                .get_block_height_with_commitment(CommitmentConfig::finalized()),
        )
    }

    fn simulate(&self, tx: &VersionedTransaction) -> Result<Result<(), String>, ChainError> {
        let result = self
            .call(self.rpc().simulate_transaction_with_config(
                tx,
                RpcSimulateTransactionConfig {
                    sig_verify: true,
                    commitment: Some(CommitmentConfig::confirmed()),
                    ..RpcSimulateTransactionConfig::default()
                },
            ))?
            .value;
        Ok(match result.err {
            None => Ok(()),
            Some(err) => Err(format!("{err:?}\n{:#?}", result.logs.unwrap_or_default())),
        })
    }

    fn send(&mut self, tx: &VersionedTransaction) -> Result<(), ChainError> {
        self.call(self.rpc().send_transaction_with_config(
            tx,
            RpcSendTransactionConfig {
                skip_preflight: true,
                max_retries: Some(0),
                ..RpcSendTransactionConfig::default()
            },
        ))
        .map(|_| ())
    }

    fn recent_prices(&self) -> Result<Vec<u64>, ChainError> {
        let slot = self.call(
            self.rpc()
                .get_slot_with_commitment(CommitmentConfig::confirmed()),
        )?;
        let block = self.call(self.rpc().get_block_with_config(
            slot,
            RpcBlockConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                transaction_details: Some(TransactionDetails::Full),
                rewards: Some(false),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(1),
            },
        ))?;
        Ok(fees::block_prices(block.transactions.unwrap_or_default()))
    }
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
        self.call(self.rpc().get_genesis_hash())
            .map(|h| h.to_bytes())
    }
    fn rent(&self, space: usize) -> Result<u64, ChainError> {
        self.call(self.rpc().get_minimum_balance_for_rent_exemption(space))
    }
}

impl RecipientChain for RpcChain {
    fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    fn finalized_status(&self, signature: &Signature) -> Result<FinalizedStatus, ChainError> {
        let statuses = self.call(
            self.rpc()
                .get_signature_statuses_with_history(&[*signature]),
        )?;
        Ok(
            match statuses
                .value
                .first()
                .and_then(Option::as_ref)
                .filter(|status| status.satisfies_commitment(CommitmentConfig::finalized()))
            {
                Some(status) if status.err.is_none() => FinalizedStatus::Succeeded,
                Some(_) => FinalizedStatus::Failed,
                None => FinalizedStatus::Unknown,
            },
        )
    }

    fn announcements(&self) -> Result<Vec<(Address, AccountData)>, ChainError> {
        use scope_interface::state::{
            ANNOUNCEMENT_DISCRIMINATOR, ANNOUNCEMENT_LEN, ANNOUNCEMENT_VERSION,
        };
        let accounts = self.call(self.rpc().get_program_ui_accounts_with_config(
            &crate::address::program_id(),
            RpcProgramAccountsConfig {
                filters: Some(vec![
                    RpcFilterType::DataSize(ANNOUNCEMENT_LEN as u64),
                    RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
                        0,
                        &[ANNOUNCEMENT_DISCRIMINATOR, ANNOUNCEMENT_VERSION],
                    )),
                ]),
                account_config: RpcAccountInfoConfig {
                    encoding: Some(UiAccountEncoding::Base64),
                    commitment: Some(CommitmentConfig::confirmed()),
                    ..Default::default()
                },
                ..Default::default()
            },
        ))?;
        accounts
            .into_iter()
            .map(|(address, a)| {
                Ok((
                    address,
                    AccountData {
                        owner: a.owner.parse().map_err(rpc_err)?,
                        lamports: a.lamports,
                        data: a.data.decode().ok_or_else(|| {
                            ChainError(format!("invalid RPC account encoding for {address}"))
                        })?,
                    },
                ))
            })
            .collect()
    }

    fn registry_entries(&self) -> Result<Vec<(Address, AccountData)>, ChainError> {
        use scope_interface::state::{META_ENTRY_DISCRIMINATOR, META_ENTRY_LEN};
        let accounts = self.call(self.rpc().get_program_ui_accounts_with_config(
            &crate::address::program_id(),
            RpcProgramAccountsConfig {
                filters: Some(vec![
                    RpcFilterType::DataSize(META_ENTRY_LEN as u64),
                    RpcFilterType::Memcmp(Memcmp::new_base58_encoded(0, &META_ENTRY_DISCRIMINATOR)),
                ]),
                account_config: RpcAccountInfoConfig {
                    encoding: Some(UiAccountEncoding::Base64),
                    commitment: Some(CommitmentConfig::confirmed()),
                    ..Default::default()
                },
                ..Default::default()
            },
        ))?;
        accounts
            .into_iter()
            .map(|(address, a)| {
                Ok((
                    address,
                    AccountData {
                        owner: a.owner.parse().map_err(rpc_err)?,
                        lamports: a.lamports,
                        data: a.data.decode().ok_or_else(|| {
                            ChainError(format!("invalid RPC account encoding for {address}"))
                        })?,
                    },
                ))
            })
            .collect()
    }

    fn fee(&self, message: &solana_message::VersionedMessage) -> Result<u64, ChainError> {
        struct WireMessage<'a>(&'a solana_message::VersionedMessage);
        impl solana_rpc_client::rpc_client::SerializableMessage for WireMessage<'_> {
            fn serialize(&self) -> Vec<u8> {
                self.0.serialize()
            }
        }
        self.call(self.rpc().get_fee_for_message(&WireMessage(message)))
    }
}

impl crate::receipt::TransactionArchive for RpcChain {
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
        Chain::genesis_hash(self)
    }

    /// Finalized only; v1 transactions need `maxSupportedTransactionVersion: 1` (V22).
    fn transaction(
        &self,
        signature: &Signature,
    ) -> Result<crate::receipt::ArchivedTransaction, ChainError> {
        let found = self.call(self.rpc().get_transaction_with_config(
            signature,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                commitment: Some(CommitmentConfig::finalized()),
                max_supported_transaction_version: Some(1),
            },
        ))?;
        let transaction = found
            .transaction
            .transaction
            .decode()
            .ok_or_else(|| ChainError(format!("{signature}: transaction does not decode")))?;
        let succeeded = found
            .transaction
            .meta
            .is_some_and(|meta| meta.err.is_none());
        Ok(crate::receipt::ArchivedTransaction {
            transaction,
            succeeded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };

    #[test]
    fn rpc_deadline_cancels_slow_responses_and_rate_limit_retries() {
        for rate_limited in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
            let url = format!("http://{}", listener.local_addr().expect("address"));
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read timeout");
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).expect("request") > 0);
                if rate_limited {
                    stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").expect("rate limit");
                } else {
                    std::thread::sleep(Duration::from_millis(500));
                }
            });
            let mut chain = RpcChain::from(RpcClient::new(url));
            let start = Instant::now();
            chain.set_deadline(Some(start + Duration::from_millis(100)));
            chain
                .finalized_block_height()
                .expect_err("deadline interrupts RPC");
            assert!(start.elapsed() < Duration::from_millis(400));
            chain.set_deadline(None);
            assert_eq!(chain.call(async { Ok(7) }).expect("deadline cleared"), 7);
            server.join().expect("server");
        }
    }

    #[test]
    fn expired_rpc_deadline_does_not_start_a_request() {
        let mut chain = RpcChain::from(RpcClient::new_mock("succeeds"));
        chain.set_deadline(Some(Instant::now()));
        let called = Cell::new(false);
        let request = async {
            called.set(true);
            Ok(())
        };
        chain.call(request).expect_err("expired");
        assert!(!called.get());
    }
    #[test]
    fn malformed_rpc_account_encoding_returns_an_error() {
        use solana_rpc_client::api::request::RpcRequest;
        let mocks = std::collections::HashMap::from([(
            RpcRequest::GetProgramAccounts,
            serde_json::json!([
                {
                    "pubkey": Address::default().to_string(),
                    "account": {
                        "owner": crate::address::program_id().to_string(),
                        "lamports": 10_000_000,
                        "data": ["not base64!", "base64"],
                        "executable": false,
                        "rentEpoch": 0,
                        "space": 68
                    }
                }
            ]),
        )]);
        let chain = RpcChain::from(RpcClient::new_mock_with_mocks("succeeds", mocks));
        let error = chain.announcements().expect_err("malformed transport data");
        assert!(error.0.contains("invalid RPC account encoding"));
    }
}
