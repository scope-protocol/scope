//! What the payer engine needs from a cluster. One trait, so the engine runs the same
//! against an RPC node and against LiteSVM (`testkit`), and tests can inject faults.

use crate::fees;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_message::Hash;
use solana_rpc_client::{
    api::{
        client_error::{Error as ClientError, ErrorKind},
        config::{
            RpcAccountInfoConfig, RpcBlockConfig, RpcProgramAccountsConfig,
            RpcSendTransactionConfig, RpcSimulateTransactionConfig, RpcTransactionConfig,
            UiAccountEncoding,
        },
        filter::{Memcmp, RpcFilterType},
        request::{RpcError, RpcRequest},
    },
    rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient},
};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, TransactionDetails, UiTransactionEncoding,
};
use std::{
    future::Future,
    time::{Duration, Instant},
};

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

/// Starts the message of the error for a signature the node does not have.
const NOT_FOUND: &str = "transaction not found";

impl ChainError {
    /// The node has no such transaction: not yet finalized, or pruned from its history.
    pub fn not_found(signature: &Signature) -> Self {
        Self(format!("{NOT_FOUND}: {signature}"))
    }

    pub fn is_not_found(&self) -> bool {
        self.0.starts_with(NOT_FOUND)
    }
}

pub trait Chain {
    fn account(
        &self,
        address: &Address,
        commitment: Commitment,
    ) -> Result<Option<AccountData>, ChainError>;

    /// Several accounts in one round trip where the node allows it, in the order asked.
    fn accounts(
        &self,
        addresses: &[Address],
        commitment: Commitment,
    ) -> Result<Vec<Option<AccountData>>, ChainError> {
        addresses
            .iter()
            .map(|address| self.account(address, commitment))
            .collect()
    }

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

    /// The error text of a transaction that landed (confirmed or better) and failed.
    /// `None` when it succeeded or is not known to the node; a chain that cannot tell
    /// keeps this default.
    fn landed_error(&self, _signature: &Signature) -> Result<Option<String>, ChainError> {
        Ok(None)
    }

    /// Every announcement whose rent refund goes to `payer`, found with a size filter and a
    /// memcmp on the payer field.
    fn announcements_by_payer(
        &self,
        _payer: &Address,
    ) -> Result<Vec<(Address, AccountData)>, ChainError> {
        Err(ChainError("this chain cannot list announcements".into()))
    }
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
    ChainError(redact(&e.to_string(), ""))
}

/// Removes every URL from `text`, and `endpoint` itself, because endpoints carry API keys.
fn redact(text: &str, endpoint: &str) -> String {
    let mut text = if endpoint.is_empty() {
        text.to_string()
    } else {
        text.replace(endpoint, "<rpc url>")
    };
    for scheme in ["https://", "http://", "wss://", "ws://"] {
        let mut from = 0;
        while let Some(start) = text[from..].find(scheme).map(|i| i + from) {
            let end = text[start..]
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, ')' | '"' | '\'' | '>' | ',' | ']')
                })
                .map_or(text.len(), |i| start + i);
            text.replace_range(start..end, "<rpc url>");
            from = start + "<rpc url>".len();
        }
    }
    text
}

/// RPC error codes for a block the node does not have: not available, slot skipped,
/// and skipped in long-term storage.
const BLOCK_GAP_CODES: [i64; 3] = [-32004, -32007, -32009];
/// Node unhealthy, and minimum context slot not reached.
const TRANSIENT_CODES: [i64; 2] = [-32005, -32016];

/// A failed call, with what a retry policy needs to know about it.
struct Failure {
    error: ChainError,
    retryable: bool,
    block_gap: bool,
}

impl Failure {
    fn from_client(e: &ClientError, endpoint: &str) -> Self {
        let code = match e.kind() {
            ErrorKind::RpcError(RpcError::RpcResponseError { code, .. }) => Some(*code),
            _ => None,
        };
        let block_gap = code.is_some_and(|c| BLOCK_GAP_CODES.contains(&c));
        let retryable = block_gap
            || code.is_some_and(|c| TRANSIENT_CODES.contains(&c))
            || match e.kind() {
                ErrorKind::Io(_) => true,
                ErrorKind::Reqwest(r) => {
                    r.is_timeout()
                        || r.is_connect()
                        || r.is_request()
                        || r.status()
                            .is_some_and(|s| s.as_u16() == 429 || s.is_server_error())
                }
                _ => false,
            };
        Self {
            error: ChainError(redact(&e.to_string(), endpoint)),
            retryable,
            block_gap,
        }
    }

    fn final_(error: ChainError) -> Self {
        Self {
            error,
            retryable: false,
            block_gap: false,
        }
    }
}

/// The first block that exists at `slot` or the few slots before it, since the newest
/// slot can be skipped or not yet stored.
fn first_available_block<T>(
    slot: u64,
    mut fetch: impl FnMut(u64) -> Result<T, Failure>,
) -> Result<T, ChainError> {
    let mut last = None;
    for back in 0..PRICE_SLOTS {
        let Some(candidate) = slot.checked_sub(back) else {
            break;
        };
        match fetch(candidate) {
            Ok(found) => return Ok(found),
            Err(f) if f.block_gap => last = Some(f.error),
            Err(f) => return Err(f.error),
        }
    }
    Err(last.unwrap_or_else(|| ChainError("no block to sample prices from".into())))
}

/// Slots tried, newest first, when sampling fees.
const PRICE_SLOTS: u64 = 5;
/// Tries per idempotent read.
const READ_TRIES: u32 = 3;

fn config(c: Commitment) -> CommitmentConfig {
    match c {
        Commitment::Confirmed => CommitmentConfig::confirmed(),
        Commitment::Finalized => CommitmentConfig::finalized(),
    }
}

pub struct RpcChain {
    client: RpcClient,
    deadline: Option<Instant>,
    /// First wait between tries of a read; it doubles.
    retry_base: Duration,
}

impl From<RpcClient> for RpcChain {
    fn from(client: RpcClient) -> Self {
        Self {
            client,
            deadline: None,
            retry_base: Duration::from_millis(200),
        }
    }
}

impl RpcChain {
    fn rpc(&self) -> &solana_rpc_client::nonblocking::rpc_client::RpcClient {
        self.client.get_inner_client()
    }

    /// One attempt. Never repeats the request, so it is the path for `send`.
    fn call<T>(
        &self,
        request: impl Future<Output = solana_rpc_client::api::client_error::Result<T>>,
    ) -> Result<T, ChainError> {
        self.call_once(request).map_err(|f| f.error)
    }

    fn call_once<T>(
        &self,
        request: impl Future<Output = solana_rpc_client::api::client_error::Result<T>>,
    ) -> Result<T, Failure> {
        let endpoint = self.client.url();
        tokio::task::block_in_place(|| {
            self.client.runtime().block_on(async {
                let outcome = match self.deadline {
                    Some(deadline) => {
                        if Instant::now() >= deadline {
                            return Err(Failure::final_(ChainError(
                                "sweep deadline exceeded".into(),
                            )));
                        }
                        match tokio::time::timeout_at(deadline.into(), request).await {
                            Ok(outcome) => outcome,
                            Err(e) => return Err(Failure::final_(rpc_err(e))),
                        }
                    }
                    None => request.await,
                };
                outcome.map_err(|e| Failure::from_client(&e, &endpoint))
            })
        })
    }

    /// An idempotent read, tried up to `READ_TRIES` times with a doubling wait when the
    /// failure is a transport error, a rate limit or a block the node lacks.
    fn read<T, Fut>(&self, make: impl Fn() -> Fut) -> Result<T, ChainError>
    where
        Fut: Future<Output = solana_rpc_client::api::client_error::Result<T>>,
    {
        self.read_with(make, true).map_err(|f| f.error)
    }

    /// Like `read`, but with `retry_gaps` false a missing block is returned at once, for
    /// callers that would rather ask for another block.
    fn read_with<T, Fut>(&self, make: impl Fn() -> Fut, retry_gaps: bool) -> Result<T, Failure>
    where
        Fut: Future<Output = solana_rpc_client::api::client_error::Result<T>>,
    {
        let mut wait = self.retry_base;
        for attempt in 1.. {
            match self.call_once(make()) {
                Err(f) if f.retryable && (retry_gaps || !f.block_gap) && attempt < READ_TRIES => {
                    std::thread::sleep(wait);
                    wait *= 2;
                }
                other => return other,
            }
        }
        unreachable!("the loop returns on its last try")
    }
}

impl Chain for RpcChain {
    fn account(
        &self,
        address: &Address,
        commitment: Commitment,
    ) -> Result<Option<AccountData>, ChainError> {
        let found = self
            .read(|| {
                self.rpc()
                    .get_account_with_commitment(address, config(commitment))
            })?
            .value;
        Ok(found.map(|a| AccountData {
            owner: a.owner,
            lamports: a.lamports,
            data: a.data,
        }))
    }

    fn accounts(
        &self,
        addresses: &[Address],
        commitment: Commitment,
    ) -> Result<Vec<Option<AccountData>>, ChainError> {
        // getMultipleAccounts accepts at most 100 keys.
        let mut found = Vec::with_capacity(addresses.len());
        for chunk in addresses.chunks(100) {
            let rows = self
                .read(|| {
                    self.rpc()
                        .get_multiple_accounts_with_commitment(chunk, config(commitment))
                })?
                .value;
            if rows.len() != chunk.len() {
                return Err(ChainError(
                    "getMultipleAccounts returned a short list".into(),
                ));
            }
            found.extend(rows.into_iter().map(|row| {
                row.map(|a| AccountData {
                    owner: a.owner,
                    lamports: a.lamports,
                    data: a.data,
                })
            }));
        }
        Ok(found)
    }

    fn blockhash(&self) -> Result<(Hash, u64), ChainError> {
        self.read(|| {
            self.rpc()
                .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())
        })
    }

    fn finalized_block_height(&self) -> Result<u64, ChainError> {
        self.read(|| {
            self.rpc()
                .get_block_height_with_commitment(CommitmentConfig::finalized())
        })
    }

    fn simulate(&self, tx: &VersionedTransaction) -> Result<Result<(), String>, ChainError> {
        let result = self
            .read(|| {
                self.rpc().simulate_transaction_with_config(
                    tx,
                    RpcSimulateTransactionConfig {
                        sig_verify: true,
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..RpcSimulateTransactionConfig::default()
                    },
                )
            })?
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
        let slot = self.read(|| {
            self.rpc()
                .get_slot_with_commitment(CommitmentConfig::confirmed())
        })?;
        let block = first_available_block(slot, |slot| {
            self.read_with(
                || {
                    self.rpc().get_block_with_config(
                        slot,
                        RpcBlockConfig {
                            encoding: Some(UiTransactionEncoding::Base64),
                            transaction_details: Some(TransactionDetails::Full),
                            rewards: Some(false),
                            commitment: Some(CommitmentConfig::confirmed()),
                            max_supported_transaction_version: Some(1),
                        },
                    )
                },
                false,
            )
        })?;
        Ok(fees::block_prices(block.transactions.unwrap_or_default()))
    }
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
        self.read(|| self.rpc().get_genesis_hash())
            .map(|h| h.to_bytes())
    }
    fn rent(&self, space: usize) -> Result<u64, ChainError> {
        self.read(|| self.rpc().get_minimum_balance_for_rent_exemption(space))
    }

    fn announcements_by_payer(
        &self,
        payer: &Address,
    ) -> Result<Vec<(Address, AccountData)>, ChainError> {
        use scope_interface::state::ANNOUNCEMENT_LEN;
        // The payer is the announcement's last field.
        const PAYER_OFFSET: usize = ANNOUNCEMENT_LEN - 32;
        let program = crate::address::program_id();
        let accounts = self.read(|| {
            self.rpc().get_program_ui_accounts_with_config(
                &program,
                RpcProgramAccountsConfig {
                    filters: Some(vec![
                        RpcFilterType::DataSize(ANNOUNCEMENT_LEN as u64),
                        RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
                            PAYER_OFFSET,
                            payer.as_ref(),
                        )),
                    ]),
                    account_config: RpcAccountInfoConfig {
                        encoding: Some(UiAccountEncoding::Base64),
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
        })?;
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

    fn landed_error(&self, signature: &Signature) -> Result<Option<String>, ChainError> {
        let signatures = [*signature];
        let statuses = self.read(|| self.rpc().get_signature_statuses_with_history(&signatures))?;
        Ok(statuses
            .value
            .into_iter()
            .next()
            .flatten()
            .filter(|status| status.satisfies_commitment(CommitmentConfig::confirmed()))
            .and_then(|status| status.err)
            .map(|err| format!("{err:?}")))
    }
}

impl RecipientChain for RpcChain {
    fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    fn finalized_status(&self, signature: &Signature) -> Result<FinalizedStatus, ChainError> {
        let signatures = [*signature];
        let statuses = self.read(|| self.rpc().get_signature_statuses_with_history(&signatures))?;
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
        let params = serde_json::json!([
            signature.to_string(),
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                commitment: Some(CommitmentConfig::finalized()),
                max_supported_transaction_version: Some(1),
            }
        ]);
        // A null result is a missing transaction; a block gap is a pruned one.
        let found = match self.read_with(
            || {
                self.rpc()
                    .send::<Option<EncodedConfirmedTransactionWithStatusMeta>>(
                        RpcRequest::GetTransaction,
                        params.clone(),
                    )
            },
            false,
        ) {
            Ok(Some(found)) => found,
            Ok(None) => return Err(ChainError::not_found(signature)),
            Err(f) if f.block_gap => return Err(ChainError::not_found(signature)),
            Err(f) => return Err(f.error),
        };
        let transaction = found
            .transaction
            .transaction
            .decode()
            .ok_or_else(|| ChainError(format!("{signature}: transaction does not decode")))?;
        // Some history providers drop the status of old transactions; unknown is not failed.
        let succeeded = found
            .transaction
            .meta
            .ok_or_else(|| ChainError(format!("{signature}: the node returned no status")))?
            .err
            .is_none();
        Ok(crate::receipt::ArchivedTransaction {
            transaction,
            succeeded,
        })
    }
}

impl crate::history::SignatureHistory for RpcChain {
    fn signatures_for_address(
        &self,
        address: &Address,
        query: &crate::history::SignatureQuery<'_>,
    ) -> Result<Vec<crate::history::SignatureEntry>, ChainError> {
        let rows = self.read(|| {
            self.rpc().get_signatures_for_address_with_config(
                address,
                GetConfirmedSignaturesForAddress2Config {
                    before: query.before.copied(),
                    until: query.until.copied(),
                    limit: Some(query.limit),
                    commitment: Some(config(query.commitment)),
                },
            )
        })?;
        rows.into_iter()
            .map(|row| {
                Ok(crate::history::SignatureEntry {
                    signature: row.signature.parse().map_err(rpc_err)?,
                    slot: row.slot,
                    succeeded: row.err.is_none(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_rpc_client::api::{
        client_error::ErrorKind,
        request::{RpcError, RpcResponseErrorData},
    };
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
                // Under load the client's deadline can fire before it writes; that is the
                // behavior under test, so there is nothing left to serve.
                if stream.read(&mut request).unwrap_or(0) == 0 {
                    return;
                }
                if rate_limited {
                    let _ = stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
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

    fn client_error(kind: ErrorKind) -> ClientError {
        kind.into()
    }

    fn gap(code: i64) -> ClientError {
        client_error(ErrorKind::RpcError(RpcError::RpcResponseError {
            code,
            message: "Block not available for slot".into(),
            data: RpcResponseErrorData::Empty,
        }))
    }

    fn io_error() -> ClientError {
        client_error(ErrorKind::Io(std::io::Error::other("connection reset")))
    }

    fn quick_chain() -> RpcChain {
        let mut chain = RpcChain::from(RpcClient::new_mock("succeeds"));
        chain.retry_base = Duration::from_millis(1);
        chain
    }

    #[test]
    fn reads_retry_transport_errors_and_block_gaps_a_bounded_number_of_times() {
        let chain = quick_chain();
        let calls = Cell::new(0);
        let flaky = |failures: usize, error: fn() -> ClientError| {
            calls.set(0);
            chain.read(|| async {
                calls.set(calls.get() + 1);
                if calls.get() <= failures {
                    Err(error())
                } else {
                    Ok(7)
                }
            })
        };
        assert_eq!(flaky(2, io_error).expect("third try succeeds"), 7);
        assert_eq!(calls.get(), 3);
        assert_eq!(flaky(2, || gap(-32004)).expect("gap clears"), 7);
        flaky(3, io_error).expect_err("three tries is the bound");
        assert_eq!(calls.get(), 3);
        // A definite answer from the node is not retried.
        let refused = || client_error(ErrorKind::Custom("invalid params".into()));
        flaky(1, refused).expect_err("not retryable");
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn prices_fall_back_to_earlier_slots_when_a_block_is_skipped() {
        let tried = std::cell::RefCell::new(Vec::new());
        let found = first_available_block(100, |slot| {
            tried.borrow_mut().push(slot);
            if slot > 98 {
                Err(Failure::from_client(&gap(-32007), "http://x"))
            } else {
                Ok(slot)
            }
        })
        .expect("an earlier slot has a block");
        assert_eq!(found, 98);
        assert_eq!(*tried.borrow(), [100, 99, 98]);
        let all_skipped = first_available_block(100, |_| -> Result<u64, Failure> {
            Err(Failure::from_client(&gap(-32009), "http://x"))
        });
        assert!(all_skipped.is_err());
        let broken = first_available_block(100, |_| -> Result<u64, Failure> {
            Err(Failure::from_client(&io_error(), "http://x"))
        });
        assert!(broken.is_err());
    }

    #[test]
    fn rpc_urls_never_reach_error_text() {
        let url = "https://rpc.example.com/v2/secret-path?api-key=hunter2";
        let text = format!("error sending request for url ({url}): connection refused");
        let redacted = redact(&text, url);
        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(!redacted.contains("secret-path"), "{redacted}");
        assert!(redacted.contains("connection refused"));
        // A redirect target is a URL too.
        let other = redact("redirect to http://other.example/x?token=abc failed", url);
        assert!(!other.contains("token=abc"), "{other}");
        // A bare host:port endpoint, which the client accepts, is removed by exact match.
        let bare = redact("dial 10.0.0.5:8899 failed", "10.0.0.5:8899");
        assert!(!bare.contains("10.0.0.5"), "{bare}");
    }

    #[test]
    fn a_failed_connection_does_not_leak_the_endpoint() {
        let mut chain = RpcChain::from(RpcClient::new(
            "http://127.0.0.1:1/v2/secret-path?api-key=hunter2".to_string(),
        ));
        chain.retry_base = Duration::from_millis(1);
        let error = chain.genesis_hash().expect_err("nothing listens there");
        assert!(!error.0.contains("hunter2"), "{}", error.0);
        assert!(!error.0.contains("secret-path"), "{}", error.0);
    }
}
