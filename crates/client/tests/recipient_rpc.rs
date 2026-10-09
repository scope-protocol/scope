use base64::{Engine, prelude::BASE64_STANDARD};
use scope_client::{
    address::{announcement_address, program_id, token_account_address},
    chain::{AccountData, RpcChain},
    confidential::{context, derive_confidential_keys},
    scan,
    testkit::Harness,
};
use scope_interface::state::Announcement;
use serde_json::{Value, json};
use solana_address::Address;
use solana_rpc_client::{
    api::{config::RpcProgramAccountsConfig, filter::RpcFilterType},
    rpc_client::RpcClient,
};
use solana_signer::Signer;
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensionsMut, StateWithExtensionsMut,
        confidential_transfer::ConfidentialTransferAccount,
    },
    state::Account,
};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use stealth_keygen::{EphemeralSecret, RecipientSecretKeys, derive_payment_with_ephemeral};

fn recipient(spend: u8, scan: u8) -> RecipientSecretKeys {
    let mut bytes = [scan; 64];
    bytes[..32].fill(0);
    bytes[0] = spend;
    RecipientSecretKeys::from_bytes(bytes).expect("test keys")
}

fn ui(account: &AccountData) -> Value {
    json!({"owner":account.owner.to_string(), "lamports":account.lamports,
        "data":[BASE64_STANDARD.encode(&account.data), "base64"], "executable":false,
        "rentEpoch":0, "space":account.data.len()})
}

/// Announcements and their token accounts: payment `i` is addressed to `owned` when
/// `is_owned(i)`, else to a stranger.
fn seed(
    h: &Harness,
    owned: &RecipientSecretKeys,
    count: u64,
    is_owned: impl Fn(u64) -> bool,
) -> HashMap<Address, AccountData> {
    let foreign = recipient(2, 3);
    let template = h.svm.get_account(&h.source).expect("template");
    let mut accounts = HashMap::new();
    for i in 0..count {
        let recipient = if is_owned(i) { owned } else { &foreign };
        let mut secret = [3; 32];
        secret[..8].copy_from_slice(&(i * 8 + 1).to_le_bytes());
        let sent = derive_payment_with_ephemeral(
            &recipient.derive_public_keys(),
            &EphemeralSecret::from_bytes(secret),
        )
        .expect("payment");
        let ephemeral = sent.announcement.ephemeral_public_key;
        let source = token_account_address(&h.payer.pubkey(), &ephemeral);
        let (announcement, bump) = announcement_address(&source);
        let record = Announcement {
            ephemeral,
            view_tag: sent.announcement.discovery_tag,
            bump,
            payer: h.payer.pubkey().to_bytes(),
        };
        accounts.insert(
            announcement,
            AccountData {
                owner: program_id(),
                lamports: 10_000_000,
                data: record.to_bytes().to_vec(),
            },
        );
        let material = sent
            .derive_ct_ikm(&context([42; 32], &h.mint, &source))
            .expect("material");
        let (keys, ae) = derive_confidential_keys(&material).expect("keys");
        let mut data = template.data.clone();
        let mut state = StateWithExtensionsMut::<Account>::unpack(&mut data).expect("state");
        state.base.owner = Address::new_from_array(sent.payment_public_key);
        state.base.close_authority = Some(announcement).into();
        let ext = state
            .get_extension_mut::<ConfidentialTransferAccount>()
            .expect("ct");
        ext.elgamal_pubkey = (*keys.pubkey()).into();
        ext.available_balance = keys.pubkey().encrypt_u64(123).into();
        ext.decryptable_available_balance = ae.encrypt(123).into();
        ext.maximum_pending_balance_credit_counter = 1.into();
        ext.allow_non_confidential_credits = false.into();
        state.pack_base();
        accounts.insert(
            source,
            AccountData {
                owner: template.owner,
                lamports: template.lamports,
                data,
            },
        );
    }
    accounts.insert(
        Address::new_from_array([97; 32]),
        AccountData {
            owner: program_id(),
            lamports: 10_000_000,
            data: vec![0; 1_000],
        },
    );
    accounts
}

#[derive(Default, Debug)]
struct Calls {
    returned: usize,
    single_reads: usize,
    multi_calls: usize,
    largest_multi: usize,
}

/// A JSON-RPC node over `accounts`; the `fail_multi`th getMultipleAccounts call (from 1)
/// answers with an error.
struct Node {
    url: String,
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<Calls>,
}

impl Node {
    fn finish(self) -> Calls {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().expect("server")
    }
}

fn serve(accounts: HashMap<Address, AccountData>, fail_multi: Option<usize>) -> Node {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let mut calls = Calls::default();
        while !stopping.load(Ordering::Relaxed) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("accept: {error}"),
            };
            // On macOS an accepted socket inherits the listener's O_NONBLOCK; Linux's does not.
            stream.set_nonblocking(false).expect("blocking");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut reader = BufReader::new(&mut stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                assert!(
                    reader.read_line(&mut line).expect("header") > 0,
                    "request ended before headers"
                );
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().expect("length");
                }
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).expect("body");
            let request: Value = serde_json::from_slice(&bytes).expect("json");
            let response = match request["method"].as_str().expect("method") {
                "getGenesisHash" => {
                    json!(solana_message::Hash::new_from_array([42; 32]).to_string())
                }
                "getProgramAccounts" => {
                    let config: RpcProgramAccountsConfig =
                        serde_json::from_value(request["params"][1].clone()).expect("config");
                    let program: Address = request["params"][0]
                        .as_str()
                        .expect("program")
                        .parse()
                        .expect("address");
                    let rows: Vec<_> = accounts
                        .iter()
                        .filter(|(_, a)| {
                            a.owner == program
                                && config.filters.as_ref().is_none_or(|filters| {
                                    filters.iter().all(|filter| match filter {
                                        RpcFilterType::DataSize(size) => {
                                            a.data.len() as u64 == *size
                                        }
                                        RpcFilterType::Memcmp(memcmp) => {
                                            memcmp.bytes_match(&a.data)
                                        }
                                        _ => false,
                                    })
                                })
                        })
                        .map(|(address, a)| json!({"pubkey":address.to_string(), "account":ui(a)}))
                        .collect();
                    calls.returned = rows.len();
                    json!(rows)
                }
                "getAccountInfo" => {
                    calls.single_reads += 1;
                    let address: Address = request["params"][0]
                        .as_str()
                        .expect("address")
                        .parse()
                        .expect("pubkey");
                    json!({"context":{"slot":1}, "value":accounts.get(&address).map(ui)})
                }
                "getMultipleAccounts" => {
                    calls.multi_calls += 1;
                    let keys = request["params"][0].as_array().expect("keys");
                    calls.largest_multi = calls.largest_multi.max(keys.len());
                    if fail_multi == Some(calls.multi_calls) {
                        let body = serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":request["id"],
                            "error":{"code":-32005, "message":"node is unhealthy"}}))
                        .expect("error");
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).expect("headers");
                        stream.write_all(&body).expect("error body");
                        continue;
                    }
                    let rows: Vec<_> = keys
                        .iter()
                        .map(|k| {
                            let address: Address =
                                k.as_str().expect("key").parse().expect("pubkey");
                            accounts.get(&address).map(ui)
                        })
                        .collect();
                    json!({"context":{"slot":1}, "value":rows})
                }
                other => panic!("unexpected RPC: {other}"),
            };
            let body = serde_json::to_vec(
                &json!({"jsonrpc":"2.0", "id":request["id"], "result":response}),
            )
            .expect("response");
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).expect("headers");
            stream.write_all(&body).expect("response");
        }
        calls
    });
    Node { url, stop, thread }
}

#[test]
fn scan_authenticates_payments_over_rpc_among_one_thousand_announcements() {
    let h = Harness::new();
    let alice = recipient(1, 2);
    let node = serve(seed(&h, &alice, 1_000, |i| i == 999), None);
    let chain = RpcChain::from(RpcClient::new(node.url.clone()));
    let start = Instant::now();
    let result = scan::scan(&chain, &alice, None);
    let elapsed = start.elapsed();
    let calls = node.finish();
    let report = result.expect("RPC scan");
    assert_eq!(report.payments.len(), 1);
    assert_eq!(report.payments[0].amount, 123);
    assert!(report.skipped.is_empty());
    assert_eq!(calls.returned, 1_000);
    assert_eq!(calls.single_reads, 0);
    assert_eq!(calls.multi_calls, 1);
    println!("1,000 seeded announcements, {calls:?}, scan {elapsed:?}");
}

#[test]
fn scan_reads_candidate_accounts_in_batches_of_one_hundred() {
    let h = Harness::new();
    let alice = recipient(1, 2);
    let node = serve(seed(&h, &alice, 250, |_| true), None);
    let chain = RpcChain::from(RpcClient::new(node.url.clone()));
    let report = scan::scan(&chain, &alice, None).expect("RPC scan");
    let calls = node.finish();
    assert_eq!(report.payments.len(), 250);
    assert_eq!(calls.single_reads, 0);
    assert_eq!(calls.multi_calls, 3);
    assert_eq!(calls.largest_multi, 100);
}

#[test]
fn a_failed_batch_stops_the_scan_with_the_progress_made() {
    let h = Harness::new();
    let alice = recipient(1, 2);
    let node = serve(seed(&h, &alice, 250, |_| true), Some(2));
    let chain = RpcChain::from(RpcClient::new(node.url.clone()));
    let mut reported = 0;
    let error = scan::scan_with_results(&chain, &alice, None, |_| {
        reported += 1;
        Ok(())
    })
    .expect_err("second batch fails");
    node.finish();
    assert!(
        matches!(
            error,
            scan::ScanError::Incomplete {
                read: 100,
                total: 250,
                ..
            }
        ),
        "{error}"
    );
    assert!(error.to_string().contains("after reading 100 of 250"));
    assert_eq!(reported, 100);
}
