//! Payer engine, plain recipients, against LiteSVM.

use scope_client::{
    chain::{AccountData, Chain, ChainError, Commitment},
    journal::{JOURNAL, Record},
    pay::{self, PayError, PayOptions, SourceKeys},
    testkit::{Harness, SOURCE_FUNDS, SvmChain},
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::Hash;
use solana_transaction::versioned::VersionedTransaction;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use spl_token_2022_interface::{
    extension::{
        BaseStateWithExtensions, StateWithExtensions,
        confidential_transfer::ConfidentialTransferAccount,
    },
    state::Account,
};
use std::{cell::Cell, path::PathBuf, time::Duration};

struct Recipient {
    account: Address,
    keys: ElGamalKeypair,
}

fn recipients(h: &mut Harness, n: usize) -> Vec<Recipient> {
    (0..n)
        .map(|_| {
            let owner = Keypair::new();
            let keys = ElGamalKeypair::new_rand();
            let account = h.plain_confidential_account(&owner, &keys, &AeKey::new_rand());
            Recipient { account, keys }
        })
        .collect()
}

/// Row i pays i + 1 whole tokens (6 decimals).
fn input(rs: &[Recipient]) -> String {
    let mut s = String::from("recipient,amount\n");
    for (i, r) in rs.iter().enumerate() {
        s += &format!("{},{}\n", r.account, i + 1);
    }
    s
}

fn pending(h: &Harness, r: &Recipient) -> u64 {
    let account = h.svm.get_account(&r.account).expect("recipient");
    let state = StateWithExtensions::<Account>::unpack(&account.data).expect("unpack");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    let lo: ElGamalCiphertext = ext.pending_balance_lo.try_into().expect("lo");
    let hi: ElGamalCiphertext = ext.pending_balance_hi.try_into().expect("hi");
    let lo = r.keys.secret().decrypt_u32(&lo).expect("lo decrypts");
    let hi = r.keys.secret().decrypt_u32(&hi).expect("hi decrypts");
    lo + (hi << 16)
}

fn opts(name: &str) -> PayOptions {
    let runs_dir = std::env::temp_dir().join(format!("scope-pay-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&runs_dir);
    PayOptions {
        runs_dir,
        max_price_per_cu: 1_000_000,
        poll: Duration::ZERO,
        again: false,
        log: |_| {},
    }
}

/// Takes the key fields, not the harness, so it can run while `h.svm` is lent out.
fn keys(elgamal: &ElGamalKeypair, ae: &AeKey) -> SourceKeys {
    SourceKeys {
        elgamal: elgamal.clone(),
        ae: ae.clone(),
    }
}

fn start(h: &mut Harness, input: &str, o: &PayOptions) -> Result<pay::Report, PayError> {
    let (mint, source, k) = (h.mint, h.source, keys(&h.source_elgamal, &h.source_ae));
    pay::start(
        SvmChain::new(&mut h.svm),
        &h.payer,
        k,
        mint,
        source,
        input.as_bytes(),
        o,
    )
}

fn journal(o: &PayOptions, run_id: &str) -> Vec<Record> {
    std::fs::read_to_string(o.runs_dir.join(run_id).join(JOURNAL))
        .expect("journal")
        .lines()
        .map(|l| serde_json::from_str(l).expect("record"))
        .collect()
}

fn only_run(o: &PayOptions) -> String {
    let mut runs: Vec<PathBuf> = std::fs::read_dir(&o.runs_dir)
        .expect("runs dir")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(runs.len(), 1);
    runs.pop()
        .expect("one run")
        .file_name()
        .expect("name")
        .to_string_lossy()
        .into_owned()
}

fn assert_paid_once(h: &Harness, rs: &[Recipient]) {
    for (i, r) in rs.iter().enumerate() {
        assert_eq!(pending(h, r), (i as u64 + 1) * 1_000_000, "row {i}");
    }
}

#[test]
fn pays_every_row_once_in_shuffled_order() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 5);
    let o = opts("happy");
    let report = start(&mut h, &input(&rs), &o).expect("run");
    assert_eq!(report.paid.len(), 5);
    assert_paid_once(&h, &rs);
    let records = journal(&o, &report.run_id);
    let Record::Run { order, .. } = &records[0] else {
        panic!("header first")
    };
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, [0, 1, 2, 3, 4]);
    assert_eq!(records.last(), Some(&Record::Done));
    // Amounts would appear in the transaction bytes as little-endian u64.
    let text =
        std::fs::read_to_string(o.runs_dir.join(&report.run_id).join(JOURNAL)).expect("journal");
    for i in 1..=5u64 {
        let le = scope_client::journal::hex(&(i * 1_000_000).to_le_bytes());
        assert!(!text.contains(&le), "plaintext amount {i} in the journal");
    }
}

#[test]
fn pays_through_a_mint_with_an_auditor() {
    let auditor = ElGamalKeypair::new_rand();
    let mut h = Harness::with_auditor(Some(auditor.pubkey()));
    let rs = recipients(&mut h, 2);
    start(&mut h, &input(&rs), &opts("auditor")).expect("run");
    assert_paid_once(&h, &rs);
}

#[test]
fn refuses_bad_recipients_and_overspend_before_sending() {
    let mut h = Harness::new();
    let o = opts("preflight");
    let missing = format!("{},1\n", Address::new_unique());
    assert!(matches!(
        start(&mut h, &missing, &o),
        Err(PayError::Recipient { .. })
    ));
    let not_account = format!("{},1\n", h.mint);
    assert!(matches!(
        start(&mut h, &not_account, &o),
        Err(PayError::Recipient { .. })
    ));
    let rs = recipients(&mut h, 1);
    let whole = SOURCE_FUNDS / 1_000_000;
    let overspend = format!("{},{}\n", rs[0].account, whole + 1);
    assert!(matches!(
        start(&mut h, &overspend, &o),
        Err(PayError::Insufficient { .. })
    ));
    assert!(!o.runs_dir.exists(), "no run was created");
}

#[test]
fn refuses_foreign_source_keys() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let (mint, source) = (h.mint, h.source);
    let wrong = SourceKeys {
        elgamal: ElGamalKeypair::new_rand(),
        ae: AeKey::new_rand(),
    };
    let result = pay::start(
        SvmChain::new(&mut h.svm),
        &h.payer,
        wrong,
        mint,
        source,
        input(&rs).as_bytes(),
        &opts("keys"),
    );
    assert!(matches!(result, Err(PayError::Source { .. })));
}

#[test]
fn refuses_the_same_input_twice_unless_again() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let mut o = opts("again");
    let text = input(&rs);
    start(&mut h, &text, &o).expect("first run");
    assert!(matches!(
        start(&mut h, &text, &o),
        Err(PayError::DuplicateInput { .. })
    ));
    o.again = true;
    start(&mut h, &text, &o).expect("second run with --again");
    assert_eq!(pending(&h, &rs[0]), 2_000_000);
}

#[test]
fn rebuilds_only_after_the_attempt_expires() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let o = opts("expire");
    let (mint, source, k) = (h.mint, h.source, keys(&h.source_elgamal, &h.source_ae));
    let mut chain = SvmChain::new(&mut h.svm);
    // Every send of the first attempt is lost; it expires after four polls.
    chain.drop_sends = 4;
    let report =
        pay::start(chain, &h.payer, k, mint, source, input(&rs).as_bytes(), &o).expect("run");
    let attempts = journal(&o, &report.run_id)
        .iter()
        .filter(|r| matches!(r, Record::Attempt { .. }))
        .count();
    assert_eq!(attempts, 2);
    assert_paid_once(&h, &rs);
}

#[derive(Clone, Copy, PartialEq)]
enum KillAt {
    /// The attempt is journaled, its transaction never leaves.
    BeforeSend(usize),
    /// The transaction lands, the journal never hears of it.
    AfterSend(usize),
    /// Between rows: the next attempt is never journaled.
    Simulate(usize),
}

/// Dies at one point; every call after that fails, like a killed process.
struct Killer<C> {
    inner: C,
    at: KillAt,
    sends: Cell<usize>,
    simulations: Cell<usize>,
    dead: Cell<bool>,
}

impl<C: Chain> Killer<C> {
    fn new(inner: C, at: KillAt) -> Self {
        Self {
            inner,
            at,
            sends: Cell::new(0),
            simulations: Cell::new(0),
            dead: Cell::new(false),
        }
    }

    fn alive(&self) -> Result<(), ChainError> {
        if self.dead.get() {
            return Err(ChainError("killed".into()));
        }
        Ok(())
    }
}

impl<C: Chain> Chain for Killer<C> {
    fn account(&self, a: &Address, c: Commitment) -> Result<Option<AccountData>, ChainError> {
        self.alive()?;
        self.inner.account(a, c)
    }

    fn blockhash(&self) -> Result<(Hash, u64), ChainError> {
        self.alive()?;
        self.inner.blockhash()
    }

    fn finalized_block_height(&self) -> Result<u64, ChainError> {
        self.alive()?;
        self.inner.finalized_block_height()
    }

    fn simulate(&self, tx: &VersionedTransaction) -> Result<Result<(), String>, ChainError> {
        self.alive()?;
        self.simulations.set(self.simulations.get() + 1);
        if self.at == KillAt::Simulate(self.simulations.get()) {
            self.dead.set(true);
            self.alive()?;
        }
        self.inner.simulate(tx)
    }

    fn send(&mut self, tx: &VersionedTransaction) -> Result<(), ChainError> {
        self.alive()?;
        self.sends.set(self.sends.get() + 1);
        let n = self.sends.get();
        if self.at == KillAt::BeforeSend(n) {
            self.dead.set(true);
            return self.alive();
        }
        let sent = self.inner.send(tx);
        if self.at == KillAt::AfterSend(n) {
            self.dead.set(true);
        }
        sent
    }

    fn recent_prices(&self) -> Result<Vec<u64>, ChainError> {
        self.alive()?;
        self.inner.recent_prices()
    }
}

/// Kills a 4-row run at `at`, resumes it, and checks every row was paid exactly once.
fn kill_and_resume(at: KillAt, name: &str) {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 4);
    let o = opts(name);
    let (mint, source) = (h.mint, h.source);
    let killed = pay::start(
        Killer::new(SvmChain::new(&mut h.svm), at),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        input(&rs).as_bytes(),
        &o,
    );
    assert!(
        matches!(killed, Err(PayError::Chain(_))),
        "killed, got {killed:?}"
    );
    let run_id = only_run(&o);
    let report = pay::resume(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        &run_id,
        &o,
    )
    .expect("resume");
    assert_eq!(report.paid.len(), 4);
    assert_paid_once(&h, &rs);
    let again = pay::resume(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        &run_id,
        &o,
    )
    .expect("resuming a finished run");
    assert_eq!(again.paid.len(), 4);
    assert_paid_once(&h, &rs);
}

#[test]
fn resumes_after_kill_before_send() {
    kill_and_resume(KillAt::BeforeSend(2), "kill-before-send");
}

#[test]
fn resumes_after_kill_after_send() {
    kill_and_resume(KillAt::AfterSend(3), "kill-after-send");
}

#[test]
fn resumes_after_kill_between_rows() {
    kill_and_resume(KillAt::Simulate(3), "kill-between-rows");
}

#[test]
fn halts_when_the_source_moves_outside_the_run() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 2);
    let o = opts("halt");
    let (mint, source) = (h.mint, h.source);
    let killed = pay::start(
        Killer::new(SvmChain::new(&mut h.svm), KillAt::BeforeSend(1)),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        input(&rs).as_bytes(),
        &o,
    );
    assert!(killed.is_err());
    // The owner spends from the source elsewhere while the run is down.
    let outside = pay::start(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        format!("{},7\n", rs[1].account).as_bytes(),
        &opts("halt-outside"),
    );
    outside.expect("outside payment");
    let run_id = only_run(&o);
    let resumed = pay::resume(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        &run_id,
        &o,
    );
    assert!(
        matches!(resumed, Err(PayError::Halted(_))),
        "got {resumed:?}"
    );
}

#[test]
fn a_second_writer_is_refused() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let o = opts("lock");
    start(&mut h, &input(&rs), &o).expect("run");
    let run_id = only_run(&o);
    let dir = o.runs_dir.join(&run_id);
    let _held = scope_client::journal::Journal::open(&dir).expect("hold the lock");
    let second = pay::resume(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        &run_id,
        &o,
    );
    assert!(matches!(second, Err(PayError::Journal(_))));
}

#[test]
fn source_keys_match_spl_token_cli() {
    let owner = Keypair::new();
    let ours = SourceKeys::from_signer(&owner).expect("keys");
    // spl-token-cli 5.6.1 `command.rs`: `derive_confidential_keys(&*owner_signer, b"")`.
    let (cli, _) = solana_zk_sdk::encryption::derivation::derive_confidential_keys(&owner, b"")
        .expect("zk-sdk derivation");
    assert_eq!(ours.elgamal.pubkey(), cli.pubkey());
    let other = SourceKeys::from_signer(&Keypair::new()).expect("keys");
    assert_ne!(ours.elgamal.pubkey(), other.elgamal.pubkey());
}
