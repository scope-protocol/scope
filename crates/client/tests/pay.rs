//! Payer engine, plain and stealth rows, against LiteSVM.

use scope_client::{
    address::token_2022,
    address::token_account_seed_str,
    chain::{AccountData, Chain, ChainError, Commitment},
    ix::create_prefunded_with_seed,
    journal::{JOURNAL, Record},
    pay::{self, PayError, PayOptions, SourceKeys},
    scan,
    testkit::{Harness, SOURCE_FUNDS, SvmChain},
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::Hash;
use solana_signer::Signer;
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
use stealth_keygen::RecipientSecretKeys;

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
        .filter(|p| p.is_dir())
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
    let runs = std::fs::read_dir(&o.runs_dir)
        .map(|d| d.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0);
    assert_eq!(runs, 0, "no run was created");
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

    fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
        self.alive()?;
        self.inner.genesis_hash()
    }

    fn rent(&self, space: usize) -> Result<u64, ChainError> {
        self.alive()?;
        self.inner.rent(space)
    }
    fn landed_error(
        &self,
        signature: &solana_signature::Signature,
    ) -> Result<Option<String>, ChainError> {
        self.inner.landed_error(signature)
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
fn resume_does_not_preflight_a_row_that_already_landed() {
    let mut h = Harness::new();
    let owner = Keypair::new();
    let keys_r = ElGamalKeypair::new_rand();
    let account = h.plain_confidential_account(&owner, &keys_r, &AeKey::new_rand());
    let rs = [Recipient {
        account,
        keys: keys_r,
    }];
    let o = opts("landed-then-closed");
    let (mint, source) = (h.mint, h.source);
    let killed = pay::start(
        Killer::new(SvmChain::new(&mut h.svm), KillAt::AfterSend(1)),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        input(&rs).as_bytes(),
        &o,
    );
    assert!(matches!(killed, Err(PayError::Chain(_))), "got {killed:?}");
    // The recipient stops taking credits after the payment landed; preflight would refuse it.
    let disable = spl_token_2022_interface::extension::confidential_transfer::instruction::disable_confidential_credits(
        &token_2022(),
        &account,
        &owner.pubkey(),
        &[],
    )
    .expect("disable");
    h.send(&[disable], &[&owner]).expect("disable credits");
    let report = pay::resume(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        &only_run(&o),
        &o,
    )
    .expect("resume");
    assert_eq!(report.paid.len(), 1);
    assert_paid_once(&h, &rs);
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

#[test]
fn halts_when_a_landed_row_is_not_on_chain() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 3);
    let o = opts("halt-landed");
    let (mint, source) = (h.mint, h.source);
    // Row one lands and is recorded; the run dies before the second attempt.
    let killed = pay::start(
        Killer::new(SvmChain::new(&mut h.svm), KillAt::Simulate(2)),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        input(&rs).as_bytes(),
        &o,
    );
    assert!(killed.is_err());
    // The source moves, as it would if the landed row's slot were dropped.
    pay::start(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        format!("{},7\n", rs[0].account).as_bytes(),
        &opts("halt-landed-outside"),
    )
    .expect("outside payment");
    let resumed = pay::resume(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        &only_run(&o),
        &o,
    );
    assert!(
        matches!(resumed, Err(PayError::Halted(_))),
        "got {resumed:?}"
    );
}

#[test]
fn a_concurrent_start_is_refused() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let o = opts("runs-lock");
    let _held = scope_client::journal::lock_dir(&o.runs_dir).expect("lock");
    assert!(matches!(
        start(&mut h, &input(&rs), &o),
        Err(PayError::Journal(_))
    ));
}

/// Test recipients differ in their spend key and share one scan key.
fn stealth_recipient(spend: u8) -> RecipientSecretKeys {
    let mut bytes = [2; 64];
    bytes[..32].fill(0);
    bytes[0] = spend;
    RecipientSecretKeys::from_bytes(bytes).expect("public test secrets")
}

/// What the recipient's own scan finds: (one-time token account, confidential amount).
fn found(h: &mut Harness, recipient: &RecipientSecretKeys) -> Vec<(Address, u64)> {
    scan::scan(&SvmChain::new(&mut h.svm), recipient, None)
        .expect("scan")
        .payments
        .iter()
        .map(|p| (p.token_account, p.amount))
        .collect()
}

/// Rows alternate plain and stealth; row i pays i + 1 whole tokens.
fn mixed_input(plain: &[Recipient], stealth: &[RecipientSecretKeys]) -> String {
    let mut s = String::from("recipient,amount\n");
    for i in 0..plain.len() + stealth.len() {
        let recipient = if i % 2 == 0 {
            plain[i / 2].account.to_string()
        } else {
            stealth[i / 2].derive_public_keys().to_meta_address()
        };
        s += &format!("{recipient},{}\n", i + 1);
    }
    s
}

/// Every row paid exactly once: plain pending balances, and one found payment per
/// stealth recipient with its row's amount.
fn assert_mixed_paid_once(h: &mut Harness, plain: &[Recipient], stealth: &[RecipientSecretKeys]) {
    for (k, r) in plain.iter().enumerate() {
        assert_eq!(pending(h, r), (2 * k as u64 + 1) * 1_000_000, "plain {k}");
    }
    for (k, r) in stealth.iter().enumerate() {
        let payments = found(h, r);
        assert_eq!(payments.len(), 1, "stealth {k}: {payments:?}");
        assert_eq!(payments[0].1, (2 * k as u64 + 2) * 1_000_000, "stealth {k}");
    }
}

#[test]
fn pays_plain_and_stealth_rows_and_each_recipient_finds_its_payment() {
    let mut h = Harness::new();
    let plain = recipients(&mut h, 2);
    let stealth = [stealth_recipient(1), stealth_recipient(2)];
    let o = opts("mixed");
    let report = start(&mut h, &mixed_input(&plain, &stealth), &o).expect("run");
    assert_eq!(report.paid.len(), 4);
    assert_mixed_paid_once(&mut h, &plain, &stealth);
    for (k, r) in stealth.iter().enumerate() {
        let account = found(&mut h, r)[0].0;
        let paid = report
            .paid
            .iter()
            .find(|p| p.row == 2 * k + 1)
            .expect("row");
        assert_eq!(
            paid.recipient, account,
            "the report names the one-time account"
        );
    }
}

fn kill_and_resume_mixed(at: KillAt, name: &str) {
    let mut h = Harness::new();
    let plain = recipients(&mut h, 2);
    let stealth = [stealth_recipient(3), stealth_recipient(4)];
    let o = opts(name);
    let (mint, source) = (h.mint, h.source);
    let killed = pay::start(
        Killer::new(SvmChain::new(&mut h.svm), at),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        mixed_input(&plain, &stealth).as_bytes(),
        &o,
    );
    assert!(
        matches!(killed, Err(PayError::Chain(_))),
        "killed, got {killed:?}"
    );
    let report = pay::resume(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        &only_run(&o),
        &o,
    )
    .expect("resume");
    assert_eq!(report.paid.len(), 4);
    assert_mixed_paid_once(&mut h, &plain, &stealth);
}

#[test]
fn stealth_rows_resume_after_kill_before_send() {
    kill_and_resume_mixed(KillAt::BeforeSend(2), "stealth-kill-before-send");
}

#[test]
fn stealth_rows_resume_after_kill_after_send() {
    kill_and_resume_mixed(KillAt::AfterSend(2), "stealth-kill-after-send");
}

#[test]
fn stealth_rows_resume_after_kill_between_rows() {
    kill_and_resume_mixed(KillAt::Simulate(3), "stealth-kill-between-rows");
}

#[test]
fn create_with_seed_refuses_a_prefunded_address_and_the_fallback_does_not() {
    let mut h = Harness::new();
    let case = h.stealth_case();
    h.svm
        .airdrop(&case.token_account, 1_000_000)
        .expect("prefund");
    assert!(
        h.send(&case.setup, &[]).is_err(),
        "CreateAccountWithSeed refuses an address holding lamports"
    );
    let account =
        spl_token_2022_interface::extension::ExtensionType::try_calculate_account_len::<Account>(
            &[spl_token_2022_interface::extension::ExtensionType::ConfidentialTransferAccount],
        )
        .expect("len");
    let mut setup = case.setup.clone();
    setup.splice(
        0..1,
        create_prefunded_with_seed(
            &h.payer.pubkey(),
            &case.token_account,
            &token_account_seed_str(&case.ephemeral),
            h.svm.minimum_balance_for_rent_exemption(account),
            1_000_000,
            account as u64,
            &token_2022(),
        ),
    );
    h.send(&setup, &[])
        .expect("the fallback creates and announces it");
}

/// Loses the first broadcast, then sends SOL to the one-time address it revealed.
struct Prefunder<'a> {
    inner: SvmChain<'a>,
    done: bool,
}

impl Chain for Prefunder<'_> {
    fn account(&self, a: &Address, c: Commitment) -> Result<Option<AccountData>, ChainError> {
        self.inner.account(a, c)
    }
    fn blockhash(&self) -> Result<(Hash, u64), ChainError> {
        self.inner.blockhash()
    }
    fn finalized_block_height(&self) -> Result<u64, ChainError> {
        self.inner.finalized_block_height()
    }
    fn simulate(&self, tx: &VersionedTransaction) -> Result<Result<(), String>, ChainError> {
        self.inner.simulate(tx)
    }
    fn send(&mut self, tx: &VersionedTransaction) -> Result<(), ChainError> {
        if self.done {
            return self.inner.send(tx);
        }
        self.done = true;
        let keys = tx.message.static_account_keys();
        let create = &tx.message.instructions()[0];
        let token_account = keys[usize::from(create.accounts[1])];
        self.inner
            .svm
            .airdrop(&token_account, 1_000_000)
            .expect("prefund");
        Ok(())
    }
    fn recent_prices(&self) -> Result<Vec<u64>, ChainError> {
        self.inner.recent_prices()
    }
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
        self.inner.genesis_hash()
    }
    fn rent(&self, space: usize) -> Result<u64, ChainError> {
        self.inner.rent(space)
    }
    fn landed_error(
        &self,
        signature: &solana_signature::Signature,
    ) -> Result<Option<String>, ChainError> {
        self.inner.landed_error(signature)
    }
}

#[test]
fn a_prefunded_one_time_address_still_gets_paid() {
    let mut h = Harness::new();
    let alice = stealth_recipient(5);
    let o = opts("prefunded");
    let (mint, source) = (h.mint, h.source);
    let input = format!("{},1\n", alice.derive_public_keys().to_meta_address());
    let report = pay::start(
        Prefunder {
            inner: SvmChain::new(&mut h.svm),
            done: false,
        },
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        input.as_bytes(),
        &o,
    )
    .expect("run");
    let attempts = journal(&o, &report.run_id)
        .iter()
        .filter(|r| matches!(r, Record::Attempt { .. }))
        .count();
    assert_eq!(attempts, 2, "the lost attempt expired and was rebuilt");
    let payments = found(&mut h, &alice);
    assert_eq!(payments.len(), 1);
    assert_eq!(payments[0].1, 1_000_000);
}

#[test]
fn refuses_stealth_rows_on_a_mint_that_does_not_auto_approve() {
    use spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensionsMut, StateWithExtensionsMut,
            confidential_transfer::ConfidentialTransferMint,
        },
        state::Mint,
    };
    let mut h = Harness::new();
    let mut mint = h.svm.get_account(&h.mint).expect("mint");
    {
        let mut state = StateWithExtensionsMut::<Mint>::unpack(&mut mint.data).expect("unpack");
        state
            .get_extension_mut::<ConfidentialTransferMint>()
            .expect("ct mint")
            .auto_approve_new_accounts = false.into();
    }
    h.svm.set_account(h.mint, mint).expect("patch mint");
    let input = format!(
        "{},1\n",
        stealth_recipient(6).derive_public_keys().to_meta_address()
    );
    let result = start(&mut h, &input, &opts("no-auto-approve"));
    assert!(
        matches!(result, Err(PayError::Mint { .. })),
        "got {result:?}"
    );
}

#[test]
fn a_paid_stealth_row_sweeps_to_the_recipient_and_returns_both_rents_to_the_payer() {
    use scope_client::sweep::{self, SweepOptions};
    use solana_zk_sdk::encryption::derivation::derive_confidential_keys;
    let mut h = Harness::new();
    let alice = stealth_recipient(7);
    let o = opts("end-to-end");
    let input = format!("{},2.5\n", alice.derive_public_keys().to_meta_address());
    start(&mut h, &input, &o).expect("pay");

    let found = scan::scan(&SvmChain::new(&mut h.svm), &alice, None).expect("scan");
    let payment = &found.payments[0];
    let lamports = |h: &Harness, a: &Address| h.svm.get_account(a).map_or(0, |a| a.lamports);
    let rents = lamports(&h, &payment.token_account) + lamports(&h, &payment.announcement);
    let payer_before = lamports(&h, &h.payer.pubkey());

    let report = sweep::sweep(
        &mut SvmChain::new(&mut h.svm),
        &alice,
        &payment.announcement,
        &SweepOptions {
            poll: Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("sweep");
    assert_eq!(report.reclaimed, Some(true));
    assert!(report.finalized_signature.is_some());
    assert_eq!(
        lamports(&h, &h.payer.pubkey()),
        payer_before + rents,
        "the payer gets back the rent of both accounts"
    );

    let seed = alice
        .derive_sweep_destination(&payment.ephemeral, &report.token_account.to_bytes())
        .expect("destination seed");
    let owner = Keypair::new_from_array(*seed.as_bytes());
    assert_eq!(owner.pubkey(), report.destination_owner);
    let (keys, _) = derive_confidential_keys(&owner, b"").expect("wallet keys");
    let account = h.svm.get_account(&report.destination).expect("D");
    let state = StateWithExtensions::<Account>::unpack(&account.data).expect("unpack");
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .expect("ct");
    let lo: ElGamalCiphertext = ext.pending_balance_lo.try_into().expect("lo");
    let hi: ElGamalCiphertext = ext.pending_balance_hi.try_into().expect("hi");
    let lo = keys.secret().decrypt_u32(&lo).expect("lo");
    let hi = keys.secret().decrypt_u32(&hi).expect("hi");
    assert_eq!(
        lo + (hi << 16),
        2_500_000,
        "D holds the amount, under the owner's wallet keys"
    );
}

/// Fails simulation of anything that calls our program, so a sweep falls back to its
/// transfer-only version and leaves the announcement open.
struct NoReclaim<'a>(SvmChain<'a>);

impl Chain for NoReclaim<'_> {
    fn account(&self, a: &Address, c: Commitment) -> Result<Option<AccountData>, ChainError> {
        self.0.account(a, c)
    }
    fn blockhash(&self) -> Result<(Hash, u64), ChainError> {
        self.0.blockhash()
    }
    fn finalized_block_height(&self) -> Result<u64, ChainError> {
        self.0.finalized_block_height()
    }
    fn simulate(&self, tx: &VersionedTransaction) -> Result<Result<(), String>, ChainError> {
        let keys = tx.message.static_account_keys();
        let calls_scope = tx.message.instructions().iter().any(|ix| {
            keys[usize::from(ix.program_id_index)] == scope_client::address::program_id()
        });
        if calls_scope {
            return Ok(Err("reclaim refused in this test".into()));
        }
        self.0.simulate(tx)
    }
    fn send(&mut self, tx: &VersionedTransaction) -> Result<(), ChainError> {
        self.0.send(tx)
    }
    fn recent_prices(&self) -> Result<Vec<u64>, ChainError> {
        self.0.recent_prices()
    }
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
        self.0.genesis_hash()
    }
    fn rent(&self, space: usize) -> Result<u64, ChainError> {
        self.0.rent(space)
    }
    fn landed_error(
        &self,
        signature: &solana_signature::Signature,
    ) -> Result<Option<String>, ChainError> {
        self.0.landed_error(signature)
    }
}

impl scope_client::chain::RecipientChain for NoReclaim<'_> {
    fn set_deadline(&mut self, deadline: Option<std::time::Instant>) {
        self.0.set_deadline(deadline)
    }
    fn announcements(&self) -> Result<Vec<(Address, AccountData)>, ChainError> {
        self.0.announcements()
    }
    fn registry_entries(&self) -> Result<Vec<(Address, AccountData)>, ChainError> {
        self.0.registry_entries()
    }
    fn fee(&self, message: &solana_message::VersionedMessage) -> Result<u64, ChainError> {
        self.0.fee(message)
    }
    fn finalized_status(
        &self,
        signature: &solana_signature::Signature,
    ) -> Result<scope_client::chain::FinalizedStatus, ChainError> {
        self.0.finalized_status(signature)
    }
}

#[test]
fn status_and_reclaim_follow_a_stealth_row_from_paid_to_reclaimed() {
    use pay::StealthState::{Open, Reclaimed, Swept};
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = stealth_recipient(8);
    let plain = recipients(&mut h, 1);
    let o = opts("status");
    let input = format!(
        "{},1\n{},2\n",
        plain[0].account,
        alice.derive_public_keys().to_meta_address()
    );
    let run_id = start(&mut h, &input, &o).expect("pay").run_id;
    let states = |h: &mut Harness| {
        pay::status(&SvmChain::new(&mut h.svm), &h.payer, &run_id, &o)
            .expect("status")
            .iter()
            .map(|s| (s.row, s.state))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        states(&mut h),
        [(1, Open)],
        "only the stealth row is listed"
    );

    let announcement = found_announcement(&mut h, &alice);
    let report = sweep::sweep(
        &mut NoReclaim(SvmChain::new(&mut h.svm)),
        &alice,
        &announcement,
        &SweepOptions {
            poll: Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("transfer-only sweep");
    assert_eq!(report.reclaimed, Some(false));
    assert_eq!(states(&mut h), [(1, Swept)]);

    let lamports = |h: &Harness, a: &Address| h.svm.get_account(a).map_or(0, |a| a.lamports);
    let token_account = pay::status(&SvmChain::new(&mut h.svm), &h.payer, &run_id, &o)
        .expect("status")[0]
        .token_account;
    let rents = lamports(&h, &token_account) + lamports(&h, &announcement);
    let before = lamports(&h, &h.payer.pubkey());
    let after_reclaim =
        pay::reclaim(&mut SvmChain::new(&mut h.svm), &h.payer, &run_id, &o).expect("reclaim");
    assert_eq!(after_reclaim[0].state, Reclaimed);
    assert_eq!(
        lamports(&h, &h.payer.pubkey()),
        before + rents - scope_client::fees::LAMPORTS_PER_SIGNATURE,
        "both rents back, less one signature"
    );
    pay::reclaim(&mut SvmChain::new(&mut h.svm), &h.payer, &run_id, &o)
        .expect("reclaiming again is a no-op");
}

fn found_announcement(h: &mut Harness, recipient: &RecipientSecretKeys) -> Address {
    scan::scan(&SvmChain::new(&mut h.svm), recipient, None)
        .expect("scan")
        .payments[0]
        .announcement
}

#[test]
fn status_shows_an_unswept_row_as_open_and_cannot_reclaim_it() {
    let mut h = Harness::new();
    let o = opts("status-open");
    let input = format!(
        "{},1\n",
        stealth_recipient(9).derive_public_keys().to_meta_address()
    );
    let run_id = start(&mut h, &input, &o).expect("pay").run_id;
    let after = pay::reclaim(&mut SvmChain::new(&mut h.svm), &h.payer, &run_id, &o)
        .expect("nothing to reclaim");
    assert_eq!(after[0].state, pay::StealthState::Open);
}

#[test]
fn status_tells_unpaid_from_unresolved_and_resume_settles_it() {
    let mut h = Harness::new();
    let input = format!(
        "{},1\n",
        stealth_recipient(10).derive_public_keys().to_meta_address()
    );
    let (mint, source) = (h.mint, h.source);
    for (at, expected) in [
        (KillAt::Simulate(1), pay::StealthState::Unpaid),
        (KillAt::BeforeSend(1), pay::StealthState::Unresolved),
    ] {
        let o = opts(&format!("status-kill-at-{expected:?}"));
        let killed = pay::start(
            Killer::new(SvmChain::new(&mut h.svm), at),
            &h.payer,
            keys(&h.source_elgamal, &h.source_ae),
            mint,
            source,
            input.as_bytes(),
            &o,
        );
        assert!(killed.is_err());
        let run_id = only_run(&o);
        let rows = pay::status(&SvmChain::new(&mut h.svm), &h.payer, &run_id, &o).expect("status");
        assert_eq!(rows[0].state, expected, "killed at the {expected:?} point");
        if expected == pay::StealthState::Unresolved {
            pay::resume(
                SvmChain::new(&mut h.svm),
                &h.payer,
                keys(&h.source_elgamal, &h.source_ae),
                &run_id,
                &o,
            )
            .expect("resume");
            let rows =
                pay::status(&SvmChain::new(&mut h.svm), &h.payer, &run_id, &o).expect("status");
            assert_eq!(rows[0].state, pay::StealthState::Open, "resume paid it");
        }
    }
}

/// The run's signed transactions from its journal, with LiteSVM's record of which landed.
struct JournalArchive(
    std::collections::HashMap<solana_signature::Signature, (VersionedTransaction, bool)>,
);

impl JournalArchive {
    fn new(h: &Harness, o: &PayOptions, run_id: &str) -> Self {
        let mut map = std::collections::HashMap::new();
        for record in journal(o, run_id) {
            if let Record::Attempt { tx, .. } = record {
                let bytes = scope_client::journal::unhex(&tx).expect("hex");
                let tx: VersionedTransaction = wincode::deserialize(&bytes).expect("tx");
                let landed = matches!(h.svm.get_transaction(&tx.signatures[0]), Some(Ok(_)));
                map.insert(tx.signatures[0], (tx, landed));
            }
        }
        Self(map)
    }
}

impl scope_client::receipt::TransactionArchive for JournalArchive {
    fn genesis_hash(&self) -> Result<[u8; 32], ChainError> {
        Ok([42; 32])
    }
    fn transaction(
        &self,
        signature: &solana_signature::Signature,
    ) -> Result<scope_client::receipt::ArchivedTransaction, ChainError> {
        let (transaction, succeeded) = self
            .0
            .get(signature)
            .cloned()
            .ok_or_else(|| ChainError("not found".into()))?;
        Ok(scope_client::receipt::ArchivedTransaction {
            transaction,
            succeeded,
        })
    }
}

/// A mixed run's plain and stealth rows, their recipients, and the archive of its transactions.
fn paid_run(
    name: &str,
) -> (
    Harness,
    PayOptions,
    String,
    Vec<Recipient>,
    RecipientSecretKeys,
) {
    let mut h = Harness::new();
    let plain = recipients(&mut h, 1);
    let alice = stealth_recipient(11);
    let o = opts(name);
    let input = format!(
        "{},1.25\n{},3.5\n",
        plain[0].account,
        alice.derive_public_keys().to_meta_address()
    );
    let run_id = start(&mut h, &input, &o).expect("pay").run_id;
    (h, o, run_id, plain, alice)
}

#[test]
fn payer_receipts_prove_plain_and_stealth_amounts() {
    use scope_client::receipt::{self, Receipt, ReceiptError};
    let (mut h, o, run_id, plain, alice) = paid_run("receipt-payer");
    let archive = JournalArchive::new(&h, &o, &run_id);
    let disclose = |h: &mut Harness, row| {
        pay::disclose(&SvmChain::new(&mut h.svm), &h.payer, &run_id, row, &o).expect("disclose")
    };

    let plain_receipt = disclose(&mut h, 0);
    let verified = receipt::verify(&archive, &plain_receipt).expect("plain receipt");
    assert_eq!(verified.amount, 1_250_000);
    assert_eq!(verified.destination, plain[0].account);
    assert_eq!(verified.payer, h.payer.pubkey());

    let stealth_receipt = disclose(&mut h, 1);
    let verified = receipt::verify(&archive, &stealth_receipt).expect("stealth receipt");
    assert_eq!(verified.amount, 3_500_000);
    assert_eq!(verified.destination, found(&mut h, &alice)[0].0);

    let Receipt::Opening { amount, .. } = &stealth_receipt else {
        panic!("payer receipts carry openings");
    };
    let mut inflated = stealth_receipt.clone();
    if let Receipt::Opening { amount: a, .. } = &mut inflated {
        *a = amount + 1;
    }
    assert!(matches!(
        receipt::verify(&archive, &inflated),
        Err(ReceiptError::Opening)
    ));
    let mut elsewhere = stealth_receipt.clone();
    if let Receipt::Opening { cluster, .. } = &mut elsewhere {
        *cluster = "00".repeat(32);
    }
    assert!(matches!(
        receipt::verify(&archive, &elsewhere),
        Err(ReceiptError::Cluster)
    ));

    // A node that answers with another transaction, or alters the one asked for, is caught.
    let signature = |r: &Receipt| match r {
        Receipt::Opening { signature, .. } | Receipt::AccountKey { signature, .. } => signature
            .parse::<solana_signature::Signature>()
            .expect("signature"),
    };
    let (plain_sig, stealth_sig) = (signature(&plain_receipt), signature(&stealth_receipt));
    let mut swapped = JournalArchive(archive.0.clone());
    swapped.0.insert(plain_sig, archive.0[&stealth_sig].clone());
    assert!(matches!(
        receipt::verify(&swapped, &plain_receipt),
        Err(ReceiptError::Unauthenticated)
    ));
    let (tx, landed) = archive.0[&plain_sig].clone();
    let mut bytes = wincode::serialize(&tx).expect("serialize");
    *bytes.last_mut().expect("bytes") ^= 1;
    let altered: VersionedTransaction = wincode::deserialize(&bytes).expect("still parses");
    let mut altered_archive = JournalArchive(archive.0.clone());
    altered_archive.0.insert(plain_sig, (altered, landed));
    assert!(matches!(
        receipt::verify(&altered_archive, &plain_receipt),
        Err(ReceiptError::Unauthenticated)
    ));
}

#[test]
fn recipient_receipts_prove_a_stealth_amount_and_reject_forged_keys() {
    use scope_client::receipt::{self, Receipt, ReceiptError};
    let (mut h, o, run_id, _, alice) = paid_run("receipt-recipient");
    let archive = JournalArchive::new(&h, &o, &run_id);
    let signature: solana_signature::Signature = journal(&o, &run_id)
        .iter()
        .find_map(|r| match r {
            Record::Landed { row: 1, signature } => Some(signature.parse().expect("sig")),
            _ => None,
        })
        .expect("stealth row landed");

    let mine = receipt::disclose_as_recipient(&archive, &alice, &signature).expect("disclose");
    let verified = receipt::verify(&archive, &mine).expect("recipient receipt");
    assert_eq!(verified.amount, 3_500_000);
    assert_eq!(verified.destination, found(&mut h, &alice)[0].0);

    let mut forged = mine.clone();
    if let Receipt::AccountKey { ct_ikm, .. } = &mut forged {
        *ct_ikm = "11".repeat(32);
    }
    assert!(matches!(
        receipt::verify(&archive, &forged),
        Err(ReceiptError::Key)
    ));
    let stranger_keys = RecipientSecretKeys::from_bytes([5; 64]).expect("other scan key");
    let stranger = receipt::disclose_as_recipient(&archive, &stranger_keys, &signature);
    assert!(
        matches!(stranger, Err(ReceiptError::NotOurs)),
        "{stranger:?}"
    );

    // About 1 in 256 strangers matches the 1-byte view tag; search for one, since R is
    // random per run, and check the derived key still refuses it.
    let address = found_announcement(&mut h, &alice);
    let announcement = h.svm.get_account(&address).expect("announcement");
    let note = stealth_keygen::PaymentAnnouncement {
        ephemeral_public_key: announcement.data[4..36].try_into().expect("R"),
        discovery_tag: announcement.data[2],
    };
    let colliding = (0u32..)
        .map(|n| {
            let mut bytes = [3; 64];
            bytes[32..36].copy_from_slice(&n.to_le_bytes());
            RecipientSecretKeys::from_bytes(bytes).expect("stranger")
        })
        .find(|s| matches!(stealth_keygen::recover_payment(s, &note), Ok(Some(_))))
        .expect("a stranger whose tag matches");
    assert!(matches!(
        receipt::disclose_as_recipient(&archive, &colliding, &signature),
        Err(ReceiptError::NotOurs)
    ));
}

#[test]
fn receipts_still_verify_after_the_sweep_closes_every_account() {
    use scope_client::{
        receipt,
        sweep::{self, SweepOptions},
    };
    let (mut h, o, run_id, _, alice) = paid_run("receipt-after-sweep");
    let announcement = found_announcement(&mut h, &alice);
    sweep::sweep(
        &mut SvmChain::new(&mut h.svm),
        &alice,
        &announcement,
        &SweepOptions {
            poll: Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("sweep and reclaim");
    assert!(found(&mut h, &alice).is_empty(), "nothing left to scan");
    let payer_receipt =
        pay::disclose(&SvmChain::new(&mut h.svm), &h.payer, &run_id, 1, &o).expect("disclose");
    let archive = JournalArchive::new(&h, &o, &run_id);
    assert_eq!(
        receipt::verify(&archive, &payer_receipt)
            .expect("verify")
            .amount,
        3_500_000
    );
}

/// The P4 chaos gate: a 20-row run, half plain and half stealth, killed at every send
/// (before and after it leaves) and at every simulation, then resumed; every row must be
/// paid exactly once. About sixty runs, so it is not part of the default suite:
/// `cargo test --locked -p scope-client --test pay chaos -- --ignored`.
#[test]
#[ignore = "sixty full runs; run by hand before a release"]
fn chaos_converges_from_every_kill_point_of_a_20_row_run() {
    const ROWS: usize = 20;
    let mut points = Vec::new();
    for n in 1..=ROWS {
        points.extend([
            KillAt::BeforeSend(n),
            KillAt::AfterSend(n),
            KillAt::Simulate(n),
        ]);
    }
    for (i, at) in points.into_iter().enumerate() {
        let mut h = Harness::new();
        let plain = recipients(&mut h, ROWS / 2);
        let stealth: Vec<RecipientSecretKeys> = (0..ROWS / 2)
            .map(|k| stealth_recipient(20 + k as u8))
            .collect();
        let o = opts(&format!("chaos-{i}"));
        let (mint, source) = (h.mint, h.source);
        let killed = pay::start(
            Killer::new(SvmChain::new(&mut h.svm), at),
            &h.payer,
            keys(&h.source_elgamal, &h.source_ae),
            mint,
            source,
            mixed_input(&plain, &stealth).as_bytes(),
            &o,
        );
        assert!(
            matches!(killed, Err(PayError::Chain(_))),
            "point {i}: {killed:?}"
        );
        let report = pay::resume(
            SvmChain::new(&mut h.svm),
            &h.payer,
            keys(&h.source_elgamal, &h.source_ae),
            &only_run(&o),
            &o,
        )
        .unwrap_or_else(|e| panic!("point {i}: resume failed: {e}"));
        assert_eq!(report.paid.len(), ROWS, "point {i}");
        assert_mixed_paid_once(&mut h, &plain, &stealth);
    }
}

#[test]
fn status_reports_a_landed_but_unrecorded_row_that_was_swept_as_unresolved() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = stealth_recipient(13);
    let o = opts("status-unresolved");
    let input = format!("{},1\n", alice.derive_public_keys().to_meta_address());
    let (mint, source) = (h.mint, h.source);
    let killed = pay::start(
        Killer::new(SvmChain::new(&mut h.svm), KillAt::AfterSend(1)),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        input.as_bytes(),
        &o,
    );
    assert!(
        killed.is_err(),
        "the payment landed, its landed record never written"
    );
    let announcement = found_announcement(&mut h, &alice);
    sweep::sweep(
        &mut SvmChain::new(&mut h.svm),
        &alice,
        &announcement,
        &SweepOptions {
            poll: Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("full sweep closes the announcement");
    let run_id = only_run(&o);
    let rows = pay::status(&SvmChain::new(&mut h.svm), &h.payer, &run_id, &o).expect("status");
    assert_eq!(
        rows[0].state,
        pay::StealthState::Unresolved,
        "not unpaid: paying it again would pay twice"
    );
}

#[test]
fn disclose_refuses_a_run_from_before_derived_openings() {
    let mut h = Harness::new();
    let plain = recipients(&mut h, 1);
    let o = opts("old-run");
    let run_id = start(&mut h, &input(&plain), &o).expect("pay").run_id;
    let path = o.runs_dir.join(&run_id).join(JOURNAL);
    let text = std::fs::read_to_string(&path).expect("journal");
    let (header, rest) = text.split_once('\n').expect("header line");
    let mut header: serde_json::Value = serde_json::from_str(header).expect("json");
    header
        .as_object_mut()
        .expect("object")
        .remove("derived_openings");
    std::fs::write(&path, format!("{header}\n{rest}")).expect("rewrite as an older run");
    let refused = pay::disclose(&SvmChain::new(&mut h.svm), &h.payer, &run_id, 0, &o);
    assert!(
        matches!(&refused, Err(PayError::Halted(why)) if why.contains("predates")),
        "{refused:?}"
    );
}

#[test]
fn reclaim_stops_after_three_lost_attempts() {
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let alice = stealth_recipient(14);
    let o = opts("reclaim-lost");
    let input = format!("{},1\n", alice.derive_public_keys().to_meta_address());
    let run_id = start(&mut h, &input, &o).expect("pay").run_id;
    let announcement = found_announcement(&mut h, &alice);
    sweep::sweep(
        &mut NoReclaim(SvmChain::new(&mut h.svm)),
        &alice,
        &announcement,
        &SweepOptions {
            poll: Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("transfer-only sweep");
    let mut chain = SvmChain::new(&mut h.svm);
    chain.drop_sends = usize::MAX;
    let stopped = pay::reclaim(&mut chain, &h.payer, &run_id, &o);
    assert!(
        matches!(&stopped, Err(PayError::Halted(why)) if why.contains("3 attempts")),
        "{stopped:?}"
    );
}

/// The mint's confidential authority changes its policy after a run started. Token-2022
/// stores an auditor key without checking it, so `bad_auditor` writes bytes that do not parse.
fn set_mint_policy(h: &mut Harness, auto_approve: bool, bad_auditor: bool) {
    let placeholder = *ElGamalKeypair::new_rand().pubkey();
    let authority = h.mint_authority.insecure_clone();
    let ix = spl_token_2022_interface::extension::confidential_transfer::instruction::update_mint(
        &token_2022(),
        &h.mint,
        &authority.pubkey(),
        &[],
        auto_approve,
        bad_auditor.then(|| placeholder.into()),
    )
    .expect("update_mint");
    h.send(&[ix], &[&authority]).expect("mint policy update");
    if bad_auditor {
        let mut account = h.svm.get_account(&h.mint).expect("mint");
        let key: [u8; 32] = placeholder.into();
        let at = account
            .data
            .windows(32)
            .position(|w| w == key)
            .expect("auditor key in the mint");
        account.data[at..at + 32].fill(0xff);
        h.svm.set_account(h.mint, account).expect("set mint");
    }
}

/// One stealth row of `whole` tokens, killed after its transaction was sent.
fn stealth_row_killed_after_send(
    name: &str,
    whole: u64,
) -> (Harness, PayOptions, RecipientSecretKeys) {
    let mut h = Harness::new();
    let alice = stealth_recipient(21);
    let o = opts(name);
    let input = format!("{},{whole}\n", alice.derive_public_keys().to_meta_address());
    let (mint, source) = (h.mint, h.source);
    let killed = pay::start(
        Killer::new(SvmChain::new(&mut h.svm), KillAt::AfterSend(1)),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        input.as_bytes(),
        &o,
    );
    assert!(matches!(killed, Err(PayError::Chain(_))), "got {killed:?}");
    (h, o, alice)
}

fn resume_run(h: &mut Harness, o: &PayOptions) -> Result<pay::Report, PayError> {
    let run_id = only_run(o);
    pay::resume(
        SvmChain::new(&mut h.svm),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        &run_id,
        o,
    )
}

#[test]
fn an_unreadable_earlier_journal_stops_a_second_run_of_the_same_input() {
    use std::os::unix::fs::PermissionsExt;
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let o = opts("unreadable");
    let text = input(&rs);
    let run_id = start(&mut h, &text, &o).expect("first run").run_id;
    let journal = o.runs_dir.join(&run_id).join(JOURNAL);
    let set = |mode| {
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(mode)).expect("chmod")
    };
    set(0o000);
    let second = start(&mut h, &text, &o);
    set(0o600);
    assert!(
        matches!(second, Err(PayError::Journal(_))),
        "got {second:?}"
    );
    assert_eq!(pending(&h, &rs[0]), 1_000_000, "paid once");
}

#[test]
fn a_landed_stealth_row_resumes_after_the_mint_stops_auto_approving() {
    let (mut h, o, alice) = stealth_row_killed_after_send("policy-change", 1);
    set_mint_policy(&mut h, false, false);
    let report = resume_run(&mut h, &o).expect("resume reconciles the landed row");
    assert_eq!(report.paid.len(), 1);
    assert_eq!(found(&mut h, &alice).len(), 1);
    resume_run(&mut h, &o).expect("a finished run resumes under the new policy");
}

#[test]
fn resuming_a_payment_that_nearly_drains_the_source_does_not_underflow() {
    let whole = SOURCE_FUNDS / 1_000_000 * 3 / 5;
    let (mut h, o, alice) = stealth_row_killed_after_send("near-empty", whole);
    let report = resume_run(&mut h, &o).expect("resume");
    assert_eq!(report.paid.len(), 1);
    assert_eq!(found(&mut h, &alice)[0].1, whole * 1_000_000);
}

#[test]
fn disclose_survives_a_later_auditor_key_that_does_not_parse() {
    use scope_client::receipt;
    let (mut h, o, run_id, _, _) = paid_run("auditor-later");
    let archive = JournalArchive::new(&h, &o, &run_id);
    set_mint_policy(&mut h, true, true);
    let receipt =
        pay::disclose(&SvmChain::new(&mut h.svm), &h.payer, &run_id, 0, &o).expect("disclose");
    assert_eq!(
        receipt::verify(&archive, &receipt).expect("verify").amount,
        1_250_000
    );
}

#[test]
fn a_run_records_its_cluster_and_refuses_another_one() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let o = opts("cluster");
    let run_id = start(&mut h, &input(&rs), &o).expect("run").run_id;
    let records = journal(&o, &run_id);
    assert!(matches!(
        &records[0],
        Record::Run { format, genesis, .. }
            if *format == scope_client::journal::FORMAT && *genesis == "2a".repeat(32)
    ));
    let wrong = |chain: &mut SvmChain| chain.genesis = [7; 32];
    let is_wrong_cluster = |e: &PayError| matches!(e, PayError::WrongCluster { .. });
    let mut chain = SvmChain::new(&mut h.svm);
    wrong(&mut chain);
    let e = pay::status(&chain, &h.payer, &run_id, &o).expect_err("status");
    assert!(is_wrong_cluster(&e), "{e}");
    let e = pay::disclose(&chain, &h.payer, &run_id, 0, &o).expect_err("disclose");
    assert!(is_wrong_cluster(&e), "{e}");
    let e = pay::reclaim(&mut chain, &h.payer, &run_id, &o).expect_err("reclaim");
    assert!(is_wrong_cluster(&e), "{e}");
    let k = keys(&h.source_elgamal, &h.source_ae);
    let e = pay::resume(chain, &h.payer, k, &run_id, &o).expect_err("resume");
    assert!(is_wrong_cluster(&e), "{e}");
}

#[test]
fn the_duplicate_guard_sees_through_formatting_and_row_order() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 3);
    let o = opts("canonical");
    let (a, b, c) = (rs[0].account, rs[1].account, rs[2].account);
    start(
        &mut h,
        &format!("recipient,amount\n{a},1\n{b},2\n{c},3\n"),
        &o,
    )
    .expect("first run");
    let variants = [
        ("reordered", format!("{c},3\n{a},1\n{b},2\n")),
        (
            "crlf",
            format!("recipient,amount\r\n{a},1\r\n{b},2\r\n{c},3\r\n"),
        ),
        ("no trailing newline", format!("{a},1\n{b},2\n{c},3")),
        (
            "comments and spaces",
            format!("# March\n{a} , 1.0 # first\n\n  {b},2.000000\n{c},3\n\n"),
        ),
    ];
    for (name, text) in variants {
        let again = start(&mut h, &text, &o);
        assert!(
            matches!(again, Err(PayError::DuplicateInput { .. })),
            "{name}: {again:?}"
        );
    }
    // A different amount is a different input.
    start(&mut h, &format!("{a},1\n{b},2\n{c},4\n"), &o).expect("different amounts");
    // The same recipient listed twice is not the same input as listed once.
    start(&mut h, &format!("{a},1\n{a},1\n{b},2\n{c},3\n"), &o).expect("a repeated row");
}

fn attempts(o: &PayOptions, run_id: &str) -> usize {
    journal(o, run_id)
        .iter()
        .filter(|r| matches!(r, Record::Attempt { .. }))
        .count()
}

#[test]
fn a_row_that_keeps_expiring_halts_after_three_attempts_and_resume_continues() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let o = opts("rebuild-cap");
    let (mint, source, k) = (h.mint, h.source, keys(&h.source_elgamal, &h.source_ae));
    let mut chain = SvmChain::new(&mut h.svm);
    // Every attempt passes simulation and is never seen on chain.
    chain.drop_sends = usize::MAX;
    let stopped = pay::start(chain, &h.payer, k, mint, source, input(&rs).as_bytes(), &o);
    assert!(
        matches!(&stopped, Err(PayError::Halted(why)) if why.contains("3 attempts")),
        "{stopped:?}"
    );
    let run_id = only_run(&o);
    assert_eq!(attempts(&o, &run_id), 3);
    let report = resume_run(&mut h, &o).expect("resume continues");
    assert_eq!(report.paid.len(), 1);
    assert_paid_once(&h, &rs);
}

#[test]
fn attempts_that_land_with_an_error_halt_the_row_with_that_error_after_three() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 2);
    let o = opts("lands-failed");
    let (mint, source, k) = (h.mint, h.source, keys(&h.source_elgamal, &h.source_ae));
    let mut chain = SvmChain::new(&mut h.svm);
    chain.land_with_error = Some("InstructionError(3, Custom(7))".into());
    let stopped = pay::start(chain, &h.payer, k, mint, source, input(&rs).as_bytes(), &o);
    assert!(
        matches!(&stopped, Err(PayError::Halted(why)) if why.contains("Custom(7)")),
        "{stopped:?}"
    );
    assert_eq!(attempts(&o, &only_run(&o)), 3);
}

#[test]
fn a_refused_mint_extension_stops_the_run_before_anything_is_sent() {
    let mut h = Harness::with_permissioned_burn();
    let rs = recipients(&mut h, 1);
    let o = opts("refused-mint");
    let stopped = start(&mut h, &input(&rs), &o);
    assert!(
        matches!(&stopped, Err(PayError::Mint { why, .. }) if why.contains("PermissionedBurn")),
        "{stopped:?}"
    );
    assert_no_run(&o);
}

/// A refused run leaves no run directory behind.
fn assert_no_run(o: &PayOptions) {
    let runs = std::fs::read_dir(&o.runs_dir)
        .map(|d| d.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0);
    assert_eq!(runs, 0, "no run was created");
}

fn set_payer_lamports(h: &mut Harness, lamports: u64) {
    let mut account = h.svm.get_account(&h.payer.pubkey()).expect("payer");
    account.lamports = lamports;
    h.svm.set_account(h.payer.pubkey(), account).expect("set");
}

#[test]
fn refuses_a_run_the_payers_sol_cannot_cover_before_sending() {
    let mut h = Harness::new();
    let o = opts("sol-need");
    let alice = stealth_recipient(21);
    let stealth_row = format!("{},1\n", alice.derive_public_keys().to_meta_address());
    // A stealth row costs 8,630,800 lamports plus fees and the payer's reserve.
    set_payer_lamports(&mut h, 8_000_000);
    let stopped = start(&mut h, &stealth_row, &o);
    assert!(
        matches!(&stopped, Err(PayError::PayerFunds { have: 8_000_000, need }) if *need > 8_630_800),
        "{stopped:?}"
    );
    assert_no_run(&o);
    // A plain row needs only its fee.
    let rs = recipients(&mut h, 1);
    set_payer_lamports(&mut h, 1_000);
    let stopped = start(&mut h, &input(&rs), &o);
    assert!(
        matches!(stopped, Err(PayError::PayerFunds { .. })),
        "{stopped:?}"
    );
    let message = stopped.expect_err("funds").to_string();
    assert!(message.contains("SOL"), "{message}");
}

#[test]
fn a_funded_stealth_run_passes_the_sol_check() {
    let mut h = Harness::new();
    let o = opts("sol-ok");
    let alice = stealth_recipient(22);
    let row = format!("{},1\n", alice.derive_public_keys().to_meta_address());
    // One stealth row at the default cap needs about 0.0087 SOL plus fees and the reserve.
    set_payer_lamports(&mut h, 3_000_000_000);
    start(&mut h, &row, &o).expect("run");
}

/// Sets the most credits `account` can hold pending.
fn set_credit_limit(h: &mut Harness, account: Address, max: u64) {
    use spl_token_2022_interface::extension::BaseStateWithExtensionsMut;
    let mut stored = h.svm.get_account(&account).expect("account");
    let mut state = spl_token_2022_interface::extension::StateWithExtensionsMut::<Account>::unpack(
        &mut stored.data,
    )
    .expect("unpack");
    state
        .get_extension_mut::<ConfidentialTransferAccount>()
        .expect("ct")
        .maximum_pending_balance_credit_counter = max.into();
    h.svm.set_account(account, stored).expect("set");
}

#[test]
fn counts_every_row_to_one_recipient_against_its_credit_room() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    set_credit_limit(&mut h, rs[0].account, 2);
    let a = rs[0].account;
    let o = opts("credits");
    let three = format!("{a},1\n{a},2\n{a},3\n");
    let stopped = start(&mut h, &three, &o);
    assert!(
        matches!(&stopped, Err(PayError::Recipient { why, .. }) if why.contains("3 rows") && why.contains("room for 2")),
        "{stopped:?}"
    );
    assert_no_run(&o);
    start(&mut h, &format!("{a},1\n{a},2\n"), &o).expect("two rows fit");
    assert_eq!(pending(&h, &rs[0]), 3_000_000);
}

#[test]
fn reclaim_all_closes_swept_announcements_without_a_journal() {
    use pay::ReclaimOutcome::{Reclaimed, StillHolding};
    use scope_client::sweep::{self, SweepOptions};
    let mut h = Harness::new();
    let (alice, bob) = (stealth_recipient(31), stealth_recipient(32));
    let o = opts("reclaim-all");
    let input = format!(
        "{},1\n{},2\n",
        alice.derive_public_keys().to_meta_address(),
        bob.derive_public_keys().to_meta_address()
    );
    start(&mut h, &input, &o).expect("pay");
    let alices = found_announcement(&mut h, &alice);
    sweep::sweep(
        &mut NoReclaim(SvmChain::new(&mut h.svm)),
        &alice,
        &alices,
        &SweepOptions {
            poll: Duration::ZERO,
            ..Default::default()
        },
    )
    .expect("transfer-only sweep");
    // The journal is not needed.
    std::fs::remove_dir_all(&o.runs_dir).expect("remove journals");

    let stranger = Keypair::new();
    let none =
        pay::reclaim_all(&mut SvmChain::new(&mut h.svm), &stranger, &o).expect("other payer");
    assert!(
        none.is_empty(),
        "only the payer's own announcements are listed"
    );

    let report = pay::reclaim_all(&mut SvmChain::new(&mut h.svm), &h.payer, &o).expect("reclaim");
    assert_eq!(report.len(), 2);
    let outcome = |a: &Address| {
        report
            .iter()
            .find(|r| &r.announcement == a)
            .expect("listed")
            .outcome
            .clone()
    };
    let bobs = found_announcement(&mut h, &bob);
    assert_eq!(outcome(&alices), Reclaimed);
    assert_eq!(outcome(&bobs), StillHolding);
    assert!(h.svm.get_account(&alices).is_none_or(|a| a.lamports == 0));
    let again = pay::reclaim_all(&mut SvmChain::new(&mut h.svm), &h.payer, &o).expect("again");
    assert_eq!(again.len(), 1, "only bob's announcement is left");
    assert_eq!(again[0].outcome, StillHolding);
}

#[test]
fn a_dry_run_reports_the_run_and_changes_nothing() {
    let mut h = Harness::new();
    let rs = recipients(&mut h, 2);
    let alice = stealth_recipient(41);
    let text = format!(
        "{}{},0.5\n",
        input(&rs),
        alice.derive_public_keys().to_meta_address()
    );
    let o = opts("dry-run");
    let before = h.svm.get_account(&h.source).expect("source").data;
    let payer_before = h
        .svm
        .get_account(&h.payer.pubkey())
        .expect("payer")
        .lamports;
    let k = keys(&h.source_elgamal, &h.source_ae);
    let mut chain = SvmChain::new(&mut h.svm);
    chain.price_samples = vec![vec![10, 20, 30, 40]];
    let dry =
        pay::dry_run(&chain, &h.payer, &k, h.mint, h.source, text.as_bytes(), &o).expect("dry run");
    assert_eq!((dry.rows, dry.plain_rows, dry.stealth_rows), (3, 2, 1));
    assert_eq!(dry.total, 3_500_000);
    assert_eq!(dry.decimals, 6);
    assert_eq!(dry.price, 30);
    assert!(
        dry.cluster.starts_with("unknown cluster "),
        "{}",
        dry.cluster
    );
    assert_eq!(dry.payer_have, payer_before);
    assert!(dry.payer_need > 8_630_800, "{}", dry.payer_need);
    assert!(dry.fee_cap_stealth > dry.fee_cap_plain);
    assert!(dry.payer_have >= dry.payer_need);
    assert!(!o.runs_dir.exists(), "a dry run writes no journal");
    assert_eq!(h.svm.get_account(&h.source).expect("source").data, before);
    assert_eq!(
        h.svm
            .get_account(&h.payer.pubkey())
            .expect("payer")
            .lamports,
        payer_before
    );
}

#[test]
fn a_dry_run_runs_the_same_preflights_as_a_real_run() {
    let mut h = Harness::with_permissioned_burn();
    let rs = recipients(&mut h, 1);
    let o = opts("dry-run-refused");
    let k = keys(&h.source_elgamal, &h.source_ae);
    let chain = SvmChain::new(&mut h.svm);
    let refused = pay::dry_run(
        &chain,
        &h.payer,
        &k,
        h.mint,
        h.source,
        input(&rs).as_bytes(),
        &o,
    );
    assert!(matches!(refused, Err(PayError::Mint { .. })), "{refused:?}");

    let mut h = Harness::new();
    let rs = recipients(&mut h, 1);
    let o = opts("dry-run-dup");
    let text = input(&rs);
    start(&mut h, &text, &o).expect("run");
    let k = keys(&h.source_elgamal, &h.source_ae);
    let chain = SvmChain::new(&mut h.svm);
    let again = pay::dry_run(&chain, &h.payer, &k, h.mint, h.source, text.as_bytes(), &o);
    assert!(
        matches!(again, Err(PayError::DuplicateInput { .. })),
        "{again:?}"
    );
}

#[test]
fn the_run_summary_counts_rows_and_tells_done_from_halted_from_unfinished() {
    use pay::RunState;
    let mut h = Harness::new();
    let rs = recipients(&mut h, 2);
    let alice = stealth_recipient(51);
    let text = format!(
        "{}{},1\n",
        input(&rs),
        alice.derive_public_keys().to_meta_address()
    );
    let summary = |h: &mut Harness, o: &PayOptions, run_id: &str| {
        pay::summary(&SvmChain::new(&mut h.svm), &h.payer, run_id, o).expect("summary")
    };

    // Killed after the first row: unfinished.
    let o = opts("summary-killed");
    let (mint, source) = (h.mint, h.source);
    let killed = pay::start(
        Killer::new(SvmChain::new(&mut h.svm), KillAt::Simulate(2)),
        &h.payer,
        keys(&h.source_elgamal, &h.source_ae),
        mint,
        source,
        text.as_bytes(),
        &o,
    );
    assert!(killed.is_err());
    let run_id = only_run(&o);
    let s = summary(&mut h, &o, &run_id);
    assert_eq!((s.rows, s.landed), (3, 1));
    assert_eq!(s.state, RunState::Unfinished);

    // Halted by the rebuild cap, then resumed to done.
    let o = opts("summary-halted");
    let mut chain = SvmChain::new(&mut h.svm);
    chain.drop_sends = usize::MAX;
    let k = keys(&h.source_elgamal, &h.source_ae);
    pay::start(chain, &h.payer, k, mint, source, text.as_bytes(), &o).expect_err("halts");
    let run_id = only_run(&o);
    let s = summary(&mut h, &o, &run_id);
    assert!(
        matches!(&s.state, RunState::Halted(why) if why.contains("3 attempts")),
        "{:?}",
        s.state
    );
    assert_eq!(s.landed, 0);
    resume_run(&mut h, &o).expect("resume");
    let s = summary(&mut h, &o, &run_id);
    assert_eq!((s.rows, s.landed, s.state), (3, 3, RunState::Done));
    assert_eq!(s.plain.len(), 2, "plain rows are listed");
    assert!(
        s.plain
            .iter()
            .all(|p| p.state == pay::PlainState::Landed && p.signature.is_some())
    );
}
