---
status: decided
last_verified: 2026-10-06
---

# Client

TL;DR: one Rust CLI, `scope`, for both sides. The payer engine resends a signed transfer freely and rebuilds it only once the previous attempt is provably dead; the recipient scans by view tag and sweeps with plain Token-2022 instructions signed by the one-time key.
Today `crates/client` holds address derivation, builders, the LiteSVM test kit, spike binaries, the payer engine for plain and stealth rows, and recipient scan and sweep. The CLI exposes `pay`, `register`, `scan`, `sweep`, `disclose` and `verify`.

## Payer engine

Built in `crates/client/src/pay.rs` for plain and stealth rows. A stealth row's setup, handover, `announce`, P's funding and transfer share one transaction ([design.md](design.md)), so the oracle below covers stealth rows too.

**At most once.** Token-2022 applies a Transfer only on the exact source ciphertext its equality proof was built on (verification: V8), and every attempt for a row is built on the same ciphertext, so at most one lands. One source account per run, one attempt in flight. The source's available ciphertext is the oracle: equal to the attempt's post-transfer ciphertext (the equality proof's context, verification: V51) means it landed, equal to the pre-transfer one means nothing did, anything else halts. Each attempt is simulated first, then sent and resent until it lands; it is rebuilt only once the finalized block height passes its last valid block height and the finalized source still shows the pre-transfer ciphertext. A row is recorded landed at confirmed; since each transfer builds on the last one's ciphertext, `done` waits for the finalized source to show the run's final ciphertext, and resume halts if the chain is not where the last landed row left it. Tests: V48, V49.

**Journal.** Append-only JSONL at `runs/<run_id>/journal.jsonl`, mode 0600, one writer holding a file lock, and a lock on `runs/` across the duplicate check: a run header (input hash, mint, source, payer, send order), then per row an attempt (signature, last valid block height, both ciphertexts, the signed transaction) fsynced before the first send, a `landed` record, and `done`. No secret, no plaintext amount; the input copy beside it, the payroll list, is mode 0600 too. A torn last line is dropped, since its attempt was never sent. `pay --resume <run_id>` reads the journal, then the chain, and converges. `pay` refuses an input whose hash matches an earlier run unless `--again`.

**Run secret.** Derived from the payer's own key, so nothing secret is stored: `run_secret = HKDF-SHA256(salt = "scope-run-secret/v1", ikm = the payer's Ed25519 signature over "scope-run-secret/v1" || run_id, info = run_id)`. Ed25519 signing is deterministic, so the payer keypair alone rebuilds it. `r_i = HKDF(run_secret, run_id || i)`, with i the row's position in the input file, and the two Pedersen openings of row i's amount come from the same secret (Audit). Stealth rows survive journal loss: resume re-derives R_i and finds the announcement at `["ann", token_account]`, which only this payer can have created ([design.md](design.md)). Refunds do not need the secret, since `reclaim` pays the stored payer (verification: V72).

`stealth-keygen::derive_payment_with_ephemeral` accepts the recipient's public keys and a protected `EphemeralSecret` imported from r_i. It reconstructs P, R and the tag; the same context reconstructs `ct_ikm` (verification: V58). The client derives the token-account address from (payer, R) before building that context, and funds P with `fees::sweep_funding` (Fees). An address someone already sent lamports to, which CreateAccountWithSeed refuses, is created by a top-up Transfer, AllocateWithSeed and AssignWithSeed instead, both signed by the payer as base; an address that already holds an account halts the run (verification: V73).

**Source.** Keys are per wallet, `derive_confidential_keys(payer, b"")`, as spl-token-cli 5.6 derives them, so a source set up with that CLI works; the engine refuses a source whose ElGamal key differs (verification: V50). The engine reads the AE hint and confirms it against the ElGamal ciphertext ([crypto.md](crypto.md), Balance cache), then proves from that verified value. It spends only the available balance; pending balance is applied before a run, with spl-token-cli 5.6 or later, never during one.

**Privacy.** Send order is a random permutation recorded in the run header, so it does not mirror the file order. Meta-addresses come from the input file; `scope lookup <wallet>...` finds published ones, fetching every registry entry in one query and picking locally (crates/client/src/registry.rs).

The library supplies `RecipientPublicKeys::to_meta_address()` and `from_meta_address(&str)`: a `scope:` Base58Check string containing a version and both public keys. The parser validates the checksum, version and keys before the payer derives a payment (verification: V62). `scope pay` reads a meta-address in a row's recipient column as a stealth row.

**Fees.** Each attempt samples the per-CU price landed non-vote transactions actually paid in the latest confirmed block: ComputeBudget price for legacy and v0, header `priority_fee` over its compute unit limit for v1. It takes p75; above `--max-price` the run stops, resumable. `getRecentPrioritizationFees` is not used: unfiltered it returns each slot's minimum and reads near zero (verification: V39). The header carries the fee as total lamports (verification: V20). Each transaction shape has its own compute-unit limit, about 15% above its measurement, since the fee is paid on the limit: plain transfer 275,000, stealth payment 295,000, sweep 310,000 (verification: V70). The loaded-accounts limit is 4 MiB.

`lamports_for_P` is `fees::sweep_funding`: D's rent, two signatures at 5,000 lamports, the priority fee at the sweep's 310,000-CU limit and a price cap of 1,000,000 micro-lamports per CU, and the rent reserve the sweep leaves in P. A fixed cap, not the sample, because the recipient may sweep weeks later; the cap is also the sweep's default `--max-price`. A P funded with exactly this sweeps at the cap, and one lamport less is refused as underfunded (verification: V71). P remains rent-exempt so incoming SOL cannot invalidate a fixed drain (verification: V23).

**Proofs.** `crates/client/src/proofs.rs` builds the transfer proofs with the same builders, in the same order, as `transfer_split_proof_data` in `spl-token-confidential-transfer-proof-generation` 0.6.1, but takes the two amount openings from the run secret instead of drawing them, so the payer can later prove an amount without storing anything (Audit). It uses the mint's auditor key when it has one. Proving is not the bottleneck: 16 ms for the range proof, about 0.2 s for a 50-recipient set (verification: V30).

Rows are `recipient,amount`, amounts in token units; the recipient is an account address for a plain row or a `scope:` meta-address for a stealth row. The engine preflights each recipient's account (Token-2022, mint, not frozen, approved, confidential credits on, credit counter below the cap) and refuses non-transferable, transfer-fee and transfer-hook mints, all before anything is sent. Stealth rows add the setup, handover and `announce` in [design.md](design.md), and need a mint that approves new confidential accounts itself and does not freeze them, since `announce` does not check approval (verification: V69). `pay --status <run_id>` shows each stealth row as unpaid, open, swept or reclaimed, reading the journal without its lock; `--reclaim` calls `reclaim` for every swept row, which is how rent comes back when a sweep took its transfer-only fallback. Token-2022 refuses to close an account with any balance, so it cannot touch funds (verification: V4, V75).

## Recipient flow

`scope register`, `scan` and `sweep` implement the recipient side: protected backups, streaming authenticated discovery and whole-balance v1 transfers into a fresh deterministic destination. Preparation and each safe rebuild simulate before sending. Recovery is flushed before every new attempt, and submission shares one deadline across RPC waits, retry preparation and polling. Source and mint state are refreshed on safe retries; a finalized successful signature proves the atomic outcome (verification: V64 to V67).

## Recipient commands

Commands, backup formats, callback APIs, recovery and supported limits are documented in [recipient.md](recipient.md). Counterparty destinations, destination reuse and receipts remain follow-up work.

## Mints

Works unmodified on mints whose `auto_approve_new_accounts` is true. The client refuses other mints, non-transferable, transfer-fee and transfer-hook mints, and mints that freeze new accounts by default. PYUSD and USDG are Token-2022 with the extension but require their authority's ApproveAccount for every new confidential account; USDC is legacy SPL Token (verification: V14). The issuer path, documented and not built: the payer stays the owner until the issuer approves, then hands over and transfers in a second transaction [likely]. The issuer's side can be one change: point the mint's confidential-transfer authority at the PDA of a small policy program that approves every account, since ApproveAccount needs only that authority's signature (verification: V13).

## Audit

A receipt names one finalized payment transaction and proves the amount it moved, against that transaction's inline ciphertext-validity proof, which Token-2022 verified when it landed. `scope verify <receipt>` needs an archival RPC with `maxSupportedTransactionVersion: 1` on `getTransaction` (verification: V22), checks the receipt's cluster against the node's genesis hash, and works after every account is closed. Two kinds, both in `crates/client/src/receipt.rs`:

- **Payer receipt**, any row, plain or stealth: `{cluster, signature, amount, opening_lo, opening_hi}`. `scope disclose --run <id> --row <i>` re-derives the row's two Pedersen openings from the run secret, so nothing was stored; `verify` checks that they open the transfer's two amount commitments. It reveals that amount and nothing else (verification: V76).
- **Recipient receipt**, stealth rows: `{cluster, signature, ct_ikm}`. `scope disclose --signature <payment>` with the recipient backup finds R and the tag in the payment's `announce` data, derives `ct_ikm`, and refuses unless its ElGamal key is the transfer's destination key, so a view-tag collision yields no receipt. `verify` derives the key, requires it to be the destination key, which a forged `ct_ikm` fails, and decrypts the amount. It grants read access to that one account (crypto.md) (verification: V77).

A mint auditor key, where the issuer sets one, remains a second path (verification: V12).

## Testing

What runs today, all with `cargo test --workspace --locked` after `cargo build-sbf`:

- `programs/scope/tests/it`: LiteSVM integration tests for `announce`, `reclaim`, `register` and `deregister` (verification: V33, V34, V78, V79), the Token-2022 rules the design relies on (V3, V6, V7, V69), CU budgets per instruction and per transaction shape (V55, V70), S3 end to end (V36) and the S1 size check (V37). LiteSVM loads the real `.so`, Token-2022 and the ZK ElGamal builtin. It does not enforce the 4,096-byte cap or the loaded-accounts limit and charges 6,960 lamports per byte of rent (verification: V31), so the S1 test measures size itself.
- `crates/client/tests/pay.rs`: the payer engine on LiteSVM, plain and stealth rows, with a fault-injecting chain that kills runs before a send, after a send and between rows (verification: V48, V72, V73); end to end to the recipient's sweep (V74); status and reclaim (V75); receipts (V76, V77). The chaos harness, run by hand with `-- --ignored`, kills a 20-row mixed run at all sixty kill points and checks each converges (V80). `crates/client/tests/registry.rs`: publish, look up and pay (V78).
- `crates/client/tests/interface_crosscheck.rs`: the account reader, program ids and CloseAccount byte against spl-token-2022-interface 3.1.1 (verification: V35).
- Unit tests in `crates/interface` (layout, instruction data, seeds, error codes) and `crates/stealth-keygen` (vectors from an independent Python generator, point checks, the nonce regression test).
- Example binaries, run by hand: `s1_v1` sends the payer transaction to a cluster (V38), reads the announcement back, then announces an unpaid account and reclaims it; `s4_fees` samples priority fees (V40, V52); `p2_fixture` sets up a mint, a funded source and plain recipients for `scope pay` (V49).

Done: an attack test for every check of all four instructions, and CU ceilings from LiteSVM logs (V54, V55, V78, V79). Recipient tests cover source and destination races, streaming output, safe retries and public recovery; a 1,000-announcement RPC fixture covers the wire format and filtering (V64 to V67). Planned: scan against Surfpool and the selected provider (P2); Mollusk 0.15.1 if a fuzz fixture is wanted (P4); devnet release smoke (P5).

## Stack

Program: pinocchio 0.11.2 (`no_std`, `cpi` feature) and pinocchio-system 0.6.1; why Pinocchio is in decisions.md.

Off-chain Solana crates follow litesvm 0.16's line and move together: solana-address ~2.6.1, solana-instruction ~3.4.1, solana-message ~4.4.1, solana-transaction ~4.1.6, solana-keypair 3.1.2, solana-signer 3.0.1, solana-system-interface 3.2.0, solana-zk-sdk 7.0.1, spl-token-2022-interface 3.1.1, spl-token-confidential-transfer-proof-extraction and -generation 0.6.1, litesvm 0.16.0, solana-rpc-client 4.2.2. Exact pins are in the root `Cargo.toml`. zk-sdk is 7.0.1, not 8, because litesvm 0.16 and zk-sdk 8 cannot share a lockfile, and `derive_confidential_keys_from_ikm` is identical in both (verification: V28, V29). When litesvm moves to solana-address 2.7, the whole line moves at once.

`crates/stealth-keygen` holds keys, HKDF-SHA256 derivation and raw-scalar signing. It exports protected, account-scoped `ct_ikm`. `scope-client::confidential::derive_confidential_keys` passes that material to the pinned `solana-zk-sdk` derivation for the ElGamal and symmetric balance keys. Receipt serialization and verification remain client work; Q14 implementation is complete and external review remains Q1. Every crate is `MIT OR Apache-2.0`.
