---
status: decided
last_verified: 2026-10-05
---

# Client

TL;DR: one Rust CLI, `scope`, for both sides. The payer engine resends a signed transfer freely and rebuilds it only once the previous attempt is provably dead; the recipient scans by view tag and sweeps with plain Token-2022 instructions signed by the one-time key.
Today `crates/client` holds address derivation, builders, the LiteSVM test kit, spike binaries, the payer engine for plain recipients, and recipient scan and sweep. The CLI exposes `pay`, `register`, `scan` and `sweep`; payer stealth rows and receipts remain planned.

## Payer engine

Built for plain recipients in `crates/client/src/pay.rs`; stealth rows come next, on the `ct_ikm` export (crypto.md).

**At most once.** Token-2022 applies a Transfer only on the exact source ciphertext its equality proof was built on (verification: V8), and every attempt for a row is built on the same ciphertext, so at most one lands. One source account per run, one attempt in flight. The source's available ciphertext is the oracle: equal to the attempt's post-transfer ciphertext (the equality proof's context, verification: V51) means it landed, equal to the pre-transfer one means nothing did, anything else halts. Each attempt is simulated first, then sent and resent until it lands; it is rebuilt only once the finalized block height passes its last valid block height and the finalized source still shows the pre-transfer ciphertext. A row is recorded landed at confirmed; since each transfer builds on the last one's ciphertext, `done` waits for the finalized source to show the run's final ciphertext, and resume halts if the chain is not where the last landed row left it. Tests: V48, V49.

**Journal.** Append-only JSONL at `runs/<run_id>/journal.jsonl`, mode 0600, one writer holding a file lock, and a lock on `runs/` across the duplicate check: a run header (input hash, mint, source, payer, send order), then per row an attempt (signature, last valid block height, both ciphertexts, the signed transaction) fsynced before the first send, a `landed` record, and `done`. No secret, no plaintext amount; the input copy beside it, the payroll list, is mode 0600 too. A torn last line is dropped, since its attempt was never sent. `pay --resume <run_id>` reads the journal, then the chain, and converges. `pay` refuses an input whose hash matches an earlier run unless `--again`.

**Run secret (stealth rows).** `r_i = HKDF(run_secret, run_id || i)`. Stealth rows survive journal loss: resume re-derives R_i and finds the announcement at `["ann", token_account]`, which only this payer can have created ([design.md](design.md)). Refunds do not need it, since `reclaim` pays the stored payer; losing it costs rebuilding or disclosing a stealth row, not money. Storage is Q16.

`stealth-keygen::derive_payment_with_ephemeral` accepts the recipient's public keys and a protected `EphemeralSecret` imported from r_i. It reconstructs P, R and the tag; the same context reconstructs `ct_ikm` (verification: V58). The client derives the token-account address from (payer, R) before building that context. Run-secret derivation and stealth-row integration remain planned.

**Source.** Keys are per wallet, `derive_confidential_keys(payer, b"")`, as spl-token-cli 5.6 derives them, so a source set up with that CLI works; the engine refuses a source whose ElGamal key differs (verification: V50). The engine reads the AE hint and confirms it against the ElGamal ciphertext ([crypto.md](crypto.md), Balance cache), then proves from that verified value. It spends only the available balance; pending balance is applied before a run, with spl-token-cli 5.6 or later, never during one.

**Privacy.** Send order is a random permutation recorded in the run header, so it does not mirror the file order; with stealth rows it will derive from the run secret. Meta-addresses come from the input file in v1; once a registry exists, they are fetched in one query and picked locally.

The library supplies `RecipientPublicKeys::to_meta_address()` and `from_meta_address(&str)`: a `scope:` Base58Check string containing a version and both public keys. The parser validates the checksum, version and keys before the payer derives a payment (verification: V62). Register output is available in the CLI; payer stealth-row input wiring remains planned.

**Fees.** Each attempt samples the per-CU price landed non-vote transactions actually paid in the latest confirmed block: ComputeBudget price for legacy and v0, header `priority_fee` over its compute unit limit for v1. It takes p75; above `--max-price` the run stops, resumable. `getRecentPrioritizationFees` is not used: unfiltered it returns each slot's minimum and reads near zero (verification: V39). The header carries the fee as total lamports (verification: V20). Until S5 measures both transactions, `tx::COMPUTE_UNIT_LIMIT` is a fixed 600,000 and the loaded-accounts limit 4 MiB.

`lamports_for_P` uses a fixed high price, not the sample, because the recipient may sweep weeks later: D's rent, two signatures and 600,000 CU at 1,000,000 micro-lamports per CU, plus a rent reserve in P. The recipient computes the exact requirement from the chain; the earlier allowance estimate must include this reserve. P remains rent-exempt so incoming SOL cannot invalidate a fixed drain (verification: V23).

**Proofs.** `spl-token-confidential-transfer-proof-generation` 0.6.1, with the mint's auditor key when it has one. Proving is not the bottleneck: 16 ms for the range proof, about 0.2 s for a 50-recipient set (verification: V30).

Plain recipients: `recipient,amount` rows, amounts in token units. The engine preflights each recipient's account (Token-2022, mint, not frozen, approved, confidential credits on, credit counter below the cap) and refuses non-transferable, transfer-fee and transfer-hook mints, all before anything is sent. Stealth recipients add the setup, handover and `announce` in [design.md](design.md). `pay --status`, planned, lists announcements still open per run and can call `reclaim` as a backstop.

## Recipient flow

The recipient keeps one private-key backup. D_owner is derived from `b_spend` and R, so transaction retries need no sweep journal. Scan includes public R, and sweep prints and flushes its destination, owner, R and attempt signature before broadcasting. Preserve this recovery output: after reclaim closes the announcement, it is needed to reconstruct D_owner and its confidential keys, or must be recovered from the historical payer transaction.

`RecipientSecretKeys::derive_sweep_destination(&R)` supplies a protected standard Ed25519 seed. The client builds D_owner with `Keypair::new_from_array(*seed.as_bytes())`; this SDK conversion and reconstruction after a recipient backup are tested (verification: V61). The source is signed through the raw-scalar `PaymentSigner` adapter (V63).

`scope_client::scan::scan` fetches program-owned accounts, validates the announcement layout and canonical PDA, and checks each tag locally. The tag depends on R and cannot be known before reading the announcement. Per candidate it recovers P, compares the token account's authority, derives the account-scoped confidential keys, verifies the ElGamal key and AE balance hint, and decrypts the pending balance. An optional mint filter restricts the results. Wrong-key candidates and malformed announcements are ignored. `ScanReport` returns valid payments and skipped invalid payments with their account and reason; the CLI prints skipped errors to stderr. Chain errors still abort the scan. RPC capacity remains unverified (S6).

`scope_client::sweep::sweep` creates a fresh account at `create_with_seed(D_owner, "scope-sweep/v1", Token-2022)`, derives its confidential keys using the standard SDK wallet schedule, and builds the full recipient transaction. It verifies mint policy, refuses an existing token destination, handles System-owned prefunds, disables incoming confidential credits, burns public dust, empties the source, refunds rent with `reclaim`, and transfers surplus SOL from P to D_owner while retaining a rent reserve in P. A surplus too small to fund a new D_owner stays in P; an already-funded owner can receive a smaller transfer. The recipient controls the retained SOL, and the report includes P and its finalized balance. It computes rent and fees from the chain and reports an exact funding shortage. Both signatures are verified during simulation; if the full transaction fails but the version without burn and reclaim simulates successfully, confidential funds are swept and the report shows any public balance and rent left behind. Dry runs send nothing.

`prepare` simulates and returns a signed `PreparedSweep`, retaining protected signing material in memory for one transfer-only retry. Its debug output contains only the public report. `submit` resends the same transaction while its outcome is unresolved; after a finalized failure or blockhash expiry, it can build and simulate one attempt without burn and reclaim using a fresh blockhash, balance and fee quote. It refuses to rebuild over an existing token destination. The deterministic owner and public R stay the same across attempts.

Timeout and status errors retain the public recovery report. `attempt_signature` names the most recent prepared transaction; `finalized_signature` is present only when that signature has a successful finalized status. A concurrent attempt can complete the payment without proving this attempt succeeded; its finalized signature and burned amount remain unknown in that case. Counterparty destinations and destination-reuse overrides remain follow-up work.

Any wallet that signs Token-2022 confidential instructions with an imported key can sweep without this CLI.

## Recipient commands

Register once and back up the resulting private file. Stdout is the public meta-address shared with payers; an existing backup is never overwritten. Raw files contain the library's 64-byte format and must be regular, nonsymlinked files with owner-only permissions. New files use mode 0600 and new directories mode 0700. Secret buffers are cleared on drop.

```sh
scope register --recipient-key ./recipient.key
scope scan --recipient-key ./recipient.key --url http://127.0.0.1:8899
scope sweep --recipient-key ./recipient.key --url http://127.0.0.1:8899 \
  --announcement <address-from-scan> --dry-run
scope sweep --recipient-key ./recipient.key --url http://127.0.0.1:8899 \
  --announcement <address-from-scan>
```

Scan prints announcement, token account, mint, confidential amount and public amount in base units, and public R. `--mint` restricts discovery. Sweep moves the whole confidential balance and attempts to burn public dust and close the source; dry-run output reports both. `--max-price` caps priority prices, and `--timeout` starts at submission, after initial preparation and simulation. It bounds RPC waits, including HTTP retry delays, and polling sleeps; the client starts no further sends after the deadline. `RpcChain` cancels unfinished RPC futures at that shared deadline, and other `RecipientChain` implementations must honor `set_deadline` for blocking I/O. A timeout or missing announcement does not authorize an extra payment: retry reads chain state and fresh destination creation prevents duplicates. If cleanup is omitted during preparation or a safe submission retry, the output explicitly shows the public balance left behind and says rent was not reclaimed. Active permissioned burning can use this transfer-only fallback; issuer authorization is still required for later dust cleanup.

For encrypted backups, install [age](https://github.com/FiloSottile/age) and supply its public recipient at registration and owner-only private identity when loading. Encryption and decryption stream through the age process; plaintext keys are never written to a temporary file.

```sh
scope register --recipient-key ./recipient.age --encrypt-to <age-public-recipient>
scope scan --recipient-key ./recipient.age --identity ./identity.txt --url <rpc-url>
scope sweep --recipient-key ./recipient.age --identity ./identity.txt \
  --url <rpc-url> --announcement <announcement-address> --dry-run
```

The default backup path is `~/.config/scope/recipient.key`, and the default RPC is localhost. Live-cluster recipient validation, counterparty destinations, destination-reuse overrides, and receipts remain planned. CLI and encrypted-backup checks are V66; on-chain recipient tests are V64 and V65.

## Mints

Works unmodified on mints whose `auto_approve_new_accounts` is true. The client refuses other mints, non-transferable mints and mints that freeze new accounts by default. PYUSD and USDG are Token-2022 with the extension but require their authority's ApproveAccount for every new confidential account; USDC is legacy SPL Token (verification: V14). The issuer path, documented and not built: the payer stays the owner until the issuer approves, then hands over and transfers in a second transaction [likely]. The issuer's side can be one change: point the mint's confidential-transfer authority at the PDA of a small policy program that approves every account, since ApproveAccount needs only that authority's signature (verification: V13).

## Audit (planned)

Disclosure receipt `{R, ct_ikm, payer transaction signature}`. `verify` re-derives the ElGamal and AES keys from `ct_ikm`, checks the ElGamal pubkey against the proof instructions in the referenced transaction, and decrypts the amount. It works after the accounts are closed, and needs an archival RPC and `maxSupportedTransactionVersion: 1` on `getTransaction` (verification: V22). A mint auditor key, where the issuer sets one, is the secondary path (verification: V12). Receipts for plain payments are open (Q15).

## Testing

What runs today, all with `cargo test --workspace --locked` after `cargo build-sbf`:
- `programs/scope/tests/it`: LiteSVM integration tests for `announce` and `reclaim` (verification: V33, V34), S3 end to end (V36) and the S1 size check (V37). LiteSVM loads the real `.so`, Token-2022 and the ZK ElGamal builtin. It does not enforce the 4,096-byte cap or the loaded-accounts limit and charges 6,960 lamports per byte of rent (verification: V31), so the S1 test measures size itself.
- `crates/client/tests/pay.rs`: the payer engine on LiteSVM, with a fault-injecting chain that kills runs before a send, after a send and between rows (verification: V48).
- `crates/client/tests/interface_crosscheck.rs`: the account reader, program ids and CloseAccount byte against spl-token-2022-interface 3.1.1 (verification: V35).
- Unit tests in `crates/interface` (layout, instruction data, seeds, error codes) and `crates/stealth-keygen` (vectors from an independent Python generator, point checks, the nonce regression test).
- Example binaries, run by hand: `s1_v1` sends the payer transaction to a cluster (V38), reads the announcement back, then announces an unpaid account and reclaims it; `s4_fees` samples priority fees (V40, V52); `p2_fixture` sets up a mint, a funded source and plain recipients for `scope pay` (V49).

Done: an attack test for every `announce` and `reclaim` check, and CU ceilings from LiteSVM logs (V54, V55). Planned: scan against Surfpool (P2); Mollusk 0.15.1 if a fuzz fixture is wanted (P4); a chaos harness over the existing `chain::Chain` trait that kills the engine at every step of a 20-recipient run and asserts convergence (P4); devnet release smoke (P5). The rest of the adversarial suite (P2 to P4) adds: transfer, apply or empty signed by any key but P after handover; public credit after setup; a second confidential credit; wrong mint; a mint that does not auto-approve; two P signatures sharing an R.

## Stack

Program: pinocchio 0.11.2 (`no_std`, `cpi` feature) and pinocchio-system 0.6.1; why Pinocchio is in decisions.md.

Off-chain Solana crates follow litesvm 0.16's line and move together: solana-address ~2.6.1, solana-instruction ~3.4.1, solana-message ~4.4.1, solana-transaction ~4.1.6, solana-keypair 3.1.2, solana-signer 3.0.1, solana-system-interface 3.2.0, solana-zk-sdk 7.0.1, spl-token-2022-interface 3.1.1, spl-token-confidential-transfer-proof-extraction and -generation 0.6.1, litesvm 0.16.0, solana-rpc-client 4.2.2. Exact pins are in the root `Cargo.toml`. zk-sdk is 7.0.1, not 8, because litesvm 0.16 and zk-sdk 8 cannot share a lockfile, and `derive_confidential_keys_from_ikm` is identical in both (verification: V28, V29). When litesvm moves to solana-address 2.7, the whole line moves at once.

`crates/stealth-keygen` holds keys, HKDF-SHA256 derivation and raw-scalar signing. It exports protected, account-scoped `ct_ikm`. `scope-client::confidential::derive_confidential_keys` passes that material to the pinned `solana-zk-sdk` derivation for the ElGamal and symmetric balance keys. Receipt serialization and verification remain client work; Q14 implementation is complete and external review remains Q1. Every crate is `MIT OR Apache-2.0`.
