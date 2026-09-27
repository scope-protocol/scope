---
status: decided
last_verified: 2026-09-28
---

# Client

TL;DR: one Rust CLI, `scope`, for both sides. The payer engine resends a signed transfer freely and rebuilds it only once the previous attempt is provably dead; the recipient scans by view tag and sweeps with plain Token-2022 instructions signed by the one-time key.
Today `crates/client` holds address derivation, instruction and v1 transaction builders, the LiteSVM test kit and the S1 and S4 spike binaries; the engine, scan, sweep and receipts below are designed, not built.

## Payer engine (planned)

**At most once.** Token-2022 checks each Transfer against the exact source ciphertext its equality proof was built on (verification: V8), so a signed transfer lands at most once. The engine resends it freely and rebuilds it only after the finalized block height passes the attempt's last valid block height; before that, the old attempt can still land on some fork. One source account per run, one attempt in flight. The source's available ciphertext is an oracle: equal to an attempt's predicted post-transfer ciphertext means that attempt landed, equal to the pre-transfer one means nothing did, anything else halts the run.

**Journal.** Append-only JSONL at `runs/<run_id>/journal.jsonl`, mode 0600, one writer holding a lock. The attempt record, with signature, last valid block height, ciphertexts and the signed transaction bytes, is fsynced before every send, so no signature exists on the network that the journal lacks. It never holds a secret or a plaintext amount. Resume reads the journal, then the chain, and converges. The input file is stored with mode 0600 too: it is the payroll list.

**Run secret.** `e_i = HKDF(run_secret, run_id || i)`. Stealth rows survive journal loss: resume re-derives E_i and finds the announcement at `["ann", token_account]`, which only this payer can have created ([design.md](design.md)). Refunds do not need the secret, since `reclaim` pays the stored payer; losing it costs the ability to rebuild or disclose a stealth row, not money. It is stored in an encrypted file; deriving it from one payer master secret is Q16. `pay` refuses an input file whose hash matches an earlier run unless `--again`.

**Source balance.** The available balance is one 64-bit ciphertext that table lookup cannot decrypt. The engine reads the AE hint it wrote itself and confirms it against the ElGamal ciphertext ([crypto.md](crypto.md), Balance cache). Pending balance is applied only before a run, never during one, since an apply changes the ciphertext every prepared transfer is bound to.

**Privacy.** Send order is shuffled by a permutation derived from the run secret, so it does not mirror the file order. Meta-addresses come from the input file in v1; once a registry exists, they are fetched in one query and picked locally, so the RPC provider does not learn whom the payer pays.

**Fees.** The priority fee is sampled from recent blocks: for each landed, non-vote transaction, the per-CU price it actually paid, read from its ComputeBudget instruction (legacy and v0) or from its v1 header's `priority_fee` divided by its compute unit limit; p75 of that set, clamped to a floor and the operator's cap. `getRecentPrioritizationFees` is not used: with no account filter it returns each slot's minimum among landed transactions, so it reads near zero by construction (verification: V39), and filtered to our accounts it reads zero because they are only read-locked. Above the cap the engine stops and exits resumable. A v1 header carries the priority fee as total lamports, so the client converts the sample (verification: V20). The CU limit will come from simulation plus 10%; until S5 measures both transactions, `tx::COMPUTE_UNIT_LIMIT` is a fixed 600,000 and the loaded-accounts limit 4 MiB.

`lamports_for_P` uses a fixed high price, not the sample, because the recipient may sweep weeks later: D's rent, two signatures and 450,000 CU at 1,000,000 micro-lamports per CU, about 0.0035 SOL at today's rent [likely]. P must hold zero or at least 650,240 lamports at every step (verification: V23).

**Proofs.** Transfer proofs come from `spl-token-confidential-transfer-proof-generation` 0.6.1, with the balance fed from the verified plaintext, never from the AE cache. Proving is not the bottleneck: 16 ms for the range proof, about 0.2 s for a 50-recipient set (verification: V30).

Plain recipients: the payer preflights the recipient's confidential account (mint, approved, credit counter below the cap, not frozen) and sends the Transfer and its proofs; no instruction of ours. Stealth recipients add the setup, handover and `announce` in [design.md](design.md). `pay --status` lists announcements still open per run and can call `reclaim` as a backstop.

## Recipient flow (planned)

Nothing on the recipient side is persisted: D_owner is derived from `b_spend` and (E, k), so a crash at any point is a retry.

`scan`: `getProgramAccounts` on our program with `dataSize = 69`, `memcmp(0, [1])`, `memcmp(2, [tag])`; per candidate one X25519, re-derive the tag, derive the token account from (payer, E, k), recompute `B_spend + t·G` and compare it with that account's owner, then derive the confidential keys and decrypt the pending balance. Expected to hold to about 100k announcements on a paid RPC [unverified, spike S6]; an indexer beyond that is out of scope.

`sweep`: builds the recipient transaction in [design.md](design.md), signed by P (raw scalar, fee payer) and D_owner. It reads the one-time account's public amount first and adds a Burn if it is nonzero. It simulates with `reclaim` and, if `reclaim` is what fails, drops it and resends. If P cannot cover the fee and D's rent, it stops and says by how much, because the only top-up path links the recipient ([privacy.md](privacy.md)). It refuses a destination it has seen before unless overridden, and offers `--spend-to` for a whole-balance payment straight to a counterparty.

Any wallet that signs Token-2022 confidential instructions with an imported key can sweep without this CLI.

## Mints

Works unmodified on mints whose `auto_approve_new_accounts` is true. The client refuses other mints, non-transferable mints and mints that freeze new accounts by default. PYUSD and USDG are Token-2022 with the extension but require their authority's ApproveAccount for every new confidential account; USDC is legacy SPL Token (verification: V14). The issuer path, documented and not built: the payer stays the owner until the issuer approves, then hands over and transfers in a second transaction [likely]. The issuer's side can be one change: point the mint's confidential-transfer authority at the PDA of a small policy program that approves every account, since ApproveAccount needs only that authority's signature (verification: V13).

## Audit (planned)

Disclosure receipt `{E, k, ct_ikm, payer transaction signature}`. `verify` re-derives the ElGamal and AES keys from `ct_ikm`, checks the ElGamal pubkey against the proof instructions in the referenced transaction, and decrypts the amount. It works after the accounts are closed, and needs an archival RPC and `maxSupportedTransactionVersion: 1` on `getTransaction` (verification: V22). A mint auditor key, where the issuer sets one, is the secondary path (verification: V12). Receipts for plain payments are open (Q15).

## Testing

What runs today, all with `cargo test --workspace --locked` after `cargo build-sbf`:
- `programs/scope/tests/it`: LiteSVM integration tests for `announce` and `reclaim` (verification: V33, V34), S3 end to end (V36) and the S1 size check (V37). LiteSVM loads the real `.so`, Token-2022 and the ZK ElGamal builtin. It does not enforce the 4,096-byte cap or the loaded-accounts limit and charges 6,960 lamports per byte of rent (verification: V31), so the S1 test measures size itself.
- `crates/client/tests/interface_crosscheck.rs`: the account reader, program ids and CloseAccount byte against spl-token-2022-interface 3.1.1 (verification: V35).
- Unit tests in `crates/interface` (layout, instruction data, seeds, error codes) and `crates/stealth-keygen` (vectors from an independent Python generator, point checks, the nonce regression test).
- Example binaries, run by hand: `s1_v1` sends the payer transaction to a cluster (V38); `s4_fees` samples priority fees (V40).

Planned: scan against Surfpool (P2); CU assertions from LiteSVM logs, and Mollusk 0.15.1 if a fuzz fixture is wanted (P4); a chaos harness with the chain behind one trait (RPC and LiteSVM backends plus a fault-injecting wrapper) that kills the engine at every step of a 20-recipient run and asserts convergence (P4); devnet release smoke (P5). The adversarial suite (P2 to P4) adds: `announce` with each of its nine checks broken; transfer, apply or empty signed by any key but P after handover; public credit after setup; a second confidential credit; wrong mint; a mint that does not auto-approve; two P signatures sharing an R.

## Stack

Program: pinocchio 0.11.2 (`no_std`, `cpi` feature) and pinocchio-system 0.6.1; why Pinocchio is in decisions.md.

Off-chain Solana crates follow litesvm 0.16's line and move together: solana-address ~2.6.1, solana-instruction ~3.4.1, solana-message ~4.4.1, solana-transaction ~4.1.6, solana-keypair 3.1.2, solana-signer 3.0.1, solana-system-interface 3.2.0, solana-zk-sdk 7.0.1, spl-token-2022-interface 3.1.1, spl-token-confidential-transfer-proof-extraction and -generation 0.6.1, litesvm 0.16.0, solana-rpc-client 4.2.2. Exact pins are in the root `Cargo.toml`. zk-sdk is 7.0.1, not 8, because litesvm 0.16 and zk-sdk 8 cannot share a lockfile, and `derive_confidential_keys_from_ikm` is identical in both (verification: V28, V29). When litesvm moves to solana-address 2.7, the whole line moves at once.

`crates/stealth-keygen` holds keys, derivations and raw-scalar signing, with no Solana dependencies; it hands `ct_ikm` to the client as bytes. Every crate is `MIT OR Apache-2.0`.
