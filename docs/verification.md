---
status: verified
last_verified: 2026-09-28
---

# Verification

TL;DR: every load-bearing claim in these docs, with the primary source that backs it: a file and line in a named crate version or commit, an RPC read with its date, or a test in this repo.
Other docs cite rows here as (verification: Vn). A claim with no row is marked [unverified] where it is stated.

Source shorthand:
- **T22** is `solana-program/token-2022` at commit `45b91ca` (main, read 2026-09-25). `t22/processor.rs` is `program/src/processor.rs`; `ct/processor.rs` is `program/src/extension/confidential_transfer/processor.rs`.
- **agave** is `anza-xyz/agave` at commit `b8c619a` (master, read 2026-09-25).
- **SIMD-0385** is `solana-foundation/solana-improvement-documents` `proposals/0385-transaction-v1.md` at `05f2ae9`.
- **RPC** means public mainnet-beta and devnet endpoints on the date given.
- Test names are in this repo; program tests are under `programs/scope/tests/it/`.

Line numbers drift; when bumping a pinned version, re-check the rows that name it.

## Token-2022 behaviour

| Id | Claim | Source |
|---|---|---|
| V1 | ConfigureAccount checks only that the current owner signed; a keypair or a PDA via invoke_signed both pass | T22 `ct/processor.rs` `process_configure_account` 256-266; `t22/processor.rs` `validate_owner` 2253-2293 |
| V2 | SetAuthority(AccountOwner) checks only the current owner; it refuses a frozen account, ImmutableOwner and an enabled CpiGuard, and clears the delegate | T22 `t22/processor.rs` 709-770 (frozen 724-727, owner check 730-737, refusals 739-748, delegate cleared 758-759) |
| V3 | ApplyPendingBalance, confidential Transfer and EmptyAccount authorise against the live owner field, never the original owner or the ElGamal key's origin | token-2022 main read 2026-09-14: `ct/processor.rs` 1213-1220, 848-874, 352-378 |
| V4 | CloseAccount authorises `close_authority`, else the owner, and refuses a nonzero public amount (`NonNativeHasBalance`) or nonzero confidential balances | T22 `t22/processor.rs` 1298-1390 (authority 1318-1321, balances 1315-1316 and 1348-1352) |
| V5 | With CpiGuard enabled, CloseAccount under CPI fails when the destination is not the owner | T22 `t22/processor.rs` `process_close_account` 1328-1334 |
| V6 | The disabled public-credit flag is checked only in Transfer; MintTo ignores it | T22 `t22/processor.rs` 537 (only call site), `process_mint_to` 1028-1090 |
| V7 | `maximum_pending_balance_credit_counter` admits exactly that many credits, is written once at configure, and has no later setter | spl-token-2022-interface 3.1.1 `src/extension/confidential_transfer/mod.rs` 161-178; T22 `ct/processor.rs` 291-292 |
| V8 | A confidential Transfer requires the new source ciphertext to equal the equality proof's; incoming credits touch only the pending balance | T22 `ct/processor.rs` 848-932 and 935-993 |
| V9 | InitializeAccount3 initialises every account extension the mint requires and fails if the account is too small | T22 `t22/processor.rs` 219-222 |
| V10 | A NonTransferable mint forces ImmutableOwner on every account | spl-token-2022-interface 3.1.1 `src/extension/mod.rs` 1299-1302 |
| V10a | The associated token account program always adds ImmutableOwner to Token-2022 accounts it creates | `solana-program/associated-token-account` master read 2026-09-14: `program/src/processor.rs` 118-141 |
| V11 | A token account for a mint with no account extensions, plus ConfidentialTransferAccount, is 465 bytes | test `reader_agrees_with_official_unpack` (`crates/client/tests/interface_crosscheck.rs`), against spl-token-2022-interface 3.1.1 |
| V12 | Transfer verifies three handles; a mint auditor key must equal the proof's third handle | T22 `ct/processor.rs` 680-705 |
| V13 | ApproveAccount needs only the mint's confidential-transfer authority to sign | token-2022 main read 2026-09-14: `ct/processor.rs` `process_approve_account` |
| V14 | PYUSD and USDG are Token-2022 with `autoApproveNewAccounts: false` under one authority (`2apBGMsS6ti9RyF5TwQTDswXBWskiJP2LD4cUEDqYJjk`) and no auditor; USDC is legacy SPL Token | RPC `getAccountInfo` jsonParsed on mainnet-beta, 2026-09-14; re-read 2026-09-25 |
| V15 | Token-2022 and the ZK ElGamal proof program are live on both clusters; mainnet Token-2022 was last deployed at slot 427,146,011 (2026-06-17) | RPC program and programdata reads, mainnet-beta and devnet, 2026-09-25 |

## Runtime, System program, transactions

| Id | Claim | Source |
|---|---|---|
| V16 | An account at `create_with_seed(base, ...)` can be allocated or assigned only when `base` signs | solana-system-program 4.3.0 `src/system_processor.rs` 36-42, 82-89, 129-131, 145-147 |
| V17 | `create_with_seed` takes a seed of at most 32 bytes and is a public, deterministic function of (base, seed, owner) | solana-address 2.7.0 `src/lib.rs` 283-301; exercised on the pinned 2.6.1 by test `announce_writes_the_record` |
| V18 | In a v1 transaction the compute-unit and loaded-accounts limits come from the header and default to 0; ComputeBudget instructions are ignored | agave `runtime-transaction/src/transaction_meta.rs` 122-129 (`from_v1_config`); SIMD-0385 |
| V19 | The account loader fails a transaction once loaded bytes exceed the limit, counting programdata; mainnet Token-2022 programdata is 1,382,061 bytes | agave `svm/src/account_loader.rs` 473-510, 561-583; RPC 2026-09-25 |
| V20 | The v1 header carries the priority fee as total lamports, not a per-CU price | SIMD-0385 |
| V21 | v1 transactions are active on mainnet-beta since slot 447,120,000 and on devnet since 492,480,000 | RPC read of feature `txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL`, 2026-09-25 |
| V22 | `getTransaction` on a v1 signature needs `maxSupportedTransactionVersion: 1`, else error -32015 | RPC test, 2026-09-25 |
| V23 | Rent is `(size + 128) x 5,080` lamports: 0 bytes 650,240; 69 bytes 1,000,760; 465 bytes 3,012,440 | RPC `getMinimumBalanceForRentExemption` and the rent sysvar, mainnet-beta and devnet, 2026-09-25 |
| V24 | A fee payer may end a transaction at zero lamports | agave master read 2026-09-14: `svm/src/account_loader.rs` `validate_fee_payer`, `svm/src/rent_calculator.rs` `transition_allowed` |
| V25 | Transaction signatures are verified as plain RFC 8032 (`verify_strict`); the pending ZIP-215 migration (SIMD-0376) accepts more, not less | anza-xyz/solana-sdk `transaction/src/lib.rs` 157-166, `signature/src/lib.rs` 110-121, read 2026-09-14 |
| V26 | Curve25519 syscalls cost 159 CU (Edwards validate) and 2,177 CU (Edwards multiply) | anza-xyz/solana-sdk `compute_budget.rs` 220-223, read 2026-09-14 |

## Proofs, keys, crates

| Id | Claim | Source |
|---|---|---|
| V27 | Proof instruction sizes and costs: equality 321 bytes, 6,400 CU; 3-handle validity 545, 16,400; U128 range 1,001, 200,000; pubkey validity 97, 2,600 | agave `programs/zk-elgamal-proof/src/lib.rs` 20-32; proof-extraction 0.6.1 `transfer.rs` 104-124 |
| V28 | `derive_confidential_keys_from_ikm(ikm: &[u8]) -> Result<(ElGamalKeypair, AeKey), ElGamalError>`, HKDF-SHA512 salt `solana-conf-bal/v1`, info `ae` and `elgamal`; the body is identical in 7.0.1 and 8.0.0 | solana-zk-sdk 8.0.0 `src/encryption/derivation.rs` 200-221, diffed against 7.0.1 |
| V29 | litesvm 0.16.0 requires `solana-address ~2.6.1`; solana-zk-sdk 8.x reaches `^2.7.0` through solana-signer 4 and solana-pubkey 4.3, so they cannot share a lockfile; zk-sdk 7.0.1 resolves | crates.io dependency API, 2026-09-25; resolver error reproduced the same day |
| V30 | Proof generation: range proof 16.3 ms mean, a 50-recipient proof set 202.5 ms wall clock on 10 threads | measured 2026-09-14, solana-zk-sdk 8.0.0, release build, 20 iterations |
| V31 | LiteSVM loads the ZK ElGamal builtin by default, does not enforce the 4,096-byte cap or the loaded-accounts limit, and charges 6,960 lamports per byte of rent | litesvm 0.16.0 `src/lib.rs` 518 (`into_basic`), 609-621; builtin load exercised by test `s3_payment_then_sweep_in_one_recipient_transaction` |
| V32 | pinocchio 0.11.2 is `no_std`; pinocchio-token-2022 0.4.0 has no confidential-transfer module | crate tarballs from crates.io, 2026-09-25 |
| V50 | spl-token-cli 5.6.1 derives confidential keys per wallet as `derive_confidential_keys(owner, b"")`, and `scope pay` pays from a source that CLI configured, deposited and applied; spl-token-cli 5.5.0, shipped with Solana CLI 3.1.10, fails `configure-confidential-transfer-account` against current mainnet state (`SigmaProof(PubkeyValidity, AlgebraicRelation)`) | spl-token-cli 5.6.1 `src/command.rs` 4193, 4866; both CLIs run on a Surfpool 1.5.0 mainnet fork, 2026-09-28; test `source_keys_match_spl_token_cli` |
| V51 | A transfer proof's equality context ciphertext is the source's new available balance, `current - (lo + hi·2^16)` | spl-token-confidential-transfer-proof-generation 0.6.1 `src/transfer.rs` 162-178 |

## This repo: tests and spike runs

| Id | Claim | Source |
|---|---|---|
| V33 | `announce` writes the 69-byte record, works on a pre-funded address, and rejects a second call, an owner still equal to the payer, another close authority, public credits enabled, and a wrong R | tests in `announce.rs`: `announce_writes_the_record`, `announce_succeeds_when_announcement_prefunded`, `announce_twice_fails`, `announce_rejects_owner_still_payer`, `announce_rejects_other_close_authority`, `announce_rejects_public_credits_enabled`, `announce_rejects_wrong_ephemeral` |
| V34 | `reclaim` returns both rents to the payer, fails while a balance remains, and rejects a decoy token account, a wrong payer and a non-announcement | tests in `reclaim.rs`: `reclaim_returns_both_rents_to_payer`, `reclaim_fails_while_balance_remains`, `reclaim_rejects_decoy_token_account`, `reclaim_rejects_wrong_payer`, `reclaim_rejects_non_announcement` |
| V35 | The Token-2022 account reader, program ids and CloseAccount byte agree with spl-token-2022-interface 3.1.1 | tests in `crates/client/tests/interface_crosscheck.rs` |
| V36 | S3: payer setup, handover, announce and transfer land in one transaction; the recipient's apply, transfer, empty and reclaim land in another; D receives the amount and the payer gets back exactly both rents. Payer 254,600 to 257,600 CU across runs (bump search), recipient 257,484 CU | test `s3_payment_then_sweep_in_one_recipient_transaction`, run 2026-09-27 and 2026-09-28 |
| V37 | S1 in LiteSVM: payer transaction 2,999 bytes, recipient transaction 2,759 bytes (D created beforehand; no Burn, no P drain) | test `s1_both_stealth_transactions_fit_4096_bytes`, 2026-09-28 |
| V38 | S1 on Surfpool 1.5.0: the payer transaction lands as v1, 2,999 bytes, 256,100 CU; Surfpool ignores both header limits (a 100 CU limit and a 1-byte loaded-accounts limit still land) | `cargo run -p scope-client --example s1_v1`, 2026-09-27 |
| V39 | `getRecentPrioritizationFees` with no account filter returns, per slot, the lowest per-CU price among landed transactions, so it reads near zero | RPC comparison against block contents on mainnet-beta, 2026-09-27 |
| V40 | S4 first sample, per-CU price paid by landed non-vote transactions in one block: n 239, p50 1, p75 8,001, p95 937,500 micro-lamports | `cargo run -p scope-client --example s4_fees -- --once` on mainnet-beta, 2026-09-27 |
| V41 | The raw-scalar nonce prefix is derived from p alone; two messages signed by the same p give different R | `crates/stealth-keygen/src/signing.rs`; test `signatures_are_deterministic_and_message_specific` in `crates/stealth-keygen/tests/payment_flow.rs`; RFC 8032 section 5.1.6 for `s = r + c·p` |
| V42 | `stealth-keygen` rejects small-order and mixed-order spend keys and an identity P | `crates/stealth-keygen/src/derivation.rs` `payment_public_key`; tests `small_order_spend_points_are_rejected`, `mixed_torsion_spend_points_are_rejected`, `cancellation_to_identity_is_rejected` |
| V48 | The plain payer engine pays each row once in a shuffled order, through a mint with an auditor key; rebuilds only after the attempt expires; resumes after a kill before a send, after a send and between rows with every row paid once; halts when the source moves outside the run or is not where the last landed row left it; refuses a second writer, a concurrent start, a repeated input, foreign source keys, a bad recipient and an overspend before sending; keeps plaintext amounts out of the journal | tests in `crates/client/tests/pay.rs` |
| V49 | `scope pay` on Surfpool 1.5.0 pays 10 plain recipients in 25 s; each transfer lands as v1, 2,395 bytes, 237,792 CU. A second run killed with SIGKILL after 3 rows resumes and pays the other 7, one `landed` record per row | `p2_fixture` then `scope pay` and `scope pay --resume`, 2026-09-28 |
| V52 | S4 second sample: n 275, p50 1,000, p75 14,000, p95 956,022 micro-lamports; the multi-day run started from this sample | `s4_fees` on mainnet-beta, 2026-09-28 |

## Market, prior art, regulation

| Id | Claim | Source |
|---|---|---|
| V43 | Payroll privacy is stated demand: Toku's CEO on payroll going public (Toku, Aleo and Paxos launch, January 2026); Zebec reports $500M a year of payroll on Solana with no privacy; Helius names payroll platforms as Ring customers | toku.com; zebec.io; helius.dev/blog/light-protocol-acquisition; read 2026-09-11 |
| V44 | Hinkal, Umbra (Solana) and Helius Rings hide recipient and amount through custodied pools with an enclave, MPC or prover-server trust | hinkal.io and its docs; umbraprivacy.com; helius.dev/privacy and github.com/helius-labs/zolana; read 2026-09-11 |
| V45 | Program-owned confidential accounts exist in Occult | github.com/Occult-fi/occult, read 2026-09-11 |
| V46 | sRFC-42's reference implementation is devnet only, with commits from 2026-05-31 to 2026-06-05 and none since | github.com/susruth/slnt, read 2026-09-11 |
| V47 | EU TFR 2023/1113 Art. 2(4) excludes person-to-person transfers without a provider; FinCEN's October 2023 mixing NPRM lists "creating and using single-use wallets, addresses, or accounts" | eur-lex.europa.eu CELEX 32023R1113; govinfo.gov FR-2023-10-23 document 2023-23449 |
| V53 | Migrated crypto crate uses HKDF-SHA256 with separate account-context ElGamal and balance-key branches; both parties derive matching keys | `crates/stealth-keygen/src/derivation.rs`; `sender_and_recipient_derive_usable_elgamal_keys`, `balance_keys_agree_and_encrypt_full_u64_balances`, and independent `tests/fixtures/hkdf.txt`; 2026-09-28: all 37 crate tests pass with workspace `solana-zk-sdk = 7.0.1`; regenerated fixture matches the standalone library |
