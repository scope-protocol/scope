---
status: draft
last_verified: 2026-10-06
---

# Plan

TL;DR: six phases, each closed by a gate that is a running command or a passing test, not a date. P0 and P1 are done except the devnet leg of S1, the multi-day S4 run and the Q1 review request; Q14 code is implemented and awaiting review. The plain payer engine runs on Surfpool; the program's attack tests, CU ceilings and S5 are in; devnet runs are next.
Three owners split by area; open questions have owners, and the cut order applies as soon as a gate stalls.

## Owners

| Area | Owner | Code | Reviewer |
|---|---|---|---|
| Program and payer engine | Valentyn | `crates/interface`, `programs/scope`, payer side of `crates/client`, `cli` pay and bench | Abhineet; Jmkoy for `programs/` |
| Crypto and recipient | Abhineet | `crates/stealth-keygen`, recipient side of `crates/client`, `cli` scan and sweep | Valentyn |
| Audit and security | Jmkoy | registry (P4), receipts in `crates/client`, `cli` disclose and verify, adversarial suite, CU assertions, CI | Valentyn; Abhineet for receipts |

The areas meet at two contracts: `crates/interface` (announcement layout, instruction data, seeds, errors, Token-2022 account reader) and the `ct_ikm` export of `crates/stealth-keygen`. A change to either needs approval from every area that uses it.

## Phases

| Phase | Work | Gate | Status |
|---|---|---|---|
| P0 Foundation | workspace, CI, lints, cargo-deny; interface crate with the Token-2022 account reader cross-checked against spl-token-2022-interface; devnet wallets funded | CI green on every crate; the reader agrees with spl-token-2022-interface 3.1.1 on every field `announce` reads | done, except funded devnet wallets |
| P1 Prove the design | S1; S3, which builds `announce` and `reclaim` with the decoy test; S4 starts; Q14, then the Q1 request | S1 and S3 green, or the fallback chosen and logged in decisions.md; Q1 request sent | S3 green; S1 green in LiteSVM and on Surfpool, devnet pending; S4 sampler built and first sample taken, multi-day run pending; Q14 code implemented, review pending; Q1 open |
| P2 First payments | payer engine pays 10 plain recipients on devnet; `announce` on devnet; scan against Surfpool; S6; adversarial tests for `announce` | plain run on devnet; 10 stealth payments announced and found by scan | `scope pay` pays plain recipients, 10 on Surfpool with a kill and resume (V49); devnet run pending; attack tests for `announce` done (V54); recipient CLI, scan and sweep are implemented with local integration and RPC fixture coverage (V64 to V67); provider-scale S6 and Surfpool scan remain open; stealth rows paid and found by the recipient's own scan in LiteSVM, with kill and resume (V72, V73) |
| P3 Stealth end to end | `reclaim` on devnet; journal and resume; sweep with plain instructions, refusing reused destinations; disclose | one stealth payment end to end on devnet, one transaction per side, rent back with the payer; a run resumes after a kill at three steps; a receipt exists for it | recipient sweep and recovery implemented in LiteSVM (V65); payer to sweep end to end in LiteSVM, rent back to the payer (V74); payer resume covered (V48); payer and recipient receipts disclosed and verified in LiteSVM (V76, V77); devnet remains open |
| P4 Hardening | chaos harness; rest of the adversarial suite; CU assertions in CI; verify; S5; Q1 findings; registry decision (Q12) and, if built, its on-chain torsion check (S7) | attacks rejected; the harness converges from every kill point of a 20-recipient run; verify accepts the P3 receipt and rejects a forged `ct_ikm` | program attack suite, CU ceilings in CI and S5 done early (V54 to V56); `verify` accepts payer and recipient receipts and rejects a forged `ct_ikm`, a changed amount and another cluster (V76, V77) |
| P5 Ship | 50-recipient run on devnet; measurements published; recorded demo; sRFC-42 write-up with the issuer spec (Q9); status page | three-minute terminal demo, mixed modes, then a receipt verified by a third party; measured numbers replace every [likely] cost | |

From P2 on, a phase starts when the previous gate has passed. Within a phase the areas work in parallel; a test of another area's code is written against `crates/interface` and turns green when that code lands.

A gate closes when it is shown to the team running. Done means CI green, reviewed by another owner, `last_verified` bumped on every doc touched, and any decision logged in decisions.md.

## Spikes

Spikes are tests or example binaries in the crate they exercise and stay as regression checks. Results: [verification.md](verification.md).

| Id | Question | Exit criterion | Owner | Result |
|---|---|---|---|---|
| S1 | v1 (4,096-byte) transactions end to end: LiteSVM, Surfpool, devnet | the payer transaction with four ZK verify instructions lands in all three | Valentyn | LiteSVM: payer 2,999 bytes, recipient 2,759 (V37). Surfpool 1.5.0: payer lands as v1, 256,100 CU, but Surfpool ignores both header limits (V38). Devnet pending: the only check of the header limits |
| S3 | payer-owned setup, handover and announce, then the recipient's apply, transfer, empty and reclaim, in LiteSVM | test passes | Valentyn | green; payer 254,600 to 257,600 CU, recipient 257,484 CU (V36) |
| S4 | per-CU priority fee paid by landed non-vote transactions, over several days | p50, p75, p95 in a table | Valentyn | sampler in `crates/client/examples/s4_fees.rs`; first samples in V40 and V52; multi-day run started 2026-09-28 |
| S5 | measured bytes and CU of both full transactions | numbers in design.md | Valentyn | LiteSVM at bump 255: payer 2,998 bytes, 254,565 CU; recipient 2,759 bytes, 256,800 CU (V56). Devnet numbers with S1 |
| S6 | `getProgramAccounts` and local per-announcement tag checks against 1,000 seeded accounts on our RPC provider | allowed, latency measured | Abhineet | P2; fixed recipient tag filtering is not possible because tags depend on R |
| S7 | curve25519 syscalls (validate, multiply by L) from a `no_std` Pinocchio program in LiteSVM | rejects a small-order point, accepts a valid one, CU measured | Jmkoy | only if the registry is built (P4) |

## Cut order

1. Status page.
2. Mollusk as a separate CI job (LiteSVM reports CU too).
3. Receipt verifier CLI (ship the format, verify by script).
4. 50-recipient run (ship 10, numbers marked as such).
5. Chaos harness (keep the resume test at three kill points).

Never cut: interface cross-check tests, the adversarial suite, the nonce regression test.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| v1 transactions unusable somewhere in the loop | transaction packing changes | S1 on devnet; fallback is proof context accounts and several transactions per side; handover unaffected |
| Derivation flaw found in review | key redesign | derivations stay in `crates/stealth-keygen`, so a fix touches that crate, not transaction shapes |
| Token-2022 account reader wrong | `announce` accepts a bad setup or refuses a good one | cross-check tests against spl-token-2022-interface 3.1.1 |
| Priority fees under congestion | P underfunded, sweeps stall | S4; floor check before each signed attempt; overprovision P |
| Devnet faucet caps | demo blocked | fund early; LiteSVM and Surfpool as the recorded fallback |
| Confidential transfers disabled on a cluster again, as in 2025 | demo blocked | same fallback |
| Regulatory reading of single-use addresses | positioning | visible payer as a hard constraint; disclosure paths documented; counsel before any "compliant" claim |
| No wallet support | adoption | CLI first; a wallet SDK is the follow-up |

## Open questions

Ids are stable; gaps are questions already closed.

| Id | Question | Owner | Resolve by | Recommendation |
|---|---|---|---|---|
| Q1 | External review of the derivations from S, and of `d` from `b_spend` | Valentyn | request after Q14; findings addressed in P4 | post the tree to the sRFC-42 discussion; ask one Anza zk contributor |
| Q5 | FinCEN mixing definition and single-use addresses | Valentyn | before public claims | assume it applies; keep the payer visible |
| Q6 | A named Solana payout platform that wants this | Valentyn | P5 | ask Zebec, Streamflow, Superteam Earn |
| Q8 | MPC-based consolidation after v1 | Valentyn | after the demo | talk to Arcium |
| Q9 | Issuer path for PYUSD and USDG | Valentyn | P5 | one-page spec in the write-up: a policy program whose PDA is the mint's confidential-transfer authority, plus a deferred handover after approval; do not build |
| Q10 | Rent refund depends on the recipient | Valentyn | after v1 | two cases: P never empties the account, or P enables CpiGuard, which blocks reclaim's CPI close. State both as limitations; a timeout reclaim needs a different custody model and is not planned |
| Q11 | One ephemeral key per run (scan cost against grouping) | Valentyn | after Q1 | defer until the review has seen the tree |
| Q12 | On-chain registry: build our own in P4, or reuse sRFC-42's | Jmkoy | P4 | if lookup matters, reuse or match sRFC-42's seeds rather than a private layout |
| Q14 | Finish `crates/stealth-keygen` on the crypto.md tree: `d`, externally supplied ephemeral keys, meta-address parsing; pin `program_id` in `C` | Abhineet, reviewed by Valentyn | before Q1 goes out | implemented: supplied ephemeral keys (V58), public imports (V59), recipient backups (V60), `d` (V61), meta-addresses (V62) and the pinned client context; keep the nonce-from-p construction and the vector generator |
