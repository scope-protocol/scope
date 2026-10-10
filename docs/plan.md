---
status: draft
last_verified: 2026-10-10
---

# Plan

TL;DR: the one status doc, for owners and anyone asking "is X done, and what comes next?". Everything is built and tested in LiteSVM; nothing is deployed, and devnet work is next.
Two owners split by area; each phase closes on a gate that is a running command or a passing test, open questions carry an owner and a recommendation, and the cut order applies as soon as a gate stalls.

## Owners

| Area | Owner | Code | Reviewer |
|---|---|---|---|
| Program, payer engine and audit | Valentyn | `crates/interface`, `programs/scope` including the registry, payer side of `crates/client`, receipts, `cli` pay, lookup, publish, disclose, verify and bench, adversarial suite, CU assertions, CI, deployment | Abhineet |
| Crypto and recipient | Abhineet | `crates/stealth-keygen`, recipient side of `crates/client`, `cli` register, scan, sweep and export-sweep-key | Valentyn |

The areas meet at two contracts: `crates/interface` (announcement and registry layouts, instruction data, seeds, errors, Token-2022 account reader) and the `ct_ikm` export of `crates/stealth-keygen`. A change to either needs approval from every area that uses it.

## Status

| Area | Built, with evidence | Open |
|---|---|---|
| Program | `announce`, `reclaim`, `register`, `deregister`; an attack test for every reachable check (V33, V34, V54, V81); `announce` refuses a locked CpiGuard (V86); S7 torsion check (V82); CU ceilings in CI (V55, V73) | not deployed; no verifiable build; devnet upgrade key, then a Squads multisig, then revocation before mainnet |
| Transactions | both stealth transactions fit v1 in LiteSVM (V56) and the payer one lands on Surfpool (V38) | S1 devnet leg, the only check of the header limits; S5 devnet numbers |
| Payer engine | plain and stealth rows, journal, resume, canonical duplicate-run guard, cluster pinned in the journal (V48, V49, V75, V76, V84, V91); status and reclaim (V78); per-shape CU limits (V73); exact P funding (V74); retries on reads, a rebuild cap, a SOL preflight, `--dry-run` and the mainnet `--yes` gate, `--reclaim-all` (V91, V92); one mint policy (V90); chaos harness, all sixty kill points, run nightly (V83) | P2 plain devnet run; stealth payments on devnet; S4 three-day window |
| Recipient | `register` backups, `scan` in batches, `sweep` and `sweep --all` with jitter and an applied balance, `export-sweep-key`, recovery journal (V64 to V71, V87, V89); `recover` from transaction history (V88); payer to sweep end to end with rent back to the payer (V77) | scan against Surfpool; S6 at provider scale; counterparty destinations and destination-reuse overrides; `recover` against a real node with transaction history (Q17) |
| Registry | `publish`, `lookup` and paying a looked-up meta-address (V81) | |
| Audit | payer and recipient receipts, `disclose` and `verify` (V79, V80); the recipient receipt finds its payment signature itself (V88) | `recover` against a real node (Q17); `disclose --run` needing the mint account to still exist is untested |
| Crypto | the crypto.md tree in `crates/stealth-keygen` (V58 to V62); run secret and derived openings (V75, V79) | external review (Q1) |
| CLI | every command but `bench`; typed exit codes (V92) | `bench` is a stub |
| Ship | | P5: devnet run, measurements, demo, write-up, status page; Q6 first, because no major stablecoin works today (V90); Q5 |

## Next

In dependency order. Each step needs the one before it unless marked parallel.

1. Confirm the program keypair kept outside the repo matches the program id, then devnet deploy and fund devnet wallets (Valentyn). A mismatch strands every `ct_ikm` derived against the id.
2. S1 on devnet, and S5's numbers measured there (Valentyn).
3. P2 plain run: 10 plain recipients on devnet (Valentyn).
4. P3: one stealth payment end to end on devnet, payer to sweep, rent back to the payer (both owners).
5. Ten stealth payments on devnet, announced and found by scan (both owners).
6. Scan against Surfpool, then S6 on the selected provider (Abhineet).
7. P5: the 50-recipient devnet run, measurements, demo, sRFC-42 write-up with the issuer spec (Q9), status page.
8. After P5: Q17, counterparty destinations and reuse overrides, Q5, Q6.

In parallel, now: send the Q1 review request; rerun S4 for an unbroken three-day window.

## Phases and gates

Phases name gates, not a strict sequence: work for a later phase can land before an earlier gate closes, and a gate closes only when its command passes on the cluster it names.

| Phase | Work | Gate | Status |
|---|---|---|---|
| P0 Foundation | workspace, CI, lints, cargo-deny; interface crate with the Token-2022 account reader cross-checked against spl-token-2022-interface; devnet wallets funded | CI green on every crate; the reader agrees with spl-token-2022-interface 3.1.1 on every field `announce` reads | done, except devnet wallets |
| P1 Prove the design | S1; S3 with the decoy test; S4 starts; Q14, then the Q1 request | S1 and S3 green, or the fallback chosen and logged in decisions.md; Q1 request sent | S3 green; S1 devnet leg open; Q1 not sent |
| P2 First payments | payer engine on devnet; `announce` on devnet; scan against Surfpool; S6; adversarial tests for `announce` | plain: 10 plain recipients paid on devnet. Stealth: 10 stealth payments announced on devnet and found by scan | plain on Surfpool (V49), stealth in LiteSVM (V75); devnet open |
| P3 Stealth end to end | `reclaim` on devnet; journal and resume; sweep with plain instructions, refusing reused destinations; disclose | one stealth payment end to end on devnet, one transaction per side, rent back with the payer; a run resumes after a kill at three steps; a receipt exists for it | done in LiteSVM (V48, V77, V79, V80); devnet open |
| P4 Hardening | chaos harness; rest of the adversarial suite; CU assertions in CI; verify; S5; Q1 findings; registry and S7 | attacks rejected; the harness converges from every kill point of a 20-recipient run; verify accepts the P3 receipt and rejects a forged `ct_ikm` | done in LiteSVM (V54 to V56, V79 to V83); Q1 findings and the devnet P3 receipt open |
| P5 Ship | 50-recipient run on devnet; measurements published; recorded demo; sRFC-42 write-up with the issuer spec (Q9); status page | three-minute terminal demo, mixed modes, then a receipt verified by a third party; measured numbers replace every [likely] cost | not started |

Within a phase the areas work in parallel; a test of another area's code is written against `crates/interface` and turns green when that code lands. Done means CI green, reviewed by the other owner, `last_verified` bumped on every doc touched, and any decision logged in decisions.md.

## Spikes

Spikes are tests or example binaries in the crate they exercise and stay as regression checks. Numbers: [verification.md](verification.md).

| Id | Question | Exit criterion | Owner | Status |
|---|---|---|---|---|
| S1 | v1 (4,096-byte) transactions end to end: LiteSVM, Surfpool, devnet | the payer transaction with four ZK verify instructions lands in all three | Valentyn | LiteSVM and Surfpool green (V56, V38); devnet open |
| S3 | payer-owned setup, handover and announce, then the recipient's apply, transfer, empty and reclaim, in LiteSVM | test passes | Valentyn | green (V56, V77) |
| S4 | per-CU priority fee paid by landed non-vote transactions, over several days | p50, p75, p95 in a table | Valentyn | single samples (V40, V52); two longer runs stopped early, 112 samples in all [unverified]; no three-day window yet |
| S5 | measured bytes and CU of both full transactions | numbers in protocol.md | Valentyn | LiteSVM done (V56); devnet open |
| S6 | `getProgramAccounts` and local per-announcement tag checks against 1,000 seeded accounts on our RPC provider | allowed, latency measured | Abhineet | RPC fixture only (V67); provider run open |
| S7 | curve25519 syscalls from a `no_std` Pinocchio program: reject small-order and mixed-order B_spend, accept a valid one | rejects a small-order point, accepts a valid one, CU measured | Valentyn | green (V82) |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| v1 transactions unusable somewhere in the loop | transaction packing changes | S1 on devnet; fallback is proof context accounts and several transactions per side; handover unaffected |
| Derivation flaw found in review | key redesign | derivations stay in `crates/stealth-keygen`, so a fix touches that crate, not transaction shapes |
| Token-2022 account reader wrong | `announce` accepts a bad setup or refuses a good one | cross-check tests against spl-token-2022-interface 3.1.1 |
| Priority fees under congestion | P underfunded, sweeps stall | S4; P funded at a fixed price cap (V74); floor check before each signed attempt |
| Devnet faucet caps | demo blocked | fund early; LiteSVM and Surfpool as the recorded fallback |
| Confidential transfers disabled on a cluster again, as in 2025 | demo blocked | same fallback |
| zk-sdk 7.0.1 differs from the cluster's proof verifier (the program was re-enabled in 2026 after the 2025 transcript fix) | proofs rejected late, in simulation | S1 on devnet before any payer run; record the SDK commit that carries the fix |
| No major stablecoin passes the mint policy (V90) | no real-money use | Q6 gates P5; the first mint is one that approves accounts and carries no fee or hook extension |
| Regulatory reading of single-use addresses | positioning | visible payer as a hard constraint; disclosure paths documented; counsel before any "compliant" claim (Q5) |
| No wallet support | adoption | CLI first; a wallet SDK is the follow-up |

## Cut order

1. Status page.
2. Mollusk as a separate CI job (LiteSVM reports CU too).
3. 50-recipient run (ship 10, numbers marked as such).

Never cut: interface cross-check tests, the adversarial suite, the chaos harness, the nonce regression test.

## Open questions

Ids are stable; gaps are questions already closed (decisions.md and its archive).

| Id | Question | Owner | Resolve by | Recommendation |
|---|---|---|---|---|
| Q1 | External review of the derivations from S, and of `d` from `b_spend` | Valentyn | now; findings addressed in P4 | send the request: post the tree to the sRFC-42 discussion and ask one Anza zk contributor |
| Q5 | FinCEN mixing definition and single-use addresses | Valentyn | before public claims | assume it applies; keep the payer visible; ask counsel |
| Q6 | A named Solana payout platform that wants this | Valentyn | before P5 starts | ask Zebec, Streamflow, Superteam Earn |
| Q8 | MPC-based consolidation after v1 | Valentyn | after the demo | talk to Arcium |
| Q9 | Issuer path for PYUSD and USDG | Valentyn | P5 | one-page spec in the write-up: a policy program whose PDA is the mint's confidential-transfer authority, plus a deferred handover after approval; do not build |
| Q10 | Rent refund depends on the recipient | Valentyn | after v1 | two cases: P never empties the account, or P enables CpiGuard, which blocks reclaim's CPI close. State both as limitations; a timeout reclaim needs a different custody model and is not planned |
| Q11 | One ephemeral key per run (scan cost against grouping) | Valentyn | after Q1 | defer until the review has seen the tree |
| Q14 | `crates/stealth-keygen` on the crypto.md tree: `d`, supplied ephemeral keys, meta-address parsing, `program_id` pinned in `C` | Abhineet, reviewed by Valentyn | with Q1 | code complete (V58 to V62); awaiting Q1 only; close with a decisions.md entry once Q1 finds nothing to change |
| Q17 | Recover swept destinations and recipient receipts from the backup alone, without a local journal | Abhineet | after P3 on devnet | built as `scope recover` over a node that keeps program transaction history (V88); open until it runs against a real node and its RPC cost per transaction is measured; keep the recovery journal beside the key backup meanwhile |
