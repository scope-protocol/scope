---
status: decided
last_verified: 2026-10-10
---

# Decisions

TL;DR: why SCOPE is built the way it is: append-only, newest first; each entry says what was decided, why, and what was rejected. Docs describe the present; this file holds the why.
Entries before 2026-10-06 and the older ones of that day are in [decisions-archive.md](decisions-archive.md). Design history from before this repository is not kept here.

## 2026-10-10 Reliability, recovery and the mint reality

- **Q17 is `scope recover`, not a counter-derived destination.** The `announce` instruction stays in the payment transaction, and T follows from (payer, R), so a node that keeps the program's history lists every payment, swept or not. `disclose` finds its own signature the same way. Cost: up to `--limit` `getTransaction` calls; tested only against a fake archive (V88).
- **The sweep applies D's pending balance.** Funds are spendable at once, at 3,402 bytes and 276,007 CU, 89% of the 310,000 limit. The limit stays: it sets P's funding, so raising it changes every fixed figure in payer.md. Revisit if a mint extension adds compute.
- **One mint policy, and PYUSD and USDG are refused.** Both mainnet mints carry a 0 bps fee config and a hook with no program; SCOPE has no `TransferWithFee` path and passes no hook accounts. Building the fee path is out of scope (Q9 stays a spec); the first usable mint approves accounts and carries neither. A paused mint is refused up front; burn-only extensions are allowed, because the sweep's burn falls back to a transfer-only sweep.
- **A row halts after three failed or expired attempts.** An attempt that lands with an error counts, so a prefunded one-time address still rebuilds (V76).
- **The duplicate guard hashes parsed rows, the mint and the payer.** Formatting and order cannot slip a payroll past it; another mint's run is not a duplicate.
- **Exit codes carry the next step:** 1 refused before sending, 3 retry or resume later, 4 stopped after sending.
- **Registry instructions go as legacy transactions.** A 109-byte account needs no v1 header.

## 2026-10-09 Pre-deploy hardening

- **The sweep destination also binds T.** `d` is `HKDF-SHA512(b_spend, info = "d-owner" || R || T)`. A payer that knows r can announce a second account under the same R from another payer address; with D keyed by R alone, sweeping that dust account first made the real payment's sweep refuse ("destination exists") until D was emptied. Funds were never at risk, the sweep stalled. `export-sweep-key` and the recovery journal now carry T, so a recipient who kept R but not T cannot rebuild D. Nothing is deployed, so there is no migration: a run started under the old run secret or a sweep into an R-only D is not recoverable. Rejected: adding B_spend to the info, which is a function of the key already used and adds nothing; and a counter-derived D with gap-limit scanning, which drops the per-R binding for no gain once R and T are recoverable from chain history.
- **`announce` refuses a locked CpiGuard on T (error 25).** With the guard locked, Token-2022 refuses a CPI close to anyone but the owner, which would make `reclaim` fail for good. Locking it also blocks the owner hand-over, so a payer cannot reach that state through the setup transaction; the check covers an account whose owner is not P or one set up by another client. It costs 11 CU and one error code. A recipient who enables the guard after the handover cannot be stopped on chain (Q10 stays).
- **Run secret v2.** The signed message is `0xff || "scope-run-secret/v2" || run_id`; a leading 0xff is a byte the runtime reserves for off-chain messages, so no transaction message starts with it. `RunSecret::derive` takes a `Keypair`, since a randomizing signer would derive another secret on resume. Independent known-answer vectors fix the whole chain (V85). Rejected: Solana's off-chain message header, which carries an application domain and signer list this signature does not need.
- **The spend scalar stays the HKDF input for d (the open question in crypto.md).** HKDF-Extract turns a high-entropy secret into a uniform key under a public salt; a dedicated master secret would add a backup artifact. Zeroization is documented as best effort.
- **The view tag stays one byte.** Spam copies a victim's real (R, tag), so a wider tag does not stop it; scan cost is fixed on the client.
- **`reclaim` and the PDA close authority stay for v1.** Giving the rent to the recipient would delete Q10 and the CpiGuard case but cost about 0.004 SOL a payment and redo the program and its tests. Revisit after Q1.

## 2026-10-07 Receipt trust and mint policy

- **Receipts authenticate the transaction they name.** `verify` and recipient `disclose` require the archived transaction to carry the receipt's signature first and every signature to verify. Without that, a node could answer with a transfer it built from openings it knows. A node can still misreport success; that trust stays with the verifier's choice of node. Rejected: checking success against a second node, which only moves the trust.
- **Mint policy binds new payments only.** Resume reconciles every recorded and open attempt before it checks the mint's stealth requirements, and only against rows still to pay; `disclose` and `status` read the mint's decimals and nothing else. A mint authority can change approval or the auditor key at any time, and that must not strand a payment already on chain or its receipt. Rejected: snapshotting the policy in the run header, which would let a run keep paying under a policy the mint no longer has.
