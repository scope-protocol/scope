---
status: decided
last_verified: 2026-10-07
---

# Decisions

TL;DR: why SCOPE is built the way it is: append-only, newest first; each entry says what was decided, why, and what was rejected. Docs describe the present; this file holds the why.
Entries before 2026-10-06 are in [decisions-archive.md](decisions-archive.md). Design history from before this repository is not kept here.

## 2026-10-07 Receipt trust and mint policy

- **Receipts authenticate the transaction they name.** `verify` and recipient `disclose` require the archived transaction to carry the receipt's signature first and every signature to verify. Without that, a node could answer with a transfer it built from openings it knows. A node can still misreport success; that trust stays with the verifier's choice of node. Rejected: checking success against a second node, which only moves the trust.
- **Mint policy binds new payments only.** Resume reconciles every recorded and open attempt before it checks the mint's stealth requirements, and only against rows still to pay; `disclose` and `status` read the mint's decimals and nothing else. A mint authority can change approval or the auditor key at any time, and that must not strand a payment already on chain or its receipt. Rejected: snapshotting the policy in the run header, which would let a run keep paying under a policy the mint no longer has.

## 2026-10-06 Payer stealth rows

- **A registry in sRFC-42's layout (Q12).** Two instructions in our program, `register` and `deregister`, writing sRFC-42 v1's entry byte for byte under the same seeds, so its readers work on ours. That answers the deferral below, whose reason was that the seeds did not match; S7's torsion check refuses a bad B_spend on chain. Payers look up with one query and paste the meta-address into the payroll file, which then records exactly whom it paid. Rejected: a private layout, resolving registry rows inside `scope pay` (a re-registration between start and resume would change a recipient mid-run), and a second program, which the one-program rule excludes.
- **Receipts: the payer's openings for every row, `ct_ikm` for the stealth recipient (Q15).** Plain recipients' keys are their wallet keys and cannot be handed out per payment, but the payer's amount openings prove any row's amount and reveal nothing else, and the run secret re-derives them. A recipient's receipt is built from the payment transaction alone and is refused unless its key is the transfer's destination key. Rejected: stealth-only receipts with plain payments left to the auditor key.
- **The run secret comes from the payer's signature (Q16).** `run_secret = HKDF(payer's Ed25519 signature over a fixed label || run_id)`. Signing is deterministic, so the payer keypair, already backed up, rebuilds every run's secret, every R_i and every amount opening; the same pattern as the source keys. Rejected: a master secret in an age file or the keychain (one more backup and storage code for the same result).
- **Amount openings are derived, not drawn.** The engine builds transfer proofs with the same builders as proof-generation 0.6.1 but takes the two amount openings from the run secret. A payer can then prove any row's amount, plain or stealth, by disclosing that row's openings, with nothing stored. Every attempt for a row moves the same amount, so reusing its openings across attempts reveals nothing. Rejected: random openings stored beside the journal (a secret on disk that the journal rule keeps out).
- **P is funded for every attempt the sweep may make.** The sweep requires one attempt's cost exactly; the payer adds one more attempt's fee per rebuild, because an attempt that lands and fails is still charged and a short P could only be topped up from a wallet that links the recipient. What P does not spend goes to D_owner. Rejected: funding exactly one attempt.
- **Status never calls a row unpaid that might be paid.** A row the run attempted but never recorded, with no open announcement, may have landed and been swept since; status calls it unresolved, and only resume, from the source ciphertext, settles it. Rejected: reporting it unpaid, which invites paying twice.
- **Send order stays random, recorded in the run header.** Deriving it from the run secret adds nothing the header does not already give resume. Rejected: deriving the order from the run secret.
- **Prefunded one-time addresses are created anyway.** An expired attempt publishes T's address; anyone can then send it lamports, which makes CreateAccountWithSeed fail. The rebuild tops up, allocates and assigns instead. Rejected: halting, which would let one transfer of dust stop a run.
- **Compute limits per shape and one funding rule for P.** The fee is paid on the header's CU limit, so each shape gets its own limit about 15% above measurement (V73), and the payer funds P with exactly what the sweep needs at the 1,000,000 micro-lamport cap (V74). Rejected: one 600,000 limit for everything, and a funding estimate the sweep did not share.

## 2026-10-06 Recipient outcomes and retry pricing

- **Completion survives metadata failures.** A successful finalized signature is authoritative. Later balance reads are optional and share the remaining deadline; absent observations remain explicit `None` values. Account-state completion similarly survives optional reporting failures. Rejected: returning `Pending` after observing completion or presenting a predicted balance as a measured one.

- **New attempts get current prices.** Preparation and safe rebuilds share the payer's p75-plus-cap policy. Identical resends retain the same fee and signature. Unresolved submission retains its latest send error without treating it as proof of failure. Rejected: reusing stale prices on new attempts or aborting solely on a transport error.

- **Recovery is durable and the destination is usable.** Every non-dry-run attempt is synchronized to a private, locked recovery journal before stdout and broadcast. Public R and the backup can export D_owner as a standard private keypair file; its wallet keys can apply and spend D's pending balance. New directory entries are synchronized, and incomplete journal tails are repaired under the lock. Historical transaction discovery remains Q17. Rejected: relying on terminal output alone, exporting secrets to stdout, overwriting key files, or changing the derivations.
