---
status: decided
last_verified: 2026-10-07
---

# Docs

TL;DR: which doc to read for your role. One flat folder, one question per doc, each fact in one place.
Start with the root README for building and testing, then the reading path for your role below.

## Files

| File | Answers |
|---|---|
| [overview.md](overview.md) | What problem SCOPE solves, what it guarantees and does not, what it costs, what counts as done |
| [protocol.md](protocol.md) | What exists on chain: accounts, addresses, the two transactions, the four instructions and their checks, the registry, costs |
| [crypto.md](crypto.md) | How every key is derived, which curve checks apply, what a cryptography reviewer should check |
| [privacy.md](privacy.md) | Who learns what, and every limit on privacy or trust |
| [payer.md](payer.md) | How do I pay people: input file, `scope pay`, crash safety, fees, accepted mints, status and reclaim |
| [recipient.md](recipient.md) | How do I receive: `register`, `publish`, `scan`, `sweep`, `export-sweep-key`, backups and recovery |
| [audit.md](audit.md) | How do I prove an amount: `disclose`, `verify`, receipt formats, what a receipt reveals |
| [plan.md](plan.md) | What is built, what is next, gates, spikes, risks, open questions with owners |
| [decisions.md](decisions.md) | Why things are the way they are, newest first |
| [decisions-archive.md](decisions-archive.md) | Decisions from before 2026-10-01 |
| [verification.md](verification.md) | The evidence: every load-bearing claim with its primary source or test |

## Reading paths

- **Operator paying people:** overview, payer, privacy, audit.
- **Recipient:** overview, recipient, privacy.
- **Auditor checking a disclosed amount:** audit, then privacy for what a receipt does not prove.
- **Reviewer of the program:** protocol, privacy, then the program rows in verification.
- **Cryptography reviewer:** crypto, protocol (Accounts and Registry), privacy; open review is Q1 in plan.
- **Contributor:** root README, plan (Owners, Next), decisions, verification.

## Rules

1. Every doc starts with front-matter `status` (todo, draft, decided or verified) and `last_verified` (a date), then a two-line TL;DR saying who the doc is for and what they can do after reading it.
2. Under about 1,500 words of prose per doc; split a doc that grows past that and list it here.
3. Every load-bearing claim cites a row in verification.md by id, as (V12) or (verification: V12), or names a test in this repo. Marks: [likely] argued from a standard result or from arithmetic on verified facts, untested here; [open] unknown or awaiting a reviewer, tracked in plan.md; [unverified] no row or test yet.
4. Docs describe the present. The why and the history go in decisions.md. What is built, next or open goes in plan.md only.
5. Each fact lives in one doc; others link to it in one line.
6. Ids are defined in plan.md: P for phases, S for spikes, Q for open questions. Ids are never reused.
7. "Payer" and "recipient", never "sender" except when quoting a standard or a type name.
