---
status: decided
last_verified: 2026-09-28
---

# Docs

TL;DR: one flat folder. `brief.md` says what and why, `design.md` how, `client.md` the off-chain side, `verification.md` the evidence, `decisions.md` the why and the history.
Start with the root README, then the brief and the plan.

## Files

| File | Purpose | Canonical for |
|---|---|---|
| [brief.md](brief.md) | What we build and why, limitations, scope, success criteria | scope |
| [design.md](design.md) | Components, keys, accounts, `announce` and `reclaim`, one payment per side, money, limitations | on-chain design |
| [client.md](client.md) | Payer engine, recipient flow, audit receipts, fees, testing, stack | off-chain design |
| [crypto.md](crypto.md) | Key derivation, curve checks, signing, reviewer checklist | cryptography |
| [privacy.md](privacy.md) | Adversaries, what an observer sees, residual leaks | privacy guarantees |
| [plan.md](plan.md) | Owners, phases and gates with status, spikes, risks, open questions | what happens next |
| [decisions.md](decisions.md) | Dated entries: what, why, what was rejected | history |
| [verification.md](verification.md) | Every load-bearing claim with its primary source | evidence |

## Reading order

- Everyone: the [root README](../README.md), then brief, then plan.
- Program and payer engine: design, client, decisions.
- Crypto and recipient: design, crypto, client (Recipient flow), privacy.
- Audit and security: design, privacy, crypto, client (Audit, Testing), verification.

## Rules

1. Every doc starts with front-matter `status` (todo, draft, decided or verified) and `last_verified` (a date), then a two-line TL;DR.
2. Under about 1,500 words of prose per doc; split a doc that grows past that and list it here.
3. Every load-bearing claim cites a row in verification.md as (verification: Vn) or a test in this repo. Anything else is marked [unverified].
4. Docs describe the present. The why and the history go in decisions.md.
5. Ids are defined in plan.md: P for phases, S for spikes, Q for open questions. Ids are never reused.
6. "Payer" and "recipient", never "sender" except when quoting a standard.
