---
status: draft
last_verified: 2026-10-10
---

# Overview

TL;DR: for anyone deciding whether SCOPE fits a payout problem. After reading you know what it hides, what it does not, what it costs per payment and what counts as done.
SCOPE is a confidential payout rail on Solana: a visible payer pays many recipients with encrypted amounts, and a recipient who wants it gets a fresh, unlinkable account per payment. No pool, no relayer, no MPC, no enclave; the money stays an ordinary Token-2022 token.

## What problem does it solve?

Every payout on a public ledger is a permanent record of who was paid and how much. Companies name this as what keeps payroll and supplier payments off chain (verification: V43).

Solana has both halves of a fix, and neither covers a real payout flow:

| Tool | Hides | Leaves public | State |
|---|---|---|---|
| Token-2022 confidential balances | the amount | the recipient's fixed address, so "X pays W monthly" is visible | live on mainnet-beta (verification: V15); usage near zero and no wallet support [unverified] |
| Stealth addresses (sRFC-42) | the recipient, through a fresh address per payment | the amount | draft, devnet reference implementation, no commits since June (verification: V46) |

They do not combine today. Configuring a confidential account needs the owner's signature and a proof that the owner holds the encryption key (verification: V1). A payer paying a fresh address has neither, so the recipient would have to be online to set up every account.

## What does SCOPE give?

**Hidden amounts for every row.** A payout run pays N recipients, one transaction per recipient, with proofs generated on the payer's machine, fees handled and an audit path. A row is one of two kinds, mixed freely in one run:

- **Plain.** The recipient already has a confidential account; the payer transfers to it. Amount hidden, address fixed.
- **Stealth.** The recipient published one reusable meta-address; each payment lands in a fresh account only they can find. Amount and recipient hidden from the public.

**Unlinkable one-time accounts, set up by the payer alone.** For a stealth row the payer creates the account, configures it with an encryption key derived from the secret both sides share through the stealth handshake, pins its rent refund to the payer and hands ownership to the recipient's one-time key, all in one transaction. The recipient later moves the money with plain Token-2022 instructions in one transaction of its own. The SCOPE program is never in the funds path. How: [protocol.md](protocol.md); the key derivations: [crypto.md](crypto.md).

**A visible payer.** By design: it keeps the rail outside mixer territory, and the payer can prove any payment's amount to an auditor. A stealth recipient can prove its own. Either proof checks against the chain without trusting whoever discloses it ([audit.md](audit.md)).

**No pool.** Nothing is deposited into shared custody, and the token is never wrapped.

## What does it not do?

Each limit is stated once, in the doc that owns it:

- Who learns what (the public, an RPC provider, the payer, a mint authority), and every limit on privacy or trust: payer visibility, the payer seeing where its own payment goes, merging re-linking payments, the one-time public amount when the payer shields treasury, headcount, scanning and registry lookups: [privacy.md](privacy.md).
- Not every mint: stealth rows need a mint that approves new confidential accounts itself, and no row works on a mint with a transfer fee or transfer hook extension. PYUSD and USDG carry both and do not auto-approve, and USDC is not a Token-2022 mint (verification: V14), so no major stablecoin works today; the first use is a mint that approves accounts and carries neither. The rules per row kind: [payer.md](payer.md).
- Recipient privacy ends where the recipient acts: the first public withdrawal or spend to a known counterparty links the destination to them ([privacy.md](privacy.md)).
- Rent refunds depend on the recipient emptying the one-time account: [protocol.md](protocol.md).
- The derivations have had no external cryptographic review [open, Q1 in plan.md].
- No wallet shows confidential balances [unverified]. The rail is useful only as far as confidential balances are adopted.
- FinCEN's 2023 proposed mixing definition lists single-use addresses on their own (verification: V47); whether it was finalized is [unverified]. The counterweights are a visible payer, no pool and amounts that can be disclosed. No agency has drawn the line. Self-hosted transfers are outside EU TFR scope by its text (verification: V47).

## What is new, and what is not?

New, as far as we can find [likely]:

- The payer sets up a stranger's confidential account. Token-2022 checks only the current owner (verification: V1, V2), and solana-zk-sdk derives confidential keys from raw material (verification: V28); nobody has joined them to a stealth scheme.
- Recipient privacy plus amount privacy on unwrapped tokens with no pool, relayer, committee or enclave. The shipped Solana systems that hide both are custodied pools that need at least one of those (verification: V44).
- One transaction per side: with the 4,096-byte v1 transaction format every proof rides inline. Measured in LiteSVM and on Surfpool (verification: V56, V38).

Not new, and cited: program-owned confidential accounts (Occult, verification: V45); the stealth construction (BIP-352, ERC-5564, sRFC-42); scan-and-trial-decrypt discovery (Zcash, Monero view tags); batch payout tooling. Rotating addresses exist; the new part is payer-side setup of a confidential account for a stranger.

## Who is it for?

Stablecoin payroll and B2B settlement platforms serving payers who are public anyway and want their counterparties and amounts private (verification: V43). Launch use: one-off payouts (grants, bounties, invoices, donations), which need no batching. Hiding merchant revenue needs only confidential balances and is not this market.

## How much does a payment cost?

A stealth row locks 4,008,120 lamports of payer rent that comes back at the sweep, funds the recipient's sweep with 4,622,680 lamports, and pays a transaction fee of 5,000 lamports plus a priority fee. A plain row costs only its fee. The priority fee is the only cost that grows with congestion. Breakdown and formulas: [payer.md](payer.md); rent per account: [protocol.md](protocol.md).

## What is in scope?

Build: one Pinocchio program (`announce`, `reclaim`, and `register` and `deregister` for an optional registry in sRFC-42's layout); one Rust CLI, `scope` (commands: [README.md](../README.md)); a privacy model; adversarial tests; a chaos harness for the payer engine; a devnet demo; a write-up posted to the sRFC-42 discussion.

Do not build: wallet integration, a web app beyond a status page, our own proof system, unlinkable consolidation (Q8), an indexer beyond demo scale, an issuer approver (a one-page spec ships in the write-up, Q9), mobile.

## What counts as done?

- A payout run to 50 recipients on devnet, some plain, some stealth, one transaction per recipient; then a third party verifying a disclosed receipt against the chain.
- Published measurements: bytes and compute per transaction, SOL fronted, SOL kept by the recipient, SOL burned, wall-clock time per payment and per run.
- A privacy model listing every artifact per payment and what it links.
- The payer engine converging after being killed at every step of a run.
- One external applied-cryptography review, findings addressed.
- A write-up someone else could implement from.

Where each criterion stands: [plan.md](plan.md).
