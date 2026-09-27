---
status: draft
last_verified: 2026-09-28
---

# Brief

TL;DR: a confidential payout rail on Solana. A visible payer pays many recipients with encrypted amounts; recipients who want it get a fresh, unlinkable account per payment that the payer sets up alone, in one transaction.
No pool, no relayer, no MPC, no enclave. The money stays an ordinary Token-2022 token, and an auditor can read amounts.

Marks: [verified] backed by a row in [verification.md](verification.md); [likely] strong evidence; [open] unknown, tracked in [plan.md](plan.md).

## Problem

Every payout on a public ledger is a permanent record of who was paid and how much. Companies name this as what keeps payroll and supplier payments off chain (verification: V43).

Solana has both halves of a fix and neither covers a real payout flow:

| Tool | Hides | Leaves public | State |
|---|---|---|---|
| Token-2022 confidential balances | the amount | the recipient's fixed address, so "X pays W monthly" is visible | live on mainnet-beta (verification: V15); usage near zero and no wallet support [unverified] |
| Stealth addresses (sRFC-42) | the recipient, via a fresh address per payment | the amount | draft, devnet reference implementation, no commits since June (verification: V46) |

They do not combine today: configuring a confidential account needs the owner's signature and a proof that the owner holds the encryption key (verification: V1). A payer paying a fresh address has neither, so the recipient would have to be online to set up every account.

## What we build

**The rail.** A payout run to N recipients with hidden amounts: one transaction per recipient, proofs generated on the payer's machine, fees handled, rent refunded, an audit path.

**The primitive.** For recipients who want to be unlinkable: a fresh account per payment whose encryption key is derived from the secret both sides share through the stealth handshake. The payer creates and configures the account as its temporary owner, pins its rent refund to our program and hands ownership to the recipient's one-time key, all in one transaction. From then on the recipient moves the money with plain Token-2022 instructions in one transaction of its own; our program is never in the funds path.

Two recipient modes in the same run:
- **Plain.** The recipient already has a confidential account; we transfer to it. Amount hidden, address fixed.
- **Stealth.** The recipient published one reusable meta-address; each payment lands in a fresh account only they can find. Amount and recipient hidden from the public.

## What is new, what is not

New, as far as we can find [likely]:
- The payer sets up a stranger's confidential account. Token-2022 checks only the current owner (verification: V1, V2), and solana-zk-sdk ships a key derivation from raw material (verification: V28); nobody has joined them to a stealth scheme.
- Recipient privacy plus amount privacy on unwrapped tokens with no pool, relayer, committee or enclave. The shipped Solana systems that hide both are custodied pools needing at least one of those (verification: V44).
- One transaction per side: with the 4,096-byte v1 format every proof rides inline. Measured in LiteSVM and on Surfpool (verification: V37, V38); devnet pending.

Not new, and cited: program-owned confidential accounts (Occult, verification: V45); the stealth construction (BIP-352, ERC-5564, sRFC-42); scan-and-trial-decrypt discovery (Zcash, Monero view tags); batch payout tooling in general. Rotating addresses exist; the new part is payer-side setup of a confidential account for a stranger.

## Who it is for

Buyers: stablecoin payroll and B2B settlement platforms serving payers who are public anyway and want their counterparties and amounts private (verification: V43). Launch use: one-off payouts (grants, bounties, invoices, donations), which need no batching. Hiding merchant revenue needs only confidential balances; not our market.

## Limitations

- **Payer is visible.** By design; it keeps this outside mixer territory. For payer privacy, use a pool.
- **Private from the public, not from the payer.** The payer sees where its payment is swept and can follow that account's later counterparties, amounts hidden, as any payer can on a public ledger. What the rail protects is the recipient's other income, as long as the recipient never merges accounts that different payers can see.
- **Payer shields once.** The payer must hold a confidential balance; converting treasury into it shows an amount that one time. The recipient's fresh account never goes through a public balance.
- **Merging re-links.** Sweeping several payments into one account clusters them. Rule: sweep each into a fresh account. Unlinkable consolidation is out of scope [open, Q8].
- **Payer holds that one account's decryption keys.** It learns only the amount it paid: the account takes one credit (verification: V7), is emptied in one transaction, and only the recipient holds the owning key. A partial spend straight from that account shows the payer the split.
- **Mint policy decides where it works.** The rail works unmodified on mints that auto-approve new confidential accounts. PYUSD and USDG require the issuer to approve every account, plain or stealth, and USDC is not a Token-2022 mint (verification: V14). Issuer-approved mints need an approver run by or for the issuer; specified, not built.
- **Cost.** Per stealth payment the payer locks 4,013,200 lamports of rent, refunded at sweep, and sends the recipient about 0.0035 SOL for its account and fees (verification: V23; the P allowance is [likely]). The payer's net cost is fees, of which the priority fee on a 200,000 CU range proof (verification: V27) is the only part that grows with congestion. Batching amortises operations, not chain cost.
- **Audit access.** Either party can disclose a stealth payment's receipt, verifiable against the chain without trusting the discloser. A mint auditor key, where the issuer sets one, is the secondary path (verification: V12). A receipt for plain payments is not designed yet [open, Q15].
- **Regulatory exposure.** FinCEN's 2023 proposed mixing definition lists single-use addresses on their own (verification: V47); whether it was finalized is [unverified]. Counter: visible payer, no pool, recoverable amounts. No agency has drawn the line. Self-hosted transfers are outside EU TFR scope by its text (verification: V47).
- **Adoption we do not control.** No wallet shows confidential balances [unverified]. The rail is useful only as far as confidential balances are.
- **Cryptographic review pending.** The derivations from one shared secret must be domain-separated; the recipe is written, the reviewer not yet found [open, Q1].

## Scope

Build: one Pinocchio program (`announce`, `reclaim`; an on-chain registry in P4 if Q12 says so), one Rust CLI (pay, scan, sweep, disclose, verify, bench), a privacy model, adversarial tests, a chaos harness for the payer engine, a devnet demo, a write-up posted to the sRFC-42 discussion.

Do not build: wallet integration, a web app beyond a status page, our own proof system, unlinkable consolidation, an indexer beyond demo scale, an issuer approver (a one-page spec ships in the write-up), mobile.

## Success criteria

- A payout run to 50 recipients on devnet, some plain, some stealth, one transaction per recipient; then a third party verifying a disclosed receipt against the chain.
- Published measurements: bytes and compute per transaction, SOL fronted, SOL kept by the recipient, SOL burned, wall-clock time per payment and per run.
- A privacy model listing every artifact per payment and what it links.
- The payer engine converging after being killed at every step of a run.
- One external applied-cryptography review, findings addressed.
- A write-up someone else could implement from.
