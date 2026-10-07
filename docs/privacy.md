---
status: draft
last_verified: 2026-10-07
---

# Privacy

TL;DR: for anyone deciding whether SCOPE protects them enough. After reading you know what each party can learn or do, and every known leak with its evidence.
Hidden from the public: who received a stealth payment and every amount. Visible: who paid, how many one-time accounts a run paid, and links the recipient creates by merging or spending. No formal analysis yet.

Transaction contents referred to here are listed in [protocol.md](protocol.md). Marks and citation format: [README.md](README.md), Rules.

## Who learns what

### A chain observer

| Learns | Does not learn |
|---|---|
| The payer of every payment: it signs and pays fees | The amount of any payment (encrypted; V12 for the auditor exception) |
| For a plain row: the recipient's fixed confidential account | For a stealth row: who the recipient is, without b_scan |
| For a stealth row: that the payer funded a fresh one-time account T and its owner P, at a given time | Which meta-address a stealth payment belongs to |
| How many rows a run paid, and their timing | Which row of an input file went to which one-time account: send order is shuffled (V48) |
| That P, D and D_owner belong together, and that D was funded from this payer's T: the sweep transaction names T, D, D_owner and, through `reclaim`, the payer | Anything linking two stealth payments to the same recipient, unless the recipient links them |
| That a published registry entry ties a wallet to a meta-address, permanently | |
| That a wallet uses this program or confidential transfers at all | |

### An RPC provider

Everything an observer sees, plus the IP address and timing of each query.

| Whose node | Sees |
|---|---|
| Payer's | the run being built: reads of the mint, the source and plain recipients' accounts before the sends, then every send |
| Payer's, `scope lookup` | that a lookup happened: it fetches every registry entry in one query and picks locally, so the query does not name the wallet looked up (V81); a payment that follows can be correlated by timing |
| Recipient's, `scope scan` | a fetch of every announcement, then reads of the token accounts whose 1-byte view tag matched; those follow-up reads reveal the candidates, about 1 in 256 of them false, together with the scanner's IP (V67) |
| Recipient's, `scope sweep` | the sweep submitted from the recipient's IP, linking that IP to P, D and D_owner |
| Auditor's, `scope verify` | which payment signature is being audited ([audit.md](audit.md)) |

Run your own node, or accept these query leaks.

### The mint authority and the auditor

These are properties of the mint, not of SCOPE.

| Party | Can |
|---|---|
| Auditor key holder | decrypt every confidential transfer amount on the mint, plain and stealth (V12) |
| Confidential-transfer authority | on a mint that does not auto-approve, see and approve every account before it can receive. The client refuses such mints for stealth rows (V72, V76); plain rows work only if the recipient's account was approved, so the issuer gates every plain recipient (V13) |
| Freeze authority | freeze T and block the sweep and the rent refund. Stealth rows refuse mints that freeze new accounts by default [unverified], since SetAuthority fails on a frozen account (V2) |
| Mint authority | mint public dust into T, since MintTo ignores the disabled public-credit flag (V6). The sweep burns it; if burning fails it falls back to a transfer-only sweep and the dust and rent stay behind (V65) |

The full list of mints the client refuses is in [payer.md](payer.md).

### The payer

| Learns or can do | Cannot |
|---|---|
| Who it paid and how much: it chose both | Read the recipient's other income, unless the recipient merges accounts |
| The shared secret S and T's decryption keys, so T's balance until it is emptied | Move T's funds: after the handover only P can apply, transfer or empty (V3) |
| At most one further confidential credit into T before the sweep: the credit cap is 1 (V7), public credits are off, and the sweep disables confidential credits in the same transaction (V65) | Decrypt D: its keys come from D_owner, which binds the recipient's spend secret (V61) |
| P, D and D_owner, from the sweep; then every later counterparty of D, amounts hidden | Stop the recipient from sweeping once T is funded and announced |
| Write a false balance hint into T: the AE key is shared. The client never trusts the hint (V64) | |
| Skip `announce`: the payment is real and can be disclosed, but the recipient's scan never finds it | |
| Underfund P: the recipient's only top-up path is a wallet it controls, which links that wallet. The client refuses to send below a computed floor (V74) | |

This is the same view any payer has of a wallet it paid on a public ledger. SCOPE hides the recipient from the public, not from the payer.

### The recipient's counterparts

Anyone the recipient later pays from D, or who pays D, sees D's history: that it was funded by a sweep from a one-time account paid by this payer, and when. They learn that this payer paid the recipient, not how much. Avoid by never spending from D toward people who must not know the payer.

### Anyone holding a receipt

A payer receipt reveals the amount, the destination and the payer of one payment; a recipient receipt reveals T's confidential keys, so every amount T ever held (V79, V80). Formats and verification: [audit.md](audit.md).

## Limitations

- **The payer is visible.** By design; it keeps SCOPE outside mixer territory. For payer privacy, use a pool.
- **Private from the public, not from the payer.** See the payer table. What SCOPE protects is the recipient's other income, as long as accounts are never merged.
- **The payer shields once.** The payer needs a confidential balance; depositing treasury into it shows that amount once. T never holds a public balance from the payer.
- **Merging re-links.** Sweeping or spending into an account another payment also reached clusters everything that touched it. Inherent to stealth addresses; BIP-352 has the same property [unverified]. The sweep refuses an existing destination and offers no reuse override [unverified]; this is client policy, not a program rule. Reusing one fee payer for later spends from several D also links them. Unlinkable consolidation is out of scope (Q8, [plan.md](plan.md)).
- **Partial spends from T.** Spending part of T's balance directly shows the payer the split. The client always sweeps the whole balance (V65).
- **Headcount and timing.** A run's transactions land close together from one payer, and every announcement stores the payer, so an observer counts a run's stealth recipients exactly. Shuffled send order hides order, not count (V48). Spreading sends over time helps; not solved.
- **Scan and lookup leak to the RPC provider.** See the RPC table (V67, V81).
- **Registration is public and permanent.** Publishing is optional; a meta-address string handed to the payer works without it. For grants or donations, publish from a wallet with no other history.
- **The recipient depends on the payer to announce.** A payer that skips `announce` makes the payment invisible to scan.
- **Mint powers.** Freeze, dust and approval are the issuer's, per mint; see the mint table.
- **Program fingerprint.** Calling this program, or confidential-transfer instructions at all, marks a wallet as privacy-seeking while usage is low [unverified]. True of every privacy tool on Solana.
- **View tag.** One byte of a hash of S is public, standard for stealth schemes (V53). It narrows a scanner's work and gives an observer nothing without b_scan.
- **Local recovery journal.** The recipient's journal groups its destinations; it is owner-only and holds no amounts or secrets (V70), but anyone who reads it links them.
- **No cryptographic review yet.** The derivations from one shared secret are written and tested but not externally reviewed (Q1, [plan.md](plan.md)).

## What SCOPE does not claim

- Payer privacy.
- Privacy from the payer.
- Unlinkable consolidation.
- Privacy from the auditor or from anyone holding a receipt.
- Resistance to a global adversary correlating timing across many payments.
- Anonymity of any kind. SCOPE is not a mixer and must not be described as one.
