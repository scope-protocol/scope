---
status: draft
last_verified: 2026-10-06
---

# Privacy

TL;DR: hidden from the public: who received and how much. Visible: who paid, that fresh accounts were paid, and, if the recipient merges accounts, which accounts belong together.
The payer can follow the funds it paid, as on any public ledger, but reads no amount after the sweep; an auditor reads amounts by disclosure. No formal analysis yet.

## Adversaries

| Adversary | Capabilities | Goal |
|---|---|---|
| Chain observer | reads every account and transaction | link payments to a recipient; learn amounts |
| Payer | knows S for its own payments, holds that account's decryption keys, sees P, D and D_owner in the sweep | learn the recipient's other income; move funds; block the sweep |
| Recipient | all its secrets | may leak by merging accounts |
| Auditor | mint key or disclosed receipts | read amounts (intended) |
| Mint authority | ApproveAccount policy, freeze authority, MintTo | gate or freeze accounts (a property of the mint, not of the rail) |
| RPC provider | sees every query | observe the scanner's IP and follow-up account reads |

## Artifacts per payment

| Artifact | Public | Links to recipient without b_scan | Amount |
|---|---|---|---|
| Meta-address string, handed to the payer off chain in v1 | no | only to whoever holds it | none |
| Payer's transfer to a plain recipient | yes | yes, fixed address | encrypted |
| Payer's transaction: token account set up and handed to P, announcement (R, tag, payer), P funded, transfer in | payer identity, one-time account | no, needs S | encrypted; auditor readable |
| Recipient's transaction: D created by P, disable source credits, apply, transfer, empty, optional burn and reclaim to the payer, surplus SOL transferred from P to D_owner with a reserve retained in P | yes | no; links P, D and D_owner to each other | encrypted |
| A later spend from D | yes | no for the public; the payer can follow it | encrypted if confidential |
| Recipient recovery journal, stored locally with owner-only permissions | no | yes if exposed, groups the recipient's destinations | none |
| A sweep or spend into an account another payment also reached | yes | **yes**, merges everything that touched it | encrypted |
| Timing of the payer's transactions in a run | yes | correlates payer with one-time accounts and counts them, not with recipients | none |

## Residual leaks and mitigations

- **Merging.** Inherent to stealth addresses (BIP-352 has it). Sweep into a fresh D per payment and never merge accounts that different payers can see. Reusing a fee payer for later spends also links destinations. The client refuses an existing token destination and offers no reuse override; this is client policy, not a program invariant. Unlinkable consolidation is out of scope (Q8).
- **The payer follows the funds.** The payer sees D in the sweep and can watch D's counterparties forever, amounts hidden. Any payer on a public ledger can do this with a wallet it paid, and the payer already knows who it paid. This rail hides the recipient from the public, not from the payer.
- **Payer's keys.** The payer can read that one account until it is emptied. It cannot move funds (P owns the account) or decrypt the destination side. The credit cap limits outstanding pending credits, and public credits are disabled; an applied source can receive one further confidential credit before sweeping, which requires fresh proofs; sweeping also disables confidential credits so a transfer-only fallback cannot reopen the source to the payer (verification: V2, V3, V7, V65). Insufficient funding and mint-authority restrictions can still prevent a sweep. A partial spend straight from the one-time account shows the payer the split; sweep the whole balance.
- **Balance cache.** The AE-encrypted balance hint is writable by anyone holding the AES key, which includes the payer. The client never trusts it.
- **Registration.** v1 has no on-chain registry; the recipient hands its meta-address string to the payer. A registry would make the registering wallet public and permanent; for a grants or donations flow, register from a wallet with no other history.
- **Underfunded P.** If the payer leaves too little on P, the only top-up path is a wallet the recipient controls, which links it. The client refuses to send below a computed floor; the payer overprovisions.
- **Headcount and timing.** A run's transactions land close together from one payer: an observer counts recipients per run with certainty. Spreading sends over time helps; not solved.
- **Send order.** A payroll file sorted by name, plus a public roster, would link the k-th one-time account to the k-th employee. The engine shuffles send order with a permutation derived from the run secret; this hides order, not headcount.
- **A payer can skip `announce`.** The payment is real and can be disclosed, but the recipient's scan never finds it, and the recipient then depends on the payer to learn of it.
- **Scanning.** Tags are checked locally after fetching announcements. Follow-up token-account reads can reveal candidates to the RPC provider together with the scanner's IP. Run your own RPC or accept this query leak.
- **Program fingerprint.** Calling this program, or confidential-transfer instructions at all, marks a wallet as privacy-seeking while usage is low. Applies to every privacy tool on Solana.
- **Mint authority.** On approval-required mints the issuer sees and gates every account; a freeze authority can freeze a one-time account and block its sweep; MintTo can put public dust in it; sweep attempts to burn it, or transfers confidential funds while leaving dust and rent cleanup outstanding (verification: V6).
- **View tag.** One byte of the shared-secret hash is public. Standard.

## What we do not claim

- Payer privacy. Use a pool.
- Privacy from the payer.
- Unlinkable consolidation.
- Privacy from the auditor or from a party a receipt was disclosed to.
- Resistance to a global adversary correlating timing across many payments.
- Anonymity of any kind. This is not a mixer and must never be described as one.
