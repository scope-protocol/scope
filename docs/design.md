---
status: decided
last_verified: 2026-09-28
---

# Design

TL;DR: the payer creates each one-time confidential account itself, configures it as its temporary owner, pins the close authority to our announcement PDA and hands ownership to the recipient's one-time key, all at top level in one transaction.
Our Pinocchio program has two instructions, `announce` and `reclaim`, and is never in the funds path; the off-chain side is in [client.md](client.md).

Marks: [verified] backed by a row in [verification.md](verification.md); [likely] arithmetic over verified facts; [open] pending a spike or review in [plan.md](plan.md).

## Components

| Component | Where | Role |
|---|---|---|
| Program `scope-program` | on-chain, Pinocchio 0.11.2, `no_std`, id `EwbfwDdaRdxzF6wJFBKQmqcGoh93wNFL7FMo31eK9V2H` | `announce` verifies a payer's setup and writes the announcement; `reclaim` returns rent to the payer |
| Token-2022 and the ZK ElGamal proof program | Solana's, unchanged | confidential balances, proof verification, auditor key; live on mainnet-beta and devnet (verification: V15) |
| `scope-interface` | `no_std`, no dependencies | account layout, instruction data, seeds, errors, Token-2022 account reader; shared by program and client |
| CLI `scope` | off-chain, Rust | payer: pay, bench; recipient: scan, sweep; either: disclose, verify |

No relayer, no indexer, no second program, no on-chain registry in v1.

## Keys

```
Recipient long-term: b_spend (Ed25519), b_scan (X25519); meta-address B_spend, B_scan
Per payment:         e derived from the run secret, E = e·X, public
Shared secret:       S = ECDH(e, B_scan) = ECDH(b_scan, E)
One-time key:        P = B_spend + t·G, t from S; scalar p = b_spend + t, recipient only
View tag:            1 byte from S, public
Confidential keys:   ElGamal + AES from S via zk-sdk, payer and recipient
Destination owner:   D_owner from b_spend and (E, k), recipient only
```

Recipe and checks: [crypto.md](crypto.md). v1 uses `k = 0`; `k` is in every address so several accounts per handshake can be added later.

## Accounts

**Token account.** Owned by Token-2022, not by us. Address `create_with_seed(payer, seed, Token-2022)`, where `seed` is the lowercase hex of the first 16 bytes of `sha256("stealth-ta/v1" || E || k)`: 32 ASCII characters, the seed limit (verification: V17). The System program allocates a seed address only when the base signs, so only the payer can create this account (verification: V16). The client sizes it from the mint: 465 bytes for a mint with no account extensions, more otherwise (verification: V9, V11). No ImmutableOwner, since that blocks the handover. Owner: the payer during setup, P after. Close authority: the announcement PDA.

**Announcement.** Ours, PDA `["ann", token_account]` with the canonical bump, 69 bytes:

| Offset | Field | Size |
|---|---|---|
| 0 | discriminator = 1 | 1 |
| 1 | version = 1 | 1 |
| 2 | view_tag | 1 |
| 3 | k | 1 |
| 4 | bump | 1 |
| 5 | E | 32 |
| 37 | payer, receives every rent refund | 32 |

P and the mint are not stored: P is the token account's owner and the mint is in the token account. Scan filter: `dataSize = 69`, `memcmp(0, [1])`, `memcmp(2, [tag])`; the scanner then derives the token account from (payer, E, k).

**P.** A system account with no data, funded in the payer transaction and drained to zero in the sweep (verification: V24).

Every field is a byte array read by copy. Layout, seeds, instruction data, error codes and the Token-2022 account reader live in `crates/interface`.

## Instructions

The first data byte selects the instruction: 0 `announce`, 1 `reclaim`. Errors are `Custom(code)` from `ScopeError`, codes append-only.

### announce

Accounts: payer (signer, writable), token account, announcement (writable), System program. Data after the discriminator: E 32, k 1, view_tag 1.

Checks, in this order:
1. Data after the discriminator is exactly 34 bytes.
2. The payer signed.
3. The System program account is the System program id.
4. The token account address equals `create_with_seed(payer, seed(E, k), Token-2022)`. This binds E, k and the payer to the account.
5. The token account is owned by Token-2022, parses as a token account and is initialized.
6. Its close authority is the announcement PDA.
7. Its owner is not the payer, so the handover happened, and it has no delegate.
8. ConfidentialTransferAccount is present with `maximum_pending_balance_credit_counter = 1` and non-confidential credits disabled.
9. The announcement is the canonical PDA `["ann", token_account]`, has no data and is owned by System.

Then the program transfers any rent-exemption deficit from the payer to the announcement, allocates and assigns it by System CPIs signed by the PDA, so a pre-funded address still works, and writes the 69 bytes. Checks 6 to 8 make the anti-griefing settings a property of every announced account, not a client promise. Tests: verification V33.

### reclaim

Accounts: announcement (writable), token account (writable), payer (writable), Token-2022 program. No data after the discriminator, no signer; anyone may call it.

Checks, in this order: no extra data; the Token-2022 program id; the announcement is owned by our program and is 69 bytes with discriminator 1 and version 1; the token account address, recomputed from the stored payer, E and k, matches the account passed; the announcement address, derived from `["ann", token_account]` and the stored bump, matches; the payer matches the stored payer. Then CloseAccount by CPI, destination the payer, signed by the PDA; Token-2022 refuses while any balance is nonzero (verification: V4). The announcement's lamports go to the payer and the account is closed.

The recompute stops a decoy attack: an attacker creates its own empty token account, points its close authority at a victim's announcement and calls `reclaim` with it. Without the recompute that closes the victim's announcement, so the payment drops out of scan and its token account can never be reclaimed. Tests: verification V34.

Funding and sweeping are not instructions of ours. Both are plain top-level Token-2022 instructions.

## One stealth payment, payer side

One v1 transaction (active on both clusters, verification: V21), one signature, 2,999 bytes of 4,096 (verification: V37). The compute-unit and loaded-accounts limits go in the v1 header; SetComputeUnitLimit is ignored in v1, and an unset header limit fails the transaction (verification: V18, V19).

```
System CreateAccountWithSeed             base payer, owner Token-2022, rent from the sysvar
T22 InitializeAccount3                   owner = payer
T22 ConfigureAccount                     payer signs; proof offset 1; credit cap 1
VerifyPubkeyValidity                     inline
T22 DisableNonConfidentialCredits        payer signs
T22 SetAuthority CloseAccount            -> announcement PDA
T22 SetAuthority AccountOwner            -> P
announce                                 ours
System Transfer payer -> P               lamports_for_P (client.md)
T22 Transfer payer -> token account      proof offsets 1, 2, 3
VerifyCiphertextCommitmentEquality, VerifyBatchedGroupedCiphertext3HandlesValidity, VerifyBatchedRangeProofU128
```

ConfigureAccount and SetAuthority check only the current owner's signature, so the payer can be that owner; SetAuthority clears any delegate on handover (verification: V1, V2). `scope_client::ix::stealth_setup` builds this sequence up to the Transfer to P. If CreateAccountWithSeed fails because someone pre-funded the address, the client retries with Transfer, AllocateWithSeed and AssignWithSeed. A plain recipient gets only the Transfer and its three proofs.

## One stealth payment, recipient side

One transaction, signed by P (fee payer) and D_owner:

```
VerifyPubkeyValidity for D
System CreateAccountWithSeed (base D_owner, P pays), InitializeAccount3 (owner D_owner), ConfigureAccount, DisableNonConfidentialCredits
T22 ApplyPendingBalance                   P signs
T22 Transfer, full balance to D           three proofs
T22 EmptyAccount                          zero-ciphertext proof
T22 Burn of any public balance            only if the public amount is nonzero
reclaim                                   rent of both accounts to the payer
System Transfer of P's remainder to D_owner
```

The core (apply, transfer, empty, reclaim, with D created beforehand) is 2,759 bytes and 257,484 CU in LiteSVM (verification: V36, V37); the full shape above is estimated at about 3,300 bytes [likely]. The zero-ciphertext proof is over the new source ciphertext from the transfer's equality proof: Transfer sets the available balance to exactly that ciphertext (verification: V8). Burn removes public dust a mint authority can mint in, since MintTo ignores the disabled public-credit flag and a nonzero public amount blocks CloseAccount (verification: V4, V6). If reclaim fails, the client drops it and resends, so our program can never block funds. D and D_owner are derived per payment; nothing is persisted on the recipient side.

With the credit cap at 1, the payer's transfer is the only credit that can land (verification: V7), and apply, transfer and empty share one transaction, so there is no boundary for a second credit.

Failure model: both transactions are atomic. Payer side: an announcement at `["ann", token_account]` means the payment landed, and only the payer can have created it. Recipient side: the announcement is gone means swept and reclaimed.

## Money

Rent is `(size + 128) x 5,080` lamports today, read from the Rent sysvar at run time, never from constants (verification: V23):

| Account | Bytes | Lamports today |
|---|---|---|
| Announcement | 69 | 1,000,760 |
| Token account, mint with no account extensions | 465 | 3,012,440 |
| P, minimum while nonzero | 0 | 650,240 |

The payer locks 4,013,200 lamports per stealth payment and sends P enough for D's rent, two signatures and a priority allowance ([client.md](client.md)). The refund goes only to the payer, but whether it happens depends on P: only P can empty the account.

## Limitations

- A payer that never calls `announce` makes the payment invisible to scan. The payment is real and can be disclosed, but the recipient depends on the payer to learn of it.
- A mint authority can freeze the account or mint public dust into it; the sweep burns dust, a freeze blocks the sweep.
- Rent needs P's cooperation. P must empty the account, and must not enable CpiGuard, which blocks reclaim's CPI close to the payer (verification: V5). P cannot close the account itself, since CloseAccount needs the close authority, the announcement PDA (verification: V4).
- The client refuses mints that are non-transferable (they force ImmutableOwner) or freeze new accounts by default (SetAuthority fails on a frozen account) (verification: V10, V2).

## Upgrade authority

The program holds no authority over tokens: the announcement PDA is only a close authority, and CloseAccount needs zero balances. A malicious upgrade can at most redirect or lock rent. The program is upgradeable by a Squads multisig on devnet, ships a verifiable build, and its upgrade authority is revoked before mainnet.

## Registry

Deferred to P4 ([plan.md](plan.md), Q12). v1 passes an encoded meta-address string (`B_spend || B_scan` with a version and checksum). Until a registry exists, the small-order and mixed-order rejection in `stealth-keygen` is the only check on B_spend (verification: V42), and the CLI does not let a user skip it.

## Fallback

If v1 transactions cannot be used end to end (spike S1), transaction packing falls back to proof context accounts and several transactions per side. Payer-owned setup, the handover, `announce` and `reclaim` stay as they are.

## Confidence

| Part | Confidence | Basis |
|---|---|---|
| Payer-owned setup, handover to P | high | V1 to V3; S3 green in LiteSVM (V36) |
| Squatting closed by `create_with_seed` | high | V16 |
| `announce` checks, `reclaim` recompute | high | V33, V34 |
| One transaction per side | medium-high | V37, V38; devnet leg of S1 pending |
| Griefing closed | high for third parties | V6, V7; a mint authority can still freeze |
| Payer-side configure with an ECDH-derived key | medium | V28; domain separation unreviewed (Q1) |
| Costs | medium | rent exact today (V23); priority fees still being sampled (S4) |
| Privacy claims | medium | residuals in [privacy.md](privacy.md); no formal analysis |
