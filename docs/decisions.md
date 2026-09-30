---
status: decided
last_verified: 2026-09-28
---

# Decisions

TL;DR: append-only, newest first. Each entry says what was decided, why, and what was rejected.
Docs describe the present; this file holds the why. Design history from before this repository lives in the team's working notes.

## 2026-09-28 Migrate the tested crypto library

Import the standalone `stealth-keygen` HKDF-SHA256, ElGamal, symmetric-key, test-vector and documentation changes. Preserve its derivation constants and use SCOPE's pinned SDK 7.0.1 so returned key types match the client dependency. This migration does not resolve Q14 or replace the target protocol tree. Rejected for this change: silently rewriting the imported derivation to HKDF-SHA512 or adding a second direct SDK version. Evidence: V48.

## 2026-09-28 Design at the start of this repository

The design as this repository starts. Evidence for each line is in [verification.md](verification.md).

- **Payer-owned setup, then handover to a one-time key.** The payer creates the one-time token account, configures it as its temporary owner, pins the close authority to our announcement PDA and sets the owner to P, all at top level. Token-2022 checks only the current owner (V1, V2) and every later authorisation reads the live owner (V3), so the program never needs to own the account and funds never depend on it. Rejected: program-owned setup by CPI (proof offsets under CPI, hand-written confidential encoders on chain, no gain after the handover); a sweep instruction of ours (the recipient sweeps with plain Token-2022).
- **Two instructions.** `announce` verifies the payer's setup with nine checks and writes a 69-byte record; `reclaim` returns rent. Rejected: an `open` instruction that performs the setup itself.
- **`create_with_seed` addressing.** The token account address is `create_with_seed(payer, seed(R, k), Token-2022)`, and the announcement is seeded on that address. Accounts keyed on (R, k) alone could be created first by anyone who saw R and k, and the payer would read the result as paid; the base must sign a seed address (V16), which closes that. Rejected: PDAs on (R, k); an associated token account (it forces ImmutableOwner, which blocks the handover; V10a, V2).
- **`reclaim` recomputes the token account.** It derives the token account from the stored payer, R and k instead of trusting the account passed. Without that, a decoy account whose close authority points at a victim's announcement would close the announcement. Found in planning; covered by `reclaim_rejects_decoy_token_account` (V34).
- **Registry deferred to P4.** v1 takes a meta-address string. The on-chain seeds did not match sRFC-42's, so the interop reason did not hold, and the torsion check protects only whoever pays a bad key; `stealth-keygen` checks it client side (V42). Reopened as Q12. Rejected: building the registry in v1; dropping it for good.
- **v1 transactions, limits in the header.** Every proof rides inline in a 4,096-byte v1 transaction, one per side. The compute-unit and loaded-accounts limits go in the header, since ComputeBudget instructions are ignored in v1 and unset limits fail the transaction (V18). Rejected as default: proof context accounts and several transactions per side, kept as the fallback if S1 fails on devnet.
- **litesvm 0.16 crate line, solana-zk-sdk 7.0.1.** litesvm 0.16 and zk-sdk 8 cannot share a lockfile (V29), and the one zk-sdk function the design names is identical in 7.0.1 (V28). The off-chain Solana crates move together when litesvm moves. Rejected: zk-sdk 8 without LiteSVM (no in-process chaos tests).
- **Pinocchio over Anchor.** The program shares a dependency-free `no_std` interface crate with the client, has two instructions, and makes one Token-2022 CPI (V32). Anchor's account constraints and IDL would replace about a page of hand-written checks. Rejected: Anchor, plain solana-program, Quasar (unreleased).
- **Fee sampling from prices actually paid.** The engine prices from the per-CU fees landed non-vote transactions paid in recent blocks. Rejected: `getRecentPrioritizationFees`, whose global result is a per-slot minimum and reads near zero (V39).
- **Nonce prefix from p.** The raw-scalar signing nonce prefix is derived from the one-time scalar p, never from S, which the payer knows (V41). `stealth-keygen` is the crypto crate and converges on crypto.md (Q14) rather than being rewritten.
- **Auto-approve mints first.** v1 targets mints that auto-approve new confidential accounts; the issuer path for PYUSD and USDG is specified, not built (V13, V14).
- **Sweep to a fresh destination.** The recipient sweeps the whole balance to a fresh D owned by D_owner, derived from `b_spend`; a partial spend from the one-time account would show the payer the split.
