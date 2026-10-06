---
status: draft
last_verified: 2026-10-06
---

# Cryptography

TL;DR: a standard stealth-address construction on Curve25519, plus derivations from the same shared secret for the Token-2022 confidential keys and, on the recipient's side only, for the sweep destination.
The shared-secret derivations are the new part and the source of every open concern; external review is pending (Q1).

## Derivation tree

Symbols follow [design.md](design.md), Keys. Implemented in `crates/stealth-keygen` (verification: V53, V61).

Payers may supply r through `EphemeralSecret::from_bytes` and `derive_payment_with_ephemeral`; the random API delegates to the same derivation. R is computed from r, and the returned payment retains S for later `ct_ikm` derivation (verification: V58). The supplied secret is cleared on drop. Use a fresh ephemeral key per distinct payment; reuse is only for reconstructing that payment.

```
S      = ECDH(r, B_scan) = ECDH(b_scan, R)              reject all-zero S
PRK    = HKDF-SHA256-Extract(salt = "stealth-keygen-v3", S)
t      = mod_wide(Expand(PRK, "spend-tweak"   || R, 64))       P = B_spend + t·G
tag    = Expand(PRK, "discovery-tag" || R, 1)
ct_ikm = Expand(PRK, "ct-ikm-v1"     || R || C, 32)  ->  zk-sdk derive_confidential_keys_from_ikm(ct_ikm)
C      = chain_id || program_id || mint || token_account, 32 bytes each

Recipient only:
prefix = SHA512(len(label) || label || p)[32..64]  ->  nonce prefix for raw-scalar Ed25519 signing, from p, never from S
d      = HKDF-SHA512(salt = "stealth-dest/v1", ikm = canonical_bytes(b_spend), info = "d-owner" || R, len = 32)  ->  Ed25519 seed for D_owner
```

Why: RFC 5869 says distinct `info` under a PRF gives computationally independent outputs; that is the whole argument for the three shared-secret leaves, the same pattern as a TLS 1.3 key schedule. Every expansion carries the exact R bytes, so encodings of R that X25519 maps to the same S still give different outputs. `C` ties the confidential keys to one account on one cluster, so a repeated R on another cluster or mint does not repeat the keys. In `C`, `chain_id` is the cluster's genesis hash and `program_id` is the SCOPE program id `EwbfwDdaRdxzF6wJFBKQmqcGoh93wNFL7FMo31eK9V2H`. `scope-client::confidential::context` builds this context for recipient discovery and sweeping (verification: V63); payer-engine stealth rows remain planned.

`derive_confidential_keys_from_ikm(ikm: &[u8]) -> Result<(ElGamalKeypair, AeKey), ElGamalError>` in solana-zk-sdk 7.0.1 runs a second HKDF-SHA512 (salt `solana-conf-bal/v1`, info `ae` and `elgamal`), unchanged in 8.0.0 (verification: V28). Feeding it `ct_ikm` rather than raw S keeps the stages separate. The crypto crate exports `ct_ikm` as `ConfidentialKeyMaterial`, a zeroizing 32-byte secret with no `Debug`, `Clone` or `Copy`, and has no Solana SDK dependency; `scope-client::confidential::derive_confidential_keys` makes the SDK call.

The payer knows S and every leaf of PRK. `d` is derived from `b_spend`, which never touches S, so the payer cannot derive D_owner. [open: the reviewer confirms using the signing secret as HKDF input, or prescribes a dedicated recipient master secret]

`RecipientSecretKeys::derive_sweep_destination(&R)` returns a protected `SweepDestinationSeed`. The client constructs a standard Ed25519 keypair from its 32 bytes and creates D. The exact canonical spend scalar and R reconstruct the same owner after a crash; scan-key changes do not change it. This adds no Solana SDK dependency to the crypto crate (verification: V61).

## Curve25519 checks

- X25519 clamping neutralises low-order points; still reject S = 0 on both sides.
- Ed25519 has cofactor 8: B_spend must satisfy `L·B_spend = identity`. In v1 the client checks it: `stealth-keygen` rejects small-order and mixed-order keys and an identity P (verification: V42), and the CLI does not let a user skip that. `register` checks it on chain too, with the curve25519 syscalls, before a key enters the registry ([design.md](design.md), Registry; verification: V82). A blacklist of the eight small-order encodings is not a substitute: it misses mixed-order points.
- Keep B_spend (Edwards) and B_scan (Montgomery) as separate keys. Converting one key between representations has a sign ambiguity.
- Reducing 512 bits mod ℓ leaves a bias below 2^-260.
- The payer's client checks that P decompresses before sending; a bad P only wastes the payer's money. No instruction of ours checks P.

## Signing with the one-time key

P is a real Ed25519 public key and the recipient holds its scalar p, so the recipient signs the sweep as P and pays the fee from P's system account, funded by the payer. The runtime verifies the signature algebraically (verification: V25); Token-2022 checks that P, the account's owner, signed; no program of ours checks P.

Raw-scalar signing follows RFC 8032 by hand in `crates/stealth-keygen/src/signing.rs`; the equivalent ed25519-dalek hazmat interface is the one implicated in RUSTSEC-2022-0093. The nonce is `r_sig = H(prefix || M) mod ℓ` with `prefix` derived from p alone (verification: V41). It must never come from S: the payer knows S, and since `s = r_sig + c·p` with `c` public, a payer who can compute `r_sig` recovers p from any one signature, including that of a failed transaction, which stays on chain. Never a caller-supplied value either: two signatures with the same `R_sig` over different messages leak p to anyone watching, and a retried sweep after a dropped transaction is exactly two different messages. One signing function for every code path, and a regression test that two messages signed by the same p produce different `R_sig`. Here `R_sig = r_sig·G` is the Ed25519 nonce point, distinct from the ephemeral X25519 public key `R`.

## Balance cache

Token-2022 stores an AE-encrypted copy of the available balance as a hint. It is not authenticated on chain, and the payer holds the same AE key. Pending balances decrypt from the ElGamal ciphertexts by table lookup on their 16-bit and 32-bit halves. The available balance is one 64-bit ciphertext that table lookup cannot decrypt, so the client reads the account's AE hint as a claimed value v and checks it: ElGamal decryption returns a `DiscreteLog` whose `target` is public, and `DiscreteLog.target == v·G` confirms v with one scalar multiplication. A mismatch rejects that payment; scan continues with other announcements (verification: V64). The client never uses the hint unchecked.

## Disclosure receipt

`{cluster, signature, ct_ikm}` for a stealth payment. The verifier re-derives the ElGamal key from `ct_ikm`, requires it to be the destination key in the transaction's ciphertext-validity proof, and decrypts the amount. A forged `ct_ikm` fails the key check, not a decryption. Disclosing `ct_ikm` hands over that account's full read access, including further credits or reuse of the same confidential keys. Fresh R per payment separates S and PRK. It reveals nothing about t, the tag, p, b_spend or other payments, given HKDF-Expand is a PRF [likely, pending review]. The payer's receipt needs no `ct_ikm`: it discloses the two Pedersen openings of the amount, derived from the run secret, which reveal that amount only ([client.md](client.md), Audit).

## Known concerns

| Concern | Assessment |
|---|---|
| Payer holds the account's ElGamal and AES keys permanently | Cannot move funds: the account is owned by P after the handover, and p needs b_spend, which never touches S. Learns only the amount it paid and the public sweep. The credit counter limits pending credits; sweep disables incoming credits while emptying the source atomically. Payers must use fresh R values; the client refuses existing token destinations. Accepted. |
| Payer can follow the funds it paid | True on any public ledger. What must not leak is the recipient's other income; that holds as long as payer-visible accounts are never merged with accounts other payers can see. |
| Does the ElGamal key leak p or b_spend | No: distinct Expand labels; b_spend is independent of S |
| Does the key-validity proof bind an owner | No: it proves knowledge of the ElGamal secret only; Token-2022 separately requires the owner's signature (verification: V1) |
| View tag leaks a byte of S | Accepted, standard (Monero, ERC-5564); domain-separated from the tweak |
| HKDF domain separation | Recipe above; needs external review [open] |
| The payer's run secret is a signature over a public message | A signature is not a secret to whatever obtains it: software that can make the payer's wallet sign `scope-run-secret/v1` and a run id learns every R_i and amount opening of that run, so which one-time accounts it paid and how much. The same holds for the source keys spl-token-cli derives from a signature (V50). Accepted with a rule: the payer key signs for this CLI only, never in a wallet that signs arbitrary messages for websites |

## Alternatives

- **Registry path.** Token-2022's ConfigureAccountWithRegistry skips the proof and owner signature if a registry owned by the token account's owner exists. The recipient would have to create one per one-time key, online. Removes the payer's key knowledge; kills offline receiving. Documented, not default.
- **One ephemeral key per run** (BIP-352 style, one R and N tags). Cuts scan work and groups every recipient of a run under one R. Deferred behind the review (Q11).
- **Pre-published one-time keys** with pre-verified proof context accounts. Refill bursts correlate a recipient's accounts, and it needs an always-on service. Rejected.

## Reviewer checklist

- The three shared-secret labels never overlap; `ct_ikm`, not raw S, feeds the zk-sdk derivation; `d` comes from `b_spend`, not S.
- Torsion check by multiply-by-L in `stealth-keygen`; zero-S rejection on both sides; P decompresses before the payer sends.
- The raw Ed25519 nonce is `H(prefix || M)` with the prefix derived from p, not S; regression test present.
- One-time use rests on `maximum_pending_balance_credit_counter = 1`, disabled public credits, and apply, transfer and empty in one transaction; `announce` checks the first two. After the handover the token account is owned by P and closable only by the announcement PDA.
- The client checks the AE balance hint against the ElGamal ciphertext before using it.
- Re-verify crate versions before shipping.

## Open questions

Q1 (external review of the tree, including `d`), Q11 (one ephemeral key per run). The run secret is derived from the payer's signature ([client.md](client.md), Run secret). Q14's library APIs and protocol context are implemented: `scope_client::confidential::context` pins the program ID and accepts the cluster genesis hash, mint and token account. Owners and recommendations: [plan.md](plan.md).
