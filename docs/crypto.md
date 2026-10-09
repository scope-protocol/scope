---
status: draft
last_verified: 2026-10-10
---

# Cryptography

TL;DR: for a cryptographer reviewing SCOPE (external review: [plan.md](plan.md), Q1). Every key and derivation with the exact labels from the code, why each one is there, how receipts are checked, and the questions we want attacked.
The construction is a standard stealth address on Curve25519; the new parts are the derivations from the shared secret into Token-2022 confidential keys and the payer's run secret.

Marks and citation format: [README.md](README.md), Rules.

## Derivation tree

`G` is the Ed25519 base point, `ℓ` its prime order, `H` the zk-sdk Pedersen generator. `Expand` and `Extract` are HKDF (RFC 5869). Code: `crates/stealth-keygen/src/` and `crates/client/src/run_secret.rs`, `confidential.rs`.

```
Recipient, long-term                                         (stealth-keygen keys.rs)
  b_spend   = 64 random bytes mod ℓ, nonzero                 B_spend = b_spend·G
  b_scan    = 32 random bytes, X25519 secret (clamped on use) B_scan  = X25519(b_scan, 9)
  meta      = "scope:" || Base58Check(0x01 || B_spend || B_scan)

Payer, per run                                               (client run_secret.rs)
  sig        = Ed25519-Sign(payer key, 0xff || "scope-run-secret/v2" || run_id)
  run_secret = HKDF-SHA256(salt = "scope-run-secret/v2", ikm = sig, info = run_id, L = 32)
  row i (0-based position in the input file), u64le(i) little-endian:
  r_i        = HKDF-SHA256(salt = "scope-ephemeral/v1", ikm = run_secret,
                           info = "scope-ephemeral/v1" || run_id || u64le(i), L = 32)
  o_lo,i     = HKDF-SHA256(salt = "scope-opening/v1", ikm = run_secret,
                           info = "scope-opening/v1" || run_id || u64le(i) || "lo", L = 64) mod ℓ
  o_hi,i     = same with "hi"

Payer, per stealth row                                       (stealth-keygen spender.rs, derivation.rs)
  R       = X25519(r_i, 9)
  S       = X25519(r_i, B_scan) = X25519(b_scan, R)          reject all-zero S
  PRK     = HKDF-SHA256-Extract(salt = "stealth-keygen-v3", ikm = S)
  tag     = Expand(PRK, "discovery-tag" || R, 1)
  t       = Expand(PRK, "spend-tweak"   || R, 64) as LE integer mod ℓ
  P       = B_spend + t·G                                    reject identity
  C       = chain_id || program_id || mint || token_account  32 bytes each
  ct_ikm  = Expand(PRK, "ct-ikm-v1" || R || C, 32)
  (e, E), ae = zk-sdk derive_confidential_keys_from_ikm(ct_ikm):
            HKDF-SHA512(salt = "solana-conf-bal/v1", ikm = ct_ikm)
            "elgamal", 64 bytes mod ℓ -> e, E = e⁻¹·H;  "ae", 16 bytes -> AeKey

Recipient only                                               (recipient.rs, signing.rs, destination.rs)
  p       = b_spend + t mod ℓ                                p·G = P
  prefix  = SHA-512(0x17 || "stealth-keygen-v1-nonce" || p)[32..64]
  r_sig   = SHA-512(prefix || M) mod ℓ,  R_sig = r_sig·G
  c       = SHA-512(R_sig || P || M) mod ℓ,  s = r_sig + c·p,  signature = R_sig || s
  d       = HKDF-SHA512(salt = "stealth-dest/v1", ikm = b_spend (32-byte canonical LE),
                        info = "d-owner" || B_spend || R || T, L = 32)
  D_owner = Ed25519 public key of seed d (RFC 8032 key expansion)
```

`chain_id` is the genesis hash and `program_id` the SCOPE program id, both filled by `scope_client::confidential::context`; the token account address comes from (payer, R) ([protocol.md](protocol.md)). 0x17 is the nonce label's length. Tag, tweak and `ct_ikm` match an independent Python generator (V53); the zk-sdk stage is V28.

## Meta-address format

`scope:` plus Base58Check of `0x01 || B_spend || B_scan`. The checksum catches typos; it does not authenticate the recipient. Encoding and error cases: [crates/stealth-keygen/README.md](../crates/stealth-keygen/README.md) (V62).

## Each derivation and why

- **S and PRK.** Only the scan key is needed to find payments, so a scanning service can hold b_scan without spending power.
- **R in every expansion.** X25519 maps distinct encodings of R (the ignored high bit, for example) to the same S. Binding the exact 32 R bytes makes those aliases give different t, tag and `ct_ikm` (test `equivalent_ephemeral_encodings_have_distinct_derivations`).
- **Three leaves under one PRK.** `discovery-tag`, `spend-tweak` and `ct-ikm-v1` are distinct `info` prefixes. RFC 5869 gives computationally independent outputs for distinct `info` when HKDF-Expand is a PRF, the same pattern as a TLS 1.3 key schedule [likely].
- **tag.** One public byte from S; the recipient skips 255 of 256 announcements without deriving P. A match is a candidate, not a payment: the client then checks the account's owner against P and its ElGamal key (V64).
- **t and P.** P is a normal Ed25519 key; only the recipient knows p, since it needs b_spend, which never touches S.
- **C and `ct_ikm`.** C ties the confidential keys to one account on one cluster and mint, so a repeated R elsewhere does not repeat the keys (test `ct_ikm_binds_every_context_field`). Feeding zk-sdk `ct_ikm` rather than S keeps the two KDF stages separate. Payer and recipient both derive the same keys (V53, V63).
- **d and D_owner.** The sweep destination's owner. From b_spend, so the payer, who knows S and every PRK leaf, cannot derive it, and a restored backup rebuilds it; the scan key does not affect it (V61). T is in the info because a payer that knows r can announce a second account under the same R, which would otherwise share D and stall behind the first sweep. The spend scalar is an acceptable HKDF input (HMAC is a PRF on a 252-bit secret); a dedicated master secret would add a backup artifact for no gain.
- **Signing nonce.** The prefix comes from p alone (V41). Never from S: the payer knows S, and with `s = r_sig + c·p` and c public, knowing r_sig gives p from one signature, even a failed transaction's. Never caller-supplied: one R_sig over two messages leaks p, and a retried sweep is two messages. Signing is written out by hand because the ed25519-dalek hazmat interface is the one implicated in RUSTSEC-2022-0093; the runtime verifies it as plain RFC 8032 (V25).
- **Balance hint.** Token-2022's AE-encrypted available balance is unauthenticated, and the payer holds the AE key. The client accepts the claimed value v only if the ElGamal ciphertext's discrete-log target equals v·G; a mismatch skips that payment (V64).

## Run secret and amount openings

The formulas are in the tree above. Ed25519 signing is deterministic, so the payer keypair alone rebuilds `run_secret`, every r_i and every opening; nothing secret is stored. The client accepts only a `Keypair`: a randomizing signer would derive another secret on resume. A leading 0xff byte cannot start a transaction message. An independent Python generator fixes the signature, `run_secret`, one r_i and both openings (V75, V85).

The openings replace the random ones in the transfer proofs: `crates/client/src/proofs.rs` uses the same builders, inputs and order as `transfer_split_proof_data` in spl-token-confidential-transfer-proof-generation 0.6.1, and the verifier cannot tell where an opening came from. The amount splits as `a_lo = a mod 2^16`, `a_hi = a >> 16`; 2^48 or more is refused. Every attempt for a row moves the same amount, so reusing its openings reveals nothing new [likely].

## Receipt math

Both receipts are checked against the payment's `VerifyBatchedGroupedCiphertext3HandlesValidity` proof, which Token-2022 verified on landing. Its context holds two grouped ciphertexts, lo and hi, each a Pedersen commitment `C = a·G + o·H` and three handles `D_j = o·E_j` (j = 0 source, 1 destination, 2 auditor; V12). Code: `crates/client/src/receipt.rs`.

**Payer receipt** `(amount a, o_lo, o_hi)`. The verifier computes `a_lo = a mod 2^16`, `a_hi = a >> 16`, refuses `a_hi ≥ 2^32`, and requires `a_lo·G + o_lo·H = C_lo` and `a_hi·G + o_hi·H = C_hi`. Pedersen binding makes a wrong amount fail; an amount raised by one is refused (V79). That the openings reveal nothing else is [likely]: the remaining-balance commitment uses a fresh opening.

**Recipient receipt** `ct_ikm`. The verifier derives (e, E) with zk-sdk, requires E to equal the proof context's destination key (handle index 1), then decrypts index 1 of each half: `C - e·D_1 = a·G`, solved as a 32-bit discrete log, and `a = a_lo + (a_hi << 16)`. A forged `ct_ikm` fails the key check, not a decryption, and so does a stranger whose view tag collides (V80). Disclosing `ct_ikm` grants full read access to that one account, including any later credits under the same keys. It reveals nothing about t, the tag, p, b_spend or other payments if HKDF-Expand is a PRF [likely].

Both checks run only after the transaction is authenticated: its first signature must be the receipt's and every signature must verify, so a node can misreport whether it landed but not what it holds (V79). Commands, formats and node trust: [audit.md](audit.md).

## Curve checks

- **Clamping.** X25519 clamps scalars, which removes small-subgroup components from S. Low-order scan keys and their high-bit aliases are still refused at import (V59), and an all-zero S on either side (test `low_order_x25519_inputs_are_rejected`).
- **Torsion.** Ed25519 has cofactor 8, so B_spend must have prime order. The client refuses a non-canonical encoding, the identity, small-order and mixed-order points at import and at derivation, using `is_torsion_free`, a multiply by ℓ (V42, V59). A blacklist of the eight small-order encodings would miss mixed-order points.
- **On chain (S7).** `register` checks B_spend with the curve25519 syscalls (instruction checks: [protocol.md](protocol.md)). The multiply syscall accepts only canonical scalars, so ℓ is out of reach; it uses `Q = (ℓ-1)·P` instead. For prime-order P, Q = -P, so `Q + P` is the identity, Q is not, and -Q re-encodes to P. Any torsion part makes `Q + P` nonzero, since ℓ is odd and torsion orders divide 8. Non-canonical encodings exist only for y < 19 (as y + p) or x = 0, none of prime order, so the re-encoding test is a backstop. Code: `programs/scope/src/curve.rs` (V82).
- **Separate keys.** B_spend (Edwards) and B_scan (Montgomery) are independent keys. Converting one key between forms has a sign ambiguity.
- **Reduction bias.** Reducing 512 bits mod ℓ leaves a statistical distance of about 2^-260 from uniform [likely].
- **P.** P is computed as a point and compressed, so it always decompresses; an identity P is refused (V42). No SCOPE instruction checks P; a bad P would only waste the payer's money.

## Known concerns

| Concern | Assessment |
|---|---|
| Payer holds the account's ElGamal and AE keys permanently | Cannot move funds: the account is owned by P, and p needs b_spend. Learns only the amount it paid and the public sweep. The pending credit counter and disabled incoming credits limit what lands there; the sweep empties it. Fresh R per payment; the payer's client halts a row whose one-time address already holds an account (`pay.rs` `stealth_setup`) [unverified: no test]. Accepted. |
| Payer can follow the funds it paid | True on any public ledger. What must not leak is the recipient's other income; that holds while payer-visible accounts are never merged with ones other payers can see ([privacy.md](privacy.md)). |
| ElGamal key leaks p or b_spend | No: distinct Expand labels, and b_spend is independent of S [likely]. |
| Key-validity proof binds an owner | No: it proves knowledge of the ElGamal secret only; Token-2022 separately requires the owner's signature (V1). |
| View tag leaks one byte of S's PRF output | Accepted, standard (Monero, ERC-5564); domain-separated from the tweak. |
| Run secret is a signature over a public message | The 0xff prefix keeps it apart from transactions, but software that obtains this signature, or a leaked payer key, learns every R_i and amount of the run; the same holds for spl-token-cli's signature-derived source keys (V50). Operator consequences: [payer.md](payer.md). |
| Zeroization is best effort | Secret wrappers wipe on drop, but by-value copies and the `Hkdf` state can remain in memory. "Nothing secret is stored" does not mean none is ever in memory. |

Alternatives considered:

- **Registry path** (ConfigureAccountWithRegistry skips the proof and owner signature). Removes the payer's key knowledge but needs the recipient online to create one per one-time key.
- **One ephemeral key per run** (BIP-352 style). Cuts scan work, groups a run's recipients under one R. Held behind the review (Q11, [plan.md](plan.md)).
- **Pre-published one-time keys.** Refills correlate a recipient's accounts and need an always-on service. Rejected.

## What we ask reviewers to check

1. The three PRK labels, the run-secret labels and the destination salt never collide; `ct_ikm`, not S, feeds zk-sdk; d comes from b_spend, not S.
2. Our position that the spend scalar may be HKDF input for d (see Each derivation), and that T and B_spend in the info are enough.
3. Whether a raw Ed25519 signature over `0xff || scope-run-secret/v2 || run_id` is a sound KDF input.
4. That derived Pedersen openings, reused across attempts of one row, leak nothing beyond the amount, and that disclosing them reveals that amount only.
5. The raw-scalar signer in `signing.rs` against RFC 8032 section 5.1.6, including the nonce prefix.
6. The S7 algebra in `curve.rs` and the client's torsion checks.
7. One-time use: `maximum_pending_balance_credit_counter = 1`, disabled public credits, and apply, transfer and empty in one transaction; `announce` checks the first two ([protocol.md](protocol.md)).
8. The balance-hint check against the ElGamal ciphertext before the hint is used.
