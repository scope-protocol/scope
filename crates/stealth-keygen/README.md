<h1 align="center">stealth-keygen</h1>

`stealth-keygen` is a Rust library for generating recipient spend and scan keypairs, deriving one-time payment public keys, recovering their private signing scalars, and signing messages with the recovered keys. A payer uses the recipient's public keys and fresh randomness to derive a destination and a public announcement. The recipient uses their private keys and that announcement to recover the matching payment key. All key calculations happen off-chain.

<p align="center">
  <img src="docs/images/stealth-keygen-overview.svg" alt="Recipient key setup and sender flow: ephemeral key generation, X25519 shared-secret agreement, discovery tag and tweak derivation, and one-time payment public key" width="600" />
</p>

A matching discovery tag identifies a candidate; the recipient must check the destination authority before accepting a payment.

This crate supplies SCOPE with stealth payment keys and account-scoped confidential key material.
The remaining protocol integration is tracked in [Q14](../../docs/plan.md).

## Key derivation

`derive_payment(&public_keys, &mut rng)` uses HKDF-SHA256 with the fixed public
salt `stealth-keygen-v3`. Every expansion binds the exact 32-byte ephemeral
public key `R` from the announcement:

```text
PRK    = Extract("stealth-keygen-v3", S)
tag    = Expand(PRK, "discovery-tag" || R, 1)
t      = reduce_mod_l(Expand(PRK, "spend-tweak" || R, 64))
ct_ikm = Expand(PRK, "ct-ikm-v1" || R || C, 32)
C      = chain_id || program_id || mint || token_account
```

Each context field is 32 bytes. Both parties derive the same `ct_ikm` with
`derive_ct_ikm(&context)`. In `scope-client`, `confidential::derive_confidential_keys`
passes it to the pinned Solana SDK's `derive_confidential_keys_from_ikm`, which
uses HKDF-SHA512 to derive an ElGamal keypair and a symmetric `AeKey`.

`ConfidentialKeyMaterial` clears its buffer on drop and has no `Debug`, `Clone`,
or `Copy` implementation. Its bytes are secret. Disclosing them grants the
account's full read access, but does not reveal the payment signing scalar.
A receipt verifier must compare the derived ElGamal public key with the
referenced transaction. The client must also check a decrypted balance hint
against the ElGamal balance before trusting it.

This schedule is incompatible with the earlier SHA-256 and unbound HKDF
versions. Both parties must upgrade together; announcements carry no scheme
identifier. Account creation, proofs, and receipt verification belong to the client.

## Public API

| Function or method | Purpose |
|---|---|
| `RecipientSecretKeys::generate(&mut rng)` | Generate the recipient's private spend and scan keys. |
| `recipient.derive_public_keys()` | Obtain the public keys shared with payers. |
| `public_keys.spend_public_key_bytes()` | Export the public spend key as 32 bytes. |
| `public_keys.scan_public_key_bytes()` | Export the public scan key as 32 bytes. |
| `derive_payment(&public_keys, &mut rng)` | Derive a one-time payment public key and discovery announcement. |
| `recover_payment(&secret_keys, &announcement)` | Recover a candidate payment; returns `Ok(None)` if the discovery tag does not match. |
| `recovered.sign(message)` | Sign message bytes with the recovered payment key. |
| `payment.derive_ct_ikm(&context)` | Derive protected input for the account's confidential keys. |
| `material.as_bytes()` | Borrow secret bytes for SDK derivation or deliberate disclosure. |
| `ConfidentialKeyMaterial::from_bytes(bytes)` | Import disclosed material for client-side verification. |

Confidential-material derivation is available on both `SenderPayment` and
`RecoveredPayment`. Both parties must supply the same `ConfidentialContext`,
containing the chain genesis hash, application program ID, mint, and token-account
address as 32-byte fields.

## Dependencies

- `curve25519-dalek`: Edwards point and scalar arithmetic for spend and payment keys.
- `hkdf`: HKDF-SHA256 extraction and expansion for discovery tags, spending tweaks, and confidential key material.
- `rand_core`: Cryptographic RNG traits for generating key material.
- `sha2`: SHA-2 hashing for discovery tags, scalar tweaks, and signing.
- `x25519-dalek`: X25519 key agreement, with the `static_secrets` feature enabled.
- `zeroize`: Clearing sensitive key material and temporary buffers from memory.

## Tests

Run `cargo test -p stealth-keygen --locked` for unit tests and the public payment-flow integration
tests. Signatures are checked with `ed25519-dalek`, a test-only dependency.
Run `cargo test -p scope-client --locked` for SDK interoperability and disclosure
tests. Fixed vectors and their independent Python generator are documented in
[tests/fixtures/README.md](tests/fixtures/README.md).
