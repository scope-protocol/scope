# Test vectors

`hkdf.txt` fixes the HKDF-SHA256 PRK, discovery tag, 64-byte tweak material,
reduced tweak, recovered scalar, payment public key, and signature.
All secrets in this file are deterministic public test inputs.

The salt is `stealth-keygen-v3`; its expansion labels are `discovery-tag`
and `spend-tweak`, followed by the exact 32-byte announcement `R`. The signing domain remains `stealth-keygen-v1-nonce`.
These versioned strings are cryptographic constants, not selectable schemes.
Renaming either would change outputs.

Generate it with `python3 scripts/generate_test_vectors.py`. The script uses
Python's standard library and separate curve arithmetic, checked against
[RFC 7748 section 6.1](https://www.rfc-editor.org/rfc/rfc7748#section-6.1),
[RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1), and
[RFC 5869 appendix A.1](https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1).

The Rust tests consume committed expected values. They never regenerate them.
Changing a vector requires review of the protocol change, not just rerunning
the script until a failing test passes. The Python arithmetic is variable-time
and must never be used with real secrets.

`ct_ikm` uses `ct-ikm-v1` followed by `R` and the fixed-width context
`chain_id || program_id || mint || token_account`. Each field is 32 bytes.
The 32-byte output is the input to the SDK's HKDF-SHA512 schedule, with salt
`solana-conf-bal/v1`, label `elgamal` for 64 bytes reduced modulo the scalar
order, and label `ae` for a 16-byte symmetric key.

The generator computes both stages independently with Python HMAC. The crypto
crate checks `ct_ikm`; `scope-client` checks the resulting ElGamal scalar and
balance key, encryption, key-validity proofs, and disclosure reconstruction.

Sweep fixtures derive a 32-byte Ed25519 seed with HKDF-SHA512, salt
`stealth-dest/v1`, the canonical spend scalar as input, and `d-owner || R` as info.
The generator independently expands that seed using RFC 8032 to produce the
destination owner's public key and signature over the existing fixture message.

`meta_address.txt` fixes the public receiving address. The generator prepends
version 1 to the spend and scan public keys, appends four bytes of double-SHA256,
and independently Base58-encodes the result with the `scope:` prefix.
