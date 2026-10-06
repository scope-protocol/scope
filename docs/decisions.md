---
status: decided
last_verified: 2026-10-06
---

# Decisions

TL;DR: append-only, newest first. Each entry says what was decided, why, and what was rejected.
Docs describe the present; this file holds the why. Design history from before this repository lives in the team's working notes.

## 2026-10-06 Payer stealth rows

- **A registry in sRFC-42's layout (Q12).** Two instructions in our program, `register` and `deregister`, writing sRFC-42 v1's entry byte for byte under the same seeds, so its readers work on ours; S7's torsion check refuses a bad B_spend on chain. Payers look up with one query and paste the meta-address into the payroll file, which then records exactly whom it paid. Rejected: a private layout, resolving registry rows inside `scope pay` (a re-registration between start and resume would change a recipient mid-run), and a second program, which the one-program rule excludes.
- **Receipts: the payer's openings for every row, `ct_ikm` for the stealth recipient (Q15).** Plain recipients' keys are their wallet keys and cannot be handed out per payment, but the payer's amount openings prove any row's amount and reveal nothing else, and the run secret re-derives them. A recipient's receipt is built from the payment transaction alone and is refused unless its key is the transfer's destination key. Rejected: stealth-only receipts with plain payments left to the auditor key.
- **The run secret comes from the payer's signature (Q16).** `run_secret = HKDF(payer's Ed25519 signature over a fixed label || run_id)`. Signing is deterministic, so the payer keypair, already backed up, rebuilds every run's secret, every R_i and every amount opening; the same pattern as the source keys. Rejected: a master secret in an age file or the keychain (one more backup and storage code for the same result).
- **Amount openings are derived, not drawn.** The engine builds transfer proofs with the same builders as proof-generation 0.6.1 but takes the two amount openings from the run secret. A payer can then prove any row's amount, plain or stealth, by disclosing that row's openings, with nothing stored. Every attempt for a row moves the same amount, so reusing its openings across attempts reveals nothing. Rejected: random openings stored beside the journal (a secret on disk that the journal rule keeps out).
- **Send order stays random, recorded in the run header.** Deriving it from the run secret adds nothing the header does not already give resume.
- **Prefunded one-time addresses are created anyway.** An expired attempt publishes T's address; anyone can then send it lamports, which makes CreateAccountWithSeed fail. The rebuild tops up, allocates and assigns instead. Rejected: halting, which would let one transfer of dust stop a run.
- **Compute limits per shape and one funding rule for P.** The fee is paid on the header's CU limit, so each shape gets its own limit about 15% above measurement (V73), and the payer funds P with exactly what the sweep needs at the 1,000,000 micro-lamport cap (V74). Rejected: one 600,000 limit for everything, and a funding estimate the sweep did not share.

## 2026-10-05 Recipient state refresh and discovery

- **Two safe retries refresh the full snapshot.** An applied source can accept a further credit, and a mint auditor can change. Each rebuild refreshes source balances, mint policy, proofs, funding and rent; two retries cover cleanup followed by one additional credit. Work remains bounded by the deadline and funding floor. Rejected: treating the pending-credit cap as a lifetime limit or reusing stale proofs.

- **Proof preparation cannot authorize a late send.** Retry decoding and proving run on a worker with no chain access; the caller stops waiting at its deadline. A successful finalized signature remains an immutable outcome proof even when the payer recreates accounts. Rejected: inferring failure from later account state.

- **Discovery streams validated results.** Scan exposes a fallible per-result callback and the CLI flushes rows immediately. RPC fetches only the announcement layout, and malformed binary transport data returns an error. Public all-zero ciphertexts skip unnecessary decoding. Rejected: withholding every result until the final scan or adding a new cryptographic decoding algorithm.

## 2026-10-05 Recipient sweep reliability

- **Destination creation tolerates concurrent prefunding.** Every build reads the current rent deficit and uses transfer, allocation and assignment with D_owner as the signing base. Rejected: a creation instruction or cached rent requirement invalidated by an incoming SOL transfer.

- **Recovery checkpoints precede every new attempt.** The CLI flushes each changed signature through a fallible callback; an output failure stops that attempt. Closed addresses funded again are classified by owner and data, so System placeholders do not undo completion or reclaim reporting.

- **Submission has one shared deadline.** RPC futures, including HTTP retries, and polling sleeps share the submission deadline; preparation precedes it. Rejected: checking elapsed time only between blocking calls or sending after a slow height query overruns the limit.

- **A safe retry omits cleanup.** State can change after simulation. One fresh transfer-only attempt is permitted after a finalized failure or blockhash expiry, with updated funding and simulation. Signing material remains protected in memory and is excluded from debug output. Rejected: rebuilding while the earlier attempt may still land or resending stale cleanup indefinitely.

- **Swept sources reject further confidential credits.** Sweep disables credits atomically with applying and emptying balances, including when cleanup is omitted. Rejected: relying on a credit counter that apply resets.

- **Backup filenames are synchronized.** Registration syncs both the file and its parent directory, using the current directory for a bare filename. Rejected: treating an empty parent path as a reason to skip directory synchronization.

- **Cleanup is optional and signatures are explicit.** The fallback omits both public dust burning and reclaim, including for permissioned-burn mints. It reports the public balance left behind. Completion from account state does not prove a specific transaction landed; the report separates the attempt signature from its verified finalized signature. Rejected: letting cleanup prevent a valid confidential transfer or reporting an unexecuted signature as successful.

- **P retains a rent reserve.** Sweep quotes fees, destination rent and P's reserve exactly. Incoming SOL cannot turn a zero drain into a rent-paying balance. Small surplus stays in P unless D_owner can receive it without becoming rent-paying. The recipient retains control of this SOL. Rejected: draining P to an exact zero based on a stale balance snapshot.

- **Recovery precedes broadcast.** Preparation and submission are separate APIs. The CLI flushes public recovery details before submission, and timeout or status errors retain the report. Rejected: returning recovery details only after successful finalization.

## 2026-10-05 Scan error isolation

- **Invalid payments do not abort discovery.** Scan returns valid payments and skipped validation errors; the CLI reports skipped accounts on stderr. A sender can announce a matching payment authority with an unrelated ElGamal key using only public recipient keys. Rejected: aborting every payment's discovery on that entry or silently hiding its validation error. Chain errors remain fatal and sweep still rejects invalid payments. Evidence: V64.

## 2026-10-04 Recipient client integration

- **CLI backup files have explicit protection.** Register creates an owner-only 64-byte raw backup, or streams it into age encryption; scan and sweep optionally stream age decryption into protected memory. Existing files are never overwritten and symlinked or group/world-readable key files are rejected. The CLI delegates discovery and transaction logic to the client. Rejected: secret arguments, plaintext temporary files, or a new encryption scheme. Sweep prints public R for later owner reconstruction after the announcement is closed.

- **Atomic sweep into a deterministic fresh account.** D uses D_owner as the signing base and fixed seed `scope-sweep/v1`; its confidential keys use the SDK's wallet derivation so the owner can reconstruct them. Preparation reads rent and message fees, simulates, and refuses reused token accounts. Only identical signed transactions are resent. A separately simulated version without reclaim keeps failed rent cleanup from blocking funds. Rejected: partial sweeps, guessed fees, or rebuilding while an earlier transaction may still land. Counterparty destinations remain follow-up work.

- **Discovery checks tags locally.** Each tag needs its announcement's R; a fixed recipient memcmp filter would miss payments. Scan validates announcement PDAs and token authorities, then authenticates the derived ElGamal key and balance hint before reporting amounts. Rejected: trusting a tag match or the payer-writable balance hint. RPC capacity remains S6.

- **One protocol context and a scalar signer adapter.** `confidential::context` pins SCOPE's program ID and binds the genesis hash, mint and account. `PaymentSigner` delegates to the crypto crate's existing nonce-safe raw-scalar signing; a fallible v1 builder accepts any Solana signer. Existing keypair builders retain their API. Rejected: treating the recovered scalar as an Ed25519 seed or duplicating signing in the client.

## 2026-10-04 Recipient key interoperability

- **Meta-address version 1 uses Base58Check.** The shareable format is `scope:` followed by Base58Check of `0x01 || B_spend || B_scan`, with four bytes of double-SHA256. Version 1 fixes the key layout and current payment schedule. The library uses the existing `bs58` package's checksum support and bounds decoding to 69 bytes and 95 encoded characters before validating both keys. Rejected: unversioned concatenation or handwritten production encoding and checksum code. CLI wiring remains client work. Evidence: V62.

- **Sweep derivation returns a standard seed.** `derive_sweep_destination` expands the documented recipient-only HKDF-SHA512 schedule to a protected 32-byte Ed25519 seed from the canonical spend scalar and exact R. The client constructs D_owner's SDK keypair and creates D. Rejected: deriving from S, returning a raw signing scalar for this standard key, or adding Solana key types to the crypto crate. Independent seed, public-key and signature vectors and SDK reconstruction are V61; external review remains Q1.

- **Back up exact recipient secrets.** The raw format is a canonical nonzero little-endian spend scalar followed by the original scan secret, 32 bytes each. Imports reject invalid scalars and exports use a zeroizing wrapper without `Debug`, `Clone` or `Copy`; encrypted storage belongs to the caller. Rejected: treating the spend scalar as an Ed25519 seed, reducing invalid imports, or silently normalizing scan bytes. Evidence: V60.

- **Validate public keys at import.** `RecipientPublicKeys::from_bytes` accepts canonical, nonidentity prime-order Edwards spend keys and contributory X25519 scan keys. Scan bytes retain X25519's input rules, including equivalent encodings; payment derivation still checks its actual shared secret. Rejected: unchecked imports, a handwritten scan-key blacklist, or converting scan keys to Edwards points, which would change the accepted X25519 inputs. Evidence: V59.

## 2026-10-03 Reconstruct payer payments from ephemeral secrets

- **Supplied r returns the full payment.** `derive_payment_with_ephemeral` borrows a protected X25519 `EphemeralSecret` and returns `SenderPayment`, including R, P, the discovery tag and private material for later `ct_ikm` derivation. The random API generates r and delegates to it. This lets the client reconstruct a payout row without changing the existing derivation or vectors (V58). Rejected: returning only R, which leaves the client without the rest of the payment; accepting context before R, since the token-account address in that context depends on R. Run-secret derivation and storage remain Q16; the rest of Q14 stays open.

## 2026-09-30 Program before devnet

- **Payer as base, not a creator key from S.** Both block front-running: only a key that signs can create the account. A key A derived from S would let a recipient find the account from R alone, but adds a second signature to every payer transaction, a raw-scalar signer on the payer side, and gives up the program's check that R matches the account. Recipients know their payer in the target uses (payroll, invoices).
- **Drop k.** v1 uses a fresh R per payment, so k was always 0. The seed is `sha256("stealth-ta/v1" || R)`, `announce` data is 33 bytes and the announcement 68, with the view tag still at offset 2. Rejected: keeping k for several accounts per R, which a fresh R covers at no cost. Supersedes the k in the 2026-09-28 `create_with_seed` line.
- **`reclaim` binds by the announcement PDA.** Only `announce` writes an announcement, and only at `["ann", T]` for the token account T it checked, so a decoy D gives `["ann", D]` and fails. The recompute from (payer, R) proved the same fact a second time. Supersedes the 2026-09-28 line "`reclaim` recomputes the token account"; the decoy test stays (V34).
- **One module per instruction.** Each instruction has an accounts struct that checks count, signer and program ids when it is built, and a `process` function for the rest. Rejected: a macro-generated error list, which added nothing the existing code-position test does not cover.
- **One crypto tree in the docs.** crypto.md describes the tree the crate implements; Q14 keeps what is still missing.
- **CU ceilings at bump 255.** `announce` searches for the canonical bump and each lower bump costs 1,500 CU, so budgets are measured at bump 255 (V55).

## 2026-09-28 Migrate the tested crypto library

Import the standalone `stealth-keygen` HKDF-SHA256, ElGamal, symmetric-key, test-vector and documentation changes. Preserve its derivation constants and use SCOPE's pinned SDK 7.0.1 so returned key types match the client dependency. This migration does not resolve Q14 or replace the target protocol tree. Rejected for this change: silently rewriting the imported derivation to HKDF-SHA512 or adding a second direct SDK version. Evidence: V53.

## 2026-09-28 Payer engine, plain rows first

- **Plain rows before stealth rows.** `scope pay` pays plain recipients now; stealth rows need the run secret, E from it, and the `ct_ikm` export, which wait on Q14. Rejected: building stealth rows against the pre-convergence `stealth-keygen` API and rewriting them after Q14.
- **Confidential funding only (Q3).** The engine spends the source's available balance and never deposits; the payer shields and applies before a run. A deposit inside `pay` would publish each run's total at the run's start; funding ahead of time keeps the two apart. Rejected for v1: a deposit step inside `pay`.
- **Source keys as spl-token-cli 5.6 derives them.** Per wallet, `derive_confidential_keys(payer, b"")`, so a source set up with that CLI works and one keypair backs up everything (V50). Rejected: per-account seeds (no CLI can then fund or apply) and zk-sdk's legacy signer derivation, deprecated in 7.0.1.
- **Send order from OS randomness until the run secret exists.** The permutation is stored in the run header, which resume needs anyway; with stealth rows it derives from the run secret as client.md says. Rejected: file order, which the chain would mirror.
- **Simulate, journal, then send.** An attempt that fails simulation is never journaled or sent, so a bad row halts the run instead of looping through expiries. Sends skip preflight and RPC retries; the engine resends until the attempt lands or its blockhash is finalized dead.
- **Two more permissive licenses.** The RPC client's TLS brings ISC (ring, rustls-webpki, untrusted) and CDLA-Permissive-2.0 (the webpki-roots CA bundle); `deny.toml` allows both.

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
