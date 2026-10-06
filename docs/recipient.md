---
status: verified
last_verified: 2026-10-06
---

# Recipient client

TL;DR: `scope register`, `scan`, `sweep` and `export-sweep-key` provide private backups, authenticated discovery, confidential sweeps and usable destination keys.
The implementation and RPC wire format are tested locally; a full sweep with an auditor and dust measures 3,350 bytes and 268,049 CU (V68). Provider-scale and devnet release gates remain open in [plan.md](plan.md).

## Commands and backups

```sh
scope register --recipient-key ./recipient.key
scope scan --recipient-key ./recipient.key --url http://127.0.0.1:8899
scope sweep --recipient-key ./recipient.key --url http://127.0.0.1:8899 \
  --announcement <address-from-scan> --dry-run
scope sweep --recipient-key ./recipient.key --url http://127.0.0.1:8899 \
  --announcement <address-from-scan>
```

Registration creates a local backup and prints the public meta-address; publishing it on chain is a separate, optional `scope publish`. Existing backups are never overwritten. Raw files contain the library's 64-byte format, must be regular and nonsymlinked, and require owner-only permissions. New files use mode 0600; new directories use 0700. The file and parent directory are synchronized before success, including a bare filename. Secret buffers are cleared on drop (verification: V66).

Encrypted backups use [age](https://github.com/FiloSottile/age). Supply its public recipient at registration and an owner-only private identity when loading. Plaintext streams through age and is never written to a temporary file. The encrypted round trip is tested with age installed (V66).

```sh
scope register --recipient-key ./recipient.age --encrypt-to <age-public-recipient>
scope scan --recipient-key ./recipient.age --identity ./identity.txt --url <rpc-url>
scope sweep --recipient-key ./recipient.age --identity ./identity.txt \
  --url <rpc-url> --announcement <announcement-address>
```

Defaults are `~/.config/scope/recipient.key` and localhost RPC.

## Discovery

`scan` fetches program-owned accounts with the announcement data size and version prefix. Recipient tags depend on each R, so they are checked locally. It validates the canonical PDA, payment authority, mint filter, account policy, derived ElGamal key and authenticated balance hint; pending amounts are decrypted locally. It checks arithmetic and single-credit component limits. Public all-zero ciphertexts are recognized without a discrete-log search (V64).

`scan_with_results` reports each valid payment or skipped candidate as soon as it is inspected. The CLI flushes valid rows and writes skipped reasons to stderr. Output errors stop scanning. Rows contain announcement, token account, mint, confidential and public amounts in base units, and public R. `--mint` restricts discovery. Plain `scan` retains a sorted `ScanReport`; chain errors remain fatal, and an interrupted CLI scan can leave already-validated rows in stdout (V64).

A local RPC fixture scans 1,000 canonical seeded announcements and authenticates the owned payment through the real SDK transport. It also verifies server-side layout filters. This is local evidence, not a provider latency guarantee or completion of S6 (V67).

## Transfer and recovery

`prepare` authenticates the payment, derives a standard Ed25519 D_owner from `b_spend` and exact R, and simulates a signed v1 transaction. D is `create_with_seed(D_owner, "scope-sweep/v1", Token-2022)`. Every build reads its current rent deficit, then transfers funding, allocates and assigns with D_owner as the signing base. Incoming SOL cannot invalidate creation. An initialized token destination is refused (V61, V65).

The transaction disables confidential credits to the source, applies pending balances, transfers the whole confidential amount, and empties the source. Full cleanup additionally burns public dust and reclaims rent to the payer. If that simulation fails, a separately simulated transfer-only version can leave public dust and rent behind, including for permissioned-burn mints. The recipient retains a rent reserve in P; surplus SOL goes to D_owner when it can receive it without becoming rent-paying. Funding quotes include chain fees, destination deficit and P's reserve (V65).

`submit` resends an identical transaction while its outcome is unresolved. Only a finalized failure or blockhash expiry authorizes rebuilding. At most two transfer-only retries refresh source balances, mint policy, auditor proofs, blockhash, rent deficit and fees. Each new attempt samples the current p75 priority price and enforces `--max-price`; identical resends keep their signed fee. This covers cleanup failure followed by a further credit to a source whose pending counter was already applied. Retry decoding and proving run on a worker with no chain access; expired waiting cannot lead to a later broadcast (V65, V69).

`submit_with_recovery` adds a fallible callback before every new attempt. The CLI synchronizes a recovery record to disk, then writes and flushes genesis hash, destination, owner, P, R and signature to stdout. Either failure prevents that attempt from being sent. Identical resends reuse the checkpoint; dry runs emit recovery information, send nothing and do not open a journal. Callbacks are synchronous and should return promptly (V65, V66, V70).

The journal defaults to `<recipient-key>.sweeps.jsonl`; `--recovery-file` selects another path. It is a locked, owner-only JSONL file with a versioned header. It records public recovery identifiers and attempt signatures, without private keys or confidential amounts. An interrupted final record is removed before appending; unrelated files and symlinks are refused. Journal entries record prepared attempts and do not prove transaction success. Back up this journal alongside the recipient key (V70).

Once reclaim closes the announcement, exact R plus the recipient backup reconstructs D_owner and its confidential keys. Without the journal or saved output, R must be recovered from historical payer transactions. The key backup alone cannot enumerate past destinations; automatic historical recovery remains Q17. `PreparedSweep` retains protected signing material only in memory and exposes only the public report in debug output (V61, V65).

A successful finalized signature proves this attempt's atomic transfer even if accounts are later closed, funded again, or recreated. It returns success even if optional balance reads fail or exhaust the deadline. Unavailable SOL and public balances are `None` and displayed as unknown; dry-run values are predictions. Without that proof, completion requires an empty or closed source and an authenticated destination; cleanup status can then be unknown. Empty System accounts at closed addresses do not undo reclaim detection. `attempt_signature` names the current attempt; `finalized_signature` is present only with verified success. `amount` describes the most recent prepared attempt. Concurrent completion can leave the amount actually transferred, this attempt's success and burned amount unknown; the CLI labels that amount as prepared (V65, V69).

Errors preserve the recovery report. Unresolved submission includes the latest send error when available. An RPC rejection or transport failure does not establish whether an earlier send landed (V69).

`--max-price` caps the priority price. `--timeout` starts after initial preparation and the first recovery checkpoint. It bounds RPC futures, HTTP retry waits, retry preparation waits and polling sleeps. No further sends start after the deadline; a submitted transaction can still finalize later (V65).

## Using the swept funds

Export D_owner from the recipient backup and public R recorded by scan, sweep or the journal:

```sh
scope export-sweep-key --recipient-key ./recipient.key \
  --ephemeral <public-R> --output ./sweep-owner-keypair.json
```

Encrypted backups accept the same `--identity` option. The command writes a standard Solana keypair file with mode 0600, refuses overwrites and symlinks, and prints only the public owner and D addresses. It makes no RPC calls. An imported owner can apply and spend D's balance with the standard SDK wallet key schedule; this complete flow is tested in LiteSVM (V71).

The swept tokens start in D's pending balance. With `spl-token-cli` 5.6.1, apply it, then transfer from the explicit D address:

```sh
spl-token --program-2022 --url <rpc-url> --fee-payer ./sweep-owner-keypair.json \
  apply-pending-balance --address <D> --owner ./sweep-owner-keypair.json
spl-token --program-2022 --url <rpc-url> --fee-payer ./sweep-owner-keypair.json \
  transfer <mint> <amount-in-token-units> <configured-recipient-token-account> \
  --from <D> --owner ./sweep-owner-keypair.json --confidential
```

Use a funded fee payer; the transfer tool can require SOL for proof context accounts as well as fees. D's keys match the CLI's empty-context derivation, and `--address`/`--from` select this seeded account instead of an associated account. Commands follow the [5.6.1 CLI source](https://github.com/solana-program/token-2022/tree/cli%40v5.6.1/clients/cli/src) and [SPL Token reference](https://solana.com/docs/references/spl-token-cli). Using a shared fee payer can link destinations; the privacy boundaries in [privacy.md](privacy.md) still apply.

## Supported boundary

- The cluster must support v1 transactions and the required Token-2022 confidential instructions; public-cluster verification remains a release gate.
- Mints must auto-approve confidential accounts. Non-transferable, transfer-fee, transfer-hook and frozen-default mints are refused. Issuer freezes, pauses, approval changes or repeated policy changes can still block transfers.
- Whole-balance transfers are limited to Token-2022's single-transfer ceiling, `2^48 - 1` base units. Larger balances require a separate partial-transfer workflow. Large supported amounts and component boundaries are tested (V65).
- Payers must use a fresh R per payment to the same recipient. Reusing R reconstructs the same D; an existing token destination is refused, and closing it does not erase its public history. Another client can spend the source through the raw-scalar signer adapter. D_owner uses the standard SDK wallet schedule (V61, V63).
- An announcement proves setup and handover, not a positive payment amount. Unpaid and already-retired accounts can appear with zero confidential balance; sweep refuses them. Public dust cleanup is separate (V64, V65).

A recipient can publish its meta-address under a wallet with `scope publish` and disclose a payment with `scope disclose --signature` ([client.md](client.md), Audit). Counterparty destinations and reuse overrides remain planned. Local validation does not replace external review of the derivations (Q1).
