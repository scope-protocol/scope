---
status: decided
last_verified: 2026-10-10
---

# Receiving with `scope`

TL;DR: for a recipient of stealth payments. After reading you can create and back up your keys, optionally publish your meta-address, find payments (even after they were swept), sweep them into an account of your own and spend from it.
Plain rows need none of this. Payer commands: [payer.md](payer.md); receipts: [audit.md](audit.md).

## Before you start

- The meta-address `scope register` prints is public: give it to payers or publish it. The key file it writes is the secret; back it up ([Backups](#backups)).
- `scope register` only writes that local file. The on-chain registry entry is `scope publish`, and it is optional.
- You need no SOL to sweep: the payer funds the one-time owner P with the sweep's fees and your new account's rent ([payer.md](payer.md)).

## A working example

```sh
# 1. Create the key backup and print your meta-address. Give the meta-address to payers.
scope register --recipient-key ~/.config/scope/recipient.key
# scope:<meta-address>                                  (stdout)
# recipient backup: /home/you/.config/scope/recipient.key   (stderr)

# 2. Optional: publish the meta-address under a wallet so payers can look it up.
scope publish --recipient-key ~/.config/scope/recipient.key \
  --keypair ~/.config/solana/id.json --url <rpc-url>
# published	<entry address>	<signature>

# 3. Find payments addressed to you.
scope scan --recipient-key ~/.config/scope/recipient.key --url <rpc-url>
# announcement	token_account	payer	mint	amount_base_units	public_amount_base_units	ephemeral
# <announcement>	<one-time account>	<payer>	<mint>	980000000	0	<R>

# 4. Simulate, then sweep one payment into a fresh account of your own.
scope sweep --recipient-key ~/.config/scope/recipient.key --url <rpc-url> \
  --announcement <announcement> --dry-run
scope sweep --recipient-key ~/.config/scope/recipient.key --url <rpc-url> \
  --announcement <announcement>

# 5. Or sweep everything scan finds, one transaction each, with a random pause between.
scope sweep --recipient-key ~/.config/scope/recipient.key --url <rpc-url> \
  --all --jitter-secs 120
```

Before each attempt the sweep prints and saves a recovery record:

```text
genesis_hash	<cluster genesis hash>
destination	<D>
owner	<D_owner>
payment_authority	<P>
ephemeral	<R>
token_account	<T>
attempt_signature	<signature>
```

and after it lands:

```text
swept: 980000000 base units to <D>
SOL remaining	<lamports> lamports at <P>
finalized_signature	<signature>
rent reclaimed
```

`swept` reads `simulated` on a dry run and `prepared amount` when this attempt's own success was not verified. Further lines report burned or remaining public balance and the rent outcome (`reclaimed`, `not reclaimed by this attempt; funds swept without cleanup` or `reclaim status unknown`).

## Flags

Every command that loads keys takes `--recipient-key` (default `~/.config/scope/recipient.key`) and `--identity <file>` for an age-encrypted backup. `scope meta-address` prints the meta-address from the backup, which works with an encrypted one too.

| Command | Flag | Default | Meaning |
|---|---|---|---|
| `register` | `--encrypt-to <age recipient>` | none | encrypt the new backup with age |
| `register` | `--verify-identity <file>` | none | with `--encrypt-to`: decrypt the new file with this age identity and check it matches |
| `publish` | `--keypair <file>` | `~/.config/solana/id.json` | wallet the entry is published under; signs and pays its rent |
| `publish` | `--remove` | off | close the wallet's entry and return its rent |
| every RPC command | `--url <rpc>` | `$SCOPE_URL`, else `http://127.0.0.1:8899` | RPC node |
| `scan` | `--mint <address>` | all mints | show payments in this mint only |
| `scan` | `--min-amount <base units>` | `0` | hide smaller payments |
| `scan` | `--ignore-payer <address>` | none | hide a payer's payments; repeatable |
| `scan` | `--with-signature` | off | add each payment's signature: one listing plus one `getTransaction` per candidate; `unknown` until the payment finalizes, about 13 seconds |
| `recover` | `--limit <n>` | `1000` | program signatures to list, newest first; failed ones count |
| `recover` | `--since <signature>` | none | stop at this signature |
| `sweep` | `--announcement <address>` | one of the two | from `scan` |
| `sweep` | `--all` | off | sweep every payment `scan` finds, one transaction each; a payment that fails alone is listed and skipped, and the run ends with an error naming them; a chain error or a sweep whose completion was not observed stops it |
| `sweep --all` | `--mint`, `--ignore-payer` | none | as for `scan` |
| `sweep --all` | `--min-amount <base units>` | `1` | skip smaller payments; a zero payment cannot be swept |
| `sweep --all` | `--jitter-secs <max>` | `0` | wait a random 0 to `max` seconds between sweeps; 30 to 300 is a sensible range (not used with `--dry-run`) |
| `sweep` | `--max-price <n>` | `1000000` | priority price cap, micro-lamports per CU; the payer funded P for this cap |
| `sweep` | `--timeout <s>` | `120` (at least 1) | deadline for sending and waiting |
| `sweep` | `--dry-run` | off | build and simulate, send nothing, write no journal |
| `sweep` | `--recovery-file <path>` | `<recipient-key>.sweeps.jsonl` | recovery journal |
| `export-sweep-key` | `--ephemeral <R>` | required | public R from scan, sweep or the journal |
| `export-sweep-key` | `--token-account <T>` | required | the payment's token account, from the same places |
| `export-sweep-key` | `--output <file>` | required | new keypair file |
| `export-sweep-key` | `--encrypt-to <age recipient>` | none | write the keypair JSON encrypted with age |
| `disclose` | `--token-account <T>` | none | recipient receipt without the signature; see [audit.md](audit.md) |

## Backups

`register` writes the 64-byte recipient secret to a new file with mode 0600 (directories 0700) and syncs file and directory before it reports success. It never overwrites an existing file. Every load refuses a file that is not a regular, non-symlinked, owner-only file of exactly 64 bytes (verification: V66).

With `--encrypt-to`, the secret streams through [age](https://github.com/FiloSottile/age) and never touches disk in plaintext; load it with `--identity`, an owner-only age identity file. The round trip is tested with age installed (verification: V66).

```sh
scope register --recipient-key ./recipient.age --encrypt-to <age-public-recipient>
scope scan --recipient-key ./recipient.age --identity ./identity.txt --url <rpc-url>
```

`register` warns on stderr about a plaintext backup, and about an encrypted one it did not read back (check it with `scope meta-address --identity <file>`). With `--verify-identity` it decrypts the file first and prints the meta-address only if it matches; on a mismatch stdout stays empty and the file is left in place, unverified.


## Publishing

`scope publish` writes your meta-address to the on-chain registry under `--keypair`'s wallet; `--remove` closes the entry and returns its rent (verification: V81). Entry layout is in [protocol.md](protocol.md); what a lookup reveals is in [privacy.md](privacy.md).

## What does scan check?

`scan` fetches program-owned accounts of the announcement's size and version, then checks each view tag locally, since tags depend on each R. Tag matches' token accounts are read with `getMultipleAccounts`, 100 per call. For a match it checks the canonical announcement address, that the token account's owner is P, its close authority and delegate, that it is not frozen, the account policy (approved, no public credits, one pending credit), the ElGamal key derived for this account, and the balance hint against the ciphertext. Valid rows go to stdout as they are found; a failed check prints `skipped payment <account>: <reason>` to stderr and scanning continues. A chain error stops the scan with "scan stopped after reading N of M candidate accounts"; rows already printed are valid and the rest were not read (verification: V64).

A local RPC fixture scans 1,000 seeded announcements in about 350 ms; provider-scale timing is not measured (verification: V67).

An announcement proves setup and handover, not a positive amount: an unpaid or already swept account can show a zero amount, and sweep refuses it (verification: V64, V65).

## What does the sweep transaction do?

One v1 transaction, fee paid by P and signed by P and D_owner. It creates your fresh account D, owned by D_owner, a standard Ed25519 key derived from your spend key and the exact R (verification: V61); moves the whole confidential amount from the one-time account into D and applies it, so D's available balance holds the amount when the sweep lands; burns any public dust and calls `reclaim`, which returns the one-time account's rent to the payer (verification: V77); and sends P's spare SOL to D_owner when that is enough for D_owner to stay rent-exempt, while P keeps its rent reserve (verification: V65). SOL someone sent to D's address cannot block it, and an existing token account at D is refused (verification: V65). Details: [protocol.md](protocol.md).

## Fallback, retries and dust

If the full transaction fails simulation, the sweep simulates a transfer-only version: steps 1 to 3 and 5, no burn, no reclaim. It moves your funds but leaves any public dust and both rents behind, for example on a mint where only the issuer may burn (verification: V65). The payer can reclaim the rent later only if no public balance remains.

The sweep resends one signed transaction while its outcome is unknown. Only a finalized failure or blockhash expiry allows a rebuild, at most two, each transfer-only, refreshing balances, mint policy, proofs, blockhash, rent deficit and price. A rebuild samples the current p75 price and refuses one above `--max-price`; a resend keeps its signed fee (verification: V65, V69). The payer funded P for three attempts at the 1,000,000 cap ([payer.md](payer.md)).

`--timeout` starts after preparation and the first recovery record; no new send starts after it, but a sent transaction can still finalize. On timeout the sweep exits with "sweep completion has not been observed; check chain state before retrying" and the last recovery record (verification: V65).

Success is a finalized successful signature for this attempt, even if follow-up reads fail (`unknown`). Otherwise it is complete only when the one-time account is empty or closed and D is yours (verification: V69).

## Recovery

The recovery journal (default `<recipient-key>.sweeps.jsonl`) is a locked, owner-only JSONL file with header `{"format":"scope-recipient-recovery","version":1}`. Before every new attempt the sweep appends `genesis_hash`, `ephemeral`, `token_account`, `destination`, `owner`, `payment_authority` and `attempt_signature`, syncs it, then prints the same record to stdout; if either fails, that attempt is not sent. It holds no private key and no amount, but it is plaintext and links P, D, D_owner and R, so keep it as private as the key backup. A torn last record is cut before the next append; a foreign file or a symlink is refused (verification: V70). An entry records a prepared attempt, not a landed one.

Once an announcement is reclaimed (a full sweep does this), scan no longer lists that payment. R and T plus the key backup rebuild D's keys, so keep the journal or the saved output.

Without them, `scope recover` rebuilds the list from history. It walks the program's transactions newest first, finds each `announce`, applies the one-byte tag check, and keeps a payment only when the transaction's own confidential transfer pays the key derived for you. It needs an RPC that keeps transaction history for the program and lists `--limit` signatures (1,000 by default, failed ones included). Rows print as found. A transport error is retried, then stops the run with the counts so far; printed rows stay valid. If the limit cut the walk short, stderr says so and prints the last signature examined for `--since`. No public RPC provider has been tried [unverified].

```sh
scope recover --recipient-key ~/.config/scope/recipient.key --url <archival-rpc-url> --limit 5000
# payer	mint	token_account	ephemeral	signature	destination	destination_exists	destination_lamports	destination_base_units
```

## Spending the swept funds

Export D_owner as a standard Solana keypair:

```sh
scope export-sweep-key --recipient-key ./recipient.key \
  --ephemeral <R> --token-account <T> --output ./sweep-owner-keypair.json
# owner	<D_owner>
# destination	<D>
```

It writes the file with mode 0600, refuses overwrites and symlinks, prints only public addresses and makes no RPC call. With `--encrypt-to <age recipient>` the file holds the keypair JSON encrypted with age; decrypt it with `age --decrypt -i <identity> <file>` before use. An imported owner spends D's balance with the standard SDK wallet key schedule; that flow is tested in LiteSVM (verification: V71).

The sweep applies the pending balance, so D_owner can transfer from D at once (tested in LiteSVM with the restored key). With spl-token-cli 5.6.1 the transfer looks like this [unverified: no test runs this command line; it follows the [5.6.1 CLI source](https://github.com/solana-program/token-2022/tree/cli%40v5.6.1/clients/cli/src)]:

```sh
spl-token --program-2022 --url <rpc-url> --fee-payer ./sweep-owner-keypair.json \
  transfer <mint> <amount-in-token-units> <configured-recipient-token-account> \
  --from <D> --owner ./sweep-owner-keypair.json --confidential
```

D_owner needs SOL for fees and possibly for proof context accounts. D's keys match spl-token-cli's own derivation from the owner (verification: V50, V77). A fee payer shared across destinations links them ([privacy.md](privacy.md)).

## Limits

- The cluster must support v1 transactions and Token-2022's confidential instructions; public-cluster checks are tracked in [plan.md](plan.md).
- The sweep refuses mints that need approval of new accounts, freeze new accounts by default, or carry non-transferable, transfer-fee or transfer-hook extensions [unverified: no test for the extension refusals]. Issuer freezes or policy changes can still block a sweep.
- One sweep moves at most 2^48 - 1 base units, Token-2022's single-transfer limit; a larger balance is refused (verification: V65).
- D depends on R and the token account T, so two announcements that reuse one R still sweep to different destinations. A payment swept twice gets the same D, which the sweep refuses once it exists (verification: V61, V65).
- Any client holding your spend key can spend a one-time account; `scope` uses a raw-scalar signer, and D_owner is a standard key (verification: V61, V63).
- Your receipt for a payment needs that payment's signature, or its token account when the node keeps history ([audit.md](audit.md)).
