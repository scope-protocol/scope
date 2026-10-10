---
status: decided
last_verified: 2026-10-10
---

# Proving an amount

TL;DR: for a payer, a recipient or an auditor who needs to show what one confidential payment moved. After reading you can produce a receipt with `scope disclose`, check one with `scope verify`, and know what it reveals and whom you trust.
A receipt names one finalized payment transaction and proves its amount against that transaction's own ciphertext-validity proof, which Token-2022 verified when it landed. It still verifies after every account involved is closed (verification: V79).

## Which receipt?

| You are | Row | Command | Receipt kind | You need |
|---|---|---|---|---|
| Payer | plain or stealth | `scope disclose --run <id> --row <i>` | `opening` | payer keypair, the run's `runs/` directory |
| Recipient | stealth | `scope disclose --signature <payment>` or `--token-account <T>` | `account_key` | recipient backup, the payment signature or its token account |
| Recipient | plain | none | | the mint's auditor, if the issuer set one (below) |

Anyone can run `scope verify` on either kind with an archival RPC node.

## Producing a receipt

As the payer, name the run and the row number from its `scope pay` output ([payer.md](payer.md)):

```sh
scope disclose --run 3f9c0a1b2d4e5f60 --row 1 \
  --keypair ~/.config/solana/id.json --runs ~/.local/share/scope/runs --url <archival-rpc-url> --out row1.receipt.json
```

It reads the run's journal and input copy, takes the row's landed signature and amount, and re-derives the row's two Pedersen amount openings from the run secret, so nothing was stored for this ([crypto.md](crypto.md)). It refuses a row that has not landed, and a run whose header has `derived_openings` false (verification: V79).

As a stealth recipient, name the payment transaction:

```sh
scope disclose --signature <payment-signature> \
  --recipient-key ~/.config/scope/recipient.key --url <archival-rpc-url> --out payment.receipt.json
```

It fetches the transaction, finds R and the view tag in its `announce` data, derives the one-time account's `ct_ikm`, and refuses unless the derived ElGamal key is the transfer's destination key, so a stranger whose view tag happens to match gets no receipt (verification: V80). An age-encrypted backup takes `--identity` as in [recipient.md](recipient.md).

If you do not have the signature, name the payment's one-time token account instead (`scope scan` and `scope recover` print it, and so does the recovery journal):

```sh
scope disclose --token-account <T> \
  --recipient-key ~/.config/scope/recipient.key --url <archival-rpc-url> --out payment.receipt.json
# payment signature: <signature>                          (stderr)
```

`disclose` then looks the signature up itself: it lists the transactions that touch `T`, and takes the oldest successful one that holds an `announce` for `T`, since anyone can send lamports to that address first. This works after `reclaim` closed `T`, because the node still lists the transaction. History is read at finalized commitment, so a payment younger than about 13 seconds is not found yet. A node that keeps no history for `T` gives "no payment transaction"; pass `--signature` then.

| Flag | Default | Meaning |
|---|---|---|
| `--run <RUN_ID>` | | payer receipt; needs `--row`; conflicts with `--signature` |
| `--row <i>` | | row number, from 0, counting rows only |
| `--keypair <file>` | `~/.config/solana/id.json` | payer keypair, with `--run` |
| `--runs <dir>` | `~/.local/share/scope/runs` | run journals, with `--run` |
| `--signature <sig>` | | recipient receipt for this payment |
| `--token-account <T>` | | recipient receipt, signature found in history; conflicts with `--signature` and `--run` |
| `--recipient-key`, `--identity` | `~/.config/scope/recipient.key`, none | recipient backup, with `--signature` or `--token-account` |
| `--out <file>` | stdout | write to a new file, mode 0600; never overwrites |
| `--url <rpc>` | as in [recipient.md](recipient.md) | RPC node that keeps transaction history |

`disclose` verifies the receipt against the chain before it writes anything; if that fails it prints "the receipt does not verify against the chain; nothing written". Without `--out` it prints the JSON to stdout; for an `account_key` receipt it also warns on stderr that the receipt grants read access to the one-time account. Prefer `--out` for those.

## Receipt formats

Both are JSON, tagged by `kind`, version 1. `cluster` is the cluster's genesis hash and every binary field is lowercase hex.

Payer receipt:

```json
{
  "kind": "opening",
  "version": 1,
  "cluster": "<genesis hash, 64 hex>",
  "signature": "<payment transaction signature, base58>",
  "amount": 980000000,
  "opening_lo": "<Pedersen opening of the low 16 bits, 64 hex>",
  "opening_hi": "<Pedersen opening of the high 32 bits, 64 hex>"
}
```

Recipient receipt:

```json
{
  "kind": "account_key",
  "version": 1,
  "cluster": "<genesis hash, 64 hex>",
  "signature": "<payment transaction signature, base58>",
  "ct_ikm": "<one-time account key material, 64 hex>"
}
```

`amount` is in base units.

## Checking a receipt

```sh
scope verify row1.receipt.json --url <archival-rpc-url>
```

```text
verified	<signature>
amount_base_units	980000000
payer	<fee payer of the payment transaction>
source	<payer's confidential token account>
destination	<account paid: the recipient's own, or the one-time account>
mint	<mint>
```

Any failed check exits with an error and prints none of these lines.

## What verify checks

1. The receipt version is 1.
2. `cluster` equals the node's genesis hash.
3. The node returns the finalized transaction for `signature`; the receipt's signature is its first, it carries exactly the required signatures, and every one verifies against the message.
4. The node reports that the transaction succeeded.
5. The transaction holds a Token-2022 confidential Transfer whose ciphertext-validity proof is inline in the same transaction; source, mint and destination come from that Transfer.
6. For `opening`: the amount fits in 48 bits, and the two openings, with the amount's low 16 and high 32 bits, reproduce the proof's two Pedersen commitments. An amount off by one fails (verification: V79).
7. For `account_key`: the ElGamal key derived from `ct_ikm` equals the transfer's destination key, then it decrypts the amount from the destination handles. A forged `ct_ikm` fails the key check (verification: V80).

The payer line is the transaction's fee payer, which signs every `scope pay` transaction. Receipt math is in [crypto.md](crypto.md).

## What a receipt reveals

| Receipt | Reveals to whoever holds it |
|---|---|
| `opening` | this one transfer's amount; nothing about other rows, the source balance or the run secret |
| `account_key` | read access to that one-time account: the amount, its balances, and any further credit to it; nothing about other payments or your keys |

Both point at a public transaction, so the holder also learns which payer, source, mint and destination the payment involved, all already public on chain. For a stealth payment, presenting the receipt links you to its one-time account. That neither kind reveals more rests on HKDF-SHA256 behaving as a PRF [likely, pending review; [crypto.md](crypto.md)]. Who learns what without a receipt is in [privacy.md](privacy.md).

## Whom do you trust?

The node. `verify` needs `getTransaction` at finalized commitment with `maxSupportedTransactionVersion: 1`, because payments are v1 transactions (verification: V22), from a node that keeps history back to the payment's slot; a node that has pruned it cannot verify the receipt.

Because the returned transaction must carry the receipt's signature first and every signature must verify, a node cannot substitute or alter the transaction: a swapped or altered transaction is refused (verification: V79). What a dishonest node can still do is misreport whether the transaction succeeded, claim not to have it, or report a different cluster's genesis hash. Use a node you trust for those, or check the result on a second one.

A mint auditor key, where the issuer set one, is a second path: the auditor decrypts every transfer on that mint from its own handle without any receipt (verification: V12). It is the only path for a plain-row recipient.

## Limits

- A recipient needs the payment signature or the token account. `scope pay` prints the signature per row, so the payer can hand it over; `scope recover` lists both from history. Recovery from the key backup alone needs an RPC that keeps transaction history for the program, within `--limit` listed signatures (failed ones count; the command says when the limit cut the walk short), and fails without one.
- The payer needs the run's journal and input copy as well as the key: the run secret rebuilds the openings, but the row's signature and amount come from the run directory.
- A receipt covers one transfer. Proving a total means one receipt per row.
- `disclose --run` reads the mint's decimals from the chain to parse the input copy, so the mint account must still exist [unverified: no test].
