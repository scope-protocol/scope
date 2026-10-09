---
status: decided
last_verified: 2026-10-10
---

# Paying with `scope pay`

TL;DR: for whoever runs payouts. After reading you can write an input file, preview a batch, pay plain and stealth rows, recover from a crash, price the run, and get stealth-row rent back.
Each row is paid at most once; the run journal and the payer key suffice to resume, check status or prove an amount ([audit.md](audit.md)).

## Before you start

| You need | Why |
|---|---|
| A cluster with Token-2022 confidential transfers enabled | every row is a confidential transfer |
| `scope-program` deployed on that cluster, for stealth rows only | stealth rows call `announce`; plain rows use Token-2022 alone. Where it is deployed: [plan.md](plan.md) |
| A source: your confidential Token-2022 account on the mint, owned by `--keypair`, with its pending balance applied | the engine derives the source's ElGamal and AE keys from `--keypair` the same way spl-token-cli 5.6.1 does (verification: V50) |
| SOL in the payer wallet | per stealth row 8,630,800 lamports (about 0.0086 SOL) plus fees: 4,008,120 of rent that comes back and 4,622,680 that funds the recipient's sweep. Twenty stealth rows need about 0.173 SOL. The run checks this first and stops with "the payer needs X SOL, has Y". Breakdown: [How much does a stealth row cost the payer?](#how-much-does-a-stealth-row-cost-the-payer) |

Setting up the source with spl-token-cli [unverified: not run in this repo]:

```sh
spl-token create-account <MINT>
spl-token configure-confidential-transfer-account --address <SOURCE>
spl-token deposit-confidential-tokens <MINT> <AMOUNT> --address <SOURCE>
spl-token apply-pending-balance --address <SOURCE>
```

## A working example

`payroll.csv`:

```text
recipient,amount
# March payroll
<recipient-token-account>,1250.50
scope:<meta-address from the recipient's `scope register`>,980   # contractor, one-time account
```

Preview first: `--dry-run` runs every check below and sends nothing.

```sh
scope pay --dry-run --input payroll.csv --mint <mint> --source <your-confidential-token-account> \
  --keypair ~/.config/solana/id.json --url <rpc-url>
```

```text
cluster	devnet
rows	2 (1 plain, 1 stealth)
total	2230.500000 (2230500000 base units)
payer SOL	needs 0.010101680, has 4.500000000
fee cap per row	280000 lamports plain, 300000 stealth, at 1000000 micro-lamports/CU
fee price now	8001 micro-lamports/CU
nothing sent, no journal written
```

Then run it. On mainnet-beta a real run also needs `--yes`.

```sh
scope pay --input payroll.csv --mint <mint> --source <your-confidential-token-account> \
  --keypair ~/.config/solana/id.json --url <rpc-url>
```

Progress goes to stderr, the result to stdout; rows go out in random order:

```text
run 3f9c0a1b2d4e5f60: 2 rows                          (stderr)
journal: ~/.local/share/scope/runs/3f9c0a1b2d4e5f60/journal.jsonl   (stderr)
row 1: <one-time token account> paid, <signature>     (stderr)
row 0: <recipient-token-account> paid, <signature>    (stderr)
run 3f9c0a1b2d4e5f60 done                             (stderr)
run 3f9c0a1b2d4e5f60: 2 rows paid
1	<one-time token account>	<signature>
0	<recipient-token-account>	<signature>
```

Each stdout line is the row, the account paid and the payment signature. Keep the run id; a stealth recipient needs the signature for a receipt ([audit.md](audit.md)).

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--input <file>` | required for a new run | `recipient,amount` rows |
| `--mint <address>` | required for a new run | Token-2022 mint with confidential transfers |
| `--source <address>` | required for a new run | your confidential token account, owned by `--keypair` |
| `--keypair <file>` | `~/.config/solana/id.json` | owns the source, signs and pays every fee |
| `--url <rpc>` | `$SCOPE_URL`, else `http://127.0.0.1:8899` | RPC node |
| `--runs <dir>` | `~/.local/share/scope/runs` | one journal directory per run; relative paths are made absolute |
| `--max-price <n>` | `1000000` | priority price cap, micro-lamports per CU |
| `--again` | off | pay an input file an earlier run already paid |
| `--resume <run_id>` | | continue an interrupted run |
| `--status <run_id>` | | rows landed, run state, plain rows, stealth rows |
| `--reclaim` | off | with `--status`: reclaim rent of swept rows |
| `--reclaim-all` | off | reclaim every swept row this payer ever made, no journal needed |
| `--dry-run` | off | check and price a new run; send nothing, write nothing |
| `--yes` | off | confirm a real run on mainnet-beta |

`--input`, `--mint` and `--source` conflict with `--resume`, `--status` and `--reclaim-all`; those three and `--dry-run` conflict with each other. `lookup`, `publish` and `disclose` read `--url` and `$SCOPE_URL` the same way.

## What can a row be?

One `recipient,amount` per line. A first line starting with `recipient` is a header; blank lines are skipped and `#` starts a comment.

- **Recipient.** A plain row names the recipient's own configured confidential token account. A stealth row names a `scope:` meta-address, whose checksum, version and keys are checked before anything is derived (verification: V62). `scope lookup <wallet>...` finds published ones ([privacy.md](privacy.md)).
- **Amount.** Token units, a plain decimal with at most the mint's decimals: no sign, no exponent, not zero, at most 2^48 - 1 base units, the limit of one confidential transfer (281474976.710655 on 6 decimals; verification: V84).
- **Row number.** Rows count from 0 in file order, skipping header, comments and blank lines; `--status`, the output and `disclose --row` use it.

The rows together must fit the source's available balance (verification: V48).

## Which mints work?

| Mint property | Plain row | Stealth row |
|---|---|---|
| Token-2022 with the confidential transfer extension | required | required |
| Auditor key | works, proofs include it (V48) | works, proofs include it |
| New confidential accounts need the issuer's approval | works if the recipient's account is already approved | refused before anything is sent (V72, V76) |
| New accounts frozen by default | works if the recipient's account is not frozen | refused [unverified: no test] |
| Transfer fee (even 0 bps), transfer hook (even a null program), non-transferable, paused | refused, naming the extension | refused, naming the extension |
| Permanent delegate, mint close authority | works; a trust limit ([privacy.md](privacy.md)) | works; a trust limit |

SCOPE has no transfer-with-fee path and passes no hook accounts, so fee and hook mints are refused. PYUSD and USDG carry both (fee config at 0 bps, a hook with no program, a confidential-transfer fee config) plus a permanent delegate, and require approval of every new confidential account; neither works today (extensions: V90; approval: V14). Stealth rows need a mint that approves new accounts itself, because `announce` does not check approval (V72). Mint policy binds rows still to pay: a later change does not stop `--resume` from settling rows already paid, nor `disclose` (V84).

## What happens to each row?

**Before anything is sent**, the run checks the mint, every row, the source (owner, mint, ElGamal key from `--keypair`, balance hint against the ciphertext), the payer's SOL, and every plain recipient (Token-2022, same mint, not frozen, approved, credits on). A recipient named by several rows needs pending-credit room for all of them. Any failure stops it with no journal created (verification: V48, V50).

**Per row**, in the random send order:

1. Build the transfer on the source's current ciphertext. A stealth row adds the one-time account's setup, handover, `announce` and P's funding in the same transaction ([protocol.md](protocol.md)).
2. Simulate it; a failure stops the run, nothing sent.
3. Journal the attempt with its signed transaction and fsync.
4. Send, and resend the same signed transaction until the source shows it landed or the attempt is dead (expired, or landed with an error).
5. Record `landed` at confirmed, then move on.

Then the run waits for the finalized source to show the last ciphertext and writes `done`.

**At most once.** Token-2022 applies a transfer only on the exact source ciphertext its equality proof was built on, and every attempt for a row is built on that ciphertext, so at most one lands (verification: V8). The source's available ciphertext is the oracle: the attempt's post-transfer value (V51) means it landed, the pre-transfer value means nothing did, anything else halts. A row is rebuilt once the finalized block height passes the attempt's last valid height with the finalized source still at the pre-transfer value, or once the attempt landed with an error. After three expired or failed attempts in a row the run halts with the last error; `--resume` tries again. Spending from the source meanwhile halts the run (V48).

If a stealth row's attempt expires and someone funds its now-public one-time address, the rebuild creates the account with a top-up transfer, AllocateWithSeed and AssignWithSeed (verification: V76); an address that already holds an account halts the run [unverified].

## What if the run crashes?

Rerun with the run id:

```sh
scope pay --resume 3f9c0a1b2d4e5f60 --keypair ~/.config/solana/id.json --url <rpc-url>
```

Resume reads the journal, then the chain: an open attempt that landed is recorded, one still alive is driven on, one that died is rebuilt. Idempotent RPC reads retry three times; sends never. Errors never print the RPC URL, which may carry an API key.

The journal is `<runs>/<run_id>/journal.jsonl`, mode 0600 in a 0700 directory, beside `input.csv`, the input copy. It holds a header (format, cluster genesis hash, input hashes, mint, source, payer, send order, `derived_openings`), then attempts (with the signed transaction), `landed` records, a `halted` record if the run stops on an error, and `done`. No secret and no plaintext amount (verification: V48). Older journals still read. Resume, status, reclaim and `disclose` refuse a node on another cluster and a journal from a newer scope. One writer holds its lock. A last line a crash cut short, or garbage, held an attempt never sent and is cut off before the next append (V84).

**Duplicate input.** `pay` refuses an input that matches an earlier run under `--runs`, naming it, and when an earlier journal is unreadable. Matching hashes the sorted recipients and base-unit amounts with the mint and the payer, so row order, line endings, comments and whitespace do not matter and the same file on another mint is a new payout. `--again` pays twice on purpose (verification: V48, V84).

Back up the runs directory: resume, status and `disclose` need it.

## Run secret

Nothing secret is stored for a run. Each stealth row's ephemeral key and every row's amount openings come from a run secret that only the payer keypair rebuilds, being derived from a deterministic Ed25519 signature (verification: V75; [crypto.md](crypto.md)). Back up the payer key and the runs directory, and never let that key sign for other software: its signature over `scope-run-secret/v1` and a run id reveals what that run paid.

## How much does a stealth row cost the payer?

| Item | Lamports | Comes back? |
|---|---|---|
| Rent of the one-time token account | rent(account size), 3,012,440 for a mint with no account extensions | yes, to the payer, when it is reclaimed |
| Rent of the 68-byte announcement | 995,680 | yes, with the token account |
| P's funding, `fees::sweep_funding` | rent(D) + rent(0) + 3 x (10,000 + 310,000) | no, it pays the recipient's sweep |
| The payment's own fee | 5,000 + priority price x 295,000 / 10^6 | no |

Rents are read from the node at run time; these are today's (verification: V23, V11). A full sweep reclaims both rents to the payer (V77).

P's funding is what the sweep needs for one attempt at the 1,000,000 micro-lamport cap: D's rent, two signatures at 5,000 lamports, the priority fee at the sweep's 310,000-CU limit, and P's rent reserve, plus a fee for each of its two rebuilds. The cap, not today's price, because the recipient may sweep weeks later; one lamport less is refused (verification: V74). With no account extensions that is 3,012,440 + 650,240 + 960,000 = 4,622,680 lamports; what P does not spend goes to the recipient.

## How are fees priced?

Each new attempt samples the latest confirmed block, or an earlier one if that slot was skipped: the per-CU price every landed non-vote transaction paid (ComputeBudget price for legacy and v0, header `priority_fee` over its compute-unit limit for v1), at the nearest-rank p75, 0 for an empty block (tests in `crates/client/src/fees.rs`). `getRecentPrioritizationFees` is not used: unfiltered it returns each slot's minimum (verification: V39).

Above `--max-price` the run stops with "priority fee ... is above the cap ...; resume later". Resends keep their signed fee. The v1 header carries total lamports, price times the shape's compute-unit limit (verification: V20), so each shape has a limit about 15% above its measurement (V73):

| Shape | CU limit |
|---|---|
| Plain row | 275,000 |
| Stealth row | 295,000 |
| Sweep (recipient) | 310,000 |
| Reclaim | 3,800 |

## How do I check stealth rows and get rent back?

```sh
scope pay --status 3f9c0a1b2d4e5f60 --keypair ~/.config/solana/id.json --url <rpc-url>
```

```text
run 3f9c0a1b2d4e5f60: 2/2 rows landed, done
journal: ~/.local/share/scope/runs/3f9c0a1b2d4e5f60/journal.jsonl
row	recipient	state	signature
0	<recipient-token-account>	landed	<signature>
row	token_account	announcement	state
1	<one-time token account>	<announcement>	open
```

The first line is `done`, `halted: <reason>` or `unfinished; scope pay --resume <id>`. Plain rows show `unpaid`, `unresolved, resume the run` or `landed`. It works while the run is live.

| State | Meaning | What to do |
|---|---|---|
| `unpaid` | the run never attempted this row | resume the run if it is unfinished |
| `unresolved, resume the run` | attempted, outcome never recorded, no open announcement; it may have landed and been swept since | `--resume`; it settles the row from the source ciphertext |
| `open` | paid and announced; not swept, or swept with public balance left | wait for the recipient |
| `swept` | announcement open, every balance of the account empty | `--reclaim` |
| `reclaimed` | announcement closed, rent back with the payer | nothing |

(verification: V78)

```sh
scope pay --status 3f9c0a1b2d4e5f60 --reclaim --keypair ~/.config/solana/id.json --url <rpc-url>
```

`--reclaim` calls `reclaim` for every `swept` row at the sampled price under `--max-price` and a 3,800-CU limit, then prints the new status. A full sweep already reclaims; this is for a transfer-only fallback. Token-2022 refuses to close an account with a balance, so reclaim cannot touch funds (verification: V4). After three expired attempts on a row it stops with "reclaim did not land in 3 attempts; try again later"; rerunning is safe (V78).

Without a journal, `--reclaim-all` finds every announcement this payer made, reclaims those whose account is empty, and prints `reclaimed`, `still holds a balance` or `failed: <why>` for each.

A transfer-only sweep that left public dust keeps the row `open`: Token-2022 will not close an account with a public balance (verification: V4), so its rent stays locked until that balance is gone, and no `scope` command removes it.
