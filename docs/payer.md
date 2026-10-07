---
status: decided
last_verified: 2026-10-07
---

# Paying with `scope pay`

TL;DR: for whoever runs payouts. After reading you can write an input file, pay a batch of plain and stealth rows, recover from a crash, price the run, and get stealth-row rent back.
Each row is paid at most once; the run journal plus the payer key are all you need to resume, check status or prove an amount later ([audit.md](audit.md)).

## Before you start

| You need | Why |
|---|---|
| A cluster with Token-2022 confidential transfers enabled | every row is a confidential transfer |
| `scope-program` deployed on that cluster, for stealth rows only | stealth rows call `announce`; plain rows use Token-2022 alone. Where it is deployed: [plan.md](plan.md) |
| A source: your confidential Token-2022 account on the mint, owned by `--keypair`, with its pending balance applied | the engine derives the source's ElGamal and AE keys from `--keypair` the same way spl-token-cli 5.6.1 does (verification: V50) |
| SOL in the payer wallet | per stealth row 8,630,800 lamports (about 0.0086 SOL) plus fees: 4,008,120 of rent that comes back and 4,622,680 that funds the recipient's sweep. Twenty stealth rows need about 0.173 SOL. Breakdown: [How much does a stealth row cost the payer?](#how-much-does-a-stealth-row-cost-the-payer) |

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

```sh
scope pay --input payroll.csv --mint <mint> --source <your-confidential-token-account> \
  --keypair ~/.config/solana/id.json --url <rpc-url>
```

Progress goes to stderr, the result to stdout; rows go out in random order:

```text
run 3f9c0a1b2d4e5f60: 2 rows                          (stderr)
row 1: <one-time token account> paid, <signature>     (stderr)
row 0: <recipient-token-account> paid, <signature>    (stderr)
run 3f9c0a1b2d4e5f60 done                             (stderr)
run 3f9c0a1b2d4e5f60: 2 rows paid
1	<one-time token account>	<signature>
0	<recipient-token-account>	<signature>
```

Each stdout line is the row, the account paid and the payment signature. Keep the run id; a stealth recipient needs its signature for a receipt ([audit.md](audit.md)).

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--input <file>` | required for a new run | `recipient,amount` rows |
| `--mint <address>` | required for a new run | Token-2022 mint with confidential transfers |
| `--source <address>` | required for a new run | your confidential token account, owned by `--keypair` |
| `--keypair <file>` | `~/.config/solana/id.json` | owns the source, signs and pays every fee |
| `--url <rpc>` | `http://127.0.0.1:8899` | RPC node |
| `--runs <dir>` | `runs` | one journal directory per run |
| `--max-price <n>` | `1000000` | priority price cap, micro-lamports per CU |
| `--again` | off | pay an input file an earlier run already paid |
| `--resume <run_id>` | | continue an interrupted run |
| `--status <run_id>` | | show each stealth row's state |
| `--reclaim` | off | with `--status`: reclaim rent of swept rows |

`--input`, `--mint` and `--source` conflict with `--resume` and `--status`, and `--resume` conflicts with `--status`.

## What can a row be?

One `recipient,amount` per line. The first line that is not blank or a comment is a header if it starts with `recipient`; blank lines are skipped and `#` starts a comment anywhere on a line.

- **Recipient.** A plain row names the recipient's own configured confidential token account. A stealth row names a `scope:` meta-address; the parser checks its checksum, version and keys before anything is derived (verification: V62). A payer can look up meta-addresses that wallets published with `scope lookup <wallet>... --url <rpc>`, which prints `<wallet>\t<meta-address>` or `<wallet>\tnot published`; it fetches every registry entry in one query and picks locally (verification: V81).
- **Amount.** Token units, a plain decimal with at most the mint's decimals: no sign, no exponent, not zero. The most one row can move is 2^48 - 1 base units, the limit of one confidential transfer; 281474976.710655 is the largest amount on a 6-decimal mint (verification: V84).
- **Row number.** Rows are numbered from 0 in file order, counting only rows, not the header, comments or blank lines. `--status`, the output and `disclose --row` use this number.

The rows together must fit the source's available balance (verification: V48).

## Which mints work?

| Mint property | Plain row | Stealth row |
|---|---|---|
| Token-2022 with the confidential transfer extension | required | required |
| Auditor key | works, proofs include it (V48) | works, proofs include it |
| New confidential accounts need the issuer's approval | works if the recipient's account is already approved | refused before anything is sent (V72, V76) |
| New accounts frozen by default | works if the recipient's account is not frozen | refused [unverified: no test] |
| Non-transferable, transfer-fee or transfer-hook extension | refused [unverified: no test] | refused [unverified: no test] |

Stealth rows need a mint that approves new confidential accounts itself, because `announce` does not check approval (verification: V72). PYUSD and USDG require approval of every new confidential account, so they take plain rows only; USDC is legacy SPL Token and takes neither (verification: V14). Mint policy binds rows still to pay: a later policy change does not stop `--resume` from settling rows already paid, nor `disclose` (verification: V84).

## What happens to each row?

**Before anything is sent**, the run checks the mint, every row, the source (owner, mint, ElGamal key derived from `--keypair`, balance hint against the ciphertext) and every plain recipient (Token-2022, same mint, not frozen, approved, confidential credits on, pending credit counter below its maximum). Any failure stops it with no journal created (verification: V48, V50).

**Per row**, in the random send order:

1. Build the transfer on the source's current ciphertext. A stealth row adds the one-time account's setup, handover, `announce` and P's funding in the same transaction ([protocol.md](protocol.md)).
2. Simulate it. A failed simulation stops the run, nothing sent.
3. Append the attempt, with the signed transaction, to the journal and fsync it.
4. Send, and resend the same signed transaction, until the source shows it landed or the attempt is provably dead.
5. Record `landed` at confirmed, then move on.

Then the run waits for the finalized source to show the last row's ciphertext and writes `done`.

**At most once.** Token-2022 applies a transfer only on the exact source ciphertext its equality proof was built on, and every attempt for a row is built on the same ciphertext, so at most one lands (verification: V8). The source's available ciphertext is the oracle: equal to the attempt's post-transfer value (verification: V51) means it landed, equal to the pre-transfer value means nothing did, anything else halts. A row is rebuilt only once the finalized block height passes the attempt's last valid block height and the finalized source still shows the pre-transfer value. Do not spend from the source with other software during a run: the run halts with "source changed outside this run" (verification: V48).

If a stealth row's attempt expires and someone then sends lamports to its now-public one-time address, the rebuild creates the account with a top-up transfer, AllocateWithSeed and AssignWithSeed; that fallback is tested (verification: V76); an address that already holds an account halts the run [unverified].

## What if the run crashes?

Rerun with the same run id:

```sh
scope pay --resume 3f9c0a1b2d4e5f60 --keypair ~/.config/solana/id.json --url <rpc-url>
```

Resume reads the journal, then the chain: an open attempt that landed is recorded, one still alive is driven on, one that died is rebuilt. A 20-row mixed run killed at each of sixty points converged every time, each row paid once (verification: V75, V83). It halts if the chain is not where the last landed row left it.

The journal is `runs/<run_id>/journal.jsonl`, mode 0600, beside `input.csv`, the input copy, also 0600. It holds a header (input hash, mint, source, payer, send order, `derived_openings`), then per row an attempt (signature, last valid block height, both ciphertexts, the signed transaction), a `landed` record, and finally `done`. No secret and no plaintext amount; amounts live in the input copy (verification: V48). One writer holds its lock. A line a crash cut short held an attempt never sent; it is dropped before the next append (verification: V84).

**Duplicate input.** `pay` refuses an input whose hash matches an earlier run under `--runs`, naming that run, and also refuses when an earlier journal cannot be read, since it may be the same input. Pass `--again` to pay the file twice on purpose (verification: V48, V84).

Back up the `runs/` directory: resume, status and `disclose` need it.

## Run secret

Nothing secret is stored for a run. Each stealth row's ephemeral key and every row's amount openings come from a run secret that the payer keypair alone rebuilds, because it is derived from a deterministic Ed25519 signature (verification: V75; formula in [crypto.md](crypto.md)). For the operator this means: back up only the payer key and the `runs/` directory. Do not let that key sign messages for other software, such as a browser wallet: anything that obtains its signature over `scope-run-secret/v1` and a run id learns which one-time accounts that run paid and how much.

## How much does a stealth row cost the payer?

| Item | Lamports | Comes back? |
|---|---|---|
| Rent of the one-time token account | rent(account size), 3,012,440 for a mint with no account extensions | yes, to the payer, when it is reclaimed |
| Rent of the 68-byte announcement | 995,680 | yes, with the token account |
| P's funding, `fees::sweep_funding` | rent(D) + rent(0) + 3 x (10,000 + 310,000) | no, it pays the recipient's sweep |
| The payment's own fee | 5,000 + priority price x 295,000 / 10^6 | no |

Rents are read from the node at run time; the numbers are today's (verification: V23, V11). A full sweep reclaims both rents to the payer (verification: V77).

P's funding is what the sweep needs for one attempt at the 1,000,000 micro-lamport cap: D's rent (D is the same size as the one-time account), two signatures at 5,000 lamports, the priority fee at the sweep's 310,000-CU limit, and the rent reserve P keeps; plus one more attempt's fee for each of the sweep's two rebuilds, because an attempt that lands and fails is still charged. The cap, not today's price, because the recipient may sweep weeks later. P holding the requirement sweeps at the cap and one lamport less is refused (verification: V74). For a mint with no account extensions that is 3,012,440 + 650,240 + 960,000 = 4,622,680 lamports. What P does not spend goes to the recipient. Byte and CU figures per transaction are in [protocol.md](protocol.md).

## How are fees priced?

Each new attempt samples the latest confirmed block: the per-CU price every landed non-vote transaction paid (the ComputeBudget price for legacy and v0, header `priority_fee` over its compute-unit limit for v1), and takes the nearest-rank p75; an empty block prices at 0 (tests `percentile_is_nearest_rank`, `priority_price_sorts_samples_and_enforces_the_cap` in `crates/client/src/fees.rs`). `getRecentPrioritizationFees` is not used: unfiltered it returns each slot's minimum and reads near zero (verification: V39). Mainnet samples put p75 at 8,001 and 14,000 micro-lamports (verification: V40, V52).

Above `--max-price` the run stops with "priority fee ... is above the cap ...; resume later". Resends keep their signed fee. The fee goes in the v1 header as total lamports, price times the shape's compute-unit limit (verification: V20), so each shape has its own limit about 15% above its measurement (verification: V73):

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
row	token_account	announcement	state
1	<one-time token account>	<announcement>	open
```

It lists stealth rows only and works while the run is live.

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

`--reclaim` calls `reclaim` for every `swept` row at the sampled price under `--max-price` and a 3,800-CU limit, then prints the new status. A full sweep already reclaims, so this is for a sweep that took its transfer-only fallback. Token-2022 refuses to close an account with any balance, so reclaim cannot touch funds (verification: V4). After three expired attempts on one row it stops with "reclaim did not land in 3 attempts; try again later"; rerunning is safe and repeats nothing already reclaimed (verification: V78).

A transfer-only sweep that left public dust in the account keeps the row `open`, not `swept`: Token-2022 will not close an account holding a public balance (verification: V4), so `--reclaim` skips it and its rent stays locked until that balance is gone. No `scope` command removes it.
