# SCOPE

Stealth Confidential Payments Engine: a confidential payout rail on Solana. A visible payer pays many recipients with encrypted amounts, and recipients who want it get a fresh, unlinkable account per payment that the payer sets up alone. The money stays an ordinary Token-2022 token, there is no pool, relayer, MPC or enclave, and the payer or recipient can prove any amount to an auditor. One Pinocchio program and one Rust CLI; a stealth payment is one transaction per side, and the program is never in the funds path. Program id: `EwbfwDdaRdxzF6wJFBKQmqcGoh93wNFL7FMo31eK9V2H`.

## Status

What is built, what is next and what is open: [docs/plan.md](docs/plan.md).

## Quick look

A recipient who wants one-time accounts creates a local key backup and shares the meta-address it prints (or publishes it in the on-chain registry):

```sh
scope register                          # writes ~/.config/scope/recipient.key, prints scope:...
scope publish --url <RPC>               # optional: registry entry under ~/.config/solana/id.json
```

The payer writes one `recipient,amount` row per payment, amounts in token units. A row is plain (a configured confidential token account) or stealth (a `scope:` meta-address):

```text
<confidential token account>,1250.00
scope:<meta-address>,800
```

```sh
scope pay --input payroll.csv --mint <MINT> --source <PAYER_CONFIDENTIAL_ACCOUNT> --url <RPC>
# run <run_id>: 2 rows paid
# 0	<recipient>	<signature>
scope pay --resume <run_id> --url <RPC>        # after a crash
scope pay --status <run_id> --url <RPC>        # unpaid, unresolved, open, swept, reclaimed
```

The recipient finds its payments and moves each into a fresh account of its own:

```sh
scope scan --url <RPC>
# announcement  token_account  payer  mint  amount_base_units  public_amount_base_units  ephemeral
scope sweep --announcement <ANNOUNCEMENT> --url <RPC>
# swept: <amount> base units to <destination>
```

Either side proves an amount with `scope disclose`, and anyone checks it with `scope verify <receipt>`. Every flag: [payer.md](docs/payer.md), [recipient.md](docs/recipient.md), [audit.md](docs/audit.md). `scope bench` is a stub.

## Layout

One cargo workspace.

| Path | Package | What |
|---|---|---|
| `programs/scope` | `scope-program` | The Pinocchio program: `announce`, `reclaim`, and the registry's `register` and `deregister`. Its LiteSVM tests and the S1 and S3 spikes live in `tests/it/` |
| `crates/interface` | `scope-interface` | `no_std`, no dependencies: program id, announcement and registry entry layouts, instruction data, seeds, error codes, a read-only view of Token-2022 token accounts. Shared by the program and the client |
| `crates/client` | `scope-client` | Address derivation, instruction and v1 transaction builders, payer engine and journal, recipient scan and sweep, receipts, registry lookup, RPC and LiteSVM (feature `litesvm`) backends, and spike binaries in `examples/` |
| `crates/stealth-keygen` | `stealth-keygen` | Recipient keys, HKDF stealth derivation, raw-scalar signing, and protected account-scoped `ct_ikm`. Off-chain |
| `cli` | `scope-cli`, binary `scope` | Argument parsing and output over `crates/client`: `register` (local recipient backup), `meta-address`, `pay`, `publish`, `lookup`, `scan`, `recover`, `sweep`, `export-sweep-key`, `disclose`, `verify`, and `bench` (a stub). Exit codes: 0 done, 1 refused before sending, 2 bad arguments, 3 transient (retry or resume), 4 stopped after sending (inspect, then resume) |
| `docs/` | | Start at [docs/README.md](docs/README.md) |

The program and the client depend on `crates/interface`, which depends on nothing. `scope-client::confidential` turns the `ct_ikm` from `crates/stealth-keygen` into ElGamal and symmetric keys with the workspace ZK SDK.

## Build and test

The host toolchain is pinned in `rust-toolchain.toml`; the program builds with Solana CLI 3.1.10 (platform-tools v1.52, rustc 1.89, which is also the workspace `rust-version`).

```sh
cargo fmt --all --check
cargo lint                                   # clippy, all targets, warnings are errors
cargo build-sbf --manifest-path programs/scope/Cargo.toml -- --locked
cargo test --workspace --locked
cargo deny check                             # licenses, advisories, sources
cargo test --locked --release -p scope-client --test pay chaos -- --ignored   # chaos harness, by hand
```

Program tests load `target/deploy/scope_program.so`, so run `cargo build-sbf` first; the test kit stops with the build command if the file is missing or older than the program sources. Unit tests sit next to the code, integration tests in `programs/scope/tests/` and `crates/client/tests/`; [docs/verification.md](docs/verification.md) maps each claim to its test. CI runs the same commands on every pull request, except the chaos harness.

**Stack.** Program: pinocchio 0.11.2 (`no_std`, `cpi` feature) and pinocchio-system 0.6.1. Off-chain Solana crates follow litesvm 0.16's line and move together: solana-address ~2.6.1, solana-instruction ~3.4.1, solana-message ~4.4.1, solana-transaction ~4.1.6, solana-keypair 3.1.2, solana-signer 3.0.1, solana-system-interface 3.2.0, solana-zk-sdk 7.0.1, spl-token-2022-interface 3.1.1, spl-token-confidential-transfer-proof-extraction and -generation 0.6.1, litesvm 0.16.0, solana-rpc-client 4.2.2. Exact pins are in the root `Cargo.toml`. zk-sdk is 7.0.1, not 8, because litesvm 0.16 and zk-sdk 8 cannot share a lockfile, and `derive_confidential_keys_from_ikm` is identical in both (verification: V28, V29). When litesvm moves to solana-address 2.7, the whole line moves at once.

**Deploying.** The program id in `crates/interface/src/lib.rs` belongs to a keypair kept outside the repo by the program owner; deploy with `solana program deploy --program-id <that keypair> target/deploy/scope_program.so`. The keypair `cargo build-sbf` writes to `target/deploy/` is not used. Keypair files are ignored by git.

## Working in the repo

- Who owns what, and who reviews it: the owners table in [docs/plan.md](docs/plan.md).
- One short-lived branch per task, named `<area>/<topic>` (for example `program/announce`, `client/scan`, `audit/receipts`), opened as a pull request to `main`.
- Merge when CI is green and the reviewer from the owners table approves; squash merge, so `main` reads one commit per change.
- A change to `crates/interface` or to the `ct_ikm` export of `crates/stealth-keygen` needs approval from every area that uses it.
- A change that decides something gets an entry in [docs/decisions.md](docs/decisions.md) in the same pull request.

## Docs

| Read | For |
|---|---|
| [overview.md](docs/overview.md) | what SCOPE guarantees and does not, cost per payment |
| [payer.md](docs/payer.md) | paying a run |
| [recipient.md](docs/recipient.md) | receiving, scanning, sweeping |
| [audit.md](docs/audit.md) | proving and checking an amount |
| [protocol.md](docs/protocol.md) | accounts, transactions, instructions |
| [crypto.md](docs/crypto.md) | key derivations |
| [privacy.md](docs/privacy.md) | who learns what |
| [plan.md](docs/plan.md) | status, next steps, open questions |
| [decisions.md](docs/decisions.md) | why |
| [verification.md](docs/verification.md) | evidence |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you state otherwise, any contribution you intentionally submit for inclusion in this
work, as defined in the Apache-2.0 license, is dual licensed as above, with no additional
terms or conditions.
