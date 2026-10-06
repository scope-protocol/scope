# SCOPE

Stealth Confidential Payments Engine: a confidential payout rail on Solana. A visible payer pays many recipients with encrypted amounts, and recipients who want it get a fresh, unlinkable account per payment that the payer sets up alone. The money stays an ordinary Token-2022 token, and an auditor can still read amounts.

It joins two existing pieces that were never combined, stealth addresses and Token-2022 confidential balances, with no pool, no relayer, no MPC and no enclave. One Pinocchio program and one Rust CLI; a stealth payment is one transaction per side, and our program is never in the funds path. Program id: `EwbfwDdaRdxzF6wJFBKQmqcGoh93wNFL7FMo31eK9V2H`.

## Status

- Design decided ([docs/design.md](docs/design.md)).
- Program with `announce` and `reclaim` built and tested in LiteSVM: every check has an attack test that trips it, and CI holds each instruction to a CU ceiling (announce 6,373 CU, reclaim 3,256).
- Spike S3 green end to end: payer setup, handover and payment in one transaction, the recipient's sweep and rent refund in another.
- Spike S1 green on Surfpool; the devnet run is pending.
- `scope pay` pays plain confidential recipients, resumably; stealth rows are next, on the `ct_ikm` export. Phases and gates: [docs/plan.md](docs/plan.md).
- `scope register`, `scan`, `sweep`, and `export-sweep-key` support recipient backups, authenticated discovery, durable recovery, and spendable confidential destinations. The flow is tested in LiteSVM; live-cluster validation remains pending. Usage: [docs/recipient.md](docs/recipient.md).

## Layout

One cargo workspace.

| Path | Package | What |
|---|---|---|
| `programs/scope` | `scope-program` | The Pinocchio program: `announce`, `reclaim`. Its LiteSVM tests and the S1 and S3 spikes live in `tests/it/` |
| `crates/interface` | `scope-interface` | `no_std`, no dependencies: program id, announcement layout, instruction data, seeds, error codes, a read-only view of Token-2022 token accounts. Shared by the program and the client |
| `crates/client` | `scope-client` | Address derivation, instruction and v1 transaction builders, payer engine and journal, recipient scan and sweep, RPC and LiteSVM (feature `litesvm`) backends, and spike binaries in `examples/`. Receipts remain planned |
| `crates/stealth-keygen` | `stealth-keygen` | Recipient keys, HKDF stealth derivation, raw-scalar signing, and protected account-scoped `ct_ikm`. Off-chain |
| `cli` | `scope-cli`, binary `scope` | Argument parsing and output over `crates/client`. Plain `pay`, recipient `register`, `scan`, `sweep` and `export-sweep-key` work; disclose, verify and bench remain stubs |
| `docs/` | | Brief, design, client, crypto, privacy, plan, decisions, verification. Start at [docs/README.md](docs/README.md) |

The program and the client depend on `crates/interface`, which depends on nothing. `crates/stealth-keygen` derives stealth keys and account-scoped `ct_ikm`. `scope-client::confidential` converts that material into ElGamal and symmetric keys with the workspace ZK SDK. Q14 implementation is complete; external derivation review remains Q1. Payer-engine stealth rows and receipts remain planned.

## Build and test

The host toolchain is pinned in `rust-toolchain.toml`; the program builds with Solana CLI 3.1.10 (platform-tools v1.52, rustc 1.89, which is also the workspace `rust-version`).

```sh
cargo fmt --all --check
cargo lint                                   # clippy, all targets, warnings are errors
cargo build-sbf --manifest-path programs/scope/Cargo.toml -- --locked
cargo test --workspace --locked
cargo deny check                             # licenses, advisories, sources
```

Unit tests sit next to the code. Program tests load `target/deploy/scope_program.so`, so run `cargo build-sbf` first; the test kit stops with the build command if the file is missing or older than the program sources. Engine tests, resume after a kill included, are in `crates/client/tests/`.

CI runs the same commands on every pull request. The program id in `crates/interface/src/lib.rs` belongs to a keypair kept outside the repo by the program owner; deploy with `solana program deploy --program-id <that keypair> target/deploy/scope_program.so`. The keypair `cargo build-sbf` writes to `target/deploy/` is not used. Keypair files are ignored by git.

## Working in the repo

- Who owns what, and who reviews it: the owners table in [docs/plan.md](docs/plan.md).
- One short-lived branch per task, named `<area>/<topic>` (for example `program/announce`, `client/scan`, `audit/receipts`), opened as a pull request to `main`.
- Merge when CI is green and the reviewer from the owners table approves; squash merge, so `main` reads one commit per change.
- A change to `crates/interface` or to the `ct_ikm` export of `crates/stealth-keygen` needs approval from every area that uses it.
- A change that decides something gets an entry in [docs/decisions.md](docs/decisions.md) in the same pull request.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you state otherwise, any contribution you intentionally submit for inclusion in this
work, as defined in the Apache-2.0 license, is dual licensed as above, with no additional
terms or conditions.
