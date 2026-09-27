# Conventions for AI sessions

SCOPE: a confidential payout rail on Solana (Token-2022 confidential balances, optional stealth one-time accounts, payer visible, no pool). Layout and commands: README.md. Owners, phases and open questions: `docs/plan.md`.

- Stack is fixed: one Pinocchio program, one Rust CLI. No Anchor, no TypeScript.
- `docs/brief.md` is canonical for scope, `docs/design.md` for how, `docs/client.md` for the off-chain side. Other docs derive from them; fix upstream first.
- `docs/verification.md` is the evidence file. Every load-bearing claim in a doc traces to a row there or to a test in this repo; anything else is marked [unverified]. A new claim gets a new row with a primary source: a file and line in a named crate version or commit, an RPC read with its date, or a test.
- Docs describe the present; `docs/decisions.md` holds the why and the history. A change that decides something adds a dated entry.
- Every doc in `docs/`: front-matter `status` (todo, draft, decided or verified) and `last_verified`, then a two-line TL;DR. Under about 1,500 words of prose.
- Committed text is human voice: no em dashes, no AI-tell words, no emoji. Nothing about how a doc was produced.
- Terms: "payer" and "recipient"; "sender" only when quoting a source or a standard.
- Open questions stay open in `docs/plan.md` with an owner and a recommendation; do not resolve them silently.
- The repo is public: nothing from private conversations, no remarks about people.
- Dependencies: no version younger than 7 days. Until stable cargo ships `min-publish-age` (Rust 1.100), resolve through nightly with the gate in the environment:
  `CARGO_UNSTABLE_MIN_PUBLISH_AGE=true CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE="7 days" cargo +nightly update` (same for `add` and `generate-lockfile`). Build and test on stable.
- Always pass `--locked` to cargo commands that build or test.
- Every new crate gets `license = "MIT OR Apache-2.0"` (through `license.workspace = true`). No per-file license headers.
