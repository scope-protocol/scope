//! Off-chain side of SCOPE (docs/payer.md, docs/recipient.md): address derivation, instruction and
//! transaction builders, and later the payer engine, scan, sweep and receipts.

#![forbid(unsafe_code)]

pub mod address;
pub mod chain;
pub mod confidential;
pub mod fees;
pub mod history;
pub mod input;
pub mod ix;
pub mod journal;
pub mod mint_policy;
pub mod pay;
pub mod proofs;
pub mod receipt;
pub mod registry;
pub mod run_secret;
pub mod scan;
pub mod signer;
pub mod sweep;
#[cfg(feature = "litesvm")]
pub mod testkit;
pub mod tx;
