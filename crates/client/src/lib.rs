//! Off-chain side of SCOPE (docs/client.md): address derivation, instruction and
//! transaction builders, and later the payer engine, scan, sweep and receipts.

#![forbid(unsafe_code)]

pub mod address;
pub mod chain;
pub mod confidential;
pub mod fees;
pub mod input;
pub mod ix;
pub mod journal;
pub mod pay;
pub mod scan;
pub mod signer;
#[cfg(feature = "litesvm")]
pub mod testkit;
pub mod tx;
