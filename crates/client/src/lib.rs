//! Off-chain side of SCOPE (docs/client.md): address derivation, instruction and
//! transaction builders, and later the payer engine, scan, sweep and receipts.

#![forbid(unsafe_code)]

pub mod address;
pub mod confidential;
pub mod ix;
#[cfg(feature = "litesvm")]
pub mod testkit;
pub mod tx;
