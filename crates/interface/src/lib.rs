//! The contract between the program and the client: account layouts, instruction
//! data, seeds, errors and a reader for Token-2022 token accounts (docs/protocol.md).
//!
//! `no_std` with no dependencies, so every side builds it without version conflicts.

#![no_std]
#![forbid(unsafe_code)]

pub mod error;
pub mod instruction;
pub mod seeds;
pub mod state;
pub mod token_account;

pub use error::ScopeError;

/// [`ID`] in base58, checked against the bytes by a client test.
pub const ID_BASE58: &str = "SCoPEvf7cwXjgzEQqqrJXN4gwU6TT81v1LC8vCZE5hT";

/// The SCOPE program id; the keypair lives outside the repo.
pub const ID: [u8; 32] = [
    6, 116, 220, 185, 149, 45, 95, 130, 3, 196, 113, 20, 177, 170, 63, 181, 225, 28, 156, 211, 11,
    57, 139, 196, 48, 56, 220, 227, 64, 105, 151, 98,
];

/// Token-2022, `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.
pub const TOKEN_2022_ID: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
];

/// The System program.
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0; 32];
