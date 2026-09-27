//! The contract between the program and the client: account layouts, instruction
//! data, seeds, errors and a reader for Token-2022 token accounts (docs/design.md).
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

/// The SCOPE program id; the keypair lives outside the repo.
pub const ID: [u8; 32] = [
    207, 36, 127, 38, 185, 19, 42, 85, 197, 222, 9, 96, 253, 80, 33, 200, 92, 157, 183, 242, 117,
    31, 69, 236, 156, 70, 78, 208, 242, 139, 15, 186,
];

/// [`ID`] in base58, checked against the bytes by a client test.
pub const ID_BASE58: &str = "EwbfwDdaRdxzF6wJFBKQmqcGoh93wNFL7FMo31eK9V2H";

/// Token-2022, `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.
pub const TOKEN_2022_ID: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
];

/// The System program.
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0; 32];
