/// Announcement PDA: `[ANNOUNCEMENT_SEED, token_account]`.
pub const ANNOUNCEMENT_SEED: &[u8] = b"ann";

/// Domain of the digest behind the token account's `create_with_seed` seed.
pub const TOKEN_ACCOUNT_SEED_DOMAIN: &[u8] = b"stealth-ta/v1";

/// SHA-256 input for the token account seed: domain and R. Each side hashes with
/// its own SHA-256 (the syscall on chain, sha2 off chain).
pub fn token_account_seed_parts(ephemeral: &[u8; 32]) -> [&[u8]; 2] {
    [TOKEN_ACCOUNT_SEED_DOMAIN, ephemeral]
}

/// The `create_with_seed` seed: lowercase hex of the digest's first 16 bytes, 32
/// ASCII characters, the System program's seed limit.
pub fn token_account_seed(digest: &[u8; 32]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 32];
    for (i, byte) in digest[..16].iter().enumerate() {
        out[2 * i] = HEX[(byte >> 4) as usize];
        out[2 * i + 1] = HEX[(byte & 0x0f) as usize];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_lowercase_hex_of_first_16_bytes() {
        let mut digest = [0u8; 32];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = i as u8;
        }
        digest[1] = 0xab;
        assert_eq!(
            &token_account_seed(&digest),
            b"00ab02030405060708090a0b0c0d0e0f"
        );
    }

    #[test]
    fn seed_parts_are_domain_and_r() {
        let r = [5u8; 32];
        let parts = token_account_seed_parts(&r);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], b"stealth-ta/v1");
        assert_eq!(parts[1], &r[..]);
    }
}
