//! S7: a registered B_spend must be the canonical encoding of a prime-order point, the
//! on-chain twin of the client's check (docs/verification.md, V42). The curve syscalls
//! multiply only by canonical scalars, so the group order L itself is out of reach:
//! with Q = (L-1)·P, a prime-order P gives Q = -P, so Q + P is the identity, Q is not,
//! and -Q re-encoded is P. Any torsion part makes Q + P nonzero, since L is odd and
//! torsion orders divide 8. Non-canonical encodings exist only for y < 19 (as y + p) or
//! x = 0, and none of those points has prime order, so the rules above already refuse
//! them; the re-encoding check is a backstop.

/// The identity's canonical encoding (y = 1).
#[cfg(target_os = "solana")]
const IDENTITY: [u8; 32] = {
    let mut id = [0u8; 32];
    id[0] = 1;
    id
};

/// L - 1, little-endian, with L = 2^252 + 27742317777372353535851937790883648493.
#[cfg(target_os = "solana")]
const L_MINUS_ONE: [u8; 32] = [
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

#[cfg(target_os = "solana")]
#[allow(unsafe_code)]
pub(crate) fn prime_order(point: &[u8; 32]) -> bool {
    use pinocchio::syscalls::sol_curve_group_op;
    // solana-curve25519 4.0.1 `curve_syscall_traits.rs` 80-85.
    const EDWARDS: u64 = 0;
    const ADD: u64 = 0;
    const SUB: u64 = 1;
    const MUL: u64 = 2;
    let op = |op: u64, left: &[u8; 32], right: &[u8; 32]| {
        let mut out = [0u8; 32];
        // SAFETY: both inputs and the output are 32-byte arrays the syscall reads or
        // writes in full; it returns nonzero, writing nothing, on invalid input.
        let failed = unsafe {
            sol_curve_group_op(EDWARDS, op, left.as_ptr(), right.as_ptr(), out.as_mut_ptr())
        };
        (failed == 0).then_some(out)
    };
    let Some(q) = op(MUL, &L_MINUS_ONE, point) else {
        return false;
    };
    let (Some(sum), Some(negated)) = (op(ADD, &q, point), op(SUB, &IDENTITY, &q)) else {
        return false;
    };
    sum == IDENTITY && q != IDENTITY && negated == *point
}

/// Host builds, for unit tests of the same rule; the program runs the syscall version.
#[cfg(not(target_os = "solana"))]
pub(crate) fn prime_order(point: &[u8; 32]) -> bool {
    use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
    CompressedEdwardsY(*point).decompress().is_some_and(|p| {
        p.is_torsion_free() && !p.is_identity() && p.compress().to_bytes() == *point
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as B, scalar::Scalar};

    /// y = 0 encodes (sqrt(-1), 0), a point of order 4.
    const SMALL_ORDER: [u8; 32] = [0; 32];

    #[test]
    fn accepts_prime_order_points_only() {
        let valid = (B * Scalar::from(7u64)).compress().to_bytes();
        assert!(prime_order(&valid));
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!prime_order(&identity), "identity");
        assert!(!prime_order(&SMALL_ORDER), "small order");
        let small = curve25519_dalek::edwards::CompressedEdwardsY(SMALL_ORDER)
            .decompress()
            .expect("on curve");
        let mixed = (B * Scalar::from(7u64) + small).compress().to_bytes();
        assert!(!prime_order(&mixed), "mixed order");
        // y = p + 1 encodes the identity non-canonically.
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xee;
        noncanonical[31] = 0x7f;
        assert!(!prime_order(&noncanonical), "non-canonical");
        let off_curve = (2u8..)
            .map(|y| {
                let mut b = [0u8; 32];
                b[0] = y;
                b
            })
            .find(|b| {
                curve25519_dalek::edwards::CompressedEdwardsY(*b)
                    .decompress()
                    .is_none()
            })
            .expect("some small y is off the curve");
        assert!(!prime_order(&off_curve), "not on the curve");
    }

    #[test]
    fn rejects_every_torsion_point_alone_and_mixed() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        for t in &EIGHT_TORSION[1..] {
            assert!(!prime_order(&t.compress().to_bytes()));
            assert!(!prime_order(
                &(B * Scalar::from(7u64) + t).compress().to_bytes()
            ));
        }
    }

    /// Why the re-encoding check is a backstop: no point a non-canonical encoding can
    /// name has prime order.
    #[test]
    fn no_point_with_a_non_canonical_encoding_has_prime_order() {
        use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
        for y in 0u8..19 {
            for sign in [0, 0x80] {
                let mut b = [0u8; 32];
                b[0] = y;
                b[31] = sign;
                if let Some(p) = CompressedEdwardsY(b).decompress() {
                    assert!(!p.is_torsion_free() || p.is_identity(), "y = {y}");
                }
            }
        }
    }
}
