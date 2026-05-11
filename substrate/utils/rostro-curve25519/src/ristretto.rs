// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Witness-side Ristretto255 compress / decompress.
//!
//! Ristretto255 is a quotient group of Edwards25519 that gives the user
//! a prime-order group encoded as 32 bytes with **canonical, unique
//! encodings** — no cofactor issues, no malleability, no edge cases at
//! the identity. The OPRF protocol (`pop_design_section1c_oprf_nullifier.md`)
//! exchanges Ristretto-encoded points; the in-circuit point arithmetic
//! happens on Edwards25519's extended (X, Y, Z, T) coords, and the
//! Ristretto encoding/decoding is the boundary.
//!
//! The pure-Rust implementation here is the witness-side oracle. The
//! corresponding compress / decompress AIRs land in R3 / R4.
//!
//! ## References
//!
//! - Ristretto255 spec / formulas: <https://ristretto.group/formulas/>
//! - curve25519-dalek's `ristretto.rs` (used as the test oracle)
//!
//! Notation here matches the dalek implementation, which itself follows
//! the published formulas.

use crate::field::{
	add as field_add, is_canonical, is_negative, is_zero, limbs_to_bytes, mul as field_mul,
	neg as field_neg, sqrt_ratio_m1, square, sub as field_sub, FIELD_NUM_LIMBS, SQRT_M1_LIMBS,
};
use crate::point::{EdwardsPoint, ED25519_D_LIMBS};

/// `INVSQRT_A_MINUS_D = 1 / √(a - d) mod p` for Edwards25519
/// (`a = -1`, `d = -121665/121666 mod p`).
///
/// The Ristretto255 compress routine uses this as a constant
/// multiplicand on one branch. Self-tested in
/// `ristretto_tests::invsqrt_a_minus_d_self_check`, which (a) verifies
/// the algebraic identity `INVSQRT_A_MINUS_D² · (a - d) == 1` and
/// (b) re-derives the LSB-positive root via `sqrt_ratio_m1` and
/// compares limb-for-limb.
pub const INVSQRT_A_MINUS_D_LIMBS: [u32; FIELD_NUM_LIMBS] = [
	0x805D_40EA,
	0x99C8_FDAA,
	0x5A41_72BE,
	0x9D2F_1617,
	0xFE01_D840,
	0x16C2_7B91,
	0xCFAF_FCA2,
	0x786C_8905,
];

/// One in the field, as 8 u32 LE limbs.
fn one() -> [u32; FIELD_NUM_LIMBS] {
	let mut o = [0u32; FIELD_NUM_LIMBS];
	o[0] = 1;
	o
}

/// Conditionally select between `lhs` and `rhs`. Returns `rhs` if
/// `pick_rhs`, else `lhs`. (Witness-side only; constant-time is not
/// a requirement here — the AIR has its own selection constraint.)
fn cond_select(
	lhs: &[u32; FIELD_NUM_LIMBS],
	rhs: &[u32; FIELD_NUM_LIMBS],
	pick_rhs: bool,
) -> [u32; FIELD_NUM_LIMBS] {
	if pick_rhs {
		*rhs
	} else {
		*lhs
	}
}

/// Ristretto255 compress: Edwards extended point → 32-byte canonical
/// encoding.
///
/// `p` MUST be a valid Edwards25519 point in the Ristretto-image cofactor
/// subgroup (the standard basepoint and any of its multiples qualify;
/// hash-to-curve outputs qualify after the appropriate map). Inputs
/// outside the Ristretto group yield a defined-but-meaningless 32-byte
/// blob — soundness of the Ristretto layer requires upstream to
/// guarantee this.
pub fn compress(p: &EdwardsPoint) -> [u8; 32] {
	// u1 = (Z + Y)(Z - Y)
	let z_plus_y = field_add(&p.z, &p.y);
	let z_minus_y = field_sub(&p.z, &p.y);
	let u1 = field_mul(&z_plus_y, &z_minus_y);

	// u2 = X · Y
	let u2 = field_mul(&p.x, &p.y);

	// invsqrt = sqrt(1 / (u1 · u2²))
	let u2_sq = square(&u2);
	let u1_u2_sq = field_mul(&u1, &u2_sq);
	let (_ok, invsqrt) = sqrt_ratio_m1(&one(), &u1_u2_sq);

	// D1 = invsqrt · u1
	// D2 = invsqrt · u2
	let d1 = field_mul(&invsqrt, &u1);
	let d2 = field_mul(&invsqrt, &u2);

	// Zinv = D1 · D2 · T
	let d1_d2 = field_mul(&d1, &d2);
	let zinv = field_mul(&d1_d2, &p.t);

	// If T · Zinv is "negative" (LSB == 1):
	//   X' = Y · SQRT_M1
	//   Y' = X · SQRT_M1
	//   D' = D1 · INVSQRT_A_MINUS_D
	// else:
	//   X' = X
	//   Y' = Y
	//   D' = D2
	let t_zinv = field_mul(&p.t, &zinv);
	let rotate = is_negative(&t_zinv);

	let y_sqrt_m1 = field_mul(&p.y, &SQRT_M1_LIMBS);
	let x_sqrt_m1 = field_mul(&p.x, &SQRT_M1_LIMBS);
	let d1_invsqrt = field_mul(&d1, &INVSQRT_A_MINUS_D_LIMBS);

	let x_prime = cond_select(&p.x, &y_sqrt_m1, rotate);
	let mut y_prime = cond_select(&p.y, &x_sqrt_m1, rotate);
	let d_prime = cond_select(&d2, &d1_invsqrt, rotate);

	// If X' · Zinv is negative: Y' = -Y'
	let x_prime_zinv = field_mul(&x_prime, &zinv);
	if is_negative(&x_prime_zinv) {
		y_prime = field_neg(&y_prime);
	}

	// s = D' · (Z - Y'), negate if "negative" so output is LSB-positive.
	let z_minus_y_prime = field_sub(&p.z, &y_prime);
	let mut s = field_mul(&d_prime, &z_minus_y_prime);
	if is_negative(&s) {
		s = field_neg(&s);
	}

	limbs_to_bytes(&s)
}

/// Ristretto255 decompress: 32-byte canonical encoding → Edwards
/// extended point.
///
/// Returns `None` on any of the rejection conditions enumerated in
/// the Ristretto255 spec:
/// - input encodes a non-canonical field element (bytes value ≥ p)
/// - input encodes a "negative" field element (LSB == 1)
/// - the recovered curve equation has no rational point (discriminant
///   is a non-square)
/// - the recovered point fails one of the parity / torsion checks
///   (Y == 0 or T is "negative")
///
/// Otherwise returns `Some(P)` where `P` is on Edwards25519, with the
/// extended-coord invariant `T · Z == X · Y` and the Ristretto-image
/// torsion checks satisfied.
pub fn decompress(s_bytes: &[u8; 32]) -> Option<EdwardsPoint> {
	use crate::field::bytes_to_limbs;

	let s = bytes_to_limbs(s_bytes);
	// Reject non-canonical inputs (value ≥ p) and "negative" encodings.
	if !is_canonical(&s) {
		return None;
	}
	if is_negative(&s) {
		return None;
	}

	let ss = square(&s);
	let u1 = field_sub(&one(), &ss); // 1 - s²
	let u2 = field_add(&one(), &ss); // 1 + s²
	let u2_sq = square(&u2);

	// v = -d · u1² - u2²
	let u1_sq = square(&u1);
	let d_u1_sq = field_mul(&ED25519_D_LIMBS, &u1_sq);
	let neg_d_u1_sq = field_neg(&d_u1_sq);
	let v = field_sub(&neg_d_u1_sq, &u2_sq);

	// I = sqrt(1 / (v · u2²)). Reject if non-square.
	let v_u2_sq = field_mul(&v, &u2_sq);
	let (was_square, big_i) = sqrt_ratio_m1(&one(), &v_u2_sq);
	if !was_square {
		return None;
	}

	// Dx = I · u2
	// Dy = I · Dx · v
	let dx = field_mul(&big_i, &u2);
	let dx_v = field_mul(&dx, &v);
	let dy = field_mul(&big_i, &dx_v);

	// X = 2 · s · Dx, with potential sign flip if X is negative
	let two_s = field_add(&s, &s);
	let mut x = field_mul(&two_s, &dx);
	if is_negative(&x) {
		x = field_neg(&x);
	}

	// Y = u1 · Dy
	let y = field_mul(&u1, &dy);

	// T = X · Y. Reject if T is "negative" or Y is zero.
	let t = field_mul(&x, &y);
	if is_negative(&t) || is_zero(&y) {
		return None;
	}

	// Z = 1 in affine recovery (extended-coord invariant T = X·Y/Z holds
	// with Z = 1 since T was just computed as X·Y).
	let z = one();
	Some(EdwardsPoint { x, y, z, t })
}
