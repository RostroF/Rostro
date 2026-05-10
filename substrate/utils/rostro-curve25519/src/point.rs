// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Witness-side Edwards25519 point arithmetic.
//!
//! Pure-Rust pencil-and-paper implementation of point addition and
//! doubling on the twisted Edwards curve `-X² + Y² = Z² + d·T²` (the
//! Edwards form of Curve25519). Uses extended (X, Y, Z, T) coordinates
//! where the curve invariant `T·Z == X·Y` holds for every valid point.
//!
//! ## What this module provides
//!
//! - [`EdwardsPoint`] struct with extended coordinates (each field is
//!   8 u32 limbs in canonical form mod p)
//! - [`add`] — point addition per Hisil-Wong-Carter-Dawson (HWCD)
//!   2008 formula
//! - [`double`] — point doubling per HWCD doubling formula
//! - [`neutral`] — the identity element `(0, 1, 1, 0)`
//! - [`is_on_curve`] — verify a point satisfies the curve equation
//! - [`ED25519_D_LIMBS`], [`ED25519_2D_LIMBS`] — twisted Edwards `d`
//!   parameter and its precomputed double
//!
//! ## Per design memo `pop_edwards25519_air_design.md`
//!
//! This is **P1**: witness scaffolding only. The AIR-side
//! [`PointAddAir`] / [`PointDoubleAir`] land in subsequent commits
//! (P3, P4) and consume field-op services via the
//! `rostro-field-{mul,add,sub}` lookup buses.
//!
//! Cross-checked against `curve25519-dalek::edwards::EdwardsPoint` in
//! `point_oracle_tests`. dalek's `EdwardsPoint` IS public (unlike
//! `FieldElement`), so it's the authoritative oracle.

use crate::field::{add as field_add, mul as field_mul, neg as field_neg, sub as field_sub, FIELD_NUM_LIMBS};

/// Twisted Edwards `d` parameter for Edwards25519:
/// `d = -121665 / 121666 mod p`.
///
/// RFC 7748 § 4.1 specifies Curve25519's birationally-equivalent
/// Edwards form with this `d`. The hex encoding (LE bytes) is
/// `52036cee2b6ffe73 8cc740797779e898 00700a4d4141d8ab 75eb4dca135978a3`.
pub const ED25519_D_LIMBS: [u32; FIELD_NUM_LIMBS] = [
	0x135978a3, 0x75eb4dca, 0x4141d8ab, 0x00700a4d, 0x7779e898, 0x8cc74079, 0x2b6ffe73,
	0x52036cee,
];

/// `2 · d mod p`, precomputed because the point-add formula uses it as
/// a constant multiplicand for `T1 · 2d · T2`.
///
/// = `2 * ED25519_D mod p`. Hex (LE bytes):
/// `a40f57b2 56dffce7 8283b15b 00e01415 ef33f730 19899810 56dffce7 2a06d9dc`
///
/// Computed at compile time from `field::add(ED25519_D, ED25519_D)`.
/// Pinned here as a constant so audits can verify by inspection.
pub const ED25519_2D_LIMBS: [u32; FIELD_NUM_LIMBS] = [
	0x26b2f159, 0xebd69b94, 0x8283b156, 0x00e0149a, 0xeef3d130, 0x198e80f2, 0x56dffce7,
	0x2406d9dc,
];

/// A point on Edwards25519 in extended coordinates `(X, Y, Z, T)` with
/// the invariant `T * Z == X * Y` (mod p). All coordinates are
/// canonical field elements (< p), represented as 8 u32 LE limbs each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdwardsPoint {
	pub x: [u32; FIELD_NUM_LIMBS],
	pub y: [u32; FIELD_NUM_LIMBS],
	pub z: [u32; FIELD_NUM_LIMBS],
	pub t: [u32; FIELD_NUM_LIMBS],
}

/// The identity (neutral) element of Edwards25519: `(0, 1, 1, 0)`.
///
/// Satisfies `T·Z = 0·1 = 0 = X·Y = 0·1`. The standard formulas for
/// point add and double handle this without special-casing — no
/// branch needed in the AIR.
pub fn neutral() -> EdwardsPoint {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	EdwardsPoint {
		x: [0u32; FIELD_NUM_LIMBS],
		y: one,
		z: one,
		t: [0u32; FIELD_NUM_LIMBS],
	}
}

/// Test whether a point's coordinates satisfy the curve equation
/// `-X² + Y² == Z² + d·T²` (or equivalently `-X²·Z² + Y²·Z² == Z⁴ +
/// d·T²·Z²`, which is the homogenized form).
///
/// In extended coords with `T·Z == X·Y`, the curve equation is:
/// `-X² + Y² == Z² + d·T²` after dehomogenization. Witness-side:
/// compute both sides via field_mul + field_add + field_sub and compare.
///
/// Used by tests + as a sanity-check anchor for the witness builder.
pub fn is_on_curve(p: &EdwardsPoint) -> bool {
	// First check the extended-coord invariant: T·Z == X·Y.
	if field_mul(&p.t, &p.z) != field_mul(&p.x, &p.y) {
		return false;
	}
	// Then check the curve equation: -X² + Y² == Z² + d·T².
	let x_sq = field_mul(&p.x, &p.x);
	let y_sq = field_mul(&p.y, &p.y);
	let z_sq = field_mul(&p.z, &p.z);
	let t_sq = field_mul(&p.t, &p.t);
	let d_t_sq = field_mul(&ED25519_D_LIMBS, &t_sq);
	let lhs = field_sub(&y_sq, &x_sq); // -X² + Y² == Y² - X²
	let rhs = field_add(&z_sq, &d_t_sq);
	lhs == rhs
}

/// Edwards25519 point addition in extended (X, Y, Z, T) coordinates.
///
/// Implements the HWCD 2008 unified formula:
/// ```text
///   A = (Y1 - X1) · (Y2 - X2)
///   B = (Y1 + X1) · (Y2 + X2)
///   C = T1 · 2d · T2
///   D = Z1 · 2 · Z2
///   E = B - A
///   F = D - C
///   G = D + C
///   H = B + A
///   X3 = E · F
///   Y3 = G · H
///   T3 = E · H
///   Z3 = F · G
/// ```
/// 9 multiplications + 9 add/subs. Both `p1` and `p2` must be valid
/// points (extended-coord invariant + on curve). Output is also valid.
pub fn add(p1: &EdwardsPoint, p2: &EdwardsPoint) -> EdwardsPoint {
	let y1_minus_x1 = field_sub(&p1.y, &p1.x);
	let y2_minus_x2 = field_sub(&p2.y, &p2.x);
	let y1_plus_x1 = field_add(&p1.y, &p1.x);
	let y2_plus_x2 = field_add(&p2.y, &p2.x);

	let a = field_mul(&y1_minus_x1, &y2_minus_x2);
	let b = field_mul(&y1_plus_x1, &y2_plus_x2);
	let k_t2 = field_mul(&ED25519_2D_LIMBS, &p2.t);
	let c = field_mul(&p1.t, &k_t2);
	let two_z2 = field_add(&p2.z, &p2.z);
	let d = field_mul(&p1.z, &two_z2);

	let e = field_sub(&b, &a);
	let f = field_sub(&d, &c);
	let g = field_add(&d, &c);
	let h = field_add(&b, &a);

	EdwardsPoint {
		x: field_mul(&e, &f),
		y: field_mul(&g, &h),
		t: field_mul(&e, &h),
		z: field_mul(&f, &g),
	}
}

/// Bit width of canonical Ristretto255 scalars (group order
/// `ell = 2^252 + 27742317777372353535851937790883648493`, so bit 252
/// is the high bit of any in-range scalar).
pub const SCALAR_NUM_BITS: usize = 253;

/// Left-to-right double-and-add scalar multiplication on Edwards25519.
///
/// Computes `scalar · point` over the 253 high-to-low bits of
/// `scalar`. Iterates **exactly 253 times regardless of scalar**:
/// uniform per-bit work is what lets the corresponding AIR (P-tier
/// commits S2-S4) have a uniform per-row structure and avoids any
/// early-exit branch that would leak the scalar's bit length.
///
/// `scalar` is little-endian (matches `curve25519-dalek::Scalar`'s
/// 32-byte canonical form). Bit `i` is `(scalar[i/8] >> (i % 8)) & 1`.
/// Bytes 31's top 3 bits MUST be zero for any in-range Ristretto255
/// scalar — caller's responsibility (a scalar produced by
/// `Scalar::from_bytes_mod_order` satisfies this).
///
/// Returns the neutral element when `scalar == 0`. For `scalar == 1`,
/// returns a point equal to `point` (up to extended-coord aliasing —
/// compare via `compress`).
pub fn scalar_mul(scalar: &[u8; 32], point: &EdwardsPoint) -> EdwardsPoint {
	let mut acc = neutral();
	for i in (0..SCALAR_NUM_BITS).rev() {
		acc = double(&acc);
		let byte = scalar[i / 8];
		let bit = (byte >> (i % 8)) & 1;
		if bit == 1 {
			acc = add(&acc, point);
		}
	}
	acc
}

/// Edwards25519 point doubling in extended coordinates.
///
/// Implements the HWCD 2008 doubling formula:
/// ```text
///   A = X1²
///   B = Y1²
///   C = 2 · Z1²
///   D = -A             (Edwards25519's a-coefficient is -1)
///   E = (X1 + Y1)² - A - B
///   G = D + B
///   F = G - C
///   H = D - B
///   X3 = E · F
///   Y3 = G · H
///   T3 = E · H
///   Z3 = F · G
/// ```
/// 4 muls + 3 squares + 6 add/subs. `p` must be a valid point;
/// output is valid.
pub fn double(p: &EdwardsPoint) -> EdwardsPoint {
	let a = field_mul(&p.x, &p.x);
	let b = field_mul(&p.y, &p.y);
	let z_sq = field_mul(&p.z, &p.z);
	let c = field_add(&z_sq, &z_sq);
	let d = field_neg(&a);
	let x_plus_y = field_add(&p.x, &p.y);
	let xpy_sq = field_mul(&x_plus_y, &x_plus_y);
	let xpy_sq_minus_a = field_sub(&xpy_sq, &a);
	let e = field_sub(&xpy_sq_minus_a, &b);
	let g = field_add(&d, &b);
	let f = field_sub(&g, &c);
	let h = field_sub(&d, &b);

	EdwardsPoint {
		x: field_mul(&e, &f),
		y: field_mul(&g, &h),
		t: field_mul(&e, &h),
		z: field_mul(&f, &g),
	}
}
