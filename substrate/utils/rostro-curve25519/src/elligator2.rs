// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Elligator2 map for hash-to-curve on Edwards25519.
//!
//! Implements `map_to_curve_elligator2_edwards25519` per RFC 9380 **§F.3**
//! + §G.2: take a field element `u ∈ F_p25519` and produce an Edwards25519
//! point. Internally goes via the Curve25519 (Montgomery) Elligator2 map
//! then applies the birational map to Edwards25519. This is the *map* leg
//! of hash-to-curve; the *hash_to_field* leg (Poseidon2 + DST + mod
//! reduction) is a separate AIR.
//!
//! ## Variant choice: §F.3, not §6.7.1
//!
//! RFC 9380 specifies two Elligator2 variants:
//! - **§6.7.1 (straight-line / constant-time):** sign rule is
//!   `sgn0(y) = sgn0(u)`. Sign depends on the *input*.
//! - **§F.3 (optimised):** sign rule is "if branch chose x1, sgn0(y) = 1;
//!   else sgn0(y) = 0," i.e., sign depends on *which branch was taken*.
//!
//! This crate implements §F.3 with the convention `want_negative =
//! is_sq_gx1` (sign = 1 when gx1 is a square, sign = 0 otherwise). The
//! opposite convention (sign = NOT is_sq_gx1, used by e.g.
//! zcash/pasta_curves) is equally valid §F.3 but produces a different
//! map; the two conventions are not interoperable. Our pinned
//! regression vectors in `hash_to_curve_air/src/tests.rs` lock this
//! choice.
//!
//! A consequence of §F.3 is `map(u) == map(-u)`: flipping the input
//! sign doesn't change `u²`, so it doesn't change the branch, so it
//! doesn't change the output sign rule, so it doesn't change the
//! output. The `fuzz_elligator2_negation_symmetry` test pins this
//! property and is **incompatible with §6.7.1** (where flipping `u`
//! would flip `sgn0(u)` and therefore flip `sgn0(y)`). Don't "fix"
//! that test against §6.7.1 — switching variants would invalidate
//! every nullifier minted under the §F.3 convention.
//!
//! For the OPRF nullifier pipeline (per `pop_zkpassport_oprf_pattern.md`),
//! Hash2Curve(private_nullifier) wraps two map_to_curve calls (RO mode)
//! plus a point addition plus cofactor clearing (×8 = three doublings).
//!
//! ## Constants
//!
//! - `MONT_A_LIMBS = 486662`: the Montgomery A coefficient for Curve25519
//!   (y² = x³ + A·x² + x).
//! - `ELLIGATOR_Z_LIMBS = 2`: the non-square in F_p25519 chosen by RFC
//!   9380 for this suite.
//! - `SQRT_NEG_A_MINUS_2 = 2 · INVSQRT_A_MINUS_D`: the constant in the
//!   Curve25519 → Edwards25519 birational map. Derivation:
//!   `sqrt(-A-2) = sqrt(-486664) = sqrt(4 · -121666) = 2 · sqrt(-121666)`,
//!   and `INVSQRT_A_MINUS_D² = 1/(a-d) = 1/(-1/121666) = -121666` for
//!   Edwards25519's parameters, so `INVSQRT_A_MINUS_D = sqrt(-121666)`.
//!   The reuse keeps the constant inventory small.

extern crate alloc;

use crate::field::{
	add as field_add, inv, is_negative, is_zero, mul as field_mul, neg as field_neg,
	sqrt_ratio_m1, square as field_square, sub as field_sub, FIELD_NUM_LIMBS,
};
use crate::point::EdwardsPoint;
use crate::ristretto::INVSQRT_A_MINUS_D_LIMBS;

/// Montgomery A coefficient for Curve25519. A = 486662 = 0x076D06.
pub const MONT_A_LIMBS: [u32; FIELD_NUM_LIMBS] = [486662, 0, 0, 0, 0, 0, 0, 0];

/// The non-square Z = 2 chosen by RFC 9380 §G.2 for Curve25519
/// Elligator2.
pub const ELLIGATOR_Z_LIMBS: [u32; FIELD_NUM_LIMBS] = [2, 0, 0, 0, 0, 0, 0, 0];

/// One in F_p25519 limb form.
const ONE_LIMBS: [u32; FIELD_NUM_LIMBS] = [1, 0, 0, 0, 0, 0, 0, 0];

/// `sqrt(-A-2) = sqrt(-486664)` for Curve25519 → Edwards25519
/// birational map. Computed as `2 · INVSQRT_A_MINUS_D` (see module
/// docs); algebraic self-check pinned in tests.
pub fn sqrt_neg_a_minus_2() -> [u32; FIELD_NUM_LIMBS] {
	let two = [2u32, 0, 0, 0, 0, 0, 0, 0];
	field_mul(&two, &INVSQRT_A_MINUS_D_LIMBS)
}

/// Map a field element `u ∈ F_p25519` to an Edwards25519 point per
/// RFC 9380 `map_to_curve_elligator2_edwards25519`.
///
/// Returns the point in extended twisted-Edwards coords `(X, Y, Z=1, T)`.
/// The map is total — for every input `u`, output is a valid Edwards25519
/// point.
pub fn map_to_curve_elligator2_edwards25519(
	u: &[u32; FIELD_NUM_LIMBS],
) -> EdwardsPoint {
	// ─── Montgomery (Curve25519) leg ──────────────────────────────────
	let u_sq = field_square(u);
	let z_u_sq = field_mul(&ELLIGATOR_Z_LIMBS, &u_sq);
	let one_plus_zu_sq = field_add(&ONE_LIMBS, &z_u_sq);
	let is_singular = is_zero(&one_plus_zu_sq);

	// x1 = -A · inv(1 + Z·u²). If 1 + Z·u² == 0 (singular), x1 = -A.
	let inv_term = inv(&one_plus_zu_sq); // inv(0) = 0 by convention
	let neg_a = field_neg(&MONT_A_LIMBS);
	let x1 = if is_singular {
		neg_a
	} else {
		field_mul(&neg_a, &inv_term)
	};

	// gx1 = x1 · (x1² + A·x1 + 1) = x1³ + A·x1² + x1
	let gx1 = compute_g_x(&x1);

	// x2 = -x1 - A
	let x2 = field_neg(&field_add(&x1, &MONT_A_LIMBS));

	// gx2 = x2 · (x2² + A·x2 + 1). The identity gx2 = Z·u²·gx1 also
	// holds, but computing gx2 directly is cleaner and the singular
	// branch is consistent.
	let gx2 = compute_g_x(&x2);

	// is_square(gx1) determines which branch.
	let (is_sq_gx1, sqrt_gx1) = sqrt_ratio_m1(&gx1, &ONE_LIMBS);

	let (x_m, y_m_pre) = if is_sq_gx1 {
		(x1, sqrt_gx1)
	} else {
		let (_is_sq_gx2, sqrt_gx2) = sqrt_ratio_m1(&gx2, &ONE_LIMBS);
		// _is_sq_gx2 is provably true (gx2 = Z·u²·gx1 with Z non-square,
		// u² square, gx1 non-square → gx2 is non-square·non-square·square
		// = square).
		(x2, sqrt_gx2)
	};

	// RFC 9380 §F.3 sign rule (NOT §6.7.1 — see module docstring).
	// If is_square(gx1) (branch chose x = x1), want sgn0(y) == 1
	// (LSB odd, "negative"). Else (x = x2), want sgn0(y) == 0
	// (LSB even, "positive"). Equivalently: flip y iff
	// is_sq_gx1 XOR is_negative(y_m_pre).
	let want_negative = is_sq_gx1;
	let y_m = if is_negative(&y_m_pre) == want_negative {
		y_m_pre
	} else {
		field_neg(&y_m_pre)
	};

	// ─── Curve25519 → Edwards25519 birational map ─────────────────────
	// x_E = sqrt(-A-2) · x_M / y_M
	// y_E = (x_M - 1) / (x_M + 1)
	// Edge case: y_M = 0 (2-torsion) maps to identity. inv(0) = 0 propagates.
	let c = sqrt_neg_a_minus_2();
	let inv_ym = inv(&y_m);
	let x_e = field_mul(&c, &field_mul(&x_m, &inv_ym));

	let x_m_minus_1 = field_sub(&x_m, &ONE_LIMBS);
	let x_m_plus_1 = field_add(&x_m, &ONE_LIMBS);
	let inv_xm_plus_1 = inv(&x_m_plus_1);
	let y_e = field_mul(&x_m_minus_1, &inv_xm_plus_1);

	// Extended twisted-Edwards: Z = 1, T = X·Y.
	let t_e = field_mul(&x_e, &y_e);
	EdwardsPoint { x: x_e, y: y_e, z: ONE_LIMBS, t: t_e }
}

/// Compute g(x) = x³ + A·x² + x = x · (x² + A·x + 1) — the right-hand
/// side of the Curve25519 (Montgomery) equation.
fn compute_g_x(x: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	let x_sq = field_square(x);
	let a_x = field_mul(&MONT_A_LIMBS, x);
	let inner = field_add(&field_add(&x_sq, &a_x), &ONE_LIMBS);
	field_mul(x, &inner)
}
