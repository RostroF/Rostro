// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for [`crate::elligator2::map_to_curve_elligator2_edwards25519`].
//!
//! Single-row AIR. Consumes:
//! - [`crate::field_air::BUS_FIELD_ADD`] / [`crate::field_sub_air::BUS_FIELD_SUB`] /
//!   [`crate::field_mul_air::BUS_FIELD_MUL`] for inline field arithmetic.
//! - [`crate::sqrt_ratio_m1_air::BUS_SQRT_RATIO_M1`] for the two square-root
//!   queries on gx1 and gx2.
//! - [`crate::field_air::BUS_U16_RANGE`] for the LSB-tie on the chosen
//!   square root.
//!
//! Provider of:
//! - [`BUS_ELLIGATOR2`] with payload `(u, x_E, y_E, z_E, t_E)` = 5 × 8 =
//!   40 cells, on row, count = -1.
//!
//! ## Fail-closed inversions (v0 limitation)
//!
//! The AIR contains three field inversions: `inv(1 + Z·u²)`, `inv(y_M)`,
//! and `inv(x_M + 1)`. Each is enforced by pushing `(x, x_inv, 1)` on
//! `BUS_FIELD_MUL`; the bus provider proves `x · x_inv ≡ 1 mod p`. If any
//! of these inputs is zero, no valid `x_inv` exists and the prover cannot
//! satisfy the bus. For random hash-to-field inputs (Poseidon2-derived),
//! each edge case has probability ≈ 2⁻²⁵⁵ and can be ignored. For
//! adversarial inputs the AIR simply rejects — failure mode is denial,
//! not a soundness break.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::elligator2::{
	map_to_curve_elligator2_edwards25519, sqrt_neg_a_minus_2, ELLIGATOR_Z_LIMBS,
	MONT_A_LIMBS,
};
use crate::field::{
	add as field_add, inv as field_inv, is_negative, mul as field_mul, neg as field_neg,
	square as field_square, sub as field_sub, FIELD_NUM_LIMBS,
};
use crate::field_air::{BUS_FIELD_ADD, BUS_U16_RANGE};
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_sub_air::BUS_FIELD_SUB;
use crate::sqrt_ratio_m1_air::BUS_SQRT_RATIO_M1;

/// Service-bus name. Payload `(u, x_E, y_E, z_E, t_E)` = 5 × 8 = 40 cells.
pub const BUS_ELLIGATOR2: &str = "rostro-elligator2";

// ─── Column layout ─────────────────────────────────────────────────────────
//
// Order: inputs → step-by-step intermediates → selections → output
// (Edwards extended coords). All field-element witnesses are 8 limbs.

pub const COL_U: usize = 0;
pub const COL_U_SQ: usize = COL_U + FIELD_NUM_LIMBS;
pub const COL_Z_U_SQ: usize = COL_U_SQ + FIELD_NUM_LIMBS;
pub const COL_ONE_PLUS_ZU_SQ: usize = COL_Z_U_SQ + FIELD_NUM_LIMBS;
pub const COL_INV_TERM: usize = COL_ONE_PLUS_ZU_SQ + FIELD_NUM_LIMBS;
pub const COL_X1: usize = COL_INV_TERM + FIELD_NUM_LIMBS;
pub const COL_X1_SQ: usize = COL_X1 + FIELD_NUM_LIMBS;
pub const COL_A_X1: usize = COL_X1_SQ + FIELD_NUM_LIMBS;
pub const COL_X1_SQ_PLUS_A_X1: usize = COL_A_X1 + FIELD_NUM_LIMBS;
pub const COL_INNER_X1: usize = COL_X1_SQ_PLUS_A_X1 + FIELD_NUM_LIMBS;
pub const COL_GX1: usize = COL_INNER_X1 + FIELD_NUM_LIMBS;
pub const COL_X1_PLUS_A: usize = COL_GX1 + FIELD_NUM_LIMBS;
pub const COL_X2: usize = COL_X1_PLUS_A + FIELD_NUM_LIMBS;
pub const COL_X2_SQ: usize = COL_X2 + FIELD_NUM_LIMBS;
pub const COL_A_X2: usize = COL_X2_SQ + FIELD_NUM_LIMBS;
pub const COL_X2_SQ_PLUS_A_X2: usize = COL_A_X2 + FIELD_NUM_LIMBS;
pub const COL_INNER_X2: usize = COL_X2_SQ_PLUS_A_X2 + FIELD_NUM_LIMBS;
pub const COL_GX2: usize = COL_INNER_X2 + FIELD_NUM_LIMBS;
pub const COL_SQRT_GX1: usize = COL_GX2 + FIELD_NUM_LIMBS;
pub const COL_SQRT_GX2: usize = COL_SQRT_GX1 + FIELD_NUM_LIMBS;
pub const COL_X_M: usize = COL_SQRT_GX2 + FIELD_NUM_LIMBS;
pub const COL_Y_M_PRE: usize = COL_X_M + FIELD_NUM_LIMBS;
pub const COL_NEG_Y_M_PRE: usize = COL_Y_M_PRE + FIELD_NUM_LIMBS;
pub const COL_Y_M: usize = COL_NEG_Y_M_PRE + FIELD_NUM_LIMBS;
pub const COL_INV_YM: usize = COL_Y_M + FIELD_NUM_LIMBS;
pub const COL_C_X_M: usize = COL_INV_YM + FIELD_NUM_LIMBS;
pub const COL_X_E: usize = COL_C_X_M + FIELD_NUM_LIMBS;
pub const COL_X_M_MINUS_1: usize = COL_X_E + FIELD_NUM_LIMBS;
pub const COL_X_M_PLUS_1: usize = COL_X_M_MINUS_1 + FIELD_NUM_LIMBS;
pub const COL_INV_XM_PLUS_1: usize = COL_X_M_PLUS_1 + FIELD_NUM_LIMBS;
pub const COL_Y_E: usize = COL_INV_XM_PLUS_1 + FIELD_NUM_LIMBS;
pub const COL_T_E: usize = COL_Y_E + FIELD_NUM_LIMBS;

// Boolean / flag columns (one cell each).
pub const COL_IS_SQ_GX1: usize = COL_T_E + FIELD_NUM_LIMBS;
pub const COL_IS_SQ_GX2: usize = COL_IS_SQ_GX1 + 1;
pub const COL_IS_NEG_Y_M_PRE: usize = COL_IS_SQ_GX2 + 1;
pub const COL_FLIP_Y: usize = COL_IS_NEG_Y_M_PRE + 1;
// LSB-tie witnesses for is_neg_y_m_pre = LSB(y_m_pre[0]).
pub const COL_Y_M_PRE_LIMB_HI_LO: usize = COL_FLIP_Y + 1;
pub const COL_Y_M_PRE_LIMB_HI_HI: usize = COL_Y_M_PRE_LIMB_HI_LO + 1;

pub const ELLIGATOR2_NUM_COLS: usize = COL_Y_M_PRE_LIMB_HI_HI + 1;

#[derive(Clone, Debug, Default)]
pub struct Elligator2Air;

impl Elligator2Air {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for Elligator2Air {
	fn width(&self) -> usize {
		ELLIGATOR2_NUM_COLS
	}
}

fn limbs<AB: AirBuilder>(local: &[AB::Var], off: usize) -> [AB::Var; FIELD_NUM_LIMBS] {
	core::array::from_fn(|i| local[off + i])
}

// ─── Bus push helpers ──────────────────────────────────────────────────────

fn push_op<AB: InteractionBuilder>(
	builder: &mut AB,
	bus: &'static str,
	a: &[AB::Var; FIELD_NUM_LIMBS],
	b: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	let payload: Vec<AB::Expr> = a
		.iter()
		.chain(b.iter())
		.chain(c.iter())
		.map(|v| (*v).into())
		.collect();
	builder.push_interaction(bus, payload, AB::Expr::ONE, 1);
}

fn push_op_const_a_first<AB: InteractionBuilder>(
	builder: &mut AB,
	bus: &'static str,
	a_first: AB::Expr,
	b: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	payload.push(a_first);
	for _ in 1..FIELD_NUM_LIMBS {
		payload.push(AB::Expr::ZERO);
	}
	for v in b.iter() {
		payload.push((*v).into());
	}
	for v in c.iter() {
		payload.push((*v).into());
	}
	builder.push_interaction(bus, payload, AB::Expr::ONE, 1);
}

fn push_mul_const_a_limbs<AB: InteractionBuilder>(
	builder: &mut AB,
	a_const: &[u32; FIELD_NUM_LIMBS],
	b: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	for &k in a_const.iter() {
		payload.push(AB::Expr::from_u32(k));
	}
	for v in b.iter() {
		payload.push((*v).into());
	}
	for v in c.iter() {
		payload.push((*v).into());
	}
	builder.push_interaction(BUS_FIELD_MUL, payload, AB::Expr::ONE, 1);
}

fn push_add_const_b_one<AB: InteractionBuilder>(
	builder: &mut AB,
	a: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	// Push (a, 1, c) on BUS_FIELD_ADD with b = 1 (constant).
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	for v in a.iter() {
		payload.push((*v).into());
	}
	payload.push(AB::Expr::ONE);
	for _ in 1..FIELD_NUM_LIMBS {
		payload.push(AB::Expr::ZERO);
	}
	for v in c.iter() {
		payload.push((*v).into());
	}
	builder.push_interaction(BUS_FIELD_ADD, payload, AB::Expr::ONE, 1);
}

fn push_sub_const_b_one<AB: InteractionBuilder>(
	builder: &mut AB,
	a: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	// Push (a, 1, c) on BUS_FIELD_SUB with b = 1 (constant): c = a - 1.
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	for v in a.iter() {
		payload.push((*v).into());
	}
	payload.push(AB::Expr::ONE);
	for _ in 1..FIELD_NUM_LIMBS {
		payload.push(AB::Expr::ZERO);
	}
	for v in c.iter() {
		payload.push((*v).into());
	}
	builder.push_interaction(BUS_FIELD_SUB, payload, AB::Expr::ONE, 1);
}

fn push_sub_zero_a<AB: InteractionBuilder>(
	builder: &mut AB,
	b: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	// Push (0, b, c) on BUS_FIELD_SUB: c = -b.
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	for _ in 0..FIELD_NUM_LIMBS {
		payload.push(AB::Expr::ZERO);
	}
	for v in b.iter() {
		payload.push((*v).into());
	}
	for v in c.iter() {
		payload.push((*v).into());
	}
	builder.push_interaction(BUS_FIELD_SUB, payload, AB::Expr::ONE, 1);
}

fn push_inv_check<AB: InteractionBuilder>(
	builder: &mut AB,
	x: &[AB::Var; FIELD_NUM_LIMBS],
	x_inv: &[AB::Var; FIELD_NUM_LIMBS],
) {
	// Push (x, x_inv, 1) on BUS_FIELD_MUL: enforces x · x_inv ≡ 1 mod p.
	// Fail-closed on x = 0.
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	for v in x.iter() {
		payload.push((*v).into());
	}
	for v in x_inv.iter() {
		payload.push((*v).into());
	}
	payload.push(AB::Expr::ONE);
	for _ in 1..FIELD_NUM_LIMBS {
		payload.push(AB::Expr::ZERO);
	}
	builder.push_interaction(BUS_FIELD_MUL, payload, AB::Expr::ONE, 1);
}

fn push_sqrt_ratio_m1_v_const_one<AB: InteractionBuilder>(
	builder: &mut AB,
	u: &[AB::Var; FIELD_NUM_LIMBS],
	was_sq: AB::Var,
	r: &[AB::Var; FIELD_NUM_LIMBS],
) {
	// Payload (u, v, was_sq, r) = 25 cells. Elligator2 needs sqrt(gx) =
	// sqrt_ratio_m1(gx, 1) so `u` is variable (the 8-limb gx) and `v` is
	// the constant 1.
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(25);
	for v_var in u.iter() {
		payload.push((*v_var).into());
	}
	payload.push(AB::Expr::ONE);
	for _ in 1..FIELD_NUM_LIMBS {
		payload.push(AB::Expr::ZERO);
	}
	payload.push(was_sq.into());
	for r_v in r.iter() {
		payload.push((*r_v).into());
	}
	builder.push_interaction(BUS_SQRT_RATIO_M1, payload, AB::Expr::ONE, 1);
}

impl<AB: InteractionBuilder> Air<AB> for Elligator2Air
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let u = limbs::<AB>(local, COL_U);
		let u_sq = limbs::<AB>(local, COL_U_SQ);
		let z_u_sq = limbs::<AB>(local, COL_Z_U_SQ);
		let one_plus_zu_sq = limbs::<AB>(local, COL_ONE_PLUS_ZU_SQ);
		let inv_term = limbs::<AB>(local, COL_INV_TERM);
		let x1 = limbs::<AB>(local, COL_X1);
		let x1_sq = limbs::<AB>(local, COL_X1_SQ);
		let a_x1 = limbs::<AB>(local, COL_A_X1);
		let x1_sq_plus_a_x1 = limbs::<AB>(local, COL_X1_SQ_PLUS_A_X1);
		let inner_x1 = limbs::<AB>(local, COL_INNER_X1);
		let gx1 = limbs::<AB>(local, COL_GX1);
		let x1_plus_a = limbs::<AB>(local, COL_X1_PLUS_A);
		let x2 = limbs::<AB>(local, COL_X2);
		let x2_sq = limbs::<AB>(local, COL_X2_SQ);
		let a_x2 = limbs::<AB>(local, COL_A_X2);
		let x2_sq_plus_a_x2 = limbs::<AB>(local, COL_X2_SQ_PLUS_A_X2);
		let inner_x2 = limbs::<AB>(local, COL_INNER_X2);
		let gx2 = limbs::<AB>(local, COL_GX2);
		let sqrt_gx1 = limbs::<AB>(local, COL_SQRT_GX1);
		let sqrt_gx2 = limbs::<AB>(local, COL_SQRT_GX2);
		let x_m = limbs::<AB>(local, COL_X_M);
		let y_m_pre = limbs::<AB>(local, COL_Y_M_PRE);
		let neg_y_m_pre = limbs::<AB>(local, COL_NEG_Y_M_PRE);
		let y_m = limbs::<AB>(local, COL_Y_M);
		let inv_ym = limbs::<AB>(local, COL_INV_YM);
		let c_x_m = limbs::<AB>(local, COL_C_X_M);
		let x_e = limbs::<AB>(local, COL_X_E);
		let x_m_minus_1 = limbs::<AB>(local, COL_X_M_MINUS_1);
		let x_m_plus_1 = limbs::<AB>(local, COL_X_M_PLUS_1);
		let inv_xm_plus_1 = limbs::<AB>(local, COL_INV_XM_PLUS_1);
		let y_e = limbs::<AB>(local, COL_Y_E);
		let t_e = limbs::<AB>(local, COL_T_E);

		let is_sq_gx1: AB::Var = local[COL_IS_SQ_GX1];
		let is_sq_gx2: AB::Var = local[COL_IS_SQ_GX2];
		let is_neg_y_m_pre: AB::Var = local[COL_IS_NEG_Y_M_PRE];
		let flip_y: AB::Var = local[COL_FLIP_Y];
		let ym_pre_lo: AB::Var = local[COL_Y_M_PRE_LIMB_HI_LO];
		let ym_pre_hi: AB::Var = local[COL_Y_M_PRE_LIMB_HI_HI];

		// ─── Boolean assertions ───────────────────────────────────────
		builder.assert_bool(is_sq_gx1);
		builder.assert_bool(is_sq_gx2);
		builder.assert_bool(is_neg_y_m_pre);
		builder.assert_bool(flip_y);

		// When gx1 is non-square, gx2 = Z·u²·gx1 IS a square (Z is the
		// chosen non-residue, u² is a square, so gx2 = non-sq·sq·non-sq =
		// square). When gx1 IS a square, gx2 is a non-square; sqrt_gx2 is
		// then unused in the selection so we don't constrain its
		// is_sq_gx2 value. Gated constraint:
		//   (1 - is_sq_gx1) · (1 - is_sq_gx2) == 0
		builder.assert_zero(
			(AB::Expr::ONE - is_sq_gx1.into()) * (AB::Expr::ONE - is_sq_gx2.into()),
		);

		// ─── Selections ───────────────────────────────────────────────

		// x_m = is_sq_gx1 ? x1 : x2
		let one_minus_is_sq = AB::Expr::ONE - is_sq_gx1.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				x_m[i].into()
					- is_sq_gx1.into() * x1[i].into()
					- one_minus_is_sq.clone() * x2[i].into(),
			);
		}

		// y_m_pre = is_sq_gx1 ? sqrt_gx1 : sqrt_gx2
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				y_m_pre[i].into()
					- is_sq_gx1.into() * sqrt_gx1[i].into()
					- one_minus_is_sq.clone() * sqrt_gx2[i].into(),
			);
		}

		// flip_y = is_sq_gx1 XOR is_neg_y_m_pre. The witness flips y when
		// is_negative(y_m_pre) disagrees with the RFC 9380 §6.7.1 required
		// sign (sgn0(y) = 1 when x = x1, sgn0(y) = 0 when x = x2).
		// flip_y = is_sq_gx1 + is_neg_y_m_pre - 2 · is_sq_gx1 · is_neg_y_m_pre
		builder.assert_zero(
			flip_y.into()
				- (is_sq_gx1.into() + is_neg_y_m_pre.into()
					- AB::Expr::from_u64(2) * is_sq_gx1.into() * is_neg_y_m_pre.into()),
		);

		// y_m = flip_y ? neg_y_m_pre : y_m_pre
		let one_minus_flip = AB::Expr::ONE - flip_y.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				y_m[i].into()
					- flip_y.into() * neg_y_m_pre[i].into()
					- one_minus_flip.clone() * y_m_pre[i].into(),
			);
		}

		// ─── LSB-tie on is_neg_y_m_pre ────────────────────────────────
		let radix_u16 = AB::Expr::from_u64(1u64 << 16);
		let two = AB::Expr::from_u64(2);
		let limb_hi_expr = ym_pre_lo.into() + ym_pre_hi.into() * radix_u16;
		builder.assert_zero(
			y_m_pre[0].into() - two * limb_hi_expr - is_neg_y_m_pre.into(),
		);
		builder.push_interaction(BUS_U16_RANGE, [ym_pre_lo], AB::Expr::ONE, 1);
		builder.push_interaction(BUS_U16_RANGE, [ym_pre_hi], AB::Expr::ONE, 1);

		// ─── Bus queries (consumer side, count = +1) ──────────────────
		// Pre-square: u·u = u_sq
		push_op::<AB>(builder, BUS_FIELD_MUL, &u, &u, &u_sq);
		// Z·u_sq = z_u_sq (Z = 2)
		push_mul_const_a_limbs::<AB>(builder, &ELLIGATOR_Z_LIMBS, &u_sq, &z_u_sq);
		// 1 + z_u_sq = one_plus_zu_sq
		push_op_const_a_first::<AB>(builder, BUS_FIELD_ADD, AB::Expr::ONE, &z_u_sq, &one_plus_zu_sq);
		// inv check: one_plus_zu_sq · inv_term ≡ 1
		push_inv_check::<AB>(builder, &one_plus_zu_sq, &inv_term);

		// x1 = -A · inv_term (-A as constant)
		let neg_a_limbs = field_neg(&MONT_A_LIMBS);
		push_mul_const_a_limbs::<AB>(builder, &neg_a_limbs, &inv_term, &x1);

		// gx1 chain: x1·x1, A·x1, sum, +1, x1·inner
		push_op::<AB>(builder, BUS_FIELD_MUL, &x1, &x1, &x1_sq);
		push_mul_const_a_limbs::<AB>(builder, &MONT_A_LIMBS, &x1, &a_x1);
		push_op::<AB>(builder, BUS_FIELD_ADD, &x1_sq, &a_x1, &x1_sq_plus_a_x1);
		push_add_const_b_one::<AB>(builder, &x1_sq_plus_a_x1, &inner_x1);
		push_op::<AB>(builder, BUS_FIELD_MUL, &x1, &inner_x1, &gx1);

		// x2 chain: x1 + A → x1_plus_a, then x2 = -x1_plus_a
		push_mul_const_a_limbs_via_add::<AB>(builder, &MONT_A_LIMBS, &x1, &x1_plus_a);
		push_sub_zero_a::<AB>(builder, &x1_plus_a, &x2);

		// gx2 chain: x2·x2, A·x2, sum, +1, x2·inner
		push_op::<AB>(builder, BUS_FIELD_MUL, &x2, &x2, &x2_sq);
		push_mul_const_a_limbs::<AB>(builder, &MONT_A_LIMBS, &x2, &a_x2);
		push_op::<AB>(builder, BUS_FIELD_ADD, &x2_sq, &a_x2, &x2_sq_plus_a_x2);
		push_add_const_b_one::<AB>(builder, &x2_sq_plus_a_x2, &inner_x2);
		push_op::<AB>(builder, BUS_FIELD_MUL, &x2, &inner_x2, &gx2);

		// sqrt_ratio_m1(gx1, 1) → (is_sq_gx1, sqrt_gx1)
		push_sqrt_ratio_m1_v_const_one::<AB>(builder, &gx1, is_sq_gx1, &sqrt_gx1);
		// sqrt_ratio_m1(gx2, 1) → (is_sq_gx2, sqrt_gx2)
		push_sqrt_ratio_m1_v_const_one::<AB>(builder, &gx2, is_sq_gx2, &sqrt_gx2);

		// neg_y_m_pre = 0 - y_m_pre
		push_sub_zero_a::<AB>(builder, &y_m_pre, &neg_y_m_pre);

		// inv_ym check
		push_inv_check::<AB>(builder, &y_m, &inv_ym);
		// c · x_m → c_x_m (c = sqrt(-A-2) constant)
		let c_limbs = sqrt_neg_a_minus_2();
		push_mul_const_a_limbs::<AB>(builder, &c_limbs, &x_m, &c_x_m);
		// x_e = c_x_m · inv_ym
		push_op::<AB>(builder, BUS_FIELD_MUL, &c_x_m, &inv_ym, &x_e);

		// x_m_minus_1 = x_m - 1
		push_sub_const_b_one::<AB>(builder, &x_m, &x_m_minus_1);
		// x_m_plus_1 = x_m + 1
		push_add_const_b_one::<AB>(builder, &x_m, &x_m_plus_1);
		// inv_xm_plus_1 check
		push_inv_check::<AB>(builder, &x_m_plus_1, &inv_xm_plus_1);
		// y_e = x_m_minus_1 · inv_xm_plus_1
		push_op::<AB>(builder, BUS_FIELD_MUL, &x_m_minus_1, &inv_xm_plus_1, &y_e);

		// t_e = x_e · y_e
		push_op::<AB>(builder, BUS_FIELD_MUL, &x_e, &y_e, &t_e);

		// ─── Service emit (count = -1) ────────────────────────────────
		// Payload: (u, x_E, y_E, z_E=1, t_E) = 5 × 8 = 40 cells.
		let mut emit_payload: Vec<AB::Expr> = Vec::with_capacity(40);
		for v in u.iter() {
			emit_payload.push((*v).into());
		}
		for v in x_e.iter() {
			emit_payload.push((*v).into());
		}
		for v in y_e.iter() {
			emit_payload.push((*v).into());
		}
		// z_E = 1
		emit_payload.push(AB::Expr::ONE);
		for _ in 1..FIELD_NUM_LIMBS {
			emit_payload.push(AB::Expr::ZERO);
		}
		for v in t_e.iter() {
			emit_payload.push((*v).into());
		}
		let neg_one = AB::Expr::ZERO - AB::Expr::ONE;
		builder.push_interaction(BUS_ELLIGATOR2, emit_payload, neg_one, 1);
	}
}

// Helper: push (a_const, b, c) on BUS_FIELD_ADD with a_const a const_limbs.
fn push_mul_const_a_limbs_via_add<AB: InteractionBuilder>(
	builder: &mut AB,
	a_const: &[u32; FIELD_NUM_LIMBS],
	b: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	for &k in a_const.iter() {
		payload.push(AB::Expr::from_u32(k));
	}
	for v in b.iter() {
		payload.push((*v).into());
	}
	for v in c.iter() {
		payload.push((*v).into());
	}
	builder.push_interaction(BUS_FIELD_ADD, payload, AB::Expr::ONE, 1);
}

// ─── Witness-side trace builder ────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Elligator2TraceRow {
	pub u: [u32; FIELD_NUM_LIMBS],
	pub u_sq: [u32; FIELD_NUM_LIMBS],
	pub z_u_sq: [u32; FIELD_NUM_LIMBS],
	pub one_plus_zu_sq: [u32; FIELD_NUM_LIMBS],
	pub inv_term: [u32; FIELD_NUM_LIMBS],
	pub x1: [u32; FIELD_NUM_LIMBS],
	pub x1_sq: [u32; FIELD_NUM_LIMBS],
	pub a_x1: [u32; FIELD_NUM_LIMBS],
	pub x1_sq_plus_a_x1: [u32; FIELD_NUM_LIMBS],
	pub inner_x1: [u32; FIELD_NUM_LIMBS],
	pub gx1: [u32; FIELD_NUM_LIMBS],
	pub x1_plus_a: [u32; FIELD_NUM_LIMBS],
	pub x2: [u32; FIELD_NUM_LIMBS],
	pub x2_sq: [u32; FIELD_NUM_LIMBS],
	pub a_x2: [u32; FIELD_NUM_LIMBS],
	pub x2_sq_plus_a_x2: [u32; FIELD_NUM_LIMBS],
	pub inner_x2: [u32; FIELD_NUM_LIMBS],
	pub gx2: [u32; FIELD_NUM_LIMBS],
	pub sqrt_gx1: [u32; FIELD_NUM_LIMBS],
	pub sqrt_gx2: [u32; FIELD_NUM_LIMBS],
	pub x_m: [u32; FIELD_NUM_LIMBS],
	pub y_m_pre: [u32; FIELD_NUM_LIMBS],
	pub neg_y_m_pre: [u32; FIELD_NUM_LIMBS],
	pub y_m: [u32; FIELD_NUM_LIMBS],
	pub inv_ym: [u32; FIELD_NUM_LIMBS],
	pub c_x_m: [u32; FIELD_NUM_LIMBS],
	pub x_e: [u32; FIELD_NUM_LIMBS],
	pub x_m_minus_1: [u32; FIELD_NUM_LIMBS],
	pub x_m_plus_1: [u32; FIELD_NUM_LIMBS],
	pub inv_xm_plus_1: [u32; FIELD_NUM_LIMBS],
	pub y_e: [u32; FIELD_NUM_LIMBS],
	pub t_e: [u32; FIELD_NUM_LIMBS],
	pub is_sq_gx1: u32,
	pub is_sq_gx2: u32,
	pub is_neg_y_m_pre: u32,
	pub flip_y: u32,
	pub y_m_pre_limb_hi_lo: u32,
	pub y_m_pre_limb_hi_hi: u32,
}

/// Build one Elligator2 trace row.
///
/// **Panics** if the input `u` would force any of the three required
/// inversions to operate on a zero element (`1 + Z·u² = 0`, `y_M = 0`,
/// or `x_M + 1 = 0`). These edge cases have probability ~2⁻²⁵⁵ for
/// random hash-to-field inputs.
pub fn build_elligator2_trace_row(u: &[u32; FIELD_NUM_LIMBS]) -> Elligator2TraceRow {
	let one_limbs = {
		let mut o = [0u32; FIELD_NUM_LIMBS];
		o[0] = 1;
		o
	};

	let u_sq = field_square(u);
	let z_u_sq = field_mul(&ELLIGATOR_Z_LIMBS, &u_sq);
	let one_plus_zu_sq = field_add(&one_limbs, &z_u_sq);
	assert!(
		!crate::field::is_zero(&one_plus_zu_sq),
		"Elligator2 AIR rejects inputs with 1 + Z·u² = 0 (singular case)",
	);
	let inv_term = field_inv(&one_plus_zu_sq);

	let neg_a = field_neg(&MONT_A_LIMBS);
	let x1 = field_mul(&neg_a, &inv_term);

	let x1_sq = field_square(&x1);
	let a_x1 = field_mul(&MONT_A_LIMBS, &x1);
	let x1_sq_plus_a_x1 = field_add(&x1_sq, &a_x1);
	let inner_x1 = field_add(&x1_sq_plus_a_x1, &one_limbs);
	let gx1 = field_mul(&x1, &inner_x1);

	let x1_plus_a = field_add(&x1, &MONT_A_LIMBS);
	let x2 = field_neg(&x1_plus_a);

	let x2_sq = field_square(&x2);
	let a_x2 = field_mul(&MONT_A_LIMBS, &x2);
	let x2_sq_plus_a_x2 = field_add(&x2_sq, &a_x2);
	let inner_x2 = field_add(&x2_sq_plus_a_x2, &one_limbs);
	let gx2 = field_mul(&x2, &inner_x2);

	let (is_sq_gx1, sqrt_gx1) = crate::field::sqrt_ratio_m1(&gx1, &one_limbs);
	let (is_sq_gx2, sqrt_gx2) = crate::field::sqrt_ratio_m1(&gx2, &one_limbs);
	// Only assert gx2 is a square when gx1 is non-square — that's the
	// branch where sqrt_gx2 is actually used. When gx1 is a square,
	// gx2 is provably a non-square; sqrt_gx2 returned by sqrt_ratio_m1
	// has the form sqrt(√-1 · gx2) and goes unused.
	if !is_sq_gx1 {
		debug_assert!(is_sq_gx2, "gx2 must be a square when gx1 is non-square");
	}

	let (x_m, y_m_pre) = if is_sq_gx1 { (x1, sqrt_gx1) } else { (x2, sqrt_gx2) };
	let is_neg_y_m_pre = is_negative(&y_m_pre);
	let neg_y_m_pre = field_neg(&y_m_pre);
	// flip_y = is_sq_gx1 XOR is_neg_y_m_pre. Per RFC 9380 §6.7.1, want
	// sgn0(y) == 1 when is_sq_gx1, else sgn0(y) == 0.
	let flip_y = is_sq_gx1 != is_neg_y_m_pre;
	let y_m = if flip_y { neg_y_m_pre } else { y_m_pre };

	assert!(
		!crate::field::is_zero(&y_m),
		"Elligator2 AIR rejects inputs with y_M = 0 (2-torsion case)",
	);
	let inv_ym = field_inv(&y_m);

	let c_limbs = sqrt_neg_a_minus_2();
	let c_x_m = field_mul(&c_limbs, &x_m);
	let x_e = field_mul(&c_x_m, &inv_ym);

	let x_m_minus_1 = field_sub(&x_m, &one_limbs);
	let x_m_plus_1 = field_add(&x_m, &one_limbs);
	assert!(
		!crate::field::is_zero(&x_m_plus_1),
		"Elligator2 AIR rejects inputs with x_M + 1 = 0 (4-torsion case)",
	);
	let inv_xm_plus_1 = field_inv(&x_m_plus_1);
	let y_e = field_mul(&x_m_minus_1, &inv_xm_plus_1);
	let t_e = field_mul(&x_e, &y_e);

	// LSB-tie witness for is_neg_y_m_pre.
	let limb0 = y_m_pre[0];
	let flag_u32 = u32::from(is_neg_y_m_pre);
	let limb_hi = (limb0 - flag_u32) / 2;
	let y_m_pre_limb_hi_lo = limb_hi & 0xFFFF;
	let y_m_pre_limb_hi_hi = limb_hi >> 16;

	Elligator2TraceRow {
		u: *u,
		u_sq,
		z_u_sq,
		one_plus_zu_sq,
		inv_term,
		x1,
		x1_sq,
		a_x1,
		x1_sq_plus_a_x1,
		inner_x1,
		gx1,
		x1_plus_a,
		x2,
		x2_sq,
		a_x2,
		x2_sq_plus_a_x2,
		inner_x2,
		gx2,
		sqrt_gx1,
		sqrt_gx2,
		x_m,
		y_m_pre,
		neg_y_m_pre,
		y_m,
		inv_ym,
		c_x_m,
		x_e,
		x_m_minus_1,
		x_m_plus_1,
		inv_xm_plus_1,
		y_e,
		t_e,
		is_sq_gx1: u32::from(is_sq_gx1),
		is_sq_gx2: u32::from(is_sq_gx2),
		is_neg_y_m_pre: u32::from(is_neg_y_m_pre),
		flip_y: u32::from(flip_y),
		y_m_pre_limb_hi_lo,
		y_m_pre_limb_hi_hi,
	}
}

impl Elligator2TraceRow {
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(ELLIGATOR2_NUM_COLS);
		for limbs in [
			&self.u,
			&self.u_sq,
			&self.z_u_sq,
			&self.one_plus_zu_sq,
			&self.inv_term,
			&self.x1,
			&self.x1_sq,
			&self.a_x1,
			&self.x1_sq_plus_a_x1,
			&self.inner_x1,
			&self.gx1,
			&self.x1_plus_a,
			&self.x2,
			&self.x2_sq,
			&self.a_x2,
			&self.x2_sq_plus_a_x2,
			&self.inner_x2,
			&self.gx2,
			&self.sqrt_gx1,
			&self.sqrt_gx2,
			&self.x_m,
			&self.y_m_pre,
			&self.neg_y_m_pre,
			&self.y_m,
			&self.inv_ym,
			&self.c_x_m,
			&self.x_e,
			&self.x_m_minus_1,
			&self.x_m_plus_1,
			&self.inv_xm_plus_1,
			&self.y_e,
			&self.t_e,
		] {
			for &v in limbs {
				out.push(F::from_u32(v));
			}
		}
		out.push(F::from_u32(self.is_sq_gx1));
		out.push(F::from_u32(self.is_sq_gx2));
		out.push(F::from_u32(self.is_neg_y_m_pre));
		out.push(F::from_u32(self.flip_y));
		out.push(F::from_u32(self.y_m_pre_limb_hi_lo));
		out.push(F::from_u32(self.y_m_pre_limb_hi_hi));
		debug_assert_eq!(out.len(), ELLIGATOR2_NUM_COLS);
		out
	}

	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), ELLIGATOR2_NUM_COLS)
	}
}

// Silence the unused-witness oracle import; it documents the function
// the AIR mirrors.
#[allow(dead_code)]
fn _force_use() {
	let _ = map_to_curve_elligator2_edwards25519;
}
