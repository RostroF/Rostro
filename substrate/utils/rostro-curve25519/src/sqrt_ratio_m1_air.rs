// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for [`crate::field::sqrt_ratio_m1`].
//!
//! Single-row AIR. Consumes:
//! - [`crate::field_air::BUS_FIELD_ADD`] / [`crate::field_sub_air::BUS_FIELD_SUB`] / [`crate::field_mul_air::BUS_FIELD_MUL`]
//!   for the inline field arithmetic;
//! - [`crate::field_pow_p58_air::BUS_FIELD_POW_P58`] for the
//!   `base^((p-5)/8)` step.
//!
//! Provider of:
//! - [`BUS_SQRT_RATIO_M1`] with payload `(u, v, was_square, r)` —
//!   25 cells: 3 × 8-limb field elements + 1 boolean.
//!
//! ## Soundness sketch
//!
//! The dalek formula computes one of three candidate roots and selects
//! based on which of three equality conditions holds:
//!
//! - `correct_sign  = (check == u)`        → r is a sqrt of u/v
//! - `flipped_sign  = (check == -u)`       → r·√-1 is a sqrt of u/v
//! - `flipped_sign_i= (check == -u·√-1)`   → r·√-1 is a sqrt of u/v
//!
//! `was_square = correct_sign + flipped_sign` (each at most 1). The AIR
//! enforces each flag is boolean and that, when set, the corresponding
//! 8-limb equality holds. A malicious prover trying to set
//! `was_square = true` for a non-square input would have to produce an
//! `r` whose square times `v` equals one of `u`, `-u`, `-u·√-1` — but
//! none of those exist for non-square `u/v`, so they cannot.
//!
//! ## Sign normalization (v0 limitation)
//!
//! The final step `r = -r if r_selected is negative` requires knowing
//! the LSB of `r_selected[0]`. v0 witnesses `is_neg_r_selected` as a
//! boolean and trusts the prover; a follow-up commit closes this gap
//! via the LSB-split + range check pattern. Downstream Ristretto AIRs
//! have their own sign normalization that catches a wrong-sign sqrt
//! root (it produces a non-canonical / rejected encoding).

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::{
	add as field_add, is_negative, mul as field_mul, neg as field_neg, square as field_square,
	sub as field_sub, FIELD_NUM_LIMBS, SQRT_M1_LIMBS,
};
use crate::field_air::{BUS_FIELD_ADD, BUS_U16_RANGE};
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_pow_p58_air::BUS_FIELD_POW_P58;
use crate::field_sub_air::BUS_FIELD_SUB;

/// Service-bus name for this AIR.
pub const BUS_SQRT_RATIO_M1: &str = "rostro-sqrt-ratio-m1";

// ─── Column layout ─────────────────────────────────────────────────────────

pub const COL_U: usize = 0;
pub const COL_V: usize = COL_U + FIELD_NUM_LIMBS;

// Pow chain intermediates.
pub const COL_V2: usize = COL_V + FIELD_NUM_LIMBS;
pub const COL_V3: usize = COL_V2 + FIELD_NUM_LIMBS;
pub const COL_V4: usize = COL_V3 + FIELD_NUM_LIMBS;
pub const COL_V7: usize = COL_V4 + FIELD_NUM_LIMBS;
pub const COL_U_V3: usize = COL_V7 + FIELD_NUM_LIMBS;
pub const COL_U_V7: usize = COL_U_V3 + FIELD_NUM_LIMBS;
pub const COL_U_V7_POW: usize = COL_U_V7 + FIELD_NUM_LIMBS;

// Verification + selection intermediates.
pub const COL_R_RAW: usize = COL_U_V7_POW + FIELD_NUM_LIMBS;
pub const COL_R_RAW_SQ: usize = COL_R_RAW + FIELD_NUM_LIMBS;
pub const COL_CHECK: usize = COL_R_RAW_SQ + FIELD_NUM_LIMBS;
pub const COL_NEG_U: usize = COL_CHECK + FIELD_NUM_LIMBS;
pub const COL_NEG_U_I: usize = COL_NEG_U + FIELD_NUM_LIMBS;
pub const COL_R_RAW_I: usize = COL_NEG_U_I + FIELD_NUM_LIMBS;
pub const COL_R_SELECTED: usize = COL_R_RAW_I + FIELD_NUM_LIMBS;
pub const COL_NEG_R_SELECTED: usize = COL_R_SELECTED + FIELD_NUM_LIMBS;
pub const COL_R: usize = COL_NEG_R_SELECTED + FIELD_NUM_LIMBS;

// Boolean flags + sign indicator (1 cell each).
pub const COL_CORRECT_SIGN: usize = COL_R + FIELD_NUM_LIMBS;
pub const COL_FLIPPED_SIGN: usize = COL_CORRECT_SIGN + 1;
pub const COL_FLIPPED_SIGN_I: usize = COL_FLIPPED_SIGN + 1;
pub const COL_WAS_SQUARE: usize = COL_FLIPPED_SIGN_I + 1;
pub const COL_IS_NEG_R_SELECTED: usize = COL_WAS_SQUARE + 1;

// Zero-test witnesses pinning each flag to its physical equality. Each
// block is: 8 per-limb-zero booleans + 8 per-limb Goldilocks inverses
// (used only when the limb is nonzero) + 1 inverse of the count-of-
// nonzero-limbs (used only when the flag is 0).
pub const COL_LZ_CORRECT: usize = COL_IS_NEG_R_SELECTED + 1;
pub const COL_LINV_CORRECT: usize = COL_LZ_CORRECT + FIELD_NUM_LIMBS;
pub const COL_INV_S_CORRECT: usize = COL_LINV_CORRECT + FIELD_NUM_LIMBS;
pub const COL_LZ_FLIPPED: usize = COL_INV_S_CORRECT + 1;
pub const COL_LINV_FLIPPED: usize = COL_LZ_FLIPPED + FIELD_NUM_LIMBS;
pub const COL_INV_S_FLIPPED: usize = COL_LINV_FLIPPED + FIELD_NUM_LIMBS;
pub const COL_LZ_FLIPPED_I: usize = COL_INV_S_FLIPPED + 1;
pub const COL_LINV_FLIPPED_I: usize = COL_LZ_FLIPPED_I + FIELD_NUM_LIMBS;
pub const COL_INV_S_FLIPPED_I: usize = COL_LINV_FLIPPED_I + FIELD_NUM_LIMBS;

// LSB-tie witnesses for is_neg_r_selected = (r_selected[0] & 1 == 1).
// Decomposes r_selected[0] as `2 * (limb_hi_lo + 65536 * limb_hi_hi) +
// is_neg_r_selected`, with both halves range-checked as u16 on
// `BUS_U16_RANGE`. Because r_selected[0] is already u32-bounded by its
// producer (FieldMulAir output carried in via the field-mul bus), the
// algebra forces the limb_hi half into u31 automatically; the LSB flag
// is then pinned to the actual LSB of r_selected[0].
pub const COL_R_SELECTED_LIMB_HI_LO: usize = COL_INV_S_FLIPPED_I + 1;
pub const COL_R_SELECTED_LIMB_HI_HI: usize = COL_R_SELECTED_LIMB_HI_LO + 1;

pub const SQRT_RATIO_M1_NUM_COLS: usize = COL_R_SELECTED_LIMB_HI_HI + 1;

/// Plonky3 AIR for sqrt_ratio_m1.
#[derive(Clone, Debug, Default)]
pub struct SqrtRatioM1Air;

impl SqrtRatioM1Air {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for SqrtRatioM1Air {
	fn width(&self) -> usize {
		SQRT_RATIO_M1_NUM_COLS
	}
}

fn limbs<AB: AirBuilder>(local: &[AB::Var], off: usize) -> [AB::Var; FIELD_NUM_LIMBS] {
	core::array::from_fn(|i| local[off + i])
}

fn push_mul<AB: InteractionBuilder>(
	builder: &mut AB,
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
	builder.push_interaction(BUS_FIELD_MUL, payload, AB::Expr::ONE, 1);
}

fn push_mul_const_b<AB: InteractionBuilder>(
	builder: &mut AB,
	a: &[AB::Var; FIELD_NUM_LIMBS],
	b_const: &[u32; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	for v in a.iter() {
		payload.push((*v).into());
	}
	for &k in b_const.iter() {
		payload.push(AB::Expr::from_u32(k));
	}
	for v in c.iter() {
		payload.push((*v).into());
	}
	builder.push_interaction(BUS_FIELD_MUL, payload, AB::Expr::ONE, 1);
}

fn push_sub_const_zero_a<AB: InteractionBuilder>(
	builder: &mut AB,
	b: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
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

impl<AB: InteractionBuilder> Air<AB> for SqrtRatioM1Air
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let u = limbs::<AB>(local, COL_U);
		let v = limbs::<AB>(local, COL_V);
		let v2 = limbs::<AB>(local, COL_V2);
		let v3 = limbs::<AB>(local, COL_V3);
		let v4 = limbs::<AB>(local, COL_V4);
		let v7 = limbs::<AB>(local, COL_V7);
		let u_v3 = limbs::<AB>(local, COL_U_V3);
		let u_v7 = limbs::<AB>(local, COL_U_V7);
		let u_v7_pow = limbs::<AB>(local, COL_U_V7_POW);
		let r_raw = limbs::<AB>(local, COL_R_RAW);
		let r_raw_sq = limbs::<AB>(local, COL_R_RAW_SQ);
		let check = limbs::<AB>(local, COL_CHECK);
		let neg_u = limbs::<AB>(local, COL_NEG_U);
		let neg_u_i = limbs::<AB>(local, COL_NEG_U_I);
		let r_raw_i = limbs::<AB>(local, COL_R_RAW_I);
		let r_selected = limbs::<AB>(local, COL_R_SELECTED);
		let neg_r_selected = limbs::<AB>(local, COL_NEG_R_SELECTED);
		let r = limbs::<AB>(local, COL_R);

		let correct_sign: AB::Var = local[COL_CORRECT_SIGN];
		let flipped_sign: AB::Var = local[COL_FLIPPED_SIGN];
		let flipped_sign_i: AB::Var = local[COL_FLIPPED_SIGN_I];
		let was_square: AB::Var = local[COL_WAS_SQUARE];
		let is_neg_r_selected: AB::Var = local[COL_IS_NEG_R_SELECTED];

		// ─── Boolean constraints ──────────────────────────────────────
		builder.assert_bool(correct_sign);
		builder.assert_bool(flipped_sign);
		builder.assert_bool(flipped_sign_i);
		builder.assert_bool(was_square);
		builder.assert_bool(is_neg_r_selected);

		// At most one of (correct_sign, flipped_sign) is set; similarly
		// at most one of (correct_sign, flipped_sign_i). flipped_sign
		// and flipped_sign_i are mutually exclusive too.
		builder.assert_zero(correct_sign.into() * flipped_sign.into());
		builder.assert_zero(correct_sign.into() * flipped_sign_i.into());
		builder.assert_zero(flipped_sign.into() * flipped_sign_i.into());

		// was_square = correct_sign + flipped_sign. (flipped_sign_i
		// alone means the input was a non-square that happened to give
		// a sign-mismatched check; the spec returns the candidate root
		// but marks it as non-square.)
		builder.assert_eq(was_square.into(), correct_sign.into() + flipped_sign.into());

		// ─── Equality enforcement via limb-by-limb gated constraints ──
		// For each of (correct_sign · (check - u) == 0,
		//              flipped_sign · (check - neg_u) == 0,
		//              flipped_sign_i · (check - neg_u_i) == 0)
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(correct_sign.into() * (check[i].into() - u[i].into()));
			builder.assert_zero(flipped_sign.into() * (check[i].into() - neg_u[i].into()));
			builder.assert_zero(flipped_sign_i.into() * (check[i].into() - neg_u_i[i].into()));
		}

		// ─── Pin each flag to its physical equality ───────────────────
		// The gated constraints above prove flag=1 ⇒ check==target. They
		// do NOT prove flag=0 ⇒ check!=target — a malicious prover could
		// claim flag=0 when the equality holds and return arbitrary r.
		// Close that direction here.
		//
		// Per-limb pattern: witness lz[i] (boolean, "diff_i is zero") +
		// linv[i] (Goldilocks inverse of diff_i if diff_i != 0):
		//   lz[i] · diff_i = 0                       (lz=1 ⇒ diff=0)
		//   (1 - lz[i]) · (diff_i · linv[i] - 1) = 0 (lz=0 ⇒ diff≠0)
		// Vector zero: s = Σ (1 - lz[i]) ∈ {0..8}. flag = (s == 0).
		// Witness inv_s (Goldilocks inverse of s when s != 0):
		//   flag · s = 0                       (flag=1 ⇒ s=0 ⇒ check==target)
		//   (1 - flag) · (s · inv_s - 1) = 0   (flag=0 ⇒ s≠0 ⇒ check≠target)
		let lz_c = limbs::<AB>(local, COL_LZ_CORRECT);
		let linv_c = limbs::<AB>(local, COL_LINV_CORRECT);
		let inv_s_c: AB::Var = local[COL_INV_S_CORRECT];
		let lz_f = limbs::<AB>(local, COL_LZ_FLIPPED);
		let linv_f = limbs::<AB>(local, COL_LINV_FLIPPED);
		let inv_s_f: AB::Var = local[COL_INV_S_FLIPPED];
		let lz_fi = limbs::<AB>(local, COL_LZ_FLIPPED_I);
		let linv_fi = limbs::<AB>(local, COL_LINV_FLIPPED_I);
		let inv_s_fi: AB::Var = local[COL_INV_S_FLIPPED_I];

		let mut s_c: AB::Expr = AB::Expr::ZERO;
		let mut s_f: AB::Expr = AB::Expr::ZERO;
		let mut s_fi: AB::Expr = AB::Expr::ZERO;
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_bool(lz_c[i]);
			builder.assert_bool(lz_f[i]);
			builder.assert_bool(lz_fi[i]);

			let d_c: AB::Expr = check[i].into() - u[i].into();
			let d_f: AB::Expr = check[i].into() - neg_u[i].into();
			let d_fi: AB::Expr = check[i].into() - neg_u_i[i].into();

			builder.assert_zero(lz_c[i].into() * d_c.clone());
			builder.assert_zero(lz_f[i].into() * d_f.clone());
			builder.assert_zero(lz_fi[i].into() * d_fi.clone());

			builder.assert_zero(
				(AB::Expr::ONE - lz_c[i].into()) * (d_c * linv_c[i].into() - AB::Expr::ONE),
			);
			builder.assert_zero(
				(AB::Expr::ONE - lz_f[i].into()) * (d_f * linv_f[i].into() - AB::Expr::ONE),
			);
			builder.assert_zero(
				(AB::Expr::ONE - lz_fi[i].into()) * (d_fi * linv_fi[i].into() - AB::Expr::ONE),
			);

			s_c = s_c + (AB::Expr::ONE - lz_c[i].into());
			s_f = s_f + (AB::Expr::ONE - lz_f[i].into());
			s_fi = s_fi + (AB::Expr::ONE - lz_fi[i].into());
		}

		builder.assert_zero(correct_sign.into() * s_c.clone());
		builder.assert_zero(flipped_sign.into() * s_f.clone());
		builder.assert_zero(flipped_sign_i.into() * s_fi.clone());
		builder.assert_zero(
			(AB::Expr::ONE - correct_sign.into()) * (s_c * inv_s_c.into() - AB::Expr::ONE),
		);
		builder.assert_zero(
			(AB::Expr::ONE - flipped_sign.into()) * (s_f * inv_s_f.into() - AB::Expr::ONE),
		);
		builder.assert_zero(
			(AB::Expr::ONE - flipped_sign_i.into())
				* (s_fi * inv_s_fi.into() - AB::Expr::ONE),
		);

		// ─── Selection: r_selected = (flipped + flipped_i) ? r_raw_i : r_raw
		let pick_r_i = flipped_sign.into() + flipped_sign_i.into();
		let one_minus_pick = AB::Expr::ONE - pick_r_i.clone();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				r_selected[i].into()
					- pick_r_i.clone() * r_raw_i[i].into()
					- one_minus_pick.clone() * r_raw[i].into(),
			);
		}

		// ─── Selection: r = is_neg ? neg_r_selected : r_selected
		let one_minus_neg = AB::Expr::ONE - is_neg_r_selected.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				r[i].into()
					- is_neg_r_selected.into() * neg_r_selected[i].into()
					- one_minus_neg.clone() * r_selected[i].into(),
			);
		}

		// ─── LSB-tie: pin `is_neg_r_selected` to the LSB of r_selected[0] ─
		// Without this, the prover could witness either flag value on the
		// same r_selected and pass downstream sign-handling. Decompose
		// r_selected[0] = 2 · (limb_hi_lo + 2^16 · limb_hi_hi) + flag,
		// with both halves range-checked as u16. Together with the
		// upstream u32 bound on r_selected[0] (carried over via the
		// field-mul producer), this forces the flag to equal the actual
		// LSB.
		let r_sel_limb_hi_lo: AB::Var = local[COL_R_SELECTED_LIMB_HI_LO];
		let r_sel_limb_hi_hi: AB::Var = local[COL_R_SELECTED_LIMB_HI_HI];
		let radix_u16 = AB::Expr::from_u64(1u64 << 16);
		let limb_hi_expr = r_sel_limb_hi_lo.into() + r_sel_limb_hi_hi.into() * radix_u16;
		builder.assert_zero(
			r_selected[0].into()
				- (limb_hi_expr * AB::Expr::from_u64(2))
				- is_neg_r_selected.into(),
		);
		builder.push_interaction(BUS_U16_RANGE, [r_sel_limb_hi_lo], AB::Expr::ONE, 1);
		builder.push_interaction(BUS_U16_RANGE, [r_sel_limb_hi_hi], AB::Expr::ONE, 1);

		// ─── Bus queries (consumer side, count = +1) ──────────────────
		// Pow chain:
		push_mul::<AB>(builder, &v, &v, &v2);
		push_mul::<AB>(builder, &v2, &v, &v3);
		push_mul::<AB>(builder, &v2, &v2, &v4);
		push_mul::<AB>(builder, &v4, &v3, &v7);
		push_mul::<AB>(builder, &u, &v3, &u_v3);
		push_mul::<AB>(builder, &u, &v7, &u_v7);
		// pow query: (u_v7, u_v7_pow) on BUS_FIELD_POW_P58 (count = +1).
		let pow_payload: Vec<AB::Expr> = u_v7
			.iter()
			.chain(u_v7_pow.iter())
			.map(|v| (*v).into())
			.collect();
		builder.push_interaction(BUS_FIELD_POW_P58, pow_payload, AB::Expr::ONE, 1);
		push_mul::<AB>(builder, &u_v3, &u_v7_pow, &r_raw);

		// Verification step:
		push_mul::<AB>(builder, &r_raw, &r_raw, &r_raw_sq);
		push_mul::<AB>(builder, &v, &r_raw_sq, &check);

		// Sign handling:
		push_sub_const_zero_a::<AB>(builder, &u, &neg_u);
		push_mul_const_b::<AB>(builder, &neg_u, &SQRT_M1_LIMBS, &neg_u_i);
		push_mul_const_b::<AB>(builder, &r_raw, &SQRT_M1_LIMBS, &r_raw_i);
		push_sub_const_zero_a::<AB>(builder, &r_selected, &neg_r_selected);

		// ─── Service emit on this row, count = -1 ─────────────────────
		// Payload: (u, v, was_square, r) = 8 + 8 + 1 + 8 = 25 cells.
		let mut payload: Vec<AB::Expr> = Vec::with_capacity(25);
		for v in u.iter() {
			payload.push((*v).into());
		}
		for v_ in v.iter() {
			payload.push((*v_).into());
		}
		payload.push(was_square.into());
		for v in r.iter() {
			payload.push((*v).into());
		}
		builder.push_interaction(
			BUS_SQRT_RATIO_M1,
			payload,
			AB::Expr::ZERO - AB::Expr::ONE,
			1,
		);
	}
}

// ─── Witness-side trace builder ────────────────────────────────────────────

/// One row of `SqrtRatioM1Air` witness, in field-element-array form.
#[derive(Clone, Debug)]
pub struct SqrtRatioM1TraceRow {
	pub u: [u32; FIELD_NUM_LIMBS],
	pub v: [u32; FIELD_NUM_LIMBS],
	pub v2: [u32; FIELD_NUM_LIMBS],
	pub v3: [u32; FIELD_NUM_LIMBS],
	pub v4: [u32; FIELD_NUM_LIMBS],
	pub v7: [u32; FIELD_NUM_LIMBS],
	pub u_v3: [u32; FIELD_NUM_LIMBS],
	pub u_v7: [u32; FIELD_NUM_LIMBS],
	pub u_v7_pow: [u32; FIELD_NUM_LIMBS],
	pub r_raw: [u32; FIELD_NUM_LIMBS],
	pub r_raw_sq: [u32; FIELD_NUM_LIMBS],
	pub check: [u32; FIELD_NUM_LIMBS],
	pub neg_u: [u32; FIELD_NUM_LIMBS],
	pub neg_u_i: [u32; FIELD_NUM_LIMBS],
	pub r_raw_i: [u32; FIELD_NUM_LIMBS],
	pub r_selected: [u32; FIELD_NUM_LIMBS],
	pub neg_r_selected: [u32; FIELD_NUM_LIMBS],
	pub r: [u32; FIELD_NUM_LIMBS],
	pub correct_sign: u32,
	pub flipped_sign: u32,
	pub flipped_sign_i: u32,
	pub was_square: u32,
	pub is_neg_r_selected: u32,
	pub lz_correct: [u32; FIELD_NUM_LIMBS],
	pub linv_correct: [u64; FIELD_NUM_LIMBS],
	pub inv_s_correct: u64,
	pub lz_flipped: [u32; FIELD_NUM_LIMBS],
	pub linv_flipped: [u64; FIELD_NUM_LIMBS],
	pub inv_s_flipped: u64,
	pub lz_flipped_i: [u32; FIELD_NUM_LIMBS],
	pub linv_flipped_i: [u64; FIELD_NUM_LIMBS],
	pub inv_s_flipped_i: u64,
	pub r_selected_limb_hi_lo: u32,
	pub r_selected_limb_hi_hi: u32,
}

/// Per-limb zero-test witness for `check == target` as a Goldilocks
/// vector. Returns `(lz, linv, inv_s)` where:
/// - `lz[i] = 1` iff `check[i] == target[i]` (canonical u32 equality);
///   `linv[i]` is `(check[i] - target[i])^{-1}` in Goldilocks when
///   nonzero, else any value (witness ignored under that branch).
/// - `inv_s` is the Goldilocks inverse of `Σ_i (1 - lz[i])` when nonzero,
///   else any value.
fn build_eq_witness(
	check: &[u32; FIELD_NUM_LIMBS],
	target: &[u32; FIELD_NUM_LIMBS],
) -> ([u32; FIELD_NUM_LIMBS], [u64; FIELD_NUM_LIMBS], u64) {
	let mut lz = [0u32; FIELD_NUM_LIMBS];
	let mut linv = [0u64; FIELD_NUM_LIMBS];
	let mut s_count: u64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let diff = Goldilocks::from_u64(u64::from(check[i]))
			- Goldilocks::from_u64(u64::from(target[i]));
		if diff == Goldilocks::ZERO {
			lz[i] = 1;
		} else {
			lz[i] = 0;
			linv[i] = diff.inverse().as_canonical_u64();
			s_count += 1;
		}
	}
	let inv_s = if s_count == 0 {
		0
	} else {
		Goldilocks::from_u64(s_count).inverse().as_canonical_u64()
	};
	(lz, linv, inv_s)
}

pub fn build_sqrt_ratio_m1_trace_row(
	u: &[u32; FIELD_NUM_LIMBS],
	v: &[u32; FIELD_NUM_LIMBS],
) -> SqrtRatioM1TraceRow {
	let v2 = field_square(v);
	let v3 = field_mul(&v2, v);
	let v4 = field_square(&v2);
	let v7 = field_mul(&v4, &v3);
	let u_v3 = field_mul(u, &v3);
	let u_v7 = field_mul(u, &v7);
	let u_v7_pow = crate::field::pow_p_minus_5_div_8(&u_v7);
	let r_raw = field_mul(&u_v3, &u_v7_pow);

	let r_raw_sq = field_square(&r_raw);
	let check = field_mul(v, &r_raw_sq);

	let neg_u = field_neg(u);
	let neg_u_i = field_mul(&neg_u, &SQRT_M1_LIMBS);
	let r_raw_i = field_mul(&r_raw, &SQRT_M1_LIMBS);

	let correct_sign = check == *u;
	let flipped_sign = check == neg_u;
	let flipped_sign_i = check == neg_u_i;
	let was_square = correct_sign || flipped_sign;

	let pick_r_i = flipped_sign || flipped_sign_i;
	let r_selected = if pick_r_i { r_raw_i } else { r_raw };
	let neg_r_selected = field_neg(&r_selected);

	let is_neg_r_selected = is_negative(&r_selected);
	let r = if is_neg_r_selected { neg_r_selected } else { r_selected };

	let (lz_correct, linv_correct, inv_s_correct) = build_eq_witness(&check, u);
	let (lz_flipped, linv_flipped, inv_s_flipped) = build_eq_witness(&check, &neg_u);
	let (lz_flipped_i, linv_flipped_i, inv_s_flipped_i) = build_eq_witness(&check, &neg_u_i);

	// LSB-tie witness for is_neg_r_selected: limb_hi = (r_selected[0] -
	// flag) / 2, split into two u16 halves.
	let limb0 = r_selected[0];
	let is_neg = u32::from(is_neg_r_selected);
	let limb_hi = (limb0 - is_neg) / 2;
	let r_selected_limb_hi_lo = limb_hi & 0xFFFF;
	let r_selected_limb_hi_hi = limb_hi >> 16;

	SqrtRatioM1TraceRow {
		u: *u,
		v: *v,
		v2,
		v3,
		v4,
		v7,
		u_v3,
		u_v7,
		u_v7_pow,
		r_raw,
		r_raw_sq,
		check,
		neg_u,
		neg_u_i,
		r_raw_i,
		r_selected,
		neg_r_selected,
		r,
		correct_sign: u32::from(correct_sign),
		flipped_sign: u32::from(flipped_sign),
		flipped_sign_i: u32::from(flipped_sign_i),
		was_square: u32::from(was_square),
		is_neg_r_selected: u32::from(is_neg_r_selected),
		lz_correct,
		linv_correct,
		inv_s_correct,
		lz_flipped,
		linv_flipped,
		inv_s_flipped,
		lz_flipped_i,
		linv_flipped_i,
		inv_s_flipped_i,
		r_selected_limb_hi_lo,
		r_selected_limb_hi_hi,
	}
}

impl SqrtRatioM1TraceRow {
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(SQRT_RATIO_M1_NUM_COLS);
		for &v in &self.u {
			out.push(F::from_u32(v));
		}
		for &v in &self.v {
			out.push(F::from_u32(v));
		}
		for limbs in [
			&self.v2,
			&self.v3,
			&self.v4,
			&self.v7,
			&self.u_v3,
			&self.u_v7,
			&self.u_v7_pow,
			&self.r_raw,
			&self.r_raw_sq,
			&self.check,
			&self.neg_u,
			&self.neg_u_i,
			&self.r_raw_i,
			&self.r_selected,
			&self.neg_r_selected,
			&self.r,
		] {
			for &v in limbs {
				out.push(F::from_u32(v));
			}
		}
		out.push(F::from_u32(self.correct_sign));
		out.push(F::from_u32(self.flipped_sign));
		out.push(F::from_u32(self.flipped_sign_i));
		out.push(F::from_u32(self.was_square));
		out.push(F::from_u32(self.is_neg_r_selected));
		for (lz, linv, inv_s) in [
			(&self.lz_correct, &self.linv_correct, self.inv_s_correct),
			(&self.lz_flipped, &self.linv_flipped, self.inv_s_flipped),
			(&self.lz_flipped_i, &self.linv_flipped_i, self.inv_s_flipped_i),
		] {
			for &b in lz {
				out.push(F::from_u32(b));
			}
			for &x in linv {
				out.push(F::from_u64(x));
			}
			out.push(F::from_u64(inv_s));
		}
		out.push(F::from_u32(self.r_selected_limb_hi_lo));
		out.push(F::from_u32(self.r_selected_limb_hi_hi));
		debug_assert_eq!(out.len(), SQRT_RATIO_M1_NUM_COLS);
		out
	}

	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), SQRT_RATIO_M1_NUM_COLS)
	}
}

// Silence unused-import warnings: field_add is used only via re-export chains
// for downstream code paths; pull in via `let _` so the import survives.
#[allow(dead_code)]
fn _force_use() {
	let _ = field_add;
	let _ = field_sub;
	let _: &'static str = BUS_FIELD_ADD;
}
