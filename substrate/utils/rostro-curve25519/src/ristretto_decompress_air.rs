// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for [`crate::ristretto::decompress`].
//!
//! Single-row AIR. Consumer of field-op + sqrt-ratio-m1 service buses.
//! Provider on [`BUS_RISTRETTO_DECOMPRESS`] with payload
//! `(s, X, Y, Z, T, is_valid)` = 8·5 + 1 = 41 cells.
//!
//! ## Pre-condition: canonical, LSB-positive s
//!
//! The caller is responsible for verifying that `s` is canonical
//! (value < p) and LSB-positive (low bit = 0). Those two rejection
//! conditions of the Ristretto255 spec live at the chain boundary,
//! not inside this AIR. The AIR's `is_valid` flag covers only the
//! remaining cases: `was_square` of the sqrt, `is_t_neg` of the
//! recovered T, and `is_y_zero`.
//!
//! ## v0 soundness gaps
//!
//! - `x_is_neg`, `is_t_neg`, `is_y_zero` are witnessed booleans without
//!   the LSB-tie / inverse-witness round-trip. A malicious prover could
//!   produce a y = 0 trace but claim is_y_zero = 0 to forge `is_valid =
//!   1` on a torsion-point encoding. Tracked in the follow-up todo.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::{
	add as field_add, is_negative, is_zero, mul as field_mul, neg as field_neg,
	square as field_square, sub as field_sub, FIELD_NUM_LIMBS,
};
use crate::field_air::BUS_FIELD_ADD;
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_sub_air::BUS_FIELD_SUB;
use crate::point::ED25519_D_LIMBS;
use crate::sqrt_ratio_m1_air::BUS_SQRT_RATIO_M1;

pub const BUS_RISTRETTO_DECOMPRESS: &str = "rostro-ristretto-decompress";

// ─── Column layout ─────────────────────────────────────────────────────────

pub const COL_S: usize = 0;
pub const COL_SS: usize = COL_S + FIELD_NUM_LIMBS;
pub const COL_U1: usize = COL_SS + FIELD_NUM_LIMBS;
pub const COL_U2: usize = COL_U1 + FIELD_NUM_LIMBS;
pub const COL_U2_SQ: usize = COL_U2 + FIELD_NUM_LIMBS;
pub const COL_U1_SQ: usize = COL_U2_SQ + FIELD_NUM_LIMBS;
pub const COL_D_U1_SQ: usize = COL_U1_SQ + FIELD_NUM_LIMBS;
pub const COL_NEG_D_U1_SQ: usize = COL_D_U1_SQ + FIELD_NUM_LIMBS;
pub const COL_V: usize = COL_NEG_D_U1_SQ + FIELD_NUM_LIMBS;
pub const COL_V_U2_SQ: usize = COL_V + FIELD_NUM_LIMBS;
pub const COL_BIG_I: usize = COL_V_U2_SQ + FIELD_NUM_LIMBS;
pub const COL_DX: usize = COL_BIG_I + FIELD_NUM_LIMBS;
pub const COL_DX_V: usize = COL_DX + FIELD_NUM_LIMBS;
pub const COL_DY: usize = COL_DX_V + FIELD_NUM_LIMBS;
pub const COL_TWO_S: usize = COL_DY + FIELD_NUM_LIMBS;
pub const COL_X_RAW: usize = COL_TWO_S + FIELD_NUM_LIMBS;
pub const COL_NEG_X_RAW: usize = COL_X_RAW + FIELD_NUM_LIMBS;
pub const COL_X: usize = COL_NEG_X_RAW + FIELD_NUM_LIMBS;
pub const COL_Y: usize = COL_X + FIELD_NUM_LIMBS;
pub const COL_Z: usize = COL_Y + FIELD_NUM_LIMBS;
pub const COL_T: usize = COL_Z + FIELD_NUM_LIMBS;

pub const COL_WAS_SQUARE: usize = COL_T + FIELD_NUM_LIMBS;
pub const COL_X_IS_NEG: usize = COL_WAS_SQUARE + 1;
pub const COL_IS_T_NEG: usize = COL_X_IS_NEG + 1;
pub const COL_IS_Y_ZERO: usize = COL_IS_T_NEG + 1;
pub const COL_IS_VALID: usize = COL_IS_Y_ZERO + 1;
pub const COL_NOT_T_NEG: usize = COL_IS_VALID + 1;
pub const COL_NOT_Y_ZERO: usize = COL_NOT_T_NEG + 1;
pub const COL_INTERMEDIATE_VALID: usize = COL_NOT_Y_ZERO + 1;

pub const RISTRETTO_DECOMPRESS_NUM_COLS: usize = COL_INTERMEDIATE_VALID + 1;

#[derive(Clone, Debug, Default)]
pub struct RistrettoDecompressAir;

impl RistrettoDecompressAir {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for RistrettoDecompressAir {
	fn width(&self) -> usize {
		RISTRETTO_DECOMPRESS_NUM_COLS
	}
}

fn limbs<AB: AirBuilder>(local: &[AB::Var], off: usize) -> [AB::Var; FIELD_NUM_LIMBS] {
	core::array::from_fn(|i| local[off + i])
}

fn push_field_op_var<AB: InteractionBuilder>(
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

fn push_op_const_a<AB: InteractionBuilder>(
	builder: &mut AB,
	bus: &'static str,
	a_const_first: AB::Expr,
	b: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	payload.push(a_const_first);
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

fn push_sub_zero_a<AB: InteractionBuilder>(
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

impl<AB: InteractionBuilder> Air<AB> for RistrettoDecompressAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let s = limbs::<AB>(local, COL_S);
		let ss = limbs::<AB>(local, COL_SS);
		let u1 = limbs::<AB>(local, COL_U1);
		let u2 = limbs::<AB>(local, COL_U2);
		let u2_sq = limbs::<AB>(local, COL_U2_SQ);
		let u1_sq = limbs::<AB>(local, COL_U1_SQ);
		let d_u1_sq = limbs::<AB>(local, COL_D_U1_SQ);
		let neg_d_u1_sq = limbs::<AB>(local, COL_NEG_D_U1_SQ);
		let v = limbs::<AB>(local, COL_V);
		let v_u2_sq = limbs::<AB>(local, COL_V_U2_SQ);
		let big_i = limbs::<AB>(local, COL_BIG_I);
		let dx = limbs::<AB>(local, COL_DX);
		let dx_v = limbs::<AB>(local, COL_DX_V);
		let dy = limbs::<AB>(local, COL_DY);
		let two_s = limbs::<AB>(local, COL_TWO_S);
		let x_raw = limbs::<AB>(local, COL_X_RAW);
		let neg_x_raw = limbs::<AB>(local, COL_NEG_X_RAW);
		let x = limbs::<AB>(local, COL_X);
		let y = limbs::<AB>(local, COL_Y);
		let z = limbs::<AB>(local, COL_Z);
		let t = limbs::<AB>(local, COL_T);

		let was_square: AB::Var = local[COL_WAS_SQUARE];
		let x_is_neg: AB::Var = local[COL_X_IS_NEG];
		let is_t_neg: AB::Var = local[COL_IS_T_NEG];
		let is_y_zero: AB::Var = local[COL_IS_Y_ZERO];
		let is_valid: AB::Var = local[COL_IS_VALID];
		let not_t_neg: AB::Var = local[COL_NOT_T_NEG];
		let not_y_zero: AB::Var = local[COL_NOT_Y_ZERO];
		let intermediate_valid: AB::Var = local[COL_INTERMEDIATE_VALID];

		builder.assert_bool(was_square);
		builder.assert_bool(x_is_neg);
		builder.assert_bool(is_t_neg);
		builder.assert_bool(is_y_zero);
		builder.assert_bool(is_valid);

		// not_t_neg == 1 - is_t_neg; not_y_zero == 1 - is_y_zero.
		builder.assert_eq(not_t_neg.into(), AB::Expr::ONE - is_t_neg.into());
		builder.assert_eq(not_y_zero.into(), AB::Expr::ONE - is_y_zero.into());

		// intermediate_valid = was_square · not_t_neg (deg-2). Then
		// is_valid = intermediate_valid · not_y_zero (deg-2). Splitting
		// into two deg-2 constraints keeps each constraint shallow.
		builder.assert_eq(intermediate_valid.into(), was_square.into() * not_t_neg.into());
		builder.assert_eq(is_valid.into(), intermediate_valid.into() * not_y_zero.into());

		// Selection: x = x_is_neg ? neg_x_raw : x_raw.
		let one_minus_xn = AB::Expr::ONE - x_is_neg.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				x[i].into()
					- x_is_neg.into() * neg_x_raw[i].into()
					- one_minus_xn.clone() * x_raw[i].into(),
			);
		}

		// z is the constant 1.
		for i in 0..FIELD_NUM_LIMBS {
			if i == 0 {
				builder.assert_eq(z[i], AB::Expr::ONE);
			} else {
				builder.assert_zero(z[i]);
			}
		}

		// Gated zero-witness: is_y_zero · y[i] == 0 for each i.
		// (Direction: flag set ⇒ y limbs all zero. The reverse direction
		// is the v0 soundness gap noted in the module docstring.)
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(is_y_zero.into() * y[i].into());
		}

		// ─── Bus queries (consumer side, count = +1) ──────────────────
		// mul: (s, s, ss)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &s, &s, &ss);
		// sub: (1, ss, u1) — constant a slot = 1.
		push_op_const_a::<AB>(builder, BUS_FIELD_SUB, AB::Expr::ONE, &ss, &u1);
		// add: (1, ss, u2) — constant a slot = 1.
		push_op_const_a::<AB>(builder, BUS_FIELD_ADD, AB::Expr::ONE, &ss, &u2);
		// mul: (u2, u2, u2_sq)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &u2, &u2, &u2_sq);
		// mul: (u1, u1, u1_sq)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &u1, &u1, &u1_sq);
		// mul: (ED25519_D, u1_sq, d_u1_sq) — constant a slot.
		push_mul_const_a_limbs::<AB>(builder, &ED25519_D_LIMBS, &u1_sq, &d_u1_sq);
		// sub: (0, d_u1_sq, neg_d_u1_sq) — zero constant a.
		push_sub_zero_a::<AB>(builder, &d_u1_sq, &neg_d_u1_sq);
		// sub: (neg_d_u1_sq, u2_sq, v)
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &neg_d_u1_sq, &u2_sq, &v);
		// mul: (v, u2_sq, v_u2_sq)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &v, &u2_sq, &v_u2_sq);

		// sqrt-ratio-m1: (1, v_u2_sq, was_square, big_i).
		let mut sqrt_payload: Vec<AB::Expr> = Vec::with_capacity(25);
		sqrt_payload.push(AB::Expr::ONE);
		for _ in 1..FIELD_NUM_LIMBS {
			sqrt_payload.push(AB::Expr::ZERO);
		}
		for vv in v_u2_sq.iter() {
			sqrt_payload.push((*vv).into());
		}
		sqrt_payload.push(was_square.into());
		for vv in big_i.iter() {
			sqrt_payload.push((*vv).into());
		}
		builder.push_interaction(BUS_SQRT_RATIO_M1, sqrt_payload, AB::Expr::ONE, 1);

		// mul: (big_i, u2, dx)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &big_i, &u2, &dx);
		// mul: (dx, v, dx_v)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &dx, &v, &dx_v);
		// mul: (big_i, dx_v, dy)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &big_i, &dx_v, &dy);
		// add: (s, s, two_s)
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &s, &s, &two_s);
		// mul: (two_s, dx, x_raw)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &two_s, &dx, &x_raw);
		// sub: (0, x_raw, neg_x_raw)
		push_sub_zero_a::<AB>(builder, &x_raw, &neg_x_raw);
		// mul: (u1, dy, y)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &u1, &dy, &y);
		// mul: (x, y, t)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &x, &y, &t);

		// ─── Service emit on this row (count = -1) ────────────────────
		// Payload: (s, X, Y, Z, T, is_valid) = 5×8 + 1 = 41 cells.
		let mut payload: Vec<AB::Expr> = Vec::with_capacity(41);
		for vv in s.iter() {
			payload.push((*vv).into());
		}
		for vv in x.iter() {
			payload.push((*vv).into());
		}
		for vv in y.iter() {
			payload.push((*vv).into());
		}
		for vv in z.iter() {
			payload.push((*vv).into());
		}
		for vv in t.iter() {
			payload.push((*vv).into());
		}
		payload.push(is_valid.into());
		builder.push_interaction(
			BUS_RISTRETTO_DECOMPRESS,
			payload,
			AB::Expr::ZERO - AB::Expr::ONE,
			1,
		);
	}
}

// ─── Witness-side trace builder ────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RistrettoDecompressTraceRow {
	pub s: [u32; FIELD_NUM_LIMBS],
	pub ss: [u32; FIELD_NUM_LIMBS],
	pub u1: [u32; FIELD_NUM_LIMBS],
	pub u2: [u32; FIELD_NUM_LIMBS],
	pub u2_sq: [u32; FIELD_NUM_LIMBS],
	pub u1_sq: [u32; FIELD_NUM_LIMBS],
	pub d_u1_sq: [u32; FIELD_NUM_LIMBS],
	pub neg_d_u1_sq: [u32; FIELD_NUM_LIMBS],
	pub v: [u32; FIELD_NUM_LIMBS],
	pub v_u2_sq: [u32; FIELD_NUM_LIMBS],
	pub big_i: [u32; FIELD_NUM_LIMBS],
	pub dx: [u32; FIELD_NUM_LIMBS],
	pub dx_v: [u32; FIELD_NUM_LIMBS],
	pub dy: [u32; FIELD_NUM_LIMBS],
	pub two_s: [u32; FIELD_NUM_LIMBS],
	pub x_raw: [u32; FIELD_NUM_LIMBS],
	pub neg_x_raw: [u32; FIELD_NUM_LIMBS],
	pub x: [u32; FIELD_NUM_LIMBS],
	pub y: [u32; FIELD_NUM_LIMBS],
	pub z: [u32; FIELD_NUM_LIMBS],
	pub t: [u32; FIELD_NUM_LIMBS],
	pub was_square: u32,
	pub x_is_neg: u32,
	pub is_t_neg: u32,
	pub is_y_zero: u32,
	pub is_valid: u32,
}

pub fn build_ristretto_decompress_trace_row(s: &[u32; FIELD_NUM_LIMBS]) -> RistrettoDecompressTraceRow {
	let mut one_limbs = [0u32; FIELD_NUM_LIMBS];
	one_limbs[0] = 1;

	let ss = field_square(s);
	let u1 = field_sub(&one_limbs, &ss);
	let u2 = field_add(&one_limbs, &ss);
	let u2_sq = field_square(&u2);
	let u1_sq = field_square(&u1);
	let d_u1_sq = field_mul(&ED25519_D_LIMBS, &u1_sq);
	let neg_d_u1_sq = field_neg(&d_u1_sq);
	let v = field_sub(&neg_d_u1_sq, &u2_sq);
	let v_u2_sq = field_mul(&v, &u2_sq);
	let (was_square, big_i) = crate::field::sqrt_ratio_m1(&one_limbs, &v_u2_sq);

	let dx = field_mul(&big_i, &u2);
	let dx_v = field_mul(&dx, &v);
	let dy = field_mul(&big_i, &dx_v);
	let two_s = field_add(s, s);
	let x_raw = field_mul(&two_s, &dx);
	let neg_x_raw = field_neg(&x_raw);
	let x_is_neg = is_negative(&x_raw);
	let x = if x_is_neg { neg_x_raw } else { x_raw };
	let y = field_mul(&u1, &dy);
	let t = field_mul(&x, &y);
	let is_t_neg = is_negative(&t);
	let is_y_zero = is_zero(&y);

	let is_valid = was_square && !is_t_neg && !is_y_zero;

	let z = one_limbs;

	RistrettoDecompressTraceRow {
		s: *s,
		ss,
		u1,
		u2,
		u2_sq,
		u1_sq,
		d_u1_sq,
		neg_d_u1_sq,
		v,
		v_u2_sq,
		big_i,
		dx,
		dx_v,
		dy,
		two_s,
		x_raw,
		neg_x_raw,
		x,
		y,
		z,
		t,
		was_square: u32::from(was_square),
		x_is_neg: u32::from(x_is_neg),
		is_t_neg: u32::from(is_t_neg),
		is_y_zero: u32::from(is_y_zero),
		is_valid: u32::from(is_valid),
	}
}

impl RistrettoDecompressTraceRow {
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(RISTRETTO_DECOMPRESS_NUM_COLS);
		for limbs in [
			&self.s,
			&self.ss,
			&self.u1,
			&self.u2,
			&self.u2_sq,
			&self.u1_sq,
			&self.d_u1_sq,
			&self.neg_d_u1_sq,
			&self.v,
			&self.v_u2_sq,
			&self.big_i,
			&self.dx,
			&self.dx_v,
			&self.dy,
			&self.two_s,
			&self.x_raw,
			&self.neg_x_raw,
			&self.x,
			&self.y,
			&self.z,
			&self.t,
		] {
			for &v in limbs {
				out.push(F::from_u32(v));
			}
		}
		out.push(F::from_u32(self.was_square));
		out.push(F::from_u32(self.x_is_neg));
		out.push(F::from_u32(self.is_t_neg));
		out.push(F::from_u32(self.is_y_zero));
		out.push(F::from_u32(self.is_valid));
		out.push(F::from_u32(1 - self.is_t_neg));
		out.push(F::from_u32(1 - self.is_y_zero));
		out.push(F::from_u32(self.was_square * (1 - self.is_t_neg)));
		debug_assert_eq!(out.len(), RISTRETTO_DECOMPRESS_NUM_COLS);
		out
	}

	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), RISTRETTO_DECOMPRESS_NUM_COLS)
	}
}
