// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for [`crate::ristretto::compress`].
//!
//! Single-row AIR. Consumer of field-op + sqrt-ratio-m1 service buses.
//! Provider on [`BUS_RISTRETTO_COMPRESS`] with payload
//! `(X, Y, Z, T, s)` = 5 × 8 = 40 cells.
//!
//! Output `s` is the LSB-positive canonical-form field element whose
//! 32-byte LE encoding IS the Ristretto255 32-byte canonical encoding.
//! Byte-level encoding (limbs ↔ bytes) is a no-op transformation at
//! the protocol boundary and is not enforced inside this AIR.
//!
//! ## Soundness gaps (v0)
//!
//! Three `is_negative` flags — `rotate`, `sign_y_prime`, `sign_s` —
//! are witnessed booleans without LSB-tie constraints. Same v0 limitation
//! as in `SqrtRatioM1Air`; tracked as a follow-up.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::{
	add as field_add, is_negative, mul as field_mul, neg as field_neg, square as field_square,
	sub as field_sub, FIELD_NUM_LIMBS, SQRT_M1_LIMBS,
};
use crate::field_air::BUS_FIELD_ADD;
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_sub_air::BUS_FIELD_SUB;
use crate::point::EdwardsPoint;
use crate::ristretto::INVSQRT_A_MINUS_D_LIMBS;
use crate::sqrt_ratio_m1_air::BUS_SQRT_RATIO_M1;

/// Service-bus name for this AIR.
pub const BUS_RISTRETTO_COMPRESS: &str = "rostro-ristretto-compress";

// ─── Column layout ─────────────────────────────────────────────────────────
//
// One row per compress invocation. Columns laid out in formula-order so
// the trace builder is straightforward.

pub const COL_X: usize = 0;
pub const COL_Y: usize = COL_X + FIELD_NUM_LIMBS;
pub const COL_Z: usize = COL_Y + FIELD_NUM_LIMBS;
pub const COL_T: usize = COL_Z + FIELD_NUM_LIMBS;

pub const COL_Z_PLUS_Y: usize = COL_T + FIELD_NUM_LIMBS;
pub const COL_Z_MINUS_Y_FOR_U1: usize = COL_Z_PLUS_Y + FIELD_NUM_LIMBS;
pub const COL_U1: usize = COL_Z_MINUS_Y_FOR_U1 + FIELD_NUM_LIMBS;
pub const COL_U2: usize = COL_U1 + FIELD_NUM_LIMBS;
pub const COL_U2_SQ: usize = COL_U2 + FIELD_NUM_LIMBS;
pub const COL_U1_U2_SQ: usize = COL_U2_SQ + FIELD_NUM_LIMBS;
pub const COL_INVSQRT: usize = COL_U1_U2_SQ + FIELD_NUM_LIMBS;
pub const COL_D1: usize = COL_INVSQRT + FIELD_NUM_LIMBS;
pub const COL_D2: usize = COL_D1 + FIELD_NUM_LIMBS;
pub const COL_D1_D2: usize = COL_D2 + FIELD_NUM_LIMBS;
pub const COL_ZINV: usize = COL_D1_D2 + FIELD_NUM_LIMBS;
pub const COL_T_ZINV: usize = COL_ZINV + FIELD_NUM_LIMBS;
pub const COL_Y_SQRT_M1: usize = COL_T_ZINV + FIELD_NUM_LIMBS;
pub const COL_X_SQRT_M1: usize = COL_Y_SQRT_M1 + FIELD_NUM_LIMBS;
pub const COL_D1_INVSQRT: usize = COL_X_SQRT_M1 + FIELD_NUM_LIMBS;
pub const COL_X_PRIME: usize = COL_D1_INVSQRT + FIELD_NUM_LIMBS;
pub const COL_Y_PRIME: usize = COL_X_PRIME + FIELD_NUM_LIMBS;
pub const COL_D_PRIME: usize = COL_Y_PRIME + FIELD_NUM_LIMBS;
pub const COL_X_PRIME_ZINV: usize = COL_D_PRIME + FIELD_NUM_LIMBS;
pub const COL_NEG_Y_PRIME: usize = COL_X_PRIME_ZINV + FIELD_NUM_LIMBS;
pub const COL_Y_PRIME_SIGNED: usize = COL_NEG_Y_PRIME + FIELD_NUM_LIMBS;
pub const COL_Z_MINUS_Y_SIGNED: usize = COL_Y_PRIME_SIGNED + FIELD_NUM_LIMBS;
pub const COL_S_RAW: usize = COL_Z_MINUS_Y_SIGNED + FIELD_NUM_LIMBS;
pub const COL_NEG_S_RAW: usize = COL_S_RAW + FIELD_NUM_LIMBS;
pub const COL_S: usize = COL_NEG_S_RAW + FIELD_NUM_LIMBS;

pub const COL_ROTATE: usize = COL_S + FIELD_NUM_LIMBS;
pub const COL_SIGN_Y_PRIME: usize = COL_ROTATE + 1;
pub const COL_SIGN_S: usize = COL_SIGN_Y_PRIME + 1;
pub const COL_INVSQRT_WAS_SQ: usize = COL_SIGN_S + 1;

pub const RISTRETTO_COMPRESS_NUM_COLS: usize = COL_INVSQRT_WAS_SQ + 1;

/// Plonky3 AIR for Ristretto255 compress.
#[derive(Clone, Debug, Default)]
pub struct RistrettoCompressAir;

impl RistrettoCompressAir {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for RistrettoCompressAir {
	fn width(&self) -> usize {
		RISTRETTO_COMPRESS_NUM_COLS
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

impl<AB: InteractionBuilder> Air<AB> for RistrettoCompressAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let x = limbs::<AB>(local, COL_X);
		let y = limbs::<AB>(local, COL_Y);
		let z = limbs::<AB>(local, COL_Z);
		let t = limbs::<AB>(local, COL_T);
		let z_plus_y = limbs::<AB>(local, COL_Z_PLUS_Y);
		let z_minus_y_for_u1 = limbs::<AB>(local, COL_Z_MINUS_Y_FOR_U1);
		let u1 = limbs::<AB>(local, COL_U1);
		let u2 = limbs::<AB>(local, COL_U2);
		let u2_sq = limbs::<AB>(local, COL_U2_SQ);
		let u1_u2_sq = limbs::<AB>(local, COL_U1_U2_SQ);
		let invsqrt = limbs::<AB>(local, COL_INVSQRT);
		let d1 = limbs::<AB>(local, COL_D1);
		let d2 = limbs::<AB>(local, COL_D2);
		let d1_d2 = limbs::<AB>(local, COL_D1_D2);
		let zinv = limbs::<AB>(local, COL_ZINV);
		let t_zinv = limbs::<AB>(local, COL_T_ZINV);
		let y_sqrt_m1 = limbs::<AB>(local, COL_Y_SQRT_M1);
		let x_sqrt_m1 = limbs::<AB>(local, COL_X_SQRT_M1);
		let d1_invsqrt = limbs::<AB>(local, COL_D1_INVSQRT);
		let x_prime = limbs::<AB>(local, COL_X_PRIME);
		let y_prime = limbs::<AB>(local, COL_Y_PRIME);
		let d_prime = limbs::<AB>(local, COL_D_PRIME);
		let x_prime_zinv = limbs::<AB>(local, COL_X_PRIME_ZINV);
		let neg_y_prime = limbs::<AB>(local, COL_NEG_Y_PRIME);
		let y_prime_signed = limbs::<AB>(local, COL_Y_PRIME_SIGNED);
		let z_minus_y_signed = limbs::<AB>(local, COL_Z_MINUS_Y_SIGNED);
		let s_raw = limbs::<AB>(local, COL_S_RAW);
		let neg_s_raw = limbs::<AB>(local, COL_NEG_S_RAW);
		let s = limbs::<AB>(local, COL_S);

		let rotate: AB::Var = local[COL_ROTATE];
		let sign_y_prime: AB::Var = local[COL_SIGN_Y_PRIME];
		let sign_s: AB::Var = local[COL_SIGN_S];
		let invsqrt_was_sq: AB::Var = local[COL_INVSQRT_WAS_SQ];

		builder.assert_bool(rotate);
		builder.assert_bool(sign_y_prime);
		builder.assert_bool(sign_s);
		builder.assert_bool(invsqrt_was_sq);

		// Selection: x_prime = rotate ? y_sqrt_m1 : x
		//            y_prime = rotate ? x_sqrt_m1 : y
		//            d_prime = rotate ? d1_invsqrt : d2
		let one_minus_rotate = AB::Expr::ONE - rotate.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				x_prime[i].into()
					- rotate.into() * y_sqrt_m1[i].into()
					- one_minus_rotate.clone() * x[i].into(),
			);
			builder.assert_zero(
				y_prime[i].into()
					- rotate.into() * x_sqrt_m1[i].into()
					- one_minus_rotate.clone() * y[i].into(),
			);
			builder.assert_zero(
				d_prime[i].into()
					- rotate.into() * d1_invsqrt[i].into()
					- one_minus_rotate.clone() * d2[i].into(),
			);
		}

		// Selection: y_prime_signed = sign_y_prime ? neg_y_prime : y_prime
		let one_minus_syp = AB::Expr::ONE - sign_y_prime.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				y_prime_signed[i].into()
					- sign_y_prime.into() * neg_y_prime[i].into()
					- one_minus_syp.clone() * y_prime[i].into(),
			);
		}

		// Selection: s = sign_s ? neg_s_raw : s_raw
		let one_minus_ss = AB::Expr::ONE - sign_s.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				s[i].into()
					- sign_s.into() * neg_s_raw[i].into()
					- one_minus_ss.clone() * s_raw[i].into(),
			);
		}

		// ─── Bus queries ──────────────────────────────────────────────
		// add: (Z, Y, z_plus_y)
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &z, &y, &z_plus_y);
		// sub: (Z, Y, z_minus_y_for_u1)
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &z, &y, &z_minus_y_for_u1);
		// mul: (z_plus_y, z_minus_y_for_u1, u1)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &z_plus_y, &z_minus_y_for_u1, &u1);
		// mul: (X, Y, u2)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &x, &y, &u2);
		// mul: (u2, u2, u2_sq)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &u2, &u2, &u2_sq);
		// mul: (u1, u2_sq, u1_u2_sq)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &u1, &u2_sq, &u1_u2_sq);

		// sqrt-ratio-m1: (1, u1_u2_sq, invsqrt_was_sq, invsqrt)
		let mut sqrt_payload: Vec<AB::Expr> = Vec::with_capacity(25);
		// u-slot: the constant 1.
		sqrt_payload.push(AB::Expr::ONE);
		for _ in 1..FIELD_NUM_LIMBS {
			sqrt_payload.push(AB::Expr::ZERO);
		}
		// v-slot: u1_u2_sq.
		for v in u1_u2_sq.iter() {
			sqrt_payload.push((*v).into());
		}
		// was_square + r.
		sqrt_payload.push(invsqrt_was_sq.into());
		for v in invsqrt.iter() {
			sqrt_payload.push((*v).into());
		}
		builder.push_interaction(BUS_SQRT_RATIO_M1, sqrt_payload, AB::Expr::ONE, 1);

		// mul: (invsqrt, u1, d1)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &invsqrt, &u1, &d1);
		// mul: (invsqrt, u2, d2)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &invsqrt, &u2, &d2);
		// mul: (d1, d2, d1_d2)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &d1, &d2, &d1_d2);
		// mul: (d1_d2, T, zinv)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &d1_d2, &t, &zinv);
		// mul: (T, zinv, t_zinv)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &t, &zinv, &t_zinv);

		// mul: (Y, SQRT_M1, y_sqrt_m1) — constant b.
		push_mul_const_b::<AB>(builder, &y, &SQRT_M1_LIMBS, &y_sqrt_m1);
		// mul: (X, SQRT_M1, x_sqrt_m1).
		push_mul_const_b::<AB>(builder, &x, &SQRT_M1_LIMBS, &x_sqrt_m1);
		// mul: (d1, INVSQRT_A_MINUS_D, d1_invsqrt).
		push_mul_const_b::<AB>(builder, &d1, &INVSQRT_A_MINUS_D_LIMBS, &d1_invsqrt);

		// mul: (x_prime, zinv, x_prime_zinv)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &x_prime, &zinv, &x_prime_zinv);
		// sub: (0, y_prime, neg_y_prime)
		push_sub_const_zero_a::<AB>(builder, &y_prime, &neg_y_prime);
		// sub: (Z, y_prime_signed, z_minus_y_signed)
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &z, &y_prime_signed, &z_minus_y_signed);
		// mul: (d_prime, z_minus_y_signed, s_raw)
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &d_prime, &z_minus_y_signed, &s_raw);
		// sub: (0, s_raw, neg_s_raw)
		push_sub_const_zero_a::<AB>(builder, &s_raw, &neg_s_raw);

		// ─── Service emit on this row (count = -1) ────────────────────
		// Payload: (X, Y, Z, T, s) = 5 × 8 = 40 cells.
		let payload: Vec<AB::Expr> = x
			.iter()
			.chain(y.iter())
			.chain(z.iter())
			.chain(t.iter())
			.chain(s.iter())
			.map(|v| (*v).into())
			.collect();
		builder.push_interaction(
			BUS_RISTRETTO_COMPRESS,
			payload,
			AB::Expr::ZERO - AB::Expr::ONE,
			1,
		);
	}
}

// ─── Witness-side trace builder ────────────────────────────────────────────

/// One row of `RistrettoCompressAir` witness.
#[derive(Clone, Debug)]
pub struct RistrettoCompressTraceRow {
	pub p: EdwardsPoint,
	pub z_plus_y: [u32; FIELD_NUM_LIMBS],
	pub z_minus_y_for_u1: [u32; FIELD_NUM_LIMBS],
	pub u1: [u32; FIELD_NUM_LIMBS],
	pub u2: [u32; FIELD_NUM_LIMBS],
	pub u2_sq: [u32; FIELD_NUM_LIMBS],
	pub u1_u2_sq: [u32; FIELD_NUM_LIMBS],
	pub invsqrt: [u32; FIELD_NUM_LIMBS],
	pub d1: [u32; FIELD_NUM_LIMBS],
	pub d2: [u32; FIELD_NUM_LIMBS],
	pub d1_d2: [u32; FIELD_NUM_LIMBS],
	pub zinv: [u32; FIELD_NUM_LIMBS],
	pub t_zinv: [u32; FIELD_NUM_LIMBS],
	pub y_sqrt_m1: [u32; FIELD_NUM_LIMBS],
	pub x_sqrt_m1: [u32; FIELD_NUM_LIMBS],
	pub d1_invsqrt: [u32; FIELD_NUM_LIMBS],
	pub x_prime: [u32; FIELD_NUM_LIMBS],
	pub y_prime: [u32; FIELD_NUM_LIMBS],
	pub d_prime: [u32; FIELD_NUM_LIMBS],
	pub x_prime_zinv: [u32; FIELD_NUM_LIMBS],
	pub neg_y_prime: [u32; FIELD_NUM_LIMBS],
	pub y_prime_signed: [u32; FIELD_NUM_LIMBS],
	pub z_minus_y_signed: [u32; FIELD_NUM_LIMBS],
	pub s_raw: [u32; FIELD_NUM_LIMBS],
	pub neg_s_raw: [u32; FIELD_NUM_LIMBS],
	pub s: [u32; FIELD_NUM_LIMBS],
	pub rotate: u32,
	pub sign_y_prime: u32,
	pub sign_s: u32,
	pub invsqrt_was_sq: u32,
}

pub fn build_ristretto_compress_trace_row(p: &EdwardsPoint) -> RistrettoCompressTraceRow {
	let z_plus_y = field_add(&p.z, &p.y);
	let z_minus_y_for_u1 = field_sub(&p.z, &p.y);
	let u1 = field_mul(&z_plus_y, &z_minus_y_for_u1);
	let u2 = field_mul(&p.x, &p.y);
	let u2_sq = field_square(&u2);
	let u1_u2_sq = field_mul(&u1, &u2_sq);

	let mut one_limbs = [0u32; FIELD_NUM_LIMBS];
	one_limbs[0] = 1;
	let (invsqrt_was_sq, invsqrt) = crate::field::sqrt_ratio_m1(&one_limbs, &u1_u2_sq);

	let d1 = field_mul(&invsqrt, &u1);
	let d2 = field_mul(&invsqrt, &u2);
	let d1_d2 = field_mul(&d1, &d2);
	let zinv = field_mul(&d1_d2, &p.t);
	let t_zinv = field_mul(&p.t, &zinv);
	let rotate = is_negative(&t_zinv);

	let y_sqrt_m1 = field_mul(&p.y, &SQRT_M1_LIMBS);
	let x_sqrt_m1 = field_mul(&p.x, &SQRT_M1_LIMBS);
	let d1_invsqrt = field_mul(&d1, &INVSQRT_A_MINUS_D_LIMBS);

	let (x_prime, y_prime, d_prime) =
		if rotate { (y_sqrt_m1, x_sqrt_m1, d1_invsqrt) } else { (p.x, p.y, d2) };

	let x_prime_zinv = field_mul(&x_prime, &zinv);
	let neg_y_prime = field_neg(&y_prime);
	let sign_y_prime = is_negative(&x_prime_zinv);
	let y_prime_signed = if sign_y_prime { neg_y_prime } else { y_prime };

	let z_minus_y_signed = field_sub(&p.z, &y_prime_signed);
	let s_raw = field_mul(&d_prime, &z_minus_y_signed);
	let neg_s_raw = field_neg(&s_raw);
	let sign_s = is_negative(&s_raw);
	let s = if sign_s { neg_s_raw } else { s_raw };

	RistrettoCompressTraceRow {
		p: *p,
		z_plus_y,
		z_minus_y_for_u1,
		u1,
		u2,
		u2_sq,
		u1_u2_sq,
		invsqrt,
		d1,
		d2,
		d1_d2,
		zinv,
		t_zinv,
		y_sqrt_m1,
		x_sqrt_m1,
		d1_invsqrt,
		x_prime,
		y_prime,
		d_prime,
		x_prime_zinv,
		neg_y_prime,
		y_prime_signed,
		z_minus_y_signed,
		s_raw,
		neg_s_raw,
		s,
		rotate: u32::from(rotate),
		sign_y_prime: u32::from(sign_y_prime),
		sign_s: u32::from(sign_s),
		invsqrt_was_sq: u32::from(invsqrt_was_sq),
	}
}

impl RistrettoCompressTraceRow {
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(RISTRETTO_COMPRESS_NUM_COLS);
		for limbs in [&self.p.x, &self.p.y, &self.p.z, &self.p.t] {
			for &v in limbs {
				out.push(F::from_u32(v));
			}
		}
		for limbs in [
			&self.z_plus_y,
			&self.z_minus_y_for_u1,
			&self.u1,
			&self.u2,
			&self.u2_sq,
			&self.u1_u2_sq,
			&self.invsqrt,
			&self.d1,
			&self.d2,
			&self.d1_d2,
			&self.zinv,
			&self.t_zinv,
			&self.y_sqrt_m1,
			&self.x_sqrt_m1,
			&self.d1_invsqrt,
			&self.x_prime,
			&self.y_prime,
			&self.d_prime,
			&self.x_prime_zinv,
			&self.neg_y_prime,
			&self.y_prime_signed,
			&self.z_minus_y_signed,
			&self.s_raw,
			&self.neg_s_raw,
			&self.s,
		] {
			for &v in limbs {
				out.push(F::from_u32(v));
			}
		}
		out.push(F::from_u32(self.rotate));
		out.push(F::from_u32(self.sign_y_prime));
		out.push(F::from_u32(self.sign_s));
		out.push(F::from_u32(self.invsqrt_was_sq));
		debug_assert_eq!(out.len(), RISTRETTO_COMPRESS_NUM_COLS);
		out
	}

	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), RISTRETTO_COMPRESS_NUM_COLS)
	}
}
