// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for one Edwards25519 point doubling in extended
//! coordinates.
//!
//! Bus-composition consumer (analog of [`crate::point_add_air`]) for
//! the HWCD 2008 doubling formula. Pushes 8 mul + 3 add + 5 sub
//! queries onto the three field-op service buses with consumer
//! multiplicity `+1`; the service AIRs respond with `-1`.
//!
//! ## HWCD 2008 doubling (a = -1)
//!
//! ```text
//!   A = X1²
//!   B = Y1²
//!   z_sq = Z1²
//!   C = z_sq + z_sq             // = 2 * Z1²
//!   D = -A                      // (0, A, D) on BUS_FIELD_SUB
//!   x_plus_y = X1 + Y1
//!   xpy_sq = (X1 + Y1)²
//!   xpy_sq_minus_a = xpy_sq - A
//!   E = xpy_sq_minus_a - B      // = (X1+Y1)² - A - B
//!   G = D + B
//!   F = G - C
//!   H = D - B
//!   X3 = E · F
//!   Y3 = G · H
//!   T3 = E · H
//!   Z3 = F · G
//! ```
//!
//! Totals: 8 muls (4 squares + 4 finals), 3 adds, 5 subs = 16 bus
//! queries per doubling.
//!
//! `T1` is **not** read by this formula (the Edwards25519 a-coefficient
//! is -1, which simplifies the doubling). The trace omits it.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::FIELD_NUM_LIMBS;
use crate::field_air::BUS_FIELD_ADD;
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_sub_air::BUS_FIELD_SUB;
use crate::point::{double as point_double, EdwardsPoint};

// ─── Column layout ─────────────────────────────────────────────────────────
//
// 19 × 8-limb groups = 152 cells per row.

/// Input p1 components used by the formula.
pub const COL_P1_X: usize = 0;
pub const COL_P1_Y: usize = COL_P1_X + FIELD_NUM_LIMBS;
pub const COL_P1_Z: usize = COL_P1_Y + FIELD_NUM_LIMBS;

/// Square outputs.
pub const COL_A: usize = COL_P1_Z + FIELD_NUM_LIMBS;
pub const COL_B: usize = COL_A + FIELD_NUM_LIMBS;
pub const COL_Z_SQ: usize = COL_B + FIELD_NUM_LIMBS;

/// First wave of linear ops.
pub const COL_C: usize = COL_Z_SQ + FIELD_NUM_LIMBS;
pub const COL_D: usize = COL_C + FIELD_NUM_LIMBS;
pub const COL_X_PLUS_Y: usize = COL_D + FIELD_NUM_LIMBS;

/// (X1+Y1)² and the intermediate of the E construction.
pub const COL_XPY_SQ: usize = COL_X_PLUS_Y + FIELD_NUM_LIMBS;
pub const COL_XPY_SQ_MINUS_A: usize = COL_XPY_SQ + FIELD_NUM_LIMBS;

/// Derived linear intermediates.
pub const COL_E: usize = COL_XPY_SQ_MINUS_A + FIELD_NUM_LIMBS;
pub const COL_G: usize = COL_E + FIELD_NUM_LIMBS;
pub const COL_F: usize = COL_G + FIELD_NUM_LIMBS;
pub const COL_H: usize = COL_F + FIELD_NUM_LIMBS;

/// Output p3.
pub const COL_P3_X: usize = COL_H + FIELD_NUM_LIMBS;
pub const COL_P3_Y: usize = COL_P3_X + FIELD_NUM_LIMBS;
pub const COL_P3_Z: usize = COL_P3_Y + FIELD_NUM_LIMBS;
pub const COL_P3_T: usize = COL_P3_Z + FIELD_NUM_LIMBS;

/// Total trace columns (= 19 × 8 = 152).
pub const POINT_DOUBLE_NUM_COLS: usize = COL_P3_T + FIELD_NUM_LIMBS;

/// Plonky3 AIR for one Edwards25519 point doubling.
#[derive(Clone, Debug, Default)]
pub struct PointDoubleAir;

impl PointDoubleAir {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for PointDoubleAir {
	fn width(&self) -> usize {
		POINT_DOUBLE_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for PointDoubleAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let p1_x: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P1_X + i]);
		let p1_y: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P1_Y + i]);
		let p1_z: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P1_Z + i]);

		let a_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_A + i]);
		let b_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_B + i]);
		let z_sq: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_Z_SQ + i]);

		let c_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_C + i]);
		let d_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_D + i]);
		let x_plus_y: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_X_PLUS_Y + i]);

		let xpy_sq: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_XPY_SQ + i]);
		let xpy_sq_minus_a: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_XPY_SQ_MINUS_A + i]);

		let e_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_E + i]);
		let g_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_G + i]);
		let f_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_F + i]);
		let h_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_H + i]);

		let p3_x: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P3_X + i]);
		let p3_y: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P3_Y + i]);
		let p3_z: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P3_Z + i]);
		let p3_t: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P3_T + i]);

		// ─── Sub queries (5 messages on BUS_FIELD_SUB) ─────────────────
		// D = 0 - A: encode as a sub with constant zero in the `a` slot.
		push_field_op_const_zero_a::<AB>(builder, BUS_FIELD_SUB, &a_col, &d_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &xpy_sq, &a_col, &xpy_sq_minus_a);
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &xpy_sq_minus_a, &b_col, &e_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &g_col, &c_col, &f_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &d_col, &b_col, &h_col);

		// ─── Add queries (3 messages on BUS_FIELD_ADD) ─────────────────
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &z_sq, &z_sq, &c_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &p1_x, &p1_y, &x_plus_y);
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &d_col, &b_col, &g_col);

		// ─── Mul queries (8 messages on BUS_FIELD_MUL) ─────────────────
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &p1_x, &p1_x, &a_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &p1_y, &p1_y, &b_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &p1_z, &p1_z, &z_sq);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &x_plus_y, &x_plus_y, &xpy_sq);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &e_col, &f_col, &p3_x);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &g_col, &h_col, &p3_y);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &e_col, &h_col, &p3_t);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &f_col, &g_col, &p3_z);
	}
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

/// `a` slot is the zero constant. Used to encode `c = -b mod p` as a
/// sub query `(0, b, c)` on BUS_FIELD_SUB.
fn push_field_op_const_zero_a<AB: InteractionBuilder>(
	builder: &mut AB,
	bus: &'static str,
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
	builder.push_interaction(bus, payload, AB::Expr::ONE, 1);
}

// ─── Witness-side trace builder ────────────────────────────────────────────

/// One row of `PointDoubleAir` witness in field-element-array form.
#[derive(Clone, Debug)]
pub struct PointDoubleTraceRow {
	pub p1: EdwardsPoint,
	pub a: [u32; FIELD_NUM_LIMBS],
	pub b: [u32; FIELD_NUM_LIMBS],
	pub z_sq: [u32; FIELD_NUM_LIMBS],
	pub c: [u32; FIELD_NUM_LIMBS],
	pub d: [u32; FIELD_NUM_LIMBS],
	pub x_plus_y: [u32; FIELD_NUM_LIMBS],
	pub xpy_sq: [u32; FIELD_NUM_LIMBS],
	pub xpy_sq_minus_a: [u32; FIELD_NUM_LIMBS],
	pub e: [u32; FIELD_NUM_LIMBS],
	pub g: [u32; FIELD_NUM_LIMBS],
	pub f: [u32; FIELD_NUM_LIMBS],
	pub h: [u32; FIELD_NUM_LIMBS],
	pub p3: EdwardsPoint,
}

pub fn build_point_double_trace_row(p1: &EdwardsPoint) -> PointDoubleTraceRow {
	use crate::field::{add as field_add, mul as field_mul, neg as field_neg, sub as field_sub};

	let a = field_mul(&p1.x, &p1.x);
	let b = field_mul(&p1.y, &p1.y);
	let z_sq = field_mul(&p1.z, &p1.z);
	let c = field_add(&z_sq, &z_sq);
	let d = field_neg(&a);
	let x_plus_y = field_add(&p1.x, &p1.y);
	let xpy_sq = field_mul(&x_plus_y, &x_plus_y);
	let xpy_sq_minus_a = field_sub(&xpy_sq, &a);
	let e = field_sub(&xpy_sq_minus_a, &b);
	let g = field_add(&d, &b);
	let f = field_sub(&g, &c);
	let h = field_sub(&d, &b);

	let p3 = point_double(p1);

	debug_assert_eq!(p3.x, field_mul(&e, &f));
	debug_assert_eq!(p3.y, field_mul(&g, &h));
	debug_assert_eq!(p3.t, field_mul(&e, &h));
	debug_assert_eq!(p3.z, field_mul(&f, &g));

	PointDoubleTraceRow {
		p1: *p1,
		a,
		b,
		z_sq,
		c,
		d,
		x_plus_y,
		xpy_sq,
		xpy_sq_minus_a,
		e,
		g,
		f,
		h,
		p3,
	}
}

impl PointDoubleTraceRow {
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(POINT_DOUBLE_NUM_COLS);
		for &v in &self.p1.x {
			out.push(F::from_u32(v));
		}
		for &v in &self.p1.y {
			out.push(F::from_u32(v));
		}
		for &v in &self.p1.z {
			out.push(F::from_u32(v));
		}
		for &v in &self.a {
			out.push(F::from_u32(v));
		}
		for &v in &self.b {
			out.push(F::from_u32(v));
		}
		for &v in &self.z_sq {
			out.push(F::from_u32(v));
		}
		for &v in &self.c {
			out.push(F::from_u32(v));
		}
		for &v in &self.d {
			out.push(F::from_u32(v));
		}
		for &v in &self.x_plus_y {
			out.push(F::from_u32(v));
		}
		for &v in &self.xpy_sq {
			out.push(F::from_u32(v));
		}
		for &v in &self.xpy_sq_minus_a {
			out.push(F::from_u32(v));
		}
		for &v in &self.e {
			out.push(F::from_u32(v));
		}
		for &v in &self.g {
			out.push(F::from_u32(v));
		}
		for &v in &self.f {
			out.push(F::from_u32(v));
		}
		for &v in &self.h {
			out.push(F::from_u32(v));
		}
		for &v in &self.p3.x {
			out.push(F::from_u32(v));
		}
		for &v in &self.p3.y {
			out.push(F::from_u32(v));
		}
		for &v in &self.p3.z {
			out.push(F::from_u32(v));
		}
		for &v in &self.p3.t {
			out.push(F::from_u32(v));
		}
		debug_assert_eq!(out.len(), POINT_DOUBLE_NUM_COLS);
		out
	}

	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), POINT_DOUBLE_NUM_COLS)
	}
}
