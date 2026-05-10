// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for one Edwards25519 point addition in extended
//! coordinates.
//!
//! Per the design memo `pop_edwards25519_air_design.md`, this AIR is a
//! **bus-composition consumer**: it witnesses the intermediates of the
//! HWCD 2008 unified point-add formula, and pushes 9 mul + 4 sub + 5
//! add queries onto the three service buses
//! (`rostro-field-mul`, `rostro-field-sub`, `rostro-field-add`) with
//! `count = +1`. The corresponding FieldMulAir / FieldSubAir /
//! FieldAddAir instances in the same batch respond with `count = -1`,
//! and LogUp balance enforces that every consumer query is answered.
//!
//! PointAddAir itself has **no arithmetic constraints** — every field
//! operation is verified by its service AIR. The trace structure plus
//! bus balance is the full soundness story.
//!
//! ## HWCD 2008 unified formula recap
//!
//! Given P1 = (X1, Y1, Z1, T1), P2 = (X2, Y2, Z2, T2):
//! ```text
//!   y1_minus_x1 = Y1 - X1     // sub
//!   y2_minus_x2 = Y2 - X2     // sub
//!   y1_plus_x1  = Y1 + X1     // add
//!   y2_plus_x2  = Y2 + X2     // add
//!   two_z2      = Z2 + Z2     // add
//!   A           = y1_minus_x1 * y2_minus_x2          // mul
//!   B           = y1_plus_x1  * y2_plus_x2           // mul
//!   k_t2        = ED25519_2D  * T2                   // mul (constant a)
//!   C           = T1          * k_t2                 // mul
//!   D           = Z1          * two_z2               // mul
//!   E = B - A   // sub
//!   F = D - C   // sub
//!   G = D + C   // add
//!   H = B + A   // add
//!   X3 = E * F  // mul
//!   Y3 = G * H  // mul
//!   T3 = E * H  // mul
//!   Z3 = F * G  // mul
//! ```
//! Totals: 9 muls + 5 adds + 4 subs = 18 service-bus queries per AIR.

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
use crate::point::{add as point_add, EdwardsPoint, ED25519_2D_LIMBS};

// ─── Column layout ─────────────────────────────────────────────────────────
//
// 26 × 8-limb groups = 208 cells per row. Order chosen to mirror the
// dataflow of the HWCD formula (inputs → linear intermediates → mul
// inputs/outputs → derived linear → final outputs).

/// Input P1 = (X1, Y1, Z1, T1).
pub const COL_P1_X: usize = 0;
pub const COL_P1_Y: usize = COL_P1_X + FIELD_NUM_LIMBS;
pub const COL_P1_Z: usize = COL_P1_Y + FIELD_NUM_LIMBS;
pub const COL_P1_T: usize = COL_P1_Z + FIELD_NUM_LIMBS;

/// Input P2 = (X2, Y2, Z2, T2).
pub const COL_P2_X: usize = COL_P1_T + FIELD_NUM_LIMBS;
pub const COL_P2_Y: usize = COL_P2_X + FIELD_NUM_LIMBS;
pub const COL_P2_Z: usize = COL_P2_Y + FIELD_NUM_LIMBS;
pub const COL_P2_T: usize = COL_P2_Z + FIELD_NUM_LIMBS;

/// Linear intermediates fed to the mul stage.
pub const COL_Y1_MINUS_X1: usize = COL_P2_T + FIELD_NUM_LIMBS;
pub const COL_Y2_MINUS_X2: usize = COL_Y1_MINUS_X1 + FIELD_NUM_LIMBS;
pub const COL_Y1_PLUS_X1: usize = COL_Y2_MINUS_X2 + FIELD_NUM_LIMBS;
pub const COL_Y2_PLUS_X2: usize = COL_Y1_PLUS_X1 + FIELD_NUM_LIMBS;
pub const COL_TWO_Z2: usize = COL_Y2_PLUS_X2 + FIELD_NUM_LIMBS;

/// Mul outputs used by the second round of linear ops.
pub const COL_A: usize = COL_TWO_Z2 + FIELD_NUM_LIMBS;
pub const COL_B: usize = COL_A + FIELD_NUM_LIMBS;
pub const COL_K_T2: usize = COL_B + FIELD_NUM_LIMBS;
pub const COL_C: usize = COL_K_T2 + FIELD_NUM_LIMBS;
pub const COL_D: usize = COL_C + FIELD_NUM_LIMBS;

/// Derived linear intermediates fed to the final mul stage.
pub const COL_E: usize = COL_D + FIELD_NUM_LIMBS;
pub const COL_F: usize = COL_E + FIELD_NUM_LIMBS;
pub const COL_G: usize = COL_F + FIELD_NUM_LIMBS;
pub const COL_H: usize = COL_G + FIELD_NUM_LIMBS;

/// Output P3 = (X3, Y3, Z3, T3).
pub const COL_P3_X: usize = COL_H + FIELD_NUM_LIMBS;
pub const COL_P3_Y: usize = COL_P3_X + FIELD_NUM_LIMBS;
pub const COL_P3_Z: usize = COL_P3_Y + FIELD_NUM_LIMBS;
pub const COL_P3_T: usize = COL_P3_Z + FIELD_NUM_LIMBS;

/// Total trace columns (= 26 × 8 = 208).
pub const POINT_ADD_NUM_COLS: usize = COL_P3_T + FIELD_NUM_LIMBS;

/// Plonky3 AIR for one Edwards25519 point addition.
#[derive(Clone, Debug, Default)]
pub struct PointAddAir;

impl PointAddAir {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for PointAddAir {
	fn width(&self) -> usize {
		POINT_ADD_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for PointAddAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		// Inputs.
		let p1_x: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P1_X + i]);
		let p1_y: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P1_Y + i]);
		let p1_z: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P1_Z + i]);
		let p1_t: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P1_T + i]);
		let p2_x: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P2_X + i]);
		let p2_y: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P2_Y + i]);
		let p2_z: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P2_Z + i]);
		let p2_t: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P2_T + i]);

		// Linear intermediates.
		let y1_minus_x1: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_Y1_MINUS_X1 + i]);
		let y2_minus_x2: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_Y2_MINUS_X2 + i]);
		let y1_plus_x1: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_Y1_PLUS_X1 + i]);
		let y2_plus_x2: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_Y2_PLUS_X2 + i]);
		let two_z2: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_TWO_Z2 + i]);

		// Mul outputs.
		let a_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_A + i]);
		let b_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_B + i]);
		let k_t2: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_K_T2 + i]);
		let c_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_C + i]);
		let d_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_D + i]);

		// Derived linear intermediates.
		let e_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_E + i]);
		let f_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_F + i]);
		let g_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_G + i]);
		let h_col: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_H + i]);

		// Outputs.
		let p3_x: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P3_X + i]);
		let p3_y: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P3_Y + i]);
		let p3_z: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P3_Z + i]);
		let p3_t: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_P3_T + i]);

		// ─── Sub queries (4 messages on BUS_FIELD_SUB) ─────────────────
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &p1_y, &p1_x, &y1_minus_x1);
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &p2_y, &p2_x, &y2_minus_x2);
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &b_col, &a_col, &e_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_SUB, &d_col, &c_col, &f_col);

		// ─── Add queries (5 messages on BUS_FIELD_ADD) ─────────────────
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &p1_y, &p1_x, &y1_plus_x1);
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &p2_y, &p2_x, &y2_plus_x2);
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &p2_z, &p2_z, &two_z2);
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &d_col, &c_col, &g_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_ADD, &b_col, &a_col, &h_col);

		// ─── Mul queries (9 messages on BUS_FIELD_MUL) ─────────────────
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &y1_minus_x1, &y2_minus_x2, &a_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &y1_plus_x1, &y2_plus_x2, &b_col);
		// k_t2 = ED25519_2D * T2 — the `a` slot is a public constant.
		push_field_op_const_a::<AB>(builder, BUS_FIELD_MUL, &ED25519_2D_LIMBS, &p2_t, &k_t2);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &p1_t, &k_t2, &c_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &p1_z, &two_z2, &d_col);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &e_col, &f_col, &p3_x);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &g_col, &h_col, &p3_y);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &e_col, &h_col, &p3_t);
		push_field_op_var::<AB>(builder, BUS_FIELD_MUL, &f_col, &g_col, &p3_z);
	}
}

/// Push one `(a, b, c)` query (24 cells) onto the named service bus
/// with consumer multiplicity `+1`. All three slots are trace columns.
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

/// Push one `(a, b, c)` query where the `a` slot is a public u32-limb
/// constant (e.g. `ED25519_2D_LIMBS`). The `b` and `c` slots are trace
/// columns. Consumer multiplicity `+1`.
fn push_field_op_const_a<AB: InteractionBuilder>(
	builder: &mut AB,
	bus: &'static str,
	a_const: &[u32; FIELD_NUM_LIMBS],
	b: &[AB::Var; FIELD_NUM_LIMBS],
	c: &[AB::Var; FIELD_NUM_LIMBS],
) {
	let mut payload: Vec<AB::Expr> = Vec::with_capacity(3 * FIELD_NUM_LIMBS);
	for &v in a_const.iter() {
		payload.push(AB::Expr::from_u32(v));
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

/// One row of `PointAddAir` witness, in field-element-array form.
#[derive(Clone, Debug)]
pub struct PointAddTraceRow {
	pub p1: EdwardsPoint,
	pub p2: EdwardsPoint,
	pub y1_minus_x1: [u32; FIELD_NUM_LIMBS],
	pub y2_minus_x2: [u32; FIELD_NUM_LIMBS],
	pub y1_plus_x1: [u32; FIELD_NUM_LIMBS],
	pub y2_plus_x2: [u32; FIELD_NUM_LIMBS],
	pub two_z2: [u32; FIELD_NUM_LIMBS],
	pub a: [u32; FIELD_NUM_LIMBS],
	pub b: [u32; FIELD_NUM_LIMBS],
	pub k_t2: [u32; FIELD_NUM_LIMBS],
	pub c: [u32; FIELD_NUM_LIMBS],
	pub d: [u32; FIELD_NUM_LIMBS],
	pub e: [u32; FIELD_NUM_LIMBS],
	pub f: [u32; FIELD_NUM_LIMBS],
	pub g: [u32; FIELD_NUM_LIMBS],
	pub h: [u32; FIELD_NUM_LIMBS],
	pub p3: EdwardsPoint,
}

/// Build a single-row witness for [`PointAddAir`] from two valid
/// Edwards25519 points. Uses [`crate::point::add`] as the witness-side
/// oracle for the output P3 and re-derives every intermediate the AIR
/// references (so the trace matches the formula exactly).
pub fn build_point_add_trace_row(p1: &EdwardsPoint, p2: &EdwardsPoint) -> PointAddTraceRow {
	use crate::field::{add as field_add, mul as field_mul, sub as field_sub};

	let y1_minus_x1 = field_sub(&p1.y, &p1.x);
	let y2_minus_x2 = field_sub(&p2.y, &p2.x);
	let y1_plus_x1 = field_add(&p1.y, &p1.x);
	let y2_plus_x2 = field_add(&p2.y, &p2.x);
	let two_z2 = field_add(&p2.z, &p2.z);

	let a = field_mul(&y1_minus_x1, &y2_minus_x2);
	let b = field_mul(&y1_plus_x1, &y2_plus_x2);
	let k_t2 = field_mul(&ED25519_2D_LIMBS, &p2.t);
	let c = field_mul(&p1.t, &k_t2);
	let d = field_mul(&p1.z, &two_z2);

	let e = field_sub(&b, &a);
	let f = field_sub(&d, &c);
	let g = field_add(&d, &c);
	let h = field_add(&b, &a);

	let p3 = point_add(p1, p2);

	// Sanity check the witness against the standalone point-add oracle:
	// every component must match the HWCD outputs.
	debug_assert_eq!(p3.x, field_mul(&e, &f));
	debug_assert_eq!(p3.y, field_mul(&g, &h));
	debug_assert_eq!(p3.t, field_mul(&e, &h));
	debug_assert_eq!(p3.z, field_mul(&f, &g));

	PointAddTraceRow {
		p1: *p1,
		p2: *p2,
		y1_minus_x1,
		y2_minus_x2,
		y1_plus_x1,
		y2_plus_x2,
		two_z2,
		a,
		b,
		k_t2,
		c,
		d,
		e,
		f,
		g,
		h,
		p3,
	}
}

impl PointAddTraceRow {
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(POINT_ADD_NUM_COLS);
		for &v in &self.p1.x {
			out.push(F::from_u32(v));
		}
		for &v in &self.p1.y {
			out.push(F::from_u32(v));
		}
		for &v in &self.p1.z {
			out.push(F::from_u32(v));
		}
		for &v in &self.p1.t {
			out.push(F::from_u32(v));
		}
		for &v in &self.p2.x {
			out.push(F::from_u32(v));
		}
		for &v in &self.p2.y {
			out.push(F::from_u32(v));
		}
		for &v in &self.p2.z {
			out.push(F::from_u32(v));
		}
		for &v in &self.p2.t {
			out.push(F::from_u32(v));
		}
		for &v in &self.y1_minus_x1 {
			out.push(F::from_u32(v));
		}
		for &v in &self.y2_minus_x2 {
			out.push(F::from_u32(v));
		}
		for &v in &self.y1_plus_x1 {
			out.push(F::from_u32(v));
		}
		for &v in &self.y2_plus_x2 {
			out.push(F::from_u32(v));
		}
		for &v in &self.two_z2 {
			out.push(F::from_u32(v));
		}
		for &v in &self.a {
			out.push(F::from_u32(v));
		}
		for &v in &self.b {
			out.push(F::from_u32(v));
		}
		for &v in &self.k_t2 {
			out.push(F::from_u32(v));
		}
		for &v in &self.c {
			out.push(F::from_u32(v));
		}
		for &v in &self.d {
			out.push(F::from_u32(v));
		}
		for &v in &self.e {
			out.push(F::from_u32(v));
		}
		for &v in &self.f {
			out.push(F::from_u32(v));
		}
		for &v in &self.g {
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
		debug_assert_eq!(out.len(), POINT_ADD_NUM_COLS);
		out
	}

	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), POINT_ADD_NUM_COLS)
	}
}
