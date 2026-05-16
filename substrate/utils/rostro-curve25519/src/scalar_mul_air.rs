// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for one Edwards25519 scalar multiplication
//! `result = scalar · point`, computed as a 256-row double-and-add
//! chain.
//!
//! **First multi-row AIR in this crate.** Per-row work is uniform: one
//! point-double query + one point-add query on the dedicated point
//! buses, plus a small linear selection. Across 256 rows that's 512
//! service-bus queries.
//!
//! ## Per-row witness (161 cells)
//!
//! ```text
//!   bit        — scalar bit at position (255 - row_index), boolean
//!   acc_in     — 32 cells: X, Y, Z, T of the accumulator entering this row
//!   tmp        — 32 cells: tmp = double(acc_in)
//!   cand       — 32 cells: cand = add(tmp, P)
//!   acc_out    — 32 cells: acc_out = bit ? cand : tmp
//!   p          — 32 cells: the point P, broadcast across every row
//! ```
//!
//! ## Constraints
//!
//! - **Per-row boolean**: `bit * (1 - bit) == 0`.
//! - **Per-row selection** (32 deg-2): `acc_out[i] == bit * cand[i] +
//!   (1 - bit) * tmp[i]`.
//! - **First-row boundary**: `acc_in[0..32] == neutral = (0, 1, 1, 0)`.
//! - **Transition** (when_transition, 64 deg-1):
//!     - `next.acc_in == cur.acc_out` (chain step)
//!     - `next.p       == cur.p`       (P constant across rows)
//!
//! ## Bus queries (per row, count = +1)
//!
//! - `BUS_POINT_DOUBLE`: `(acc_in.xyz, tmp)` = 56 cells
//! - `BUS_POINT_ADD`: `(tmp, p, cand)` = 96 cells
//!
//! The matching providers are `PointDoubleAir` and `PointAddAir`
//! instances elsewhere in the batch.
//!
//! ## Reading the result
//!
//! `acc_out` of the last row (= row 255) holds `scalar · point` in
//! extended coordinates. The caller exposes this via downstream
//! constraints — ScalarMulAir itself emits no result bus.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::FIELD_NUM_LIMBS;
use crate::point::{
	add as point_add, double as point_double, neutral, scalar_mul, EdwardsPoint, SCALAR_NUM_BITS,
};
use crate::point_add_air::BUS_POINT_ADD;
use crate::point_double_air::BUS_POINT_DOUBLE;

/// Trace height for one scalar multiplication (= `SCALAR_NUM_BITS` =
/// 256). Power-of-2 by construction.
pub const SCALAR_MUL_HEIGHT: usize = SCALAR_NUM_BITS;

// ─── Column layout (per row) ───────────────────────────────────────────────
//
// 161 cells. Order is structured so each "slot" of 32 cells corresponds
// to one EdwardsPoint extended-coord group: X, Y, Z, T.

pub const COL_BIT: usize = 0;

pub const COL_ACC_IN_X: usize = COL_BIT + 1;
pub const COL_ACC_IN_Y: usize = COL_ACC_IN_X + FIELD_NUM_LIMBS;
pub const COL_ACC_IN_Z: usize = COL_ACC_IN_Y + FIELD_NUM_LIMBS;
pub const COL_ACC_IN_T: usize = COL_ACC_IN_Z + FIELD_NUM_LIMBS;

pub const COL_TMP_X: usize = COL_ACC_IN_T + FIELD_NUM_LIMBS;
pub const COL_TMP_Y: usize = COL_TMP_X + FIELD_NUM_LIMBS;
pub const COL_TMP_Z: usize = COL_TMP_Y + FIELD_NUM_LIMBS;
pub const COL_TMP_T: usize = COL_TMP_Z + FIELD_NUM_LIMBS;

pub const COL_CAND_X: usize = COL_TMP_T + FIELD_NUM_LIMBS;
pub const COL_CAND_Y: usize = COL_CAND_X + FIELD_NUM_LIMBS;
pub const COL_CAND_Z: usize = COL_CAND_Y + FIELD_NUM_LIMBS;
pub const COL_CAND_T: usize = COL_CAND_Z + FIELD_NUM_LIMBS;

pub const COL_ACC_OUT_X: usize = COL_CAND_T + FIELD_NUM_LIMBS;
pub const COL_ACC_OUT_Y: usize = COL_ACC_OUT_X + FIELD_NUM_LIMBS;
pub const COL_ACC_OUT_Z: usize = COL_ACC_OUT_Y + FIELD_NUM_LIMBS;
pub const COL_ACC_OUT_T: usize = COL_ACC_OUT_Z + FIELD_NUM_LIMBS;

pub const COL_P_X: usize = COL_ACC_OUT_T + FIELD_NUM_LIMBS;
pub const COL_P_Y: usize = COL_P_X + FIELD_NUM_LIMBS;
pub const COL_P_Z: usize = COL_P_Y + FIELD_NUM_LIMBS;
pub const COL_P_T: usize = COL_P_Z + FIELD_NUM_LIMBS;

/// Start of the 32-byte scalar accumulator. `byte_acc[b]` for `b ∈ 0..32`
/// is the running value of byte `b` of the scalar after this row's bit
/// has been folded in (MSB-first within each byte). After the final row,
/// `byte_acc[b]` equals byte `b` of the scalar in little-endian
/// orientation (so `byte_acc[0]` is the LSB byte). The last row emits
/// `(byte_acc[0..32], P, acc_out)` on [`BUS_SCALAR_MUL`].
pub const COL_SCALAR_BYTE_ACC: usize = COL_P_T + FIELD_NUM_LIMBS;
pub const SCALAR_BYTE_LEN: usize = 32;

pub const SCALAR_MUL_NUM_COLS: usize = COL_SCALAR_BYTE_ACC + SCALAR_BYTE_LEN;

/// Width of the preprocessed trace. One selector column per scalar byte;
/// row `r` has a `1` in column `(255 - r) / 8` and zeros elsewhere.
pub const SCALAR_MUL_NUM_PREPROC_COLS: usize = SCALAR_BYTE_LEN;

/// Service-bus name. Payload: `(byte_acc[0..32], P.{x,y,z,t}[0..32],
/// acc_out.{x,y,z,t}[0..32])` = 32 + 32 + 32 = 96 cells. Emitted exactly
/// once per scalar-mul chain (gated by `is_last_row`).
pub const BUS_SCALAR_MUL: &str = "rostro-scalar-mul";

/// Plonky3 AIR for one Edwards25519 scalar multiplication.
#[derive(Clone, Debug, Default)]
pub struct ScalarMulAir;

impl ScalarMulAir {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for ScalarMulAir {
	fn width(&self) -> usize {
		SCALAR_MUL_NUM_COLS
	}

	fn preprocessed_width(&self) -> usize {
		SCALAR_MUL_NUM_PREPROC_COLS
	}

	fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
		// Selector matrix: row r has 1 at column (255 - r) / 8, zeros
		// elsewhere. This pins the per-row "which byte's accumulator is
		// updated" decision to verifier-known data.
		let mut values = Vec::with_capacity(SCALAR_MUL_HEIGHT * SCALAR_MUL_NUM_PREPROC_COLS);
		for r in 0..SCALAR_MUL_HEIGHT {
			let active_byte = (SCALAR_NUM_BITS - 1 - r) / 8;
			for b in 0..SCALAR_BYTE_LEN {
				values.push(if b == active_byte { F::ONE } else { F::ZERO });
			}
		}
		Some(RowMajorMatrix::new(values, SCALAR_MUL_NUM_PREPROC_COLS))
	}
}

fn coords<AB: AirBuilder>(
	row: &AB::MainWindow,
	x_off: usize,
) -> ([AB::Var; FIELD_NUM_LIMBS], [AB::Var; FIELD_NUM_LIMBS], [AB::Var; FIELD_NUM_LIMBS], [AB::Var; FIELD_NUM_LIMBS])
where
	AB::MainWindow: WindowAccess<AB::Var>,
{
	let slice = row.current_slice();
	let x = core::array::from_fn(|i| slice[x_off + i]);
	let y = core::array::from_fn(|i| slice[x_off + FIELD_NUM_LIMBS + i]);
	let z = core::array::from_fn(|i| slice[x_off + 2 * FIELD_NUM_LIMBS + i]);
	let t = core::array::from_fn(|i| slice[x_off + 3 * FIELD_NUM_LIMBS + i]);
	(x, y, z, t)
}

fn coords_next<AB: AirBuilder>(
	row: &AB::MainWindow,
	x_off: usize,
) -> ([AB::Var; FIELD_NUM_LIMBS], [AB::Var; FIELD_NUM_LIMBS], [AB::Var; FIELD_NUM_LIMBS], [AB::Var; FIELD_NUM_LIMBS])
where
	AB::MainWindow: WindowAccess<AB::Var>,
{
	let slice = row.next_slice();
	let x = core::array::from_fn(|i| slice[x_off + i]);
	let y = core::array::from_fn(|i| slice[x_off + FIELD_NUM_LIMBS + i]);
	let z = core::array::from_fn(|i| slice[x_off + 2 * FIELD_NUM_LIMBS + i]);
	let t = core::array::from_fn(|i| slice[x_off + 3 * FIELD_NUM_LIMBS + i]);
	(x, y, z, t)
}

impl<AB: InteractionBuilder> Air<AB> for ScalarMulAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let bit: AB::Var = local[COL_BIT];

		let (acc_in_x, acc_in_y, acc_in_z, acc_in_t) = coords::<AB>(&main, COL_ACC_IN_X);
		let (tmp_x, tmp_y, tmp_z, tmp_t) = coords::<AB>(&main, COL_TMP_X);
		let (cand_x, cand_y, cand_z, cand_t) = coords::<AB>(&main, COL_CAND_X);
		let (acc_out_x, acc_out_y, acc_out_z, acc_out_t) = coords::<AB>(&main, COL_ACC_OUT_X);
		let (p_x, p_y, p_z, p_t) = coords::<AB>(&main, COL_P_X);

		// ─── Per-row constraints ──────────────────────────────────────

		// Boolean: bit * (1 - bit) == 0.
		builder.assert_bool(bit);

		// Selection: acc_out[i] == bit * cand[i] + (1 - bit) * tmp[i]
		// for each of the 4 × 8 = 32 limbs.
		let one_minus_bit = AB::Expr::ONE - bit.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				acc_out_x[i].into()
					- bit.into() * cand_x[i].into()
					- one_minus_bit.clone() * tmp_x[i].into(),
			);
			builder.assert_zero(
				acc_out_y[i].into()
					- bit.into() * cand_y[i].into()
					- one_minus_bit.clone() * tmp_y[i].into(),
			);
			builder.assert_zero(
				acc_out_z[i].into()
					- bit.into() * cand_z[i].into()
					- one_minus_bit.clone() * tmp_z[i].into(),
			);
			builder.assert_zero(
				acc_out_t[i].into()
					- bit.into() * cand_t[i].into()
					- one_minus_bit.clone() * tmp_t[i].into(),
			);
		}

		// ─── First-row boundary: acc_in == neutral = (0, 1, 1, 0) ─────
		let mut first = builder.when_first_row();
		for i in 0..FIELD_NUM_LIMBS {
			first.assert_zero(acc_in_x[i]);
			first.assert_zero(acc_in_t[i]);
			if i == 0 {
				first.assert_eq(acc_in_y[i], AB::Expr::ONE);
				first.assert_eq(acc_in_z[i], AB::Expr::ONE);
			} else {
				first.assert_zero(acc_in_y[i]);
				first.assert_zero(acc_in_z[i]);
			}
		}

		// ─── Transition: chain + P broadcast ──────────────────────────
		let (n_acc_in_x, n_acc_in_y, n_acc_in_z, n_acc_in_t) = coords_next::<AB>(&main, COL_ACC_IN_X);
		let (n_p_x, n_p_y, n_p_z, n_p_t) = coords_next::<AB>(&main, COL_P_X);

		let mut trans = builder.when_transition();
		for i in 0..FIELD_NUM_LIMBS {
			trans.assert_eq(n_acc_in_x[i], acc_out_x[i]);
			trans.assert_eq(n_acc_in_y[i], acc_out_y[i]);
			trans.assert_eq(n_acc_in_z[i], acc_out_z[i]);
			trans.assert_eq(n_acc_in_t[i], acc_out_t[i]);

			trans.assert_eq(n_p_x[i], p_x[i]);
			trans.assert_eq(n_p_y[i], p_y[i]);
			trans.assert_eq(n_p_z[i], p_z[i]);
			trans.assert_eq(n_p_t[i], p_t[i]);
		}

		// ─── Scalar-byte accumulator: pin bit chain to (byte_acc[0..32]) ─
		// At row r, the bit being processed is at scalar position
		// (255 - r). It belongs to byte b = (255 - r) / 8 at bit-within-
		// byte (255 - r) % 8 (MSB-first). The preprocessed selector
		// `selector_b[r]` is 1 iff this row updates byte b.
		//
		// Recurrence per byte (MSB-first within the byte, processed in
		// 8 consecutive rows):
		//   byte_acc[b]_r = byte_acc[b]_{r-1} + selector_b[r] *
		//                   (byte_acc[b]_{r-1} + bit[r])
		// = if selector=1: 2 * prev + bit  (shift-and-or)
		//   if selector=0: prev            (other bytes are untouched)
		//
		// First row: byte_acc[b]_0 = selector_b[0] * bit[0]
		//   → byte_acc[31] = bit[0] (MSB of byte 31); all others = 0.
		// Last row: byte_acc[b]_255 = canonical value of scalar byte b.
		let byte_acc: [AB::Var; SCALAR_BYTE_LEN] =
			core::array::from_fn(|b| local[COL_SCALAR_BYTE_ACC + b]);
		let next_slice = main.next_slice();
		let next_bit: AB::Var = next_slice[COL_BIT];
		let next_byte_acc: [AB::Var; SCALAR_BYTE_LEN] =
			core::array::from_fn(|b| next_slice[COL_SCALAR_BYTE_ACC + b]);
		let sel_pre: [AB::Var; SCALAR_BYTE_LEN] =
			core::array::from_fn(|b| builder.preprocessed().current(b).unwrap());
		let next_sel_pre: [AB::Var; SCALAR_BYTE_LEN] =
			core::array::from_fn(|b| builder.preprocessed().next(b).unwrap());

		let mut first_byte = builder.when_first_row();
		for b in 0..SCALAR_BYTE_LEN {
			first_byte.assert_zero(byte_acc[b].into() - sel_pre[b].into() * bit.into());
		}
		let mut trans_byte = builder.when_transition();
		for b in 0..SCALAR_BYTE_LEN {
			trans_byte.assert_zero(
				next_byte_acc[b].into()
					- byte_acc[b].into()
					- next_sel_pre[b].into() * (byte_acc[b].into() + next_bit.into()),
			);
		}

		// ─── Bus queries (every row, count = +1) ──────────────────────

		// rostro-point-double: (acc_in.x, acc_in.y, acc_in.z, tmp.x,
		// tmp.y, tmp.z, tmp.t) = 56 cells. T1 omitted to match
		// PointDoubleAir's payload.
		let pd_payload: Vec<AB::Expr> = acc_in_x
			.iter()
			.chain(acc_in_y.iter())
			.chain(acc_in_z.iter())
			.chain(tmp_x.iter())
			.chain(tmp_y.iter())
			.chain(tmp_z.iter())
			.chain(tmp_t.iter())
			.map(|v| (*v).into())
			.collect();
		builder.push_interaction(BUS_POINT_DOUBLE, pd_payload, AB::Expr::ONE, 1);

		// rostro-point-add: (tmp, p, cand) = 96 cells.
		let pa_payload: Vec<AB::Expr> = tmp_x
			.iter()
			.chain(tmp_y.iter())
			.chain(tmp_z.iter())
			.chain(tmp_t.iter())
			.chain(p_x.iter())
			.chain(p_y.iter())
			.chain(p_z.iter())
			.chain(p_t.iter())
			.chain(cand_x.iter())
			.chain(cand_y.iter())
			.chain(cand_z.iter())
			.chain(cand_t.iter())
			.map(|v| (*v).into())
			.collect();
		builder.push_interaction(BUS_POINT_ADD, pa_payload, AB::Expr::ONE, 1);

		// ─── Service-bus emit (last row only, count = -1) ─────────────
		// Payload: (byte_acc[0..32], P.{x,y,z,t}, acc_out.{x,y,z,t}).
		// The byte_acc columns above pin this to the scalar implied by
		// the per-row bit chain, closing the audit-flagged scalar-binding
		// gap. Caller pushes (scalar_bytes_LE, P, k·P) on this bus.
		let mut emit_payload: Vec<AB::Expr> = Vec::with_capacity(96);
		for b in 0..SCALAR_BYTE_LEN {
			emit_payload.push(byte_acc[b].into());
		}
		for v in p_x.iter().chain(p_y.iter()).chain(p_z.iter()).chain(p_t.iter()) {
			emit_payload.push((*v).into());
		}
		for v in acc_out_x
			.iter()
			.chain(acc_out_y.iter())
			.chain(acc_out_z.iter())
			.chain(acc_out_t.iter())
		{
			emit_payload.push((*v).into());
		}
		let neg_one = AB::Expr::ZERO - AB::Expr::ONE;
		builder.push_interaction(
			BUS_SCALAR_MUL,
			emit_payload,
			builder.is_last_row() * neg_one,
			1,
		);
	}
}

// ─── Witness-side trace builder ────────────────────────────────────────────

/// Build the 256-row trace for one scalar mul `result = scalar · p`.
///
/// `scalar` is little-endian; bit `i` is `(scalar[i/8] >> (i % 8)) & 1`.
/// Iterates bits from MSB (255) down to LSB (0). The last row's
/// `acc_out` columns hold the result in extended coords; the caller
/// reads from row index `SCALAR_MUL_HEIGHT - 1`.
pub fn build_scalar_mul_trace<F: PrimeCharacteristicRing>(
	scalar: &[u8; 32],
	p: &EdwardsPoint,
) -> Vec<F> {
	let mut out = Vec::with_capacity(SCALAR_MUL_HEIGHT * SCALAR_MUL_NUM_COLS);

	let mut acc_in = neutral();
	let mut byte_acc = [0u32; SCALAR_BYTE_LEN];
	for row_index in 0..SCALAR_MUL_HEIGHT {
		// Bit at position (SCALAR_NUM_BITS - 1 - row_index), MSB-first.
		let bit_pos = SCALAR_NUM_BITS - 1 - row_index;
		let bit = (scalar[bit_pos / 8] >> (bit_pos % 8)) & 1;

		let tmp = point_double(&acc_in);
		let cand = point_add(&tmp, p);
		let acc_out = if bit == 1 { cand } else { tmp };

		// Update the byte accumulator: this row updates byte
		// `(255 - row_index) / 8` by shifting left and OR-ing the new
		// bit. Other bytes stay put.
		let active_byte = bit_pos / 8;
		byte_acc[active_byte] = byte_acc[active_byte] * 2 + u32::from(bit);

		// Push the row in column-layout order.
		out.push(F::from_u32(u32::from(bit)));
		push_point::<F>(&mut out, &acc_in);
		push_point::<F>(&mut out, &tmp);
		push_point::<F>(&mut out, &cand);
		push_point::<F>(&mut out, &acc_out);
		push_point::<F>(&mut out, p);
		for b in 0..SCALAR_BYTE_LEN {
			out.push(F::from_u32(byte_acc[b]));
		}

		acc_in = acc_out;
	}

	debug_assert_eq!(out.len(), SCALAR_MUL_HEIGHT * SCALAR_MUL_NUM_COLS);

	// Sanity: the witness's terminal acc matches the standalone oracle,
	// and the byte accumulator matches the scalar's LE bytes.
	debug_assert_eq!(acc_in, scalar_mul(scalar, p));
	for b in 0..SCALAR_BYTE_LEN {
		debug_assert_eq!(byte_acc[b], u32::from(scalar[b]));
	}

	out
}

fn push_point<F: PrimeCharacteristicRing>(out: &mut Vec<F>, p: &EdwardsPoint) {
	for &v in &p.x {
		out.push(F::from_u32(v));
	}
	for &v in &p.y {
		out.push(F::from_u32(v));
	}
	for &v in &p.z {
		out.push(F::from_u32(v));
	}
	for &v in &p.t {
		out.push(F::from_u32(v));
	}
}

pub fn build_scalar_mul_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
	scalar: &[u8; 32],
	p: &EdwardsPoint,
) -> RowMajorMatrix<F> {
	RowMajorMatrix::new(build_scalar_mul_trace::<F>(scalar, p), SCALAR_MUL_NUM_COLS)
}

/// Read the result `scalar · p` from the last row of a built trace.
/// Convenience for tests and downstream code.
pub fn read_result_from_trace<F: PrimeCharacteristicRing + Copy>(
	trace: &[F],
) -> ([F; FIELD_NUM_LIMBS], [F; FIELD_NUM_LIMBS], [F; FIELD_NUM_LIMBS], [F; FIELD_NUM_LIMBS]) {
	let last_row_start = (SCALAR_MUL_HEIGHT - 1) * SCALAR_MUL_NUM_COLS;
	let row = &trace[last_row_start..last_row_start + SCALAR_MUL_NUM_COLS];
	let x = core::array::from_fn(|i| row[COL_ACC_OUT_X + i]);
	let y = core::array::from_fn(|i| row[COL_ACC_OUT_Y + i]);
	let z = core::array::from_fn(|i| row[COL_ACC_OUT_Z + i]);
	let t = core::array::from_fn(|i| row[COL_ACC_OUT_T + i]);
	(x, y, z, t)
}
