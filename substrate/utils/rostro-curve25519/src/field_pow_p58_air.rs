// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for `base^((p - 5) / 8) mod p`, the Ristretto255 / hash-
//! to-curve pow primitive.
//!
//! Multi-row square-and-multiply over a fixed exponent. 256 rows
//! (4 padding rows of leading zeros + 252 bits of `(p - 5)/8`,
//! MSB-first). Per row: one field-square query and one conditional
//! field-multiply query on `rostro-field-mul`. The exponent bit is a
//! **preprocessed column** (public, verifier-known) — not a witness.
//!
//! Mirrors `ScalarMulAir`'s shape exactly: same trace height (256),
//! same selection pattern, same first-row + transition structure. The
//! key differences are:
//!
//! 1. The "increment" operation is multiply-by-`base` (a constant
//!    across the row, also broadcast) — not point-add.
//! 2. The "step" operation is squaring — not point-double.
//! 3. The bit comes from a preprocessed column instead of a witness.
//!
//! ## Per-row witness (41 cells)
//!
//! ```text
//!   acc_in       — 8 cells: accumulator entering this row
//!   acc_sq       — 8 cells: acc_in²
//!   acc_sq_b     — 8 cells: acc_sq · base (always computed; only used if bit = 1)
//!   acc_out      — 8 cells: bit ? acc_sq_b : acc_sq
//!   base         — 8 cells: broadcast constant
//! ```
//!
//! Plus one preprocessed column holding the exponent bit for that row.
//!
//! ## Bus queries (per row, both on `BUS_FIELD_MUL`)
//!
//! - `(acc_in, acc_in, acc_sq)` with `count = +1` — always emitted.
//! - `(acc_sq, base, acc_sq_b)` with `count = bit` — emitted only when
//!   the preprocessed exponent bit is 1. Multiplicity-as-expression
//!   lets the LogUp accumulator skip these when bit = 0.
//!
//! ## Service emit (last row, count = -1)
//!
//! `rostro-field-pow-p58` payload `(base, acc_out)` = 16 cells.
//! Consumers (SqrtRatioM1Air, ...) query the same shape with count = +1.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::{pow_p_minus_5_div_8, square as field_square, FIELD_NUM_LIMBS};
use crate::field_mul_air::BUS_FIELD_MUL;

/// Trace height (= number of bits we iterate, padded to a power of 2).
pub const FIELD_POW_P58_HEIGHT: usize = 256;

/// Service-bus name for FieldPowP58Air.
pub const BUS_FIELD_POW_P58: &str = "rostro-field-pow-p58";

// ─── Column layout (main trace) ────────────────────────────────────────────

pub const COL_ACC_IN: usize = 0;
pub const COL_ACC_SQ: usize = COL_ACC_IN + FIELD_NUM_LIMBS;
pub const COL_ACC_SQ_B: usize = COL_ACC_SQ + FIELD_NUM_LIMBS;
pub const COL_ACC_OUT: usize = COL_ACC_SQ_B + FIELD_NUM_LIMBS;
pub const COL_BASE: usize = COL_ACC_OUT + FIELD_NUM_LIMBS;

pub const FIELD_POW_P58_NUM_COLS: usize = COL_BASE + FIELD_NUM_LIMBS;

/// Width of the preprocessed trace (one column: the exponent bit).
pub const FIELD_POW_P58_NUM_PREPROC_COLS: usize = 1;

/// Build the preprocessed bit sequence for `(p - 5)/8 = 2^252 - 3`.
///
/// MSB-first across 256 rows. Row `r` holds bit at exponent position
/// `255 - r`. Positions 252..=255 are zero (padding to a power of 2);
/// positions 0..=251 follow `2^252 - 3 = 252_ones_with_bit1_clear`,
/// so position 251 = 1, position 250 = 1, ..., position 2 = 1,
/// position 1 = 0, position 0 = 1.
fn exp_bits_msb_first() -> [bool; FIELD_POW_P58_HEIGHT] {
	let mut bits = [false; FIELD_POW_P58_HEIGHT];
	for r in 0..FIELD_POW_P58_HEIGHT {
		let bit_position = (FIELD_POW_P58_HEIGHT - 1).wrapping_sub(r);
		// Above the exponent's MSB: zero pad.
		if bit_position >= 252 {
			bits[r] = false;
		} else if bit_position == 1 {
			bits[r] = false;
		} else {
			// All other positions in [0, 251] are 1.
			bits[r] = true;
		}
	}
	bits
}

/// Plonky3 AIR for `base^((p - 5) / 8) mod p`.
#[derive(Clone, Debug, Default)]
pub struct FieldPowP58Air;

impl FieldPowP58Air {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for FieldPowP58Air {
	fn width(&self) -> usize {
		FIELD_POW_P58_NUM_COLS
	}

	fn preprocessed_width(&self) -> usize {
		FIELD_POW_P58_NUM_PREPROC_COLS
	}

	fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
		let bits = exp_bits_msb_first();
		let mut values = Vec::with_capacity(FIELD_POW_P58_HEIGHT);
		for &b in bits.iter() {
			values.push(if b { F::ONE } else { F::ZERO });
		}
		Some(RowMajorMatrix::new(values, FIELD_POW_P58_NUM_PREPROC_COLS))
	}
}

impl<AB: InteractionBuilder> Air<AB> for FieldPowP58Air
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let acc_in: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_ACC_IN + i]);
		let acc_sq: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_ACC_SQ + i]);
		let acc_sq_b: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ACC_SQ_B + i]);
		let acc_out: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ACC_OUT + i]);
		let base: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_BASE + i]);

		// Preprocessed: the exponent bit for this row. Copy out before
		// the mutable borrow on `builder` activates.
		let bit: AB::Var = builder.preprocessed().current(0).unwrap();

		// Selection: acc_out[i] = bit · acc_sq_b[i] + (1 - bit) · acc_sq[i].
		let one_minus_bit = AB::Expr::ONE - bit.into();
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				acc_out[i].into()
					- bit.into() * acc_sq_b[i].into()
					- one_minus_bit.clone() * acc_sq[i].into(),
			);
		}

		// First-row boundary: acc_in == 1 (multiplicative identity).
		let mut first = builder.when_first_row();
		for i in 0..FIELD_NUM_LIMBS {
			if i == 0 {
				first.assert_eq(acc_in[i], AB::Expr::ONE);
			} else {
				first.assert_zero(acc_in[i]);
			}
		}

		// Transition: next.acc_in == cur.acc_out, next.base == cur.base.
		let next = main.next_slice();
		let mut trans = builder.when_transition();
		for i in 0..FIELD_NUM_LIMBS {
			trans.assert_eq(next[COL_ACC_IN + i], acc_out[i]);
			trans.assert_eq(next[COL_BASE + i], base[i]);
		}

		// Always-emit square query (count = +1):
		//   (acc_in, acc_in, acc_sq) on BUS_FIELD_MUL.
		let sq_payload: Vec<AB::Expr> = acc_in
			.iter()
			.chain(acc_in.iter())
			.chain(acc_sq.iter())
			.map(|v| (*v).into())
			.collect();
		builder.push_interaction(BUS_FIELD_MUL, sq_payload, AB::Expr::ONE, 1);

		// Conditional multiply query (count = bit):
		//   (acc_sq, base, acc_sq_b) on BUS_FIELD_MUL.
		let mul_payload: Vec<AB::Expr> = acc_sq
			.iter()
			.chain(base.iter())
			.chain(acc_sq_b.iter())
			.map(|v| (*v).into())
			.collect();
		builder.push_interaction(BUS_FIELD_MUL, mul_payload, bit.into(), 1);

		// Service-bus emit (last row only, count = -1):
		//   (base, acc_out) on BUS_FIELD_POW_P58.
		// We can't use `when_last_row` directly for `push_interaction`'s
		// count expression in all builders, so multiply the count by
		// `is_last_row` to gate.
		let emit_payload: Vec<AB::Expr> =
			base.iter().chain(acc_out.iter()).map(|v| (*v).into()).collect();
		let neg_one = AB::Expr::ZERO - AB::Expr::ONE;
		builder.push_interaction(
			BUS_FIELD_POW_P58,
			emit_payload,
			builder.is_last_row() * neg_one,
			1,
		);
	}
}

// ─── Witness-side trace builder ────────────────────────────────────────────

/// Build the 256-row trace for `base^((p - 5)/8) mod p`.
pub fn build_field_pow_p58_trace<F: PrimeCharacteristicRing>(
	base: &[u32; FIELD_NUM_LIMBS],
) -> Vec<F> {
	let mut out = Vec::with_capacity(FIELD_POW_P58_HEIGHT * FIELD_POW_P58_NUM_COLS);
	let bits = exp_bits_msb_first();

	// acc starts at 1 (the multiplicative identity).
	let mut acc = {
		let mut v = [0u32; FIELD_NUM_LIMBS];
		v[0] = 1;
		v
	};

	for row in 0..FIELD_POW_P58_HEIGHT {
		let bit = bits[row];
		let acc_sq = field_square(&acc);
		let acc_sq_b = crate::field::mul(&acc_sq, base);
		let acc_out = if bit { acc_sq_b } else { acc_sq };

		// Push columns in layout order.
		push_limbs::<F>(&mut out, &acc);
		push_limbs::<F>(&mut out, &acc_sq);
		push_limbs::<F>(&mut out, &acc_sq_b);
		push_limbs::<F>(&mut out, &acc_out);
		push_limbs::<F>(&mut out, base);

		acc = acc_out;
	}

	debug_assert_eq!(out.len(), FIELD_POW_P58_HEIGHT * FIELD_POW_P58_NUM_COLS);
	debug_assert_eq!(acc, pow_p_minus_5_div_8(base), "trace's final acc must equal the oracle");
	out
}

fn push_limbs<F: PrimeCharacteristicRing>(out: &mut Vec<F>, limbs: &[u32; FIELD_NUM_LIMBS]) {
	for &v in limbs {
		out.push(F::from_u32(v));
	}
}

pub fn build_field_pow_p58_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
	base: &[u32; FIELD_NUM_LIMBS],
) -> RowMajorMatrix<F> {
	RowMajorMatrix::new(build_field_pow_p58_trace::<F>(base), FIELD_POW_P58_NUM_COLS)
}

/// Read the final result `base^((p-5)/8)` from the last row of a built
/// trace's acc_out columns.
pub fn read_result_from_trace<F: PrimeCharacteristicRing + Copy>(
	trace: &[F],
) -> [F; FIELD_NUM_LIMBS] {
	let last_row_start = (FIELD_POW_P58_HEIGHT - 1) * FIELD_POW_P58_NUM_COLS;
	let row = &trace[last_row_start..last_row_start + FIELD_POW_P58_NUM_COLS];
	core::array::from_fn(|i| row[COL_ACC_OUT + i])
}
