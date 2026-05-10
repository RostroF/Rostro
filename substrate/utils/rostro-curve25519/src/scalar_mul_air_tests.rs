// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::scalar_mul_air::ScalarMulAir`].
//!
//! This is the first multi-row AIR in this crate, so we exercise both
//! per-row shape and inter-row transition behavior:
//! - Layout + height pin.
//! - Witness builder produces the same result as `point::scalar_mul`.
//! - Witness builder satisfies the AIR's per-row constraints
//!   (booleans, selection) and transition constraints (chain + P
//!   broadcast) — checked via a constraint-asserting builder against
//!   every row.
//! - Bus push count matches expectation (2 per row × 256 rows = 512).

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::field::{mul as field_mul, FIELD_NUM_LIMBS};
use crate::point::{neutral, scalar_mul, EdwardsPoint};
use crate::point_add_air::BUS_POINT_ADD;
use crate::point_double_air::BUS_POINT_DOUBLE;
use crate::scalar_mul_air::{
	build_scalar_mul_trace, read_result_from_trace, ScalarMulAir, COL_ACC_IN_X, COL_ACC_IN_Y,
	COL_ACC_IN_Z, COL_ACC_OUT_T, COL_ACC_OUT_X, COL_BIT, COL_CAND_X, COL_P_X, COL_TMP_X,
	SCALAR_MUL_HEIGHT, SCALAR_MUL_NUM_COLS,
};

// ─── Constraint-asserting builder (per-row evaluator) ─────────────────────

struct ExpectZeroBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	is_first_row: Goldilocks,
	is_transition: Goldilocks,
	constraint_index: usize,
	row_label: usize,
}

impl<'a> AirBuilder for ExpectZeroBuilder<'a> {
	type F = Goldilocks;
	type Expr = Goldilocks;
	type Var = Goldilocks;
	type MainWindow = RowWindow<'a, Goldilocks>;
	type PreprocessedWindow = RowWindow<'a, Goldilocks>;
	type PublicVar = Goldilocks;
	type PeriodicVar = Goldilocks;
	fn main(&self) -> Self::MainWindow {
		self.main_window
	}
	fn preprocessed(&self) -> &Self::PreprocessedWindow {
		&self.preprocessed_window
	}
	fn is_first_row(&self) -> Self::Expr {
		self.is_first_row
	}
	fn is_last_row(&self) -> Self::Expr {
		Goldilocks::ZERO
	}
	fn is_transition_window(&self, _: usize) -> Self::Expr {
		self.is_transition
	}
	fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
		let v: Goldilocks = x.into();
		assert!(
			v.is_zero(),
			"row {} constraint #{} failed: value = {:?}",
			self.row_label,
			self.constraint_index,
			v,
		);
		self.constraint_index += 1;
	}
}

impl<'a> InteractionBuilder for ExpectZeroBuilder<'a> {
	fn push_interaction<E: Into<Self::Expr>>(
		&mut self,
		_bus: &str,
		fields: impl IntoIterator<Item = E>,
		_count: impl Into<Self::Expr>,
		_count_weight: u32,
	) {
		fields.into_iter().for_each(drop);
	}
	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

/// Run the AIR against every (row, next_row) window in the trace,
/// firing first_row / transition constraints exactly where the prover
/// would. Panics on any constraint violation.
fn check_constraints(trace: &[Goldilocks]) {
	let air = ScalarMulAir::new();
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	for row in 0..SCALAR_MUL_HEIGHT {
		let next = (row + 1) % SCALAR_MUL_HEIGHT;
		let cur_slice =
			&trace[row * SCALAR_MUL_NUM_COLS..(row + 1) * SCALAR_MUL_NUM_COLS];
		let next_slice =
			&trace[next * SCALAR_MUL_NUM_COLS..(next + 1) * SCALAR_MUL_NUM_COLS];
		let is_first = if row == 0 { Goldilocks::ONE } else { Goldilocks::ZERO };
		// Transition fires on every row except the wrap-around (last row → first row).
		let is_trans =
			if row == SCALAR_MUL_HEIGHT - 1 { Goldilocks::ZERO } else { Goldilocks::ONE };
		let mut builder = ExpectZeroBuilder {
			main_window: RowWindow::from_two_rows(cur_slice, next_slice),
			preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
			is_first_row: is_first,
			is_transition: is_trans,
			constraint_index: 0,
			row_label: row,
		};
		<ScalarMulAir as Air<ExpectZeroBuilder>>::eval(&air, &mut builder);
	}
}

// ─── Layout pin tests ──────────────────────────────────────────────────────

#[test]
fn column_layout_constants_are_stable() {
	assert_eq!(COL_BIT, 0);
	assert_eq!(COL_ACC_IN_X, 1);
	assert_eq!(COL_TMP_X, 33);
	assert_eq!(COL_CAND_X, 65);
	assert_eq!(COL_ACC_OUT_X, 97);
	assert_eq!(COL_P_X, 129);
	assert_eq!(SCALAR_MUL_NUM_COLS, 161);
	assert_eq!(SCALAR_MUL_HEIGHT, 256);
}

#[test]
fn trace_dimensions_match_layout() {
	let mut scalar = [0u8; 32];
	scalar[0] = 7;
	let p = basepoint();
	let trace = build_scalar_mul_trace::<Goldilocks>(&scalar, &p);
	assert_eq!(trace.len(), SCALAR_MUL_HEIGHT * SCALAR_MUL_NUM_COLS);
}

// ─── Witness builder correctness against scalar_mul oracle ─────────────────

#[test]
fn last_row_acc_out_equals_scalar_mul_oracle() {
	// Random in-range scalar; trace's last-row acc_out matches
	// `point::scalar_mul`.
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xc0de_face_dead_beef);
	let mut scalar = [0u8; 32];
	rng.fill_bytes(&mut scalar);
	// Clear top 3 bits so the scalar is in range.
	scalar[31] &= 0x1f;

	let p = basepoint();
	let trace = build_scalar_mul_trace::<Goldilocks>(&scalar, &p);
	let (x, y, z, t) = read_result_from_trace(&trace);

	let oracle = scalar_mul(&scalar, &p);
	for i in 0..FIELD_NUM_LIMBS {
		assert_eq!(
			x[i].as_canonical_u64() as u32,
			oracle.x[i],
			"last-row acc_out.x[{}] mismatch",
			i,
		);
		assert_eq!(y[i].as_canonical_u64() as u32, oracle.y[i]);
		assert_eq!(z[i].as_canonical_u64() as u32, oracle.z[i]);
		assert_eq!(t[i].as_canonical_u64() as u32, oracle.t[i]);
	}
}

// ─── AIR constraint satisfaction ───────────────────────────────────────────

#[test]
fn air_accepts_scalar_zero() {
	let zero_scalar = [0u8; 32];
	let trace = build_scalar_mul_trace::<Goldilocks>(&zero_scalar, &basepoint());
	check_constraints(&trace);
}

#[test]
fn air_accepts_scalar_one() {
	let mut one_scalar = [0u8; 32];
	one_scalar[0] = 1;
	let trace = build_scalar_mul_trace::<Goldilocks>(&one_scalar, &basepoint());
	check_constraints(&trace);
}

#[test]
fn air_accepts_scalar_two() {
	let mut two_scalar = [0u8; 32];
	two_scalar[0] = 2;
	let trace = build_scalar_mul_trace::<Goldilocks>(&two_scalar, &basepoint());
	check_constraints(&trace);
}

#[test]
fn air_accepts_small_scalars_1_to_5() {
	let bp = basepoint();
	for n in 1u8..=5 {
		let mut scalar = [0u8; 32];
		scalar[0] = n;
		let trace = build_scalar_mul_trace::<Goldilocks>(&scalar, &bp);
		check_constraints(&trace);
	}
}

// ─── Constraint rejection tests ────────────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_flipped_bit() {
	// Flip bit on row 7. The boolean constraint still holds (bit ∈
	// {0,1}), but the selection chain breaks — acc_out will not equal
	// bit*cand + (1-bit)*tmp.
	let mut scalar = [0u8; 32];
	scalar[0] = 0b1010_1010;
	let mut trace = build_scalar_mul_trace::<Goldilocks>(&scalar, &basepoint());
	let target_row = 7;
	let bit_pos = target_row * SCALAR_MUL_NUM_COLS + COL_BIT;
	trace[bit_pos] = Goldilocks::ONE - trace[bit_pos];
	check_constraints(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_acc_in_first_row() {
	let scalar = [0u8; 32];
	let mut trace = build_scalar_mul_trace::<Goldilocks>(&scalar, &basepoint());
	// First row acc_in.x[0] is constrained to 0. Set it to 1 — first-row
	// boundary fails.
	trace[COL_ACC_IN_X] = Goldilocks::ONE;
	check_constraints(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_broken_chain_transition() {
	// Corrupt acc_in of row 1: it must equal acc_out of row 0. Mutate
	// row 1's acc_in.y[0] (canonical neutral value = 1) → 2.
	let scalar = [0u8; 32];
	let mut trace = build_scalar_mul_trace::<Goldilocks>(&scalar, &basepoint());
	let target = SCALAR_MUL_NUM_COLS + COL_ACC_IN_Y;
	trace[target] = Goldilocks::TWO;
	check_constraints(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_p_change_across_rows() {
	let scalar = [0u8; 32];
	let mut trace = build_scalar_mul_trace::<Goldilocks>(&scalar, &basepoint());
	// Corrupt P.x[0] in row 5; transition constraint at row 4→5 catches
	// it (current.P != next.P).
	let target = 5 * SCALAR_MUL_NUM_COLS + COL_P_X;
	trace[target] = trace[target] + Goldilocks::ONE;
	check_constraints(&trace);
}

// ─── Bus push count ────────────────────────────────────────────────────────

struct CountingBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	pd_count: usize,
	pa_count: usize,
	other_count: usize,
	pd_payload_arity: usize,
	pa_payload_arity: usize,
}

impl<'a> AirBuilder for CountingBuilder<'a> {
	type F = Goldilocks;
	type Expr = Goldilocks;
	type Var = Goldilocks;
	type MainWindow = RowWindow<'a, Goldilocks>;
	type PreprocessedWindow = RowWindow<'a, Goldilocks>;
	type PublicVar = Goldilocks;
	type PeriodicVar = Goldilocks;
	fn main(&self) -> Self::MainWindow {
		self.main_window
	}
	fn preprocessed(&self) -> &Self::PreprocessedWindow {
		&self.preprocessed_window
	}
	fn is_first_row(&self) -> Self::Expr {
		Goldilocks::ZERO
	}
	fn is_last_row(&self) -> Self::Expr {
		Goldilocks::ZERO
	}
	fn is_transition_window(&self, _: usize) -> Self::Expr {
		Goldilocks::ZERO
	}
	fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
}

impl<'a> InteractionBuilder for CountingBuilder<'a> {
	fn push_interaction<E: Into<Self::Expr>>(
		&mut self,
		bus: &str,
		fields: impl IntoIterator<Item = E>,
		_count: impl Into<Self::Expr>,
		_count_weight: u32,
	) {
		let arity = fields.into_iter().count();
		if bus == BUS_POINT_DOUBLE {
			self.pd_count += 1;
			self.pd_payload_arity = arity;
		} else if bus == BUS_POINT_ADD {
			self.pa_count += 1;
			self.pa_payload_arity = arity;
		} else {
			self.other_count += 1;
		}
	}
	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

#[test]
fn each_row_pushes_one_point_double_and_one_point_add() {
	let scalar = [0u8; 32];
	let trace = build_scalar_mul_trace::<Goldilocks>(&scalar, &neutral());

	// Per-row eval count: 1 row of trace → 1 pd push + 1 pa push.
	let cur_slice = &trace[0..SCALAR_MUL_NUM_COLS];
	let next_slice = &trace[SCALAR_MUL_NUM_COLS..2 * SCALAR_MUL_NUM_COLS];
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut builder = CountingBuilder {
		main_window: RowWindow::from_two_rows(cur_slice, next_slice),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		pd_count: 0,
		pa_count: 0,
		other_count: 0,
		pd_payload_arity: 0,
		pa_payload_arity: 0,
	};
	let air = ScalarMulAir::new();
	<ScalarMulAir as Air<CountingBuilder>>::eval(&air, &mut builder);
	assert_eq!(builder.pd_count, 1, "one point-double consumer push per row");
	assert_eq!(builder.pa_count, 1, "one point-add consumer push per row");
	assert_eq!(builder.other_count, 0, "no other bus pushes from ScalarMulAir");
	assert_eq!(builder.pd_payload_arity, 56, "point-double payload = 56 cells");
	assert_eq!(builder.pa_payload_arity, 96, "point-add payload = 96 cells");
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn basepoint() -> EdwardsPoint {
	let x: [u32; FIELD_NUM_LIMBS] = [
		0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760, 0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE,
		0x216936D3,
	];
	let y: [u32; FIELD_NUM_LIMBS] = [
		0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666,
		0x66666666,
	];
	let mut z = [0u32; FIELD_NUM_LIMBS];
	z[0] = 1;
	let t = field_mul(&x, &y);
	EdwardsPoint { x, y, z, t }
}

// Compile-time silence helpers: ensure unused imports stay loaded if
// future tests need them.
#[allow(dead_code)]
fn _force_use() {
	let _ = ToString::to_string("");
	let _ = String::new();
}
