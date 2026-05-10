// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::field_pow_p58_air::FieldPowP58Air`].

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::Matrix;

use crate::field::{pow_p_minus_5_div_8, FIELD_NUM_LIMBS};
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_pow_p58_air::{
	build_field_pow_p58_trace, read_result_from_trace, FieldPowP58Air, BUS_FIELD_POW_P58,
	COL_ACC_IN, COL_ACC_OUT, COL_ACC_SQ, COL_ACC_SQ_B, COL_BASE, FIELD_POW_P58_HEIGHT,
	FIELD_POW_P58_NUM_COLS, FIELD_POW_P58_NUM_PREPROC_COLS,
};
use crate::oracle_tests_helpers::random_canonical;

// ─── Constraint-asserting builder (per-row evaluator) ──────────────────────

struct ExpectZeroBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	is_first_row: Goldilocks,
	is_last_row: Goldilocks,
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
		self.is_last_row
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

fn check_constraints(trace: &[Goldilocks]) {
	let air = FieldPowP58Air::new();
	let preproc =
		<FieldPowP58Air as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("preproc trace");
	let pp_values = preproc.values;

	for row in 0..FIELD_POW_P58_HEIGHT {
		let next = (row + 1) % FIELD_POW_P58_HEIGHT;
		let cur_slice =
			&trace[row * FIELD_POW_P58_NUM_COLS..(row + 1) * FIELD_POW_P58_NUM_COLS];
		let next_slice =
			&trace[next * FIELD_POW_P58_NUM_COLS..(next + 1) * FIELD_POW_P58_NUM_COLS];
		let pp_cur = &pp_values[row * FIELD_POW_P58_NUM_PREPROC_COLS
			..(row + 1) * FIELD_POW_P58_NUM_PREPROC_COLS];
		let pp_next = &pp_values[next * FIELD_POW_P58_NUM_PREPROC_COLS
			..(next + 1) * FIELD_POW_P58_NUM_PREPROC_COLS];
		let is_first = if row == 0 { Goldilocks::ONE } else { Goldilocks::ZERO };
		let is_last = if row == FIELD_POW_P58_HEIGHT - 1 { Goldilocks::ONE } else { Goldilocks::ZERO };
		let is_trans =
			if row == FIELD_POW_P58_HEIGHT - 1 { Goldilocks::ZERO } else { Goldilocks::ONE };
		let mut builder = ExpectZeroBuilder {
			main_window: RowWindow::from_two_rows(cur_slice, next_slice),
			preprocessed_window: RowWindow::from_two_rows(pp_cur, pp_next),
			is_first_row: is_first,
			is_last_row: is_last,
			is_transition: is_trans,
			constraint_index: 0,
			row_label: row,
		};
		<FieldPowP58Air as Air<ExpectZeroBuilder>>::eval(&air, &mut builder);
	}
}

// ─── Layout + preprocessed-trace pin tests ────────────────────────────────

#[test]
fn column_layout_constants_are_stable() {
	assert_eq!(COL_ACC_IN, 0);
	assert_eq!(COL_ACC_SQ, 8);
	assert_eq!(COL_ACC_SQ_B, 16);
	assert_eq!(COL_ACC_OUT, 24);
	assert_eq!(COL_BASE, 32);
	assert_eq!(FIELD_POW_P58_NUM_COLS, 40);
	assert_eq!(FIELD_POW_P58_HEIGHT, 256);
	assert_eq!(FIELD_POW_P58_NUM_PREPROC_COLS, 1);
}

#[test]
fn preprocessed_trace_has_correct_shape() {
	let air = FieldPowP58Air::new();
	let preproc =
		<FieldPowP58Air as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("preproc trace");
	assert_eq!(preproc.values.len(), FIELD_POW_P58_HEIGHT);
	assert_eq!(preproc.width(), 1);
}

#[test]
fn preprocessed_bit_pattern_matches_p_minus_5_div_8() {
	// (p-5)/8 = 2^252 - 3. Padded to 256 bits MSB-first:
	//   rows 0..=3   → 0 (positions 255..=252 of the extended exponent)
	//   row 4        → 1 (position 251 = MSB of (p-5)/8)
	//   rows 5..=253 → 1 (positions 250..=2)
	//   row 254      → 0 (position 1 of (p-5)/8)
	//   row 255      → 1 (position 0)
	let air = FieldPowP58Air::new();
	let preproc =
		<FieldPowP58Air as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("preproc trace");
	let bits = preproc.values;

	for r in 0..=3 {
		assert_eq!(bits[r], Goldilocks::ZERO, "row {} should be a leading-zero pad", r);
	}
	assert_eq!(bits[4], Goldilocks::ONE, "row 4 = MSB of exponent should be 1");
	for r in 5..=253 {
		assert_eq!(bits[r], Goldilocks::ONE, "row {} should be 1 (mid bits of exponent)", r);
	}
	assert_eq!(bits[254], Goldilocks::ZERO, "row 254 = bit position 1 of (p-5)/8 should be 0");
	assert_eq!(bits[255], Goldilocks::ONE, "row 255 = bit position 0 of (p-5)/8 should be 1");
}

// ─── Witness builder correctness against the field oracle ──────────────────

#[test]
fn last_row_acc_out_equals_pow_oracle_for_small_base() {
	let mut base = [0u32; FIELD_NUM_LIMBS];
	base[0] = 7;
	let trace = build_field_pow_p58_trace::<Goldilocks>(&base);
	let result = read_result_from_trace(&trace);
	let oracle = pow_p_minus_5_div_8(&base);
	for i in 0..FIELD_NUM_LIMBS {
		assert_eq!(
			result[i].as_canonical_u64() as u32,
			oracle[i],
			"trace's last-row acc_out[{}] diverges from pow_p_minus_5_div_8",
			i,
		);
	}
}

#[test]
fn last_row_matches_oracle_for_random_bases() {
	use rand::{rngs::StdRng, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xfade_f00d_f00d_fade);
	for _ in 0..3 {
		let base = random_canonical(&mut rng);
		let trace = build_field_pow_p58_trace::<Goldilocks>(&base);
		let result = read_result_from_trace(&trace);
		let oracle = pow_p_minus_5_div_8(&base);
		for i in 0..FIELD_NUM_LIMBS {
			assert_eq!(result[i].as_canonical_u64() as u32, oracle[i]);
		}
	}
}

// ─── AIR constraint satisfaction ───────────────────────────────────────────

#[test]
fn air_accepts_base_seven() {
	let mut base = [0u32; FIELD_NUM_LIMBS];
	base[0] = 7;
	let trace = build_field_pow_p58_trace::<Goldilocks>(&base);
	check_constraints(&trace);
}

#[test]
fn air_accepts_base_one() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let trace = build_field_pow_p58_trace::<Goldilocks>(&one);
	check_constraints(&trace);
}

#[test]
fn air_accepts_random_base() {
	use rand::{rngs::StdRng, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0x1234_5678_face_dead);
	let base = random_canonical(&mut rng);
	let trace = build_field_pow_p58_trace::<Goldilocks>(&base);
	check_constraints(&trace);
}

// ─── Rejection tests ───────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_acc_in_first_row() {
	let mut base = [0u32; FIELD_NUM_LIMBS];
	base[0] = 7;
	let mut trace = build_field_pow_p58_trace::<Goldilocks>(&base);
	// First-row acc_in[0] must be 1; clobber it to 2.
	trace[COL_ACC_IN] = Goldilocks::TWO;
	check_constraints(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_broken_chain_transition() {
	let mut base = [0u32; FIELD_NUM_LIMBS];
	base[0] = 7;
	let mut trace = build_field_pow_p58_trace::<Goldilocks>(&base);
	// Row 1's acc_in must equal row 0's acc_out. Corrupt row 1's acc_in[0].
	let target = FIELD_POW_P58_NUM_COLS + COL_ACC_IN;
	trace[target] = trace[target] + Goldilocks::ONE;
	check_constraints(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_base_change_across_rows() {
	let mut base = [0u32; FIELD_NUM_LIMBS];
	base[0] = 7;
	let mut trace = build_field_pow_p58_trace::<Goldilocks>(&base);
	// Row 5 has base[0] = 7; corrupt it to 8.
	let target = 5 * FIELD_POW_P58_NUM_COLS + COL_BASE;
	trace[target] = trace[target] + Goldilocks::ONE;
	check_constraints(&trace);
}

// ─── Bus push count + service emit shape ───────────────────────────────────

struct CountingBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	is_last_row: Goldilocks,
	pushed: Vec<(String, Goldilocks, usize, u32)>,
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
		self.is_last_row
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
		count: impl Into<Self::Expr>,
		count_weight: u32,
	) {
		let m: Goldilocks = count.into();
		let arity = fields.into_iter().count();
		self.pushed.push((bus.to_string(), m, arity, count_weight));
	}
	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

#[test]
fn non_last_row_emits_two_mul_pushes_zero_service_emit() {
	let mut base = [0u32; FIELD_NUM_LIMBS];
	base[0] = 7;
	let trace = build_field_pow_p58_trace::<Goldilocks>(&base);
	let air = FieldPowP58Air::new();
	let preproc =
		<FieldPowP58Air as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("preproc trace");
	let pp_values = preproc.values;

	// Use row 5 (bit = 1 in the preproc).
	let row = 5;
	let cur_slice = &trace[row * FIELD_POW_P58_NUM_COLS..(row + 1) * FIELD_POW_P58_NUM_COLS];
	let next_slice =
		&trace[(row + 1) * FIELD_POW_P58_NUM_COLS..(row + 2) * FIELD_POW_P58_NUM_COLS];
	let pp_cur = &pp_values[row..row + 1];
	let pp_next = &pp_values[row + 1..row + 2];
	let mut b = CountingBuilder {
		main_window: RowWindow::from_two_rows(cur_slice, next_slice),
		preprocessed_window: RowWindow::from_two_rows(pp_cur, pp_next),
		is_last_row: Goldilocks::ZERO,
		pushed: Vec::new(),
	};
	<FieldPowP58Air as Air<CountingBuilder>>::eval(&air, &mut b);

	let mul_pushes: Vec<_> = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_MUL).collect();
	let pow_pushes: Vec<_> =
		b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_POW_P58).collect();
	assert_eq!(mul_pushes.len(), 2, "expected 2 mul pushes per row");
	for (_, _, arity, _) in &mul_pushes {
		assert_eq!(*arity, 24, "mul payload = (a, b, c) × 8 limbs = 24 cells");
	}
	assert_eq!(pow_pushes.len(), 1, "service emit is pushed each row but gated by is_last_row");
	// On non-last rows, is_last_row = 0 so the count multiplied by neg_one is 0 — net no effect.
	assert_eq!(pow_pushes[0].1, Goldilocks::ZERO, "non-last-row service emit must have count = 0");
}

#[test]
fn last_row_emits_one_service_push_with_correct_count() {
	let mut base = [0u32; FIELD_NUM_LIMBS];
	base[0] = 7;
	let trace = build_field_pow_p58_trace::<Goldilocks>(&base);
	let air = FieldPowP58Air::new();
	let preproc =
		<FieldPowP58Air as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("preproc trace");
	let pp_values = preproc.values;

	let row = FIELD_POW_P58_HEIGHT - 1;
	let next = 0;
	let cur_slice = &trace[row * FIELD_POW_P58_NUM_COLS..(row + 1) * FIELD_POW_P58_NUM_COLS];
	let next_slice =
		&trace[next * FIELD_POW_P58_NUM_COLS..(next + 1) * FIELD_POW_P58_NUM_COLS];
	let pp_cur = &pp_values[row..row + 1];
	let pp_next = &pp_values[next..next + 1];
	let mut b = CountingBuilder {
		main_window: RowWindow::from_two_rows(cur_slice, next_slice),
		preprocessed_window: RowWindow::from_two_rows(pp_cur, pp_next),
		is_last_row: Goldilocks::ONE,
		pushed: Vec::new(),
	};
	<FieldPowP58Air as Air<CountingBuilder>>::eval(&air, &mut b);

	let pow_pushes: Vec<_> =
		b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_POW_P58).collect();
	assert_eq!(pow_pushes.len(), 1);
	assert_eq!(pow_pushes[0].1, Goldilocks::ZERO - Goldilocks::ONE, "provider count = -1");
	assert_eq!(pow_pushes[0].2, 16, "service payload = (base, result) × 8 limbs = 16 cells");
}

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_FIELD_POW_P58, "rostro-field-pow-p58");
}
