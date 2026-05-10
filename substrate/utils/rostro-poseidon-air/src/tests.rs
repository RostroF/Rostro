// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for the Goldilocks-Poseidon2 external-round AIR.
//!
//! Strategy: build a real-valued (state + S-box intermediate) trace by running
//! the per-round permutation in plain Rust against Goldilocks values, then drive
//! [`ExternalRoundAir::eval`] with an [`ExpectZeroBuilder`] that asserts every
//! constraint expression evaluates to the field's zero. Cross-check the final
//! output state against `p3_poseidon2::external_terminal_permute_state` to prove
//! the per-round reference matches the upstream permutation byte-for-byte.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::{
	GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
	Goldilocks,
};
use p3_goldilocks::{GOLDILOCKS_POSEIDON2_RC_8_INTERNAL, MATRIX_DIAG_8_GOLDILOCKS};
use p3_poseidon2::{
	MDSMat4, add_rc_and_sbox_generic, external_terminal_permute_state, internal_permute_state,
	matmul_internal,
};

use crate::external_round::{
	COL_STATE, COL_X_SQUARED, COL_X_TO_4, EXTERNAL_ROUND_NUM_COLS, ExternalRoundAir,
	ExternalRoundKind, HALF_FULL_ROUNDS, PREPROCESSED_NUM_COLS, TRACE_HEIGHT, WIDTH,
	mds_light_permutation_8,
};
use crate::internal_round::{
	COL_INT_STATE, COL_INT_X_SQUARED, COL_INT_X_TO_4, INTERNAL_ROUND_NUM_COLS, InternalRoundAir,
	PARTIAL_ROUNDS, PREPROCESSED_NUM_COLS_INTERNAL, TRACE_HEIGHT_INTERNAL,
	internal_linear_layer_8,
};

/// Pure-Rust reference for one external round at concrete Goldilocks values.
///
/// Returns `(next_state, x_squared, x_to_4)` so a trace builder can fill the
/// witness intermediate-witness columns.
fn ref_step_external_round(
	state: [Goldilocks; WIDTH],
	rc: [Goldilocks; WIDTH],
) -> ([Goldilocks; WIDTH], [Goldilocks; WIDTH], [Goldilocks; WIDTH]) {
	let x: [Goldilocks; WIDTH] = core::array::from_fn(|i| state[i] + rc[i]);
	let x_squared: [Goldilocks; WIDTH] = core::array::from_fn(|i| x[i] * x[i]);
	let x_to_4: [Goldilocks; WIDTH] = core::array::from_fn(|i| x_squared[i] * x_squared[i]);
	let mut sbox_out: [Goldilocks; WIDTH] =
		core::array::from_fn(|i| x[i] * x_squared[i] * x_to_4[i]);
	mds_light_permutation_8(&mut sbox_out);
	(sbox_out, x_squared, x_to_4)
}

/// Build a 5-row witness trace + 5-row preprocessed trace from an input state
/// and a round-constant table. Returns the flat row-major buffers.
fn build_traces(
	input_state: [Goldilocks; WIDTH],
	rc_table: &[[Goldilocks; WIDTH]; HALF_FULL_ROUNDS],
) -> (Vec<Goldilocks>, Vec<Goldilocks>) {
	let mut witness = Vec::with_capacity(TRACE_HEIGHT * EXTERNAL_ROUND_NUM_COLS);
	let mut preprocessed = Vec::with_capacity(TRACE_HEIGHT * PREPROCESSED_NUM_COLS);

	let mut state = input_state;
	for round in 0..HALF_FULL_ROUNDS {
		let rc = rc_table[round];
		let (next_state, x_squared, x_to_4) = ref_step_external_round(state, rc);

		witness.extend_from_slice(&state);
		witness.extend_from_slice(&x_squared);
		witness.extend_from_slice(&x_to_4);
		preprocessed.extend_from_slice(&rc);

		state = next_state;
	}

	witness.extend_from_slice(&state);
	for _ in 0..(WIDTH * 2) {
		witness.push(Goldilocks::ZERO);
	}
	for _ in 0..WIDTH {
		preprocessed.push(Goldilocks::ZERO);
	}

	(witness, preprocessed)
}

/// Concrete-valued [`AirBuilder`] for tests. Each `assert_zero` panics if the
/// supplied expression doesn't evaluate to the field's additive identity.
struct ExpectZeroBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	is_first: Goldilocks,
	is_last: Goldilocks,
	is_trans: Goldilocks,
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
		self.is_first
	}

	fn is_last_row(&self) -> Self::Expr {
		self.is_last
	}

	fn is_transition_window(&self, size: usize) -> Self::Expr {
		assert_eq!(size, 2, "ExpectZeroBuilder only supports 2-row windows");
		self.is_trans
	}

	fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
		let val: Goldilocks = x.into();
		assert!(
			val.is_zero(),
			"constraint failed at row pair starting at row {}: value = {:?}",
			self.row_label,
			val,
		);
	}
}

fn run_eval_for_pair(
	air: &ExternalRoundAir,
	witness: &[Goldilocks],
	preprocessed: &[Goldilocks],
	current_row: usize,
	is_last_pair: bool,
) {
	let main_curr = &witness
		[current_row * EXTERNAL_ROUND_NUM_COLS..(current_row + 1) * EXTERNAL_ROUND_NUM_COLS];
	let main_next = &witness[(current_row + 1) * EXTERNAL_ROUND_NUM_COLS
		..(current_row + 2) * EXTERNAL_ROUND_NUM_COLS];
	let pre_curr = &preprocessed
		[current_row * PREPROCESSED_NUM_COLS..(current_row + 1) * PREPROCESSED_NUM_COLS];
	let pre_next = &preprocessed[(current_row + 1) * PREPROCESSED_NUM_COLS
		..(current_row + 2) * PREPROCESSED_NUM_COLS];

	let main_window = RowWindow::from_two_rows(main_curr, main_next);
	let preprocessed_window = RowWindow::from_two_rows(pre_curr, pre_next);

	let is_first = if current_row == 0 { Goldilocks::ONE } else { Goldilocks::ZERO };
	let is_last = if is_last_pair { Goldilocks::ONE } else { Goldilocks::ZERO };
	let is_trans = if is_last_pair { Goldilocks::ZERO } else { Goldilocks::ONE };

	let mut builder = ExpectZeroBuilder {
		main_window,
		preprocessed_window,
		is_first,
		is_last,
		is_trans,
		row_label: current_row,
	};
	air.eval(&mut builder);
}

fn check_trace(
	air: &ExternalRoundAir,
	input_state: [Goldilocks; WIDTH],
) -> [Goldilocks; WIDTH] {
	let rc_table = air.round_constants();
	let (witness, preprocessed) = build_traces(input_state, rc_table);

	for row in 0..(TRACE_HEIGHT - 1) {
		let is_last_pair = row == TRACE_HEIGHT - 2;
		run_eval_for_pair(air, &witness, &preprocessed, row, is_last_pair);
	}

	let last_row_start = (TRACE_HEIGHT - 1) * EXTERNAL_ROUND_NUM_COLS + COL_STATE;
	let mut output = [Goldilocks::ZERO; WIDTH];
	for i in 0..WIDTH {
		output[i] = witness[last_row_start + i];
	}
	output
}

fn input_vector_seq() -> [Goldilocks; WIDTH] {
	core::array::from_fn(|i| Goldilocks::from_u64(i as u64))
}

fn input_vector_arbitrary() -> [Goldilocks; WIDTH] {
	let raw: [u64; WIDTH] = [
		0xa3c2_5b1f_4e7d_8a09,
		0x12fb_3984_77c1_d2e6,
		0x55aa_55aa_55aa_55aa,
		0x0000_0001_0000_0001,
		0xffff_fffe_ffff_fffe,
		0x7f80_8182_8384_8586,
		0x1111_2222_3333_4444,
		0xdead_beef_cafe_babe,
	];
	core::array::from_fn(|i| Goldilocks::from_u64(raw[i]))
}

#[test]
fn external_round_constants_widths_match() {
	assert_eq!(EXTERNAL_ROUND_NUM_COLS, 24);
	assert_eq!(PREPROCESSED_NUM_COLS, 8);
	assert_eq!(TRACE_HEIGHT, 5);
	assert_eq!(GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL.len(), HALF_FULL_ROUNDS);
	assert_eq!(GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL.len(), HALF_FULL_ROUNDS);
}

#[test]
fn base_air_width_reports_correctly() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Initial);
	let w = <ExternalRoundAir as BaseAir<Goldilocks>>::width(&air);
	assert_eq!(w, EXTERNAL_ROUND_NUM_COLS);
}

#[test]
fn preprocessed_trace_initial_matches_constants_table() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Initial);
	let pre =
		<ExternalRoundAir as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("Some");
	assert_eq!(pre.values.len(), TRACE_HEIGHT * PREPROCESSED_NUM_COLS);
	assert_eq!(pre.width, PREPROCESSED_NUM_COLS);

	for round in 0..HALF_FULL_ROUNDS {
		for i in 0..WIDTH {
			let trace_val = pre.values[round * PREPROCESSED_NUM_COLS + i];
			let expected = GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL[round][i];
			assert_eq!(trace_val, expected, "round {} cell {}", round, i);
		}
	}
	for i in 0..WIDTH {
		let last_row_val =
			pre.values[(TRACE_HEIGHT - 1) * PREPROCESSED_NUM_COLS + i];
		assert_eq!(last_row_val, Goldilocks::ZERO);
	}
}

#[test]
fn preprocessed_trace_terminal_matches_constants_table() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Terminal);
	let pre =
		<ExternalRoundAir as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("Some");
	for round in 0..HALF_FULL_ROUNDS {
		for i in 0..WIDTH {
			let trace_val = pre.values[round * PREPROCESSED_NUM_COLS + i];
			let expected = GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL[round][i];
			assert_eq!(trace_val, expected, "round {} cell {}", round, i);
		}
	}
}

#[test]
fn ref_step_matches_p3_poseidon2_initial_constants() {
	let mut state_p3 = input_vector_seq();
	external_terminal_permute_state(
		&mut state_p3,
		&GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
		add_rc_and_sbox_generic::<Goldilocks, Goldilocks, 7>,
		&MDSMat4,
	);

	let mut state_ref = input_vector_seq();
	for round in 0..HALF_FULL_ROUNDS {
		let (next, _xs, _x4) =
			ref_step_external_round(state_ref, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL[round]);
		state_ref = next;
	}

	assert_eq!(state_ref, state_p3, "reference per-round impl diverges from p3-poseidon2");
}

#[test]
fn ref_step_matches_p3_poseidon2_terminal_constants() {
	let mut state_p3 = input_vector_arbitrary();
	external_terminal_permute_state(
		&mut state_p3,
		&GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
		add_rc_and_sbox_generic::<Goldilocks, Goldilocks, 7>,
		&MDSMat4,
	);

	let mut state_ref = input_vector_arbitrary();
	for round in 0..HALF_FULL_ROUNDS {
		let (next, _xs, _x4) =
			ref_step_external_round(state_ref, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL[round]);
		state_ref = next;
	}

	assert_eq!(state_ref, state_p3, "reference per-round impl diverges from p3-poseidon2");
}

#[test]
fn air_eval_accepts_honest_initial_block_zero_input() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Initial);
	let _output = check_trace(&air, [Goldilocks::ZERO; WIDTH]);
}

#[test]
fn air_eval_accepts_honest_initial_block_seq_input() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Initial);
	let output = check_trace(&air, input_vector_seq());

	let mut expected = input_vector_seq();
	external_terminal_permute_state(
		&mut expected,
		&GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
		add_rc_and_sbox_generic::<Goldilocks, Goldilocks, 7>,
		&MDSMat4,
	);
	assert_eq!(output, expected, "AIR-attested output diverges from p3-poseidon2");
}

#[test]
fn air_eval_accepts_honest_terminal_block_arbitrary_input() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Terminal);
	let output = check_trace(&air, input_vector_arbitrary());

	let mut expected = input_vector_arbitrary();
	external_terminal_permute_state(
		&mut expected,
		&GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
		add_rc_and_sbox_generic::<Goldilocks, Goldilocks, 7>,
		&MDSMat4,
	);
	assert_eq!(output, expected, "AIR-attested output diverges from p3-poseidon2");
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_eval_rejects_corrupted_x_squared() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Initial);
	let rc_table = air.round_constants();
	let (mut witness, preprocessed) = build_traces(input_vector_seq(), rc_table);

	let target = COL_X_SQUARED + 3;
	witness[target] = witness[target] + Goldilocks::ONE;

	for row in 0..(TRACE_HEIGHT - 1) {
		let is_last_pair = row == TRACE_HEIGHT - 2;
		run_eval_for_pair(&air, &witness, &preprocessed, row, is_last_pair);
	}
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_eval_rejects_corrupted_x_to_4() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Initial);
	let rc_table = air.round_constants();
	let (mut witness, preprocessed) = build_traces(input_vector_seq(), rc_table);

	let target = COL_X_TO_4 + 5;
	witness[target] = witness[target] + Goldilocks::ONE;

	for row in 0..(TRACE_HEIGHT - 1) {
		let is_last_pair = row == TRACE_HEIGHT - 2;
		run_eval_for_pair(&air, &witness, &preprocessed, row, is_last_pair);
	}
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_eval_rejects_corrupted_next_state_cell() {
	let air = ExternalRoundAir::new(ExternalRoundKind::Initial);
	let rc_table = air.round_constants();
	let (mut witness, preprocessed) = build_traces(input_vector_seq(), rc_table);

	let next_row_state_cell_0 = EXTERNAL_ROUND_NUM_COLS + COL_STATE + 0;
	witness[next_row_state_cell_0] = witness[next_row_state_cell_0] + Goldilocks::ONE;

	for row in 0..(TRACE_HEIGHT - 1) {
		let is_last_pair = row == TRACE_HEIGHT - 2;
		run_eval_for_pair(&air, &witness, &preprocessed, row, is_last_pair);
	}
}

// ---------------------------------------------------------------------------
// Internal-round AIR tests.
// ---------------------------------------------------------------------------

/// Pure-Rust reference for one internal round at concrete Goldilocks values.
///
/// Returns `(next_state, x_squared, x_to_4)` — `x_squared` and `x_to_4` are
/// scalars because the S-box only fires on cell 0.
fn ref_step_internal_round(
	state: [Goldilocks; WIDTH],
	rc: Goldilocks,
) -> ([Goldilocks; WIDTH], Goldilocks, Goldilocks) {
	let x = state[0] + rc;
	let x_squared = x * x;
	let x_to_4 = x_squared * x_squared;
	let x_to_7 = x * x_squared * x_to_4;

	let mut sbox_out: [Goldilocks; WIDTH] = state;
	sbox_out[0] = x_to_7;

	let diag: [Goldilocks; WIDTH] = MATRIX_DIAG_8_GOLDILOCKS;
	internal_linear_layer_8(&mut sbox_out, &diag);

	(sbox_out, x_squared, x_to_4)
}

/// Build a 23-row internal-round witness + preprocessed trace pair.
fn build_traces_internal(
	input_state: [Goldilocks; WIDTH],
) -> (Vec<Goldilocks>, Vec<Goldilocks>) {
	let mut witness =
		Vec::with_capacity(TRACE_HEIGHT_INTERNAL * INTERNAL_ROUND_NUM_COLS);
	let mut preprocessed =
		Vec::with_capacity(TRACE_HEIGHT_INTERNAL * PREPROCESSED_NUM_COLS_INTERNAL);

	let mut state = input_state;
	for round in 0..PARTIAL_ROUNDS {
		let rc = GOLDILOCKS_POSEIDON2_RC_8_INTERNAL[round];
		let (next_state, x_squared, x_to_4) = ref_step_internal_round(state, rc);

		witness.extend_from_slice(&state);
		witness.push(x_squared);
		witness.push(x_to_4);
		preprocessed.push(rc);

		state = next_state;
	}

	witness.extend_from_slice(&state);
	witness.push(Goldilocks::ZERO);
	witness.push(Goldilocks::ZERO);
	preprocessed.push(Goldilocks::ZERO);

	(witness, preprocessed)
}

fn run_eval_for_pair_internal(
	air: &InternalRoundAir,
	witness: &[Goldilocks],
	preprocessed: &[Goldilocks],
	current_row: usize,
	is_last_pair: bool,
) {
	let main_curr = &witness
		[current_row * INTERNAL_ROUND_NUM_COLS..(current_row + 1) * INTERNAL_ROUND_NUM_COLS];
	let main_next = &witness[(current_row + 1) * INTERNAL_ROUND_NUM_COLS
		..(current_row + 2) * INTERNAL_ROUND_NUM_COLS];
	let pre_curr = &preprocessed[current_row * PREPROCESSED_NUM_COLS_INTERNAL
		..(current_row + 1) * PREPROCESSED_NUM_COLS_INTERNAL];
	let pre_next = &preprocessed[(current_row + 1) * PREPROCESSED_NUM_COLS_INTERNAL
		..(current_row + 2) * PREPROCESSED_NUM_COLS_INTERNAL];

	let main_window = RowWindow::from_two_rows(main_curr, main_next);
	let preprocessed_window = RowWindow::from_two_rows(pre_curr, pre_next);

	let is_first = if current_row == 0 { Goldilocks::ONE } else { Goldilocks::ZERO };
	let is_last = if is_last_pair { Goldilocks::ONE } else { Goldilocks::ZERO };
	let is_trans = if is_last_pair { Goldilocks::ZERO } else { Goldilocks::ONE };

	let mut builder = ExpectZeroBuilder {
		main_window,
		preprocessed_window,
		is_first,
		is_last,
		is_trans,
		row_label: current_row,
	};
	air.eval(&mut builder);
}

fn check_trace_internal(
	air: &InternalRoundAir,
	input_state: [Goldilocks; WIDTH],
) -> [Goldilocks; WIDTH] {
	let (witness, preprocessed) = build_traces_internal(input_state);

	for row in 0..(TRACE_HEIGHT_INTERNAL - 1) {
		let is_last_pair = row == TRACE_HEIGHT_INTERNAL - 2;
		run_eval_for_pair_internal(air, &witness, &preprocessed, row, is_last_pair);
	}

	let last_row_start = (TRACE_HEIGHT_INTERNAL - 1) * INTERNAL_ROUND_NUM_COLS + COL_INT_STATE;
	let mut output = [Goldilocks::ZERO; WIDTH];
	for i in 0..WIDTH {
		output[i] = witness[last_row_start + i];
	}
	output
}

#[test]
fn internal_round_constants_widths_match() {
	assert_eq!(INTERNAL_ROUND_NUM_COLS, 10);
	assert_eq!(PREPROCESSED_NUM_COLS_INTERNAL, 1);
	assert_eq!(TRACE_HEIGHT_INTERNAL, 23);
	assert_eq!(GOLDILOCKS_POSEIDON2_RC_8_INTERNAL.len(), PARTIAL_ROUNDS);
	assert_eq!(COL_INT_X_SQUARED, WIDTH);
	assert_eq!(COL_INT_X_TO_4, WIDTH + 1);
}

#[test]
fn internal_base_air_width_reports_correctly() {
	let air = InternalRoundAir::new();
	let w = <InternalRoundAir as BaseAir<Goldilocks>>::width(&air);
	assert_eq!(w, INTERNAL_ROUND_NUM_COLS);
}

#[test]
fn internal_preprocessed_trace_matches_constants_table() {
	let air = InternalRoundAir::new();
	let pre =
		<InternalRoundAir as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("Some");
	assert_eq!(pre.values.len(), TRACE_HEIGHT_INTERNAL * PREPROCESSED_NUM_COLS_INTERNAL);
	assert_eq!(pre.width, PREPROCESSED_NUM_COLS_INTERNAL);

	for round in 0..PARTIAL_ROUNDS {
		let trace_val = pre.values[round];
		let expected = GOLDILOCKS_POSEIDON2_RC_8_INTERNAL[round];
		assert_eq!(trace_val, expected, "round {}", round);
	}
	let last_row_val = pre.values[TRACE_HEIGHT_INTERNAL - 1];
	assert_eq!(last_row_val, Goldilocks::ZERO);
}

#[test]
fn ref_internal_step_matches_p3_poseidon2_seq_input() {
	let mut state_p3 = input_vector_seq();
	internal_permute_state::<Goldilocks, Goldilocks, WIDTH, 7>(
		&mut state_p3,
		|s| matmul_internal(s, MATRIX_DIAG_8_GOLDILOCKS),
		&GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
	);

	let mut state_ref = input_vector_seq();
	for round in 0..PARTIAL_ROUNDS {
		let (next, _xs, _x4) =
			ref_step_internal_round(state_ref, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL[round]);
		state_ref = next;
	}

	assert_eq!(state_ref, state_p3, "internal-round reference diverges from p3-poseidon2");
}

#[test]
fn ref_internal_step_matches_p3_poseidon2_arbitrary_input() {
	let mut state_p3 = input_vector_arbitrary();
	internal_permute_state::<Goldilocks, Goldilocks, WIDTH, 7>(
		&mut state_p3,
		|s| matmul_internal(s, MATRIX_DIAG_8_GOLDILOCKS),
		&GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
	);

	let mut state_ref = input_vector_arbitrary();
	for round in 0..PARTIAL_ROUNDS {
		let (next, _xs, _x4) =
			ref_step_internal_round(state_ref, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL[round]);
		state_ref = next;
	}

	assert_eq!(state_ref, state_p3, "internal-round reference diverges from p3-poseidon2");
}

#[test]
fn internal_air_eval_accepts_honest_zero_input() {
	let air = InternalRoundAir::new();
	let _output = check_trace_internal(&air, [Goldilocks::ZERO; WIDTH]);
}

#[test]
fn internal_air_eval_accepts_honest_seq_input() {
	let air = InternalRoundAir::new();
	let output = check_trace_internal(&air, input_vector_seq());

	let mut expected = input_vector_seq();
	internal_permute_state::<Goldilocks, Goldilocks, WIDTH, 7>(
		&mut expected,
		|s| matmul_internal(s, MATRIX_DIAG_8_GOLDILOCKS),
		&GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
	);
	assert_eq!(output, expected, "AIR-attested internal output diverges from p3-poseidon2");
}

#[test]
fn internal_air_eval_accepts_honest_arbitrary_input() {
	let air = InternalRoundAir::new();
	let output = check_trace_internal(&air, input_vector_arbitrary());

	let mut expected = input_vector_arbitrary();
	internal_permute_state::<Goldilocks, Goldilocks, WIDTH, 7>(
		&mut expected,
		|s| matmul_internal(s, MATRIX_DIAG_8_GOLDILOCKS),
		&GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
	);
	assert_eq!(output, expected, "AIR-attested internal output diverges from p3-poseidon2");
}

#[test]
#[should_panic(expected = "constraint failed")]
fn internal_air_eval_rejects_corrupted_x_squared() {
	let air = InternalRoundAir::new();
	let (mut witness, preprocessed) = build_traces_internal(input_vector_seq());

	witness[COL_INT_X_SQUARED] = witness[COL_INT_X_SQUARED] + Goldilocks::ONE;

	for row in 0..(TRACE_HEIGHT_INTERNAL - 1) {
		let is_last_pair = row == TRACE_HEIGHT_INTERNAL - 2;
		run_eval_for_pair_internal(&air, &witness, &preprocessed, row, is_last_pair);
	}
}

#[test]
#[should_panic(expected = "constraint failed")]
fn internal_air_eval_rejects_corrupted_x_to_4() {
	let air = InternalRoundAir::new();
	let (mut witness, preprocessed) = build_traces_internal(input_vector_seq());

	witness[COL_INT_X_TO_4] = witness[COL_INT_X_TO_4] + Goldilocks::ONE;

	for row in 0..(TRACE_HEIGHT_INTERNAL - 1) {
		let is_last_pair = row == TRACE_HEIGHT_INTERNAL - 2;
		run_eval_for_pair_internal(&air, &witness, &preprocessed, row, is_last_pair);
	}
}

/// Compose all three AIRs' references end-to-end and check the result matches
/// the upstream `default_goldilocks_poseidon2_8` permutation exactly. This is
/// the load-bearing test: it proves that (a) the pre-MDS handled at the
/// call-site, (b) the 4 initial rounds in `ExternalRoundAir` (Initial), (c) the
/// 22 partial rounds in `InternalRoundAir`, and (d) the 4 terminal rounds in
/// `ExternalRoundAir` (Terminal) compose into the same permutation that
/// upstream Plonky3 ships.
#[test]
fn full_permutation_composition_matches_p3_default() {
	use p3_goldilocks::default_goldilocks_poseidon2_8;
	use p3_poseidon2::mds_light_permutation;
	use p3_symmetric::Permutation;

	let input = input_vector_arbitrary();

	let mut state = input;
	mds_light_permutation::<Goldilocks, MDSMat4, WIDTH>(&mut state, &MDSMat4);

	let initial_air = ExternalRoundAir::new(ExternalRoundKind::Initial);
	for round in 0..HALF_FULL_ROUNDS {
		let (next, _xs, _x4) = ref_step_external_round(state, initial_air.round_constants()[round]);
		state = next;
	}

	for round in 0..PARTIAL_ROUNDS {
		let (next, _xs, _x4) =
			ref_step_internal_round(state, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL[round]);
		state = next;
	}

	let terminal_air = ExternalRoundAir::new(ExternalRoundKind::Terminal);
	for round in 0..HALF_FULL_ROUNDS {
		let (next, _xs, _x4) =
			ref_step_external_round(state, terminal_air.round_constants()[round]);
		state = next;
	}

	let mut expected = input;
	let perm = default_goldilocks_poseidon2_8();
	perm.permute_mut(&mut expected);

	assert_eq!(state, expected, "composed AIR references diverge from default_goldilocks_poseidon2_8");
}

#[test]
#[should_panic(expected = "constraint failed")]
fn internal_air_eval_rejects_corrupted_state_cell_5() {
	let air = InternalRoundAir::new();
	let (mut witness, preprocessed) = build_traces_internal(input_vector_seq());

	let next_row_state_5 = INTERNAL_ROUND_NUM_COLS + COL_INT_STATE + 5;
	witness[next_row_state_5] = witness[next_row_state_5] + Goldilocks::ONE;

	for row in 0..(TRACE_HEIGHT_INTERNAL - 1) {
		let is_last_pair = row == TRACE_HEIGHT_INTERNAL - 2;
		run_eval_for_pair_internal(&air, &witness, &preprocessed, row, is_last_pair);
	}
}
