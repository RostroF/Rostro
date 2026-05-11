// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for `rostro-poseidon-sponge-air`.
//!
//! Three layers of coverage:
//! 1. Witness function `poseidon2_sponge_8` vs upstream
//!    `default_goldilocks_poseidon2_8` — proves the reference is the
//!    canonical permutation byte-for-byte.
//! 2. `SpongeShellAir::eval` against an `ExpectZeroBuilder` over an honest
//!    trace + corrupted-trace rejection — proves the in-row pre-MDS
//!    constraint is sound.
//! 3. Bus push count + bus name pin via a recording `InteractionBuilder` —
//!    proves the wiring contract (3 pushes: bus_query receive, bus_init_in
//!    send, bus_term_out receive) and that the bus name string is stable.
//!
//! End-to-end LogUp-balance verification across all four AIRs is left to
//! the integration test in `rostro-hash-to-field-air` (next phase, H4) —
//! that's the first place the full sponge service is consumed and the
//! natural site to assert balance under real prover wiring.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::{
	build_sponge_airs, build_sponge_shell_trace, poseidon2_sponge_8, SpongeShellAir,
	COL_INPUT, COL_OUTPUT, COL_POST_MDS, SPONGE_SHELL_NUM_COLS,
};
use rostro_poseidon_air::{mds_light_permutation_8, WIDTH};

// ─── Witness layer ─────────────────────────────────────────────────────────

#[test]
fn witness_matches_p3_default_zero_input() {
	use p3_goldilocks::default_goldilocks_poseidon2_8;
	use p3_symmetric::Permutation;

	let input = [Goldilocks::ZERO; WIDTH];
	let mut expected = input;
	default_goldilocks_poseidon2_8().permute_mut(&mut expected);
	assert_eq!(poseidon2_sponge_8(input), expected);
}

#[test]
fn witness_matches_p3_default_sequential_input() {
	use p3_goldilocks::default_goldilocks_poseidon2_8;
	use p3_symmetric::Permutation;

	let input: [Goldilocks; WIDTH] =
		core::array::from_fn(|i| Goldilocks::from_u64((i + 1) as u64));
	let mut expected = input;
	default_goldilocks_poseidon2_8().permute_mut(&mut expected);
	assert_eq!(poseidon2_sponge_8(input), expected);
}

#[test]
fn witness_matches_p3_default_random_inputs() {
	use p3_goldilocks::default_goldilocks_poseidon2_8;
	use p3_symmetric::Permutation;
	use rand::{rngs::StdRng, RngCore, SeedableRng};

	let mut rng = StdRng::seed_from_u64(0x5_0_5_e_0_3_8_a_u64);
	for _ in 0..100 {
		let input: [Goldilocks; WIDTH] =
			core::array::from_fn(|_| Goldilocks::from_u64(rng.next_u64()));
		let mut expected = input;
		default_goldilocks_poseidon2_8().permute_mut(&mut expected);
		assert_eq!(poseidon2_sponge_8(input), expected);
	}
}

// ─── Trace layout ──────────────────────────────────────────────────────────

#[test]
fn trace_layout_input_post_mds_output() {
	let input: [Goldilocks; WIDTH] =
		core::array::from_fn(|i| Goldilocks::from_u64((i * 17 + 3) as u64));
	let trace = build_sponge_shell_trace(input);
	let cells = trace.values;
	assert_eq!(cells.len(), SPONGE_SHELL_NUM_COLS);

	// Input segment
	for i in 0..WIDTH {
		assert_eq!(cells[COL_INPUT + i], input[i], "input cell {} mismatch", i);
	}
	// Post-MDS segment (independently re-derive)
	let mut expected_post_mds = input;
	mds_light_permutation_8(&mut expected_post_mds);
	for i in 0..WIDTH {
		assert_eq!(
			cells[COL_POST_MDS + i],
			expected_post_mds[i],
			"post_mds cell {} mismatch",
			i,
		);
	}
	// Output segment
	let expected_output = poseidon2_sponge_8(input);
	for i in 0..WIDTH {
		assert_eq!(
			cells[COL_OUTPUT + i],
			expected_output[i],
			"output cell {} mismatch",
			i,
		);
	}
}

// ─── ExpectZeroBuilder for AIR-eval tests ──────────────────────────────────

struct ExpectZeroBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	is_first: Goldilocks,
	is_last: Goldilocks,
	is_trans: Goldilocks,
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
		assert!(val.is_zero(), "constraint failed: value = {:?}", val);
	}
}

impl<'a> InteractionBuilder for ExpectZeroBuilder<'a> {
	fn push_interaction<E: Into<Self::Expr>>(
		&mut self,
		_bus_name: &str,
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

fn run_shell_eval(trace_row: &[Goldilocks]) {
	let air = SpongeShellAir::new("test-bus-query", "test-bus-init-in", "test-bus-term-out");
	// Single-row trace: pass row twice to satisfy from_two_rows; is_first =
	// is_last = 1, no transition active.
	let pp: [Goldilocks; 0] = [];
	let mut builder = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(trace_row, trace_row),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
		is_first: Goldilocks::ONE,
		is_last: Goldilocks::ONE,
		is_trans: Goldilocks::ZERO,
	};
	air.eval(&mut builder);
}

#[test]
fn shell_air_accepts_honest_trace_zero_input() {
	let trace = build_sponge_shell_trace([Goldilocks::ZERO; WIDTH]);
	run_shell_eval(&trace.values);
}

#[test]
fn shell_air_accepts_honest_trace_sequential_input() {
	let input: [Goldilocks; WIDTH] =
		core::array::from_fn(|i| Goldilocks::from_u64((i + 1) as u64 * 7));
	let trace = build_sponge_shell_trace(input);
	run_shell_eval(&trace.values);
}

#[test]
fn shell_air_accepts_honest_trace_random_inputs() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xa1_a1_a1_a1u64);
	for _ in 0..20 {
		let input: [Goldilocks; WIDTH] =
			core::array::from_fn(|_| Goldilocks::from_u64(rng.next_u64()));
		let trace = build_sponge_shell_trace(input);
		run_shell_eval(&trace.values);
	}
}

#[test]
#[should_panic(expected = "constraint failed")]
fn shell_air_rejects_corrupted_post_mds_cell_0() {
	let trace = build_sponge_shell_trace([Goldilocks::from_u64(42); WIDTH]);
	let mut cells = trace.values.clone();
	cells[COL_POST_MDS] += Goldilocks::ONE;
	run_shell_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn shell_air_rejects_corrupted_post_mds_cell_5() {
	let trace = build_sponge_shell_trace([Goldilocks::from_u64(42); WIDTH]);
	let mut cells = trace.values.clone();
	cells[COL_POST_MDS + 5] -= Goldilocks::ONE;
	run_shell_eval(&cells);
}

#[test]
fn shell_air_does_not_constrain_input_or_output_locally() {
	// Corrupting `input` or `output` violates LogUp balance with the round
	// chain (verified at integration time), but the local pre-MDS constraint
	// only binds post_mds to input. Sanity-check: corrupting only `output`
	// still passes the in-row constraint (it'll fail balance under a real
	// prover; that's the round chain's job, not the shell's).
	let trace = build_sponge_shell_trace([Goldilocks::from_u64(7); WIDTH]);
	let mut cells = trace.values.clone();
	cells[COL_OUTPUT + 3] += Goldilocks::ONE;
	run_shell_eval(&cells); // must NOT panic
}

// ─── Recording builder for bus-shape tests ─────────────────────────────────

#[derive(Default)]
struct RecordedPush {
	bus_name: String,
	field_count: usize,
}

struct RecordingBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	pushes: Vec<RecordedPush>,
}

impl<'a> AirBuilder for RecordingBuilder<'a> {
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
		Goldilocks::ONE
	}

	fn is_last_row(&self) -> Self::Expr {
		Goldilocks::ONE
	}

	fn is_transition_window(&self, _size: usize) -> Self::Expr {
		Goldilocks::ZERO
	}

	fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {
		// Constraint check is the ExpectZeroBuilder's job; here we only
		// record bus pushes. Drain the expression so no side effect leaks.
	}
}

impl<'a> InteractionBuilder for RecordingBuilder<'a> {
	fn push_interaction<E: Into<Self::Expr>>(
		&mut self,
		bus_name: &str,
		fields: impl IntoIterator<Item = E>,
		_count: impl Into<Self::Expr>,
		_count_weight: u32,
	) {
		let collected: Vec<Goldilocks> = fields.into_iter().map(Into::into).collect();
		self.pushes.push(RecordedPush {
			bus_name: String::from(bus_name),
			field_count: collected.len(),
		});
	}

	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

#[test]
fn shell_air_emits_three_bus_pushes_per_row() {
	let trace = build_sponge_shell_trace([Goldilocks::from_u64(5); WIDTH]);
	let pp: [Goldilocks; 0] = [];
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace.values, &trace.values),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
		pushes: Vec::new(),
	};
	let air = SpongeShellAir::new("rostro-poseidon-sponge", "init-in", "term-out");
	air.eval(&mut builder);

	assert_eq!(builder.pushes.len(), 3, "expected 3 bus pushes, got {}", builder.pushes.len());

	// Pin the order + payload sizes:
	// (1) bus_query receive, payload = input || output = 2*WIDTH cells
	assert_eq!(builder.pushes[0].bus_name, "rostro-poseidon-sponge");
	assert_eq!(builder.pushes[0].field_count, 2 * WIDTH);
	// (2) bus_init_in send, payload = post_mds = WIDTH cells
	assert_eq!(builder.pushes[1].bus_name, "init-in");
	assert_eq!(builder.pushes[1].field_count, WIDTH);
	// (3) bus_term_out receive, payload = output = WIDTH cells
	assert_eq!(builder.pushes[2].bus_name, "term-out");
	assert_eq!(builder.pushes[2].field_count, WIDTH);
}

// ─── SpongeAirs builder ───────────────────────────────────────────────────

#[test]
fn build_sponge_airs_threads_internal_bus_names_consistently() {
	let bundle = build_sponge_airs("hash-to-field-call-0");
	assert_eq!(bundle.shell.bus_query, "hash-to-field-call-0");
	// Shell SENDS on bus_init_in; Initial round AIR RECEIVES on bus_in.
	assert_eq!(bundle.shell.bus_init_in, bundle.external_initial.bus_in);
	// Initial → Internal handoff
	assert_eq!(bundle.external_initial.bus_out, bundle.internal.bus_in);
	// Internal → Terminal handoff
	assert_eq!(bundle.internal.bus_out, bundle.external_terminal.bus_in);
	// Terminal SENDS to bus_term_out; Shell RECEIVES on bus_term_out.
	assert_eq!(bundle.external_terminal.bus_out, bundle.shell.bus_term_out);
}

#[test]
fn build_sponge_airs_distinct_instances_have_distinct_internal_buses() {
	let a = build_sponge_airs("call-A");
	let b = build_sponge_airs("call-B");
	// Internal buses must NOT collide across instances; LogUp would otherwise
	// mix unrelated permutations.
	assert_ne!(a.shell.bus_init_in, b.shell.bus_init_in);
	assert_ne!(a.shell.bus_term_out, b.shell.bus_term_out);
	assert_ne!(a.internal.bus_in, b.internal.bus_in);
	assert_ne!(a.internal.bus_out, b.internal.bus_out);
}
