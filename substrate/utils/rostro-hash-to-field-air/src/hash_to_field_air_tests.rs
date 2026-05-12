// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`HashToFieldAir`].
//!
//! Coverage:
//! - Honest acceptance (zero, sequential, random private_nullifier).
//! - Per-constraint corruption rejection — packing tie, canonicality guard
//!   forward, canonicality guard reverse zero-test, low-zero clamp.
//! - Bus shape pin (count + payload sizes).
//!
//! Bus-balance verification across the SpongeShellAir + Reduce384Air
//! cluster is left for H6 integration time, where the full sponge +
//! reduction + h2f stack is composed against a real prover.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::hash_to_field_air::{
	build_hash_to_field_trace, HashToFieldAir, BUS_HASH_TO_FIELD,
	HASH_TO_FIELD_AIR_NUM_COLS,
};

const TEST_BUS_SPONGE_0: &str = "test-h2f-sponge-0";
const TEST_BUS_SPONGE_1: &str = "test-h2f-sponge-1";
const TEST_BUS_REDUCE_0: &str = "test-h2f-reduce-0";
const TEST_BUS_REDUCE_1: &str = "test-h2f-reduce-1";

fn make_air() -> HashToFieldAir {
	HashToFieldAir::new(
		BUS_HASH_TO_FIELD,
		TEST_BUS_SPONGE_0,
		TEST_BUS_SPONGE_1,
		TEST_BUS_REDUCE_0,
		TEST_BUS_REDUCE_1,
	)
}

// ─── ExpectZeroBuilder ─────────────────────────────────────────────────────

struct ExpectZeroBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
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
		Goldilocks::ONE
	}

	fn is_last_row(&self) -> Self::Expr {
		Goldilocks::ONE
	}

	fn is_transition_window(&self, _size: usize) -> Self::Expr {
		Goldilocks::ZERO
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

fn run_eval(trace_row: &[Goldilocks]) {
	let air = make_air();
	let pp: [Goldilocks; 0] = [];
	let mut builder = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(trace_row, trace_row),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
	};
	air.eval(&mut builder);
}

// ─── Honest acceptance ─────────────────────────────────────────────────────

#[test]
fn air_accepts_private_nullifier_zero() {
	let trace = build_hash_to_field_trace(Goldilocks::ZERO);
	run_eval(&trace.values);
}

#[test]
fn air_accepts_private_nullifier_one() {
	let trace = build_hash_to_field_trace(Goldilocks::ONE);
	run_eval(&trace.values);
}

#[test]
fn air_accepts_random_private_nullifier() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xa1_03_5_70u64);
	for _ in 0..30 {
		let pn = Goldilocks::from_u64(rng.next_u64());
		let trace = build_hash_to_field_trace(pn);
		run_eval(&trace.values);
	}
}

// ─── Corruption rejection ──────────────────────────────────────────────────

fn make_honest_trace() -> Vec<Goldilocks> {
	build_hash_to_field_trace(Goldilocks::from_u64(0xdead_beef)).values
}

#[allow(dead_code)]
const COL_PRIVATE_NULLIFIER: usize = 0;
const COL_W_0_GOLDILOCKS: usize = 1;
#[allow(dead_code)]
const COL_W_1_GOLDILOCKS: usize = 9;
const COL_W_0_U32: usize = 17;
#[allow(dead_code)]
const COL_W_1_U32: usize = 29;
const COL_CANON_HIGH_MAX_0: usize = 41;
const COL_CANON_INV_DIFF_0: usize = 47;
#[allow(dead_code)]
const COL_CANON_HIGH_MAX_1: usize = 53;
#[allow(dead_code)]
const COL_CANON_INV_DIFF_1: usize = 59;
const COL_U_0: usize = 65;
const COL_U_1: usize = 73;

#[test]
fn layout_offsets_are_internally_consistent() {
	// Sanity-pin the offsets used by corruption tests.
	assert_eq!(HASH_TO_FIELD_AIR_NUM_COLS, COL_U_1 + 8);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_bad_packing() {
	// Bump W_0[0]: now W_0[0] + 2^32 · W_0[1] != w_0[0].
	let mut cells = make_honest_trace();
	cells[COL_W_0_U32] += Goldilocks::ONE;
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_canon_high_max_set_when_high_not_max() {
	// For honest random pn, w_0_u32[1] is ~uniform in [0, 2^32) — almost
	// never 0xFFFFFFFF. So canon_high_max_0[0] honestly = 0. Set it to 1
	// to break the forward constraint: 1 · (W[1] - 0xFFFFFFFF) ≠ 0.
	let mut cells = make_honest_trace();
	cells[COL_CANON_HIGH_MAX_0] = Goldilocks::ONE;
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_canon_inv_diff_zeroed() {
	// Honest case: canon_high_max_0[0] = 0 and canon_inv_diff_0[0] =
	// (W[1] - max).inverse(). Zeroing inv_diff makes the reverse zero-test
	// fail: 0 + 0 - 1 = -1 != 0.
	let mut cells = make_honest_trace();
	cells[COL_CANON_INV_DIFF_0] = Goldilocks::ZERO;
	run_eval(&cells);
}

// u_0 / u_1 corruption is caught by LogUp imbalance against Reduce384Air's
// receive (which the in-row ExpectZeroBuilder cannot see); coverage moves
// to H6 integration time when the full sponge + reduce + h2f stack runs
// against a real LogUp-tracking prover.

#[test]
fn private_nullifier_changes_propagate_to_u_0() {
	// Determinism cross-check via the trace builder, not the AIR.
	let t1 = build_hash_to_field_trace(Goldilocks::from_u64(1));
	let t2 = build_hash_to_field_trace(Goldilocks::from_u64(2));
	// u_0 occupies cells [COL_U_0, COL_U_0 + 8); they must differ.
	let mut differ = false;
	for i in 0..8 {
		if t1.values[COL_U_0 + i] != t2.values[COL_U_0 + i] {
			differ = true;
			break;
		}
	}
	assert!(differ, "u_0 must depend on private_nullifier");
}

// ─── Synthetic adversarial canonicality attack ─────────────────────────────

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_non_canonical_goldilocks_encoding_attack() {
	// Construct a synthetic trace where w_0[0] = 0 but the prover
	// witnesses the non-canonical encoding (W_0[0] = 1, W_0[1] =
	// 0xFFFFFFFF) and tries to disable the guard by setting
	// canon_high_max_0[0] = 0. The reverse zero-test catches it: with
	// W_0[1] = 0xFFFFFFFF, diff = 0, so 0 · inv_diff + 0 - 1 = -1 ≠ 0.
	let mut cells = make_honest_trace();
	// Force w_0[0] (Goldilocks) to 0.
	cells[COL_W_0_GOLDILOCKS] = Goldilocks::ZERO;
	// Fake non-canonical packing.
	cells[COL_W_0_U32] = Goldilocks::ONE;
	cells[COL_W_0_U32 + 1] = Goldilocks::from_u64(0xFFFF_FFFF);
	// Disable the guard.
	cells[COL_CANON_HIGH_MAX_0] = Goldilocks::ZERO;
	cells[COL_CANON_INV_DIFF_0] = Goldilocks::ZERO;
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_non_canonical_with_guard_high_max_set_but_low_nonzero() {
	// Same setup but adversary sets canon_high_max_0[0] = 1 honestly
	// (acknowledging high = max). Then the W[2k] = 0 clamp must fire,
	// since W[0] = 1.
	let mut cells = make_honest_trace();
	cells[COL_W_0_GOLDILOCKS] = Goldilocks::ZERO;
	cells[COL_W_0_U32] = Goldilocks::ONE;
	cells[COL_W_0_U32 + 1] = Goldilocks::from_u64(0xFFFF_FFFF);
	cells[COL_CANON_HIGH_MAX_0] = Goldilocks::ONE;
	cells[COL_CANON_INV_DIFF_0] = Goldilocks::ZERO; // unconstrained when high_max=1
	run_eval(&cells);
}

// ─── Bus shape ─────────────────────────────────────────────────────────────

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

	fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
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
fn bus_pushes_match_documented_shape() {
	let cells = make_honest_trace();
	let pp: [Goldilocks; 0] = [];
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&cells, &cells),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
		pushes: Vec::new(),
	};
	let air = make_air();
	air.eval(&mut builder);

	assert_eq!(
		builder.pushes.len(),
		5,
		"expected 5 bus pushes (2 sponge + 2 reduce + 1 service); got {}",
		builder.pushes.len(),
	);

	// Order of pushes mirrors the eval body.
	assert_eq!(builder.pushes[0].bus_name, TEST_BUS_SPONGE_0);
	assert_eq!(builder.pushes[0].field_count, 16, "sponge_0 payload");
	assert_eq!(builder.pushes[1].bus_name, TEST_BUS_SPONGE_1);
	assert_eq!(builder.pushes[1].field_count, 16, "sponge_1 payload");
	assert_eq!(builder.pushes[2].bus_name, TEST_BUS_REDUCE_0);
	assert_eq!(builder.pushes[2].field_count, 20, "reduce_0 payload");
	assert_eq!(builder.pushes[3].bus_name, TEST_BUS_REDUCE_1);
	assert_eq!(builder.pushes[3].field_count, 20, "reduce_1 payload");
	assert_eq!(builder.pushes[4].bus_name, BUS_HASH_TO_FIELD);
	assert_eq!(builder.pushes[4].field_count, 17, "service payload");
}

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_HASH_TO_FIELD, "rostro-hash-to-field");
}

#[test]
fn trace_width_pin() {
	assert_eq!(HASH_TO_FIELD_AIR_NUM_COLS, 81);
}
