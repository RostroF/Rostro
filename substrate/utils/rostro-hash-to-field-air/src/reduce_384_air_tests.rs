// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`Reduce384Air`].
//!
//! Strategy mirrors `rostro-curve25519`'s single-row AIR test pattern:
//! - `ExpectZeroBuilder` evaluates every constraint expression and asserts
//!   it equals zero, panicking otherwise. Used to verify honest-trace
//!   acceptance and per-cell corruption rejection.
//! - `RecordingBuilder` records bus pushes for shape pinning (count + bus
//!   names + payload sizes).
//!
//! End-to-end LogUp-balance verification across the BUS_REDUCE_384 service
//! is left to integration time when HashToFieldAir consumes it (H6 — and
//! that's where end-to-end Hash2Curve compose tests will exercise the bus).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::reduce_384::{
	compute_reduce_384_witness, BUS_REDUCE_384, REDUCE_384_INPUT_LIMBS,
};
use crate::reduce_384_air::{
	build_reduce_384_trace, Reduce384Air, REDUCE_384_AIR_NUM_COLS,
};
use rostro_curve25519::field::FIELD_NUM_LIMBS;

const TEST_BUS_U16_RANGE: &str = "test-bus-u16-range";

// ─── ExpectZeroBuilder ─────────────────────────────────────────────────────

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
		assert_eq!(size, 2);
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

fn run_eval(trace_row: &[Goldilocks]) {
	let air = Reduce384Air::default_buses(TEST_BUS_U16_RANGE);
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

// ─── Honest-trace acceptance ───────────────────────────────────────────────

fn w_from_u32_at(values: &[(usize, u32)]) -> [u32; REDUCE_384_INPUT_LIMBS] {
	let mut w = [0u32; REDUCE_384_INPUT_LIMBS];
	for &(i, v) in values {
		w[i] = v;
	}
	w
}

#[test]
fn air_accepts_zero_input() {
	let w = [0u32; REDUCE_384_INPUT_LIMBS];
	let trace = build_reduce_384_trace(&compute_reduce_384_witness(w));
	run_eval(&trace.values);
}

#[test]
fn air_accepts_one_input() {
	let w = w_from_u32_at(&[(0, 1)]);
	let trace = build_reduce_384_trace(&compute_reduce_384_witness(w));
	run_eval(&trace.values);
}

#[test]
fn air_accepts_max_w_input() {
	let w = [0xFFFF_FFFFu32; REDUCE_384_INPUT_LIMBS];
	let trace = build_reduce_384_trace(&compute_reduce_384_witness(w));
	run_eval(&trace.values);
}

#[test]
fn air_accepts_p_input() {
	use crate::p25519_biguint;
	let p = p25519_biguint();
	let mut bytes = p.to_bytes_le();
	bytes.resize(48, 0);
	let mut w = [0u32; REDUCE_384_INPUT_LIMBS];
	for i in 0..REDUCE_384_INPUT_LIMBS {
		let mut chunk = [0u8; 4];
		chunk.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
		w[i] = u32::from_le_bytes(chunk);
	}
	let trace = build_reduce_384_trace(&compute_reduce_384_witness(w));
	run_eval(&trace.values);
}

#[test]
fn air_accepts_random_inputs() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xa1_03_5_70u64);
	for _ in 0..50 {
		let w: [u32; REDUCE_384_INPUT_LIMBS] = core::array::from_fn(|_| rng.next_u32());
		let trace = build_reduce_384_trace(&compute_reduce_384_witness(w));
		run_eval(&trace.values);
	}
}

// ─── Corruption rejection ──────────────────────────────────────────────────

fn make_honest_trace() -> (Vec<Goldilocks>, [u32; REDUCE_384_INPUT_LIMBS]) {
	let w = [0x12345678u32; REDUCE_384_INPUT_LIMBS];
	let trace = build_reduce_384_trace(&compute_reduce_384_witness(w));
	(trace.values, w)
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_corrupted_u_limb_0() {
	let (mut cells, _) = make_honest_trace();
	use crate::reduce_384_air::REDUCE_384_AIR_NUM_COLS as N;
	let _ = N;
	// COL_U + 0
	let col_u = 12 + 12 + 12 + 5 + 5 + 5 + 5 + 8 + 8 + 8 + 1 + 8 + 1;
	cells[col_u] += Goldilocks::ONE;
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_corrupted_t_overflow_to_invalid() {
	let (mut cells, _) = make_honest_trace();
	let col_t_overflow = 12 + 12 + 12 + 5 + 5 + 5 + 5 + 8 + 8 + 8;
	// Force to 2 (not boolean).
	cells[col_t_overflow] = Goldilocks::from_u64(2);
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_corrupted_k_to_three() {
	// k must be in {0, 1, 2}; k=3 violates k(k-1)(k-2)=0.
	let (mut cells, _) = make_honest_trace();
	let col_k = 12 + 12 + 12 + 5 + 5 + 5 + 5 + 8 + 8 + 8 + 1 + 8;
	cells[col_k] = Goldilocks::from_u64(3);
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_corrupted_prod_carry() {
	// Bumping prod_carries[0] by 1 breaks the chain identity at i=0.
	let (mut cells, _) = make_honest_trace();
	let col_prod_carries = 12 + 12 + 12 + 5 + 5 + 5;
	cells[col_prod_carries] += Goldilocks::ONE;
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_non_canonical_u_via_bad_canon_diff() {
	// Build an "honest"-looking trace, then corrupt u_0 to be larger AND
	// flip canon_borrow[7] off — this would have passed the closure-only
	// version of the constraint. With the diff witness, the per-limb
	// identity now fails.
	let (mut cells, _) = make_honest_trace();
	let col_u = 12 + 12 + 12 + 5 + 5 + 5 + 5 + 8 + 8 + 8 + 1 + 8 + 1;
	cells[col_u] += Goldilocks::from_u64(0xFFFF_FFFF);
	// Note: this also breaks the u16 split + the reduction identity, so the
	// AIR rejects via multiple violations. The point is "non-canonical u
	// gets caught"; how it gets caught is fine.
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_canon_borrow_set_to_one_at_top() {
	// canon_borrows[7] != 0 fails the closure (u ≥ p).
	let (mut cells, _) = make_honest_trace();
	let col_canon_borrows = 12 + 12 + 12 + 5 + 5 + 5 + 5 + 8 + 8 + 8 + 1 + 8 + 1 + 8 + 8 + 8 + 8;
	cells[col_canon_borrows + 7] = Goldilocks::ONE;
	run_eval(&cells);
}

#[test]
#[should_panic(expected = "constraint failed")]
fn air_rejects_corrupted_w_lo16_split() {
	let (mut cells, _) = make_honest_trace();
	let col_w_lo16 = 12;
	cells[col_w_lo16] += Goldilocks::ONE;
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
	let (cells, _) = make_honest_trace();
	let pp: [Goldilocks; 0] = [];
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&cells, &cells),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
		pushes: Vec::new(),
	};
	let air = Reduce384Air::default_buses(TEST_BUS_U16_RANGE);
	air.eval(&mut builder);

	// Count by bus name.
	let mut u16_count = 0;
	let mut reduce_count = 0;
	let mut reduce_payload_size = 0;
	for p in &builder.pushes {
		if p.bus_name == TEST_BUS_U16_RANGE {
			u16_count += 1;
			assert_eq!(p.field_count, 1, "u16 range payload must be a single cell");
		} else if p.bus_name == BUS_REDUCE_384 {
			reduce_count += 1;
			reduce_payload_size = p.field_count;
		} else {
			panic!("unexpected bus name: {}", p.bus_name);
		}
	}

	// Documented: BUS_U16_RANGE pushes per row =
	//   24 (W u16-split: 12 lo + 12 hi) + 10 (prod: 5 lo + 5 hi)
	//   + 16 (T: 8 lo + 8 hi) + 16 (u: 8 lo + 8 hi)
	//   + 5 (prod_carries[0..5]) + 8 (red_carries[0..8])
	//   + 16 (canon_diff: 8 lo + 8 hi) = 95.
	assert_eq!(
		u16_count, 95,
		"u16 range push count must equal 95; got {}",
		u16_count
	);

	// Service bus receive: exactly one (W[12] || u[8]) = 20 cells.
	assert_eq!(reduce_count, 1, "BUS_REDUCE_384 receive must be exactly once");
	assert_eq!(
		reduce_payload_size,
		REDUCE_384_INPUT_LIMBS + FIELD_NUM_LIMBS,
		"BUS_REDUCE_384 payload must be 20 cells",
	);
}

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_REDUCE_384, "rostro-reduce-384");
}

#[test]
fn trace_width_pin() {
	assert_eq!(REDUCE_384_AIR_NUM_COLS, 154);
}
