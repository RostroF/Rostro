// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::field_air::FieldAddAir`].
//!
//! Strategy mirrors `rostro-poseidon-air`'s test harness: a recording
//! builder (`ExpectZeroBuilder` for honest acceptance, panicking on
//! any non-zero constraint) drives the AIR's `eval` and verifies every
//! constraint expression evaluates to the field's additive identity.
//!
//! Corrupted-witness tests use `#[should_panic]` to confirm that
//! flipping witness bits trips the balance / carry / boolean
//! constraints.
//!
//! What these tests DON'T cover (per the soundness gaps documented
//! in `field_air.rs`):
//! - Canonical-form rejection of `c >= p` (commit 2 closes)
//! - Out-of-range `c[i] >= 2^32` smuggling attacks (commit 3 closes)
//!
//! Honest witnesses produced by `build_field_add_trace_row` always
//! satisfy both gaps; corrupted-witness tests exercise corruptions
//! that the current balance/carry constraints DO catch (sign-flipped
//! limbs, wrong carry, wrong t).

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use rand::SeedableRng;

use crate::field::{add, FIELD_NUM_LIMBS, P_MINUS_ONE_LIMBS};
use crate::field_air::{
	build_field_add_trace_row, FieldAddAir, COL_ADD_A, COL_ADD_B, COL_ADD_C, COL_ADD_CARRY,
	COL_ADD_T, FIELD_ADD_NUM_COLS,
};
use crate::oracle_tests_helpers::random_canonical;

/// Single-row AirBuilder for testing: every constraint must evaluate
/// to zero; panics with the limb index if it doesn't. Same pattern as
/// rostro-poseidon-air's `ExpectZeroBuilder`.
struct ExpectZeroBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	is_first: Goldilocks,
	is_last: Goldilocks,
	is_trans: Goldilocks,
	constraint_index: usize,
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
	fn is_transition_window(&self, _size: usize) -> Self::Expr {
		self.is_trans
	}
	fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
		let v: Goldilocks = x.into();
		assert!(
			v.is_zero(),
			"constraint #{} failed: value = {:?}",
			self.constraint_index,
			v,
		);
		self.constraint_index += 1;
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
		// No-op for this commit; range-check interactions land in commit 3.
		fields.into_iter().for_each(drop);
	}
	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

fn run_eval(row: &[Goldilocks]) {
	assert_eq!(row.len(), FIELD_ADD_NUM_COLS, "trace row width mismatch");
	let next_row = row;
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut builder = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(row, next_row),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		is_first: Goldilocks::ONE,
		is_last: Goldilocks::ONE,
		is_trans: Goldilocks::ZERO,
		constraint_index: 0,
	};
	let air = FieldAddAir::new();
	<FieldAddAir as Air<ExpectZeroBuilder>>::eval(&air, &mut builder);
}

// ─── Honest-witness acceptance tests ────────────────────────────────────────

#[test]
fn air_accepts_zero_plus_zero() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_add_trace_row(&zero, &zero);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_p_minus_one_plus_one() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_field_add_trace_row(&P_MINUS_ONE_LIMBS, &one);
	assert_eq!(row.t, 1, "expected t=1 for wrap-around at p-1 + 1");
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_p_minus_one_plus_p_minus_one() {
	let row = build_field_add_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	assert_eq!(row.t, 1, "expected t=1 for (p-1) + (p-1) = 2p-2");
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_no_wrap_case() {
	// Two values whose sum stays below p (no conditional subtract).
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0x1234_5678;
	b[0] = 0x8765_4321;
	let row = build_field_add_trace_row(&a, &b);
	assert_eq!(row.t, 0, "expected t=0 when sum < p");
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_random_fuzz() {
	// 50 random canonical pairs; each must satisfy every constraint.
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xc057_1257_19_de_ad);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let row = build_field_add_trace_row(&a, &b);
		// Sanity: c matches the witness-side `add`.
		assert_eq!(row.c, add(&a, &b));
		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

// ─── Corrupted-witness rejection tests ─────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_c_limb_0() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0x1234;
	b[0] = 0x5678;
	let row = build_field_add_trace_row(&a, &b);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip c[0] by adding 1 — balance equation at limb 0 fails.
	trace[COL_ADD_C] = trace[COL_ADD_C] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_t() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0x1234;
	b[0] = 0x5678;
	let row = build_field_add_trace_row(&a, &b);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip t: was 0 (no wrap), becomes 1; balance must fail because
	// `a + b - c - p` is now p off.
	trace[COL_ADD_T] = trace[COL_ADD_T] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_non_boolean_t() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_add_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Set t = 2: t-boolean constraint fails.
	trace[COL_ADD_T] = Goldilocks::from_u32(2);
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_out_of_range_carry() {
	let row = build_field_add_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Set carry[0] = 2: tertiary check fails.
	trace[COL_ADD_CARRY] = Goldilocks::from_u32(2);
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_carry_chain() {
	// Honest trace, then corrupt one intermediate carry. The balance
	// at the limb following the corruption breaks.
	let row = build_field_add_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip carry[3]: balance at limb 4 breaks (carry_in[4] is wrong).
	trace[COL_ADD_CARRY + 3] = trace[COL_ADD_CARRY + 3] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_nonzero_top_carry() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_add_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Set carry[7] = 1 with a non-trivial inconsistency in c[7].
	// This breaks the top-balance closure constraint that pins
	// carry[7] = 0.
	trace[COL_ADD_CARRY + (FIELD_NUM_LIMBS - 1)] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
fn column_layout_constants_are_stable() {
	// Pin the column layout. If anyone reorders, this fails loudly so
	// downstream code that constructs traces or reads constraint values
	// at specific offsets gets caught.
	assert_eq!(COL_ADD_A, 0);
	assert_eq!(COL_ADD_B, 8);
	assert_eq!(COL_ADD_C, 16);
	assert_eq!(COL_ADD_T, 24);
	assert_eq!(COL_ADD_CARRY, 25);
	assert_eq!(FIELD_ADD_NUM_COLS, 33);
}
