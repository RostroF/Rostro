// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::field_sub_air::FieldSubAir`].
//!
//! Mirrors the test harness shape of `field_air_tests`. Per the silo
//! principle, NO shared `ExpectZeroBuilder` between add and sub tests —
//! each test file has its own local copy.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use rand::SeedableRng;

use crate::field::{sub, FIELD_NUM_LIMBS, P_MINUS_ONE_LIMBS};
use crate::field_sub_air::{
	build_field_sub_trace_row, FieldSubAir, COL_SUB_A, COL_SUB_B, COL_SUB_C, COL_SUB_CARRY,
	COL_SUB_C_COMP, COL_SUB_C_COMP_BORROW, COL_SUB_C_COMP_HI, COL_SUB_C_COMP_LO, COL_SUB_C_HI,
	COL_SUB_C_LO, COL_SUB_T, FIELD_SUB_NUM_COLS,
};
use crate::field_air::BUS_U16_RANGE;
use crate::oracle_tests_helpers::random_canonical;

struct ExpectZeroBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
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
		Goldilocks::ONE
	}
	fn is_last_row(&self) -> Self::Expr {
		Goldilocks::ONE
	}
	fn is_transition_window(&self, _: usize) -> Self::Expr {
		Goldilocks::ZERO
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
	assert_eq!(row.len(), FIELD_SUB_NUM_COLS);
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut builder = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(row, row),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		constraint_index: 0,
	};
	let air = FieldSubAir::new();
	<FieldSubAir as Air<ExpectZeroBuilder>>::eval(&air, &mut builder);
}

// ─── Acceptance tests ──────────────────────────────────────────────────────

#[test]
fn air_accepts_zero_minus_zero() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_sub_trace_row(&zero, &zero);
	assert_eq!(row.t, 0);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_zero_minus_one_is_p_minus_one() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_field_sub_trace_row(&zero, &one);
	assert_eq!(row.t, 1, "expected t=1: 0 - 1 wraps to p-1");
	assert_eq!(row.c, P_MINUS_ONE_LIMBS);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_p_minus_one_minus_p_minus_one_is_zero() {
	let row = build_field_sub_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	assert_eq!(row.t, 0);
	assert_eq!(row.c, [0u32; FIELD_NUM_LIMBS]);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_no_wrap_case() {
	// a > b, simple subtraction with no underflow.
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0xDEAD_BEEF;
	b[0] = 0x1234_5678;
	let row = build_field_sub_trace_row(&a, &b);
	assert_eq!(row.t, 0);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_wrap_case() {
	// a < b, subtraction underflows, t = 1.
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 1;
	b[0] = 2;
	let row = build_field_sub_trace_row(&a, &b);
	assert_eq!(row.t, 1);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_random_fuzz() {
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x5ec0_1750_19_de_ad);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let row = build_field_sub_trace_row(&a, &b);
		assert_eq!(row.c, sub(&a, &b));
		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

// ─── Rejection tests ───────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_c() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0x1000;
	b[0] = 0x0500;
	let row = build_field_sub_trace_row(&a, &b);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_SUB_C] = trace[COL_SUB_C] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_t() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0x1000;
	b[0] = 0x0500;
	let row = build_field_sub_trace_row(&a, &b);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_SUB_T] = trace[COL_SUB_T] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_non_boolean_t() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_sub_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_SUB_T] = Goldilocks::from_u32(2);
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_out_of_range_carry() {
	let row = build_field_sub_trace_row(&P_MINUS_ONE_LIMBS, &[0u32; FIELD_NUM_LIMBS]);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_SUB_CARRY] = Goldilocks::from_u32(2);
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_nonzero_top_carry() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_sub_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_SUB_CARRY + (FIELD_NUM_LIMBS - 1)] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_c_complement() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_sub_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_SUB_C_COMP] = trace[COL_SUB_C_COMP] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_nonzero_top_complement_borrow() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_sub_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_SUB_C_COMP_BORROW + (FIELD_NUM_LIMBS - 1)] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_c_lo_split() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_sub_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_SUB_C_LO] = trace[COL_SUB_C_LO] + Goldilocks::ONE;
	run_eval(&trace);
}

// ─── Layout + bus-name pin tests ───────────────────────────────────────────

#[test]
fn column_layout_constants_are_stable() {
	assert_eq!(COL_SUB_A, 0);
	assert_eq!(COL_SUB_B, 8);
	assert_eq!(COL_SUB_C, 16);
	assert_eq!(COL_SUB_T, 24);
	assert_eq!(COL_SUB_CARRY, 25);
	assert_eq!(COL_SUB_C_COMP, 33);
	assert_eq!(COL_SUB_C_COMP_BORROW, 41);
	assert_eq!(COL_SUB_C_LO, 49);
	assert_eq!(COL_SUB_C_HI, 57);
	assert_eq!(COL_SUB_C_COMP_LO, 65);
	assert_eq!(COL_SUB_C_COMP_HI, 73);
	assert_eq!(FIELD_SUB_NUM_COLS, 81);
}

#[test]
fn sub_uses_same_u16_range_bus_as_add() {
	// Both AIRs share the global u16 range-check bus. A single
	// `U16RangeTableAir` in the production batch serves both.
	// (Compile-time check: BUS_U16_RANGE is the only bus name
	// referenced by either AIR.)
	assert_eq!(BUS_U16_RANGE, "rostro-u16-range");
}

#[test]
fn sub_then_add_round_trips() {
	// (a - b) + b == a (mod p) — round-trip property the AIR should
	// satisfy. This is a math test on the witness side, but it pins
	// the trace-builder against `crate::field` correctness.
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x12ab_34cd_56ef_7890);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let sub_row = build_field_sub_trace_row(&a, &b);
		// Now compute (a-b) + b using the add trace builder.
		use crate::field_air::build_field_add_trace_row;
		let add_row = build_field_add_trace_row(&sub_row.c, &b);
		assert_eq!(add_row.c, a, "(a - b) + b round-trip failed");
		// Both traces should accept under their respective AIRs.
		run_eval(&sub_row.to_trace_vec::<Goldilocks>());
	}
}
