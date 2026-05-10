// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::sqrt_ratio_m1_air::SqrtRatioM1Air`].

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::field::{
	add as field_add, mul as field_mul, sqrt_ratio_m1, square, sub as field_sub, FIELD_NUM_LIMBS,
};
use crate::field_air::BUS_FIELD_ADD;
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_pow_p58_air::BUS_FIELD_POW_P58;
use crate::field_sub_air::BUS_FIELD_SUB;
use crate::oracle_tests_helpers::random_canonical;
use crate::sqrt_ratio_m1_air::{
	build_sqrt_ratio_m1_trace_row, SqrtRatioM1Air, BUS_SQRT_RATIO_M1, COL_CORRECT_SIGN,
	COL_FLIPPED_SIGN, COL_FLIPPED_SIGN_I, COL_IS_NEG_R_SELECTED, COL_R, COL_U, COL_V,
	COL_WAS_SQUARE, SQRT_RATIO_M1_NUM_COLS,
};

// ─── Constraint-asserting builder ──────────────────────────────────────────

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

fn run_eval(trace: &[Goldilocks]) {
	assert_eq!(trace.len(), SQRT_RATIO_M1_NUM_COLS);
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut b = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(trace, trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		constraint_index: 0,
	};
	let air = SqrtRatioM1Air::new();
	<SqrtRatioM1Air as Air<ExpectZeroBuilder>>::eval(&air, &mut b);
}

// ─── Layout pin ────────────────────────────────────────────────────────────

#[test]
fn column_layout_constants_are_stable() {
	assert_eq!(COL_U, 0);
	assert_eq!(COL_V, 8);
	assert_eq!(COL_R, 8 + 16 * 8);
	assert_eq!(COL_CORRECT_SIGN, COL_R + 8);
	assert_eq!(COL_FLIPPED_SIGN, COL_CORRECT_SIGN + 1);
	assert_eq!(COL_FLIPPED_SIGN_I, COL_FLIPPED_SIGN + 1);
	assert_eq!(COL_WAS_SQUARE, COL_FLIPPED_SIGN_I + 1);
	assert_eq!(COL_IS_NEG_R_SELECTED, COL_WAS_SQUARE + 1);
	assert_eq!(SQRT_RATIO_M1_NUM_COLS, COL_IS_NEG_R_SELECTED + 1);
}

// ─── Witness builder correctness ───────────────────────────────────────────

#[test]
fn witness_matches_field_oracle_for_random_inputs() {
	use rand::{rngs::StdRng, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xc0de_face_d00d_d00d);
	for _ in 0..10 {
		let u = random_canonical(&mut rng);
		let v = random_canonical(&mut rng);
		let row = build_sqrt_ratio_m1_trace_row(&u, &v);
		let (oracle_ok, oracle_r) = sqrt_ratio_m1(&u, &v);
		assert_eq!(row.was_square == 1, oracle_ok, "was_square diverges from oracle");
		assert_eq!(row.r, oracle_r, "r diverges from oracle");
	}
}

// ─── AIR acceptance ────────────────────────────────────────────────────────

#[test]
fn air_accepts_sqrt_of_square_one() {
	// u = 1, v = 1: trivially a square, sqrt = ±1, canonical positive = p-1.
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_sqrt_ratio_m1_trace_row(&one, &one);
	assert_eq!(row.was_square, 1);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_sqrt_of_random_squares() {
	use rand::{rngs::StdRng, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xface_5151_5151_face);
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	for _ in 0..5 {
		let x = random_canonical(&mut rng);
		let u = square(&x); // u is always a square.
		let row = build_sqrt_ratio_m1_trace_row(&u, &one);
		assert_eq!(row.was_square, 1);
		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

#[test]
fn air_accepts_non_square_input() {
	// u = 2, v = 1: 2 is a non-square mod p. AIR must still accept the
	// trace (with was_square = 0).
	let mut two = [0u32; FIELD_NUM_LIMBS];
	two[0] = 2;
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_sqrt_ratio_m1_trace_row(&two, &one);
	assert_eq!(row.was_square, 0);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_random_inputs() {
	use rand::{rngs::StdRng, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xdeed_5151_face_dead);
	for _ in 0..10 {
		let u = random_canonical(&mut rng);
		let v = random_canonical(&mut rng);
		let row = build_sqrt_ratio_m1_trace_row(&u, &v);
		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

// ─── Rejection tests ───────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_flipped_was_square() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_sqrt_ratio_m1_trace_row(&one, &one);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip was_square — must violate was_square == correct_sign + flipped_sign.
	trace[COL_WAS_SQUARE] = Goldilocks::ONE - trace[COL_WAS_SQUARE];
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_two_flags_set() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_sqrt_ratio_m1_trace_row(&one, &one);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Force both correct_sign and flipped_sign on — at-most-one
	// constraint must fire.
	trace[COL_CORRECT_SIGN] = Goldilocks::ONE;
	trace[COL_FLIPPED_SIGN] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_r() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_sqrt_ratio_m1_trace_row(&one, &one);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Corrupt r[0]: selection constraint catches it.
	trace[COL_R] = trace[COL_R] + Goldilocks::ONE;
	run_eval(&trace);
}

// ─── Bus push shape ────────────────────────────────────────────────────────

struct RecordingBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	pushed: Vec<(String, Goldilocks, usize, u32)>,
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

impl<'a> InteractionBuilder for RecordingBuilder<'a> {
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
fn bus_push_count_per_row() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_sqrt_ratio_m1_trace_row(&one, &one);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut b = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace, &trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		pushed: Vec::new(),
	};
	let air = SqrtRatioM1Air::new();
	<SqrtRatioM1Air as Air<RecordingBuilder>>::eval(&air, &mut b);

	let muls = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_MUL).count();
	let subs = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_SUB).count();
	let pows = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_POW_P58).count();
	let services = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_SQRT_RATIO_M1).count();
	// Expected: 11 muls (v², v²·v, v²·v², v⁴·v³, u·v³, u·v⁷, u_v3·u_v7_pow,
	// r_raw², v·r_raw_sq, neg_u·SQRT_M1, r_raw·SQRT_M1) + 2 subs (neg_u, neg_r_selected)
	// + 1 pow + 1 service emit.
	assert_eq!(muls, 11, "expected 11 mul consumer queries");
	assert_eq!(subs, 2, "expected 2 sub consumer queries");
	assert_eq!(pows, 1, "expected 1 pow consumer query");
	assert_eq!(services, 1, "expected 1 service emit");

	// Service emit shape: 25 cells, count = -1.
	let svc = b.pushed.iter().find(|(bus, _, _, _)| bus == BUS_SQRT_RATIO_M1).unwrap();
	assert_eq!(svc.2, 25, "service payload = (u, v, was_square, r) = 8+8+1+8 = 25 cells");
	assert_eq!(svc.1, Goldilocks::ZERO - Goldilocks::ONE, "provider count = -1");
}

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_SQRT_RATIO_M1, "rostro-sqrt-ratio-m1");
}

// Suppress unused warnings for re-export helpers.
#[allow(dead_code)]
fn _force_use() {
	let _ = field_add;
	let _ = field_mul;
	let _ = field_sub;
	let _: &'static str = BUS_FIELD_ADD;
}
