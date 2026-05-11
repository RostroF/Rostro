// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for `Elligator2Air`.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::elligator2::map_to_curve_elligator2_edwards25519;
use crate::elligator2_air::{
	build_elligator2_trace_row, Elligator2Air, BUS_ELLIGATOR2, COL_FLIP_Y, COL_IS_NEG_Y_M_PRE,
	COL_IS_SQ_GX1, ELLIGATOR2_NUM_COLS,
};
use crate::field::{bytes_to_limbs, is_canonical, FIELD_NUM_LIMBS};
use crate::field_air::BUS_U16_RANGE;
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::point::is_on_curve;
use crate::sqrt_ratio_m1_air::BUS_SQRT_RATIO_M1;

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
		Goldilocks::ZERO
	}
	fn is_last_row(&self) -> Self::Expr {
		Goldilocks::ZERO
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
	assert_eq!(trace.len(), ELLIGATOR2_NUM_COLS);
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut b = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(trace, trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		constraint_index: 0,
	};
	let air = Elligator2Air::new();
	<Elligator2Air as Air<ExpectZeroBuilder>>::eval(&air, &mut b);
}

// ─── Bus name pin ─────────────────────────────────────────────────────────

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_ELLIGATOR2, "rostro-elligator2");
}

#[test]
fn column_layout_constants_are_stable() {
	// Pin the layout size so accidental reordering trips the test.
	// 32 field-element witnesses × 8 limbs + 6 flag/LSB cells = 262.
	assert_eq!(ELLIGATOR2_NUM_COLS, 32 * 8 + 6);
}

// ─── AIR acceptance ────────────────────────────────────────────────────────

#[test]
fn air_accepts_small_inputs() {
	for n in 1u32..=10 {
		let mut u = [0u32; FIELD_NUM_LIMBS];
		u[0] = n;
		let row = build_elligator2_trace_row(&u);
		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

#[test]
fn air_accepts_random_inputs() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xe7_71_61_70_72_e2);
	for _ in 0..10 {
		let u = loop {
			let mut bytes = [0u8; 32];
			rng.fill_bytes(&mut bytes);
			bytes[31] &= 0x7F;
			let limbs = bytes_to_limbs(&bytes);
			if is_canonical(&limbs) {
				break limbs;
			}
		};
		let row = build_elligator2_trace_row(&u);
		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

#[test]
fn trace_row_output_matches_witness_oracle() {
	// The AIR's trace row should compute the same Edwards point as the
	// standalone witness function.
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xe7_71_61_70_74_e2);
	for _ in 0..5 {
		let u = loop {
			let mut bytes = [0u8; 32];
			rng.fill_bytes(&mut bytes);
			bytes[31] &= 0x7F;
			let limbs = bytes_to_limbs(&bytes);
			if is_canonical(&limbs) {
				break limbs;
			}
		};
		let row = build_elligator2_trace_row(&u);
		let oracle = map_to_curve_elligator2_edwards25519(&u);
		assert_eq!(row.x_e, oracle.x, "x_E should match oracle");
		assert_eq!(row.y_e, oracle.y, "y_E should match oracle");
		assert_eq!(row.t_e, oracle.t, "t_E should match oracle");
		// And the output IS on Edwards25519.
		assert!(is_on_curve(&oracle), "output must be on Edwards25519");
	}
}

// ─── AIR rejection ─────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_flipped_is_neg_y_m_pre() {
	let mut u = [0u32; FIELD_NUM_LIMBS];
	u[0] = 3;
	let row = build_elligator2_trace_row(&u);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_IS_NEG_Y_M_PRE] = Goldilocks::ONE - trace[COL_IS_NEG_Y_M_PRE];
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_flipped_flip_y() {
	let mut u = [0u32; FIELD_NUM_LIMBS];
	u[0] = 3;
	let row = build_elligator2_trace_row(&u);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_FLIP_Y] = Goldilocks::ONE - trace[COL_FLIP_Y];
	run_eval(&trace);
}

// Note: corrupting x_E, y_E, or t_E directly is NOT caught by this AIR's
// in-row constraints — those values are bus-only outputs of BUS_FIELD_MUL
// queries, so a row-level constraint builder can't detect mismatches.
// LogUp balance at the full-prove level catches them. The in-row
// rejection coverage here focuses on selection / boolean / LSB-tie
// failures.

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_flipped_is_sq_gx1() {
	let mut u = [0u32; FIELD_NUM_LIMBS];
	u[0] = 3;
	let row = build_elligator2_trace_row(&u);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flipping is_sq_gx1 changes the x_m / y_m_pre selection without
	// updating the selected outputs — the selection constraint catches.
	trace[COL_IS_SQ_GX1] = Goldilocks::ONE - trace[COL_IS_SQ_GX1];
	run_eval(&trace);
}

// ─── Bus push count ────────────────────────────────────────────────────────

struct CountingBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	muls: usize,
	adds: usize,
	subs: usize,
	sqrts: usize,
	u16r: usize,
	services: usize,
	service_arity: usize,
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
		if bus == BUS_FIELD_MUL {
			self.muls += 1;
		} else if bus == "rostro-field-add" {
			self.adds += 1;
		} else if bus == "rostro-field-sub" {
			self.subs += 1;
		} else if bus == BUS_SQRT_RATIO_M1 {
			self.sqrts += 1;
		} else if bus == BUS_U16_RANGE {
			self.u16r += 1;
		} else if bus == BUS_ELLIGATOR2 {
			self.services += 1;
			self.service_arity = arity;
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
fn bus_push_count_per_row() {
	let mut u = [0u32; FIELD_NUM_LIMBS];
	u[0] = 3;
	let row = build_elligator2_trace_row(&u);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut b = CountingBuilder {
		main_window: RowWindow::from_two_rows(&trace, &trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		muls: 0,
		adds: 0,
		subs: 0,
		sqrts: 0,
		u16r: 0,
		services: 0,
		service_arity: 0,
	};
	let air = Elligator2Air::new();
	<Elligator2Air as Air<CountingBuilder>>::eval(&air, &mut b);
	assert_eq!(b.sqrts, 2, "two sqrt_ratio_m1 queries");
	assert_eq!(b.u16r, 2, "two u16-range lookups (LSB-tie)");
	assert_eq!(b.services, 1, "one service emit");
	assert_eq!(b.service_arity, 40, "service payload = 40 cells (u, x_E, y_E, z_E, t_E)");
}

// Quiet unused-import lints when test names change.
#[allow(dead_code)]
fn _force_use() {
	let _: u32 = 0;
	let _: <Goldilocks as Field>::Packing = Goldilocks::ONE.into();
	let _: u64 = Goldilocks::ONE.as_canonical_u64();
	let _: String = "".to_string();
}
