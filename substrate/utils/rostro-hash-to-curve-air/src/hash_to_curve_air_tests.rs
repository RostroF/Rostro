// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`Hash2CurveAir`].
//!
//! Hash2CurveAir is pure orchestration — no in-row constraints. So the
//! tests here pin:
//! - Trace shape (column count + segment offsets).
//! - Bus push count + payload sizes per documented shape.
//! - Bus name pin (default service buses match what upstream AIRs export).
//!
//! Honest-trace acceptance is trivially true (no constraints to violate).
//! Real corruption rejection requires LogUp balance against the upstream
//! Hash2Curve cluster (HashToFieldAir + Elligator2Air + PointAddAir +
//! PointDoubleAir + their dependents); that integration coverage lands
//! when the prover is wired end-to-end. Until then, this AIR's soundness
//! claim is "the bus payloads are well-formed and would balance against
//! honest upstream witnesses."

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use rostro_curve25519::elligator2_air::BUS_ELLIGATOR2;
use rostro_curve25519::point_add_air::BUS_POINT_ADD;
use rostro_curve25519::point_double_air::BUS_POINT_DOUBLE;
use rostro_hash_to_field_air::hash_to_field_air::BUS_HASH_TO_FIELD;

use crate::hash_to_curve_air::{
	build_hash_to_curve_trace, Hash2CurveAir, HASH_TO_CURVE_AIR_NUM_COLS,
};
use crate::BUS_HASH_TO_CURVE;

// ─── ExpectZeroBuilder (no constraints to fire, but still need an AB) ─────

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

#[test]
fn air_eval_does_not_panic_on_honest_trace() {
	let trace = build_hash_to_curve_trace(Goldilocks::from_u64(0xdead_beef));
	let air = Hash2CurveAir::default_buses();
	let pp: [Goldilocks; 0] = [];
	let mut builder = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(&trace.values, &trace.values),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
	};
	air.eval(&mut builder);
}

// ─── RecordingBuilder for bus-shape pinning ────────────────────────────────

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
	let trace = build_hash_to_curve_trace(Goldilocks::from_u64(7));
	let pp: [Goldilocks; 0] = [];
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace.values, &trace.values),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
		pushes: Vec::new(),
	};
	let air = Hash2CurveAir::default_buses();
	air.eval(&mut builder);

	assert_eq!(builder.pushes.len(), 8, "expected 8 bus pushes");

	// (1) hash_to_field
	assert_eq!(builder.pushes[0].bus_name, BUS_HASH_TO_FIELD);
	assert_eq!(builder.pushes[0].field_count, 17);

	// (2) elligator2 for u_0
	assert_eq!(builder.pushes[1].bus_name, BUS_ELLIGATOR2);
	assert_eq!(builder.pushes[1].field_count, 40);

	// (3) elligator2 for u_1
	assert_eq!(builder.pushes[2].bus_name, BUS_ELLIGATOR2);
	assert_eq!(builder.pushes[2].field_count, 40);

	// (4) point_add
	assert_eq!(builder.pushes[3].bus_name, BUS_POINT_ADD);
	assert_eq!(builder.pushes[3].field_count, 96);

	// (5–7) point_double × 3
	for i in 4..7 {
		assert_eq!(builder.pushes[i].bus_name, BUS_POINT_DOUBLE);
		assert_eq!(builder.pushes[i].field_count, 56);
	}

	// (8) service-bus close
	assert_eq!(builder.pushes[7].bus_name, BUS_HASH_TO_CURVE);
	assert_eq!(builder.pushes[7].field_count, 33);
}

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_HASH_TO_CURVE, "rostro-hash-to-curve");
}

#[test]
fn trace_width_pin() {
	assert_eq!(HASH_TO_CURVE_AIR_NUM_COLS, 209);
}

#[test]
fn trace_builder_round_trip_consistent_with_witness() {
	// Pull the final point cells out of the trace and verify they match
	// what the public witness function returns.
	let pn = Goldilocks::from_u64(0xcafe_babe);
	let trace = build_hash_to_curve_trace(pn);
	let oracle = crate::hash_to_curve(pn);

	// COL_EIGHT_Q is the last segment; the EdwardsPoint ordering is
	// (x, y, z, t) × 8 cells each. Reproduce the offsets here.
	const FIELD_LIMBS: usize = 8;
	const POINT_CELLS: usize = 4 * FIELD_LIMBS;
	let final_start = HASH_TO_CURVE_AIR_NUM_COLS - POINT_CELLS;

	let mut x = [0u32; FIELD_LIMBS];
	let mut y = [0u32; FIELD_LIMBS];
	let mut z = [0u32; FIELD_LIMBS];
	let mut t = [0u32; FIELD_LIMBS];
	use p3_field::PrimeField64;
	for i in 0..FIELD_LIMBS {
		x[i] = trace.values[final_start + i].as_canonical_u64() as u32;
		y[i] = trace.values[final_start + FIELD_LIMBS + i].as_canonical_u64() as u32;
		z[i] = trace.values[final_start + 2 * FIELD_LIMBS + i].as_canonical_u64() as u32;
		t[i] = trace.values[final_start + 3 * FIELD_LIMBS + i].as_canonical_u64() as u32;
	}

	assert_eq!(x, oracle.x);
	assert_eq!(y, oracle.y);
	assert_eq!(z, oracle.z);
	assert_eq!(t, oracle.t);
}
