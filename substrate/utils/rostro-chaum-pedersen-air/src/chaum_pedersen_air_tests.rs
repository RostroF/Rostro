// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`ChaumPedersenAir`].
//!
//! Like Hash2CurveAir, this is pure orchestration — no in-row constraints
//! mean the in-row ExpectZeroBuilder can't catch corruption (LogUp
//! balance against ScalarMulAir + PointAddAir does the work). Tests
//! pin trace shape + bus push count/payloads + service bus name.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use rostro_curve25519::point::scalar_mul;
use rostro_curve25519::point_add_air::BUS_POINT_ADD;
use rostro_curve25519::scalar_mul_air::BUS_SCALAR_MUL;

use crate::chaum_pedersen_air::{
	build_chaum_pedersen_trace, ChaumPedersenAir, CHAUM_PEDERSEN_AIR_NUM_COLS,
};
use crate::{ed25519_basepoint, BUS_CP_DLOG_EQ};

// ─── Builders ──────────────────────────────────────────────────────────────

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

// ─── Helpers ───────────────────────────────────────────────────────────────

fn make_honest_inputs() -> (
	rostro_curve25519::point::EdwardsPoint, // pk
	rostro_curve25519::point::EdwardsPoint, // blinded
	rostro_curve25519::point::EdwardsPoint, // response
	rostro_curve25519::point::EdwardsPoint, // R_pk
	rostro_curve25519::point::EdwardsPoint, // R_resp
	[u8; 32],                                // e
	[u8; 32],                                // s
) {
	use curve25519_dalek::scalar::Scalar as DScalar;
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0x1357_9bdfu64);
	let mut k = [0u8; 32];
	let mut r = [0u8; 32];
	let mut e = [0u8; 32];
	let mut blinded_seed = [0u8; 32];
	rng.fill_bytes(&mut k);
	rng.fill_bytes(&mut r);
	rng.fill_bytes(&mut e);
	rng.fill_bytes(&mut blinded_seed);

	let g = ed25519_basepoint();
	let pk = scalar_mul(&k, &g);
	let blinded = scalar_mul(&blinded_seed, &g);
	let response = scalar_mul(&k, &blinded);
	let r_pk = scalar_mul(&r, &g);
	let r_resp = scalar_mul(&r, &blinded);

	let r_scalar = DScalar::from_bytes_mod_order(r);
	let e_scalar = DScalar::from_bytes_mod_order(e);
	let k_scalar = DScalar::from_bytes_mod_order(k);
	let s_scalar = r_scalar + e_scalar * k_scalar;
	let s = s_scalar.to_bytes();

	(pk, blinded, response, r_pk, r_resp, e, s)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[test]
fn air_eval_does_not_panic_on_honest_trace() {
	let (pk, blinded, response, r_pk, r_resp, e, s) = make_honest_inputs();
	let trace =
		build_chaum_pedersen_trace(&pk, &blinded, &response, &r_pk, &r_resp, &e, &s);
	let air = ChaumPedersenAir::default_buses();
	let pp: [Goldilocks; 0] = [];
	let mut builder = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(&trace.values, &trace.values),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
	};
	air.eval(&mut builder);
}

#[test]
fn bus_pushes_match_documented_shape() {
	let (pk, blinded, response, r_pk, r_resp, e, s) = make_honest_inputs();
	let trace =
		build_chaum_pedersen_trace(&pk, &blinded, &response, &r_pk, &r_resp, &e, &s);
	let pp: [Goldilocks; 0] = [];
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace.values, &trace.values),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
		pushes: Vec::new(),
	};
	let air = ChaumPedersenAir::default_buses();
	air.eval(&mut builder);

	assert_eq!(builder.pushes.len(), 7, "expected 7 bus pushes");

	// (1-4) Four scalar mults
	for i in 0..4 {
		assert_eq!(builder.pushes[i].bus_name, BUS_SCALAR_MUL);
		assert_eq!(builder.pushes[i].field_count, 96);
	}
	// (5-6) Two point adds
	for i in 4..6 {
		assert_eq!(builder.pushes[i].bus_name, BUS_POINT_ADD);
		assert_eq!(builder.pushes[i].field_count, 96);
	}
	// (7) Service bus close
	assert_eq!(builder.pushes[6].bus_name, BUS_CP_DLOG_EQ);
	assert_eq!(builder.pushes[6].field_count, 224);
}

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_CP_DLOG_EQ, "rostro-cp-dlog-eq");
}

#[test]
fn trace_width_pin() {
	assert_eq!(CHAUM_PEDERSEN_AIR_NUM_COLS, 352);
}

#[test]
fn trace_builder_consistent_across_runs() {
	let (pk, blinded, response, r_pk, r_resp, e, s) = make_honest_inputs();
	let t1 = build_chaum_pedersen_trace(&pk, &blinded, &response, &r_pk, &r_resp, &e, &s);
	let t2 = build_chaum_pedersen_trace(&pk, &blinded, &response, &r_pk, &r_resp, &e, &s);
	assert_eq!(t1.values, t2.values, "trace builder is non-deterministic");
}
