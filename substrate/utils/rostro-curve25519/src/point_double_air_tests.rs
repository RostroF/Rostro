// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::point_double_air::PointDoubleAir`]. Mirrors
//! `point_add_air_tests` (same recording-builder shape, silo'd).

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::field::{add as field_add, mul as field_mul, sub as field_sub, FIELD_NUM_LIMBS};
use crate::field_air::BUS_FIELD_ADD;
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_sub_air::BUS_FIELD_SUB;
use crate::point::{double as point_double, neutral, EdwardsPoint};
use crate::point_double_air::{
	build_point_double_trace_row, PointDoubleAir, COL_A, COL_B, COL_C, COL_D, COL_E, COL_F,
	COL_G, COL_H, COL_P1_X, COL_P1_Y, COL_P1_Z, COL_P3_T, COL_P3_X, COL_P3_Y, COL_P3_Z,
	COL_XPY_SQ, COL_XPY_SQ_MINUS_A, COL_X_PLUS_Y, COL_Z_SQ, POINT_DOUBLE_NUM_COLS,
};

struct RecordingBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	pushed: Vec<(String, Goldilocks, Vec<Goldilocks>, u32)>,
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
	fn is_transition_window(&self, _: usize) -> Self::Expr {
		Goldilocks::ZERO
	}
	fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
}

impl<'a> InteractionBuilder for RecordingBuilder<'a> {
	fn push_interaction<E: Into<Self::Expr>>(
		&mut self,
		bus_name: &str,
		fields: impl IntoIterator<Item = E>,
		count: impl Into<Self::Expr>,
		count_weight: u32,
	) {
		let multiplicity: Goldilocks = count.into();
		let payload: Vec<Goldilocks> = fields.into_iter().map(Into::into).collect();
		self.pushed.push((bus_name.to_string(), multiplicity, payload, count_weight));
	}
	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

fn record_eval(p1: &EdwardsPoint) -> Vec<(String, Goldilocks, Vec<Goldilocks>, u32)> {
	let row = build_point_double_trace_row(p1);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace, &trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		pushed: Vec::new(),
	};
	let air = PointDoubleAir::new();
	<PointDoubleAir as Air<RecordingBuilder>>::eval(&air, &mut builder);
	builder.pushed
}

#[test]
fn column_layout_constants_are_stable() {
	assert_eq!(COL_P1_X, 0);
	assert_eq!(COL_P1_Y, 8);
	assert_eq!(COL_P1_Z, 16);
	assert_eq!(COL_A, 24);
	assert_eq!(COL_B, 32);
	assert_eq!(COL_Z_SQ, 40);
	assert_eq!(COL_C, 48);
	assert_eq!(COL_D, 56);
	assert_eq!(COL_X_PLUS_Y, 64);
	assert_eq!(COL_XPY_SQ, 72);
	assert_eq!(COL_XPY_SQ_MINUS_A, 80);
	assert_eq!(COL_E, 88);
	assert_eq!(COL_G, 96);
	assert_eq!(COL_F, 104);
	assert_eq!(COL_H, 112);
	assert_eq!(COL_P3_X, 120);
	assert_eq!(COL_P3_Y, 128);
	assert_eq!(COL_P3_Z, 136);
	assert_eq!(COL_P3_T, 144);
	assert_eq!(POINT_DOUBLE_NUM_COLS, 152);
}

#[test]
fn trace_vec_width_matches_layout() {
	let row = build_point_double_trace_row(&neutral());
	let trace = row.to_trace_vec::<Goldilocks>();
	assert_eq!(trace.len(), POINT_DOUBLE_NUM_COLS);
}

#[test]
fn point_double_emits_16_service_bus_queries() {
	let pushes = record_eval(&neutral());
	assert_eq!(pushes.len(), 16, "expected exactly 16 service-bus pushes");

	let num_subs = pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_SUB).count();
	let num_adds = pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_ADD).count();
	let num_muls = pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_MUL).count();
	assert_eq!(num_subs, 5, "expected 5 sub queries");
	assert_eq!(num_adds, 3, "expected 3 add queries");
	assert_eq!(num_muls, 8, "expected 8 mul queries");

	for (bus, mult, payload, weight) in &pushes {
		assert_eq!(*mult, Goldilocks::ONE, "consumer count must be +1 (bus={})", bus);
		assert_eq!(payload.len(), 24, "payload must be 24 cells (bus={})", bus);
		assert_eq!(*weight, 1, "count_weight must be 1 (bus={})", bus);
	}
}

fn limbs_from(payload: &[Goldilocks], offset: usize) -> [u32; FIELD_NUM_LIMBS] {
	let mut out = [0u32; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		out[i] = payload[offset + i].as_canonical_u64() as u32;
	}
	out
}

#[test]
fn every_pushed_tuple_satisfies_its_field_op() {
	let pushes = record_eval(&basepoint());

	for (bus, _, payload, _) in &pushes {
		let a = limbs_from(payload, 0);
		let b = limbs_from(payload, FIELD_NUM_LIMBS);
		let c = limbs_from(payload, 2 * FIELD_NUM_LIMBS);
		let expected = if bus == BUS_FIELD_ADD {
			field_add(&a, &b)
		} else if bus == BUS_FIELD_SUB {
			field_sub(&a, &b)
		} else if bus == BUS_FIELD_MUL {
			field_mul(&a, &b)
		} else {
			panic!("unexpected bus name: {}", bus);
		};
		assert_eq!(
			c, expected,
			"tuple on bus {} fails its field op:\n  a = {:?}\n  b = {:?}\n  c = {:?}\n  expected c = {:?}",
			bus, a, b, c, expected,
		);
	}
}

#[test]
fn output_p3_matches_point_double_oracle() {
	let bp = basepoint();
	let row = build_point_double_trace_row(&bp);
	assert_eq!(row.p3, point_double(&bp), "trace builder's p3 must equal point::double(p1)");
}

#[test]
fn first_sub_query_encodes_negation() {
	// D = -A. The first sub query MUST be (0, A, D) — the zero-constant
	// pattern that encodes negation via a field-sub.
	let pushes = record_eval(&basepoint());
	let (bus, _, payload, _) = pushes
		.iter()
		.find(|(b, _, _, _)| b == BUS_FIELD_SUB)
		.expect("at least one sub query");
	assert_eq!(bus, BUS_FIELD_SUB);
	for i in 0..FIELD_NUM_LIMBS {
		assert_eq!(payload[i], Goldilocks::ZERO, "a-slot limb {} must be zero", i);
	}
}

fn basepoint() -> EdwardsPoint {
	let x: [u32; FIELD_NUM_LIMBS] = [
		0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760, 0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE,
		0x216936D3,
	];
	let y: [u32; FIELD_NUM_LIMBS] = [
		0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666,
		0x66666666,
	];
	let mut z = [0u32; FIELD_NUM_LIMBS];
	z[0] = 1;
	let t = field_mul(&x, &y);
	EdwardsPoint { x, y, z, t }
}
