// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::point_add_air::PointAddAir`].
//!
//! Per the silo principle (`feedback_no_cross_purpose_files.md`), a
//! local recording builder is duplicated here rather than shared with
//! field_*_air_tests. A bug in one AIR's test harness cannot affect
//! another.
//!
//! Test strategy:
//! - **Layout pin**: column constants are stable.
//! - **Bus pin**: bus names match the service AIRs we depend on.
//! - **Shape test**: eval emits exactly 18 bus messages (4 sub + 5 add
//!   + 9 mul), each with 24-cell payload and consumer count = +1.
//! - **Per-message content**: every (a, b, c) tuple in the recorded
//!   bus traffic satisfies the corresponding field op (oracle cross-
//!   check via `crate::field::{add, sub, mul}`). This is the
//!   bus-composition correctness proof: the service AIRs would
//!   accept these tuples, so balance holds.

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
use crate::point::{add as point_add, double as point_double, neutral, EdwardsPoint};
use crate::point_add_air::{
	build_point_add_trace_row, PointAddAir, COL_A, COL_B, COL_C, COL_D, COL_E, COL_F, COL_G,
	COL_H, COL_K_T2, COL_P1_T, COL_P1_X, COL_P1_Y, COL_P1_Z, COL_P2_T, COL_P2_X, COL_P2_Y,
	COL_P2_Z, COL_P3_T, COL_P3_X, COL_P3_Y, COL_P3_Z, COL_TWO_Z2, COL_Y1_MINUS_X1,
	COL_Y1_PLUS_X1, COL_Y2_MINUS_X2, COL_Y2_PLUS_X2, POINT_ADD_NUM_COLS,
};

// ─── Recording builder ─────────────────────────────────────────────────────

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

/// Convenience: build trace, run eval against the recording builder,
/// return the captured push log.
fn record_eval(
	p1: &EdwardsPoint,
	p2: &EdwardsPoint,
) -> Vec<(String, Goldilocks, Vec<Goldilocks>, u32)> {
	let row = build_point_add_trace_row(p1, p2);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace, &trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		pushed: Vec::new(),
	};
	let air = PointAddAir::new();
	<PointAddAir as Air<RecordingBuilder>>::eval(&air, &mut builder);
	builder.pushed
}

// ─── Layout + bus-name pin tests ───────────────────────────────────────────

#[test]
fn column_layout_constants_are_stable() {
	// Each group is 8 limbs (= FIELD_NUM_LIMBS) wide.
	assert_eq!(COL_P1_X, 0);
	assert_eq!(COL_P1_Y, 8);
	assert_eq!(COL_P1_Z, 16);
	assert_eq!(COL_P1_T, 24);
	assert_eq!(COL_P2_X, 32);
	assert_eq!(COL_P2_Y, 40);
	assert_eq!(COL_P2_Z, 48);
	assert_eq!(COL_P2_T, 56);
	assert_eq!(COL_Y1_MINUS_X1, 64);
	assert_eq!(COL_Y2_MINUS_X2, 72);
	assert_eq!(COL_Y1_PLUS_X1, 80);
	assert_eq!(COL_Y2_PLUS_X2, 88);
	assert_eq!(COL_TWO_Z2, 96);
	assert_eq!(COL_A, 104);
	assert_eq!(COL_B, 112);
	assert_eq!(COL_K_T2, 120);
	assert_eq!(COL_C, 128);
	assert_eq!(COL_D, 136);
	assert_eq!(COL_E, 144);
	assert_eq!(COL_F, 152);
	assert_eq!(COL_G, 160);
	assert_eq!(COL_H, 168);
	assert_eq!(COL_P3_X, 176);
	assert_eq!(COL_P3_Y, 184);
	assert_eq!(COL_P3_Z, 192);
	assert_eq!(COL_P3_T, 200);
	assert_eq!(POINT_ADD_NUM_COLS, 208);
}

#[test]
fn trace_vec_width_matches_layout() {
	let p1 = neutral();
	let p2 = neutral();
	let row = build_point_add_trace_row(&p1, &p2);
	let trace = row.to_trace_vec::<Goldilocks>();
	assert_eq!(trace.len(), POINT_ADD_NUM_COLS);
}

// ─── Shape test: 18 pushes total ───────────────────────────────────────────

#[test]
fn point_add_emits_18_service_bus_queries() {
	let p1 = neutral();
	let p2 = neutral();
	let pushes = record_eval(&p1, &p2);

	// 4 sub + 5 add + 9 mul = 18.
	assert_eq!(pushes.len(), 18, "expected exactly 18 service-bus pushes");

	let num_subs = pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_SUB).count();
	let num_adds = pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_ADD).count();
	let num_muls = pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_MUL).count();
	assert_eq!(num_subs, 4, "expected 4 sub queries");
	assert_eq!(num_adds, 5, "expected 5 add queries");
	assert_eq!(num_muls, 9, "expected 9 mul queries");

	// Each push is a consumer query: count = +1, payload = 24 cells, weight = 1.
	for (bus, mult, payload, weight) in &pushes {
		assert_eq!(*mult, Goldilocks::ONE, "consumer count must be +1 (bus={})", bus);
		assert_eq!(payload.len(), 24, "payload must be 24 cells (bus={})", bus);
		assert_eq!(*weight, 1, "count_weight must be 1 (bus={})", bus);
	}
}

// ─── Content correctness via field-op oracles ──────────────────────────────
//
// For every (a, b, c) tuple pushed onto a service bus, the field-op
// oracle should agree that c = a OP b mod p. This proves the consumer
// is asking the service AIR a question it would answer truthfully —
// the bus-composition soundness story.

fn limbs_from(payload: &[Goldilocks], offset: usize) -> [u32; FIELD_NUM_LIMBS] {
	let mut out = [0u32; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		// Goldilocks values produced by the AIR are always in [0, 2^32)
		// for limb columns. Use the canonical representative.
		let v = payload[offset + i].as_canonical_u64();
		out[i] = v as u32;
	}
	out
}

#[test]
fn every_pushed_tuple_satisfies_its_field_op() {
	// Use 2G + G (basepoint-derived points) to exercise non-trivial
	// witness values across every (a, b, c) tuple.
	let bp = basepoint();
	let p1 = point_double(&bp);
	let p2 = bp;
	let pushes = record_eval(&p1, &p2);

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
fn output_p3_matches_point_add_oracle() {
	// Whatever PointAddAir's trace publishes for p3, it should match
	// `crate::point::add` (which is itself dalek-verified by
	// point_oracle_tests).
	let bp = basepoint();
	let p1 = bp;
	let p2 = point_double(&bp);
	let row = build_point_add_trace_row(&p1, &p2);
	let expected = point_add(&p1, &p2);
	assert_eq!(row.p3, expected, "trace builder's p3 must equal point::add(p1, p2)");
}

// ─── Witness helper: basepoint in extended coords ──────────────────────────
//
// Duplicated locally to keep this test file silo'd from
// point_oracle_tests::basepoint. The basepoint coordinates are pinned
// by RFC 8032 and cross-checked there.

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
