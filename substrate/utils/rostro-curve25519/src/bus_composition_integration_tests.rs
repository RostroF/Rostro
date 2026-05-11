// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! End-to-end bus-composition correctness test (P5 of the
//! `pop_edwards25519_air_design.md` plan).
//!
//! Strategy: run a real Edwards25519 point operation against:
//!  - one `PointAddAir` / `PointDoubleAir` (consumer, count = +1)
//!  - one `FieldAddAir`, `FieldSubAir`, `FieldMulAir` per query the
//!    consumer emits (provider, count = -1)
//!
//! For each `BUS_FIELD_{ADD,SUB,MUL}` tuple `(a, b, c)`:
//!  - the consumer pushes it with multiplicity `+1`
//!  - the matching provider pushes the same tuple with multiplicity `-1`
//!  - LogUp net = 0
//!
//! Asserting net-balance = 0 for every distinct `(bus, tuple)` is the
//! soundness-by-composition proof: a real batch-STARK proof for this
//! AIR composition would verify, because the LogUp accumulator
//! telescopes to zero.
//!
//! u16 range-check balance is NOT verified here (that's
//! `rostro-range-check`'s own test surface). The integration here is
//! specifically the new `rostro-field-{add,sub,mul}` service buses.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::field::{add as field_add, mul as field_mul, sub as field_sub, FIELD_NUM_LIMBS};
use crate::field_air::{build_field_add_trace_row, FieldAddAir, BUS_FIELD_ADD};
use crate::field_mul_air::{build_field_mul_trace_row, FieldMulAir, BUS_FIELD_MUL};
use crate::field_sub_air::{build_field_sub_trace_row, FieldSubAir, BUS_FIELD_SUB};
use crate::point::{double as point_double, EdwardsPoint};
use crate::point_add_air::{build_point_add_trace_row, PointAddAir, BUS_POINT_ADD};
use crate::point_double_air::{build_point_double_trace_row, PointDoubleAir, BUS_POINT_DOUBLE};
use crate::scalar_mul_air::{
	build_scalar_mul_trace_matrix, ScalarMulAir, SCALAR_MUL_HEIGHT, SCALAR_MUL_NUM_COLS,
	SCALAR_MUL_NUM_PREPROC_COLS,
};
use crate::elligator2::map_to_curve_elligator2_edwards25519;
use crate::elligator2_air::{
	build_elligator2_trace_row, Elligator2Air, BUS_ELLIGATOR2,
};
use crate::field_air::BUS_U16_RANGE;
use crate::sqrt_ratio_m1_air::BUS_SQRT_RATIO_M1;

// ─── Generic recording builder ─────────────────────────────────────────────
//
// Captures every `push_interaction` so the test can verify LogUp
// balance across multiple AIR runs. The same builder type is reused
// for the consumer (PointAddAir/PointDoubleAir) and the providers
// (FieldAddAir/SubAir/MulAir).

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

fn run_air<A>(air: &A, trace: &[Goldilocks]) -> Vec<(String, Goldilocks, Vec<Goldilocks>, u32)>
where
	A: for<'a> Air<RecordingBuilder<'a>>,
{
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(trace, trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		pushed: Vec::new(),
	};
	air.eval(&mut builder);
	builder.pushed
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn limbs_from(payload: &[Goldilocks], offset: usize) -> [u32; FIELD_NUM_LIMBS] {
	let mut out = [0u32; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		out[i] = payload[offset + i].as_canonical_u64() as u32;
	}
	out
}

/// Render a `(bus, payload)` tuple as a stable key suitable for use in
/// a `BTreeMap` balance ledger. We drop multiplicity / weight here —
/// those are summed per key.
fn ledger_key(bus: &str, payload: &[Goldilocks]) -> (String, Vec<u64>) {
	let key: Vec<u64> = payload.iter().map(|v| v.as_canonical_u64()).collect();
	(bus.to_string(), key)
}

/// For every consumer push the AIR emits on a `rostro-field-*` service
/// bus, instantiate the matching field-op AIR with `(a, b)` from the
/// payload, run its eval, and accumulate every push into a global
/// balance map. Asserts net = 0 for every `(bus, tuple)` on the
/// service buses (the u16 range bus is excluded — that's checked by
/// `rostro-range-check` in isolation).
fn assert_service_bus_balanced_for(consumer_pushes: &[(String, Goldilocks, Vec<Goldilocks>, u32)]) {
	let mut ledger: BTreeMap<(String, Vec<u64>), i64> = BTreeMap::new();

	// Accumulate consumer side first.
	for (bus, mult, payload, _weight) in consumer_pushes {
		if !is_service_bus(bus) {
			continue;
		}
		let key = ledger_key(bus, payload);
		let delta = mult_to_signed(*mult);
		*ledger.entry(key).or_insert(0) += delta;
	}

	// For each consumer-side service-bus push, build + run the matching
	// provider AIR and accumulate its pushes.
	for (bus, _mult, payload, _weight) in consumer_pushes {
		if !is_service_bus(bus) {
			continue;
		}
		let a = limbs_from(payload, 0);
		let b = limbs_from(payload, FIELD_NUM_LIMBS);
		let provider_pushes = run_provider_for(bus, &a, &b);

		// Accumulate ONLY the provider's service-bus push into the
		// service ledger. The provider's u16 range-check pushes are
		// not part of this balance test.
		for (p_bus, p_mult, p_payload, _) in &provider_pushes {
			if !is_service_bus(p_bus) {
				continue;
			}
			let key = ledger_key(p_bus, p_payload);
			let delta = mult_to_signed(*p_mult);
			*ledger.entry(key).or_insert(0) += delta;
		}
	}

	// Every entry should now net to zero.
	for (key, net) in &ledger {
		assert_eq!(
			*net, 0,
			"service-bus balance broken for {:?}: net = {}",
			key.0, net,
		);
	}
}

fn is_service_bus(bus: &str) -> bool {
	bus == BUS_FIELD_ADD || bus == BUS_FIELD_SUB || bus == BUS_FIELD_MUL
}

fn mult_to_signed(m: Goldilocks) -> i64 {
	// Goldilocks's -1 representation: `p - 1 = 2^64 - 2^32`. Encode +1
	// and -1 only — any other multiplicity is a bug in the AIR under
	// test and we surface it loudly.
	if m == Goldilocks::ONE {
		1
	} else if m == Goldilocks::ZERO - Goldilocks::ONE {
		-1
	} else {
		panic!("unexpected multiplicity: {:?}", m);
	}
}

fn run_provider_for(
	bus: &str,
	a: &[u32; FIELD_NUM_LIMBS],
	b: &[u32; FIELD_NUM_LIMBS],
) -> Vec<(String, Goldilocks, Vec<Goldilocks>, u32)> {
	match bus {
		x if x == BUS_FIELD_ADD => {
			let row = build_field_add_trace_row(a, b);
			let trace = row.to_trace_vec::<Goldilocks>();
			run_air(&FieldAddAir::new(), &trace)
		},
		x if x == BUS_FIELD_SUB => {
			let row = build_field_sub_trace_row(a, b);
			let trace = row.to_trace_vec::<Goldilocks>();
			run_air(&FieldSubAir::new(), &trace)
		},
		x if x == BUS_FIELD_MUL => {
			let row = build_field_mul_trace_row(a, b);
			let trace = row.to_trace_vec::<Goldilocks>();
			run_air(&FieldMulAir::new(), &trace)
		},
		_ => panic!("not a service bus: {}", bus),
	}
}

// ─── Tests ─────────────────────────────────────────────────────────────────

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

#[test]
fn point_add_basepoint_plus_2g_balances_against_field_op_providers() {
	let p1 = basepoint();
	let p2 = point_double(&p1);
	let row = build_point_add_trace_row(&p1, &p2);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pushes = run_air(&PointAddAir::new(), &trace);
	// 18 field-op consumer queries + 1 point-add provider emit = 19.
	assert_eq!(pushes.len(), 19, "PointAddAir should push 18 field-op + 1 point-add = 19");
	assert_service_bus_balanced_for(&pushes);
}

#[test]
fn point_double_basepoint_balances_against_field_op_providers() {
	let p1 = basepoint();
	let row = build_point_double_trace_row(&p1);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pushes = run_air(&PointDoubleAir::new(), &trace);
	// 16 field-op consumer queries + 1 point-double provider emit = 17.
	assert_eq!(pushes.len(), 17, "PointDoubleAir should push 16 field-op + 1 point-double = 17");
	assert_service_bus_balanced_for(&pushes);
}

#[test]
fn provider_emits_exactly_one_service_bus_push_per_field_op() {
	// Sanity: each provider AIR emits exactly one push on its service
	// bus (the rest are u16 range queries). Catches accidental
	// duplication of the service-bus emit in any field-op AIR.
	let zero = [0u32; FIELD_NUM_LIMBS];

	let add_pushes = {
		let row = build_field_add_trace_row(&zero, &zero);
		let trace = row.to_trace_vec::<Goldilocks>();
		run_air(&FieldAddAir::new(), &trace)
	};
	assert_eq!(
		add_pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_ADD).count(),
		1,
		"FieldAddAir must emit exactly one service-bus push per row",
	);

	let sub_pushes = {
		let row = build_field_sub_trace_row(&zero, &zero);
		let trace = row.to_trace_vec::<Goldilocks>();
		run_air(&FieldSubAir::new(), &trace)
	};
	assert_eq!(
		sub_pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_SUB).count(),
		1,
		"FieldSubAir must emit exactly one service-bus push per row",
	);

	let mul_pushes = {
		let row = build_field_mul_trace_row(&zero, &zero);
		let trace = row.to_trace_vec::<Goldilocks>();
		run_air(&FieldMulAir::new(), &trace)
	};
	assert_eq!(
		mul_pushes.iter().filter(|(b, _, _, _)| b == BUS_FIELD_MUL).count(),
		1,
		"FieldMulAir must emit exactly one service-bus push per row",
	);
}

#[test]
fn provider_service_emit_carries_canonical_negative_one() {
	// Each provider's service-bus push uses multiplicity -1 (encoded as
	// Goldilocks ZERO - ONE). Make sure we haven't accidentally
	// regressed to +1, which would balance against another provider
	// instead of a consumer.
	let zero = [0u32; FIELD_NUM_LIMBS];

	let row = build_field_add_trace_row(&zero, &zero);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pushes = run_air(&FieldAddAir::new(), &trace);
	let (_, mult, _, _) = pushes
		.iter()
		.find(|(b, _, _, _)| b == BUS_FIELD_ADD)
		.expect("FieldAddAir emits a service push");
	assert_eq!(*mult, Goldilocks::ZERO - Goldilocks::ONE);

	let row = build_field_sub_trace_row(&zero, &zero);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pushes = run_air(&FieldSubAir::new(), &trace);
	let (_, mult, _, _) = pushes
		.iter()
		.find(|(b, _, _, _)| b == BUS_FIELD_SUB)
		.expect("FieldSubAir emits a service push");
	assert_eq!(*mult, Goldilocks::ZERO - Goldilocks::ONE);

	let row = build_field_mul_trace_row(&zero, &zero);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pushes = run_air(&FieldMulAir::new(), &trace);
	let (_, mult, _, _) = pushes
		.iter()
		.find(|(b, _, _, _)| b == BUS_FIELD_MUL)
		.expect("FieldMulAir emits a service push");
	assert_eq!(*mult, Goldilocks::ZERO - Goldilocks::ONE);
}

#[test]
fn point_add_then_double_chain_balances() {
	// Chain: (X3, Y3, Z3, T3) = 2G + G  →  doubled = 6G.
	// Two consumer AIRs, all service-bus tuples must balance.
	let bp = basepoint();
	let two_g = point_double(&bp);

	let row1 = build_point_add_trace_row(&two_g, &bp);
	let trace1 = row1.to_trace_vec::<Goldilocks>();
	let pushes_add = run_air(&PointAddAir::new(), &trace1);

	let three_g = row1.p3;
	let row2 = build_point_double_trace_row(&three_g);
	let trace2 = row2.to_trace_vec::<Goldilocks>();
	let pushes_double = run_air(&PointDoubleAir::new(), &trace2);

	// Combine both consumer push streams; the balance helper
	// instantiates one provider per consumer push, so the combined
	// service-bus ledger should still net to zero. (Each point AIR also
	// emits one provider push on its own point-bus — counted in length
	// but not part of the field-op balance check.)
	let mut combined: Vec<(String, Goldilocks, Vec<Goldilocks>, u32)> = Vec::new();
	combined.extend(pushes_add.into_iter());
	combined.extend(pushes_double.into_iter());
	assert_eq!(combined.len(), 19 + 17);
	assert_service_bus_balanced_for(&combined);

	// And: 3G doubled equals 6G via the standalone point oracle.
	let six_g = point_double(&three_g);
	assert_eq!(row2.p3, six_g, "trace row's p3 must match point::double(3G)");

	// Use the field_add/field_sub witness builders for control flow
	// (silence unused-warning in test build).
	let _ = field_add;
	let _ = field_sub;
}

// ─── S4: ScalarMulAir end-to-end point-bus balance ─────────────────────────
//
// ScalarMulAir pushes 256 consumer queries each on rostro-point-double
// and rostro-point-add. For balance, each consumer (acc_in.xyz, tmp)
// or (tmp, p, cand) tuple must be answered by exactly one provider
// emit from a PointDoubleAir / PointAddAir instance respectively.
//
// We don't run the full 256-instance batch (that's tens of seconds of
// witness time). Instead, we deduplicate the consumer queries by their
// payload, instantiate ONE matching provider per unique payload, and
// require an EXACT 1-to-1 match between consumer and provider tuples.
// LogUp tolerates only matching counts; if even one consumer query
// has no provider answer the proof rejects. A 1:1 instantiation is
// the minimal sufficient witness.

fn point_bus_payloads(
	pushes: &[(String, Goldilocks, Vec<Goldilocks>, u32)],
	bus: &str,
) -> Vec<Vec<Goldilocks>> {
	pushes
		.iter()
		.filter(|(b, _, _, _)| b == bus)
		.map(|(_, _, p, _)| p.clone())
		.collect()
}

/// Decode a `(X, Y, Z, T)` slice (offset, length 32) into an
/// `EdwardsPoint`.
fn point_from_payload(payload: &[Goldilocks], offset: usize) -> EdwardsPoint {
	let mut x = [0u32; FIELD_NUM_LIMBS];
	let mut y = [0u32; FIELD_NUM_LIMBS];
	let mut z = [0u32; FIELD_NUM_LIMBS];
	let mut t = [0u32; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		x[i] = payload[offset + i].as_canonical_u64() as u32;
		y[i] = payload[offset + FIELD_NUM_LIMBS + i].as_canonical_u64() as u32;
		z[i] = payload[offset + 2 * FIELD_NUM_LIMBS + i].as_canonical_u64() as u32;
		t[i] = payload[offset + 3 * FIELD_NUM_LIMBS + i].as_canonical_u64() as u32;
	}
	EdwardsPoint { x, y, z, t }
}

#[test]
fn scalar_mul_air_point_buses_balance_against_point_providers() {
	// Use scalar = 7 (binary 0b111) so the early bits exercise both
	// double-and-add paths (bit=1) without making the test long.
	let mut scalar = [0u8; 32];
	scalar[0] = 7;
	let p = basepoint();

	// Run ScalarMulAir against the recording builder by stepping through
	// each row's (current, next) window and accumulating all pushes.
	let trace_matrix = build_scalar_mul_trace_matrix::<Goldilocks>(&scalar, &p);
	let trace = trace_matrix.values;
	let mut all_pushes: Vec<(String, Goldilocks, Vec<Goldilocks>, u32)> = Vec::new();
	let air = ScalarMulAir::new();
	let preproc = <ScalarMulAir as BaseAir<Goldilocks>>::preprocessed_trace(&air)
		.expect("scalar-mul preprocessed trace");
	for row in 0..SCALAR_MUL_HEIGHT {
		let next = (row + 1) % SCALAR_MUL_HEIGHT;
		let cur_slice = &trace[row * SCALAR_MUL_NUM_COLS..(row + 1) * SCALAR_MUL_NUM_COLS];
		let next_slice =
			&trace[next * SCALAR_MUL_NUM_COLS..(next + 1) * SCALAR_MUL_NUM_COLS];
		let pp_cur = &preproc.values
			[row * SCALAR_MUL_NUM_PREPROC_COLS..(row + 1) * SCALAR_MUL_NUM_PREPROC_COLS];
		let pp_next = &preproc.values
			[next * SCALAR_MUL_NUM_PREPROC_COLS..(next + 1) * SCALAR_MUL_NUM_PREPROC_COLS];
		let mut b = RecordingBuilder {
			main_window: RowWindow::from_two_rows(cur_slice, next_slice),
			preprocessed_window: RowWindow::from_two_rows(pp_cur, pp_next),
			pushed: Vec::new(),
		};
		<ScalarMulAir as Air<RecordingBuilder>>::eval(&air, &mut b);
		all_pushes.extend(b.pushed.into_iter());
	}

	// ScalarMulAir's only buses are point-double + point-add.
	let pd_payloads = point_bus_payloads(&all_pushes, BUS_POINT_DOUBLE);
	let pa_payloads = point_bus_payloads(&all_pushes, BUS_POINT_ADD);
	assert_eq!(pd_payloads.len(), SCALAR_MUL_HEIGHT, "1 double query / row");
	assert_eq!(pa_payloads.len(), SCALAR_MUL_HEIGHT, "1 add query / row");

	// For each consumer payload, instantiate ONE matching provider and
	// confirm its provider emit produces an identical 56/96-cell
	// payload. Equality of payloads + opposite count = +1 vs -1 means
	// LogUp balances by construction.
	for payload in &pd_payloads {
		// rostro-point-double payload: (X1, Y1, Z1, X3, Y3, Z3, T3).
		// X3, Y3, Z3, T3 are at offsets 24, 32, 40, 48 (limbs 24..56).
		let mut x1 = [0u32; FIELD_NUM_LIMBS];
		let mut y1 = [0u32; FIELD_NUM_LIMBS];
		let mut z1 = [0u32; FIELD_NUM_LIMBS];
		for i in 0..FIELD_NUM_LIMBS {
			x1[i] = payload[i].as_canonical_u64() as u32;
			y1[i] = payload[FIELD_NUM_LIMBS + i].as_canonical_u64() as u32;
			z1[i] = payload[2 * FIELD_NUM_LIMBS + i].as_canonical_u64() as u32;
		}
		// Recover T1 from the curve invariant T1 = X1·Y1/Z1 is wrong
		// because acc_in has T1; we don't have it in the bus payload.
		// PointDoubleAir's witness builder constructs its own T1 too —
		// just feed (x1, y1, z1, 0) as p1 and let `build_point_double_
		// trace_row` recompute the formula (it doesn't read T1 anyway).
		let p1 = EdwardsPoint { x: x1, y: y1, z: z1, t: [0u32; FIELD_NUM_LIMBS] };
		let row = build_point_double_trace_row(&p1);
		let trace = row.to_trace_vec::<Goldilocks>();
		let provider_pushes = run_air(&PointDoubleAir::new(), &trace);
		let provider_emit = provider_pushes
			.iter()
			.find(|(b, _, _, _)| b == BUS_POINT_DOUBLE)
			.expect("PointDoubleAir provider push present");
		assert_eq!(
			&provider_emit.2, payload,
			"PointDoubleAir provider payload diverges from ScalarMulAir consumer query",
		);
		// Provider multiplicity is -1; consumer is +1; net = 0.
		assert_eq!(provider_emit.1, Goldilocks::ZERO - Goldilocks::ONE);
	}

	for payload in &pa_payloads {
		// rostro-point-add payload: (p1, p2, p3) — each 32 cells.
		let p1 = point_from_payload(payload, 0);
		let p2 = point_from_payload(payload, 32);
		let row = build_point_add_trace_row(&p1, &p2);
		let trace = row.to_trace_vec::<Goldilocks>();
		let provider_pushes = run_air(&PointAddAir::new(), &trace);
		let provider_emit = provider_pushes
			.iter()
			.find(|(b, _, _, _)| b == BUS_POINT_ADD)
			.expect("PointAddAir provider push present");
		assert_eq!(
			&provider_emit.2, payload,
			"PointAddAir provider payload diverges from ScalarMulAir consumer query",
		);
		assert_eq!(provider_emit.1, Goldilocks::ZERO - Goldilocks::ONE);
	}
}

// ─── H2: Elligator2Air bus balance ─────────────────────────────────────────
//
// Closes the in-row test gap from `elligator2_air_tests`: corrupting an
// output column (x_E, y_E, t_E) of a BUS_FIELD_MUL push isn't caught by
// row-local constraints. Here we verify every consumer push the AIR emits
// is algebraically consistent — for each (a, b, c) on a field bus, c must
// equal op(a, b); for each sqrt-ratio query, (was_sq, r) must match
// `field::sqrt_ratio_m1(u, v)`. This is the necessary condition for any
// honest provider trace to balance the LogUp.

fn limbs_from_payload(p: &[Goldilocks], offset: usize) -> [u32; FIELD_NUM_LIMBS] {
	core::array::from_fn(|i| p[offset + i].as_canonical_u64() as u32)
}

#[test]
fn elligator2_air_bus_pushes_are_algebraically_consistent() {
	let mut u = [0u32; FIELD_NUM_LIMBS];
	u[0] = 7;
	let row = build_elligator2_trace_row(&u);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pushes = run_air(&Elligator2Air::new(), &trace);

	let mut mul_count = 0;
	let mut add_count = 0;
	let mut sub_count = 0;
	let mut sqrt_count = 0;
	let mut u16r_count = 0;
	let mut service_count = 0;

	for (bus, _count, payload, _weight) in &pushes {
		if bus == BUS_FIELD_MUL || bus == BUS_FIELD_ADD || bus == BUS_FIELD_SUB {
			assert_eq!(payload.len(), 24, "{} payload = 24 cells", bus);
			let a = limbs_from_payload(payload, 0);
			let b = limbs_from_payload(payload, FIELD_NUM_LIMBS);
			let c = limbs_from_payload(payload, 2 * FIELD_NUM_LIMBS);
			let expected = if bus == BUS_FIELD_MUL {
				mul_count += 1;
				field_mul(&a, &b)
			} else if bus == BUS_FIELD_ADD {
				add_count += 1;
				field_add(&a, &b)
			} else {
				sub_count += 1;
				field_sub(&a, &b)
			};
			assert_eq!(c, expected, "{} consumer payload mismatch: a={:?} b={:?}", bus, a, b);
		} else if bus == BUS_SQRT_RATIO_M1 {
			sqrt_count += 1;
			assert_eq!(payload.len(), 25, "sqrt-ratio payload = 25 cells");
			let u_arg = limbs_from_payload(payload, 0);
			let v_arg = limbs_from_payload(payload, FIELD_NUM_LIMBS);
			let was_sq_emitted = payload[2 * FIELD_NUM_LIMBS].as_canonical_u64();
			let r = limbs_from_payload(payload, 2 * FIELD_NUM_LIMBS + 1);
			let (oracle_was_sq, oracle_r) =
				crate::field::sqrt_ratio_m1(&u_arg, &v_arg);
			assert_eq!(
				was_sq_emitted, u64::from(oracle_was_sq),
				"sqrt_ratio_m1 was_square mismatch",
			);
			assert_eq!(r, oracle_r, "sqrt_ratio_m1 r mismatch");
		} else if bus == BUS_U16_RANGE {
			u16r_count += 1;
			assert_eq!(payload.len(), 1, "u16-range payload = 1 cell");
			let v = payload[0].as_canonical_u64();
			assert!(v < (1u64 << 16), "u16-range value {} exceeds 2^16", v);
		} else if bus == BUS_ELLIGATOR2 {
			service_count += 1;
			assert_eq!(payload.len(), 40, "service emit = 40 cells");
			// Verify the emitted point matches the witness oracle.
			let u_emit = limbs_from_payload(payload, 0);
			let x_e = limbs_from_payload(payload, FIELD_NUM_LIMBS);
			let y_e = limbs_from_payload(payload, 2 * FIELD_NUM_LIMBS);
			let z_e = limbs_from_payload(payload, 3 * FIELD_NUM_LIMBS);
			let t_e = limbs_from_payload(payload, 4 * FIELD_NUM_LIMBS);
			assert_eq!(u_emit, u, "service emit u doesn't match input");
			let oracle = map_to_curve_elligator2_edwards25519(&u);
			assert_eq!(x_e, oracle.x, "service emit x_E mismatch");
			assert_eq!(y_e, oracle.y, "service emit y_E mismatch");
			assert_eq!(z_e, oracle.z, "service emit z_E mismatch");
			assert_eq!(t_e, oracle.t, "service emit t_E mismatch");
		}
	}

	assert!(mul_count > 0, "expected BUS_FIELD_MUL pushes");
	assert!(add_count > 0, "expected BUS_FIELD_ADD pushes");
	assert!(sub_count > 0, "expected BUS_FIELD_SUB pushes");
	assert_eq!(sqrt_count, 2, "expected 2 BUS_SQRT_RATIO_M1 pushes");
	assert_eq!(u16r_count, 2, "expected 2 BUS_U16_RANGE pushes (LSB-tie)");
	assert_eq!(service_count, 1, "expected 1 service emit");
}
