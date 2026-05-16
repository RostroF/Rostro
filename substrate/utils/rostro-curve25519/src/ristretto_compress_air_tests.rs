// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::ristretto_compress_air::RistrettoCompressAir`].

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::field::{mul as field_mul, FIELD_NUM_LIMBS};
use crate::field_air::BUS_FIELD_ADD;
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_sub_air::BUS_FIELD_SUB;
use crate::point::{double as point_double, EdwardsPoint};
use crate::ristretto::compress as oracle_compress;
use crate::ristretto_compress_air::{
	build_ristretto_compress_trace_row, RistrettoCompressAir, BUS_RISTRETTO_COMPRESS,
	COL_INVSQRT_WAS_SQ, COL_ROTATE, COL_S, COL_SIGN_S, RISTRETTO_COMPRESS_NUM_COLS,
};
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
	assert_eq!(trace.len(), RISTRETTO_COMPRESS_NUM_COLS);
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut b = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(trace, trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		constraint_index: 0,
	};
	let air = RistrettoCompressAir::new();
	<RistrettoCompressAir as Air<ExpectZeroBuilder>>::eval(&air, &mut b);
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

// ─── Witness oracle cross-check ────────────────────────────────────────────

#[test]
fn trace_row_s_matches_oracle_compress() {
	use crate::field::limbs_to_bytes;
	for p in [basepoint(), point_double(&basepoint())].iter() {
		let row = build_ristretto_compress_trace_row(p);
		let oracle_bytes = oracle_compress(p);
		let trace_bytes = limbs_to_bytes(&row.s);
		assert_eq!(trace_bytes, oracle_bytes, "trace's s diverges from ristretto::compress");
	}
}

// ─── AIR acceptance ────────────────────────────────────────────────────────

#[test]
fn air_accepts_basepoint_compress() {
	let row = build_ristretto_compress_trace_row(&basepoint());
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_double_basepoint_compress() {
	let row = build_ristretto_compress_trace_row(&point_double(&basepoint()));
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_basepoint_chain() {
	// G, 2G, 3G, 4G all compress correctly.
	use crate::point::add as point_add;
	let g = basepoint();
	let g2 = point_double(&g);
	let g3 = point_add(&g2, &g);
	let g4 = point_double(&g2);
	for p in [g, g2, g3, g4].iter() {
		let row = build_ristretto_compress_trace_row(p);
		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

// ─── Rejection ─────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_s() {
	let row = build_ristretto_compress_trace_row(&basepoint());
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_S] = trace[COL_S] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_flipped_sign_s() {
	let row = build_ristretto_compress_trace_row(&basepoint());
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip sign_s; the s = (sign_s ? neg_s_raw : s_raw) selection breaks.
	trace[COL_SIGN_S] = Goldilocks::ONE - trace[COL_SIGN_S];
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_forged_rotate() {
	// Audit gap (closed): without LSB-tie, the prover could swing rotate
	// independently of (T · zinv)'s actual parity, picking which 4-coset
	// representative gets emitted. The LSB decomposition pins rotate to
	// the actual LSB of T_ZINV[0]; flipping rotate without re-deriving
	// the limb_hi witness must fail the algebraic equation.
	let row = build_ristretto_compress_trace_row(&basepoint());
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_ROTATE] = Goldilocks::ONE - trace[COL_ROTATE];
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_invsqrt_was_sq_zero() {
	// Ristretto255 guarantees 1/(u1·u2²) IS a square for any image point.
	// A malicious prover claiming was_square=0 would let SqrtRatioM1Air
	// fulfill the lookup on its broken was_square=0 branch with arbitrary
	// invsqrt. assert_one(invsqrt_was_sq) closes that path; this test
	// proves the assertion is active.
	let row = build_ristretto_compress_trace_row(&basepoint());
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_INVSQRT_WAS_SQ] = Goldilocks::ZERO;
	run_eval(&trace);
}

// ─── Bus push count ────────────────────────────────────────────────────────

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
	let row = build_ristretto_compress_trace_row(&basepoint());
	let trace = row.to_trace_vec::<Goldilocks>();
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut b = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace, &trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		pushed: Vec::new(),
	};
	let air = RistrettoCompressAir::new();
	<RistrettoCompressAir as Air<RecordingBuilder>>::eval(&air, &mut b);

	let muls = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_MUL).count();
	let subs = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_SUB).count();
	let adds = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_ADD).count();
	let sqrts = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_SQRT_RATIO_M1).count();
	let services = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_RISTRETTO_COMPRESS).count();
	assert_eq!(muls, 14, "expected 14 mul consumer queries");
	assert_eq!(subs, 4, "expected 4 sub consumer queries");
	assert_eq!(adds, 1, "expected 1 add consumer query");
	assert_eq!(sqrts, 1, "expected 1 sqrt-ratio-m1 consumer query");
	assert_eq!(services, 1, "expected 1 service emit");

	let svc = b.pushed.iter().find(|(bus, _, _, _)| bus == BUS_RISTRETTO_COMPRESS).unwrap();
	assert_eq!(svc.2, 40, "service payload = (X, Y, Z, T, s) × 8 = 40 cells");
	assert_eq!(svc.1, Goldilocks::ZERO - Goldilocks::ONE, "provider count = -1");
}

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_RISTRETTO_COMPRESS, "rostro-ristretto-compress");
}

// Make sure unused vars in `silenced` paths don't trigger warnings.
#[allow(dead_code)]
fn _force_use() {
	let _: u32 = 0;
	let _: <Goldilocks as Field>::Packing = Goldilocks::ONE.into();
	let _: u64 = Goldilocks::ONE.as_canonical_u64();
}
