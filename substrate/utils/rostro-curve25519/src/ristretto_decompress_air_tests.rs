// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::ristretto_decompress_air::RistrettoDecompressAir`].

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::field::{bytes_to_limbs, mul as field_mul, FIELD_NUM_LIMBS};
use crate::field_air::BUS_FIELD_ADD;
use crate::field_mul_air::BUS_FIELD_MUL;
use crate::field_sub_air::BUS_FIELD_SUB;
use crate::point::{double as point_double, EdwardsPoint};
use crate::ristretto::compress as oracle_compress;
use crate::ristretto_decompress_air::{
	build_ristretto_decompress_trace_row, RistrettoDecompressAir, BUS_RISTRETTO_DECOMPRESS,
	COL_IS_T_NEG, COL_IS_VALID, COL_IS_Y_ZERO, COL_S, COL_X, COL_X_IS_NEG, COL_Y,
	RISTRETTO_DECOMPRESS_NUM_COLS,
};
use crate::sqrt_ratio_m1_air::BUS_SQRT_RATIO_M1;

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
		assert!(v.is_zero(), "constraint #{} failed: value = {:?}", self.constraint_index, v);
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
	assert_eq!(trace.len(), RISTRETTO_DECOMPRESS_NUM_COLS);
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut b = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(trace, trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		constraint_index: 0,
	};
	let air = RistrettoDecompressAir::new();
	<RistrettoDecompressAir as Air<ExpectZeroBuilder>>::eval(&air, &mut b);
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
fn trace_row_decompresses_basepoint_compress_output() {
	// Round-trip: compress(G) → bytes → decompress → trace.
	let bp = basepoint();
	let bytes = oracle_compress(&bp);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	assert_eq!(row.is_valid, 1, "basepoint encoding must decompress validly");
	// Recompress the trace's (x, y, z=1, t) and compare bytes.
	let recompressed = oracle_compress(&EdwardsPoint {
		x: row.x,
		y: row.y,
		z: row.z,
		t: row.t,
	});
	assert_eq!(
		recompressed, bytes,
		"trace's decompressed point must re-compress to the same bytes",
	);
}

#[test]
fn trace_row_rejects_zero_s_via_is_y_zero() {
	// s = 0 decompresses to (X=0, Y=1, ...) — the identity. The Ristretto
	// witness function decompress(zero) returns Some(identity), so
	// is_valid should be 1 (zero encoding is the canonical identity).
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_ristretto_decompress_trace_row(&zero);
	assert_eq!(row.is_valid, 1, "zero encoding decompresses to identity (valid)");
	assert_eq!(row.is_y_zero, 0, "identity has Y=1, not zero");
}

// ─── AIR acceptance ────────────────────────────────────────────────────────

#[test]
fn air_accepts_basepoint_decompress() {
	let bp = basepoint();
	let bytes = oracle_compress(&bp);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_2g_decompress() {
	let g2 = point_double(&basepoint());
	let bytes = oracle_compress(&g2);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_zero_encoding() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_ristretto_decompress_trace_row(&zero);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

// ─── AIR rejection ─────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_is_valid() {
	let bp = basepoint();
	let bytes = oracle_compress(&bp);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip is_valid: the deg-2 chain is_valid = intermediate · not_y_zero
	// catches it.
	trace[COL_IS_VALID] = Goldilocks::ONE - trace[COL_IS_VALID];
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_forged_x_is_neg() {
	// Audit gap (closed): without the LSB-tie, the prover could swing
	// x_is_neg independently of LSB(x_raw[0]) and emit either the +x or
	// -x branch indistinguishably. Flipping the flag without re-deriving
	// limb_hi witnesses must violate `x_raw[0] = 2·limb_hi + flag`.
	let bp = basepoint();
	let bytes = oracle_compress(&bp);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_X_IS_NEG] = Goldilocks::ONE - trace[COL_X_IS_NEG];
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_forged_is_t_neg() {
	// Symmetric coverage for the second LSB-tie on T[0].
	let bp = basepoint();
	let bytes = oracle_compress(&bp);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_IS_T_NEG] = Goldilocks::ONE - trace[COL_IS_T_NEG];
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_forged_is_y_zero_when_y_nonzero() {
	// Audit gap (closed) — direction A: y is nonzero (basepoint),
	// honest is_y_zero=0. Forging to 1 violates `is_y_zero · Σ(1-y_lz[i])
	// = 0` because at least one y limb is nonzero.
	let bp = basepoint();
	let bytes = oracle_compress(&bp);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	assert_eq!(row.is_y_zero, 0, "basepoint has y != 0");
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_IS_Y_ZERO] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_forged_is_y_zero_when_y_is_zero() {
	// Audit gap (closed) — direction B (the headline attack):
	// s=1 yields y=0 (a torsion-flavored encoding). Honest is_y_zero=1
	// gives is_valid=0; forging is_y_zero=0 would let is_valid=1 slip
	// through. The new constraint `(1 - is_y_zero) · (s_y · inv_s - 1)`
	// rejects: s_y = 0 here, so s_y · inv_s - 1 = -1 ≠ 0.
	let mut s = [0u32; FIELD_NUM_LIMBS];
	s[0] = 1;
	let row = build_ristretto_decompress_trace_row(&s);
	assert_eq!(row.is_y_zero, 1, "test premise: s=1 produces y=0");
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_IS_Y_ZERO] = Goldilocks::ZERO;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_x() {
	let bp = basepoint();
	let bytes = oracle_compress(&bp);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Corrupt x[0]: the x = x_is_neg ? neg_x_raw : x_raw selection breaks.
	trace[COL_X] = trace[COL_X] + Goldilocks::ONE;
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
	let bp = basepoint();
	let bytes = oracle_compress(&bp);
	let s = bytes_to_limbs(&bytes);
	let row = build_ristretto_decompress_trace_row(&s);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut b = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace, &trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		pushed: Vec::new(),
	};
	let air = RistrettoDecompressAir::new();
	<RistrettoDecompressAir as Air<RecordingBuilder>>::eval(&air, &mut b);

	let muls = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_MUL).count();
	let subs = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_SUB).count();
	let adds = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_FIELD_ADD).count();
	let sqrts = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_SQRT_RATIO_M1).count();
	let services = b.pushed.iter().filter(|(bus, _, _, _)| bus == BUS_RISTRETTO_DECOMPRESS).count();
	assert_eq!(muls, 11, "expected 11 mul consumer queries");
	assert_eq!(subs, 4, "expected 4 sub consumer queries");
	assert_eq!(adds, 2, "expected 2 add consumer queries");
	assert_eq!(sqrts, 1, "expected 1 sqrt-ratio-m1 consumer query");
	assert_eq!(services, 1, "expected 1 service emit");

	let svc = b.pushed.iter().find(|(bus, _, _, _)| bus == BUS_RISTRETTO_DECOMPRESS).unwrap();
	assert_eq!(svc.2, 41, "service payload = (s, X, Y, Z, T, is_valid) = 5×8 + 1 = 41 cells");
	assert_eq!(svc.1, Goldilocks::ZERO - Goldilocks::ONE, "provider count = -1");
}

#[test]
fn service_bus_name_is_pinned() {
	assert_eq!(BUS_RISTRETTO_DECOMPRESS, "rostro-ristretto-decompress");
}

// Suppress unused warnings.
#[allow(dead_code)]
fn _force_use() {
	let _ = COL_S;
	let _ = COL_Y;
	let _: u64 = Goldilocks::ONE.as_canonical_u64();
}
