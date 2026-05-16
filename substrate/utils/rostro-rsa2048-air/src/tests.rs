// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for the RSA-2048 multiply service AIR (C20a scaffold).
//!
//! Coverage at scaffold stage:
//! - Constants and column layout offsets.
//! - `schoolbook_mul` correctness vs known products + cross-check
//!   via composition (a · (b + c) == a · b + a · c).
//! - Trace builder shape: width, padding to power-of-two, is_active
//!   flag layout.
//! - eval() emits exactly one BUS_RSA2048_MUL push per active row.
//!
//! Correctness coverage for the constraint set lands in C20b's tests.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::Matrix;

use crate::{
	build_mul_row, build_padding_row, build_trace, schoolbook_mul, Rsa2048MulAir,
	BUS_PAYLOAD_LEN, BUS_RSA2048_MUL, COL_A, COL_B, COL_C, COL_C_END, COL_IS_ACTIVE,
	NUM_COLS, RSA2048_LIMBS, RSA2048_PRODUCT_LIMBS,
};

// ─── Constants + layout ────────────────────────────────────────────────────

#[test]
fn limb_counts_match_rsa2048_geometry() {
	// 2048 bits / 32 bits per limb = 64 limbs per operand.
	assert_eq!(RSA2048_LIMBS, 64);
	// Product can be up to 2 × 2048 bits → 128 limbs.
	assert_eq!(RSA2048_PRODUCT_LIMBS, 128);
	// Bus payload: a + b + c = 64 + 64 + 128.
	assert_eq!(BUS_PAYLOAD_LEN, 256);
}

#[test]
fn column_layout_offsets_are_contiguous() {
	assert_eq!(COL_IS_ACTIVE, 0);
	assert_eq!(COL_A, 1);
	assert_eq!(COL_B, COL_A + RSA2048_LIMBS);
	assert_eq!(COL_C, COL_B + RSA2048_LIMBS);
	assert_eq!(COL_C_END, COL_C + RSA2048_PRODUCT_LIMBS);
	assert_eq!(NUM_COLS, COL_C_END);
	// Scaffold width: 1 + 64 + 64 + 128 = 257.
	assert_eq!(NUM_COLS, 257);
}

#[test]
fn bus_name_is_pinned() {
	assert_eq!(BUS_RSA2048_MUL, "rostro-rsa2048-mul");
}

// ─── schoolbook_mul correctness ────────────────────────────────────────────

#[test]
fn schoolbook_mul_zero_times_anything_is_zero() {
	let a = [0u32; RSA2048_LIMBS];
	let b = [0xDEAD_BEEFu32; RSA2048_LIMBS];
	let c = schoolbook_mul(&a, &b);
	assert!(c.iter().all(|&x| x == 0));
}

#[test]
fn schoolbook_mul_one_times_b_is_b_padded_with_zeros() {
	let mut a = [0u32; RSA2048_LIMBS];
	a[0] = 1;
	let mut b = [0u32; RSA2048_LIMBS];
	for i in 0..RSA2048_LIMBS {
		b[i] = (i as u32).wrapping_mul(13).wrapping_add(7);
	}
	let c = schoolbook_mul(&a, &b);
	// c[0..64] == b, c[64..128] == 0.
	for i in 0..RSA2048_LIMBS {
		assert_eq!(c[i], b[i], "limb {} mismatch", i);
	}
	for i in RSA2048_LIMBS..RSA2048_PRODUCT_LIMBS {
		assert_eq!(c[i], 0, "high limb {} should be zero", i);
	}
}

#[test]
fn schoolbook_mul_max_squared_matches_oracle() {
	// (2^2048 - 1) * (2^2048 - 1) = 2^4096 - 2^2049 + 1.
	// As 128 u32 LE limbs:
	//   limb[0] = 1
	//   limb[1..64] = 0
	//   limb[64] = 0xFFFF_FFFE  (since 2^2048 - 2^2049 contribution at bit 2049)
	//
	// Wait — let me redo. (2^N - 1)^2 = 2^(2N) - 2^(N+1) + 1.
	// For N = 2048: 2^4096 - 2^2049 + 1.
	// At bit position 2049: contribution is -2^2049 + (already 1 at bit 0).
	// In LE limb form (32 bits each):
	//   limb[0] (bits 0..32) = 1
	//   limbs[1..64] (bits 32..2048) = 0
	//   limb[64] (bits 2048..2080) = 0  (since -2^2049 starts at bit 2049, limb 64 covers bits 2048..2080)
	//     The -2^2049 contribution to bits 2048..2080: borrow propagates from bit 2049 down.
	//     2^4096 - 2^2049 + 1 = (2^4096 - 1) - (2^2049 - 1) + (1 - 1) ... ugh let me just compute.
	//
	// Easier: use num-style limb-array arithmetic to verify via composition
	// (a * b * c == (a * b) * c when shapes allow) on tractable inputs.
	let mut all_max = [0u32; RSA2048_LIMBS];
	for i in 0..RSA2048_LIMBS {
		all_max[i] = u32::MAX;
	}
	let c = schoolbook_mul(&all_max, &all_max);
	// limb[0] of (2^N - 1)^2: 1.
	assert_eq!(c[0], 1, "limb[0] of max² must be 1");
	// limbs [1..64] zero (no contribution from 2^4096 or 2^2049 yet).
	for i in 1..RSA2048_LIMBS {
		assert_eq!(c[i], 0, "limb[{}] of max² must be 0", i);
	}
	// limb[64]: the 2^4096 + 1 - 2^2049 term, bits 2048..2080.
	//   2^4096 - 2^2049 = 2^2049 * (2^2047 - 1).
	//   At bit position 2048 (low end of limb 64): the value is
	//   (...0 0xFFFFFFFE ...). Specifically, limb[64] = 0xFFFFFFFE.
	assert_eq!(c[64], 0xFFFF_FFFE, "limb[64] of max² must be 0xFFFFFFFE");
	// limbs [65..127] all ones (the 2^4096 - 2^2049 pattern fills with 0xFFFF_FFFF).
	for i in 65..(RSA2048_PRODUCT_LIMBS - 1) {
		assert_eq!(c[i], 0xFFFF_FFFF, "limb[{}] of max² must be all-ones", i);
	}
	// limb[127] (high limb): (2^4096 - 1)'s top is 0x7FFFFFFE? Let me think.
	//   2^4096 is past our representation; the actual value is 2^4096 - 2^2049,
	//   whose top u32 limb (bits 4064..4096) is 0xFFFF_FFFF.
	assert_eq!(c[127], 0xFFFF_FFFF, "limb[127] of max² must be all-ones");
}

#[test]
fn schoolbook_mul_distributive_over_addition() {
	// (a) · (b + c) == (a · b) + (a · c) — distribute through. We compute
	// a · (b + c) as a single multiply AND as the sum of two, then
	// compare limb-by-limb. This is a powerful soundness sanity check
	// because it'd catch any systematic bug in the carry propagation.
	let mut a = [0u32; RSA2048_LIMBS];
	let mut b = [0u32; RSA2048_LIMBS];
	let mut c = [0u32; RSA2048_LIMBS];
	for i in 0..RSA2048_LIMBS {
		a[i] = (i as u32).wrapping_mul(31).wrapping_add(17);
		b[i] = (i as u32).wrapping_mul(7).wrapping_add(3);
		c[i] = (i as u32).wrapping_mul(41).wrapping_add(11);
	}
	// b_plus_c with overflow: capture overflow as a separate carry.
	// To keep `b + c` representable in 64 limbs (i.e., < 2^2048), pick
	// small values. The constants above keep each limb under 2^31, so
	// b + c per limb fits in u32.
	let mut bpc = [0u32; RSA2048_LIMBS];
	let mut carry = 0u64;
	for i in 0..RSA2048_LIMBS {
		let s = u64::from(b[i]) + u64::from(c[i]) + carry;
		bpc[i] = (s & 0xFFFF_FFFF) as u32;
		carry = s >> 32;
	}
	assert_eq!(carry, 0, "test setup: b + c overflowed 2048 bits");

	let lhs = schoolbook_mul(&a, &bpc);
	let ab = schoolbook_mul(&a, &b);
	let ac = schoolbook_mul(&a, &c);

	// rhs = ab + ac, limb-by-limb with carry.
	let mut rhs = [0u32; RSA2048_PRODUCT_LIMBS];
	let mut carry = 0u64;
	for i in 0..RSA2048_PRODUCT_LIMBS {
		let s = u64::from(ab[i]) + u64::from(ac[i]) + carry;
		rhs[i] = (s & 0xFFFF_FFFF) as u32;
		carry = s >> 32;
	}
	// Since lhs == rhs in integer value, the limb arrays must match.
	assert_eq!(lhs, rhs, "distributivity check failed");
	// And no final overflow since the inputs were sized to fit.
	assert_eq!(carry, 0);
}

// ─── Trace builder shape ───────────────────────────────────────────────────

#[test]
fn build_mul_row_marks_is_active_one() {
	let a = [1u32; RSA2048_LIMBS];
	let b = [2u32; RSA2048_LIMBS];
	let row = build_mul_row(&a, &b);
	assert_eq!(row[COL_IS_ACTIVE], Goldilocks::ONE);
	for i in 0..RSA2048_LIMBS {
		assert_eq!(row[COL_A + i], Goldilocks::from_u32(1));
		assert_eq!(row[COL_B + i], Goldilocks::from_u32(2));
	}
}

#[test]
fn build_padding_row_is_inert() {
	let row = build_padding_row();
	assert_eq!(row[COL_IS_ACTIVE], Goldilocks::ZERO);
	for cell in row.iter() {
		assert_eq!(*cell, Goldilocks::ZERO);
	}
}

#[test]
fn build_trace_pads_to_power_of_two() {
	// 3 multiplies → trace height 4 (next power of 2).
	let a = [3u32; RSA2048_LIMBS];
	let b = [5u32; RSA2048_LIMBS];
	let multiplies = vec![(a, b), (a, b), (a, b)];
	let trace = build_trace(&multiplies);
	assert_eq!(trace.height(), 4, "3 multiplies → height 4 after padding");
	assert_eq!(trace.width, NUM_COLS);
	// First 3 rows active, last row padding.
	for r in 0..3 {
		assert_eq!(trace.values[r * NUM_COLS + COL_IS_ACTIVE], Goldilocks::ONE);
	}
	assert_eq!(trace.values[3 * NUM_COLS + COL_IS_ACTIVE], Goldilocks::ZERO);
}

#[test]
fn build_trace_handles_one_multiply() {
	let a = [7u32; RSA2048_LIMBS];
	let b = [11u32; RSA2048_LIMBS];
	let trace = build_trace(&[(a, b)]);
	assert_eq!(trace.height(), 1, "1 multiply → height 1 (already power-of-2)");
}

// ─── eval() emits one bus push per row ─────────────────────────────────────

struct CountingBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	pushes: Vec<(String, usize)>,
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
		self.pushes.push((String::from(bus), arity));
	}
	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

#[test]
fn eval_emits_one_bus_rsa2048_mul_push_with_correct_arity() {
	let a = [0u32; RSA2048_LIMBS];
	let b = [0u32; RSA2048_LIMBS];
	let row: Vec<Goldilocks> = build_mul_row(&a, &b).to_vec();
	let pp: Vec<Goldilocks> = Vec::new();
	let mut b = CountingBuilder {
		main_window: RowWindow::from_two_rows(&row, &row),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
		pushes: Vec::new(),
	};
	Rsa2048MulAir.eval(&mut b);
	assert_eq!(b.pushes.len(), 1, "exactly one bus push per row");
	assert_eq!(b.pushes[0].0, BUS_RSA2048_MUL);
	assert_eq!(b.pushes[0].1, BUS_PAYLOAD_LEN);
}
