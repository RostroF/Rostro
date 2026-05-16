// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::field_mul_air::FieldMulAir`] M1 stage (schoolbook
//! trace, no Barrett reduction yet).
//!
//! Per silo principle, NO shared `ExpectZeroBuilder` between AIR test
//! files — each has its own local copy.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use rand::SeedableRng;

use crate::field::{FIELD_NUM_LIMBS, P_MINUS_ONE_LIMBS};
use crate::field_air::BUS_U16_RANGE;
use crate::field_mul_air::{
	build_field_mul_trace_row, FieldMulAir, COL_MUL_A, COL_MUL_A_HI, COL_MUL_A_LO, COL_MUL_B,
	COL_MUL_B_HI, COL_MUL_B_LO, COL_MUL_C, COL_MUL_C_COMP, COL_MUL_C_COMP_BORROW,
	COL_MUL_C_COMP_HI, COL_MUL_C_COMP_LO, COL_MUL_C_HI, COL_MUL_C_LO, COL_MUL_CARRY,
	COL_MUL_CARRY_HI, COL_MUL_CARRY_LO, COL_MUL_Q, COL_MUL_QP_BORROW, COL_MUL_QP_CARRY,
	COL_MUL_QP_CARRY_HI, COL_MUL_QP_CARRY_LO, COL_MUL_QP_WIDE, COL_MUL_QP_WIDE_HI,
	COL_MUL_QP_WIDE_LO, COL_MUL_Q_HI, COL_MUL_Q_LO, COL_MUL_WIDE, COL_MUL_WIDE_HI,
	COL_MUL_WIDE_LO, FIELD_MUL_M1_NUM_COLS, FIELD_MUL_NUM_COLS, NUM_COLS_SCHOOLBOOK,
	WIDE_NUM_LIMBS,
};
use crate::oracle_tests_helpers::random_canonical;

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

fn run_eval(row: &[Goldilocks]) {
	assert_eq!(row.len(), FIELD_MUL_NUM_COLS);
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut builder = ExpectZeroBuilder {
		main_window: RowWindow::from_two_rows(row, row),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		constraint_index: 0,
	};
	let air = FieldMulAir::new();
	<FieldMulAir as Air<ExpectZeroBuilder>>::eval(&air, &mut builder);
}

// ─── Acceptance tests ──────────────────────────────────────────────────────

#[test]
fn air_accepts_zero_times_zero() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	assert_eq!(row.wide, [0u32; WIDE_NUM_LIMBS]);
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_one_times_one() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let row = build_field_mul_trace_row(&one, &one);
	// wide_product = 1 * 1 = 1.
	assert_eq!(row.wide[0], 1);
	for i in 1..WIDE_NUM_LIMBS {
		assert_eq!(row.wide[i], 0);
	}
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_small_product() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 7;
	b[0] = 11;
	let row = build_field_mul_trace_row(&a, &b);
	assert_eq!(row.wide[0], 77);
	for i in 1..WIDE_NUM_LIMBS {
		assert_eq!(row.wide[i], 0);
	}
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_p_minus_one_squared() {
	// (p-1)^2 as integer is a 510-bit value; should fit in 16 u32 limbs.
	let row = build_field_mul_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	// Cross-check the witnessed wide against num-bigint.
	use num_bigint::BigUint;
	let p_minus_one = BigUint::from_bytes_le(&crate::field::limbs_to_bytes(&P_MINUS_ONE_LIMBS));
	let expected = &p_minus_one * &p_minus_one;
	let expected_bytes = expected.to_bytes_le();
	let mut expected_padded = [0u8; 64];
	expected_padded[..expected_bytes.len()].copy_from_slice(&expected_bytes);
	let mut actual_bytes = [0u8; 64];
	for (i, limb) in row.wide.iter().enumerate() {
		actual_bytes[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_le_bytes());
	}
	assert_eq!(actual_bytes, expected_padded, "(p-1)^2 wide product diverges from bigint");
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_accepts_random_fuzz() {
	use num_bigint::BigUint;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xff11_22ee_33dd_44cc);
	for _ in 0..30 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let row = build_field_mul_trace_row(&a, &b);

		// Cross-check wide_product against num-bigint.
		let a_big = BigUint::from_bytes_le(&crate::field::limbs_to_bytes(&a));
		let b_big = BigUint::from_bytes_le(&crate::field::limbs_to_bytes(&b));
		let expected = &a_big * &b_big;
		let expected_bytes = expected.to_bytes_le();
		let mut expected_padded = [0u8; 64];
		expected_padded[..expected_bytes.len()].copy_from_slice(&expected_bytes);
		let mut actual_bytes = [0u8; 64];
		for (i, limb) in row.wide.iter().enumerate() {
			actual_bytes[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_le_bytes());
		}
		assert_eq!(actual_bytes, expected_padded, "wide product diverges from bigint");

		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

// ─── Rejection tests ───────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_a_lo_split() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0x1234_5678;
	b[0] = 0x9abc_def0;
	let row = build_field_mul_trace_row(&a, &b);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip a_lo[0] — limb-split constraint for a fails.
	trace[COL_MUL_A_LO] = trace[COL_MUL_A_LO] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_wide_lo_split() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_MUL_WIDE_LO] = trace[COL_MUL_WIDE_LO] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_wide_product() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 7;
	b[0] = 11;
	let row = build_field_mul_trace_row(&a, &b);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Corrupt wide[0] (the actual product): schoolbook column 0 will
	// not balance because col_sum[0] = a_lo[0] * b_lo[0] = 7*11 = 77,
	// but wide_u16[0] is now wrong.
	trace[COL_MUL_WIDE] = trace[COL_MUL_WIDE] + Goldilocks::ONE;
	// Also corrupt the corresponding low half so the limb-split constraint
	// passes — to isolate the schoolbook-column failure rather than the
	// limb-split failure.
	trace[COL_MUL_WIDE_LO] = trace[COL_MUL_WIDE_LO] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_carry_chain() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0xFFFF_FFFF;
	b[0] = 0xFFFF_FFFF;
	let row = build_field_mul_trace_row(&a, &b);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip carry[3]: the column-4 balance breaks because carry_in[4]
	// (= carry[3]) is wrong.
	trace[COL_MUL_CARRY + 3] = trace[COL_MUL_CARRY + 3] + Goldilocks::ONE;
	// Also fix the carry limb-split so we isolate the schoolbook failure.
	trace[COL_MUL_CARRY_LO + 3] = trace[COL_MUL_CARRY_LO + 3] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_nonzero_top_carry() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Set carry[31] = 1: top-balance closure constraint fails.
	trace[COL_MUL_CARRY + (NUM_COLS_SCHOOLBOOK - 1)] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_rejects_corrupted_carry_lo_split() {
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 0xFFFF_FFFF;
	b[0] = 0xFFFF_FFFF;
	let row = build_field_mul_trace_row(&a, &b);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_MUL_CARRY_LO] = trace[COL_MUL_CARRY_LO] + Goldilocks::ONE;
	run_eval(&trace);
}

// ─── Layout + bus-name pin ──────────────────────────────────────────────────

#[test]
fn column_layout_constants_are_stable() {
	// M1 block.
	assert_eq!(COL_MUL_A, 0);
	assert_eq!(COL_MUL_B, 8);
	assert_eq!(COL_MUL_A_LO, 16);
	assert_eq!(COL_MUL_A_HI, 24);
	assert_eq!(COL_MUL_B_LO, 32);
	assert_eq!(COL_MUL_B_HI, 40);
	assert_eq!(COL_MUL_WIDE, 48);
	assert_eq!(COL_MUL_WIDE_LO, 64);
	assert_eq!(COL_MUL_WIDE_HI, 80);
	assert_eq!(COL_MUL_CARRY, 96);
	assert_eq!(COL_MUL_CARRY_LO, 128);
	assert_eq!(COL_MUL_CARRY_HI, 160);
	assert_eq!(FIELD_MUL_M1_NUM_COLS, 192);
	// M2 block.
	assert_eq!(COL_MUL_Q, 192);
	assert_eq!(COL_MUL_Q_LO, 200);
	assert_eq!(COL_MUL_Q_HI, 208);
	assert_eq!(COL_MUL_QP_WIDE, 216);
	assert_eq!(COL_MUL_QP_WIDE_LO, 232);
	assert_eq!(COL_MUL_QP_WIDE_HI, 248);
	assert_eq!(COL_MUL_QP_CARRY, 264);
	assert_eq!(COL_MUL_QP_CARRY_LO, 296);
	assert_eq!(COL_MUL_QP_CARRY_HI, 328);
	assert_eq!(COL_MUL_C, 360);
	assert_eq!(COL_MUL_C_LO, 368);
	assert_eq!(COL_MUL_C_HI, 376);
	assert_eq!(COL_MUL_C_COMP, 384);
	assert_eq!(COL_MUL_C_COMP_BORROW, 392);
	assert_eq!(COL_MUL_C_COMP_LO, 400);
	assert_eq!(COL_MUL_C_COMP_HI, 408);
	assert_eq!(COL_MUL_QP_BORROW, 416);
	assert_eq!(FIELD_MUL_NUM_COLS, 432);
}

#[test]
fn mul_uses_same_u16_range_bus_as_add_sub() {
	// All field-arithmetic AIRs share the global u16 range-check bus.
	assert_eq!(BUS_U16_RANGE, "rostro-u16-range");
}

/// Recording builder for verifying bus interactions. Captures bus
/// name, multiplicity, payload arity, and weight per push so callers
/// can assert the full shape of every emit.
struct RecordingBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	pushed: Vec<(alloc::string::String, Goldilocks, usize, u32)>,
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
		let collected: Vec<Goldilocks> = fields.into_iter().map(Into::into).collect();
		self.pushed.push((
			alloc::string::String::from(bus_name),
			multiplicity,
			collected.len(),
			count_weight,
		));
	}
	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

// ─── M2 acceptance + rejection tests ───────────────────────────────────────

#[test]
fn air_m2_accepts_canonical_c_for_random_inputs() {
	// For each random (a, b), the witness builder produces c = (a*b) mod p
	// and the AIR's M2 constraints accept it. Cross-check c against the
	// field::mul oracle.
	use crate::field::mul;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xb0bb_a1ec_4242_1337);
	for _ in 0..30 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let row = build_field_mul_trace_row(&a, &b);
		assert_eq!(row.c, mul(&a, &b), "witness c diverges from field::mul oracle");
		run_eval(&row.to_trace_vec::<Goldilocks>());
	}
}

#[test]
fn air_m2_accepts_p_minus_one_squared_reduced() {
	// (p-1)^2 mod p = 1. Verify the AIR accepts the canonical reduction.
	let row = build_field_mul_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	assert_eq!(row.c, one, "(p-1)^2 mod p should equal 1");
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
fn air_m2_accepts_zero_q_for_small_product() {
	// For a small product (< p), q should be 0 and c == wide_product[0..8].
	let mut a = [0u32; FIELD_NUM_LIMBS];
	let mut b = [0u32; FIELD_NUM_LIMBS];
	a[0] = 7;
	b[0] = 11;
	let row = build_field_mul_trace_row(&a, &b);
	assert_eq!(row.q, [0u32; FIELD_NUM_LIMBS]);
	assert_eq!(row.c[0], 77);
	for i in 1..FIELD_NUM_LIMBS {
		assert_eq!(row.c[i], 0);
	}
	run_eval(&row.to_trace_vec::<Goldilocks>());
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_corrupted_q() {
	let row = build_field_mul_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip q[0]: q*p schoolbook (and downstream wide subtraction) breaks.
	trace[COL_MUL_Q] = trace[COL_MUL_Q] + Goldilocks::ONE;
	trace[COL_MUL_Q_LO] = trace[COL_MUL_Q_LO] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_corrupted_qp_wide() {
	let row = build_field_mul_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_MUL_QP_WIDE] = trace[COL_MUL_QP_WIDE] + Goldilocks::ONE;
	trace[COL_MUL_QP_WIDE_LO] = trace[COL_MUL_QP_WIDE_LO] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_corrupted_qp_carry_chain() {
	let row = build_field_mul_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_MUL_QP_CARRY + 3] = trace[COL_MUL_QP_CARRY + 3] + Goldilocks::ONE;
	trace[COL_MUL_QP_CARRY_LO + 3] = trace[COL_MUL_QP_CARRY_LO + 3] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_nonzero_top_qp_carry() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_MUL_QP_CARRY + (NUM_COLS_SCHOOLBOOK - 1)] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_corrupted_c() {
	let row = build_field_mul_trace_row(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Flip c[0]: wide subtraction at limb 0 breaks.
	trace[COL_MUL_C] = trace[COL_MUL_C] + Goldilocks::ONE;
	trace[COL_MUL_C_LO] = trace[COL_MUL_C_LO] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_corrupted_c_complement() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_MUL_C_COMP] = trace[COL_MUL_C_COMP] + Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_nonzero_top_complement_borrow() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	trace[COL_MUL_C_COMP_BORROW + (FIELD_NUM_LIMBS - 1)] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_non_boolean_qp_borrow() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Set qp_borrow[0] = 2: boolean check fails.
	trace[COL_MUL_QP_BORROW] = Goldilocks::from_u32(2);
	run_eval(&trace);
}

#[test]
#[should_panic(expected = "constraint")]
fn air_m2_rejects_nonzero_top_qp_borrow() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	let mut trace = row.to_trace_vec::<Goldilocks>();
	// Set qp_borrow[15] = 1: top-borrow closure fails.
	trace[COL_MUL_QP_BORROW + (WIDE_NUM_LIMBS - 1)] = Goldilocks::ONE;
	run_eval(&trace);
}

#[test]
fn air_emits_272_range_lookups_plus_one_service_emit_per_multiply() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let row = build_field_mul_trace_row(&zero, &zero);
	let trace = row.to_trace_vec::<Goldilocks>();
	let pp: Vec<Goldilocks> = Vec::new();
	let pp_next: Vec<Goldilocks> = Vec::new();
	let mut builder = RecordingBuilder {
		main_window: RowWindow::from_two_rows(&trace, &trace),
		preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
		pushed: Vec::new(),
	};
	let air = FieldMulAir::new();
	<FieldMulAir as Air<RecordingBuilder>>::eval(&air, &mut builder);
	// Expected:
	//   M1: 16 (a halves) + 16 (b halves) + 32 (wide halves) + 64 (carry) = 128
	//   M3: 16 (q) + 32 (qp_wide) + 64 (qp_carry) + 16 (c) + 16 (c_comp) = 144
	//   Service-bus emit: 1 push on BUS_FIELD_MUL
	//   Total: 273
	assert_eq!(builder.pushed.len(), 273);

	// First 272 are u16 range queries on BUS_U16_RANGE, count = +1, arity = 1.
	for (bus, mult, arity, weight) in &builder.pushed[..272] {
		assert_eq!(bus, BUS_U16_RANGE, "first 272 should be on the u16 range bus");
		assert_eq!(*mult, Goldilocks::ONE);
		assert_eq!(*arity, 1);
		assert_eq!(*weight, 1);
	}

	// Last is the service-bus emit on BUS_FIELD_MUL, count = -1, arity = 24.
	let (bus, mult, arity, weight) = &builder.pushed[272];
	assert_eq!(
		bus,
		crate::field_mul_air::BUS_FIELD_MUL,
		"service-bus emit on rostro-field-mul",
	);
	assert_eq!(*mult, Goldilocks::ZERO - Goldilocks::ONE, "provider count = -1");
	assert_eq!(*arity, 24, "service payload = a (8) + b (8) + c (8) = 24 cells");
	assert_eq!(*weight, 1);
}

#[test]
fn mul_service_bus_name_is_pinned() {
	// Service-bus pin: PointAddAir / PointDoubleAir must push on this
	// exact name to be answered by FieldMulAir.
	assert_eq!(crate::field_mul_air::BUS_FIELD_MUL, "rostro-field-mul");
}
