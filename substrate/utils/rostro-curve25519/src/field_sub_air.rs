// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for modular subtraction over Curve25519's base field
//! (`F_p` with `p = 2^255 - 19`).
//!
//! Mirrors [`crate::field_air::FieldAddAir`] in structure. Soundness-
//! complete (commits 1-3 of add merged into this single file). Per
//! the silo principle (`feedback_no_cross_purpose_files.md`), this is
//! a separate AIR with no shared helpers — a bug in
//! `FieldAddAir::eval` cannot influence `FieldSubAir::eval` because
//! they share no code beyond the field-element module's constants.
//!
//! ## What this AIR proves
//!
//! Given witnesses `a, b, c, t, carry, c_complement, c_complement_borrow`,
//! and the u16-half splits for range checking, the AIR enforces
//! `a + t * p == c + b` (as integers, limb-wise with carry chain),
//! `c <= p - 1` (canonical), and `c[i], c_complement[i] < 2^32`
//! (range-checked via `BUS_U16_RANGE`).
//!
//! When honest, `t = 1` iff `a < b` (subtraction underflowed mod p)
//! and `c = (a - b) mod p`. When `t = 0`, `c = a - b` directly.
//!
//! ## Bus
//!
//! Range-check lookups go on [`crate::field_air::BUS_U16_RANGE`] (the
//! shared u16 table bus). Production batches instantiate exactly one
//! [`rostro_range_check::U16RangeTableAir`] on this bus to serve all
//! consumer AIRs.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::{FIELD_NUM_LIMBS, P_LIMBS, P_MINUS_ONE_LIMBS};
use crate::field_air::{BUS_U16_RANGE, RADIX_LIMB, RADIX_U16};

/// Service-bus name for FieldSubAir. Each FieldSubAir invocation
/// emits its `(a[0..8], b[0..8], c[0..8])` tuple on this bus with
/// count = -1; consumers (PointAddAir, etc.) emit the same shape
/// with count = +1 to query "compute c = (a - b) mod p". LogUp
/// balances: every consumer query is answered by exactly one
/// FieldSubAir instance in the batch.
pub const BUS_FIELD_SUB: &str = "rostro-field-sub";

/// Column index of `a[0]` (8 limbs, input — caller's responsibility to range-check).
pub const COL_SUB_A: usize = 0;
/// Column index of `b[0]` (8 limbs, input).
pub const COL_SUB_B: usize = COL_SUB_A + FIELD_NUM_LIMBS;
/// Column index of `c[0]` (8 limbs, output = a - b mod p).
pub const COL_SUB_C: usize = COL_SUB_B + FIELD_NUM_LIMBS;
/// Column index of `t` (1 limb, boolean: was a < b before reduction?).
pub const COL_SUB_T: usize = COL_SUB_C + FIELD_NUM_LIMBS;
/// Column index of `carry[0]` (8 signed limbs, `carry[7] = 0` pinned).
pub const COL_SUB_CARRY: usize = COL_SUB_T + 1;
/// Column index of `c_complement[0]` (8 limbs of `p - 1 - c`).
pub const COL_SUB_C_COMP: usize = COL_SUB_CARRY + FIELD_NUM_LIMBS;
/// Column index of `c_complement_borrow[0]` (8 booleans, `borrow[7] = 0`).
pub const COL_SUB_C_COMP_BORROW: usize = COL_SUB_C_COMP + FIELD_NUM_LIMBS;
/// Column index of `c_lo[0]` — low u16 of `c[i]`.
pub const COL_SUB_C_LO: usize = COL_SUB_C_COMP_BORROW + FIELD_NUM_LIMBS;
/// Column index of `c_hi[0]` — high u16 of `c[i]`.
pub const COL_SUB_C_HI: usize = COL_SUB_C_LO + FIELD_NUM_LIMBS;
/// Column index of `c_comp_lo[0]` — low u16 of `c_complement[i]`.
pub const COL_SUB_C_COMP_LO: usize = COL_SUB_C_HI + FIELD_NUM_LIMBS;
/// Column index of `c_comp_hi[0]` — high u16 of `c_complement[i]`.
pub const COL_SUB_C_COMP_HI: usize = COL_SUB_C_COMP_LO + FIELD_NUM_LIMBS;
/// Total trace columns for the field-sub AIR (81 = same shape as add).
pub const FIELD_SUB_NUM_COLS: usize = COL_SUB_C_COMP_HI + FIELD_NUM_LIMBS;

/// Plonky3 AIR for one field-subtraction operation over `F_p`.
#[derive(Clone, Debug, Default)]
pub struct FieldSubAir;

impl FieldSubAir {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for FieldSubAir {
	fn width(&self) -> usize {
		FIELD_SUB_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for FieldSubAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let a: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_A + i]);
		let b: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_B + i]);
		let c: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_C + i]);
		let t: AB::Var = local[COL_SUB_T];
		let carry: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_CARRY + i]);
		let c_complement: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_C_COMP + i]);
		let c_complement_borrow: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_C_COMP_BORROW + i]);
		let c_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_C_LO + i]);
		let c_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_C_HI + i]);
		let c_comp_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_C_COMP_LO + i]);
		let c_comp_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_SUB_C_COMP_HI + i]);

		// `t` boolean.
		builder.assert_bool(t);

		// Per-limb balance: a + t*p == c + b.
		//   a[i] + t * p[i] + carry_in[i] - c[i] - b[i] == carry[i] * 2^32
		let radix = AB::Expr::from_u64(RADIX_LIMB);
		for i in 0..FIELD_NUM_LIMBS {
			let p_limb = AB::Expr::from_u32(P_LIMBS[i]);
			let carry_in: AB::Expr = if i == 0 {
				AB::Expr::ZERO
			} else {
				carry[i - 1].into()
			};
			// balance := a[i] + t * p[i] + carry_in - c[i] - b[i] - carry[i] * 2^32
			let balance: AB::Expr = a[i].into()
				+ t.into() * p_limb
				+ carry_in
				- c[i].into()
				- b[i].into()
				- carry[i].into() * radix.clone();
			builder.assert_zero(balance);
		}

		// Top-balance closure: carry[7] = 0.
		builder.assert_zero(carry[FIELD_NUM_LIMBS - 1]);

		// Signed-carry tertiary check ∈ {-1, 0, 1} for i ∈ {0..6}.
		for i in 0..(FIELD_NUM_LIMBS - 1) {
			let c_var: AB::Expr = carry[i].into();
			let c_minus_one: AB::Expr = c_var.clone() - AB::Expr::ONE;
			let c_plus_one: AB::Expr = c_var.clone() + AB::Expr::ONE;
			builder.assert_zero(c_var * c_minus_one * c_plus_one);
		}

		// Canonical-form check on c (same shape as add).
		for i in 0..FIELD_NUM_LIMBS {
			let p_minus_one_limb = AB::Expr::from_u32(P_MINUS_ONE_LIMBS[i]);
			let borrow_in: AB::Expr = if i == 0 {
				AB::Expr::ZERO
			} else {
				c_complement_borrow[i - 1].into()
			};
			let canonical_balance: AB::Expr = p_minus_one_limb
				- c[i].into()
				- borrow_in
				+ c_complement_borrow[i].into() * radix.clone()
				- c_complement[i].into();
			builder.assert_zero(canonical_balance);
		}
		for i in 0..(FIELD_NUM_LIMBS - 1) {
			builder.assert_bool(c_complement_borrow[i]);
		}
		builder.assert_zero(c_complement_borrow[FIELD_NUM_LIMBS - 1]);

		// u16 range-check via limb split. Range-check c and c_complement
		// only; a and b are caller's responsibility.
		let radix_u16 = AB::Expr::from_u32(RADIX_U16);
		for i in 0..FIELD_NUM_LIMBS {
			let c_split: AB::Expr =
				c_lo[i].into() + c_hi[i].into() * radix_u16.clone() - c[i].into();
			builder.assert_zero(c_split);

			let cc_split: AB::Expr = c_comp_lo[i].into()
				+ c_comp_hi[i].into() * radix_u16.clone()
				- c_complement[i].into();
			builder.assert_zero(cc_split);

			builder.push_interaction(BUS_U16_RANGE, [c_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_hi[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_comp_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_comp_hi[i]], AB::Expr::ONE, 1);
		}

		// ─── Service-bus emit (P2 of Edwards25519 point-ops plan) ─────
		//
		// Expose this AIR's (a, b, c) tuple on BUS_FIELD_SUB with
		// count = -1 (provider side). Consumer AIRs push the same
		// shape with count = +1 to query "verify c = (a - b) mod p".
		let service_payload: alloc::vec::Vec<AB::Var> =
			a.iter().chain(b.iter()).chain(c.iter()).copied().collect();
		builder.push_interaction(
			BUS_FIELD_SUB,
			service_payload,
			AB::Expr::ZERO - AB::Expr::ONE,
			1,
		);
	}
}

// ─── Witness-side trace builder ────────────────────────────────────────────

/// Trace row produced by [`build_field_sub_trace_row`]. Shape mirrors
/// `FieldAddTraceRow` for ergonomic consistency.
#[derive(Clone, Debug)]
pub struct FieldSubTraceRow {
	pub a: [u32; FIELD_NUM_LIMBS],
	pub b: [u32; FIELD_NUM_LIMBS],
	pub c: [u32; FIELD_NUM_LIMBS],
	pub t: u32,
	pub carry: [i64; FIELD_NUM_LIMBS],
	pub c_complement: [u32; FIELD_NUM_LIMBS],
	pub c_complement_borrow: [u8; FIELD_NUM_LIMBS],
	pub c_lo: [u16; FIELD_NUM_LIMBS],
	pub c_hi: [u16; FIELD_NUM_LIMBS],
	pub c_comp_lo: [u16; FIELD_NUM_LIMBS],
	pub c_comp_hi: [u16; FIELD_NUM_LIMBS],
}

/// Build a single-row trace for [`FieldSubAir`] from canonical inputs.
pub fn build_field_sub_trace_row(
	a: &[u32; FIELD_NUM_LIMBS],
	b: &[u32; FIELD_NUM_LIMBS],
) -> FieldSubTraceRow {
	use crate::field::{cmp, sub};

	let c = sub(a, b);

	// t = 1 iff a < b (subtraction needed to add p to wrap).
	let t: u32 = if cmp(a, b) == core::cmp::Ordering::Less {
		1
	} else {
		0
	};

	// Carry chain: from balance equation a + t*p - c - b + carry_in == carry * 2^32.
	let mut carry = [0i64; FIELD_NUM_LIMBS];
	let mut carry_in: i64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let numerator: i64 = i64::from(a[i])
			+ i64::from(t) * i64::from(P_LIMBS[i])
			+ carry_in
			- i64::from(c[i])
			- i64::from(b[i]);
		assert_eq!(
			numerator.rem_euclid(1i64 << 32),
			0,
			"build_field_sub_trace_row: balance not divisible by 2^32 at limb {}",
			i,
		);
		let carry_out = numerator / (1i64 << 32);
		assert!(
			carry_out.abs() <= 1,
			"build_field_sub_trace_row: carry out of range at limb {} (={})",
			i,
			carry_out,
		);
		carry[i] = carry_out;
		carry_in = carry_out;
	}
	assert_eq!(carry[FIELD_NUM_LIMBS - 1], 0, "top-balance closure violated");

	// Canonical-form witness (same construction as add).
	let mut c_complement = [0u32; FIELD_NUM_LIMBS];
	let mut c_complement_borrow = [0u8; FIELD_NUM_LIMBS];
	let mut borrow: i64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let d: i64 = i64::from(P_MINUS_ONE_LIMBS[i]) - i64::from(c[i]) - borrow;
		if d < 0 {
			c_complement[i] = (d + (1i64 << 32)) as u32;
			c_complement_borrow[i] = 1;
			borrow = 1;
		} else {
			c_complement[i] = d as u32;
			c_complement_borrow[i] = 0;
			borrow = 0;
		}
	}
	assert_eq!(c_complement_borrow[FIELD_NUM_LIMBS - 1], 0);

	// u16 splits.
	let mut c_lo = [0u16; FIELD_NUM_LIMBS];
	let mut c_hi = [0u16; FIELD_NUM_LIMBS];
	let mut c_comp_lo = [0u16; FIELD_NUM_LIMBS];
	let mut c_comp_hi = [0u16; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		c_lo[i] = (c[i] & 0xFFFF) as u16;
		c_hi[i] = (c[i] >> 16) as u16;
		c_comp_lo[i] = (c_complement[i] & 0xFFFF) as u16;
		c_comp_hi[i] = (c_complement[i] >> 16) as u16;
	}

	FieldSubTraceRow {
		a: *a,
		b: *b,
		c,
		t,
		carry,
		c_complement,
		c_complement_borrow,
		c_lo,
		c_hi,
		c_comp_lo,
		c_comp_hi,
	}
}

impl FieldSubTraceRow {
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(FIELD_SUB_NUM_COLS);
		for &v in &self.a {
			out.push(F::from_u32(v));
		}
		for &v in &self.b {
			out.push(F::from_u32(v));
		}
		for &v in &self.c {
			out.push(F::from_u32(v));
		}
		out.push(F::from_u32(self.t));
		for &v in &self.carry {
			if v >= 0 {
				out.push(F::from_u64(v as u64));
			} else {
				out.push(F::ZERO - F::ONE);
			}
		}
		for &v in &self.c_complement {
			out.push(F::from_u32(v));
		}
		for &v in &self.c_complement_borrow {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c_comp_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c_comp_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		debug_assert_eq!(out.len(), FIELD_SUB_NUM_COLS);
		out
	}

	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), FIELD_SUB_NUM_COLS)
	}
}
