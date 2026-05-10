// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for modular addition over Curve25519's base field
//! (`F_p` with `p = 2^255 - 19`), represented as 8 × u32 limbs per the
//! locked Goldilocks packing convention.
//!
//! ## What this AIR proves
//!
//! Given witnesses `a, b, c, t, carry[0..8]`, the AIR enforces
//! `a + b == c + t * p` as integers, via a limb-wise carry chain
//! with signed carries ∈ {-1, 0, 1}.
//!
//! ## Constraint set (commit 1 of 3)
//!
//! - **Balance per limb (8 deg-2):**
//!   ```text
//!   a[i] + b[i] - c[i] - t * p[i] + carry_in[i] == carry[i] * 2^32
//!   ```
//!   where `carry_in[0] = 0`, `carry_in[i] = carry[i-1]` for i > 0.
//! - **Top-balance closure (1 deg-1):**
//!   ```text
//!   carry[7] == 0
//!   ```
//!   (no overflow beyond limb 7; this forces the equation to actually
//!   balance modulo p).
//! - **Signed-carry tertiary check (7 deg-3):**
//!   ```text
//!   carry[i] * (carry[i] - 1) * (carry[i] + 1) == 0
//!   ```
//!   for `i ∈ {0..6}` (carry[7] already pinned by top-balance, so its
//!   tertiary check is redundant).
//! - **`t` boolean (1 deg-2):** `t * (1 - t) == 0`.
//!
//! ## Soundness gaps in this commit (closed in subsequent commits)
//!
//! 1. **No canonical-form check on `c`.** A malicious prover could
//!    submit `c == c' + p` (non-canonical) by setting `t = 0` when
//!    `t = 1` was correct. The balance equation still holds, but the
//!    "output is in canonical form" property is not enforced. Closing
//!    commit lands the `c < p` constraint via a `c_complement` borrow
//!    chain (~16 witness cols + 8 constraints).
//! 2. **No u32 range-check on trace cells.** Each of `a[i]`, `b[i]`,
//!    `c[i]` is treated as a Goldilocks field element by the AIR, which
//!    allows values up to `p_G ≈ 2^64`. A malicious prover could
//!    smuggle `c[i]` values ≥ `2^32`, breaking the limb-decomposition
//!    invariant. Closing commit pushes `lookup_key` interactions into
//!    the `rostro-range-check` bus (32 interactions per add: 8 limbs × 2
//!    u16 halves × 2 sides where each value gets split into low/high
//!    halves).
//!
//! Until both close, **THIS AIR MUST NOT BE USED IN PRODUCTION** —
//! the field-add primitive is structurally correct but not
//! soundness-complete. Tests in this commit use a helper that generates
//! canonical witnesses; corrupted-witness tests work because the
//! balance/carry constraints alone catch the corruptions the tests
//! exercise. Production tests will be re-run after commits 2-3 to
//! confirm the closed soundness gaps reject the corresponding attacks.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::{FIELD_NUM_LIMBS, P_LIMBS};

/// Column index of `a[0]` (8 limbs).
pub const COL_ADD_A: usize = 0;
/// Column index of `b[0]` (8 limbs).
pub const COL_ADD_B: usize = COL_ADD_A + FIELD_NUM_LIMBS;
/// Column index of `c[0]` (8 limbs).
pub const COL_ADD_C: usize = COL_ADD_B + FIELD_NUM_LIMBS;
/// Column index of `t` (1 limb, boolean).
pub const COL_ADD_T: usize = COL_ADD_C + FIELD_NUM_LIMBS;
/// Column index of `carry[0]` (8 signed limbs each ∈ {-1, 0, 1}, with
/// `carry[7] = 0` constrained by top-balance).
pub const COL_ADD_CARRY: usize = COL_ADD_T + 1;
/// Total trace columns for the field-add AIR (33 = 8 + 8 + 8 + 1 + 8).
pub const FIELD_ADD_NUM_COLS: usize = COL_ADD_CARRY + FIELD_NUM_LIMBS;

/// `2^32` as a Goldilocks-fitting constant. Fits in u64 (= 4_294_967_296)
/// and well below `p_G = 2^64 - 2^32 + 1`. Used as the per-limb radix in
/// the balance equation.
pub const RADIX_LIMB: u64 = 1u64 << 32;

/// Plonky3 AIR for one field-addition operation over `F_p`.
///
/// Single-row AIR: all witnesses live on row 0; no transition
/// constraints. Each "field add" in a larger AIR (e.g. point ops,
/// scalar mul) instantiates one copy of this AIR on shared bus(es)
/// when range-check / canonical-form sub-AIRs are added.
#[derive(Clone, Debug, Default)]
pub struct FieldAddAir;

impl FieldAddAir {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for FieldAddAir {
	fn width(&self) -> usize {
		FIELD_ADD_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for FieldAddAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		// Extract witnesses.
		let a: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_A + i]);
		let b: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_B + i]);
		let c: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_C + i]);
		let t: AB::Var = local[COL_ADD_T];
		let carry: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_CARRY + i]);

		// `t` is boolean.
		builder.assert_bool(t);

		// Per-limb balance:
		//   a[i] + b[i] - c[i] - t * p[i] + carry_in[i] - carry[i] * 2^32 == 0
		// carry_in[0] = 0; carry_in[i] = carry[i-1] otherwise.
		let radix = AB::Expr::from_u64(RADIX_LIMB);
		for i in 0..FIELD_NUM_LIMBS {
			let p_limb = AB::Expr::from_u32(P_LIMBS[i]);
			let carry_in: AB::Expr = if i == 0 {
				AB::Expr::ZERO
			} else {
				carry[i - 1].into()
			};
			// balance_i := a[i] + b[i] - c[i] - t * p[i] + carry_in - carry[i] * radix
			let balance: AB::Expr = a[i].into()
				+ b[i].into()
				- c[i].into()
				- t.into() * p_limb
				+ carry_in
				- carry[i].into() * radix.clone();
			builder.assert_zero(balance);
		}

		// Top-balance closure: carry[7] = 0 (no overflow beyond limb 7).
		// This is what forces the equation to balance modulo p — without
		// it, the prover could absorb mismatches into a fictitious top
		// carry. With it, the entire integer equation `a + b == c + t*p`
		// holds.
		builder.assert_zero(carry[FIELD_NUM_LIMBS - 1]);

		// Signed-carry tertiary check: each carry[i] for i ∈ {0..6}
		// must be in {-1, 0, 1}. Encoded as the cubic constraint
		//   carry * (carry - 1) * (carry + 1) == 0
		// which factors to `carry * (carry^2 - 1) == 0`. Degree 3.
		//
		// carry[7] is already pinned to 0 by the top-balance closure
		// above; its tertiary check is redundant and skipped.
		for i in 0..(FIELD_NUM_LIMBS - 1) {
			let c_var: AB::Expr = carry[i].into();
			let c_minus_one: AB::Expr = c_var.clone() - AB::Expr::ONE;
			let c_plus_one: AB::Expr = c_var.clone() + AB::Expr::ONE;
			builder.assert_zero(c_var * c_minus_one * c_plus_one);
		}

		// TODO(curve25519-air, commit 2): canonical-form check on c.
		// Witness c_complement[0..8] = p_minus_one - c, plus borrow
		// chain; constrain no top borrow → c <= p-1.
		//
		// TODO(curve25519-air, commit 3): u32 range-check lookups on
		// every prover-controlled limb (a, b, c). Split each u32 into
		// two u16 halves; lookup each half via `rostro-range-check`
		// bus. Closes the "smuggle Goldilocks values > 2^32 into
		// limb cells" attack surface.
	}
}

// ─── Witness-side trace builder ────────────────────────────────────────────
//
// Pure-Rust trace generator: given canonical inputs `a, b`, computes
// `c = (a + b) mod p` plus the witnessed `t` and `carry` chain values
// the AIR expects. Used by tests to feed honest witnesses into the
// recording builder.

/// Build a single-row trace for [`FieldAddAir`] from canonical inputs.
///
/// Output layout matches the column constants above. Returns the trace
/// row as a flat `Vec<u32>` of length [`FIELD_ADD_NUM_COLS`].
///
/// Each carry value is encoded as the natural integer ∈ {-1, 0, 1};
/// the caller converts to Goldilocks via `Goldilocks::from_i64` (or
/// `from_u32` for non-negative).
pub fn build_field_add_trace_row(
	a: &[u32; FIELD_NUM_LIMBS],
	b: &[u32; FIELD_NUM_LIMBS],
) -> FieldAddTraceRow {
	use crate::field::{add, cmp};

	let c = add(a, b);

	// Determine t: did the conditional subtraction of p happen?
	// Equivalent: is c + p == a + b? If yes, t = 1; else t = 0.
	//
	// Cheaper: compute raw sum, check whether it >= p.
	let mut raw_sum_low = [0u32; FIELD_NUM_LIMBS];
	let mut raw_carry: u64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let s = u64::from(a[i]) + u64::from(b[i]) + raw_carry;
		raw_sum_low[i] = s as u32;
		raw_carry = s >> 32;
	}
	let raw_above_p = raw_carry != 0
		|| cmp(&raw_sum_low, &P_LIMBS) != core::cmp::Ordering::Less;
	let t: u32 = if raw_above_p { 1 } else { 0 };

	// Compute the carry chain from the balance equation:
	//   carry[i] = (a[i] + b[i] - c[i] - t*p[i] + carry[i-1]) / 2^32
	// Performed as signed i64 arithmetic; the result should land in {-1, 0, 1}.
	let mut carry = [0i64; FIELD_NUM_LIMBS];
	let mut carry_in: i64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let numerator: i64 = i64::from(a[i])
			+ i64::from(b[i])
			- i64::from(c[i])
			- i64::from(t) * i64::from(P_LIMBS[i])
			+ carry_in;
		assert_eq!(
			numerator.rem_euclid(1i64 << 32),
			0,
			"build_field_add_trace_row: balance equation not divisible by 2^32 at limb {}",
			i,
		);
		let carry_out = numerator / (1i64 << 32);
		assert!(
			carry_out.abs() <= 1,
			"build_field_add_trace_row: carry out of range at limb {} (={})",
			i,
			carry_out,
		);
		carry[i] = carry_out;
		carry_in = carry_out;
	}
	assert_eq!(carry[FIELD_NUM_LIMBS - 1], 0, "top-balance closure violated");

	FieldAddTraceRow { a: *a, b: *b, c, t, carry }
}

/// Trace row produced by [`build_field_add_trace_row`]. Holds the
/// signed carry chain as `i64` (the AIR converts to Goldilocks).
#[derive(Clone, Debug)]
pub struct FieldAddTraceRow {
	pub a: [u32; FIELD_NUM_LIMBS],
	pub b: [u32; FIELD_NUM_LIMBS],
	pub c: [u32; FIELD_NUM_LIMBS],
	pub t: u32,
	pub carry: [i64; FIELD_NUM_LIMBS],
}

impl FieldAddTraceRow {
	/// Flatten the row into a flat `Vec<F>` of length
	/// [`FIELD_ADD_NUM_COLS`], encoding signed carries as
	/// Goldilocks-modular values (where -1 = p_G - 1).
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(FIELD_ADD_NUM_COLS);
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
				// -1 encoded as p_G - 1 = ZERO - ONE.
				out.push(F::ZERO - F::ONE);
			}
		}
		debug_assert_eq!(out.len(), FIELD_ADD_NUM_COLS);
		out
	}

	/// Wrap the flat trace vector as a [`RowMajorMatrix`] of the proper
	/// width, suitable for feeding into a prover or recording builder.
	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), FIELD_ADD_NUM_COLS)
	}
}
