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
//! ## Constraint set (commits 1-2 of 3)
//!
//! - **`t` boolean (1 deg-2):** `t * (1 - t) == 0`.
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
//! - **Canonical-form balance per limb (8 deg-2):**
//!   ```text
//!   p_minus_one[i] - c[i] - borrow_in[i] + borrow[i] * 2^32 == c_complement[i]
//!   ```
//!   where borrow chain is the per-limb borrow witness array
//!   `c_complement_borrow[0..8]`.
//! - **Complement-borrow boolean (7 deg-2):**
//!   `c_complement_borrow[i] * (1 - c_complement_borrow[i]) == 0` for
//!   `i ∈ {0..6}`. borrow[7] is pinned by top-borrow closure below.
//! - **Top-borrow closure (1 deg-1):**
//!   `c_complement_borrow[7] == 0`. This is what actually enforces
//!   `c <= p - 1` — if c > p - 1, the subtraction would underflow,
//!   requiring a borrow at the top, which this constraint forbids.
//!
//! - **u16 range-check via limb split** (commit 3 of 3): each prover-
//!   controlled u32 limb (`c[i]`, `c_complement[i]`) is split into two
//!   u16 halves via the constraint `limb == lo + hi * 2^16`. Each half
//!   is then looked up against the shared [`BUS_U16_RANGE`] table bus.
//!   Input columns `a` and `b` are NOT range-checked here — their range
//!   correctness is the caller's responsibility (the AIR that produced
//!   them). 32 lookup pushes per add (8 limbs × 4 halves: c_lo, c_hi,
//!   c_comp_lo, c_comp_hi).
//!
//! ## Production readiness
//!
//! All three soundness gaps from commit 1 are now closed. The AIR is
//! soundness-complete for the field-addition operation **assuming** the
//! caller produces canonical, range-correct `a` and `b` inputs (or
//! routes them through their own range-check sub-AIRs). In production
//! batches, instantiate ONE [`rostro_range_check::U16RangeTableAir`]
//! on [`BUS_U16_RANGE`] to provide the table side of the lookup; LogUp
//! balances the bus across all consumer AIRs in the batch.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::field::{FIELD_NUM_LIMBS, P_LIMBS, P_MINUS_ONE_LIMBS};

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
/// Column index of `c_complement[0]` (8 limbs of `p - 1 - c`). Used by
/// the canonical-form check (commit 2 of 3).
pub const COL_ADD_C_COMP: usize = COL_ADD_CARRY + FIELD_NUM_LIMBS;
/// Column index of `complement_borrow[0]` (8 booleans, with
/// `complement_borrow[7] = 0` pinned by top-borrow closure). Limb-wise
/// borrow chain of the subtraction `p - 1 - c`.
pub const COL_ADD_C_COMP_BORROW: usize = COL_ADD_C_COMP + FIELD_NUM_LIMBS;
/// Column index of `c_lo[0]` — low u16 half of each `c[i]` (8 cells,
/// each ∈ [0, 2^16)). Range-checked via `BUS_U16_RANGE`.
pub const COL_ADD_C_LO: usize = COL_ADD_C_COMP_BORROW + FIELD_NUM_LIMBS;
/// Column index of `c_hi[0]` — high u16 half of each `c[i]` (8 cells).
pub const COL_ADD_C_HI: usize = COL_ADD_C_LO + FIELD_NUM_LIMBS;
/// Column index of `c_comp_lo[0]` — low u16 half of each `c_complement[i]`.
pub const COL_ADD_C_COMP_LO: usize = COL_ADD_C_HI + FIELD_NUM_LIMBS;
/// Column index of `c_comp_hi[0]` — high u16 half of each `c_complement[i]`.
pub const COL_ADD_C_COMP_HI: usize = COL_ADD_C_COMP_LO + FIELD_NUM_LIMBS;
/// Total trace columns for the field-add AIR
/// (81 = 8 + 8 + 8 + 1 + 8 + 8 + 8 + 8 + 8 + 8 + 8).
pub const FIELD_ADD_NUM_COLS: usize = COL_ADD_C_COMP_HI + FIELD_NUM_LIMBS;

/// Bus name for the shared u16 range-check table. Caller AIRs send
/// `lookup_key(BUS_U16_RANGE, [value], 1)` for each u16 value they
/// want range-proven; the `rostro-range-check::U16RangeTableAir`
/// instance in the same batch provides the table entries on this bus.
///
/// Per-AIR convention: ALL u16 range checks across the PoP batch
/// share this single global bus name. LogUp matches lookups by
/// content; multiple AIRs on the same bus pair up correctly with the
/// single table AIR. Production deployments instantiate ONE
/// `U16RangeTableAir::new(BUS_U16_RANGE)` per batch.
pub const BUS_U16_RANGE: &str = "rostro-u16-range";

/// `2^16` as a u32. Used as the radix for the u16 limb split.
pub const RADIX_U16: u32 = 1u32 << 16;

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
		let c_complement: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_C_COMP + i]);
		let c_complement_borrow: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_C_COMP_BORROW + i]);
		let c_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_C_LO + i]);
		let c_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_C_HI + i]);
		let c_comp_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_C_COMP_LO + i]);
		let c_comp_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_C_COMP_HI + i]);

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

		// ─── Canonical-form check on c (commit 2 of 3) ────────────────
		//
		// Constrains `c <= p - 1` (i.e., c is in canonical form) via the
		// subtraction `c_complement = p_minus_one - c` with a per-limb
		// borrow chain. The structure mirrors the balance equation:
		//   p_minus_one[i] - c[i] - borrow_in[i] + borrow[i] * 2^32
		//     == c_complement[i]
		// where borrow_in[0] = 0, borrow_in[i] = borrow[i-1] otherwise.
		// The TOP-borrow closure (`borrow[7] == 0`) asserts no underflow
		// at limb 7, which proves `c <= p - 1`.
		//
		// Combined with the per-limb u32 range checks on c (commit 3),
		// this rejects any non-canonical c.

		let radix = AB::Expr::from_u64(RADIX_LIMB);
		for i in 0..FIELD_NUM_LIMBS {
			let p_minus_one_limb = AB::Expr::from_u32(P_MINUS_ONE_LIMBS[i]);
			let borrow_in: AB::Expr = if i == 0 {
				AB::Expr::ZERO
			} else {
				c_complement_borrow[i - 1].into()
			};
			// canonical_balance_i :=
			//   p_minus_one[i] - c[i] - borrow_in + borrow[i] * radix
			//     - c_complement[i]
			let canonical_balance: AB::Expr = p_minus_one_limb
				- c[i].into()
				- borrow_in
				+ c_complement_borrow[i].into() * radix.clone()
				- c_complement[i].into();
			builder.assert_zero(canonical_balance);
		}

		// Each c_complement_borrow[i] for i ∈ {0..6} is boolean (= 0 or 1).
		// borrow[7] is pinned to 0 by the top-borrow closure below, so its
		// boolean check is redundant.
		for i in 0..(FIELD_NUM_LIMBS - 1) {
			builder.assert_bool(c_complement_borrow[i]);
		}

		// Top-borrow closure: borrow[7] must equal 0. This is the
		// constraint that actually enforces `c <= p - 1`: if c were
		// greater than p - 1, the subtraction would underflow, requiring
		// a borrow at the top.
		builder.assert_zero(c_complement_borrow[FIELD_NUM_LIMBS - 1]);

		// ─── u32 range-check via u16 limb split (commit 3 of 3) ───────
		//
		// For each prover-controlled u32 limb (c[i] and c_complement[i]),
		// witness two u16 halves and constrain
		//   limb == low + high * 2^16
		// Then lookup_key each half against the shared u16 range-check
		// bus. The bus is balanced by a `U16RangeTableAir` instance in
		// the same batch providing all values in [0, 2^16).
		//
		// Input columns a, b are NOT range-checked here — their range
		// correctness is the caller's responsibility (the AIR that
		// produced them, typically). Per the standard input/output
		// AIR composition pattern.
		//
		// `carry[i]` is constrained to {-1, 0, 1} via the tertiary
		// check above, so it doesn't need a u16 range check.
		// `c_complement_borrow[i]` is constrained to {0, 1} via the
		// boolean check, so likewise.
		// `t` is constrained to {0, 1}.
		//
		// 16 prover-controlled u32 limbs × 2 halves = 32 lookup_key
		// interactions per add operation.

		let radix_u16 = AB::Expr::from_u32(RADIX_U16);

		for i in 0..FIELD_NUM_LIMBS {
			// c[i] limb-split: c[i] == c_lo[i] + c_hi[i] * 2^16
			let c_split: AB::Expr =
				c_lo[i].into() + c_hi[i].into() * radix_u16.clone() - c[i].into();
			builder.assert_zero(c_split);

			// c_complement[i] limb-split.
			let cc_split: AB::Expr = c_comp_lo[i].into()
				+ c_comp_hi[i].into() * radix_u16.clone()
				- c_complement[i].into();
			builder.assert_zero(cc_split);

			// Lookup each half against the u16 range-check bus. count = +1
			// per query; weight = 1 per `LookupBus::lookup_key` convention.
			// The table AIR (in the same batch) provides matching entries
			// with negative multiplicities; LogUp balances the bus.
			builder.push_interaction(BUS_U16_RANGE, [c_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_hi[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_comp_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_comp_hi[i]], AB::Expr::ONE, 1);
		}
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

	// Compute canonical-form witnesses: c_complement = p_minus_one - c
	// with a per-limb borrow chain. Since `c < p` is what makes this AIR
	// honest, the subtraction here is straight subtraction with at most
	// per-limb borrow, no top underflow.
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
	assert_eq!(
		c_complement_borrow[FIELD_NUM_LIMBS - 1],
		0,
		"top-borrow closure violated: c >= p (witness builder bug or non-canonical c)",
	);

	// Split each prover-controlled u32 limb into u16 halves for the
	// range-check lookup (commit 3).
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

	FieldAddTraceRow {
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

/// Trace row produced by [`build_field_add_trace_row`]. Holds the
/// signed carry chain as `i64` (the AIR converts to Goldilocks).
#[derive(Clone, Debug)]
pub struct FieldAddTraceRow {
	pub a: [u32; FIELD_NUM_LIMBS],
	pub b: [u32; FIELD_NUM_LIMBS],
	pub c: [u32; FIELD_NUM_LIMBS],
	pub t: u32,
	pub carry: [i64; FIELD_NUM_LIMBS],
	/// Canonical-form witness: `c_complement[i] = p_minus_one - c` at
	/// limb i (with borrow chain accounted for). Combined with
	/// `c_complement_borrow[7] == 0`, proves `c <= p - 1`.
	pub c_complement: [u32; FIELD_NUM_LIMBS],
	/// Per-limb borrow chain for the canonical-form subtraction.
	/// Each value ∈ {0, 1}; borrow[7] must equal 0.
	pub c_complement_borrow: [u8; FIELD_NUM_LIMBS],
	/// Low u16 half of each `c[i]`. Constrained by `c == lo + hi * 2^16`
	/// and range-checked via the u16 lookup bus.
	pub c_lo: [u16; FIELD_NUM_LIMBS],
	/// High u16 half of each `c[i]`.
	pub c_hi: [u16; FIELD_NUM_LIMBS],
	/// Low u16 half of each `c_complement[i]`.
	pub c_comp_lo: [u16; FIELD_NUM_LIMBS],
	/// High u16 half of each `c_complement[i]`.
	pub c_comp_hi: [u16; FIELD_NUM_LIMBS],
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
