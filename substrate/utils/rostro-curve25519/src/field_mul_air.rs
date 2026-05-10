// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIR for modular multiplication over Curve25519's base field
//! (`F_p` with `p = 2^255 - 19`).
//!
//! Per the design spec at `pop_field_mul_air_design.md`, this AIR
//! lands in three commits:
//!
//! - **M1 (THIS commit):** schoolbook multiplication `a * b →
//!   wide_product` (16 × u32 limbs, integer product, no reduction).
//!   16×16 u16-half schoolbook (256 partials) keeps column sums in
//!   Goldilocks range (~2^36 max vs `p_G ≈ 2^64`). Includes u16
//!   range-check lookups on every prover-controlled half so the
//!   schoolbook trace is sound modulo "no reduction" gap.
//! - **M2:** Barrett reduction. Witness `q` (quotient) and `c`
//!   (remainder); constrain `wide_product == q * p + c` (via a
//!   second schoolbook for `q * p`) + canonical-form check on `c`.
//! - **M3 (current):** u16 range-check lookups for every M2 prover-
//!   controlled u32 cell, on the shared `BUS_U16_RANGE`. 144 lookups
//!   added (M1's 128 + M3's 144 = 272 total per multiply).
//!
//! After M3, `FieldMulAir` is **soundness-complete** modulo caller-
//! supplied range correctness on inputs a, b.
//!
//! ## Why u16 sub-limbs
//!
//! Naive 8×8 schoolbook on u32 limbs: 64 partials, each `a[i] * b[j]
//! ≤ (2^32-1)^2 ≈ 2^64`. Column k can have up to 8 partials, summing
//! to `2^67`, which **overflows Goldilocks** (`p_G ≈ 2^64`).
//!
//! Splitting each u32 limb into two u16 halves gives 16×16 = 256
//! partials of u16 × u16 ≤ `(2^16-1)^2 ≈ 2^32`. Column k has up to
//! 16 partials, summing to `2^36`. Comfortably within Goldilocks.
//!
//! ## Column layout (M1: 192 columns)
//!
//! ```text
//!   cols   0..  8   a[0..8]         (input u32 limbs)
//!   cols   8.. 16   b[0..8]         (input u32 limbs)
//!   cols  16.. 24   a_lo[0..8]      (low u16 of each a[i])
//!   cols  24.. 32   a_hi[0..8]      (high u16 of each a[i])
//!   cols  32.. 40   b_lo[0..8]
//!   cols  40.. 48   b_hi[0..8]
//!   cols  48.. 64   wide_product[0..16]   (u32 limbs of a * b)
//!   cols  64.. 80   wide_lo[0..16]        (low u16 of each wide_product)
//!   cols  80.. 96   wide_hi[0..16]        (high u16)
//!   cols  96..128   carry[0..32]          (schoolbook column carry chain)
//!   cols 128..160   carry_lo[0..32]       (low u16 of each carry)
//!   cols 160..192   carry_hi[0..32]       (high u16)
//! ```
//!
//! ## Constraints (M1)
//!
//! - **Limb-split** (8 + 8 + 16 + 32 = 64 × deg-2): each u32 cell is
//!   constrained to equal `lo + hi * 2^16`. Combined with the u16
//!   range-check lookups on the halves, this enforces the u32 cell
//!   is in `[0, 2^32)`.
//! - **Schoolbook column sum** (32 × deg-2): for each column
//!   `k ∈ [0..32)`,
//!   ```text
//!   Σ_{i+j=k, 0≤i,j<16} a_u16[i] * b_u16[j]
//!     + carry_in[k]
//!     == wide_u16[k] + carry[k] * 2^16
//!   ```
//!   where `carry_in[0] = 0`, `carry_in[k] = carry[k-1]` otherwise,
//!   and `wide_u16[k] = wide_lo[k/2]` if k is even, `wide_hi[k/2]`
//!   if k is odd. Same indexing for `a_u16` and `b_u16`.
//! - **Top-balance closure** (1 × deg-1): `carry[31] == 0`. Forces
//!   the schoolbook to actually balance — without it, the prover
//!   could absorb mismatches into a non-zero top carry.
//!
//! ## Range-check lookups
//!
//! 128 u16 lookups per multiply on `BUS_U16_RANGE`:
//! - a_lo, a_hi: 16
//! - b_lo, b_hi: 16
//! - wide_lo, wide_hi: 32
//! - carry_lo, carry_hi: 64
//!
//! Input limbs a, b are NOT range-checked here (caller's
//! responsibility), but their u16 halves ARE — required because
//! the limb-split constraint alone doesn't force u32 shape on a, b.
//! Practically, range-checking the halves is the standard way to
//! enforce u32 shape on the u32 input cell too.
//!
//! ## Soundness gap (closed in M2)
//!
//! **wide_product is the actual integer product `a * b`, NOT
//! `(a * b) mod p`.** This AIR alone is not a modular multiplication
//! — it's a schoolbook trace. The Barrett reduction step in M2 takes
//! `wide_product` and produces a canonical `c < p` such that
//! `wide_product == q * p + c`.
//!
//! Until M2 lands, **THIS AIR MUST NOT BE USED ALONE** as a
//! modular-multiply primitive. M1 tests verify the integer-product
//! correctness against `num-bigint` (via `wide_mul` from `field.rs`);
//! M2 will add tests for canonical c.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use num_bigint::BigUint;
use num_integer::Integer;

use crate::field::{
	bytes_to_limbs, limbs_to_bytes, wide_mul, FIELD_NUM_LIMBS, P_LIMBS, P_MINUS_ONE_LIMBS,
};
use crate::field_air::{BUS_U16_RANGE, RADIX_LIMB, RADIX_U16};

/// Number of u32 limbs in the wide product (16 = 2 × FIELD_NUM_LIMBS).
pub const WIDE_NUM_LIMBS: usize = 2 * FIELD_NUM_LIMBS;

/// Number of u16 sub-limbs in the schoolbook view of each input.
pub const U16_NUM_SUBLIMBS: usize = 2 * FIELD_NUM_LIMBS;

/// Number of schoolbook columns (= u16 sub-limbs in the wide product).
pub const NUM_COLS_SCHOOLBOOK: usize = 2 * U16_NUM_SUBLIMBS;

// ─── Column indices ────────────────────────────────────────────────────────

/// Input `a` u32 limbs (8 cells).
pub const COL_MUL_A: usize = 0;
/// Input `b` u32 limbs (8 cells).
pub const COL_MUL_B: usize = COL_MUL_A + FIELD_NUM_LIMBS;
/// Low u16 of each a[i] (8 cells).
pub const COL_MUL_A_LO: usize = COL_MUL_B + FIELD_NUM_LIMBS;
/// High u16 of each a[i] (8 cells).
pub const COL_MUL_A_HI: usize = COL_MUL_A_LO + FIELD_NUM_LIMBS;
/// Low u16 of each b[i] (8 cells).
pub const COL_MUL_B_LO: usize = COL_MUL_A_HI + FIELD_NUM_LIMBS;
/// High u16 of each b[i] (8 cells).
pub const COL_MUL_B_HI: usize = COL_MUL_B_LO + FIELD_NUM_LIMBS;
/// Wide product u32 limbs (16 cells).
pub const COL_MUL_WIDE: usize = COL_MUL_B_HI + FIELD_NUM_LIMBS;
/// Low u16 of each wide_product[m] (16 cells).
pub const COL_MUL_WIDE_LO: usize = COL_MUL_WIDE + WIDE_NUM_LIMBS;
/// High u16 of each wide_product[m] (16 cells).
pub const COL_MUL_WIDE_HI: usize = COL_MUL_WIDE_LO + WIDE_NUM_LIMBS;
/// Schoolbook column carry chain (32 cells, carry[31] pinned to 0).
pub const COL_MUL_CARRY: usize = COL_MUL_WIDE_HI + WIDE_NUM_LIMBS;
/// Low u16 of each carry[k] (32 cells).
pub const COL_MUL_CARRY_LO: usize = COL_MUL_CARRY + NUM_COLS_SCHOOLBOOK;
/// High u16 of each carry[k] (32 cells).
pub const COL_MUL_CARRY_HI: usize = COL_MUL_CARRY_LO + NUM_COLS_SCHOOLBOOK;
/// Snapshot of the M1 column count (192), kept for historical
/// reference and column-layout pin tests. Use [`FIELD_MUL_NUM_COLS`]
/// for the current full AIR width.
pub const FIELD_MUL_M1_NUM_COLS: usize = COL_MUL_CARRY_HI + NUM_COLS_SCHOOLBOOK;

// ─── M2 columns: Barrett reduction witnesses ───────────────────────────────
//
// q is the witnessed quotient `wide / p` (integer division). Since
// a, b < p ≈ 2^255, the wide product < p^2 < 2^510, and q < p, so q
// fits in 8 u32 limbs (the same canonical shape as a, b, c). No
// extra top bit needed.
//
// qp_wide is q * p computed via a second schoolbook (mirrors the
// a*b schoolbook structurally; separate witness block per silo).
//
// The subtraction wide - qp_wide == c (with c < p) is verified
// limb-wise with a borrow chain `qp_borrow[0..16]`. The top borrow
// (qp_borrow[15]) is pinned to 0, which enforces wide >= qp_wide.
// For limbs m ∈ [8..16), the equation says (wide - qp_wide - borrow_in)
// == 0 since c has no contribution there; this is what forces wide
// to actually equal qp_wide + c (rather than wide >> 256 + something).

/// Witnessed Barrett quotient `q = floor(wide / p)` (8 u32 limbs).
pub const COL_MUL_Q: usize = FIELD_MUL_M1_NUM_COLS;
/// Low u16 of each q[i] (8 cells).
pub const COL_MUL_Q_LO: usize = COL_MUL_Q + FIELD_NUM_LIMBS;
/// High u16 of each q[i] (8 cells).
pub const COL_MUL_Q_HI: usize = COL_MUL_Q_LO + FIELD_NUM_LIMBS;
/// `q * p` as a 16 u32-limb wide value (mirrors `wide_product` shape).
pub const COL_MUL_QP_WIDE: usize = COL_MUL_Q_HI + FIELD_NUM_LIMBS;
/// Low u16 of each qp_wide[m] (16 cells).
pub const COL_MUL_QP_WIDE_LO: usize = COL_MUL_QP_WIDE + WIDE_NUM_LIMBS;
/// High u16 of each qp_wide[m] (16 cells).
pub const COL_MUL_QP_WIDE_HI: usize = COL_MUL_QP_WIDE_LO + WIDE_NUM_LIMBS;
/// Schoolbook column carry chain for `q * p` (32 cells, qp_carry[31]
/// pinned to 0 by top-balance closure).
pub const COL_MUL_QP_CARRY: usize = COL_MUL_QP_WIDE_HI + WIDE_NUM_LIMBS;
/// Low u16 of each qp_carry[k] (32 cells).
pub const COL_MUL_QP_CARRY_LO: usize = COL_MUL_QP_CARRY + NUM_COLS_SCHOOLBOOK;
/// High u16 of each qp_carry[k] (32 cells).
pub const COL_MUL_QP_CARRY_HI: usize = COL_MUL_QP_CARRY_LO + NUM_COLS_SCHOOLBOOK;
/// Output of the modular multiply: `c = (a * b) mod p`, 8 u32 limbs.
pub const COL_MUL_C: usize = COL_MUL_QP_CARRY_HI + NUM_COLS_SCHOOLBOOK;
/// Low u16 of each c[i] (8 cells).
pub const COL_MUL_C_LO: usize = COL_MUL_C + FIELD_NUM_LIMBS;
/// High u16 of each c[i] (8 cells).
pub const COL_MUL_C_HI: usize = COL_MUL_C_LO + FIELD_NUM_LIMBS;
/// `c_complement = p_minus_one - c` (8 u32 limbs) for canonical-form check.
pub const COL_MUL_C_COMP: usize = COL_MUL_C_HI + FIELD_NUM_LIMBS;
/// Per-limb borrow chain for the canonical-form subtraction
/// (8 booleans, borrow[7] pinned to 0).
pub const COL_MUL_C_COMP_BORROW: usize = COL_MUL_C_COMP + FIELD_NUM_LIMBS;
/// Low u16 of each c_complement[i] (8 cells).
pub const COL_MUL_C_COMP_LO: usize = COL_MUL_C_COMP_BORROW + FIELD_NUM_LIMBS;
/// High u16 of each c_complement[i] (8 cells).
pub const COL_MUL_C_COMP_HI: usize = COL_MUL_C_COMP_LO + FIELD_NUM_LIMBS;
/// Per-limb borrow chain for the wide subtraction `wide == qp_wide + c`
/// (16 booleans, qp_borrow[15] pinned to 0).
pub const COL_MUL_QP_BORROW: usize = COL_MUL_C_COMP_HI + FIELD_NUM_LIMBS;
/// Total columns for FieldMulAir M2 (432 = 192 M1 + 240 M2).
pub const FIELD_MUL_NUM_COLS: usize = COL_MUL_QP_BORROW + WIDE_NUM_LIMBS;

/// Plonky3 AIR for one field-multiplication operation, M1 stage (schoolbook
/// trace only, no Barrett reduction yet).
#[derive(Clone, Debug, Default)]
pub struct FieldMulAir;

impl FieldMulAir {
	pub const fn new() -> Self {
		Self
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for FieldMulAir {
	fn width(&self) -> usize {
		FIELD_MUL_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for FieldMulAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		// Extract witnesses.
		let a: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_A + i]);
		let b: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_B + i]);
		let a_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_A_LO + i]);
		let a_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_A_HI + i]);
		let b_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_B_LO + i]);
		let b_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_B_HI + i]);
		let wide: [AB::Var; WIDE_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_WIDE + i]);
		let wide_lo: [AB::Var; WIDE_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_WIDE_LO + i]);
		let wide_hi: [AB::Var; WIDE_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_WIDE_HI + i]);
		let carry: [AB::Var; NUM_COLS_SCHOOLBOOK] =
			core::array::from_fn(|i| local[COL_MUL_CARRY + i]);
		let carry_lo: [AB::Var; NUM_COLS_SCHOOLBOOK] =
			core::array::from_fn(|i| local[COL_MUL_CARRY_LO + i]);
		let carry_hi: [AB::Var; NUM_COLS_SCHOOLBOOK] =
			core::array::from_fn(|i| local[COL_MUL_CARRY_HI + i]);

		let radix_u16 = AB::Expr::from_u32(RADIX_U16);

		// ─── Limb-split constraints ───────────────────────────────────
		//
		// For each u32 cell, constrain `cell == lo + hi * 2^16`. The
		// halves are independently range-checked below (lookup pushes);
		// together, the limb-split constraint forces the u32 cell to
		// `[0, 2^32)`.

		for i in 0..FIELD_NUM_LIMBS {
			let a_split: AB::Expr =
				a_lo[i].into() + a_hi[i].into() * radix_u16.clone() - a[i].into();
			builder.assert_zero(a_split);
			let b_split: AB::Expr =
				b_lo[i].into() + b_hi[i].into() * radix_u16.clone() - b[i].into();
			builder.assert_zero(b_split);
		}
		for m in 0..WIDE_NUM_LIMBS {
			let wide_split: AB::Expr =
				wide_lo[m].into() + wide_hi[m].into() * radix_u16.clone() - wide[m].into();
			builder.assert_zero(wide_split);
		}
		for k in 0..NUM_COLS_SCHOOLBOOK {
			let carry_split: AB::Expr = carry_lo[k].into()
				+ carry_hi[k].into() * radix_u16.clone()
				- carry[k].into();
			builder.assert_zero(carry_split);
		}

		// ─── Schoolbook column constraints ────────────────────────────
		//
		// View a, b, wide_product as 16-element u16 vectors. For each
		// column k ∈ [0..32), accumulate `Σ a_u16[i] * b_u16[j]` for
		// i + j = k, then balance against `wide_u16[k] + carry[k] *
		// 2^16` with the previous column's carry as input.
		//
		// `a_u16[i] = a_lo[i/2] if i even, a_hi[i/2] if i odd`. Same
		// indexing for b_u16 and wide_u16.

		let a_u16 = |i: usize| -> AB::Var {
			if i % 2 == 0 {
				a_lo[i / 2]
			} else {
				a_hi[i / 2]
			}
		};
		let b_u16 = |j: usize| -> AB::Var {
			if j % 2 == 0 {
				b_lo[j / 2]
			} else {
				b_hi[j / 2]
			}
		};
		let wide_u16 = |k: usize| -> AB::Var {
			if k % 2 == 0 {
				wide_lo[k / 2]
			} else {
				wide_hi[k / 2]
			}
		};

		for k in 0..NUM_COLS_SCHOOLBOOK {
			// col_partial_sum[k] = Σ a_u16[i] * b_u16[j] over i+j=k.
			let mut col_sum: AB::Expr = AB::Expr::ZERO;
			for i in 0..U16_NUM_SUBLIMBS {
				if i > k {
					continue;
				}
				let j = k - i;
				if j >= U16_NUM_SUBLIMBS {
					continue;
				}
				col_sum = col_sum + a_u16(i).into() * b_u16(j).into();
			}

			let carry_in: AB::Expr = if k == 0 {
				AB::Expr::ZERO
			} else {
				carry[k - 1].into()
			};

			// balance := col_sum + carry_in - wide_u16[k] - carry[k] * 2^16
			let balance: AB::Expr =
				col_sum + carry_in - wide_u16(k).into() - carry[k].into() * radix_u16.clone();
			builder.assert_zero(balance);
		}

		// Top-balance closure: carry[31] == 0. Without this, the prover
		// could pick wrong wide_u16 values and shove the mismatch into
		// the top carry.
		builder.assert_zero(carry[NUM_COLS_SCHOOLBOOK - 1]);

		// ─── u16 range-check lookups (128 per multiply) ───────────────
		//
		// For each u16 cell, push a lookup_key on BUS_U16_RANGE. The
		// shared U16RangeTableAir in the production batch provides the
		// table entries; LogUp balances.

		for i in 0..FIELD_NUM_LIMBS {
			builder.push_interaction(BUS_U16_RANGE, [a_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [a_hi[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [b_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [b_hi[i]], AB::Expr::ONE, 1);
		}
		for m in 0..WIDE_NUM_LIMBS {
			builder.push_interaction(BUS_U16_RANGE, [wide_lo[m]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [wide_hi[m]], AB::Expr::ONE, 1);
		}
		for k in 0..NUM_COLS_SCHOOLBOOK {
			builder.push_interaction(BUS_U16_RANGE, [carry_lo[k]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [carry_hi[k]], AB::Expr::ONE, 1);
		}

		// ──────────────────────────────────────────────────────────────
		// M2: Barrett reduction
		// ──────────────────────────────────────────────────────────────
		//
		// Extract M2 witnesses + verify the q*p schoolbook + wide
		// subtraction + canonical-form check on c. Together these
		// constrain `wide_product == q * p + c` with `c < p`, which
		// is the modular-multiply reduction.
		//
		// M2 witnesses (no u16 range-check lookups yet — those land in
		// M3; the M2 soundness gap is "prover could put non-u32-shaped
		// values in M2 cells"). The Barrett math is structurally
		// correct here; range-check closes the last gap.

		let q: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_Q + i]);
		let q_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_Q_LO + i]);
		let q_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_Q_HI + i]);
		let qp_wide: [AB::Var; WIDE_NUM_LIMBS] =
			core::array::from_fn(|m| local[COL_MUL_QP_WIDE + m]);
		let qp_wide_lo: [AB::Var; WIDE_NUM_LIMBS] =
			core::array::from_fn(|m| local[COL_MUL_QP_WIDE_LO + m]);
		let qp_wide_hi: [AB::Var; WIDE_NUM_LIMBS] =
			core::array::from_fn(|m| local[COL_MUL_QP_WIDE_HI + m]);
		let qp_carry: [AB::Var; NUM_COLS_SCHOOLBOOK] =
			core::array::from_fn(|k| local[COL_MUL_QP_CARRY + k]);
		let qp_carry_lo: [AB::Var; NUM_COLS_SCHOOLBOOK] =
			core::array::from_fn(|k| local[COL_MUL_QP_CARRY_LO + k]);
		let qp_carry_hi: [AB::Var; NUM_COLS_SCHOOLBOOK] =
			core::array::from_fn(|k| local[COL_MUL_QP_CARRY_HI + k]);
		let c: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_C + i]);
		let c_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_C_LO + i]);
		let c_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_C_HI + i]);
		let c_complement: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_C_COMP + i]);
		let c_complement_borrow: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_C_COMP_BORROW + i]);
		let c_comp_lo: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_C_COMP_LO + i]);
		let c_comp_hi: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_MUL_C_COMP_HI + i]);
		let qp_borrow: [AB::Var; WIDE_NUM_LIMBS] =
			core::array::from_fn(|m| local[COL_MUL_QP_BORROW + m]);

		// ─── Limb-split constraints for M2 u32 witnesses ──────────────
		//
		// Same shape as M1's splits. The lo/hi halves get range-checked
		// in M3; for now the splits ensure the u32 cell equals lo + hi
		// * 2^16 (which combined with range checks forces u32 shape).

		for i in 0..FIELD_NUM_LIMBS {
			let q_split: AB::Expr =
				q_lo[i].into() + q_hi[i].into() * radix_u16.clone() - q[i].into();
			builder.assert_zero(q_split);
			let c_split: AB::Expr =
				c_lo[i].into() + c_hi[i].into() * radix_u16.clone() - c[i].into();
			builder.assert_zero(c_split);
			let cc_split: AB::Expr = c_comp_lo[i].into()
				+ c_comp_hi[i].into() * radix_u16.clone()
				- c_complement[i].into();
			builder.assert_zero(cc_split);
		}
		for m in 0..WIDE_NUM_LIMBS {
			let qpw_split: AB::Expr = qp_wide_lo[m].into()
				+ qp_wide_hi[m].into() * radix_u16.clone()
				- qp_wide[m].into();
			builder.assert_zero(qpw_split);
		}
		for k in 0..NUM_COLS_SCHOOLBOOK {
			let qpc_split: AB::Expr = qp_carry_lo[k].into()
				+ qp_carry_hi[k].into() * radix_u16.clone()
				- qp_carry[k].into();
			builder.assert_zero(qpc_split);
		}

		// ─── q * p schoolbook ─────────────────────────────────────────
		//
		// Mirrors the a*b schoolbook structurally; q's u16 halves
		// multiply against the constant p's u16 halves to produce
		// qp_wide. Same column-sum + carry-chain pattern.
		//
		// p_u16[k] is the k-th u16 sub-limb of P_LIMBS (a constant).
		// p_u16[2m]   = P_LIMBS[m] & 0xFFFF
		// p_u16[2m+1] = P_LIMBS[m] >> 16

		let q_u16 = |i: usize| -> AB::Var {
			if i % 2 == 0 {
				q_lo[i / 2]
			} else {
				q_hi[i / 2]
			}
		};
		let p_u16_const = |k: usize| -> u32 {
			let m = k / 2;
			if k % 2 == 0 {
				P_LIMBS[m] & 0xFFFF
			} else {
				P_LIMBS[m] >> 16
			}
		};
		let qp_wide_u16 = |k: usize| -> AB::Var {
			if k % 2 == 0 {
				qp_wide_lo[k / 2]
			} else {
				qp_wide_hi[k / 2]
			}
		};

		for k in 0..NUM_COLS_SCHOOLBOOK {
			let mut col_sum: AB::Expr = AB::Expr::ZERO;
			for i in 0..U16_NUM_SUBLIMBS {
				if i > k {
					continue;
				}
				let j = k - i;
				if j >= U16_NUM_SUBLIMBS {
					continue;
				}
				let p_j = AB::Expr::from_u32(p_u16_const(j));
				col_sum = col_sum + q_u16(i).into() * p_j;
			}
			let carry_in: AB::Expr = if k == 0 {
				AB::Expr::ZERO
			} else {
				qp_carry[k - 1].into()
			};
			let balance: AB::Expr = col_sum
				+ carry_in
				- qp_wide_u16(k).into()
				- qp_carry[k].into() * radix_u16.clone();
			builder.assert_zero(balance);
		}
		// Top-balance closure for q*p schoolbook.
		builder.assert_zero(qp_carry[NUM_COLS_SCHOOLBOOK - 1]);

		// ─── Wide subtraction: wide == qp_wide + c ────────────────────
		//
		// Per-limb borrow-chain subtraction. For limbs m ∈ [0..8), the
		// equation is `wide[m] - qp_wide[m] - borrow_in[m] +
		// qp_borrow[m] * 2^32 == c[m]`. For limbs m ∈ [8..16), c has no
		// contribution, so the RHS is 0. The top borrow (qp_borrow[15])
		// must be 0 (no underflow → wide >= qp_wide, which means c >= 0).

		let radix_limb = AB::Expr::from_u64(RADIX_LIMB);
		for m in 0..WIDE_NUM_LIMBS {
			let borrow_in: AB::Expr = if m == 0 {
				AB::Expr::ZERO
			} else {
				qp_borrow[m - 1].into()
			};
			let c_contrib: AB::Expr = if m < FIELD_NUM_LIMBS {
				c[m].into()
			} else {
				AB::Expr::ZERO
			};
			let sub_balance: AB::Expr = wide[m].into()
				- qp_wide[m].into()
				- borrow_in
				+ qp_borrow[m].into() * radix_limb.clone()
				- c_contrib;
			builder.assert_zero(sub_balance);
		}

		// qp_borrow booleans for m ∈ [0..15). qp_borrow[15] is pinned
		// by the top-balance closure below; its boolean check is
		// redundant.
		for m in 0..(WIDE_NUM_LIMBS - 1) {
			builder.assert_bool(qp_borrow[m]);
		}
		// Top-borrow closure: qp_borrow[15] == 0.
		builder.assert_zero(qp_borrow[WIDE_NUM_LIMBS - 1]);

		// ─── Canonical-form check on c ────────────────────────────────
		//
		// Mirrors FieldAddAir's canonical-form check: c_complement =
		// p_minus_one - c with a borrow chain. If c > p - 1, the
		// subtraction underflows at the top, which the closure rejects.

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
				+ c_complement_borrow[i].into() * radix_limb.clone()
				- c_complement[i].into();
			builder.assert_zero(canonical_balance);
		}
		for i in 0..(FIELD_NUM_LIMBS - 1) {
			builder.assert_bool(c_complement_borrow[i]);
		}
		builder.assert_zero(c_complement_borrow[FIELD_NUM_LIMBS - 1]);

		// ─── M3: u16 range-check lookups for M2 witnesses ─────────────
		//
		// Closes the last soundness gap. Without these, the prover
		// could put non-u32-shaped Goldilocks values in M2 cells and
		// satisfy the M2 constraints via mod-p_G wraparound. With
		// these lookups, every prover-controlled u32 cell is forced
		// into [0, 2^32) via its u16 halves.
		//
		// c_complement_borrow and qp_borrow are NOT range-checked: they
		// are constrained to {0, 1} by the boolean checks above; the
		// boolean polynomial `x * (1 - x) == 0` forces u8 shape
		// without needing a lookup.
		//
		// 144 lookups added here (M1's 128 + M3's 144 = 272 total per
		// multiply on BUS_U16_RANGE):
		// - q_lo / q_hi: 16
		// - qp_wide_lo / qp_wide_hi: 32
		// - qp_carry_lo / qp_carry_hi: 64
		// - c_lo / c_hi: 16
		// - c_comp_lo / c_comp_hi: 16

		for i in 0..FIELD_NUM_LIMBS {
			builder.push_interaction(BUS_U16_RANGE, [q_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [q_hi[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_hi[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_comp_lo[i]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [c_comp_hi[i]], AB::Expr::ONE, 1);
		}
		for m in 0..WIDE_NUM_LIMBS {
			builder.push_interaction(BUS_U16_RANGE, [qp_wide_lo[m]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [qp_wide_hi[m]], AB::Expr::ONE, 1);
		}
		for k in 0..NUM_COLS_SCHOOLBOOK {
			builder.push_interaction(BUS_U16_RANGE, [qp_carry_lo[k]], AB::Expr::ONE, 1);
			builder.push_interaction(BUS_U16_RANGE, [qp_carry_hi[k]], AB::Expr::ONE, 1);
		}
	}
}

// ─── Witness-side trace builder ────────────────────────────────────────────

/// Trace row produced by [`build_field_mul_trace_row`]. Holds every
/// witness column the AIR's eval reads, in flat-row order.
#[derive(Clone, Debug)]
pub struct FieldMulTraceRow {
	pub a: [u32; FIELD_NUM_LIMBS],
	pub b: [u32; FIELD_NUM_LIMBS],
	pub a_lo: [u16; FIELD_NUM_LIMBS],
	pub a_hi: [u16; FIELD_NUM_LIMBS],
	pub b_lo: [u16; FIELD_NUM_LIMBS],
	pub b_hi: [u16; FIELD_NUM_LIMBS],
	/// Wide product = `a * b` as 16 u32 LE limbs (no reduction).
	pub wide: [u32; WIDE_NUM_LIMBS],
	pub wide_lo: [u16; WIDE_NUM_LIMBS],
	pub wide_hi: [u16; WIDE_NUM_LIMBS],
	/// Schoolbook column carries. `carry[31]` is always 0 (top-balance
	/// closure); witnessed as a sanity-check anchor.
	pub carry: [u32; NUM_COLS_SCHOOLBOOK],
	pub carry_lo: [u16; NUM_COLS_SCHOOLBOOK],
	pub carry_hi: [u16; NUM_COLS_SCHOOLBOOK],

	// ── M2 witnesses (Barrett reduction) ─────────────────────────────
	/// Quotient `q = floor(wide / p)`, 8 u32 limbs.
	pub q: [u32; FIELD_NUM_LIMBS],
	pub q_lo: [u16; FIELD_NUM_LIMBS],
	pub q_hi: [u16; FIELD_NUM_LIMBS],
	/// `q * p` as 16 u32 limbs (mirrors wide_product shape).
	pub qp_wide: [u32; WIDE_NUM_LIMBS],
	pub qp_wide_lo: [u16; WIDE_NUM_LIMBS],
	pub qp_wide_hi: [u16; WIDE_NUM_LIMBS],
	/// q*p schoolbook column carries (32 cells; carry[31] = 0).
	pub qp_carry: [u32; NUM_COLS_SCHOOLBOOK],
	pub qp_carry_lo: [u16; NUM_COLS_SCHOOLBOOK],
	pub qp_carry_hi: [u16; NUM_COLS_SCHOOLBOOK],
	/// Output: `c = (a * b) mod p`, 8 u32 limbs in canonical form.
	pub c: [u32; FIELD_NUM_LIMBS],
	pub c_lo: [u16; FIELD_NUM_LIMBS],
	pub c_hi: [u16; FIELD_NUM_LIMBS],
	/// Canonical-form witness: `c_complement = p_minus_one - c`.
	pub c_complement: [u32; FIELD_NUM_LIMBS],
	/// Per-limb borrow chain for the canonical-form subtraction.
	pub c_complement_borrow: [u8; FIELD_NUM_LIMBS],
	pub c_comp_lo: [u16; FIELD_NUM_LIMBS],
	pub c_comp_hi: [u16; FIELD_NUM_LIMBS],
	/// Per-limb borrow chain for the wide subtraction `wide == qp_wide + c`.
	/// 16 booleans; qp_borrow[15] is always 0 (top-borrow closure).
	pub qp_borrow: [u8; WIDE_NUM_LIMBS],
}

/// Build a single-row trace for [`FieldMulAir`] (M1) from canonical
/// inputs. Computes `wide = a * b` as integer (no reduction yet), plus
/// the u16 splits and the schoolbook carry chain.
pub fn build_field_mul_trace_row(
	a: &[u32; FIELD_NUM_LIMBS],
	b: &[u32; FIELD_NUM_LIMBS],
) -> FieldMulTraceRow {
	let wide = wide_mul(a, b);

	// u16 splits of inputs and wide.
	let mut a_lo = [0u16; FIELD_NUM_LIMBS];
	let mut a_hi = [0u16; FIELD_NUM_LIMBS];
	let mut b_lo = [0u16; FIELD_NUM_LIMBS];
	let mut b_hi = [0u16; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		a_lo[i] = (a[i] & 0xFFFF) as u16;
		a_hi[i] = (a[i] >> 16) as u16;
		b_lo[i] = (b[i] & 0xFFFF) as u16;
		b_hi[i] = (b[i] >> 16) as u16;
	}
	let mut wide_lo = [0u16; WIDE_NUM_LIMBS];
	let mut wide_hi = [0u16; WIDE_NUM_LIMBS];
	for m in 0..WIDE_NUM_LIMBS {
		wide_lo[m] = (wide[m] & 0xFFFF) as u16;
		wide_hi[m] = (wide[m] >> 16) as u16;
	}

	// Compute the schoolbook carry chain.
	//
	// For each column k, col_partial_sum + carry_in must equal
	// wide_u16[k] + carry_out * 2^16. We solve for carry_out:
	//   carry_out = (col_partial_sum + carry_in - wide_u16[k]) / 2^16
	//
	// Helper closures for u16 view.
	let a_u16 = |i: usize| -> u32 {
		if i % 2 == 0 {
			u32::from(a_lo[i / 2])
		} else {
			u32::from(a_hi[i / 2])
		}
	};
	let b_u16 = |j: usize| -> u32 {
		if j % 2 == 0 {
			u32::from(b_lo[j / 2])
		} else {
			u32::from(b_hi[j / 2])
		}
	};
	let wide_u16_view = |k: usize| -> u32 {
		if k % 2 == 0 {
			u32::from(wide_lo[k / 2])
		} else {
			u32::from(wide_hi[k / 2])
		}
	};

	let mut carry = [0u32; NUM_COLS_SCHOOLBOOK];
	let mut carry_in: u64 = 0;
	for k in 0..NUM_COLS_SCHOOLBOOK {
		let mut col_partial: u64 = 0;
		for i in 0..U16_NUM_SUBLIMBS {
			if i > k {
				continue;
			}
			let j = k - i;
			if j >= U16_NUM_SUBLIMBS {
				continue;
			}
			col_partial += u64::from(a_u16(i)) * u64::from(b_u16(j));
		}
		let total = col_partial + carry_in;
		let wide_k = u64::from(wide_u16_view(k));
		assert!(
			total >= wide_k,
			"build_field_mul_trace_row: column {} balance failed (col={}, carry_in={}, wide_u16={})",
			k,
			col_partial,
			carry_in,
			wide_k,
		);
		let carry_out = (total - wide_k) / (1u64 << 16);
		// Sanity: carry_out should fit in u32 (typically much smaller).
		assert!(carry_out < u64::from(u32::MAX), "carry overflow at column {}", k);
		carry[k] = carry_out as u32;
		carry_in = carry_out;
	}
	assert_eq!(
		carry[NUM_COLS_SCHOOLBOOK - 1],
		0,
		"top-balance closure violated: schoolbook didn't balance at column 31",
	);

	// u16 splits of carries.
	let mut carry_lo = [0u16; NUM_COLS_SCHOOLBOOK];
	let mut carry_hi = [0u16; NUM_COLS_SCHOOLBOOK];
	for k in 0..NUM_COLS_SCHOOLBOOK {
		carry_lo[k] = (carry[k] & 0xFFFF) as u16;
		carry_hi[k] = (carry[k] >> 16) as u16;
	}

	// ─── M2 witnesses: Barrett reduction ──────────────────────────────

	// Compute q = floor(wide / p) and c = wide mod p via num-bigint.
	let mut wide_bytes = [0u8; 64];
	for (m, limb) in wide.iter().enumerate() {
		wide_bytes[m * 4..(m + 1) * 4].copy_from_slice(&limb.to_le_bytes());
	}
	let wide_big = BigUint::from_bytes_le(&wide_bytes);
	let p_big = BigUint::from_bytes_le(&limbs_to_bytes(&P_LIMBS));
	let (q_big, c_big) = wide_big.div_rem(&p_big);

	// q fits in 8 u32 limbs because wide < p^2 implies q < p.
	let mut q_bytes_padded = q_big.to_bytes_le();
	q_bytes_padded.resize(32, 0);
	let mut q_bytes = [0u8; 32];
	q_bytes.copy_from_slice(&q_bytes_padded[..32]);
	let q = bytes_to_limbs(&q_bytes);

	// c also fits in 8 u32 limbs (canonical: < p).
	let mut c_bytes_padded = c_big.to_bytes_le();
	c_bytes_padded.resize(32, 0);
	let mut c_bytes = [0u8; 32];
	c_bytes.copy_from_slice(&c_bytes_padded[..32]);
	let c = bytes_to_limbs(&c_bytes);

	// qp_wide = q * p as 16-limb wide integer.
	let qp_wide = wide_mul(&q, &P_LIMBS);

	// u16 splits.
	let mut q_lo = [0u16; FIELD_NUM_LIMBS];
	let mut q_hi = [0u16; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		q_lo[i] = (q[i] & 0xFFFF) as u16;
		q_hi[i] = (q[i] >> 16) as u16;
	}
	let mut qp_wide_lo = [0u16; WIDE_NUM_LIMBS];
	let mut qp_wide_hi = [0u16; WIDE_NUM_LIMBS];
	for m in 0..WIDE_NUM_LIMBS {
		qp_wide_lo[m] = (qp_wide[m] & 0xFFFF) as u16;
		qp_wide_hi[m] = (qp_wide[m] >> 16) as u16;
	}
	let mut c_lo = [0u16; FIELD_NUM_LIMBS];
	let mut c_hi = [0u16; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		c_lo[i] = (c[i] & 0xFFFF) as u16;
		c_hi[i] = (c[i] >> 16) as u16;
	}

	// q*p schoolbook carry chain. Same shape as the a*b schoolbook
	// above: per-column witnessed carries derived by walking columns
	// low-to-high and solving for carry_out at each step.
	let q_u16 = |i: usize| -> u32 {
		if i % 2 == 0 {
			u32::from(q_lo[i / 2])
		} else {
			u32::from(q_hi[i / 2])
		}
	};
	let p_u16_const = |k: usize| -> u32 {
		let m = k / 2;
		if k % 2 == 0 {
			P_LIMBS[m] & 0xFFFF
		} else {
			P_LIMBS[m] >> 16
		}
	};
	let qp_wide_u16_view = |k: usize| -> u32 {
		if k % 2 == 0 {
			u32::from(qp_wide_lo[k / 2])
		} else {
			u32::from(qp_wide_hi[k / 2])
		}
	};

	let mut qp_carry = [0u32; NUM_COLS_SCHOOLBOOK];
	let mut carry_in: u64 = 0;
	for k in 0..NUM_COLS_SCHOOLBOOK {
		let mut col_partial: u64 = 0;
		for i in 0..U16_NUM_SUBLIMBS {
			if i > k {
				continue;
			}
			let j = k - i;
			if j >= U16_NUM_SUBLIMBS {
				continue;
			}
			col_partial += u64::from(q_u16(i)) * u64::from(p_u16_const(j));
		}
		let total = col_partial + carry_in;
		let qp_k = u64::from(qp_wide_u16_view(k));
		assert!(
			total >= qp_k,
			"build_field_mul_trace_row: qp schoolbook column {} balance failed",
			k,
		);
		let carry_out = (total - qp_k) / (1u64 << 16);
		assert!(carry_out < u64::from(u32::MAX), "qp_carry overflow at column {}", k);
		qp_carry[k] = carry_out as u32;
		carry_in = carry_out;
	}
	assert_eq!(qp_carry[NUM_COLS_SCHOOLBOOK - 1], 0, "qp top-balance violated");

	let mut qp_carry_lo = [0u16; NUM_COLS_SCHOOLBOOK];
	let mut qp_carry_hi = [0u16; NUM_COLS_SCHOOLBOOK];
	for k in 0..NUM_COLS_SCHOOLBOOK {
		qp_carry_lo[k] = (qp_carry[k] & 0xFFFF) as u16;
		qp_carry_hi[k] = (qp_carry[k] >> 16) as u16;
	}

	// Wide subtraction: wide - qp_wide = c (with c zero-padded to 16
	// limbs). Compute the limb-wise borrow chain.
	let mut qp_borrow = [0u8; WIDE_NUM_LIMBS];
	let mut borrow_in: i64 = 0;
	for m in 0..WIDE_NUM_LIMBS {
		let c_contrib: i64 = if m < FIELD_NUM_LIMBS {
			i64::from(c[m])
		} else {
			0
		};
		let lhs: i64 = i64::from(wide[m]) - i64::from(qp_wide[m]) - borrow_in;
		let d: i64 = lhs - c_contrib;
		if d < 0 {
			qp_borrow[m] = 1;
			borrow_in = 1;
		} else {
			qp_borrow[m] = 0;
			borrow_in = 0;
		}
	}
	assert_eq!(
		qp_borrow[WIDE_NUM_LIMBS - 1],
		0,
		"wide-subtraction top-borrow closure violated (witness builder bug or wide < q*p)",
	);

	// Canonical-form witness on c: c_complement = p_minus_one - c.
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
		"canonical-form top-borrow closure violated (c >= p)",
	);

	let mut c_comp_lo = [0u16; FIELD_NUM_LIMBS];
	let mut c_comp_hi = [0u16; FIELD_NUM_LIMBS];
	for i in 0..FIELD_NUM_LIMBS {
		c_comp_lo[i] = (c_complement[i] & 0xFFFF) as u16;
		c_comp_hi[i] = (c_complement[i] >> 16) as u16;
	}

	FieldMulTraceRow {
		a: *a,
		b: *b,
		a_lo,
		a_hi,
		b_lo,
		b_hi,
		wide,
		wide_lo,
		wide_hi,
		carry,
		carry_lo,
		carry_hi,
		q,
		q_lo,
		q_hi,
		qp_wide,
		qp_wide_lo,
		qp_wide_hi,
		qp_carry,
		qp_carry_lo,
		qp_carry_hi,
		c,
		c_lo,
		c_hi,
		c_complement,
		c_complement_borrow,
		c_comp_lo,
		c_comp_hi,
		qp_borrow,
	}
}

impl FieldMulTraceRow {
	pub fn to_trace_vec<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
		let mut out = Vec::with_capacity(FIELD_MUL_NUM_COLS);
		// M1 block.
		for &v in &self.a {
			out.push(F::from_u32(v));
		}
		for &v in &self.b {
			out.push(F::from_u32(v));
		}
		for &v in &self.a_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.a_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.b_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.b_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.wide {
			out.push(F::from_u32(v));
		}
		for &v in &self.wide_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.wide_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.carry {
			out.push(F::from_u32(v));
		}
		for &v in &self.carry_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.carry_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		debug_assert_eq!(out.len(), FIELD_MUL_M1_NUM_COLS);
		// M2 block.
		for &v in &self.q {
			out.push(F::from_u32(v));
		}
		for &v in &self.q_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.q_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.qp_wide {
			out.push(F::from_u32(v));
		}
		for &v in &self.qp_wide_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.qp_wide_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.qp_carry {
			out.push(F::from_u32(v));
		}
		for &v in &self.qp_carry_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.qp_carry_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c {
			out.push(F::from_u32(v));
		}
		for &v in &self.c_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c_complement {
			out.push(F::from_u32(v));
		}
		for &v in &self.c_complement_borrow {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c_comp_lo {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.c_comp_hi {
			out.push(F::from_u32(u32::from(v)));
		}
		for &v in &self.qp_borrow {
			out.push(F::from_u32(u32::from(v)));
		}
		debug_assert_eq!(out.len(), FIELD_MUL_NUM_COLS);
		out
	}

	pub fn to_trace_matrix<F: PrimeCharacteristicRing + Send + Sync>(
		&self,
	) -> RowMajorMatrix<F> {
		RowMajorMatrix::new(self.to_trace_vec::<F>(), FIELD_MUL_NUM_COLS)
	}
}
