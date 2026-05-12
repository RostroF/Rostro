// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-rsa2048-air
//!
//! Service AIR providing the 64-limb u32 schoolbook multiplication
//! primitive for RSA-2048 over Goldilocks. Consumed by the AA AIR's
//! modular exponentiation chain (`s^65537 mod N == EM`); each modular
//! multiply in the chain pushes one bus interaction onto
//! [`BUS_RSA2048_MUL`] with payload `(a[64], b[64], c[128])`, this
//! AIR provides one row per such interaction.
//!
//! ## Why a service AIR (vs inlined into the AA AIR)
//!
//! The AA AIR's modular exponentiation requires 17 modular multiplies
//! (16 squarings + 1 multiply for `e = 65537 = 2^16 + 1`). Each multiply
//! materializes ~8500 cells of partial-product + carry-chain state.
//! Inlining all 17 into the AA AIR would balloon its column count past
//! 140k cells; factoring out as a service AIR with a per-row multiply
//! drops the AA AIR's per-multiply cost to one bus push (256 payload
//! cells) and locates the multiplication machinery in one auditable
//! crate.
//!
//! Per the silo principle (`feedback_no_cross_purpose_files.md`), the
//! 64-limb shape is locked to RSA-2048. NIST-P256 (8 limbs), Brainpool
//! P-256 (8 limbs), and any future AA variants with different modulus
//! sizes get their own per-modulus multiply crates rather than
//! parameterising this one.
//!
//! ## Status (2026-05-12, C20a scaffold)
//!
//! - Crate registered in workspace, bus name + payload shape locked.
//! - AIR struct + `BaseAir` impl + minimal `eval()` (is_active
//!   boolean assertion + bus receive). No correctness constraints
//!   yet — the AIR accepts any `(a, b, c)` tuple. Marked unsafe to
//!   wire into the AA AIR until C20b lands the schoolbook constraints.
//! - Trace builder writes honest `c = a · b` using `num-bigint`-style
//!   limb arithmetic so the future constraint set has a reference
//!   trace to test against.
//!
//! **The next commit (C20b) lands the partial-product constraints + carry
//! chain + range checks**, at which point this AIR provides real
//! soundness for the multiply primitive.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

/// Service bus name for the RSA-2048 multiply.
/// Payload = `(a[64], b[64], c[128])` = 256 cells, all u32-limbed LE.
///
/// Caller AIRs push `+is_active` (positive multiplicity) onto this bus
/// per multiply requested. This AIR receives `-is_active` (negative
/// multiplicity) per row. LogUp balance forces every caller-pushed
/// `(a, b, c)` tuple to appear as a row in this AIR's trace, which
/// (once C20b's constraints land) is in turn proven to satisfy
/// `c == a · b` over 4096-bit unsigned integers.
pub const BUS_RSA2048_MUL: &str = "rostro-rsa2048-mul";

/// Number of u32 limbs in an RSA-2048 operand (2048 / 32).
pub const RSA2048_LIMBS: usize = 64;

/// Number of u32 limbs in the product (2 × 2048 bits / 32).
pub const RSA2048_PRODUCT_LIMBS: usize = 2 * RSA2048_LIMBS;

/// Bus payload size: `a[64] + b[64] + c[128]`.
pub const BUS_PAYLOAD_LEN: usize = 2 * RSA2048_LIMBS + RSA2048_PRODUCT_LIMBS;

// ─── Column layout (scaffold) ──────────────────────────────────────────────
//
// Minimal columns for C20a. C20b extends this with partial-product
// and carry-chain witness columns. The layout below is forward-
// compatible: C20b adds new columns after `COL_C_END` without
// renumbering existing offsets.

/// Column index of the `is_active` boolean (1 cell, 0 or 1).
///
/// Set to 1 on rows representing a real multiply; 0 on padding rows
/// (Plonky3 traces are power-of-two height, so padding is common).
/// Padding rows skip the bus push AND would skip the future
/// correctness constraints, so unused trace space is "free."
pub const COL_IS_ACTIVE: usize = 0;

/// Starting column of input `a` (64 u32 limbs, LE).
pub const COL_A: usize = COL_IS_ACTIVE + 1;

/// Starting column of input `b` (64 u32 limbs, LE).
pub const COL_B: usize = COL_A + RSA2048_LIMBS;

/// Starting column of output `c = a · b` (128 u32 limbs, LE).
pub const COL_C: usize = COL_B + RSA2048_LIMBS;

/// One-past-the-end of the output block. Used as the insertion point
/// for C20b's partial-product columns.
pub const COL_C_END: usize = COL_C + RSA2048_PRODUCT_LIMBS;

/// Trace column count (scaffold). Grows in C20b to include
/// `pp_lo[64][64] + pp_hi[64][64] + carry[129]`.
pub const NUM_COLS: usize = COL_C_END;

// ─── AIR ───────────────────────────────────────────────────────────────────

/// Per-row schoolbook multiply for RSA-2048 operands. Stateless;
/// constructed once per batch.
///
/// One row = one multiply. Multiple multiplies in a batch (e.g. the
/// 17 needed for `s^65537`) live as multiple rows in this AIR's
/// trace; the caller AIR pushes one bus interaction per multiply,
/// LogUp balances against the rows.
#[derive(Clone, Copy, Debug)]
pub struct Rsa2048MulAir;

impl<F: Field> BaseAir<F> for Rsa2048MulAir {
	fn width(&self) -> usize {
		NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for Rsa2048MulAir
where
	AB::F: Field + Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		// (1) is_active is boolean.
		let is_active: AB::Var = local[COL_IS_ACTIVE].clone();
		builder.assert_bool(is_active.clone());

		// (2) Service-bus receive: -is_active per row. The caller's
		//     `+is_active` push (one per multiply request) must
		//     balance against the receives. Payload is the row's
		//     (a, b, c) cells in declaration order.
		let mut payload: Vec<AB::Expr> = Vec::with_capacity(BUS_PAYLOAD_LEN);
		for i in 0..RSA2048_LIMBS {
			payload.push(local[COL_A + i].clone().into());
		}
		for i in 0..RSA2048_LIMBS {
			payload.push(local[COL_B + i].clone().into());
		}
		for i in 0..RSA2048_PRODUCT_LIMBS {
			payload.push(local[COL_C + i].clone().into());
		}
		let neg_active: AB::Expr = AB::Expr::ZERO - is_active.into();
		builder.push_interaction(BUS_RSA2048_MUL, payload, neg_active, 1);

		// TODO(C20b): partial-product constraints
		//   For each (i, j) in 0..64 × 0..64:
		//     assert is_active · (a[i] · b[j] - pp_lo[i][j] - 2^32 · pp_hi[i][j]) == 0
		//
		// TODO(C20b): carry-chain constraints
		//   For each k in 0..128:
		//     Let pp_sum_k = Σ_{i+j=k} pp_lo[i][j] + Σ_{i+j=k-1} pp_hi[i][j]
		//     assert is_active · (pp_sum_k + carry[k] - c[k] - 2^32 · carry[k+1]) == 0
		//   Boundary: carry[0] == 0 (asserted), carry[128] == 0 (asserted: no overflow).
		//
		// TODO(C20b): range checks
		//   Every u32 cell (a, b, c, pp_lo, pp_hi, carry) pushed on
		//   BUS_U16_RANGE (split into low/high u16 halves) — same
		//   pattern as rostro-curve25519::field_mul_air. Multiplicity
		//   gated on is_active so padding rows don't inflate lookup
		//   counts.
		//
		// Until C20b lands, this AIR proves NOTHING about c being
		// equal to a · b. The bus balance only enforces that whatever
		// (a, b, c) tuple the caller pushed appears as a row here,
		// not that the tuple is a valid multiply. Do not wire the
		// AA AIR's modexp to push on BUS_RSA2048_MUL until C20b.
	}
}

// ─── Witness side ──────────────────────────────────────────────────────────

/// Compute `c = a · b` as a 128-limb LE u32 result via schoolbook
/// multiplication. Reference implementation for the AIR's trace
/// builder; honest output that the (forthcoming) constraint set
/// proves correctness of.
///
/// Mirrors the column layout the AIR will witness: each entry in
/// the returned product is a u32, with index 0 the least significant.
pub fn schoolbook_mul(
	a: &[u32; RSA2048_LIMBS],
	b: &[u32; RSA2048_LIMBS],
) -> [u32; RSA2048_PRODUCT_LIMBS] {
	let mut c = [0u32; RSA2048_PRODUCT_LIMBS];
	let mut carry_chain = [0u64; RSA2048_PRODUCT_LIMBS + 1];
	for i in 0..RSA2048_LIMBS {
		for j in 0..RSA2048_LIMBS {
			let pp = u64::from(a[i]) * u64::from(b[j]);
			carry_chain[i + j] = carry_chain[i + j].wrapping_add(pp & 0xFFFF_FFFF);
			// Propagate the local carry-out from this column's accumulator
			// up before storing, so the next iteration sees the reduced value.
			let mask_lo = carry_chain[i + j] & 0xFFFF_FFFF;
			let overflow = carry_chain[i + j] >> 32;
			carry_chain[i + j] = mask_lo;
			carry_chain[i + j + 1] = carry_chain[i + j + 1]
				.wrapping_add(overflow)
				.wrapping_add(pp >> 32);
		}
	}
	// Final carry sweep: each position's u64 accumulator must reduce to u32.
	for k in 0..RSA2048_PRODUCT_LIMBS {
		let lo = carry_chain[k] & 0xFFFF_FFFF;
		let hi = carry_chain[k] >> 32;
		c[k] = lo as u32;
		carry_chain[k + 1] = carry_chain[k + 1].wrapping_add(hi);
	}
	debug_assert_eq!(
		carry_chain[RSA2048_PRODUCT_LIMBS], 0,
		"schoolbook_mul overflowed past 128 limbs; inputs not u32?"
	);
	c
}

/// Build a single AIR trace row for one multiply. Fills the
/// `is_active = 1` slot plus the input + output cells; partial-product
/// and carry columns land in C20b. The returned row has length
/// [`NUM_COLS`] regardless.
pub fn build_mul_row(
	a: &[u32; RSA2048_LIMBS],
	b: &[u32; RSA2048_LIMBS],
) -> [Goldilocks; NUM_COLS] {
	let c = schoolbook_mul(a, b);
	let mut row = [Goldilocks::ZERO; NUM_COLS];
	row[COL_IS_ACTIVE] = Goldilocks::ONE;
	for i in 0..RSA2048_LIMBS {
		row[COL_A + i] = Goldilocks::from_u32(a[i]);
		row[COL_B + i] = Goldilocks::from_u32(b[i]);
	}
	for k in 0..RSA2048_PRODUCT_LIMBS {
		row[COL_C + k] = Goldilocks::from_u32(c[k]);
	}
	row
}

/// Build a padding row (`is_active = 0`, all other cells zero). Used
/// to pad the AIR's trace height to a power of two.
pub fn build_padding_row() -> [Goldilocks; NUM_COLS] {
	[Goldilocks::ZERO; NUM_COLS]
}

/// Build a complete trace as a `RowMajorMatrix` from a vector of
/// `(a, b)` input pairs. Pads with `is_active = 0` rows to the next
/// power of two.
pub fn build_trace(
	multiplies: &[([u32; RSA2048_LIMBS], [u32; RSA2048_LIMBS])],
) -> RowMajorMatrix<Goldilocks> {
	let n_active = multiplies.len();
	let height = n_active.next_power_of_two().max(1);
	let mut cells = Vec::with_capacity(height * NUM_COLS);
	for (a, b) in multiplies {
		cells.extend_from_slice(&build_mul_row(a, b));
	}
	for _ in n_active..height {
		cells.extend_from_slice(&build_padding_row());
	}
	RowMajorMatrix::new(cells, NUM_COLS)
}

#[cfg(test)]
mod tests;
