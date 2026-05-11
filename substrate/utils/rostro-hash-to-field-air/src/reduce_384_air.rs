// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! AIR for the 384-bit → F_p25519 Barrett reduction.
//!
//! See [`crate::reduce_384`] for the algorithm + witness shape. This module
//! implements the constraint set + bus wiring; trace builder consumes a
//! [`Reduce384Witness`] from that module.
//!
//! Single-row AIR. One row = one Barrett reduction.
//!
//! ## Column layout (154 columns)
//!
//! | Segment             | Width | Range / type        |
//! |---|---|---|
//! | W[12]               | 12    | u32 (u16-split)     |
//! | W_lo16[12]          | 12    | u16                 |
//! | W_hi16[12]          | 12    | u16                 |
//! | prod[5]             | 5     | u32 (u16-split)     |
//! | prod_lo16[5]        | 5     | u16                 |
//! | prod_hi16[5]        | 5     | u16                 |
//! | prod_carries[5]     | 5     | ≤ 38                |
//! | t[8]                | 8     | u32 (u16-split)     |
//! | t_lo16[8]           | 8     | u16                 |
//! | t_hi16[8]           | 8     | u16                 |
//! | t_overflow          | 1     | bool                |
//! | add_carries[8]      | 8     | bool                |
//! | k                   | 1     | ∈ {0, 1, 2}         |
//! | u[8]                | 8     | u32 (u16-split)     |
//! | u_lo16[8]           | 8     | u16                 |
//! | u_hi16[8]           | 8     | u16                 |
//! | red_carries[8]      | 8     | ≤ 3                 |
//! | canon_borrows[8]    | 8     | bool                |
//! | canon_diff[8]       | 8     | u32 (u16-split)     |
//! | canon_diff_lo16[8]  | 8     | u16                 |
//! | canon_diff_hi16[8]  | 8     | u16                 |
//!
//! ## Constraints
//!
//! 1. **u16 decomposition** for each u32 cell: `cell == lo + 2^16 · hi` and
//!    push `(lo,)` and `(hi,)` to `bus_u16_range`. Soundness: lo and hi being
//!    u16-bounded forces the cell into `[0, 2^32)`.
//! 2. **Booleans**: `assert_bool` on every t_overflow / add_carries[i] /
//!    canon_borrows[i].
//! 3. **k constraint**: `k(k-1)(k-2) == 0`.
//! 4. **prod chain** (i ∈ 0..4): `prod[i] + 2^32 · prod_carries[i] ==
//!    38 · W[8+i] + prod_carries[i-1]` (carry_in for i=0 is 0). Closure:
//!    `prod[4] == prod_carries[3]` (top limb = final carry only).
//!    `prod_carries[i]` pushed to `bus_u16_range` (bound ≤ 38, u16 lookup
//!    is loose but safe).
//! 5. **T add chain** (i ∈ 0..7): `t[i] + 2^32 · add_carries[i] == W[i] +
//!    prod_padded[i] + add_carries[i-1]` where prod_padded[i] = prod[i] for
//!    i < 5 else 0. Closure at i=7: `add_carries[7] == t_overflow`.
//! 6. **Reduction-add chain** (i ∈ 0..7): `u[i] + k · P_LIMBS[i] +
//!    red_carries[i-1] == t[i] + 2^32 · red_carries[i]`. Closure at i=7:
//!    `red_carries[7] == t_overflow`. `red_carries[i]` pushed to
//!    `bus_u16_range` (bound ≤ 3, loose lookup).
//! 7. **Canonical check** (i ∈ 0..7): per-limb borrow-subtraction identity
//!    `canon_diff[i] + 2^32 · canon_borrows[i] == p_minus_1[i] - u[i] -
//!    canon_borrows[i-1]` with `canon_diff[i]` u32-bounded (u16-split +
//!    BUS_U16_RANGE). Closure at i=7: `canon_borrows[7] == 0`. The diff
//!    witness is what makes this sufficient — without it, an adversary
//!    could set all borrows to 0 and pass the closure trivially.
//! 8. **Service-bus receive**: `(W[12] || u[8])` on [`crate::reduce_384::BUS_REDUCE_384`]
//!    with multiplicity −1.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use rostro_curve25519::field::{FIELD_NUM_LIMBS, P_LIMBS};

use crate::reduce_384::{
	Reduce384Witness, BUS_REDUCE_384, PROD_LIMBS, REDUCE_384_INPUT_LIMBS, W_HI_LIMBS,
};

// ─── Column layout ────────────────────────────────────────────────────────

const COL_W: usize = 0;
const COL_W_LO16: usize = COL_W + REDUCE_384_INPUT_LIMBS;
const COL_W_HI16: usize = COL_W_LO16 + REDUCE_384_INPUT_LIMBS;
const COL_PROD: usize = COL_W_HI16 + REDUCE_384_INPUT_LIMBS;
const COL_PROD_LO16: usize = COL_PROD + PROD_LIMBS;
const COL_PROD_HI16: usize = COL_PROD_LO16 + PROD_LIMBS;
const COL_PROD_CARRIES: usize = COL_PROD_HI16 + PROD_LIMBS;
const COL_T: usize = COL_PROD_CARRIES + PROD_LIMBS;
const COL_T_LO16: usize = COL_T + FIELD_NUM_LIMBS;
const COL_T_HI16: usize = COL_T_LO16 + FIELD_NUM_LIMBS;
const COL_T_OVERFLOW: usize = COL_T_HI16 + FIELD_NUM_LIMBS;
const COL_ADD_CARRIES: usize = COL_T_OVERFLOW + 1;
const COL_K: usize = COL_ADD_CARRIES + FIELD_NUM_LIMBS;
const COL_U: usize = COL_K + 1;
const COL_U_LO16: usize = COL_U + FIELD_NUM_LIMBS;
const COL_U_HI16: usize = COL_U_LO16 + FIELD_NUM_LIMBS;
const COL_RED_CARRIES: usize = COL_U_HI16 + FIELD_NUM_LIMBS;
const COL_CANON_BORROWS: usize = COL_RED_CARRIES + FIELD_NUM_LIMBS;
const COL_CANON_DIFF: usize = COL_CANON_BORROWS + FIELD_NUM_LIMBS;
const COL_CANON_DIFF_LO16: usize = COL_CANON_DIFF + FIELD_NUM_LIMBS;
const COL_CANON_DIFF_HI16: usize = COL_CANON_DIFF_LO16 + FIELD_NUM_LIMBS;

/// Total trace column width.
pub const REDUCE_384_AIR_NUM_COLS: usize = COL_CANON_DIFF_HI16 + FIELD_NUM_LIMBS;

/// Single-row AIR.
pub const REDUCE_384_AIR_TRACE_HEIGHT: usize = 1;

// ─── AIR ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Reduce384Air {
	/// Service bus this AIR PROVIDES (receives queries on).
	pub bus_query: &'static str,
	/// Bus this AIR PUSHES TO for every u16 range check.
	pub bus_u16_range: &'static str,
}

impl Reduce384Air {
	pub const fn new(bus_query: &'static str, bus_u16_range: &'static str) -> Self {
		Self { bus_query, bus_u16_range }
	}

	/// The default service bus name. Always equals [`BUS_REDUCE_384`]. Use
	/// when there is exactly one Reduce384Air instance per batch (the typical
	/// case for HashToFieldAir consumers).
	pub const fn default_buses(bus_u16_range: &'static str) -> Self {
		Self { bus_query: BUS_REDUCE_384, bus_u16_range }
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for Reduce384Air {
	fn width(&self) -> usize {
		REDUCE_384_AIR_NUM_COLS
	}
}

/// `p25519 - 1` as 8 u32 LE limbs. Const-eval friendly.
const fn p_minus_1_limbs() -> [u32; FIELD_NUM_LIMBS] {
	let mut arr = P_LIMBS;
	arr[0] = arr[0].wrapping_sub(1);
	arr
}

const P_MINUS_1: [u32; FIELD_NUM_LIMBS] = p_minus_1_limbs();

impl<AB: InteractionBuilder> Air<AB> for Reduce384Air
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		// Pull every column slice once.
		let w: [AB::Var; REDUCE_384_INPUT_LIMBS] =
			core::array::from_fn(|i| local[COL_W + i]);
		let w_lo16: [AB::Var; REDUCE_384_INPUT_LIMBS] =
			core::array::from_fn(|i| local[COL_W_LO16 + i]);
		let w_hi16: [AB::Var; REDUCE_384_INPUT_LIMBS] =
			core::array::from_fn(|i| local[COL_W_HI16 + i]);
		let prod: [AB::Var; PROD_LIMBS] = core::array::from_fn(|i| local[COL_PROD + i]);
		let prod_lo16: [AB::Var; PROD_LIMBS] =
			core::array::from_fn(|i| local[COL_PROD_LO16 + i]);
		let prod_hi16: [AB::Var; PROD_LIMBS] =
			core::array::from_fn(|i| local[COL_PROD_HI16 + i]);
		let prod_carries: [AB::Var; PROD_LIMBS] =
			core::array::from_fn(|i| local[COL_PROD_CARRIES + i]);
		let t: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_T + i]);
		let t_lo16: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_T_LO16 + i]);
		let t_hi16: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_T_HI16 + i]);
		let t_overflow: AB::Var = local[COL_T_OVERFLOW];
		let add_carries: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_ADD_CARRIES + i]);
		let k: AB::Var = local[COL_K];
		let u: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_U + i]);
		let u_lo16: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_U_LO16 + i]);
		let u_hi16: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_U_HI16 + i]);
		let red_carries: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_RED_CARRIES + i]);
		let canon_borrows: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_CANON_BORROWS + i]);
		let canon_diff: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_CANON_DIFF + i]);
		let canon_diff_lo16: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_CANON_DIFF_LO16 + i]);
		let canon_diff_hi16: [AB::Var; FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| local[COL_CANON_DIFF_HI16 + i]);

		let radix_u16 = AB::Expr::from_u64(1u64 << 16);
		let radix_u32 = AB::Expr::from_u64(1u64 << 32);

		// ─── (1) u16 decomposition + range-check pushes ────────────────────
		// W
		for i in 0..REDUCE_384_INPUT_LIMBS {
			builder.assert_zero(
				w[i].into() - w_lo16[i].into() - radix_u16.clone() * w_hi16[i].into(),
			);
			builder.push_interaction(self.bus_u16_range, [w_lo16[i]], AB::Expr::ONE, 1);
			builder.push_interaction(self.bus_u16_range, [w_hi16[i]], AB::Expr::ONE, 1);
		}
		// prod
		for i in 0..PROD_LIMBS {
			builder.assert_zero(
				prod[i].into()
					- prod_lo16[i].into()
					- radix_u16.clone() * prod_hi16[i].into(),
			);
			builder.push_interaction(self.bus_u16_range, [prod_lo16[i]], AB::Expr::ONE, 1);
			builder.push_interaction(self.bus_u16_range, [prod_hi16[i]], AB::Expr::ONE, 1);
		}
		// T
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				t[i].into() - t_lo16[i].into() - radix_u16.clone() * t_hi16[i].into(),
			);
			builder.push_interaction(self.bus_u16_range, [t_lo16[i]], AB::Expr::ONE, 1);
			builder.push_interaction(self.bus_u16_range, [t_hi16[i]], AB::Expr::ONE, 1);
		}
		// u
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_zero(
				u[i].into() - u_lo16[i].into() - radix_u16.clone() * u_hi16[i].into(),
			);
			builder.push_interaction(self.bus_u16_range, [u_lo16[i]], AB::Expr::ONE, 1);
			builder.push_interaction(self.bus_u16_range, [u_hi16[i]], AB::Expr::ONE, 1);
		}

		// ─── (2) Booleans ──────────────────────────────────────────────────
		builder.assert_bool(t_overflow);
		for i in 0..FIELD_NUM_LIMBS {
			builder.assert_bool(add_carries[i]);
			builder.assert_bool(canon_borrows[i]);
		}

		// ─── (3) k ∈ {0, 1, 2} ─────────────────────────────────────────────
		// k * (k - 1) * (k - 2) == 0  (degree 3)
		let k_e: AB::Expr = k.into();
		builder.assert_zero(
			k_e.clone() * (k_e.clone() - AB::Expr::ONE) * (k_e.clone() - AB::Expr::from_u64(2)),
		);

		// ─── (4) prod chain: prod = 38 · W_hi ──────────────────────────────
		// prod[i] + 2^32 · prod_carries[i] == 38 · W[8 + i] + prod_carries[i-1]
		// (i ∈ 0..W_HI_LIMBS), with prod_carries[-1] = 0.
		// Closure for the top prod limb (index 4): prod[4] == prod_carries[3].
		let const_38 = AB::Expr::from_u64(38);
		for i in 0..W_HI_LIMBS {
			let carry_in: AB::Expr = if i == 0 {
				AB::Expr::ZERO
			} else {
				prod_carries[i - 1].into()
			};
			builder.assert_zero(
				prod[i].into() + radix_u32.clone() * prod_carries[i].into()
					- const_38.clone() * w[FIELD_NUM_LIMBS + i].into()
					- carry_in,
			);
			// Range-check the carry: pushes to BUS_U16_RANGE (carry ≤ 38, u16
			// is loose but safe).
			builder.push_interaction(
				self.bus_u16_range,
				[prod_carries[i]],
				AB::Expr::ONE,
				1,
			);
		}
		// Top limb closure: only the final carry contributes (no W_hi entry
		// at position 4).
		builder.assert_zero(prod[W_HI_LIMBS].into() - prod_carries[W_HI_LIMBS - 1].into());
		// And prod_carries[W_HI_LIMBS] is unused (top closure gives it no
		// meaning); range-check it anyway to keep the layout uniform.
		builder.push_interaction(
			self.bus_u16_range,
			[prod_carries[W_HI_LIMBS]],
			AB::Expr::ONE,
			1,
		);

		// ─── (5) T add chain: T = W_lo + prod_padded ───────────────────────
		// Padded: prod_padded[i] = prod[i] for i < 5, else 0.
		for i in 0..FIELD_NUM_LIMBS {
			let carry_in: AB::Expr = if i == 0 {
				AB::Expr::ZERO
			} else {
				add_carries[i - 1].into()
			};
			let prod_pad: AB::Expr =
				if i < PROD_LIMBS { prod[i].into() } else { AB::Expr::ZERO };
			builder.assert_zero(
				t[i].into() + radix_u32.clone() * add_carries[i].into()
					- w[i].into() - prod_pad
					- carry_in,
			);
		}
		// Final carry equals the overflow bit (closes T at bit 256).
		builder.assert_zero(add_carries[FIELD_NUM_LIMBS - 1].into() - t_overflow.into());

		// ─── (6) Reduction-add: u + k · p == T_full ────────────────────────
		// u[i] + k · P_LIMBS[i] + red_carries[i-1] == t[i] + 2^32 · red_carries[i]
		for i in 0..FIELD_NUM_LIMBS {
			let carry_in: AB::Expr = if i == 0 {
				AB::Expr::ZERO
			} else {
				red_carries[i - 1].into()
			};
			let p_const = AB::Expr::from_u64(P_LIMBS[i] as u64);
			builder.assert_zero(
				u[i].into() + k_e.clone() * p_const + carry_in
					- t[i].into() - radix_u32.clone() * red_carries[i].into(),
			);
			// Range-check the reduction carry (≤ 3, u16 lookup loose but safe).
			builder.push_interaction(
				self.bus_u16_range,
				[red_carries[i]],
				AB::Expr::ONE,
				1,
			);
		}
		// Final reduction carry equals overflow bit (closes the identity).
		builder.assert_zero(
			red_carries[FIELD_NUM_LIMBS - 1].into() - t_overflow.into(),
		);

		// ─── (7) Canonical check: u < p via (p - 1) - u borrow chain ───────
		// Per limb: canon_diff[i] + 2^32 · canon_borrows[i] ==
		//           p_minus_1[i] - u[i] - canon_borrows[i-1]
		// where canon_diff[i] is u32-bounded (u16-split below). Closure
		// canon_borrows[7] == 0 forces u ≤ p - 1, i.e., u < p.
		//
		// Soundness: u[i] is u32-bounded (constraint 1), canon_borrows[i]
		// is boolean (constraint 2), canon_diff[i] is u32-bounded (this
		// section). The identity has a unique solution for (canon_diff[i],
		// canon_borrows[i]) given fixed inputs, because canon_diff[i] ∈
		// [0, 2^32) and 2^32 · canon_borrows[i] ∈ {0, 2^32} are non-overlapping
		// addition zones.
		for i in 0..FIELD_NUM_LIMBS {
			// u16 decomposition + range checks for canon_diff[i].
			builder.assert_zero(
				canon_diff[i].into()
					- canon_diff_lo16[i].into()
					- radix_u16.clone() * canon_diff_hi16[i].into(),
			);
			builder.push_interaction(
				self.bus_u16_range,
				[canon_diff_lo16[i]],
				AB::Expr::ONE,
				1,
			);
			builder.push_interaction(
				self.bus_u16_range,
				[canon_diff_hi16[i]],
				AB::Expr::ONE,
				1,
			);

			// Borrow-chain identity:
			//   canon_diff[i] + u[i] + borrow_in == p_minus_1[i] + 2^32 · canon_borrows[i]
			// Derivation: raw = p_minus_1[i] - u[i] - borrow_in. If raw ≥ 0:
			// canon_diff[i] = raw, canon_borrows[i] = 0. Else: canon_diff[i] =
			// raw + 2^32, canon_borrows[i] = 1. Either way the identity holds.
			let borrow_in: AB::Expr = if i == 0 {
				AB::Expr::ZERO
			} else {
				canon_borrows[i - 1].into()
			};
			let p_minus_1_const = AB::Expr::from_u64(P_MINUS_1[i] as u64);
			builder.assert_zero(
				canon_diff[i].into() + u[i].into() + borrow_in
					- p_minus_1_const - radix_u32.clone() * canon_borrows[i].into(),
			);
		}
		// Closure: final borrow must be 0 (i.e., (p-1) - u didn't underflow → u ≤ p-1).
		builder.assert_zero(canon_borrows[FIELD_NUM_LIMBS - 1].into());

		// ─── (8) Service bus receive ───────────────────────────────────────
		// Payload: W[12] || u[8] = 20 cells.
		let payload: [AB::Expr; REDUCE_384_INPUT_LIMBS + FIELD_NUM_LIMBS] =
			core::array::from_fn(|i| {
				if i < REDUCE_384_INPUT_LIMBS {
					w[i].into()
				} else {
					u[i - REDUCE_384_INPUT_LIMBS].into()
				}
			});
		builder.push_interaction(self.bus_query, payload, -AB::Expr::ONE, 1);
	}
}

// ─── Trace builder ────────────────────────────────────────────────────────

/// Build the trace row from a precomputed [`Reduce384Witness`].
pub fn build_reduce_384_trace(witness: &Reduce384Witness) -> RowMajorMatrix<Goldilocks> {
	let mut cells = Vec::with_capacity(REDUCE_384_AIR_NUM_COLS);

	// W[12]
	for &v in &witness.w_input {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// W lo/hi 16
	for &v in &witness.w_input {
		cells.push(Goldilocks::from_u64(u64::from(v & 0xFFFF)));
	}
	for &v in &witness.w_input {
		cells.push(Goldilocks::from_u64(u64::from(v >> 16)));
	}
	// prod[5]
	for &v in &witness.prod {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// prod lo/hi 16
	for &v in &witness.prod {
		cells.push(Goldilocks::from_u64(u64::from(v & 0xFFFF)));
	}
	for &v in &witness.prod {
		cells.push(Goldilocks::from_u64(u64::from(v >> 16)));
	}
	// prod_carries[5]
	for &v in &witness.prod_carries {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// T[8]
	for &v in &witness.t {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// T lo/hi 16
	for &v in &witness.t {
		cells.push(Goldilocks::from_u64(u64::from(v & 0xFFFF)));
	}
	for &v in &witness.t {
		cells.push(Goldilocks::from_u64(u64::from(v >> 16)));
	}
	// T_overflow
	cells.push(Goldilocks::from_u64(u64::from(witness.t_overflow)));
	// add_carries[8]
	for &v in &witness.add_carries {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// k
	cells.push(Goldilocks::from_u64(u64::from(witness.k)));
	// u[8]
	for &v in &witness.u {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// u lo/hi 16
	for &v in &witness.u {
		cells.push(Goldilocks::from_u64(u64::from(v & 0xFFFF)));
	}
	for &v in &witness.u {
		cells.push(Goldilocks::from_u64(u64::from(v >> 16)));
	}
	// red_carries[8]
	for &v in &witness.red_carries {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// canon_borrows[8]
	for &v in &witness.canon_borrows {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// canon_diff[8]
	for &v in &witness.canon_diff {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	// canon_diff lo/hi 16
	for &v in &witness.canon_diff {
		cells.push(Goldilocks::from_u64(u64::from(v & 0xFFFF)));
	}
	for &v in &witness.canon_diff {
		cells.push(Goldilocks::from_u64(u64::from(v >> 16)));
	}

	debug_assert_eq!(cells.len(), REDUCE_384_AIR_NUM_COLS);
	RowMajorMatrix::new(cells, REDUCE_384_AIR_NUM_COLS)
}
