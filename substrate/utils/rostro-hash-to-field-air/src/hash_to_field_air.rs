// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! AIR for [`crate::hash_to_field`].
//!
//! Single-row AIR. One row = one `hash_to_field` invocation = mapping one
//! Goldilocks `private_nullifier` to `(u_0, u_1) ∈ F_p25519²`.
//!
//! ## Pipeline (mirrors [`crate::hash_to_field_one`])
//!
//! For each `i ∈ {0, 1}`:
//! 1. Push `(input_state[8] || output_state[8])` to a sponge bus where
//!    `input_state = (private_nullifier, i, dst[6])` and
//!    `output_state = w_i[8]` (we use only `w_i[0..6]` downstream but bus
//!    balance requires all 8).
//! 2. Pack each `w_i[k]` (`k ∈ 0..6`) into two u32 limbs `W_i[2k]`,
//!    `W_i[2k+1]` such that `w_i[k] = W_i[2k] + 2³² · W_i[2k+1]` AND the
//!    encoding is canonical (rejects the `W_i[2k+1] = 0xFFFFFFFF AND
//!    W_i[2k] ≥ 1` non-canonical wrap of `Goldilocks`).
//! 3. Push `(W_i[12] || u_i[8])` to a Reduce384 bus where Reduce384Air
//!    proves `u_i = W_i mod p25519`.
//!
//! Then receive `(private_nullifier, u_0[8], u_1[8])` on the service bus
//! [`BUS_HASH_TO_FIELD`].
//!
//! ## Range checks come "for free" via LogUp balance
//!
//! `W_i` and `u_i` cells are u32-bounded by Reduce384Air on the receive
//! side. LogUp balance forces our sent values to match exactly, so we
//! don't need our own u16-split + range checks for them.
//!
//! ## Canonicality guard
//!
//! For each Goldilocks → (u32, u32) pair `(low, high) = (W[2k], W[2k+1])`:
//! the sole non-canonical encoding satisfying the algebraic identity is
//! `(low ≥ 1, high = 0xFFFFFFFF)`. (Goldilocks `p_g = 2⁶⁴ - 2³² + 1`, so
//! the wrap range is exactly `[p_g, 2⁶⁴) = [(0xFFFFFFFF, 1), (0xFFFFFFFF, 2³²-1)]`
//! when written as `(high, low)`.) Without a guard, an attacker could
//! pick a `private_nullifier` whose sponge output `w_i[k]` admits both a
//! canonical and a non-canonical encoding, choose the non-canonical one,
//! and produce a different `u_i` — breaking determinism of `hash_to_field`
//! and forging multiple distinct nullifiers per passport.
//!
//! Per limb: witness `is_high_max ∈ {0, 1}` and `inv_diff ∈ Goldilocks`
//! such that:
//! - `is_high_max · (W[2k+1] - 0xFFFFFFFF) = 0` (forces `W[2k+1] = 0xFFFFFFFF`
//!   when `is_high_max = 1`)
//! - `(W[2k+1] - 0xFFFFFFFF) · inv_diff + is_high_max - 1 = 0` (zero-test:
//!   forces `is_high_max = 1` when `W[2k+1] = 0xFFFFFFFF`, else
//!   `is_high_max = 0`)
//! - `is_high_max · W[2k] = 0` (forces `W[2k] = 0` in the non-canonical
//!   wrap range, which is the only case where the encoding is non-canonical)
//!
//! Cost per Goldilocks limb: 2 cells, 4 constraints (1 boolean + 3 above).
//! 6 limbs × 2 calls = 24 cells, 48 constraints.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::reduce_384::REDUCE_384_INPUT_LIMBS;
use crate::{
	dst_packed, hash_to_field_one, COUNTER_U0, COUNTER_U1, SPONGE_WIDTH, SQUEEZE_LIMBS,
};
use rostro_curve25519::field::FIELD_NUM_LIMBS;

/// Service bus name for hash-to-field. Payload `(private_nullifier, u_0[8],
/// u_1[8])` = 17 cells.
pub const BUS_HASH_TO_FIELD: &str = "rostro-hash-to-field";

// ─── Column layout ────────────────────────────────────────────────────────

const COL_PRIVATE_NULLIFIER: usize = 0;
const COL_W_0_GOLDILOCKS: usize = COL_PRIVATE_NULLIFIER + 1;
const COL_W_1_GOLDILOCKS: usize = COL_W_0_GOLDILOCKS + SPONGE_WIDTH;
const COL_W_0_U32: usize = COL_W_1_GOLDILOCKS + SPONGE_WIDTH;
const COL_W_1_U32: usize = COL_W_0_U32 + REDUCE_384_INPUT_LIMBS;
const COL_CANON_HIGH_MAX_0: usize = COL_W_1_U32 + REDUCE_384_INPUT_LIMBS;
const COL_CANON_INV_DIFF_0: usize = COL_CANON_HIGH_MAX_0 + SQUEEZE_LIMBS;
const COL_CANON_HIGH_MAX_1: usize = COL_CANON_INV_DIFF_0 + SQUEEZE_LIMBS;
const COL_CANON_INV_DIFF_1: usize = COL_CANON_HIGH_MAX_1 + SQUEEZE_LIMBS;
const COL_U_0: usize = COL_CANON_INV_DIFF_1 + SQUEEZE_LIMBS;
const COL_U_1: usize = COL_U_0 + FIELD_NUM_LIMBS;

/// Total trace column width.
pub const HASH_TO_FIELD_AIR_NUM_COLS: usize = COL_U_1 + FIELD_NUM_LIMBS;

/// Single-row AIR.
pub const HASH_TO_FIELD_AIR_TRACE_HEIGHT: usize = 1;

// ─── AIR ──────────────────────────────────────────────────────────────────

/// AIR for one hash_to_field invocation.
///
/// Wires three service buses:
/// - `bus_query` — service bus this AIR provides (default
///   [`BUS_HASH_TO_FIELD`]).
/// - `bus_sponge_0`, `bus_sponge_1` — distinct sponge bus names so the two
///   Poseidon2 invocations within one hash_to_field call are
///   independently witnessed (see [`rostro_poseidon_sponge_air`] for sponge
///   bus discipline).
/// - `bus_reduce_0`, `bus_reduce_1` — distinct Reduce384 bus names so the
///   two Barrett reductions within one hash_to_field call are
///   independently witnessed.
#[derive(Clone, Debug)]
pub struct HashToFieldAir {
	pub bus_query: &'static str,
	pub bus_sponge_0: &'static str,
	pub bus_sponge_1: &'static str,
	pub bus_reduce_0: &'static str,
	pub bus_reduce_1: &'static str,
}

impl HashToFieldAir {
	pub const fn new(
		bus_query: &'static str,
		bus_sponge_0: &'static str,
		bus_sponge_1: &'static str,
		bus_reduce_0: &'static str,
		bus_reduce_1: &'static str,
	) -> Self {
		Self {
			bus_query,
			bus_sponge_0,
			bus_sponge_1,
			bus_reduce_0,
			bus_reduce_1,
		}
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for HashToFieldAir {
	fn width(&self) -> usize {
		HASH_TO_FIELD_AIR_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for HashToFieldAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let private_nullifier: AB::Var = local[COL_PRIVATE_NULLIFIER];
		let w_0_g: [AB::Var; SPONGE_WIDTH] =
			core::array::from_fn(|i| local[COL_W_0_GOLDILOCKS + i]);
		let w_1_g: [AB::Var; SPONGE_WIDTH] =
			core::array::from_fn(|i| local[COL_W_1_GOLDILOCKS + i]);
		let w_0_u32: [AB::Var; REDUCE_384_INPUT_LIMBS] =
			core::array::from_fn(|i| local[COL_W_0_U32 + i]);
		let w_1_u32: [AB::Var; REDUCE_384_INPUT_LIMBS] =
			core::array::from_fn(|i| local[COL_W_1_U32 + i]);
		let canon_high_max_0: [AB::Var; SQUEEZE_LIMBS] =
			core::array::from_fn(|i| local[COL_CANON_HIGH_MAX_0 + i]);
		let canon_inv_diff_0: [AB::Var; SQUEEZE_LIMBS] =
			core::array::from_fn(|i| local[COL_CANON_INV_DIFF_0 + i]);
		let canon_high_max_1: [AB::Var; SQUEEZE_LIMBS] =
			core::array::from_fn(|i| local[COL_CANON_HIGH_MAX_1 + i]);
		let canon_inv_diff_1: [AB::Var; SQUEEZE_LIMBS] =
			core::array::from_fn(|i| local[COL_CANON_INV_DIFF_1 + i]);
		let u_0: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_U_0 + i]);
		let u_1: [AB::Var; FIELD_NUM_LIMBS] = core::array::from_fn(|i| local[COL_U_1 + i]);

		let radix_u32 = AB::Expr::from_u64(1u64 << 32);
		let max_u32 = AB::Expr::from_u64(0xFFFF_FFFFu64);

		// ─── (1) Goldilocks → u32 packing tie ──────────────────────────────
		// w_i[k] == W_i[2k] + 2^32 · W_i[2k+1]
		for k in 0..SQUEEZE_LIMBS {
			builder.assert_zero(
				w_0_g[k].into() - w_0_u32[2 * k].into()
					- radix_u32.clone() * w_0_u32[2 * k + 1].into(),
			);
			builder.assert_zero(
				w_1_g[k].into() - w_1_u32[2 * k].into()
					- radix_u32.clone() * w_1_u32[2 * k + 1].into(),
			);
		}

		// ─── (2) Canonicality guard (per Goldilocks limb, both calls) ──────
		canon_guard::<AB>(builder, &w_0_u32, &canon_high_max_0, &canon_inv_diff_0, &max_u32);
		canon_guard::<AB>(builder, &w_1_u32, &canon_high_max_1, &canon_inv_diff_1, &max_u32);

		// ─── (3) Sponge bus pushes (one per call, send +1) ─────────────────
		// Input: (private_nullifier, counter, dst[6])
		// Output: w_i[8]
		let dst = dst_packed();
		for (counter, w_g, bus_name) in [
			(COUNTER_U0, &w_0_g, self.bus_sponge_0),
			(COUNTER_U1, &w_1_g, self.bus_sponge_1),
		] {
			let payload: [AB::Expr; 2 * SPONGE_WIDTH] = core::array::from_fn(|i| {
				if i < SPONGE_WIDTH {
					// Input state cells.
					match i {
						0 => private_nullifier.into(),
						1 => AB::Expr::from_u64(counter),
						_ => AB::Expr::from_u64(dst[i - 2].as_canonical_u64()),
					}
				} else {
					// Output state cells.
					w_g[i - SPONGE_WIDTH].into()
				}
			});
			builder.push_interaction(bus_name, payload, AB::Expr::ONE, 1);
		}

		// ─── (4) Reduce384 bus pushes (one per call, send +1) ──────────────
		// Payload: (W_i[12] || u_i[8])
		for (w_u32, u, bus_name) in [
			(&w_0_u32, &u_0, self.bus_reduce_0),
			(&w_1_u32, &u_1, self.bus_reduce_1),
		] {
			let payload: [AB::Expr; REDUCE_384_INPUT_LIMBS + FIELD_NUM_LIMBS] =
				core::array::from_fn(|i| {
					if i < REDUCE_384_INPUT_LIMBS {
						w_u32[i].into()
					} else {
						u[i - REDUCE_384_INPUT_LIMBS].into()
					}
				});
			builder.push_interaction(bus_name, payload, AB::Expr::ONE, 1);
		}

		// ─── (5) Service-bus receive on bus_query ──────────────────────────
		// Payload: (private_nullifier, u_0[8], u_1[8]) = 17 cells.
		const SERVICE_PAYLOAD: usize = 1 + 2 * FIELD_NUM_LIMBS;
		let service_payload: [AB::Expr; SERVICE_PAYLOAD] = core::array::from_fn(|i| {
			if i == 0 {
				private_nullifier.into()
			} else if i <= FIELD_NUM_LIMBS {
				u_0[i - 1].into()
			} else {
				u_1[i - 1 - FIELD_NUM_LIMBS].into()
			}
		});
		builder.push_interaction(self.bus_query, service_payload, -AB::Expr::ONE, 1);
	}
}

fn canon_guard<AB: InteractionBuilder>(
	builder: &mut AB,
	w_u32: &[AB::Var; REDUCE_384_INPUT_LIMBS],
	canon_high_max: &[AB::Var; SQUEEZE_LIMBS],
	canon_inv_diff: &[AB::Var; SQUEEZE_LIMBS],
	max_u32: &AB::Expr,
) {
	for k in 0..SQUEEZE_LIMBS {
		let high = w_u32[2 * k + 1];
		let low = w_u32[2 * k];
		let diff: AB::Expr = high.into() - max_u32.clone();
		let f: AB::Expr = canon_high_max[k].into();

		// is_high_max ∈ {0, 1}
		builder.assert_bool(canon_high_max[k]);

		// Forward: f · diff = 0 (if f = 1, then diff = 0, i.e., high = 0xFFFFFFFF)
		builder.assert_zero(f.clone() * diff.clone());

		// Reverse via zero-test: diff · inv_diff + f - 1 = 0
		// (forces f = 1 iff diff = 0 iff high = 0xFFFFFFFF)
		builder.assert_zero(diff * canon_inv_diff[k].into() + f.clone() - AB::Expr::ONE);

		// Force low = 0 in the non-canonical wrap range.
		builder.assert_zero(f * low.into());
	}
}

// ─── Trace builder ────────────────────────────────────────────────────────

/// Build the trace row for one hash_to_field invocation given a
/// `private_nullifier` input. Calls the witness pipeline internally.
pub fn build_hash_to_field_trace(
	private_nullifier: Goldilocks,
) -> RowMajorMatrix<Goldilocks> {
	use rostro_poseidon_sponge_air::poseidon2_sponge_8;

	let dst = dst_packed();

	// Build sponge inputs and outputs for each counter.
	let sponge_input = |counter: u64| -> [Goldilocks; SPONGE_WIDTH] {
		let mut input = [Goldilocks::ZERO; SPONGE_WIDTH];
		input[0] = private_nullifier;
		input[1] = Goldilocks::from_u64(counter);
		for i in 0..SQUEEZE_LIMBS {
			input[2 + i] = dst[i];
		}
		input
	};

	let w_0_g = poseidon2_sponge_8(sponge_input(COUNTER_U0));
	let w_1_g = poseidon2_sponge_8(sponge_input(COUNTER_U1));

	// Pack Goldilocks → u32 via canonical decomposition. Each w_i[k] in
	// [0, p_g) decomposes uniquely as low + 2^32 · high where low, high
	// are u32. The non-canonical wrap (high = 0xFFFFFFFF, low ≥ 1) only
	// arises if a different u64 representation is chosen — we always
	// pick canonical here.
	let pack = |w_g: &[Goldilocks; SPONGE_WIDTH]| -> [u32; REDUCE_384_INPUT_LIMBS] {
		core::array::from_fn(|i| {
			let k = i / 2;
			let v = w_g[k].as_canonical_u64();
			if i.is_multiple_of(2) {
				(v & 0xFFFF_FFFF) as u32
			} else {
				(v >> 32) as u32
			}
		})
	};
	let w_0_u32 = pack(&w_0_g);
	let w_1_u32 = pack(&w_1_g);

	// Canonicality guard witnesses: for each Goldilocks limb, compute
	// is_high_max + inv_diff. Honest case has high < 0xFFFFFFFF for
	// uniformly-sampled Poseidon2 outputs (probability of high = 0xFFFFFFFF
	// is ~2^-32); the witness still needs to be supplied.
	let canon = |w_u32: &[u32; REDUCE_384_INPUT_LIMBS]| -> ([Goldilocks; SQUEEZE_LIMBS], [Goldilocks; SQUEEZE_LIMBS]) {
		let mut high_max = [Goldilocks::ZERO; SQUEEZE_LIMBS];
		let mut inv_diff = [Goldilocks::ZERO; SQUEEZE_LIMBS];
		for k in 0..SQUEEZE_LIMBS {
			let high = w_u32[2 * k + 1];
			if high == 0xFFFF_FFFF {
				high_max[k] = Goldilocks::ONE;
				// inv_diff is unconstrained when is_high_max = 1; set to 0.
			} else {
				high_max[k] = Goldilocks::ZERO;
				let diff = Goldilocks::from_u64(high as u64) - Goldilocks::from_u64(0xFFFF_FFFF);
				// inv_diff = 1 / diff. diff is non-zero by branch.
				inv_diff[k] = diff.inverse();
			}
		}
		(high_max, inv_diff)
	};
	let (canon_high_max_0, canon_inv_diff_0) = canon(&w_0_u32);
	let (canon_high_max_1, canon_inv_diff_1) = canon(&w_1_u32);

	// Compute u_0, u_1 via the existing witness path (so the bus payloads
	// match what Reduce384Air will assert internally).
	let u_0 = hash_to_field_one(private_nullifier, COUNTER_U0, &dst);
	let u_1 = hash_to_field_one(private_nullifier, COUNTER_U1, &dst);

	// Pack into a flat row.
	let mut cells = Vec::with_capacity(HASH_TO_FIELD_AIR_NUM_COLS);
	cells.push(private_nullifier);
	cells.extend_from_slice(&w_0_g);
	cells.extend_from_slice(&w_1_g);
	for &v in &w_0_u32 {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	for &v in &w_1_u32 {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	cells.extend_from_slice(&canon_high_max_0);
	cells.extend_from_slice(&canon_inv_diff_0);
	cells.extend_from_slice(&canon_high_max_1);
	cells.extend_from_slice(&canon_inv_diff_1);
	for &v in &u_0 {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	for &v in &u_1 {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}

	debug_assert_eq!(cells.len(), HASH_TO_FIELD_AIR_NUM_COLS);
	RowMajorMatrix::new(cells, HASH_TO_FIELD_AIR_NUM_COLS)
}

