// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `ChainConsistencyAir` — the v0.5 chain-shape AIR. Constrains the trace-
//! matrix's pair-of-adjacent-rows structure to enforce three invariants:
//!
//! 1. **Sequential block numbers**: `next.block_number == local.block_number + 1`
//! 2. **State-root chain**: `next.pre_state_root == local.post_state_root`
//!    (each of the 8 limbs of the 32-byte hash)
//! 3. **Parent-hash chain**: `next.parent_hash == local.block_hash`
//!    (the standard chain-of-hashes property)
//!
//! These are chain-hygiene constraints, not runtime-execution constraints.
//! They demonstrate the wiring (trace → AIR → Plonky3 STARK proof) end-to-
//! end and tighten the structural well-formedness story. v1 of the AIR
//! will model FRAME's hot path (apply_extrinsic, on_initialize,
//! on_finalize) at row granularity — that's months of zkVM engineering and
//! its own discrete project.
//!
//! Data columns added at v0.5 with no constraint yet (presence in trace
//! only): `extrinsics_root`. Wiring it into a future "extrinsic-count
//! commits to extrinsics_root" constraint is a v0.7 step.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};

// ─── Column layout for the trace matrix ────────────────────────────────────
//
// Total columns: 42
//
//   col  0      block_number          (1 col,  u32 → 1 Goldilocks)
//   col  1      extrinsic_count       (1 col,  u32 → 1 Goldilocks)
//   cols 2..10  pre_state_root        (8 cols, 32 bytes → 8 × u32)
//   cols 10..18 post_state_root       (8 cols, 32 bytes → 8 × u32)
//   cols 18..26 block_hash            (8 cols, 32 bytes → 8 × u32)
//   cols 26..34 parent_hash           (8 cols, 32 bytes → 8 × u32)   [v0.5 add]
//   cols 34..42 extrinsics_root       (8 cols, 32 bytes → 8 × u32)   [v0.5 add, data-only]

/// Column index of the block number.
pub const COL_BLOCK_NUMBER: usize = 0;
/// Column index of the extrinsic count.
pub const COL_EXTRINSIC_COUNT: usize = 1;
/// Starting column of the pre-state-root limbs (8 limbs follow).
pub const COL_PRE_STATE_ROOT: usize = 2;
/// Starting column of the post-state-root limbs (8 limbs follow).
pub const COL_POST_STATE_ROOT: usize = 10;
/// Starting column of the block-hash limbs (8 limbs follow).
pub const COL_BLOCK_HASH: usize = 18;
/// Starting column of the parent-hash limbs (8 limbs follow). Constrained
/// against `local.block_hash` in transition pairs (v0.5).
pub const COL_PARENT_HASH: usize = 26;
/// Starting column of the extrinsics-root limbs (8 limbs follow). Data
/// only at v0.5; future AIR commits this to the extrinsic body.
pub const COL_EXTRINSICS_ROOT: usize = 34;
/// Total number of trace-matrix columns.
pub const NUM_COLS: usize = 42;

/// Number of u32 limbs per 32-byte hash (8 × 4 bytes).
const HASH_LIMBS: usize = 8;

/// The v0 chain-consistency AIR. Stateless; no parameters.
pub struct ChainConsistencyAir;

impl<F: Field> BaseAir<F> for ChainConsistencyAir {
	fn width(&self) -> usize {
		NUM_COLS
	}
}

impl<AB: AirBuilder> Air<AB> for ChainConsistencyAir
where
	AB::F: Field,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();
		let next = main.next_slice();

		// Sequential block numbers across every transition.
		builder.when_transition().assert_eq(
			next[COL_BLOCK_NUMBER].clone(),
			local[COL_BLOCK_NUMBER].clone() + AB::Expr::ONE,
		);

		// State-root chain: next.pre_state_root must equal local.post_state_root,
		// limb by limb across the 8 × u32 representation.
		for limb in 0..HASH_LIMBS {
			builder.when_transition().assert_eq(
				next[COL_PRE_STATE_ROOT + limb].clone(),
				local[COL_POST_STATE_ROOT + limb].clone(),
			);
		}

		// Parent-hash chain: next.parent_hash must equal local.block_hash,
		// limb by limb. This is the standard chain-of-hashes property —
		// once a block is committed, its hash is forever the parent
		// pointer of the next block. Forging a block requires forging
		// the parent_hash limb-for-limb, which the constraint catches.
		for limb in 0..HASH_LIMBS {
			builder.when_transition().assert_eq(
				next[COL_PARENT_HASH + limb].clone(),
				local[COL_BLOCK_HASH + limb].clone(),
			);
		}
	}
}
