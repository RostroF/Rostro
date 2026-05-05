// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `BlockTraceRow` — one row of the execution-trace matrix per block.

use codec::{Decode, Encode};
use p3_goldilocks::Goldilocks;

use crate::air::NUM_COLS;

/// A single row of the chain trace, one per block.
///
/// All hash fields are 32 bytes. When converted to the Plonky3 trace matrix
/// (Goldilocks field) we chunk each hash into 8 × u32 (4 bytes each), so
/// each hash spans 8 columns. `block_number` and `extrinsic_count` are u32
/// and each fit in a single Goldilocks field element.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockTraceRow {
	pub block_number: u32,
	pub extrinsic_count: u32,
	pub pre_state_root: [u8; 32],
	pub post_state_root: [u8; 32],
	pub block_hash: [u8; 32],
}

impl BlockTraceRow {
	/// Convert this row into `NUM_COLS` Goldilocks field elements, in the
	/// column order declared by `air::COL_*` constants.
	pub fn to_goldilocks_row(&self) -> [Goldilocks; NUM_COLS] {
		let mut out = [Goldilocks::new(0); NUM_COLS];
		out[crate::air::COL_BLOCK_NUMBER] = Goldilocks::new(self.block_number as u64);
		out[crate::air::COL_EXTRINSIC_COUNT] = Goldilocks::new(self.extrinsic_count as u64);
		write_hash(&self.pre_state_root, &mut out[crate::air::COL_PRE_STATE_ROOT..]);
		write_hash(&self.post_state_root, &mut out[crate::air::COL_POST_STATE_ROOT..]);
		write_hash(&self.block_hash, &mut out[crate::air::COL_BLOCK_HASH..]);
		out
	}
}

/// Pack a 32-byte hash into 8 × u32 limbs, each limb a Goldilocks element.
/// Big-endian within each limb so the trace string is human-readable when
/// printed alongside the source bytes.
fn write_hash(hash: &[u8; 32], dst: &mut [Goldilocks]) {
	for (i, chunk) in hash.chunks_exact(4).enumerate() {
		let limb = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
		dst[i] = Goldilocks::new(limb);
	}
}
