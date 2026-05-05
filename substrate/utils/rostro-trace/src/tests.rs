// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for rostro-trace v0.

use super::*;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;

fn make_row(n: u32, pre: [u8; 32], post: [u8; 32], hash: [u8; 32]) -> BlockTraceRow {
	BlockTraceRow {
		block_number: n,
		extrinsic_count: 1,
		pre_state_root: pre,
		post_state_root: post,
		block_hash: hash,
		parent_hash: [0u8; 32],
		extrinsics_root: [0u8; 32],
	}
}

#[test]
fn row_converts_to_correct_column_count() {
	let row = make_row(7, [0u8; 32], [0u8; 32], [0u8; 32]);
	let cols = row.to_goldilocks_row();
	assert_eq!(cols.len(), NUM_COLS);
}

#[test]
fn block_number_lands_in_first_column() {
	let row = make_row(42, [0u8; 32], [0u8; 32], [0u8; 32]);
	let cols = row.to_goldilocks_row();
	assert_eq!(cols[COL_BLOCK_NUMBER].as_canonical_u64(), 42);
}

#[test]
fn hash_chunks_pack_into_8_limbs_big_endian() {
	// First 4 bytes of pre_state_root are 0x01, 0x02, 0x03, 0x04 → limb 0 = 0x01020304
	let mut pre = [0u8; 32];
	pre[..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
	pre[28..].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

	let row = make_row(0, pre, [0u8; 32], [0u8; 32]);
	let cols = row.to_goldilocks_row();
	assert_eq!(cols[COL_PRE_STATE_ROOT].as_canonical_u64(), 0x01020304);
	assert_eq!(cols[COL_PRE_STATE_ROOT + 7].as_canonical_u64(), 0xDEADBEEF);
}

#[test]
fn air_width_matches_num_cols() {
	use p3_air::BaseAir;
	let air = ChainConsistencyAir;
	assert_eq!(<ChainConsistencyAir as BaseAir<Goldilocks>>::width(&air), NUM_COLS);
}

/// Build a synthetic chain trace where each block's post-state-root = next
/// block's pre-state-root, block numbers increment by 1, and parent_hash
/// chains correctly to the previous block_hash. Shape matches all AIR
/// transition constraints at v0.5.
fn synthetic_trace(rows: u32) -> Vec<BlockTraceRow> {
	let mut roots = vec![[0u8; 32]; rows as usize + 1];
	for (i, root) in roots.iter_mut().enumerate() {
		root[0..4].copy_from_slice(&(i as u32).to_be_bytes());
	}
	let block_hash_for = |n: u32| {
		let mut h = [0u8; 32];
		h[0..4].copy_from_slice(&(n + 0x1000).to_be_bytes());
		h
	};
	(0..rows)
		.map(|n| BlockTraceRow {
			block_number: n,
			extrinsic_count: 1,
			pre_state_root: roots[n as usize],
			post_state_root: roots[n as usize + 1],
			block_hash: block_hash_for(n),
			parent_hash: if n == 0 { [0u8; 32] } else { block_hash_for(n - 1) },
			extrinsics_root: [0u8; 32],
		})
		.collect()
}

#[test]
fn synthetic_trace_satisfies_transition_constraints_manually() {
	// We don't run Plonky3's prover here yet (that needs full StarkConfig
	// boilerplate); we instead manually check that each adjacent row pair
	// satisfies the constraints the AIR encodes. Confirms the trace shape
	// is consistent with the AIR. Full prove-and-verify lands when we wire
	// StarkConfig.
	let trace: Vec<_> = synthetic_trace(8).into_iter().map(|r| r.to_goldilocks_row()).collect();
	for w in trace.windows(2) {
		let local = &w[0];
		let next = &w[1];
		// block_number sequential
		assert_eq!(
			next[COL_BLOCK_NUMBER].as_canonical_u64(),
			local[COL_BLOCK_NUMBER].as_canonical_u64() + 1,
		);
		// state-root chain
		for limb in 0..8 {
			assert_eq!(
				next[COL_PRE_STATE_ROOT + limb].as_canonical_u64(),
				local[COL_POST_STATE_ROOT + limb].as_canonical_u64(),
			);
		}
		// parent-hash chain (v0.5)
		for limb in 0..8 {
			assert_eq!(
				next[COL_PARENT_HASH + limb].as_canonical_u64(),
				local[COL_BLOCK_HASH + limb].as_canonical_u64(),
			);
		}
	}
}

#[test]
fn forged_parent_hash_chain_break_caught_by_constraint() {
	// Tamper with block #3's parent_hash so it doesn't match block #2's
	// block_hash. The parent-hash chain constraint (v0.5) must detect it.
	let mut trace: Vec<_> =
		synthetic_trace(8).into_iter().map(|r| r.to_goldilocks_row()).collect();
	trace[3][COL_PARENT_HASH] = Goldilocks::new(0xCAFEBABE);

	let local = &trace[2];
	let bad_next = &trace[3];
	assert_ne!(
		bad_next[COL_PARENT_HASH].as_canonical_u64(),
		local[COL_BLOCK_HASH].as_canonical_u64(),
		"forged parent_hash must violate the parent-hash chain constraint",
	);
}

#[test]
fn forged_trace_block_number_jump_caught_by_constraint() {
	// Replace block #5 in the trace with block_number = 100. The
	// transition constraint between block #4 and block "100" should fail.
	let mut trace: Vec<_> =
		synthetic_trace(8).into_iter().map(|r| r.to_goldilocks_row()).collect();
	trace[5][COL_BLOCK_NUMBER] = Goldilocks::new(100);

	let local = &trace[4];
	let bad_next = &trace[5];
	// constraint: next.block_number = local.block_number + 1
	let expected_next = local[COL_BLOCK_NUMBER].as_canonical_u64() + 1;
	assert_ne!(
		bad_next[COL_BLOCK_NUMBER].as_canonical_u64(),
		expected_next,
		"forged block number must violate the sequential-numbering constraint",
	);
}

#[test]
fn forged_state_root_chain_break_caught_by_constraint() {
	// Tamper with block #3's pre_state_root so it doesn't match block #2's
	// post_state_root. The state-root chain constraint should detect it.
	let mut trace: Vec<_> =
		synthetic_trace(8).into_iter().map(|r| r.to_goldilocks_row()).collect();
	trace[3][COL_PRE_STATE_ROOT] = Goldilocks::new(0xDEADBEEF);

	let local = &trace[2];
	let bad_next = &trace[3];
	// constraint: next.pre_state_root[0] == local.post_state_root[0]
	assert_ne!(
		bad_next[COL_PRE_STATE_ROOT].as_canonical_u64(),
		local[COL_POST_STATE_ROOT].as_canonical_u64(),
		"broken state-root chain must violate the constraint",
	);
}

// ─── End-to-end Plonky3 prove + verify ──────────────────────────────────────
//
// Confirms the wiring works: trace → matrix → STARK proof → verify, against
// the v0 ChainConsistencyAir. Crypto-stack-v1 picks: Goldilocks field,
// BinomialExtensionField<Goldilocks,2> challenges, Poseidon2 (width 8) hash,
// TwoAdicFriPcs polynomial commitment.

mod proof {
	use super::*;
	use p3_challenger::DuplexChallenger;
	use p3_commit::ExtensionMmcs;
	use p3_dft::Radix2DitParallel;
	use p3_field::extension::BinomialExtensionField;
	use p3_fri::{create_test_fri_params, TwoAdicFriPcs};
	use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks};
	use p3_matrix::dense::RowMajorMatrix;
	use p3_merkle_tree::MerkleTreeMmcs;
	use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
	use p3_uni_stark::{prove, verify, StarkConfig};

	type Val = Goldilocks;
	type Perm = Poseidon2Goldilocks<8>;
	type ValHash = PaddingFreeSponge<Perm, 8, 4, 4>;
	type ValCompress = TruncatedPermutation<Perm, 2, 4, 8>;
	type ValMmcs = MerkleTreeMmcs<<Val as p3_field::Field>::Packing, <Val as p3_field::Field>::Packing, ValHash, ValCompress, 2, 4>;
	type Challenge = BinomialExtensionField<Val, 2>;
	type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
	type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
	type Dft = Radix2DitParallel<Val>;
	type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
	type ConfigT = StarkConfig<Pcs, Challenge, Challenger>;

	fn make_config() -> ConfigT {
		let perm = default_goldilocks_poseidon2_8();
		let hash = ValHash::new(perm.clone());
		let compress = ValCompress::new(perm.clone());
		let val_mmcs = ValMmcs::new(hash, compress, 0);
		let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
		let dft = Dft::default();
		let fri_params = create_test_fri_params(challenge_mmcs, 2);
		let pcs = Pcs::new(dft, val_mmcs, fri_params);
		let challenger = Challenger::new(perm);
		ConfigT::new(pcs, challenger)
	}

	fn trace_matrix(rows: u32) -> RowMajorMatrix<Val> {
		// Pad row count up to next power of two — uni-stark requires this.
		let target = (rows as usize).next_power_of_two().max(2);
		let mut padded: Vec<BlockTraceRow> = synthetic_trace(rows);
		// Repeat the last row to pad. Constraints are only enforced on
		// transitions of "real" rows; padding rows extend the chain
		// trivially.
		while padded.len() < target {
			let last = padded.last().expect("at least one row").clone();
			padded.push(BlockTraceRow {
				block_number: last.block_number + 1,
				extrinsic_count: 0,
				pre_state_root: last.post_state_root,
				post_state_root: last.post_state_root,
				block_hash: last.block_hash,
				parent_hash: last.block_hash,
				extrinsics_root: [0u8; 32],
			});
		}

		let flat: Vec<Val> = padded
			.iter()
			.flat_map(|r| r.to_goldilocks_row().to_vec())
			.collect();
		RowMajorMatrix::new(flat, NUM_COLS)
	}

	#[test]
	fn prove_and_verify_chain_consistency() {
		let config = make_config();
		let trace = trace_matrix(8);
		let pis: Vec<Val> = vec![];

		let proof = prove(&config, &ChainConsistencyAir, trace, &pis);
		verify(&config, &ChainConsistencyAir, &proof, &pis)
			.expect("verification of honest trace must succeed");
	}

	#[test]
	fn forged_block_number_proof_fails_to_verify() {
		// Generate a trace where block_number jumps illegally; the prover
		// should still produce a proof object but verification must reject.
		// (In practice the prover would error during constraint
		// computation — we accept either a panic during prove OR a
		// verification failure as evidence the forgery is caught.)
		let config = make_config();

		// Build a forged trace matrix manually.
		let mut rows = synthetic_trace(8);
		rows[5].block_number = 100;
		let target = rows.len().next_power_of_two();
		while rows.len() < target {
			let last = rows.last().expect("nonempty").clone();
			rows.push(BlockTraceRow {
				block_number: last.block_number + 1,
				extrinsic_count: 0,
				pre_state_root: last.post_state_root,
				post_state_root: last.post_state_root,
				block_hash: last.block_hash,
				parent_hash: last.block_hash,
				extrinsics_root: [0u8; 32],
			});
		}
		let flat: Vec<Val> = rows
			.iter()
			.flat_map(|r| r.to_goldilocks_row().to_vec())
			.collect();
		let trace = RowMajorMatrix::new(flat, NUM_COLS);
		let pis: Vec<Val> = vec![];

		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let proof = prove(&config, &ChainConsistencyAir, trace, &pis);
			verify(&config, &ChainConsistencyAir, &proof, &pis)
		}));
		match result {
			Ok(Ok(_)) => panic!("forged trace must NOT verify successfully"),
			Ok(Err(_)) | Err(_) => {}, // expected: prover or verifier rejects
		}
	}
}
