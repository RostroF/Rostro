// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 STARK prover bindings for Rostro's chain-consistency AIR.
//!
//! Wraps the Plonky3 `prove` / `verify` APIs in the v0 crypto stack:
//! Goldilocks field, `BinomialExtensionField<Goldilocks, 2>` challenges,
//! Poseidon2 width-8 hash, TwoAdicFriPcs PCS. Both `pallet-proof-verifier`
//! and the node-side per-block prover loop consume this module.
//!
//! Public surface:
//! - [`prove_chain_window`]: take a slice of [`BlockTraceRow`]s and return
//!   a `(Proof, ProofMeta)` pair. Pads to next power-of-two if needed.
//! - [`verify_chain_window`]: re-verify a proof, mainly for advisory
//!   self-check during the observer phase.
//! - [`Proof`], [`Config`]: re-exported types so callers can name them.

use crate::{air::ChainConsistencyAir, row::BlockTraceRow, NUM_COLS};

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::{create_test_fri_params, TwoAdicFriPcs};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig, VerificationError};

// ─── Plonky3 type aliases (crypto stack v1) ────────────────────────────────

type Val = Goldilocks;
type Perm = Poseidon2Goldilocks<8>;
type ValHash = PaddingFreeSponge<Perm, 8, 4, 4>;
type ValCompress = TruncatedPermutation<Perm, 2, 4, 8>;
type ValMmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, ValHash, ValCompress, 2, 4>;
type Challenge = BinomialExtensionField<Val, 2>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Concrete `StarkConfig` type the prover and verifier share.
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// Re-export of the proof type produced by `prove_chain_window`.
pub type Proof = p3_uni_stark::Proof<Config>;

/// Metadata about a generated proof — useful for advisory logging.
#[derive(Debug, Clone)]
pub struct ProofMeta {
	/// Number of rows in the trace matrix that fed the prover (post-padding).
	pub trace_rows: usize,
	/// Block number of the first real (non-padding) row.
	pub first_block_number: u32,
	/// Block number of the last real (non-padding) row.
	pub last_block_number: u32,
	/// Approximate serialized size of the proof in bytes.
	pub proof_bytes: usize,
}

/// Errors the prover loop can produce.
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
	#[error("trace window is empty; need at least 2 rows for transition constraints")]
	WindowEmpty,
	#[error("verification failed: {0}")]
	Verification(String),
}

/// Build a fresh `Config` for prove/verify. Each call constructs a new
/// permutation and MMCS — these are cheap to instantiate; the more expensive
/// state lives in the proving key derived during `prove`.
pub fn make_config() -> Config {
	let perm = default_goldilocks_poseidon2_8();
	let hash = ValHash::new(perm.clone());
	let compress = ValCompress::new(perm.clone());
	let val_mmcs = ValMmcs::new(hash, compress, 0);
	let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
	let dft = Dft::default();
	let fri_params = create_test_fri_params(challenge_mmcs, 2);
	let pcs = Pcs::new(dft, val_mmcs, fri_params);
	let challenger = Challenger::new(perm);
	Config::new(pcs, challenger)
}

/// Generate a STARK proof over the supplied window of block trace rows.
///
/// Plonky3's uni-stark requires the trace matrix to have a power-of-two
/// number of rows. If the window isn't aligned, we pad by repeating the
/// last row's terminal state — block_number incrementing, state-root
/// stable, extrinsic_count zero. Padding rows satisfy the AIR's
/// transition constraints by construction.
pub fn prove_chain_window(
	rows: &[BlockTraceRow],
) -> Result<(Proof, ProofMeta), ProverError> {
	if rows.is_empty() {
		return Err(ProverError::WindowEmpty);
	}

	let first_block_number = rows.first().expect("non-empty checked").block_number;
	let last_real_block_number = rows.last().expect("non-empty checked").block_number;

	// Plonky3 uni-stark requires power-of-two row counts >= 2 for the
	// transition constraints to apply across at least one pair.
	let target = rows.len().max(2).next_power_of_two();

	let mut padded: Vec<BlockTraceRow> = rows.to_vec();
	while padded.len() < target {
		let last = padded.last().expect("non-empty").clone();
		padded.push(BlockTraceRow {
			block_number: last.block_number.saturating_add(1),
			extrinsic_count: 0,
			pre_state_root: last.post_state_root,
			post_state_root: last.post_state_root,
			// Padding rows extend the chain trivially: same block_hash so
			// next.parent_hash = local.block_hash holds for the chain.
			block_hash: last.block_hash,
			parent_hash: last.block_hash,
			extrinsics_root: [0u8; 32],
		});
	}

	let flat: Vec<Val> = padded
		.iter()
		.flat_map(|r| r.to_goldilocks_row().to_vec())
		.collect();
	let trace = RowMajorMatrix::new(flat, NUM_COLS);

	let config = make_config();
	let pis: Vec<Val> = vec![];
	let proof = prove(&config, &ChainConsistencyAir, trace, &pis);

	// Approximate proof size by re-serializing — useful for advisory
	// "proof X bytes for N blocks" log lines.
	let proof_bytes = postcard_size(&proof);

	let meta = ProofMeta {
		trace_rows: target,
		first_block_number,
		last_block_number: last_real_block_number,
		proof_bytes,
	};
	Ok((proof, meta))
}

/// Re-verify a proof. Used in advisory mode to confirm honest blocks
/// produce honest proofs end-to-end.
pub fn verify_chain_window(proof: &Proof) -> Result<(), ProverError> {
	let config = make_config();
	let pis: Vec<Val> = vec![];
	verify(&config, &ChainConsistencyAir, proof, &pis)
		.map_err(|e: VerificationError<_>| ProverError::Verification(format!("{:?}", e)))
}

/// Postcard-encoded byte length, for logging only. Errors round to 0 so we
/// never break the prover loop on a serialization quirk.
fn postcard_size<T: serde::Serialize>(value: &T) -> usize {
	postcard::to_allocvec(value).map(|v| v.len()).unwrap_or(0)
}
