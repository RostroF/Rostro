// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Equivocation-reporter loop: take an [`EquivocationProof`] from the
//! [`crate::EquivocationDetector`], produce the
//! [`OpaqueKeyOwnershipProof`] the runtime needs to validate the
//! offender's session-historical key ownership, submit the bundle
//! on-chain via [`crate::providers::EquivocationReporter`].
//!
//! ## Composition
//!
//! Detection (R2e) runs synchronously per imported block. Reporting
//! (this module) is the second half: each detected proof goes through
//! [`process_equivocation`] which:
//!
//! 1. Asks [`KeyOwnershipProver`] for the offender's key-ownership
//!    proof at the parent of the *first* offending header. If the
//!    runtime can't produce one (None), the report is silently
//!    dropped — the offender has likely already rotated out, and
//!    submitting a report for a non-current authority would just be
//!    rejected on-chain.
//! 2. Hands the bundle to [`EquivocationReporter::submit_report`],
//!    which crafts the unsigned extrinsic and gossips it.
//!
//! ## Why this is a function, not a struct
//!
//! Equivocation reporting is a one-shot transformation: input proof
//! → side-effect of on-chain submission. No state to carry between
//! calls. A function with the providers as parameters is the simplest
//! shape.

use sp_consensus_sassafras::EquivocationProof;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};

use crate::providers::{EquivocationReporter, KeyOwnershipProver, ProviderError};

/// Outcome of an equivocation report attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOutcome {
	/// The proof was bundled with a key-ownership proof and submitted.
	Submitted,
	/// The runtime couldn't generate a key-ownership proof for the
	/// offender (None return). Most commonly: offender already
	/// rotated out of the active set. Report dropped without error.
	NoKeyOwnershipProof,
}

/// Process a single equivocation proof: generate the key-ownership
/// proof, submit the bundle. Returns the outcome or a provider error
/// that wraps a runtime API failure.
pub fn process_equivocation<Block, K, R>(
	proof: EquivocationProof<Block::Header>,
	key_owner_prover: &K,
	reporter: &R,
) -> Result<ReportOutcome, ProviderError>
where
	Block: BlockT,
	K: KeyOwnershipProver<Block>,
	R: EquivocationReporter<Block>,
{
	let parent_hash = *proof.first_header.parent_hash();
	let offender = proof.offender.clone();

	let key_owner_proof =
		match key_owner_prover.generate_key_ownership_proof(parent_hash, offender)? {
			Some(p) => p,
			None => return Ok(ReportOutcome::NoKeyOwnershipProof),
		};

	reporter.submit_report(proof, key_owner_proof)?;
	Ok(ReportOutcome::Submitted)
}
