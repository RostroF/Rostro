// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Verification errors surfaced by the slot-claim verifier and (later)
//! the import-queue verifier.

use sp_consensus_sassafras::{AuthorityIndex, Slot};
use thiserror::Error;

/// Reasons a slot claim or block can be rejected during verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerificationError {
	/// The claim references an authority index outside the active
	/// epoch's authority list. Either the claim is forged, or the
	/// caller passed the wrong epoch context.
	#[error("authority_idx {index} is out of range for epoch authority set of size {set_size}")]
	AuthorityIndexOutOfRange {
		/// Index named in the slot claim.
		index: AuthorityIndex,
		/// Size of the authorities slice the caller supplied.
		set_size: usize,
	},

	/// The bandersnatch IETF VRF signature in the slot claim does not
	/// verify against the named authority's public key + the expected
	/// `slot_claim_sign_data(randomness, slot, epoch_index)` input.
	/// Either the signature is forged, the authority is wrong, or the
	/// epoch context (randomness / index) doesn't match what the
	/// signer used.
	#[error("VRF signature invalid for slot {slot} (authority_idx {authority_index}, epoch {epoch_index})")]
	InvalidVrfSignature {
		/// Slot the claim is for.
		slot: Slot,
		/// Authority index named in the claim.
		authority_index: AuthorityIndex,
		/// Epoch index used to build the sign-data.
		epoch_index: u64,
	},

	/// The claim slot doesn't fall in the supplied epoch — sanity check
	/// for caller errors. (The verifier itself doesn't enforce slot ↔
	/// epoch mapping cryptographically; it just verifies what the
	/// caller asks. This variant is raised by helpers that *do* enforce
	/// the mapping.)
	#[error("slot {slot} does not fall within epoch {epoch_index} (start={epoch_start}, length={epoch_length})")]
	SlotOutsideEpoch {
		/// Claim slot.
		slot: Slot,
		/// Epoch index.
		epoch_index: u64,
		/// First slot of the epoch.
		epoch_start: Slot,
		/// Number of slots in the epoch.
		epoch_length: u32,
	},
}
