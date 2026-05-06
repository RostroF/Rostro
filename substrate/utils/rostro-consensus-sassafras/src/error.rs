// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Verification errors surfaced by the slot-claim verifier and (later)
//! the import-queue verifier.

use sp_consensus_sassafras::{AuthorityIndex, Slot};
use thiserror::Error;

// Re-export so error consumers don't need a direct sp-consensus-sassafras dep
// for the type that names a slot in error variants.
pub use sp_consensus_sassafras::Slot as ErrorSlot;

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

	/// Header has no `PreRuntime(SASS, …)` digest entry. Either the
	/// block isn't Sassafras-produced, or the digest was stripped /
	/// malformed. Reject — Sassafras blocks must carry a slot claim.
	#[error("header has no Sassafras PreRuntime digest entry; not a Sassafras-produced block")]
	MissingSlotClaim,

	/// The slot has a ticket bound to it (per the runtime's
	/// `slot_ticket(slot)` lookup), so the block author *must* attach
	/// a `TicketClaim` proving they hold the erased ephemeral secret.
	/// They didn't.
	#[error("slot {slot} has a bound ticket but the claim has no ticket_claim payload")]
	MissingTicketClaim {
		/// Slot the verifier was checking.
		slot: Slot,
	},

	/// The block author attached a `TicketClaim` but the slot has no
	/// ticket bound to it (per `slot_ticket(slot) == None`). Either
	/// they're forging a ticket binding, or they're using a fallback
	/// path with the wrong digest shape. Reject.
	#[error("slot {slot} has no bound ticket but the claim carries a ticket_claim payload")]
	UnexpectedTicketClaim {
		/// Slot the verifier was checking.
		slot: Slot,
	},

	/// The `TicketClaim::erased_signature` did not verify against the
	/// bound ticket body's `erased_public` over the expected message
	/// (see `ticket_claim::signed_data_for_ticket_binding` for what
	/// "expected message" means and the assumption that drives it).
	#[error("ticket-binding ed25519 signature failed to verify for slot {slot}")]
	TicketBindingFailed {
		/// Slot the binding was for.
		slot: Slot,
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
