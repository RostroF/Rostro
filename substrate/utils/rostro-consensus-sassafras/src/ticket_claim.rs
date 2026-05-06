// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Ticket-binding cryptographic verification.
//!
//! When a Sassafras validator submits a ticket envelope at the start of
//! an epoch, the body contains an *erased* ephemeral ed25519 public key
//! whose secret half lives only on the submitting validator's machine.
//! When that validator later claims a slot they were assigned, they
//! attach a [`TicketClaim`] containing an `erased_signature` over data
//! that ties the ephemeral key to *this specific slot claim*.
//!
//! ## Why this matters
//!
//! Without the ticket-binding signature, an attacker who somehow
//! intercepted a validator's ticket envelope (which is public-by-design
//! once it lands in the ticket pool) could try to claim that ticket's
//! slot themselves. The erased ed25519 secret prevents this — only the
//! submitting validator holds it, and forgeing the signature requires
//! breaking ed25519.
//!
//! ## ASSUMPTION-TICKET-BINDING-1 — what does the erased_signature sign?
//!
//! The Sassafras research papers describe ticket-binding as "the
//! erased_secret signs slot-specific data" but the precise bit-level
//! contract is implementation-defined. The pallet (`pallet_sassafras`)
//! doesn't verify this signature — it only does runtime housekeeping.
//! The W3F implementation in their `client/consensus/sassafras` (which
//! never landed in upstream Substrate) is where the contract would be
//! pinned, and we don't have it to copy from.
//!
//! Our working assumption — to be ground-truthed against
//! Polkadot-produced blocks once any exist — is that
//! `erased_signature` is an ed25519 signature over the slot claim's
//! VRF pre-output bytes:
//!
//! ```text
//!   message = SlotClaim::vrf_signature::pre_output::make_bytes()  // 32 bytes
//!   ed25519_verify(erased_signature, message, body.erased_public)
//! ```
//!
//! Reasoning behind this guess:
//!
//! - The pre-output bytes are *unique per slot claim* (they're the VRF
//!   output of (randomness, slot, epoch) with the validator's
//!   bandersnatch secret). That binds the erased signature to this
//!   specific slot, preventing replay across different slots.
//! - They're *deterministic* given the slot claim, so the verifier and
//!   producer agree on the message without extra negotiation.
//! - The 32-byte message length matches typical ed25519 usage.
//!
//! If ground-truth reveals the actual contract is different (e.g. the
//! message is the SCALE-encoded `(slot, epoch, randomness)` tuple, or
//! the full SlotClaim header digest), this module is the single point
//! of change — the function signature stays the same, only the
//! `signed_data_for_ticket_binding` helper updates.

use sp_consensus_sassafras::{
	digests::SlotClaim,
	ticket::{TicketBody, TicketClaim},
};
use sp_core::{ed25519, Pair};

use crate::error::VerificationError;

/// Compute the bytes the erased_signature is expected to sign for a
/// given SlotClaim.
///
/// **ASSUMPTION-TICKET-BINDING-1**: 32-byte VRF pre-output bytes from
/// the slot claim. See module docs for reasoning + the procedure for
/// updating this if ground-truth contradicts the assumption.
pub fn signed_data_for_ticket_binding(claim: &SlotClaim) -> [u8; 32] {
	claim.vrf_signature.pre_output.make_bytes()
}

/// Verify a `TicketClaim`'s `erased_signature` against the bound
/// `TicketBody`'s `erased_public`, with the message derived from the
/// supplied `SlotClaim` per [`signed_data_for_ticket_binding`].
///
/// On success returns `Ok(())`. On signature failure returns
/// [`VerificationError::TicketBindingFailed`].
pub fn verify_ticket_claim(
	claim: &SlotClaim,
	ticket_claim: &TicketClaim,
	ticket_body: &TicketBody,
) -> Result<(), VerificationError> {
	let message = signed_data_for_ticket_binding(claim);
	if ed25519::Pair::verify(&ticket_claim.erased_signature, message, &ticket_body.erased_public) {
		Ok(())
	} else {
		Err(VerificationError::TicketBindingFailed { slot: claim.slot })
	}
}
