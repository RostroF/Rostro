// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Slot-claim decision logic — the producer-side analog of R2.5a's
//! import verifier.
//!
//! Each slot, every validator's slot worker asks: *"Is this my slot,
//! and if so how do I claim it?"* This module implements that
//! decision as a pure function over provider closures, so the async
//! slot-driving loop above (sc-consensus-slots integration, proposer
//! wiring, block-import plumbing) is a thin wrapper rather than a
//! tangle of coupled concerns.
//!
//! ## ASSUMPTION-FALLBACK-1
//!
//! When a slot has no ticket bound to it, Sassafras allows fallback
//! / secondary-slot production by some deterministic rule the W3F
//! research specifies. Concretely, the rule is meant to pick a
//! validator from the active set such that:
//!
//! - exactly one validator is selected per fallback slot (no ties)
//! - the selection is verifiable from the slot + epoch context alone
//!   (no off-chain coordination)
//! - the rule produces no observable correlation with which validators
//!   hold which tickets (preserves the anonymity story where
//!   possible)
//!
//! The W3F implementation that would have pinned the bit-level rule
//! never landed in upstream Substrate. Until we ground-truth against
//! a working reference, our placeholder rule is:
//!
//! ```text
//!   fallback_winner(slot, epoch) =
//!       blake2_256(epoch.randomness || slot.encode()) modulo authorities.len()
//! ```
//!
//! Returns the index of the assigned fallback producer. Single-shot
//! deterministic; gives every authority an equal share over time.
//! Lacks the unpredictability of the real spec rule (which uses a
//! VRF) but is a defensible placeholder until R3-twin-node testing
//! lets us cross-check against expected behavior. Documented as
//! ASSUMPTION-FALLBACK-1; the function
//! [`fallback_winner_index`] is the single point of change.

use codec::Encode;
use sp_consensus_sassafras::{
	digests::SlotClaim,
	ticket::{TicketBody, TicketId},
	AuthorityIndex, Slot,
};
use sp_core::ed25519;
use sp_io::hashing::blake2_256;

use crate::{
	epoch::EpochContext,
	producer::{produce_primary_slot_claim, produce_slot_claim},
	signer::BandersnatchVrfSigner,
};

/// Outcome of the per-slot claim-decision routine.
#[derive(Clone, Debug)]
pub enum ClaimDecision {
	/// Local authority is the bound ticket-holder for this slot;
	/// claim built with the ticket-binding signature attached.
	Primary {
		/// Local authority's index in the epoch's authority list.
		authority_idx: AuthorityIndex,
		/// Fully-formed slot claim (ticket_claim attached).
		claim: SlotClaim,
	},
	/// Local authority is the fallback producer for this unbound
	/// slot per [`fallback_winner_index`]; claim built without a
	/// ticket binding.
	Fallback {
		/// Local authority's index in the epoch's authority list.
		authority_idx: AuthorityIndex,
		/// Slot claim with `ticket_claim: None`.
		claim: SlotClaim,
	},
	/// Not our slot — either someone else's ticket is bound here, or
	/// the fallback rule selected a different authority.
	NotMyTurn,
}

/// Compute the fallback producer's authority index per
/// ASSUMPTION-FALLBACK-1. Single point of change when the real spec
/// rule lands.
pub fn fallback_winner_index(slot: Slot, epoch: &EpochContext<'_>) -> Option<AuthorityIndex> {
	if epoch.authorities.is_empty() {
		return None;
	}
	let mut input = Vec::with_capacity(40);
	input.extend_from_slice(epoch.randomness);
	input.extend_from_slice(&slot.encode());
	let h = blake2_256(&input);
	// Take the first 4 bytes as a u32, modulo authorities count.
	let idx_bytes: [u8; 4] = h[..4].try_into().expect("4 bytes; qed");
	let idx = u32::from_le_bytes(idx_bytes) as usize % epoch.authorities.len();
	Some(idx as AuthorityIndex)
}

/// Decide whether the local authority should claim `slot` and, if
/// yes, build the fully-formed [`SlotClaim`].
///
/// Caller responsibilities:
///
/// - `local_authority_idx` — local authority's position in
///   `epoch.authorities`. The slot worker pulls this once per epoch
///   from a keystore-vs-authority-set match.
/// - `local_authority_pair` — bandersnatch keypair held by the local
///   keystore. Used to sign the slot-claim VRF.
/// - `ticket_lookup` — `FnOnce(Slot) -> Option<(TicketId,
///   TicketBody)>`. Wraps `SassafrasApi::slot_ticket(slot)`.
/// - `erased_secret_lookup` — `FnOnce(&TicketBody) ->
///   Option<ed25519::Pair>`. Looks up the erased ephemeral secret
///   for a given ticket body. The slot worker stashes erased secrets
///   locally at ticket-generation time; this lookup checks whether
///   the local validator holds the secret matching the ticket's
///   `erased_public`. None means "not our ticket."
pub fn try_claim_slot<S, TL, EL>(
	slot: Slot,
	epoch: EpochContext<'_>,
	local_authority_idx: AuthorityIndex,
	signer: &S,
	ticket_lookup: TL,
	erased_secret_lookup: EL,
) -> ClaimDecision
where
	S: BandersnatchVrfSigner,
	TL: FnOnce(Slot) -> Option<(TicketId, TicketBody)>,
	EL: FnOnce(&TicketBody) -> Option<ed25519::Pair>,
{
	match ticket_lookup(slot) {
		Some((_id, body)) => match erased_secret_lookup(&body) {
			Some(erased_pair) => {
				match produce_primary_slot_claim(
					signer,
					local_authority_idx,
					slot,
					epoch,
					&erased_pair,
				) {
					Some(claim) =>
						ClaimDecision::Primary { authority_idx: local_authority_idx, claim },
					None => ClaimDecision::NotMyTurn,
				}
			},
			None => ClaimDecision::NotMyTurn,
		},
		None => match fallback_winner_index(slot, &epoch) {
			Some(winner) if winner == local_authority_idx =>
				match produce_slot_claim(signer, local_authority_idx, slot, epoch, None) {
					Some(claim) =>
						ClaimDecision::Fallback { authority_idx: local_authority_idx, claim },
					None => ClaimDecision::NotMyTurn,
				},
			_ => ClaimDecision::NotMyTurn,
		},
	}
}
