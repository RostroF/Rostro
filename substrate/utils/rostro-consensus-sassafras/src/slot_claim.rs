// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Pure-crypto verification of a Sassafras [`SlotClaim`] digest entry.
//!
//! ## What this verifies
//!
//! Given a `SlotClaim` extracted from a block's pre-runtime digest, the
//! epoch's authority list, and the epoch index + randomness:
//!
//! 1. The claim's `authority_idx` is in range for the authority list.
//! 2. The claim's bandersnatch IETF VRF signature
//!    (`vrf_signature: VrfSignature`) verifies against the indexed
//!    authority's public key, with input
//!    [`sp_consensus_sassafras::vrf::slot_claim_sign_data`]`(randomness, slot, epoch_index)`.
//!
//! That's the load-bearing cryptographic check that the named
//! authority did, in fact, claim that slot under that epoch's
//! parameters.
//!
//! ## What this does *not* verify
//!
//! - **Ticket binding.** If `claim.ticket_claim` is `Some`, the slot
//!   was claimed by a ticket-holder; the `erased_signature` proves the
//!   author held the ticket-binding key. Verifying that requires
//!   knowing *which* ticket is bound to the slot, which only the
//!   runtime API (`SassafrasApi::slot_ticket`) can answer. Lives in
//!   the import-queue verifier (R2b).
//! - **Fallback / secondary slot logic.** Sassafras allows a slot to
//!   be claimed without a ticket if no ticket was assigned; whether
//!   that's allowed for a given slot depends on the protocol's
//!   secondary-slot rule. Also R2b territory.
//! - **Slot/epoch alignment.** The verifier doesn't enforce that the
//!   claim slot falls inside `[epoch_start, epoch_start + length)`.
//!   Callers that need that should check it explicitly via
//!   [`crate::epoch::EpochContext::slot_falls_in_epoch`].

use sp_consensus_sassafras::{
	digests::SlotClaim,
	vrf::{slot_claim_sign_data, VrfSignature},
	AuthorityId,
};
use sp_core::crypto::{VrfPublic, Wraps};

use crate::{epoch::EpochContext, error::VerificationError};

/// Verify a slot claim against the epoch context.
///
/// Returns the resolved authority public key on success — useful for
/// the import-queue caller, which then attributes the block to that
/// authority for accounting / equivocation tracking.
///
/// Errors map to [`VerificationError`] variants and carry enough
/// detail to produce useful telemetry without further lookups.
pub fn verify_slot_claim<'a>(
	claim: &SlotClaim,
	epoch: EpochContext<'a>,
) -> Result<&'a AuthorityId, VerificationError> {
	let authority = epoch.authority(claim.authority_idx)?;
	verify_vrf_signature(&claim.vrf_signature, authority, claim.slot, epoch).map_err(|_| {
		VerificationError::InvalidVrfSignature {
			slot: claim.slot,
			authority_index: claim.authority_idx,
			epoch_index: epoch.index,
		}
	})?;
	Ok(authority)
}

/// Internal: verify the VRF signature against the authority and the
/// expected sign-data. Bool-returning to keep the caller in charge of
/// error formatting.
fn verify_vrf_signature(
	signature: &VrfSignature,
	authority: &AuthorityId,
	slot: sp_consensus_sassafras::Slot,
	epoch: EpochContext<'_>,
) -> Result<(), ()> {
	let sign_data = slot_claim_sign_data(epoch.randomness, slot, epoch.index);
	if authority.as_inner_ref().vrf_verify(&sign_data, signature) {
		Ok(())
	} else {
		Err(())
	}
}
