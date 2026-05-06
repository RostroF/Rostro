// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Block-header verifier: composes [`crate::slot_claim::verify_slot_claim`]
//! with header-digest extraction so callers can hand in a `Header` and
//! ask "does this block's claim verify against this epoch?"
//!
//! What R2b's verifier does:
//!
//! 1. Pull the `SlotClaim` PreRuntime digest out of the header. Header
//!    without one isn't Sassafras-produced; reject.
//! 2. Run the slot_claim verifier (R2a) against the supplied
//!    `EpochContext`. This is the cryptographic gate.
//! 3. Optionally surface the `NextEpochDescriptor` if present (caller
//!    decides whether to enforce its presence — that's policy, not
//!    cryptography).
//! 4. Return a [`VerifiedHeader`] bundling the resolved authority,
//!    slot, and any next-epoch descriptor for downstream consumers.
//!
//! What R2b's verifier does NOT do:
//!
//! - **Ticket-claim cryptographic verification.** `SlotClaim::ticket_claim`
//!   is the ephemeral ed25519 signature that binds a ticket-holder to
//!   the slot they're claiming. Verifying it requires looking up the
//!   ticket bound to the slot via `SassafrasApi::slot_ticket(slot)` —
//!   that's a runtime-API call, which means a `Client` handle, which
//!   is the import-queue Verifier's job (its own follow-up). R2b
//!   surfaces `ticket_claim` for the caller to handle.
//! - **Slot↔epoch alignment.** The `EpochContext` doesn't know its own
//!   start slot or length; whoever constructs the context has already
//!   decided "this is the right epoch for that slot." Helpers in
//!   [`crate::epoch::EpochContext::slot_falls_in_epoch`] are available
//!   for callers that want explicit alignment checks.
//! - **Block weight, parent-hash, finality.** Standard import-queue
//!   responsibilities, not consensus-protocol cryptography.

use sp_consensus_sassafras::{
	digests::{NextEpochDescriptor, SlotClaim},
	AuthorityId, Slot,
};
use sp_runtime::traits::Header as HeaderT;

use crate::{
	epoch::EpochContext,
	error::VerificationError,
	header::{extract_next_epoch_descriptor, extract_slot_claim},
	slot_claim::verify_slot_claim,
};

/// Bundle of facts the verifier extracts from a Sassafras block
/// header. Returned to callers so they can route on the resolved
/// authority, the slot, and any epoch-transition payload without
/// having to re-walk the digest log.
#[derive(Clone, Debug)]
pub struct VerifiedHeader<'a> {
	/// The slot this block claims.
	pub slot: Slot,
	/// Authority whose VRF signature passed verification.
	pub authority: &'a AuthorityId,
	/// The slot claim itself — kept for downstream callers (e.g. the
	/// import-queue Verifier needs `ticket_claim` for the ticket-
	/// binding cross-check).
	pub claim: SlotClaim,
	/// Next-epoch descriptor, if the block carries one. The verifier
	/// itself doesn't enforce whether this is required — that's
	/// epoch-boundary policy, decided by the import-queue caller.
	pub next_epoch: Option<NextEpochDescriptor>,
}

/// Verify a Sassafras block header against the supplied epoch context.
///
/// Returns a [`VerifiedHeader`] on success. The header must carry a
/// `PreRuntime(SASSAFRAS_ENGINE_ID, …)` digest; absence is treated as
/// `MissingSlotClaim`. The bandersnatch IETF VRF signature in the
/// claim must verify against the authority indexed by
/// `claim.authority_idx` in the supplied epoch.
pub fn verify_header<'a, H: HeaderT>(
	header: &H,
	epoch: EpochContext<'a>,
) -> Result<VerifiedHeader<'a>, VerificationError> {
	let claim = extract_slot_claim(header).ok_or(VerificationError::MissingSlotClaim)?;
	let authority = verify_slot_claim(&claim, epoch)?;
	let next_epoch = extract_next_epoch_descriptor(header);
	Ok(VerifiedHeader { slot: claim.slot, authority, claim, next_epoch })
}
