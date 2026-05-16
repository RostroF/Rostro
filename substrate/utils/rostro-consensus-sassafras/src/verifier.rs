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
	ticket::{TicketBody, TicketId},
	AuthorityId, Slot,
};
use sp_runtime::traits::Header as HeaderT;

use crate::{
	epoch::EpochContext,
	error::VerificationError,
	header::{extract_next_epoch_descriptor, extract_slot_claim},
	slot_claim::verify_slot_claim,
	ticket_claim::verify_ticket_claim,
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
///
/// **This entry point doesn't run the ticket-binding check** — see
/// [`verify_block`] for the composition that adds it via a
/// caller-supplied ticket lookup.
pub fn verify_header<'a, H: HeaderT>(
	header: &H,
	epoch: EpochContext<'a>,
) -> Result<VerifiedHeader<'a>, VerificationError> {
	let claim = extract_slot_claim(header).ok_or(VerificationError::MissingSlotClaim)?;
	let authority = verify_slot_claim(&claim, epoch)?;
	let next_epoch = extract_next_epoch_descriptor(header);
	Ok(VerifiedHeader { slot: claim.slot, authority, claim, next_epoch })
}

/// Verify a Sassafras block end-to-end: header digest + slot-claim
/// VRF + ticket-binding cross-check.
///
/// The caller supplies `ticket_lookup` — a closure that mirrors the
/// `SassafrasApi::slot_ticket(slot)` runtime API. This keeps the
/// verifier function pure and testable without dragging in a `Client`
/// dependency at this layer; the import-queue Verifier impl (its own
/// follow-up) is the thin glue that calls the runtime API and feeds
/// the result here.
///
/// Cross-check policy enforced:
///
/// - If `ticket_lookup(slot)` returns `Some(ticket_id, body)`:
///   - the claim **must** have a `ticket_claim` payload, OR error
///     [`VerificationError::MissingTicketClaim`].
///   - the `ticket_claim.erased_signature` **must** verify against
///     `body.erased_public` per [`crate::ticket_claim::verify_ticket_claim`],
///     OR error [`VerificationError::TicketBindingFailed`].
/// - If `ticket_lookup(slot)` returns `None`:
///   - the claim **must not** have a `ticket_claim` payload, OR error
///     [`VerificationError::UnexpectedTicketClaim`]. (This is the
///     "fallback / secondary slot" path; protocol policy on whether
///     fallback is allowed at all is up to the import-queue caller.)
pub fn verify_block<'a, H, F>(
	header: &H,
	epoch: EpochContext<'a>,
	mut ticket_lookup: F,
) -> Result<VerifiedHeader<'a>, VerificationError>
where
	H: HeaderT,
	F: FnMut(Slot) -> Option<(TicketId, TicketBody)>,
{
	let verified = verify_header(header, epoch)?;
	let slot = verified.slot;

	match (ticket_lookup(slot), verified.claim.ticket_claim.as_ref()) {
		(Some((_id, body)), Some(ticket_claim)) =>
			verify_ticket_claim(&verified.claim, ticket_claim, &body)?,
		(Some(_), None) => return Err(VerificationError::MissingTicketClaim { slot }),
		(None, Some(_)) => return Err(VerificationError::UnexpectedTicketClaim { slot }),
		(None, None) => { /* fallback / secondary slot path; caller decides policy */ },
	}

	Ok(verified)
}
