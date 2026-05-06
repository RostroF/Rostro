// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Producer-side crypto helpers — the inverse of the verifier surface
//! in [`crate::slot_claim`], [`crate::ticket_claim`], and
//! [`crate::verifier`].
//!
//! ## What this module provides
//!
//! Pure functions that build the cryptographic payloads a Sassafras
//! block author needs:
//!
//! - [`produce_slot_claim`] — builds a [`SlotClaim`] by signing the
//!   slot-claim VRF input with the author's bandersnatch keypair.
//!   Output is round-trip-compatible with [`crate::verify_slot_claim`]:
//!   `produce → verify` is the identity property.
//! - [`produce_ticket_claim`] — builds a [`TicketClaim`] by signing
//!   the [ticket-binding message][`crate::signed_data_for_ticket_binding`]
//!   with the erased ephemeral ed25519 secret. Output is round-trip-
//!   compatible with [`crate::verify_ticket_claim`].
//!
//! ## What this module does NOT do
//!
//! - **No async runtime, no slot-driver loop.** The real block-author
//!   service polls the slot stream from `sc-consensus-slots`, calls
//!   into a `Proposer`, gathers extrinsics, builds the block, attaches
//!   the digest entries this module produces. That glue lives in
//!   R2c's slot-worker module (its own session — depends on
//!   `sc-consensus-slots`, async-trait, and a real `BlockImport` /
//!   `Proposer` integration).
//! - **No keystore lookup.** Caller passes pairs directly. The real
//!   slot worker pulls them from `KeystorePtr::sr25519_public_keys` /
//!   bandersnatch equivalents.
//! - **No fallback / secondary-slot policy decisions.** Caller decides
//!   whether the local authority is allowed to claim this slot (via
//!   ticket lookup or fallback rule); this module just signs.

use sp_consensus_sassafras::{
	digests::SlotClaim,
	ticket::TicketClaim,
	vrf::{slot_claim_sign_data, VrfSignature},
	AuthorityIndex, AuthorityPair, Slot,
};
use sp_core::{
	crypto::{VrfSecret, Wraps},
	ed25519, Pair,
};

use crate::{epoch::EpochContext, ticket_claim::signed_data_for_ticket_binding};

/// Build a SlotClaim for the local authority claiming `slot` in the
/// given epoch.
///
/// The bandersnatch IETF VRF signature commits to
/// `slot_claim_sign_data(epoch.randomness, slot, epoch.index)` — the
/// same input the verifier rebuilds in [`crate::verify_slot_claim`].
///
/// `authority_idx` must be the local authority's position in
/// `epoch.authorities`. Producing a SlotClaim with the wrong index
/// will pass crypto (the signer's pair is what's signing) but fail
/// verification because the verifier looks up by index.
///
/// `ticket_claim` is `Some` when claiming a primary (ticket-bound)
/// slot, `None` for the fallback path. Build it with
/// [`produce_ticket_claim`].
pub fn produce_slot_claim(
	pair: &AuthorityPair,
	authority_idx: AuthorityIndex,
	slot: Slot,
	epoch: EpochContext<'_>,
	ticket_claim: Option<TicketClaim>,
) -> SlotClaim {
	let sign_data = slot_claim_sign_data(epoch.randomness, slot, epoch.index);
	let vrf_signature: VrfSignature = pair.as_inner_ref().vrf_sign(&sign_data);
	SlotClaim { authority_idx, slot, vrf_signature, ticket_claim }
}

/// Build a TicketClaim for the local validator claiming a primary
/// slot. The erased ephemeral secret signs
/// [`crate::signed_data_for_ticket_binding`] derived from the freshly-
/// built SlotClaim.
///
/// Ordering note: the SlotClaim must be built *first* (it's the input
/// to the message), then the ticket claim is signed and slotted into
/// the SlotClaim's `ticket_claim` field. [`produce_primary_slot_claim`]
/// is the convenience wrapper that does both in the right order.
pub fn produce_ticket_claim(
	erased_pair: &ed25519::Pair,
	slot_claim_without_ticket: &SlotClaim,
) -> TicketClaim {
	let message = signed_data_for_ticket_binding(slot_claim_without_ticket);
	let erased_signature = erased_pair.sign(&message);
	TicketClaim { erased_signature }
}

/// Convenience: build a primary (ticket-bound) SlotClaim end-to-end.
///
/// Order matters because the ticket-binding signature is over the
/// SlotClaim's VRF pre-output. This helper:
///
/// 1. Builds the SlotClaim with `ticket_claim: None`.
/// 2. Computes the ticket-binding signature against the result of (1).
/// 3. Returns a SlotClaim with the ticket_claim attached.
///
/// The intermediate SlotClaim from (1) is *not* the one that ships on
/// the wire — only the final one in (3) goes into the digest log.
pub fn produce_primary_slot_claim(
	authority_pair: &AuthorityPair,
	authority_idx: AuthorityIndex,
	slot: Slot,
	epoch: EpochContext<'_>,
	erased_pair: &ed25519::Pair,
) -> SlotClaim {
	let intermediate = produce_slot_claim(authority_pair, authority_idx, slot, epoch, None);
	let ticket_claim = produce_ticket_claim(erased_pair, &intermediate);
	SlotClaim { ticket_claim: Some(ticket_claim), ..intermediate }
}
