// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Producer-side ticket-envelope generation. The cryptographic core
//! of what a Sassafras validator does at the start of each epoch:
//! generate `attempts_number` candidate tickets, ring-VRF-sign each
//! one, filter by the ticket-id threshold, submit the survivors to
//! the chain's ticket pool.
//!
//! ## What this module provides
//!
//! - [`compute_ticket_id`] — cheap (single bandersnatch VRF
//!   evaluation, no ring proof) helper that lets the worker decide
//!   which attempts are worth pursuing before paying for a ring proof.
//!   The chain's threshold filter uses the same `make_ticket_id` so
//!   pre-filtering producer-side avoids wasted ring-proof CPU on
//!   tickets that won't make the cut.
//!
//! - [`produce_ticket_envelope`] — full envelope construction.
//!   Generates the bandersnatch ring-VRF signature over the ticket
//!   body; output is a [`TicketEnvelope`] ready for the chain's
//!   `submit_tickets` extrinsic.
//!
//! ## What this module does NOT do
//!
//! - **No ring-context construction.** Caller passes a [`RingProver`]
//!   built from the epoch's [`RingContext`] (which itself comes from
//!   the chain via `SassafrasApi::ring_context`). Building the prover
//!   is per-epoch work the worker does once.
//! - **No epheneral keypair generation.** Caller passes erased +
//!   revealed pairs. The async ticket-generation worker generates
//!   them once per attempt, persists the secrets locally so the
//!   `erased_signature` can be produced when claiming the slot later.
//! - **No threshold filtering.** Caller computes the threshold from
//!   epoch parameters via
//!   [`sp_consensus_sassafras::ticket_id_threshold`] and decides which
//!   envelopes are worth submitting based on
//!   [`compute_ticket_id`] output.
//! - **No submission.** That's an offchain-tx flow + the
//!   rostro-ratchet peer-relay channel (since `pallet_sassafras`'s
//!   `validate_unsigned` rejects `TransactionSource::External`).
//!   Lives in R2d.5, its own session.

use sp_consensus_sassafras::{
	ticket::{TicketBody, TicketEnvelope, TicketId},
	vrf::{make_ticket_id, ticket_body_sign_data, ticket_id_input, RingProver},
	AuthorityPair, Randomness,
};
use sp_core::{
	crypto::{VrfSecret, Wraps},
	ed25519, Pair,
};

/// Compute a candidate ticket's `TicketId` without producing the ring
/// proof. Use this to filter against the epoch's threshold before
/// paying for [`produce_ticket_envelope`].
///
/// The id is the first 16 bytes of the bandersnatch VRF pre-output of
/// `(randomness, attempt_idx, epoch_index)` interpreted as a little-
/// endian `u128` — same as the chain's verification path uses for the
/// threshold compare.
pub fn compute_ticket_id(
	authority_pair: &AuthorityPair,
	randomness: &Randomness,
	attempt_idx: u32,
	epoch_index: u64,
) -> TicketId {
	let input = ticket_id_input(randomness, attempt_idx, epoch_index);
	let pre_output = authority_pair.as_inner_ref().vrf_pre_output(&input);
	make_ticket_id(&pre_output)
}

/// Build a fully-formed [`TicketEnvelope`] suitable for submission via
/// `pallet_sassafras::submit_tickets`.
///
/// The bandersnatch ring-VRF signature commits to the ticket body
/// (attempt_idx + erased + revealed publics) under the supplied
/// `RingProver`. Verification on-chain rebuilds the same sign-data
/// from the body and runs the ring-VRF verifier against the epoch's
/// `RingVerifierData`.
///
/// `erased_pair` and `revealed_pair` are caller-managed ephemeral
/// ed25519 keypairs. The caller must persist `erased_pair`'s secret
/// locally so it can sign the ticket-binding message when the slot
/// this ticket lands on actually arrives.
pub fn produce_ticket_envelope(
	authority_pair: &AuthorityPair,
	erased_pair: &ed25519::Pair,
	revealed_pair: &ed25519::Pair,
	attempt_idx: u32,
	randomness: &Randomness,
	epoch_index: u64,
	ring_prover: &RingProver,
) -> TicketEnvelope {
	let id_input = ticket_id_input(randomness, attempt_idx, epoch_index);
	let body = TicketBody {
		attempt_idx,
		erased_public: erased_pair.public(),
		revealed_public: revealed_pair.public(),
	};
	let sign_data = ticket_body_sign_data(&body, id_input);
	let signature = authority_pair.as_inner_ref().ring_vrf_sign(&sign_data, ring_prover);
	TicketEnvelope { body, signature }
}
