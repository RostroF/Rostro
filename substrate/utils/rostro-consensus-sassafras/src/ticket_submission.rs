// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Ticket-submission orchestration.
//!
//! At the start of each epoch, every validator's ticket-generation
//! worker:
//!
//! 1. Computes the ticket-id threshold from epoch parameters via
//!    [`ticket_threshold`].
//! 2. For each attempt index, calls
//!    [`crate::compute_ticket_id`] (cheap — single bandersnatch VRF
//!    eval, no ring proof) to get the candidate's id.
//! 3. Skips attempts whose id is at or above the threshold.
//! 4. For survivors, calls [`crate::produce_ticket_envelope`]
//!    (expensive — full ring-VRF signature) to build the envelope.
//! 5. Submits each envelope via a [`TicketSubmitter`].
//!
//! This module covers (1) and the submission orchestration; (2)-(4)
//! live in `ticket_generation.rs` and the actual ring-context wiring
//! is per-epoch worker setup that R3's chainspec integration will
//! pin down.
//!
//! ## Local vs relay submission — why an abstraction
//!
//! `pallet_sassafras::validate_unsigned` rejects ticket submissions
//! from `TransactionSource::External` (line 476-481 of the pallet).
//! Only `Local` and `InBlock` sources are accepted. Two production
//! paths satisfy this:
//!
//! - **Direct local**: validator submits its own envelope to its own
//!   node's local mempool. Local source. Accepted. *Downside*:
//!   observable. The block that includes the ticket will (eventually)
//!   have been produced by someone whose mempool saw it; if we submit
//!   directly and then claim our own slot when the ticket lands on
//!   it, the (slot, claimer, ticket-source) correlation is observable.
//!
//! - **Peer relay (via [`crate::ratchet`]-class authenticated FS
//!   channel)**: validator A sends its envelope to validator B over
//!   an authenticated peer-to-peer channel; B submits to B's local
//!   mempool. The block that lands the ticket has *no observable
//!   link* to A's identity. This is the path the W3F spec calls for
//!   to preserve anonymity end-to-end.
//!
//! Both implementations satisfy the [`TicketSubmitter`] trait. The
//! validator service plugs in whichever it prefers (or both, with a
//! relay-then-local fallback).
//!
//! [`crate::ratchet`]: ../../../rostro_ratchet/index.html

use sp_consensus_sassafras::{
	ticket::{TicketEnvelope, TicketId},
	ticket_id_threshold,
};
use sp_runtime::traits::Block as BlockT;

use crate::providers::ProviderError;

/// Epoch parameters needed to compute the ticket-id threshold.
/// Lifted from the chain via `SassafrasApi::current_epoch()` /
/// `next_epoch()` and the active validator count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TicketThresholdParams {
	/// `EpochConfiguration::redundancy_factor`.
	pub redundancy_factor: u32,
	/// `EpochConfiguration::attempts_number`.
	pub attempts_number: u32,
	/// `Epoch::length` — number of slots per epoch.
	pub epoch_length: u32,
	/// Active validator count for the epoch.
	pub validator_count: u32,
}

/// Compute the ticket-id threshold for an epoch. Tickets with id
/// strictly less than this value are accepted on-chain; tickets at
/// or above are rejected.
///
/// Wraps `sp_consensus_sassafras::ticket_id_threshold` so callers can
/// pass the typed `TicketThresholdParams` instead of four naked u32s.
pub fn ticket_threshold(params: &TicketThresholdParams) -> TicketId {
	ticket_id_threshold(
		params.redundancy_factor,
		params.epoch_length,
		params.attempts_number,
		params.validator_count,
	)
}

/// Submit a ticket envelope. Implementations dispatch to either
/// local mempool insertion or peer relay (per the module-level docs).
#[async_trait::async_trait]
pub trait TicketSubmitter<Block: BlockT>: Send + Sync {
	/// Submit an envelope. Returns `Err(ProviderError)` only on
	/// hard infrastructure failure — the runtime API conventionally
	/// returns `false` on extrinsic-construction failure, which the
	/// implementer can choose to surface as `Err` or as a soft "no-op"
	/// outcome depending on retry policy.
	async fn submit_ticket(&self, envelope: TicketEnvelope) -> Result<(), ProviderError>;
}

/// Outcome statistics from a batch submission. Useful for telemetry
/// — "we generated N candidates, M were under threshold, K of those
/// submitted successfully."
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubmissionStats {
	/// Envelopes attempted.
	pub attempted: usize,
	/// Envelopes that submitted successfully.
	pub successful: usize,
	/// Envelopes that errored on submission.
	pub failed: usize,
}

/// Submit a batch of envelopes via a single submitter. Returns
/// statistics for telemetry; does not propagate per-envelope errors
/// (each is individually retryable so a hard error on one shouldn't
/// abort the rest).
pub async fn submit_batch<Block, S>(
	envelopes: Vec<TicketEnvelope>,
	submitter: &S,
) -> SubmissionStats
where
	Block: BlockT,
	S: TicketSubmitter<Block>,
{
	let mut stats = SubmissionStats { attempted: envelopes.len(), ..Default::default() };
	for envelope in envelopes {
		match submitter.submit_ticket(envelope).await {
			Ok(()) => stats.successful += 1,
			Err(_) => stats.failed += 1,
		}
	}
	stats
}
