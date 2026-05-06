// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rc_consensus::Verifier` implementation — wires the pure-crypto
//! [`verify_block`] core into substrate's import-queue protocol.
//!
//! ## What this layer does
//!
//! Substrate's import queue calls [`Verifier::verify`][rc_consensus::Verifier]
//! on each incoming block before any state-transition or storage
//! work. We:
//!
//! 1. Pull the parent hash out of the block's header.
//! 2. Ask [`EpochProvider`] for the epoch active at that parent.
//! 3. Build an [`EpochContext`] from the epoch struct.
//! 4. Build a `ticket_lookup` closure that asks [`TicketProvider`]
//!    for `slot_ticket(parent, slot)` on demand.
//! 5. Run [`verify_block`] — the pure-crypto pipeline that already
//!    enforces slot-claim VRF + ticket binding cross-checks.
//! 6. On success return the unmodified `BlockImportParams` so the
//!    rest of the import queue can do its job (state-transition,
//!    storage, finality).
//!
//! ## What this layer does NOT do
//!
//! - **No epoch-boundary handling.** If the block carries a
//!   `NextEpochDescriptor`, this verifier just passes the block
//!   through; recording the next-epoch authorities into chain state
//!   is `pallet_sassafras::on_initialize`'s job. Cross-checking the
//!   descriptor's contents against expected (e.g. that the
//!   authorities match the validator-selection algorithm's output)
//!   is an aux-schema enhancement (R2.5b).
//! - **No fork handling.** The verifier uses the block's parent hash
//!   to scope provider lookups; the import queue handles fork choice
//!   separately via `ForkChoiceStrategy`.
//! - **No equivocation reporting.** [`crate::EquivocationDetector`]
//!   is a separate component the service wires alongside the
//!   verifier; on detection, the reporter loop submits an unsigned
//!   extrinsic via `submit_report_equivocation_unsigned_extrinsic`.

use std::marker::PhantomData;

use rc_consensus::{BlockImportParams, ForkChoiceStrategy, Verifier as ConsensusVerifier};
use sp_runtime::{
	traits::{Block as BlockT, Header as HeaderT},
	DigestItem,
};

use sp_consensus_sassafras::SASSAFRAS_ENGINE_ID;

use crate::{
	epoch::EpochContext,
	providers::{EpochProvider, TicketProvider},
	verifier::verify_block,
};

/// Sassafras import-queue verifier. Plug into substrate's import
/// queue via `BasicQueue::new(...)` etc.
///
/// `EP` and `TP` are typically the same Client-backed type that
/// implements both provider traits, but they're split here so test
/// stubs can mock one independently.
pub struct SassafrasImportVerifier<Block, EP, TP> {
	epoch_provider: EP,
	ticket_provider: TP,
	_phantom: PhantomData<Block>,
}

impl<Block, EP, TP> SassafrasImportVerifier<Block, EP, TP> {
	/// Construct from provider impls. Both are typically the same
	/// `Arc<Client>` in production wiring.
	pub fn new(epoch_provider: EP, ticket_provider: TP) -> Self {
		Self { epoch_provider, ticket_provider, _phantom: PhantomData }
	}
}

#[async_trait::async_trait]
impl<Block, EP, TP> ConsensusVerifier<Block> for SassafrasImportVerifier<Block, EP, TP>
where
	Block: BlockT,
	EP: EpochProvider<Block>,
	TP: TicketProvider<Block>,
{
	async fn verify(
		&self,
		mut block: BlockImportParams<Block>,
	) -> Result<BlockImportParams<Block>, String> {
		// Strip the SASS Seal digest off the header before block-execution
		// hands it to the runtime's `final_checks`. The runtime computes
		// the expected digest from on_initialize/on_finalize state — it
		// has no knowledge of the post-execution Seal that the block
		// author signed. Leaving the Seal in place causes the runtime's
		// digest-count assertion to fail with "Number of digest items
		// must match that calculated."
		//
		// Pattern lifted from rc-consensus-aura's import_queue::check_header.
		// We pop, stash in post_digests so substrate appends it back to
		// the canonical block-storage form on success, and proceed.
		let seal = match block.header.digest_mut().pop() {
			Some(item @ DigestItem::Seal(engine_id, _))
				if engine_id == SASSAFRAS_ENGINE_ID =>
				item,
			Some(other) => {
				// Put it back if it wasn't ours — let the next layer
				// decide what to do with the unexpected entry.
				block.header.digest_mut().push(other);
				return Err("Sassafras: header's last digest entry is not a SASS Seal"
					.to_string());
			},
			None => return Err("Sassafras: header has no digest entries to seal-strip".to_string()),
		};
		block.post_digests.push(seal);

		let parent_hash = *block.header.parent_hash();

		let epoch = self
			.epoch_provider
			.epoch_at(parent_hash)
			.map_err(|e| format!("Sassafras: epoch lookup at {parent_hash:?}: {e}"))?;

		let ctx = EpochContext::from_epoch(&epoch);

		let ticket_provider = &self.ticket_provider;
		let lookup = |slot| {
			// Errors during lookup degrade to "no ticket bound" —
			// matches sc-consensus-aura's permissive shape. Hard
			// errors during epoch lookup already aborted above.
			ticket_provider.slot_ticket(parent_hash, slot).ok().flatten()
		};

		verify_block(&block.header, ctx, lookup)
			.map_err(|e| format!("Sassafras: block verification failed: {e}"))?;

		// Set fork choice. The import pipeline rejects blocks with
		// fork_choice=None as `IncompletePipeline`. LongestChain is
		// the right policy for a Sassafras-only chain at this stage —
		// GRANDPA's finality kicks in separately and will trim short
		// forks via its justification stream.
		if block.fork_choice.is_none() {
			block.fork_choice = Some(ForkChoiceStrategy::LongestChain);
		}

		Ok(block)
	}
}
