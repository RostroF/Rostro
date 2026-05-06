// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Provider traits abstracting the chain-state lookups the import-
//! queue verifier needs.
//!
//! At the verifier layer we need two things from chain state:
//!
//! 1. **The epoch context active at a given parent hash** —
//!    [`EpochProvider`]. The verifier rebuilds the bandersnatch VRF
//!    sign-data from `(randomness, slot, epoch_index)`, all of which
//!    live in the epoch struct. Production wiring queries
//!    `SassafrasApi::current_epoch()` (or `next_epoch` on epoch-
//!    boundary blocks) via a `Client` runtime-API handle.
//!
//! 2. **The ticket bound to a given slot at a given parent hash** —
//!    [`TicketProvider`]. Returns `Some(ticket_id, body)` for primary
//!    slots, `None` for fallback. Production wiring calls
//!    `SassafrasApi::slot_ticket(slot)` against the runtime API.
//!
//! Abstracting both as traits keeps the import-queue verifier testable
//! without dragging in a `Client` mock: tests provide stub
//! implementations that return canned values, the production service
//! plumbing (R3) supplies Client-backed implementations.

use sp_consensus_sassafras::{
	ticket::{TicketBody, TicketId},
	AuthorityId, Epoch, EquivocationProof, OpaqueKeyOwnershipProof, Slot,
};
use sp_runtime::traits::Block as BlockT;
use thiserror::Error;

/// Reasons a provider lookup can fail. Both verifier-layer providers
/// surface the same error type — caller can attribute via context.
#[derive(Debug, Error)]
pub enum ProviderError {
	/// Runtime API call surfaced an error (block hash unknown, runtime
	/// unavailable, decode failure, etc.).
	#[error("runtime API error: {0}")]
	Runtime(String),

	/// Caller asked for state at a block hash that doesn't exist /
	/// isn't yet imported.
	#[error("unknown block hash")]
	UnknownBlock,
}

/// Look up the Sassafras epoch context that should be in effect at
/// the given parent hash.
///
/// "At parent hash" because the block being verified hasn't been
/// imported yet — its epoch context comes from the chain state at its
/// parent. For epoch-boundary blocks that introduce a `NextEpochData`
/// digest, the verifier may need to consult the *next* epoch instead;
/// this trait provides the basic lookup, the verifier composes.
pub trait EpochProvider<Block: BlockT>: Send + Sync {
	/// Return the epoch context active at `parent_hash`.
	fn epoch_at(&self, parent_hash: Block::Hash) -> Result<Epoch, ProviderError>;

	/// Return the *next* epoch's context as known at `parent_hash`.
	/// Used for epoch-boundary blocks.
	fn next_epoch_at(&self, parent_hash: Block::Hash) -> Result<Epoch, ProviderError>;
}

/// Look up the ticket assigned to a given slot at a given parent hash.
///
/// Returns `None` for fallback / secondary slots that have no ticket
/// assignment. The verifier uses this to enforce the cross-check
/// policy in [`crate::verify_block`].
pub trait TicketProvider<Block: BlockT>: Send + Sync {
	/// Look up the ticket bound to `slot` per the chain state at
	/// `parent_hash`. `None` if no ticket is bound.
	fn slot_ticket(
		&self,
		parent_hash: Block::Hash,
		slot: Slot,
	) -> Result<Option<(TicketId, TicketBody)>, ProviderError>;
}

/// Generate a `KeyOwnershipProof` for an authority at a given parent
/// hash. Required by the equivocation-reporter flow before the proof
/// can be submitted on-chain.
///
/// Production wiring queries `SassafrasApi::generate_key_ownership_proof`.
/// Returns `None` if the runtime can't produce one (e.g. authority
/// rotated out, session-historical state pruned).
pub trait KeyOwnershipProver<Block: BlockT>: Send + Sync {
	/// Generate the opaque key-ownership proof for `authority` per
	/// chain state at `parent_hash`.
	fn generate_key_ownership_proof(
		&self,
		parent_hash: Block::Hash,
		authority: AuthorityId,
	) -> Result<Option<OpaqueKeyOwnershipProof>, ProviderError>;
}

/// Submit an equivocation report on-chain. Mirrors
/// `SassafrasApi::submit_report_equivocation_unsigned_extrinsic`.
///
/// Production wiring calls the runtime API, which crafts and gossips
/// an unsigned extrinsic. Returns `false` per the runtime API
/// convention if extrinsic construction fails — we surface that as an
/// `Err` so callers don't silently lose reports.
pub trait EquivocationReporter<Block: BlockT>: Send + Sync {
	/// Submit the equivocation proof bundle.
	fn submit_report(
		&self,
		proof: EquivocationProof<Block::Header>,
		key_owner_proof: OpaqueKeyOwnershipProof,
	) -> Result<(), ProviderError>;
}
