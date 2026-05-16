// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Helpers for extracting Sassafras-specific entries from a block
//! header's digest log.
//!
//! Two kinds of entries land in a Sassafras block's digest:
//!
//! - **`PreRuntime(SASS, encoded SlotClaim)`** — produced by the
//!   block author before runtime execution. Mandatory on every block.
//!   Tells the runtime + verifier *who* claimed the slot, *which* slot,
//!   and via *what* VRF signature. Extracted via [`extract_slot_claim`].
//!
//! - **`Consensus(SASS, encoded ConsensusLog)`** — produced by the
//!   *runtime* (specifically `pallet_sassafras` during epoch
//!   transition) and emitted into the digest log. Mandatory in the
//!   first block of each epoch (carrying [`NextEpochDescriptor`]) and
//!   conditionally on authority disablement. Extracted via
//!   [`extract_consensus_log`] / [`extract_next_epoch_descriptor`].
//!
//! - **`Seal(SASS, encoded AuthoritySignature)`** — produced by the
//!   block author after the runtime has produced the header. Strips
//!   off before block hashing in some flows; we don't read it here
//!   because the cryptographic guarantee comes from the SlotClaim
//!   pre-runtime VRF signature, not from the seal.
//!
//! All extraction functions return `Option<T>` rather than `Result<T,
//! _>`. Caller decides whether absence is an error — for example, the
//! SlotClaim is mandatory but a NextEpochDescriptor is only mandatory
//! on epoch-boundary blocks.

use sp_consensus_sassafras::{
	digests::{ConsensusLog, NextEpochDescriptor, SlotClaim},
	SASSAFRAS_ENGINE_ID,
};
use sp_runtime::{generic::DigestItem, traits::Header};
use codec::Decode;

/// Pull the `SlotClaim` pre-runtime digest entry out of a header.
/// Returns `None` if no entry with the Sassafras engine ID is present
/// or if the entry doesn't decode cleanly.
///
/// Mandatory on every Sassafras block. Callers should treat `None` as
/// "this isn't a Sassafras-produced block" and reject accordingly.
pub fn extract_slot_claim<H: Header>(header: &H) -> Option<SlotClaim> {
	header
		.digest()
		.logs()
		.iter()
		.find_map(|item: &DigestItem| SlotClaim::try_from(item).ok())
}

/// Pull a `ConsensusLog` from a header's `DigestItem::Consensus(SASS, _)`.
///
/// Currently used to surface `NextEpochDescriptor` and `OnDisabled`
/// runtime-emitted entries. Returns the first match (multiple
/// consensus entries with the same engine ID would be ambiguous and
/// indicate a malformed header — callers can re-scan if they need
/// stricter handling).
pub fn extract_consensus_log<H: Header>(header: &H) -> Option<ConsensusLog> {
	header.digest().logs().iter().find_map(|item: &DigestItem| match item {
		DigestItem::Consensus(engine_id, payload) if *engine_id == SASSAFRAS_ENGINE_ID =>
			ConsensusLog::decode(&mut &payload[..]).ok(),
		_ => None,
	})
}

/// Convenience: pull a `NextEpochDescriptor` out of a header if and
/// only if the consensus log entry happens to be `NextEpochData`.
/// Returns `None` for any other consensus log variant or for absence.
///
/// Callers verifying epoch-boundary blocks should additionally check
/// "did we *expect* a NextEpochData here?" — this helper just decodes,
/// it doesn't enforce when the entry must be present.
pub fn extract_next_epoch_descriptor<H: Header>(header: &H) -> Option<NextEpochDescriptor> {
	match extract_consensus_log(header)? {
		ConsensusLog::NextEpochData(desc) => Some(desc),
		ConsensusLog::OnDisabled(_) => None,
	}
}
