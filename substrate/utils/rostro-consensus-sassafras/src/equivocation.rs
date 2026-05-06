// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Equivocation detection: catch validators signing two different
//! blocks for the same slot.
//!
//! ## What "equivocation" means in Sassafras
//!
//! A validator who claims slot S in epoch E with their bandersnatch
//! key can produce *exactly one* block at that slot — the slot claim
//! is a VRF signature over a fixed input, so the signature is unique
//! per (validator, randomness, slot, epoch). If the same validator
//! signs two *different* block headers for the same slot, that's
//! cryptographic evidence of double-signing, slashable under the
//! protocol's economic-security rules.
//!
//! Two cases of equivocation:
//!
//! 1. **Same authority, same slot, two distinct headers** — the
//!    canonical case. Both headers carry the validator's slot-claim
//!    VRF signature; both verify; but they're distinct blocks. Direct
//!    proof for slashing.
//! 2. **Cross-key equivocation** (out of scope for this module) — if
//!    the same physical operator runs multiple keys and claims slots
//!    under each, that's not detectable from on-chain data alone.
//!
//! ## What this module provides
//!
//! - [`EquivocationDetector`] — in-memory state tracking the first
//!   header seen for each (slot, authority) pair. Calling
//!   [`EquivocationDetector::observe`] with a new header either
//!   records it as the first sighting, or returns an
//!   [`EquivocationProof`] if it conflicts with an earlier one.
//!
//! ## What this module does NOT do
//!
//! - **No slashing dispatch.** Producing the proof is half the job;
//!   the other half is calling
//!   `SassafrasApi::submit_report_equivocation_unsigned_extrinsic`
//!   to push the proof on-chain. That's R2.5's reporter loop, which
//!   needs runtime-API access via a Client handle.
//! - **No persistent state.** The detector is in-memory only. A
//!   restart loses the first-sighting cache; an attacker who
//!   equivocates across a node restart wouldn't be caught by *this*
//!   detector instance, though peers and other validators that didn't
//!   restart would. Persistence is an aux_schema concern.
//! - **No cross-validator gossip integration.** This detector only
//!   sees blocks the local node imports. The network as a whole
//!   catches equivocations through every honest node's local
//!   detection + on-chain reporting.

use sp_consensus_sassafras::{AuthorityId, EquivocationProof, Slot};
use sp_runtime::traits::Header as HeaderT;
use std::collections::HashMap;

use crate::{epoch::EpochContext, error::VerificationError, verifier::verify_header};

/// In-memory equivocation detector. Tracks the first verified header
/// seen for each (slot, authority) pair; raises an
/// [`EquivocationProof`] when a *different* header arrives for an
/// already-seen pair.
///
/// Construct one per node service (or per epoch — see
/// [`EquivocationDetector::clear`] for the latter pattern). The
/// detector owns header clones; memory grows with the number of
/// distinct (slot, authority) pairs observed, bounded in practice by
/// `epoch_length * max_authorities`.
pub struct EquivocationDetector<H: HeaderT> {
	seen: HashMap<(Slot, AuthorityId), H>,
}

impl<H: HeaderT> Default for EquivocationDetector<H> {
	fn default() -> Self {
		Self { seen: HashMap::new() }
	}
}

impl<H: HeaderT> EquivocationDetector<H> {
	/// Build an empty detector.
	pub fn new() -> Self {
		Self::default()
	}

	/// Drop all observed headers. Useful at epoch boundaries when the
	/// authority set rotates and old (slot, authority) keys can never
	/// produce new equivocations against current state.
	pub fn clear(&mut self) {
		self.seen.clear();
	}

	/// Observe a header. Verifies it against the supplied epoch
	/// context (so we don't record bogus claims), then either:
	///
	/// - records it as the first sighting for its (slot, authority)
	///   key, OR
	/// - returns `Some(EquivocationProof)` if a *different* header was
	///   already recorded for the same key.
	///
	/// Identical headers (same hash) re-observed return `None` — they
	/// aren't equivocations, they're duplicate imports.
	pub fn observe(
		&mut self,
		header: H,
		epoch: EpochContext<'_>,
	) -> Result<Option<EquivocationProof<H>>, VerificationError> {
		let verified = verify_header(&header, epoch)?;
		let slot = verified.slot;
		let offender = verified.authority.clone();
		drop(verified); // release the borrow on `header` before moving it below.

		let key = (slot, offender.clone());
		match self.seen.get(&key) {
			Some(prior) if prior.hash() == header.hash() => {
				// Same block, re-observed. Not an equivocation.
				Ok(None)
			},
			Some(prior) => {
				// Distinct headers, same (slot, authority). Equivocation.
				Ok(Some(EquivocationProof {
					offender,
					slot,
					first_header: prior.clone(),
					second_header: header,
				}))
			},
			None => {
				self.seen.insert(key, header);
				Ok(None)
			},
		}
	}

	/// Number of (slot, authority) pairs currently tracked. Useful for
	/// telemetry / leak detection.
	pub fn tracked_count(&self) -> usize {
		self.seen.len()
	}
}
