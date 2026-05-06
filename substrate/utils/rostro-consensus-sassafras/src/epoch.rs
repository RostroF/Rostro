// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Typed wrapper around the per-epoch context the slot-claim verifier
//! needs.
//!
//! `sp_consensus_sassafras::Epoch` carries everything (index, start,
//! length, randomness, authorities, config) but it's a runtime-API
//! return type with codec / SCALE wiring that's heavier than what
//! pure-verifier code wants. [`EpochContext`] is the thin slice of
//! that struct the slot-claim verifier actually consumes:
//!
//! - `index` — folded into the VRF sign-data.
//! - `randomness` — folded into the VRF sign-data.
//! - `authorities` — looked up by the claim's `authority_idx` field.
//!
//! Built either from a runtime-API `Epoch` (lossy: drops `start`,
//! `length`, `config`) or directly from primitive components, depending
//! on caller's source.

use sp_consensus_sassafras::{AuthorityId, Epoch, Randomness, Slot};

use crate::error::VerificationError;

/// Per-epoch context the slot-claim verifier requires.
///
/// Borrows the authorities slice — keeps allocation off the hot path
/// when the caller already holds an `Epoch` or equivalent.
#[derive(Clone, Copy, Debug)]
pub struct EpochContext<'a> {
	/// Epoch index, folded into the VRF sign-data.
	pub index: u64,
	/// Per-epoch randomness, folded into the VRF sign-data.
	pub randomness: &'a Randomness,
	/// Authority public keys, indexed by `SlotClaim::authority_idx`.
	pub authorities: &'a [AuthorityId],
}

impl<'a> EpochContext<'a> {
	/// Construct from a runtime-API `Epoch`. Cheap — borrows the
	/// authorities and randomness fields directly.
	pub fn from_epoch(epoch: &'a Epoch) -> Self {
		Self {
			index: epoch.index,
			randomness: &epoch.randomness,
			authorities: &epoch.authorities,
		}
	}

	/// Look up the authority public key for a given index, or return
	/// the structured out-of-range error.
	pub fn authority(&self, idx: u32) -> Result<&'a AuthorityId, VerificationError> {
		self.authorities.get(idx as usize).ok_or(VerificationError::AuthorityIndexOutOfRange {
			index: idx,
			set_size: self.authorities.len(),
		})
	}

	/// Whether a given slot falls inside `[start, start + length)`.
	/// Used by helpers that enforce the slot/epoch mapping (the bare
	/// VRF verifier doesn't, since it can't see the epoch's start
	/// slot).
	pub fn slot_falls_in_epoch(&self, slot: Slot, epoch_start: Slot, epoch_length: u32) -> bool {
		let s: u64 = slot.into();
		let start: u64 = epoch_start.into();
		s >= start && s < start.saturating_add(u64::from(epoch_length))
	}
}
