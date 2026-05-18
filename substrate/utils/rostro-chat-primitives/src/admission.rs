// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Channel admission gate — structural enforcement of the
//! validator/non-validator channel separation invariant.
//!
//! Phase B5 of the MLS-chat plan. The chat layer's threat model
//! requires that **the active validator set is not aware of the
//! chat channel** (validators focus on consensus) and conversely
//! that **non-validators cannot reach the validator-only encrypted
//! gossip channel**. Cryptographic domain separation in
//! `rostro-chat-dr` vs `rostro-validator-channel` is one half of
//! that enforcement; the other half is libp2p-substream admission
//! control — refuse to open `/rostro/chat-*` to a peer in the
//! active validator set, and refuse to open the validator channel
//! to anyone not in it.
//!
//! This module ships the **policy** that the rc-network adapter in
//! gemini-node (Phase B6) consults at substream-open time. The
//! actual role determination (looking up the peer's session key in
//! the on-chain active-validator set) is the caller's job via the
//! [`RoleResolver`] trait — implementations plug in whatever
//! authoritative source the relay uses (runtime API, cached
//! snapshot, etc.).
//!
//! ## Conservative default for Unknown
//!
//! When the role resolver can't determine a peer's role
//! (resolution timed out, peer claim hasn't been verified yet,
//! chain client unreachable), the admission policy defaults to
//! **reject for both channels**. Better to fail closed than admit
//! a peer to a channel they may not be entitled to.

use crate::descriptor::RelayPubkey;

/// A peer's role for the purposes of channel admission. Determined
/// from the relay's current view of the on-chain active validator
/// set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelRole {
	/// Peer's session key is in the current active validator set.
	/// Admitted to validator-channel, rejected from chat-channel.
	Validator,
	/// Peer is gate-passed but is NOT in the active validator set.
	/// Admitted to chat-channel, rejected from validator-channel.
	NonValidator,
	/// Could not determine the peer's role (chain unreachable,
	/// timeout, missing keys, etc.). Conservative: reject from
	/// BOTH channels.
	Unknown,
}

/// Resolves a peer's [`ChannelRole`] from the relay's view of the
/// chain. Implementations plug in the active-set source — a
/// runtime API query against the local client, a cached snapshot
/// of the validator set, a test stub, etc.
pub trait RoleResolver {
	/// Return the role for a peer identified by their
	/// [`RelayPubkey`]. Should not block; resolvers should
	/// pre-cache active-set membership.
	fn role(&self, peer: &RelayPubkey) -> ChannelRole;
}

/// `true` if a peer with `role` is admitted to the
/// `/rostro/chat-*` protocol family. Validators rejected,
/// non-validators admitted, Unknown rejected.
pub fn admit_to_chat_channel(role: ChannelRole) -> bool {
	matches!(role, ChannelRole::NonValidator)
}

/// `true` if a peer with `role` is admitted to the
/// `/rostro/validator-channel/*` protocol family. Validators
/// admitted, non-validators rejected, Unknown rejected.
pub fn admit_to_validator_channel(role: ChannelRole) -> bool {
	matches!(role, ChannelRole::Validator)
}

/// Resolve a peer's role via `resolver` and check whether they
/// should be admitted to the chat channel. Convenience wrapper
/// that combines the two operations for the common path.
pub fn admit_peer_to_chat<R: RoleResolver + ?Sized>(
	resolver: &R,
	peer: &RelayPubkey,
) -> bool {
	admit_to_chat_channel(resolver.role(peer))
}

/// Resolve a peer's role via `resolver` and check whether they
/// should be admitted to the validator channel.
pub fn admit_peer_to_validator_channel<R: RoleResolver + ?Sized>(
	resolver: &R,
	peer: &RelayPubkey,
) -> bool {
	admit_to_validator_channel(resolver.role(peer))
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::collections::BTreeMap;

	struct StubResolver {
		map: BTreeMap<RelayPubkey, ChannelRole>,
	}

	impl StubResolver {
		fn new() -> Self {
			Self { map: BTreeMap::new() }
		}
		fn with(mut self, peer: RelayPubkey, role: ChannelRole) -> Self {
			self.map.insert(peer, role);
			self
		}
	}

	impl RoleResolver for StubResolver {
		fn role(&self, peer: &RelayPubkey) -> ChannelRole {
			// Unknown is the conservative default for unmapped peers,
			// matching production behavior on a chain query miss.
			self.map.get(peer).copied().unwrap_or(ChannelRole::Unknown)
		}
	}

	const ALICE: RelayPubkey = RelayPubkey([0x01; 32]);
	const BOB: RelayPubkey = RelayPubkey([0x02; 32]);
	const STRANGER: RelayPubkey = RelayPubkey([0x99; 32]);

	// ── chat-channel admission ────────────────────────────────────

	#[test]
	fn chat_admits_non_validator() {
		assert!(admit_to_chat_channel(ChannelRole::NonValidator));
	}

	#[test]
	fn chat_rejects_validator() {
		assert!(!admit_to_chat_channel(ChannelRole::Validator));
	}

	#[test]
	fn chat_rejects_unknown() {
		assert!(!admit_to_chat_channel(ChannelRole::Unknown));
	}

	// ── validator-channel admission ───────────────────────────────

	#[test]
	fn validator_admits_validator() {
		assert!(admit_to_validator_channel(ChannelRole::Validator));
	}

	#[test]
	fn validator_rejects_non_validator() {
		assert!(!admit_to_validator_channel(ChannelRole::NonValidator));
	}

	#[test]
	fn validator_rejects_unknown() {
		assert!(!admit_to_validator_channel(ChannelRole::Unknown));
	}

	// ── symmetric exclusion ───────────────────────────────────────

	#[test]
	fn no_role_admits_to_both_channels() {
		for role in [
			ChannelRole::Validator,
			ChannelRole::NonValidator,
			ChannelRole::Unknown,
		] {
			assert!(
				!(admit_to_chat_channel(role) && admit_to_validator_channel(role)),
				"role {:?} should not be admitted to both channels",
				role,
			);
		}
	}

	#[test]
	fn every_role_admitted_to_at_most_one_channel() {
		// Validator: validator-channel only.
		assert!(admit_to_validator_channel(ChannelRole::Validator));
		assert!(!admit_to_chat_channel(ChannelRole::Validator));
		// NonValidator: chat-channel only.
		assert!(admit_to_chat_channel(ChannelRole::NonValidator));
		assert!(!admit_to_validator_channel(ChannelRole::NonValidator));
		// Unknown: neither.
		assert!(!admit_to_chat_channel(ChannelRole::Unknown));
		assert!(!admit_to_validator_channel(ChannelRole::Unknown));
	}

	// ── resolver integration ──────────────────────────────────────

	#[test]
	fn resolver_drives_chat_admission() {
		let resolver = StubResolver::new()
			.with(ALICE, ChannelRole::Validator)
			.with(BOB, ChannelRole::NonValidator);
		assert!(!admit_peer_to_chat(&resolver, &ALICE), "validator rejected");
		assert!(admit_peer_to_chat(&resolver, &BOB), "non-validator admitted");
		assert!(
			!admit_peer_to_chat(&resolver, &STRANGER),
			"unmapped peer = Unknown = rejected"
		);
	}

	#[test]
	fn resolver_drives_validator_channel_admission() {
		let resolver = StubResolver::new()
			.with(ALICE, ChannelRole::Validator)
			.with(BOB, ChannelRole::NonValidator);
		assert!(admit_peer_to_validator_channel(&resolver, &ALICE));
		assert!(!admit_peer_to_validator_channel(&resolver, &BOB));
		assert!(!admit_peer_to_validator_channel(&resolver, &STRANGER));
	}

	#[test]
	fn unknown_default_is_conservative_reject() {
		// Empty resolver = all peers Unknown = rejected from both
		// channels.
		let resolver = StubResolver::new();
		assert!(!admit_peer_to_chat(&resolver, &ALICE));
		assert!(!admit_peer_to_chat(&resolver, &BOB));
		assert!(!admit_peer_to_validator_channel(&resolver, &ALICE));
		assert!(!admit_peer_to_validator_channel(&resolver, &BOB));
	}

	#[test]
	fn role_enum_has_eq_and_hash() {
		// Sanity that ChannelRole can key a HashMap / be deduped.
		use alloc::collections::BTreeSet;
		let mut s = BTreeSet::new();
		s.insert(format!("{:?}", ChannelRole::Validator));
		s.insert(format!("{:?}", ChannelRole::NonValidator));
		s.insert(format!("{:?}", ChannelRole::Unknown));
		assert_eq!(s.len(), 3);
	}
}
