// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Node-level admission gate for the `/rostro/chat-*` libp2p
//! protocols.
//!
//! Implements the channel-split invariant from the architecture
//! memo: **the chat-gossip channel is for non-validator peers
//! only.** Active GRANDPA authorities should not carry chat traffic
//! — they focus on consensus, and validator-to-validator chatter
//! has its own encrypted gossip channel (`validator-channel`).
//!
//! ## How the gate identifies validators
//!
//! In Substrate the libp2p node-identity Ed25519 key is **distinct
//! from** any GRANDPA authority key. We therefore cannot map an
//! inbound `PeerId` directly to an entry in
//! `GrandpaApi::grandpa_authorities()`.
//!
//! What we *can* do is consult the validator-channel's
//! [`SharedSessions`] map, which records the [`PeerId`] of every
//! peer that has successfully completed the validator-channel
//! handshake — i.e., every peer that has proven possession of a
//! currently-active GRANDPA authority pubkey. That handshake is
//! authoritative: a peer in the sessions map is a current
//! validator; a peer not in the map either isn't one or hasn't
//! handshaken yet.
//!
//! ## Default-admit for unknown peers
//!
//! We can't prove negative identity at the libp2p layer (no one
//! signs a "I am not a validator" attestation). So the conservative
//! default of the abstract
//! [`rostro_chat_primitives::admission::ChannelRole::Unknown`]
//! variant — reject — is the wrong fit here. Instead:
//!
//! - Peer is in [`SharedSessions`] → known validator → **reject**
//!   from chat substreams.
//! - Peer is NOT in [`SharedSessions`] → either a non-validator or
//!   a validator who hasn't completed the validator-channel
//!   handshake yet → **admit**.
//!
//! The window between a validator's node starting up and completing
//! its validator-channel handshake is short. During that window a
//! validator could receive chat traffic, but: (a) chat payloads are
//! opaque ciphertext under MLS / DR / Sealed Sender, (b) the
//! validator can simply not act on it, (c) the channel-split here
//! is an efficiency / scope concern, not a confidentiality one
//! (confidentiality is enforced by the cryptographic envelope
//! end-to-end).
//!
//! End-user-level admission (HW-attested cert presented at
//! JSON-RPC by mobile-app users) is a separate gate that lands in
//! Stage 2b on top of this one.
//!
//! ## Replacement for `TODO(B6b)`
//!
//! This module closes the `TODO(B6b)` markers in
//! `chat_chunk_protocol.rs` and `chat_fetch_protocol.rs`.

use rc_network::PeerId;

use crate::validator_channel::SharedSessions;

/// Returns `true` if `peer` is admitted to the chat substreams.
///
/// Peers that have a live validator-channel session (i.e., have
/// proven themselves to be current GRANDPA authorities) are denied;
/// all others are admitted. See the module documentation for the
/// rationale.
pub fn is_chat_admitted(sessions: &SharedSessions, peer: &PeerId) -> bool {
	!sessions.lock().contains_key(peer)
}

#[cfg(test)]
mod tests {
	use super::*;
	use rostro_validator_channel::{handshake_shared_secret, Session};
	use std::collections::HashMap;
	use std::sync::Arc;
	use parking_lot::Mutex;
	use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Secret};

	/// Build a placeholder Session for "this peer is a known
	/// validator." The keys/transcript don't matter for the
	/// admission decision — the test only cares whether the peer is
	/// present in the sessions map.
	fn dummy_session() -> Session {
		let local_secret = X25519Secret::from([0x11u8; 32]);
		let peer_pub = X25519Pub::from([0x22u8; 32]);
		let shared = handshake_shared_secret(&local_secret, &peer_pub);
		Session::from_handshake_initiator(shared, local_secret, peer_pub)
	}

	#[test]
	fn unknown_peer_is_admitted() {
		let sessions: SharedSessions = Arc::new(Mutex::new(HashMap::new()));
		let stranger = PeerId::random();
		assert!(
			is_chat_admitted(&sessions, &stranger),
			"a peer with no validator-channel session is admitted",
		);
	}

	#[test]
	fn known_validator_is_rejected() {
		let sessions: SharedSessions = Arc::new(Mutex::new(HashMap::new()));
		let validator = PeerId::random();
		sessions.lock().insert(validator, dummy_session());
		assert!(
			!is_chat_admitted(&sessions, &validator),
			"a peer with a live validator-channel session is rejected from chat",
		);
	}

	#[test]
	fn admission_tracks_session_lifecycle() {
		let sessions: SharedSessions = Arc::new(Mutex::new(HashMap::new()));
		let peer = PeerId::random();

		// Before handshake: admitted.
		assert!(is_chat_admitted(&sessions, &peer));

		// Handshake completes: rejected.
		sessions.lock().insert(peer, dummy_session());
		assert!(!is_chat_admitted(&sessions, &peer));

		// Peer disconnects (validator-channel removes from map):
		// admitted again. (Their next chat request before any
		// subsequent validator-channel handshake will be admitted —
		// the validator-channel handshake-on-reconnect is what
		// repopulates the map.)
		sessions.lock().remove(&peer);
		assert!(is_chat_admitted(&sessions, &peer));
	}
}
