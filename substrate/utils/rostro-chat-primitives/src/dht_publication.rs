// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Kademlia DHT publication / provider-query abstractions.
//!
//! Phase B4 of the MLS-chat plan. Defines the trait surface that
//! the libp2p Kademlia binding in gemini-node (Phase B6) plugs into
//! to expose share-routing metadata over the DHT.
//!
//! ## The provider-record model
//!
//! Recipients can't query the DHT for "what message_ids are
//! waiting for me" because the DHT carries no plaintext metadata
//! about messages — only the recipient's [`PickupKey`] is
//! observable on the wire. So the routing layer uses Kademlia's
//! **provider record** pattern (the same primitive libp2p uses for
//! IPFS content routing):
//!
//! 1. **Relay-side announcement.** When a relay has any stored
//!    shares for a given pickup_key, it calls
//!    [`DhtAnnouncer::announce_provider`] to register itself in
//!    the DHT as a provider for that key. Kademlia auto-republishes
//!    provider records periodically (libp2p's default is ~24 h);
//!    a relay that stops announcing has its record expire naturally
//!    once republish stops.
//! 2. **Recipient-side lookup.** A recipient queries
//!    [`DhtProviderQuery::query_providers`] with their own pickup
//!    key. Kademlia walks the DHT and returns the set of relay
//!    [`RelayPubkey`]s currently providing that key.
//! 3. **Fetch.** Recipient connects to each returned relay via
//!    `/rostro/chat-fetch/1` (see [`crate::fetch_protocol`]) and
//!    asks for their shares.
//!
//! The DHT layer never carries the shares themselves — only the
//! "who has shares" hint. Two-step lookup (DHT → relay) is the
//! standard libp2p content-routing dance.
//!
//! ## What the store contributes
//!
//! The DHT layer needs to know **which pickup keys to announce.**
//! That's a function of the store's contents:
//! [`crate::store_protocol::ShareStore::pickup_keys`] returns every
//! pickup_key currently backed by at least one stored share. The
//! relay's announcement task calls this periodically (or after each
//! insert / sweep) and announces the set.
//!
//! ## What this crate does NOT do
//!
//! - **Not the libp2p Kademlia binding.** That lives in gemini-node
//!   (Phase B6) and is the minimal rc-network shim. This crate only
//!   defines the trait surface so the binding plugs into a
//!   transport-agnostic abstraction.
//! - **Not provider-record lifecycle policy.** "When to call
//!   announce_provider" is the relay's policy: typically on first
//!   insert + on a periodic refresh tick. "When to stop_providing"
//!   is similar — Kademlia's natural republish-expiry handles the
//!   simple case; explicit stop_providing is an optimization.

use alloc::vec::Vec;

use crate::descriptor::{PickupKey, RelayPubkey};

/// Errors a [`DhtProviderQuery`] implementation may surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtQueryError {
	/// Kademlia walk timed out or returned no peers in the search
	/// radius. May indicate a sparsely-populated DHT or a network
	/// partition.
	Timeout,
	/// Underlying libp2p transport error.
	Transport,
}

/// Relay-side: announce that this relay holds shares for a given
/// pickup key. The libp2p binding maps this to Kademlia's
/// `start_providing` call.
///
/// Implementations are non-blocking — the actual DHT walk happens
/// asynchronously inside libp2p. Failure modes (transport errors,
/// bootstrap issues) are observable in libp2p's event stream, not
/// in this trait's return value. The trait stays simple to keep
/// the Apache-2.0 surface free of transport concerns.
pub trait DhtAnnouncer {
	/// Begin advertising this relay as a provider for `pickup_key`.
	/// Safe to call repeatedly with the same key — implementations
	/// deduplicate or refresh the provider record.
	fn announce_provider(&self, pickup_key: PickupKey);

	/// Stop advertising. Called when the last share under
	/// `pickup_key` has been swept from the store. Optional in the
	/// sense that Kademlia's republish-expiry will eventually let
	/// the record lapse anyway; explicit stop is an optimization
	/// for cleaner DHT state.
	fn stop_providing(&self, pickup_key: PickupKey);
}

/// Recipient-side: query the DHT for relays currently providing
/// for a given pickup key. The libp2p binding maps this to
/// Kademlia's `get_providers` call.
///
/// Returns the set of relay [`RelayPubkey`]s the DHT reports as
/// providers. The recipient then connects to each via
/// `/rostro/chat-fetch/1` to retrieve their stored shares.
///
/// Implementations are blocking-or-async at the caller's choice —
/// the simple version is a synchronous wait on the Kademlia
/// future. Async variants live one layer up.
pub trait DhtProviderQuery {
	type Error;

	/// Walk the DHT and return current providers for `pickup_key`.
	fn query_providers(
		&mut self,
		pickup_key: PickupKey,
	) -> Result<Vec<RelayPubkey>, Self::Error>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::descriptor::GroupId;
	use alloc::collections::{BTreeMap, BTreeSet};
	use core::cell::RefCell;

	/// In-memory stub announcer: tracks which pickup_keys are
	/// currently being advertised. Used by integration tests that
	/// pair an AnnouncingShareStore with a real / stub announcer.
	#[derive(Default)]
	struct StubAnnouncer {
		active: RefCell<BTreeSet<PickupKey>>,
	}

	impl StubAnnouncer {
		fn is_active(&self, key: &PickupKey) -> bool {
			self.active.borrow().contains(key)
		}
	}

	impl DhtAnnouncer for StubAnnouncer {
		fn announce_provider(&self, pickup_key: PickupKey) {
			self.active.borrow_mut().insert(pickup_key);
		}
		fn stop_providing(&self, pickup_key: PickupKey) {
			self.active.borrow_mut().remove(&pickup_key);
		}
	}

	#[test]
	fn announcer_tracks_added_keys() {
		let a = StubAnnouncer::default();
		let k1 = PickupKey::for_group(&GroupId([0x01; 32]));
		let k2 = PickupKey::for_group(&GroupId([0x02; 32]));
		a.announce_provider(k1);
		assert!(a.is_active(&k1));
		assert!(!a.is_active(&k2));
		a.announce_provider(k2);
		assert!(a.is_active(&k2));
	}

	#[test]
	fn announcer_drops_stopped_keys() {
		let a = StubAnnouncer::default();
		let k = PickupKey::for_group(&GroupId([0x03; 32]));
		a.announce_provider(k);
		assert!(a.is_active(&k));
		a.stop_providing(k);
		assert!(!a.is_active(&k));
	}

	#[test]
	fn announcer_dedupes_repeated_announce() {
		let a = StubAnnouncer::default();
		let k = PickupKey::for_group(&GroupId([0x04; 32]));
		a.announce_provider(k);
		a.announce_provider(k);
		a.announce_provider(k);
		// Set semantics — one entry regardless of call count.
		assert_eq!(a.active.borrow().len(), 1);
	}

	#[test]
	fn announcer_stop_on_unknown_key_is_noop() {
		let a = StubAnnouncer::default();
		let k = PickupKey::for_group(&GroupId([0x05; 32]));
		a.stop_providing(k);
		assert!(!a.is_active(&k));
	}

	// ── ProviderQuery stub ────────────────────────────────────────

	struct StubProviderQuery {
		table: BTreeMap<PickupKey, Vec<RelayPubkey>>,
	}

	impl DhtProviderQuery for StubProviderQuery {
		type Error = DhtQueryError;
		fn query_providers(
			&mut self,
			pickup_key: PickupKey,
		) -> Result<Vec<RelayPubkey>, DhtQueryError> {
			Ok(self.table.get(&pickup_key).cloned().unwrap_or_default())
		}
	}

	#[test]
	fn provider_query_returns_recorded_providers() {
		let k = PickupKey::for_group(&GroupId([0x10; 32]));
		let providers = alloc::vec![RelayPubkey([0xAA; 32]), RelayPubkey([0xBB; 32])];
		let mut table = BTreeMap::new();
		table.insert(k, providers.clone());
		let mut q = StubProviderQuery { table };
		assert_eq!(q.query_providers(k).unwrap(), providers);
	}

	#[test]
	fn provider_query_returns_empty_for_unknown_key() {
		let mut q = StubProviderQuery { table: BTreeMap::new() };
		let unknown = PickupKey::for_group(&GroupId([0x11; 32]));
		assert!(q.query_providers(unknown).unwrap().is_empty());
	}

	#[test]
	fn dht_query_error_is_distinguishable() {
		// Sanity that the error variants can be matched and
		// distinguished by callers.
		let e1 = DhtQueryError::Timeout;
		let e2 = DhtQueryError::Transport;
		assert_ne!(e1, e2);
	}
}
