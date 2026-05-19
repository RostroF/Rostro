// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Share-fetch protocol primitives (server-side of
//! `/rostro/chat-fetch/1`).
//!
//! Recipient queries a relay with a pickup key (their domain-
//! separated DHT lookup key); relay returns all stored shares
//! matching that pickup key, up to a response cap.
//!
//! ## What this module is
//!
//! - SCALE-encoded [`FetchRequest`] / [`FetchResponse`] /
//!   [`FetchedShare`] wire types
//! - [`handle_fetch_request`]: pure function that calls
//!   [`crate::store_protocol::ShareStore::get_by_pickup_key`]
//!   and assembles a response respecting [`MAX_FETCH_RESPONSE_SHARES`]
//! - [`process_fetch_request_bytes`]: byte-in/byte-out shim for
//!   the libp2p adapter (the Apache-2.0 surface; gemini-node's
//!   rc-network wiring just calls this with raw bytes)
//!
//! ## What this module is NOT
//!
//! - **Not the libp2p binding.** That lands in Phase B6 as a
//!   minimal `rc-network` adapter in gemini-node.
//! - **Not rate-limiting / abuse control.** A relay receiving a
//!   flood of pickup queries handles that at the libp2p admission
//!   layer (Phase B5), not here.

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::descriptor::{PickupKey, ShareDescriptor};
use crate::store_protocol::ShareStore;
use crate::verify::ShareMacTag;

/// Hard cap on the number of shares returned in a single fetch
/// response. Bounds response size + handler workload. With
/// per-share cap [`crate::store_protocol::MAX_SHARE_BYTES`] = 4 MiB,
/// 32 shares = 128 MiB worst-case response. Real chat traffic is
/// kilobytes per message, so 32 covers many messages comfortably.
///
/// If a recipient legitimately has more than 32 shares waiting at a
/// single relay, they can issue successive fetches and the relay
/// will return progressively older entries (no pagination protocol
/// yet — that's a follow-up).
pub const MAX_FETCH_RESPONSE_SHARES: usize = 32;

/// On-the-wire fetch request from recipient to relay.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct FetchRequest {
	/// Recipient's domain-separated DHT pickup key. The relay
	/// returns all shares whose descriptor's `pickup_key` matches.
	pub pickup_key: PickupKey,
}

/// One share returned by [`FetchResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct FetchedShare {
	/// Descriptor as originally stored (relay_pubkey, message_id,
	/// share_index, total_shares, pickup_key, expires_at_unix_ts).
	pub descriptor: ShareDescriptor,
	/// XOR-stripe share bytes.
	pub share_bytes: Vec<u8>,
	/// Per-share MAC tag — recipient verifies on assembly.
	pub mac_tag: ShareMacTag,
}

/// On-the-wire fetch response. Carries up to
/// [`MAX_FETCH_RESPONSE_SHARES`] matching shares. Empty `shares` =
/// "no entries for this pickup key" (a legitimate answer, not an
/// error).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct FetchResponse {
	pub shares: Vec<FetchedShare>,
}

/// Server-side handler. Looks up matching shares in `store`,
/// truncates to [`MAX_FETCH_RESPONSE_SHARES`], returns the response.
///
/// The recipient is expected to verify the MAC on each returned
/// share before XOR-combining (see
/// [`crate::stripe::combine_xor_authenticated`]). This handler does
/// NOT verify MACs — the relay doesn't have the MAC key, and the
/// recipient is the only party authorized to authenticate the data.
pub fn handle_fetch_request<S: ShareStore + ?Sized>(
	store: &S,
	request: &FetchRequest,
) -> FetchResponse {
	let mut matches = store.get_by_pickup_key(&request.pickup_key);
	if matches.len() > MAX_FETCH_RESPONSE_SHARES {
		matches.truncate(MAX_FETCH_RESPONSE_SHARES);
	}
	let shares = matches
		.into_iter()
		.map(|(descriptor, share_bytes, mac_tag)| FetchedShare {
			descriptor,
			share_bytes,
			mac_tag,
		})
		.collect();
	FetchResponse { shares }
}

/// Byte-in / byte-out wrapper around [`handle_fetch_request`].
/// The libp2p adapter in gemini-node calls this from its rc-network
/// adapter — keeping it here in the Apache-2.0 crate means the
/// adapter stays minimal (no SCALE encode/decode in the GPL-3.0 zone).
///
/// On decode failure of the inbound payload, returns an
/// encoded empty [`FetchResponse`] as a generic decline. Caller
/// inspects the `decoded_ok` boolean to distinguish "decoded OK,
/// no shares matched" from "decode failed."
pub fn process_fetch_request_bytes<S: ShareStore + ?Sized>(
	store: &S,
	payload: &[u8],
) -> (Vec<u8>, bool) {
	let request = match FetchRequest::decode(&mut &payload[..]) {
		Ok(r) => r,
		Err(_) => {
			let resp = FetchResponse { shares: Vec::new() };
			return (resp.encode(), false);
		},
	};
	let response = handle_fetch_request(store, &request);
	(response.encode(), true)
}

/// Client-side abstraction: a thing that turns a [`FetchRequest`]
/// into a [`FetchResponse`]. Mirrors
/// [`crate::store_protocol::StoreTransport`] for the read path.
pub trait FetchTransport {
	type Error;

	/// Send the request, await the response.
	fn send_request(&mut self, request: FetchRequest) -> Result<FetchResponse, Self::Error>;
}

/// Helper: issue a [`FetchRequest`] via `transport`, return the
/// response. The recipient-side policy (which relays to query,
/// how to merge responses across relays) is the caller's
/// responsibility.
pub fn fetch_from_relay<T: FetchTransport>(
	transport: &mut T,
	request: FetchRequest,
) -> Result<FetchResponse, T::Error> {
	transport.send_request(request)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::descriptor::{
		GroupId, MessageId, RelayPubkey, ShareDescriptor, UnixTimestamp,
		CHAT_TTL_SECONDS,
	};
	use crate::store_protocol::{StoreInsertError, ShareStore as ShareStoreTrait};
	use crate::verify::mac_share;
	use alloc::collections::BTreeMap;
	use alloc::sync::Arc;
	use core::cell::RefCell;

	const NOW_TS: UnixTimestamp = 1_700_000_000;

	fn make_descriptor(
		message_id_byte: u8,
		share_index: u8,
		pickup_byte: u8,
	) -> ShareDescriptor {
		ShareDescriptor {
			relay_pubkey: RelayPubkey([0x11; 32]),
			message_id: MessageId([message_id_byte; 32]),
			share_index,
			total_shares: 5,
			pickup_key: PickupKey::for_group(&GroupId([pickup_byte; 32])),
			expires_at_unix_ts: NOW_TS + CHAT_TTL_SECONDS,
		}
	}

	struct StubStore {
		entries:
			RefCell<BTreeMap<(MessageId, u8), (ShareDescriptor, Vec<u8>, ShareMacTag)>>,
	}

	impl StubStore {
		fn new() -> Self {
			Self { entries: RefCell::new(BTreeMap::new()) }
		}
	}

	impl ShareStoreTrait for StubStore {
		fn insert(
			&self,
			descriptor: ShareDescriptor,
			share_bytes: Vec<u8>,
			mac_tag: ShareMacTag,
		) -> Result<(), StoreInsertError> {
			let mut e = self.entries.borrow_mut();
			let key = (descriptor.message_id, descriptor.share_index);
			if e.contains_key(&key) {
				return Err(StoreInsertError::DuplicateShare);
			}
			e.insert(key, (descriptor, share_bytes, mac_tag));
			Ok(())
		}

		fn get_by_pickup_key(
			&self,
			pickup_key: &PickupKey,
		) -> Vec<(ShareDescriptor, Vec<u8>, ShareMacTag)> {
			self.entries
				.borrow()
				.values()
				.filter(|(d, _, _)| d.pickup_key == *pickup_key)
				.cloned()
				.collect()
		}
	}

	fn insert_share(store: &StubStore, mid: u8, idx: u8, pickup: u8, body: Vec<u8>) {
		let d = make_descriptor(mid, idx, pickup);
		let t = mac_share(&[0u8; 32], &body, idx);
		store.insert(d, body, t).unwrap();
	}

	// ── happy path ────────────────────────────────────────────────

	#[test]
	fn handle_returns_matching_shares() {
		let store = StubStore::new();
		insert_share(&store, 0x01, 0, 0x99, alloc::vec![1, 2, 3]);
		insert_share(&store, 0x01, 1, 0x99, alloc::vec![4, 5, 6]);
		insert_share(&store, 0x02, 0, 0x99, alloc::vec![7, 8, 9]);
		let pickup = PickupKey::for_group(&GroupId([0x99; 32]));
		let req = FetchRequest { pickup_key: pickup };
		let resp = handle_fetch_request(&store, &req);
		assert_eq!(resp.shares.len(), 3);
	}

	#[test]
	fn handle_returns_empty_when_no_match() {
		let store = StubStore::new();
		insert_share(&store, 0x01, 0, 0x55, alloc::vec![1, 2, 3]);
		let other_pickup = PickupKey::for_group(&GroupId([0xAA; 32]));
		let req = FetchRequest { pickup_key: other_pickup };
		let resp = handle_fetch_request(&store, &req);
		assert!(resp.shares.is_empty());
	}

	#[test]
	fn handle_returns_empty_for_empty_store() {
		let store = StubStore::new();
		let req = FetchRequest { pickup_key: PickupKey([0; 32]) };
		assert!(handle_fetch_request(&store, &req).shares.is_empty());
	}

	#[test]
	fn handle_respects_max_response_shares_cap() {
		let store = StubStore::new();
		// Insert more than the cap with the same pickup key.
		// Use distinct (message_id, share_index) pairs.
		let pickup_byte = 0x42;
		let total = MAX_FETCH_RESPONSE_SHARES + 10;
		for i in 0..total {
			// Cycle (message_id, share_index) to stay unique.
			let mid = (i / 5) as u8;
			let idx = (i % 5) as u8;
			// Use a different filler so we don't blow stub-store
			// duplicate detection across (mid, idx) reuses; instead
			// rotate mid to keep keys unique.
			let mid = mid.wrapping_add(1);
			insert_share(&store, mid, idx, pickup_byte, alloc::vec![i as u8]);
		}
		let pickup = PickupKey::for_group(&GroupId([pickup_byte; 32]));
		let req = FetchRequest { pickup_key: pickup };
		let resp = handle_fetch_request(&store, &req);
		assert_eq!(resp.shares.len(), MAX_FETCH_RESPONSE_SHARES);
	}

	#[test]
	fn returned_fetched_share_round_trips_to_input() {
		let store = StubStore::new();
		let mid = 0x77;
		let idx = 3;
		let body = alloc::vec![0xAB, 0xCD, 0xEF];
		insert_share(&store, mid, idx, 0x11, body.clone());
		let pickup = PickupKey::for_group(&GroupId([0x11; 32]));
		let resp = handle_fetch_request(&store, &FetchRequest { pickup_key: pickup });
		assert_eq!(resp.shares.len(), 1);
		assert_eq!(resp.shares[0].descriptor.message_id, MessageId([mid; 32]));
		assert_eq!(resp.shares[0].descriptor.share_index, idx);
		assert_eq!(resp.shares[0].share_bytes, body);
	}

	// ── SCALE roundtrips ──────────────────────────────────────────

	#[test]
	fn fetch_request_scale_roundtrip() {
		let r = FetchRequest { pickup_key: PickupKey([0x55; 32]) };
		let bytes = r.encode();
		assert_eq!(FetchRequest::decode(&mut &bytes[..]).unwrap(), r);
	}

	#[test]
	fn fetched_share_scale_roundtrip() {
		let s = FetchedShare {
			descriptor: make_descriptor(0x01, 0, 0x99),
			share_bytes: alloc::vec![1, 2, 3, 4],
			mac_tag: [0xAB; 32],
		};
		let bytes = s.encode();
		assert_eq!(FetchedShare::decode(&mut &bytes[..]).unwrap(), s);
	}

	#[test]
	fn fetch_response_scale_roundtrip_empty() {
		let r = FetchResponse { shares: Vec::new() };
		let bytes = r.encode();
		assert_eq!(FetchResponse::decode(&mut &bytes[..]).unwrap(), r);
	}

	#[test]
	fn fetch_response_scale_roundtrip_with_shares() {
		let r = FetchResponse {
			shares: alloc::vec![
				FetchedShare {
					descriptor: make_descriptor(0x01, 0, 0x99),
					share_bytes: alloc::vec![1, 2, 3],
					mac_tag: [0xAA; 32],
				},
				FetchedShare {
					descriptor: make_descriptor(0x02, 1, 0x99),
					share_bytes: alloc::vec![4, 5, 6, 7],
					mac_tag: [0xBB; 32],
				},
			],
		};
		let bytes = r.encode();
		assert_eq!(FetchResponse::decode(&mut &bytes[..]).unwrap(), r);
	}

	// ── byte shim ─────────────────────────────────────────────────

	#[test]
	fn process_bytes_returns_matching_shares() {
		let store = StubStore::new();
		insert_share(&store, 0x01, 0, 0xDD, alloc::vec![1, 2, 3]);
		let pickup = PickupKey::for_group(&GroupId([0xDD; 32]));
		let payload = FetchRequest { pickup_key: pickup }.encode();
		let (resp_bytes, decoded_ok) = process_fetch_request_bytes(&store, &payload);
		assert!(decoded_ok);
		let resp = FetchResponse::decode(&mut &resp_bytes[..]).unwrap();
		assert_eq!(resp.shares.len(), 1);
	}

	#[test]
	fn process_bytes_returns_decline_on_malformed() {
		let store = StubStore::new();
		let garbage = alloc::vec![0xFFu8; 4];
		let (resp_bytes, decoded_ok) = process_fetch_request_bytes(&store, &garbage);
		assert!(!decoded_ok);
		// Caller can still parse — empty response.
		let resp = FetchResponse::decode(&mut &resp_bytes[..]).unwrap();
		assert!(resp.shares.is_empty());
	}

	// ── client-side FetchTransport helper ─────────────────────────

	struct HonestTransport {
		store: Arc<StubStore>,
	}

	impl FetchTransport for HonestTransport {
		type Error = ();
		fn send_request(
			&mut self,
			request: FetchRequest,
		) -> Result<FetchResponse, Self::Error> {
			Ok(handle_fetch_request(&*self.store, &request))
		}
	}

	#[test]
	fn fetch_from_relay_via_transport() {
		let store = Arc::new(StubStore::new());
		insert_share(&store, 0x01, 0, 0xEE, alloc::vec![1, 2, 3]);
		let mut transport = HonestTransport { store: store.clone() };
		let pickup = PickupKey::for_group(&GroupId([0xEE; 32]));
		let resp =
			fetch_from_relay(&mut transport, FetchRequest { pickup_key: pickup }).unwrap();
		assert_eq!(resp.shares.len(), 1);
	}

	// ── default trait method ──────────────────────────────────────

	#[test]
	fn default_get_by_pickup_key_returns_empty() {
		// A ShareStore that only implements insert (relies on the
		// default get_by_pickup_key) returns empty matches —
		// fetch handler treats this as "no entries."
		struct InsertOnly;
		impl ShareStoreTrait for InsertOnly {
			fn insert(
				&self,
				_: ShareDescriptor,
				_: Vec<u8>,
				_: ShareMacTag,
			) -> Result<(), StoreInsertError> {
				Ok(())
			}
		}
		let store = InsertOnly;
		let req = FetchRequest { pickup_key: PickupKey([0; 32]) };
		assert!(handle_fetch_request(&store, &req).shares.is_empty());
	}
}
