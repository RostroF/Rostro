// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Share-storage protocol primitives (server-side of
//! `/rostro/chat-stripe/1`).
//!
//! Sender fans out a [`StoreRequest`] per share to N distinct
//! relays. Each relay validates the descriptor + tag, inserts into
//! its [`ShareStore`], and replies with [`StoreResponse::Stored`]
//! (success) or [`StoreResponse::Rejected`] (validation or capacity
//! failure).
//!
//! ## What this module is
//!
//! - SCALE-encoded [`StoreRequest`] / [`StoreResponse`] wire types
//! - [`ShareStore`] trait abstracting the relay's storage backend
//! - [`handle_store_request`] pure function: validates the request,
//!   calls into the [`ShareStore`], returns a structured response.
//!
//! ## What this module is NOT
//!
//! - **Not the libp2p binding.** The gemini-node integration that
//!   wires [`handle_store_request`] to a request-response substream
//!   is a separate module (Phase B1 follow-up).
//! - **Not the mlock'd in-memory store.** The concrete
//!   [`ShareStore`] impl with TTL sweep + capacity bound + mlock'd
//!   buffers lands in B2; this module only defines the abstract
//!   trait.
//! - **Not the fetch path.** B3 ships a separate
//!   `/rostro/chat-fetch/1` protocol for recipients to query
//!   their pickup_key.

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::descriptor::{ShareDescriptor, UnixTimestamp};
use crate::stripe::MAX_SHARES;
use crate::verify::{ShareMacTag, MAC_TAG_LEN};

/// Hard cap on a single share's byte length. 4 MiB is generous for
/// a chat message divided into a handful of shares — typical chat
/// payloads are kilobytes. Cap exists so a malicious sender can't
/// claim to be sending a 100 GB share and OOM the relay.
pub const MAX_SHARE_BYTES: usize = 4 * 1024 * 1024;

/// On-the-wire share-store request from sender to relay.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct StoreRequest {
	/// Public descriptor for this share (DHT-publishable).
	pub descriptor: ShareDescriptor,
	/// XOR-stripe share bytes — opaque ciphertext fragment.
	pub share_bytes: Vec<u8>,
	/// Per-share MAC tag, keyed by the sender+recipient session
	/// secret (see [`crate::verify::mac_share`]). Relays do not
	/// verify the MAC (they don't have the key); only recipients
	/// verify on assembly.
	pub mac_tag: ShareMacTag,
}

/// Relay's reply to a [`StoreRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum StoreResponse {
	/// Share accepted and persisted in the relay's store.
	Stored,
	/// Share rejected. The variant communicates why so the sender
	/// can choose to retry, fan out to a different relay, or
	/// abandon this share.
	Rejected(StoreRejection),
}

/// Concrete rejection reasons returned by [`handle_store_request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum StoreRejection {
	/// `descriptor.expires_at_unix_ts` is outside the receive-time
	/// bounds for `now_unix_ts` — either already expired beyond the
	/// past grace window, or claiming a far-future expiry the
	/// receiver refuses to squat on. See
	/// [`crate::descriptor::ShareDescriptor::expiry_within_bounds`].
	DescriptorExpired,
	/// `descriptor.share_index >= descriptor.total_shares` —
	/// nonsensical index; the descriptor is internally inconsistent.
	ShareIndexOutOfRange,
	/// `descriptor.total_shares > MAX_TOTAL_SHARES` — beyond the
	/// protocol's per-message share cap.
	TotalSharesTooLarge,
	/// `descriptor.total_shares < 2` — degenerate "stripe" with
	/// only one share, which provides no relay-side confidentiality.
	TotalSharesTooSmall,
	/// `share_bytes.len() > MAX_SHARE_BYTES` — payload exceeds the
	/// protocol's per-share size cap.
	ShareTooLarge,
	/// Relay has no remaining capacity (memory budget exhausted).
	StorageFull,
	/// `(message_id, share_index)` already present in this relay's
	/// store — duplicate insert.
	DuplicateShare,
}

/// Errors a [`ShareStore`] implementation may surface from
/// [`ShareStore::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreInsertError {
	/// `(message_id, share_index)` is already present.
	DuplicateShare,
	/// Capacity exhausted; relay refuses additional shares until
	/// some are evicted by TTL sweep.
	StorageFull,
}

/// Abstraction over a relay's share store. The gemini-node binding
/// passes an `Arc<dyn ShareStore>` to the protocol handlers; the
/// concrete impl (Phase B2) is the mlock'd in-memory store.
pub trait ShareStore {
	/// Insert a (descriptor, share_bytes, mac_tag) triple, keyed
	/// internally by `(descriptor.message_id, descriptor.share_index)`
	/// and indexed for lookup by `descriptor.pickup_key`.
	///
	/// Returns `Ok(())` on success, [`StoreInsertError`] otherwise.
	/// Implementations are expected to be cheap to call concurrently
	/// (the handler may dispatch in a multi-threaded reactor).
	fn insert(
		&self,
		descriptor: ShareDescriptor,
		share_bytes: Vec<u8>,
		mac_tag: ShareMacTag,
	) -> Result<(), StoreInsertError>;

	/// Return all `(descriptor, share_bytes, mac_tag)` triples
	/// whose `descriptor.pickup_key == pickup_key`. Used by the
	/// fetch path (`/rostro/chat-fetch/1`) to serve a recipient's
	/// pickup query.
	///
	/// Implementations clone the share bytes so the caller can
	/// consume them freely; the in-store copy remains held until
	/// its TTL expires.
	///
	/// Default: returns empty (a store can be insert-only).
	fn get_by_pickup_key(
		&self,
		_pickup_key: &crate::descriptor::PickupKey,
	) -> Vec<(ShareDescriptor, Vec<u8>, ShareMacTag)> {
		Vec::new()
	}

	/// Return every pickup_key currently backed by at least one
	/// stored share. The libp2p Kademlia binding (Phase B6) reads
	/// this list periodically and calls
	/// [`crate::dht_publication::DhtAnnouncer::announce_provider`]
	/// for each, so the recipient's
	/// [`crate::dht_publication::DhtProviderQuery::query_providers`]
	/// lookup finds this relay.
	///
	/// Order is implementation-defined; callers should not depend
	/// on it. Calling this repeatedly is allowed — the libp2p
	/// republish task may invoke it on every tick.
	///
	/// Default: returns empty (a store with no observable pickup
	/// state acts as if it isn't providing for anything).
	fn pickup_keys(&self) -> Vec<crate::descriptor::PickupKey> {
		Vec::new()
	}
}

/// Server-side handler. Validates the request, defers to `store`
/// for persistence, returns a structured [`StoreResponse`].
///
/// `now_unix_ts` is the receiver's local wall-clock; used to bound
/// the descriptor's expiry timestamp on receive (rejects past-too-far
/// AND future-too-far, the latter to prevent squatters). No chain
/// involvement.
///
/// **No signature verification here** — the share descriptor is a
/// public artifact (it ends up in the DHT); per-message integrity
/// is checked by the recipient via the share MAC, not at the
/// relay. The relay treats shares as opaque transit, not trusted
/// content.
pub fn handle_store_request<S: ShareStore + ?Sized>(
	store: &S,
	request: &StoreRequest,
	now_unix_ts: UnixTimestamp,
) -> StoreResponse {
	let d = &request.descriptor;

	// Descriptor sanity checks (cheap, before touching the store).
	if !d.expiry_within_bounds(now_unix_ts) {
		return StoreResponse::Rejected(StoreRejection::DescriptorExpired);
	}
	if (d.total_shares as usize) > MAX_SHARES {
		return StoreResponse::Rejected(StoreRejection::TotalSharesTooLarge);
	}
	if (d.total_shares as usize) < 2 {
		return StoreResponse::Rejected(StoreRejection::TotalSharesTooSmall);
	}
	if d.share_index >= d.total_shares {
		return StoreResponse::Rejected(StoreRejection::ShareIndexOutOfRange);
	}
	if request.share_bytes.len() > MAX_SHARE_BYTES {
		return StoreResponse::Rejected(StoreRejection::ShareTooLarge);
	}
	// MAC-tag length is structurally fixed by ShareMacTag = [u8; 32];
	// the encode/decode roundtrip enforces it. Belt-and-suspenders
	// check the constant so a future type change can't silently
	// invalidate this assumption.
	debug_assert_eq!(MAC_TAG_LEN, 32);

	match store.insert(d.clone(), request.share_bytes.clone(), request.mac_tag) {
		Ok(()) => StoreResponse::Stored,
		Err(StoreInsertError::DuplicateShare) => {
			StoreResponse::Rejected(StoreRejection::DuplicateShare)
		},
		Err(StoreInsertError::StorageFull) => {
			StoreResponse::Rejected(StoreRejection::StorageFull)
		},
	}
}

/// Byte-in / byte-out wrapper around [`handle_store_request`].
/// The libp2p binding in gemini-node calls this from its rc-network
/// adapter — keeping it here in the Apache-2.0 utility crate means
/// the gemini-node-side adapter stays minimal (no SCALE
/// encode/decode logic in the GPL-3.0 zone).
///
/// On `payload` that fails to SCALE-decode as a [`StoreRequest`],
/// returns an encoded `StoreResponse::Rejected(StoreRejection::ShareTooLarge)`
/// as a generic decline signal. Callers can distinguish "decode
/// failed" via the boolean return: `(response_bytes, decoded_ok)`.
pub fn process_store_request_bytes<S: ShareStore + ?Sized>(
	store: &S,
	now_unix_ts: UnixTimestamp,
	payload: &[u8],
) -> (Vec<u8>, bool) {
	let request = match StoreRequest::decode(&mut &payload[..]) {
		Ok(r) => r,
		Err(_) => {
			// Wire-format decode failure. Reply with a generic
			// rejection so the peer learns we didn't accept.
			let resp = StoreResponse::Rejected(StoreRejection::ShareTooLarge);
			return (resp.encode(), false);
		},
	};
	let response = handle_store_request(store, &request, now_unix_ts);
	(response.encode(), true)
}

/// Client-side abstraction: a thing that turns a [`StoreRequest`]
/// into a [`StoreResponse`]. Implementors plug in their own
/// libp2p / transport routing. The libp2p binding in gemini-node
/// provides a concrete impl for the production path; tests use
/// a closure-backed stub.
pub trait StoreTransport {
	type Error;

	/// Send the request, await the response.
	fn send_request(&mut self, request: StoreRequest) -> Result<StoreResponse, Self::Error>;
}

/// Helper: issue a [`StoreRequest`] via `transport`, return the
/// [`StoreResponse`]. The fan-out across multiple relays is the
/// caller's policy (one share per relay, or several relays per
/// share with replication for availability).
pub fn store_one_share<T: StoreTransport>(
	transport: &mut T,
	request: StoreRequest,
) -> Result<StoreResponse, T::Error> {
	transport.send_request(request)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::descriptor::{
		GroupId, MessageId, PickupKey, RelayPubkey, CHAT_TTL_SECONDS,
		MAX_TTL_SLOP_SECONDS, PAST_GRACE_SECONDS,
	};
	use crate::verify::mac_share;
	use alloc::collections::BTreeMap;
	use alloc::sync::Arc;
	use core::cell::RefCell;

	/// Reference unix timestamp used as "now" in tests. Arbitrary
	/// recent-past value; the only constraint is it leaves room to
	/// stamp expiries both before and after.
	const NOW_TS: UnixTimestamp = 1_700_000_000;

	fn make_descriptor(
		share_index: u8,
		total_shares: u8,
		expires_at_unix_ts: UnixTimestamp,
	) -> ShareDescriptor {
		ShareDescriptor {
			relay_pubkey: RelayPubkey([0x11; 32]),
			message_id: MessageId([0x22; 32]),
			share_index,
			total_shares,
			pickup_key: PickupKey::for_group(&GroupId([0x33; 32])),
			expires_at_unix_ts,
		}
	}

	fn make_request(d: ShareDescriptor, bytes: Vec<u8>) -> StoreRequest {
		let tag = mac_share(&[0u8; 32], &bytes, d.share_index);
		StoreRequest { descriptor: d, share_bytes: bytes, mac_tag: tag }
	}

	/// Stub HashMap-backed store for tests. Replaced by the
	/// mlock'd ephemeral store in B2.
	struct StubStore {
		entries: RefCell<BTreeMap<(MessageId, u8), (ShareDescriptor, Vec<u8>, ShareMacTag)>>,
		capacity: usize,
	}

	impl StubStore {
		fn new(capacity: usize) -> Self {
			Self { entries: RefCell::new(BTreeMap::new()), capacity }
		}
	}

	impl ShareStore for StubStore {
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
			if e.len() >= self.capacity {
				return Err(StoreInsertError::StorageFull);
			}
			e.insert(key, (descriptor, share_bytes, mac_tag));
			Ok(())
		}

		fn get_by_pickup_key(
			&self,
			pickup_key: &crate::descriptor::PickupKey,
		) -> Vec<(ShareDescriptor, Vec<u8>, ShareMacTag)> {
			self.entries
				.borrow()
				.values()
				.filter(|(d, _, _)| d.pickup_key == *pickup_key)
				.cloned()
				.collect()
		}
	}

	// ── happy path ────────────────────────────────────────────────

	#[test]
	fn store_accepts_well_formed_share() {
		let store = StubStore::new(100);
		let d = make_descriptor(0, 5, NOW_TS + CHAT_TTL_SECONDS);
		let req = make_request(d, alloc::vec![1, 2, 3, 4]);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Stored,
		);
		assert_eq!(store.entries.borrow().len(), 1);
	}

	#[test]
	fn store_accepts_multiple_shares_of_same_message() {
		let store = StubStore::new(100);
		for i in 0..5u8 {
			let d = make_descriptor(i, 5, NOW_TS + CHAT_TTL_SECONDS);
			let req = make_request(d, alloc::vec![i; 16]);
			assert_eq!(
				handle_store_request(&store, &req, NOW_TS),
				StoreResponse::Stored,
			);
		}
		assert_eq!(store.entries.borrow().len(), 5);
	}

	// ── rejections ────────────────────────────────────────────────

	#[test]
	fn rejects_descriptor_expired_in_past_beyond_grace() {
		let store = StubStore::new(100);
		// expires_at is well in the past — beyond PAST_GRACE_SECONDS.
		let d = make_descriptor(0, 5, NOW_TS - PAST_GRACE_SECONDS - 60);
		let req = make_request(d, alloc::vec![1, 2, 3]);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Rejected(StoreRejection::DescriptorExpired),
		);
		assert!(store.entries.borrow().is_empty());
	}

	#[test]
	fn rejects_descriptor_squatting_far_future() {
		let store = StubStore::new(100);
		// expires_at is well past the receive-time future bound.
		let d = make_descriptor(
			0,
			5,
			NOW_TS + CHAT_TTL_SECONDS + MAX_TTL_SLOP_SECONDS + 60,
		);
		let req = make_request(d, alloc::vec![1, 2, 3]);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Rejected(StoreRejection::DescriptorExpired),
		);
		assert!(store.entries.borrow().is_empty());
	}

	#[test]
	fn rejects_total_shares_too_large() {
		let store = StubStore::new(100);
		// total_shares > MAX_SHARES (64).
		let mut d = make_descriptor(0, 5, NOW_TS + CHAT_TTL_SECONDS);
		d.total_shares = (MAX_SHARES as u8).saturating_add(1);
		let req = make_request(d, alloc::vec![1]);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Rejected(StoreRejection::TotalSharesTooLarge),
		);
	}

	#[test]
	fn rejects_total_shares_too_small() {
		let store = StubStore::new(100);
		// total_shares = 1 is degenerate.
		let d = make_descriptor(0, 1, NOW_TS + CHAT_TTL_SECONDS);
		let req = make_request(d, alloc::vec![1]);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Rejected(StoreRejection::TotalSharesTooSmall),
		);
	}

	#[test]
	fn rejects_share_index_out_of_range() {
		let store = StubStore::new(100);
		// share_index == total_shares → out of range.
		let d = make_descriptor(5, 5, NOW_TS + CHAT_TTL_SECONDS);
		let req = make_request(d, alloc::vec![1]);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Rejected(StoreRejection::ShareIndexOutOfRange),
		);
	}

	#[test]
	fn rejects_oversized_share() {
		let store = StubStore::new(100);
		let d = make_descriptor(0, 5, NOW_TS + CHAT_TTL_SECONDS);
		let huge = alloc::vec![0u8; MAX_SHARE_BYTES + 1];
		let req = make_request(d, huge);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Rejected(StoreRejection::ShareTooLarge),
		);
	}

	#[test]
	fn rejects_duplicate_share() {
		let store = StubStore::new(100);
		let d = make_descriptor(0, 5, NOW_TS + CHAT_TTL_SECONDS);
		let req = make_request(d.clone(), alloc::vec![1, 2, 3]);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Stored,
		);
		// Same (message_id, share_index) again → duplicate.
		let req2 = make_request(d, alloc::vec![4, 5, 6]);
		assert_eq!(
			handle_store_request(&store, &req2, NOW_TS),
			StoreResponse::Rejected(StoreRejection::DuplicateShare),
		);
	}

	#[test]
	fn rejects_when_store_full() {
		let store = StubStore::new(2);
		for i in 0..2u8 {
			let d = make_descriptor(i, 5, NOW_TS + CHAT_TTL_SECONDS);
			let req = make_request(d, alloc::vec![i]);
			handle_store_request(&store, &req, NOW_TS);
		}
		// Third insert hits capacity.
		let d = make_descriptor(2, 5, NOW_TS + CHAT_TTL_SECONDS);
		let req = make_request(d, alloc::vec![2]);
		assert_eq!(
			handle_store_request(&store, &req, NOW_TS),
			StoreResponse::Rejected(StoreRejection::StorageFull),
		);
	}

	// ── SCALE roundtrips ──────────────────────────────────────────

	#[test]
	fn store_request_scale_roundtrip() {
		let d = make_descriptor(2, 5, NOW_TS + CHAT_TTL_SECONDS);
		let req = make_request(d, alloc::vec![1, 2, 3, 4]);
		let bytes = req.encode();
		assert_eq!(StoreRequest::decode(&mut &bytes[..]).unwrap(), req);
	}

	#[test]
	fn store_response_stored_scale_roundtrip() {
		let r = StoreResponse::Stored;
		let bytes = r.encode();
		assert_eq!(StoreResponse::decode(&mut &bytes[..]).unwrap(), r);
	}

	#[test]
	fn store_response_rejected_variants_scale_roundtrip() {
		let variants = [
			StoreRejection::DescriptorExpired,
			StoreRejection::ShareIndexOutOfRange,
			StoreRejection::TotalSharesTooLarge,
			StoreRejection::TotalSharesTooSmall,
			StoreRejection::ShareTooLarge,
			StoreRejection::StorageFull,
			StoreRejection::DuplicateShare,
		];
		for v in variants {
			let resp = StoreResponse::Rejected(v);
			let bytes = resp.encode();
			assert_eq!(StoreResponse::decode(&mut &bytes[..]).unwrap(), resp);
		}
	}

	// ── client-side StoreTransport helper ─────────────────────────

	struct HonestTransport {
		store: Arc<StubStore>,
		now_unix_ts: UnixTimestamp,
	}

	impl StoreTransport for HonestTransport {
		type Error = ();
		fn send_request(
			&mut self,
			request: StoreRequest,
		) -> Result<StoreResponse, Self::Error> {
			Ok(handle_store_request(&*self.store, &request, self.now_unix_ts))
		}
	}

	#[test]
	fn store_one_share_via_transport() {
		let store = Arc::new(StubStore::new(100));
		let mut transport =
			HonestTransport { store: store.clone(), now_unix_ts: NOW_TS };
		let d = make_descriptor(0, 3, NOW_TS + CHAT_TTL_SECONDS);
		let req = make_request(d, alloc::vec![1, 2, 3]);
		let resp = store_one_share(&mut transport, req).unwrap();
		assert_eq!(resp, StoreResponse::Stored);
		assert_eq!(store.entries.borrow().len(), 1);
	}

	// ── process_store_request_bytes (byte-in/byte-out shim) ───────

	#[test]
	fn process_bytes_decodes_and_dispatches_valid_request() {
		let store = StubStore::new(100);
		let d = make_descriptor(0, 5, NOW_TS + CHAT_TTL_SECONDS);
		let req = make_request(d, alloc::vec![1, 2, 3, 4]);
		let payload = req.encode();
		let (resp_bytes, decoded_ok) =
			process_store_request_bytes(&store, NOW_TS, &payload);
		assert!(decoded_ok);
		let resp = StoreResponse::decode(&mut &resp_bytes[..]).unwrap();
		assert_eq!(resp, StoreResponse::Stored);
	}

	#[test]
	fn process_bytes_returns_decline_on_malformed_payload() {
		let store = StubStore::new(100);
		let garbage = alloc::vec![0xFFu8; 4];
		let (resp_bytes, decoded_ok) =
			process_store_request_bytes(&store, NOW_TS, &garbage);
		assert!(!decoded_ok);
		// Caller can still parse the response — it's a Rejected variant.
		let resp = StoreResponse::decode(&mut &resp_bytes[..]).unwrap();
		assert!(matches!(resp, StoreResponse::Rejected(_)));
	}

	#[test]
	fn process_bytes_rejects_expired() {
		let store = StubStore::new(100);
		// expires_at well in the past, beyond PAST_GRACE_SECONDS.
		let d = make_descriptor(0, 5, NOW_TS - PAST_GRACE_SECONDS - 60);
		let req = make_request(d, alloc::vec![1, 2]);
		let payload = req.encode();
		let (resp_bytes, decoded_ok) =
			process_store_request_bytes(&store, NOW_TS, &payload);
		assert!(decoded_ok);
		let resp = StoreResponse::decode(&mut &resp_bytes[..]).unwrap();
		assert_eq!(
			resp,
			StoreResponse::Rejected(StoreRejection::DescriptorExpired),
		);
	}
}
