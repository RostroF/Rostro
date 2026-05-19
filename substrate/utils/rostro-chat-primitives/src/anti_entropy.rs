// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Wire types for `/rostro/chat-anti-entropy/1`.
//!
//! Anti-entropy is the periodic gap-filling protocol that runs
//! between bucket-subscribed peers. It catches cases where push
//! gossip (Commit B) reached some bucket peers but not others —
//! e.g., a peer was briefly offline during the push, or a network
//! partition delayed delivery to some subset — without waiting for
//! a recipient to do a fallback fetch (Commit C) to discover the
//! gap retroactively.
//!
//! ## Sync semantics
//!
//! One-way per request. When peer A initiates anti-entropy with B
//! for bucket X:
//!
//! 1. A sends [`AeRequest`] carrying A's digest over its
//!    `(pickup_key, message_id, share_index)` set scoped to bucket X.
//! 2. B compares to its own digest. If equal, responds
//!    [`AeResponse::Match`]. If different, responds
//!    [`AeResponse::Mismatch`] with B's full entry list for that
//!    bucket.
//! 3. A diff's B's list against its own. For each entry B has that
//!    A doesn't, A issues an existing `/rostro/chat-fetch/1`
//!    request keyed on the pickup_key — that protocol returns the
//!    actual share bytes + MAC.
//!
//! Bi-directional sync emerges because B periodically initiates
//! its own anti-entropy against random peers (including A); over
//! time the bucket converges across all peers that subscribe to it.
//!
//! ## Digest construction
//!
//! [`compute_bucket_digest`] takes a slice of
//! `(PickupKey, MessageId, ShareIndex)` tuples, sorts them
//! lexicographically, and runs blake2_256 over the concatenated
//! field bytes (32 + 32 + 1 = 65 bytes per tuple). Sequential
//! hash rather than Merkle — for v0.1 simplicity, and because
//! mismatch responses dump the full list anyway. A future v0.2
//! could swap to range-partitioned digests for bandwidth-bounded
//! sync; the wire-format hook is stable.
//!
//! ## Bandwidth profile
//!
//! Worst case per exchange: a node with K entries in a bucket
//! sends ~33 bytes (digest + bucket byte + framing) for the
//! request, and on mismatch receives K × 65 bytes for the entry
//! list. For 10k entries that's ~650 KB. At 30s cadence and one
//! peer per tick, that's ~21 KB/s sustained per node in the worst
//! case. Compared to a continuous flood, this is bounded; in
//! practice the K-of-N partial-overlap case is much smaller than
//! the worst-case "full list."

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use sp_crypto_hashing::blake2_256;

use crate::descriptor::{MessageId, PickupKey, ShareIndex};

/// Wire request from initiator A to responder B. Names a single
/// bucket and carries A's digest for that bucket's contents.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AeRequest {
	/// Which bucket A wants to sync. One bucket per request keeps
	/// the wire shape tight; A's periodic task picks a different
	/// bucket each tick.
	pub bucket: u8,
	/// blake2_256 over A's sorted `(pickup_key, message_id,
	/// share_index)` tuples for `bucket`. Computed via
	/// [`compute_bucket_digest`].
	pub digest: [u8; 32],
}

/// Wire response from B back to A.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum AeResponse {
	/// B's digest for the same bucket equals A's. No data exchange
	/// needed; both sides are in sync for this bucket as of this
	/// tick.
	Match,
	/// B's digest differs from A's. B includes its full entry list
	/// for the bucket so A can diff and request what it's missing
	/// via the existing `/rostro/chat-fetch/1` protocol.
	Mismatch { entries: Vec<AeEntry> },
}

/// One entry in an anti-entropy mismatch response. Carries just
/// enough for A to identify which shares B has — A then fetches
/// the actual share bytes + MAC via chat-fetch keyed by
/// `pickup_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct AeEntry {
	pub pickup_key: PickupKey,
	pub message_id: MessageId,
	pub share_index: ShareIndex,
}

/// Compute a deterministic digest over the entries currently held
/// in a single bucket. Sorts lexicographically before hashing so
/// two nodes with the same set produce the same digest regardless
/// of iteration order in their local stores.
pub fn compute_bucket_digest(
	entries: &[(PickupKey, MessageId, ShareIndex)],
) -> [u8; 32] {
	let mut sorted: Vec<(PickupKey, MessageId, ShareIndex)> = entries.to_vec();
	sorted.sort_by(|(p1, m1, s1), (p2, m2, s2)| {
		(p1.0, m1.0, *s1).cmp(&(p2.0, m2.0, *s2))
	});

	let mut buf = Vec::with_capacity(sorted.len() * (32 + 32 + 1));
	for (pk, mid, si) in sorted.iter() {
		buf.extend_from_slice(&pk.0);
		buf.extend_from_slice(&mid.0);
		buf.push(*si);
	}
	blake2_256(&buf)
}

/// Convert a `(PickupKey, MessageId, ShareIndex)` tuple list into
/// the wire-shape `Vec<AeEntry>`. Pure rearrangement; no I/O.
pub fn to_ae_entries(
	src: &[(PickupKey, MessageId, ShareIndex)],
) -> Vec<AeEntry> {
	src.iter()
		.map(|(pk, mid, si)| AeEntry {
			pickup_key: *pk,
			message_id: *mid,
			share_index: *si,
		})
		.collect()
}

/// Maximum response payload size for `AeResponse::Mismatch`. Each
/// `AeEntry` is 65 bytes; framing + enum-discriminant adds ~5.
/// At 16384 entries cap, the response is ~1 MiB. Larger than
/// chat-fetch's response cap because mismatch dumps every entry
/// in the bucket; bounds memory but allows reasonable convergence
/// on the first exchange.
pub const MAX_AE_ENTRIES_PER_RESPONSE: usize = 16_384;

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;

	fn pk(b: u8) -> PickupKey {
		PickupKey([b; 32])
	}
	fn mid(b: u8) -> MessageId {
		MessageId([b; 32])
	}

	#[test]
	fn empty_digest_is_blake2_of_empty() {
		let d = compute_bucket_digest(&[]);
		assert_eq!(d, blake2_256(&[]));
	}

	#[test]
	fn digest_deterministic_irrespective_of_input_order() {
		let entries_a = vec![
			(pk(0x11), mid(0xAA), 0u8),
			(pk(0x22), mid(0xBB), 1u8),
			(pk(0x33), mid(0xCC), 2u8),
		];
		let entries_b = vec![
			(pk(0x33), mid(0xCC), 2u8),
			(pk(0x11), mid(0xAA), 0u8),
			(pk(0x22), mid(0xBB), 1u8),
		];
		assert_eq!(
			compute_bucket_digest(&entries_a),
			compute_bucket_digest(&entries_b),
			"same set, different insertion order, same digest",
		);
	}

	#[test]
	fn digest_differs_on_added_entry() {
		let entries_a = vec![(pk(0x11), mid(0xAA), 0u8)];
		let entries_b = vec![
			(pk(0x11), mid(0xAA), 0u8),
			(pk(0x22), mid(0xBB), 1u8),
		];
		assert_ne!(
			compute_bucket_digest(&entries_a),
			compute_bucket_digest(&entries_b),
		);
	}

	#[test]
	fn digest_differs_on_share_index_change() {
		let entries_a = vec![(pk(0x11), mid(0xAA), 0u8)];
		let entries_b = vec![(pk(0x11), mid(0xAA), 1u8)];
		assert_ne!(
			compute_bucket_digest(&entries_a),
			compute_bucket_digest(&entries_b),
		);
	}

	#[test]
	fn ae_request_scale_roundtrip() {
		let req = AeRequest { bucket: 42, digest: [0xCD; 32] };
		let bytes = req.encode();
		assert_eq!(AeRequest::decode(&mut &bytes[..]).unwrap(), req);
	}

	#[test]
	fn ae_response_match_scale_roundtrip() {
		let resp = AeResponse::Match;
		let bytes = resp.encode();
		assert_eq!(AeResponse::decode(&mut &bytes[..]).unwrap(), resp);
	}

	#[test]
	fn ae_response_mismatch_scale_roundtrip() {
		let resp = AeResponse::Mismatch {
			entries: vec![
				AeEntry { pickup_key: pk(0x11), message_id: mid(0xAA), share_index: 0 },
				AeEntry { pickup_key: pk(0x22), message_id: mid(0xBB), share_index: 1 },
			],
		};
		let bytes = resp.encode();
		assert_eq!(AeResponse::decode(&mut &bytes[..]).unwrap(), resp);
	}

	#[test]
	fn to_ae_entries_preserves_data() {
		let src = vec![
			(pk(0x11), mid(0xAA), 0u8),
			(pk(0x22), mid(0xBB), 1u8),
		];
		let out = to_ae_entries(&src);
		assert_eq!(out.len(), 2);
		assert_eq!(out[0].pickup_key, pk(0x11));
		assert_eq!(out[0].message_id, mid(0xAA));
		assert_eq!(out[0].share_index, 0);
		assert_eq!(out[1].share_index, 1);
	}

	#[test]
	fn digest_stable_across_calls() {
		// Pin the digest of a known input so a future edit to
		// `compute_bucket_digest` can't silently change the wire
		// semantics for already-deployed nodes.
		let entries = vec![
			(pk(0x11), mid(0xAA), 0u8),
			(pk(0x22), mid(0xBB), 1u8),
		];
		let d1 = compute_bucket_digest(&entries);
		let d2 = compute_bucket_digest(&entries);
		assert_eq!(d1, d2);
		// Pinned value: blake2_256 of
		//   pk(0x11) ‖ mid(0xAA) ‖ 0x00 ‖ pk(0x22) ‖ mid(0xBB) ‖ 0x01
		// (sorted-by-bytes, same as construction order here).
		// If this assertion breaks, the wire format has shifted.
		let expected = {
			let mut buf: Vec<u8> = Vec::new();
			buf.extend_from_slice(&[0x11; 32]);
			buf.extend_from_slice(&[0xAA; 32]);
			buf.push(0);
			buf.extend_from_slice(&[0x22; 32]);
			buf.extend_from_slice(&[0xBB; 32]);
			buf.push(1);
			blake2_256(&buf)
		};
		assert_eq!(d1, expected);
	}
}
