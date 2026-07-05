// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Chunk split/combine primitives + client-prepared share types.
//!
//! Replaces the XOR-stripe layer (hard cutover, 2026-07; design of
//! record: docs/CHAT-SHARE-CHUNKING.md). A message's SCALE-encoded
//! `SealedEnvelope` is cut into N contiguous chunks that SUM to the
//! original size — a 25 KB message costs relays ~25 KB × replication,
//! not N × 25 KB × replication as under the XOR stripe.
//!
//! ## Why plain chunking is sufficient (and the stripe was not)
//!
//! The split payload is already sealed-sender AEAD ciphertext; a
//! contiguous slice of it is computationally indistinguishable from
//! random bytes to a relay, exactly as an XOR share appeared. The
//! only adversary who gained from the stripe over chunking is one who
//! can break the symmetric AEAD itself — not a realistic threat, and
//! not a quantum one (Grover only; the PQ exposure is key exchange,
//! addressed by the PQXDH workstream). Meanwhile the stripe's
//! all-or-nothing property was void as deployed: the fan-out sent
//! every share to the same replica set, so each relay could XOR the
//! full message back together locally. The consciously dropped
//! property is information-theoretic all-or-nothing confidentiality
//! against relay collusion; if it is ever wanted back, the tool is
//! AONT-RS layered into this same pipeline, not a return to N×-size
//! shares.
//!
//! ## Who does what
//!
//! - **Sender device** ([`prepare_batch`]): split, MAC each chunk
//!   with the per-message key (derived from the per-conversation
//!   stripe-MAC secret — see [`crate::verify`]), author the
//!   descriptor fields. The device is the only party holding the MAC
//!   key, so every relay downstream is reduced to
//!   drop-or-deliver-intact.
//! - **Distributing node** ([`validate_prepared_batch`] then fan-out):
//!   pure routing. Validates shape + expiry bounds, stamps its own
//!   `relay_pubkey` into descriptors, pushes each chunk to its
//!   replica set. Computes no MACs, holds no key, splits nothing.
//! - **Recipient device** ([`combine_chunks_authenticated`]): verify
//!   every chunk's MAC, concatenate in index order. Verification is
//!   local-only and produces no wire traffic; remediation follows the
//!   privacy rules in docs/CHAT-SHARE-CHUNKING.md §4.6 (retries ride
//!   a NORMAL-shaped fetch; attribution never leaves the device).

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::descriptor::{
	expiry_within_bounds_at, MessageId, PickupKey, ShareIndex, UnixTimestamp,
};
use crate::verify::{mac_chunk, verify_chunk_mac, ShareMacKey, ShareMacTag};

/// Minimum number of chunks. `n=1` would hand a single relay the
/// whole (AEAD-sealed) message; requiring ≥2 preserves the "no single
/// relay holds the full ciphertext" property at the computational
/// level.
pub const MIN_CHUNKS: usize = 2;

/// Sanity cap on the number of chunks. Practical relay counts are
/// 3-10. This cap exists to prevent accidental memory/fan-out blowup
/// from uncapped caller input. Raise deliberately if a larger N is
/// ever needed.
pub const MAX_CHUNKS: usize = 64;

/// Errors from [`split_chunks`] / [`prepare_batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkError {
	/// Caller requested `n` outside `[MIN_CHUNKS, MAX_CHUNKS]`.
	InvalidN { got: usize, min: usize, max: usize },
	/// Zero-length payload. A SCALE-encoded `SealedEnvelope` is never
	/// empty; reject explicitly rather than manufacture N empty
	/// chunks.
	EmptyPayload,
}

/// Split `payload` into `n` contiguous chunks that concatenate (in
/// index order) back to `payload`.
///
/// Sizes are as even as possible: with `L = payload.len()`, the first
/// `L % n` chunks carry `L/n + 1` bytes and the rest `L/n`. No
/// randomness, no padding, no expansion: the chunks SUM to `L`.
///
/// # Errors
///
/// * [`ChunkError::InvalidN`] — `n` outside `[MIN_CHUNKS, MAX_CHUNKS]`.
/// * [`ChunkError::EmptyPayload`] — empty payload.
///
/// # Edge cases
///
/// * `L < n`: the trailing `n - L` chunks are empty. Well-defined and
///   round-trips (real envelopes are always far larger than N); the
///   MAC covers empty chunks like any others.
pub fn split_chunks(payload: &[u8], n: usize) -> Result<Vec<Vec<u8>>, ChunkError> {
	if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&n) {
		return Err(ChunkError::InvalidN { got: n, min: MIN_CHUNKS, max: MAX_CHUNKS });
	}
	if payload.is_empty() {
		return Err(ChunkError::EmptyPayload);
	}
	let base = payload.len() / n;
	let rem = payload.len() % n;
	let mut chunks = Vec::with_capacity(n);
	let mut offset = 0usize;
	for i in 0..n {
		let len = if i < rem { base + 1 } else { base };
		chunks.push(payload[offset..offset + len].to_vec());
		offset += len;
	}
	debug_assert_eq!(offset, payload.len());
	Ok(chunks)
}

/// One client-prepared, MAC-tagged chunk, ready for a distributing
/// node to wrap in a full `ShareDescriptor` (adding its own
/// `relay_pubkey`) and push to storing relays.
///
/// Everything here is sender-authored and covered by `mac_tag`
/// (see [`crate::verify::mac_chunk`]) together with the batch-level
/// `message_id` + `pickup_key` — a distributing node or storing relay
/// that rewrites any field produces a MAC failure on the recipient's
/// device.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PreparedShare {
	/// Position of this chunk within the message (0-based).
	pub share_index: ShareIndex,
	/// Total chunk count for the message. Duplicated per share so a
	/// single fetched share tells the recipient how many to expect.
	pub total_shares: u8,
	/// Sender-stamped expiry (`now + CHAT_TTL_SECONDS` by
	/// convention). Receiving relays bound-check it
	/// ([`crate::descriptor::expiry_within_bounds_at`]).
	pub expires_at_unix_ts: UnixTimestamp,
	/// The contiguous slice of the SCALE-encoded envelope.
	pub chunk_bytes: Vec<u8>,
	/// v2 descriptor-bound MAC tag, computed on the sender's device.
	pub mac_tag: ShareMacTag,
}

/// A full client-prepared message: the routing key, the message id,
/// and every tagged chunk. This is:
///
/// - the **onion `Deliver` drop encoding** (the drop bytes ARE
///   `PreparedBatch::encode()`; the onion layer treats them as
///   opaque), and
/// - the **`chat_send_prepared` RPC payload** (SCALE-encoded, hex),
///   where the cert-auth signature covers exactly these bytes.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PreparedBatch {
	/// Sender-derived routing key (pairwise / group / dead-drop —
	/// uniform blake2 outputs, indistinguishable to relays).
	pub pickup_key: PickupKey,
	/// The message id, also inside each chunk's MAC preimage.
	pub message_id: MessageId,
	/// The tagged chunks, in index order as produced by
	/// [`prepare_batch`]. Validators do not assume order
	/// ([`validate_prepared_batch`] checks the index set).
	pub shares: Vec<PreparedShare>,
}

/// Sender-device pipeline: split the encoded envelope into `n`
/// chunks and MAC each one under `key` with the full v2 descriptor
/// binding. The one shared implementation for dotwave and
/// rostro-client (this crate is the Apache-2.0 seam both consume).
///
/// `key` is the per-message MAC key from
/// [`crate::verify::derive_share_mac_key`]; `expires_at_unix_ts` is
/// stamped by the sender (`now + CHAT_TTL_SECONDS` by convention)
/// and bound into every tag.
pub fn prepare_batch(
	encoded_envelope: &[u8],
	n: usize,
	key: &ShareMacKey,
	message_id: MessageId,
	pickup_key: PickupKey,
	expires_at_unix_ts: UnixTimestamp,
) -> Result<PreparedBatch, ChunkError> {
	let chunks = split_chunks(encoded_envelope, n)?;
	let total = n as u8;
	let shares = chunks
		.into_iter()
		.enumerate()
		.map(|(i, chunk_bytes)| {
			let share_index = i as ShareIndex;
			let mac_tag = mac_chunk(
				key,
				&message_id,
				&pickup_key,
				share_index,
				total,
				expires_at_unix_ts,
				&chunk_bytes,
			);
			PreparedShare {
				share_index,
				total_shares: total,
				expires_at_unix_ts,
				chunk_bytes,
				mac_tag,
			}
		})
		.collect();
	Ok(PreparedBatch { pickup_key, message_id, shares })
}

/// Rejection reasons from [`validate_prepared_batch`]. These are the
/// distribution-handoff checks a node runs on a client-prepared batch
/// BEFORE any fan-out — reject known-invalid input at the boundary,
/// don't let it ride to the storing relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchValidationError {
	/// Empty share list.
	NoShares,
	/// `total_shares` outside `[MIN_CHUNKS, MAX_CHUNKS]`.
	TotalOutOfRange { got: u8 },
	/// A share's `total_shares` disagrees with the first share's.
	TotalMismatch { slice_index: usize },
	/// A share's `expires_at_unix_ts` disagrees with the first
	/// share's. The sender stamps ONE expiry per message.
	ExpiryMismatch { slice_index: usize },
	/// The batch does not carry exactly `total_shares` shares.
	WrongShareCount { got: usize, total: u8 },
	/// A `share_index` outside `0..total_shares`.
	IndexOutOfRange { share_index: ShareIndex, total: u8 },
	/// The same `share_index` appears twice.
	DuplicateIndex { share_index: ShareIndex },
	/// A chunk exceeds the per-share byte cap
	/// ([`crate::store_protocol::MAX_SHARE_BYTES`]).
	ChunkTooLarge { slice_index: usize, len: usize },
	/// The sender-stamped expiry fails the receive-time bounds
	/// ([`crate::descriptor::expiry_within_bounds_at`]).
	ExpiryOutOfBounds { expires_at_unix_ts: UnixTimestamp },
}

/// Validate a client-prepared batch at the distribution handoff.
/// Shape + bounds only — the node CANNOT verify MACs (it has no key,
/// by design) and does not try. Returns the validated `total_shares`.
///
/// Checks: non-empty; consistent `total_shares` and expiry across
/// shares; total within `[MIN_CHUNKS, MAX_CHUNKS]`; exactly `total`
/// shares carrying each index `0..total` once; per-chunk size cap;
/// sender expiry within receive-time bounds for `now_unix_ts`.
pub fn validate_prepared_batch(
	batch: &PreparedBatch,
	now_unix_ts: UnixTimestamp,
) -> Result<u8, BatchValidationError> {
	let first = batch.shares.first().ok_or(BatchValidationError::NoShares)?;
	let total = first.total_shares;
	let expires = first.expires_at_unix_ts;

	if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&(total as usize)) {
		return Err(BatchValidationError::TotalOutOfRange { got: total });
	}
	if batch.shares.len() != total as usize {
		return Err(BatchValidationError::WrongShareCount {
			got: batch.shares.len(),
			total,
		});
	}
	if !expiry_within_bounds_at(expires, now_unix_ts) {
		return Err(BatchValidationError::ExpiryOutOfBounds {
			expires_at_unix_ts: expires,
		});
	}

	// One pass for per-share consistency + index-set coverage.
	// MAX_CHUNKS ≤ 64 keeps a u64 bitmask sufficient.
	let mut seen: u64 = 0;
	for (i, s) in batch.shares.iter().enumerate() {
		if s.total_shares != total {
			return Err(BatchValidationError::TotalMismatch { slice_index: i });
		}
		if s.expires_at_unix_ts != expires {
			return Err(BatchValidationError::ExpiryMismatch { slice_index: i });
		}
		if s.share_index >= total {
			return Err(BatchValidationError::IndexOutOfRange {
				share_index: s.share_index,
				total,
			});
		}
		let bit = 1u64 << s.share_index;
		if seen & bit != 0 {
			return Err(BatchValidationError::DuplicateIndex {
				share_index: s.share_index,
			});
		}
		seen |= bit;
		if s.chunk_bytes.len() > crate::store_protocol::MAX_SHARE_BYTES {
			return Err(BatchValidationError::ChunkTooLarge {
				slice_index: i,
				len: s.chunk_bytes.len(),
			});
		}
	}
	// len == total and no duplicates ⇒ exact coverage of 0..total.
	Ok(total)
}

/// One fetched chunk as presented to [`combine_chunks_authenticated`]:
/// the descriptor fields AS FETCHED (a tampered field must be fed
/// back exactly as received so the MAC check catches it), the bytes,
/// and the claimed tag.
#[derive(Debug, Clone, Copy)]
pub struct TaggedChunk<'a> {
	pub share_index: ShareIndex,
	pub total_shares: u8,
	pub expires_at_unix_ts: UnixTimestamp,
	pub bytes: &'a [u8],
	pub tag: &'a ShareMacTag,
}

/// Errors from [`combine_chunks_authenticated`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkCombineError {
	/// Empty input slice.
	NoChunks,
	/// MAC verification failed on the chunk at position `slice_index`
	/// in the caller's input slice; `share_index` is its claimed
	/// canonical position.
	///
	/// Remediation (privacy rules, docs/CHAT-SHARE-CHUNKING.md §4.6):
	/// re-fetch via a NORMAL-shaped pickup query against a different
	/// replica — never a per-chunk request — and keep the conclusion
	/// about which relay served bad bytes on-device.
	TamperedChunk { slice_index: usize, share_index: ShareIndex },
	/// `total_shares` (after MAC verification, i.e. sender-authored)
	/// is outside `[MIN_CHUNKS, MAX_CHUNKS]`.
	TotalOutOfRange { got: u8 },
	/// Two verified chunks disagree on `total_shares`. Cannot happen
	/// from one honest sender batch; indicates mixed batches for the
	/// same message id.
	TotalMismatch { slice_index: usize },
	/// The same `share_index` appears twice (both copies MAC-valid,
	/// i.e. duplicates of the same honest chunk). Callers typically
	/// dedupe on `(message_id, share_index)` before combining.
	DuplicateIndex { share_index: ShareIndex },
	/// A verified chunk's index is outside `0..total_shares`.
	IndexOutOfRange { share_index: ShareIndex, total: u8 },
	/// Fewer than `total_shares` distinct chunks present. Fetch more
	/// replicas and retry.
	IncompleteSet { present: usize, total: u8 },
}

/// Recipient-device reassembly: verify every chunk's v2 MAC under
/// `key` + the message context, then concatenate in index order.
///
/// MAC verification runs FIRST, per chunk, using each chunk's fields
/// exactly as fetched — so a relay-rewritten `total_shares` or
/// `expires_at` surfaces as [`ChunkCombineError::TamperedChunk`] on
/// that specific chunk (localization), not as a shape error. Shape
/// checks (consistency, coverage, completeness) run on the verified
/// survivors.
///
/// `message_id` comes off the fetched descriptors (it is also the
/// grouping key); `pickup_key` is the key the recipient fetched
/// under. Both are bound into every tag.
pub fn combine_chunks_authenticated(
	key: &ShareMacKey,
	message_id: &MessageId,
	pickup_key: &PickupKey,
	chunks: &[TaggedChunk<'_>],
) -> Result<Vec<u8>, ChunkCombineError> {
	if chunks.is_empty() {
		return Err(ChunkCombineError::NoChunks);
	}

	// 1. Authenticate every chunk (localizes tampering to a chunk).
	for (i, c) in chunks.iter().enumerate() {
		if verify_chunk_mac(
			key,
			message_id,
			pickup_key,
			c.share_index,
			c.total_shares,
			c.expires_at_unix_ts,
			c.bytes,
			c.tag,
		)
		.is_err()
		{
			return Err(ChunkCombineError::TamperedChunk {
				slice_index: i,
				share_index: c.share_index,
			});
		}
	}

	// 2. Shape checks on the verified set.
	let total = chunks[0].total_shares;
	if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&(total as usize)) {
		return Err(ChunkCombineError::TotalOutOfRange { got: total });
	}
	let mut seen: u64 = 0;
	for (i, c) in chunks.iter().enumerate() {
		if c.total_shares != total {
			return Err(ChunkCombineError::TotalMismatch { slice_index: i });
		}
		if c.share_index >= total {
			return Err(ChunkCombineError::IndexOutOfRange {
				share_index: c.share_index,
				total,
			});
		}
		let bit = 1u64 << c.share_index;
		if seen & bit != 0 {
			return Err(ChunkCombineError::DuplicateIndex { share_index: c.share_index });
		}
		seen |= bit;
	}
	if chunks.len() != total as usize {
		return Err(ChunkCombineError::IncompleteSet {
			present: chunks.len(),
			total,
		});
	}

	// 3. Concatenate in index order.
	let mut ordered: Vec<&TaggedChunk<'_>> = chunks.iter().collect();
	ordered.sort_by_key(|c| c.share_index);
	let out_len = ordered.iter().map(|c| c.bytes.len()).sum();
	let mut out = Vec::with_capacity(out_len);
	for c in ordered {
		out.extend_from_slice(c.bytes);
	}
	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::descriptor::CHAT_TTL_SECONDS;
	use crate::verify::derive_share_mac_key;

	const NOW: UnixTimestamp = 1_700_000_000;
	const EXPIRY: UnixTimestamp = NOW + CHAT_TTL_SECONDS;

	fn mid() -> MessageId {
		MessageId([0xAA; 32])
	}
	fn pickup() -> PickupKey {
		PickupKey([0xBB; 32])
	}
	fn key() -> ShareMacKey {
		derive_share_mac_key(&[0x42; 32], &mid())
	}

	fn tagged_refs(batch: &PreparedBatch) -> Vec<TaggedChunk<'_>> {
		batch
			.shares
			.iter()
			.map(|s| TaggedChunk {
				share_index: s.share_index,
				total_shares: s.total_shares,
				expires_at_unix_ts: s.expires_at_unix_ts,
				bytes: &s.chunk_bytes,
				tag: &s.mac_tag,
			})
			.collect()
	}

	// ── split_chunks ──────────────────────────────────────────────

	#[test]
	fn split_even_division() {
		let payload: Vec<u8> = (0..100u8).collect();
		let chunks = split_chunks(&payload, 5).unwrap();
		assert_eq!(chunks.len(), 5);
		for c in &chunks {
			assert_eq!(c.len(), 20);
		}
		assert_eq!(chunks.concat(), payload);
	}

	#[test]
	fn split_uneven_division_front_loads_remainder() {
		// 103 = 5*20 + 3: first three chunks get 21, last two get 20.
		let payload: Vec<u8> = (0..103u8).map(|i| i ^ 0x5A).collect();
		let chunks = split_chunks(&payload, 5).unwrap();
		let sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
		assert_eq!(sizes, vec![21, 21, 21, 20, 20]);
		assert_eq!(chunks.concat(), payload);
	}

	#[test]
	fn split_sums_to_original_never_expands() {
		// The whole point of the cutover: N chunks sum to 1× the
		// payload, not N×.
		let payload = vec![0xCD; 25 * 1024];
		for n in [2usize, 3, 5, 10, 64] {
			let chunks = split_chunks(&payload, n).unwrap();
			let total: usize = chunks.iter().map(|c| c.len()).sum();
			assert_eq!(total, payload.len(), "n={n}: chunks must sum to payload");
			assert_eq!(chunks.concat(), payload, "n={n}: order must round-trip");
		}
	}

	#[test]
	fn split_payload_shorter_than_n() {
		// L < n: trailing chunks empty, still round-trips.
		let payload = vec![1u8, 2, 3];
		let chunks = split_chunks(&payload, 5).unwrap();
		assert_eq!(chunks.len(), 5);
		let sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
		assert_eq!(sizes, vec![1, 1, 1, 0, 0]);
		assert_eq!(chunks.concat(), payload);
	}

	#[test]
	fn split_single_byte() {
		let chunks = split_chunks(&[0x7F], 2).unwrap();
		assert_eq!(chunks[0], vec![0x7F]);
		assert!(chunks[1].is_empty());
	}

	#[test]
	fn split_rejects_bad_n() {
		for n in [0usize, 1, MAX_CHUNKS + 1] {
			match split_chunks(b"x", n) {
				Err(ChunkError::InvalidN { got, min, max }) => {
					assert_eq!(got, n);
					assert_eq!(min, MIN_CHUNKS);
					assert_eq!(max, MAX_CHUNKS);
				},
				other => panic!("n={n}: expected InvalidN, got {other:?}"),
			}
		}
	}

	#[test]
	fn split_accepts_n_at_bounds() {
		let payload = vec![0u8; 128];
		assert_eq!(split_chunks(&payload, MIN_CHUNKS).unwrap().len(), MIN_CHUNKS);
		assert_eq!(split_chunks(&payload, MAX_CHUNKS).unwrap().len(), MAX_CHUNKS);
	}

	#[test]
	fn split_rejects_empty_payload() {
		assert_eq!(split_chunks(&[], 5), Err(ChunkError::EmptyPayload));
	}

	// ── prepare_batch + combine roundtrip ─────────────────────────

	#[test]
	fn prepare_combine_roundtrip() {
		let payload: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
		let batch =
			prepare_batch(&payload, 5, &key(), mid(), pickup(), EXPIRY).unwrap();
		assert_eq!(batch.shares.len(), 5);
		assert_eq!(validate_prepared_batch(&batch, NOW), Ok(5));

		let recovered =
			combine_chunks_authenticated(&key(), &mid(), &pickup(), &tagged_refs(&batch))
				.unwrap();
		assert_eq!(recovered, payload);
	}

	#[test]
	fn combine_is_order_independent() {
		let payload = b"order independence across fetch merges".to_vec();
		let batch =
			prepare_batch(&payload, 4, &key(), mid(), pickup(), EXPIRY).unwrap();
		let mut refs = tagged_refs(&batch);
		refs.reverse();
		let recovered =
			combine_chunks_authenticated(&key(), &mid(), &pickup(), &refs).unwrap();
		assert_eq!(recovered, payload);
	}

	#[test]
	fn batch_scale_roundtrips() {
		// The batch IS the wire format (onion drop + RPC payload).
		let payload = vec![0xEE; 300];
		let batch =
			prepare_batch(&payload, 3, &key(), mid(), pickup(), EXPIRY).unwrap();
		let bytes = batch.encode();
		let decoded = PreparedBatch::decode(&mut &bytes[..]).unwrap();
		assert_eq!(decoded, batch);
	}

	// ── combine: tamper localization ──────────────────────────────

	#[test]
	fn combine_localizes_tampered_bytes() {
		let payload = vec![0x11; 500];
		let mut batch =
			prepare_batch(&payload, 5, &key(), mid(), pickup(), EXPIRY).unwrap();
		batch.shares[3].chunk_bytes[0] ^= 0xFF;
		match combine_chunks_authenticated(&key(), &mid(), &pickup(), &tagged_refs(&batch)) {
			Err(ChunkCombineError::TamperedChunk { slice_index, share_index }) => {
				assert_eq!(slice_index, 3);
				assert_eq!(share_index, 3);
			},
			other => panic!("expected TamperedChunk at 3, got {other:?}"),
		}
	}

	#[test]
	fn combine_localizes_rewritten_expiry() {
		// A relay shortening the TTL on one stored chunk is caught as
		// tampering ON THAT CHUNK — the v2 descriptor binding.
		let payload = vec![0x22; 500];
		let mut batch =
			prepare_batch(&payload, 5, &key(), mid(), pickup(), EXPIRY).unwrap();
		batch.shares[1].expires_at_unix_ts -= 3600;
		match combine_chunks_authenticated(&key(), &mid(), &pickup(), &tagged_refs(&batch)) {
			Err(ChunkCombineError::TamperedChunk { slice_index: 1, share_index: 1 }) => {},
			other => panic!("expected TamperedChunk at 1, got {other:?}"),
		}
	}

	#[test]
	fn combine_localizes_rewritten_total() {
		let payload = vec![0x33; 500];
		let mut batch =
			prepare_batch(&payload, 5, &key(), mid(), pickup(), EXPIRY).unwrap();
		batch.shares[2].total_shares = 3;
		match combine_chunks_authenticated(&key(), &mid(), &pickup(), &tagged_refs(&batch)) {
			Err(ChunkCombineError::TamperedChunk { slice_index: 2, share_index: 2 }) => {},
			other => panic!("expected TamperedChunk at 2, got {other:?}"),
		}
	}

	#[test]
	fn combine_localizes_index_swap() {
		// Chunk 1's bytes presented under index 0: MAC binds position.
		let payload = vec![0x44; 500];
		let batch =
			prepare_batch(&payload, 3, &key(), mid(), pickup(), EXPIRY).unwrap();
		let mut refs = tagged_refs(&batch);
		refs[0] = TaggedChunk { share_index: 0, ..refs[1] };
		match combine_chunks_authenticated(&key(), &mid(), &pickup(), &refs) {
			Err(ChunkCombineError::TamperedChunk { slice_index: 0, .. }) => {},
			other => panic!("expected TamperedChunk at 0, got {other:?}"),
		}
	}

	#[test]
	fn combine_rejects_wrong_message_context() {
		// Same chunks presented under a different message_id or
		// pickup_key fail wholesale — no cross-message replay.
		let payload = vec![0x55; 200];
		let batch =
			prepare_batch(&payload, 3, &key(), mid(), pickup(), EXPIRY).unwrap();
		let refs = tagged_refs(&batch);
		assert!(matches!(
			combine_chunks_authenticated(&key(), &MessageId([0x01; 32]), &pickup(), &refs),
			Err(ChunkCombineError::TamperedChunk { .. }),
		));
		assert!(matches!(
			combine_chunks_authenticated(&key(), &mid(), &PickupKey([0x01; 32]), &refs),
			Err(ChunkCombineError::TamperedChunk { .. }),
		));
	}

	// ── combine: shape errors ─────────────────────────────────────

	#[test]
	fn combine_rejects_empty() {
		assert_eq!(
			combine_chunks_authenticated(&key(), &mid(), &pickup(), &[]),
			Err(ChunkCombineError::NoChunks),
		);
	}

	#[test]
	fn combine_reports_incomplete_set() {
		let payload = vec![0x66; 500];
		let batch =
			prepare_batch(&payload, 5, &key(), mid(), pickup(), EXPIRY).unwrap();
		let refs: Vec<TaggedChunk<'_>> =
			tagged_refs(&batch).into_iter().take(4).collect();
		assert_eq!(
			combine_chunks_authenticated(&key(), &mid(), &pickup(), &refs),
			Err(ChunkCombineError::IncompleteSet { present: 4, total: 5 }),
		);
	}

	#[test]
	fn combine_reports_duplicate_index() {
		let payload = vec![0x77; 500];
		let batch =
			prepare_batch(&payload, 3, &key(), mid(), pickup(), EXPIRY).unwrap();
		let mut refs = tagged_refs(&batch);
		refs[2] = refs[0]; // honest duplicate of chunk 0
		assert_eq!(
			combine_chunks_authenticated(&key(), &mid(), &pickup(), &refs),
			Err(ChunkCombineError::DuplicateIndex { share_index: 0 }),
		);
	}

	// ── validate_prepared_batch ───────────────────────────────────

	#[test]
	fn validate_accepts_honest_batch() {
		let batch = prepare_batch(&vec![0x88; 400], 5, &key(), mid(), pickup(), EXPIRY)
			.unwrap();
		assert_eq!(validate_prepared_batch(&batch, NOW), Ok(5));
	}

	#[test]
	fn validate_rejects_empty() {
		let batch = PreparedBatch { pickup_key: pickup(), message_id: mid(), shares: alloc::vec![] };
		assert_eq!(
			validate_prepared_batch(&batch, NOW),
			Err(BatchValidationError::NoShares),
		);
	}

	#[test]
	fn validate_rejects_missing_share() {
		let mut batch =
			prepare_batch(&vec![0x99; 400], 5, &key(), mid(), pickup(), EXPIRY).unwrap();
		batch.shares.pop();
		assert_eq!(
			validate_prepared_batch(&batch, NOW),
			Err(BatchValidationError::WrongShareCount { got: 4, total: 5 }),
		);
	}

	#[test]
	fn validate_rejects_duplicate_index() {
		let mut batch =
			prepare_batch(&vec![0xAB; 400], 3, &key(), mid(), pickup(), EXPIRY).unwrap();
		batch.shares[2] = batch.shares[0].clone();
		assert_eq!(
			validate_prepared_batch(&batch, NOW),
			Err(BatchValidationError::DuplicateIndex { share_index: 0 }),
		);
	}

	#[test]
	fn validate_rejects_index_out_of_range() {
		let mut batch =
			prepare_batch(&vec![0xAC; 400], 3, &key(), mid(), pickup(), EXPIRY).unwrap();
		batch.shares[2].share_index = 7;
		assert_eq!(
			validate_prepared_batch(&batch, NOW),
			Err(BatchValidationError::IndexOutOfRange { share_index: 7, total: 3 }),
		);
	}

	#[test]
	fn validate_rejects_total_mismatch() {
		let mut batch =
			prepare_batch(&vec![0xAD; 400], 3, &key(), mid(), pickup(), EXPIRY).unwrap();
		batch.shares[1].total_shares = 4;
		assert_eq!(
			validate_prepared_batch(&batch, NOW),
			Err(BatchValidationError::TotalMismatch { slice_index: 1 }),
		);
	}

	#[test]
	fn validate_rejects_expiry_mismatch() {
		let mut batch =
			prepare_batch(&vec![0xAE; 400], 3, &key(), mid(), pickup(), EXPIRY).unwrap();
		batch.shares[1].expires_at_unix_ts += 1;
		assert_eq!(
			validate_prepared_batch(&batch, NOW),
			Err(BatchValidationError::ExpiryMismatch { slice_index: 1 }),
		);
	}

	#[test]
	fn validate_rejects_stale_expiry() {
		// Sender-stamped expiry far in the past fails receive bounds.
		let batch = prepare_batch(&vec![0xAF; 400], 3, &key(), mid(), pickup(), NOW - 7200)
			.unwrap();
		assert!(matches!(
			validate_prepared_batch(&batch, NOW),
			Err(BatchValidationError::ExpiryOutOfBounds { .. }),
		));
	}

	#[test]
	fn validate_rejects_far_future_expiry() {
		let batch = prepare_batch(
			&vec![0xB0; 400],
			3,
			&key(),
			mid(),
			pickup(),
			NOW + CHAT_TTL_SECONDS + 100_000,
		)
		.unwrap();
		assert!(matches!(
			validate_prepared_batch(&batch, NOW),
			Err(BatchValidationError::ExpiryOutOfBounds { .. }),
		));
	}
}
