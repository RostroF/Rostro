// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Bucket-routing primitives for the chat-gossip layer.
//!
//! ## Buckets, not shards
//!
//! Each pickup_key falls into one of [`BUCKET_COUNT`] (256) **buckets**
//! based on its top byte ([`bucket_for_pickup_key`]). Buckets divide
//! the global pickup-key keyspace so each gossip-channel node can
//! choose to carry traffic for only a subset of buckets.
//!
//! **Buckets are not the same as XOR shards.** A single chat message
//! is still split into N XOR-stripe shares
//! ([`crate::stripe::split_xor`], default N=5); all shares of one
//! message share the same pickup_key and therefore live in the same
//! bucket. The bucket layer routes those shares to nodes; the shard
//! layer is the on-wire stripe-and-reassemble primitive.
//!
//! ## Subscription model
//!
//! Each node advertises a [`BucketSubscription`] — a signed bitmap
//! over the 256 buckets, declaring which ones it carries. Peers
//! cache the advertisement (keyed by `node_pubkey`), versioned for
//! monotonicity, and timestamped for replay-resistance.
//!
//! Subscription is operator-capacity-bound but network-assignment-
//! driven: the operator sets a `target_bucket_count`; the runtime
//! algorithm picks which `target_bucket_count` buckets to subscribe
//! to based on the network's current balance (which the local
//! [`BucketSubscription`] cache reveals). For v0.1 demo /
//! early-network the default is 256 of 256 — every node carries
//! every bucket, no filtering. Operators dial down as the network
//! grows.
//!
//! ## Rebalance timing
//!
//! Rebalance once per week, at a per-node deterministic-random time
//! within a 12-hour window on **Tuesday UTC** (low-traffic day).
//! The per-node offset within the window is
//! `blake2_256(node_pubkey || week_number)`, taken as a u64 mod
//! [`REBALANCE_WINDOW_DURATION_SECS`]. This spreads rebalance
//! events uniformly across the network's nodes during the
//! 12-hour window; an attacker can compute one specific node's
//! rebalance time but can't synchronize an attack against the
//! whole network.
//!
//! Pressure relief *between* weekly rebalances: new nodes joining
//! pick the least-subscribed buckets at boot (using the cache they
//! build from connected peers' advertisements). Existing nodes
//! hold their subscription until the next weekly slot — stability
//! over reactivity.

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use sp_crypto_hashing::blake2_256;

use crate::descriptor::PickupKey;

/// Total number of buckets in the keyspace partition. A pickup_key's
/// top byte selects a bucket. 256 is the natural choice — clean
/// byte alignment, large enough to enable per-node tuning down to
/// 1.5% of keyspace at mainnet scale, small enough that the bitmap
/// is 32 bytes (one byte per bit).
pub const BUCKET_COUNT: u16 = 256;

/// Bitmap byte length for a [`BucketSubscription`]. 256 bits = 32
/// bytes. Each bit position `b` corresponds to bucket `b`.
pub const BUCKET_BITMAP_BYTES: usize = 32;

/// Default per-node subscription count for v0.1 demo and early
/// networks: every node carries every bucket. Operators dial this
/// down (via a future `--chat-bucket-subscription-count` CLI flag)
/// as the network grows past the regime where redundancy is the
/// limiting factor.
pub const DEFAULT_SUBSCRIPTION_COUNT: u16 = 256;

/// Maximum age of a received [`BucketSubscription`] advertisement
/// before it's rejected as stale. 12 hours covers the rebalance
/// window itself plus operational slack; older advertisements are
/// presumed replays and dropped.
pub const MAX_ADVERTISEMENT_AGE_SECS: u64 = 12 * 3600;

/// Anchor for week-number computation: Tuesday 2024-01-02 06:00:00
/// UTC. Week 0 starts here; week N starts at
/// `WEEK_ZERO_ANCHOR_UNIX_S + N * SECONDS_PER_WEEK`. Anchoring on
/// a known Tuesday 06:00 UTC makes the rebalance window
/// `[week_start, week_start + REBALANCE_WINDOW_DURATION_SECS]`
/// exactly the Tuesday 06:00-18:00 UTC window each week.
pub const WEEK_ZERO_ANCHOR_UNIX_S: u64 = 1_704_175_200;

/// 7 days in seconds.
pub const SECONDS_PER_WEEK: u64 = 7 * 86_400;

/// Duration of the weekly rebalance window in seconds. 12 hours.
/// Per-node rebalance times are spread deterministic-randomly
/// across this window via
/// [`compute_rebalance_time`].
pub const REBALANCE_WINDOW_DURATION_SECS: u64 = 12 * 3600;

/// Return the bucket index for a given pickup key. Top byte of the
/// pickup_key (which is itself a blake2_256 hash, so uniformly
/// distributed) — gives a uniform distribution over the 256
/// buckets at no extra hash cost.
pub fn bucket_for_pickup_key(pk: &PickupKey) -> u8 {
	pk.0[0]
}

/// 256-bit bitmap over the [`BUCKET_COUNT`] buckets. Bit position
/// `b` in this bitmap corresponds to bucket `b`.
///
/// Wire representation is the 32-byte array directly; SCALE encoding
/// is just the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct BucketBitmap(pub [u8; BUCKET_BITMAP_BYTES]);

impl BucketBitmap {
	/// Empty bitmap — no buckets subscribed.
	pub fn empty() -> Self {
		Self([0u8; BUCKET_BITMAP_BYTES])
	}

	/// Full bitmap — every bucket subscribed. This is the v0.1
	/// demo / early-network default for a new node.
	pub fn all() -> Self {
		Self([0xFFu8; BUCKET_BITMAP_BYTES])
	}

	/// `true` if bucket `b` is set in the bitmap.
	pub fn contains(&self, b: u8) -> bool {
		let byte_idx = (b >> 3) as usize;
		let bit_mask = 1u8 << (b & 0b111);
		self.0[byte_idx] & bit_mask != 0
	}

	/// Set bucket `b` in the bitmap. Idempotent.
	pub fn insert(&mut self, b: u8) {
		let byte_idx = (b >> 3) as usize;
		let bit_mask = 1u8 << (b & 0b111);
		self.0[byte_idx] |= bit_mask;
	}

	/// Clear bucket `b` in the bitmap. Idempotent.
	pub fn remove(&mut self, b: u8) {
		let byte_idx = (b >> 3) as usize;
		let bit_mask = 1u8 << (b & 0b111);
		self.0[byte_idx] &= !bit_mask;
	}

	/// Number of buckets set.
	pub fn count(&self) -> u32 {
		self.0.iter().map(|byte| byte.count_ones()).sum()
	}

	/// Iterate over the bucket indices that are set, in ascending
	/// order.
	pub fn iter_set(&self) -> BucketBitmapIter<'_> {
		BucketBitmapIter { bitmap: self, cursor: 0 }
	}
}

/// Iterator over the set bucket indices of a [`BucketBitmap`].
pub struct BucketBitmapIter<'a> {
	bitmap: &'a BucketBitmap,
	cursor: u16,
}

impl<'a> Iterator for BucketBitmapIter<'a> {
	type Item = u8;
	fn next(&mut self) -> Option<u8> {
		while self.cursor < BUCKET_COUNT {
			let b = self.cursor as u8;
			self.cursor += 1;
			if self.bitmap.contains(b) {
				return Some(b);
			}
		}
		None
	}
}

/// Signed bucket subscription advertisement broadcast by a node on
/// `/rostro/chat-gossip/1`. Peers cache one of these per
/// `node_pubkey`, keeping the latest by `version`.
///
/// The signature is Ed25519 over [`Self::signing_payload`]; the
/// signing key is the node's libp2p node-identity key (the one its
/// PeerId derives from). Peers verify the signature with
/// [`Self::verify_signature`] before caching.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BucketSubscription {
	/// Issuing node's 32-byte Ed25519 libp2p node-identity pubkey.
	pub node_pubkey: [u8; 32],
	/// Monotonic per-node counter. Cache rejects advertisements
	/// whose version is not strictly greater than the cached one.
	pub version: u32,
	/// The 256-bit bitmap of subscribed buckets.
	pub bitmap: BucketBitmap,
	/// Unix-timestamp (seconds) at which the advertisement was
	/// produced. Used for replay-window enforcement
	/// ([`MAX_ADVERTISEMENT_AGE_SECS`]).
	pub timestamp_unix_s: u64,
	/// Ed25519 signature over [`Self::signing_payload`].
	pub signature: [u8; 64],
}

impl BucketSubscription {
	/// Byte sequence the signature covers: `node_pubkey || version
	/// (BE) || bitmap || timestamp (BE)`. Stable across runtime
	/// versions; do not change without bumping the protocol version
	/// suffix.
	pub fn signing_payload(&self) -> Vec<u8> {
		let mut buf = Vec::with_capacity(32 + 4 + BUCKET_BITMAP_BYTES + 8);
		buf.extend_from_slice(&self.node_pubkey);
		buf.extend_from_slice(&self.version.to_be_bytes());
		buf.extend_from_slice(&self.bitmap.0);
		buf.extend_from_slice(&self.timestamp_unix_s.to_be_bytes());
		buf
	}

	/// Build a signed advertisement. The caller provides a closure
	/// that signs an arbitrary byte slice with the local node's
	/// Ed25519 identity key (typically via the libp2p `Keypair`).
	pub fn build_signed<F>(
		node_pubkey: [u8; 32],
		version: u32,
		bitmap: BucketBitmap,
		timestamp_unix_s: u64,
		sign_fn: F,
	) -> Self
	where
		F: FnOnce(&[u8]) -> [u8; 64],
	{
		let unsigned = Self {
			node_pubkey,
			version,
			bitmap,
			timestamp_unix_s,
			signature: [0u8; 64],
		};
		let sig = sign_fn(&unsigned.signing_payload());
		Self { signature: sig, ..unsigned }
	}

	/// Verify the Ed25519 signature against `node_pubkey`. Returns
	/// `Err(InvalidPubkey)` if the pubkey isn't a valid Edwards
	/// point, or `Err(SignatureInvalid)` if the signature doesn't
	/// verify.
	pub fn verify_signature(&self) -> Result<(), AdvertisementError> {
		let vk = ed25519_zebra::VerificationKey::try_from(self.node_pubkey)
			.map_err(|_| AdvertisementError::InvalidPubkey)?;
		let sig = ed25519_zebra::Signature::from(self.signature);
		vk.verify(&sig, &self.signing_payload())
			.map_err(|_| AdvertisementError::SignatureInvalid)
	}

	/// Check freshness against the receiver's local clock. Returns
	/// `false` if the advertisement is older than
	/// [`MAX_ADVERTISEMENT_AGE_SECS`] or more than a small
	/// allowance in the future (handles minor sender-clock skew
	/// without admitting wildly-future replays).
	pub fn is_fresh(&self, now_unix_s: u64) -> bool {
		if self.timestamp_unix_s > now_unix_s {
			let skew = self.timestamp_unix_s - now_unix_s;
			return skew <= 60;
		}
		let age = now_unix_s - self.timestamp_unix_s;
		age <= MAX_ADVERTISEMENT_AGE_SECS
	}
}

/// Reasons a [`BucketSubscription`] is rejected at receive time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertisementError {
	/// `node_pubkey` is not a valid Ed25519 / Edwards curve point.
	InvalidPubkey,
	/// Signature did not verify against `node_pubkey`.
	SignatureInvalid,
	/// Advertisement age exceeds [`MAX_ADVERTISEMENT_AGE_SECS`] (or
	/// is wildly in the future).
	Stale,
	/// `version` is not strictly greater than the cached version
	/// for this `node_pubkey`. Prevents replay of older
	/// advertisements after the cache TTL'd them out.
	VersionRegression,
}

/// Compute the week number (relative to [`WEEK_ZERO_ANCHOR_UNIX_S`])
/// for a given Unix timestamp. Returns 0 for any timestamp at or
/// before the anchor (degenerate-but-defined behavior).
pub fn current_rebalance_week(now_unix_s: u64) -> u32 {
	if now_unix_s <= WEEK_ZERO_ANCHOR_UNIX_S {
		return 0;
	}
	((now_unix_s - WEEK_ZERO_ANCHOR_UNIX_S) / SECONDS_PER_WEEK) as u32
}

/// Compute this node's deterministic rebalance time for a given
/// week. Returns the Unix-seconds timestamp at which the node
/// should perform its weekly rebalance — somewhere within the
/// Tuesday 06:00-18:00 UTC window for that week.
pub fn compute_rebalance_time(node_pubkey: &[u8; 32], week_number: u32) -> u64 {
	let week_start_unix_s =
		WEEK_ZERO_ANCHOR_UNIX_S + (week_number as u64) * SECONDS_PER_WEEK;
	let mut input = Vec::with_capacity(32 + 4);
	input.extend_from_slice(node_pubkey);
	input.extend_from_slice(&week_number.to_be_bytes());
	let h = blake2_256(&input);
	let offset = u64::from_be_bytes([
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
	]) % REBALANCE_WINDOW_DURATION_SECS;
	week_start_unix_s + offset
}

/// Compute this node's target bucket subscription given the
/// network's current presence distribution. Picks the
/// `target_count` buckets with the fewest current subscribers,
/// breaking ties deterministically via a hash of
/// `(node_pubkey || bucket)`.
///
/// `distribution[b]` is the count of cached peers subscribed to
/// bucket `b` (typically from `BucketCache::full_distribution`).
///
/// Properties:
///
/// - **Network-driven assignment**: this node's pick depends on
///   what *other* nodes carry. As the network shifts, this node's
///   weekly rebalance reads the latest distribution and lands on
///   underloaded buckets.
/// - **Deterministic tie-breaking**: at network bootstrap when
///   every bucket has 0 subscribers, the hash tiebreaker spreads
///   different nodes' choices uniformly across the 256-bucket
///   space without any coordination. Two nodes with different
///   pubkeys land on different bucket sets even with identical
///   input distributions.
/// - **Pure function**: no I/O, no side effects. Unit-testable.
///   Call this whenever you want a new bitmap; the periodic
///   rebalance task is the one that decides *when* to apply it.
///
/// `target_count` is clamped to `[0, BUCKET_COUNT]`. Passing
/// 0 returns an empty bitmap; passing `>=BUCKET_COUNT` returns
/// `BucketBitmap::all()` (no rebalance needed at default
/// subscription).
pub fn compute_target_subscription(
	distribution: &[usize; BUCKET_COUNT as usize],
	target_count: u16,
	node_pubkey: &[u8; 32],
) -> BucketBitmap {
	let cap = (BUCKET_COUNT as u16).min(target_count) as usize;
	if cap == 0 {
		return BucketBitmap::empty();
	}
	if cap >= BUCKET_COUNT as usize {
		return BucketBitmap::all();
	}

	// Score each bucket: (subscriber_count, hash-derived tiebreak).
	// Ascending sort by this composite picks least-subscribed first,
	// with deterministic tie resolution.
	let mut scored: alloc::vec::Vec<(u8, usize, u64)> = (0..=255u8)
		.map(|b| {
			let mut input = alloc::vec::Vec::with_capacity(33);
			input.extend_from_slice(node_pubkey);
			input.push(b);
			let h = blake2_256(&input);
			let tie = u64::from_be_bytes([
				h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
			]);
			(b, distribution[b as usize], tie)
		})
		.collect();
	scored.sort_by(|a, b| (a.1, a.2).cmp(&(b.1, b.2)));

	let mut bitmap = BucketBitmap::empty();
	for (b, _, _) in scored.iter().take(cap) {
		bitmap.insert(*b);
	}
	bitmap
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::descriptor::PickupKey;
	use ed25519_zebra::SigningKey;
	use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

	// ── BucketBitmap ──────────────────────────────────────────────

	#[test]
	fn bitmap_empty_contains_nothing() {
		let b = BucketBitmap::empty();
		for bucket in 0..=255u8 {
			assert!(!b.contains(bucket));
		}
		assert_eq!(b.count(), 0);
	}

	#[test]
	fn bitmap_all_contains_everything() {
		let b = BucketBitmap::all();
		for bucket in 0..=255u8 {
			assert!(b.contains(bucket));
		}
		assert_eq!(b.count(), 256);
	}

	#[test]
	fn bitmap_insert_and_contains() {
		let mut b = BucketBitmap::empty();
		b.insert(0);
		b.insert(7);
		b.insert(8);
		b.insert(127);
		b.insert(255);
		assert!(b.contains(0));
		assert!(b.contains(7));
		assert!(b.contains(8));
		assert!(b.contains(127));
		assert!(b.contains(255));
		assert!(!b.contains(1));
		assert!(!b.contains(128));
		assert_eq!(b.count(), 5);
	}

	#[test]
	fn bitmap_remove_clears_specific_bit() {
		let mut b = BucketBitmap::all();
		b.remove(42);
		assert!(!b.contains(42));
		// All others remain.
		for bucket in (0..=255u8).filter(|&b| b != 42) {
			assert!(b.contains(bucket));
		}
		assert_eq!(b.count(), 255);
	}

	#[test]
	fn bitmap_iter_set_yields_sorted_indices() {
		let mut b = BucketBitmap::empty();
		b.insert(7);
		b.insert(255);
		b.insert(0);
		b.insert(42);
		let v: Vec<u8> = b.iter_set().collect();
		assert_eq!(v, vec![0, 7, 42, 255]);
	}

	#[test]
	fn bitmap_scale_roundtrip() {
		let mut b = BucketBitmap::empty();
		b.insert(1);
		b.insert(2);
		b.insert(254);
		let bytes = b.encode();
		assert_eq!(bytes.len(), BUCKET_BITMAP_BYTES);
		let decoded = BucketBitmap::decode(&mut &bytes[..]).unwrap();
		assert_eq!(b, decoded);
	}

	#[test]
	fn bitmap_idempotent_insert_remove() {
		let mut b = BucketBitmap::empty();
		b.insert(100);
		b.insert(100);
		assert_eq!(b.count(), 1);
		b.remove(100);
		b.remove(100);
		assert_eq!(b.count(), 0);
	}

	// ── bucket_for_pickup_key ─────────────────────────────────────

	#[test]
	fn bucket_for_pickup_key_uses_top_byte() {
		let mut pk = PickupKey([0u8; 32]);
		pk.0[0] = 0xAB;
		assert_eq!(bucket_for_pickup_key(&pk), 0xAB);

		pk.0[0] = 0x00;
		assert_eq!(bucket_for_pickup_key(&pk), 0x00);

		pk.0[0] = 0xFF;
		assert_eq!(bucket_for_pickup_key(&pk), 0xFF);
	}

	// ── BucketSubscription sign + verify ──────────────────────────

	fn sign_with(key: &SigningKey) -> impl FnOnce(&[u8]) -> [u8; 64] + '_ {
		move |payload: &[u8]| key.sign(payload).into()
	}

	#[test]
	fn subscription_sign_and_verify_roundtrip() {
		let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
		let sk = SigningKey::new(&mut rng);
		let vk = ed25519_zebra::VerificationKey::from(&sk);
		let pubkey_bytes: [u8; 32] = vk.into();

		let sub = BucketSubscription::build_signed(
			pubkey_bytes,
			1,
			BucketBitmap::all(),
			1_700_000_000,
			sign_with(&sk),
		);
		assert!(sub.verify_signature().is_ok());
	}

	#[test]
	fn subscription_tampered_bitmap_fails_verify() {
		let mut rng = ChaCha20Rng::from_seed([0x43; 32]);
		let sk = SigningKey::new(&mut rng);
		let vk = ed25519_zebra::VerificationKey::from(&sk);
		let pubkey_bytes: [u8; 32] = vk.into();

		let mut sub = BucketSubscription::build_signed(
			pubkey_bytes,
			1,
			BucketBitmap::empty(),
			1_700_000_000,
			sign_with(&sk),
		);
		// Flip a bit in the bitmap.
		sub.bitmap.insert(100);
		assert_eq!(
			sub.verify_signature(),
			Err(AdvertisementError::SignatureInvalid),
		);
	}

	#[test]
	fn subscription_tampered_version_fails_verify() {
		let mut rng = ChaCha20Rng::from_seed([0x44; 32]);
		let sk = SigningKey::new(&mut rng);
		let vk = ed25519_zebra::VerificationKey::from(&sk);
		let pubkey_bytes: [u8; 32] = vk.into();

		let mut sub = BucketSubscription::build_signed(
			pubkey_bytes,
			1,
			BucketBitmap::all(),
			1_700_000_000,
			sign_with(&sk),
		);
		sub.version = 2;
		assert_eq!(
			sub.verify_signature(),
			Err(AdvertisementError::SignatureInvalid),
		);
	}

	#[test]
	fn subscription_swapped_pubkey_fails_verify() {
		let mut rng = ChaCha20Rng::from_seed([0x45; 32]);
		let sk_a = SigningKey::new(&mut rng);
		let sk_b = SigningKey::new(&mut rng);
		let vk_b = ed25519_zebra::VerificationKey::from(&sk_b);
		let pubkey_b: [u8; 32] = vk_b.into();

		// Sign with A but claim B's pubkey.
		let sub = BucketSubscription::build_signed(
			pubkey_b,
			1,
			BucketBitmap::all(),
			1_700_000_000,
			sign_with(&sk_a),
		);
		assert_eq!(
			sub.verify_signature(),
			Err(AdvertisementError::SignatureInvalid),
		);
	}

	#[test]
	fn subscription_bogus_pubkey_bytes_fail_verify() {
		// All-0xFF bytes are unlikely to decompress to a valid
		// Edwards point. Some 32-byte sequences (e.g. [0u8; 32])
		// DO lift to a valid (if degenerate) point and pass
		// VerificationKey decode; bogus bytes hit the SignatureInvalid
		// or InvalidPubkey path depending on which curve check
		// rejects them. Either path preserves the contract that
		// bogus pubkey bytes do not verify a signature.
		let sub = BucketSubscription {
			node_pubkey: [0xFFu8; 32],
			version: 1,
			bitmap: BucketBitmap::all(),
			timestamp_unix_s: 1_700_000_000,
			signature: [0u8; 64],
		};
		match sub.verify_signature() {
			Err(AdvertisementError::InvalidPubkey)
			| Err(AdvertisementError::SignatureInvalid) => {},
			other => panic!(
				"expected InvalidPubkey or SignatureInvalid, got {:?}",
				other,
			),
		}
	}

	#[test]
	fn subscription_scale_roundtrip() {
		let mut rng = ChaCha20Rng::from_seed([0x46; 32]);
		let sk = SigningKey::new(&mut rng);
		let vk = ed25519_zebra::VerificationKey::from(&sk);
		let pubkey_bytes: [u8; 32] = vk.into();

		let sub = BucketSubscription::build_signed(
			pubkey_bytes,
			42,
			BucketBitmap::all(),
			1_700_000_000,
			sign_with(&sk),
		);
		let bytes = sub.encode();
		let decoded = BucketSubscription::decode(&mut &bytes[..]).unwrap();
		assert_eq!(sub, decoded);
		assert!(decoded.verify_signature().is_ok());
	}

	// ── freshness ─────────────────────────────────────────────────

	#[test]
	fn fresh_subscription_within_window() {
		let now = 1_700_000_000;
		let sub = BucketSubscription {
			node_pubkey: [1u8; 32],
			version: 1,
			bitmap: BucketBitmap::all(),
			timestamp_unix_s: now - 3600, // 1h old
			signature: [0u8; 64],
		};
		assert!(sub.is_fresh(now));
	}

	#[test]
	fn stale_subscription_beyond_window() {
		let now = 1_700_000_000;
		let sub = BucketSubscription {
			node_pubkey: [1u8; 32],
			version: 1,
			bitmap: BucketBitmap::all(),
			timestamp_unix_s: now - (MAX_ADVERTISEMENT_AGE_SECS + 60),
			signature: [0u8; 64],
		};
		assert!(!sub.is_fresh(now));
	}

	#[test]
	fn slightly_future_subscription_accepted() {
		let now = 1_700_000_000;
		let sub = BucketSubscription {
			node_pubkey: [1u8; 32],
			version: 1,
			bitmap: BucketBitmap::all(),
			timestamp_unix_s: now + 30, // sender's clock 30s fast
			signature: [0u8; 64],
		};
		assert!(sub.is_fresh(now));
	}

	#[test]
	fn far_future_subscription_rejected() {
		let now = 1_700_000_000;
		let sub = BucketSubscription {
			node_pubkey: [1u8; 32],
			version: 1,
			bitmap: BucketBitmap::all(),
			timestamp_unix_s: now + 3600, // 1h in the future
			signature: [0u8; 64],
		};
		assert!(!sub.is_fresh(now));
	}

	// ── rebalance timing ──────────────────────────────────────────

	#[test]
	fn week_zero_anchor_is_at_zero() {
		assert_eq!(current_rebalance_week(WEEK_ZERO_ANCHOR_UNIX_S), 0);
	}

	#[test]
	fn one_week_after_anchor_is_week_one() {
		assert_eq!(
			current_rebalance_week(WEEK_ZERO_ANCHOR_UNIX_S + SECONDS_PER_WEEK),
			1,
		);
	}

	#[test]
	fn fractional_week_rounds_down() {
		// 3 days into week 5 → still week 5.
		let mid_week_5 =
			WEEK_ZERO_ANCHOR_UNIX_S + 5 * SECONDS_PER_WEEK + 3 * 86_400;
		assert_eq!(current_rebalance_week(mid_week_5), 5);
	}

	#[test]
	fn before_anchor_returns_week_zero() {
		assert_eq!(current_rebalance_week(0), 0);
		assert_eq!(current_rebalance_week(WEEK_ZERO_ANCHOR_UNIX_S - 1), 0);
	}

	#[test]
	fn rebalance_time_lies_within_window() {
		let key = [0x77u8; 32];
		// Check 20 consecutive weeks — every one of them must fall
		// within the Tuesday 06:00-18:00 UTC window.
		for week in 0..20u32 {
			let week_start =
				WEEK_ZERO_ANCHOR_UNIX_S + week as u64 * SECONDS_PER_WEEK;
			let rebalance = compute_rebalance_time(&key, week);
			assert!(rebalance >= week_start, "week {week}: rebalance before window");
			assert!(
				rebalance < week_start + REBALANCE_WINDOW_DURATION_SECS,
				"week {week}: rebalance after window",
			);
		}
	}

	#[test]
	fn rebalance_time_deterministic_per_key_and_week() {
		let key = [0x11u8; 32];
		let a = compute_rebalance_time(&key, 7);
		let b = compute_rebalance_time(&key, 7);
		assert_eq!(a, b);
	}

	#[test]
	fn rebalance_time_differs_across_keys() {
		let week = 10;
		let mut seen = alloc::collections::BTreeSet::new();
		for i in 0..32u8 {
			let mut key = [0u8; 32];
			key[0] = i;
			seen.insert(compute_rebalance_time(&key, week));
		}
		// 32 distinct keys, expect roughly 32 distinct rebalance
		// times. Some collisions are statistically possible but
		// vanishingly improbable for 32 draws from a 43_200-element
		// space. Require at least 30 distinct.
		assert!(
			seen.len() >= 30,
			"expected nearly-distinct rebalance times across keys; got {} unique out of 32",
			seen.len(),
		);
	}

	#[test]
	fn rebalance_time_differs_across_weeks_for_same_key() {
		let key = [0x42u8; 32];
		let a = compute_rebalance_time(&key, 100);
		let b = compute_rebalance_time(&key, 101);
		assert_ne!(a, b);
	}

	#[test]
	fn rebalance_time_uniformly_distributed_across_window() {
		// Sample many node keys for the same week; check that
		// rebalance times are spread across the 12-hour window
		// (each of 12 1-hour buckets has at least one).
		let week = 200;
		let mut hour_bucket_hits = [false; 12];
		for i in 0..256u32 {
			let mut key = [0u8; 32];
			key[..4].copy_from_slice(&i.to_be_bytes());
			let rebalance = compute_rebalance_time(&key, week);
			let week_start = WEEK_ZERO_ANCHOR_UNIX_S + week as u64 * SECONDS_PER_WEEK;
			let offset_into_window = rebalance - week_start;
			let hour = (offset_into_window / 3600) as usize;
			hour_bucket_hits[hour.min(11)] = true;
		}
		let hits = hour_bucket_hits.iter().filter(|&&h| h).count();
		assert_eq!(
			hits, 12,
			"every 1-hour sub-bucket of the 12-hour window should be hit \
			 by at least one of 256 sample keys; only {hits}/12 were",
		);
	}

	// ── compute_target_subscription ───────────────────────────────

	fn empty_distribution() -> [usize; BUCKET_COUNT as usize] {
		[0usize; BUCKET_COUNT as usize]
	}

	#[test]
	fn target_zero_returns_empty_bitmap() {
		let dist = empty_distribution();
		let bm = compute_target_subscription(&dist, 0, &[1u8; 32]);
		assert_eq!(bm.count(), 0);
	}

	#[test]
	fn target_full_returns_all_bitmap() {
		let dist = empty_distribution();
		let bm = compute_target_subscription(&dist, BUCKET_COUNT, &[1u8; 32]);
		assert_eq!(bm, BucketBitmap::all());
	}

	#[test]
	fn target_clamps_above_bucket_count() {
		let dist = empty_distribution();
		let bm = compute_target_subscription(&dist, 1000, &[1u8; 32]);
		assert_eq!(bm, BucketBitmap::all());
	}

	#[test]
	fn target_count_exact_at_zero_distribution() {
		// With zero subscribers everywhere, ties are broken by
		// hash; we should get exactly `target_count` buckets.
		let dist = empty_distribution();
		for target in [1, 4, 16, 64, 128, 255u16] {
			let bm = compute_target_subscription(&dist, target, &[0x42u8; 32]);
			assert_eq!(
				bm.count(),
				target as u32,
				"target={target}: bitmap should have exactly target buckets",
			);
		}
	}

	#[test]
	fn different_keys_pick_different_buckets() {
		// At empty distribution, the hash tiebreaker drives uniform
		// spread. Two distinct node keys should land on largely
		// distinct bucket sets.
		let dist = empty_distribution();
		let target = 16u16;
		let bm_a = compute_target_subscription(&dist, target, &[0x01u8; 32]);
		let bm_b = compute_target_subscription(&dist, target, &[0x02u8; 32]);
		let overlap = (0..=255u8)
			.filter(|b| bm_a.contains(*b) && bm_b.contains(*b))
			.count();
		// 16 of 256 chosen by each, independently uniform → expected
		// overlap = 16 * 16 / 256 = 1. Allow up to 8 (lots of slack).
		assert!(
			overlap <= 8,
			"two distinct keys produced suspiciously high bucket overlap: {overlap}",
		);
	}

	#[test]
	fn deterministic_for_same_inputs() {
		let dist = empty_distribution();
		let key = [0x77u8; 32];
		let bm_a = compute_target_subscription(&dist, 32, &key);
		let bm_b = compute_target_subscription(&dist, 32, &key);
		assert_eq!(bm_a, bm_b);
	}

	#[test]
	fn picks_least_subscribed_buckets() {
		// Build a distribution where bucket 0 has 1000 subscribers
		// and bucket 1 has 0; with target_count = 1, we should
		// pick bucket 1, not bucket 0.
		let mut dist = empty_distribution();
		dist[0] = 1000;
		// All other buckets at 0; bucket 1 should be picked first
		// (tie-broken by hash among the 255 zero-count buckets).
		let bm = compute_target_subscription(&dist, 1, &[0xAAu8; 32]);
		assert!(!bm.contains(0));
		assert_eq!(bm.count(), 1);
	}

	#[test]
	fn avoids_oversubscribed_buckets() {
		// Bucket 0 is heavily oversubscribed; 100 other buckets are
		// at 0. With target_count = 100, bucket 0 should be excluded.
		let mut dist = empty_distribution();
		dist[0] = 9999;
		let bm = compute_target_subscription(&dist, 100, &[0xBBu8; 32]);
		assert!(!bm.contains(0));
		assert_eq!(bm.count(), 100);
	}

	#[test]
	fn rebalance_picks_underloaded_after_distribution_shift() {
		// Simulate two scenarios: first all buckets equal, then
		// some buckets become oversubscribed. The rebalance result
		// should shift away from the oversubscribed buckets.
		let dist_before = empty_distribution();
		let mut dist_after = empty_distribution();
		// Make buckets 0..32 heavily subscribed.
		for b in 0..32usize {
			dist_after[b] = 100;
		}
		let key = [0xCCu8; 32];
		let bm_before = compute_target_subscription(&dist_before, 32, &key);
		let bm_after = compute_target_subscription(&dist_after, 32, &key);

		// `bm_after` should NOT pick any of the oversubscribed
		// buckets (0..32 all have count=100; everything else is 0).
		let picked_oversub = (0..32u8).filter(|b| bm_after.contains(*b)).count();
		assert_eq!(
			picked_oversub, 0,
			"rebalance should avoid the oversubscribed buckets",
		);
		// And the before/after bitmaps should differ (the
		// distribution shift caused a meaningful change).
		assert_ne!(bm_before, bm_after);
	}

	// ── pickup-key bucket distribution (smoke test) ───────────────

	#[test]
	fn pickup_keys_distribute_across_buckets() {
		// blake2-derived pickup_keys should spread uniformly across
		// the 256 buckets. Test that at least 200 of 256 buckets
		// receive at least one of 1024 sample pickup_keys.
		let mut bucket_hits = [false; 256];
		for i in 0..1024u32 {
			let mut bytes = [0u8; 32];
			bytes[..4].copy_from_slice(&i.to_be_bytes());
			// Hash to get blake2-uniform.
			let pk = PickupKey(blake2_256(&bytes));
			let bucket = bucket_for_pickup_key(&pk);
			bucket_hits[bucket as usize] = true;
		}
		let hits = bucket_hits.iter().filter(|&&h| h).count();
		assert!(
			hits >= 200,
			"1024 pickup_keys should hit at least 200/256 buckets via \
			 hash uniformity; only {hits} hit",
		);
	}
}
