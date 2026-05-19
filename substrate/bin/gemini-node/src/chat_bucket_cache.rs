// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Bucket subscription cache for the chat-gossip layer.
//!
//! Holds the most recent valid [`BucketSubscription`] advertisement
//! we've received from each connected peer, keyed by their libp2p
//! [`PeerId`]. The cache is the data plane behind two queries the
//! rest of the chat-gossip layer needs to ask:
//!
//! - **"Which peers carry bucket `b`?"** — used by Commit B's push
//!   gossip orchestration to pick recipients for a shard whose
//!   `pickup_key` falls in bucket `b`.
//! - **"How many peers carry bucket `b`?"** — used by the rebalance
//!   algorithm (Commit A.1) to decide which buckets are
//!   underloaded.
//!
//! ## Lifecycle
//!
//! - Populated by `chat_gossip_protocol`'s inbound handler when a
//!   peer sends a valid signed advertisement.
//! - Entries replaced when a peer sends a higher-versioned
//!   advertisement.
//! - Entries dropped when libp2p emits `PeerDisconnected` for the
//!   peer. The libp2p connection state is the implicit TTL — no
//!   periodic heartbeat needed; no timer-driven sweep.
//!
//! ## Concurrency
//!
//! Internal state is `RwLock<HashMap<...>>`. Reads (the routing /
//! count queries) take a read lock; writes (insert / drop) take a
//! write lock. Both held briefly — a couple of hash-map operations,
//! no I/O, no contention surface beyond what `parking_lot` handles.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use rc_network::PeerId;

use rostro_chat_primitives::bucket::{
	AdvertisementError, BucketSubscription, BUCKET_COUNT,
};

/// Thread-safe handle to the bucket subscription cache. Cheap to
/// clone (just clones the inner `Arc`).
#[derive(Clone)]
pub struct BucketCache {
	inner: Arc<RwLock<HashMap<PeerId, BucketSubscription>>>,
}

impl BucketCache {
	/// Construct an empty cache.
	pub fn new() -> Self {
		Self { inner: Arc::new(RwLock::new(HashMap::new())) }
	}

	/// Attempt to insert (or replace) the subscription for `peer`.
	///
	/// The advertisement is rejected if:
	///   * Its signature is invalid or `node_pubkey` is malformed
	///     (`AdvertisementError::InvalidPubkey` /
	///     `AdvertisementError::SignatureInvalid`).
	///   * Its `timestamp_unix_s` is too old (or wildly in the
	///     future) relative to `now_unix_s`
	///     (`AdvertisementError::Stale`).
	///   * There's a cached entry for `peer` with version `>=`
	///     this advertisement's version
	///     (`AdvertisementError::VersionRegression`).
	///
	/// Successful insertion replaces any prior entry for `peer`.
	pub fn try_insert(
		&self,
		peer: PeerId,
		sub: BucketSubscription,
		now_unix_s: u64,
	) -> Result<(), AdvertisementError> {
		sub.verify_signature()?;
		if !sub.is_fresh(now_unix_s) {
			return Err(AdvertisementError::Stale);
		}
		let mut guard = self.inner.write();
		if let Some(existing) = guard.get(&peer) {
			if sub.version <= existing.version {
				return Err(AdvertisementError::VersionRegression);
			}
		}
		guard.insert(peer, sub);
		Ok(())
	}

	/// Drop any cached entry for `peer`. Called by the libp2p
	/// presence watcher on `PeerDisconnected`.
	pub fn drop_peer(&self, peer: &PeerId) {
		let mut guard = self.inner.write();
		guard.remove(peer);
	}

	/// Number of peers currently cached.
	pub fn len(&self) -> usize {
		self.inner.read().len()
	}

	/// `true` if the cache holds no entries.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Number of cached peers subscribed to bucket `b`. The
	/// rebalance algorithm uses this to find underloaded buckets.
	pub fn subscriber_count(&self, b: u8) -> usize {
		self.inner
			.read()
			.values()
			.filter(|sub| sub.bitmap.contains(b))
			.count()
	}

	/// Return the PeerIds of cached peers subscribed to bucket `b`.
	/// Used by Commit B's push orchestration to pick targets.
	pub fn peers_for_bucket(&self, b: u8) -> Vec<PeerId> {
		self.inner
			.read()
			.iter()
			.filter(|(_, sub)| sub.bitmap.contains(b))
			.map(|(peer, _)| *peer)
			.collect()
	}

	/// Snapshot subscriber counts across all 256 buckets in one
	/// read-locked pass. Avoids 256 lock acquisitions when the
	/// rebalance algorithm needs the full distribution.
	pub fn full_distribution(&self) -> [usize; BUCKET_COUNT as usize] {
		let mut counts = [0usize; BUCKET_COUNT as usize];
		let guard = self.inner.read();
		for sub in guard.values() {
			for bucket in 0..=255u8 {
				if sub.bitmap.contains(bucket) {
					counts[bucket as usize] += 1;
				}
			}
		}
		counts
	}

	/// Inspect the cached subscription for a specific peer.
	/// Returns a clone (cheap — the struct is ~140 bytes) so the
	/// caller doesn't hold the read lock.
	pub fn get(&self, peer: &PeerId) -> Option<BucketSubscription> {
		self.inner.read().get(peer).cloned()
	}

	/// Return every peer currently in the cache, with a clone of
	/// their cached subscription. Used by the anti-entropy
	/// periodic task to pick a random peer + iterate their
	/// subscription overlap.
	pub fn all_peers(&self) -> Vec<(PeerId, BucketSubscription)> {
		let g = self.inner.read();
		g.iter().map(|(p, s)| (*p, s.clone())).collect()
	}
}

impl Default for BucketCache {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ed25519_zebra::{SigningKey, VerificationKey};
	use rostro_chat_primitives::bucket::BucketBitmap;

	/// Helper: build a signed subscription with the given parameters.
	/// Derives the signing key from the seed byte deterministically
	/// (no RNG dep needed) so test outputs are reproducible.
	fn make_sub(
		seed: u8,
		version: u32,
		bitmap: BucketBitmap,
		timestamp_unix_s: u64,
	) -> (PeerId, BucketSubscription) {
		let sk = SigningKey::from([seed; 32]);
		let vk = VerificationKey::from(&sk);
		let pubkey: [u8; 32] = vk.into();

		let sub = BucketSubscription::build_signed(
			pubkey,
			version,
			bitmap,
			timestamp_unix_s,
			|payload| sk.sign(payload).into(),
		);
		// PeerId is random for tests; the cache keys on PeerId
		// directly, so we don't need to derive it from the pubkey.
		(PeerId::random(), sub)
	}

	/// Helper: build a signed subscription using the *same* signing
	/// key as a prior `make_sub(seed, ...)` call. Used by the
	/// version-monotonicity tests that need to re-sign a peer's
	/// state at a higher version.
	fn make_sub_same_key(
		seed: u8,
		version: u32,
		bitmap: BucketBitmap,
		timestamp_unix_s: u64,
	) -> BucketSubscription {
		let sk = SigningKey::from([seed; 32]);
		let vk = VerificationKey::from(&sk);
		let pubkey: [u8; 32] = vk.into();
		BucketSubscription::build_signed(
			pubkey,
			version,
			bitmap,
			timestamp_unix_s,
			|payload| sk.sign(payload).into(),
		)
	}

	const NOW: u64 = 1_700_000_000;

	#[test]
	fn empty_cache_starts_empty() {
		let cache = BucketCache::new();
		assert!(cache.is_empty());
		assert_eq!(cache.len(), 0);
		assert_eq!(cache.subscriber_count(42), 0);
		assert!(cache.peers_for_bucket(42).is_empty());
	}

	#[test]
	fn insert_then_drop() {
		let cache = BucketCache::new();
		let (peer, sub) = make_sub(1, 1, BucketBitmap::all(), NOW);
		cache.try_insert(peer, sub, NOW).unwrap();
		assert_eq!(cache.len(), 1);
		cache.drop_peer(&peer);
		assert!(cache.is_empty());
	}

	#[test]
	fn version_monotonic_replace_accepts_higher() {
		let cache = BucketCache::new();
		let (peer, sub1) = make_sub(2, 1, BucketBitmap::all(), NOW);
		cache.try_insert(peer, sub1, NOW).unwrap();

		// Re-sign at version 2 with the same key.
		let mut new_bitmap = BucketBitmap::empty();
		new_bitmap.insert(7);
		let sub2 = make_sub_same_key(2, 2, new_bitmap, NOW);
		cache.try_insert(peer, sub2, NOW).unwrap();

		// Cache now holds the version-2 subscription.
		let cached = cache.get(&peer).unwrap();
		assert_eq!(cached.version, 2);
		assert!(cached.bitmap.contains(7));
		assert!(!cached.bitmap.contains(0));
	}

	#[test]
	fn version_regression_rejected() {
		let cache = BucketCache::new();
		let (peer, sub_v5) = make_sub(3, 5, BucketBitmap::all(), NOW);
		cache.try_insert(peer, sub_v5, NOW).unwrap();

		// Same-or-lower version → reject.
		for v in [1, 4, 5] {
			let sub = make_sub_same_key(3, v, BucketBitmap::empty(), NOW);
			assert_eq!(
				cache.try_insert(peer, sub, NOW),
				Err(AdvertisementError::VersionRegression),
			);
		}
	}

	#[test]
	fn stale_advertisement_rejected() {
		let cache = BucketCache::new();
		let very_old = NOW - 24 * 3600;
		let (peer, sub) = make_sub(4, 1, BucketBitmap::all(), very_old);
		assert_eq!(
			cache.try_insert(peer, sub, NOW),
			Err(AdvertisementError::Stale),
		);
		assert!(cache.is_empty());
	}

	#[test]
	fn invalid_signature_rejected() {
		let cache = BucketCache::new();
		// Start from an empty bitmap so post-signing tamper is
		// observable (changing a clear bit to set produces a
		// different signing payload than what was signed).
		let (peer, mut sub) = make_sub(5, 1, BucketBitmap::empty(), NOW);
		sub.bitmap.insert(99);
		assert_eq!(
			cache.try_insert(peer, sub, NOW),
			Err(AdvertisementError::SignatureInvalid),
		);
	}

	#[test]
	fn subscriber_count_reflects_membership() {
		let cache = BucketCache::new();

		// Three peers, each subscribed to different bucket sets.
		let mut bm_a = BucketBitmap::empty();
		bm_a.insert(10);
		bm_a.insert(20);
		let (peer_a, sub_a) = make_sub(10, 1, bm_a, NOW);
		cache.try_insert(peer_a, sub_a, NOW).unwrap();

		let mut bm_b = BucketBitmap::empty();
		bm_b.insert(10);
		bm_b.insert(30);
		let (peer_b, sub_b) = make_sub(11, 1, bm_b, NOW);
		cache.try_insert(peer_b, sub_b, NOW).unwrap();

		let bm_c = BucketBitmap::all();
		let (peer_c, sub_c) = make_sub(12, 1, bm_c, NOW);
		cache.try_insert(peer_c, sub_c, NOW).unwrap();

		// bucket 10: A, B, C → 3 subscribers
		assert_eq!(cache.subscriber_count(10), 3);
		// bucket 20: A, C → 2 subscribers
		assert_eq!(cache.subscriber_count(20), 2);
		// bucket 30: B, C → 2 subscribers
		assert_eq!(cache.subscriber_count(30), 2);
		// bucket 50: only C (all) → 1 subscriber
		assert_eq!(cache.subscriber_count(50), 1);
	}

	#[test]
	fn peers_for_bucket_returns_matching_peers() {
		let cache = BucketCache::new();
		let mut bm_a = BucketBitmap::empty();
		bm_a.insert(50);
		let (peer_a, sub_a) = make_sub(20, 1, bm_a, NOW);
		cache.try_insert(peer_a, sub_a, NOW).unwrap();

		let mut bm_b = BucketBitmap::empty();
		bm_b.insert(60);
		let (peer_b, sub_b) = make_sub(21, 1, bm_b, NOW);
		cache.try_insert(peer_b, sub_b, NOW).unwrap();

		let in_50 = cache.peers_for_bucket(50);
		let in_60 = cache.peers_for_bucket(60);
		let in_70 = cache.peers_for_bucket(70);

		assert_eq!(in_50, vec![peer_a]);
		assert_eq!(in_60, vec![peer_b]);
		assert!(in_70.is_empty());
	}

	#[test]
	fn full_distribution_one_pass() {
		let cache = BucketCache::new();
		let mut bm_a = BucketBitmap::empty();
		bm_a.insert(0);
		bm_a.insert(255);
		let (peer_a, sub_a) = make_sub(30, 1, bm_a, NOW);
		cache.try_insert(peer_a, sub_a, NOW).unwrap();

		let mut bm_b = BucketBitmap::empty();
		bm_b.insert(0);
		bm_b.insert(128);
		let (peer_b, sub_b) = make_sub(31, 1, bm_b, NOW);
		cache.try_insert(peer_b, sub_b, NOW).unwrap();

		let dist = cache.full_distribution();
		assert_eq!(dist[0], 2);
		assert_eq!(dist[127], 0);
		assert_eq!(dist[128], 1);
		assert_eq!(dist[255], 1);
	}

	#[test]
	fn drop_peer_clears_their_subscriptions() {
		let cache = BucketCache::new();
		let (peer, sub) = make_sub(40, 1, BucketBitmap::all(), NOW);
		cache.try_insert(peer, sub, NOW).unwrap();
		assert_eq!(cache.subscriber_count(0), 1);
		cache.drop_peer(&peer);
		assert_eq!(cache.subscriber_count(0), 0);
		assert_eq!(cache.len(), 0);
	}

	#[test]
	fn drop_unknown_peer_is_noop() {
		let cache = BucketCache::new();
		let stranger = PeerId::random();
		cache.drop_peer(&stranger);
		assert!(cache.is_empty());
	}

	#[test]
	fn clone_shares_state() {
		let cache_a = BucketCache::new();
		let cache_b = cache_a.clone();
		let (peer, sub) = make_sub(50, 1, BucketBitmap::all(), NOW);
		cache_a.try_insert(peer, sub, NOW).unwrap();
		assert_eq!(cache_b.len(), 1, "cloned handle sees the same state");
	}
}
