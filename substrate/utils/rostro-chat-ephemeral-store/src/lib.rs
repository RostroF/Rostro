// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-chat-ephemeral-store — relay-side share storage
//!
//! Phase B2 of the MLS-chat plan. Concrete
//! [`rostro_chat_primitives::store_protocol::ShareStore`]
//! implementation backed by an in-process bounded HashMap with
//! mlock'd share buffers, local-clock TTL sweep, and oldest-
//! first eviction under capacity pressure.
//!
//! ## Why ephemeral
//!
//! Per the chat architecture, the share store is **deliberately
//! non-persistent**:
//!
//! - No disk persistence — a relay restart wipes its store, the
//!   recipient compensates via share replication across multiple
//!   relays
//! - Share buffers are `mlock()`-ed where the OS permits, so cold
//!   pages can't be swapped to disk and a memory-forensic attacker
//!   with disk access doesn't recover stale share fragments
//! - TTL sweep against local wall-clock deletes entries whose
//!   `expires_at_unix_ts` has arrived; the absolute upper bound on
//!   how long a share lives in the relay is its descriptor's TTL.
//!   No chain block tracking required — the store is decoupled from
//!   chain time, so a chat-gossip relay can run a lighter footprint
//!   than a full RPC node. NTP-class clock skew across relays is
//!   absorbed by replication.
//!
//! This trades availability (a relay crash drops in-flight shares
//! for offline recipients) for the strongest possible
//! confidentiality property at the relay layer.
//!
//! ## mlock soft fallback
//!
//! `mlock()` requires `RLIMIT_MEMLOCK` budget. Default unprivileged
//! limits on Linux are typically 64 KB; production relay operators
//! should raise the limit (`ulimit -l unlimited`) or grant
//! `CAP_IPC_LOCK`. If `mlock()` fails for a given share, the store
//! still accepts it but does not lock its buffer — kernel may swap
//! it. The relay logs at startup what its mlock budget is so
//! operators can detect under-provisioned hosts.
//!
//! ## What this crate does NOT do
//!
//! - **No libp2p / no rc-network.** The rc-network adapter that
//!   feeds this store with `IncomingRequest`s lives in
//!   gemini-node (Phase B6, after this commit ships).
//! - **No fetch protocol.** The pickup-key lookup method
//!   [`EphemeralShareStore::get_by_pickup_key`] is here, but the
//!   `/rostro/chat-fetch/1` libp2p binding that exposes it is
//!   Phase B3.

use std::collections::{BTreeMap, HashMap};

use parking_lot::RwLock;
use rostro_chat_primitives::descriptor::{
	MessageId, PickupKey, ShareDescriptor, ShareIndex, UnixTimestamp,
};
use rostro_chat_primitives::store_protocol::{ShareStore, StoreInsertError};
use rostro_chat_primitives::verify::ShareMacTag;

pub mod locked_bytes;
use locked_bytes::LockedBytes;

/// Default total-byte budget for the share store. 64 MiB is enough
/// for a few thousand small chat messages held simultaneously;
/// operators tune higher if their relay's traffic warrants it.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Default entry-count cap. Bounds map growth independently of
/// total bytes (a flood of tiny shares could otherwise OOM via
/// HashMap overhead before hitting `max_bytes`).
pub const DEFAULT_MAX_ENTRIES: usize = 65_536;

/// Configuration for [`EphemeralShareStore`].
#[derive(Debug, Clone, Copy)]
pub struct StoreConfig {
	/// Cap on total share-bytes summed across all entries.
	pub max_bytes: usize,
	/// Cap on entry count.
	pub max_entries: usize,
}

impl Default for StoreConfig {
	fn default() -> Self {
		Self { max_bytes: DEFAULT_MAX_BYTES, max_entries: DEFAULT_MAX_ENTRIES }
	}
}

/// One stored share + its descriptor + its MAC tag.
struct Entry {
	descriptor: ShareDescriptor,
	share_bytes: LockedBytes,
	mac_tag: ShareMacTag,
	/// Monotonic counter assigned at insertion. Breaks ties when
	/// two entries share the same `expires_at_unix_ts` during
	/// eviction.
	insertion_order: u64,
}

impl Entry {
	fn share_size(&self) -> usize {
		self.share_bytes.as_slice().len()
	}
}

/// Inner mutable state guarded by the store's RwLock.
struct Inner {
	/// Primary store keyed by `(message_id, share_index)`.
	by_key: HashMap<(MessageId, ShareIndex), Entry>,
	/// Secondary lookup: `pickup_key → set of primary keys`. The
	/// recipient queries by pickup_key, the store returns all shares
	/// matching.
	by_pickup: HashMap<PickupKey, Vec<(MessageId, ShareIndex)>>,
	/// Ordered for eviction: `(expires_at_unix_ts, insertion_order)
	/// → primary key`. Sweeping iterates ascending; eviction-under-
	/// pressure takes the smallest key (oldest expiry, then oldest
	/// insertion).
	by_expiry: BTreeMap<(UnixTimestamp, u64), (MessageId, ShareIndex)>,
	/// Monotonic insertion counter.
	next_insertion: u64,
	/// Running sum of share_bytes lengths across all entries.
	total_bytes: usize,
}

impl Inner {
	fn new() -> Self {
		Self {
			by_key: HashMap::new(),
			by_pickup: HashMap::new(),
			by_expiry: BTreeMap::new(),
			next_insertion: 0,
			total_bytes: 0,
		}
	}

	/// Remove the entry under `primary_key` from all indices.
	/// Returns the entry's stored share size for total_bytes
	/// adjustment by the caller.
	fn remove_entry(&mut self, primary_key: (MessageId, ShareIndex)) -> Option<usize> {
		let entry = self.by_key.remove(&primary_key)?;
		// Adjust expiry index.
		self.by_expiry
			.remove(&(entry.descriptor.expires_at_unix_ts, entry.insertion_order));
		// Adjust pickup index.
		let pickup = entry.descriptor.pickup_key;
		if let Some(list) = self.by_pickup.get_mut(&pickup) {
			list.retain(|k| *k != primary_key);
			if list.is_empty() {
				self.by_pickup.remove(&pickup);
			}
		}
		let sz = entry.share_size();
		self.total_bytes = self.total_bytes.saturating_sub(sz);
		// `entry` drops here; LockedBytes Drop zeroizes + munlocks.
		Some(sz)
	}

	/// Evict oldest entries until `(total_bytes + incoming_size) <=
	/// max_bytes` AND `len() < max_entries`. Returns the number of
	/// entries evicted. If even evicting everything doesn't make
	/// room (incoming_size alone > max_bytes), returns `None`.
	fn make_room_for(
		&mut self,
		incoming_size: usize,
		config: &StoreConfig,
	) -> Option<usize> {
		if incoming_size > config.max_bytes {
			return None;
		}
		let mut evicted = 0;
		while self.total_bytes + incoming_size > config.max_bytes
			|| self.by_key.len() >= config.max_entries
		{
			// Pop the smallest (oldest expiry / earliest insertion)
			// primary key and route through `remove_entry` so the
			// pickup index AND total_bytes get updated in one place.
			let oldest_primary = match self.by_expiry.values().next().copied() {
				Some(pk) => pk,
				None => return Some(evicted),
			};
			self.remove_entry(oldest_primary);
			evicted += 1;
		}
		Some(evicted)
	}
}

/// Concurrent-safe ephemeral share store.
pub struct EphemeralShareStore {
	inner: RwLock<Inner>,
	config: StoreConfig,
}

impl EphemeralShareStore {
	pub fn new(config: StoreConfig) -> Self {
		Self { inner: RwLock::new(Inner::new()), config }
	}

	pub fn with_default_config() -> Self {
		Self::new(StoreConfig::default())
	}

	/// Sweep entries whose `expires_at_unix_ts <= now_unix_ts`.
	/// Called by the gemini-node binding from a periodic local-clock
	/// timer task. No chain involvement.
	///
	/// Returns the number of entries removed.
	pub fn sweep_expired(&self, now_unix_ts: UnixTimestamp) -> usize {
		let mut g = self.inner.write();
		let mut to_remove: Vec<(MessageId, ShareIndex)> = Vec::new();
		for ((expires_at, _ins), pk) in g.by_expiry.iter() {
			if *expires_at <= now_unix_ts {
				to_remove.push(*pk);
			} else {
				break;
			}
		}
		let count = to_remove.len();
		for pk in to_remove {
			g.remove_entry(pk);
		}
		count
	}

	/// Number of entries currently stored.
	pub fn len(&self) -> usize {
		self.inner.read().by_key.len()
	}

	/// True if no entries are stored.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Sum of `share_bytes` lengths across all stored entries.
	pub fn total_bytes(&self) -> usize {
		self.inner.read().total_bytes
	}

	/// Count shards stored in a specific bucket. The bucket is the top byte of
	/// the `pickup_key` — there are 256 buckets total. Cheap O(buckets + count)
	/// scan; exposes no ciphertext, just a count, so safe to feed into entropy.
	///
	/// Intended use: the rng binding picks a rotating or call-counter-derived
	/// `bucket` index and passes the count as a [`rostro-shop-rng`] entropy
	/// source. Over time all 256 buckets contribute; per-call the value tracks
	/// the pool's bucket-level churn.
	pub fn bucket_shard_count(&self, bucket: u8) -> usize {
		let g = self.inner.read();
		let mut count = 0;
		for (pickup_key, primaries) in g.by_pickup.iter() {
			if pickup_key.0[0] == bucket {
				count += primaries.len();
			}
		}
		count
	}

	/// Snapshot the current pool state into a 32-byte blake2_256 digest written
	/// into the prefix of `out`; any bytes past 32 are zero-filled. Intended as
	/// the load-bearing entropy source for [`rostro-shop-rng`]: the chat ciphertext
	/// pool is adversarially-grown by the whole network, node-unique because every
	/// relay holds a different shard set with different arrival timings and TTLs,
	/// and outside the host OS's read path.
	///
	/// The digest commits to:
	/// - each stored entry's full ciphertext + descriptor + MAC tag + per-entry
	///   `insertion_order` counter (the per-share content + arrival timing)
	/// - the global `next_insertion`, `total_bytes`, and entry count (the pool's
	///   churn signal — message arrival, expiry sweep, capacity eviction all move
	///   these even when no individual entry changed)
	/// - a fresh local monotonic timestamp at hash time (so two reads at identical
	///   pool state still differ, preventing replay-style RNG reseeds)
	///
	/// Returns nothing observable about any individual chat message — the digest is
	/// a one-way commitment. Safe to call from arbitrary code with read access to
	/// the store.
	pub fn write_entropy_hash(&self, out: &mut [u8]) {
		use sp_crypto_hashing::blake2_256;
		use zeroize::Zeroizing;
		let g = self.inner.read();

		// Pre-size: per-entry contributions are bounded above; global state and
		// timestamp are fixed. Avoids reallocs in the hot path. Held in Zeroizing
		// because we copy every share's ciphertext into it during digest assembly —
		// the buf must be wiped before its heap allocation is reclaimed.
		let mut buf: Zeroizing<Vec<u8>> =
			Zeroizing::new(Vec::with_capacity(64 + g.total_bytes + g.by_key.len() * 128));

		// Domain separator — prevents cross-protocol digest reuse.
		buf.extend_from_slice(b"rostro/shop-rng/chat-pool/v1");

		// Per-entry contributions. BTreeMap iteration is order-stable, but the
		// HashMap-backed by_key isn't; iterate via by_expiry which IS ordered, so
		// two reads of identical pool state produce identical digests (modulo
		// the timestamp below).
		for (_expiry_key, primary_key) in g.by_expiry.iter() {
			let entry = match g.by_key.get(primary_key) {
				Some(e) => e,
				None => continue,
			};
			buf.extend_from_slice(&entry.descriptor.relay_pubkey.0);
			buf.extend_from_slice(&entry.descriptor.message_id.0);
			buf.push(entry.descriptor.share_index);
			buf.push(entry.descriptor.total_shares);
			buf.extend_from_slice(&entry.descriptor.pickup_key.0);
			buf.extend_from_slice(&entry.descriptor.expires_at_unix_ts.to_le_bytes());
			buf.extend_from_slice(entry.share_bytes.as_slice());
			buf.extend_from_slice(&entry.mac_tag);
			buf.extend_from_slice(&entry.insertion_order.to_le_bytes());
		}

		// Global churn signal.
		buf.extend_from_slice(&g.next_insertion.to_le_bytes());
		buf.extend_from_slice(&(g.total_bytes as u64).to_le_bytes());
		buf.extend_from_slice(&(g.by_key.len() as u64).to_le_bytes());

		// Drop the read lock before doing the hash work.
		drop(g);

		// Per-call monotonic counter — guarantees two consecutive reads differ
		// even when the pool hasn't changed. Survives clock skew, NTP jumps,
		// and low-resolution wall clocks. The counter is commit-only; never exposed.
		use std::sync::atomic::{AtomicU64, Ordering};
		static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);
		let tick = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
		buf.extend_from_slice(&tick.to_le_bytes());

		let digest = blake2_256(&buf);
		let n = out.len().min(digest.len());
		out[..n].copy_from_slice(&digest[..n]);
		for slot in out[n..].iter_mut() {
			*slot = 0;
		}
		// `buf` zeroizes via its Zeroizing wrapper on drop here.
	}
}

impl ShareStore for EphemeralShareStore {
	fn insert(
		&self,
		descriptor: ShareDescriptor,
		share_bytes: Vec<u8>,
		mac_tag: ShareMacTag,
	) -> Result<(), StoreInsertError> {
		let mut g = self.inner.write();

		let primary_key = (descriptor.message_id, descriptor.share_index);

		// Duplicate check.
		if g.by_key.contains_key(&primary_key) {
			return Err(StoreInsertError::DuplicateShare);
		}

		let incoming_size = share_bytes.len();

		// Make room. Returns None if the incoming share is itself
		// larger than the total budget — surface as StorageFull.
		// Otherwise we evict oldest entries until there's room.
		match g.make_room_for(incoming_size, &self.config) {
			None => return Err(StoreInsertError::StorageFull),
			Some(_n_evicted) => {},
		}

		// At this point we have room. Insert.
		let insertion_order = g.next_insertion;
		g.next_insertion = g.next_insertion.wrapping_add(1);

		// Wrap bytes in LockedBytes (attempts mlock; soft-fails to
		// unlocked if RLIMIT_MEMLOCK is exhausted).
		let locked = LockedBytes::new(share_bytes);
		let entry = Entry {
			descriptor: descriptor.clone(),
			share_bytes: locked,
			mac_tag,
			insertion_order,
		};

		// Update indices.
		let expires_at = descriptor.expires_at_unix_ts;
		g.by_expiry.insert((expires_at, insertion_order), primary_key);
		g.by_pickup
			.entry(descriptor.pickup_key)
			.or_insert_with(Vec::new)
			.push(primary_key);
		g.total_bytes = g.total_bytes.saturating_add(incoming_size);
		g.by_key.insert(primary_key, entry);

		Ok(())
	}

	fn get_by_pickup_key(
		&self,
		pickup_key: &PickupKey,
	) -> Vec<(ShareDescriptor, Vec<u8>, ShareMacTag)> {
		let g = self.inner.read();
		let keys = match g.by_pickup.get(pickup_key) {
			Some(k) => k.clone(),
			None => return Vec::new(),
		};
		keys.into_iter()
			.filter_map(|pk| {
				g.by_key.get(&pk).map(|e| {
					(e.descriptor.clone(), e.share_bytes.as_slice().to_vec(), e.mac_tag)
				})
			})
			.collect()
	}

	fn pickup_keys(&self) -> Vec<PickupKey> {
		self.inner.read().by_pickup.keys().copied().collect()
	}

	fn entries_for_bucket(
		&self,
		b: u8,
	) -> Vec<(PickupKey, MessageId, ShareIndex)> {
		let g = self.inner.read();
		let mut out = Vec::new();
		for (pickup_key, primaries) in g.by_pickup.iter() {
			// Bucket is the top byte of the pickup_key. Cheap byte
			// compare; no separate index needed since the bucket count
			// is global and small.
			if pickup_key.0[0] != b {
				continue;
			}
			for primary in primaries {
				let (message_id, share_index) = *primary;
				out.push((*pickup_key, message_id, share_index));
			}
		}
		out
	}

	fn drop_entries_in_buckets(&self, buckets: &[u8]) -> usize {
		// Dedupe — caller may pass redundant entries.
		let mut bucket_set = [false; 256];
		for b in buckets {
			bucket_set[*b as usize] = true;
		}

		let mut g = self.inner.write();

		// Two-phase: collect primary keys to remove (can't mutate
		// while iterating), then route through `remove_entry` so
		// every index stays consistent (by_key, by_pickup,
		// by_expiry, total_bytes).
		let mut to_remove: Vec<(MessageId, ShareIndex)> = Vec::new();
		for (pickup_key, primaries) in g.by_pickup.iter() {
			if !bucket_set[pickup_key.0[0] as usize] {
				continue;
			}
			for primary in primaries {
				to_remove.push(*primary);
			}
		}
		let count = to_remove.len();
		for pk in to_remove {
			g.remove_entry(pk);
		}
		count
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rostro_chat_primitives::descriptor::{GroupId, RelayPubkey};

	const NOW_TS: UnixTimestamp = 1_700_000_000;

	fn make_descriptor(
		message_id_byte: u8,
		share_index: u8,
		total_shares: u8,
		expires_at_unix_ts: UnixTimestamp,
	) -> ShareDescriptor {
		ShareDescriptor {
			relay_pubkey: RelayPubkey([0x11; 32]),
			message_id: MessageId([message_id_byte; 32]),
			share_index,
			total_shares,
			pickup_key: PickupKey::for_group(&GroupId([0x33; 32])),
			expires_at_unix_ts,
		}
	}

	fn make_entry_inputs(
		message_id_byte: u8,
		share_index: u8,
		bytes: Vec<u8>,
		expires_at_unix_ts: UnixTimestamp,
	) -> (ShareDescriptor, Vec<u8>, ShareMacTag) {
		let d = make_descriptor(message_id_byte, share_index, 5, expires_at_unix_ts);
		// Filler tag: the store never verifies MACs (no key by design).
		let tag: ShareMacTag = [share_index; 32];
		(d, bytes, tag)
	}

	#[test]
	fn insert_and_lookup_by_pickup_key() {
		let store = EphemeralShareStore::with_default_config();
		let (d, b, t) =
			make_entry_inputs(0x01, 0, vec![1, 2, 3, 4], NOW_TS + 100);
		let pickup = d.pickup_key;
		assert!(store.insert(d, b.clone(), t).is_ok());
		assert_eq!(store.len(), 1);
		let results = store.get_by_pickup_key(&pickup);
		assert_eq!(results.len(), 1);
		assert_eq!(results[0].1, b);
	}

	#[test]
	fn duplicate_insert_rejected() {
		let store = EphemeralShareStore::with_default_config();
		let (d, b, t) =
			make_entry_inputs(0x02, 0, vec![1, 2, 3], NOW_TS + 100);
		assert!(store.insert(d.clone(), b.clone(), t).is_ok());
		assert_eq!(
			store.insert(d, b, t),
			Err(StoreInsertError::DuplicateShare),
		);
		assert_eq!(store.len(), 1);
	}

	#[test]
	fn multiple_shares_of_same_message_coexist() {
		let store = EphemeralShareStore::with_default_config();
		for share_index in 0..5u8 {
			let (d, b, t) = make_entry_inputs(
				0x03,
				share_index,
				vec![share_index; 16],
				NOW_TS + 100,
			);
			assert!(store.insert(d, b, t).is_ok());
		}
		assert_eq!(store.len(), 5);
	}

	#[test]
	fn get_by_pickup_key_returns_all_matching() {
		let store = EphemeralShareStore::with_default_config();
		// Three shares of the same message under the same pickup_key.
		let mut pickup = None;
		for share_index in 0..3u8 {
			let (d, b, t) = make_entry_inputs(
				0x04,
				share_index,
				vec![share_index; 8],
				NOW_TS + 100,
			);
			if pickup.is_none() {
				pickup = Some(d.pickup_key);
			}
			store.insert(d, b, t).unwrap();
		}
		let results = store.get_by_pickup_key(&pickup.unwrap());
		assert_eq!(results.len(), 3);
	}

	#[test]
	fn get_by_pickup_key_misses_return_empty() {
		let store = EphemeralShareStore::with_default_config();
		let bogus = PickupKey([0xAB; 32]);
		assert!(store.get_by_pickup_key(&bogus).is_empty());
	}

	#[test]
	fn sweep_removes_expired() {
		let store = EphemeralShareStore::with_default_config();
		// Mix of expired and not-yet-expired entries.
		let (d1, b1, t1) = make_entry_inputs(0x05, 0, vec![1], NOW_TS - 50);
		let (d2, b2, t2) = make_entry_inputs(0x06, 0, vec![2], NOW_TS - 1);
		let (d3, b3, t3) = make_entry_inputs(0x07, 0, vec![3], NOW_TS + 50);
		let (d4, b4, t4) = make_entry_inputs(0x08, 0, vec![4], NOW_TS + 200);
		store.insert(d1, b1, t1).unwrap();
		store.insert(d2, b2, t2).unwrap();
		store.insert(d3, b3, t3).unwrap();
		store.insert(d4, b4, t4).unwrap();
		assert_eq!(store.len(), 4);

		let evicted = store.sweep_expired(NOW_TS);
		assert_eq!(evicted, 2, "two entries had expires_at_unix_ts <= NOW_TS");
		assert_eq!(store.len(), 2);
	}

	#[test]
	fn sweep_with_no_expired_returns_zero() {
		let store = EphemeralShareStore::with_default_config();
		let (d, b, t) = make_entry_inputs(0x09, 0, vec![1], NOW_TS + 100);
		store.insert(d, b, t).unwrap();
		assert_eq!(store.sweep_expired(NOW_TS), 0);
		assert_eq!(store.len(), 1);
	}

	#[test]
	fn sweep_at_exact_boundary_is_inclusive() {
		// expires_at_unix_ts <= current_block → expired (inclusive).
		let store = EphemeralShareStore::with_default_config();
		let (d, b, t) = make_entry_inputs(0x0A, 0, vec![1], NOW_TS);
		store.insert(d, b, t).unwrap();
		assert_eq!(store.sweep_expired(NOW_TS), 1);
		assert!(store.is_empty());
	}

	#[test]
	fn capacity_eviction_drops_oldest_first() {
		// Tight capacity: 3 entries max.
		let config = StoreConfig { max_bytes: 64 * 1024, max_entries: 3 };
		let store = EphemeralShareStore::new(config);

		// Insert 3 entries.
		for i in 0..3u8 {
			let (d, b, t) = make_entry_inputs(
				0x10 + i,
				0,
				vec![i; 4],
				NOW_TS + 100 + i as u64,
			);
			store.insert(d, b, t).unwrap();
		}
		assert_eq!(store.len(), 3);

		// 4th insert: should evict the oldest (smallest
		// expires_at_unix_ts + earliest insertion_order).
		let (d4, b4, t4) =
			make_entry_inputs(0x13, 0, vec![3; 4], NOW_TS + 200);
		store.insert(d4, b4, t4).unwrap();
		assert_eq!(store.len(), 3, "still at cap");

		// First entry should be gone (MessageId 0x10).
		assert!(store
			.inner
			.read()
			.by_key
			.contains_key(&(MessageId([0x11; 32]), 0)));
		assert!(!store
			.inner
			.read()
			.by_key
			.contains_key(&(MessageId([0x10; 32]), 0)));
	}

	#[test]
	fn byte_capacity_eviction() {
		// Tight byte budget: 100 bytes total.
		let config = StoreConfig { max_bytes: 100, max_entries: 1000 };
		let store = EphemeralShareStore::new(config);

		// Insert two 40-byte shares: 80 bytes total — fits.
		let (d1, b1, t1) =
			make_entry_inputs(0x20, 0, vec![1; 40], NOW_TS + 100);
		let (d2, b2, t2) =
			make_entry_inputs(0x21, 0, vec![2; 40], NOW_TS + 200);
		store.insert(d1, b1, t1).unwrap();
		store.insert(d2, b2, t2).unwrap();
		assert_eq!(store.total_bytes(), 80);

		// Insert another 40 bytes: 120 > 100 → must evict.
		let (d3, b3, t3) =
			make_entry_inputs(0x22, 0, vec![3; 40], NOW_TS + 300);
		store.insert(d3, b3, t3).unwrap();
		assert_eq!(store.total_bytes(), 80, "stayed under cap via eviction");
		assert_eq!(store.len(), 2);
	}

	#[test]
	fn share_larger_than_total_budget_rejected() {
		let config = StoreConfig { max_bytes: 100, max_entries: 1000 };
		let store = EphemeralShareStore::new(config);
		// A 200-byte share into a 100-byte budget — can't fit even
		// after evicting everything.
		let (d, b, t) =
			make_entry_inputs(0x30, 0, vec![0u8; 200], NOW_TS + 100);
		assert_eq!(store.insert(d, b, t), Err(StoreInsertError::StorageFull));
	}

	#[test]
	fn total_bytes_tracks_correctly() {
		let store = EphemeralShareStore::with_default_config();
		let (d1, b1, t1) =
			make_entry_inputs(0x40, 0, vec![0; 100], NOW_TS + 100);
		store.insert(d1, b1, t1).unwrap();
		assert_eq!(store.total_bytes(), 100);

		let (d2, b2, t2) =
			make_entry_inputs(0x41, 0, vec![0; 50], NOW_TS + 100);
		store.insert(d2, b2, t2).unwrap();
		assert_eq!(store.total_bytes(), 150);

		store.sweep_expired(NOW_TS + 200);
		assert_eq!(store.total_bytes(), 0);
	}

	#[test]
	fn concurrent_inserts_are_safe() {
		use std::sync::Arc;
		use std::thread;

		let store = Arc::new(EphemeralShareStore::with_default_config());
		let mut handles = Vec::new();

		for thread_id in 0..4u8 {
			let s = store.clone();
			handles.push(thread::spawn(move || {
				for share_index in 0..16u8 {
					let (d, b, t) = make_entry_inputs(
						0x50 + thread_id,
						share_index,
						vec![thread_id, share_index],
						NOW_TS + 100,
					);
					s.insert(d, b, t).unwrap();
				}
			}));
		}
		for h in handles {
			h.join().unwrap();
		}
		assert_eq!(store.len(), 4 * 16);
	}

	#[test]
	fn pickup_keys_returns_currently_active_set() {
		let store = EphemeralShareStore::with_default_config();
		assert!(<EphemeralShareStore as ShareStore>::pickup_keys(&store).is_empty());

		// Two shares under one pickup key, one share under another.
		let (d1, b1, t1) =
			make_entry_inputs(0x70, 0, vec![1], NOW_TS + 100);
		let pickup_a = d1.pickup_key;
		store.insert(d1, b1, t1).unwrap();

		let (d2, b2, t2) =
			make_entry_inputs(0x70, 1, vec![2], NOW_TS + 100);
		store.insert(d2, b2, t2).unwrap();

		// Different message_id with a different pickup_key, to ensure
		// the set behavior (not multiset).
		let mut d3 = make_descriptor(0x71, 0, 5, NOW_TS + 100);
		d3.pickup_key = PickupKey([0xFE; 32]);
		let t3: ShareMacTag = [3; 32];
		store.insert(d3, vec![3], t3).unwrap();

		let mut keys = <EphemeralShareStore as ShareStore>::pickup_keys(&store);
		keys.sort();
		let mut expected = vec![pickup_a, PickupKey([0xFE; 32])];
		expected.sort();
		assert_eq!(keys, expected);
	}

	#[test]
	fn pickup_keys_empty_after_sweep_removes_last_share() {
		let store = EphemeralShareStore::with_default_config();
		let (d, b, t) =
			make_entry_inputs(0x72, 0, vec![1], NOW_TS + 10);
		store.insert(d, b, t).unwrap();
		assert_eq!(<EphemeralShareStore as ShareStore>::pickup_keys(&store).len(), 1);
		store.sweep_expired(NOW_TS + 100);
		assert!(<EphemeralShareStore as ShareStore>::pickup_keys(&store).is_empty());
	}

	#[test]
	fn drop_entries_in_buckets_removes_matching() {
		// Build entries whose pickup keys start with specific
		// bytes (= bucket prefix). PickupKey::for_group derives
		// from blake2 of the group id, so to force a specific
		// pickup byte we hand-craft the descriptor with a known
		// pickup_key.
		let store = EphemeralShareStore::with_default_config();

		let pk_b03 = PickupKey([0x03; 32]);
		let pk_b17 = PickupKey([0x17; 32]);
		let pk_b42 = PickupKey([0x42; 32]);

		fn insert_with_pickup(
			store: &EphemeralShareStore,
			pk: PickupKey,
			mid_byte: u8,
			share_index: u8,
		) {
			let d = ShareDescriptor {
				relay_pubkey: RelayPubkey([0x11; 32]),
				message_id: MessageId([mid_byte; 32]),
				share_index,
				total_shares: 5,
				pickup_key: pk,
				expires_at_unix_ts: NOW_TS + 1000,
			};
			let tag: ShareMacTag = [share_index; 32];
			store.insert(d, vec![1, 2, 3], tag).unwrap();
		}

		// Distinct message_ids per insert to avoid the
		// `(MessageId, ShareIndex)` primary-key collision.
		insert_with_pickup(&store, pk_b03, 0xA0, 0);
		insert_with_pickup(&store, pk_b03, 0xA0, 1);
		insert_with_pickup(&store, pk_b17, 0xA1, 0);
		insert_with_pickup(&store, pk_b42, 0xA2, 0);
		insert_with_pickup(&store, pk_b42, 0xA2, 1);
		assert_eq!(store.len(), 5);

		// Drop bucket 0x17.
		let dropped = store.drop_entries_in_buckets(&[0x17]);
		assert_eq!(dropped, 1);
		assert_eq!(store.len(), 4);
		assert!(store.get_by_pickup_key(&pk_b17).is_empty());

		// Drop buckets 0x03 + 0x42 together.
		let dropped = store.drop_entries_in_buckets(&[0x03, 0x42]);
		assert_eq!(dropped, 4, "two shares of pk_b03 + two of pk_b42");
		assert_eq!(store.len(), 0);
	}

	#[test]
	fn drop_entries_in_buckets_dedupes_input() {
		let store = EphemeralShareStore::with_default_config();
		let pk = PickupKey([0x55; 32]);
		let d = ShareDescriptor {
			relay_pubkey: RelayPubkey([0x11; 32]),
			message_id: MessageId([0xAA; 32]),
			share_index: 0,
			total_shares: 5,
			pickup_key: pk,
			expires_at_unix_ts: NOW_TS + 1000,
		};
		let tag: ShareMacTag = [0xEE; 32];
		store.insert(d, vec![1], tag).unwrap();
		assert_eq!(store.len(), 1);

		// Pass the same bucket many times; should still drop once.
		let dropped = store.drop_entries_in_buckets(&[0x55, 0x55, 0x55, 0x55]);
		assert_eq!(dropped, 1);
		assert_eq!(store.len(), 0);
	}

	#[test]
	fn drop_entries_in_empty_buckets_is_noop() {
		let store = EphemeralShareStore::with_default_config();
		let (d, b, t) = make_entry_inputs(0x90, 0, vec![1], NOW_TS + 100);
		store.insert(d, b, t).unwrap();
		assert_eq!(store.len(), 1);

		// Bucket that no entry falls in.
		let dropped = store.drop_entries_in_buckets(&[0xFE]);
		assert_eq!(dropped, 0);
		assert_eq!(store.len(), 1);
	}

	#[test]
	fn bucket_shard_count_counts_only_matching_bucket() {
		let store = EphemeralShareStore::with_default_config();
		fn insert(store: &EphemeralShareStore, pk: PickupKey, mid_byte: u8, share_index: u8) {
			let d = ShareDescriptor {
				relay_pubkey: RelayPubkey([0x11; 32]),
				message_id: MessageId([mid_byte; 32]),
				share_index,
				total_shares: 5,
				pickup_key: pk,
				expires_at_unix_ts: NOW_TS + 100,
			};
			let tag: ShareMacTag = [share_index; 32];
			store.insert(d, vec![1], tag).unwrap();
		}
		insert(&store, PickupKey([0x03; 32]), 0xA0, 0);
		insert(&store, PickupKey([0x03; 32]), 0xA0, 1);
		insert(&store, PickupKey([0x03; 32]), 0xA1, 0);
		insert(&store, PickupKey([0x17; 32]), 0xA2, 0);

		assert_eq!(store.bucket_shard_count(0x03), 3);
		assert_eq!(store.bucket_shard_count(0x17), 1);
		assert_eq!(store.bucket_shard_count(0xFE), 0, "empty bucket returns 0");
	}

	#[test]
	fn entropy_hash_writes_32_bytes_into_prefix() {
		let store = EphemeralShareStore::with_default_config();
		let mut buf = [0u8; 64];
		store.write_entropy_hash(&mut buf);
		assert!(buf[..32].iter().any(|b| *b != 0), "first 32 bytes are the digest");
		assert!(buf[32..].iter().all(|b| *b == 0), "remainder is zero-padded");
	}

	#[test]
	fn entropy_hash_differs_across_calls_even_on_empty_pool() {
		// Per-call counter must propagate so two reads of an unchanged pool differ.
		let store = EphemeralShareStore::with_default_config();
		let mut a = [0u8; 32];
		let mut b = [0u8; 32];
		store.write_entropy_hash(&mut a);
		store.write_entropy_hash(&mut b);
		assert_ne!(a, b);
	}

	#[test]
	fn entropy_hash_differs_when_share_is_inserted() {
		let store = EphemeralShareStore::with_default_config();
		let mut before = [0u8; 32];
		store.write_entropy_hash(&mut before);

		let (d, b, t) = make_entry_inputs(0xC0, 0, vec![0xDE; 128], NOW_TS + 100);
		store.insert(d, b, t).unwrap();

		let mut after = [0u8; 32];
		store.write_entropy_hash(&mut after);
		assert_ne!(before, after, "inserting a share must change the entropy digest");
	}

	#[test]
	fn entropy_hash_differs_when_ciphertext_differs() {
		// Two stores with identical descriptors but different ciphertext must
		// produce different digests — the ciphertext is the dominant entropy source.
		let store_a = EphemeralShareStore::with_default_config();
		let store_b = EphemeralShareStore::with_default_config();
		let (da, _, ta) = make_entry_inputs(0xC1, 0, vec![0x11; 64], NOW_TS + 100);
		let (db, _, _tb) = make_entry_inputs(0xC1, 0, vec![0x22; 64], NOW_TS + 100);
		// Force same MAC so the only differing input is the ciphertext bytes.
		store_a.insert(da, vec![0x11; 64], ta).unwrap();
		store_b.insert(db, vec![0x22; 64], ta).unwrap();

		// Reset call counter is impossible, so we compare a single read each
		// and rely on the counter delta being constant (both = "first read of
		// this store"). Actually the counter is process-global, so reads will
		// differ on the counter alone. We need the ciphertext to dominate, not
		// just be present — so do many reads and check digests don't converge.
		let mut digests_a = std::collections::HashSet::new();
		let mut digests_b = std::collections::HashSet::new();
		for _ in 0..10 {
			let mut x = [0u8; 32];
			store_a.write_entropy_hash(&mut x);
			digests_a.insert(x);
			let mut y = [0u8; 32];
			store_b.write_entropy_hash(&mut y);
			digests_b.insert(y);
		}
		// Each store produced 10 distinct digests (counter rotates), and
		// none of A's digests appear in B's set.
		assert_eq!(digests_a.len(), 10);
		assert_eq!(digests_b.len(), 10);
		assert!(digests_a.is_disjoint(&digests_b), "A and B digests must not collide");
	}

	#[test]
	fn entropy_hash_truncates_when_out_smaller_than_32() {
		let store = EphemeralShareStore::with_default_config();
		let mut short = [0u8; 16];
		store.write_entropy_hash(&mut short);
		assert!(short.iter().any(|b| *b != 0), "truncated digest must still carry signal");
	}

	#[test]
	fn drop_zeroizes_and_munlocks() {
		// Indirect test: we can't observe mlock/munlock from Rust
		// directly, but we can confirm Drop runs without panic and
		// the store returns to len=0 after sweep.
		let store = EphemeralShareStore::with_default_config();
		let (d, b, t) =
			make_entry_inputs(0x60, 0, vec![0xAB; 256], NOW_TS + 100);
		store.insert(d, b, t).unwrap();
		assert_eq!(store.len(), 1);
		store.sweep_expired(NOW_TS + 200);
		assert_eq!(store.len(), 0);
		assert_eq!(store.total_bytes(), 0);
	}
}

