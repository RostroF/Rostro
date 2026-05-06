// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! In-process cache for epoch metadata. Wraps an inner
//! [`EpochProvider`] (typically Client+RuntimeApi-backed) with a
//! parent-hash-keyed cache so the import-queue verifier doesn't pay
//! the runtime-API roundtrip cost on every block.
//!
//! ## Scope
//!
//! Pure in-memory cache. Survives within a single node-service
//! lifetime; not persisted across restarts. Cross-restart persistence
//! would require an `rc-client-api::AuxStore` integration (different
//! dependency, different trade-offs); for the verifier hot path the
//! in-memory cache delivers most of the benefit at zero
//! infrastructure cost.
//!
//! ## Cache key choice
//!
//! Keyed by `parent_hash` rather than by epoch index because callers
//! ask "what's the epoch at this parent?" without first knowing the
//! epoch index. Multiple parent hashes within the same epoch share the
//! same `Epoch` value — there's redundancy in the cache, but the
//! `Epoch` struct is cheap to clone (a few hundred bytes max), so the
//! redundancy is tolerable in exchange for a one-lookup hit path.
//!
//! ## Eviction
//!
//! On-demand only. [`CachedEpochProvider::clear`] flushes everything;
//! [`CachedEpochProvider::evict_below_epoch`] drops entries older than
//! a given epoch index. Workers should evict at epoch boundaries to
//! bound memory; the cache itself doesn't auto-evict because it can't
//! tell when an entry's "parent_hash" was retired by chain pruning.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Mutex;

use sp_consensus_sassafras::Epoch;
use sp_runtime::traits::Block as BlockT;

use crate::providers::{EpochProvider, ProviderError};

/// Cached wrapper around an inner [`EpochProvider`].
///
/// Forwards cache-miss lookups to `inner`; caches the result keyed by
/// parent hash. `next_epoch_at` calls don't cache — those are only
/// needed at epoch-boundary blocks (rare relative to body blocks) and
/// caching them would require invalidation logic when the next-epoch
/// authority list rotates.
pub struct CachedEpochProvider<Block: BlockT, Inner> {
	inner: Inner,
	cache: Mutex<HashMap<Block::Hash, Epoch>>,
	_phantom: PhantomData<Block>,
}

impl<Block: BlockT, Inner> CachedEpochProvider<Block, Inner> {
	/// Wrap an inner provider.
	pub fn new(inner: Inner) -> Self {
		Self { inner, cache: Mutex::new(HashMap::new()), _phantom: PhantomData }
	}

	/// Drop all cached entries.
	pub fn clear(&self) {
		self.cache.lock().expect("cache mutex not poisoned in normal use").clear();
	}

	/// Drop cache entries whose epoch index is strictly less than the
	/// given threshold. Call this at epoch boundaries to bound memory:
	/// after epoch N+1 starts, no honest verifier needs to look up a
	/// block in epoch N-1 or earlier (assuming standard finalization
	/// + pruning).
	pub fn evict_below_epoch(&self, min_epoch_index: u64) {
		self.cache
			.lock()
			.expect("cache mutex not poisoned in normal use")
			.retain(|_, epoch| epoch.index >= min_epoch_index);
	}

	/// Number of cached entries. Telemetry helper.
	pub fn cache_size(&self) -> usize {
		self.cache.lock().expect("cache mutex not poisoned in normal use").len()
	}
}

impl<Block, Inner> EpochProvider<Block> for CachedEpochProvider<Block, Inner>
where
	Block: BlockT,
	Inner: EpochProvider<Block>,
{
	fn epoch_at(&self, parent_hash: Block::Hash) -> Result<Epoch, ProviderError> {
		// Fast path: cache hit. We hold the lock briefly, clone the
		// Epoch out, drop the lock before returning.
		if let Some(cached) =
			self.cache.lock().expect("cache mutex not poisoned in normal use").get(&parent_hash)
		{
			return Ok(cached.clone());
		}

		// Slow path: forward to inner, populate cache, return.
		let fresh = self.inner.epoch_at(parent_hash)?;
		self.cache
			.lock()
			.expect("cache mutex not poisoned in normal use")
			.insert(parent_hash, fresh.clone());
		Ok(fresh)
	}

	fn next_epoch_at(&self, parent_hash: Block::Hash) -> Result<Epoch, ProviderError> {
		// Pass through — see the type-level doc for why next-epoch
		// lookups aren't cached.
		self.inner.next_epoch_at(parent_hash)
	}
}
