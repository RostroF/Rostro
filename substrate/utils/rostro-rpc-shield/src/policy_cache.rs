// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! In-memory cache of RPC method policies sourced from on-chain state.
//!
//! The hard-coded policy table in [`crate::statecall::StateCallPolicy`] is
//! the bootstrap fallback — what the shield uses before it has heard from
//! the chain, and what it falls back to if the chain becomes unreachable.
//! For routine operation, the source of truth is the on-chain
//! `pallet-rostro-rpc-method-policy` registry; the shield mirrors that
//! registry into this cache and queries the cache first.
//!
//! ## Why mirror in process
//!
//! Querying the runtime API on every incoming RPC request would add a
//! latency hop to every dispatch (and a lock + storage read), which
//! defeats the per-request shield's "cheapest check first" design. Caching
//! avoids that. The cost is a refresh window during which the cache is
//! stale relative to chain state — bounded by the refresh interval (30 s
//! by default in the substrate-side glue).
//!
//! ## Threading
//!
//! Wrapped in `Arc<RwLock<...>>` so:
//!   - `Shield::check_state_call` (read path, hot) takes a read lock,
//!     bounded by the HashMap lookup cost.
//!   - The substrate-side refresh task (write path, infrequent) takes a
//!     write lock once per refresh and replaces the contents wholesale.
//!
//! Replaces, not merges. A method removed from the on-chain registry must
//! disappear from the cache too, otherwise revocations don't propagate.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::statecall::MethodPolicy;

/// Thread-safe mirror of the on-chain RPC method-policy registry.
#[derive(Clone, Default)]
pub struct PolicyCache {
	inner: Arc<RwLock<Inner>>,
}

#[derive(Default)]
struct Inner {
	/// (method-name → policy) pairs. Method names are byte vecs because
	/// the substrate-side runtime API returns `Vec<(Vec<u8>, MethodPolicy)>`
	/// and we don't want to assume UTF-8 validity at the cache boundary —
	/// validation happens at the shield's lookup site.
	map: HashMap<Vec<u8>, MethodPolicy>,
	/// Whether at least one bootstrap from chain has succeeded. Until
	/// this flips true the shield falls back to the hard-coded
	/// `StateCallPolicy` allowlist.
	bootstrapped: bool,
}

impl PolicyCache {
	/// Construct an empty, un-bootstrapped cache. Until `set_policies`
	/// is called at least once, [`Self::lookup`] returns `None` and
	/// callers should fall back to the hard-coded policy table.
	pub fn new() -> Self {
		Self::default()
	}

	/// Replace the cache contents wholesale. Marks the cache as
	/// bootstrapped. Called by the substrate-side refresh task with the
	/// result of `RpcMethodPolicyApi::all_policies(at)`.
	pub fn set_policies(&self, policies: Vec<(Vec<u8>, MethodPolicy)>) {
		let mut guard = match self.inner.write() {
			Ok(g) => g,
			// A poisoned lock means a panic happened mid-write. Recover
			// the inner state and continue — we'd rather replace possibly-
			// inconsistent state with a fresh on-chain snapshot than halt.
			Err(p) => p.into_inner(),
		};
		guard.map = policies.into_iter().collect();
		guard.bootstrapped = true;
	}

	/// Look up a method's policy. Returns `None` if the cache hasn't
	/// been bootstrapped yet OR the method isn't registered. Callers
	/// should distinguish via [`Self::is_bootstrapped`] when they need
	/// to choose between "fall back to hard-coded table" (not
	/// bootstrapped) and "definitely deny" (bootstrapped + not found).
	pub fn lookup(&self, method: &[u8]) -> Option<MethodPolicy> {
		let guard = match self.inner.read() {
			Ok(g) => g,
			Err(p) => p.into_inner(),
		};
		if !guard.bootstrapped {
			return None;
		}
		guard.map.get(method).copied()
	}

	/// Whether the cache has been populated from chain at least once.
	pub fn is_bootstrapped(&self) -> bool {
		match self.inner.read() {
			Ok(g) => g.bootstrapped,
			Err(p) => p.into_inner().bootstrapped,
		}
	}

	/// Cache size for metrics / observability.
	pub fn len(&self) -> usize {
		match self.inner.read() {
			Ok(g) => g.map.len(),
			Err(p) => p.into_inner().map.len(),
		}
	}

	/// True iff the cache has zero entries.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fresh_cache_is_unbootstrapped_and_returns_none() {
		let c = PolicyCache::new();
		assert!(!c.is_bootstrapped());
		assert!(c.is_empty());
		assert_eq!(c.lookup(b"Core_version"), None);
	}

	#[test]
	fn set_policies_marks_bootstrapped_even_if_empty() {
		// An empty registry result is a legitimate state (nothing
		// registered yet). We still mark it bootstrapped — the shield's
		// fallback-to-hard-coded path is for "we haven't heard from the
		// chain at all," not "the chain says nothing's registered."
		let c = PolicyCache::new();
		c.set_policies(Vec::new());
		assert!(c.is_bootstrapped());
		assert!(c.is_empty());
		assert_eq!(c.lookup(b"Core_version"), None);
	}

	#[test]
	fn lookup_after_set_returns_policy() {
		let c = PolicyCache::new();
		c.set_policies(vec![
			(b"Core_version".to_vec(), MethodPolicy::PublicSafe),
			(b"SassafrasApi_ring_context".to_vec(), MethodPolicy::Deny),
		]);
		assert_eq!(c.lookup(b"Core_version"), Some(MethodPolicy::PublicSafe));
		assert_eq!(
			c.lookup(b"SassafrasApi_ring_context"),
			Some(MethodPolicy::Deny),
		);
		assert_eq!(c.lookup(b"unknown_method"), None);
	}

	#[test]
	fn set_policies_replaces_wholesale() {
		// Removed entries must disappear; replacement is total, not merge.
		// Critical for revocation: an SRT-removed Deny-tier method must
		// not linger in cache as Deny if the runtime upgrade actually
		// retired it (or vice versa, a method's policy was relaxed).
		let c = PolicyCache::new();
		c.set_policies(vec![
			(b"a".to_vec(), MethodPolicy::PublicSafe),
			(b"b".to_vec(), MethodPolicy::Deny),
		]);
		c.set_policies(vec![(b"a".to_vec(), MethodPolicy::PublicGated)]);
		assert_eq!(c.lookup(b"a"), Some(MethodPolicy::PublicGated));
		assert_eq!(c.lookup(b"b"), None, "removed entry must not persist");
	}

	#[test]
	fn clones_share_state() {
		// PolicyCache is Clone via Arc — clones must observe each other's
		// updates. The substrate-side refresh task and the shield read
		// path will hold separate clones of the same Arc.
		let c1 = PolicyCache::new();
		let c2 = c1.clone();
		c1.set_policies(vec![(b"x".to_vec(), MethodPolicy::Deny)]);
		assert_eq!(c2.lookup(b"x"), Some(MethodPolicy::Deny));
		assert!(c2.is_bootstrapped());
	}
}
