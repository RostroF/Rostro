// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors
//
// Inflight-cap primitive ported from the snorkel DNS resolver
// (~/Polkadot/snorkel/crates/snorkel-dns/src/worker.rs).

//! Atomic concurrency cap.
//!
//! Hard ceiling on the number of in-flight requests. Cheap to check and
//! cheap to release; no per-source bookkeeping. Used as the last line
//! of defense before a request reaches the runtime.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic in-flight counter with a fixed maximum.
pub struct InFlightCap {
	current: AtomicU64,
	max: u64,
}

impl InFlightCap {
	/// Construct with an explicit ceiling.
	pub fn new(max: u64) -> Self {
		Self { current: AtomicU64::new(0), max }
	}

	/// Try to acquire a slot. Returns `true` on success; on failure the
	/// counter is rolled back to its prior value.
	pub fn try_acquire(&self) -> bool {
		let prev = self.current.fetch_add(1, Ordering::Relaxed);
		if prev >= self.max {
			self.current.fetch_sub(1, Ordering::Relaxed);
			return false;
		}
		true
	}

	/// Release a slot. Must be paired with each successful `try_acquire`.
	///
	/// Saturates at 0 — a release without a matching acquire is a
	/// caller bug, but we refuse to underflow the counter (which would
	/// wrap to `u64::MAX` and starve all subsequent callers when the
	/// counter eventually wraps past `max`). Saturating fail-safe is
	/// preferable to a node-wide DoS triggered by one buggy release path.
	pub fn release(&self) {
		// fetch_update with saturating semantics. Spins on contention
		// but contention here is at most a few CPU instructions worth.
		let _ = self.current.fetch_update(
			Ordering::Relaxed,
			Ordering::Relaxed,
			|n| if n == 0 { None } else { Some(n - 1) },
		);
	}

	/// Current in-flight count (Relaxed read; for metrics only).
	pub fn current(&self) -> u64 {
		self.current.load(Ordering::Relaxed)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn acquires_until_cap_then_refuses() {
		let c = InFlightCap::new(3);
		assert!(c.try_acquire());
		assert!(c.try_acquire());
		assert!(c.try_acquire());
		assert!(!c.try_acquire());
		assert_eq!(c.current(), 3);
	}

	#[test]
	fn release_restores_capacity() {
		let c = InFlightCap::new(2);
		assert!(c.try_acquire());
		assert!(c.try_acquire());
		assert!(!c.try_acquire());
		c.release();
		assert!(c.try_acquire());
	}

	#[test]
	fn failed_acquire_does_not_leak_slot() {
		let c = InFlightCap::new(1);
		assert!(c.try_acquire());
		assert!(!c.try_acquire());
		c.release();
		assert_eq!(c.current(), 0);
	}

	#[test]
	fn release_without_acquire_saturates_at_zero() {
		// If a buggy caller releases without acquiring, the counter
		// must NOT underflow to u64::MAX (which would wrap past `max`
		// and starve subsequent acquires). It must saturate at 0.
		let c = InFlightCap::new(10);
		c.release();
		c.release();
		c.release();
		assert_eq!(c.current(), 0, "counter must saturate at 0, not underflow");
		// Subsequent acquires must still work.
		assert!(c.try_acquire());
		assert_eq!(c.current(), 1);
	}
}
