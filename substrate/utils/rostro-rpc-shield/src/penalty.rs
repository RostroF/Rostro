// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors
//
// Penalty-tracking primitive ported from the snorkel DNS resolver
// (~/Polkadot/snorkel/crates/snorkel-dns/src/penalty.rs).

//! Escalating-block penalty tracker keyed by /24 subnet.
//!
//! Strikes accumulate on rate-limit exhaustion or other misbehavior.
//! Block durations escalate: 1s → 10s → 60s. After 5 minutes of no
//! observation an entry is pruned. The HashMap is capped at
//! `MAX_ENTRIES`; once full, new strikes are silently dropped (the cap
//! is the failure mode — we'd rather lose a strike than exhaust memory).
//!
//! The `is_penalized` check is the cheapest gate in the stack — a
//! single HashMap lookup, no allocation. It runs first so a known-bad
//! source pays the minimum cost to be turned away.

use std::collections::HashMap;

const MAX_ENTRIES: usize = 4096;
const PRUNE_INTERVAL_MICROS: u64 = 60_000_000;
const TTL_MICROS: u64 = 5 * 60 * 1_000_000;

const STRIKE_1_BLOCK_MICROS: u64 = 1_000_000;
const STRIKE_2_BLOCK_MICROS: u64 = 10_000_000;
const STRIKE_3PLUS_BLOCK_MICROS: u64 = 60_000_000;

#[derive(Clone, Copy)]
struct Penalty {
	strikes: u8,
	blocked_until_micros: u64,
}

/// Tracks per-/24 penalty state.
pub struct PenaltyTracker {
	entries: HashMap<[u8; 4], Penalty>,
	last_prune_micros: u64,
}

impl PenaltyTracker {
	/// Construct a fresh tracker.
	pub fn new() -> Self {
		Self {
			entries: HashMap::with_capacity(MAX_ENTRIES),
			last_prune_micros: 0,
		}
	}

	/// Cheap check: is this subnet currently in a block window?
	pub fn is_penalized(&self, subnet: &[u8; 4], now_micros: u64) -> bool {
		match self.entries.get(subnet) {
			Some(p) => now_micros < p.blocked_until_micros,
			None => false,
		}
	}

	/// Record a strike against `subnet`. Escalates the block window
	/// according to the strike count.
	pub fn record_strike(&mut self, subnet: [u8; 4], now_micros: u64) {
		self.maybe_prune(now_micros);

		let existing = self.entries.get(&subnet).copied();
		let new_penalty = match existing {
			Some(prev) => {
				let strikes = prev.strikes.saturating_add(1);
				let block_micros = match strikes {
					1 => STRIKE_1_BLOCK_MICROS,
					2 => STRIKE_2_BLOCK_MICROS,
					_ => STRIKE_3PLUS_BLOCK_MICROS,
				};
				Penalty {
					strikes,
					blocked_until_micros: now_micros.saturating_add(block_micros),
				}
			}
			None => {
				if self.entries.len() >= MAX_ENTRIES {
					return;
				}
				Penalty {
					strikes: 1,
					blocked_until_micros: now_micros.saturating_add(STRIKE_1_BLOCK_MICROS),
				}
			}
		};
		self.entries.insert(subnet, new_penalty);
	}

	fn maybe_prune(&mut self, now_micros: u64) {
		if now_micros.saturating_sub(self.last_prune_micros) < PRUNE_INTERVAL_MICROS {
			return;
		}
		self.last_prune_micros = now_micros;
		let cutoff = now_micros.saturating_sub(TTL_MICROS);
		self.entries.retain(|_, p| p.blocked_until_micros > cutoff);
	}
}

impl Default for PenaltyTracker {
	fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fresh_subnet_not_penalized() {
		let p = PenaltyTracker::new();
		assert!(!p.is_penalized(&[10, 0, 0, 4], 0));
	}

	#[test]
	fn first_strike_blocks_one_second() {
		let mut p = PenaltyTracker::new();
		p.record_strike([10, 0, 0, 4], 0);
		assert!(p.is_penalized(&[10, 0, 0, 4], 999_999));
		assert!(!p.is_penalized(&[10, 0, 0, 4], 1_000_001));
	}

	#[test]
	fn third_strike_blocks_one_minute() {
		let mut p = PenaltyTracker::new();
		p.record_strike([10, 0, 0, 4], 0);
		p.record_strike([10, 0, 0, 4], 1);
		p.record_strike([10, 0, 0, 4], 2);
		// Strike 3 → 60s block.
		assert!(p.is_penalized(&[10, 0, 0, 4], 30_000_000));
		assert!(!p.is_penalized(&[10, 0, 0, 4], 60_000_010));
	}

	#[test]
	fn cap_silently_drops_new_strikes() {
		let mut p = PenaltyTracker::new();
		for i in 0..MAX_ENTRIES {
			let octet1 = (i >> 8) as u8;
			let octet2 = (i & 0xff) as u8;
			p.record_strike([10, octet1, octet2, 4], 0);
		}
		// Cap full — strike on a new subnet is dropped, not penalized.
		p.record_strike([192, 168, 100, 4], 0);
		assert!(!p.is_penalized(&[192, 168, 100, 4], 0));
	}
}
