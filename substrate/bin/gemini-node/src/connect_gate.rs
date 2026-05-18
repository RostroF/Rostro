// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase 7 v2 Piece 3 — drift ledger + rate-limited gate state for
//! the canonical-files connect-time attest exchange.
//!
//! Per [`canonical_files_gate_grief_defense`] memory:
//!
//! * **Rate limit:** a peer may send at most 2 attest requests within
//!   any rolling 5-minute window; exceeding triggers a 300-second
//!   cooldown during which further requests are silently dropped.
//!   PeerId-keyed (not IP-keyed; Sybil-grief defense is a separate
//!   workstream).
//!
//! * **Drift ledger:** per-peer attest state tracked across the
//!   lifetime of the connection. `Pending` → `Passed` / `Failed` /
//!   `Cooldown`. Used by the asker side to route disconnects and by
//!   the server side to gate over-limit traffic.
//!
//! * **Strict pre-attest packet drop (deferred):** the v0 stub does
//!   NOT yet drop notification-protocol messages from peers in
//!   `Pending` state. See [`gossip_channels_split`] — the long-term
//!   architecture splits gossip into a validator-only privileged
//!   channel (which gates non-validators by construction) and a
//!   general channel (which will carry its own gate at the channel
//!   boundary). The strict packet-drop lands in that workstream;
//!   for v0 we rely on rate-limit + disconnect-on-RootMismatch.
//!
//! ## Why these types are peer-id generic
//!
//! The rate-limit and ledger logic is pure — no libp2p, no sc-network,
//! just `Hash + Eq + Clone` on the peer identifier. Unit tests use
//! `&'static str` or `u64` peer IDs and exercise every branch in
//! microseconds. The libp2p binding (Piece 3c/3d) supplies concrete
//! `sc_network::PeerId` at the call site.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Default: 2 incoming attest requests per peer per 5-minute window,
/// 300-second cooldown after exceeding the limit. Tunable but
/// locked-in-design for v0 — see `canonical_files_gate_grief_defense`
/// memory for the reasoning.
pub const DEFAULT_MAX_PER_WINDOW: usize = 2;
pub const DEFAULT_WINDOW_SECS: u64 = 300;
pub const DEFAULT_COOLDOWN_SECS: u64 = 300;

/// Knobs for the per-peer rate limiter on incoming attest requests.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
	pub max_per_window: usize,
	pub window: Duration,
	pub cooldown: Duration,
}

impl Default for RateLimitConfig {
	fn default() -> Self {
		Self {
			max_per_window: DEFAULT_MAX_PER_WINDOW,
			window: Duration::from_secs(DEFAULT_WINDOW_SECS),
			cooldown: Duration::from_secs(DEFAULT_COOLDOWN_SECS),
		}
	}
}

/// Outcome of [`RateLimiter::check_and_record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateOutcome {
	/// Request is allowed and has been recorded.
	Allowed,
	/// Request is rejected; peer is in cooldown until `until`.
	/// All requests during cooldown are silently dropped and DO NOT
	/// extend the cooldown — the cooldown timer is anchored to when
	/// the limit was first exceeded.
	Cooldown { until: Instant },
}

/// Sliding-window rate limiter, PeerId-keyed.
///
/// Per peer:
///   * keeps a small `VecDeque<Instant>` of recent request timestamps
///     (max length = `max_per_window`).
///   * keeps an optional `cooldown_until: Instant` set when the
///     limit was last exceeded.
///
/// Memory bound: O(active_peers × max_per_window). With v0 defaults
/// (2 entries per peer) this is negligible.
pub struct RateLimiter<P>
where
	P: Hash + Eq + Clone,
{
	requests: HashMap<P, RateState>,
	config: RateLimitConfig,
}

#[derive(Debug)]
struct RateState {
	recent: VecDeque<Instant>,
	cooldown_until: Option<Instant>,
}

impl<P> RateLimiter<P>
where
	P: Hash + Eq + Clone,
{
	pub fn new(config: RateLimitConfig) -> Self {
		Self { requests: HashMap::new(), config }
	}

	pub fn with_defaults() -> Self {
		Self::new(RateLimitConfig::default())
	}

	/// Number of peers currently tracked. Diagnostic only.
	pub fn tracked_peers(&self) -> usize {
		self.requests.len()
	}

	/// Test whether `peer` may issue another attest request right now.
	/// If allowed, records the request timestamp. If rejected, the
	/// caller should drop the request and emit no protocol-level
	/// response (per the grief-defense design).
	///
	/// The `now` argument lets unit tests inject a clock without
	/// pulling in a system-time mock. Production calls pass
	/// `Instant::now()`.
	pub fn check_and_record(&mut self, peer: &P, now: Instant) -> RateOutcome {
		let cfg = self.config;
		let state = self.requests.entry(peer.clone()).or_insert_with(RateState::new);

		// 1. Cooldown takes precedence — if active, reject without
		//    recording. Cooldown does NOT extend on attempts inside
		//    the window (anchored to the first violation).
		if let Some(until) = state.cooldown_until {
			if now < until {
				return RateOutcome::Cooldown { until };
			}
			// Cooldown elapsed: clear the marker AND drop stale
			// request timestamps so the peer gets a fresh budget.
			state.cooldown_until = None;
			state.recent.clear();
		}

		// 2. Drop timestamps that fell outside the rolling window.
		let window_start = now.checked_sub(cfg.window).unwrap_or(now);
		while state.recent.front().map(|t| *t < window_start).unwrap_or(false) {
			state.recent.pop_front();
		}

		// 3. If the post-trim count is already at the cap, this
		//    request exceeds the limit → start cooldown and reject.
		if state.recent.len() >= cfg.max_per_window {
			let until = now + cfg.cooldown;
			state.cooldown_until = Some(until);
			return RateOutcome::Cooldown { until };
		}

		// 4. Otherwise record and allow.
		state.recent.push_back(now);
		RateOutcome::Allowed
	}

	/// Forget rate-limit state for `peer`. Called when the peer
	/// disconnects so memory doesn't grow unbounded across churn.
	pub fn forget(&mut self, peer: &P) {
		self.requests.remove(peer);
	}
}

impl RateState {
	fn new() -> Self {
		Self { recent: VecDeque::with_capacity(DEFAULT_MAX_PER_WINDOW), cooldown_until: None }
	}
}

/// Per-peer attest state across the connection lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerGateState {
	/// Just connected. Attest request is in flight. Strict packet-
	/// drop SHOULD apply here (deferred to channel-split workstream).
	Pending,
	/// Attest passed. Normal traffic allowed.
	Passed,
	/// Attest mismatched. Disconnect imminent. Held briefly so the
	/// disconnect path can find the peer's state before the entry is
	/// GC'd.
	Failed,
	/// Peer is in rate-limit cooldown. Equivalent to `Failed` for
	/// gating purposes but distinct for operator-visible logging.
	Cooldown,
}

/// Drift ledger: PeerId → gate state. Looked up by both server
/// (rate-limit decisions) and asker (route disconnects on
/// RootMismatch).
///
/// Wrapping with `Arc<parking_lot::RwLock<...>>` is the call-site
/// pattern; this struct stays Send+Sync-friendly by not holding
/// locks internally.
pub struct DriftLedger<P>
where
	P: Hash + Eq + Clone,
{
	state: HashMap<P, PeerGateState>,
}

impl<P> Default for DriftLedger<P>
where
	P: Hash + Eq + Clone,
{
	fn default() -> Self {
		Self::new()
	}
}

impl<P> DriftLedger<P>
where
	P: Hash + Eq + Clone,
{
	pub fn new() -> Self {
		Self { state: HashMap::new() }
	}

	pub fn get(&self, peer: &P) -> Option<PeerGateState> {
		self.state.get(peer).copied()
	}

	pub fn set(&mut self, peer: P, new_state: PeerGateState) {
		self.state.insert(peer, new_state);
	}

	pub fn forget(&mut self, peer: &P) {
		self.state.remove(peer);
	}

	pub fn tracked_peers(&self) -> usize {
		self.state.len()
	}

	/// Has this peer passed attest and is therefore eligible for
	/// non-attest traffic? Convenience for the (deferred) strict
	/// packet-drop filter.
	pub fn is_passed(&self, peer: &P) -> bool {
		matches!(self.state.get(peer), Some(PeerGateState::Passed))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cfg() -> RateLimitConfig {
		RateLimitConfig {
			max_per_window: 2,
			window: Duration::from_secs(300),
			cooldown: Duration::from_secs(300),
		}
	}

	#[test]
	fn rate_limit_allows_first_two_requests() {
		let mut rl = RateLimiter::<&'static str>::new(cfg());
		let t0 = Instant::now();
		assert_eq!(rl.check_and_record(&"alice", t0), RateOutcome::Allowed);
		assert_eq!(
			rl.check_and_record(&"alice", t0 + Duration::from_secs(10)),
			RateOutcome::Allowed,
		);
	}

	#[test]
	fn rate_limit_blocks_third_request_in_window() {
		let mut rl = RateLimiter::<&'static str>::new(cfg());
		let t0 = Instant::now();
		rl.check_and_record(&"alice", t0);
		rl.check_and_record(&"alice", t0 + Duration::from_secs(60));
		match rl.check_and_record(&"alice", t0 + Duration::from_secs(120)) {
			RateOutcome::Cooldown { until } => {
				// Cooldown anchored to the violation point, not the
				// original first request.
				let expected = t0 + Duration::from_secs(120) + Duration::from_secs(300);
				assert_eq!(until, expected);
			},
			other => panic!("expected Cooldown, got {:?}", other),
		}
	}

	#[test]
	fn rate_limit_does_not_extend_cooldown_on_re_attempt() {
		let mut rl = RateLimiter::<&'static str>::new(cfg());
		let t0 = Instant::now();
		rl.check_and_record(&"alice", t0);
		rl.check_and_record(&"alice", t0 + Duration::from_secs(60));
		let third = t0 + Duration::from_secs(120);
		let cooldown_until = match rl.check_and_record(&"alice", third) {
			RateOutcome::Cooldown { until } => until,
			other => panic!("expected Cooldown, got {:?}", other),
		};
		// Attempt again 60s later — still rejected, same cooldown
		// end-time (no extension).
		let fourth = third + Duration::from_secs(60);
		match rl.check_and_record(&"alice", fourth) {
			RateOutcome::Cooldown { until } => assert_eq!(until, cooldown_until),
			other => panic!("expected Cooldown, got {:?}", other),
		}
	}

	#[test]
	fn rate_limit_resets_after_cooldown_elapses() {
		let mut rl = RateLimiter::<&'static str>::new(cfg());
		let t0 = Instant::now();
		rl.check_and_record(&"alice", t0);
		rl.check_and_record(&"alice", t0 + Duration::from_secs(60));
		rl.check_and_record(&"alice", t0 + Duration::from_secs(120)); // triggers cooldown
		// After 300s cooldown expires, alice gets a fresh budget.
		let post_cooldown = t0 + Duration::from_secs(120 + 301);
		assert_eq!(rl.check_and_record(&"alice", post_cooldown), RateOutcome::Allowed);
		assert_eq!(
			rl.check_and_record(&"alice", post_cooldown + Duration::from_secs(1)),
			RateOutcome::Allowed,
		);
	}

	#[test]
	fn rate_limit_sliding_window_allows_after_first_request_ages_out() {
		let mut rl = RateLimiter::<&'static str>::new(cfg());
		let t0 = Instant::now();
		rl.check_and_record(&"alice", t0);
		rl.check_and_record(&"alice", t0 + Duration::from_secs(60));
		// Wait long enough for the first request to fall outside the
		// 300s window. The third request slots into the freed slot.
		let later = t0 + Duration::from_secs(301);
		assert_eq!(rl.check_and_record(&"alice", later), RateOutcome::Allowed);
	}

	#[test]
	fn rate_limit_is_per_peer() {
		let mut rl = RateLimiter::<&'static str>::new(cfg());
		let t0 = Instant::now();
		// alice maxes out
		rl.check_and_record(&"alice", t0);
		rl.check_and_record(&"alice", t0 + Duration::from_secs(60));
		assert!(matches!(
			rl.check_and_record(&"alice", t0 + Duration::from_secs(120)),
			RateOutcome::Cooldown { .. },
		));
		// bob is unaffected
		assert_eq!(
			rl.check_and_record(&"bob", t0 + Duration::from_secs(120)),
			RateOutcome::Allowed,
		);
	}

	#[test]
	fn rate_limit_forget_drops_peer() {
		let mut rl = RateLimiter::<&'static str>::new(cfg());
		let t0 = Instant::now();
		rl.check_and_record(&"alice", t0);
		assert_eq!(rl.tracked_peers(), 1);
		rl.forget(&"alice");
		assert_eq!(rl.tracked_peers(), 0);
		// alice gets a fresh budget after forget.
		assert_eq!(rl.check_and_record(&"alice", t0), RateOutcome::Allowed);
	}

	#[test]
	fn ledger_default_state_is_unknown() {
		let l: DriftLedger<&'static str> = DriftLedger::new();
		assert_eq!(l.get(&"alice"), None);
		assert!(!l.is_passed(&"alice"));
	}

	#[test]
	fn ledger_records_and_reads_state_transitions() {
		let mut l: DriftLedger<&'static str> = DriftLedger::new();
		l.set("alice", PeerGateState::Pending);
		assert_eq!(l.get(&"alice"), Some(PeerGateState::Pending));
		assert!(!l.is_passed(&"alice"));
		l.set("alice", PeerGateState::Passed);
		assert!(l.is_passed(&"alice"));
		l.set("alice", PeerGateState::Failed);
		assert!(!l.is_passed(&"alice"));
	}

	#[test]
	fn ledger_forget_drops_peer() {
		let mut l: DriftLedger<&'static str> = DriftLedger::new();
		l.set("alice", PeerGateState::Passed);
		assert_eq!(l.tracked_peers(), 1);
		l.forget(&"alice");
		assert_eq!(l.tracked_peers(), 0);
		assert_eq!(l.get(&"alice"), None);
	}

	#[test]
	fn default_config_matches_locked_design_values() {
		// Pin the v0 numbers against accidental refactors — these
		// match `canonical_files_gate_grief_defense` memory.
		let c = RateLimitConfig::default();
		assert_eq!(c.max_per_window, 2);
		assert_eq!(c.window, Duration::from_secs(300));
		assert_eq!(c.cooldown, Duration::from_secs(300));
	}
}
