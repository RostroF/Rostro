// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Shield orchestrator.
//!
//! Composes the rate limiters, penalty tracker, inflight cap, and
//! `state_call` policy into a single gate stack. The integration code
//! in the node binary calls [`Shield::check_request`] before
//! dispatching each RPC, and [`Shield::check_response`] before
//! returning the response.
//!
//! Lock granularity: the limiters are wrapped in a single
//! `parking_lot::Mutex` for v0. They are O(1) HashMap lookups, so
//! contention is bounded; if profiling shows contention we can swap to
//! per-shard locks. We use `std::sync::Mutex` here to avoid pulling in
//! parking_lot — the substrate workspace already has it but we want
//! this crate to have minimal deps.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::inflight::{InFlightCap, OwnedInflightGuard};
use crate::policy_cache::PolicyCache;
use crate::penalty::PenaltyTracker;
use crate::ratelimit::{MethodRateLimiter, SourceRateLimiter, subnet_key};
use crate::statecall::{MethodPolicy, StateCallPolicy};

/// Configuration knobs.
#[derive(Debug, Clone)]
pub struct ShieldConfig {
	/// Maximum concurrent in-flight requests across all sources.
	pub inflight_cap: u64,
	/// Maximum response size in bytes. Responses larger than this are
	/// denied at [`Shield::check_response`] time.
	pub max_response_bytes: usize,
}

impl Default for ShieldConfig {
	fn default() -> Self {
		Self {
			inflight_cap: 256,
			// 64 KiB. ring_context (~580KB) is denied outright by the
			// state_call policy; this catches anything else that grows
			// unexpectedly.
			max_response_bytes: 64 * 1024,
		}
	}
}

/// Why a request was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
	/// Source subnet is currently in a penalty block window.
	PenaltyBlock,
	/// Per-/24 source rate limit exhausted.
	SourceRateLimit,
	/// Per-method rate limit exhausted.
	MethodRateLimit,
	/// Inflight cap reached.
	InflightCap,
	/// `state_call` for a method not on the public allowlist.
	StateCallDenied,
	/// `state_call` for a local-only method, called from a non-loopback peer.
	StateCallLocalOnly,
	/// Response payload exceeded `max_response_bytes`.
	ResponseTooLarge,
}

/// Shield decision for a single request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
	/// Request may proceed.
	Allow,
	/// Request denied, with reason.
	Deny(DenyReason),
}

/// Shield orchestrator: one instance per node, shared across all RPC
/// worker threads.
///
/// The inflight cap is held in `Arc<InFlightCap>` so it can hand out
/// owned RAII guards. This makes the acquisition pattern resilient to
/// future cancellation (connection close mid-request, timeout, etc.) —
/// the slot releases on guard drop regardless of whether the holding
/// future ever resumes.
///
/// The state_call method policy is sourced from two layers:
///   1. **Primary**: an on-chain registry (`pallet-rostro-rpc-method-policy`)
///      mirrored into [`PolicyCache`]. The substrate-side bridge code
///      refreshes the cache periodically.
///   2. **Fallback**: hard-coded [`StateCallPolicy::lookup`]. Used while
///      the cache is unbootstrapped (early in startup, before the first
///      successful runtime API query) or if the chain becomes unreachable.
///
/// Both layers share a single [`MethodPolicy`] enum. When the cache is
/// bootstrapped its answer wins, including for "method not found" — the
/// hard-coded fallback only fires when the cache hasn't heard from chain
/// yet.
pub struct Shield {
	cfg: ShieldConfig,
	inflight: Arc<InFlightCap>,
	state: Mutex<MutableState>,
	started: Instant,
	policy_cache: PolicyCache,
}

struct MutableState {
	src_rl: SourceRateLimiter,
	method_rl: MethodRateLimiter,
	penalty: PenaltyTracker,
}

impl Shield {
	/// Construct from configuration. The policy cache starts empty; the
	/// substrate-side bridge populates it after the runtime API becomes
	/// queryable (typically a few seconds after startup).
	pub fn new(cfg: ShieldConfig) -> Self {
		Self {
			inflight: Arc::new(InFlightCap::new(cfg.inflight_cap)),
			cfg,
			state: Mutex::new(MutableState {
				src_rl: SourceRateLimiter::new(),
				method_rl: MethodRateLimiter::new(),
				penalty: PenaltyTracker::new(),
			}),
			started: Instant::now(),
			policy_cache: PolicyCache::new(),
		}
	}

	/// Read configuration.
	pub fn config(&self) -> &ShieldConfig {
		&self.cfg
	}

	/// Cloneable handle to the policy cache, for the substrate-side
	/// refresh task to push updates into. Cheap clone (Arc).
	pub fn policy_cache(&self) -> PolicyCache {
		self.policy_cache.clone()
	}

	/// Convert wall-clock to monotonic micros for the rate limiters.
	fn now_micros(&self) -> u64 {
		u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
	}

	/// Gate a non-state_call RPC method.
	///
	/// Order: penalty → source RL → method RL → inflight cap. Each
	/// failure increments the appropriate counter; rate-limit
	/// exhaustion records a penalty strike so repeat offenders escalate
	/// into the cheap penalty-block path.
	///
	/// On `Allow`, returns an [`OwnedInflightGuard`] that releases the
	/// slot on drop. Carry it across the dispatch `.await` so the slot
	/// frees even if the future is cancelled (connection close,
	/// timeout, etc.). On `Deny`, no slot was acquired.
	pub fn check_request(
		&self,
		source: IpAddr,
		method: &str,
	) -> (Decision, Option<OwnedInflightGuard>) {
		let subnet = subnet_key(source);
		let now = self.now_micros();

		// Lock the limiters together. Held only for HashMap ops.
		let mut state = match self.state.lock() {
			Ok(g) => g,
			Err(poisoned) => poisoned.into_inner(),
		};

		// 1. Penalty: cheapest gate first. Blocked subnets pay one HashMap lookup.
		if state.penalty.is_penalized(&subnet, now) {
			return (Decision::Deny(DenyReason::PenaltyBlock), None);
		}

		// 2. Source rate limit. Exhaustion → strike.
		if !state.src_rl.check_and_consume(subnet, now) {
			state.penalty.record_strike(subnet, now);
			return (Decision::Deny(DenyReason::SourceRateLimit), None);
		}

		// 3. Method rate limit. Exhaustion → strike.
		if !state.method_rl.check_and_consume(method, now) {
			state.penalty.record_strike(subnet, now);
			return (Decision::Deny(DenyReason::MethodRateLimit), None);
		}

		drop(state);

		// 4. Inflight cap. No strike on exhaustion — normal back-pressure.
		match self.inflight.try_acquire_owned() {
			Some(guard) => (Decision::Allow, Some(guard)),
			None => (Decision::Deny(DenyReason::InflightCap), None),
		}
	}

	/// Gate a `state_call` for a specific runtime API method. Composes
	/// the policy lookup with [`Self::check_request`].
	///
	/// `is_loopback` should be true if the connection came in over
	/// 127.0.0.1 / ::1; LocalOnly methods are admitted only in that case.
	///
	/// On `Allow`, returns an [`OwnedInflightGuard`] (see
	/// [`Self::check_request`]). Deny tier paths return no guard.
	pub fn check_state_call(
		&self,
		source: IpAddr,
		runtime_api_method: &str,
		is_loopback: bool,
	) -> (Decision, Option<OwnedInflightGuard>) {
		let policy = self.resolve_policy(runtime_api_method);
		match policy {
			MethodPolicy::Deny => (Decision::Deny(DenyReason::StateCallDenied), None),
			MethodPolicy::LocalOnly if !is_loopback => {
				(Decision::Deny(DenyReason::StateCallLocalOnly), None)
			}
			MethodPolicy::LocalOnly | MethodPolicy::PublicSafe | MethodPolicy::PublicGated => {
				// Charge the request against the per-source / per-method buckets,
				// using the runtime API method name as the method key (more
				// granular than just "state_call").
				self.check_request(source, runtime_api_method)
			}
		}
	}

	/// Resolve a state_call method to its policy.
	///
	/// On-chain cache wins when bootstrapped — including its "not found"
	/// answer (which becomes Deny, the explicit-allowlist default). The
	/// hard-coded [`StateCallPolicy::lookup`] is the fallback used only
	/// while the cache hasn't heard from chain yet (typically a few
	/// seconds at startup) or if the chain becomes unreachable and the
	/// refresh task has stopped pushing updates. Either way the result
	/// is a single [`MethodPolicy`]; the cache's "not found while
	/// bootstrapped" maps to Deny because that's the registry's
	/// default-deny semantics.
	fn resolve_policy(&self, method: &str) -> MethodPolicy {
		if self.policy_cache.is_bootstrapped() {
			return self.policy_cache.lookup(method.as_bytes()).unwrap_or(MethodPolicy::Deny);
		}
		StateCallPolicy::lookup(method)
	}

	/// Gate the response payload size. Call before sending the response
	/// to the client.
	pub fn check_response(&self, response_bytes: usize) -> Decision {
		if response_bytes > self.cfg.max_response_bytes {
			Decision::Deny(DenyReason::ResponseTooLarge)
		} else {
			Decision::Allow
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::Ipv4Addr;

	fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
		IpAddr::V4(Ipv4Addr::new(a, b, c, d))
	}

	#[test]
	fn allows_first_request() {
		let s = Shield::new(ShieldConfig::default());
		let (d, _g) = s.check_request(ip(10, 0, 0, 1), "system_chain");
		assert_eq!(d, Decision::Allow);
	}

	#[test]
	fn denies_state_call_to_ring_context() {
		let s = Shield::new(ShieldConfig::default());
		let (d, _) = s.check_state_call(ip(10, 0, 0, 1), "SassafrasApi_ring_context", false);
		assert_eq!(d, Decision::Deny(DenyReason::StateCallDenied));
	}

	#[test]
	fn denies_state_call_to_offchain_panic_apis() {
		let s = Shield::new(ShieldConfig::default());
		for method in [
			"SassafrasApi_submit_tickets_unsigned_extrinsic",
			"SassafrasApi_submit_report_equivocation_unsigned_extrinsic",
			"GrandpaApi_submit_report_equivocation_unsigned_extrinsic",
		] {
			let (d, _) = s.check_state_call(ip(1, 2, 3, 4), method, false);
			assert_eq!(
				d,
				Decision::Deny(DenyReason::StateCallDenied),
				"method {method} should be denied",
			);
		}
	}

	#[test]
	fn local_only_admitted_only_on_loopback() {
		let s = Shield::new(ShieldConfig::default());
		let (d_remote, _) = s.check_state_call(
			ip(1, 2, 3, 4),
			"SassafrasApi_generate_key_ownership_proof",
			false,
		);
		assert_eq!(d_remote, Decision::Deny(DenyReason::StateCallLocalOnly));
		let (d_local, _g) = s.check_state_call(
			ip(127, 0, 0, 1),
			"SassafrasApi_generate_key_ownership_proof",
			true,
		);
		assert_eq!(d_local, Decision::Allow);
	}

	#[test]
	fn unknown_state_call_method_denied() {
		let s = Shield::new(ShieldConfig::default());
		let (d, _) = s.check_state_call(ip(1, 2, 3, 4), "MadeUpApi_method", false);
		assert_eq!(d, Decision::Deny(DenyReason::StateCallDenied));
	}

	#[test]
	fn source_rate_limit_eventually_denies_then_strikes() {
		let s = Shield::new(ShieldConfig::default());
		let src = ip(10, 9, 8, 1);
		// 30 tokens default in the source bucket. Drop guards explicitly
		// so the inflight cap doesn't fill (default cap=256).
		for _ in 0..30 {
			let (d, g) = s.check_request(src, "system_chain");
			assert_eq!(d, Decision::Allow);
			drop(g);
		}
		// Exhausted → first denial is SourceRateLimit, *and* records a strike.
		let (d_first, _) = s.check_request(src, "system_chain");
		assert_eq!(d_first, Decision::Deny(DenyReason::SourceRateLimit));
		// Subsequent requests fall to PenaltyBlock (cheaper gate) because
		// the strike has now blocked the subnet.
		let (d_second, _) = s.check_request(src, "system_chain");
		assert_eq!(d_second, Decision::Deny(DenyReason::PenaltyBlock));
	}

	#[test]
	fn response_size_cap() {
		let s = Shield::new(ShieldConfig::default());
		assert_eq!(s.check_response(1024), Decision::Allow);
		assert_eq!(s.check_response(64 * 1024 + 1), Decision::Deny(DenyReason::ResponseTooLarge));
	}

	#[test]
	fn inflight_cap_releases_on_guard_drop() {
		let s = Shield::new(ShieldConfig { inflight_cap: 2, ..Default::default() });
		let (d1, g1) = s.check_request(ip(10, 0, 0, 1), "system_chain");
		let (d2, g2) = s.check_request(ip(10, 0, 0, 2), "system_chain");
		assert_eq!(d1, Decision::Allow);
		assert_eq!(d2, Decision::Allow);
		// Cap full now; next request should be InflightCap-denied.
		let (d3, _) = s.check_request(ip(10, 0, 0, 3), "system_chain");
		assert_eq!(d3, Decision::Deny(DenyReason::InflightCap));
		drop(g1);
		drop(g2);
		// After releases, capacity is restored.
		let (d4, _g) = s.check_request(ip(10, 0, 0, 4), "system_chain");
		assert_eq!(d4, Decision::Allow);
	}

	#[test]
	fn cancelled_future_releases_inflight_slot() {
		// Simulates the connection-cancel-mid-request scenario: we
		// acquire a guard but never explicitly release. Drop happens
		// implicitly when the guard goes out of scope, mimicking what
		// the borrow checker enforces when an async future is dropped.
		let s = Shield::new(ShieldConfig { inflight_cap: 1, ..Default::default() });
		{
			let (d, _g) = s.check_request(ip(10, 0, 0, 1), "system_chain");
			assert_eq!(d, Decision::Allow);
			// _g goes out of scope here, simulating future cancellation.
		}
		// Slot must have been freed.
		let (d, _g) = s.check_request(ip(10, 0, 0, 2), "system_chain");
		assert_eq!(d, Decision::Allow, "cancelled guard must release slot");
	}
}
