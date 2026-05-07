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
use std::sync::Mutex;
use std::time::Instant;

use crate::inflight::InFlightCap;
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
pub struct Shield {
	cfg: ShieldConfig,
	inflight: InFlightCap,
	state: Mutex<MutableState>,
	started: Instant,
}

struct MutableState {
	src_rl: SourceRateLimiter,
	method_rl: MethodRateLimiter,
	penalty: PenaltyTracker,
}

impl Shield {
	/// Construct from configuration.
	pub fn new(cfg: ShieldConfig) -> Self {
		Self {
			inflight: InFlightCap::new(cfg.inflight_cap),
			cfg,
			state: Mutex::new(MutableState {
				src_rl: SourceRateLimiter::new(),
				method_rl: MethodRateLimiter::new(),
				penalty: PenaltyTracker::new(),
			}),
			started: Instant::now(),
		}
	}

	/// Read configuration.
	pub fn config(&self) -> &ShieldConfig {
		&self.cfg
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
	/// The returned [`Decision`] tells the caller whether to proceed.
	/// On `Allow`, the inflight slot has already been acquired; the
	/// caller must call [`Self::release_inflight`] when done. We don't
	/// hand out an RAII guard because async callers can't hold one
	/// across an `.await` cleanly (lifetime-tied to `&Shield`); a
	/// separate release call works around that.
	pub fn check_request(&self, source: IpAddr, method: &str) -> Decision {
		let subnet = subnet_key(source);
		let now = self.now_micros();

		// Lock the limiters together. Held only for HashMap ops.
		let mut state = match self.state.lock() {
			Ok(g) => g,
			Err(poisoned) => poisoned.into_inner(),
		};

		// 1. Penalty: cheapest gate first. Blocked subnets pay one HashMap lookup.
		if state.penalty.is_penalized(&subnet, now) {
			return Decision::Deny(DenyReason::PenaltyBlock);
		}

		// 2. Source rate limit. Exhaustion → strike.
		if !state.src_rl.check_and_consume(subnet, now) {
			state.penalty.record_strike(subnet, now);
			return Decision::Deny(DenyReason::SourceRateLimit);
		}

		// 3. Method rate limit. Exhaustion → strike.
		if !state.method_rl.check_and_consume(method, now) {
			state.penalty.record_strike(subnet, now);
			return Decision::Deny(DenyReason::MethodRateLimit);
		}

		drop(state);

		// 4. Inflight cap. No strike on exhaustion — this is normal back-pressure.
		if !self.inflight.try_acquire() {
			return Decision::Deny(DenyReason::InflightCap);
		}

		Decision::Allow
	}

	/// Release a slot acquired by an `Allow` decision from
	/// [`Self::check_request`] / [`Self::check_state_call`]. Must be
	/// called once per `Allow` and only once.
	pub fn release_inflight(&self) {
		self.inflight.release();
	}

	/// Gate a `state_call` for a specific runtime API method. Composes
	/// the policy lookup with [`Self::check_request`].
	///
	/// `is_loopback` should be true if the connection came in over
	/// 127.0.0.1 / ::1; LocalOnly methods are admitted only in that case.
	pub fn check_state_call(
		&self,
		source: IpAddr,
		runtime_api_method: &str,
		is_loopback: bool,
	) -> Decision {
		match StateCallPolicy::lookup(runtime_api_method) {
			MethodPolicy::Deny => Decision::Deny(DenyReason::StateCallDenied),
			MethodPolicy::LocalOnly if !is_loopback => {
				Decision::Deny(DenyReason::StateCallLocalOnly)
			}
			MethodPolicy::LocalOnly | MethodPolicy::PublicSafe | MethodPolicy::PublicGated => {
				// Charge the request against the per-source / per-method buckets,
				// using the runtime API method name as the method key (more
				// granular than just "state_call").
				self.check_request(source, runtime_api_method)
			}
		}
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
		let d = s.check_request(ip(10, 0, 0, 1), "system_chain");
		assert_eq!(d, Decision::Allow);
		s.release_inflight();
	}

	#[test]
	fn denies_state_call_to_ring_context() {
		let s = Shield::new(ShieldConfig::default());
		let d = s.check_state_call(ip(10, 0, 0, 1), "SassafrasApi_ring_context", false);
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
			let d = s.check_state_call(ip(1, 2, 3, 4), method, false);
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
		let d_remote = s.check_state_call(
			ip(1, 2, 3, 4),
			"SassafrasApi_generate_key_ownership_proof",
			false,
		);
		assert_eq!(d_remote, Decision::Deny(DenyReason::StateCallLocalOnly));
		let d_local = s.check_state_call(
			ip(127, 0, 0, 1),
			"SassafrasApi_generate_key_ownership_proof",
			true,
		);
		assert_eq!(d_local, Decision::Allow);
		s.release_inflight();
	}

	#[test]
	fn unknown_state_call_method_denied() {
		let s = Shield::new(ShieldConfig::default());
		let d = s.check_state_call(ip(1, 2, 3, 4), "MadeUpApi_method", false);
		assert_eq!(d, Decision::Deny(DenyReason::StateCallDenied));
	}

	#[test]
	fn source_rate_limit_eventually_denies_then_strikes() {
		let s = Shield::new(ShieldConfig::default());
		let src = ip(10, 9, 8, 1);
		// 30 tokens default in the source bucket.
		for _ in 0..30 {
			let d = s.check_request(src, "system_chain");
			assert_eq!(d, Decision::Allow);
			s.release_inflight();
		}
		// Exhausted → first denial is SourceRateLimit, *and* records a strike.
		let d_first = s.check_request(src, "system_chain");
		assert_eq!(d_first, Decision::Deny(DenyReason::SourceRateLimit));
		// Subsequent requests fall to PenaltyBlock (cheaper gate) because
		// the strike has now blocked the subnet.
		let d_second = s.check_request(src, "system_chain");
		assert_eq!(d_second, Decision::Deny(DenyReason::PenaltyBlock));
	}

	#[test]
	fn response_size_cap() {
		let s = Shield::new(ShieldConfig::default());
		assert_eq!(s.check_response(1024), Decision::Allow);
		assert_eq!(s.check_response(64 * 1024 + 1), Decision::Deny(DenyReason::ResponseTooLarge));
	}

	#[test]
	fn inflight_cap_releases_via_release_call() {
		let s = Shield::new(ShieldConfig { inflight_cap: 2, ..Default::default() });
		let d1 = s.check_request(ip(10, 0, 0, 1), "system_chain");
		let d2 = s.check_request(ip(10, 0, 0, 2), "system_chain");
		assert_eq!(d1, Decision::Allow);
		assert_eq!(d2, Decision::Allow);
		// Cap full now; next request should be InflightCap-denied.
		let d3 = s.check_request(ip(10, 0, 0, 3), "system_chain");
		assert_eq!(d3, Decision::Deny(DenyReason::InflightCap));
		s.release_inflight();
		s.release_inflight();
		// After releases, capacity is restored.
		let d4 = s.check_request(ip(10, 0, 0, 4), "system_chain");
		assert_eq!(d4, Decision::Allow);
		s.release_inflight();
	}
}
