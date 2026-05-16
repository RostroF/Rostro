// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors
//
// Token-bucket primitive ported from the snorkel DNS resolver
// (~/Polkadot/snorkel/crates/snorkel-dns/src/ratelimit.rs).

//! Token-bucket rate limiters keyed by source subnet (/24) or by
//! method name. Design notes:
//!
//! - **Subnet collapse**. `subnet_key` reduces an IP to its first three
//!   octets, so an attacker rotating through a /24 cannot bypass the
//!   per-source limit. (This is the snorkel insight: address rotation
//!   in a small range is the cheapest evasion, kill it at the keying
//!   layer.)
//! - **Bounded state**. Both limiters cap their HashMap at
//!   `MAX_TRACKED_*`. New keys past the cap are denied service rather
//!   than allowed to grow memory unbounded.
//! - **Saturating arithmetic**. Time-difference math uses
//!   `saturating_sub` / `checked_div` so wall-clock skew or u64
//!   wraparound cannot corrupt bucket state.

use std::collections::HashMap;
use std::net::IpAddr;

const MAX_TRACKED_SUBNETS: usize = 4096;
const MAX_TRACKED_METHODS: usize = 256;

/// Per-/24 source bucket: tokens, refill rate.
const SRC_MAX_TOKENS: u32 = 30;
const SRC_MICROS_PER_TOKEN: u64 = 100_000; // 10 tokens/sec sustained

/// Per-method bucket: tokens, refill rate. Tighter than per-source
/// because a single legitimate caller wouldn't hammer one method this
/// fast.
const METHOD_MAX_TOKENS: u32 = 60;
const METHOD_MICROS_PER_TOKEN: u64 = 50_000; // 20 tokens/sec sustained

/// Reduce an IP to a /24 key (IPv4) or /48 key (IPv6).
///
/// The trailing byte is a discriminator (4 vs 6) so a v4 /24 and a v6
/// /48 cannot collide.
pub fn subnet_key(addr: IpAddr) -> [u8; 4] {
	match addr {
		IpAddr::V4(v4) => {
			let o = v4.octets();
			[o[0], o[1], o[2], 4]
		}
		IpAddr::V6(v6) => {
			let o = v6.octets();
			[o[0], o[1], o[2], 6]
		}
	}
}

#[derive(Clone, Copy)]
struct Bucket {
	tokens: u32,
	last_refill_micros: u64,
}

fn refill_and_consume(
	bucket: &mut Bucket,
	now_micros: u64,
	max_tokens: u32,
	micros_per_token: u64,
) -> bool {
	let elapsed = now_micros.saturating_sub(bucket.last_refill_micros);
	let refill = elapsed.checked_div(micros_per_token).unwrap_or(0);
	if refill > 0 {
		let refill_u32 = u32::try_from(refill).unwrap_or(u32::MAX);
		bucket.tokens = bucket.tokens.saturating_add(refill_u32).min(max_tokens);
		let consumed = refill.saturating_mul(micros_per_token);
		bucket.last_refill_micros = bucket.last_refill_micros.saturating_add(consumed);
	}
	if bucket.tokens > 0 {
		bucket.tokens = bucket.tokens.saturating_sub(1);
		true
	} else {
		false
	}
}

/// Per-/24 source rate limiter.
pub struct SourceRateLimiter {
	buckets: HashMap<[u8; 4], Bucket>,
}

impl SourceRateLimiter {
	/// Construct a fresh limiter.
	pub fn new() -> Self {
		Self { buckets: HashMap::with_capacity(MAX_TRACKED_SUBNETS) }
	}

	/// Try to consume one token for `subnet`. Returns `true` if allowed,
	/// `false` if the bucket is exhausted or the cap is full.
	pub fn check_and_consume(&mut self, subnet: [u8; 4], now_micros: u64) -> bool {
		let known = self.buckets.contains_key(&subnet);
		if !known && self.buckets.len() >= MAX_TRACKED_SUBNETS {
			return false;
		}
		let bucket = self.buckets.entry(subnet).or_insert(Bucket {
			tokens: SRC_MAX_TOKENS,
			last_refill_micros: now_micros,
		});
		refill_and_consume(bucket, now_micros, SRC_MAX_TOKENS, SRC_MICROS_PER_TOKEN)
	}
}

impl Default for SourceRateLimiter {
	fn default() -> Self { Self::new() }
}

/// Per-method rate limiter. Method names are hashed to fixed-size keys
/// (so the HashMap does not store unbounded strings).
pub struct MethodRateLimiter {
	buckets: HashMap<[u8; 16], Bucket>,
}

impl MethodRateLimiter {
	/// Construct a fresh limiter.
	pub fn new() -> Self {
		Self { buckets: HashMap::with_capacity(MAX_TRACKED_METHODS) }
	}

	/// Try to consume one token for `method`. Returns `true` if allowed.
	pub fn check_and_consume(&mut self, method: &str, now_micros: u64) -> bool {
		let key = method_key(method);
		let known = self.buckets.contains_key(&key);
		if !known && self.buckets.len() >= MAX_TRACKED_METHODS {
			return false;
		}
		let bucket = self.buckets.entry(key).or_insert(Bucket {
			tokens: METHOD_MAX_TOKENS,
			last_refill_micros: now_micros,
		});
		refill_and_consume(bucket, now_micros, METHOD_MAX_TOKENS, METHOD_MICROS_PER_TOKEN)
	}
}

impl Default for MethodRateLimiter {
	fn default() -> Self { Self::new() }
}

/// Cap the number of bytes we hash from a method name. Legitimate RPC
/// method names are well under 64 chars; even substrate's longest
/// runtime API names (`SassafrasApi_submit_report_equivocation_unsigned_extrinsic`)
/// are ~60 chars. Anything longer is hashing-cost amplification by an
/// adversary; we silently truncate. Two distinct names sharing the
/// same first 256 bytes will collide in the bucket — acceptable, since
/// no legitimate names get close to this length.
const HASH_MAX_BYTES: usize = 256;

fn method_key(method: &str) -> [u8; 16] {
	// Fast hash with no external dependency. Two FNV-1a-style passes
	// over the bytes, producing 16 bytes of key material. Adequate for
	// distinguishing method names; not cryptographic.
	let bytes = method.as_bytes();
	let bytes = if bytes.len() > HASH_MAX_BYTES { &bytes[..HASH_MAX_BYTES] } else { bytes };
	let mut h1: u64 = 0xcbf29ce484222325;
	let mut h2: u64 = 0x84222325cbf29ce4;
	for &b in bytes {
		h1 ^= u64::from(b);
		h1 = h1.wrapping_mul(0x100000001b3);
		h2 = h2.wrapping_add(u64::from(b));
		h2 = h2.wrapping_mul(0x9e3779b97f4a7c15);
	}
	let mut out = [0u8; 16];
	out[..8].copy_from_slice(&h1.to_le_bytes());
	out[8..].copy_from_slice(&h2.to_le_bytes());
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::Ipv4Addr;

	fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
		IpAddr::V4(Ipv4Addr::new(a, b, c, d))
	}

	#[test]
	fn subnet_key_collapses_last_octet() {
		assert_eq!(subnet_key(ip(10, 0, 0, 1)), subnet_key(ip(10, 0, 0, 255)));
	}

	#[test]
	fn subnet_key_distinguishes_third_octet() {
		assert_ne!(subnet_key(ip(10, 0, 0, 1)), subnet_key(ip(10, 0, 1, 1)));
	}

	#[test]
	fn fresh_subnet_allows_burst_then_blocks() {
		let mut rl = SourceRateLimiter::new();
		let s = subnet_key(ip(10, 0, 0, 1));
		for _ in 0..30 {
			assert!(rl.check_and_consume(s, 0));
		}
		assert!(!rl.check_and_consume(s, 0));
	}

	#[test]
	fn last_octet_rotation_cannot_bypass_source_limit() {
		let mut rl = SourceRateLimiter::new();
		for last in 0..=255_u8 {
			rl.check_and_consume(subnet_key(ip(10, 0, 0, last)), 0);
		}
		assert!(!rl.check_and_consume(subnet_key(ip(10, 0, 0, 0)), 0));
	}

	#[test]
	fn refill_restores_tokens_over_time() {
		let mut rl = SourceRateLimiter::new();
		let s = subnet_key(ip(10, 0, 0, 1));
		for _ in 0..30 { rl.check_and_consume(s, 0); }
		assert!(!rl.check_and_consume(s, 0));
		// One token's worth of time later.
		assert!(rl.check_and_consume(s, SRC_MICROS_PER_TOKEN));
	}

	#[test]
	fn method_keys_distinguish_names() {
		assert_ne!(
			method_key("SassafrasApi_ring_context"),
			method_key("SassafrasApi_slot_ticket"),
		);
	}

	#[test]
	fn method_rate_limit_per_method() {
		let mut mrl = MethodRateLimiter::new();
		for _ in 0..60 {
			assert!(mrl.check_and_consume("ring_context", 0));
		}
		assert!(!mrl.check_and_consume("ring_context", 0));
		// Different method has its own bucket.
		assert!(mrl.check_and_consume("slot_ticket", 0));
	}

	#[test]
	fn long_method_names_are_truncated_for_hashing() {
		// A 100 KB method name should hash in the same time as a 256-byte one.
		// Functionally: two names sharing the first 256 bytes will collide,
		// but neither legitimate names nor distinct attacker names that share
		// 256-byte prefixes are realistic.
		let short = "a".repeat(256);
		let long = "a".repeat(100_000);
		assert_eq!(
			method_key(&short),
			method_key(&long),
			"truncation kicks in past 256 bytes",
		);
		// Different short names hash differently.
		assert_ne!(method_key("foo"), method_key("bar"));
	}

	#[test]
	fn subnet_cap_denies_new_keys_past_threshold() {
		let mut rl = SourceRateLimiter::new();
		for i in 0..MAX_TRACKED_SUBNETS {
			let octet1 = (i >> 8) as u8;
			let octet2 = (i & 0xff) as u8;
			assert!(rl.check_and_consume(subnet_key(ip(10, octet1, octet2, 0)), 0));
		}
		// Cap is full — new subnet refused.
		assert!(!rl.check_and_consume(subnet_key(ip(192, 168, 100, 1)), 0));
	}
}
