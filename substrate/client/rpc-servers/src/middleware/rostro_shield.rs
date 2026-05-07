// Copyright (C) 2026 Rostro Foundation contributors
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Rostro RPC shield middleware.
//!
//! Defense-in-depth layer wrapping the per-request `RpcServiceT`
//! pipeline with the `rostro-rpc-shield` library's gate stack:
//! method-policy lookup, per-method rate limit, per-/24 source rate
//! limit, escalating penalty tracker, inflight cap.
//!
//! Activation is gated by the `ROSTRO_RPC_SHIELD` environment variable.
//! The default is **off** so this module is a no-op in stock substrate
//! tests; for Rostro chains we set the env var in the binary's
//! `service.rs` (or via the launch command).
//!
//! ## Layer ordering note
//!
//! This layer must be added **last** in the `RpcServiceBuilder` chain
//! so it becomes the innermost wrapper around `RpcService`. Tower's
//! `Stack` applies last-added closest to the base service. Adding this
//! layer earlier makes its `S` resolve to a type containing substrate's
//! non-`Clone` `Middleware<S>`, breaking the `S: Clone` bound on our
//! `RpcServiceT` impl. With this layer innermost, `S = RpcService`
//! (which derives `Clone`) and the bounds are satisfied.
//!
//! ## Source IP plumbing
//!
//! Source-IP-aware checks (per-/24 source rate limit, penalty tracker,
//! local-only methods) need connection metadata that this layer does
//! not yet receive in jsonrpsee 0.24's `RpcServiceT`. They are wired
//! through the shield's API but currently see a synthetic loopback IP
//! — equivalent to "all callers share one bucket". The library is
//! built so that plumbing the real source through (via jsonrpsee
//! `ConnectionGuard` extensions) is a local change to this file only.

use std::sync::{Arc, OnceLock};

use futures::future::{BoxFuture, FutureExt};
use jsonrpsee::{
	server::middleware::rpc::RpcServiceT,
	types::{ErrorObject, Id, Request},
	MethodResponse,
};
use rostro_rpc_shield::{Decision, DenyReason, Shield, ShieldConfig};

const ROSTRO_RPC_SHIELD_ENV: &str = "ROSTRO_RPC_SHIELD";

/// Process-wide singleton holding the shield (or `None` if not
/// activated via env). Computed once on the first `from_env()` call,
/// observed identically by all subsequent callers. This guarantees
/// that the substrate RPC server's shield instance and the binary's
/// (e.g. gemini-node's) refresh task operate on the same `Shield`
/// — they share its `policy_cache`, rate-limit state, etc.
static SHIELD_SINGLETON: OnceLock<Option<RostroShieldLayer>> = OnceLock::new();

/// Layer that activates the shield from environment configuration.
#[derive(Clone)]
pub struct RostroShieldLayer {
	shield: Arc<Shield>,
}

impl RostroShieldLayer {
	/// Activate from `ROSTRO_RPC_SHIELD=1`. Returns `None` if the env
	/// var is unset or set to anything other than `1`.
	///
	/// Memoized: the first call computes the layer (or `None`) and
	/// every subsequent call returns the same instance. This is what
	/// lets the substrate-side RPC service and the binary-side
	/// refresh task observe the same `Shield`.
	pub fn from_env() -> Option<Self> {
		SHIELD_SINGLETON
			.get_or_init(|| {
				match std::env::var(ROSTRO_RPC_SHIELD_ENV).ok().as_deref() {
					Some("1") => Some(Self {
						shield: Arc::new(Shield::new(ShieldConfig::default())),
					}),
					_ => None,
				}
			})
			.clone()
	}

	/// Construct with an explicit shield. Useful for tests and for
	/// future config plumbing.
	pub fn with_shield(shield: Arc<Shield>) -> Self {
		Self { shield }
	}

	/// Cloneable handle to the underlying shield. Used by the
	/// substrate-side bridge (`spawn_chain_policy_refresh`) to push
	/// on-chain policy data into the shield's [`PolicyCache`].
	pub fn shield(&self) -> Arc<Shield> {
		self.shield.clone()
	}
}

impl<S> tower::Layer<S> for RostroShieldLayer {
	type Service = RostroShieldMiddleware<S>;

	fn layer(&self, service: S) -> Self::Service {
		RostroShieldMiddleware { service, shield: self.shield.clone() }
	}
}

/// Per-service shield middleware.
#[derive(Clone)]
pub struct RostroShieldMiddleware<S> {
	service: S,
	shield: Arc<Shield>,
}

impl<'a, S> RpcServiceT<'a> for RostroShieldMiddleware<S>
where
	S: Send + Sync + RpcServiceT<'a> + Clone + 'static,
{
	type Future = BoxFuture<'a, MethodResponse>;

	fn call(&self, req: Request<'a>) -> Self::Future {
		let service = self.service.clone();
		let shield = self.shield.clone();

		async move {
			// We don't have the source IP here yet (jsonrpsee 0.24
			// passes ConnectionGuard through tower::Service extensions,
			// not RpcServiceT). Use a synthetic loopback IP so the
			// per-/24 limiter and penalty tracker keep working —
			// effectively a single shared bucket until source plumbing
			// lands.
			let synthetic_source =
				std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
			let is_loopback = true;

			let method_name = req.method.as_ref();

			// Special-case `state_call` — peek at params[0] to extract
			// the runtime API method name and apply the state_call
			// policy. The shield's check_* methods return an owned
			// guard on Allow; we hold it across the dispatch await so
			// the inflight slot frees on guard drop, including when the
			// future itself is cancelled (connection close mid-request).
			let (decision, _guard) = if method_name == "state_call" {
				match peek_state_call_method(&req) {
					Some(api_method) =>
						shield.check_state_call(synthetic_source, &api_method, is_loopback),
					// Couldn't parse params — pass through to
					// substrate's normal error path without claiming
					// an inflight slot. _guard remains None, no
					// release ever fires.
					None => (Decision::Allow, None),
				}
			} else {
				shield.check_request(synthetic_source, method_name)
			};

			if let Decision::Deny(reason) = decision {
				return reject(req.id, reason);
			}

			// _guard is held across this await. If the future is
			// cancelled, _guard drops, releasing the slot. If the
			// future completes, _guard drops at end-of-block, also
			// releasing. Either way, no slot leak.
			let response = service.call(req).await;
			drop(_guard);
			response
		}
		.boxed()
	}
}

/// Maximum raw params size we will attempt to JSON-parse for state_call
/// peek. Legitimate state_call params are well under 4 KiB (method name
/// is ~50 chars; encoded ticket envelopes are ~1.7 KiB hex; even
/// generous over-padding stays under this cap). Anything larger is
/// either a buggy client or a memory-amplification probe — we refuse
/// to parse it. (Bug-test phase: without this cap, a 9 MB state_call
/// params payload triggers a ~10 MB serde_json::Value allocation per
/// call, multiplied by jsonrpsee's max_request_body_size budget.)
const MAX_STATE_CALL_PARAMS_BYTES: usize = 4 * 1024;

/// Maximum runtime API method name length we will hash. Legitimate
/// names are well under 100 chars; the longest currently in our policy
/// table is ~60. Anything longer is hashing-cost amplification, since
/// `method_key` iterates one pass per byte.
const MAX_METHOD_NAME_LEN: usize = 256;

fn peek_state_call_method(req: &Request<'_>) -> Option<String> {
	// JSON-RPC 2.0 allows BOTH positional (array) and named (object)
	// params. substrate's state_call accepts both:
	//   positional: ["MethodName", "0xhex", optional_block_hash]
	//   named:      {"name": "MethodName", "bytes": "0xhex", ...}
	//
	// Earlier versions of this code peeked the array form only, which
	// meant a named-params request bypassed the StateCallPolicy lookup
	// entirely — F-NEW-2 / F-NEW-1 / F-6 were all reachable via the
	// named form. (Bug-test phase: discovered when curl with
	// `params: {"name":"SassafrasApi_ring_context","bytes":"0x"}`
	// reached the runtime instead of being shield-denied.)
	let raw = req.params.as_ref()?;
	let raw_str = raw.get();
	if raw_str.len() > MAX_STATE_CALL_PARAMS_BYTES {
		// Refuse to parse — caller has either misuse or a memory-amp
		// attack in flight. Returning None lets the request fall through
		// to substrate's normal error path; the per-source rate limit
		// still gates how often this can happen.
		return None;
	}
	let parsed: serde_json::Value = serde_json::from_str(raw_str).ok()?;
	let s = match &parsed {
		serde_json::Value::Array(arr) => arr.first()?.as_str()?,
		serde_json::Value::Object(map) => map.get("name")?.as_str()?,
		_ => return None,
	};
	if s.len() > MAX_METHOD_NAME_LEN {
		return None;
	}
	Some(s.to_owned())
}

fn reject(id: Id<'_>, reason: DenyReason) -> MethodResponse {
	let (code, message) = match reason {
		DenyReason::PenaltyBlock => (-32011, "rostro-shield: penalty block"),
		DenyReason::SourceRateLimit => (-32012, "rostro-shield: source rate limit"),
		DenyReason::MethodRateLimit => (-32013, "rostro-shield: method rate limit"),
		DenyReason::InflightCap => (-32014, "rostro-shield: inflight cap"),
		DenyReason::StateCallDenied => (-32015, "rostro-shield: state_call method denied"),
		DenyReason::StateCallLocalOnly => {
			(-32016, "rostro-shield: state_call method is local-only")
		}
		DenyReason::ResponseTooLarge => (-32017, "rostro-shield: response too large"),
	};
	MethodResponse::error(id, ErrorObject::owned(code, message, None::<()>))
}
