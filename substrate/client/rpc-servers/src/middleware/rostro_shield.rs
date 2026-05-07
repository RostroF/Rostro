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

use std::sync::Arc;

use futures::future::{BoxFuture, FutureExt};
use jsonrpsee::{
	server::middleware::rpc::RpcServiceT,
	types::{ErrorObject, Id, Request},
	MethodResponse,
};
use rostro_rpc_shield::{Decision, DenyReason, Shield, ShieldConfig};

const ROSTRO_RPC_SHIELD_ENV: &str = "ROSTRO_RPC_SHIELD";

/// Layer that activates the shield from environment configuration.
#[derive(Clone)]
pub struct RostroShieldLayer {
	shield: Arc<Shield>,
}

impl RostroShieldLayer {
	/// Activate from `ROSTRO_RPC_SHIELD=1`. Returns `None` if the env
	/// var is unset or set to anything other than `1`.
	pub fn from_env() -> Option<Self> {
		match std::env::var(ROSTRO_RPC_SHIELD_ENV).ok().as_deref() {
			Some("1") => Some(Self {
				shield: Arc::new(Shield::new(ShieldConfig::default())),
			}),
			_ => None,
		}
	}

	/// Construct with an explicit shield. Useful for tests and for
	/// future config plumbing.
	pub fn with_shield(shield: Arc<Shield>) -> Self {
		Self { shield }
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
			// policy.
			//
			// `acquired` tracks whether the shield's `Allow` decision
			// reserved an inflight slot. The library acquires a slot
			// only on `Allow` from `check_request` / `check_state_call`
			// (after passing penalty + source RL + method RL + inflight
			// gates). The Deny short-circuits in those checks (and the
			// special `None` arm below) do NOT acquire. We must
			// `release_inflight()` only when we actually acquired —
			// otherwise the counter underflows to `u64::MAX`,
			// eventually wraps past `max`, and starves all callers.
			let (decision, acquired) = if method_name == "state_call" {
				match peek_state_call_method(&req) {
					Some(api_method) => {
						let d = shield.check_state_call(
							synthetic_source,
							&api_method,
							is_loopback,
						);
						let acq = matches!(d, Decision::Allow);
						(d, acq)
					}
					// Couldn't parse params — pass through to
					// substrate's normal error path. We did NOT
					// acquire an inflight slot, so we must NOT release
					// later.
					None => (Decision::Allow, false),
				}
			} else {
				let d = shield.check_request(synthetic_source, method_name);
				let acq = matches!(d, Decision::Allow);
				(d, acq)
			};

			if let Decision::Deny(reason) = decision {
				return reject(req.id, reason);
			}

			// Response-size check is deferred — jsonrpsee 0.24
			// `MethodResponse` does not expose body bytes from this
			// middleware position. The shield's `check_response` API
			// is already in place; once we plumb a response body
			// inspection point (or replace the response post-hoc), this
			// becomes one extra call. For now the highest-severity
			// amplifier (ring_context) is covered by the state_call
			// method allowlist (Deny tier), which fires *before* the
			// runtime executes — no body to inspect.
			let response = service.call(req).await;
			if acquired {
				shield.release_inflight();
			}
			response
		}
		.boxed()
	}
}

fn peek_state_call_method(req: &Request<'_>) -> Option<String> {
	// state_call params: ["MethodName", "0xhex", optional_block_hash]
	let raw = req.params.as_ref()?;
	let parsed: serde_json::Value = serde_json::from_str(raw.get()).ok()?;
	let arr = parsed.as_array()?;
	let first = arr.first()?;
	first.as_str().map(|s| s.to_owned())
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
