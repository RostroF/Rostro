// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Defense-in-depth RPC middleware for Rostro nodes.
//!
//! Built in response to the Phase 4 Fagan inspection of Sassafras, which
//! documented three externally-reachable findings on the public RPC
//! surface — all inherited from upstream Substrate/Parity:
//!
//! - **F-25-sub** — `author_submitExtrinsic` flood with malformed bytes
//!   panics the runtime in `TaggedTransactionQueue::validate_transaction`,
//!   burning ~13k panics/sec per attacker connection.
//! - **F-NEW-1** — runtime APIs that call offchain-only host functions
//!   (`SassafrasApi.submit_tickets_unsigned_extrinsic`,
//!   `SassafrasApi.submit_report_equivocation_unsigned_extrinsic`,
//!   `GrandpaApi.submit_report_equivocation_unsigned_extrinsic`) panic
//!   on every external `state_call` invocation.
//! - **F-NEW-2** — `SassafrasApi.ring_context` returns ~580KB unauthenticated;
//!   we measured 276 MB/s sustained outbound from one connection set,
//!   threatening libp2p peering via NIC saturation.
//!
//! The shield is a host-side gate stack that runs *before* requests
//! reach the runtime. Method-allowlist + per-/24 source rate limit +
//! per-method rate limit + escalating penalty + inflight cap +
//! response-size cap. Patterned on the snorkel DNS resolver's
//! abuse-absorption layer.
//!
//! No runtime fork required. No pallet fork required. Deployed as
//! jsonrpsee middleware in the node binary.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod inflight;
pub mod penalty;
pub mod ratelimit;
pub mod shield;
pub mod statecall;

pub use inflight::{InFlightCap, OwnedInflightGuard};
pub use penalty::PenaltyTracker;
pub use ratelimit::{MethodRateLimiter, SourceRateLimiter, subnet_key};
pub use shield::{Decision, DenyReason, Shield, ShieldConfig};
pub use statecall::{MethodPolicy, StateCallPolicy};
