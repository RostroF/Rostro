// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-client
//!
//! Native Rostro chain client. Recognizes canonical types by **fingerprint
//! match** against the on-chain `pallet-rostro-type-registry` rather than by
//! hardcoded path strings.
//!
//! Tier-2 of the recognizer architecture. Zero dependency on `@polkadot/api`
//! or its `PortableRegistry.PATHS_ALIAS` path-trust assumption.
//!
//! ## How recognition works
//!
//! 1. The chain anchors a per-role canonical fingerprint in
//!    `WellKnownTypeFingerprints` at genesis. The runtime-upgrade gate
//!    ensures these can never silently change shape.
//! 2. This client fetches the chain's metadata (`PortableRegistry`) and the
//!    fingerprint map (`WellKnownTypeFingerprints`).
//! 3. For each metadata type, the client uses the type's path as a *hint*
//!    (e.g., `sp_core::crypto::AccountId32` → guess `Account`).
//! 4. The hint is *verified* by recomputing the fingerprint from the type's
//!    structural canonical_def + the hinted role + version, and comparing
//!    against the on-chain entry.
//! 5. If the fingerprint matches, the metadata type is canonically that
//!    role. If it doesn't, the path-claim is unauthenticated and we fall
//!    back to generic SCALE decoding.
//!
//! Forged metadata that points the same role at a differently-shaped type
//! cannot pass — the structural fingerprint diverges.
//!
//! ## v1 scope
//!
//! - Canonicalization + fingerprint + recognition for the seven v0
//!   well-known roles, with canonical_defs derived at compile time from
//!   real `scale_info::TypeInfo` (see `rostro-canonicalize/build.rs`).
//! - WebSocket JSON-RPC + `state_getMetadata` + on-chain fingerprint map
//!   reads + `Recognizer` orchestration.

mod recognizer;
mod role;
mod rpc;
mod storage;
mod storage_query;

#[cfg(test)]
mod tests;

// Re-exports from the shared rostro-canonicalize crate (single source of
// truth for the canonicalize algorithm and the build-time-derived
// canonical_def constants).
pub use rostro_canonicalize::{
	canonical_def, fingerprint, well_known_canonical_defs, well_known_roles, CanonicalizeError,
	FINGERPRINT_VERSION, MAX_CANONICALIZE_DEPTH, V0_WELL_KNOWN_ROLE_DEFS,
};

pub use recognizer::{recognize, Recognition, Recognizer};
pub use role::WellKnownRole;
pub use rpc::{RostroClient, RpcError};
pub use storage::{
	decode_role_from_storage_key, well_known_fingerprints_prefix, PALLET_NAME, STORAGE_NAME,
};
pub use storage_query::{
	build_storage_key, decode_runtime_api_return, decode_storage_value, StorageQueryError,
};
