// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-client
//!
//! Native Rostro chain client. Recognizes canonical types by **fingerprint
//! match** against the on-chain `pallet-rostro-type-registry` rather than by
//! hardcoded path strings.
//!
//! This is the Tier-2 piece of the recognizer architecture decided 2026-05-03
//! (see `~/.claude/projects/-home-coder-Rostro/memory/recognizer_architecture_decision.md`).
//! It deliberately has zero dependency on `@polkadot/api` or its
//! `PortableRegistry.PATHS_ALIAS` path-trust assumption.
//!
//! ## How recognition works
//!
//! 1. The chain anchors a per-role canonical fingerprint in
//!    `WellKnownTypeFingerprints` at genesis. The runtime-upgrade gate ensures
//!    these can never silently change shape.
//! 2. This client fetches the chain's metadata (`PortableRegistry`) and the
//!    fingerprint map (`WellKnownTypeFingerprints`).
//! 3. For each metadata type, the client uses the type's path as a *hint* for
//!    which role it might be (e.g., `sp_core::crypto::AccountId32` → guess
//!    `Account`).
//! 4. The hint is *verified* by recomputing the fingerprint from the type's
//!    structural canonical_def + the hinted role + version, and comparing
//!    against the on-chain entry.
//! 5. If the fingerprint matches, the metadata type is canonically that role.
//!    If it doesn't, the path-claim is unauthenticated and we fall back to
//!    generic SCALE decoding.
//!
//! Forged metadata that points the same role at a differently-shaped type
//! cannot pass — the structural fingerprint diverges.
//!
//! ## v0 scope
//!
//! - Pure canonicalization + fingerprint + recognition logic. No network code.
//! - Covers the seven v0 well-known roles seeded by `pallet-rostro-type-registry`.
//! - Network layer (WebSocket JSON-RPC, live storage reads) lands in a
//!   follow-up commit.

use scale_info::{
	form::PortableForm, PortableRegistry, TypeDef, TypeDefPrimitive,
};

mod canonicalize;
mod fingerprint;
mod recognizer;
mod role;

#[cfg(test)]
mod tests;

pub use canonicalize::{canonical_def, CanonicalizeError};
pub use fingerprint::{fingerprint, FINGERPRINT_VERSION};
pub use recognizer::{recognize, Recognition, Recognizer};
pub use role::WellKnownRole;

/// Maximum depth of type-tree recursion the canonicalizer will accept.
/// Prevents adversarial metadata from forcing unbounded recursion.
pub const MAX_CANONICALIZE_DEPTH: u32 = 32;

/// Internal helper: resolve a type id from a registry, returning `None` if
/// the id is missing rather than panicking. Adversarial metadata may carry
/// dangling ids — types prove shape, not validity (per
/// `feedback_input_validation_at_handoffs.md`).
fn resolve<'r>(
	id: u32,
	registry: &'r PortableRegistry,
) -> Option<&'r scale_info::Type<PortableForm>> {
	registry.resolve(id)
}

/// Internal helper: name of a primitive type in the canonical_def grammar.
fn primitive_name(p: &TypeDefPrimitive) -> &'static str {
	use TypeDefPrimitive::*;
	match p {
		Bool => "bool",
		Char => "char",
		Str => "str",
		U8 => "u8",
		U16 => "u16",
		U32 => "u32",
		U64 => "u64",
		U128 => "u128",
		U256 => "u256",
		I8 => "i8",
		I16 => "i16",
		I32 => "i32",
		I64 => "i64",
		I128 => "i128",
		I256 => "i256",
	}
}

/// Internal helper: detect the "newtype wrapper" pattern. A single-field
/// composite (tuple struct or single-named-field struct) is treated as
/// transparent — its canonical_def is the inner type's canonical_def. The
/// role marker carries the semantic distinction.
fn newtype_inner_id(td: &TypeDef<PortableForm>) -> Option<u32> {
	if let TypeDef::Composite(c) = td {
		if c.fields.len() == 1 {
			return Some(c.fields[0].ty.id);
		}
	}
	None
}
