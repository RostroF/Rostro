// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-canonicalize
//!
//! Single source of truth for the recognizer architecture's structural
//! canonicalization + fingerprint hashing. Used by both
//! `pallet-rostro-type-registry` (to seed and gate well-known canonical_defs)
//! and the `rostro-client` recognizer (to verify metadata types at runtime).
//!
//! The shared `canonicalize.rs` and `fingerprint.rs` source files are
//! `include!`d by both `lib.rs` (here, as `mod`) and the build script, so
//! the runtime side and the build-time deriver use identical logic.
//!
//! Constants for the v1 well-known role types are emitted by `build.rs` into
//! `OUT_DIR/well_known_canonical_defs.rs` from real `scale_info::TypeInfo`
//! and re-exported here.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod canonicalize;
mod fingerprint;

pub use canonicalize::{
	canonical_def, newtype_inner_id, primitive_name, CanonicalizeError, MAX_CANONICALIZE_DEPTH,
};
pub use fingerprint::{fingerprint, FINGERPRINT_VERSION};

include!(concat!(env!("OUT_DIR"), "/well_known_canonical_defs.rs"));
