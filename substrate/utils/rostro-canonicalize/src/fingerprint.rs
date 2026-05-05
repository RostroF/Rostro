// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

// Fingerprint computation. Mirrors `pallet-rostro-type-registry::fingerprint`
// byte-for-byte — both ends of the recognition path must produce identical
// hashes for any matching `(canonical_def, role, version)` triple.
//
// Shared between `lib.rs` (via `mod`) and `build.rs` (via `include!`); use
// regular `//` comments only.

use alloc::vec::Vec;
use sp_core::hashing::blake2_256;

/// Fingerprint format version. Bumped when the canonical_def grammar
/// changes. v0/v1 ship at 1.
pub const FINGERPRINT_VERSION: u32 = 1;

/// Compute the canonical type fingerprint.
///
/// `blake2_256(canonical_def_bytes ‖ b':' ‖ role ‖ b':' ‖ version_u32_le)`
pub fn fingerprint(canonical_def: &[u8], role: &[u8], version: u32) -> [u8; 32] {
	let mut buf = Vec::with_capacity(canonical_def.len() + role.len() + 6);
	buf.extend_from_slice(canonical_def);
	buf.push(b':');
	buf.extend_from_slice(role);
	buf.push(b':');
	buf.extend_from_slice(&version.to_le_bytes());
	blake2_256(&buf)
}
