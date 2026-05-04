// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Fingerprint computation. Mirrors `pallet-rostro-type-registry::fingerprint`
//! byte-for-byte — both ends of the recognition path must produce identical
//! hashes for any matching `(canonical_def, role, version)` triple.

use sp_core::hashing::blake2_256;

/// Fingerprint format version. Bumped when the canonical_def grammar
/// changes. v0 ships at 1, matching the on-chain pallet.
pub const FINGERPRINT_VERSION: u32 = 1;

/// Compute the canonical type fingerprint.
///
/// `blake2_256(canonical_def_bytes ‖ b':' ‖ role ‖ b':' ‖ version_u32_le)`
///
/// Identical construction to `pallet_rostro_type_registry::fingerprint`. The
/// recognizer compares the result against the on-chain
/// `WellKnownTypeFingerprints` map.
pub fn fingerprint(canonical_def: &[u8], role: &[u8], version: u32) -> [u8; 32] {
	let mut buf = Vec::with_capacity(canonical_def.len() + role.len() + 6);
	buf.extend_from_slice(canonical_def);
	buf.push(b':');
	buf.extend_from_slice(role);
	buf.push(b':');
	buf.extend_from_slice(&version.to_le_bytes());
	blake2_256(&buf)
}
