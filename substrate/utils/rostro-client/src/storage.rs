// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Storage key construction for the on-chain fingerprint map.
//!
//! Substrate storage keys for a `StorageMap` with hasher `Blake2_128Concat`
//! are constructed as:
//!
//! `twox_128(pallet_name) || twox_128(storage_name) || blake2_128(encoded_key) || encoded_key`
//!
//! Reading the map remotely:
//! - Use the 32-byte `pallet || storage` prefix with `state_getKeysPaged` to
//!   enumerate every entry under the map
//! - For each returned key, the trailing bytes after the prefix +
//!   blake2_128 are the SCALE-encoded role marker
//! - Fetch the value with `state_getStorage` against the full key

use sp_core::hashing::twox_128;

/// Pallet name for the on-chain fingerprint registry.
pub const PALLET_NAME: &[u8] = b"RostroTypeRegistry";

/// Storage map name within the pallet.
pub const STORAGE_NAME: &[u8] = b"WellKnownTypeFingerprints";

/// 32-byte storage prefix for `WellKnownTypeFingerprints`. Used with
/// `state_getKeysPaged` to enumerate entries.
pub fn well_known_fingerprints_prefix() -> [u8; 32] {
	let pallet = twox_128(PALLET_NAME);
	let storage = twox_128(STORAGE_NAME);
	let mut out = [0u8; 32];
	out[..16].copy_from_slice(&pallet);
	out[16..].copy_from_slice(&storage);
	out
}

/// Extract the role marker (the original `BoundedVec<u8, ConstU32<32>>`)
/// from a storage key returned by `state_getKeysPaged`.
///
/// The full key layout is:
/// `[16-byte pallet hash][16-byte storage hash][16-byte blake2_128(encoded_key)][SCALE-encoded role bytes]`
///
/// The encoded role is `compact_len ++ raw_bytes`. For the v0 well-known
/// roles (all under 64 bytes), `compact_len` is a single byte equal to
/// `len << 2`.
pub fn decode_role_from_storage_key(key: &[u8]) -> Option<Vec<u8>> {
	// 16 (pallet) + 16 (storage) + 16 (blake2_128) = 48 bytes of prefix,
	// then at minimum 1 byte of compact length.
	if key.len() < 49 {
		return None;
	}
	let body = &key[48..];
	let compact_first = body[0];
	// We only handle compact-mode 0 (single byte; lengths < 64). The v0
	// roles are all ≤ 12 bytes; if a chain spec ever seeds a 64+ byte role
	// we'd need full compact decoding here.
	if compact_first & 0b11 != 0 {
		return None;
	}
	let len = (compact_first >> 2) as usize;
	if body.len() != 1 + len {
		return None;
	}
	Some(body[1..].to_vec())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn well_known_prefix_matches_observed() {
		// Observed value from the live --dev node during Phase 2 v0
		// verification. If this changes, the recognizer's storage reads
		// would silently miss the on-chain map.
		let prefix = well_known_fingerprints_prefix();
		assert_eq!(
			hex::encode(prefix),
			"47fe79cda5b56af5f27a6a2d534b33bb16e2bccb4f40f38c4228b8f4a9f58da0",
		);
	}

	#[test]
	fn decode_role_round_trip() {
		// Construct a synthetic storage key for role b"account" and verify
		// the decoder extracts it back. blake2_128 segment is filler — the
		// decoder doesn't validate it.
		let prefix = well_known_fingerprints_prefix();
		let mut key = Vec::new();
		key.extend_from_slice(&prefix);
		key.extend_from_slice(&[0u8; 16]); // blake2_128 placeholder
		let role = b"account";
		key.push((role.len() as u8) << 2);
		key.extend_from_slice(role);

		assert_eq!(decode_role_from_storage_key(&key), Some(role.to_vec()));
	}

	#[test]
	fn decode_rejects_truncated_key() {
		let short = vec![0u8; 47];
		assert_eq!(decode_role_from_storage_key(&short), None);
	}
}
