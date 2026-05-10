// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Curve25519 base-field arithmetic (`F_p`, `p = 2^255 - 19`) as a
//! non-native foreign field over Goldilocks.
//!
//! ## Representation
//!
//! Per the locked Goldilocks packing convention
//! (`pop_air_goldilocks_packing_convention.md`), each Goldilocks
//! trace cell holds at most one u32. A Curve25519 base-field element
//! is therefore encoded as **8 × u32 limbs, little-endian**:
//!
//! ```text
//!   value = limb[0] + limb[1]·2^32 + limb[2]·2^64 + ... + limb[7]·2^224
//! ```
//!
//! This is the EXACT representation used in trace columns. A future
//! Edwards25519 point AIR reserves 8 trace columns per coordinate (32
//! per point in extended (X, Y, Z, T) form) plus the working
//! intermediates for each operation.
//!
//! ## Why u32 limbs and not u51 / u64
//!
//! `curve25519-dalek` uses 5 × u51 limbs (radix-51) for fast multiply
//! by exploiting 64-bit machine words. We can't: Goldilocks elements
//! safely hold u32-shaped values but a u64 (or any value > 2^32) risks
//! mod-p wraparound for some byte patterns (the silent-soundness-break
//! footgun the packing convention was locked to prevent). u32 limbs
//! plus lookup-based range checks (`rostro-range-check`) is the right
//! tradeoff for soundness.
//!
//! ## Status
//!
//! Module scaffold + constants + reference encoder/decoder against
//! `curve25519-dalek`'s `Scalar` and `FieldElement`. Constraint-side
//! AIRs land in subsequent commits.

use alloc::vec::Vec;

/// Number of u32 limbs in a Curve25519 base-field element (256 bits / 32 = 8).
pub const FIELD_NUM_LIMBS: usize = 8;

/// `p = 2^255 - 19`, the Curve25519 base-field prime, encoded as 8 ×
/// little-endian u32 limbs. Pinned at compile time so the constraint
/// constants are auditable directly from this file.
///
/// `p_LE_bytes = ED FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF FF
///               FF FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF 7F`
///
/// limb[0] = 0xFFFFFFED  (least significant)
/// limb[1..=6] = 0xFFFFFFFF
/// limb[7] = 0x7FFFFFFF  (high bit clear: 2^255 - 1 - 18)
pub const P_LIMBS: [u32; FIELD_NUM_LIMBS] = [
	0xFFFF_FFED,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0x7FFF_FFFF,
];

/// `p - 1` as 8 × little-endian u32 limbs. Used for canonical-form
/// rejection (a value v is in canonical form iff v < p ≡ v ≤ p - 1).
pub const P_MINUS_ONE_LIMBS: [u32; FIELD_NUM_LIMBS] = [
	0xFFFF_FFEC, // 0xFFFF_FFED - 1
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0x7FFF_FFFF,
];

/// Encode a 32-byte little-endian field element into 8 u32 limbs (LE).
/// Pure deterministic byte→limb conversion; not constraint-side.
#[inline]
pub fn bytes_to_limbs(bytes: &[u8; 32]) -> [u32; FIELD_NUM_LIMBS] {
	let mut limbs = [0u32; FIELD_NUM_LIMBS];
	for (i, chunk) in bytes.chunks_exact(4).enumerate() {
		limbs[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
	}
	limbs
}

/// Inverse of [`bytes_to_limbs`].
#[inline]
pub fn limbs_to_bytes(limbs: &[u32; FIELD_NUM_LIMBS]) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	for (i, limb) in limbs.iter().enumerate() {
		let lb = limb.to_le_bytes();
		bytes[i * 4..(i + 1) * 4].copy_from_slice(&lb);
	}
	bytes
}

/// Test whether a limb representation is in canonical form, i.e.,
/// strictly less than `p`. Pure-Rust (oracle/witness side); the AIR's
/// canonical-form constraint enforces the same predicate via subtraction
/// + range checks.
///
/// Returns `true` iff `value < p`.
pub fn is_canonical(limbs: &[u32; FIELD_NUM_LIMBS]) -> bool {
	// Compare from most significant limb downward.
	for i in (0..FIELD_NUM_LIMBS).rev() {
		match limbs[i].cmp(&P_LIMBS[i]) {
			core::cmp::Ordering::Less => return true,
			core::cmp::Ordering::Greater => return false,
			core::cmp::Ordering::Equal => {}
		}
	}
	// limbs == p exactly → not canonical (equal not less).
	false
}

/// Convenience: pack a list of u32 limbs into a `Vec<u32>` for use in
/// trace builders. Non-circuit; just buffer plumbing.
pub fn limbs_to_vec(limbs: &[u32; FIELD_NUM_LIMBS]) -> Vec<u32> {
	limbs.to_vec()
}
