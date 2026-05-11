// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-hash-to-field-air
//!
//! Hash-to-field for `F_p25519` per RFC 9380 §5.3 (RO mode for
//! Edwards25519, count=2, m=1, L=48 bytes), with the SHA-512–based
//! `expand_message_xmd` substituted by a Goldilocks-Poseidon2 sponge call.
//! The substitution is documented in the suite ID embedded in [`DST`].
//!
//! ## Inputs and outputs
//!
//! - **Input:** a single Goldilocks field element (typically the OPRF
//!   `private_nullifier = Poseidon2(packed_dg1 || packed_e_content || packed_sod_sig)`
//!   per [`pop_zkpassport_oprf_pattern.md`](../../../../home/coder/.claude/projects/-home-coder-Rostro/memory/pop_zkpassport_oprf_pattern.md)).
//! - **Output:** `(u_0, u_1) ∈ F_p25519²`, each as `[u32; 8]` little-endian
//!   limbs. These are the two field elements consumed by Hash2Curve in RO
//!   mode for Edwards25519.
//!
//! ## Pipeline (per `u_i`)
//!
//! 1. Initialise a width-8 sponge state:
//!    `state[0] = private_nullifier`, `state[1] = counter` (0 for `u_0`, 1
//!    for `u_1`), `state[2..8] = DST_chunks` (6 Goldilocks limbs holding
//!    `DST` zero-padded to 48 bytes, LE-packed 8 bytes per limb).
//! 2. Apply one Poseidon2 permutation
//!    ([`rostro_poseidon_sponge_air::poseidon2_sponge_8`]).
//! 3. Squeeze `output[0..6]` as 6 Goldilocks limbs → 48 bytes (LE) → a
//!    384-bit unsigned integer `w_i`. Goldilocks limb is < `2^64 - 2^32 + 1`,
//!    so `w_i < (2^64 - 2^32 + 1)^6 < 2^384` with bias to ideal-uniform
//!    bounded by `< 2^-128` after reduction mod `p25519` — within RFC k=128.
//! 4. Barrett-reduce `w_i mod (2^255 - 19)`; output as `[u32; 8]` limbs.
//!
//! ## DST
//!
//! [`DST`] is `"ROSTRO-V01-CS02-edwards25519_POS2_ELL2_RO_"` (42 bytes,
//! padded to 48 with zeros). Format follows RFC 9380 §3.1:
//! `<protocol>-<version>-CS<n>-<curve>_<expand>_<map>_<RO|NU>_`. The `POS2`
//! token records the Poseidon2 substitution for `expand_message`.
//! **Locking decision:** changing `DST` invalidates all stored nullifiers,
//! so `CS02` must be incremented for any future re-tune.
//!
//! ## What this crate is NOT
//!
//! - The AIR for hash-to-field is forthcoming (phase H5). This crate
//!   currently exports only the witness function + DST helpers.
//! - Multi-block input absorption (e.g., long messages) is intentionally
//!   out of scope. The OPRF input is one Goldilocks element by construction.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use num_bigint::BigUint;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use rostro_curve25519::field::FIELD_NUM_LIMBS;
use rostro_poseidon_sponge_air::poseidon2_sponge_8;

/// Domain Separation Tag, RFC 9380 §3.1 conformant. 42 bytes; padded to 48
/// when packed into the sponge input. Locked.
pub const DST: &[u8] = b"ROSTRO-V01-CS02-edwards25519_POS2_ELL2_RO_";

/// Counter byte selecting the first hash-to-field output, `u_0`.
pub const COUNTER_U0: u64 = 0;
/// Counter byte selecting the second hash-to-field output, `u_1`.
pub const COUNTER_U1: u64 = 1;

/// Number of Goldilocks limbs in the sponge state (= `WIDTH = 8`).
pub const SPONGE_WIDTH: usize = 8;
/// Number of Goldilocks limbs squeezed per call (= rate; first `SQUEEZE_LIMBS`
/// of the post-permutation state).
pub const SQUEEZE_LIMBS: usize = 6;
/// `L` per RFC 9380 §5.3 for Edwards25519 with k=128: `ceil((255+128)/8) = 48`.
pub const L_BYTES: usize = 48;

/// Pack [`DST`] into 6 Goldilocks limbs, LE-encoded 8 bytes per limb,
/// zero-padded to 48 bytes total.
pub fn dst_packed() -> [Goldilocks; SQUEEZE_LIMBS] {
	let mut padded = [0u8; L_BYTES];
	let len = DST.len().min(L_BYTES);
	padded[..len].copy_from_slice(&DST[..len]);
	core::array::from_fn(|i| {
		let mut chunk = [0u8; 8];
		chunk.copy_from_slice(&padded[i * 8..(i + 1) * 8]);
		Goldilocks::from_u64(u64::from_le_bytes(chunk))
	})
}

/// Hash a Goldilocks field element to two `F_p25519` elements per RFC 9380
/// RO mode (count=2, m=1) for Edwards25519, with Poseidon2 in place of
/// `expand_message_xmd`. Returns `(u_0, u_1)` each as 8 u32 limbs in
/// little-endian order; both are canonical (< `p25519`).
pub fn hash_to_field(
	private_nullifier: Goldilocks,
) -> ([u32; FIELD_NUM_LIMBS], [u32; FIELD_NUM_LIMBS]) {
	let dst = dst_packed();
	let u_0 = hash_to_field_one(private_nullifier, COUNTER_U0, &dst);
	let u_1 = hash_to_field_one(private_nullifier, COUNTER_U1, &dst);
	(u_0, u_1)
}

/// Inner — one sponge call + Barrett reduction. Visible to the AIR-side
/// trace builder (forthcoming) so witness and AIR can share the per-call
/// flow.
pub fn hash_to_field_one(
	private_nullifier: Goldilocks,
	counter: u64,
	dst: &[Goldilocks; SQUEEZE_LIMBS],
) -> [u32; FIELD_NUM_LIMBS] {
	let mut input = [Goldilocks::ZERO; SPONGE_WIDTH];
	input[0] = private_nullifier;
	input[1] = Goldilocks::from_u64(counter);
	for i in 0..SQUEEZE_LIMBS {
		input[2 + i] = dst[i];
	}

	let output = poseidon2_sponge_8(input);

	let mut bytes = [0u8; L_BYTES];
	for i in 0..SQUEEZE_LIMBS {
		let val = output[i].as_canonical_u64();
		bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
	}

	barrett_reduce_48_to_p25519(&bytes)
}

/// Reduce a 48-byte little-endian unsigned integer mod `p25519 = 2^255 - 19`,
/// returning 8 u32 LE limbs.
pub fn barrett_reduce_48_to_p25519(bytes: &[u8; L_BYTES]) -> [u32; FIELD_NUM_LIMBS] {
	let w = BigUint::from_bytes_le(bytes);
	let p = p25519_biguint();
	let reduced = w % &p;
	biguint_to_limbs_8(&reduced)
}

/// `p25519` as a [`BigUint`]: `2^255 - 19`.
pub fn p25519_biguint() -> BigUint {
	(BigUint::from(1u32) << 255) - BigUint::from(19u32)
}

/// Convert a [`BigUint`] in `[0, p25519)` to 8 u32 LE limbs.
fn biguint_to_limbs_8(v: &BigUint) -> [u32; FIELD_NUM_LIMBS] {
	let bytes_le: Vec<u8> = v.to_bytes_le();
	let mut padded = [0u8; 32];
	let take = bytes_le.len().min(32);
	padded[..take].copy_from_slice(&bytes_le[..take]);
	core::array::from_fn(|i| {
		let mut chunk = [0u8; 4];
		chunk.copy_from_slice(&padded[i * 4..(i + 1) * 4]);
		u32::from_le_bytes(chunk)
	})
}

pub mod reduce_384;
pub mod reduce_384_air;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod reduce_384_air_tests;
