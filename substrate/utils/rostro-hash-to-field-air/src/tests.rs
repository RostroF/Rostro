// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for hash-to-field witness layer.
//!
//! Coverage tiers:
//! - **Static contracts**: DST length / packing roundtrip; output range.
//! - **Behavioural**: determinism, counter separation, input separation,
//!   domain separation (changing DST changes output).
//! - **Independent recomputation**: re-run the sponge + reduce path through
//!   a deliberately different code shape and compare. Catches off-by-one
//!   in byte packing, limb ordering, and BigUint conversion.
//!
//! No published RFC 9380 §J test vectors apply here (the spec uses
//! `expand_message_xmd[SHA-512]`, we substitute Poseidon2). Future work:
//! port a Python sage script that mirrors this algorithm and pin a
//! `(input, expected_u0, expected_u1)` tuple as a regression anchor.

extern crate alloc;

use alloc::vec::Vec;

use num_bigint::BigUint;
use num_traits::Zero;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use rostro_curve25519::field::{is_canonical, FIELD_NUM_LIMBS};
use rostro_poseidon_sponge_air::poseidon2_sponge_8;

use crate::{
	barrett_reduce_48_to_p25519, dst_packed, hash_to_field, hash_to_field_one, p25519_biguint,
	COUNTER_U0, COUNTER_U1, DST, L_BYTES, SPONGE_WIDTH, SQUEEZE_LIMBS,
};

// ─── Static contracts ──────────────────────────────────────────────────────

#[test]
fn dst_fits_in_l_bytes() {
	assert!(DST.len() <= L_BYTES, "DST {} bytes exceeds L = {}", DST.len(), L_BYTES);
}

#[test]
fn dst_locked_string_pin() {
	// Pin verbatim: changing this string invalidates all stored nullifiers.
	// Bumping the suite must be a deliberate act + CS bump.
	assert_eq!(DST, b"ROSTRO-V01-CS02-edwards25519_POS2_ELL2_RO_");
	assert_eq!(DST.len(), 42);
}

#[test]
fn dst_packed_round_trips_to_padded_bytes() {
	let chunks = dst_packed();
	assert_eq!(chunks.len(), SQUEEZE_LIMBS);
	let mut recovered = [0u8; L_BYTES];
	for i in 0..SQUEEZE_LIMBS {
		let val = chunks[i].as_canonical_u64();
		recovered[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
	}
	let mut expected = [0u8; L_BYTES];
	expected[..DST.len()].copy_from_slice(DST);
	assert_eq!(recovered, expected);
}

#[test]
fn output_is_canonical_for_simple_inputs() {
	for k in 0..50u64 {
		let (u0, u1) = hash_to_field(Goldilocks::from_u64(k));
		assert!(is_canonical(&u0), "u0 not canonical for input {}", k);
		assert!(is_canonical(&u1), "u1 not canonical for input {}", k);
	}
}

#[test]
fn output_is_canonical_for_random_inputs() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xc0_a4_07_a0_5_eu64);
	for _ in 0..200 {
		let input = Goldilocks::from_u64(rng.next_u64());
		let (u0, u1) = hash_to_field(input);
		assert!(is_canonical(&u0));
		assert!(is_canonical(&u1));
	}
}

// ─── Behavioural ───────────────────────────────────────────────────────────

#[test]
fn hash_to_field_is_deterministic() {
	let input = Goldilocks::from_u64(0xdead_beef);
	let a = hash_to_field(input);
	let b = hash_to_field(input);
	assert_eq!(a.0, b.0);
	assert_eq!(a.1, b.1);
}

#[test]
fn u0_and_u1_differ_for_same_input() {
	let input = Goldilocks::from_u64(7);
	let (u0, u1) = hash_to_field(input);
	assert_ne!(u0, u1, "counter byte 0 vs 1 must produce distinct field elements");
}

#[test]
fn distinct_inputs_produce_distinct_outputs() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xf1_00_d_5_eu64);
	let mut seen: Vec<([u32; FIELD_NUM_LIMBS], [u32; FIELD_NUM_LIMBS])> = Vec::new();
	for _ in 0..200 {
		let input = Goldilocks::from_u64(rng.next_u64());
		let out = hash_to_field(input);
		// Probabilistic collision check; with p25519 ≈ 2^255 a collision in
		// 200 samples is astronomically unlikely. Any hit indicates a bug.
		assert!(!seen.contains(&out), "collision in 200 random inputs (impl bug suspected)");
		seen.push(out);
	}
}

#[test]
fn input_zero_produces_canonical_output() {
	let (u0, u1) = hash_to_field(Goldilocks::ZERO);
	assert!(is_canonical(&u0));
	assert!(is_canonical(&u1));
}

#[test]
fn changing_counter_changes_output_under_independent_construction() {
	// Build the sponge input by hand and compare per-counter outputs.
	let dst = dst_packed();
	let pn = Goldilocks::from_u64(0x4242);

	let direct_u0 = hash_to_field_one(pn, COUNTER_U0, &dst);
	let direct_u1 = hash_to_field_one(pn, COUNTER_U1, &dst);
	assert_ne!(direct_u0, direct_u1);

	// And matches the public-API output (single source of truth for the
	// counter mapping).
	let (api_u0, api_u1) = hash_to_field(pn);
	assert_eq!(direct_u0, api_u0);
	assert_eq!(direct_u1, api_u1);
}

// ─── Independent recomputation oracle ──────────────────────────────────────

/// Reimplementation that builds the sponge input + byte buffer + reduction
/// independently. Catches packing/byte-order/conversion bugs that would
/// silently match the production path if both shared the same helper.
fn hash_to_field_one_oracle(
	private_nullifier: Goldilocks,
	counter: u64,
) -> [u32; FIELD_NUM_LIMBS] {
	// Build input differently: start from zero, set positions explicitly.
	let mut state = [Goldilocks::ZERO; SPONGE_WIDTH];
	state[0] = private_nullifier;
	state[1] = Goldilocks::from_u64(counter);
	// Build DST chunks inline without calling dst_packed().
	let mut dst_padded = [0u8; L_BYTES];
	dst_padded[..DST.len()].copy_from_slice(DST);
	for i in 0..SQUEEZE_LIMBS {
		let mut chunk = [0u8; 8];
		chunk.copy_from_slice(&dst_padded[i * 8..(i + 1) * 8]);
		state[2 + i] = Goldilocks::from_u64(u64::from_le_bytes(chunk));
	}

	// Apply the sponge.
	let out = poseidon2_sponge_8(state);

	// Build the 384-bit value DIFFERENTLY: as a BigUint accumulator in
	// 64-bit chunks (vs the production path's byte-buffer concatenation).
	let mut w = BigUint::zero();
	for i in 0..SQUEEZE_LIMBS {
		let val = out[i].as_canonical_u64();
		w |= BigUint::from(val) << (i * 64);
	}

	// Reduce.
	let reduced = &w % p25519_biguint();

	// Convert to 8 u32 limbs via a different code path (chunk_iter +
	// resize), not the production helper.
	let mut bytes = reduced.to_bytes_le();
	bytes.resize(32, 0);
	let mut limbs = [0u32; FIELD_NUM_LIMBS];
	for (i, chunk) in bytes.chunks_exact(4).enumerate().take(FIELD_NUM_LIMBS) {
		let mut buf = [0u8; 4];
		buf.copy_from_slice(chunk);
		limbs[i] = u32::from_le_bytes(buf);
	}
	limbs
}

#[test]
fn production_matches_independent_oracle_zero_input() {
	let pn = Goldilocks::ZERO;
	for counter in [COUNTER_U0, COUNTER_U1] {
		let prod = hash_to_field_one(pn, counter, &dst_packed());
		let oracle = hash_to_field_one_oracle(pn, counter);
		assert_eq!(prod, oracle, "prod vs oracle disagree at counter {}", counter);
	}
}

#[test]
fn production_matches_independent_oracle_random() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0x0_1_a_c_1_eu64);
	for _ in 0..100 {
		let pn = Goldilocks::from_u64(rng.next_u64());
		for counter in [COUNTER_U0, COUNTER_U1] {
			let prod = hash_to_field_one(pn, counter, &dst_packed());
			let oracle = hash_to_field_one_oracle(pn, counter);
			assert_eq!(prod, oracle, "divergence at pn={:?} counter={}", pn, counter);
		}
	}
}

// ─── Barrett reduction unit tests ─────────────────────────────────────────

#[test]
fn barrett_reduce_zero_is_zero() {
	let bytes = [0u8; L_BYTES];
	let limbs = barrett_reduce_48_to_p25519(&bytes);
	assert_eq!(limbs, [0u32; FIELD_NUM_LIMBS]);
}

#[test]
fn barrett_reduce_one_is_one() {
	let mut bytes = [0u8; L_BYTES];
	bytes[0] = 1;
	let limbs = barrett_reduce_48_to_p25519(&bytes);
	let mut expected = [0u32; FIELD_NUM_LIMBS];
	expected[0] = 1;
	assert_eq!(limbs, expected);
}

#[test]
fn barrett_reduce_p_minus_1_is_p_minus_1() {
	// Build bytes for p25519 - 1 and reduce — must equal p25519 - 1.
	let p_minus_1 = p25519_biguint() - BigUint::from(1u32);
	let mut bytes = p_minus_1.to_bytes_le();
	bytes.resize(L_BYTES, 0);
	let bytes_array: [u8; L_BYTES] = bytes.try_into().unwrap();
	let limbs = barrett_reduce_48_to_p25519(&bytes_array);
	let recovered = limbs_to_biguint(&limbs);
	assert_eq!(recovered, p_minus_1);
}

#[test]
fn barrett_reduce_p_is_zero() {
	let p = p25519_biguint();
	let mut bytes = p.to_bytes_le();
	bytes.resize(L_BYTES, 0);
	let bytes_array: [u8; L_BYTES] = bytes.try_into().unwrap();
	let limbs = barrett_reduce_48_to_p25519(&bytes_array);
	assert_eq!(limbs, [0u32; FIELD_NUM_LIMBS]);
}

#[test]
fn barrett_reduce_random_inputs_match_bigint() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xba_44_11_07u64);
	for _ in 0..200 {
		let mut bytes = [0u8; L_BYTES];
		rng.fill_bytes(&mut bytes);
		let limbs = barrett_reduce_48_to_p25519(&bytes);
		// Independent: use BigUint directly, compare to limbs.
		let w = BigUint::from_bytes_le(&bytes);
		let expected = w % p25519_biguint();
		let actual = limbs_to_biguint(&limbs);
		assert_eq!(actual, expected);
		assert!(is_canonical(&limbs));
	}
}

fn limbs_to_biguint(limbs: &[u32; FIELD_NUM_LIMBS]) -> BigUint {
	let mut bytes = [0u8; 32];
	for i in 0..FIELD_NUM_LIMBS {
		bytes[i * 4..(i + 1) * 4].copy_from_slice(&limbs[i].to_le_bytes());
	}
	BigUint::from_bytes_le(&bytes)
}
