// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for the hash-to-curve composition.
//!
//! Coverage tiers:
//! - **Algebraic**: output is on Edwards25519, cofactor clear matches an
//!   independent ×8 via `point::scalar_mul`.
//! - **Behavioural**: determinism, input separation, output distinct from
//!   identity for varied inputs.
//! - **Pinned regression vectors**: `(private_nullifier, expected_P)`
//!   captured from this Rust witness. Anchor against accidental regressions
//!   in any underlying primitive (DST, sign rule, MDS, scalar mul).

extern crate alloc;

use alloc::vec::Vec;

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use rostro_curve25519::point::{is_on_curve, scalar_mul, EdwardsPoint, SCALAR_NUM_BITS};
use rostro_curve25519::ristretto::compress as ristretto_compress;

use crate::{clear_cofactor, hash_to_curve};

// ─── Algebraic ─────────────────────────────────────────────────────────────

#[test]
fn output_on_curve_for_simple_inputs() {
	for k in 0..50u64 {
		let p = hash_to_curve(Goldilocks::from_u64(k));
		assert!(is_on_curve(&p), "output not on curve for input {}", k);
	}
}

#[test]
fn output_on_curve_for_random_inputs() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xa1_07_0_70u64);
	for _ in 0..200 {
		let pn = Goldilocks::from_u64(rng.next_u64());
		let p = hash_to_curve(pn);
		assert!(is_on_curve(&p), "output not on curve");
	}
}

#[test]
fn clear_cofactor_matches_scalar_mul_by_eight() {
	// For an arbitrary on-curve point P, clear_cofactor(P) must equal 8·P
	// computed via the canonical scalar-mul path. Catches off-by-one in
	// the doubling sequence.
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xc0_fa_c70_8u64);

	// scalar = 8 = bit 3 set
	let mut scalar_bytes = [0u8; SCALAR_NUM_BITS / 8];
	scalar_bytes[0] = 8;

	for _ in 0..20 {
		// Pick a "random" on-curve point by hashing a random Goldilocks
		// element to the curve. This lets us avoid hand-rolling
		// random-point generation.
		let pn = Goldilocks::from_u64(rng.next_u64());
		let p = hash_to_curve(pn);

		// Independent ×8 via scalar_mul.
		let eight_p_via_scalar = scalar_mul(&scalar_bytes, &p);
		// Test target.
		let eight_p_via_doublings = clear_cofactor(&p);

		assert_points_equal(
			&eight_p_via_scalar,
			&eight_p_via_doublings,
			"×8 disagreement",
		);
	}
}

// ─── Behavioural ───────────────────────────────────────────────────────────

#[test]
fn deterministic() {
	let pn = Goldilocks::from_u64(0xdead_beef);
	let a = hash_to_curve(pn);
	let b = hash_to_curve(pn);
	assert_points_equal(&a, &b, "non-deterministic");
}

#[test]
fn distinct_inputs_distinct_outputs() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xd1_5_71_c7u64);
	let mut seen: Vec<[u8; 32]> = Vec::new();
	for _ in 0..200 {
		let pn = Goldilocks::from_u64(rng.next_u64());
		let p = hash_to_curve(pn);
		// Use Ristretto compression as a canonical 32-byte fingerprint
		// (Edwards points have multiple extended-coord representations
		// of the same affine point; Ristretto compresses to a unique tag).
		let tag = ristretto_compress(&p);
		assert!(!seen.contains(&tag), "collision in 200 random inputs");
		seen.push(tag);
	}
}

#[test]
fn input_zero_produces_valid_curve_point() {
	let p = hash_to_curve(Goldilocks::ZERO);
	assert!(is_on_curve(&p), "h2c(0) not on curve");
}

// ─── Pinned regression vectors ─────────────────────────────────────────────
//
// Captured by running the Rust witness function once and recording the
// Ristretto-compressed output. Anchors against any accidental change in
// the underlying primitives (DST, sponge constants, sign convention,
// scalar mul, Elligator2 map, Edwards constants, etc.).
//
// To regenerate after a deliberate change: comment out the assert lines,
// run, copy the printed values, paste back in.

fn pin_vector(input: u64, expected_compressed: [u8; 32]) {
	let pn = Goldilocks::from_u64(input);
	let p = hash_to_curve(pn);
	let actual = ristretto_compress(&p);
	assert_eq!(
		actual, expected_compressed,
		"regression vector mismatch for input={}\nactual = {:02x?}\nexpected = {:02x?}",
		input, actual, expected_compressed,
	);
}

#[test]
fn pinned_vector_input_zero() {
	pin_vector(
		0,
		[
			0xe4, 0x5e, 0x13, 0x78, 0xff, 0x2f, 0x83, 0x72, 0xd6, 0x15, 0xfa, 0x84,
			0x37, 0x16, 0x08, 0x3e, 0xef, 0xcc, 0xec, 0x5d, 0xd9, 0xf2, 0x3b, 0x6e,
			0x2b, 0x04, 0x64, 0xe8, 0xb9, 0x68, 0x78, 0x4b,
		],
	);
}

#[test]
fn pinned_vector_input_one() {
	pin_vector(
		1,
		[
			0xc6, 0xbb, 0x58, 0xf0, 0xea, 0x2b, 0xa3, 0xed, 0x53, 0x96, 0x3b, 0x90,
			0xe1, 0xe8, 0xe0, 0xac, 0xf1, 0xf7, 0xcb, 0x16, 0x90, 0x2e, 0x88, 0x65,
			0x33, 0x01, 0x99, 0xb5, 0x55, 0x9b, 0xd1, 0x70,
		],
	);
}

#[test]
fn pinned_vector_input_dead_beef() {
	pin_vector(
		0xdead_beef,
		[
			0xd2, 0xea, 0xb4, 0x27, 0x9d, 0x41, 0xa2, 0xbf, 0xa4, 0xc6, 0x83, 0xb0,
			0x33, 0xb0, 0xf9, 0x36, 0x7b, 0x6a, 0x3d, 0x2b, 0xfd, 0xbf, 0xcf, 0x4b,
			0x87, 0xc4, 0x3a, 0x61, 0xe2, 0x1b, 0x7a, 0x3d,
		],
	);
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Edwards points have multiple extended-coord representations; compare
/// via Ristretto compression to get a canonical equality.
fn assert_points_equal(a: &EdwardsPoint, b: &EdwardsPoint, msg: &str) {
	let a_tag = ristretto_compress(a);
	let b_tag = ristretto_compress(b);
	assert_eq!(a_tag, b_tag, "{}\na = {:02x?}\nb = {:02x?}", msg, a_tag, b_tag);
}
