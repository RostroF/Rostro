// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Oracle tests pinning every primitive in this crate against
//! `curve25519-dalek` 4.1.
//!
//! These run as `cargo test`-time only; the dev-dep on
//! `curve25519-dalek` never reaches the AIR's no_std production path.
//! The role of this module is to make sure the limb encoding,
//! constants, and (eventually) constraint-side computations match
//! the audited pure-Rust impl byte-for-byte. If ANY constant in
//! `field.rs` drifts, a test here fails and points at the wrong limb.

use crate::field::{
	add, bytes_to_limbs, is_canonical, is_zero, limbs_to_bytes, neg, reduce, sub,
	FIELD_NUM_LIMBS, P_LIMBS, P_MINUS_ONE_LIMBS,
};
use num_bigint::BigUint;
use num_traits::Num;

/// `p = 2^255 - 19` in little-endian bytes, taken from RFC 7748 § 4.1.
/// This is the source-of-truth byte sequence we encode into limbs.
const P_BYTES_LE: [u8; 32] = [
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

#[test]
fn p_limbs_pin_matches_rfc_7748_byte_layout() {
	assert_eq!(
		bytes_to_limbs(&P_BYTES_LE),
		P_LIMBS,
		"P_LIMBS drifted from the RFC 7748 byte layout",
	);
}

#[test]
fn p_minus_one_limbs_pin_is_p_minus_one() {
	let mut p_minus_one_bytes = P_BYTES_LE;
	// Subtract 1 from the LE byte sequence: only the lowest byte is
	// affected because 0xED > 0.
	p_minus_one_bytes[0] = 0xec;
	assert_eq!(
		bytes_to_limbs(&p_minus_one_bytes),
		P_MINUS_ONE_LIMBS,
		"P_MINUS_ONE_LIMBS drifted",
	);
}

#[test]
fn limb_round_trip_preserves_zero() {
	let zero_bytes = [0u8; 32];
	let limbs = bytes_to_limbs(&zero_bytes);
	assert_eq!(limbs, [0u32; FIELD_NUM_LIMBS]);
	assert_eq!(limbs_to_bytes(&limbs), zero_bytes);
}

#[test]
fn limb_round_trip_preserves_arbitrary_bytes() {
	let bytes: [u8; 32] = [
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
		0x10, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99,
	];
	let limbs = bytes_to_limbs(&bytes);
	assert_eq!(limbs_to_bytes(&limbs), bytes);
}

#[test]
fn limb_endianness_is_little() {
	// Specific pin: byte sequence 01 02 03 04 ... = limb[0] = 0x04030201
	// (little-endian). If anyone flips to big-endian, this tells them
	// at which limb the convention diverges.
	let mut bytes = [0u8; 32];
	bytes[0] = 0x01;
	bytes[1] = 0x02;
	bytes[2] = 0x03;
	bytes[3] = 0x04;
	let limbs = bytes_to_limbs(&bytes);
	assert_eq!(limbs[0], 0x0403_0201);
	assert_eq!(limbs[1], 0);
}

#[test]
fn is_canonical_accepts_zero() {
	assert!(is_canonical(&[0u32; FIELD_NUM_LIMBS]));
}

#[test]
fn is_canonical_accepts_one() {
	let mut limbs = [0u32; FIELD_NUM_LIMBS];
	limbs[0] = 1;
	assert!(is_canonical(&limbs));
}

#[test]
fn is_canonical_accepts_p_minus_one() {
	assert!(is_canonical(&P_MINUS_ONE_LIMBS));
}

#[test]
fn is_canonical_rejects_p_exactly() {
	assert!(!is_canonical(&P_LIMBS), "p itself is not canonical (equal-not-less)");
}

#[test]
fn is_canonical_rejects_p_plus_one() {
	let mut limbs = P_LIMBS;
	limbs[0] = limbs[0].wrapping_add(1);
	assert!(!is_canonical(&limbs));
}

#[test]
fn is_canonical_rejects_two_to_255() {
	// 2^255 in LE bytes: high bit of last byte set.
	let mut bytes = [0u8; 32];
	bytes[31] = 0x80;
	let limbs = bytes_to_limbs(&bytes);
	assert!(!is_canonical(&limbs), "2^255 > p, must be rejected");
}

#[test]
fn dalek_field_element_round_trips_through_our_limbs() {
	use curve25519_dalek::scalar::Scalar;

	// Use a Scalar (curve25519-dalek's exposed canonical-byte-form
	// type) as the dalek-side oracle for byte-encoding/decoding. A
	// reduced Scalar's bytes are guaranteed canonical mod l (the
	// scalar field), but for these tests we only care about byte
	// round-tripping through our limb representation, which is
	// agnostic to whether bytes come from base-field or scalar-field
	// values.
	let dalek = Scalar::ONE;
	let bytes = dalek.to_bytes();
	let limbs = bytes_to_limbs(&bytes);
	let back = limbs_to_bytes(&limbs);
	assert_eq!(back, bytes, "limb encoder must round-trip dalek bytes byte-for-byte");
}

#[test]
fn p_minus_one_is_canonical_and_p_is_not() {
	// Most basic distinction: the predicate's job is to draw the line
	// between p-1 (last canonical) and p (first non-canonical). If a
	// future refactor flips the equality direction, this test catches it.
	assert!(is_canonical(&P_MINUS_ONE_LIMBS));
	assert!(!is_canonical(&P_LIMBS));
}

// ─── Modular arithmetic oracle tests (num-bigint reference) ────────────────
//
// num-bigint with explicit modulus `2^255 - 19` is the pure-Rust oracle.
// curve25519-dalek's FieldElement is private (internal type), so it
// can't be used directly for raw field-arithmetic comparison. num-bigint
// is well-audited and gives us byte-for-byte ground truth for `mod p`.

/// `p = 2^255 - 19` as a BigUint, computed from RFC 7748 hex.
fn p_biguint() -> BigUint {
	BigUint::from_str_radix(
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
		16,
	)
	.unwrap()
}

fn limbs_to_biguint(limbs: &[u32; FIELD_NUM_LIMBS]) -> BigUint {
	BigUint::from_bytes_le(&limbs_to_bytes(limbs))
}

fn biguint_to_limbs(v: &BigUint) -> [u32; FIELD_NUM_LIMBS] {
	let mut bytes = v.to_bytes_le();
	bytes.resize(32, 0);
	let mut arr = [0u8; 32];
	arr.copy_from_slice(&bytes[..32]);
	bytes_to_limbs(&arr)
}

use crate::oracle_tests_helpers::random_canonical;

#[test]
fn add_zero_is_identity() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	assert_eq!(add(&P_MINUS_ONE_LIMBS, &zero), P_MINUS_ONE_LIMBS);
	assert_eq!(add(&zero, &P_MINUS_ONE_LIMBS), P_MINUS_ONE_LIMBS);
	assert_eq!(add(&zero, &zero), zero);
}

#[test]
fn add_p_minus_one_plus_one_is_zero() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let result = add(&P_MINUS_ONE_LIMBS, &one);
	assert_eq!(result, [0u32; FIELD_NUM_LIMBS], "(p-1) + 1 mod p must equal 0");
}

#[test]
fn add_p_minus_one_plus_p_minus_one_is_p_minus_two() {
	let result = add(&P_MINUS_ONE_LIMBS, &P_MINUS_ONE_LIMBS);
	// (p - 1) + (p - 1) mod p = 2p - 2 mod p = p - 2.
	let expected: [u32; FIELD_NUM_LIMBS] = {
		let mut limbs = P_LIMBS;
		// Subtract 2 from the lowest limb (no borrow since limb[0] = 0xFFFFFFED >> 1).
		limbs[0] -= 2;
		limbs
	};
	assert_eq!(result, expected);
}

#[test]
fn add_commutative_random() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xdead_beef_cafe_babe);
	for _ in 0..100 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		assert_eq!(add(&a, &b), add(&b, &a), "a + b must equal b + a");
	}
}

#[test]
fn add_matches_bigint_oracle_random() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x1234_5678_9abc_def0);
	let p = p_biguint();
	for _ in 0..200 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let actual = add(&a, &b);
		let a_big = limbs_to_biguint(&a);
		let b_big = limbs_to_biguint(&b);
		let expected_big = (&a_big + &b_big) % &p;
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(actual, expected, "add diverges from bigint oracle\n  a = {:?}\n  b = {:?}", a, b);
		assert!(is_canonical(&actual), "add output not canonical");
	}
}

#[test]
fn sub_self_is_zero() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x0123_4567_89ab_cdef);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		assert_eq!(sub(&a, &a), [0u32; FIELD_NUM_LIMBS]);
	}
}

#[test]
fn sub_zero_is_identity() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xfedc_ba98_7654_3210);
	let zero = [0u32; FIELD_NUM_LIMBS];
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		assert_eq!(sub(&a, &zero), a);
	}
}

#[test]
fn sub_zero_minus_one_is_p_minus_one() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	assert_eq!(sub(&zero, &one), P_MINUS_ONE_LIMBS);
}

#[test]
fn sub_matches_bigint_oracle_random() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xaaaa_bbbb_cccc_dddd);
	let p = p_biguint();
	for _ in 0..200 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let actual = sub(&a, &b);
		let a_big = limbs_to_biguint(&a);
		let b_big = limbs_to_biguint(&b);
		// num-bigint won't subtract directly if a < b — use the
		// (p + a - b) % p formula explicitly.
		let expected_big = ((&a_big + &p) - &b_big) % &p;
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(actual, expected, "sub diverges from bigint oracle\n  a = {:?}\n  b = {:?}", a, b);
		assert!(is_canonical(&actual), "sub output not canonical");
	}
}

#[test]
fn add_then_sub_round_trips() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x1111_2222_3333_4444);
	for _ in 0..100 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		// (a + b) - b == a (mod p)
		let sum = add(&a, &b);
		let back = sub(&sum, &b);
		assert_eq!(back, a, "(a + b) - b round-trip failed");
		// (a - b) + b == a (mod p)
		let diff = sub(&a, &b);
		let restored = add(&diff, &b);
		assert_eq!(restored, a, "(a - b) + b round-trip failed");
	}
}

#[test]
fn neg_zero_is_zero() {
	assert_eq!(neg(&[0u32; FIELD_NUM_LIMBS]), [0u32; FIELD_NUM_LIMBS]);
}

#[test]
fn neg_one_is_p_minus_one() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	assert_eq!(neg(&one), P_MINUS_ONE_LIMBS);
}

#[test]
fn neg_plus_value_is_zero_random() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x5555_6666_7777_8888);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		let neg_a = neg(&a);
		assert_eq!(add(&a, &neg_a), [0u32; FIELD_NUM_LIMBS], "a + (-a) must be zero");
	}
}

#[test]
fn reduce_already_canonical_is_identity() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x9999_aaaa_bbbb_cccc);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		assert_eq!(reduce(&a), a);
	}
}

#[test]
fn reduce_p_is_zero() {
	assert_eq!(reduce(&P_LIMBS), [0u32; FIELD_NUM_LIMBS]);
}

#[test]
fn is_zero_pin() {
	assert!(is_zero(&[0u32; FIELD_NUM_LIMBS]));
	assert!(!is_zero(&P_MINUS_ONE_LIMBS));
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	assert!(!is_zero(&one));
}
