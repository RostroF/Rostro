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
	add, bytes_to_limbs, inv, is_canonical, is_negative, is_zero, limbs_to_bytes, mul, neg,
	pow_p_minus_5_div_8, reduce, sqrt_ratio_m1, square, sub, FIELD_NUM_LIMBS, P_LIMBS,
	P_MINUS_ONE_LIMBS, SQRT_M1_LIMBS,
};
use num_bigint::BigUint;
use num_traits::Num;
use rand::SeedableRng;

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

// ─── Debug-asserts: arithmetic rejects non-canonical inputs ──────────────────
//
// The witness-side arithmetic functions document a "caller must pass
// canonical inputs" contract. In debug builds (= cargo test) the contract
// is enforced via debug_assert!; in release the asserts compile out so
// production callers (oracle tests, AIR trace builders) pay no cost.
// Tests pin each of the six entry points so a future refactor that
// removes an assert fails CI loud rather than silently widening the
// caller contract.

#[test]
#[should_panic(expected = "field::add called with non-canonical a")]
#[cfg(debug_assertions)]
fn add_debug_asserts_canonical_a() {
	let _ = add(&P_LIMBS, &[0u32; FIELD_NUM_LIMBS]);
}

#[test]
#[should_panic(expected = "field::sub called with non-canonical b")]
#[cfg(debug_assertions)]
fn sub_debug_asserts_canonical_b() {
	let mut not_canon = P_LIMBS;
	not_canon[0] = not_canon[0].wrapping_add(1); // p + 1
	let _ = sub(&[0u32; FIELD_NUM_LIMBS], &not_canon);
}

#[test]
#[should_panic(expected = "field::mul called with non-canonical")]
#[cfg(debug_assertions)]
fn mul_debug_asserts_canonical_inputs() {
	let _ = mul(&P_LIMBS, &P_LIMBS);
}

#[test]
#[should_panic(expected = "field::square called with non-canonical")]
#[cfg(debug_assertions)]
fn square_debug_asserts_canonical_input() {
	let _ = crate::field::square(&P_LIMBS);
}

#[test]
#[should_panic(expected = "field::neg called with non-canonical")]
#[cfg(debug_assertions)]
fn neg_debug_asserts_canonical_input() {
	let _ = neg(&P_LIMBS);
}

#[test]
#[should_panic(expected = "field::inv called with non-canonical")]
#[cfg(debug_assertions)]
fn inv_debug_asserts_canonical_input() {
	let _ = inv(&P_LIMBS);
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

// ─── Modular multiplication / squaring / inversion oracle tests ────────────

#[test]
fn mul_zero_is_zero() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x4040_5050_6060_7070);
	let zero = [0u32; FIELD_NUM_LIMBS];
	for _ in 0..20 {
		let a = random_canonical(&mut rng);
		assert_eq!(mul(&a, &zero), zero, "a * 0 == 0");
		assert_eq!(mul(&zero, &a), zero, "0 * a == 0");
	}
}

#[test]
fn mul_one_is_identity() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x9090_a0a0_b0b0_c0c0);
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	for _ in 0..20 {
		let a = random_canonical(&mut rng);
		assert_eq!(mul(&a, &one), a, "a * 1 == a");
		assert_eq!(mul(&one, &a), a, "1 * a == a");
	}
}

#[test]
fn mul_commutative_random() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xd0d0_e0e0_f0f0_0101);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		assert_eq!(mul(&a, &b), mul(&b, &a), "a * b == b * a");
	}
}

#[test]
fn mul_matches_bigint_oracle_random() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x1357_2468_aceb_df02);
	let p = p_biguint();
	for _ in 0..100 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let actual = mul(&a, &b);
		let a_big = limbs_to_biguint(&a);
		let b_big = limbs_to_biguint(&b);
		let expected_big = (&a_big * &b_big) % &p;
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(actual, expected, "mul diverges from bigint oracle");
		assert!(is_canonical(&actual), "mul output not canonical");
	}
}

#[test]
fn mul_distributive_over_add_random() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x7777_8888_9999_aaaa);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		let b = random_canonical(&mut rng);
		let c = random_canonical(&mut rng);
		// a * (b + c) == a*b + a*c (mod p)
		let lhs = mul(&a, &add(&b, &c));
		let rhs = add(&mul(&a, &b), &mul(&a, &c));
		assert_eq!(lhs, rhs, "distributive law violated");
	}
}

#[test]
fn square_matches_self_mul() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xbbbb_cccc_dddd_eeee);
	for _ in 0..50 {
		let a = random_canonical(&mut rng);
		assert_eq!(square(&a), mul(&a, &a), "square != mul-with-self");
	}
}

#[test]
fn inv_of_zero_is_zero() {
	// Documented behavior: inv(0) returns 0 (no inverse exists).
	assert_eq!(inv(&[0u32; FIELD_NUM_LIMBS]), [0u32; FIELD_NUM_LIMBS]);
}

#[test]
fn inv_of_one_is_one() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	assert_eq!(inv(&one), one, "inv(1) == 1");
}

#[test]
fn inv_times_v_is_one_random() {
	use rand::SeedableRng;
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xffff_eeee_dddd_cccc);
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	// 20 random non-zero values; verify v * inv(v) == 1 (mod p).
	for _ in 0..20 {
		let v = random_canonical(&mut rng);
		if is_zero(&v) {
			continue; // skip the negligible-probability zero draw
		}
		let v_inv = inv(&v);
		let product = mul(&v, &v_inv);
		assert_eq!(product, one, "v * inv(v) != 1 mod p");
	}
}

#[test]
fn inv_matches_bigint_oracle_random() {
	use num_bigint::BigUint;
	use rand::SeedableRng;

	let mut rng = rand::rngs::StdRng::seed_from_u64(0xeeee_ffff_0000_1111);
	let p = p_biguint();
	let p_minus_two = &p - BigUint::from(2u32);
	for _ in 0..10 {
		// Fewer iterations: inv is O(255 * mul) = O(255 * 8^2) = slow
		// at the oracle level.
		let v = random_canonical(&mut rng);
		if is_zero(&v) {
			continue;
		}
		let actual = inv(&v);
		let v_big = limbs_to_biguint(&v);
		// num-bigint inv via modpow(p - 2, p).
		let expected_big = v_big.modpow(&p_minus_two, &p);
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(actual, expected, "inv diverges from bigint oracle");
		assert!(is_canonical(&actual));
		// Sanity: v * actual == 1.
		let mut one = [0u32; FIELD_NUM_LIMBS];
		one[0] = 1;
		assert_eq!(mul(&v, &actual), one);
	}
}

// ─── sqrt_ratio_m1 + supporting primitives ────────────────────────────────

#[test]
fn sqrt_m1_squared_equals_minus_one() {
	// SQRT_M1² mod p == p - 1 ≡ -1 mod p.
	let squared = square(&SQRT_M1_LIMBS);
	assert_eq!(squared, P_MINUS_ONE_LIMBS, "SQRT_M1² must be p - 1");
}

#[test]
fn sqrt_m1_is_canonical() {
	assert!(is_canonical(&SQRT_M1_LIMBS), "SQRT_M1 must be in [0, p)");
}

#[test]
fn pow_p_minus_5_div_8_matches_bigint_oracle() {
	// (p - 5) / 8 = 2^252 - 3.
	let p = p_biguint();
	let exp = (&p - BigUint::from(5u8)) / BigUint::from(8u8);
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xd00d_face_face_d00d);
	for _ in 0..10 {
		let v = random_canonical(&mut rng);
		let actual = pow_p_minus_5_div_8(&v);
		let v_big = limbs_to_biguint(&v);
		let expected_big = v_big.modpow(&exp, &p);
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(actual, expected, "pow_p_minus_5_div_8 diverges from bigint oracle");
	}
}

#[test]
fn pow_p_minus_5_div_8_zero_is_zero() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let actual = pow_p_minus_5_div_8(&zero);
	assert_eq!(actual, zero);
}

#[test]
fn pow_p_minus_5_div_8_one_is_one() {
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let actual = pow_p_minus_5_div_8(&one);
	assert_eq!(actual, one);
}

/// Bigint oracle: compute the unique non-negative (LSB = 0) square root
/// of `target` mod p, if it exists. Returns `None` if `target` is a
/// non-square. Uses the closed form for p ≡ 5 mod 8.
fn sqrt_oracle(target: &BigUint) -> Option<BigUint> {
	let p = p_biguint();
	if target.modpow(&((&p - BigUint::from(1u8)) / BigUint::from(2u8)), &p)
		!= BigUint::from(1u8) && *target != BigUint::from(0u8)
	{
		return None;
	}
	// For p ≡ 5 mod 8: candidate = target^((p+3)/8); if candidate² == target, use it.
	// Else if candidate² == -target, multiply by √-1.
	let cand = target.modpow(&((&p + BigUint::from(3u8)) / BigUint::from(8u8)), &p);
	let cand_sq = (&cand * &cand) % &p;
	let mut r = if &cand_sq == target {
		cand
	} else {
		let i = limbs_to_biguint(&SQRT_M1_LIMBS);
		(&cand * &i) % &p
	};
	// Normalize sign: pick the root with LSB = 0.
	if &r % BigUint::from(2u8) == BigUint::from(1u8) {
		r = (&p - &r) % &p;
	}
	Some(r)
}

#[test]
fn sqrt_ratio_m1_of_a_square_matches_oracle() {
	// For random x, set u = x², v = 1: sqrt_ratio_m1 should return
	// (true, ±x), with ±x chosen by the LSB-positive convention.
	let mut rng = rand::rngs::StdRng::seed_from_u64(0x5151_face_5151_face);
	for _ in 0..10 {
		let x = random_canonical(&mut rng);
		let u = square(&x);
		let mut v = [0u32; FIELD_NUM_LIMBS];
		v[0] = 1;
		let (ok, r) = sqrt_ratio_m1(&u, &v);
		assert!(ok, "x² is always a square");
		assert!(!is_negative(&r), "sqrt_ratio_m1 must return the LSB-positive root");
		// r² must equal x² == u.
		assert_eq!(square(&r), u, "(sqrt(x²))² must equal x²");
	}
}

#[test]
fn sqrt_ratio_m1_ratio_form_matches_oracle() {
	// For random u, v (v ≠ 0): r² · v should equal u (when u/v is a
	// square). Compare against the bigint oracle.
	let p = p_biguint();
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xface_0001_5151_d00d);
	for _ in 0..20 {
		let u = random_canonical(&mut rng);
		let v = random_canonical(&mut rng);
		if is_zero(&v) {
			continue;
		}
		let u_big = limbs_to_biguint(&u);
		let v_big = limbs_to_biguint(&v);
		let v_inv = v_big.modpow(&(&p - BigUint::from(2u8)), &p);
		let target = (&u_big * &v_inv) % &p;
		let oracle = sqrt_oracle(&target);

		let (ok, r) = sqrt_ratio_m1(&u, &v);
		match (oracle, ok) {
			(Some(expected_big), true) => {
				let expected = biguint_to_limbs(&expected_big);
				assert_eq!(r, expected, "sqrt result diverges from bigint oracle");
			},
			(None, false) => {
				// Both agree: u/v is a non-square. The returned `r` is
				// the fallback; don't constrain its value.
			},
			(Some(_), false) => panic!("sqrt_ratio_m1 reported non-square for an actual square"),
			(None, true) => panic!("sqrt_ratio_m1 reported square for an actual non-square"),
		}
	}
}

#[test]
fn sqrt_ratio_m1_of_zero_over_anything_is_zero() {
	let zero = [0u32; FIELD_NUM_LIMBS];
	let mut rng = rand::rngs::StdRng::seed_from_u64(0xabcd_1234_5678_face);
	for _ in 0..5 {
		let v = random_canonical(&mut rng);
		if is_zero(&v) {
			continue;
		}
		let (ok, r) = sqrt_ratio_m1(&zero, &v);
		assert!(ok, "0/v is a square (= 0)");
		assert_eq!(r, zero, "sqrt(0/v) must be 0");
	}
}

#[test]
fn sqrt_ratio_m1_one_over_one_picks_canonical_positive_root() {
	// sqrt(1/1) has two roots: 1 and p-1. The Ristretto convention picks
	// the LSB-zero one. 1 has LSB=1 (so is_negative=true), p-1 has low
	// byte 0xEC (LSB=0, is_negative=false) — so the canonical positive
	// root is p-1.
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let (ok, r) = sqrt_ratio_m1(&one, &one);
	assert!(ok);
	assert_eq!(r, P_MINUS_ONE_LIMBS, "canonical sqrt(1) must be p-1, not 1");
	// And: r² == 1 (the input).
	assert_eq!(square(&r), one);
}

#[test]
fn sqrt_ratio_m1_non_square_returns_false() {
	// A known non-square: 2 is a non-square mod p (verify with bigint
	// Euler's criterion, then check our function reports it).
	let p = p_biguint();
	let two = BigUint::from(2u8);
	let euler = two.modpow(&((&p - BigUint::from(1u8)) / BigUint::from(2u8)), &p);
	assert_ne!(euler, BigUint::from(1u8), "2 should be a non-square mod p");

	let mut u = [0u32; FIELD_NUM_LIMBS];
	u[0] = 2;
	let mut v = [0u32; FIELD_NUM_LIMBS];
	v[0] = 1;
	let (ok, _r) = sqrt_ratio_m1(&u, &v);
	assert!(!ok, "sqrt_ratio_m1 must report 2 as a non-square");
}

#[test]
fn is_negative_pin() {
	let mut even = [0u32; FIELD_NUM_LIMBS];
	even[0] = 2;
	assert!(!is_negative(&even));
	let mut odd = [0u32; FIELD_NUM_LIMBS];
	odd[0] = 1;
	assert!(is_negative(&odd));
	// p - 1 has low byte 0xEC, which is even — so p - 1 is NOT "negative".
	assert!(!is_negative(&P_MINUS_ONE_LIMBS));
}
