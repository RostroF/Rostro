// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Oracle tests for [`crate::point`]: cross-check witness-side
//! Edwards25519 point ops against `curve25519-dalek 4.1`.
//!
//! Strategy:
//! - **Property tests** (no oracle): commutativity, identity,
//!   double == add-self, associativity over random points.
//! - **Dalek bridge** (oracle): start with the standard Ed25519
//!   basepoint (known constant), compute scalar multiples via dalek,
//!   cross-check our `add`/`double` produces points that compress to
//!   the same bytes dalek produces.
//!
//! Compression in this module is the standard Ed25519 encoding:
//! the 32-byte LE encoding of y_affine = Y/Z, with the high bit of
//! byte 31 set to the sign of x_affine = X/Z (sign = low bit).

extern crate alloc;

use alloc::format;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint as DalekEdwards;

use crate::field::{add as field_add, inv, limbs_to_bytes, mul as field_mul, FIELD_NUM_LIMBS};
use crate::point::{add, double, is_on_curve, neutral, EdwardsPoint, ED25519_2D_LIMBS, ED25519_D_LIMBS};

/// Compress one of our `EdwardsPoint`s to the standard 32-byte
/// Edwards25519 encoding. Verifies against `dalek.compress().to_bytes()`
/// in cross-check tests.
fn compress(p: &EdwardsPoint) -> [u8; 32] {
	// Convert to affine: y = Y/Z, x = X/Z.
	let z_inv = inv(&p.z);
	let y_affine = field_mul(&p.y, &z_inv);
	let x_affine = field_mul(&p.x, &z_inv);

	let mut bytes = limbs_to_bytes(&y_affine);
	// Set high bit of byte 31 to the sign of x_affine. RFC 8032 § 5.1.2
	// says: sign = x_affine & 1 (low bit).
	let x_sign = (x_affine[0] & 1) as u8;
	bytes[31] |= x_sign << 7;
	bytes
}

/// Edwards25519 basepoint in extended (X, Y, Z, T) coordinates.
///
/// Standard Ed25519 basepoint from RFC 8032 § 5.1:
/// - y_affine = 4/5 mod p
/// - x_affine = unique non-negative root of the curve equation given y
///
/// Encoded in our 8-u32-LE-limb representation. Cross-checked against
/// dalek's basepoint compression in the basepoint_matches_dalek test.
fn basepoint() -> EdwardsPoint {
	// Affine x: 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
	//   (BE hex from RFC 8032 § 5.1)
	// As LE u32 limbs (low 32 bits first).
	let x: [u32; FIELD_NUM_LIMBS] = [
		0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760, 0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE,
		0x216936D3,
	];
	// Affine y: 0x6666666666666666666666666666666666666666666666666666666666666658
	let y: [u32; FIELD_NUM_LIMBS] = [
		0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666,
		0x66666666,
	];
	// Z = 1.
	let mut z = [0u32; FIELD_NUM_LIMBS];
	z[0] = 1;
	// T = x * y (mod p).
	let t = field_mul(&x, &y);
	EdwardsPoint { x, y, z, t }
}

// ─── Constant-pin tests ────────────────────────────────────────────────────

#[test]
fn ed25519_2d_equals_2_times_d() {
	let computed = field_add(&ED25519_D_LIMBS, &ED25519_D_LIMBS);
	assert_eq!(
		ED25519_2D_LIMBS, computed,
		"ED25519_2D_LIMBS must equal 2 * ED25519_D_LIMBS mod p",
	);
}

// ─── Property tests (no oracle) ────────────────────────────────────────────

#[test]
fn neutral_is_on_curve() {
	assert!(is_on_curve(&neutral()));
}

#[test]
fn basepoint_is_on_curve() {
	assert!(is_on_curve(&basepoint()));
}

#[test]
fn add_with_neutral_is_identity() {
	let bp = basepoint();
	let result = add(&bp, &neutral());
	assert!(is_on_curve(&result));
	// In extended coords, P + O can have different (X, Y, Z, T) than
	// P even though they represent the same affine point. Compare
	// via compression (the canonical form).
	assert_eq!(compress(&result), compress(&bp), "P + neutral should equal P");
}

#[test]
fn neutral_plus_neutral_is_neutral() {
	let result = add(&neutral(), &neutral());
	assert_eq!(compress(&result), compress(&neutral()));
}

#[test]
fn double_neutral_is_neutral() {
	let result = double(&neutral());
	assert_eq!(compress(&result), compress(&neutral()));
}

#[test]
fn double_matches_add_self() {
	// double(P) == add(P, P) for any valid point.
	let bp = basepoint();
	let via_double = double(&bp);
	let via_add = add(&bp, &bp);
	assert!(is_on_curve(&via_double));
	assert!(is_on_curve(&via_add));
	assert_eq!(
		compress(&via_double),
		compress(&via_add),
		"double(P) must compress to the same point as add(P, P)",
	);
}

#[test]
fn add_is_commutative_for_basepoint() {
	let bp = basepoint();
	let bp2 = double(&bp);
	let lhs = add(&bp, &bp2);
	let rhs = add(&bp2, &bp);
	assert_eq!(compress(&lhs), compress(&rhs));
}

#[test]
fn add_is_associative_for_basepoint() {
	let bp = basepoint();
	let bp2 = double(&bp);
	let bp3 = add(&bp2, &bp);
	// (bp + bp2) + bp3 == bp + (bp2 + bp3)
	let lhs_inner = add(&bp, &bp2);
	let lhs = add(&lhs_inner, &bp3);
	let rhs_inner = add(&bp2, &bp3);
	let rhs = add(&bp, &rhs_inner);
	assert_eq!(compress(&lhs), compress(&rhs));
}

// ─── Dalek oracle tests ────────────────────────────────────────────────────

#[test]
fn basepoint_matches_dalek() {
	let our_bytes = compress(&basepoint());
	let dalek_bytes = ED25519_BASEPOINT_POINT.compress().to_bytes();
	assert_eq!(
		our_bytes, dalek_bytes,
		"our basepoint compression must match dalek's:\n  ours:  {:?}\n  dalek: {:?}",
		hex_string(&our_bytes),
		hex_string(&dalek_bytes),
	);
}

#[test]
fn double_basepoint_matches_dalek() {
	let our_2g = double(&basepoint());
	let dalek_2g: DalekEdwards = ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT;
	assert_eq!(
		compress(&our_2g),
		dalek_2g.compress().to_bytes(),
		"our 2·G must match dalek's 2·G",
	);
}

#[test]
fn add_basepoint_plus_double_matches_dalek_3g() {
	let bp = basepoint();
	let bp2 = double(&bp);
	let our_3g = add(&bp, &bp2);
	let dalek_3g = ED25519_BASEPOINT_POINT
		+ ED25519_BASEPOINT_POINT
		+ ED25519_BASEPOINT_POINT;
	assert_eq!(
		compress(&our_3g),
		dalek_3g.compress().to_bytes(),
		"our 3·G must match dalek's 3·G",
	);
}

#[test]
fn quadruple_basepoint_matches_dalek() {
	// 4·G computed two ways:
	// - via our: double(double(G))
	// - via dalek: 4 successive adds
	let bp = basepoint();
	let our_4g = double(&double(&bp));
	let dalek_4g = ED25519_BASEPOINT_POINT
		+ ED25519_BASEPOINT_POINT
		+ ED25519_BASEPOINT_POINT
		+ ED25519_BASEPOINT_POINT;
	assert_eq!(
		compress(&our_4g),
		dalek_4g.compress().to_bytes(),
		"our 4·G must match dalek's 4·G",
	);
}

#[test]
fn double_add_chain_matches_dalek_for_small_multiples() {
	// Verify 5·G, 6·G, 7·G via mixed double + add operations against
	// dalek. Catches drift in either point operation.
	let bp = basepoint();
	let our_2g = double(&bp);
	let our_3g = add(&our_2g, &bp);
	let our_4g = double(&our_2g);
	let our_5g = add(&our_4g, &bp);
	let our_6g = double(&our_3g);
	let our_7g = add(&our_6g, &bp);

	let dalek_g = ED25519_BASEPOINT_POINT;
	let dalek_5g = dalek_g + dalek_g + dalek_g + dalek_g + dalek_g;
	let dalek_6g = dalek_5g + dalek_g;
	let dalek_7g = dalek_6g + dalek_g;

	assert_eq!(compress(&our_5g), dalek_5g.compress().to_bytes(), "5·G mismatch");
	assert_eq!(compress(&our_6g), dalek_6g.compress().to_bytes(), "6·G mismatch");
	assert_eq!(compress(&our_7g), dalek_7g.compress().to_bytes(), "7·G mismatch");
}

fn hex_string(bytes: &[u8; 32]) -> alloc::string::String {
	let mut s = alloc::string::String::with_capacity(64);
	for b in bytes {
		s.push_str(&format!("{:02x}", b));
	}
	s
}
