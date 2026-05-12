// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`crate::ristretto`] — compress / decompress witness-side.
//!
//! Strategy:
//! - **Self-check** that `INVSQRT_A_MINUS_D_LIMBS` actually equals
//!   `1/√(a - d) mod p` via our own primitives. If the constant ever
//!   drifts, this test points at the right byte.
//! - **Roundtrip via dalek**: compress points produced by dalek (basepoint
//!   and its scalar multiples) and verify our output matches
//!   `dalek_point.compress().to_bytes()` byte-for-byte. Then decompress
//!   the same bytes via ours and verify the result matches dalek's
//!   decompression.
//! - **Decompression rejection** of the canonical Ristretto255 invalid
//!   inputs (non-canonical bytes, the "negative" encoding, a known
//!   non-square s²).

extern crate alloc;

use alloc::format;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;

use crate::field::{
	inv, is_negative, mul as field_mul, neg as field_neg, sqrt_ratio_m1, square,
	sub as field_sub, FIELD_NUM_LIMBS, P_LIMBS,
};
use crate::point::{add as point_add, double as point_double, EdwardsPoint, ED25519_D_LIMBS};
use crate::ristretto::{compress, decompress, INVSQRT_A_MINUS_D_LIMBS};

fn one() -> [u32; FIELD_NUM_LIMBS] {
	let mut o = [0u32; FIELD_NUM_LIMBS];
	o[0] = 1;
	o
}

// ─── Constant self-check ───────────────────────────────────────────────────

#[test]
fn invsqrt_a_minus_d_self_check() {
	// a - d = -1 - d (Edwards25519's `a` coefficient is -1).
	let a_minus_d = field_sub(&field_neg(&one()), &ED25519_D_LIMBS);
	// 1 / (a - d).
	let inv_a_minus_d = inv(&a_minus_d);
	// √(1 / (a - d)) via sqrt_ratio_m1(1, a - d).
	let (ok, derived) = sqrt_ratio_m1(&one(), &a_minus_d);
	assert!(ok, "a - d must be a square (it is, for Ed25519)");

	// Two algebraic checks:
	// (a) INVSQRT_A_MINUS_D² · (a - d) == 1.
	let sq = square(&INVSQRT_A_MINUS_D_LIMBS);
	let product = field_mul(&sq, &a_minus_d);
	assert_eq!(
		product,
		one(),
		"INVSQRT_A_MINUS_D² · (a - d) must equal 1; got:\n  product = {:?}\n  derived from sqrt = {:?}",
		product,
		derived,
	);
	// (b) The pinned constant equals the LSB-positive sqrt produced by
	// our own sqrt_ratio_m1.
	assert_eq!(
		INVSQRT_A_MINUS_D_LIMBS, derived,
		"pinned INVSQRT_A_MINUS_D drifted from derived sqrt; replace with: {:?}",
		derived,
	);

	// Sanity: it's LSB-positive (matches the canonical sign convention).
	assert!(!is_negative(&INVSQRT_A_MINUS_D_LIMBS));
	// Suppress unused warning.
	let _ = inv_a_minus_d;
}

// ─── Compress / decompress against dalek ───────────────────────────────────

/// Convert a dalek `RistrettoPoint` into our `EdwardsPoint` extended
/// coords. We don't get direct access to dalek's internal Edwards
/// representation, so we go via decompression: take dalek's compressed
/// bytes and decompress with our own decompress to obtain extended
/// coords. The round-trip is itself a partial test, so for the
/// compression-direction test we generate the input differently.
fn our_edwards_for_basepoint() -> EdwardsPoint {
	let x: [u32; FIELD_NUM_LIMBS] = [
		0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760, 0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE,
		0x216936D3,
	];
	let y: [u32; FIELD_NUM_LIMBS] = [
		0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666,
		0x66666666,
	];
	let mut z = [0u32; FIELD_NUM_LIMBS];
	z[0] = 1;
	let t = field_mul(&x, &y);
	EdwardsPoint { x, y, z, t }
}

#[test]
fn compress_basepoint_matches_dalek_ristretto_basepoint() {
	// Edwards25519 basepoint G compresses (via Ristretto) to dalek's
	// RISTRETTO_BASEPOINT_POINT.compress().to_bytes().
	let our_g = our_edwards_for_basepoint();
	let ours = compress(&our_g);
	let dalek_bytes = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
	assert_eq!(
		ours, dalek_bytes,
		"Ristretto basepoint compression mismatch:\n  ours:  {}\n  dalek: {}",
		hex(&ours),
		hex(&dalek_bytes),
	);
}

#[test]
fn compress_then_decompress_round_trips_for_basepoint_multiples() {
	// Take G, 2G, 3G, 4G via our point ops and verify
	// decompress(compress(P)) reconstructs an Edwards point that
	// compresses to the same bytes. We don't check raw extended-coord
	// equality because the round-trip can produce a representative on a
	// different affine cover.
	let g = our_edwards_for_basepoint();
	let g2 = point_double(&g);
	let g3 = point_add(&g2, &g);
	let g4 = point_double(&g2);

	for p in [g, g2, g3, g4].iter() {
		let bytes = compress(p);
		let recovered = decompress(&bytes).expect("compress→decompress must round-trip");
		let bytes_again = compress(&recovered);
		assert_eq!(
			bytes, bytes_again,
			"compress→decompress→compress should be the identity in byte space",
		);
	}
}

#[test]
fn compress_matches_dalek_for_scalar_multiples() {
	// Cross-check compression against dalek over 5 scalar multiples of
	// the basepoint. We use dalek to compute n·G in Ristretto, dump its
	// compressed bytes, and verify that decompressing via ours →
	// compressing via ours gives the same bytes. This catches drift
	// in the encoding formula even when we don't have a direct dalek
	// Edwards extracter.
	for n in [1u8, 2, 3, 7, 42] {
		let dalek_n_g: RistrettoPoint = DalekScalar::from(n) * RISTRETTO_BASEPOINT_POINT;
		let dalek_bytes = dalek_n_g.compress().to_bytes();
		let recovered = decompress(&dalek_bytes)
			.unwrap_or_else(|| panic!("our decompress failed on dalek's {}·G bytes", n));
		let our_bytes = compress(&recovered);
		assert_eq!(
			our_bytes, dalek_bytes,
			"compress(decompress(dalek_bytes_for_{}·G)) diverges:\n  ours:  {}\n  dalek: {}",
			n,
			hex(&our_bytes),
			hex(&dalek_bytes),
		);
	}
}

// ─── Decompression rejection ───────────────────────────────────────────────

#[test]
fn decompress_rejects_non_canonical_bytes() {
	// p itself as bytes: 0xED 0xFF...0xFF 0x7F. is_canonical returns
	// false because value == p, not < p. Decompress must reject.
	let p_bytes = crate::field::limbs_to_bytes(&P_LIMBS);
	assert!(
		decompress(&p_bytes).is_none(),
		"decompress must reject non-canonical bytes (value ≥ p)",
	);

	// p + 1 (low byte 0xEE) is also non-canonical.
	let mut p_plus_one_bytes = p_bytes;
	p_plus_one_bytes[0] = 0xEE;
	assert!(decompress(&p_plus_one_bytes).is_none());
}

#[test]
fn decompress_rejects_negative_encoding() {
	// A value with LSB == 1: byte 0 = 0x01. The Ristretto spec mandates
	// the encoded field element be LSB-positive (= non-negative).
	let mut bytes = [0u8; 32];
	bytes[0] = 0x01;
	assert!(decompress(&bytes).is_none(), "decompress must reject negative encodings");

	// Another: byte 0 = 0x03 (also LSB=1).
	let mut bytes = [0u8; 32];
	bytes[0] = 0x03;
	assert!(decompress(&bytes).is_none());
}

#[test]
fn decompress_zero_encoding_is_neutral() {
	// The all-zero encoding decodes to the identity element. Cross-
	// checked: dalek's RistrettoPoint::identity().compress() returns
	// all zeros.
	let zero = [0u8; 32];
	let our = decompress(&zero).expect("zero encoding must decompress to identity");
	let recompressed = compress(&our);
	assert_eq!(recompressed, zero, "identity must compress back to all-zero bytes");

	let dalek_identity_bytes = CompressedRistretto::from_slice(&zero)
		.unwrap()
		.decompress()
		.expect("dalek decompresses zero to identity")
		.compress()
		.to_bytes();
	assert_eq!(recompressed, dalek_identity_bytes);
}

#[test]
fn decompress_rejects_edwards_small_order_compressions() {
	// Per audit math-finding M7: the Edwards-compressed encodings of the
	// 8-torsion subgroup (other than the [0;32] collision case, which IS
	// the Ristretto identity and is covered by the
	// decompress_zero_encoding_is_neutral test above) are not valid
	// Ristretto encodings — they're outside the prime-order image that
	// Ristretto255 represents. Pin specific byte sequences so a future
	// refactor to the decompress predicate that subtly accepted any of
	// these gets caught with deterministic test data.
	//
	// Source: each entry is dalek's curve25519_dalek::constants::EIGHT_TORSION[i]
	// passed through EdwardsPoint::compress().to_bytes(). Generated 2026-05-11.
	// Cross-checked against dalek's own Ristretto::decompress at end of test;
	// the assertion shape "neither ours nor dalek's accepts" is the contract.
	//
	// Indices 0, 1, 2, 3, 4, 5, 7 reject. Index 6 is the all-zero bytes
	// (which IS the Ristretto identity encoding) and is excluded here —
	// see decompress_zero_encoding_is_neutral.
	const SMALL_ORDER_EDWARDS_COMPRESSIONS: &[[u8; 32]] = &[
		// EIGHT_TORSION[0] — Edwards identity (0, 1): Edwards-compressed
		// as [1, 0, ..., 0]. Not a valid Ristretto encoding (Ristretto
		// identity is the all-zero bytes; s=1 is not).
		[
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		],
		// EIGHT_TORSION[1] — order-8 point.
		[
			0xC7, 0x17, 0x6A, 0x70, 0x3D, 0x4D, 0xD8, 0x4F, 0xBA, 0x3C, 0x0B, 0x76,
			0x0D, 0x10, 0x67, 0x0F, 0x2A, 0x20, 0x53, 0xFA, 0x2C, 0x39, 0xCC, 0xC6,
			0x4E, 0xC7, 0xFD, 0x77, 0x92, 0xAC, 0x03, 0x7A,
		],
		// EIGHT_TORSION[2] — order-4 point (Y = 0, x sign = 0).
		[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
		],
		// EIGHT_TORSION[3] — order-8 point.
		[
			0x26, 0xE8, 0x95, 0x8F, 0xC2, 0xB2, 0x27, 0xB0, 0x45, 0xC3, 0xF4, 0x89,
			0xF2, 0xEF, 0x98, 0xF0, 0xD5, 0xDF, 0xAC, 0x05, 0xD3, 0xC6, 0x33, 0x39,
			0xB1, 0x38, 0x02, 0x88, 0x6D, 0x53, 0xFC, 0x05,
		],
		// EIGHT_TORSION[4] — order-2 point (Y = -1, x = 0).
		[
			0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
		],
		// EIGHT_TORSION[5] — order-8 point (negation of EIGHT_TORSION[3]).
		[
			0x26, 0xE8, 0x95, 0x8F, 0xC2, 0xB2, 0x27, 0xB0, 0x45, 0xC3, 0xF4, 0x89,
			0xF2, 0xEF, 0x98, 0xF0, 0xD5, 0xDF, 0xAC, 0x05, 0xD3, 0xC6, 0x33, 0x39,
			0xB1, 0x38, 0x02, 0x88, 0x6D, 0x53, 0xFC, 0x85,
		],
		// EIGHT_TORSION[7] — order-8 point (negation of EIGHT_TORSION[1]).
		[
			0xC7, 0x17, 0x6A, 0x70, 0x3D, 0x4D, 0xD8, 0x4F, 0xBA, 0x3C, 0x0B, 0x76,
			0x0D, 0x10, 0x67, 0x0F, 0x2A, 0x20, 0x53, 0xFA, 0x2C, 0x39, 0xCC, 0xC6,
			0x4E, 0xC7, 0xFD, 0x77, 0x92, 0xAC, 0x03, 0xFA,
		],
	];
	for (idx, bytes) in SMALL_ORDER_EDWARDS_COMPRESSIONS.iter().enumerate() {
		// Our decompress: must reject.
		assert!(
			decompress(bytes).is_none(),
			"small-order vector {idx} (bytes {:x?}) must reject as Ristretto",
			bytes,
		);
		// Dalek cross-check: must also reject.
		let dalek_out = CompressedRistretto::from_slice(bytes).unwrap().decompress();
		assert!(
			dalek_out.is_none(),
			"dalek disagrees on small-order vector {idx} \
			 (bytes {:x?}); this would mean our pinned data is wrong",
			bytes,
		);
	}
}

#[test]
fn decompress_rejects_a_known_non_square_s() {
	// Construct an s value such that v · u2² is a non-square in F_p,
	// then attempt decompress. The Ristretto spec says decompress must
	// reject.
	//
	// Easiest: take a random LSB-even s, attempt decompress, and check
	// against dalek for an authoritative reject answer. Iterate until
	// we find one dalek rejects but our function accepts (or vice
	// versa) — i.e., this is an oracle test against dalek over random
	// inputs.
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xfade_face_dead_5151);
	for _ in 0..20 {
		let mut bytes = [0u8; 32];
		rng.fill_bytes(&mut bytes);
		// Force LSB-even and high bits clear (in [0, 2^255)).
		bytes[0] &= 0xFE;
		bytes[31] &= 0x7F;
		let our_out = decompress(&bytes);
		let dalek_out = CompressedRistretto::from_slice(&bytes).unwrap().decompress();
		assert_eq!(
			our_out.is_some(),
			dalek_out.is_some(),
			"decompress accept/reject disagrees with dalek for input {}",
			hex(&bytes),
		);
		// When both accept: cross-check by re-compressing.
		if let (Some(our_pt), Some(dalek_pt)) = (our_out, dalek_out) {
			let our_bytes = compress(&our_pt);
			let dalek_bytes = dalek_pt.compress().to_bytes();
			assert_eq!(
				our_bytes, dalek_bytes,
				"compress diverges after random-input round trip",
			);
		}
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn hex(bytes: &[u8; 32]) -> alloc::string::String {
	let mut s = alloc::string::String::with_capacity(64);
	for b in bytes {
		s.push_str(&format!("{:02x}", b));
	}
	s
}
