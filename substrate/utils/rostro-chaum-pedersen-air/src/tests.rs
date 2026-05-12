// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for the off-circuit Chaum-Pedersen verification + the
//! ed25519_basepoint constants.

extern crate alloc;

use rostro_curve25519::point::{is_on_curve, scalar_mul};
use rostro_curve25519::ristretto::compress as ristretto_compress;

use crate::{ed25519_basepoint, verify_chaum_pedersen};

// ─── Basepoint constants ───────────────────────────────────────────────────

#[test]
fn basepoint_is_on_curve() {
	let g = ed25519_basepoint();
	assert!(is_on_curve(&g), "basepoint must lie on Edwards25519");
}

#[test]
fn basepoint_scalar_arithmetic_is_self_consistent() {
	// Algebraic check: 2·G computed via scalar_mul([2]) must equal
	// double(G) computed directly. Catches off-by-one in basepoint coords
	// or scalar_mul against the basepoint specifically.
	use rostro_curve25519::point::double as point_double;

	let g = ed25519_basepoint();
	let mut two = [0u8; 32];
	two[0] = 2;
	let two_g_via_scalar = scalar_mul(&two, &g);
	let two_g_via_double = point_double(&g);

	assert_eq!(
		ristretto_compress(&two_g_via_scalar),
		ristretto_compress(&two_g_via_double),
		"2·G via scalar_mul disagrees with double(G)",
	);
}

#[test]
fn basepoint_distributive_check() {
	// (a + b)·G == a·G + b·G via Ristretto-compressed equality. Validates
	// scalar_mul against the basepoint over a wider range than just the
	// double check above.
	use curve25519_dalek::scalar::Scalar as DScalar;
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	use rostro_curve25519::point::add as point_add;
	let mut rng = StdRng::seed_from_u64(0xdb_d57_b07u64);
	let g = ed25519_basepoint();

	for _ in 0..10 {
		let mut a = [0u8; 32];
		let mut b = [0u8; 32];
		rng.fill_bytes(&mut a);
		rng.fill_bytes(&mut b);
		// Reduce mod ℓ so a, b are canonical scalars (avoids
		// scalar_mul-on-reduced vs scalar_mul-on-raw discrepancies).
		a = DScalar::from_bytes_mod_order(a).to_bytes();
		b = DScalar::from_bytes_mod_order(b).to_bytes();
		let sum_ab = (DScalar::from_bytes_mod_order(a)
			+ DScalar::from_bytes_mod_order(b))
		.to_bytes();

		let lhs = scalar_mul(&sum_ab, &g);
		let rhs = point_add(&scalar_mul(&a, &g), &scalar_mul(&b, &g));

		assert_eq!(
			ristretto_compress(&lhs),
			ristretto_compress(&rhs),
			"(a+b)·G != a·G + b·G",
		);
	}
}

// ─── verify_chaum_pedersen ─────────────────────────────────────────────────

/// Honest-prover helper used by the verification tests.
fn honest_prove(
	k_bytes: &[u8; 32],
	r_bytes: &[u8; 32],
	blinded: &rostro_curve25519::point::EdwardsPoint,
	e_bytes: &[u8; 32],
) -> (
	rostro_curve25519::point::EdwardsPoint, // R_pk
	rostro_curve25519::point::EdwardsPoint, // R_resp
	[u8; 32],                                // s
) {
	use curve25519_dalek::scalar::Scalar as DScalar;
	let g = ed25519_basepoint();
	let r_pk = scalar_mul(r_bytes, &g);
	let r_resp = scalar_mul(r_bytes, blinded);

	let r_scalar = DScalar::from_bytes_mod_order(*r_bytes);
	let e_scalar = DScalar::from_bytes_mod_order(*e_bytes);
	let k_scalar = DScalar::from_bytes_mod_order(*k_bytes);
	let s_scalar = r_scalar + e_scalar * k_scalar;

	(r_pk, r_resp, s_scalar.to_bytes())
}

#[test]
fn honest_proof_verifies() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xc0_ffe_e_07);

	for _ in 0..10 {
		let mut k = [0u8; 32];
		let mut r = [0u8; 32];
		let mut e = [0u8; 32];
		let mut blinded_seed = [0u8; 32];
		rng.fill_bytes(&mut k);
		rng.fill_bytes(&mut r);
		rng.fill_bytes(&mut e);
		rng.fill_bytes(&mut blinded_seed);

		let g = ed25519_basepoint();
		let pk = scalar_mul(&k, &g);
		let blinded = scalar_mul(&blinded_seed, &g);
		let response = scalar_mul(&k, &blinded);
		let (r_pk, r_resp, s) = honest_prove(&k, &r, &blinded, &e);

		assert!(
			verify_chaum_pedersen(&pk, &blinded, &response, &r_pk, &r_resp, &e, &s),
			"honest proof rejected",
		);
	}
}

#[test]
fn corrupted_s_fails_verification() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0x_ba_d_5_e_u64);
	let mut k = [0u8; 32];
	let mut r = [0u8; 32];
	let mut e = [0u8; 32];
	rng.fill_bytes(&mut k);
	rng.fill_bytes(&mut r);
	rng.fill_bytes(&mut e);
	let g = ed25519_basepoint();
	let pk = scalar_mul(&k, &g);
	let blinded = scalar_mul(&[0x42u8; 32], &g);
	let response = scalar_mul(&k, &blinded);
	let (r_pk, r_resp, mut s) = honest_prove(&k, &r, &blinded, &e);
	s[0] ^= 1; // flip a bit

	assert!(
		!verify_chaum_pedersen(&pk, &blinded, &response, &r_pk, &r_resp, &e, &s),
		"corrupted s passed verification",
	);
}

#[test]
fn corrupted_e_fails_verification() {
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0x_ba_d_e_07u64);
	let mut k = [0u8; 32];
	let mut r = [0u8; 32];
	let mut e = [0u8; 32];
	rng.fill_bytes(&mut k);
	rng.fill_bytes(&mut r);
	rng.fill_bytes(&mut e);
	let g = ed25519_basepoint();
	let pk = scalar_mul(&k, &g);
	let blinded = scalar_mul(&[0x42u8; 32], &g);
	let response = scalar_mul(&k, &blinded);
	let (r_pk, r_resp, s) = honest_prove(&k, &r, &blinded, &e);
	let mut e_bad = e;
	e_bad[0] ^= 1;

	assert!(
		!verify_chaum_pedersen(&pk, &blinded, &response, &r_pk, &r_resp, &e_bad, &s),
		"corrupted e passed verification",
	);
}

#[test]
fn wrong_k_in_response_fails_verification() {
	// Federation cheats: uses a different K' for `response` vs `pk`.
	// The whole point of dlog-equality is to detect this.
	use rand::{rngs::StdRng, RngCore, SeedableRng};
	let mut rng = StdRng::seed_from_u64(0xc4_e4_07u64);
	let mut k = [0u8; 32];
	let mut k_prime = [0u8; 32];
	let mut r = [0u8; 32];
	let mut e = [0u8; 32];
	rng.fill_bytes(&mut k);
	rng.fill_bytes(&mut k_prime);
	rng.fill_bytes(&mut r);
	rng.fill_bytes(&mut e);
	let g = ed25519_basepoint();
	let pk = scalar_mul(&k, &g);
	let blinded = scalar_mul(&[0x42u8; 32], &g);
	// Cheat: use k_prime not k.
	let response_dishonest = scalar_mul(&k_prime, &blinded);
	let (r_pk, r_resp, s) = honest_prove(&k, &r, &blinded, &e);

	assert!(
		!verify_chaum_pedersen(&pk, &blinded, &response_dishonest, &r_pk, &r_resp, &e, &s),
		"dishonest K' in response was not detected",
	);
}
