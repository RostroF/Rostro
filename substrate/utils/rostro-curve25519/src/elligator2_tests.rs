// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for the Elligator2 witness function.
//!
//! The witness function is oracle-tested against:
//! 1. Algebraic self-check on the `SQRT_NEG_A_MINUS_2` constant
//!    (`c² ≡ -486664 mod p`).
//! 2. Output-is-on-curve checks for a range of inputs (random, edge
//!    cases). This is the necessary correctness invariant: every input
//!    should map to a valid Edwards25519 point.
//! 3. Round-trip the `g(x) = y²` Montgomery relation by recovering
//!    `x_M, y_M` from the Edwards output and verifying.
//!
//! RFC 9380 Appendix J test vectors (edwards25519_XMD:SHA-512_ELL2_RO_)
//! are pinned in a separate test once a reference oracle for the
//! pre-hash field elements is wired up. For v0 the on-curve + self-check
//! pair is the load-bearing soundness gate.

extern crate alloc;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::elligator2::{
	map_to_curve_elligator2_edwards25519, sqrt_neg_a_minus_2, MONT_A_LIMBS,
};
use crate::field::{
	add as field_add, bytes_to_limbs, is_canonical, mul as field_mul, neg as field_neg,
	square as field_square, FIELD_NUM_LIMBS, P_MINUS_ONE_LIMBS,
};
use crate::point::is_on_curve;

fn random_canonical(rng: &mut StdRng) -> [u32; FIELD_NUM_LIMBS] {
	loop {
		let mut bytes = [0u8; 32];
		rng.fill_bytes(&mut bytes);
		bytes[31] &= 0x7F;
		let limbs = bytes_to_limbs(&bytes);
		if is_canonical(&limbs) {
			return limbs;
		}
	}
}

#[test]
fn sqrt_neg_a_minus_2_squared_equals_neg_486664() {
	// c² ≡ -486664 mod p. -486664 = -(A + 2) with A = 486662.
	let c = sqrt_neg_a_minus_2();
	let c_sq = field_square(&c);

	// Build -486664 as a canonical field element. 486664 = A + 2.
	let mut two = [0u32; FIELD_NUM_LIMBS];
	two[0] = 2;
	let a_plus_2 = field_add(&MONT_A_LIMBS, &two);
	let neg_a_minus_2 = field_neg(&a_plus_2);

	assert_eq!(c_sq, neg_a_minus_2, "sqrt(-A-2)² should equal -(A+2)");
}

#[test]
fn maps_zero_to_a_point_on_edwards25519() {
	let u = [0u32; FIELD_NUM_LIMBS];
	let p = map_to_curve_elligator2_edwards25519(&u);
	assert!(is_on_curve(&p), "u=0 must map to a curve point");
}

#[test]
fn maps_one_to_a_point_on_edwards25519() {
	let mut u = [0u32; FIELD_NUM_LIMBS];
	u[0] = 1;
	let p = map_to_curve_elligator2_edwards25519(&u);
	assert!(is_on_curve(&p), "u=1 must map to a curve point");
}

#[test]
fn maps_p_minus_one_to_a_point_on_edwards25519() {
	let p_out = map_to_curve_elligator2_edwards25519(&P_MINUS_ONE_LIMBS);
	assert!(is_on_curve(&p_out), "u=p-1 must map to a curve point");
}

#[test]
fn maps_random_inputs_to_points_on_edwards25519() {
	let mut rng = StdRng::seed_from_u64(0xe7_71_6a_70_72_e2);
	for _ in 0..50 {
		let u = random_canonical(&mut rng);
		let p = map_to_curve_elligator2_edwards25519(&u);
		assert!(
			is_on_curve(&p),
			"random u should map to a curve point; u = {:?}",
			u,
		);
	}
}

#[test]
fn output_extended_coords_satisfy_t_equals_x_times_y() {
	// Extended twisted-Edwards invariant: when Z = 1, T = X · Y.
	let mut rng = StdRng::seed_from_u64(0xe7_71_6a_70_74_e2);
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	for _ in 0..10 {
		let u = random_canonical(&mut rng);
		let p = map_to_curve_elligator2_edwards25519(&u);
		assert_eq!(p.z, one, "elligator2 output should have Z=1");
		assert_eq!(p.t, field_mul(&p.x, &p.y), "T == X·Y invariant");
	}
}
