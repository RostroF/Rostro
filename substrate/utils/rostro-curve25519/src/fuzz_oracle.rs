// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Differential fuzzer for the witness-layer math in this crate.
//!
//! Methodology: every fuzz test seeds an `StdRng` from a deterministic
//! constant, mixes structured edge cases at known iteration indices, and
//! cross-checks each witness function against an independently-computed
//! oracle (num-bigint with explicit modulus `p = 2^255 - 19`, or
//! `curve25519-dalek` 4.1 for group / Ristretto operations).
//!
//! On mismatch, the failing assertion prints the seed, iteration index,
//! and both inputs/outputs so the failure is reproducible by re-running
//! the same fuzz_* test.
//!
//! Dev-only — never reaches production. Run with:
//! ```
//! SKIP_WASM_BUILD=1 cargo test -p rostro-curve25519 --lib --release fuzz_ \
//!     -- --nocapture --test-threads=1
//! ```

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use num_bigint::BigUint;
use num_traits::{Num, One, Zero};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::edwards::EdwardsPoint as DalekEdwards;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use curve25519_dalek::traits::Identity;

use crate::elligator2::map_to_curve_elligator2_edwards25519;
use crate::field::{
	add, bytes_to_limbs, inv, is_negative, is_zero, limbs_to_bytes, mul, neg,
	pow_p_minus_5_div_8, sqrt_ratio_m1, square, sub, FIELD_NUM_LIMBS, P_LIMBS,
	P_MINUS_ONE_LIMBS, SQRT_M1_LIMBS,
};
use crate::point::{add as point_add, double as point_double, is_on_curve, neutral, scalar_mul,
	EdwardsPoint};
use crate::ristretto::{compress as ristretto_compress, decompress as ristretto_decompress};

// ─── Oracle helpers ────────────────────────────────────────────────────────

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

fn random_canonical(rng: &mut StdRng) -> [u32; FIELD_NUM_LIMBS] {
	loop {
		let mut bytes = [0u8; 32];
		rng.fill_bytes(&mut bytes);
		bytes[31] &= 0x7F;
		let limbs = bytes_to_limbs(&bytes);
		if crate::field::is_canonical(&limbs) {
			return limbs;
		}
	}
}

/// Edge-case field-element table. Iteration indices `0..edge_cases().len()`
/// use these structured values; later iterations sample uniformly from
/// `random_canonical`.
fn edge_cases() -> Vec<[u32; FIELD_NUM_LIMBS]> {
	let mut zero = [0u32; FIELD_NUM_LIMBS];
	let _ = &mut zero; // silence
	let zero = [0u32; FIELD_NUM_LIMBS];
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	let mut two = [0u32; FIELD_NUM_LIMBS];
	two[0] = 2;
	let mut p_minus_two = P_LIMBS;
	p_minus_two[0] -= 2;
	let mut high_bit = [0u32; FIELD_NUM_LIMBS];
	high_bit[7] = 0x4000_0000;
	let mut all_ones_low = [0u32; FIELD_NUM_LIMBS];
	all_ones_low[0] = 0xFFFF_FFFF;
	let mut limb_max_each = [0u32; FIELD_NUM_LIMBS];
	for i in 0..7 {
		limb_max_each[i] = 0xFFFF_FFFF;
	}
	limb_max_each[7] = 0x7FFF_FFFE;
	alloc::vec![
		zero,
		one,
		two,
		P_MINUS_ONE_LIMBS,
		p_minus_two,
		SQRT_M1_LIMBS,
		high_bit,
		all_ones_low,
		limb_max_each,
	]
}

fn pick_input(i: usize, rng: &mut StdRng) -> [u32; FIELD_NUM_LIMBS] {
	let edges = edge_cases();
	if i < edges.len() {
		edges[i]
	} else {
		random_canonical(rng)
	}
}

fn limbs_hex(limbs: &[u32; FIELD_NUM_LIMBS]) -> String {
	let bytes = limbs_to_bytes(limbs);
	let mut s = String::with_capacity(64);
	for b in bytes.iter().rev() {
		s.push_str(&format!("{:02x}", b));
	}
	s
}

// ─── Field-op fuzzers ──────────────────────────────────────────────────────

const ITERS_FAST: usize = 5_000;
const ITERS_SLOW: usize = 500;

#[test]
fn fuzz_field_add_vs_bigint() {
	let seed: u64 = 0xADDA_1FAC_EFAC_E001;
	let mut rng = StdRng::seed_from_u64(seed);
	let p = p_biguint();
	for i in 0..ITERS_FAST {
		let a = pick_input(i, &mut rng);
		let b = pick_input(i.wrapping_add(7), &mut rng);
		let actual = add(&a, &b);
		let expected_big = (limbs_to_biguint(&a) + limbs_to_biguint(&b)) % &p;
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(
			actual, expected,
			"add diverges (seed=0x{:x}, iter={})\n  a = {}\n  b = {}\n  got = {}\n  want = {}",
			seed,
			i,
			limbs_hex(&a),
			limbs_hex(&b),
			limbs_hex(&actual),
			limbs_hex(&expected),
		);
	}
}

#[test]
fn fuzz_field_sub_vs_bigint() {
	let seed: u64 = 0x5B5B_5B5B_5B5B_0002;
	let mut rng = StdRng::seed_from_u64(seed);
	let p = p_biguint();
	for i in 0..ITERS_FAST {
		let a = pick_input(i, &mut rng);
		let b = pick_input(i.wrapping_add(13), &mut rng);
		let actual = sub(&a, &b);
		let a_big = limbs_to_biguint(&a);
		let b_big = limbs_to_biguint(&b);
		let expected_big = ((&a_big + &p) - &b_big) % &p;
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(
			actual, expected,
			"sub diverges (seed=0x{:x}, iter={})\n  a = {}\n  b = {}\n  got = {}\n  want = {}",
			seed,
			i,
			limbs_hex(&a),
			limbs_hex(&b),
			limbs_hex(&actual),
			limbs_hex(&expected),
		);
	}
}

#[test]
fn fuzz_field_mul_vs_bigint() {
	let seed: u64 = 0xFACE_FACE_FACE_F003;
	let mut rng = StdRng::seed_from_u64(seed);
	let p = p_biguint();
	for i in 0..ITERS_FAST {
		let a = pick_input(i, &mut rng);
		let b = pick_input(i.wrapping_add(11), &mut rng);
		let actual = mul(&a, &b);
		let expected_big = (limbs_to_biguint(&a) * limbs_to_biguint(&b)) % &p;
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(
			actual, expected,
			"mul diverges (seed=0x{:x}, iter={})\n  a = {}\n  b = {}\n  got = {}\n  want = {}",
			seed,
			i,
			limbs_hex(&a),
			limbs_hex(&b),
			limbs_hex(&actual),
			limbs_hex(&expected),
		);
	}
}

#[test]
fn fuzz_field_square_vs_bigint() {
	let seed: u64 = 0xCAFE_BABE_CAFE_B004;
	let mut rng = StdRng::seed_from_u64(seed);
	let p = p_biguint();
	for i in 0..ITERS_FAST {
		let a = pick_input(i, &mut rng);
		let actual = square(&a);
		let a_big = limbs_to_biguint(&a);
		let expected_big = (&a_big * &a_big) % &p;
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(
			actual, expected,
			"square diverges (seed=0x{:x}, iter={})\n  a = {}\n  got = {}\n  want = {}",
			seed,
			i,
			limbs_hex(&a),
			limbs_hex(&actual),
			limbs_hex(&expected),
		);
		// Cross-check: square(a) == mul(a, a).
		let via_mul = mul(&a, &a);
		assert_eq!(actual, via_mul, "square != mul-self at iter={}", i);
	}
}

#[test]
fn fuzz_field_neg_vs_bigint() {
	let seed: u64 = 0xDEAD_BEEF_DEAD_B005;
	let mut rng = StdRng::seed_from_u64(seed);
	let p = p_biguint();
	for i in 0..ITERS_FAST {
		let a = pick_input(i, &mut rng);
		let actual = neg(&a);
		let a_big = limbs_to_biguint(&a);
		let expected_big = if a_big.is_zero() { BigUint::zero() } else { &p - &a_big };
		let expected = biguint_to_limbs(&expected_big);
		assert_eq!(
			actual, expected,
			"neg diverges (iter={})\n  a = {}\n  got = {}\n  want = {}",
			i,
			limbs_hex(&a),
			limbs_hex(&actual),
			limbs_hex(&expected),
		);
		// Cross-check: a + neg(a) == 0.
		assert_eq!(add(&a, &actual), [0u32; FIELD_NUM_LIMBS], "a + neg(a) != 0 at iter={}", i);
	}
}

#[test]
fn fuzz_field_inv_vs_bigint() {
	// inv is heavy (Fermat: ~255 muls per call). Use fewer iterations.
	let seed: u64 = 0x1A1A_1A1A_1A1A_0006;
	let mut rng = StdRng::seed_from_u64(seed);
	let p = p_biguint();
	let p_minus_two = &p - BigUint::from(2u8);
	let mut one = [0u32; FIELD_NUM_LIMBS];
	one[0] = 1;
	for i in 0..ITERS_SLOW {
		let v = pick_input(i, &mut rng);
		let actual = inv(&v);
		let v_big = limbs_to_biguint(&v);
		// Documented behavior: inv(0) returns 0.
		let expected = if v_big.is_zero() {
			[0u32; FIELD_NUM_LIMBS]
		} else {
			biguint_to_limbs(&v_big.modpow(&p_minus_two, &p))
		};
		assert_eq!(
			actual, expected,
			"inv diverges (iter={})\n  v = {}\n  got = {}\n  want = {}",
			i,
			limbs_hex(&v),
			limbs_hex(&actual),
			limbs_hex(&expected),
		);
		// Cross-check: v * inv(v) == 1, except for v=0.
		if !v_big.is_zero() {
			assert_eq!(mul(&v, &actual), one, "v * inv(v) != 1 at iter={}", i);
		}
	}
}

#[test]
fn fuzz_field_pow_p_minus_5_div_8_vs_bigint() {
	let mut rng = StdRng::seed_from_u64(0xB058_B058_B058_0007u64);
	let p = p_biguint();
	let exp = (&p - BigUint::from(5u8)) / BigUint::from(8u8);
	// Hand-pinned cross-check: 1^anything == 1, 0^anything (for exp>0) == 0.
	{
		let mut one = [0u32; FIELD_NUM_LIMBS];
		one[0] = 1;
		assert_eq!(pow_p_minus_5_div_8(&one), one, "pow(1) must be 1");
		assert_eq!(
			pow_p_minus_5_div_8(&[0u32; FIELD_NUM_LIMBS]),
			[0u32; FIELD_NUM_LIMBS],
			"pow(0) must be 0",
		);
	}
	for i in 0..ITERS_SLOW {
		let v = pick_input(i, &mut rng);
		let actual = pow_p_minus_5_div_8(&v);
		let expected = biguint_to_limbs(&limbs_to_biguint(&v).modpow(&exp, &p));
		assert_eq!(
			actual, expected,
			"pow_p_minus_5_div_8 diverges (iter={})\n  v = {}\n  got = {}\n  want = {}",
			i,
			limbs_hex(&v),
			limbs_hex(&actual),
			limbs_hex(&expected),
		);
	}
}

#[test]
fn fuzz_field_is_negative_vs_lsb() {
	// is_negative is defined as `limbs[0] & 1 == 1`. Verify it agrees
	// with the LE-byte LSB across random + edge cases.
	let mut rng = StdRng::seed_from_u64(0x1515_E61E_6151_5008u64);
	for i in 0..ITERS_FAST {
		let a = pick_input(i, &mut rng);
		let bytes = limbs_to_bytes(&a);
		let oracle = (bytes[0] & 1) == 1;
		assert_eq!(is_negative(&a), oracle, "is_negative disagrees with LE-byte LSB at iter={}", i);
	}
}

// ─── sqrt_ratio_m1 fuzzer ──────────────────────────────────────────────────

/// Independent oracle for `sqrt_ratio_m1(u, v)`.
///
/// Per RFC 9380 §F.2.1: returns `(r, was_sq)` where if `u/v` is a square
/// then `r² == u/v` and `was_sq=true`; otherwise `r² == SQRT_M1 · u/v` and
/// `was_sq=false`. By Ristretto convention, the LSB-positive root is
/// chosen.
///
/// Special case from the witness contract: `sqrt_ratio_m1(0, anything) =
/// (0, true)`. `sqrt_ratio_m1(anything_nonzero, 0)` is undefined in the
/// math; the witness behavior is whatever it is — we don't oracle that.
fn sqrt_ratio_m1_oracle(
	u: &[u32; FIELD_NUM_LIMBS],
	v: &[u32; FIELD_NUM_LIMBS],
) -> Option<(BigUint, bool)> {
	let p = p_biguint();
	let u_big = limbs_to_biguint(u);
	let v_big = limbs_to_biguint(v);
	if v_big.is_zero() {
		return None; // undefined for the oracle
	}
	let v_inv = v_big.modpow(&(&p - BigUint::from(2u8)), &p);
	let target = (&u_big * &v_inv) % &p;
	if target.is_zero() {
		return Some((BigUint::zero(), true));
	}
	// Euler's criterion.
	let exp_half = (&p - BigUint::from(1u8)) / BigUint::from(2u8);
	let euler = target.modpow(&exp_half, &p);
	let is_square = euler == BigUint::one();
	// Compute candidate root via p ≡ 5 mod 8 closed form: target^((p+3)/8).
	// If target is a square, candidate² == ±target; multiply by SQRT_M1 if needed.
	// If target is NOT a square, the algorithm returns sqrt(SQRT_M1 · target).
	let exp_eighth = (&p + BigUint::from(3u8)) / BigUint::from(8u8);
	let cand = target.modpow(&exp_eighth, &p);
	let cand_sq = (&cand * &cand) % &p;
	let i = limbs_to_biguint(&SQRT_M1_LIMBS);
	let r_unsigned: BigUint = if is_square {
		if cand_sq == target {
			cand
		} else {
			(&cand * &i) % &p
		}
	} else {
		// Non-square branch: r² = SQRT_M1 · target.
		// Note cand² = target^((p+3)/4) = target · target^((p-1)/4).
		// For non-square target, target^((p-1)/2) = -1, so target^((p-1)/4) is
		// either SQRT_M1 or -SQRT_M1. Therefore cand² ∈ {SQRT_M1·target, -SQRT_M1·target}.
		let i_target = (&i * &target) % &p;
		if cand_sq == i_target {
			cand
		} else {
			(&cand * &i) % &p
		}
	};
	// LSB-positive normalize.
	let r = if &r_unsigned % BigUint::from(2u8) == BigUint::one() {
		(&p - &r_unsigned) % &p
	} else {
		r_unsigned
	};
	Some((r, is_square))
}

#[test]
fn fuzz_sqrt_ratio_m1_vs_oracle() {
	let mut rng = StdRng::seed_from_u64(0x5B57_5B57_5B57_5009u64);
	for i in 0..ITERS_SLOW {
		let u = pick_input(i, &mut rng);
		let v = pick_input(i.wrapping_add(3), &mut rng);
		// Skip iterations where v=0 (oracle undefined).
		if is_zero(&v) {
			continue;
		}
		let (was_sq, r) = sqrt_ratio_m1(&u, &v);
		let oracle = sqrt_ratio_m1_oracle(&u, &v).expect("v != 0 here");
		assert_eq!(
			was_sq, oracle.1,
			"sqrt_ratio_m1 was_sq disagrees (iter={})\n  u = {}\n  v = {}",
			i,
			limbs_hex(&u),
			limbs_hex(&v),
		);
		// On the square branch the result is constrained; on the non-square
		// branch the witness's `r` is also a specific value (the sqrt of
		// SQRT_M1·u/v) — both should match the oracle.
		let expected = biguint_to_limbs(&oracle.0);
		assert_eq!(
			r, expected,
			"sqrt_ratio_m1 r disagrees (iter={}, was_sq={})\n  u = {}\n  v = {}\n  got = {}\n  want = {}",
			i,
			was_sq,
			limbs_hex(&u),
			limbs_hex(&v),
			limbs_hex(&r),
			limbs_hex(&expected),
		);
		// Always: r is LSB-positive (per Ristretto convention).
		if !is_zero(&r) {
			assert!(!is_negative(&r), "sqrt_ratio_m1 result must be LSB-positive (iter={})", i);
		}
	}
}

// ─── Edwards25519 point-op fuzzers ─────────────────────────────────────────

/// Edwards25519 basepoint G in our extended-coord representation.
fn our_basepoint() -> EdwardsPoint {
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
	let t = mul(&x, &y);
	EdwardsPoint { x, y, z, t }
}

/// Compress one of our `EdwardsPoint`s to standard Ed25519 32-byte
/// encoding (Y/Z, sign of X/Z in high bit). Used to compare against
/// dalek's `EdwardsPoint::compress()`.
fn our_ed_compress(p: &EdwardsPoint) -> [u8; 32] {
	let z_inv = inv(&p.z);
	let y_aff = mul(&p.y, &z_inv);
	let x_aff = mul(&p.x, &z_inv);
	let mut bytes = limbs_to_bytes(&y_aff);
	let x_sign = (x_aff[0] & 1) as u8;
	bytes[31] |= x_sign << 7;
	bytes
}

#[test]
fn fuzz_point_add_vs_dalek() {
	// Strategy: generate random scalars k1, k2; compute P1 = k1·G and
	// P2 = k2·G via dalek; cross-decompress dalek's bytes through our
	// Ed25519 decoder is not exposed, so instead we build P1, P2 on our
	// side via point ops (small chains of double + add) and compare
	// compressed outputs against dalek's matching scalar arithmetic.
	let mut rng = StdRng::seed_from_u64(0xBADD_BADD_BADD_500Au64);
	let bp = our_basepoint();
	let dalek_g = ED25519_BASEPOINT_POINT;

	// Build a precomputed table of n·G on both sides for n in [0, 16].
	let mut ours = alloc::vec![neutral()];
	let mut dalek = alloc::vec![DalekEdwards::identity()];
	for _ in 1..=16 {
		ours.push(point_add(ours.last().unwrap(), &bp));
		dalek.push(*dalek.last().unwrap() + dalek_g);
	}
	// Fuzz: add ours[i] + ours[j] vs dalek[i] + dalek[j], for random
	// (i, j) including all edge pairs.
	let total = 500;
	for k in 0..total {
		let (i, j) = if k < 17 {
			(k, k) // diagonal: P + P
		} else if k < 34 {
			(0, k - 17) // identity + P
		} else if k < 51 {
			(k - 34, 0) // P + identity
		} else {
			let i = (rng.next_u32() as usize) % ours.len();
			let j = (rng.next_u32() as usize) % ours.len();
			(i, j)
		};
		let our_sum = point_add(&ours[i], &ours[j]);
		let dalek_sum = dalek[i] + dalek[j];
		assert_eq!(
			our_ed_compress(&our_sum),
			dalek_sum.compress().to_bytes(),
			"point_add diverges (k={}, i={}, j={})",
			k, i, j,
		);
		assert!(is_on_curve(&our_sum), "point_add output off-curve (k={})", k);
	}
}

#[test]
fn fuzz_point_double_vs_dalek() {
	let mut rng = StdRng::seed_from_u64(0xBDB1_BDB1_BDB1_500Bu64);
	let bp = our_basepoint();
	let dalek_g = ED25519_BASEPOINT_POINT;

	// Build small table; double each entry, compare.
	let mut ours = alloc::vec![neutral(), bp];
	let mut dalek = alloc::vec![DalekEdwards::identity(), dalek_g];
	for _ in 0..30 {
		let next_ours = point_add(ours.last().unwrap(), &bp);
		let next_dalek = *dalek.last().unwrap() + dalek_g;
		ours.push(next_ours);
		dalek.push(next_dalek);
	}
	// Edge cases: double identity, double basepoint, double random points.
	for i in 0..ours.len() {
		let our_d = point_double(&ours[i]);
		let dalek_d = dalek[i] + dalek[i];
		assert_eq!(
			our_ed_compress(&our_d),
			dalek_d.compress().to_bytes(),
			"point_double diverges at i={}",
			i,
		);
		assert!(is_on_curve(&our_d), "point_double output off-curve at i={}", i);
	}
	// Additional random doublings via random scalar mul.
	for k in 0..50 {
		let mut sb = [0u8; 32];
		rng.fill_bytes(&mut sb);
		// Reduce mod ell so it's a valid Ristretto255 scalar.
		let dalek_s = DalekScalar::from_bytes_mod_order(sb);
		let scalar_bytes = dalek_s.to_bytes();
		let our_kg = scalar_mul(&scalar_bytes, &bp);
		let our_2kg = point_double(&our_kg);
		let dalek_kg = dalek_s * dalek_g;
		let dalek_2kg = dalek_kg + dalek_kg;
		assert_eq!(
			our_ed_compress(&our_2kg),
			dalek_2kg.compress().to_bytes(),
			"point_double after scalar_mul diverges (k={})",
			k,
		);
	}
}

#[test]
fn fuzz_scalar_mul_vs_dalek() {
	// scalar_mul is heavy (256 doubles + ~128 adds per call). Keep small.
	let mut rng = StdRng::seed_from_u64(0x5111_5111_5111_500Cu64);
	let bp = our_basepoint();
	let dalek_g = ED25519_BASEPOINT_POINT;

	// Edge cases first.
	let mut zero_s = [0u8; 32];
	let _ = &mut zero_s;
	let zero_s = [0u8; 32];
	let mut one_s = [0u8; 32];
	one_s[0] = 1;
	// ell - 1 (largest valid scalar mod ell).
	// ell = 2^252 + 27742317777372353535851937790883648493.
	let ell_minus_one = {
		let ell = DalekScalar::ZERO - DalekScalar::ONE;
		ell.to_bytes()
	};
	// ell itself reduces to 0 — Scalar::from_bytes_mod_order will reduce.

	let edge_scalars: Vec<[u8; 32]> = alloc::vec![zero_s, one_s, ell_minus_one];

	for (idx, sb) in edge_scalars.iter().enumerate() {
		let dalek_s = DalekScalar::from_bytes_mod_order(*sb);
		let our = scalar_mul(&dalek_s.to_bytes(), &bp);
		let dalek_pt = dalek_s * dalek_g;
		assert_eq!(
			our_ed_compress(&our),
			dalek_pt.compress().to_bytes(),
			"scalar_mul edge case {} diverges\n  scalar = {:?}",
			idx,
			dalek_s.to_bytes(),
		);
	}
	// Random scalars.
	for k in 0..30 {
		let mut sb = [0u8; 32];
		rng.fill_bytes(&mut sb);
		let dalek_s = DalekScalar::from_bytes_mod_order(sb);
		let scalar_bytes = dalek_s.to_bytes();
		let our = scalar_mul(&scalar_bytes, &bp);
		let dalek_pt = dalek_s * dalek_g;
		assert_eq!(
			our_ed_compress(&our),
			dalek_pt.compress().to_bytes(),
			"scalar_mul random diverges (k={})",
			k,
		);
	}
}

#[test]
fn fuzz_is_on_curve_accepts_basepoint_and_multiples() {
	let bp = our_basepoint();
	assert!(is_on_curve(&bp));
	assert!(is_on_curve(&neutral()));
	let mut acc = bp;
	for k in 0..50 {
		acc = point_add(&acc, &bp);
		assert!(is_on_curve(&acc), "n·G failed is_on_curve at n={}", k + 2);
	}
}

#[test]
fn fuzz_is_on_curve_rejects_perturbed_points() {
	// Take basepoint, perturb a single coordinate, expect rejection.
	let bp = our_basepoint();
	let mut bad = bp;
	bad.x[0] = bad.x[0].wrapping_add(1);
	assert!(!is_on_curve(&bad), "is_on_curve must reject x-perturbed basepoint");

	let mut bad = bp;
	bad.y[0] = bad.y[0].wrapping_add(1);
	assert!(!is_on_curve(&bad), "is_on_curve must reject y-perturbed basepoint");

	let mut bad = bp;
	bad.t[0] = bad.t[0].wrapping_add(1);
	assert!(!is_on_curve(&bad), "is_on_curve must reject t-perturbed basepoint");
}

// ─── Ristretto fuzzers ─────────────────────────────────────────────────────

#[test]
fn fuzz_ristretto_compress_vs_dalek() {
	// Strategy: take dalek's compressed bytes for n·R_basepoint, decompress
	// via our function, recompress, compare bytes.
	let mut rng = StdRng::seed_from_u64(0xCBCB_CBCB_CBCB_500Du64);
	let dalek_rg = RISTRETTO_BASEPOINT_POINT;

	// Edge cases: identity, basepoint, small multiples.
	for n in 0u32..32 {
		let dalek_pt: RistrettoPoint = DalekScalar::from(n) * dalek_rg;
		let dalek_bytes = dalek_pt.compress().to_bytes();
		let our = ristretto_decompress(&dalek_bytes)
			.unwrap_or_else(|| panic!("decompress failed on n={}·G bytes", n));
		let recompressed = ristretto_compress(&our);
		assert_eq!(
			recompressed, dalek_bytes,
			"compress(decompress(dalek({}·G))) diverges:\n  ours:  {:x?}\n  dalek: {:x?}",
			n, recompressed, dalek_bytes,
		);
	}
	// Random multiples.
	for k in 0..50 {
		let mut sb = [0u8; 32];
		rng.fill_bytes(&mut sb);
		let dalek_s = DalekScalar::from_bytes_mod_order(sb);
		let dalek_pt: RistrettoPoint = dalek_s * dalek_rg;
		let dalek_bytes = dalek_pt.compress().to_bytes();
		let our = ristretto_decompress(&dalek_bytes)
			.unwrap_or_else(|| panic!("decompress failed on random k={}", k));
		let recompressed = ristretto_compress(&our);
		assert_eq!(
			recompressed, dalek_bytes,
			"random ristretto compress diverges (k={})", k,
		);
	}
}

#[test]
fn fuzz_ristretto_decompress_accept_reject_vs_dalek() {
	// Random 32-byte inputs (LSB even, top bit clear). For each, our
	// decompress and dalek's CompressedRistretto::decompress must agree
	// on accept/reject. When both accept, recompress must match.
	let mut rng = StdRng::seed_from_u64(0xDEC0_DEC0_DEC0_500Eu64);
	let total = 500;
	let mut accepts = 0;
	let mut rejects = 0;
	for k in 0..total {
		let mut bytes = [0u8; 32];
		rng.fill_bytes(&mut bytes);
		// Force LSB-even and high bit clear so we don't sample the trivial-reject space.
		bytes[0] &= 0xFE;
		bytes[31] &= 0x7F;
		let our = ristretto_decompress(&bytes);
		let dalek_compressed = CompressedRistretto::from_slice(&bytes).unwrap();
		let dalek = dalek_compressed.decompress();
		assert_eq!(
			our.is_some(),
			dalek.is_some(),
			"decompress accept/reject disagrees with dalek at k={}\n  bytes = {:x?}",
			k, bytes,
		);
		if let (Some(our_pt), Some(dalek_pt)) = (our, dalek) {
			accepts += 1;
			let our_bytes = ristretto_compress(&our_pt);
			let dalek_bytes = dalek_pt.compress().to_bytes();
			assert_eq!(
				our_bytes, dalek_bytes,
				"compress mismatch after decompress at k={}", k,
			);
		} else {
			rejects += 1;
		}
	}
	// Sanity: we should have exercised both branches.
	assert!(accepts > 0, "no accepts in {} iters — input distribution wrong", total);
	assert!(rejects > 0, "no rejects in {} iters — input distribution wrong", total);
}

#[test]
fn fuzz_ristretto_decompress_rejects_non_canonical() {
	// Build inputs that are >= p: low byte 0xED..0xFF + high byte 0x7F.
	let mut rng = StdRng::seed_from_u64(0xCBCB_CBCB_CBCB_500Fu64);
	for _ in 0..50 {
		let mut bytes = [0xFFu8; 32];
		bytes[31] = 0x7F;
		// Vary the low byte from 0xED upward.
		bytes[0] = 0xED + (rng.next_u32() as u8 & 0x12);
		assert!(
			ristretto_decompress(&bytes).is_none(),
			"decompress accepted non-canonical input {:x?}", bytes,
		);
	}
}

#[test]
fn fuzz_ristretto_decompress_rejects_negative() {
	let mut rng = StdRng::seed_from_u64(0xE6E6_E6E6_E6E6_5010u64);
	for _ in 0..50 {
		let mut bytes = [0u8; 32];
		rng.fill_bytes(&mut bytes);
		bytes[31] &= 0x7F;
		bytes[0] |= 0x01; // force LSB=1.
		assert!(
			ristretto_decompress(&bytes).is_none(),
			"decompress accepted negative encoding {:x?}", bytes,
		);
	}
}

// ─── Elligator2 fuzzer ─────────────────────────────────────────────────────

#[test]
fn fuzz_elligator2_outputs_are_on_curve() {
	let mut rng = StdRng::seed_from_u64(0xE111_E111_E111_5011u64);
	let total = 1_000;
	let mut sq_branch = 0;
	let mut nsq_branch = 0;
	for i in 0..total {
		let u = pick_input(i, &mut rng);
		let p_out = map_to_curve_elligator2_edwards25519(&u);
		assert!(
			is_on_curve(&p_out),
			"elligator2 output off-curve at iter={}\n  u = {}",
			i,
			limbs_hex(&u),
		);
		// Track which branch (gx1 square vs not) was taken so we can
		// confirm we exercised both. gx1 = x1·(x1² + A·x1 + 1) where
		// x1 = -A · inv(1 + 2u²); recomputing via num-bigint.
		let p = p_biguint();
		let u_big = limbs_to_biguint(&u);
		let two_u_sq = (BigUint::from(2u8) * &u_big * &u_big) % &p;
		let denom = (BigUint::one() + &two_u_sq) % &p;
		let mont_a = BigUint::from(486662u32);
		let neg_a = (&p - &mont_a) % &p;
		let x1 = if denom.is_zero() {
			neg_a.clone()
		} else {
			let denom_inv = denom.modpow(&(&p - BigUint::from(2u8)), &p);
			(&neg_a * &denom_inv) % &p
		};
		let gx1 = {
			let x1_sq = (&x1 * &x1) % &p;
			let a_x1 = (&mont_a * &x1) % &p;
			let inner = (&x1_sq + &a_x1 + BigUint::one()) % &p;
			(&x1 * &inner) % &p
		};
		// is_square via Euler's criterion (treat 0 as square).
		let is_sq = gx1.is_zero() || gx1.modpow(
			&((&p - BigUint::from(1u8)) / BigUint::from(2u8)), &p,
		) == BigUint::one();
		if is_sq { sq_branch += 1; } else { nsq_branch += 1; }
	}
	assert!(sq_branch > 0, "elligator2 fuzzer never hit gx1-square branch");
	assert!(nsq_branch > 0, "elligator2 fuzzer never hit gx1-nonsquare branch");
}

#[test]
fn fuzz_elligator2_is_deterministic() {
	let mut rng = StdRng::seed_from_u64(0xEDE7_EDE7_EDE7_5012u64);
	for i in 0..200 {
		let u = pick_input(i, &mut rng);
		let p1 = map_to_curve_elligator2_edwards25519(&u);
		let p2 = map_to_curve_elligator2_edwards25519(&u);
		assert_eq!(p1, p2, "elligator2 not deterministic at iter={}", i);
	}
}

#[test]
fn fuzz_elligator2_negation_symmetry() {
	// RFC 9380 §G.2.1: the Elligator2 map for Curve25519 satisfies
	// map(u) = map(-u) (sign of u doesn't change the point — `u_sq` is
	// the only place u enters the algebra). Verify by sampling random u
	// and checking outputs match.
	let mut rng = StdRng::seed_from_u64(0xE6E6_E6E6_E6E6_5013u64);
	for i in 0..200 {
		let u = pick_input(i, &mut rng);
		let neg_u = neg(&u);
		let p1 = map_to_curve_elligator2_edwards25519(&u);
		let p2 = map_to_curve_elligator2_edwards25519(&neg_u);
		// Compare via Edwards-compressed bytes (extended-coord aliasing).
		let b1 = our_ed_compress(&p1);
		let b2 = our_ed_compress(&p2);
		assert_eq!(
			b1, b2,
			"elligator2 fails u/-u symmetry at iter={}\n  u = {}",
			i,
			limbs_hex(&u),
		);
	}
}
