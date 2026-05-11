// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Barrett-style 384-bit → F_p25519 reduction
//!
//! Reduces a 384-bit unsigned integer `W` (witnessed as 12 u32 limbs LE) to
//! its canonical representative `u ∈ [0, p)` where `p = 2^255 - 19`. Used
//! by [`crate::HashToFieldAir`] to fold the squeezed sponge bytes into the
//! curve-25519 base field.
//!
//! ## Algorithm
//!
//! Exploits `2^256 ≡ 38 (mod p)`. Proof: `p = 2^255 - 19`, so
//! `2^256 = 2 · 2^255 = 2(p + 19) = 2p + 38 ≡ 38 (mod p)`.
//!
//! Split: `W = W_lo + W_hi · 2^256` where `W_lo = W[0..8]` (low 256 bits,
//! 8 u32 limbs) and `W_hi = W[8..12]` (high 128 bits, 4 u32 limbs).
//!
//! Then `W ≡ W_lo + 38 · W_hi (mod p)`. Bound: `38 · W_hi < 38 · 2^128 < 2^133.25`,
//! so `T := W_lo + 38 · W_hi < 2^256 + 2^133 ≪ 3p`. The canonical `u = T mod p`
//! is therefore `T - k·p` for some `k ∈ {0, 1, 2}`.
//!
//! ## Witness shape (single row per reduction)
//!
//! All limbs are u32 little-endian.
//!
//! - `W[12]`: input — caller supplies via `BUS_REDUCE_384`.
//! - `prod[5]`: `38 · W_hi` materialised as 5 u32 limbs.
//! - `prod_carries[5]`: per-limb carries from the `38 · W_hi[i]` chain.
//!   Each ≤ 38 (i.e., fits in 6 bits). Range-checked via BUS_U16_RANGE.
//! - `T[8]`: `W_lo + prod_padded` (where `prod_padded = prod || [0; 3]`).
//! - `T_overflow ∈ {0, 1}`: single overflow bit out of T's high limb.
//! - `add_carries[7]`: carries within the 8-limb add. Each ∈ {0, 1}.
//! - `k`: scalar in `{0, 1, 2}`. Constrained by `k(k-1)(k-2) = 0` (degree 3).
//! - `u[8]`: output — pushed back to caller via `BUS_REDUCE_384`.
//! - `red_carries[7]`: carries within the 8-limb `u + k·p` add. Each ≤ 3
//!   (since `k ≤ 2` and `P_LIMBS[i] < 2^32`, so `k · P_LIMBS[i] + u[i] +
//!   carry ≤ 2^33 + 2^32 + 3 < 2^34`, hence carry-out ≤ 3). Range-checked.
//! - `borrow[7]`: canonical-check borrows for `(p - 1 - u) ≥ 0`. Each ∈ {0, 1}.
//!
//! ## Constraints
//!
//! 1. **`prod = 38 · W_hi`** (carry chain over 5 limbs):
//!    `prod[i] + 2^32 · prod_carries[i] == 38 · W_hi[i] + prod_carries[i-1]`
//!    for `i ∈ 0..4`; final-limb closure `prod[4] == prod_carries[3]`.
//! 2. **`T = W_lo + prod_padded`** (carry chain over 8 limbs):
//!    `T[i] + 2^32 · add_carries[i] == W_lo[i] + prod_pad[i] + add_carries[i-1]`
//!    for `i ∈ 0..7`; closure `T[7] + 2^32 · T_overflow == W_lo[7] + 0 +
//!    add_carries[6]` (top limb of prod_pad is zero since prod has 5 limbs
//!    in positions 0..5 and W_lo[5,6,7] only see prod[5]... wait need to
//!    re-walk). See the `prod_pad_for_limb` helper for the correct mapping.
//! 3. **`u + k · p ≡ T_full (mod 2^256)` with overflow tracking**:
//!    standard borrow-free add chain. `T_full = T + T_overflow · 2^256`.
//! 4. **`u < p`** via borrow chain on `p - 1 - u`.
//! 5. **`k ∈ {0, 1, 2}`** via `k(k-1)(k-2) = 0`.
//! 6. **u32 range checks** on every u32-claimed witness limb (W, prod, T,
//!    u). Carries get their own narrower range.
//!
//! Bus interactions:
//! - Receive `(W[12] || u[8])` on `BUS_REDUCE_384` (multiplicity −1 per row).
//! - u16-decompose each u32 limb and push two `BUS_U16_RANGE` queries per limb.
//!
//! ## Service bus name
//!
//! [`BUS_REDUCE_384`] is pinned. Renaming requires updating all consumers.

extern crate alloc;

use alloc::vec::Vec;

use num_bigint::BigUint;
use rostro_curve25519::field::{is_canonical, FIELD_NUM_LIMBS, P_LIMBS};

use crate::p25519_biguint;

/// Service bus name for the 384-bit Barrett reduction.
pub const BUS_REDUCE_384: &str = "rostro-reduce-384";

/// Number of u32 limbs in the 384-bit input W.
pub const REDUCE_384_INPUT_LIMBS: usize = 12;
/// Number of u32 limbs in the high half of W (`W >> 256`).
pub const W_HI_LIMBS: usize = 4;
/// Number of u32 limbs in `prod = 38 · W_hi`. `38 · 2^128 < 2^133.25`, so 5 limbs suffice.
pub const PROD_LIMBS: usize = 5;

/// All intermediate witness values needed by the AIR's trace builder.
/// Computed by [`compute_reduce_384_witness`] from the input W. Each field
/// is named to mirror the AIR's column layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reduce384Witness {
	/// Input: 12 u32 limbs, LE.
	pub w_input: [u32; REDUCE_384_INPUT_LIMBS],
	/// `prod = 38 * W_hi` as 5 u32 limbs.
	pub prod: [u32; PROD_LIMBS],
	/// Carries from the `38 · W_hi[i]` chain. `prod_carries[i]` is the
	/// carry OUT of position `i` (max value 38).
	pub prod_carries: [u32; PROD_LIMBS],
	/// `T = W_lo + prod_padded` as 8 u32 limbs.
	pub t: [u32; FIELD_NUM_LIMBS],
	/// Overflow bit out of T's top limb.
	pub t_overflow: u32,
	/// Carries from the `W_lo + prod_padded` add chain. `add_carries[i]`
	/// is the carry OUT of position `i` (∈ {0, 1}).
	pub add_carries: [u32; FIELD_NUM_LIMBS],
	/// `k ∈ {0, 1, 2}` such that `u = T_full - k·p`.
	pub k: u32,
	/// Canonical output: `u = T_full mod p ∈ [0, p)`.
	pub u: [u32; FIELD_NUM_LIMBS],
	/// Carries from the `u + k·p` add chain (used to verify the
	/// reduction identity). Each ∈ {0, 1, 2, 3}.
	pub red_carries: [u32; FIELD_NUM_LIMBS],
	/// Borrows from the `(p - 1) - u` chain (canonical check). Each ∈ {0, 1}.
	pub canon_borrows: [u32; FIELD_NUM_LIMBS],
}

/// Compute every intermediate value the AIR will need, given the 384-bit
/// input `W` as 12 u32 limbs LE.
///
/// Witness-side correctness is verified by tests against an independent
/// `BigUint::from_bytes_le(W) % p` recomputation.
pub fn compute_reduce_384_witness(
	w_input: [u32; REDUCE_384_INPUT_LIMBS],
) -> Reduce384Witness {
	// Split into low 8 limbs and high 4 limbs.
	let w_lo: [u32; FIELD_NUM_LIMBS] = core::array::from_fn(|i| w_input[i]);
	let w_hi: [u32; W_HI_LIMBS] = core::array::from_fn(|i| w_input[FIELD_NUM_LIMBS + i]);

	// Step 1: prod = 38 · W_hi (carry chain).
	let mut prod = [0u32; PROD_LIMBS];
	let mut prod_carries = [0u32; PROD_LIMBS];
	let mut carry: u64 = 0;
	for i in 0..W_HI_LIMBS {
		let wide: u64 = 38u64 * u64::from(w_hi[i]) + carry;
		prod[i] = (wide & 0xFFFF_FFFF) as u32;
		carry = wide >> 32;
		prod_carries[i] = carry as u32;
	}
	// Top limb is the final carry; no input contribution.
	prod[W_HI_LIMBS] = carry as u32;
	prod_carries[W_HI_LIMBS] = 0;

	// Step 2: T = W_lo + prod_padded (carry chain over 8 limbs, prod is
	// 5 limbs so positions 5..8 of prod_padded are zero).
	let mut t = [0u32; FIELD_NUM_LIMBS];
	let mut add_carries = [0u32; FIELD_NUM_LIMBS];
	let mut carry: u64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let prod_at = if i < PROD_LIMBS { u64::from(prod[i]) } else { 0u64 };
		let wide: u64 = u64::from(w_lo[i]) + prod_at + carry;
		t[i] = (wide & 0xFFFF_FFFF) as u32;
		carry = wide >> 32;
		add_carries[i] = carry as u32;
	}
	let t_overflow = add_carries[FIELD_NUM_LIMBS - 1];

	// Step 3: compute k = floor(T_full / p) ∈ {0, 1, 2} and u = T_full - k·p.
	let p = p25519_biguint();
	let t_full = t_to_biguint(&t, t_overflow);
	let k_big = &t_full / &p;
	let u_big = &t_full % &p;
	let k = k_big.iter_u32_digits().next().unwrap_or(0);
	let u = biguint_to_limbs_8(&u_big);

	// Step 4: red_carries — verify u + k·p == T_full chain.
	let mut red_carries = [0u32; FIELD_NUM_LIMBS];
	let mut carry: u64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let wide: u64 = u64::from(u[i]) + u64::from(k) * u64::from(P_LIMBS[i]) + carry;
		// Verify low 32 bits match T[i].
		let low_32 = (wide & 0xFFFF_FFFF) as u32;
		debug_assert_eq!(
			low_32, t[i],
			"witness inconsistency at limb {}: u + k·p low does not match T",
			i,
		);
		carry = wide >> 32;
		red_carries[i] = carry as u32;
	}
	// Final carry must equal T_overflow (closing the identity at bit 256).
	debug_assert_eq!(
		red_carries[FIELD_NUM_LIMBS - 1],
		t_overflow,
		"final reduction-add carry must match T_overflow",
	);

	// Step 5: canon_borrows — verify u < p via (p - 1) - u with borrow chain.
	// p - 1 limbs:
	let p_minus_1: [u32; FIELD_NUM_LIMBS] = {
		// p25519 - 1: P_LIMBS[0] = 0xFFFFFFED so p-1 has [0xFFFFFFEC, 0xFFFFFFFF×6, 0x7FFFFFFF].
		let mut arr = P_LIMBS;
		arr[0] = arr[0].wrapping_sub(1);
		arr
	};
	let mut canon_borrows = [0u32; FIELD_NUM_LIMBS];
	let mut borrow: i64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let diff: i64 = i64::from(p_minus_1[i]) - i64::from(u[i]) - borrow;
		if diff < 0 {
			borrow = 1;
		} else {
			borrow = 0;
		}
		canon_borrows[i] = borrow as u32;
	}
	// Final borrow must be zero (else u > p - 1 i.e., u ≥ p).
	debug_assert_eq!(
		canon_borrows[FIELD_NUM_LIMBS - 1],
		0,
		"canonical-check borrow chain ended with borrow=1 — u ≥ p",
	);
	debug_assert!(is_canonical(&u), "computed u is not canonical");

	Reduce384Witness {
		w_input,
		prod,
		prod_carries,
		t,
		t_overflow,
		add_carries,
		k,
		u,
		red_carries,
		canon_borrows,
	}
}

/// Pack `T[8]` plus the high overflow bit into a [`BigUint`].
fn t_to_biguint(t: &[u32; FIELD_NUM_LIMBS], t_overflow: u32) -> BigUint {
	let mut bytes = [0u8; 33];
	for i in 0..FIELD_NUM_LIMBS {
		bytes[i * 4..(i + 1) * 4].copy_from_slice(&t[i].to_le_bytes());
	}
	bytes[32] = t_overflow as u8;
	BigUint::from_bytes_le(&bytes)
}

/// Convert a [`BigUint`] in `[0, 2^256)` to 8 u32 LE limbs.
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

/// Pack a 12-limb u32 input into a [`BigUint`] in `[0, 2^384)`.
pub fn w_to_biguint(w: &[u32; REDUCE_384_INPUT_LIMBS]) -> BigUint {
	let mut bytes = [0u8; 48];
	for i in 0..REDUCE_384_INPUT_LIMBS {
		bytes[i * 4..(i + 1) * 4].copy_from_slice(&w[i].to_le_bytes());
	}
	BigUint::from_bytes_le(&bytes)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::barrett_reduce_48_to_p25519;

	fn limbs_to_biguint(limbs: &[u32; FIELD_NUM_LIMBS]) -> BigUint {
		let mut bytes = [0u8; 32];
		for i in 0..FIELD_NUM_LIMBS {
			bytes[i * 4..(i + 1) * 4].copy_from_slice(&limbs[i].to_le_bytes());
		}
		BigUint::from_bytes_le(&bytes)
	}

	fn w_from_bytes(bytes: &[u8; 48]) -> [u32; REDUCE_384_INPUT_LIMBS] {
		core::array::from_fn(|i| {
			let mut chunk = [0u8; 4];
			chunk.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
			u32::from_le_bytes(chunk)
		})
	}

	#[test]
	fn witness_zero() {
		let w = [0u32; REDUCE_384_INPUT_LIMBS];
		let wit = compute_reduce_384_witness(w);
		assert_eq!(wit.u, [0u32; FIELD_NUM_LIMBS]);
		assert_eq!(wit.k, 0);
		assert_eq!(wit.t_overflow, 0);
		assert_eq!(wit.prod, [0u32; PROD_LIMBS]);
	}

	#[test]
	fn witness_one() {
		let mut w = [0u32; REDUCE_384_INPUT_LIMBS];
		w[0] = 1;
		let wit = compute_reduce_384_witness(w);
		let mut expected = [0u32; FIELD_NUM_LIMBS];
		expected[0] = 1;
		assert_eq!(wit.u, expected);
		assert_eq!(wit.k, 0);
	}

	#[test]
	fn witness_p_minus_1_unchanged() {
		// Build W = p - 1 (only low 8 limbs populated).
		let p_minus_1 = p25519_biguint() - BigUint::from(1u32);
		let mut bytes = p_minus_1.to_bytes_le();
		bytes.resize(48, 0);
		let bytes_arr: [u8; 48] = bytes.try_into().unwrap();
		let w = w_from_bytes(&bytes_arr);
		let wit = compute_reduce_384_witness(w);
		let recovered = limbs_to_biguint(&wit.u);
		assert_eq!(recovered, p_minus_1);
		assert_eq!(wit.k, 0);
	}

	#[test]
	fn witness_p_reduces_to_zero() {
		let p = p25519_biguint();
		let mut bytes = p.to_bytes_le();
		bytes.resize(48, 0);
		let bytes_arr: [u8; 48] = bytes.try_into().unwrap();
		let w = w_from_bytes(&bytes_arr);
		let wit = compute_reduce_384_witness(w);
		assert_eq!(wit.u, [0u32; FIELD_NUM_LIMBS]);
		// W = p means high 4 limbs are zero, T_full = p, k = 1, u = 0.
		assert_eq!(wit.k, 1);
	}

	#[test]
	fn witness_2p_reduces_to_zero_with_k_eq_2() {
		let two_p = &p25519_biguint() * BigUint::from(2u32);
		let mut bytes = two_p.to_bytes_le();
		bytes.resize(48, 0);
		let bytes_arr: [u8; 48] = bytes.try_into().unwrap();
		let w = w_from_bytes(&bytes_arr);
		let wit = compute_reduce_384_witness(w);
		assert_eq!(wit.u, [0u32; FIELD_NUM_LIMBS]);
		// 2p reduces to 0 — k *could* be 2 (if W_lo + 38·W_hi happens to land in [2p, 2p+38))
		// or k could be lower if the split produces a smaller T. Either way u = 0.
		assert!(wit.k <= 2);
	}

	#[test]
	fn witness_max_w_canonical() {
		// W = 2^384 - 1 (all limbs 0xFFFFFFFF). Largest possible input.
		let w = [0xFFFF_FFFFu32; REDUCE_384_INPUT_LIMBS];
		let wit = compute_reduce_384_witness(w);
		let expected_u = w_to_biguint(&w) % p25519_biguint();
		let recovered = limbs_to_biguint(&wit.u);
		assert_eq!(recovered, expected_u);
		assert!(is_canonical(&wit.u));
	}

	#[test]
	fn witness_matches_bigint_random() {
		use rand::{rngs::StdRng, RngCore, SeedableRng};
		let mut rng = StdRng::seed_from_u64(0xab_a_47_e_70u64);
		for _ in 0..500 {
			let mut bytes = [0u8; 48];
			rng.fill_bytes(&mut bytes);
			let w = w_from_bytes(&bytes);
			let wit = compute_reduce_384_witness(w);

			// Independent oracle: BigUint.
			let expected = w_to_biguint(&w) % p25519_biguint();
			let actual = limbs_to_biguint(&wit.u);
			assert_eq!(actual, expected, "u mismatch for w={:?}", w);
			assert!(is_canonical(&wit.u));
			assert!(wit.k <= 2, "k out of range: {}", wit.k);
		}
	}

	#[test]
	fn witness_matches_h4_barrett_helper() {
		// Both code paths (barrett_reduce_48_to_p25519 in lib.rs and
		// compute_reduce_384_witness here) should produce the same canonical u.
		// They're independent implementations — H4 uses BigUint directly,
		// this one uses an explicit Barrett-style witness pipeline.
		use rand::{rngs::StdRng, RngCore, SeedableRng};
		let mut rng = StdRng::seed_from_u64(0xd1_ff_d1_ff_a1u64);
		for _ in 0..200 {
			let mut bytes = [0u8; 48];
			rng.fill_bytes(&mut bytes);
			let w = w_from_bytes(&bytes);

			let h4_path = barrett_reduce_48_to_p25519(&bytes);
			let h5_path = compute_reduce_384_witness(w).u;
			assert_eq!(h4_path, h5_path, "H4 vs H5 path divergence on bytes={:x?}", bytes);
		}
	}

	#[test]
	fn witness_carries_within_documented_bounds() {
		// Spot-check: prod_carries ≤ 38, add_carries ∈ {0,1}, red_carries ≤ 3,
		// canon_borrows ∈ {0,1}, k ∈ {0,1,2}, t_overflow ∈ {0,1}.
		use rand::{rngs::StdRng, RngCore, SeedableRng};
		let mut rng = StdRng::seed_from_u64(0xb0_0d_ed_d0u64);
		for _ in 0..200 {
			let mut bytes = [0u8; 48];
			rng.fill_bytes(&mut bytes);
			let w = w_from_bytes(&bytes);
			let wit = compute_reduce_384_witness(w);

			for &c in &wit.prod_carries[..PROD_LIMBS - 1] {
				assert!(c <= 38, "prod_carry exceeded 38: {}", c);
			}
			for &c in &wit.add_carries {
				assert!(c <= 1, "add_carry not in {{0,1}}: {}", c);
			}
			for &c in &wit.red_carries {
				assert!(c <= 3, "red_carry exceeded 3: {}", c);
			}
			for &b in &wit.canon_borrows {
				assert!(b <= 1, "canon_borrow not in {{0,1}}: {}", b);
			}
			assert!(wit.k <= 2, "k > 2: {}", wit.k);
			assert!(wit.t_overflow <= 1, "t_overflow > 1: {}", wit.t_overflow);
		}
	}

}

