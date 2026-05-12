// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-hash-to-curve-air
//!
//! Hash-to-curve for Edwards25519 over the Rostro Goldilocks-Plonky3 stack.
//! Composes existing primitives — hash_to_field (H4/H5), Elligator2 map
//! (H1), Edwards25519 point add (P), Edwards25519 point double (P) — into
//! the RFC 9380 §5.2 RO-mode hash_to_curve construction:
//!
//! ```text
//! hash_to_curve(msg) =
//!     (u_0, u_1) := hash_to_field(msg, count=2);
//!     P_0       := map_to_curve(u_0);
//!     P_1       := map_to_curve(u_1);
//!     R         := P_0 + P_1;
//!     P         := clear_cofactor(R);   // ×8 for Edwards25519
//!     return P;
//! ```
//!
//! ## Inputs and outputs
//!
//! - **Input:** `private_nullifier ∈ F_q` (Goldilocks). The OPRF input per
//!   `pop_zkpassport_oprf_pattern.md`.
//! - **Output:** `EdwardsPoint` in the prime-order subgroup of Edwards25519.
//!
//! ## What this crate is NOT
//!
//! - The AIR for hash_to_curve is forthcoming (H6b). This commit lands only
//!   the witness function + tests.
//! - Cofactor clearing here is the simple `8 · R` (RFC 9380 §7) — sufficient
//!   for Edwards25519 because the cofactor is exactly 8.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use p3_goldilocks::Goldilocks;
use rostro_curve25519::elligator2::map_to_curve_elligator2_edwards25519;
use rostro_curve25519::point::{add as point_add, double as point_double, EdwardsPoint};
use rostro_hash_to_field_air::hash_to_field;

/// Service bus name for hash-to-curve (used by the forthcoming
/// [`Hash2CurveAir`] in H6b). Payload `(private_nullifier, P[32])` =
/// 33 cells, where `P` is `(x[8], y[8], z[8], t[8])` extended-coords.
pub const BUS_HASH_TO_CURVE: &str = "rostro-hash-to-curve";

/// Hash a Goldilocks field element to a prime-order Edwards25519 point per
/// RFC 9380 §5.2 RO-mode construction (Poseidon2-flavored expand_message
/// per the locked `DST` in [`rostro_hash_to_field_air::DST`]).
///
/// Composition:
/// 1. `(u_0, u_1) := hash_to_field(private_nullifier)`
/// 2. `P_0 := map_to_curve_elligator2_edwards25519(u_0)`
/// 3. `P_1 := map_to_curve_elligator2_edwards25519(u_1)`
/// 4. `R := P_0 + P_1`
/// 5. `P := 8 · R` (cofactor clear)
///
/// Returns `P` in extended twisted-Edwards coordinates `(X, Y, Z, T)`.
/// `P` is on Edwards25519 and in the prime-order subgroup.
pub fn hash_to_curve(private_nullifier: Goldilocks) -> EdwardsPoint {
	let (u_0, u_1) = hash_to_field(private_nullifier);
	let p_0 = map_to_curve_elligator2_edwards25519(&u_0);
	let p_1 = map_to_curve_elligator2_edwards25519(&u_1);
	let r = point_add(&p_0, &p_1);
	clear_cofactor(&r)
}

/// Multiply by the Edwards25519 cofactor (8) via three point doublings.
///
/// Per RFC 9380 §7: for a curve with cofactor `h = 2^k`, the cheapest
/// cofactor clear is `k` point doublings rather than a generic scalar
/// multiplication. Edwards25519 has `k = 3`.
pub fn clear_cofactor(p: &EdwardsPoint) -> EdwardsPoint {
	let two_p = point_double(p);
	let four_p = point_double(&two_p);
	point_double(&four_p)
}

pub mod hash_to_curve_air;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod hash_to_curve_air_tests;
