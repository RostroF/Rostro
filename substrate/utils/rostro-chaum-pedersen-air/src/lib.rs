// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-chaum-pedersen-air
//!
//! Chaum-Pedersen discrete-log equality verification over Edwards25519.
//!
//! Given:
//! - `pk` = `K · G`           (verifier-known)
//! - `response` = `K · blinded` (verifier-known)
//! - `R_pk`, `R_resp`, scalars `e`, `s`  (proof commitments + challenge + response)
//!
//! The AIR verifies the Σ-protocol equations:
//! - `s · G == R_pk + e · pk`
//! - `s · blinded == R_resp + e · response`
//!
//! Both equations holding implies the prover knows `K` such that
//! `pk = K · G` AND `response = K · blinded` (i.e., the same `K` was
//! used in both — dlog-equality).
//!
//! ## Scope
//!
//! This AIR ONLY verifies the algebraic equations. The Fiat-Shamir hash
//! that binds `e` to the transcript (`e = Hash(pk, blinded, response,
//! R_pk, R_resp)`) is the OUTER circuit's responsibility; verifying `e`
//! comes from the right transcript is what makes the proof
//! non-interactive. Splitting these concerns keeps this AIR
//! single-purpose and lets the outer FS hash evolve independently
//! (different sponge widths, transcript shapes, etc.).
//!
//! ## Use in OPRF nullifier flow
//!
//! Per `pop_zkpassport_oprf_pattern.md`, the federation publishes
//! `(response_blinded, dlog_e, dlog_s, pk)` after honestly evaluating
//! `K · blinded`. The user-side circuit verifies the dlog-equality via
//! this AIR before unblinding `response = response_blinded · beta⁻¹`
//! and computing the scoped nullifier. Without dlog-equality, a
//! dishonest federation could substitute a different scalar and link
//! nullifiers across services.
//!
//! ## Status
//!
//! v1 = Edwards25519 only. PQ migration via `OprfCurveId` discriminant
//! per `pop_pq_migration_oprf.md`; future Chaum-Pedersen-equivalent for
//! a lattice-based OPRF will live in a sibling crate.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use rostro_curve25519::field::{mul as field_mul, FIELD_NUM_LIMBS};
use rostro_curve25519::point::{add as point_add, scalar_mul, EdwardsPoint};
use rostro_curve25519::ristretto::compress as ristretto_compress;

/// Service bus name for the Chaum-Pedersen verification.
/// Payload = `(pk[32], blinded[32], response[32], R_pk[32], R_resp[32],
///             e_bytes[32], s_bytes[32])` = 224 cells.
pub const BUS_CP_DLOG_EQ: &str = "rostro-cp-dlog-eq";

/// Edwards25519 basepoint G in extended-coords. Pinned constants.
/// Re-derive: `dalek::ED25519_BASEPOINT_POINT` extended coordinates,
/// converted to our 8-limb u32 representation.
pub const ED25519_BASEPOINT_X: [u32; FIELD_NUM_LIMBS] = [
	0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760, 0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE,
	0x216936D3,
];
pub const ED25519_BASEPOINT_Y: [u32; FIELD_NUM_LIMBS] = [
	0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666,
	0x66666666,
];
pub const ED25519_BASEPOINT_Z: [u32; FIELD_NUM_LIMBS] =
	[1, 0, 0, 0, 0, 0, 0, 0];

/// Construct the Edwards25519 basepoint as an [`EdwardsPoint`].
/// `t = x · y mod p` is computed at call-time (small cost; could be a const
/// once `field_mul` is const-eval-friendly).
pub fn ed25519_basepoint() -> EdwardsPoint {
	let t = field_mul(&ED25519_BASEPOINT_X, &ED25519_BASEPOINT_Y);
	EdwardsPoint {
		x: ED25519_BASEPOINT_X,
		y: ED25519_BASEPOINT_Y,
		z: ED25519_BASEPOINT_Z,
		t,
	}
}

/// Off-circuit Chaum-Pedersen dlog-equality verification. Returns `true`
/// iff both Σ-protocol equations hold.
pub fn verify_chaum_pedersen(
	pk: &EdwardsPoint,
	blinded: &EdwardsPoint,
	response: &EdwardsPoint,
	r_pk: &EdwardsPoint,
	r_resp: &EdwardsPoint,
	e: &[u8; 32],
	s: &[u8; 32],
) -> bool {
	let g = ed25519_basepoint();
	let s_g = scalar_mul(s, &g);
	let e_pk = scalar_mul(e, pk);
	let s_blinded = scalar_mul(s, blinded);
	let e_response = scalar_mul(e, response);

	let lhs1 = ristretto_compress(&s_g);
	let rhs1 = ristretto_compress(&point_add(r_pk, &e_pk));
	if lhs1 != rhs1 {
		return false;
	}

	let lhs2 = ristretto_compress(&s_blinded);
	let rhs2 = ristretto_compress(&point_add(r_resp, &e_response));
	lhs2 == rhs2
}

pub mod chaum_pedersen_air;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod chaum_pedersen_air_tests;
