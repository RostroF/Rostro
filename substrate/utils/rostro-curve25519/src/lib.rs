// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-curve25519
//!
//! Non-native Curve25519 / Ristretto255 arithmetic as Plonky3 AIRs over Goldilocks.
//!
//! This crate is the foundational primitive for the PoP path's
//! `verified_oprf` step. It implements 256-bit base-field arithmetic
//! (`F_p` with `p = 2^255 - 19`) over Plonky3's Goldilocks
//! (`p_G = 2^64 - 2^32 + 1`) field via a foreign-field representation.
//! Every primitive carries constraint discipline and is dev-tested
//! against `curve25519-dalek` as the pure-Rust oracle.
//!
//! ## Why this crate exists
//!
//! Per `pop_design_section1c_oprf_nullifier.md` (locked 2026-05-09,
//! refined 2026-05-10), Rostro's OPRF nullifier is a 2HashDH-VOPRF over
//! Ristretto255. Verification needs:
//! - Hash-to-curve (RFC 9380 `edwards25519_XMD:SHA-512_ELL2_RO_`)
//! - Edwards25519 group ops (point add, double, scalar mul)
//! - Ristretto255 encoding / decoding (canonical-form check + decode)
//! - Chaum-Pedersen dlog-equality verification (Lagrange-aggregated
//!   single proof against the on-chain combined `K_pub`)
//!
//! Curve25519 is not native to Goldilocks. Its base field is
//! `2^255 - 19`, which doesn't embed in Goldilocks (`2^64 - 2^32 + 1`).
//! All field operations are foreign-field arithmetic: a 256-bit value is
//! represented as 8 × u32 limbs (per the locked
//! `pop_air_goldilocks_packing_convention.md` — one u32 per Goldilocks
//! element), and field multiply/reduce is a multi-limb schoolbook with
//! witnessed quotients + range-check lookups against `rostro-range-check`.
//!
//! The cost is real (O(thousands) of constraints per scalar mul) but
//! the cost is paid ONCE per PoP mint, which is a once-per-5-years
//! event per user. Not a hot loop.
//!
//! ## Status (2026-05-10) — scaffolded
//!
//! - Crate created with explicit dev-dep on `curve25519-dalek` 4.1 as
//!   the pure-Rust oracle for all soundness tests.
//! - 256-bit field-element representation: 8 × u32 limbs little-endian,
//!   matching the locked packing convention.
//! - **Pending:** add/sub field arithmetic + AIR constraints + tests.
//! - **Pending:** mul + Barrett or Montgomery reduction (the heavy
//!   primitive; ~hundreds of constraints per multiply).
//! - **Pending:** Edwards25519 point representation + group ops.
//! - **Pending:** scalar mul (double-and-add over scalar bits).
//! - **Pending:** Ristretto255 canonical encoding + decoding.
//! - **Pending:** hash-to-curve (Edwards25519 ELL2 RO method).
//! - **Pending:** Chaum-Pedersen dlog-equality AIR.
//!
//! Each pending unit lands in its own commit with its own oracle-test
//! suite. The full crate is multi-session work; soundness is
//! load-bearing for PoP privacy guarantees, so no shortcuts.
//!
//! ## Curve25519 base field constants
//!
//! `p = 2^255 - 19`. Big-endian byte representation:
//! `7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED`.
//! Little-endian u32-limb representation (8 limbs, limb[0] = least
//! significant 32 bits) is pinned in [`field::P_LIMBS`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod field;
pub mod field_air;
pub mod field_sub_air;

#[cfg(test)]
mod oracle_tests_helpers;

#[cfg(test)]
mod oracle_tests;

#[cfg(test)]
mod field_air_tests;

#[cfg(test)]
mod field_sub_air_tests;
