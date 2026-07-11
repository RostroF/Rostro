// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # rostro-guest-crypto — the runtime crypto facade
//!
//! The single crate through which Rostro runtime code touches cryptography.
//! Policy (docs/RVM-VERIFY-INTRINSICS.md §6, enforced by review and a CI
//! grep): **runtime code does not depend on raw crypto crates for verify
//! paths; it goes through this facade.** The next cipher decision is a
//! facade entry plus an intrinsic, not an architecture discussion.
//!
//! Per cipher, operations dispatch to the best correct backend per target:
//!
//! | cipher / op | runtime backend | native/test backend |
//! |---|---|---|
//! | ed25519, sr25519, ecdsa-k1 verify | sp_io host functions | same |
//! | common hashes | sp_io host functions | same |
//! | P-256 verify | ecalli 112 | p256 crate |
//! | P-521 verify | ecalli 111 | p521 crate |
//! | ML-DSA-65 verify | ecalli 110 | fips204 crate |
//! | SLH-DSA-128s verify | ecalli 113 | vendored slh-dsa crate |
//! | secp256k1 recover (outside sp_io contexts) | ecalli 123 | k256 crate |
//! | BLS12-381 pairing check / MSM / miller / final-exp / mul | ecalli 114-118, 127/128 | ark-bls12-381 |
//! | bandersnatch TE/SW MSM + mul | ecalli 119, 124-126 | ark-ed-on-bls12-381-bandersnatch |
//!
//! The arkworks story rides [`RostroCurveHooks`]: one type implementing both
//! `ark_bls12_381_ext::CurveHooks` and
//! `ark_ed_on_bls12_381_bandersnatch_ext::CurveHooks`. On
//! `target_env = "polkavm"` every hooked group operation marshals to the
//! RVM's reserved ecalli intrinsics (native speed inside the interpreter);
//! natively the hooks replicate the ext-crate defaults (zero-cost
//! transmutation into plain arkworks), so hooked and plain constructions are
//! byte-equal — the consensus gate for the ring-VRF curve switch.
//!
//! The native verify backends are the SAME crates the RVM intrinsic bodies
//! use (`substrate/external/rostrovm/polkavm/src/interpreter.rs`), so the
//! two sides cannot drift; the differential tests in `tests/` pin them.
//!
//! Goldilocks / Poseidon2 (STARK path, ecalli 100-103/130) are not yet
//! surfaced here: they have no runtime consumer, and their native halves
//! live only in the VM crate. They join the table with their first consumer.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(target_env = "polkavm")]
mod ecalli;
pub mod verify;

/// The curve half lives in `rostro-curve-hooks` (split so the vendored
/// ark-vrf and sp-core can depend on the hooked curves without a cycle
/// through sp-io); the facade remains the single import path for runtime
/// code.
pub mod hooks {
	pub use rostro_curve_hooks::*;
}

pub use hooks::{
	RostroCurveHooks, MAX_BLS_MSM, MAX_BLS_PAIRS, MAX_G1_MUL_PROJECTIVE_LIMBS,
	MAX_MUL_PROJECTIVE_LIMBS,
};

/// Common hashes, delegated to sp_io host functions on both targets.
pub mod hashing {
	pub use sp_io::hashing::{blake2_128, blake2_256, keccak_256, sha2_256, twox_128, twox_256, twox_64};
}
