// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # rostro-curve-hooks
//!
//! [`RostroCurveHooks`]: one type implementing both
//! `ark_bls12_381_ext::CurveHooks` and
//! `ark_ed_on_bls12_381_bandersnatch_ext::CurveHooks`. On
//! `target_env = "polkavm"` every hooked group operation marshals to the
//! RVM's reserved ecalli intrinsics; natively the hooks replicate the
//! ext-crate defaults via zero-cost transmutation into plain arkworks, so
//! hooked and plain constructions are byte-equal by construction.
//!
//! This crate is the curve half of `rostro-guest-crypto` (the runtime
//! crypto facade), split out so the vendored `ark-vrf` and `sp-core` can
//! depend on the hooked curves without a dependency cycle through sp-io.
//! Runtime code should keep reaching it through the facade
//! (`rostro_guest_crypto::hooks`).
//!
//! ## MSM entry-point footgun
//!
//! On the hooked curves, call `VariableBaseMSM::msm(bases, scalars)` — it
//! routes through the curve config's override into the hooks. ark-ec's
//! `msm_unchecked`/`msm_bigint` defaults go straight to the generic
//! Pippenger implementation and BYPASS the config seam entirely: correct
//! results, interpreted speed (50-150x). w3f-pcs/ring-proof already call
//! `msm()` for exactly this reason; the facade bench harness
//! (`facade-rvm-bench`) guards against regressions to the bypassing entry
//! points.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(target_env = "polkavm")]
mod ecalli;
mod hooks;

pub use hooks::*;

/// Operand caps, mirrored from the RVM intrinsic arms
/// (`substrate/external/rostrovm/polkavm/src/interpreter.rs`). Enforced on
/// BOTH targets so behavior is target-independent; the hooks chunk MSM and
/// Miller-loop inputs beyond the caps (both are additive/multiplicative
/// over their inputs, so chunked results are bit-identical).
pub const MAX_BLS_PAIRS: usize = 8;
pub const MAX_BLS_MSM: usize = 8192;
pub const MAX_MUL_PROJECTIVE_LIMBS: usize = 8;
/// ark-bls12-381 0.5's G1 `mul_projective` is GLV and asserts limbs ≤ 4;
/// the G1 intrinsic fails closed above this and the hooks fall back to
/// in-guest arkworks (which panics exactly as plain ark would).
pub const MAX_G1_MUL_PROJECTIVE_LIMBS: usize = 4;
