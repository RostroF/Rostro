// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Tier 2 H2 (2026-05-12) — RostroVM crypto intrinsic imports.
//!
//! These imports get rewired by the polkavm linker into ecalli instructions
//! with the declared `index = N`. The RostroVM runtime's FAST_OP_ECALLI arm
//! intercepts these IDs and dispatches the native body inline (no run-loop
//! exit). Each intrinsic replaces ~10-130 decomposed PVM ops with a single
//! ecalli dispatch + the native body.
//!
//! Index allocation (matches `ROSTRO_INTRINSIC_*` in
//! `substrate/external/rostrovm/polkavm/src/interpreter.rs`):
//!   100 = goldilocks_mul   — single u64×u64 → u64 mod p
//!   101 = goldilocks_add   — u64+u64 → u64 (non-canonical, like gp::add)
//!   102 = goldilocks_sub   — u64-u64 → u64 (non-canonical)
//!   103 = goldilocks_inv   — Fermat inverse, ~127 mul-cost ops
//!   130 = poseidon2_perm   — full WIDTH=8 permutation, in-place

#[polkavm_derive::polkavm_import]
extern "C" {
    #[polkavm_import(index = 100)]
    pub fn rostro_goldilocks_mul(a: u64, b: u64) -> u64;

    #[polkavm_import(index = 101)]
    pub fn rostro_goldilocks_add(a: u64, b: u64) -> u64;

    #[polkavm_import(index = 102)]
    pub fn rostro_goldilocks_sub(a: u64, b: u64) -> u64;

    #[polkavm_import(index = 103)]
    pub fn rostro_goldilocks_inv(x: u64) -> u64;

    /// Phase 2 Tier 2 (2026-05-15) — full Poseidon2-Goldilocks-WIDTH8
    /// permutation. In-place; state_ptr points to 8 little-endian u64s
    /// (64 bytes). Returns 0 on success, 1 on memory-access failure.
    #[polkavm_import(index = 130)]
    pub fn rostro_poseidon2_permute(state_ptr: *mut u64) -> u32;
}
