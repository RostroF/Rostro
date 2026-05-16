// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Goldilocks-multiplication-only benchmark. Runs `MUL_COUNT` multiplications
//! in a chain so each iteration's input depends on the previous output —
//! prevents the optimizer from lifting the loop body out.
//!
//! Returns the low 32 bits of the canonicalized accumulator for cross-VM
//! correctness checking.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_arch = "wasm32")]
mod wasm;

use gp::{canonical, mul};

const MUL_COUNT: u32 = 100_000;
const SEED: u64 = 0x123456789abcdef0;
const MULTIPLIER: u64 = 0x9E3779B97F4A7C15;

// gp::mul itself now dispatches via the rostro_goldilocks_mul intrinsic on
// polkavm targets (Tier 2 H2 wiring moved into the gp crate so all services
// benefit). No service-local shim needed.
pub fn goldilocks_mul_bench() -> u32 {
	let mut acc = SEED;
	let mut i = 0;
	while i < MUL_COUNT {
		acc = mul(acc, MULTIPLIER);
		i += 1;
	}
	(canonical(acc) & 0xFFFF_FFFF) as u32
}
