// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Poseidon2-WIDTH8 permutation-only benchmark. Runs `PERM_COUNT` permutations
//! in a chain so each iteration's input depends on the previous output.
//!
//! Returns the low 32 bits of state[0] for cross-VM correctness checking.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_arch = "wasm32")]
mod wasm;

use gp::{canonical, permute};

const PERM_COUNT: u32 = 1_000;

pub fn poseidon2_perm_bench() -> u32 {
	let mut state: [u64; 8] = [
		0xdeadbeef_00000000,
		0xdeadbeef_00000001,
		0xdeadbeef_00000002,
		0xdeadbeef_00000003,
		0xdeadbeef_00000004,
		0xdeadbeef_00000005,
		0xdeadbeef_00000006,
		0xdeadbeef_00000007,
	];
	let mut i = 0;
	while i < PERM_COUNT {
		permute(&mut state);
		i += 1;
	}
	(canonical(state[0]) & 0xFFFF_FFFF) as u32
}
