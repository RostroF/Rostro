// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Plonky3 STARK-verifier-shaped workload — Fiat-Shamir transcript +
//! FRI-fold linear combinations + AIR constraint evaluation, all in
//! Goldilocks field with WIDTH=8 Poseidon2 hash. Mirrors what
//! `p3_uni_stark::verify` does in its hot loop.
//!
//! ## Why hand-written instead of using Plonky3 directly
//!
//! Plonky3's crates transitively pull in `tracing`, which requires
//! atomic-pointer-width support. JAR/Grey's javm target sets
//! `max-atomic-width: 0` (no atomics — single-threaded VM by design),
//! so anything pulling in `tracing` doesn't compile to javm. Hand-written
//! Goldilocks + Poseidon2 with no deps compiles to javm, polkavm, AND
//! wasm32 cleanly.
//!
//! The implementation is bit-exact with `p3_goldilocks::default_goldilocks_poseidon2_8`
//! (same round constants, same MDS matrices, same S-box) — verified by a
//! host-side test in `tests/`.
//!
//! ## Workload proportions per `mini_verifier_bench()` call
//!
//!   - 16 transcript Poseidon2 permutations (Fiat-Shamir derives)
//!   - 32 FRI queries × 12 fold steps = 384 permutations + 384 linear combs
//!   - 32 constraint-eval chains × 50 mul-add ops = 1600 Goldilocks ops
//!
//! Total ≈ 400 permutations + ~2400 Goldilocks field ops per call —
//! representative of one moderate STARK verify.
//!
//! Returns the low 32 bits of a deterministic accumulator for cross-VM
//! correctness checking.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_arch = "wasm32")]
mod wasm;

use gp::{add, canonical, mul, permute, sub, ONE, WIDTH, ZERO};
const TRANSCRIPT_PERMS: usize = 16;
const FRI_QUERIES: usize = 32;
const FRI_FOLDS_PER_QUERY: usize = 12;
const CONSTRAINT_EVALS: usize = 32;
const CONSTRAINT_OPS_PER_EVAL: usize = 50;

/// One STARK-verifier-shaped pass. Returns low 32 bits of the accumulator
/// for cross-VM correctness checking.
pub fn mini_verifier_bench() -> u32 {
	// Deterministic seed — every cell distinct so all-zero collisions
	// don't hide bugs.
	let mut state: [u64; WIDTH] = [
		0xdeadbeef_00000000,
		0xdeadbeef_00000001,
		0xdeadbeef_00000002,
		0xdeadbeef_00000003,
		0xdeadbeef_00000004,
		0xdeadbeef_00000005,
		0xdeadbeef_00000006,
		0xdeadbeef_00000007,
	];

	// Stage 1 — Fiat-Shamir transcript: absorb pseudo-public-inputs and
	// squeeze derived challenges. Mirrors the verifier deriving each
	// round's challenge from the prior commitment.
	let mut i = 0u64;
	while i < TRANSCRIPT_PERMS as u64 {
		let slot = (i as usize) % WIDTH;
		state[slot] = add(state[slot], i.wrapping_mul(0x9E3779B97F4A7C15));
		permute(&mut state);
		i += 1;
	}

	// Stage 2 — FRI verification: per query, walk the fold tree. Per fold,
	// hash to advance the transcript + do a degree-1 linear combination
	// (the actual FRI fold formula).
	let mut accum = ZERO;
	let mut q = 0;
	while q < FRI_QUERIES {
		let mut left = state[0];
		let mut right = state[1];
		let mut sibling = state[2];
		let mut fold = 0;
		while fold < FRI_FOLDS_PER_QUERY {
			permute(&mut state);
			let challenge = state[(q + fold) % WIDTH];
			// FRI fold: f_next = (1 - challenge) * left + challenge * right.
			// Three muls + one add — matches the actual fold formula's
			// operation count on the verifier side.
			let one_minus_c = sub(ONE, challenge);
			left = add(mul(one_minus_c, left), mul(challenge, right));
			right = sibling;
			sibling = state[3];
			fold += 1;
		}
		accum = add(accum, left);
		q += 1;
	}

	// Stage 3 — AIR constraint evaluation at challenge points. Each
	// "constraint" reduces to a small chain of mul-adds in the field.
	// 32 × 50 = 1600 Goldilocks ops; representative of a moderate AIR's
	// per-row constraint count.
	let coeff_a = state[3];
	let coeff_b = state[5];
	let mut k = 0;
	while k < CONSTRAINT_EVALS {
		let mut x = state[k % WIDTH];
		let mut j = 0;
		while j < CONSTRAINT_OPS_PER_EVAL {
			x = add(mul(x, coeff_a), coeff_b);
			j += 1;
		}
		accum = add(accum, x);
		k += 1;
	}

	(canonical(accum) & 0xFFFF_FFFF) as u32
}
