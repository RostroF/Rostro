// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Polynomial evaluation via Horner's method — mirrors `p3_uni_stark::verify`'s
//! AIR constraint polynomial evaluation at FRI challenge points.
//!
//! For each of `NUM_POINTS` challenge points x, evaluate a degree-(`DEGREE`-1)
//! polynomial p(x) = c_0 + c_1·x + c_2·x² + … + c_{DEGREE-1}·x^(DEGREE-1) via
//! Horner's method:
//!
//!   result = c[DEGREE-1]
//!   for i in (DEGREE-2)..=0:
//!       result = result * x + c[i]
//!
//! Memory access: sequential streaming read of `coeffs[]` (4096 × u64 = 32 KiB,
//! fits in L1). Compute: `DEGREE-1` chained `mul` + `add` per point —
//! totally dependent (each step needs the previous result), so no
//! instruction-level parallelism between iterations of the inner loop.
//!
//! This complements the existing benches:
//!   - `goldilocks-mul`: chained mul, no add, no memory
//!   - `mini-verifier`: closed-form constraint eval (no memory access)
//!   - `fri-fold-tree`: scattered memory access
//!
//! Together they decompose every memory-access pattern Plonky3's verifier
//! actually does.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
mod bump_alloc {
	use core::alloc::{GlobalAlloc, Layout};
	use core::cell::UnsafeCell;

	const HEAP_SIZE: usize = 64 * 1024; // 64 KiB — covers 32 KiB coeffs + slack

	pub struct BumpAlloc {
		heap: UnsafeCell<[u8; HEAP_SIZE]>,
		pos: UnsafeCell<usize>,
	}

	unsafe impl Sync for BumpAlloc {}

	unsafe impl GlobalAlloc for BumpAlloc {
		unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
			let pos = unsafe { &mut *self.pos.get() };
			let aligned = (*pos + layout.align() - 1) & !(layout.align() - 1);
			let next = aligned + layout.size();
			if next > HEAP_SIZE {
				return core::ptr::null_mut();
			}
			*pos = next;
			unsafe { (*self.heap.get()).as_mut_ptr().add(aligned) }
		}
		unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
	}

	#[global_allocator]
	static ALLOC: BumpAlloc = BumpAlloc {
		heap: UnsafeCell::new([0; HEAP_SIZE]),
		pos: UnsafeCell::new(0),
	};
}

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_os = "none")]
use alloc::vec::Vec;

use gp::{add, canonical, mul, ZERO};

const DEGREE: usize = 4096;
const NUM_POINTS: usize = 64;
const SEED_COEFFS: u64 = 0x123456789abcdef0;
const SEED_POINTS: u64 = 0xfedcba9876543210;
const MULTIPLIER: u64 = 0x9E3779B97F4A7C15;

pub fn poly_eval_bench() -> u32 {
	// Generate DEGREE coefficients deterministically via a Goldilocks
	// chain — sequential write into the bump-allocated buffer.
	let mut coeffs: Vec<u64> = Vec::with_capacity(DEGREE);
	let mut x = SEED_COEFFS;
	let mut i = 0;
	while i < DEGREE {
		x = mul(x, MULTIPLIER);
		coeffs.push(x);
		i += 1;
	}

	// Stack-allocated challenge points. NUM_POINTS = 64 → 512 B,
	// trivially fits in L1.
	let mut points: [u64; NUM_POINTS] = [0; NUM_POINTS];
	let mut y = SEED_POINTS;
	let mut j = 0;
	while j < NUM_POINTS {
		y = mul(y, MULTIPLIER);
		points[j] = y;
		j += 1;
	}

	// For each challenge point, evaluate via Horner's method.
	// Inner loop is fully data-dependent (no ILP between iterations).
	let mut accum = ZERO;
	let mut k = 0;
	while k < NUM_POINTS {
		let z = points[k];
		let mut result = coeffs[DEGREE - 1];
		let mut idx = DEGREE - 1;
		while idx > 0 {
			idx -= 1;
			result = add(mul(result, z), coeffs[idx]);
		}
		accum = add(accum, result);
		k += 1;
	}

	(canonical(accum) & 0xFFFF_FFFF) as u32
}
