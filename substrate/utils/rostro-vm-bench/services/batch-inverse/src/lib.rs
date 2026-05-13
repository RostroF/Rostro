// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! Montgomery's batch-inversion trick over Goldilocks.
//!
//! Algorithm — invert N elements with N-1 forward muls + 1 inversion + 2(N-1) back-pass muls:
//!   - Forward: prefix products p[i] = x[0] * x[1] * ... * x[i]
//!   - Single inversion: q = inv(p[N-1])
//!   - Backward: x[i]^-1 = q * p[i-1] for i = N-1..1, then x[0]^-1 = final q
//!
//! Total: ~3N muls + 1 inversion. Without the trick: N inversions ≈
//! 127N mul-shaped ops — ~40× more expensive at N=10⁵.
//!
//! The single inversion via Fermat's little theorem (`x^(p-2)`) does a
//! square-and-multiply ladder: ~64 squares + popcount(p-2)=63 muls, all
//! with dependent operands and a branchy bit dispatch. Different shape
//! from the chained-mul workloads we've benched so far.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
mod bump_alloc {
	use core::alloc::{GlobalAlloc, Layout};
	use core::cell::UnsafeCell;

	const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB — covers 2× 800 KiB Vecs + slack

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

use gp::{add, canonical, inv, mul, ZERO};

const N: usize = 100_000;
const SEED: u64 = 0x123456789abcdef0;
const MULTIPLIER: u64 = 0x9E3779B97F4A7C15;

pub fn batch_inverse_bench() -> u32 {
	// Generate N input values deterministically.
	let mut x: Vec<u64> = Vec::with_capacity(N);
	let mut s = SEED;
	let mut i = 0;
	while i < N {
		s = mul(s, MULTIPLIER);
		x.push(s);
		i += 1;
	}

	// Forward pass — prefix products. p[i] = x[0] * x[1] * ... * x[i].
	let mut p: Vec<u64> = Vec::with_capacity(N);
	let mut acc = x[0];
	p.push(acc);
	let mut j = 1;
	while j < N {
		acc = mul(acc, x[j]);
		p.push(acc);
		j += 1;
	}

	// Single field inversion of the total product. Costs ~127 mul-shaped
	// ops via square-and-multiply on `p - 2`.
	let mut q = inv(p[N - 1]);

	// Backward pass — derive each x[i]^-1 in reverse, in-place into x.
	let mut k = N - 1;
	while k >= 1 {
		let inv_x_k = mul(q, p[k - 1]);
		q = mul(q, x[k]);
		x[k] = inv_x_k;
		k -= 1;
	}
	// After the loop, q = inv(x[0]) (since p[-1] = 1 is implicit).
	x[0] = q;

	// Sum the inverses for a deterministic fingerprint.
	let mut accum = ZERO;
	let mut m = 0;
	while m < N {
		accum = add(accum, x[m]);
		m += 1;
	}

	(canonical(accum) & 0xFFFF_FFFF) as u32
}
