// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Sanity check that the JIT (`polkavm-comp` with Phase 2a CustomCodegen)
//! actually does the goldilocks_mul work and isn't just returning garbage.
//!
//! Two independent confirmations:
//! 1. **Result fingerprint** matches the canonical 0x2cf73e57 (which can only
//!    arise from running all 100k chained multiplies).
//! 2. **Gas consumed** by the JIT matches gas consumed by the interpreter.
//!    Gas is incremented per PVM instruction executed; if the JIT were
//!    skipping work, it would consume far less gas than the interpreter.
//!
//! Also prints the native-Rust reference computation for comparison.

use rostro_vm_bench::{RvmRunner, runners::PolkaVmRunner, service_blobs::GOLDILOCKS_MUL_POLKAVM_BLOB};

const GOLDILOCKS_P: u64 = 0xFFFFFFFF00000001;
const SEED: u64 = 0x123456789abcdef0;
const MULTIPLIER: u64 = 0x9E3779B97F4A7C15;
const MUL_COUNT: u32 = 100_000;

#[inline]
fn reduce128(x: u128) -> u64 {
	let lo = x as u64;
	let hi = (x >> 64) as u64;
	let hi_hi = hi >> 32;
	let hi_lo = hi & 0xFFFFFFFF;
	let (t, b) = lo.overflowing_sub(hi_hi);
	let t = if b { t.wrapping_add(GOLDILOCKS_P) } else { t };
	let prod_lo = (hi_lo << 32).wrapping_sub(hi_lo);
	let (r, c) = t.overflowing_add(prod_lo);
	if c || r >= GOLDILOCKS_P { r.wrapping_sub(GOLDILOCKS_P) } else { r }
}

fn native_reference() -> u32 {
	let mut acc = SEED;
	for _ in 0..MUL_COUNT {
		acc = reduce128((acc as u128) * (MULTIPLIER as u128));
	}
	let canonical = if acc >= GOLDILOCKS_P { acc - GOLDILOCKS_P } else { acc };
	(canonical & 0xFFFF_FFFF) as u32
}

fn main() {
	let blob = GOLDILOCKS_MUL_POLKAVM_BLOB;
	let expected = native_reference();
	println!("native reference: 0x{expected:08x}\n");

	for (label, mut runner) in [
		("rvm-int", PolkaVmRunner::interpreter().expect("interp build")),
		("rvm-jit", PolkaVmRunner::compiler().expect("compiler build")),
	] {
		let out = runner.run(&blob, &[]).unwrap();
		let result_low32 = out.result_a0 as u32;
		let agree = if result_low32 == expected { "✓ AGREE" } else { "✗ DISAGREE" };
		println!(
			"{label:>8}: result=0x{result_low32:08x} ({agree})  gas_consumed={}",
			out.gas_consumed
		);
	}
}
