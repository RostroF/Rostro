// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Synthetic shape exhibits for the coin-sort tracer.
//!
//! Each `shape_*` function isolates ONE dispatch-shape pattern so the tracer
//! can record a clean, repetition-free trace of it. The compiler's choice
//! of PVM ops for each function is what we observe — the source code is
//! kept minimal so the resulting blob is small enough to trace exhaustively.
//!
//! Use via the `trace_synth` example — it loads this blob, picks each
//! `shape_*` export by symbol, runs it under the tracer, and dumps the
//! per-shape result.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_arch = "wasm32")]
mod wasm;

// ── shape_add_chain ─────────────────────────────────────────────────────
// Five sequential add-with-immediate operations. Tests ArmRegRegImm64 in
// isolation. Should produce ~5 FAST_OP_ADD_IMM_64 dispatches with no
// branches, no memory access, no intrinsics.
pub fn shape_add_chain() -> u32 {
	let mut acc: u32 = 0x1000;
	acc = acc.wrapping_add(0x10);
	acc = acc.wrapping_add(0x20);
	acc = acc.wrapping_add(0x30);
	acc = acc.wrapping_add(0x40);
	acc = acc.wrapping_add(0x50);
	acc
}

// ── shape_branch_loop ───────────────────────────────────────────────────
// Tight loop with backward branch (3 iterations). Tests ArmBranchRegImm
// + UnresolvedFirstTime → Optimal transition on the loop branch.
pub fn shape_branch_loop() -> u32 {
	let mut sum: u32 = 0;
	let mut i: u32 = 0;
	while i < 3 {
		sum = sum.wrapping_add(i);
		i = i.wrapping_add(1);
	}
	sum
}

// ── shape_load_store ────────────────────────────────────────────────────
// Stack-allocated 4-element array, write each, read each. Tests
// ArmStoreIndirect + ArmLoadIndirect. Real memory access patterns.
#[inline(never)]
pub fn shape_load_store() -> u32 {
	let mut buf: [u32; 4] = [0; 4];
	buf[0] = 0xAA;
	buf[1] = 0xBB;
	buf[2] = 0xCC;
	buf[3] = 0xDD;
	buf[0].wrapping_add(buf[1]).wrapping_add(buf[2]).wrapping_add(buf[3])
}

// ── shape_intrinsic_once ────────────────────────────────────────────────
// ONE call to gp::mul (goldilocks intrinsic via ecalli 100). Tests
// IntrinsicOptimal in isolation — verify the intrinsic interception path.
pub fn shape_intrinsic_once() -> u32 {
	let result = gp::mul(0x123456789abcdef0, 0x9E3779B97F4A7C15);
	(result & 0xFFFF_FFFF) as u32
}
