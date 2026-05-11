// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! SCALE-shape roundtrip workload: read a `Vec<u32>` from memory, transform
//! each element, write to a separate output buffer, then checksum the output.
//!
//! ## Why this shape
//!
//! Rostro shop sidecars decode SCALE-encoded chain payloads on every IPC
//! turn (incoming requests) and re-encode results to send back. For
//! fixed-width primitives (`u32`, `u64`, `[u8; N]`), SCALE encoding is
//! sequential little-endian byte storage — the dominant cost is the
//! memory traffic pattern (sequential load + sequential store), not the
//! encoding logic. This workload captures that cost shape without the
//! complexity of full SCALE compact-int encoding (which has 4 variable-
//! length cases and would balloon the hand-assembled blob).
//!
//! ## Algorithm
//!
//! Three sequential loops, all over `[base, base + N*4)`:
//!   1. **Init.** Store `i` (the index, as `u32`) at `input[i]`.
//!   2. **Roundtrip.** For each `i`: load `input[i]`, XOR with `0x42`,
//!      store at `output[i]`. (XOR catches a "read from wrong buffer"
//!      bug — without the transform, the test would pass even if we
//!      accidentally summed the input instead of the output.)
//!   3. **Checksum.** Sum `output[i]` for all `i`, return as A0.
//!
//! Memory layout: 2 × N × 4 bytes allocated on stack. Input occupies
//! the lower half, output the upper half.
//!
//! ## Uses
//!
//! - `store_indirect_u32` / `load_indirect_u32` — sequential memory ops.
//! - `xor` — Assembler extension method (`feature/assembler-extended-ops`).
//! - `branch_less_unsigned` — same; loop back-edges.
//! - `add_imm_64`, `add_64`, `move_reg`, `load_imm_64` — existing.

use grey_transpiler::assembler::{Assembler, Reg};
use polkavm_common::program::{Instruction as PInst, InstructionSetKind, RawReg, Reg as PReg};
use polkavm_common::writer::ProgramBlobBuilder;

fn pr(reg: PReg) -> RawReg {
	reg.into()
}

/// XOR transformation constant. Picked to be small enough to encode as
/// a 1-byte immediate but non-zero so an "identity copy" bug shows up.
const TRANSFORM_XOR: u64 = 0x42;

/// Build the SCALE-roundtrip workload as a javm-native blob.
///
/// Caller must ensure `n >= 1` (do-while loop semantics; for n == 0
/// the loops would execute spuriously once).
pub fn javm_blob(n: u64) -> Vec<u8> {
	assert!(n >= 1, "scale_roundtrip workload requires n >= 1");
	let stack_bytes: u64 = 2 * n * 4;
	let stack_pages: u32 = ((stack_bytes + 4095) / 4096) as u32 + 1;
	let stack_top: u64 = stack_pages as u64 * 4096;

	let mut asm = Assembler::new();
	asm.set_stack_pages(stack_pages);
	asm.set_heap_pages(0);

	// SP preamble — javm's `InvocationKernel` does NOT auto-initialize SP
	// (unlike polkavm's `module.default_sp()`). grey-transpiler's linker
	// emits this preamble for compiled programs; for hand-assembled blobs
	// we have to emit it ourselves. Without it, SP defaults to 0 and any
	// `SP -= N` wraps around to high addresses → page fault.
	asm.load_imm_64(Reg::SP, stack_top);

	// Stack carve: SP -= 2*N*4. Input at SP+0..SP+N*4; output at SP+N*4..SP+2*N*4.
	asm.add_imm_64(Reg::SP, Reg::SP, -(stack_bytes as i32));
	asm.move_reg(Reg::S0, Reg::SP); // S0 = input_base
	asm.load_imm_64(Reg::S1, n * 4); // S1 = N*4 (one-buffer size)
	asm.add_64(Reg::A3, Reg::S0, Reg::S1); // A3 = output_base = input_base + N*4
	asm.load_imm_64(Reg::A4, stack_bytes); // A4 = 2*N*4
	asm.add_64(Reg::A5, Reg::S0, Reg::A4); // A5 = end of buffers
	asm.load_imm_64(Reg::A2, TRANSFORM_XOR); // A2 = XOR const

	// === Init loop: addr = S0, i = 0; while addr < A3: [addr] = i; addr += 4; i += 1 ===
	asm.move_reg(Reg::T0, Reg::S0); // T0 = init_addr
	asm.load_imm_64(Reg::T1, 0); // T1 = i

	let init_pre = asm.current_offset();
	asm.jump(5);
	let init_pc = asm.current_offset();
	assert_eq!(init_pc, init_pre + 5);

	asm.store_ind_u32(Reg::T1, Reg::T0, 0); // [init_addr] = i
	asm.add_imm_64(Reg::T0, Reg::T0, 4);
	asm.add_imm_64(Reg::T1, Reg::T1, 1);
	let init_branch_pc = asm.current_offset();
	let init_rel = (init_pc as i64) - (init_branch_pc as i64);
	asm.branch_less_unsigned(Reg::T0, Reg::A3, init_rel as i32);

	// === Roundtrip loop: in = S0, out = A3; while in < A3:
	//     val = [in]; val ^= XOR; [out] = val; in += 4; out += 4 ===
	asm.move_reg(Reg::T0, Reg::S0); // T0 = in_addr
	asm.move_reg(Reg::T1, Reg::A3); // T1 = out_addr

	let rt_pre = asm.current_offset();
	asm.jump(5);
	let rt_pc = asm.current_offset();
	assert_eq!(rt_pc, rt_pre + 5);

	asm.load_ind_u32(Reg::T2, Reg::T0, 0); // T2 = [in_addr]
	asm.xor(Reg::T2, Reg::T2, Reg::A2); // T2 ^= XOR
	asm.store_ind_u32(Reg::T2, Reg::T1, 0); // [out_addr] = T2
	asm.add_imm_64(Reg::T0, Reg::T0, 4);
	asm.add_imm_64(Reg::T1, Reg::T1, 4);
	let rt_branch_pc = asm.current_offset();
	let rt_rel = (rt_pc as i64) - (rt_branch_pc as i64);
	asm.branch_less_unsigned(Reg::T0, Reg::A3, rt_rel as i32);

	// === Sum loop: addr = A3, A0 = 0; while addr < A5:
	//     A0 += [addr]; addr += 4 ===
	asm.move_reg(Reg::T0, Reg::A3); // T0 = sum_addr (start of output)
	asm.load_imm_64(Reg::A0, 0); // A0 = sum

	let sum_pre = asm.current_offset();
	asm.jump(5);
	let sum_pc = asm.current_offset();
	assert_eq!(sum_pc, sum_pre + 5);

	asm.load_ind_u32(Reg::T2, Reg::T0, 0);
	asm.add_64(Reg::A0, Reg::A0, Reg::T2);
	asm.add_imm_64(Reg::T0, Reg::T0, 4);
	let sum_branch_pc = asm.current_offset();
	let sum_rel = (sum_pc as i64) - (sum_branch_pc as i64);
	asm.branch_less_unsigned(Reg::T0, Reg::A5, sum_rel as i32);

	asm.ecalli(0);

	asm.build()
}

/// Build the SCALE-roundtrip workload as a polkavm-native blob.
pub fn polkavm_blob(n: u64) -> Vec<u8> {
	assert!(n >= 1, "scale_roundtrip workload requires n >= 1");
	let stack_bytes: u64 = 2 * n * 4;

	let mut builder = ProgramBlobBuilder::new(InstructionSetKind::JamV1);
	builder.set_stack_size(stack_bytes as u32 + 4096);

	let code = vec![
		// BB0: stack setup + constants
		PInst::add_imm_64(pr(PReg::SP), pr(PReg::SP), (-(stack_bytes as i32)) as u32),
		PInst::move_reg(pr(PReg::S0), pr(PReg::SP)),
		PInst::load_imm64(pr(PReg::S1), n * 4),
		PInst::add_64(pr(PReg::A3), pr(PReg::S0), pr(PReg::S1)),
		PInst::load_imm64(pr(PReg::A4), stack_bytes),
		PInst::add_64(pr(PReg::A5), pr(PReg::S0), pr(PReg::A4)),
		PInst::load_imm64(pr(PReg::A2), TRANSFORM_XOR),
		PInst::move_reg(pr(PReg::T0), pr(PReg::S0)),
		PInst::load_imm64(pr(PReg::T1), 0),
		PInst::jump(1),
		// BB1: init loop body
		PInst::store_indirect_u32(pr(PReg::T1), pr(PReg::T0), 0),
		PInst::add_imm_64(pr(PReg::T0), pr(PReg::T0), 4),
		PInst::add_imm_64(pr(PReg::T1), pr(PReg::T1), 1),
		PInst::branch_less_unsigned(pr(PReg::T0), pr(PReg::A3), 1),
		// BB2: roundtrip loop setup
		PInst::move_reg(pr(PReg::T0), pr(PReg::S0)),
		PInst::move_reg(pr(PReg::T1), pr(PReg::A3)),
		PInst::jump(3),
		// BB3: roundtrip loop body
		PInst::load_indirect_u32(pr(PReg::T2), pr(PReg::T0), 0),
		PInst::xor(pr(PReg::T2), pr(PReg::T2), pr(PReg::A2)),
		PInst::store_indirect_u32(pr(PReg::T2), pr(PReg::T1), 0),
		PInst::add_imm_64(pr(PReg::T0), pr(PReg::T0), 4),
		PInst::add_imm_64(pr(PReg::T1), pr(PReg::T1), 4),
		PInst::branch_less_unsigned(pr(PReg::T0), pr(PReg::A3), 3),
		// BB4: sum loop setup
		PInst::move_reg(pr(PReg::T0), pr(PReg::A3)),
		PInst::load_imm64(pr(PReg::A0), 0),
		PInst::jump(5),
		// BB5: sum loop body
		PInst::load_indirect_u32(pr(PReg::T2), pr(PReg::T0), 0),
		PInst::add_64(pr(PReg::A0), pr(PReg::A0), pr(PReg::T2)),
		PInst::add_imm_64(pr(PReg::T0), pr(PReg::T0), 4),
		PInst::branch_less_unsigned(pr(PReg::T0), pr(PReg::A5), 5),
		// BB6: halt
		PInst::jump_indirect(pr(PReg::RA), 0),
	];

	builder.set_code(&code, &[]);
	builder.add_export_by_basic_block(0, b"main");
	builder.to_vec().expect("polkavm scale_roundtrip blob build")
}

/// Native-Rust reference: matches the on-VM algorithm exactly.
pub fn expected_result(n: u64) -> u64 {
	(0..n).fold(0u64, |acc, i| acc.wrapping_add((i as u32 ^ TRANSFORM_XOR as u32) as u64))
}
