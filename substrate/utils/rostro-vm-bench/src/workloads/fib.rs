// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Workload structure mirrors `grey_bench::grey_fib_blob` and
// `grey_bench::polkavm_fib_blob` (Apache-2.0, Bitarray GmbH). Reproduced
// here so the comparison sits at the same baseline grey-bench publishes.

//! Iterative Fibonacci compute workload.
//!
//! Computes `fib(N)` (where the loop iterates N times starting from
//! `prev = 0, curr = 1`) using only register operations — no memory
//! traffic, no host calls, no SCALE codec. Pure ALU throughput.
//!
//! Two blob builders are exposed:
//! - [`javm_blob`] uses `grey_transpiler::Assembler` (javm's native format).
//! - [`polkavm_blob`] uses `polkavm_common::writer::ProgramBlobBuilder`
//!   (polkavm's native format).
//!
//! Both emit logically-equivalent RVM bytecode; the difference is the
//! blob container + halt convention (javm: `ecalli 0`; polkavm:
//! `jump_indirect(RA, 0)` to `VM_ADDR_RETURN_TO_HOST`).
//!
//! [`expected_result`] computes the same Fibonacci in native Rust for
//! correctness assertions in tests + benches.

use grey_transpiler::assembler::{Assembler, Reg};
use polkavm_common::program::{Instruction as PInst, InstructionSetKind, RawReg, Reg as PReg};
use polkavm_common::writer::ProgramBlobBuilder;

fn pr(reg: PReg) -> RawReg {
	reg.into()
}

/// Emit a `branch_lt_u ra, rb, rel_offset` instruction by raw byte
/// encoding. The grey-transpiler `Assembler` does not expose a typed
/// helper for this opcode in its current surface — matches grey-bench's
/// workaround verbatim.
fn emit_branch_lt_u(asm: &mut Assembler, ra: Reg, rb: Reg, rel_offset: i32) {
	asm.emit_raw(172, true);
	asm.emit_raw((ra as u8) | ((rb as u8) << 4), false);
	for &b in &rel_offset.to_le_bytes() {
		asm.emit_raw(b, false);
	}
}

/// Build the Fibonacci workload as a javm-native blob.
pub fn javm_blob(n: u64) -> Vec<u8> {
	let mut asm = Assembler::new();
	asm.set_stack_pages(1);
	asm.set_heap_pages(0);

	asm.load_imm_64(Reg::T0, 0); // prev = 0
	asm.load_imm_64(Reg::T1, 1); // curr = 1
	asm.load_imm_64(Reg::T2, 0); // counter = 0
	asm.load_imm_64(Reg::S1, n); // N

	let jump_pc = asm.current_offset();
	asm.jump(5); // 5-byte forward jump → creates a BB boundary at loop_pc

	let loop_pc = asm.current_offset();
	assert_eq!(loop_pc, jump_pc + 5);
	asm.add_64(Reg::S0, Reg::T0, Reg::T1); // tmp = prev + curr
	asm.move_reg(Reg::T0, Reg::T1); // prev = curr
	asm.move_reg(Reg::T1, Reg::S0); // curr = tmp
	asm.add_imm_64(Reg::T2, Reg::T2, 1); // counter++

	let branch_pc = asm.current_offset();
	let rel_offset = (loop_pc as i64) - (branch_pc as i64);
	emit_branch_lt_u(&mut asm, Reg::T2, Reg::S1, rel_offset as i32);

	asm.move_reg(Reg::A0, Reg::T1);
	asm.ecalli(0x00); // JAM REPLY → halt

	asm.build()
}

/// Build the Fibonacci workload as a polkavm-native blob.
pub fn polkavm_blob(n: u64) -> Vec<u8> {
	let mut builder = ProgramBlobBuilder::new(InstructionSetKind::JamV1);
	builder.set_stack_size(4096);

	let code = vec![
		// BB0: init
		PInst::load_imm64(pr(PReg::T0), 0),
		PInst::load_imm64(pr(PReg::T1), 1),
		PInst::load_imm64(pr(PReg::T2), 0),
		PInst::load_imm64(pr(PReg::S1), n),
		PInst::jump(1),
		// BB1: loop body
		PInst::add_64(pr(PReg::S0), pr(PReg::T0), pr(PReg::T1)),
		PInst::move_reg(pr(PReg::T0), pr(PReg::T1)),
		PInst::move_reg(pr(PReg::T1), pr(PReg::S0)),
		PInst::add_imm_64(pr(PReg::T2), pr(PReg::T2), 1),
		PInst::branch_less_unsigned(pr(PReg::T2), pr(PReg::S1), 1),
		// BB2: done — jump_indirect through RA = VM_ADDR_RETURN_TO_HOST halts
		PInst::move_reg(pr(PReg::A0), pr(PReg::T1)),
		PInst::jump_indirect(pr(PReg::RA), 0),
	];

	builder.set_code(&code, &[]);
	builder.add_export_by_basic_block(0, b"main");
	builder.to_vec().expect("polkavm fib blob build")
}

/// Build the Fibonacci workload as a WASM module via WAT.
///
/// Mirrors the RVM blobs above instruction-class for instruction-class:
/// three locals for `prev`/`curr`/`i`, one temp, one back-edge branch.
/// Exports `main` returning the final `curr` as i64. No memory, no host
/// imports — pure ALU. WAT keeps the comparison apples-to-apples with the
/// hand-assembled RVM side: same algorithm, no compiler optimization
/// asymmetry between the two sides of the bench.
pub fn wat_blob(n: u64) -> Vec<u8> {
	let wat = format!(
		r#"
(module
  (func (export "main") (result i64)
    (local $prev i64) (local $curr i64) (local $i i64) (local $tmp i64)
    (local.set $prev (i64.const 0))
    (local.set $curr (i64.const 1))
    (local.set $i (i64.const 0))
    (block $exit
      (loop $loop
        (local.set $tmp (i64.add (local.get $prev) (local.get $curr)))
        (local.set $prev (local.get $curr))
        (local.set $curr (local.get $tmp))
        (local.set $i (i64.add (local.get $i) (i64.const 1)))
        (br_if $loop (i64.lt_u (local.get $i) (i64.const {n})))
      )
    )
    (local.get $curr)
  )
)
"#
	);
	wat::parse_str(&wat).expect("fib wat parse")
}

/// Native-Rust reference: same iterative recurrence, wrapping arithmetic.
/// Use to assert correctness against VM-produced A0.
pub fn expected_result(n: u64) -> u64 {
	let mut prev: u64 = 0;
	let mut curr: u64 = 1;
	for _ in 0..n {
		let s = prev.wrapping_add(curr);
		prev = curr;
		curr = s;
	}
	curr
}
