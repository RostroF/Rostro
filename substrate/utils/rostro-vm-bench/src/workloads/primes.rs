// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Trial-division prime counting workload (apples-to-apples javm + polkavm).
//!
//! Counts primes in `[2, N)` by naive trial division. Both blob builders
//! emit logically-equivalent RVM bytecode (same JamV1 ISA, same instruction
//! sequence); the only difference is the blob container + halt convention
//! each VM expects.
//!
//! ## Algorithm (no early-exit, no forward branches)
//!
//! ```text
//! count = (2 < N) ? 1 : 0          // pre-count i=2 if in range
//! for i in 3..(N+1):
//!     is_prime = 1
//!     for j in 2..i:               // do-while; i >= 3 so always runs >= 1
//!         rem = i %u j
//!         is_prime *= (0 <u rem)   // stays 1 only if all rems nonzero
//!     in_range = (i < N) ? 1 : 0   // masks the final overshoot iteration
//!     count += is_prime * in_range
//! return count
//! ```
//!
//! The two `mul *= flag` patterns replace forward early-exit branches
//! with backward-only branches. Forward branches in hand-assembled
//! programs need their target at a basic-block start, which means a
//! preceding terminator — solvable but fragile. The mul-by-flag trick
//! sidesteps it entirely while keeping the same asymptotic O(N²) cost.
//!
//! ## Provenance
//!
//! Mirrors `grey_primes_blob` / `polkavm_primes_blob` in
//! `/home/coder/jar/grey/crates/grey-bench/src/lib.rs` — the same
//! algorithm we contributed upstream to grey-bench. The local Assembler
//! extension methods (`mul_64`, `rem_unsigned_64`, `set_less_than_unsigned`,
//! `branch_less_unsigned`) are available because `rostro-vm-bench` path-
//! deps the `feature/assembler-extended-ops` branch of `grey-transpiler`.

use grey_transpiler::assembler::{Assembler, Reg};
use polkavm_common::program::{Instruction as PInst, InstructionSetKind, RawReg, Reg as PReg};
use polkavm_common::writer::ProgramBlobBuilder;

fn pr(reg: PReg) -> RawReg {
	reg.into()
}

/// Build the trial-division primes workload as a javm-native blob.
pub fn javm_blob(n: u64) -> Vec<u8> {
	let mut asm = Assembler::new();
	asm.set_stack_pages(1);
	asm.set_heap_pages(0);

	asm.load_imm_64(Reg::A3, n);
	asm.load_imm_64(Reg::T0, n.wrapping_add(1));
	asm.load_imm_64(Reg::A1, 0);
	asm.load_imm_64(Reg::A2, 2);
	asm.set_less_than_unsigned(Reg::T1, Reg::A2, Reg::A3);
	asm.load_imm_64(Reg::T2, 3);

	let outer_pre = asm.current_offset();
	asm.jump(5);
	let outer_pc = asm.current_offset();
	assert_eq!(outer_pc, outer_pre + 5);

	asm.load_imm_64(Reg::S0, 1);
	asm.load_imm_64(Reg::S1, 2);

	let inner_pre = asm.current_offset();
	asm.jump(5);
	let inner_pc = asm.current_offset();
	assert_eq!(inner_pc, inner_pre + 5);

	asm.move_reg(Reg::A0, Reg::T2);
	asm.rem_unsigned_64(Reg::A0, Reg::A0, Reg::S1);
	asm.set_less_than_unsigned(Reg::A2, Reg::A1, Reg::A0);
	asm.mul_64(Reg::S0, Reg::S0, Reg::A2);

	asm.add_imm_64(Reg::S1, Reg::S1, 1);
	let inner_branch_pc = asm.current_offset();
	let inner_rel = (inner_pc as i64) - (inner_branch_pc as i64);
	asm.branch_less_unsigned(Reg::S1, Reg::T2, inner_rel as i32);

	asm.set_less_than_unsigned(Reg::A2, Reg::T2, Reg::A3);
	asm.mul_64(Reg::S0, Reg::S0, Reg::A2);
	asm.add_64(Reg::T1, Reg::T1, Reg::S0);

	asm.add_imm_64(Reg::T2, Reg::T2, 1);
	let outer_branch_pc = asm.current_offset();
	let outer_rel = (outer_pc as i64) - (outer_branch_pc as i64);
	asm.branch_less_unsigned(Reg::T2, Reg::T0, outer_rel as i32);

	asm.move_reg(Reg::A0, Reg::T1);
	asm.ecalli(0);

	asm.build()
}

/// Build the trial-division primes workload as a polkavm-native blob.
pub fn polkavm_blob(n: u64) -> Vec<u8> {
	let mut builder = ProgramBlobBuilder::new(InstructionSetKind::JamV1);
	builder.set_stack_size(4096);

	let code = vec![
		// BB0: init constants + pre-count i=2 if in range
		PInst::load_imm64(pr(PReg::A3), n),
		PInst::load_imm64(pr(PReg::T0), n.wrapping_add(1)),
		PInst::load_imm64(pr(PReg::A1), 0),
		PInst::load_imm64(pr(PReg::A2), 2),
		PInst::set_less_than_unsigned(pr(PReg::T1), pr(PReg::A2), pr(PReg::A3)),
		PInst::load_imm64(pr(PReg::T2), 3),
		PInst::jump(1),
		// BB1: inner setup
		PInst::load_imm64(pr(PReg::S0), 1),
		PInst::load_imm64(pr(PReg::S1), 2),
		PInst::jump(2),
		// BB2: inner body (loop back to self while j < i)
		PInst::move_reg(pr(PReg::A0), pr(PReg::T2)),
		PInst::rem_unsigned_64(pr(PReg::A0), pr(PReg::A0), pr(PReg::S1)),
		PInst::set_less_than_unsigned(pr(PReg::A2), pr(PReg::A1), pr(PReg::A0)),
		PInst::mul_64(pr(PReg::S0), pr(PReg::S0), pr(PReg::A2)),
		PInst::add_imm_64(pr(PReg::S1), pr(PReg::S1), 1),
		PInst::branch_less_unsigned(pr(PReg::S1), pr(PReg::T2), 2),
		// BB3: post-inner — mask by in_range, accumulate, advance i
		PInst::set_less_than_unsigned(pr(PReg::A2), pr(PReg::T2), pr(PReg::A3)),
		PInst::mul_64(pr(PReg::S0), pr(PReg::S0), pr(PReg::A2)),
		PInst::add_64(pr(PReg::T1), pr(PReg::T1), pr(PReg::S0)),
		PInst::add_imm_64(pr(PReg::T2), pr(PReg::T2), 1),
		PInst::branch_less_unsigned(pr(PReg::T2), pr(PReg::T0), 1),
		// BB4: halt
		PInst::move_reg(pr(PReg::A0), pr(PReg::T1)),
		PInst::jump_indirect(pr(PReg::RA), 0),
	];

	builder.set_code(&code, &[]);
	builder.add_export_by_basic_block(0, b"main");
	builder.to_vec().expect("polkavm primes blob build")
}

/// Native-Rust reference: count primes in `[2, n)` by naive trial
/// division. Use to assert correctness against VM-produced A0.
pub fn expected_result(n: u64) -> u64 {
	let mut count: u64 = 0;
	for i in 2..n {
		let mut is_prime = true;
		let mut j = 2u64;
		while j < i {
			if i % j == 0 {
				is_prime = false;
				break;
			}
			j += 1;
		}
		if is_prime {
			count += 1;
		}
	}
	count
}
