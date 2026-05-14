// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! `CustomCodegen` impl that wires Rostro intrinsics directly into JIT-emitted
//! machine code, skipping the standard host-call trampoline.
//!
//! ## Why this exists
//!
//! The standard ecalli sequence stores three immediates to vmctx and calls
//! `ecall_label`, which is a trampoline that spills all 13 guest registers to
//! vmctx, then jumps to `syscall_hostcall` (a Rust dispatcher that returns
//! `InterruptKind::Ecalli(N)` to the host run loop). The host then dispatches
//! the intrinsic and re-enters via `inst.run()`. End-to-end ~50-120 ns per
//! call. For an intrinsic-heavy workload like `goldilocks_mul` (100k calls
//! per iteration), this overhead dominates.
//!
//! With CustomCodegen: emit our own asm that mirrors the trampoline's spill,
//! calls the native intrinsic *directly*, writes the result back, then
//! reloads guest state. Skip the host roundtrip entirely. Per-call cost
//! drops to ~12-15 ns + the native body cost.
//!
//! ## Calling convention
//!
//! Per `polkavm_common::regmap`, the JIT keeps PVM guest registers live in
//! native registers throughout JIT-emitted code:
//!
//! ```text
//!   A0 → rdi    A1 → rax    SP → rsi    RA → rbx    A2 → rdx
//!   A3 → rbp    S0 → r8     S1 → r9     A4 → r10    A5 → r11
//!   T0 → r13    T1 → r14    T2 → r12
//! ```
//!
//! At an ecalli boundary, every guest register is live in its native
//! register. SysV AMD64 ABI says the callee preserves rbx, rbp, r12-r15.
//! That covers RA, A3, T0, T1, T2, AUX_TMP_REG (vmctx). Caller-saved (the
//! callee may clobber): rax, rcx, rdx, rsi, rdi, r8-r11. That covers
//! A0, A1, SP, A2, S0, S1, A4, A5.
//!
//! The caller-saved set is what we must spill before calling SysV code.
//! Mirroring `save_registers_to_vmctx` is correct AND simpler than tracking
//! liveness — full-spill is what the standard ecalli trampoline already does.
//!
//! ## Sandbox awareness
//!
//! vmctx access differs between Linux and Generic sandboxes (different base
//! offset relative to `r15`/`AUX_TMP_REG`), so the codegen takes a
//! `SandboxKind` at construction.

use polkavm_assembler::Assembler;
use polkavm_assembler::amd64::{LoadKind, MemOp, RegSize, Size};
use polkavm_assembler::amd64::addr::reg_indirect;
use polkavm_assembler::amd64::inst::{call, load, mov_imm64, store};
use polkavm_assembler::amd64::{Reg, RegMem};
use polkavm_common::program::Reg as PvmReg;
use polkavm_common::regmap::{AUX_TMP_REG, to_native_reg};

use crate::config::CustomCodegen;
use crate::interpreter::{
    ROSTRO_INTRINSIC_GOLDILOCKS_ADD, ROSTRO_INTRINSIC_GOLDILOCKS_INV,
    ROSTRO_INTRINSIC_GOLDILOCKS_MUL, ROSTRO_INTRINSIC_GOLDILOCKS_SUB,
    rostro_jit_goldilocks_add, rostro_jit_goldilocks_inv, rostro_jit_goldilocks_mul,
    rostro_jit_goldilocks_sub,
};
use crate::sandbox::Sandbox;
use crate::SandboxKind;

#[inline]
fn vmctx_offset(sandbox_kind: SandboxKind, regs_base: usize, nth: usize) -> i32 {
    let raw = (regs_base + nth * 8) as i32;
    match sandbox_kind {
        SandboxKind::Linux => raw,
        SandboxKind::Generic => {
            #[cfg(feature = "generic-sandbox")]
            {
                raw + crate::sandbox::generic::GUEST_MEMORY_TO_VMCTX_OFFSET as i32
            }
            #[cfg(not(feature = "generic-sandbox"))]
            {
                let _ = raw;
                unreachable!("generic-sandbox feature disabled");
            }
        }
    }
}

#[inline]
fn vmctx_reg(sandbox_kind: SandboxKind, regs_base: usize, reg: PvmReg) -> MemOp {
    reg_indirect(RegSize::R64, AUX_TMP_REG + vmctx_offset(sandbox_kind, regs_base, reg as usize))
}

/// Convert a `polkavm_common` PvmReg index to its assembler `Reg` (where
/// `to_native_reg` returns a `RegIndex`, but the `Assembler::push(load(...))`
/// API on amd64 takes a `Reg`). They share encoding bits — we go through `into`.
#[inline]
fn native_reg_for(pvm: PvmReg) -> Reg {
    to_native_reg(pvm).into()
}

/// `CustomCodegen` that emits direct calls to Rostro goldilocks intrinsics.
/// Goldilocks-only for now (IDs 100-103); other ecalli IDs (including
/// reserved big-crypto 110/111) fall back to the standard host-call sequence.
pub struct RostroIntrinsicsCodegen {
    sandbox_kind: SandboxKind,
    regs_base: usize,
}

impl RostroIntrinsicsCodegen {
    pub fn new(sandbox_kind: SandboxKind) -> Self {
        let regs_base = match sandbox_kind {
            SandboxKind::Linux => crate::sandbox::linux::Sandbox::offset_table().regs,
            SandboxKind::Generic => {
                #[cfg(feature = "generic-sandbox")]
                {
                    crate::sandbox::generic::Sandbox::offset_table().regs
                }
                #[cfg(not(feature = "generic-sandbox"))]
                {
                    unreachable!("generic-sandbox feature disabled");
                }
            }
        };
        Self { sandbox_kind, regs_base }
    }

    /// Spill caller-saved guest regs to vmctx. Mirrors what the standard
    /// `save_registers_to_vmctx` trampoline does, but only for the caller-
    /// saved subset (since callees following SysV preserve the rest).
    fn spill_caller_saved(&self, asm: &mut Assembler) {
        // Caller-saved guest regs: A0, A1, SP, A2, S0, S1, A4, A5.
        // (RA, A3, T0, T1, T2 are mapped to callee-saved native regs.)
        for reg in [PvmReg::A0, PvmReg::A1, PvmReg::SP, PvmReg::A2,
                    PvmReg::S0, PvmReg::S1, PvmReg::A4, PvmReg::A5] {
            asm.push(store(
                Size::U64,
                vmctx_reg(self.sandbox_kind, self.regs_base, reg),
                native_reg_for(reg),
            ));
        }
    }

    /// Reload caller-saved guest regs from vmctx after the native call.
    fn reload_caller_saved(&self, asm: &mut Assembler) {
        for reg in [PvmReg::A0, PvmReg::A1, PvmReg::SP, PvmReg::A2,
                    PvmReg::S0, PvmReg::S1, PvmReg::A4, PvmReg::A5] {
            asm.push(load(
                LoadKind::U64,
                native_reg_for(reg),
                vmctx_reg(self.sandbox_kind, self.regs_base, reg),
            ));
        }
    }

    /// Emit a 2-arg intrinsic call: A0, A1 → fn(a0, a1) → A0.
    fn emit_binary(&self, asm: &mut Assembler, fn_addr: u64) {
        // Spill all caller-saved guest regs before any clobber.
        self.spill_caller_saved(asm);
        // Set SysV args from the spilled vmctx copies (live native regs were
        // just saved — those copies are the source of truth now).
        asm.push(load(LoadKind::U64, Reg::rdi, vmctx_reg(self.sandbox_kind, self.regs_base, PvmReg::A0)));
        asm.push(load(LoadKind::U64, Reg::rsi, vmctx_reg(self.sandbox_kind, self.regs_base, PvmReg::A1)));
        // Call.
        asm.push(mov_imm64(Reg::rax, fn_addr));
        asm.push(call(RegMem::Reg(Reg::rax)));
        // Write result to A0's vmctx slot, then reload all caller-saved regs.
        // The reload of A0 picks up our just-written result.
        asm.push(store(Size::U64, vmctx_reg(self.sandbox_kind, self.regs_base, PvmReg::A0), Reg::rax));
        self.reload_caller_saved(asm);
    }

    /// Emit a 1-arg intrinsic call: A0 → fn(a0) → A0.
    fn emit_unary(&self, asm: &mut Assembler, fn_addr: u64) {
        self.spill_caller_saved(asm);
        asm.push(load(LoadKind::U64, Reg::rdi, vmctx_reg(self.sandbox_kind, self.regs_base, PvmReg::A0)));
        asm.push(mov_imm64(Reg::rax, fn_addr));
        asm.push(call(RegMem::Reg(Reg::rax)));
        asm.push(store(Size::U64, vmctx_reg(self.sandbox_kind, self.regs_base, PvmReg::A0), Reg::rax));
        self.reload_caller_saved(asm);
    }
}

impl CustomCodegen for RostroIntrinsicsCodegen {
    fn should_emit_ecalli(&self, number: u32, asm: &mut Assembler) -> bool {
        match number {
            ROSTRO_INTRINSIC_GOLDILOCKS_MUL => {
                self.emit_binary(asm, rostro_jit_goldilocks_mul as *const () as usize as u64);
                false
            }
            ROSTRO_INTRINSIC_GOLDILOCKS_ADD => {
                self.emit_binary(asm, rostro_jit_goldilocks_add as *const () as usize as u64);
                false
            }
            ROSTRO_INTRINSIC_GOLDILOCKS_SUB => {
                self.emit_binary(asm, rostro_jit_goldilocks_sub as *const () as usize as u64);
                false
            }
            ROSTRO_INTRINSIC_GOLDILOCKS_INV => {
                self.emit_unary(asm, rostro_jit_goldilocks_inv as *const () as usize as u64);
                false
            }
            // Big-crypto (110/111) and any other ID: defer to the standard
            // host-call trampoline. The bench harness's `dispatch_rostro_intrinsic`
            // handles 110/111 host-side.
            _ => true,
        }
    }
}
