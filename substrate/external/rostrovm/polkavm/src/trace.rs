// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Research-grade interpreter tracing.
//!
//! This module is **not** used by the production hot path — it lives entirely
//! in a parallel `run_match_traced` function that the user opts into. The
//! hot `run_match` is unchanged.
//!
//! # The "coin-sort" model
//!
//! The interpreter is a deterministic dispatch loop: each `compiled_decoded`
//! entry (a "coin") has an opcode (a "shape") that determines which match arm
//! fires (the "slot it falls into"). Within that arm, one of ten dispatch-
//! shape macros (`arm_reg_reg_reg_64`, `arm_load_indirect`, …) does the
//! operand decode + math + write-back, then computes the next offset.
//!
//! From outside the interpreter, that dispatch chain often looks Rube-Goldberg
//! — the same source PVM instruction can take different paths at different
//! times because:
//!
//! 1. **Predecode interception**: a source op like `gp::mul` always emits
//!    `ecalli 100` on polkavm targets (cfg-gated in the `gp` crate). The
//!    PVM-level shape is "ecalli 100" regardless of intent. The intrinsic
//!    intercepts the math.
//! 2. **Unresolved-then-rewrite**: branches whose target isn't known at
//!    predecode time get `FAST_OP_UNRESOLVED_BRANCH_*`. First execution
//!    rewrites the inst to the real `FAST_OP_BRANCH_*`. Second visit takes
//!    a different arm than the first — same source PVM instruction.
//! 3. **Pre-block gas charge**: out-of-gas at a basic block boundary
//!    intercepts every shape downstream.
//! 4. **Macro-shape dispatch**: two opcodes routed through the same
//!    `arm_reg_reg_reg_64` macro have different closures spliced in. The
//!    macro shape is uniform; the math isn't.
//!
//! This tracer captures **both** layers (predecode + dispatch) and classifies
//! each event so research questions like "did this shape take an inefficient
//! path? what was the optimal one?" are answerable from the recorded log.

use alloc::string::String;
use alloc::vec::Vec;

/// 13-register snapshot (PVM general registers RA..A5 in declaration order).
/// Matches `polkavm_common::program::Reg::ALL`.
pub type RegSnapshot = [u64; 13];

/// Captured copy of a `DecodedInst`'s fields — pub mirror of the internal
/// crate-private struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstFields {
    pub pc: u32,
    pub next_pc: u32,
    pub next_idx: u32,
    pub target_idx: u32,
    pub bb_gas_cost: u32,
    pub opcode: u8,
    pub r0: u8,
    pub r1: u8,
    pub r2: u8,
    pub imm1: u64,
    pub imm2: u64,
}

/// Which dispatch-shape macro processed an arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacroShape {
    ArmRegRegReg64,
    ArmRegRegReg32,
    ArmRegRegImm64,
    ArmRegRegImm32,
    ArmAltRegRegImm64,
    ArmAltRegRegImm32,
    ArmRegReg64,
    ArmRegReg32,
    ArmBranchRegReg,
    ArmBranchRegImm,
    ArmLoadNonindirect,
    ArmLoadIndirect,
    ArmStoreNonindirect,
    ArmStoreIndirect,
    ArmStoreImm,
    ArmStoreImmIndirect,
    ArmUnresolved,
    ArmCmovReg,
    ArmCmovImm,
    InlineTrap,
    InlineJump,
    InlineJumpIndirect,
    InlineEcalli,
    InlineMemset,
    InlineBookkeeping,
    InlineLoadImm64,
    InlineCmov,
    InlineSbrk,
    InlineOther,
}

/// What kind of side-effect the dispatch had beyond updating registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideEffect {
    OneShotRewrite { from_opcode: u8, to_opcode: u8 },
    MemoryWrite { addr: u32, len: u32, value: u64 },
    MemoryRead { addr: u32, len: u32, value: u64 },
    BranchOutcome { taken: bool, condition: String },
    JumpTo { target_offset: u32 },
    InterruptExit { reason: String },
    IntrinsicIntercepted { intrinsic_id: u32, native_fn: &'static str },
    HostEcalliExit { hostcall_number: u32 },
    OutOfGas { gas_at_block_entry: i64, block_cost: u32 },
}

/// Classification of how the actual dispatch path compares to the optimal one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchClassification {
    /// Direct dispatch on the named opcode arm — no interception, no rewrite.
    Optimal,
    /// First visit through `arm_unresolved!`. Will rewrite the inst so the
    /// next visit hits the named arm directly.
    UnresolvedFirstTime { will_resolve_to: &'static str },
    /// Subsequent visit still going through `arm_unresolved!` — should not
    /// happen if resolution worked. Correctness flag.
    UnresolvedRepeatVisit,
    /// Rostro intrinsic intercepted inline (interpreter or JIT-CustomCodegen).
    /// Optimal for Rostro chain code.
    IntrinsicOptimal { intrinsic_id: u32 },
    /// Host-trampoline ecalli (no intrinsic interception). For Rostro IDs
    /// (100..1023), this is a missed-interception. For others, the only path.
    HostTrampoline { id: u32, was_rostro_intrinsic: bool },
    /// `compiled_decoded` was reset; future branches pay the cold-path cost.
    CacheEvictionRebuild,
    /// Out-of-gas trap.
    GasTrap,
    /// Trap (illegal opcode, unaligned access, etc.). Terminal.
    Trap,
}

/// Per-instruction trace event from the dispatch loop.
#[derive(Debug, Clone)]
pub struct DispatchEvent {
    pub offset: u32,
    pub opcode_name: &'static str,
    pub macro_shape: MacroShape,
    pub inst: InstFields,
    pub regs_before: RegSnapshot,
    pub regs_after: RegSnapshot,
    pub gas_before: i64,
    pub gas_after: i64,
    pub next_offset: u32,
    pub side_effect: Option<SideEffect>,
    pub classification: DispatchClassification,
}

/// Per-source-instruction trace event from `compile_block_impl` (predecode).
#[derive(Debug, Clone)]
pub struct PredecodeEvent {
    pub source_pc: u32,
    pub source_op_name: String,
    pub emit_offset: u32,
    pub emitted: Vec<EmittedEntry>,
    pub bb_gas_cost: u32,
}

/// One DecodedInst entry as recorded by predecode.
#[derive(Debug, Clone)]
pub struct EmittedEntry {
    pub offset: u32,
    pub opcode_name: &'static str,
    pub inst: InstFields,
}

/// A trace event of either kind.
#[derive(Debug, Clone)]
pub enum TraceEvent {
    Predecode(PredecodeEvent),
    Dispatch(DispatchEvent),
}

/// User-supplied tracer. Receives every predecode + dispatch event from
/// `run_match_traced`.
pub trait Tracer {
    fn on_predecode(&mut self, evt: &PredecodeEvent);
    fn on_dispatch(&mut self, evt: &DispatchEvent);
}

// ──────────────────────────────────────────────────────────────────────────
// ConsoleTracer
// ──────────────────────────────────────────────────────────────────────────

/// Verbose console output. Each event prints multiple lines with full register
/// snapshots, decoded operands, and the optimal-path classification.
#[cfg(feature = "std")]
pub struct ConsoleTracer {
    pub print_regs: bool,
    pub print_predecode: bool,
}

#[cfg(feature = "std")]
impl ConsoleTracer {
    pub fn verbose() -> Self {
        Self { print_regs: true, print_predecode: true }
    }

    pub fn dispatch_only() -> Self {
        Self { print_regs: true, print_predecode: false }
    }
}

#[cfg(feature = "std")]
impl Tracer for ConsoleTracer {
    fn on_predecode(&mut self, evt: &PredecodeEvent) {
        if !self.print_predecode {
            return;
        }
        std::println!(
            "[predecode] source_pc=0x{:04x} {:<22} → emit @offset {} ({} entries) bb_gas={}",
            evt.source_pc,
            evt.source_op_name,
            evt.emit_offset,
            evt.emitted.len(),
            evt.bb_gas_cost,
        );
        for entry in &evt.emitted {
            std::println!(
                "              [{:>4}] {:<28} pc=0x{:04x} next_pc=0x{:04x} \
                 r0={} r1={} r2={} imm1=0x{:x} imm2=0x{:x} target_idx={} next_idx={}",
                entry.offset, entry.opcode_name,
                entry.inst.pc, entry.inst.next_pc,
                entry.inst.r0, entry.inst.r1, entry.inst.r2,
                entry.inst.imm1, entry.inst.imm2,
                fmt_idx(entry.inst.target_idx), fmt_idx(entry.inst.next_idx),
            );
        }
    }

    fn on_dispatch(&mut self, evt: &DispatchEvent) {
        std::println!(
            "\n[dispatch @{:>4}] {:<26} via {:?}  → next @{}",
            evt.offset, evt.opcode_name, evt.macro_shape, evt.next_offset,
        );
        std::println!(
            "              inst {{ pc=0x{:04x} next_pc=0x{:04x} r0={} r1={} r2={} \
             imm1=0x{:x} imm2=0x{:x} target_idx={} next_idx={} bb_gas_cost={} }}",
            evt.inst.pc, evt.inst.next_pc, evt.inst.r0, evt.inst.r1, evt.inst.r2,
            evt.inst.imm1, evt.inst.imm2,
            fmt_idx(evt.inst.target_idx), fmt_idx(evt.inst.next_idx), evt.inst.bb_gas_cost,
        );
        std::println!("              classification: {:?}", evt.classification);
        if let Some(se) = &evt.side_effect {
            std::println!("              side_effect: {:?}", se);
        }
        std::println!(
            "              gas: {} → {} (Δ {})",
            evt.gas_before, evt.gas_after, evt.gas_before - evt.gas_after,
        );
        if self.print_regs {
            print_reg_diff("              ", &evt.regs_before, &evt.regs_after);
        }
    }
}

#[cfg(feature = "std")]
fn print_reg_diff(prefix: &str, before: &RegSnapshot, after: &RegSnapshot) {
    let names = ["RA", "SP", "T0", "T1", "T2", "S0", "S1", "A0", "A1", "A2", "A3", "A4", "A5"];
    let mut chunks: Vec<String> = Vec::with_capacity(13);
    for (i, name) in names.iter().enumerate() {
        let b = before[i];
        let a = after[i];
        if b == a {
            chunks.push(std::format!("{}=0x{:x}", name, a));
        } else {
            chunks.push(std::format!("{}=0x{:x}→0x{:x}", name, b, a));
        }
    }
    for chunk in chunks.chunks(4) {
        std::println!("{}{}", prefix, chunk.join("  "));
    }
}

fn fmt_idx(idx: u32) -> String {
    if idx == u32::MAX {
        String::from("MAX")
    } else {
        alloc::format!("{}", idx)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// RecordingTracer
// ──────────────────────────────────────────────────────────────────────────

/// Records every event into `events` for post-run analysis.
#[derive(Default)]
pub struct RecordingTracer {
    pub events: Vec<TraceEvent>,
}

impl RecordingTracer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Histogram by `MacroShape` — which arm shapes did this run exercise?
    pub fn shape_histogram(&self) -> alloc::collections::BTreeMap<&'static str, usize> {
        let mut out = alloc::collections::BTreeMap::new();
        for evt in &self.events {
            if let TraceEvent::Dispatch(d) = evt {
                let key = macro_shape_name(d.macro_shape);
                *out.entry(key).or_insert(0) += 1;
            }
        }
        out
    }

    /// Histogram by `DispatchClassification` — how often did each path class fire?
    pub fn classification_histogram(&self) -> alloc::collections::BTreeMap<&'static str, usize> {
        let mut out = alloc::collections::BTreeMap::new();
        for evt in &self.events {
            if let TraceEvent::Dispatch(d) = evt {
                let key: &'static str = match d.classification {
                    DispatchClassification::Optimal => "Optimal",
                    DispatchClassification::UnresolvedFirstTime { .. } => "UnresolvedFirstTime",
                    DispatchClassification::UnresolvedRepeatVisit => "UnresolvedRepeatVisit",
                    DispatchClassification::IntrinsicOptimal { .. } => "IntrinsicOptimal",
                    DispatchClassification::HostTrampoline { .. } => "HostTrampoline",
                    DispatchClassification::CacheEvictionRebuild => "CacheEvictionRebuild",
                    DispatchClassification::GasTrap => "GasTrap",
                    DispatchClassification::Trap => "Trap",
                };
                *out.entry(key).or_insert(0) += 1;
            }
        }
        out
    }
}

impl Tracer for RecordingTracer {
    fn on_predecode(&mut self, evt: &PredecodeEvent) {
        self.events.push(TraceEvent::Predecode(evt.clone()));
    }
    fn on_dispatch(&mut self, evt: &DispatchEvent) {
        self.events.push(TraceEvent::Dispatch(evt.clone()));
    }
}

pub fn macro_shape_name(s: MacroShape) -> &'static str {
    match s {
        MacroShape::ArmRegRegReg64 => "ArmRegRegReg64",
        MacroShape::ArmRegRegReg32 => "ArmRegRegReg32",
        MacroShape::ArmRegRegImm64 => "ArmRegRegImm64",
        MacroShape::ArmRegRegImm32 => "ArmRegRegImm32",
        MacroShape::ArmAltRegRegImm64 => "ArmAltRegRegImm64",
        MacroShape::ArmAltRegRegImm32 => "ArmAltRegRegImm32",
        MacroShape::ArmRegReg64 => "ArmRegReg64",
        MacroShape::ArmRegReg32 => "ArmRegReg32",
        MacroShape::ArmBranchRegReg => "ArmBranchRegReg",
        MacroShape::ArmBranchRegImm => "ArmBranchRegImm",
        MacroShape::ArmLoadNonindirect => "ArmLoadNonindirect",
        MacroShape::ArmLoadIndirect => "ArmLoadIndirect",
        MacroShape::ArmStoreNonindirect => "ArmStoreNonindirect",
        MacroShape::ArmStoreIndirect => "ArmStoreIndirect",
        MacroShape::ArmStoreImm => "ArmStoreImm",
        MacroShape::ArmStoreImmIndirect => "ArmStoreImmIndirect",
        MacroShape::ArmUnresolved => "ArmUnresolved",
        MacroShape::ArmCmovReg => "ArmCmovReg",
        MacroShape::ArmCmovImm => "ArmCmovImm",
        MacroShape::InlineTrap => "InlineTrap",
        MacroShape::InlineJump => "InlineJump",
        MacroShape::InlineJumpIndirect => "InlineJumpIndirect",
        MacroShape::InlineEcalli => "InlineEcalli",
        MacroShape::InlineMemset => "InlineMemset",
        MacroShape::InlineBookkeeping => "InlineBookkeeping",
        MacroShape::InlineLoadImm64 => "InlineLoadImm64",
        MacroShape::InlineCmov => "InlineCmov",
        MacroShape::InlineSbrk => "InlineSbrk",
        MacroShape::InlineOther => "InlineOther",
    }
}
