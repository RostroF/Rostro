// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Coin-sort tracer v3 — runs a tiny prefix of a known guest blob through the
//! interpreter with `step_tracing` enabled, emits a structured per-source-
//! instruction event for each step, looks up the actual FAST_OP_* the source
//! got sorted into, classifies the dispatch path (Optimal / UnresolvedFirstTime
//! / IntrinsicOptimal / HostTrampoline / Trap), and dumps the result so we can
//! see exactly which slot each shape took and what happened to it.
//!
//! v3 features (vs v1 MVP):
//! - **Real opcode names** via `polkavm::trace::opcode_info` lookup.
//! - **Real macro shapes** for each dispatched instruction.
//! - **Classification** computed from before/after `compiled_decoded[offset]`
//!   snapshots:
//!     * `UnresolvedFirstTime { will_resolve_to }` when the inst's opcode at
//!       `offset` was `FAST_OP_UNRESOLVED_*` before the step and a real
//!       opcode after (the unresolved arm self-rewrote).
//!     * `IntrinsicOptimal { intrinsic_id }` when the inst was FAST_OP_ECALLI
//!       with an imm in 100..1023 (Rostro intrinsic ID range).
//!     * `HostTrampoline` for ECALLI with imm outside 100..1023.
//!     * `Trap` for FAST_OP_TRAP arms.
//!     * `Optimal` for everything else.
//!
//! Usage: `cargo run -p rostro-vm-bench --example trace_shapes --release`

use polkavm::{
	BackendKind, Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, RawInstance,
	Reg, SandboxKind,
	trace::{
		ConsoleTracer, DispatchClassification, DispatchEvent, InstFields, RecordingTracer,
		SideEffect, Tracer, opcode_info,
	},
};
use rostro_vm_bench::service_blobs::GOLDILOCKS_MUL_POLKAVM_BLOB;

const MAX_EVENTS: usize = 30;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut config = Config::new();
	config.set_allow_experimental(true);
	config.set_backend(Some(BackendKind::Interpreter));
	config.set_sandboxing_enabled(false);
	if config.sandbox().is_none() {
		config.set_sandbox(Some(SandboxKind::Generic));
	}
	let engine = Engine::new(&config)?;

	let mut mc = ModuleConfig::new();
	mc.set_gas_metering(Some(GasMeteringKind::Sync));
	mc.set_step_tracing(true); // ← key: predecode inserts FAST_OP_STEP between source ops
	let module = Module::new(&engine, &mc, GOLDILOCKS_MUL_POLKAVM_BLOB.to_vec().into())?;

	let mut inst = module.instantiate()?;
	inst.set_gas(1_000_000_000);

	let export = module.exports().next().ok_or("no exports in goldilocks_mul blob")?;
	inst.set_next_program_counter(export.program_counter());
	inst.set_reg(Reg::RA, 0xFFFF_0000);
	inst.set_reg(Reg::SP, module.default_sp());

	let mut console = ConsoleTracer::verbose();
	let mut recorder = RecordingTracer::new();

	println!("════════════════════════════════════════════════════════════════════════");
	println!("  Coin-sort trace v3: goldilocks_mul (first {} source instructions)", MAX_EVENTS);
	println!("════════════════════════════════════════════════════════════════════════");

	let mut prev_offset: Option<u32> = None;
	let mut prev_inst: Option<InstFields> = None;
	let mut prev_regs = snapshot_regs(&inst);
	let mut prev_gas = inst.gas();
	let mut event_count = 0;

	loop {
		match inst.run()? {
			InterruptKind::Step => {
				let regs = snapshot_regs(&inst);
				let gas = inst.gas();
				let offset_now = inst.trace_compiled_offset();

				if let (Some(po), Some(pi)) = (prev_offset, prev_inst) {
					// FAST_OP_STEP (174) is the trace machinery itself — skip,
					// it's not a real source-instruction dispatch.
					if pi.opcode == 174 {
						let new_offset = offset_now.unwrap_or(0);
						prev_offset = Some(new_offset);
						prev_inst = inst.trace_compiled_inst_at(new_offset);
						prev_regs = regs;
						prev_gas = gas;
						continue;
					}
					// The instruction at `prev_offset` just executed. Look up
					// what's there NOW (it may have self-rewritten if it was
					// an unresolved arm).
					let inst_after = inst.trace_compiled_inst_at(po).unwrap_or(pi);
					let (opcode_name_before, macro_shape_before) = opcode_info(pi.opcode);
					let (opcode_name_after, _) = opcode_info(inst_after.opcode);

					let next_offset_now = offset_now.unwrap_or(0);
					let classification = classify(pi, inst_after, opcode_name_after);
					let side_effect = compute_side_effect(pi, inst_after, opcode_name_after, next_offset_now);

					let evt = DispatchEvent {
						offset: po,
						opcode_name: opcode_name_before,
						macro_shape: macro_shape_before,
						inst: pi,
						regs_before: prev_regs,
						regs_after: regs,
						gas_before: prev_gas,
						gas_after: gas,
						next_offset: offset_now.unwrap_or(0),
						side_effect,
						classification,
					};
					console.on_dispatch(&evt);
					recorder.on_dispatch(&evt);
					event_count += 1;
					if event_count >= MAX_EVENTS {
						println!("\n══════════ stopped after {} events ══════════", event_count);
						break;
					}
				}

				// Capture the inst we're about to execute (compiled_offset has
				// advanced past FAST_OP_STEP, so the entry at the new offset is
				// the real source inst).
				let new_offset = offset_now.unwrap_or(0);
				prev_offset = Some(new_offset);
				prev_inst = inst.trace_compiled_inst_at(new_offset);
				prev_regs = regs;
				prev_gas = gas;
			}
			InterruptKind::Finished => {
				println!("\n══════════ program finished after {} events ══════════", event_count);
				break;
			}
			InterruptKind::Ecalli(0) => {
				println!("\n══════════ ecalli(0) terminal halt after {} events ══════════", event_count);
				break;
			}
			InterruptKind::Ecalli(n) => {
				println!("  → ecalli({n}) — host call, continuing");
				continue;
			}
			InterruptKind::Trap => {
				println!("\n══════════ trap after {} events ══════════", event_count);
				break;
			}
			other => {
				println!("\n══════════ exit {:?} after {} events ══════════", other, event_count);
				break;
			}
		}
	}

	println!("\n════════════════ macro-shape histogram ════════════════");
	for (shape, count) in recorder.shape_histogram() {
		println!("  {:<30} {}", shape, count);
	}
	println!("\n══════════════ classification histogram ═══════════════");
	for (cls, count) in recorder.classification_histogram() {
		println!("  {:<30} {}", cls, count);
	}

	// v4.1: predecode dump — show the complete shape map for everything
	// that's been compiled. Use a small console tracer that only prints
	// predecode (no dispatch noise here).
	println!("\n════════════════ predecode dump (compiled_decoded) ════════════════");
	let mut predecode_console = ConsoleTracer { print_regs: false, print_predecode: true };
	let dumped = inst.trace_predecode_dump(&mut predecode_console).unwrap_or(0);
	println!("\n  ({} entries in compiled_decoded)", dumped);

	Ok(())
}

/// Classify the dispatch based on before/after inst snapshots and opcode names.
fn classify(
	before: InstFields,
	after: InstFields,
	opcode_name_after: &'static str,
) -> DispatchClassification {
	// FAST_OP_TRAP = 4 (per OPCODE_TABLE)
	if before.opcode == 4 {
		return DispatchClassification::Trap;
	}
	// FAST_OP_ECALLI = 122 (per OPCODE_TABLE)
	if before.opcode == 122 {
		let id = before.imm1 as u32;
		if (100..=1023).contains(&id) {
			return DispatchClassification::IntrinsicOptimal { intrinsic_id: id };
		} else {
			return DispatchClassification::HostTrampoline {
				id,
				was_rostro_intrinsic: false,
			};
		}
	}
	// Detect UnresolvedFirstTime: the opcode at this offset CHANGED between
	// before and after the step. The unresolved arm self-rewrote.
	let (before_name, _) = opcode_info(before.opcode);
	if before_name.starts_with("FAST_OP_UNRESOLVED_") && before.opcode != after.opcode {
		return DispatchClassification::UnresolvedFirstTime {
			will_resolve_to: opcode_name_after,
		};
	}
	if before_name.starts_with("FAST_OP_UNRESOLVED_") && before.opcode == after.opcode {
		return DispatchClassification::UnresolvedRepeatVisit;
	}
	DispatchClassification::Optimal
}

fn compute_side_effect(
	before: InstFields,
	after: InstFields,
	to_opcode_name: &'static str,
	next_offset: u32,
) -> Option<SideEffect> {
	if before.opcode != after.opcode {
		return Some(SideEffect::OneShotRewrite {
			from_opcode: before.opcode,
			to_opcode: after.opcode,
		});
	}
	// FAST_OP_ECALLI intrinsic interception
	if before.opcode == 122 {
		let id = before.imm1 as u32;
		if (100..=1023).contains(&id) {
			let native_fn = match id {
				100 => "rostro_jit_goldilocks_mul",
				101 => "rostro_jit_goldilocks_add",
				102 => "rostro_jit_goldilocks_sub",
				103 => "rostro_jit_goldilocks_inv",
				110 => "rostro_dilithium_verify",
				111 => "rostro_p521_ecdsa_verify_prehash",
				_ => "(unknown intrinsic)",
			};
			return Some(SideEffect::IntrinsicIntercepted { intrinsic_id: id, native_fn });
		} else {
			return Some(SideEffect::HostEcalliExit { hostcall_number: id });
		}
	}
	// v4.2 — branch direction detection. Use AFTER's target/next idx because
	// UnresolvedFirstTime branches have MAX sentinels in `before`; the
	// resolution rewrite stamps real values that we only see post-step.
	//
	// With step_tracing enabled, each source instruction is preceded by a
	// FAST_OP_STEP entry. So `next_offset` (the offset where the NEXT step
	// fired) is one past the actual destination — i.e. target_idx+1 if
	// taken, next_idx+1 if fallthrough.
	if to_opcode_name.contains("BRANCH") {
		let taken_step = after.target_idx.wrapping_add(1);
		let ft_step = after.next_idx.wrapping_add(1);
		let taken = next_offset == taken_step;
		let fallthrough = next_offset == ft_step;
		let condition = if taken {
			format!("taken (target_idx={} → STEP@{})", after.target_idx, next_offset)
		} else if fallthrough {
			format!("fallthrough (next_idx={} → STEP@{})", after.next_idx, next_offset)
		} else {
			format!(
				"unmatched: next_offset={} vs target_idx+1={} next_idx+1={}",
				next_offset, taken_step, ft_step
			)
		};
		return Some(SideEffect::BranchOutcome { taken, condition });
	}
	None
}

fn snapshot_regs(inst: &RawInstance) -> [u64; 13] {
	let mut s = [0u64; 13];
	let regs = [
		Reg::RA, Reg::SP, Reg::T0, Reg::T1, Reg::T2,
		Reg::S0, Reg::S1, Reg::A0, Reg::A1, Reg::A2,
		Reg::A3, Reg::A4, Reg::A5,
	];
	for (i, r) in regs.iter().enumerate() {
		s[i] = inst.reg(*r);
	}
	s
}
