// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Coin-sort tracer — runs a tiny prefix of a known guest blob through the
//! interpreter with `step_tracing` enabled, emits a structured per-source-
//! instruction event for each step, and dumps the dispatch path so we can
//! observe which slot each source instruction was actually sorted into.
//!
//! v1 scope (this commit): PC + register diff per instruction. Opcode-name
//! decoding, macro-shape classification, predecode events, and the optimal-
//! vs-actual diagnosis come in a follow-up — they need additional pub API
//! on the polkavm crate (compiled_decoded introspection).
//!
//! Usage: `cargo run -p rostro-vm-bench --example trace_shapes --release`
//!
//! Output: ConsoleTracer pretty-print of the first MAX_EVENTS source-
//! instruction events from goldilocks_mul. Goldilocks_mul has a small chained
//! multiply loop — we cap output at 30 events to see the loop structure +
//! the intrinsic interception pattern without drowning in repetition.

use polkavm::{
	BackendKind, Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, RawInstance,
	Reg, SandboxKind,
	trace::{
		ConsoleTracer, DispatchClassification, DispatchEvent, InstFields, MacroShape,
		RecordingTracer, Tracer,
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
	println!("  Coin-sort trace: goldilocks_mul (first {} source instructions)", MAX_EVENTS);
	println!("════════════════════════════════════════════════════════════════════════");

	let mut prev_pc: Option<u32> = None;
	let mut prev_regs = snapshot_regs(&inst);
	let mut prev_gas = inst.gas();
	let mut event_count = 0;

	loop {
		match inst.run()? {
			InterruptKind::Step => {
				let regs = snapshot_regs(&inst);
				let gas = inst.gas();
				let pc = inst.next_program_counter().map(|p| p.0);

				if let Some(pc_just_ran) = prev_pc {
					let evt = DispatchEvent {
						offset: 0, // not yet exposed via public API; placeholder
						opcode_name: "(source PVM op — opcode-name lookup is v2)",
						macro_shape: MacroShape::InlineOther,
						inst: InstFields {
							pc: pc_just_ran,
							next_pc: pc.unwrap_or(0),
							next_idx: 0,
							target_idx: 0,
							bb_gas_cost: 0,
							opcode: 0,
							r0: 0,
							r1: 0,
							r2: 0,
							imm1: 0,
							imm2: 0,
						},
						regs_before: prev_regs,
						regs_after: regs,
						gas_before: prev_gas,
						gas_after: gas,
						next_offset: 0,
						side_effect: None,
						classification: DispatchClassification::Optimal,
					};
					console.on_dispatch(&evt);
					recorder.on_dispatch(&evt);
					event_count += 1;
					if event_count >= MAX_EVENTS {
						println!("\n══════════ stopped after {} events ══════════", event_count);
						break;
					}
				}

				prev_pc = pc;
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

	// Post-run summary from RecordingTracer
	println!("\n════════════════ macro-shape histogram ════════════════");
	for (shape, count) in recorder.shape_histogram() {
		println!("  {:<30} {}", shape, count);
	}
	println!("\n══════════════ classification histogram ═══════════════");
	for (cls, count) in recorder.classification_histogram() {
		println!("  {:<30} {}", cls, count);
	}

	Ok(())
}

fn snapshot_regs(inst: &RawInstance) -> [u64; 13] {
	let mut s = [0u64; 13];
	let regs = [
		Reg::RA,
		Reg::SP,
		Reg::T0,
		Reg::T1,
		Reg::T2,
		Reg::S0,
		Reg::S1,
		Reg::A0,
		Reg::A1,
		Reg::A2,
		Reg::A3,
		Reg::A4,
		Reg::A5,
	];
	for (i, r) in regs.iter().enumerate() {
		s[i] = inst.reg(*r);
	}
	s
}
