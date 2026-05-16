// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Coin-sort tracer driven by the synthetic shape suite.
//!
//! Loads `trace-shapes-suite.polkavm` and runs each `shape_*` export through
//! the tracer in turn, printing the full per-shape dispatch trace +
//! predecode dump + classification histogram. Since each synthetic shape is
//! tiny (3-10 source instructions), no event cap is needed — we trace
//! exhaustively.
//!
//! The synthetics are designed to isolate ONE dispatch pattern each:
//!
//! - `shape_add_chain`     — 5 sequential add-imm (ArmRegRegImm64 in isolation)
//! - `shape_branch_loop`   — 3-iteration loop with backward branch
//! - `shape_load_store`    — stack alloc + 4-element write/read (load/store arms)
//! - `shape_intrinsic_once` — single goldilocks_mul intrinsic call
//!
//! Usage: `cargo run -p rostro-vm-bench --example trace_synth --release`

use std::fmt::Write as _;

use polkavm::{
	BackendKind, Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, RawInstance,
	Reg, SandboxKind,
	trace::{
		ConsoleTracer, DispatchClassification, DispatchEvent, InstFields, RecordingTracer,
		SideEffect, TraceEvent, Tracer, opcode_info,
	},
};
use rostro_vm_bench::service_blobs::TRACE_SHAPES_SUITE_POLKAVM_BLOB;

const SHAPES: &[&str] = &[
	"shape_add_chain",
	"shape_branch_loop",
	"shape_load_store",
	"shape_intrinsic_once",
];

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
	mc.set_step_tracing(true);
	let module = Module::new(&engine, &mc, TRACE_SHAPES_SUITE_POLKAVM_BLOB.to_vec().into())?;

	for shape in SHAPES {
		println!("\n\n████████████████████████████████████████████████████████████████████████");
		println!("██  shape: {}", shape);
		println!("████████████████████████████████████████████████████████████████████████");

		let export = module.exports().find(|e| e == *shape).ok_or_else(|| {
			format!("export '{}' not found in trace-shapes-suite blob", shape)
		})?;

		let mut inst = module.instantiate()?;
		inst.set_gas(10_000_000);
		inst.set_next_program_counter(export.program_counter());
		inst.set_reg(Reg::RA, 0xFFFF_0000);
		inst.set_reg(Reg::SP, module.default_sp());

		let mut console = ConsoleTracer::verbose();
		let mut recorder = RecordingTracer::new();

		let mut prev_offset: Option<u32> = None;
		let mut prev_inst: Option<InstFields> = None;
		let mut prev_regs = snapshot_regs(&inst);
		let mut prev_gas = inst.gas();

		loop {
			match inst.run()? {
				InterruptKind::Step => {
					let regs = snapshot_regs(&inst);
					let gas = inst.gas();
					let offset_now = inst.trace_compiled_offset();

					if let (Some(po), Some(pi)) = (prev_offset, prev_inst) {
						if pi.opcode != 174 {
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
								next_offset: next_offset_now,
								side_effect,
								classification,
							};
							console.on_dispatch(&evt);
							recorder.on_dispatch(&evt);
						}
					}

					let new_offset = offset_now.unwrap_or(0);
					prev_offset = Some(new_offset);
					prev_inst = inst.trace_compiled_inst_at(new_offset);
					prev_regs = regs;
					prev_gas = gas;
				}
				InterruptKind::Finished | InterruptKind::Ecalli(0) => {
					println!("\n  ── shape returned (gas remaining: {}) ──", inst.gas());
					break;
				}
				InterruptKind::Ecalli(n) => {
					// Real host call — won't happen for our synthetics except
					// the goldilocks intrinsic, which the interpreter
					// intercepts inline.
					println!("  → ecalli({n}) host exit, continuing");
					continue;
				}
				InterruptKind::Trap => {
					println!("  → trap");
					break;
				}
				other => {
					println!("  → exit {:?}", other);
					break;
				}
			}
		}

		// Per-shape histograms
		println!("\n  ── macro-shape histogram for {} ──", shape);
		for (s, c) in recorder.shape_histogram() {
			println!("    {:<28} {}", s, c);
		}
		println!("\n  ── classification histogram for {} ──", shape);
		for (cls, c) in recorder.classification_histogram() {
			println!("    {:<28} {}", cls, c);
		}

		// Predecode dump for this shape
		println!("\n  ── predecode dump for {} ──", shape);
		let mut pdc = ConsoleTracer { print_regs: false, print_predecode: true };
		let n = inst.trace_predecode_dump(&mut pdc).unwrap_or(0);
		println!("    ({} entries)", n);

		// Per-shape JSON
		let json_path = format!("/tmp/trace_synth_{}.json", shape);
		let mut json = String::new();
		writeln!(&mut json, "{{")?;
		writeln!(&mut json, "  \"shape\": \"{}\",", shape)?;
		writeln!(&mut json, "  \"dispatch_events\": [")?;
		for (i, evt) in recorder.events.iter().enumerate() {
			write_event_json(&mut json, evt, i + 1 < recorder.events.len())?;
		}
		writeln!(&mut json, "  ]")?;
		writeln!(&mut json, "}}")?;
		std::fs::write(&json_path, &json)?;
		println!("\n  ✓ {} ({} bytes)", json_path, json.len());
	}

	Ok(())
}

fn classify(
	before: InstFields,
	after: InstFields,
	opcode_name_after: &'static str,
) -> DispatchClassification {
	if before.opcode == 4 {
		return DispatchClassification::Trap;
	}
	if before.opcode == 122 {
		let id = before.imm1 as u32;
		if (100..=1023).contains(&id) {
			return DispatchClassification::IntrinsicOptimal { intrinsic_id: id };
		} else {
			return DispatchClassification::HostTrampoline { id, was_rostro_intrinsic: false };
		}
	}
	let (before_name, _) = opcode_info(before.opcode);
	if before_name.starts_with("FAST_OP_UNRESOLVED_") && before.opcode != after.opcode {
		return DispatchClassification::UnresolvedFirstTime { will_resolve_to: opcode_name_after };
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
		return Some(SideEffect::OneShotRewrite { from_opcode: before.opcode, to_opcode: after.opcode });
	}
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

fn write_event_json(out: &mut String, evt: &TraceEvent, more: bool) -> Result<(), std::fmt::Error> {
	let comma = if more { "," } else { "" };
	if let TraceEvent::Dispatch(d) = evt {
		writeln!(
			out,
			"    {{ \"offset\": {}, \"opcode_name\": \"{}\", \"macro_shape\": \"{:?}\", \
			 \"classification\": \"{:?}\", \"side_effect\": \"{:?}\" }}{}",
			d.offset, d.opcode_name, d.macro_shape, d.classification,
			d.side_effect.as_ref().map(|s| format!("{:?}", s)).unwrap_or_else(|| "null".into()),
			comma,
		)?;
	}
	Ok(())
}
