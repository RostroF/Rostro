// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # rostro-executor — PVM runtime executor for Rostro
//!
//! Apache-2.0 implementation of the substrate runtime executor surface,
//! targeting the vendored rostrovm fork at `substrate/external/rostrovm/`
//! (polkavm 0.32 + Tier 2 crypto intrinsics + audit hardening). Replaces
//! the inherited GPL-3.0 `rc-executor-polkavm` so the Rostro runtime path
//! can ship under Apache-2.0 — see [[feedback_client_dir_gpl3]].
//!
//! ## Scope (Phase Star, workstream B)
//!
//! - **B1** — crate scaffold, workspace registration.
//! - **B2** (this commit) — engine/module/instance lifecycle against the
//!   fork's 0.32 API, call dispatch, trap → [`Error`] mapping, gas →
//!   substrate [`Weight`] conversion. No host functions yet — guest
//!   blobs are pure compute (the `mint_pop`/storage paths arrive in B3).
//! - **B3a/b/c** — `sp-io` host-fn bindings: storage, hashing + crypto,
//!   allocator + logging + trie.
//!
//! ## Gas accounting
//!
//! RVM gas is calibrated so that 1 unit ≈ 1 ns of native work on the
//! audit reference machine (see
//! `substrate/external/rostrovm/polkavm/src/rostro_intrinsic_gas.rs`).
//! Substrate's [`Weight`] is denominated in picoseconds, so the substrate
//! boundary multiplies by 1000: see [`rvm_gas_to_weight`].
//!
//! [`Weight`]: sp_weights::Weight

#![cfg_attr(not(feature = "std"), no_std)]

use polkavm::{Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, Reg};

// ─── Error ─────────────────────────────────────────────────────────────────

/// Failures the executor can surface to substrate. Internal `polkavm`
/// errors are stringified at the boundary — callers see structured
/// kinds, not the upstream error enum.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Engine construction failed (sandbox unavailable, config rejected,
	/// etc.). Pre-instance; not a guest-induced fault.
	#[error("engine init: {0}")]
	EngineInit(String),
	/// Module compile failed — blob malformed, unsupported instruction
	/// set, or codegen rejected. Pre-instance.
	#[error("module compile: {0}")]
	ModuleCompile(String),
	/// Instance instantiation failed. Memory map setup, JIT region
	/// allocation, etc. Pre-call.
	#[error("instantiate: {0}")]
	Instantiate(String),
	/// The requested export symbol is not present in the module.
	#[error("export not found: {0}")]
	ExportNotFound(String),
	/// The run loop returned an error from `inst.run()` itself — a
	/// backend-level fault, not a guest-induced one.
	#[error("run loop: {0}")]
	RunLoop(String),
	/// Guest hit a trap instruction (illegal access, panic). Equivalent
	/// to a substrate runtime panic.
	#[error("guest trap")]
	Trap,
	/// Gas exhausted mid-execution.
	#[error("out of gas")]
	OutOfGas,
	/// Guest segfaulted on a memory access.
	#[error("guest segfault")]
	Segfault,
	/// Guest invoked an ecalli the executor hasn't been taught to
	/// dispatch yet. B2 surfaces this as an error; B3+ wires the sp-io
	/// host-function table so the dispatcher knows what to do.
	#[error("unhandled ecalli: id={0}")]
	UnhandledEcalli(u32),
	/// Guest single-stepped — only emitted under `polkavm` step mode,
	/// which we don't enable. If we ever see this, the executor or the
	/// fork has drifted.
	#[error("unexpected single-step interrupt")]
	UnexpectedStep,
}

// ─── Gas ───────────────────────────────────────────────────────────────────

/// Convert RVM gas (1 unit ≈ 1 ns native) to substrate
/// [`Weight`](sp_weights::Weight) (1 unit = 1 ps ref_time). One conversion
/// constant in one place — see crate docs.
pub fn rvm_gas_to_weight(gas: i64) -> sp_weights::Weight {
	let ns = u64::try_from(gas).unwrap_or(0);
	sp_weights::Weight::from_parts(ns.saturating_mul(1_000), 0)
}

// ─── Executor ──────────────────────────────────────────────────────────────

/// Loaded PVM runtime: an engine + a compiled module. Holds no per-call
/// state — each [`Self::call`] spins up a fresh instance so memory state
/// is isolated across calls (matches substrate's per-extrinsic execution
/// semantics).
pub struct RostroExecutor {
	engine: Engine,
	module: Module,
}

impl RostroExecutor {
	/// Compile a PVM blob into a reusable executor handle.
	pub fn from_blob(blob: &[u8]) -> Result<Self, Error> {
		let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
		config.set_allow_experimental(true);
		// In-process sandbox is sufficient for runtime execution — the
		// node already runs the executor inside its own process boundary
		// and substrate's sp-panic-handler is the outer fault boundary.
		if config.sandbox().is_none() {
			config.set_sandbox(Some(polkavm::SandboxKind::Generic));
		}
		if std::env::var_os("POLKAVM_SANDBOXING_ENABLED").is_none() {
			config.set_sandboxing_enabled(false);
		}

		let engine = Engine::new(&config).map_err(|e| Error::EngineInit(e.to_string()))?;

		let mut mc = ModuleConfig::new();
		mc.set_gas_metering(Some(GasMeteringKind::Sync));
		let module = Module::new(&engine, &mc, blob.to_vec().into())
			.map_err(|e| Error::ModuleCompile(e.to_string()))?;

		Ok(Self { engine, module })
	}

	/// Reference to the underlying compiled module. Useful for
	/// inspection (exports, memory map) without re-running.
	pub fn module(&self) -> &Module {
		&self.module
	}

	/// Reference to the underlying engine. Will become load-bearing in
	/// B3 when the host-function `Linker` is constructed against it.
	pub fn engine(&self) -> &Engine {
		&self.engine
	}

	/// Call an exported function and return the value left in `A0` plus
	/// the gas actually consumed. No host functions are wired in B2 —
	/// any guest `ecalli` is surfaced as [`Error::UnhandledEcalli`].
	///
	/// `gas_limit` is in RVM units (≈ ns). Use [`rvm_gas_to_weight`] at
	/// the substrate boundary.
	pub fn call(&self, export_name: &str, gas_limit: i64) -> Result<CallOutcome, Error> {
		let export = self
			.module
			.exports()
			.find(|e| e.symbol().as_bytes() == export_name.as_bytes())
			.ok_or_else(|| Error::ExportNotFound(export_name.to_string()))?;

		let mut inst =
			self.module.instantiate().map_err(|e| Error::Instantiate(e.to_string()))?;
		inst.set_gas(gas_limit);
		inst.set_next_program_counter(export.program_counter());
		// Sentinel return address — guest sees this on the stack and
		// `ret` halts the run loop with `Finished` instead of jumping
		// into bogus code. Matches the pattern in
		// `rostro-vm-bench/src/runners/polkavm_runner.rs`.
		inst.set_reg(Reg::RA, 0xFFFF_0000);

		loop {
			let interrupt = inst.run().map_err(|e| Error::RunLoop(e.to_string()))?;
			match interrupt {
				InterruptKind::Finished => {
					let a0 = inst.reg(Reg::A0);
					let gas_consumed = gas_limit.saturating_sub(inst.gas());
					return Ok(CallOutcome { a0, gas_consumed });
				},
				InterruptKind::Trap => return Err(Error::Trap),
				InterruptKind::NotEnoughGas => return Err(Error::OutOfGas),
				InterruptKind::Segfault(_) => return Err(Error::Segfault),
				InterruptKind::Ecalli(id) => return Err(Error::UnhandledEcalli(id)),
				InterruptKind::Step => return Err(Error::UnexpectedStep),
			}
		}
	}
}

/// Result of a successful guest call.
#[derive(Debug, Clone, Copy)]
pub struct CallOutcome {
	/// Value left in register `A0` at `ret` — the standard PVM ABI
	/// return slot. Substrate runtime APIs encode their return values
	/// here.
	pub a0: u64,
	/// Gas spent during this call. Convert with [`rvm_gas_to_weight`]
	/// for substrate weighing.
	pub gas_consumed: i64,
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;

	/// Build the trivial halt-with-42 blob using polkavm's assembler.
	/// Same pattern as `rostro-vm-bench/tests/smoke.rs`.
	fn tiny_halt_42_blob() -> Vec<u8> {
		let source = "\
			%isa = jam_v1\n\
			pub @main:\n\
			\ta0 = 42\n\
			\tret\n\
		";
		polkavm::program::assemble(None, source).expect("assemble tiny blob")
	}

	#[test]
	fn load_and_call_trivial_blob() {
		let blob = tiny_halt_42_blob();
		let exec = RostroExecutor::from_blob(&blob).expect("from_blob");
		let outcome = exec.call("main", 1_000_000).expect("call");
		assert_eq!(outcome.a0, 42, "a0 should hold the constant 42");
		assert!(outcome.gas_consumed > 0, "some gas should have been consumed");
		assert!(outcome.gas_consumed < 1_000_000, "trivial blob should not exhaust gas");
	}

	#[test]
	fn export_not_found_is_structured_error() {
		let blob = tiny_halt_42_blob();
		let exec = RostroExecutor::from_blob(&blob).expect("from_blob");
		let err = exec.call("nope_not_an_export", 1_000_000).unwrap_err();
		assert!(matches!(err, Error::ExportNotFound(ref name) if name == "nope_not_an_export"));
	}

	#[test]
	fn malformed_blob_surfaces_module_compile_error() {
		// Not a valid PVM blob — should fail at module compile.
		// `RostroExecutor` deliberately doesn't `derive(Debug)` (the
		// polkavm `Engine`/`Module` it wraps don't either), so we
		// destructure via `match` rather than `.unwrap_err()`.
		let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
		match RostroExecutor::from_blob(&garbage) {
			Ok(_) => panic!("garbage should not parse"),
			Err(Error::ModuleCompile(_)) => {},
			Err(other) => panic!("expected ModuleCompile, got {other:?}"),
		}
	}

	#[test]
	fn gas_to_weight_conversion_locked_ratio() {
		// Locked: 1 RVM gas = 1 ns = 1000 ps Weight ref_time.
		let w = rvm_gas_to_weight(1_000);
		assert_eq!(w.ref_time(), 1_000_000, "1000 ns = 1_000_000 ps");
		assert_eq!(w.proof_size(), 0, "B2 doesn't track proof size yet");
	}

	#[test]
	fn negative_gas_clamps_to_zero_weight() {
		// Defensive: RVM gas is i64 (signed for delta math), but Weight
		// is u64. Negative input should clamp to zero.
		let w = rvm_gas_to_weight(-1);
		assert_eq!(w.ref_time(), 0);
	}
}
