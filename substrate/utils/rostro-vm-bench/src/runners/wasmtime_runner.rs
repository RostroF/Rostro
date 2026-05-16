// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! [`RvmRunner`] implementation backed by Bytecode Alliance's `wasmtime` crate.
//!
//! The whole point of having this runner is to put WASM on the same axis as
//! javm + polkavm so the "drop WASM, replace with PVM" decision has actual
//! head-to-head numbers behind it. Two backends mirror polkavm's
//! interpreter/compiler split:
//!
//!   - [`WasmtimeRunner::cranelift`] — the optimizing JIT (substrate prod).
//!   - [`WasmtimeRunner::winch`] — the baseline compiler (faster compile,
//!     less-optimized code; rough analog of "interpreter tier" for wasmtime,
//!     since wasmtime has no software interpreter).
//!
//! Convention: each WAT/WASM workload exports a function named `main` with
//! signature `() -> i64`. The returned value is reported as
//! [`RunOutput::result_a0`] for parity with the RVM runners. Fuel is enabled
//! for gas-consumption parity with polkavm's `GasMeteringKind::Sync`.

use crate::{RvmRunner, RunOutput};
use super::DEFAULT_GAS_LIMIT;

use wasmtime::{Config, Engine, Module, Store, Strategy};

/// Opaque handle returned by [`WasmtimeRunner::precompile`]. Wraps a fully
/// JIT-compiled `wasmtime::Module`; subsequent [`WasmtimeRunner::run_compiled`]
/// calls only do Store + Instance + call.
pub struct WasmtimeCompiled {
	module: Module,
}

pub struct WasmtimeRunner {
	engine: Engine,
	gas_limit: u64,
	name: &'static str,
}

impl WasmtimeRunner {
	/// Default backend — cranelift (matches `sc-executor-wasmtime`'s prod choice).
	pub fn new() -> Result<Self, String> {
		Self::cranelift()
	}

	/// Cranelift JIT — optimizing compiler. Production-grade output codegen.
	pub fn cranelift() -> Result<Self, String> {
		Self::build("wasmtime-cranelift", Strategy::Cranelift)
	}

	/// Winch baseline compiler — faster compile, slower code. Lets us probe
	/// the "compile latency vs runtime perf" tradeoff that polkavm gets via
	/// interpreter-vs-compiler.
	pub fn winch() -> Result<Self, String> {
		Self::build("wasmtime-winch", Strategy::Winch)
	}

	pub fn with_gas_limit(mut self, gas: u64) -> Self {
		self.gas_limit = gas;
		self
	}

	fn build(name: &'static str, strategy: Strategy) -> Result<Self, String> {
		let mut config = Config::new();
		config.strategy(strategy);
		// Fuel metering for gas-consumption parity with polkavm's Sync mode.
		// Without this, gas_consumed would always be 0 and the side-by-side
		// comparison would lose a column.
		config.consume_fuel(true);
		// Match substrate prod's optimization knob — see the Phase 3a audit
		// for why `SpeedAndSize` (not `Speed`) is the chosen tradeoff.
		// Winch ignores cranelift_opt_level by design.
		if matches!(strategy, Strategy::Cranelift) {
			config.cranelift_opt_level(wasmtime::OptLevel::SpeedAndSize);
		}
		let engine = Engine::new(&config)
			.map_err(|e| format!("wasmtime Engine::new ({name}): {e}"))?;
		Ok(Self { engine, gas_limit: DEFAULT_GAS_LIMIT, name })
	}
}

impl WasmtimeRunner {
	/// Compile `blob` into a reusable [`WasmtimeCompiled`] handle. Cranelift
	/// (or winch) JIT runs here, not in `run_compiled`.
	pub fn precompile(&self, blob: &[u8]) -> Result<WasmtimeCompiled, String> {
		let module = Module::new(&self.engine, blob)
			.map_err(|e| format!("wasmtime Module::new (precompile): {e}"))?;
		Ok(WasmtimeCompiled { module })
	}

	/// Warm-path execute: skips `Module::new`. Fresh Store + Instance per
	/// call so memory state is isolated.
	pub fn run_compiled(
		&mut self,
		compiled: &WasmtimeCompiled,
		_input: &[u8],
	) -> Result<RunOutput, String> {
		let mut store: Store<()> = Store::new(&self.engine, ());
		store
			.set_fuel(self.gas_limit)
			.map_err(|e| format!("wasmtime set_fuel: {e}"))?;
		let instance = wasmtime::Instance::new(&mut store, &compiled.module, &[])
			.map_err(|e| format!("wasmtime Instance::new: {e}"))?;
		let main = instance
			.get_typed_func::<(), i64>(&mut store, "main")
			.map_err(|e| format!("wasmtime get_typed_func 'main': {e}"))?;
		let result = main
			.call(&mut store, ())
			.map_err(|e| format!("wasmtime main(): {e}"))?;

		let remaining = store.get_fuel().unwrap_or(0);
		Ok(RunOutput {
			result_a0: result as u64,
			gas_consumed: self.gas_limit.saturating_sub(remaining),
		})
	}
}

impl RvmRunner for WasmtimeRunner {
	fn name(&self) -> &'static str {
		self.name
	}

	fn run(&mut self, blob: &[u8], _input: &[u8]) -> Result<RunOutput, String> {
		let module = Module::new(&self.engine, blob)
			.map_err(|e| format!("wasmtime Module::new: {e}"))?;
		let mut store: Store<()> = Store::new(&self.engine, ());
		store
			.set_fuel(self.gas_limit)
			.map_err(|e| format!("wasmtime set_fuel: {e}"))?;

		let instance = wasmtime::Instance::new(&mut store, &module, &[])
			.map_err(|e| format!("wasmtime Instance::new: {e}"))?;
		let main = instance
			.get_typed_func::<(), i64>(&mut store, "main")
			.map_err(|e| format!("wasmtime get_typed_func 'main': {e}"))?;
		let result = main
			.call(&mut store, ())
			.map_err(|e| format!("wasmtime main(): {e}"))?;

		let remaining = store.get_fuel().unwrap_or(0);
		Ok(RunOutput {
			result_a0: result as u64,
			gas_consumed: self.gas_limit.saturating_sub(remaining),
		})
	}
}
