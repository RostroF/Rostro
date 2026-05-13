// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Reference [`RvmRunner`] backed by pristine polkavm 0.32.0 from crates.io.
//!
//! This is the unmodified upstream polkavm — the "before" against which the
//! vendored RostroVM fork (see [`super::PolkaVmRunner`]) is measured. The
//! in-tree visitor path (`run_impl`) is NOT a clean reference; it was
//! contaminated during the R1+R3+Phase1a/b/c session. See memory entry
//! rostrovm_option_a_external_reference.md for the methodology.
//!
//! Implementation mirrors [`super::PolkaVmRunner`] line-for-line — only the
//! crate import differs (`polkavm_pristine` vs `polkavm`). Keeping the runner
//! shape identical means the bench harness's iteration cost is the same on
//! both runners; any delta in measured ms is interpreter-level.

use crate::{RunOutput, RvmRunner};
use super::DEFAULT_GAS_LIMIT;

use polkavm_pristine::{
	BackendKind, Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, Reg,
	SandboxKind,
};

/// Opaque handle returned by [`PolkaVmPristineRunner::precompile`].
pub struct PolkaVmPristineCompiled {
	module: Module,
}

/// Reference runner. Defaults to backend resolved by `Config::from_env()`;
/// use [`PolkaVmPristineRunner::interpreter`] / [`PolkaVmPristineRunner::compiler`]
/// to pin a backend.
pub struct PolkaVmPristineRunner {
	engine: Engine,
	gas_limit: i64,
	name: &'static str,
}

impl PolkaVmPristineRunner {
	pub fn new() -> Result<Self, String> {
		Self::build("polkavm-pristine", None)
	}

	pub fn interpreter() -> Result<Self, String> {
		Self::build("polkavm-pristine-interpreter", Some(BackendKind::Interpreter))
	}

	pub fn compiler() -> Result<Self, String> {
		Self::build("polkavm-pristine-compiler", Some(BackendKind::Compiler))
	}

	pub fn with_gas_limit(mut self, gas: u64) -> Self {
		self.gas_limit = gas as i64;
		self
	}

	fn build(name: &'static str, backend: Option<BackendKind>) -> Result<Self, String> {
		let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
		config.set_allow_experimental(true);
		if let Some(b) = backend {
			config.set_backend(Some(b));
		}
		if std::env::var_os("POLKAVM_SANDBOXING_ENABLED").is_none() {
			config.set_sandboxing_enabled(false);
		}
		if config.sandbox().is_none() {
			config.set_sandbox(Some(SandboxKind::Generic));
		}
		let engine = Engine::new(&config)
			.map_err(|e| format!("polkavm-pristine Engine::new ({name}): {e}"))?;
		Ok(Self { engine, gas_limit: DEFAULT_GAS_LIMIT as i64, name })
	}

	pub fn precompile(&self, blob: &[u8]) -> Result<PolkaVmPristineCompiled, String> {
		let mut mc = ModuleConfig::new();
		mc.set_gas_metering(Some(GasMeteringKind::Sync));
		let module = Module::new(&self.engine, &mc, blob.to_vec().into())
			.map_err(|e| format!("polkavm-pristine Module::new (precompile): {e}"))?;
		Ok(PolkaVmPristineCompiled { module })
	}

	pub fn run_compiled(
		&mut self,
		compiled: &PolkaVmPristineCompiled,
		_input: &[u8],
	) -> Result<RunOutput, String> {
		let module = &compiled.module;
		let mut inst = module
			.instantiate()
			.map_err(|e| format!("polkavm-pristine instantiate: {}", e))?;
		inst.set_gas(self.gas_limit);

		let export = module
			.exports()
			.next()
			.ok_or_else(|| "polkavm-pristine: no exports".to_string())?;
		inst.set_next_program_counter(export.program_counter());
		inst.set_reg(Reg::RA, 0xFFFF_0000);
		inst.set_reg(Reg::SP, module.default_sp());

		loop {
			match inst.run() {
				Ok(InterruptKind::Finished) => break,
				Ok(InterruptKind::Ecalli(0)) => break,
				Ok(InterruptKind::Ecalli(_)) => continue,
				Ok(InterruptKind::Trap) =>
					return Err("polkavm-pristine: trap".to_string()),
				Ok(InterruptKind::NotEnoughGas) =>
					return Err("polkavm-pristine: out of gas".to_string()),
				Ok(other) =>
					return Err(format!("polkavm-pristine: unexpected interrupt {:?}", other)),
				Err(e) => return Err(format!("polkavm-pristine run error: {}", e)),
			}
		}

		let remaining = inst.gas();
		Ok(RunOutput {
			result_a0: inst.reg(Reg::A0),
			gas_consumed: self.gas_limit.saturating_sub(remaining).max(0) as u64,
		})
	}
}

impl RvmRunner for PolkaVmPristineRunner {
	fn name(&self) -> &'static str {
		self.name
	}

	fn run(&mut self, blob: &[u8], _input: &[u8]) -> Result<RunOutput, String> {
		let mut mc = ModuleConfig::new();
		mc.set_gas_metering(Some(GasMeteringKind::Sync));
		let module = Module::new(&self.engine, &mc, blob.to_vec().into())
			.map_err(|e| format!("polkavm-pristine Module::new: {}", e))?;

		let mut inst = module
			.instantiate()
			.map_err(|e| format!("polkavm-pristine instantiate: {}", e))?;
		inst.set_gas(self.gas_limit);

		let export = module
			.exports()
			.next()
			.ok_or_else(|| "polkavm-pristine: no exports".to_string())?;
		inst.set_next_program_counter(export.program_counter());

		inst.set_reg(Reg::RA, 0xFFFF_0000);
		inst.set_reg(Reg::SP, module.default_sp());

		loop {
			match inst.run() {
				Ok(InterruptKind::Finished) => break,
				Ok(InterruptKind::Ecalli(0)) => break,
				Ok(InterruptKind::Ecalli(_)) => continue,
				Ok(InterruptKind::Trap) =>
					return Err("polkavm-pristine: trap".to_string()),
				Ok(InterruptKind::NotEnoughGas) =>
					return Err("polkavm-pristine: out of gas".to_string()),
				Ok(other) =>
					return Err(format!("polkavm-pristine: unexpected interrupt {:?}", other)),
				Err(e) => return Err(format!("polkavm-pristine run error: {}", e)),
			}
		}

		let remaining = inst.gas();
		Ok(RunOutput {
			result_a0: inst.reg(Reg::A0),
			gas_consumed: self.gas_limit.saturating_sub(remaining).max(0) as u64,
		})
	}
}
