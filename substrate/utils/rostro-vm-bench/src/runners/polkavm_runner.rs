// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! [`RvmRunner`] implementation backed by Parity's `polkavm` crate (0.31.0).

use crate::{RvmRunner, RunOutput};
use super::DEFAULT_GAS_LIMIT;

use polkavm::{Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, Reg};

/// RVM runner using `polkavm::Module::instantiate()` + manual register setup.
///
/// Mirrors `grey_bench::run_polkavm_module` so the comparison is apples-to-apples.
/// The engine is built once and reused across `run` calls; modules are rebuilt
/// per call (matches the "compile + execute every iteration" benchmark fairness
/// note from grey-bench).
pub struct PolkaVmRunner {
	engine: Engine,
	gas_limit: i64,
}

impl PolkaVmRunner {
	pub fn new() -> Result<Self, String> {
		let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
		config.set_allow_experimental(true);
		let engine =
			Engine::new(&config).map_err(|e| format!("polkavm Engine::new: {}", e))?;
		Ok(Self { engine, gas_limit: DEFAULT_GAS_LIMIT as i64 })
	}

	pub fn with_gas_limit(mut self, gas: u64) -> Self {
		self.gas_limit = gas as i64;
		self
	}
}

impl RvmRunner for PolkaVmRunner {
	fn name(&self) -> &'static str {
		"polkavm"
	}

	fn run(&mut self, blob: &[u8], _input: &[u8]) -> Result<RunOutput, String> {
		let mut mc = ModuleConfig::new();
		mc.set_gas_metering(Some(GasMeteringKind::Sync));
		let module = Module::new(&self.engine, &mc, blob.to_vec().into())
			.map_err(|e| format!("polkavm Module::new: {}", e))?;

		let mut inst =
			module.instantiate().map_err(|e| format!("polkavm instantiate: {}", e))?;
		inst.set_gas(self.gas_limit);

		let export =
			module.exports().next().ok_or_else(|| "polkavm: no exports".to_string())?;
		inst.set_next_program_counter(export.program_counter());

		// Sentinel return address — when the guest returns to this PC,
		// the run loop sees InterruptKind::Trap and we read A0. Matches
		// grey-bench's convention.
		inst.set_reg(Reg::RA, 0xFFFF_0000);
		inst.set_reg(Reg::SP, module.default_sp());

		loop {
			match inst.run() {
				Ok(InterruptKind::Finished) => break,
				// JAM REPLY (ecalli 0) is a terminal halt — javm's InvocationKernel
				// treats it as `KernelResult::Halt(a0)`. Mirror that here so a
				// JAM-convention blob produces the same observable outcome on
				// both runners. Other ecallis are host calls; for bench workloads
				// they're stubbed (no-op continue).
				Ok(InterruptKind::Ecalli(0)) => break,
				Ok(InterruptKind::Ecalli(_)) => continue,
				Ok(InterruptKind::Trap) => return Err("polkavm: trap".to_string()),
				Ok(InterruptKind::NotEnoughGas) =>
					return Err("polkavm: out of gas".to_string()),
				Ok(other) => return Err(format!("polkavm: unexpected interrupt {:?}", other)),
				Err(e) => return Err(format!("polkavm run error: {}", e)),
			}
		}

		let remaining = inst.gas();
		Ok(RunOutput {
			result_a0: inst.reg(Reg::A0),
			gas_consumed: self.gas_limit.saturating_sub(remaining).max(0) as u64,
		})
	}
}
