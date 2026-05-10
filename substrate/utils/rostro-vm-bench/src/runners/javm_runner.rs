// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! [`RvmRunner`] implementation backed by Wei Tang's `javm` kernel.

use crate::{RvmRunner, RunOutput};
use super::DEFAULT_GAS_LIMIT;

/// RVM runner using `javm::kernel::InvocationKernel`.
///
/// Constructs a fresh kernel per call — no caching across runs. Mirrors
/// `grey_bench::run_kernel_with_backend` so the comparison is apples-to-apples
/// with grey-bench's published numbers.
pub struct JavmRunner {
	backend: javm::PvmBackend,
	gas_limit: u64,
}

impl JavmRunner {
	/// Run with the default backend selection (recompiler on Linux x86-64,
	/// interpreter elsewhere).
	pub fn default_backend() -> Self {
		Self { backend: javm::PvmBackend::Default, gas_limit: DEFAULT_GAS_LIMIT }
	}

	/// Force the software interpreter path.
	pub fn interpreter() -> Self {
		Self { backend: javm::PvmBackend::ForceInterpreter, gas_limit: DEFAULT_GAS_LIMIT }
	}

	/// Force the JIT recompiler path (Linux x86-64 only).
	#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
	pub fn recompiler() -> Self {
		Self { backend: javm::PvmBackend::ForceRecompiler, gas_limit: DEFAULT_GAS_LIMIT }
	}

	/// Override the gas budget. Default is [`DEFAULT_GAS_LIMIT`].
	pub fn with_gas_limit(mut self, gas: u64) -> Self {
		self.gas_limit = gas;
		self
	}
}

impl RvmRunner for JavmRunner {
	fn name(&self) -> &'static str {
		match self.backend {
			javm::PvmBackend::Default => "javm",
			javm::PvmBackend::ForceInterpreter => "javm-interpreter",
			#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
			javm::PvmBackend::ForceRecompiler => "javm-recompiler",
		}
	}

	fn run(&mut self, blob: &[u8], _input: &[u8]) -> Result<RunOutput, String> {
		let mut kernel =
			javm::kernel::InvocationKernel::new_with_backend(blob, &[], self.gas_limit, self.backend)
				.map_err(|e| format!("javm kernel init failed: {:?}", e))?;

		loop {
			match kernel.run() {
				javm::kernel::KernelResult::Halt(v) =>
					return Ok(RunOutput {
						result_a0: v,
						gas_consumed: self.gas_limit.saturating_sub(kernel.active_gas()),
					}),
				javm::kernel::KernelResult::Panic =>
					return Err("javm: panic".to_string()),
				javm::kernel::KernelResult::OutOfGas =>
					return Err("javm: out of gas".to_string()),
				javm::kernel::KernelResult::PageFault(addr) =>
					return Err(format!("javm: page fault at {:#x}", addr)),
				// Protocol calls are JAM-spec host-call dispatches; the
				// kernel handles them transparently and returns control.
				javm::kernel::KernelResult::ProtocolCall { .. } => continue,
			}
		}
	}
}
