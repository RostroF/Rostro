// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! [`RvmRunner`] implementation backed by Wei Tang's `javm` kernel.

use crate::{RvmRunner, RunOutput};
use super::DEFAULT_GAS_LIMIT;

use javm::kernel::CodeCache;

/// Opaque handle returned by [`JavmRunner::precompile`]. Carries the blob
/// for re-instantiation; the JIT-compiled artifacts live in the runner's
/// shared [`CodeCache`].
pub struct JavmCompiled {
	blob: Vec<u8>,
}

/// RVM runner using `javm::kernel::InvocationKernel`.
///
/// Cold path: `run` constructs a fresh kernel per call (matches
/// `grey_bench::run_kernel_with_backend`).
///
/// Warm path: `precompile` populates the runner's [`CodeCache`] once;
/// subsequent `run_compiled` calls reuse the cached JIT compilation but
/// still spin up a fresh kernel + memory backing per iteration so each
/// run starts in a clean state.
pub struct JavmRunner {
	backend: javm::PvmBackend,
	gas_limit: u64,
	cache: CodeCache,
}

impl JavmRunner {
	/// Run with the default backend selection (recompiler on Linux x86-64,
	/// interpreter elsewhere).
	pub fn default_backend() -> Self {
		Self { backend: javm::PvmBackend::Default, gas_limit: DEFAULT_GAS_LIMIT, cache: CodeCache::new() }
	}

	/// Force the software interpreter path.
	pub fn interpreter() -> Self {
		Self { backend: javm::PvmBackend::ForceInterpreter, gas_limit: DEFAULT_GAS_LIMIT, cache: CodeCache::new() }
	}

	/// Force the JIT recompiler path (Linux x86-64 only).
	#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
	pub fn recompiler() -> Self {
		Self { backend: javm::PvmBackend::ForceRecompiler, gas_limit: DEFAULT_GAS_LIMIT, cache: CodeCache::new() }
	}

	/// Override the gas budget. Default is [`DEFAULT_GAS_LIMIT`].
	pub fn with_gas_limit(mut self, gas: u64) -> Self {
		self.gas_limit = gas;
		self
	}

	/// Pre-populate the runner's code cache with the JIT compilation for
	/// `blob`. Subsequent calls to [`Self::run_compiled`] with the returned
	/// handle skip the compile step.
	pub fn precompile(&mut self, blob: &[u8]) -> Result<JavmCompiled, String> {
		// Spin up + discard a kernel; the side effect is that the cache now
		// holds the compiled artifact for this blob (keyed by blake2b-256).
		let _kernel = javm::kernel::InvocationKernel::new_cached(
			blob,
			&[],
			self.gas_limit,
			&mut self.cache,
		)
		.map_err(|e| format!("javm precompile: {:?}", e))?;
		Ok(JavmCompiled { blob: blob.to_vec() })
	}

	/// Warm-path execute: re-uses the JIT compilation populated by
	/// [`Self::precompile`]. A fresh kernel + memory backing is still
	/// constructed per call (matches per-request shop semantics).
	pub fn run_compiled(
		&mut self,
		compiled: &JavmCompiled,
		_input: &[u8],
	) -> Result<RunOutput, String> {
		let mut kernel = javm::kernel::InvocationKernel::new_cached(
			&compiled.blob,
			&[],
			self.gas_limit,
			&mut self.cache,
		)
		.map_err(|e| format!("javm warm init failed: {:?}", e))?;

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
				javm::kernel::KernelResult::ProtocolCall { .. } => continue,
			}
		}
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
