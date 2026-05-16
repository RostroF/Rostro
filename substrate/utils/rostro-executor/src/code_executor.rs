// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! `RostroCodeExecutor` — the substrate
//! [`CodeExecutor`](sp_core::traits::CodeExecutor) /
//! [`ReadRuntimeVersion`](sp_core::traits::ReadRuntimeVersion) impl that
//! lets `rostro-runtime` (compiled to PVM) plug into the substrate client
//! pipeline. Replaces the inherited GPL-3 `rc-executor-polkavm`'s
//! equivalents under Apache-2.0.
//!
//! ## Call ABI
//!
//! `impl_runtime_apis!`-generated entry points on the PVM target take
//! `(input_ptr: u32, input_len: u32)` as args (SCALE-encoded input lives
//! in guest memory starting at `heap_base`) and return a packed fat
//! pointer in `A0`: `(len << 32) | ptr`. The packed return points at the
//! SCALE-encoded result, also in guest memory.
//!
//! `RostroCodeExecutor::call` follows that contract:
//!
//! 1. Compile the blob into a [`polkavm::Module`].
//! 2. Register `H: HostFunctions` against a [`polkavm::Linker`].
//! 3. Instantiate, reset memory, `sbrk(input_len)` to extend the heap.
//! 4. Write the input bytes at `module.memory_map().heap_base()`.
//! 5. `call_typed` the entry point with `(data_ptr, data_len)`.
//! 6. Read `A0`, unpack the fat pointer, `read_memory` the result bytes.
//!
//! No module caching in B6 — every call recompiles. Cache is a
//! straightforward follow-up once we measure the perf cost on the
//! testbed.
//!
//! ## Clone
//!
//! Substrate's [`CodeExecutor`] supertrait set requires `Clone` so the
//! client pipeline can hand out copies to async tasks. We Arc-wrap the
//! engine; modules are recompiled per call so they don't need to flow
//! through `Clone`.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::marker::PhantomData;

use codec::Decode;
use polkavm::{CallError, Config, Engine, Module, ModuleConfig, Reg, SandboxKind};
use rc_executor::{error as rc_executor_error, RuntimeVersionOf};
use sp_core::traits::{CallContext, CodeExecutor, ReadRuntimeVersion, RuntimeCode};
use sp_externalities::Externalities;
use sp_version::RuntimeVersion;
use sp_wasm_interface::HostFunctions;

use crate::host_fn;

/// Substrate-runtime executor backed by the vendored rostrovm fork.
/// Generic over `H: HostFunctions` so the consumer picks the host-fn
/// surface — production wires `sp_io::SubstrateHostFunctions`; tests can
/// pass narrower tuples to fence off what the runtime should be allowed
/// to call.
pub struct RostroCodeExecutor<H: HostFunctions + 'static> {
	engine: Arc<Engine>,
	_phantom: PhantomData<fn() -> H>,
}

impl<H: HostFunctions + 'static> Clone for RostroCodeExecutor<H> {
	fn clone(&self) -> Self {
		Self { engine: Arc::clone(&self.engine), _phantom: PhantomData }
	}
}

impl<H: HostFunctions + 'static> RostroCodeExecutor<H> {
	/// Build a new executor with our standard config (generic sandbox,
	/// sandboxing off unless `POLKAVM_SANDBOXING_ENABLED` is set, sync
	/// gas metering opt-in per module).
	pub fn new() -> Result<Self, String> {
		let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
		config.set_allow_experimental(true);
		if config.sandbox().is_none() {
			config.set_sandbox(Some(SandboxKind::Generic));
		}
		if std::env::var_os("POLKAVM_SANDBOXING_ENABLED").is_none() {
			config.set_sandboxing_enabled(false);
		}
		let engine =
			Engine::new(&config).map_err(|e| format!("RostroCodeExecutor engine init: {e}"))?;
		Ok(Self { engine: Arc::new(engine), _phantom: PhantomData })
	}

	/// Per-call invocation: compile, link, instantiate, run, read return.
	/// Factored out so `CodeExecutor::call` and `ReadRuntimeVersion::
	/// read_runtime_version` share the same implementation.
	fn call_inner(
		&self,
		ext: &mut dyn Externalities,
		blob: &[u8],
		method: &str,
		data: &[u8],
	) -> Result<Vec<u8>, String> {
		// Substrate runtime calls aren't gas-metered at the VM level —
		// the runtime's `Weight` tracking does the equivalent at the
		// FRAME layer. Matches what `rc-executor-polkavm` does
		// (`NotEnoughGas` is unreachable in its run loop).
		let module_config = ModuleConfig::new();
		let module = Module::new(&self.engine, &module_config, blob.to_vec().into())
			.map_err(|e| format!("module compile for '{method}': {e}"))?;

		let mut linker = polkavm::Linker::<(), String>::new();
		host_fn::register_substrate_host_functions::<(), H>(&mut linker)
			.map_err(|e| format!("linker setup for '{method}': {e}"))?;

		let instance_pre = linker
			.instantiate_pre(&module)
			.map_err(|e| format!("instantiate_pre for '{method}': {e}"))?;
		let mut instance = instance_pre
			.instantiate()
			.map_err(|e| format!("instantiate for '{method}': {e}"))?;

		let pc = module
			.exports()
			.find(|e| e.symbol().as_bytes() == method.as_bytes())
			.ok_or_else(|| format!("export not found: '{method}'"))?
			.program_counter();

		let data_length: u32 = data
			.len()
			.try_into()
			.map_err(|_| format!("input payload for '{method}' is too large for u32"))?;

		// Reset, then grow the heap to hold the input payload. The substrate
		// ABI puts the input bytes starting at `heap_base()`.
		instance.reset_memory().map_err(|e| format!("reset_memory: {e}"))?;
		instance
			.sbrk(data_length)
			.map_err(|e| format!("sbrk for input payload ({data_length} bytes): {e}"))?;
		let data_pointer = module.memory_map().heap_base();
		if data_length > 0 {
			instance
				.write_memory(data_pointer, data)
				.map_err(|e| format!("write input payload: {e}"))?;
		}

		// Drive the run loop under thread-local externalities so the sp-io
		// host fns see the caller's state. Clear the panic-message slot
		// first so any leftover from a previous call doesn't bleed into
		// this trap error.
		host_fn::reset_last_panic_message();
		let result = sp_externalities::set_and_run_with_externalities(ext, || {
			instance.call_typed::<(u32, u32)>(&mut (), pc, (data_pointer, data_length))
		});

		match result {
			Ok(()) => {},
			Err(CallError::Trap) => {
				let pc_str = instance
					.program_counter()
					.map(|p| format!("0x{:08x}", p.0))
					.unwrap_or_else(|| "<unknown>".into());
				let panic_msg = host_fn::take_last_panic_message()
					.map(|m| format!(" panic_msg=\"{m}\""))
					.unwrap_or_default();
				// Polkavm logs source location via `log::log!(log_level, ...)`
				// at the requested level; route to `Error` so the substrate
				// node logger (which is set up by the time we reach a runtime
				// call) prints the symbol+line that bracketed the trap.
				if let Some(pc) = instance.program_counter() {
					module.debug_print_location(log::Level::Error, pc);
				}
				return Err(format!("guest trap in '{method}' at pc={pc_str}{panic_msg}"));
			},
			Err(CallError::NotEnoughGas) =>
				return Err(format!("out of gas in '{method}'")),
			Err(CallError::Step) =>
				return Err(format!("unexpected single-step in '{method}'")),
			Err(CallError::Error(e)) =>
				return Err(format!("run loop error in '{method}': {e}")),
			Err(CallError::User(msg)) =>
				return Err(format!("host fn error in '{method}': {msg}")),
		}

		// Substrate runtime APIs return a packed fat pointer in A0:
		//   low 32 bits = ptr into guest memory,
		//   high 32 bits = length of the SCALE-encoded result.
		let packed = instance.reg(Reg::A0);
		let result_ptr = packed as u32;
		let result_len = (packed >> 32) as u32;
		instance
			.read_memory(result_ptr, result_len)
			.map_err(|e| format!("read return payload for '{method}': {e}"))
	}
}

impl<H: HostFunctions + 'static> ReadRuntimeVersion for RostroCodeExecutor<H> {
	fn read_runtime_version(
		&self,
		wasm_code: &[u8],
		ext: &mut dyn Externalities,
	) -> Result<Vec<u8>, String> {
		// Fast path (embedded `runtime_version` section) would go here;
		// for B6 we use the slow path — actually call `Core_version`.
		// `runtime_apis!` documents `Core_version` as the legacy
		// fallback substrate uses today when no embedded version is
		// present, so functionally we're correct.
		self.call_inner(ext, wasm_code, "Core_version", &[])
	}
}

impl<H: HostFunctions + 'static> CodeExecutor for RostroCodeExecutor<H> {
	type Error = String;

	fn call(
		&self,
		ext: &mut dyn Externalities,
		runtime_code: &RuntimeCode,
		method: &str,
		data: &[u8],
		_context: CallContext,
	) -> (Result<Vec<u8>, Self::Error>, bool) {
		let blob = match runtime_code.code_fetcher.fetch_runtime_code() {
			Some(bytes) => bytes,
			None =>
				return (
					Err(format!("RostroCodeExecutor::call('{method}'): no runtime code")),
					false,
				),
		};
		(self.call_inner(ext, blob.as_ref(), method, data), false)
	}
}

impl<H: HostFunctions + 'static> RuntimeVersionOf for RostroCodeExecutor<H> {
	fn runtime_version(
		&self,
		ext: &mut dyn Externalities,
		runtime_code: &RuntimeCode,
	) -> rc_executor_error::Result<RuntimeVersion> {
		// Slow path only: actually call `Core_version`. The WASM executor has
		// an embedded-version fast path that reads the `runtime_version`
		// custom section; polkavm-linker may or may not preserve that
		// section, so it's parked until the testbed measures the cost
		// (see PHASE-STAR-HANDOFF.md "Open decisions").
		let blob = runtime_code.code_fetcher.fetch_runtime_code().ok_or_else(|| {
			rc_executor_error::Error::ApiError(
				"RostroCodeExecutor::runtime_version: no runtime code".into(),
			)
		})?;
		let encoded = self
			.call_inner(ext, blob.as_ref(), "Core_version", &[])
			.map_err(|e| rc_executor_error::Error::ApiError(e.into()))?;
		RuntimeVersion::decode(&mut encoded.as_slice()).map_err(|e| {
			rc_executor_error::Error::ApiError(
				format!("RostroCodeExecutor::runtime_version: SCALE decode failed: {e}").into(),
			)
		})
	}
}
