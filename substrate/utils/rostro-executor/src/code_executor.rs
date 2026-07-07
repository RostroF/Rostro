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
//! 1. Fetch the compiled-and-linked runtime from the module cache
//!    (compile + link on miss — see below).
//! 2. Instantiate, reset memory, `sbrk(input_len)` to extend the heap.
//! 3. Write the input bytes at `module.memory_map().heap_base()`.
//! 4. `call_typed` the entry point with `(data_ptr, data_len)`.
//! 5. Read `A0`, unpack the fat pointer, `read_memory` the result bytes.
//!
//! ## Module cache
//!
//! Decompress + [`polkavm::Module`] parse of the ~5 MB runtime blob costs
//! ~14 ms on dev hardware; instantiating from a cached
//! [`polkavm::InstancePre`] costs ~300 ns (measured 2026-07-06, lab
//! throughput investigation). Since every runtime call — each
//! `validate_transaction` on tx submission, each `apply_extrinsic` during
//! authoring — funnels through here, the compiled module + resolved
//! host-fn linkage are cached per code blob and shared across calls and
//! executor clones. Capacity is [`RUNTIME_CACHE_CAPACITY`]; the key is
//! the client-supplied [`RuntimeCode::hash`] (the `:code` storage hash),
//! falling back to a content hash when the caller supplies an empty one.
//! Per-call mutable state lives in the [`polkavm::Instance`] created
//! fresh from the cached `InstancePre` — nothing written by one call is
//! visible to the next.
//!
//! ## Clone
//!
//! Substrate's [`CodeExecutor`] supertrait set requires `Clone` so the
//! client pipeline can hand out copies to async tasks. We Arc-wrap the
//! engine and the module cache, so all clones share both.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::marker::PhantomData;
use std::sync::{Mutex, MutexGuard};

use codec::Decode;
use polkavm::{BackendKind, CallError, Config, Engine, InstancePre, Module, ModuleConfig, Reg};
use rc_executor::{error as rc_executor_error, RuntimeVersionOf};
use sp_core::traits::{CallContext, CodeExecutor, ReadRuntimeVersion, RuntimeCode};
use sp_externalities::Externalities;
use sp_version::RuntimeVersion;
use sp_wasm_interface::HostFunctions;

use crate::host_fn;

/// Max distinct runtimes kept compiled: the live runtime plus the
/// incoming one while a `set_code` upgrade is in flight (the same bound
/// upstream `sc-executor` defaults its runtime cache to).
const RUNTIME_CACHE_CAPACITY: usize = 2;

/// One compiled-and-linked runtime, shared read-only across calls.
/// `instance_pre` carries the module with its host-fn imports resolved;
/// per-call mutable state lives in the `Instance` created from it.
struct CachedRuntime {
	module: Module,
	instance_pre: InstancePre<(), String>,
}

/// MRU-ordered cache slots: most recently used at index 0.
type RuntimeCache = Vec<(Vec<u8>, Arc<CachedRuntime>)>;

/// Substrate-runtime executor backed by the vendored rostrovm fork.
/// Generic over `H: HostFunctions` so the consumer picks the host-fn
/// surface — production wires `sp_io::SubstrateHostFunctions`; tests can
/// pass narrower tuples to fence off what the runtime should be allowed
/// to call.
pub struct RostroCodeExecutor<H: HostFunctions + 'static> {
	engine: Arc<Engine>,
	cache: Arc<Mutex<RuntimeCache>>,
	_phantom: PhantomData<fn() -> H>,
}

impl<H: HostFunctions + 'static> Clone for RostroCodeExecutor<H> {
	fn clone(&self) -> Self {
		Self {
			engine: Arc::clone(&self.engine),
			cache: Arc::clone(&self.cache),
			_phantom: PhantomData,
		}
	}
}

impl<H: HostFunctions + 'static> RostroCodeExecutor<H> {
	/// Build a new executor pinned to RostroVM's interpreter backend.
	///
	/// **Phase H (2026-05-25):** RostroVM's chain-runtime workload runs
	/// under the predecode-flatten interpreter, not the JIT-via-generic-
	/// sandbox path inherited from upstream polkavm 0.32. Rationale:
	///
	/// - Upstream's JIT exists for contract execution (hot-path,
	///   per-tx). Rostro's runtime is per-block, single blob — the
	///   interpreter's per-instruction overhead is amortized across
	///   block-level work, not call-level.
	/// - The JIT path requires anonymous W→X mappings (PolkaVM's runtime
	///   patches into mmap'd code pages) and the `generic-sandbox`
	///   feature for per-instance memory isolation. Both are vestiges of
	///   "polkavm as embeddable contract VM"; Cannae provides the
	///   host-level envelope so the in-process sandbox is redundant.
	/// - With interpreter pinned, Cannae's seccomp filter denies all
	///   `mprotect(PROT_EXEC)` (no JIT-flip carve-out needed) and all
	///   anonymous `mmap(PROT_EXEC)` — closing F06 in code. Combined
	///   with the supervisor's `MS_NOEXEC` bind-mount on RW paths
	///   (closes F05), Cannae achieves zero in-sandbox native code
	///   execution.
	///
	/// `set_sandbox` and `set_sandboxing_enabled` are NOT called: both
	/// are JIT-path concerns. The interpreter doesn't use a sandbox in
	/// the polkavm sense at all.
	pub fn new() -> Result<Self, String> {
		let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
		config.set_allow_experimental(true);
		config.set_backend(Some(BackendKind::Interpreter));
		let engine =
			Engine::new(&config).map_err(|e| format!("RostroCodeExecutor engine init: {e}"))?;
		Ok(Self {
			engine: Arc::new(engine),
			cache: Arc::new(Mutex::new(Vec::with_capacity(RUNTIME_CACHE_CAPACITY))),
			_phantom: PhantomData,
		})
	}

	/// The cache holds only `Arc`s in a plain `Vec` — structurally valid
	/// even if a panic unwound while the lock was held — so recover from
	/// poisoning instead of cascading the panic into every runtime call.
	fn lock_cache(&self) -> MutexGuard<'_, RuntimeCache> {
		self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Fetch the compiled-and-linked runtime for `cache_key`, compiling
	/// `blob` on a miss.
	///
	/// The caller-supplied key is trusted to identify the blob (it is the
	/// `:code` storage hash on the `CodeExecutor::call` path — the same
	/// contract upstream sc-executor's runtime cache relies on). An empty
	/// key is a known-invalid sentinel: it would alias every caller that
	/// failed to supply one, so it is rejected here and replaced with a
	/// content hash before lookup.
	fn cached_runtime(
		&self,
		cache_key: &[u8],
		blob: &[u8],
		method: &str,
	) -> Result<Arc<CachedRuntime>, String> {
		let cache_key: Vec<u8> = if cache_key.is_empty() {
			sp_core::hashing::blake2_256(blob).to_vec()
		} else {
			cache_key.to_vec()
		};

		{
			let mut cache = self.lock_cache();
			if let Some(pos) = cache.iter().position(|(key, _)| *key == cache_key) {
				let slot = cache.remove(pos);
				let runtime = Arc::clone(&slot.1);
				cache.insert(0, slot);
				return Ok(runtime);
			}
		}

		// Miss: build outside the lock so a ~14 ms compile never blocks
		// calls that hit on another runtime. Two racing misses on the
		// same key both build; the later insert wins and the loser's
		// runtime just drops. Correctness is unaffected — both were
		// built from the same blob.

		// Forkless upgrades submit :code in the sp-maybe-compressed-blob
		// envelope (zstd + 8-byte magic); genesis blobs are raw PVM\0.
		// Decompress here, at the single seam all three trait impls
		// funnel through (CodeExecutor::call, RuntimeVersionOf,
		// ReadRuntimeVersion), so a compressed blob is valid everywhere
		// or nowhere. Raw blobs pass through borrowed, zero cost.
		let blob = sp_maybe_compressed_blob::decompress(
			blob,
			sp_maybe_compressed_blob::CODE_BLOB_BOMB_LIMIT,
		)
		.map_err(|e| format!("decompress runtime blob for '{method}': {e:?}"))?;

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

		let runtime = Arc::new(CachedRuntime { module, instance_pre });
		let mut cache = self.lock_cache();
		cache.retain(|(key, _)| *key != cache_key);
		cache.insert(0, (cache_key, Arc::clone(&runtime)));
		cache.truncate(RUNTIME_CACHE_CAPACITY);
		Ok(runtime)
	}

	/// Per-call invocation: fetch cached runtime, instantiate, run, read
	/// return. Factored out so `CodeExecutor::call` and
	/// `ReadRuntimeVersion::read_runtime_version` share the same
	/// implementation. `cache_key` identifies `blob` for the module
	/// cache; pass empty to key by content hash.
	fn call_inner(
		&self,
		ext: &mut dyn Externalities,
		cache_key: &[u8],
		blob: &[u8],
		method: &str,
		data: &[u8],
	) -> Result<Vec<u8>, String> {
		let runtime = self.cached_runtime(cache_key, blob, method)?;
		let module = &runtime.module;

		let mut instance = runtime
			.instance_pre
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
		//
		// No caller-supplied code hash on this trait; empty key = the
		// executor derives a content hash (cold path, called on code
		// changes and startup).
		self.call_inner(ext, &[], wasm_code, "Core_version", &[])
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
		(self.call_inner(ext, &runtime_code.hash, blob.as_ref(), method, data), false)
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
			.call_inner(ext, &runtime_code.hash, blob.as_ref(), "Core_version", &[])
			.map_err(|e| rc_executor_error::Error::ApiError(e.into()))?;
		RuntimeVersion::decode(&mut encoded.as_slice()).map_err(|e| {
			rc_executor_error::Error::ApiError(
				format!("RostroCodeExecutor::runtime_version: SCALE decode failed: {e}").into(),
			)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rostro_executor_fixture_storage_roundtrip as fixture;

	/// Host-fn tuple wide enough to resolve the fixture blob's imports.
	type FixtureHostFns = (
		sp_io::storage::HostFunctions,
		sp_io::hashing::HostFunctions,
		sp_io::crypto::HostFunctions,
		sp_io::misc::HostFunctions,
		sp_io::allocator::HostFunctions,
	);

	fn executor() -> RostroCodeExecutor<FixtureHostFns> {
		RostroCodeExecutor::new().expect("construct executor")
	}

	#[test]
	fn same_key_hits_cache() {
		let exec = executor();
		let blob = fixture::binary_unwrap();
		let first = exec.cached_runtime(b"key-a", blob, "test").expect("compile");
		let second = exec.cached_runtime(b"key-a", blob, "test").expect("cached");
		assert!(Arc::ptr_eq(&first, &second), "second lookup must reuse the cached runtime");
	}

	#[test]
	fn empty_key_falls_back_to_content_hash() {
		let exec = executor();
		let blob = fixture::binary_unwrap();
		let first = exec.cached_runtime(&[], blob, "test").expect("compile");
		let second = exec.cached_runtime(&[], blob, "test").expect("cached");
		assert!(Arc::ptr_eq(&first, &second), "content-hash key must be stable for one blob");
	}

	#[test]
	fn capacity_evicts_least_recently_used() {
		let exec = executor();
		let blob = fixture::binary_unwrap();
		assert_eq!(RUNTIME_CACHE_CAPACITY, 2, "test written for capacity 2");

		let a = exec.cached_runtime(b"key-a", blob, "test").expect("compile a");
		exec.cached_runtime(b"key-b", blob, "test").expect("compile b");
		// Touch `a` so `b` is the LRU, then insert a third runtime.
		exec.cached_runtime(b"key-a", blob, "test").expect("hit a");
		exec.cached_runtime(b"key-c", blob, "test").expect("compile c");

		let a_again = exec.cached_runtime(b"key-a", blob, "test").expect("hit a");
		assert!(Arc::ptr_eq(&a, &a_again), "recently-used entry must survive eviction");

		let keys: Vec<Vec<u8>> = exec.lock_cache().iter().map(|(k, _)| k.clone()).collect();
		assert_eq!(
			keys,
			vec![b"key-a".to_vec(), b"key-c".to_vec()],
			"LRU entry (key-b) must be the one evicted"
		);
	}

	#[test]
	fn clones_share_the_cache() {
		let exec = executor();
		let blob = fixture::binary_unwrap();
		let first = exec.cached_runtime(b"key-a", blob, "test").expect("compile");
		let second = exec.clone().cached_runtime(b"key-a", blob, "test").expect("cached");
		assert!(Arc::ptr_eq(&first, &second), "clones must share one cache");
	}
}
