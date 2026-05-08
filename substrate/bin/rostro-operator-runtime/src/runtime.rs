// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! WASM hosting via wasmtime. v1 minimum:
//!
//! - One [`OperatorRuntime`] per loaded WASM blob, owns an `Engine`,
//!   `Module`, `Store`, and `Instance`.
//! - One bound host function: `rostro::log(ptr, len)` — reads a
//!   UTF-8 string from the WASM's linear memory at `[ptr, ptr+len)`
//!   and forwards it to `log::info!` on stderr (via `env_logger`).
//! - One supported invocation shape: an export with signature
//!   `() -> i32` (i32 because that's what wasmtime sees for
//!   WAT/Wasm `i32`-returning funcs; we re-cast to `u32` at the
//!   boundary because Rostro's protocol is unsigned).
//!
//! Heavier ABI (memory-allocator convention for typed args, store
//! ops, signature requests) lands in v2 once we know what shape
//! the bilateral-receipt + sponsorship voucher pallet wants
//! operators to produce.

use std::path::Path;
use thiserror::Error;
use wasmtime::{Caller, Engine, Extern, Instance, Linker, Memory, Module, Store};

#[derive(Debug, Error)]
pub enum RuntimeError {
	#[error("loading WASM module: {0}")]
	Load(String),
	#[error("instantiating WASM module: {0}")]
	Instantiate(String),
	#[error("export `{0}` not found in WASM module")]
	ExportMissing(String),
	#[error("export `{0}` has wrong signature (expected `() -> i32`)")]
	WrongSignature(String),
	#[error("WASM trap during call: {0}")]
	Trap(String),
}

/// Per-store state. Just a placeholder for v1; later this will hold
/// references to the chain client, sidecar DB, signature channel,
/// etc. so host functions can interact with them.
pub struct HostState {
	// nothing yet
}

pub struct OperatorRuntime {
	store: Store<HostState>,
	instance: Instance,
}

impl OperatorRuntime {
	/// Load a WASM blob from disk and instantiate it. Binds host
	/// functions during instantiation; subsequent invocations reuse
	/// the same store/instance.
	pub fn load(wasm_path: &Path) -> Result<Self, RuntimeError> {
		let bytes = std::fs::read(wasm_path)
			.map_err(|e| RuntimeError::Load(format!("read {}: {e}", wasm_path.display())))?;
		Self::from_bytes(&bytes)
	}

	/// Like [`Self::load`] but with an in-memory blob. Used by
	/// tests; production callers use [`Self::load`].
	pub fn from_bytes(wasm_bytes: &[u8]) -> Result<Self, RuntimeError> {
		let engine = Engine::default();
		let module = Module::from_binary(&engine, wasm_bytes)
			.map_err(|e| RuntimeError::Load(e.to_string()))?;
		let mut store = Store::new(&engine, HostState {});
		let mut linker = Linker::new(&engine);
		bind_host_functions(&mut linker)
			.map_err(|e| RuntimeError::Instantiate(e.to_string()))?;
		let instance = linker
			.instantiate(&mut store, &module)
			.map_err(|e| RuntimeError::Instantiate(e.to_string()))?;
		Ok(Self { store, instance })
	}

	/// Call an exported WASM function with signature `() -> i32`.
	/// The i32 return value is re-cast to u32 at the boundary.
	pub fn invoke_no_args(&mut self, method: &str) -> Result<u32, RuntimeError> {
		let func = self
			.instance
			.get_func(&mut self.store, method)
			.ok_or_else(|| RuntimeError::ExportMissing(method.to_string()))?;
		let typed = func
			.typed::<(), i32>(&self.store)
			.map_err(|_| RuntimeError::WrongSignature(method.to_string()))?;
		let raw = typed
			.call(&mut self.store, ())
			.map_err(|e| RuntimeError::Trap(e.to_string()))?;
		Ok(raw as u32)
	}
}

fn bind_host_functions(linker: &mut Linker<HostState>) -> Result<(), wasmtime::Error> {
	linker.func_wrap(
		"rostro",
		"log",
		|mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
			let memory = match caller.get_export("memory") {
				Some(Extern::Memory(m)) => m,
				_ => {
					log::warn!("WASM called rostro::log but exports no `memory`; dropping");
					return;
				},
			};
			match read_utf8_from_memory(&memory, &caller, ptr as u32, len as u32) {
				Some(s) => log::info!(target: "operator-wasm", "{}", s),
				None => log::warn!(
					"WASM called rostro::log with out-of-bounds or non-UTF-8 buffer; dropping",
				),
			}
		},
	)?;
	Ok(())
}

fn read_utf8_from_memory(
	memory: &Memory,
	caller: &Caller<'_, HostState>,
	ptr: u32,
	len: u32,
) -> Option<String> {
	let data = memory.data(caller);
	let start = ptr as usize;
	let end = start.checked_add(len as usize)?;
	let slice = data.get(start..end)?;
	core::str::from_utf8(slice).ok().map(String::from)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A minimal WAT module that exports a `ping` function returning
	/// a magic constant. No host calls.
	const PING_WAT: &str = r#"
		(module
		  (func (export "ping") (result i32)
		    i32.const 0x12345678))
	"#;

	/// WAT module that imports `rostro::log`, calls it once, and
	/// returns. Used to verify the host function is callable from
	/// WASM without trapping.
	const HELLO_WAT: &str = r#"
		(module
		  (import "rostro" "log" (func $log (param i32 i32)))
		  (memory (export "memory") 1)
		  (data (i32.const 0) "hello from wasm")
		  (func (export "say_hello") (result i32)
		    i32.const 0
		    i32.const 15
		    call $log
		    i32.const 7))
	"#;

	/// WAT module without the expected export — exercises the
	/// ExportMissing path.
	const EMPTY_WAT: &str = r#"
		(module)
	"#;

	/// WAT module whose export has the wrong signature — exercises
	/// the WrongSignature path.
	const BAD_SIG_WAT: &str = r#"
		(module
		  (func (export "ping") (param i32) (result i32)
		    local.get 0))
	"#;

	#[test]
	fn invoke_no_args_returns_export_value() {
		let bytes = wat::parse_str(PING_WAT).unwrap();
		let mut rt = OperatorRuntime::from_bytes(&bytes).unwrap();
		let v = rt.invoke_no_args("ping").unwrap();
		assert_eq!(v, 0x12345678);
	}

	#[test]
	fn invoke_no_args_calls_host_log_without_trapping() {
		let bytes = wat::parse_str(HELLO_WAT).unwrap();
		let mut rt = OperatorRuntime::from_bytes(&bytes).unwrap();
		let v = rt.invoke_no_args("say_hello").unwrap();
		assert_eq!(v, 7);
	}

	#[test]
	fn invoke_returns_export_missing_error_for_unknown_method() {
		let bytes = wat::parse_str(PING_WAT).unwrap();
		let mut rt = OperatorRuntime::from_bytes(&bytes).unwrap();
		let err = rt.invoke_no_args("does_not_exist").unwrap_err();
		assert!(matches!(err, RuntimeError::ExportMissing(_)));
	}

	#[test]
	fn invoke_returns_wrong_signature_error_for_mismatched_export() {
		let bytes = wat::parse_str(BAD_SIG_WAT).unwrap();
		let mut rt = OperatorRuntime::from_bytes(&bytes).unwrap();
		let err = rt.invoke_no_args("ping").unwrap_err();
		assert!(matches!(err, RuntimeError::WrongSignature(_)));
	}

	#[test]
	fn load_returns_error_for_invalid_wasm() {
		// Don't use unwrap_err — OperatorRuntime intentionally
		// doesn't impl Debug (wasmtime's Store/Instance don't).
		match OperatorRuntime::from_bytes(b"not a wasm module") {
			Err(RuntimeError::Load(_)) => {},
			Err(other) => panic!("expected Load error, got {:?}", other),
			Ok(_) => panic!("expected Err, got Ok"),
		}
	}

	#[test]
	fn empty_module_has_no_exports() {
		let bytes = wat::parse_str(EMPTY_WAT).unwrap();
		let mut rt = OperatorRuntime::from_bytes(&bytes).unwrap();
		let err = rt.invoke_no_args("ping").unwrap_err();
		assert!(matches!(err, RuntimeError::ExportMissing(_)));
	}
}
