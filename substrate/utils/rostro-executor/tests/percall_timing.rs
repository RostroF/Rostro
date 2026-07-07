// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Per-runtime-call cost probe. Skips (passes) unless `ROSTRO_BLOB`
//! points at a runtime blob, so it costs nothing in CI; run it manually
//! against the live chain's `:code` to check for per-call regressions.
//!
//! Times the pieces of `RostroCodeExecutor`'s per-call work:
//!   1.  `read_runtime_version` round trip (empty cache key → pays a
//!       content hash of the blob per call; cold trait, called on code
//!       changes and startup),
//!   1b. `CodeExecutor::call` with a client-supplied code hash — the hot
//!       path every `validate_transaction` / `apply_extrinsic` takes,
//!   2.  `Module::new` alone (parse/predecode; the cache-miss cost),
//!   3.  instantiate alone from a cached module (the cache-hit cost).
//!
//! Baseline (2026-07-06, Ryzen 5900HX, 5.16 MB lab blob): (1) 5.6ms,
//! (1b) 1.07ms, (2) 13.0ms, (3) ~210ns. Pre-cache, (1) and (1b) were
//! both ~17.4ms — the throughput-characterization root cause.
//!
//! Run:
//!   ROSTRO_BLOB=/path/to/code.pvm cargo test -p rostro-executor \
//!     --test percall_timing --release -- --nocapture

use polkavm::{Config, Engine, Module, ModuleConfig};
use rostro_executor::RostroCodeExecutor;
use sp_core::traits::ReadRuntimeVersion;
use sp_state_machine::BasicExternalities;
use std::time::Instant;

#[test]
fn percall_cost_breakdown() {
	let path = match std::env::var("ROSTRO_BLOB") {
		Ok(p) => p,
		Err(_) => {
			eprintln!("ROSTRO_BLOB not set; skipping");
			return;
		},
	};
	let blob = std::fs::read(&path).expect("read blob");
	assert!(blob.starts_with(b"PVM\0"), "not a PVM blob");
	eprintln!("blob: {} bytes", blob.len());

	// (1) Full per-call round trip through the real executor path.
	let executor =
		RostroCodeExecutor::<sp_io::SubstrateHostFunctions>::new().expect("construct executor");
	let mut ext = BasicExternalities::default();
	// warm-up
	executor.read_runtime_version(&blob, &mut ext).expect("Core_version");
	const N: u32 = 10;
	let t = Instant::now();
	for _ in 0..N {
		executor.read_runtime_version(&blob, &mut ext).expect("Core_version");
	}
	let full = t.elapsed() / N;
	eprintln!("full read_runtime_version (Core_version) per call: {full:?}");

	// (1b) The hot path: CodeExecutor::call with a client-supplied code
	// hash (as sc-service provides on every validate_transaction /
	// apply_extrinsic) — no per-call content hashing.
	use sp_core::traits::{CallContext, CodeExecutor, RuntimeCode, WrappedRuntimeCode};
	let wrapped = WrappedRuntimeCode(blob.as_slice().into());
	let runtime_code =
		RuntimeCode { code_fetcher: &wrapped, heap_pages: None, hash: vec![0x42; 32] };
	let (warm, _) =
		executor.call(&mut ext, &runtime_code, "Core_version", &[], CallContext::Offchain);
	warm.expect("Core_version via CodeExecutor::call");
	let t = Instant::now();
	for _ in 0..N {
		let (r, _) =
			executor.call(&mut ext, &runtime_code, "Core_version", &[], CallContext::Offchain);
		r.expect("Core_version via CodeExecutor::call");
	}
	let hot = t.elapsed() / N;
	eprintln!("CodeExecutor::call w/ provided hash (hot path) per call: {hot:?}");

	// (2) Module::new alone on the same engine config the executor uses.
	let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
	config.set_allow_experimental(true);
	config.set_backend(Some(polkavm::BackendKind::Interpreter));
	let engine = Engine::new(&config).expect("engine");
	let t = Instant::now();
	for _ in 0..N {
		let mc = ModuleConfig::new();
		let m = Module::new(&engine, &mc, blob.to_vec().into()).expect("module");
		std::hint::black_box(&m);
	}
	let parse = t.elapsed() / N;
	eprintln!("Module::new (parse/predecode) per call: {parse:?}");

	// (3) Instantiate alone, module reused across calls.
	let mc = ModuleConfig::new();
	let module = Module::new(&engine, &mc, blob.to_vec().into()).expect("module");
	let linker: polkavm::Linker = polkavm::Linker::new();
	// Core_version's imports aren't wired here; just measure raw instantiation.
	if let Ok(pre) = linker.instantiate_pre(&module) {
		let t = Instant::now();
		for _ in 0..N {
			let inst = pre.instantiate().expect("instantiate");
			std::hint::black_box(&inst);
		}
		let inst = t.elapsed() / N;
		eprintln!("instantiate per call (module cached): {inst:?}");
	} else {
		eprintln!("instantiate_pre failed without host fns; skipping (3)");
	}
}
