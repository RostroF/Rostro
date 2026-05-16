// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! B5 gate: prove `rostro-runtime` (the solochain runtime — Aura + GRANDPA
//! over a dozen pallets) cross-compiles to a PVM blob via the existing
//! `substrate-wasm-builder` toolchain, and the resulting blob is well-
//! formed enough for `rostro-executor` to load it through
//! [`RostroExecutor::from_blob`].
//!
//! Gated `#[ignore]` because `rostro-runtime`'s `WASM_BINARY` content
//! depends on the build-time `SUBSTRATE_RUNTIME_TARGET` value. With it
//! set to `riscv` we get a PVM blob and the test runs end-to-end; with
//! it unset (default), we'd get a WASM blob that `from_blob` correctly
//! refuses to parse. Run as:
//!
//! ```sh
//! SUBSTRATE_RUNTIME_TARGET=riscv cargo test -p rostro-executor -- --ignored
//! ```

use rostro_executor::RostroExecutor;

/// PVM blobs from polkavm-linker carry the same magic the polkavm parser
/// uses (`b"PVM\0"`, first 4 bytes of every well-formed blob). WASM
/// modules use `b"\0asm"`. We sniff the first 4 bytes so the test fails
/// with a clear "rebuild with SUBSTRATE_RUNTIME_TARGET=riscv" message
/// instead of a hexdumped polkavm parse error.
fn is_pvm_blob(bytes: &[u8]) -> bool {
	bytes.starts_with(b"PVM\0")
}

#[test]
#[ignore = "requires SUBSTRATE_RUNTIME_TARGET=riscv to build rostro-runtime as a PVM blob"]
fn rostro_runtime_pvm_blob_loads_against_executor() {
	let blob = rostro_runtime::WASM_BINARY.expect(
		"rostro-runtime WASM_BINARY is None — set SUBSTRATE_RUNTIME_TARGET=riscv \
		 and rebuild, or check that SKIP_WASM_BUILD wasn't set",
	);

	assert!(
		is_pvm_blob(blob),
		"rostro-runtime blob is not in PVM format — first 4 bytes {:02x?}, expected PVM\\0. \
		 The build did not set SUBSTRATE_RUNTIME_TARGET=riscv.",
		&blob[..4.min(blob.len())]
	);

	let executor = RostroExecutor::from_blob(blob).expect("rostro-runtime PVM blob loads");

	// A real substrate runtime exports a stack of `Core_*`, `BlockBuilder_*`,
	// `Metadata_*`, etc. entry points via `impl_runtime_apis!`. We don't
	// need every one — just confirm the export table isn't empty and that
	// at least one well-known substrate runtime API symbol made it through.
	let module = executor.module();
	let exports: Vec<_> = module.exports().collect();
	assert!(!exports.is_empty(), "rostro-runtime blob has no exports");

	let names: Vec<&[u8]> = exports.iter().map(|e| e.symbol().as_bytes()).collect();
	let has_core_api = names.iter().any(|n| n.starts_with(b"Core_"));
	assert!(
		has_core_api,
		"rostro-runtime PVM blob exports no `Core_*` symbol. Exports: {:?}",
		names
			.iter()
			.map(|n| String::from_utf8_lossy(n))
			.collect::<Vec<_>>()
	);
}
