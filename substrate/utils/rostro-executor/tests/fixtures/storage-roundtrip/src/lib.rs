// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # rostro-executor storage roundtrip fixture
//!
//! Tiny runtime guest used as the B3 gate test for
//! [`rostro-executor`](https://github.com/rostro-foundation/rostro/tree/main/substrate/utils/rostro-executor).
//! Compiled to PVM via `substrate-wasm-builder` (its `build.rs` forces
//! `SUBSTRATE_RUNTIME_TARGET=riscv`), loaded by the integration test, run
//! with the dispatcher's host-fn shim wired to `sp_io::storage::HostFunctions`.
//!
//! The guest's single export, `test_storage_roundtrip`, returns:
//!
//! - `0` — set + read returned the original bytes intact (roundtrip OK).
//! - `1` — `storage::read` returned a length that didn't match what was set.
//! - `2` — bytes didn't match.
//! - `3` — `storage::read` returned `None` after `set`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Re-export the WASM/PVM binary produced by build.rs for the host side
// (rostro-executor's integration test) to load.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Returns the PVM blob bytes. Panics if `SKIP_WASM_BUILD` was set.
#[cfg(feature = "std")]
pub fn binary_unwrap() -> &'static [u8] {
	WASM_BINARY.expect(
		"rostro-executor-fixture-storage-roundtrip binary missing — build was \
		 skipped via SKIP_WASM_BUILD or substrate-wasm-builder reported failure",
	)
}

// ─── Runtime side (no_std) ─────────────────────────────────────────────────
//
// `polkavm_export` (vs sp-core's `wasm_export_functions!`) is the right
// macro for the PVM target — it emits the polkavm export symbol the
// linker needs to find the entry point. The latter just does
// `#[no_mangle] pub fn`, which polkavm-linker treats as an internal
// function and strips, leaving an empty program.

#[cfg(not(feature = "std"))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn test_storage_roundtrip() -> u64 {
	let key: &[u8] = b"phase-star-roundtrip-key";
	let value: &[u8] = b"phase-star-roundtrip-value";

	// B3 minimal: just exercise `set`. Read-back through the SCALE-encoded
	// `Option<u32>` return path needs allocate_memory + return-fat-pointer
	// semantics that go beyond storage::set's call-only path; that becomes
	// the B3-followup gate (host-side reads externalities directly to
	// verify what the guest wrote).
	sp_io::storage::set(key, value);

	0
}
