// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

// wasm-cull W5 (per D1): the `metadata-hash` build feature is gone with the
// wasm executor that computed it; CheckMetadataHash stays in the runtime in
// disabled mode (docs/WASM-SURFACE-AUDIT.md).
#[cfg(feature = "std")]
fn main() {
	substrate_wasm_builder::WasmBuilder::init_with_defaults().build();
}

#[cfg(not(feature = "std"))]
fn main() {}
