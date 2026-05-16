// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Wasmtime-side entrypoint mirroring `polkavm.rs`. The bench harness's
// `WasmtimeRunner` looks up an export named `main` with signature `() -> i64`.

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i64 {
	crate::ed25519_verify_bench() as i64
}
