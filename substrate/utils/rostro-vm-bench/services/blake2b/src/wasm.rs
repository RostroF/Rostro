// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Wasmtime-side entrypoint mirroring `polkavm.rs`. The bench harness's
// `WasmtimeRunner` looks up an export named `main` with signature `() -> i64`,
// so we widen the underlying u32 result to i64 here.

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i64 {
	crate::blake2b_bench() as i64
}
