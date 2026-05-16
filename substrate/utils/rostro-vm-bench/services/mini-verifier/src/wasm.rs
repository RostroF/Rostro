// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation
//
// Wasmtime-side entrypoint. Rostro-side addition only — when the service
// is shared back to JAR/Grey's bench set this file is a no-op (wasm32 isn't
// a JAR target), and the rest of the crate is upstream-clean.

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i64 {
    crate::mini_verifier_bench() as i64
}
