// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// javm entry — picks the first shape (shape_add_chain) by default. The
// trace_synth example doesn't use this entry point on the polkavm side
// (it picks exports by symbol).

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
javm_builtins::javm_entry!(javm_main);

#[cfg(target_env = "javm")]
#[no_mangle]
extern "C" fn javm_main() -> u32 {
	rostro_bench_trace_shapes_suite::shape_add_chain()
}

#[cfg(not(target_env = "javm"))]
fn main() {}
