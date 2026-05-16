// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! polkavm-export shims for each shape exhibit.
//!
//! The trace_synth example picks the export by symbol name (e.g.
//! `module.exports().find(|e| e == "shape_add_chain")`).

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn shape_add_chain() -> u32 {
	crate::shape_add_chain()
}

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn shape_branch_loop() -> u32 {
	crate::shape_branch_loop()
}

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn shape_load_store() -> u32 {
	crate::shape_load_store()
}

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn shape_intrinsic_once() -> u32 {
	crate::shape_intrinsic_once()
}
