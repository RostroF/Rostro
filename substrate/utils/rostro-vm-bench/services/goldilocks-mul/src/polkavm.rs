// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

//! polkavm target glue: bench entry point.
//!
//! The Tier 2 H2 intrinsic imports moved into the gp crate (see
//! `goldilocks-poseidon2/src/polkavm.rs`); gp::mul itself dispatches via
//! the intrinsic on polkavm targets. This file just exports the bench fn.

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn goldilocks_mul_bench() -> u32 {
    crate::goldilocks_mul_bench()
}
