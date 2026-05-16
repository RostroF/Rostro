// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn mini_verifier_bench() -> u32 {
    crate::mini_verifier_bench()
}
