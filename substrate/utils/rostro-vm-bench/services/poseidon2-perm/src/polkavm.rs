// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn poseidon2_perm_bench() -> u32 {
    crate::poseidon2_perm_bench()
}
