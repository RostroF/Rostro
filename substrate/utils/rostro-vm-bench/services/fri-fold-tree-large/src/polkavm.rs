// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn fri_fold_tree_large_bench() -> u32 {
    crate::fri_fold_tree_large_bench()
}
