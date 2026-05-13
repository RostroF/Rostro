// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) Rostro Foundation

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i64 {
	crate::fri_fold_tree_large_bench() as i64
}
