// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i64 {
	crate::ecrecover_bench() as i64
}
