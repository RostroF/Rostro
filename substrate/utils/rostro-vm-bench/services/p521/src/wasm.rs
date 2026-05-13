// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i64 {
	crate::p521_verify_bench() as i64
}
