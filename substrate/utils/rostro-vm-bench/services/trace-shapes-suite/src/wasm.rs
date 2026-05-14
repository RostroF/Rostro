// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i64 {
	crate::shape_add_chain() as i64
}
