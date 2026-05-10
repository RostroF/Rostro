// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! RVM runner implementations for the [`crate::RvmRunner`] trait.

mod javm_runner;
mod polkavm_runner;

pub use javm_runner::JavmRunner;
pub use polkavm_runner::PolkaVmRunner;

/// Default gas budget for bench workloads. Matches grey-bench's `GAS_LIMIT`.
pub const DEFAULT_GAS_LIMIT: u64 = 100_000_000;
