// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! RVM runner implementations for the [`crate::RvmRunner`] trait.

mod javm_runner;
mod polkavm_pristine_runner;
mod polkavm_runner;
mod wasmtime_runner;

pub use javm_runner::JavmRunner;
pub use polkavm_pristine_runner::PolkaVmPristineRunner;
pub use polkavm_runner::PolkaVmRunner;
pub use wasmtime_runner::WasmtimeRunner;

/// Default gas budget for bench workloads. Originally matched grey-bench's
/// `GAS_LIMIT = 100_000_000`, but bumped to 10 billion to accommodate the
/// fri-fold-tree-large workload — which does ~500K Poseidon2 perms +
/// millions of Goldilocks ops. Wasmtime's fuel is metered per-wasm-instruction
/// and polkavm gas per-instruction-similar; both run dry at the smaller limit
/// while polkavm and javm succeed (different cost models). 10B is generous
/// enough to cover any plausible bench workload.
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000_000;
