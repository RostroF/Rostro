// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Smoke test: build a trivial RVM blob in-test using polkavm's assembler,
//! execute it on [`PolkaVmRunner`], assert the runner trait surface is
//! functional end-to-end without pulling in any external blob toolchain.
//!
//! Halt-convention note: the blob uses polkavm's `ret`-to-host-sentinel
//! convention (`ret` with RA = `VM_ADDR_RETURN_TO_HOST = 0xFFFF_0000`).
//! `JavmRunner` cannot cleanly run this same blob because its
//! `InvocationKernel` expects JAM-style halt via `ecalli 0` (REPLY) —
//! a single source can't trigger both halt mechanisms. Apples-to-apples
//! javm-vs-polkavm validation arrives with the grey-transpiler integration
//! (see the planned follow-up commit adding grey-transpiler as a path-dep);
//! grey-transpiler produces blobs that halt via the JAM convention which
//! both VMs handle identically.

use rostro_vm_bench::{
	runners::{JavmRunner, PolkaVmRunner},
	RvmRunner,
};

/// Build the trivial blob: `a0 = 42; ret`.
///
/// Uses polkavm's built-in assembler, re-exported as
/// `polkavm::program::assemble`. No grey-transpiler dependency.
fn tiny_blob_polkavm_halt() -> Vec<u8> {
	let source = "\
		%isa = jam_v1\n\
		pub @main:\n\
		\ta0 = 42\n\
		\tret\n\
	";
	polkavm::program::assemble(None, source).expect("assemble tiny blob")
}

#[test]
fn polkavm_runs_tiny_blob_and_returns_42() {
	let blob = tiny_blob_polkavm_halt();
	let mut runner = PolkaVmRunner::new().expect("PolkaVmRunner::new");
	let out = runner.run(&blob, &[]).expect("polkavm run");
	assert_eq!(out.result_a0, 42, "expected A0 = 42, got {}", out.result_a0);
	assert!(out.gas_consumed > 0, "gas_consumed should be non-zero");
}

#[test]
fn polkavm_runner_name_is_polkavm() {
	let runner = PolkaVmRunner::new().expect("PolkaVmRunner::new");
	assert_eq!(runner.name(), "polkavm");
}

#[test]
fn javm_runner_names_match_backend() {
	assert_eq!(JavmRunner::default_backend().name(), "javm");
	assert_eq!(JavmRunner::interpreter().name(), "javm-interpreter");
	#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
	assert_eq!(JavmRunner::recompiler().name(), "javm-recompiler");
}
