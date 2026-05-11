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
	workloads::{fib, primes},
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

/// Build a javm-flavor blob using grey-transpiler's Assembler:
/// `a0 = 42; ecalli 0` (JAM REPLY). The Assembler emits javm's native
/// blob format with its own magic header — polkavm cannot parse this.
fn tiny_blob_javm_native() -> Vec<u8> {
	use grey_transpiler::assembler::{Assembler, Reg};
	let mut asm = Assembler::new();
	asm.set_stack_pages(1);
	asm.set_heap_pages(0);
	asm.load_imm_64(Reg::A0, 42);
	asm.ecalli(0x00);
	asm.build()
}

#[test]
fn javm_runs_native_blob_and_returns_42() {
	let blob = tiny_blob_javm_native();
	let mut runner = JavmRunner::interpreter();
	let out = runner.run(&blob, &[]).expect("javm run");
	assert_eq!(out.result_a0, 42, "expected A0 = 42, got {}", out.result_a0);
	assert!(out.gas_consumed > 0, "gas_consumed should be non-zero");
}

#[test]
fn fib_javm_matches_native_reference() {
	let n: u64 = 10;
	let blob = fib::javm_blob(n);
	let mut runner = JavmRunner::interpreter();
	let out = runner.run(&blob, &[]).expect("javm fib");
	assert_eq!(out.result_a0, fib::expected_result(n));
}

#[test]
fn fib_polkavm_matches_native_reference() {
	let n: u64 = 10;
	let blob = fib::polkavm_blob(n);
	let mut runner = PolkaVmRunner::new().expect("PolkaVmRunner");
	let out = runner.run(&blob, &[]).expect("polkavm fib");
	assert_eq!(out.result_a0, fib::expected_result(n));
}

/// Real workload apples-to-apples: both VMs compute the same Fibonacci
/// iteration and produce the same A0. Gas counts differ (different cost
/// models) — emitted for visibility but not asserted on.
/// Naive trial-division primes — both VMs now, apples-to-apples.
/// Uses the Assembler extension methods (`mul_64`, `rem_unsigned_64`,
/// `set_less_than_unsigned`, `branch_less_unsigned`) on the
/// `feature/assembler-extended-ops` branch of grey-transpiler.
#[test]
fn primes_javm_matches_native_reference() {
	let n: u64 = 30;
	let blob = primes::javm_blob(n);
	let mut runner = JavmRunner::interpreter();
	let out = runner.run(&blob, &[]).expect("javm primes");
	assert_eq!(out.result_a0, primes::expected_result(n), "javm primes({n})");
}

#[test]
fn primes_polkavm_matches_native_reference() {
	let n: u64 = 30;
	let blob = primes::polkavm_blob(n);
	let mut runner = PolkaVmRunner::new().expect("PolkaVmRunner");
	let out = runner.run(&blob, &[]).expect("polkavm primes");
	assert_eq!(out.result_a0, primes::expected_result(n), "polkavm primes({n})");
}

#[test]
fn primes_javm_polkavm_agree() {
	let n: u64 = 30;
	let mut javm = JavmRunner::interpreter();
	let mut polkavm = PolkaVmRunner::new().expect("PolkaVmRunner");

	let javm_out = javm.run(&primes::javm_blob(n), &[]).expect("javm primes");
	let polkavm_out = polkavm
		.run(&primes::polkavm_blob(n), &[])
		.expect("polkavm primes");

	assert_eq!(
		javm_out.result_a0, polkavm_out.result_a0,
		"javm ({}) vs polkavm ({}) disagree on primes({n})",
		javm_out.result_a0, polkavm_out.result_a0,
	);
	assert_eq!(javm_out.result_a0, primes::expected_result(n));

	eprintln!(
		"primes({}) workload: javm gas={} polkavm gas={} (delta {})",
		n,
		javm_out.gas_consumed,
		polkavm_out.gas_consumed,
		javm_out.gas_consumed as i128 - polkavm_out.gas_consumed as i128,
	);
}

#[test]
fn fib_javm_polkavm_agree() {
	let n: u64 = 10;
	let mut javm = JavmRunner::interpreter();
	let mut polkavm = PolkaVmRunner::new().expect("PolkaVmRunner");

	let javm_out = javm.run(&fib::javm_blob(n), &[]).expect("javm fib");
	let polkavm_out = polkavm.run(&fib::polkavm_blob(n), &[]).expect("polkavm fib");

	assert_eq!(
		javm_out.result_a0, polkavm_out.result_a0,
		"javm A0 ({}) vs polkavm A0 ({}) disagree",
		javm_out.result_a0, polkavm_out.result_a0,
	);
	assert_eq!(javm_out.result_a0, fib::expected_result(n));

	eprintln!(
		"fib({}) workload: javm gas={} polkavm gas={} (delta {})",
		n,
		javm_out.gas_consumed,
		polkavm_out.gas_consumed,
		javm_out.gas_consumed as i128 - polkavm_out.gas_consumed as i128,
	);
}

/// Apples-to-apples on the observable program result. The two VMs use
/// incompatible blob magic headers, so each gets its native blob built
/// from logically-equivalent source: load 42 into A0, halt. Both VMs
/// should report A0 = 42 at halt. Gas counts differ (different cost
/// models) — we don't assert on gas, just emit it.
#[test]
fn javm_and_polkavm_agree_on_result_42() {
	let javm_blob = tiny_blob_javm_native();
	let polkavm_blob = tiny_blob_polkavm_halt();

	let mut javm = JavmRunner::interpreter();
	let mut polkavm = PolkaVmRunner::new().expect("PolkaVmRunner::new");

	let javm_out = javm.run(&javm_blob, &[]).expect("javm");
	let polkavm_out = polkavm.run(&polkavm_blob, &[]).expect("polkavm");

	assert_eq!(
		javm_out.result_a0, polkavm_out.result_a0,
		"javm A0 ({}) vs polkavm A0 ({}) disagree",
		javm_out.result_a0, polkavm_out.result_a0,
	);
	assert_eq!(javm_out.result_a0, 42);

	eprintln!(
		"a0=42 workload: javm gas={} polkavm gas={} (delta {})",
		javm_out.gas_consumed,
		polkavm_out.gas_consumed,
		javm_out.gas_consumed as i128 - polkavm_out.gas_consumed as i128,
	);
}
