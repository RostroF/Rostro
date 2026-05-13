// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Real-Rust crypto bench across all six VM backends. Each workload is a
// vendored guest service (see `services/`) compiled to javm + polkavm +
// wasm32 by `build.rs`. The same Rust source is the source of truth across
// all three target ABIs — no hand-assembled apples-to-oranges mismatch.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rostro_vm_bench::{
	runners::{JavmRunner, PolkaVmPristineRunner, PolkaVmRunner, WasmtimeRunner},
	service_blobs::{
		BATCH_INVERSE_JAVM_BLOB, BATCH_INVERSE_POLKAVM_BLOB, BATCH_INVERSE_WASM_BLOB,
		BLAKE2B_JAVM_BLOB, BLAKE2B_POLKAVM_BLOB, BLAKE2B_WASM_BLOB,
		CURVE_CONVERSION_JAVM_BLOB, CURVE_CONVERSION_POLKAVM_BLOB, CURVE_CONVERSION_WASM_BLOB,
		DILITHIUM_JAVM_BLOB, DILITHIUM_POLKAVM_BLOB, DILITHIUM_WASM_BLOB,
		ECRECOVER_JAVM_BLOB, ECRECOVER_POLKAVM_BLOB, ECRECOVER_WASM_BLOB,
		ED25519_JAVM_BLOB, ED25519_POLKAVM_BLOB, ED25519_WASM_BLOB,
		FRI_FOLD_TREE_JAVM_BLOB, FRI_FOLD_TREE_LARGE_JAVM_BLOB,
		FRI_FOLD_TREE_LARGE_POLKAVM_BLOB, FRI_FOLD_TREE_LARGE_WASM_BLOB,
		FRI_FOLD_TREE_POLKAVM_BLOB, FRI_FOLD_TREE_WASM_BLOB,
		GOLDILOCKS_MUL_JAVM_BLOB, GOLDILOCKS_MUL_POLKAVM_BLOB, GOLDILOCKS_MUL_WASM_BLOB,
		KECCAK_JAVM_BLOB, KECCAK_POLKAVM_BLOB, KECCAK_WASM_BLOB,
		MINI_VERIFIER_JAVM_BLOB, MINI_VERIFIER_POLKAVM_BLOB, MINI_VERIFIER_WASM_BLOB,
		P521_JAVM_BLOB, P521_POLKAVM_BLOB, P521_WASM_BLOB,
		POLY_EVAL_JAVM_BLOB, POLY_EVAL_POLKAVM_BLOB, POLY_EVAL_WASM_BLOB,
		POSEIDON2_PERM_JAVM_BLOB, POSEIDON2_PERM_POLKAVM_BLOB, POSEIDON2_PERM_WASM_BLOB,
	},
	RvmRunner,
};

/// Run one workload (a triplet of javm/polkavm/wasm blobs) across every
/// available backend, in both cold and warm modes.
fn bench_workload(
	c: &mut Criterion,
	name: &str,
	javm_blob: &[u8],
	polkavm_blob: &[u8],
	wasm_blob: &[u8],
) {
	// === Cold ===
	let mut cold = c.benchmark_group(name);
	cold.bench_function(BenchmarkId::new("javm-interpreter", "cold"), |b| {
		let mut r = JavmRunner::interpreter();
		b.iter(|| black_box(r.run(black_box(javm_blob), &[]).expect("javm-int")));
	});
	#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
	cold.bench_function(BenchmarkId::new("javm-recompiler", "cold"), |b| {
		let mut r = JavmRunner::recompiler();
		b.iter(|| black_box(r.run(black_box(javm_blob), &[]).expect("javm-rec")));
	});
	cold.bench_function(BenchmarkId::new("polkavm-interpreter", "cold"), |b| {
		let mut r = PolkaVmRunner::interpreter().expect("pvm-int");
		b.iter(|| black_box(r.run(black_box(polkavm_blob), &[]).expect("pvm-int")));
	});
	if let Ok(mut r) = PolkaVmRunner::compiler() {
		cold.bench_function(BenchmarkId::new("polkavm-compiler", "cold"), |b| {
			b.iter(|| black_box(r.run(black_box(polkavm_blob), &[]).expect("pvm-com")));
		});
	}
	cold.bench_function(BenchmarkId::new("polkavm-pristine-interpreter", "cold"), |b| {
		let mut r = PolkaVmPristineRunner::interpreter().expect("pvm-prist-int");
		b.iter(|| black_box(r.run(black_box(polkavm_blob), &[]).expect("pvm-prist-int")));
	});
	if let Ok(mut r) = PolkaVmPristineRunner::compiler() {
		cold.bench_function(BenchmarkId::new("polkavm-pristine-compiler", "cold"), |b| {
			b.iter(|| black_box(r.run(black_box(polkavm_blob), &[]).expect("pvm-prist-com")));
		});
	}
	if let Ok(mut r) = WasmtimeRunner::cranelift() {
		cold.bench_function(BenchmarkId::new("wasmtime-cranelift", "cold"), |b| {
			b.iter(|| black_box(r.run(black_box(wasm_blob), &[]).expect("wt-cl")));
		});
	}
	if let Ok(mut r) = WasmtimeRunner::winch() {
		cold.bench_function(BenchmarkId::new("wasmtime-winch", "cold"), |b| {
			b.iter(|| black_box(r.run(black_box(wasm_blob), &[]).expect("wt-w")));
		});
	}
	cold.finish();

	// === Warm ===
	let mut warm = c.benchmark_group(format!("{name}_warm"));
	{
		let mut r = JavmRunner::interpreter();
		let c = r.precompile(javm_blob).expect("precompile");
		warm.bench_function(BenchmarkId::new("javm-interpreter", "warm"), |b| {
			b.iter(|| black_box(r.run_compiled(black_box(&c), &[]).expect("javm-int-w")));
		});
	}
	#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
	{
		let mut r = JavmRunner::recompiler();
		let c = r.precompile(javm_blob).expect("precompile");
		warm.bench_function(BenchmarkId::new("javm-recompiler", "warm"), |b| {
			b.iter(|| black_box(r.run_compiled(black_box(&c), &[]).expect("javm-rec-w")));
		});
	}
	{
		let mut r = PolkaVmRunner::interpreter().expect("pvm-int");
		let c = r.precompile(polkavm_blob).expect("precompile");
		warm.bench_function(BenchmarkId::new("polkavm-interpreter", "warm"), |b| {
			b.iter(|| black_box(r.run_compiled(black_box(&c), &[]).expect("pvm-int-w")));
		});
	}
	if let Ok(mut r) = PolkaVmRunner::compiler() {
		let c = r.precompile(polkavm_blob).expect("precompile");
		warm.bench_function(BenchmarkId::new("polkavm-compiler", "warm"), |b| {
			b.iter(|| black_box(r.run_compiled(black_box(&c), &[]).expect("pvm-com-w")));
		});
	}
	{
		let mut r = PolkaVmPristineRunner::interpreter().expect("pvm-prist-int");
		let c = r.precompile(polkavm_blob).expect("precompile");
		warm.bench_function(BenchmarkId::new("polkavm-pristine-interpreter", "warm"), |b| {
			b.iter(|| black_box(r.run_compiled(black_box(&c), &[]).expect("pvm-prist-int-w")));
		});
	}
	if let Ok(mut r) = PolkaVmPristineRunner::compiler() {
		let c = r.precompile(polkavm_blob).expect("precompile");
		warm.bench_function(BenchmarkId::new("polkavm-pristine-compiler", "warm"), |b| {
			b.iter(|| black_box(r.run_compiled(black_box(&c), &[]).expect("pvm-prist-com-w")));
		});
	}
	if let Ok(mut r) = WasmtimeRunner::cranelift() {
		let c = r.precompile(wasm_blob).expect("precompile");
		warm.bench_function(BenchmarkId::new("wasmtime-cranelift", "warm"), |b| {
			b.iter(|| black_box(r.run_compiled(black_box(&c), &[]).expect("wt-cl-w")));
		});
	}
	if let Ok(mut r) = WasmtimeRunner::winch() {
		let c = r.precompile(wasm_blob).expect("precompile");
		warm.bench_function(BenchmarkId::new("wasmtime-winch", "warm"), |b| {
			b.iter(|| black_box(r.run_compiled(black_box(&c), &[]).expect("wt-w-w")));
		});
	}
	warm.finish();
}

fn bench_blake2b(c: &mut Criterion) {
	bench_workload(c, "blake2b", BLAKE2B_JAVM_BLOB, BLAKE2B_POLKAVM_BLOB, BLAKE2B_WASM_BLOB);
}

fn bench_mini_verifier(c: &mut Criterion) {
	bench_workload(
		c,
		"mini_verifier",
		MINI_VERIFIER_JAVM_BLOB,
		MINI_VERIFIER_POLKAVM_BLOB,
		MINI_VERIFIER_WASM_BLOB,
	);
}

fn bench_goldilocks_mul(c: &mut Criterion) {
	bench_workload(
		c,
		"goldilocks_mul",
		GOLDILOCKS_MUL_JAVM_BLOB,
		GOLDILOCKS_MUL_POLKAVM_BLOB,
		GOLDILOCKS_MUL_WASM_BLOB,
	);
}

fn bench_poseidon2_perm(c: &mut Criterion) {
	bench_workload(
		c,
		"poseidon2_perm",
		POSEIDON2_PERM_JAVM_BLOB,
		POSEIDON2_PERM_POLKAVM_BLOB,
		POSEIDON2_PERM_WASM_BLOB,
	);
}

fn bench_fri_fold_tree(c: &mut Criterion) {
	bench_workload(
		c,
		"fri_fold_tree",
		FRI_FOLD_TREE_JAVM_BLOB,
		FRI_FOLD_TREE_POLKAVM_BLOB,
		FRI_FOLD_TREE_WASM_BLOB,
	);
}

fn bench_fri_fold_tree_large(c: &mut Criterion) {
	bench_workload(
		c,
		"fri_fold_tree_large",
		FRI_FOLD_TREE_LARGE_JAVM_BLOB,
		FRI_FOLD_TREE_LARGE_POLKAVM_BLOB,
		FRI_FOLD_TREE_LARGE_WASM_BLOB,
	);
}

fn bench_poly_eval(c: &mut Criterion) {
	bench_workload(
		c,
		"poly_eval",
		POLY_EVAL_JAVM_BLOB,
		POLY_EVAL_POLKAVM_BLOB,
		POLY_EVAL_WASM_BLOB,
	);
}

fn bench_batch_inverse(c: &mut Criterion) {
	bench_workload(
		c,
		"batch_inverse",
		BATCH_INVERSE_JAVM_BLOB,
		BATCH_INVERSE_POLKAVM_BLOB,
		BATCH_INVERSE_WASM_BLOB,
	);
}

fn bench_ed25519(c: &mut Criterion) {
	bench_workload(c, "ed25519", ED25519_JAVM_BLOB, ED25519_POLKAVM_BLOB, ED25519_WASM_BLOB);
}

fn bench_ecrecover(c: &mut Criterion) {
	bench_workload(c, "ecrecover", ECRECOVER_JAVM_BLOB, ECRECOVER_POLKAVM_BLOB, ECRECOVER_WASM_BLOB);
}

fn bench_keccak(c: &mut Criterion) {
	bench_workload(c, "keccak", KECCAK_JAVM_BLOB, KECCAK_POLKAVM_BLOB, KECCAK_WASM_BLOB);
}

fn bench_dilithium(c: &mut Criterion) {
	bench_workload(c, "dilithium", DILITHIUM_JAVM_BLOB, DILITHIUM_POLKAVM_BLOB, DILITHIUM_WASM_BLOB);
}

fn bench_p521(c: &mut Criterion) {
	bench_workload(c, "p521", P521_JAVM_BLOB, P521_POLKAVM_BLOB, P521_WASM_BLOB);
}

fn bench_curve_conversion(c: &mut Criterion) {
	bench_workload(
		c,
		"curve_conversion",
		CURVE_CONVERSION_JAVM_BLOB,
		CURVE_CONVERSION_POLKAVM_BLOB,
		CURVE_CONVERSION_WASM_BLOB,
	);
}

criterion_group!(
	benches,
	bench_blake2b,
	bench_goldilocks_mul,
	bench_poseidon2_perm,
	bench_poly_eval,
	bench_batch_inverse,
	bench_mini_verifier,
	bench_fri_fold_tree,
	bench_fri_fold_tree_large,
	bench_ed25519,
	bench_ecrecover,
	bench_keccak,
	bench_dilithium,
	bench_p521,
	bench_curve_conversion,
);
criterion_main!(benches);
