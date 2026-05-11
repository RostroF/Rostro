// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Criterion bench for the trial-division primes workload, javm + polkavm.
//!
//! Sweeps `count_primes_up_to(N)` for N ∈ {100, 500, 1_000}. The naive
//! algorithm is roughly `O(N²)` — sweeping N produces the "inverted dyno"
//! curve the bench was designed to surface.
//!
//! Run with:
//!     cargo bench -p rostro-vm-bench --bench primes_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rostro_vm_bench::{
	runners::{JavmRunner, PolkaVmRunner},
	workloads::primes,
	RvmRunner,
};

/// N values to sweep. Smaller than the fib sweep because the inner
/// loop is more expensive — `O(N²)` vs `fib`'s `O(N)`.
const PRIMES_N_VALUES: &[u64] = &[100, 500, 1_000];

fn bench_primes(c: &mut Criterion) {
	let mut group = c.benchmark_group("primes");

	for &n in PRIMES_N_VALUES {
		let javm_blob = primes::javm_blob(n);
		let polkavm_blob = primes::polkavm_blob(n);

		// Correctness check at bench-startup — a broken blob builder
		// gets caught before any timing samples are taken.
		let expected = primes::expected_result(n);
		let mut javm_warm = JavmRunner::interpreter();
		let mut polkavm_warm = PolkaVmRunner::new().expect("PolkaVmRunner::new");
		assert_eq!(
			javm_warm.run(&javm_blob, &[]).expect("warmup javm").result_a0,
			expected,
			"javm primes({}) mismatch in bench setup",
			n
		);
		assert_eq!(
			polkavm_warm
				.run(&polkavm_blob, &[])
				.expect("warmup polkavm")
				.result_a0,
			expected,
			"polkavm primes({}) mismatch in bench setup",
			n
		);

		group.bench_with_input(
			BenchmarkId::new("javm-interpreter", n),
			&javm_blob,
			|b, blob| {
				let mut runner = JavmRunner::interpreter();
				b.iter(|| {
					let out = runner.run(black_box(blob), &[]).expect("javm primes");
					black_box(out);
				});
			},
		);

		group.bench_with_input(BenchmarkId::new("polkavm", n), &polkavm_blob, |b, blob| {
			let mut runner = PolkaVmRunner::new().expect("PolkaVmRunner::new");
			b.iter(|| {
				let out = runner.run(black_box(blob), &[]).expect("polkavm primes");
				black_box(out);
			});
		});
	}

	group.finish();
}

criterion_group!(benches, bench_primes);
criterion_main!(benches);
