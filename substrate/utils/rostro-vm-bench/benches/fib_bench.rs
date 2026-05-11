// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Criterion bench for the Fibonacci workload across javm and polkavm.
//!
//! Sweeps `fib(N)` for several N values to characterize per-VM throughput
//! and surface scaling behavior. Each blob is built once outside the timed
//! region; the inner loop measures VM build-module + instantiate + execute
//! + halt + read-A0 — matches grey-bench's "compile + execute every
//! iteration" fairness convention.
//!
//! Run with:
//!     cargo bench -p rostro-vm-bench --bench fib_bench
//!
//! HTML reports land at `target/criterion/`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rostro_vm_bench::{
	runners::{JavmRunner, PolkaVmRunner},
	workloads::fib,
	RvmRunner,
};

/// N values to sweep. Spans three orders of magnitude of inner-loop
/// iterations — enough to surface scaling behavior without making the
/// bench wall-clock punishingly long.
const FIB_N_VALUES: &[u64] = &[1_000, 100_000, 1_000_000];

fn bench_fib(c: &mut Criterion) {
	let mut group = c.benchmark_group("fib");

	for &n in FIB_N_VALUES {
		let javm_blob = fib::javm_blob(n);
		let polkavm_blob = fib::polkavm_blob(n);

		// Sanity: both blobs should produce the same result (already
		// checked by the smoke tests, but we re-assert here so a broken
		// blob builder is caught at bench-startup rather than producing
		// silently-bogus numbers.
		let expected = fib::expected_result(n);
		let mut javm_warm = JavmRunner::interpreter();
		let mut polkavm_warm = PolkaVmRunner::new().expect("PolkaVmRunner::new");
		assert_eq!(
			javm_warm.run(&javm_blob, &[]).expect("warmup javm").result_a0,
			expected,
			"javm fib({}) mismatch in bench setup",
			n
		);
		assert_eq!(
			polkavm_warm.run(&polkavm_blob, &[]).expect("warmup polkavm").result_a0,
			expected,
			"polkavm fib({}) mismatch in bench setup",
			n
		);

		group.bench_with_input(BenchmarkId::new("javm-interpreter", n), &javm_blob, |b, blob| {
			let mut runner = JavmRunner::interpreter();
			b.iter(|| {
				let out = runner.run(black_box(blob), &[]).expect("javm run");
				black_box(out);
			});
		});

		group.bench_with_input(BenchmarkId::new("polkavm", n), &polkavm_blob, |b, blob| {
			let mut runner = PolkaVmRunner::new().expect("PolkaVmRunner::new");
			b.iter(|| {
				let out = runner.run(black_box(blob), &[]).expect("polkavm run");
				black_box(out);
			});
		});
	}

	group.finish();
}

criterion_group!(benches, bench_fib);
criterion_main!(benches);
