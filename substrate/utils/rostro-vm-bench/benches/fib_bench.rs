// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Criterion bench for the Fibonacci workload — four-way characterization:
//!   - javm-interpreter
//!   - javm-recompiler (Linux x86-64 only)
//!   - polkavm-interpreter
//!   - polkavm-compiler (when supported by the host)
//!
//! Sweeps `fib(N)` for several N values to surface scaling behavior + the
//! interpreter-vs-JIT gap on each VM. Each blob is built once outside the
//! timed region; the inner loop measures VM build-module + instantiate +
//! execute + halt + read-A0.
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

const FIB_N_VALUES: &[u64] = &[1_000, 100_000, 1_000_000];

fn bench_fib(c: &mut Criterion) {
	let mut group = c.benchmark_group("fib");

	for &n in FIB_N_VALUES {
		let javm_blob = fib::javm_blob(n);
		let polkavm_blob = fib::polkavm_blob(n);

		// Correctness check at bench-startup.
		let expected = fib::expected_result(n);
		assert_eq!(
			JavmRunner::interpreter()
				.run(&javm_blob, &[])
				.expect("warmup javm")
				.result_a0,
			expected,
			"javm fib({n}) mismatch in bench setup"
		);
		assert_eq!(
			PolkaVmRunner::interpreter()
				.expect("polkavm-interpreter")
				.run(&polkavm_blob, &[])
				.expect("warmup polkavm")
				.result_a0,
			expected,
			"polkavm fib({n}) mismatch in bench setup"
		);

		group.bench_with_input(
			BenchmarkId::new("javm-interpreter", n),
			&javm_blob,
			|b, blob| {
				let mut runner = JavmRunner::interpreter();
				b.iter(|| {
					let out = runner.run(black_box(blob), &[]).expect("javm run");
					black_box(out);
				});
			},
		);

		#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
		group.bench_with_input(
			BenchmarkId::new("javm-recompiler", n),
			&javm_blob,
			|b, blob| {
				let mut runner = JavmRunner::recompiler();
				b.iter(|| {
					let out = runner.run(black_box(blob), &[]).expect("javm run");
					black_box(out);
				});
			},
		);

		group.bench_with_input(
			BenchmarkId::new("polkavm-interpreter", n),
			&polkavm_blob,
			|b, blob| {
				let mut runner =
					PolkaVmRunner::interpreter().expect("polkavm-interpreter");
				b.iter(|| {
					let out = runner.run(black_box(blob), &[]).expect("polkavm run");
					black_box(out);
				});
			},
		);

		// Polkavm compiler is host-dependent — skip the bench if it's
		// not available on this build.
		if let Ok(mut runner) = PolkaVmRunner::compiler() {
			// Verify it agrees before benching.
			assert_eq!(
				runner.run(&polkavm_blob, &[]).expect("warmup compiler").result_a0,
				expected,
				"polkavm-compiler fib({n}) mismatch in bench setup",
			);
			group.bench_with_input(
				BenchmarkId::new("polkavm-compiler", n),
				&polkavm_blob,
				|b, blob| {
					b.iter(|| {
						let out = runner.run(black_box(blob), &[]).expect("polkavm run");
						black_box(out);
					});
				},
			);
		}
	}

	group.finish();
}

criterion_group!(benches, bench_fib);
criterion_main!(benches);
