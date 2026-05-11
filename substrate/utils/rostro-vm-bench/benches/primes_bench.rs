// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Criterion bench for the trial-division primes workload — four-way
//! characterization (javm interp/recomp + polkavm interp/comp).
//!
//! Sweeps `count_primes_up_to(N)` for N ∈ {100, 500, 1_000}. The naive
//! algorithm is roughly O(N²) — sweeping N produces the "inverted dyno"
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

const PRIMES_N_VALUES: &[u64] = &[100, 500, 1_000];

fn bench_primes(c: &mut Criterion) {
	let mut group = c.benchmark_group("primes");

	for &n in PRIMES_N_VALUES {
		let javm_blob = primes::javm_blob(n);
		let polkavm_blob = primes::polkavm_blob(n);

		let expected = primes::expected_result(n);
		assert_eq!(
			JavmRunner::interpreter()
				.run(&javm_blob, &[])
				.expect("warmup javm")
				.result_a0,
			expected,
			"javm primes({n}) mismatch in bench setup"
		);
		assert_eq!(
			PolkaVmRunner::interpreter()
				.expect("polkavm-interpreter")
				.run(&polkavm_blob, &[])
				.expect("warmup polkavm")
				.result_a0,
			expected,
			"polkavm primes({n}) mismatch in bench setup"
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

		#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
		group.bench_with_input(
			BenchmarkId::new("javm-recompiler", n),
			&javm_blob,
			|b, blob| {
				let mut runner = JavmRunner::recompiler();
				b.iter(|| {
					let out = runner.run(black_box(blob), &[]).expect("javm primes");
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
					let out = runner.run(black_box(blob), &[]).expect("polkavm primes");
					black_box(out);
				});
			},
		);

		if let Ok(mut runner) = PolkaVmRunner::compiler() {
			assert_eq!(
				runner.run(&polkavm_blob, &[]).expect("warmup compiler").result_a0,
				expected,
				"polkavm-compiler primes({n}) mismatch in bench setup",
			);
			group.bench_with_input(
				BenchmarkId::new("polkavm-compiler", n),
				&polkavm_blob,
				|b, blob| {
					b.iter(|| {
						let out = runner.run(black_box(blob), &[]).expect("polkavm primes");
						black_box(out);
					});
				},
			);
		}
	}

	group.finish();
}

criterion_group!(benches, bench_primes);
criterion_main!(benches);
