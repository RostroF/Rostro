// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Criterion bench for the trial-division primes workload on polkavm.
//!
//! Sweeps `count_primes_up_to(N)` for N ∈ {100, 500, 1_000}. The naive
//! algorithm is roughly `O(N²)` (modulo-via-subtraction inflates the
//! constant further) — sweeping N produces the "inverted dyno" curve
//! the bench was designed to surface.
//!
//! Currently polkavm-only; javm-flavor is deferred (see
//! `workloads::primes` module docs for the rationale).
//!
//! Run with:
//!     cargo bench -p rostro-vm-bench --bench primes_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rostro_vm_bench::{runners::PolkaVmRunner, workloads::primes, RvmRunner};

/// N values to sweep. Smaller than the fib sweep because the inner
/// loop is much more expensive — `O(N²)` with a multiplicative mod
/// constant, vs `fib`'s `O(N)`.
const PRIMES_N_VALUES: &[u64] = &[100, 500, 1_000];

fn bench_primes(c: &mut Criterion) {
	let mut group = c.benchmark_group("primes");

	for &n in PRIMES_N_VALUES {
		let blob = primes::polkavm_blob(n);

		// Correctness check at bench-startup — a broken blob builder
		// gets caught before any timing samples are taken.
		let expected = primes::expected_result(n);
		let mut warm = PolkaVmRunner::new().expect("PolkaVmRunner::new");
		assert_eq!(
			warm.run(&blob, &[]).expect("warmup polkavm").result_a0,
			expected,
			"polkavm primes({}) mismatch in bench setup",
			n
		);

		group.bench_with_input(BenchmarkId::new("polkavm", n), &blob, |b, blob| {
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
