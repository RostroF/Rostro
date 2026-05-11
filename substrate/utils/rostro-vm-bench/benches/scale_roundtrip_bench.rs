// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Criterion bench for the SCALE-shape roundtrip workload — four-way
//! characterization (javm interp/recomp + polkavm interp/comp).
//!
//! Sweeps `N ∈ {1_024, 4_096, 16_384}`. Each blob runs three sequential
//! loops over a `2*N*4`-byte stack region (init, XOR-transform-and-copy,
//! checksum). Linear in N — surfaces the memory-traffic cost of each
//! VM (load/store + ALU) rather than pure ALU loops like fib/primes.
//!
//! Run with:
//!     cargo bench -p rostro-vm-bench --bench scale_roundtrip_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rostro_vm_bench::{
	runners::{JavmRunner, PolkaVmRunner},
	workloads::scale_roundtrip,
	RvmRunner,
};

const N_VALUES: &[u64] = &[1_024, 4_096, 16_384];

fn bench_scale_roundtrip(c: &mut Criterion) {
	let mut group = c.benchmark_group("scale_roundtrip");

	for &n in N_VALUES {
		let javm_blob = scale_roundtrip::javm_blob(n);
		let polkavm_blob = scale_roundtrip::polkavm_blob(n);

		let expected = scale_roundtrip::expected_result(n);
		assert_eq!(
			JavmRunner::interpreter()
				.run(&javm_blob, &[])
				.expect("warmup javm")
				.result_a0,
			expected,
			"javm scale_roundtrip({n}) mismatch in bench setup"
		);
		assert_eq!(
			PolkaVmRunner::interpreter()
				.expect("polkavm-interpreter")
				.run(&polkavm_blob, &[])
				.expect("warmup polkavm")
				.result_a0,
			expected,
			"polkavm scale_roundtrip({n}) mismatch in bench setup"
		);

		group.bench_with_input(
			BenchmarkId::new("javm-interpreter", n),
			&javm_blob,
			|b, blob| {
				let mut runner = JavmRunner::interpreter();
				b.iter(|| {
					let out = runner.run(black_box(blob), &[]).expect("javm");
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
					let out = runner.run(black_box(blob), &[]).expect("javm");
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
					let out = runner.run(black_box(blob), &[]).expect("polkavm");
					black_box(out);
				});
			},
		);

		if let Ok(mut runner) = PolkaVmRunner::compiler() {
			assert_eq!(
				runner.run(&polkavm_blob, &[]).expect("warmup compiler").result_a0,
				expected,
			);
			group.bench_with_input(
				BenchmarkId::new("polkavm-compiler", n),
				&polkavm_blob,
				|b, blob| {
					b.iter(|| {
						let out = runner.run(black_box(blob), &[]).expect("polkavm");
						black_box(out);
					});
				},
			);
		}
	}

	group.finish();
}

criterion_group!(benches, bench_scale_roundtrip);
criterion_main!(benches);
