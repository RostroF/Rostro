// Confirmation test for the suspicious wasmtime-cranelift fib(1k) result.
//
// Hypothesis: cranelift's optimizer is doing something to fib's loop —
// either constant-folding it (if N is hardcoded), heavy loop optimization,
// or just very efficient codegen. The way to tell which: run the same
// backend at multiple orders of magnitude of N and compute ns per loop
// iteration. If the loop is real work, ns/iter is stable across N. If the
// loop is being eliminated, total time stays roughly flat as N grows
// (so ns/iter shrinks toward zero).
//
// Compare three JITs (wasmtime-cranelift, polkavm-compiler, javm-recompiler)
// across N ∈ {1k, 10k, 100k, 1M, 10M}. Warm mode (compile once outside
// timed region) so we measure execution only.

use std::time::Instant;

use rostro_vm_bench::{
	runners::{JavmRunner, PolkaVmRunner, WasmtimeRunner},
	workloads::fib,
};

const N_VALUES: &[u64] = &[1_000, 10_000, 100_000, 1_000_000, 10_000_000];
const ITERS_PER_N: u32 = 100;
const GAS_FOR_LARGE_N: u64 = 1_000_000_000;

fn main() {
	println!(
		"{:>16} {:>10} {:>10} {:>14} {:>10}",
		"backend", "N", "total ms", "per-call µs", "ns/iter"
	);
	println!("{}", "-".repeat(70));

	for &n in N_VALUES {
		// wasmtime-cranelift
		match WasmtimeRunner::cranelift() {
			Ok(mut runner) => {
				runner = runner.with_gas_limit(GAS_FOR_LARGE_N);
				let blob = fib::wat_blob(n);
				let compiled = runner.precompile(&blob).expect("wt precompile");
				// Warmup
				let _ = runner.run_compiled(&compiled, &[]);
				let start = Instant::now();
				for _ in 0..ITERS_PER_N {
					let out = runner.run_compiled(&compiled, &[]).expect("wt run");
					std::hint::black_box(out);
				}
				let elapsed = start.elapsed();
				let per_call = elapsed.as_secs_f64() * 1e6 / ITERS_PER_N as f64;
				let ns_per_iter = per_call * 1000.0 / n as f64;
				println!(
					"{:>16} {:>10} {:>10.2} {:>14.3} {:>10.3}",
					"wt-cranelift",
					n,
					elapsed.as_secs_f64() * 1000.0,
					per_call,
					ns_per_iter,
				);
			},
			Err(e) => println!("wt-cranelift unavailable: {e}"),
		}

		// polkavm-compiler
		match PolkaVmRunner::compiler() {
			Ok(mut runner) => {
				runner = runner.with_gas_limit(GAS_FOR_LARGE_N);
				let blob = fib::polkavm_blob(n);
				let compiled = runner.precompile(&blob).expect("pvm precompile");
				let _ = runner.run_compiled(&compiled, &[]);
				let start = Instant::now();
				for _ in 0..ITERS_PER_N {
					let out = runner.run_compiled(&compiled, &[]).expect("pvm run");
					std::hint::black_box(out);
				}
				let elapsed = start.elapsed();
				let per_call = elapsed.as_secs_f64() * 1e6 / ITERS_PER_N as f64;
				let ns_per_iter = per_call * 1000.0 / n as f64;
				println!(
					"{:>16} {:>10} {:>10.2} {:>14.3} {:>10.3}",
					"pvm-compiler",
					n,
					elapsed.as_secs_f64() * 1000.0,
					per_call,
					ns_per_iter,
				);
			},
			Err(e) => println!("pvm-compiler unavailable: {e}"),
		}

		// javm-recompiler (Linux x86-64)
		#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
		{
			let mut runner = JavmRunner::recompiler().with_gas_limit(GAS_FOR_LARGE_N);
			let blob = fib::javm_blob(n);
			let compiled = runner.precompile(&blob).expect("javm precompile");
			let _ = runner.run_compiled(&compiled, &[]);
			let start = Instant::now();
			for _ in 0..ITERS_PER_N {
				let out = runner.run_compiled(&compiled, &[]).expect("javm run");
				std::hint::black_box(out);
			}
			let elapsed = start.elapsed();
			let per_call = elapsed.as_secs_f64() * 1e6 / ITERS_PER_N as f64;
			let ns_per_iter = per_call * 1000.0 / n as f64;
			println!(
				"{:>16} {:>10} {:>10.2} {:>14.3} {:>10.3}",
				"javm-recomp",
				n,
				elapsed.as_secs_f64() * 1000.0,
				per_call,
				ns_per_iter,
			);
		}
		#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
		{
			let _ = JavmRunner::interpreter; // silence unused
		}

		println!();
	}
}
