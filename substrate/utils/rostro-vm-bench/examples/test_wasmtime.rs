use rostro_vm_bench::{
	runners::WasmtimeRunner,
	workloads::{fib, primes, scale_roundtrip},
	RvmRunner,
};

fn check<F: Fn(u64) -> Vec<u8>, G: Fn(u64) -> u64>(
	label: &str,
	ns: &[u64],
	build_blob: F,
	expected: G,
) {
	for &n in ns {
		let blob = build_blob(n);
		let want = expected(n);
		for (backend, runner_res) in [
			("cranelift", WasmtimeRunner::cranelift()),
			("winch", WasmtimeRunner::winch()),
		] {
			match runner_res {
				Ok(mut runner) => match runner.run(&blob, &[]) {
					Ok(out) => {
						let ok = out.result_a0 == want;
						println!(
							"wasmtime-{backend} {label}({n}) = {} (want {want}) {} fuel={}",
							out.result_a0,
							if ok { "OK" } else { "MISMATCH" },
							out.gas_consumed,
						);
					},
					Err(e) => println!("wasmtime-{backend} {label}({n}) RUN ERR: {e}"),
				},
				Err(e) => println!("wasmtime-{backend} unavailable: {e}"),
			}
		}
	}
}

fn main() {
	check("fib", &[10, 100, 1000], fib::wat_blob, fib::expected_result);
	check("primes", &[10, 50, 200], primes::wat_blob, primes::expected_result);
	check(
		"scale",
		&[16, 256, 4096],
		scale_roundtrip::wat_blob,
		scale_roundtrip::expected_result,
	);
}
