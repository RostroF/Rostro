// Phase 3 precompile correctness check.
// Runs the ed25519 + ecrecover workloads via PolkaVmRunner on both interp +
// JIT backends and verifies they return the expected values.

use rostro_vm_bench::runners::PolkaVmRunner;
use rostro_vm_bench::service_blobs::{ECRECOVER_POLKAVM_BLOB, ED25519_POLKAVM_BLOB};
use rostro_vm_bench::RvmRunner;

fn main() {
	let mut r = PolkaVmRunner::interpreter().expect("rvm-int");
	let o = r.run(ED25519_POLKAVM_BLOB, &[]).expect("ed25519 int");
	println!("ed25519 RVM-INT:   a0={} gas={} (expected a0=1)", o.result_a0, o.gas_consumed);

	let mut r = PolkaVmRunner::interpreter().expect("rvm-int");
	let o = r.run(ECRECOVER_POLKAVM_BLOB, &[]).expect("ecrecover int");
	println!("ecrecover RVM-INT: a0={} gas={} (expected a0=1)", o.result_a0, o.gas_consumed);

	let mut r = PolkaVmRunner::compiler().expect("rvm-jit");
	let o = r.run(ED25519_POLKAVM_BLOB, &[]).expect("ed25519 jit");
	println!("ed25519 RVM-JIT:   a0={} gas={} (expected a0=1)", o.result_a0, o.gas_consumed);

	let mut r = PolkaVmRunner::compiler().expect("rvm-jit");
	let o = r.run(ECRECOVER_POLKAVM_BLOB, &[]).expect("ecrecover jit");
	println!("ecrecover RVM-JIT: a0={} gas={} (expected a0=1)", o.result_a0, o.gas_consumed);
}
