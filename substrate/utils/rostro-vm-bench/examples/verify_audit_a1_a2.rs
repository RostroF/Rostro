// Validates the audit A1+A2 mitigations land in actual VM behavior:
//   A1: gas underflow on a heavy intrinsic with a tight budget → trap.
//   A2: the gas charge on a successful intrinsic call matches the table.
//
// The msg_len cap (A2 part 2) is unit-tested in
// polkavm/src/rostro_intrinsic_gas.rs::tests::msg_len_cap_rejects; this file
// covers the VM-level integration end of the mitigations.

use rostro_vm_bench::runners::PolkaVmRunner;
use rostro_vm_bench::service_blobs::{
	ECRECOVER_POLKAVM_BLOB, ED25519_POLKAVM_BLOB,
};
use rostro_vm_bench::RvmRunner;

fn main() {
	println!("=== A1 mitigation: gas charge matches table ===\n");

	let mut r = PolkaVmRunner::interpreter().expect("rvm-int");
	let o = r.run(ED25519_POLKAVM_BLOB, &[]).expect("ed25519");
	println!(
		"ed25519 RVM-INT  : gas_consumed = {} (expect ~50,013 = 50_000 flat + dispatch)",
		o.gas_consumed,
	);
	assert!(o.gas_consumed >= 50_000, "ed25519 must charge ≥50_000 gas");
	assert!(o.gas_consumed < 51_000, "ed25519 must charge <51_000 gas (no double-charge)");

	let mut r = PolkaVmRunner::interpreter().expect("rvm-int");
	let o = r.run(ECRECOVER_POLKAVM_BLOB, &[]).expect("ecrecover");
	println!(
		"ecrecover RVM-INT: gas_consumed = {} (expect ~160,039 = 160_000 flat + dispatch)",
		o.gas_consumed,
	);
	assert!(o.gas_consumed >= 160_000, "ecrecover must charge ≥160_000 gas");
	assert!(o.gas_consumed < 161_000, "ecrecover must charge <161_000 gas (no double-charge)");

	let mut r = PolkaVmRunner::compiler().expect("rvm-jit");
	let o = r.run(ED25519_POLKAVM_BLOB, &[]).expect("ed25519 jit");
	println!(
		"ed25519 RVM-JIT  : gas_consumed = {} (expect ~50,013)",
		o.gas_consumed,
	);
	assert!(o.gas_consumed >= 50_000 && o.gas_consumed < 51_000);

	let mut r = PolkaVmRunner::compiler().expect("rvm-jit");
	let o = r.run(ECRECOVER_POLKAVM_BLOB, &[]).expect("ecrecover jit");
	println!(
		"ecrecover RVM-JIT: gas_consumed = {} (expect ~160,039)",
		o.gas_consumed,
	);
	assert!(o.gas_consumed >= 160_000 && o.gas_consumed < 161_000);

	println!("\n=== A1 mitigation: gas underflow traps ===\n");

	// Try ecrecover with a budget below its 160K cost — should NOT complete.
	let mut r = PolkaVmRunner::interpreter().expect("rvm-int").with_gas_limit(50_000);
	let res = r.run(ECRECOVER_POLKAVM_BLOB, &[]);
	match res {
		Err(e) if e.contains("out of gas") => {
			println!("ecrecover RVM-INT @ 50K gas budget: TRAPPED ({e}) — A1 mitigation working");
		},
		Err(e) => panic!("expected out-of-gas trap, got: {e}"),
		Ok(o) => panic!(
			"ecrecover completed at 50K gas budget (consumed {}) — A1 mitigation NOT enforced",
			o.gas_consumed,
		),
	}

	let mut r = PolkaVmRunner::compiler().expect("rvm-jit").with_gas_limit(50_000);
	let res = r.run(ECRECOVER_POLKAVM_BLOB, &[]);
	match res {
		Err(e) if e.contains("out of gas") => {
			println!("ecrecover RVM-JIT @ 50K gas budget: TRAPPED ({e}) — A1 mitigation working");
		},
		Err(e) => panic!("expected out-of-gas trap, got: {e}"),
		Ok(o) => panic!(
			"ecrecover JIT completed at 50K gas budget (consumed {}) — A1 JIT mitigation NOT enforced",
			o.gas_consumed,
		),
	}

	println!("\nAll audit A1+A2 integration assertions PASS.");
}
