// Validates the audit mitigations land in actual VM behavior:
//   A1: gas underflow on a heavy intrinsic with a tight budget → trap.
//   A2: the gas charge on a successful intrinsic call matches the table.
//   A11: secp256k1_recover rejects high-s and recovery_id ∈ {2, 3}.
//
// The msg_len cap (A2 part 2) is unit-tested in
// polkavm/src/rostro_intrinsic_gas.rs::tests::msg_len_cap_rejects; this file
// covers the VM-level integration end of the mitigations.

use polkavm::rostro_intrinsics::rostro_secp256k1_recover;
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

	println!("\n=== A11 mitigation: secp256k1_recover input validation ===\n");

	// Build a real valid signature first, then mutate it to test the rejection
	// paths. The known test vector below is the one used by the ecrecover
	// service crate; recovery should succeed with v=0 and low-s.
	let msg_hash = [
		0x88, 0xcf, 0x3d, 0xb1, 0xc2, 0x69, 0xe2, 0xd2, 0x35, 0x4c, 0xa9, 0x4f, 0xe5, 0x21, 0xb1,
		0xf2, 0x46, 0xf2, 0xf0, 0x67, 0xb0, 0xb2, 0xa0, 0x90, 0xc2, 0x9b, 0xdd, 0xe6, 0x70, 0xb4,
		0xb6, 0x65,
	];
	let valid_sig = [
		0x80, 0xa6, 0x71, 0xc1, 0x52, 0x14, 0x32, 0xc4, 0x2c, 0x52, 0x71, 0x5d, 0xf0, 0x6c, 0x9c,
		0xe5, 0x3f, 0x32, 0x88, 0xa6, 0xc4, 0x16, 0x52, 0x71, 0xf2, 0x8d, 0x86, 0x46, 0xab, 0x77,
		0xab, 0xea, 0x14, 0x66, 0x35, 0xc3, 0xff, 0xc1, 0x83, 0xd1, 0xe1, 0x4a, 0xeb, 0xe2, 0xa2,
		0x6f, 0xff, 0xab, 0xfe, 0x84, 0x83, 0xc3, 0x42, 0x18, 0x1c, 0x9a, 0xd5, 0x29, 0xe3, 0x4d,
		0x4e, 0x53, 0xa4, 0xc2, 0x00,
	];
	let mut out_pk = [0u8; 64];

	let ok = rostro_secp256k1_recover(&msg_hash, &valid_sig, &mut out_pk);
	assert!(ok, "baseline valid signature must recover");
	println!("baseline valid sig (v=0, low-s)          : recovered (OK)");

	// Mutate recovery_id to 2 — strict mode must reject.
	let mut sig_v2 = valid_sig;
	sig_v2[64] = 2;
	let ok = rostro_secp256k1_recover(&msg_hash, &sig_v2, &mut out_pk);
	assert!(!ok, "recovery_id=2 must be rejected (Ethereum-compat strict)");
	println!("recovery_id = 2 (x-reduced bit)          : REJECTED — A11 working");

	let mut sig_v3 = valid_sig;
	sig_v3[64] = 3;
	let ok = rostro_secp256k1_recover(&msg_hash, &sig_v3, &mut out_pk);
	assert!(!ok, "recovery_id=3 must be rejected (Ethereum-compat strict)");
	println!("recovery_id = 3                          : REJECTED — A11 working");

	// Build a high-s malleable equivalent: replace s with (n - s) and flip
	// recovery_id. secp256k1's group order n:
	const N: [u8; 32] = [
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
		0x41, 0x41,
	];
	let mut high_s = valid_sig;
	// s_high = n - s_low; subtract bytewise (n is big-endian, s is bytes 32..64).
	let mut borrow: i32 = 0;
	for i in (0..32).rev() {
		let diff = N[i] as i32 - valid_sig[32 + i] as i32 - borrow;
		if diff < 0 {
			high_s[32 + i] = (diff + 256) as u8;
			borrow = 1;
		} else {
			high_s[32 + i] = diff as u8;
			borrow = 0;
		}
	}
	high_s[64] = 1; // flip v
	let ok = rostro_secp256k1_recover(&msg_hash, &high_s, &mut out_pk);
	assert!(!ok, "high-s signature must be rejected (EIP-2)");
	println!("high-s (n - s, malleable equivalent)     : REJECTED — A11 working");

	println!("\nAll audit A1+A2+A11 integration assertions PASS.");
}
