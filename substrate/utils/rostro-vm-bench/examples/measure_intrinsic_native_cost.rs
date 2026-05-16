// Calibration measurement for the Tier 2 intrinsic gas audit.
//
// Calls each native body directly (no VM, no dispatch, no memory borrow) and
// reports per-call ns. These numbers anchor the per-intrinsic gas table —
// see docs/SECURITY-AUDIT-TIER2-INTRINSICS.md.

use polkavm::rostro_intrinsics::{
	goldilocks_add_native, goldilocks_inv_native, goldilocks_mul_native, goldilocks_sub_native,
	rostro_blake2b_256, rostro_dilithium_verify, rostro_ed25519_verify, rostro_keccak_256,
	rostro_p521_ecdsa_verify_prehash, rostro_poseidon2_permute, rostro_secp256k1_recover,
};
use std::time::Instant;

fn time_ns<F: FnMut()>(name: &str, iters: u64, mut f: F) {
	for _ in 0..3 {
		f();
	}
	let start = Instant::now();
	for _ in 0..iters {
		f();
	}
	let elapsed = start.elapsed();
	let per_call_ns = elapsed.as_nanos() as f64 / iters as f64;
	println!(
		"{name:>32}: {per_call_ns:>12.2} ns/call  ({iters} iters in {:.2} ms)",
		elapsed.as_secs_f64() * 1000.0,
	);
}

fn main() {
	println!("Native-body cost measurement (no VM, no dispatch).\n");

	let msg_1k = vec![0xAAu8; 1024];
	let msg_64 = vec![0xAAu8; 64];
	let msg_empty: Vec<u8> = Vec::new();
	let msg_4mb = vec![0xAAu8; 4 * 1024 * 1024];

	time_ns("goldilocks_mul", 1_000_000, || {
		let r = goldilocks_mul_native(0x123456789ABCDEFu64, 0xFEDCBA987654321u64);
		std::hint::black_box(r);
	});
	time_ns("goldilocks_add", 1_000_000, || {
		let r = goldilocks_add_native(0x123456789ABCDEFu64, 0xFEDCBA987654321u64);
		std::hint::black_box(r);
	});
	time_ns("goldilocks_sub", 1_000_000, || {
		let r = goldilocks_sub_native(0x123456789ABCDEFu64, 0xFEDCBA987654321u64);
		std::hint::black_box(r);
	});
	time_ns("goldilocks_inv", 200_000, || {
		let r = goldilocks_inv_native(0x123456789ABCDEFu64);
		std::hint::black_box(r);
	});

	time_ns("poseidon2_permute", 100_000, || {
		let mut s = [0xDEADBEEF_00000000u64; 8];
		rostro_poseidon2_permute(&mut s);
		std::hint::black_box(s);
	});

	time_ns("blake2b_256 (empty)", 50_000, || {
		let h = rostro_blake2b_256(&msg_empty);
		std::hint::black_box(h);
	});
	time_ns("blake2b_256 (64B)", 50_000, || {
		let h = rostro_blake2b_256(&msg_64);
		std::hint::black_box(h);
	});
	time_ns("blake2b_256 (1KB)", 10_000, || {
		let h = rostro_blake2b_256(&msg_1k);
		std::hint::black_box(h);
	});
	time_ns("blake2b_256 (4MB)", 50, || {
		let h = rostro_blake2b_256(&msg_4mb);
		std::hint::black_box(h);
	});

	time_ns("keccak_256 (empty)", 50_000, || {
		let h = rostro_keccak_256(&msg_empty);
		std::hint::black_box(h);
	});
	time_ns("keccak_256 (64B)", 50_000, || {
		let h = rostro_keccak_256(&msg_64);
		std::hint::black_box(h);
	});
	time_ns("keccak_256 (1KB)", 10_000, || {
		let h = rostro_keccak_256(&msg_1k);
		std::hint::black_box(h);
	});
	time_ns("keccak_256 (4MB)", 50, || {
		let h = rostro_keccak_256(&msg_4mb);
		std::hint::black_box(h);
	});

	let ed_pk = [
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
		0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
		0x51, 0x1a,
	];
	let ed_sig = [
		0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
		0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
		0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
		0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
		0x8e, 0x7a, 0x10, 0x0b,
	];
	let ed_msg: Vec<u8> = Vec::new();
	time_ns("ed25519_verify (empty msg)", 5_000, || {
		let r = rostro_ed25519_verify(&ed_pk, &ed_sig, &ed_msg);
		std::hint::black_box(r);
	});

	let mut zero_msg = [0u8; 32];
	let mut out_pk = [0u8; 64];
	let test_hash = [
		0x88, 0xcf, 0x3d, 0xb1, 0xc2, 0x69, 0xe2, 0xd2, 0x35, 0x4c, 0xa9, 0x4f, 0xe5, 0x21, 0xb1,
		0xf2, 0x46, 0xf2, 0xf0, 0x67, 0xb0, 0xb2, 0xa0, 0x90, 0xc2, 0x9b, 0xdd, 0xe6, 0x70, 0xb4,
		0xb6, 0x65,
	];
	let test_sig65 = [
		0x80, 0xa6, 0x71, 0xc1, 0x52, 0x14, 0x32, 0xc4, 0x2c, 0x52, 0x71, 0x5d, 0xf0, 0x6c, 0x9c,
		0xe5, 0x3f, 0x32, 0x88, 0xa6, 0xc4, 0x16, 0x52, 0x71, 0xf2, 0x8d, 0x86, 0x46, 0xab, 0x77,
		0xab, 0xea, 0x14, 0x66, 0x35, 0xc3, 0xff, 0xc1, 0x83, 0xd1, 0xe1, 0x4a, 0xeb, 0xe2, 0xa2,
		0x6f, 0xff, 0xab, 0xfe, 0x84, 0x83, 0xc3, 0x42, 0x18, 0x1c, 0x9a, 0xd5, 0x29, 0xe3, 0x4d,
		0x4e, 0x53, 0xa4, 0xc2, 0x00,
	];
	let _ = &mut zero_msg;
	let _ = &mut out_pk;
	let _ = test_hash;
	let _ = test_sig65;

	time_ns("secp256k1_recover", 5_000, || {
		let _ = rostro_secp256k1_recover(&test_hash, &test_sig65, &mut out_pk);
	});

	// Dilithium (ML-DSA-65) verify — need real key/sig material. Use the
	// bench's existing fixture if available, else skip.
	use rostro_vm_bench::service_blobs::DILITHIUM_VERIFY_ONLY_POLKAVM_BLOB;
	let _ = DILITHIUM_VERIFY_ONLY_POLKAVM_BLOB;
	// dilithium and p521 use embedded fixtures inside their service crates;
	// for direct measurement we'd need to extract them. Use the workload-level
	// numbers from the bench instead (one verify per workload call).
	let _ = rostro_dilithium_verify;
	let _ = rostro_p521_ecdsa_verify_prehash;
	println!();
	println!("dilithium_verify / p521_ecdsa_verify: see workload-level numbers");
	println!("    (each workload runs exactly one verify; direct-measure would");
	println!("    require extracting the fixture key/sig into this example).");
}
