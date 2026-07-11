// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Facade correctness harness: for every rostro-guest-crypto entry, compute
//! the expected result through the facade's NATIVE backend, then run the
//! matching fixture export in the RVM interpreter (executor-mirrored
//! configuration) and assert the guest's ecalli backend reproduced it
//! byte-for-byte (A0 = 0).

use rostro_facade_rvm_test::{build_cases, run_case, setup_vm};

fn main() {
	let cases = build_cases();
	let mut vm = setup_vm();
	let mut ext = sp_state_machine::BasicExternalities::default();

	let mut failures = 0u32;
	for case in &cases {
		let status = run_case(&mut vm, &mut ext, case);
		if status == 0 {
			println!("PASS  {}", case.name);
		} else {
			println!("FAIL  {} (status {status})", case.name);
			failures += 1;
		}
	}

	if failures > 0 {
		eprintln!("\n{failures} facade guest case(s) FAILED");
		std::process::exit(1);
	}
	println!("\nall {} facade guest cases passed — ecalli backend == native backend", cases.len());
}
