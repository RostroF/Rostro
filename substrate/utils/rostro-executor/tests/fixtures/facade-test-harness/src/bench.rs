// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Facade bench harness (W4 proof b): every facade entry timed in-guest
//! against its native baseline, so cipher coverage is regression-tested as
//! a set. The regression target is a silently interpreted fallback — an
//! entry that stops reaching its intrinsic lands at 50-450x native, so the
//! ratio guard is deliberately loose (well above marshalling + input-parse
//! overhead, far below any interpreted cipher).
//!
//! Guest times include input parsing / point deserialization in-guest,
//! which dominates the cheap entries; the guard therefore applies only to
//! entries whose native cost is ≥ 100 µs (where crypto dominates and the
//! interpreted fallback signal is unambiguous).

use std::time::{Duration, Instant};

use rostro_facade_rvm_test::{build_cases, run_case, setup_vm};

/// Fail if a guarded entry exceeds this multiple of its native baseline.
const MAX_RATIO: f64 = 15.0;
/// Guard only entries with native cost above this (crypto-dominated).
const GUARD_FLOOR: Duration = Duration::from_micros(100);

fn time_it(mut f: impl FnMut(), budget: Duration, max: u32) -> Duration {
	f(); // warm-up
	let start = Instant::now();
	let mut iters = 0u32;
	while iters < max && start.elapsed() < budget {
		f();
		iters += 1;
	}
	start.elapsed() / iters.max(1)
}

fn fmt(d: Duration) -> String {
	if d >= Duration::from_millis(1) {
		format!("{:9.3} ms", d.as_secs_f64() * 1e3)
	} else {
		format!("{:9.2} µs", d.as_secs_f64() * 1e6)
	}
}

fn main() {
	let mut cases = build_cases();
	let mut vm = setup_vm();
	let mut ext = sp_state_machine::BasicExternalities::default();
	let budget = Duration::from_millis(500);

	println!(
		"== facade entries, in-guest (ecalli) vs native — guard: ratio ≤ {MAX_RATIO}x where native ≥ {} ==",
		fmt(GUARD_FLOOR)
	);
	println!("{:<20} {:>12} {:>12} {:>8}  guard", "entry", "native", "in-guest", "ratio");

	let mut violations = 0u32;
	for case in cases.iter_mut() {
		let native = time_it(&mut case.native, budget, 2000);
		let guest = {
			let vm = &mut vm;
			let ext = &mut ext;
			let case_ref = &*case;
			time_it(
				move || {
					let status = run_case(vm, ext, case_ref);
					assert_eq!(status, 0, "{}: status {status}", case_ref.name);
				},
				budget,
				2000,
			)
		};
		let ratio = guest.as_secs_f64() / native.as_secs_f64();
		let max_ratio = case.guard_max.unwrap_or(MAX_RATIO);
		let guarded = native >= GUARD_FLOOR || case.guard_max.is_some();
		let verdict = if !guarded {
			"-"
		} else if ratio <= max_ratio {
			"ok"
		} else {
			violations += 1;
			"VIOLATION"
		};
		println!("{:<20} {:>12} {:>12} {:>7.2}x  {}", case.name, fmt(native), fmt(guest), ratio, verdict);
	}

	if violations > 0 {
		eprintln!("\n{violations} entr(ies) exceeded the intrinsic-speed guard — interpreted fallback?");
		std::process::exit(1);
	}
	println!("\nall guarded entries within {MAX_RATIO}x native — no interpreted fallbacks");
}
