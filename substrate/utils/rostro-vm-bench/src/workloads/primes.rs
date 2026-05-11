// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Trial-division prime counting workload.
//!
//! Counts primes in `[2, N]` by naive trial division: for each candidate
//! `i`, test divisors `j` from `2` to `i-1`. Total work is roughly
//! `O(N²)` — produces a parabolic wall-clock curve when sweeping `N`,
//! the "inverted dyno" characterization shape.
//!
//! Currently polkavm-flavor only. javm-flavor (via `grey_transpiler`
//! Assembler) is deferred — grey-transpiler's Assembler does not expose
//! typed helpers for `mul_64` / `rem_64` / register-register branches,
//! so a javm-flavor primes blob would require either hand-byte-encoding
//! (via the `emit_raw` escape hatch, ~30 instructions of fragile
//! offset tracking) or a build-script that compiles a Rust source to
//! RISC-V → RVM (matches the path grey-bench uses for `sieve`/`ed25519`/
//! `blake2b` blobs). Pick one when the comparison becomes urgent.
//!
//! Until then: polkavm-side runs in benches, javm-side is left as TODO.

/// Build the trial-division primes workload as a polkavm-native blob.
///
/// Counts primes in `[2, n]` and returns the count in `A0`. Halts via
/// `ret` → `VM_ADDR_RETURN_TO_HOST`.
///
/// Implementation note: modulo is computed by repeated subtraction
/// rather than the assembler's `%u` operator (which targets an ISA
/// extension absent from JamV1). Trades 1 instruction for an inner
/// loop, makes the workload compatible with the same ISA javm uses.
pub fn polkavm_blob(n: u64) -> Vec<u8> {
	// Register usage (PVM has only ra/sp/t0/t1/t2/s0/s1/a0..a5):
	//   s1 — N (limit)         a0 — count (output)
	//   t0 — i (outer counter) t1 — j (inner counter)
	//   a1 — is_prime flag     s0 — rem (mod accumulator)
	let source = format!(
		"\
%isa = jam_v1

pub @main:
\ts1 = {n}
\ta0 = 0
\tt0 = 2
\tjump @outer

@outer:
\tjump @halt if t0 >=u s1
\ta1 = 1
\tt1 = 2
\tjump @inner

@inner:
\tjump @check if t1 >=u t0
\ts0 = t0
\tjump @mod_loop

@mod_loop:
\tjump @mod_done if s0 <u t1
\ts0 = s0 - t1
\tjump @mod_loop

@mod_done:
\tjump @composite if s0 == 0
\tt1 = t1 + 1
\tjump @inner

@composite:
\ta1 = 0
\tjump @check

@check:
\tjump @next if a1 == 0
\ta0 = a0 + 1

@next:
\tt0 = t0 + 1
\tjump @outer

@halt:
\tret
"
	);
	polkavm::program::assemble(None, &source).expect("assemble primes polkavm blob")
}

/// Native-Rust reference: count primes in `[2, n]` by the same naive
/// trial-division algorithm. Use to assert correctness against the
/// VM-produced A0.
pub fn expected_result(n: u64) -> u64 {
	let mut count: u64 = 0;
	for i in 2..n {
		let mut is_prime = true;
		let mut j = 2u64;
		while j < i {
			if i % j == 0 {
				is_prime = false;
				break;
			}
			j += 1;
		}
		if is_prime {
			count += 1;
		}
	}
	count
}
