// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Parameter-set benchmark for the finality-vote scheme decision at
//! mainnet validator scale. Not a correctness test — run explicitly:
//!
//!   cargo test --release -p rostro-hybrid-sig --test param_bench -- --ignored --nocapture
//!
//! Measures sign + verify latency and signature size for the SLH-DSA
//! parameter sets under consideration, and extrapolates justification
//! size / per-node verify cost to N validators. Signing happens once per
//! validator per round; verification happens for ALL N signatures in
//! every justification on every node, so verify cost and size are the
//! bottlenecks, signing latency is the slack.

#![allow(non_snake_case)]

use std::time::Instant;

use slh_dsa::signature::Keypair as _;
use slh_dsa::{Sha2_128f, Sha2_128s, Sha2_192s, SigningKey};

const DOMAIN: &[u8] = b"rostro/finality-vote/hybrid/v1";
const SIGN_ITERS: u32 = 20;
const VERIFY_ITERS: u32 = 50;

fn bench<P>(name: &str, sig_len: usize)
where
	P: slh_dsa::ParameterSet + slh_dsa::VerifyingKeyLen,
{
	let mut rng = rand::rngs::OsRng;
	let sk = SigningKey::<P>::new(&mut rng);
	let vk = sk.verifying_key();
	let msg = b"finality vote: precommit target #123456";

	// Warm one to build the FORS/hypertree caches, then time.
	let sig0 = sk.try_sign_with_context(msg, DOMAIN, None).unwrap();

	let t = Instant::now();
	for _ in 0..SIGN_ITERS {
		let _ = sk.try_sign_with_context(msg, DOMAIN, None).unwrap();
	}
	let sign_ms = t.elapsed().as_secs_f64() * 1000.0 / SIGN_ITERS as f64;

	let t = Instant::now();
	for _ in 0..VERIFY_ITERS {
		vk.try_verify_with_context(msg, DOMAIN, &sig0).unwrap();
	}
	let verify_ms = t.elapsed().as_secs_f64() * 1000.0 / VERIFY_ITERS as f64;

	let hybrid_sig = sig_len + 64; // + ed25519 half + id overhead (approx per-sig 17252 for 128f)
	let per_sig_just = sig_len + 64 + 36 + 64; // slh + id(64) + precommit(36) + ed25519(64)

	println!(
		"{:<14} sig={:>6} B  sign={:>8.2} ms  verify={:>6.2} ms  | per-vote-in-justification={:>6} B",
		name, sig_len, sign_ms, verify_ms, per_sig_just
	);
	// Extrapolations at N validators (full-set commit).
	for n in [100usize, 500, 1000] {
		let just_mb = (46 + n * per_sig_just) as f64 / 1_048_576.0;
		let verify_total_ms = verify_ms * n as f64;
		println!(
			"    N={:<5} justification={:>7.2} MiB   per-node verify-all={:>8.1} ms",
			n, just_mb, verify_total_ms
		);
	}
	let _ = hybrid_sig;
}

#[test]
#[ignore = "benchmark; run with --release --ignored --nocapture"]
fn slh_param_set_bench() {
	println!("\n=== SLH-DSA parameter-set bench (finality-vote decision) ===");
	println!("(signing = once per validator per round; verify = N sigs per justification, every node)\n");
	bench::<Sha2_128f>("SHA2-128f", 17088);
	bench::<Sha2_128s>("SHA2-128s", 7856);
	bench::<Sha2_192s>("SHA2-192s", 16224);
	println!();
}
