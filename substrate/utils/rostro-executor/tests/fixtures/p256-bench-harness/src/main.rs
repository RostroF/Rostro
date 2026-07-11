// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! p256-in-RVM benchmark harness. See the fixture crate docs for what
//! each guest export measures. VM configuration mirrors
//! `RostroCodeExecutor` exactly: interpreter backend, experimental
//! allowed, default `ModuleConfig` (no VM-level gas metering), host fns
//! registered through `register_substrate_host_functions`, input written
//! at `heap_base` after `reset_memory` + `sbrk`, status read from `A0`.

use std::time::{Duration, Instant};

use p256::ecdsa::{
	signature::{hazmat::PrehashVerifier, Signer, Verifier},
	Signature, SigningKey, VerifyingKey,
};
use polkavm::{BackendKind, Config, Engine, Module, ModuleConfig, Reg};
use rostro_executor::register_substrate_host_functions;
use sha2::{Digest, Sha256};

/// Host-fn surface wide enough for the fixture: allocator (alloc guest),
/// hashing (`sha2_256` for the hostsha variant), plus the small set the
/// executor's own tests wire.
type HostFns = (
	sp_io::storage::HostFunctions,
	sp_io::hashing::HostFunctions,
	sp_io::crypto::HostFunctions,
	sp_io::misc::HostFunctions,
	sp_io::allocator::HostFunctions,
);

/// Message size for the "full verify" variants — roughly a signed
/// extrinsic's signing payload (call + 11-tuple extension implicit data).
const MSG_LEN: usize = 200;

fn mean(total: Duration, iters: u32) -> Duration {
	total / iters.max(1)
}

fn fmt(d: Duration) -> String {
	if d >= Duration::from_millis(1) {
		format!("{:8.3} ms", d.as_secs_f64() * 1e3)
	} else {
		format!("{:8.2} µs", d.as_secs_f64() * 1e6)
	}
}

/// Time `f` adaptively: warm up, then run until ~2s elapsed or `max`
/// iterations, whichever first. Returns (mean, iters).
fn time_it(mut f: impl FnMut(), max: u32) -> (Duration, u32) {
	for _ in 0..3 {
		f();
	}
	let budget = Duration::from_secs(2);
	let start = Instant::now();
	let mut iters = 0u32;
	while iters < max && start.elapsed() < budget {
		f();
		iters += 1;
	}
	(mean(start.elapsed(), iters), iters)
}

fn main() {
	// ── Vectors: fixed key, deterministic RFC 6979 signature ──────────
	let sk = SigningKey::from_slice(&[0x42u8; 32]).expect("valid P-256 scalar");
	let vk = VerifyingKey::from(&sk);
	let pubkey = vk.to_encoded_point(true);
	let pubkey = pubkey.as_bytes();
	assert_eq!(pubkey.len(), 33, "compressed SEC1 point");

	let msg = vec![0xA5u8; MSG_LEN];
	let sig: Signature = sk.sign(&msg);
	let sig_raw = sig.to_bytes();
	assert_eq!(sig_raw.len(), 64, "raw r||s");
	let digest: [u8; 32] = Sha256::digest(&msg).into();

	// Native sanity: the exact vectors the guest will see must verify.
	vk.verify(msg.as_slice(), &sig).expect("native full verify");
	vk.verify_prehash(&digest, &sig).expect("native prehash verify");

	let mut in_prehash = Vec::with_capacity(33 + 64 + 32);
	in_prehash.extend_from_slice(pubkey);
	in_prehash.extend_from_slice(&sig_raw);
	in_prehash.extend_from_slice(&digest);

	let mut in_full = Vec::with_capacity(33 + 64 + MSG_LEN);
	in_full.extend_from_slice(pubkey);
	in_full.extend_from_slice(&sig_raw);
	in_full.extend_from_slice(&msg);

	// ── Native baselines ───────────────────────────────────────────────
	println!("== native (host CPU, {} byte msg) ==", MSG_LEN);
	let (t, n) = time_it(
		|| {
			vk.verify_prehash(std::hint::black_box(&digest), std::hint::black_box(&sig))
				.expect("verify");
		},
		20_000,
	);
	let native_prehash = t;
	println!("native verify_prehash   {}  ({n} iters)", fmt(t));
	let (t, n) = time_it(
		|| {
			vk.verify(std::hint::black_box(msg.as_slice()), std::hint::black_box(&sig))
				.expect("verify");
		},
		20_000,
	);
	println!("native verify (full)    {}  ({n} iters)", fmt(t));

	// ── RVM interpreter, executor-mirrored config ──────────────────────
	let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
	config.set_allow_experimental(true);
	config.set_backend(Some(BackendKind::Interpreter));
	let engine = Engine::new(&config).expect("engine");

	let blob = rostro_executor_fixture_p256_bench::binary_unwrap();
	let module =
		Module::new(&engine, &ModuleConfig::new(), blob.to_vec().into()).expect("module compile");

	let mut linker = polkavm::Linker::<(), String>::new();
	register_substrate_host_functions::<(), HostFns>(&mut linker).expect("register host fns");
	// The P-256 intrinsic import (ecalli 112) is intercepted inline by the
	// interpreter's FAST_OP_ECALLI arm and never reaches host dispatch; the
	// stub only satisfies instantiation's import resolution, keeping the
	// missing-host-function check strict for everything else.
	linker
		.define_untyped(
			"rostro_p256_verify_prehash",
			|_caller: polkavm::Caller<()>| -> Result<(), String> {
				Err("unreachable: ecalli 112 is dispatched inline by the interpreter".into())
			},
		)
		.expect("define intrinsic stub");
	let instance_pre = linker.instantiate_pre(&module).expect("instantiate_pre");
	let mut instance = instance_pre.instantiate().expect("instantiate");

	let heap_base = module.memory_map().heap_base();
	let mut ext = sp_state_machine::BasicExternalities::default();

	let find_pc = |name: &str| {
		module
			.exports()
			.find(|e| e.symbol().as_bytes() == name.as_bytes())
			.unwrap_or_else(|| panic!("export not found: {name}"))
			.program_counter()
	};

	println!("\n== RVM interpreter (executor config) ==");
	let benches: &[(&str, &[u8], Option<u64>)] = &[
		("bench_noop", &[], Some(0)),
		("bench_sha256_soft", &in_full, None),
		("bench_verify_prehash", &in_prehash, Some(0)),
		("bench_verify_prehash_intrinsic", &in_prehash, Some(0)),
		("bench_verify_full_hostsha", &in_full, Some(0)),
		("bench_verify_full_soft", &in_full, Some(0)),
	];

	let mut results: Vec<(&str, Duration)> = Vec::new();
	for (name, input, expect) in benches {
		let pc = find_pc(name);
		let len: u32 = input.len().try_into().expect("input fits u32");
		let mut run = || {
			instance.reset_memory().expect("reset_memory");
			instance.sbrk(len).expect("sbrk");
			if len > 0 {
				instance.write_memory(heap_base, input).expect("write input");
			}
			sp_externalities::set_and_run_with_externalities(&mut ext, || {
				instance
					.call_typed::<(u32, u32)>(&mut (), pc, (heap_base, len))
					.unwrap_or_else(|e| panic!("guest call {name}: {e:?}"));
			});
			let a0 = instance.reg(Reg::A0);
			if let Some(want) = expect {
				assert_eq!(a0, *want, "{name} returned {a0}");
			} else {
				assert_ne!(a0, 0, "{name} must do real work");
			}
		};
		let (t, n) = time_it(&mut run, 2_000);
		println!("{name:26} {}  ({n} iters)", fmt(t));
		results.push((name, t));
	}

	// ── Decision summary ───────────────────────────────────────────────
	let get = |name: &str| results.iter().find(|(n, _)| *n == name).expect("bench ran").1;
	let noop = get("bench_noop");
	let prehash = get("bench_verify_prehash").saturating_sub(noop);
	let intrinsic = get("bench_verify_prehash_intrinsic").saturating_sub(noop);
	let hostsha = get("bench_verify_full_hostsha").saturating_sub(noop);
	let fullsoft = get("bench_verify_full_soft").saturating_sub(noop);

	println!("\n== summary (call overhead subtracted) ==");
	println!("EC verify floor (prehash supplied)   {}", fmt(prehash));
	println!("EC verify via ecalli intrinsic       {}", fmt(intrinsic));
	println!("EC verify + sp_io sha2_256 (hostsha) {}", fmt(hostsha));
	println!("EC verify + in-guest soft sha256     {}", fmt(fullsoft));
	println!(
		"interpreted/native ratio (prehash)   {:.0}x",
		prehash.as_secs_f64() / native_prehash.as_secs_f64()
	);
	println!(
		"intrinsic/native ratio (prehash)     {:.2}x",
		intrinsic.as_secs_f64() / native_prehash.as_secs_f64()
	);
	println!(
		"implied single-thread validate ceiling: {:.0} verifies/s (hostsha variant)",
		1.0 / hostsha.as_secs_f64()
	);
	println!(
		"implied single-thread validate ceiling: {:.0} verifies/s (intrinsic variant)",
		1.0 / (intrinsic + noop).as_secs_f64()
	);
}
