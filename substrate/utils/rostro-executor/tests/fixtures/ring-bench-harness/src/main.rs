// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Ring verifier-key harness: the era-boundary proof.
//!
//! Builds `RingProofParams` + authority keys natively (vendored hooked
//! stack — natively identical to plain arkworks, byte-equality proven in
//! `rostro-guest-crypto/tests/ring_equality.rs`), then times
//! `verifier_key(&pks)` three ways: native, in-guest hooked (ecalli
//! intrinsics), in-guest plain (interpreted arkworks). Deserialization
//! cost is measured separately per stack and subtracted. Every leg is
//! equality-checked against the same expected bytes.

use std::time::{Duration, Instant};

use ark_serialize::CanonicalSerialize;
use ark_vrf::suites::bandersnatch as suite;
use polkavm::{BackendKind, Config, Engine, Module, ModuleConfig, Reg};
use rostro_executor::register_substrate_host_functions;

type HostFns = (
	sp_io::storage::HostFunctions,
	sp_io::hashing::HostFunctions,
	sp_io::crypto::HostFunctions,
	sp_io::misc::HostFunctions,
	sp_io::allocator::HostFunctions,
);

/// Default ring size for the proof; override with RING_SIZE=n. The NPoS
/// PoC livelock fired on the session-boundary rebuild; testnet plans cap
/// the active set well below 255. The interpreted residue's domain-bound
/// part steps at powers of two (N + ~257 rounded up), so 255 (domain 512)
/// and 500 (domain 1024) bracket the interesting scale points.
const DEFAULT_RING_SIZE: usize = 255;
const SRS_SEED: [u8; 32] = [11u8; 32];

fn ser<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
	let mut buf = Vec::new();
	t.serialize_uncompressed(&mut buf).expect("serialize");
	buf
}

fn fmt(d: Duration) -> String {
	if d >= Duration::from_secs(1) {
		format!("{:8.2} s ", d.as_secs_f64())
	} else {
		format!("{:8.2} ms", d.as_secs_f64() * 1e3)
	}
}

fn main() {
	let ring_size: usize = std::env::var("RING_SIZE")
		.ok()
		.map(|v| v.parse().expect("RING_SIZE must be a number"))
		.unwrap_or(DEFAULT_RING_SIZE);
	// ── Inputs + native leg ─────────────────────────────────────────────
	println!("building ring params (ring_size = {ring_size})...");
	let params = suite::RingProofParams::from_seed(ring_size, SRS_SEED);
	let pks: Vec<_> = (0..ring_size as u64)
		.map(|i| suite::Secret::from_seed(&i.to_le_bytes()).public().0)
		.collect();

	let t0 = Instant::now();
	let vk = params.verifier_key(&pks);
	let mut native = t0.elapsed();
	// Best-of-3 to shed cold-cache noise.
	for _ in 0..2 {
		let t = Instant::now();
		let vk2 = params.verifier_key(&pks);
		native = native.min(t.elapsed());
		assert_eq!(ser(&vk2), ser(&vk));
	}
	let expected_vk = ser(&vk);

	let mut input = (ser(&params).len() as u32).to_le_bytes().to_vec();
	input.extend_from_slice(&ser(&params));
	input.extend_from_slice(&(pks.len() as u32).to_le_bytes());
	for pk in &pks {
		input.extend_from_slice(&ser(pk));
	}
	input.extend_from_slice(&(expected_vk.len() as u32).to_le_bytes());
	input.extend_from_slice(&expected_vk);
	println!("input: {} KiB (params + {} pks + expected vk)", input.len() / 1024, pks.len());

	// ── RVM interpreter, executor-mirrored config ───────────────────────
	let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
	config.set_allow_experimental(true);
	config.set_backend(Some(BackendKind::Interpreter));
	let engine = Engine::new(&config).expect("engine");
	let blob = rostro_executor_fixture_ring_bench::binary_unwrap();
	let module =
		Module::new(&engine, &ModuleConfig::new(), blob.to_vec().into()).expect("module compile");
	let mut linker = polkavm::Linker::<(), String>::new();
	register_substrate_host_functions::<(), HostFns>(&mut linker).expect("register host fns");
	rostro_executor::register_rostro_intrinsic_stubs::<()>(&mut linker).expect("register stubs");
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

	let mut run = |name: &str, iters: u32| -> Duration {
		let pc = find_pc(name);
		let mut best = Duration::MAX;
		for _ in 0..iters {
			instance.reset_memory().expect("reset_memory");
			instance.set_gas(i64::MAX / 2);
			instance.sbrk(input.len() as u32).expect("sbrk");
			instance.write_memory(heap_base, &input).expect("write input");
			let t = Instant::now();
			sp_externalities::set_and_run_with_externalities(&mut ext, || {
				instance
					.call_typed::<(u32, u32)>(&mut (), pc, (heap_base, input.len() as u32))
					.unwrap_or_else(|e| panic!("{name}: trap: {e:?}"));
			});
			best = best.min(t.elapsed());
			let status = instance.reg(Reg::A0);
			assert_eq!(status, 0, "{name}: status {status}");
		}
		best
	};

	println!("running guest legs...");
	let deser_hooked = run("rb_deser_hooked", 3);
	let vk_hooked = run("rb_vk_hooked", 3);
	let deser_plain = run("rb_deser_plain", 1);
	let vk_plain = run("rb_vk_plain", 1);

	let hooked = vk_hooked.saturating_sub(deser_hooked);
	let plain = vk_plain.saturating_sub(deser_plain);

	println!("\n== ring verifier_key({} pks), byte-equal across all legs ==", pks.len());
	println!("native (plain arkworks)     {}", fmt(native));
	println!(
		"in-guest HOOKED (intrinsics){}  ({:.2}x native)   [raw {} incl. {} deser]",
		fmt(hooked),
		hooked.as_secs_f64() / native.as_secs_f64(),
		fmt(vk_hooked),
		fmt(deser_hooked),
	);
	println!(
		"in-guest PLAIN (interpreted){}  ({:.0}x native)   [raw {} incl. {} deser]",
		fmt(plain),
		plain.as_secs_f64() / native.as_secs_f64(),
		fmt(vk_plain),
		fmt(deser_plain),
	);
	println!(
		"\nera-boundary verdict: hooked/plain speedup = {:.0}x",
		plain.as_secs_f64() / hooked.as_secs_f64()
	);
}
