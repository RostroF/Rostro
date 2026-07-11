// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Multi-cipher RVM benchmark harness. See the fixture crate docs for
//! what each guest export measures. VM configuration mirrors
//! `RostroCodeExecutor`: interpreter backend, experimental allowed,
//! default `ModuleConfig`, host fns via `register_substrate_host_functions`,
//! input at `heap_base` after `reset_memory` + `sbrk`, status in `A0`.
//! Gas is funded to a huge budget each call because several intrinsic
//! arms charge a surplus even when VM-level metering is off.

use std::time::{Duration, Instant};

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use polkavm::{BackendKind, Config, Engine, Module, ModuleConfig, Reg};
use rostro_executor::register_substrate_host_functions;
use sha2::{Digest, Sha256, Sha512};

type HostFns = (
	sp_io::storage::HostFunctions,
	sp_io::hashing::HostFunctions,
	sp_io::crypto::HostFunctions,
	sp_io::misc::HostFunctions,
	sp_io::allocator::HostFunctions,
);

/// Message size — roughly a signed extrinsic's signing payload.
const MSG_LEN: usize = 200;

fn mean(total: Duration, iters: u32) -> Duration {
	total / iters.max(1)
}

fn fmt(d: Duration) -> String {
	if d >= Duration::from_millis(1) {
		format!("{:9.3} ms", d.as_secs_f64() * 1e3)
	} else {
		format!("{:9.2} µs", d.as_secs_f64() * 1e6)
	}
}

/// Time `f` adaptively: warm up, then run until ~2s elapsed or `max`
/// iterations, whichever first. Returns (mean, iters).
fn time_it(mut f: impl FnMut(), max: u32) -> (Duration, u32) {
	for _ in 0..2 {
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

struct Workload {
	name: &'static str,
	input: Vec<u8>,
	/// Expected A0 (None = "nonzero" check for digest-returning exports).
	expect: Option<u64>,
	/// Native baseline closure result, printed alongside.
	native: Option<Duration>,
}

fn main() {
	let msg = vec![0xA5u8; MSG_LEN];
	let mut workloads: Vec<Workload> = Vec::new();
	let native_of = |label: &str, f: &mut dyn FnMut()| -> Duration {
		let (t, n) = time_it(f, 20_000);
		println!("native {label:28} {}  ({n} iters)", fmt(t));
		t
	};

	println!("== native baselines (host CPU, {} byte msg) ==", MSG_LEN);

	// ── ed25519 (ed25519-zebra, ZIP-215 — matches intrinsic 122) ───────
	let ed_sk = ed25519_zebra::SigningKey::from([0x42u8; 32]);
	let ed_vk = ed25519_zebra::VerificationKey::from(&ed_sk);
	let ed_sig = ed_sk.sign(&msg);
	let ed_pk_bytes: [u8; 32] = ed_vk.into();
	let ed_sig_bytes: [u8; 64] = ed_sig.into();
	let t = native_of("ed25519 verify", &mut || {
		let vk = ed25519_zebra::VerificationKey::try_from(&ed_pk_bytes[..]).expect("vk");
		vk.verify(&ed25519_zebra::Signature::from(ed_sig_bytes), std::hint::black_box(&msg))
			.expect("verify");
	});
	let mut in_ed = Vec::new();
	in_ed.extend_from_slice(&ed_pk_bytes);
	in_ed.extend_from_slice(&ed_sig_bytes);
	in_ed.extend_from_slice(&msg);
	workloads.push(Workload { name: "bench_ed25519_soft", input: in_ed.clone(), expect: Some(0), native: Some(t) });
	workloads.push(Workload { name: "bench_ed25519_intrinsic", input: in_ed, expect: Some(0), native: Some(t) });

	// ── sr25519 (schnorrkel) ───────────────────────────────────────────
	let mini = schnorrkel::MiniSecretKey::from_bytes(&[0x42u8; 32]).expect("mini key");
	let keypair = mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
	let ctx = schnorrkel::signing_context(b"substrate");
	let sr_sig = keypair.sign(ctx.bytes(&msg));
	let sr_pk_bytes = keypair.public.to_bytes();
	let sr_sig_bytes = sr_sig.to_bytes();
	let t = native_of("sr25519 verify_simple", &mut || {
		let vk = schnorrkel::PublicKey::from_bytes(&sr_pk_bytes).expect("pk");
		let sig = schnorrkel::Signature::from_bytes(&sr_sig_bytes).expect("sig");
		vk.verify_simple(b"substrate", std::hint::black_box(&msg), &sig).expect("verify");
	});
	let mut in_sr = Vec::new();
	in_sr.extend_from_slice(&sr_pk_bytes);
	in_sr.extend_from_slice(&sr_sig_bytes);
	in_sr.extend_from_slice(&msg);
	workloads.push(Workload { name: "bench_sr25519_soft", input: in_sr, expect: Some(0), native: Some(t) });

	// ── secp256k1 ecrecover (k256 — matches intrinsic 123) ─────────────
	let k_sk = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).expect("k256 scalar");
	let k_vk = k256::ecdsa::VerifyingKey::from(&k_sk);
	let hash: [u8; 32] = Sha256::digest(&msg).into();
	let (k_sig, recid) = k_sk.sign_prehash_recoverable(&hash).expect("sign");
	let k_sig_bytes = k_sig.to_bytes();
	let expected_pk = k_vk.to_encoded_point(false);
	let expected_pk = &expected_pk.as_bytes()[1..65];
	let t = native_of("secp256k1 recover", &mut || {
		let sig = k256::ecdsa::Signature::from_slice(&k_sig_bytes).expect("sig");
		let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(
			std::hint::black_box(&hash),
			&sig,
			recid,
		)
		.expect("recover");
		assert_eq!(&vk.to_encoded_point(false).as_bytes()[1..65], expected_pk);
	});
	let mut in_ec = Vec::new();
	in_ec.extend_from_slice(&hash);
	in_ec.extend_from_slice(&k_sig_bytes);
	in_ec.push(recid.to_byte());
	in_ec.extend_from_slice(expected_pk);
	workloads.push(Workload { name: "bench_ecrecover_soft", input: in_ec.clone(), expect: Some(0), native: Some(t) });
	workloads.push(Workload { name: "bench_ecrecover_intrinsic", input: in_ec, expect: Some(0), native: Some(t) });

	// ── P-521 (matches intrinsic 111) ──────────────────────────────────
	let mut p521_sk_bytes = [0x42u8; 66];
	p521_sk_bytes[0] = 0x00; // keep the scalar below the P-521 group order
	let p5_sk = p521::ecdsa::SigningKey::from_slice(&p521_sk_bytes).expect("p521 scalar");
	let p5_vk = p521::ecdsa::VerifyingKey::from(&p5_sk);
	let digest512: [u8; 64] = Sha512::digest(&msg).into();
	let p5_sig: p521::ecdsa::Signature = {
		// p521 0.13 only exposes the randomized prehash signer; the
		// verification side is deterministic either way.
		use p521::ecdsa::signature::hazmat::RandomizedPrehashSigner;
		p5_sk
			.sign_prehash_with_rng(&mut p521::elliptic_curve::rand_core::OsRng, &digest512)
			.expect("sign")
	};
	let p5_vk_bytes = p5_vk.to_encoded_point(false);
	let p5_vk_bytes = p5_vk_bytes.as_bytes();
	assert_eq!(p5_vk_bytes.len(), 133);
	let p5_sig_bytes = p5_sig.to_bytes();
	assert_eq!(p5_sig_bytes.len(), 132);
	let t = native_of("p521 verify_prehash", &mut || {
		use p521::ecdsa::signature::hazmat::PrehashVerifier;
		let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(p5_vk_bytes).expect("vk");
		let sig = p521::ecdsa::Signature::from_slice(&p5_sig_bytes).expect("sig");
		vk.verify_prehash(std::hint::black_box(&digest512), &sig).expect("verify");
	});
	let mut in_p5 = Vec::new();
	in_p5.extend_from_slice(p5_vk_bytes);
	in_p5.extend_from_slice(&p5_sig_bytes);
	in_p5.extend_from_slice(&digest512);
	workloads.push(Workload { name: "bench_p521_soft", input: in_p5.clone(), expect: Some(0), native: Some(t) });
	workloads.push(Workload { name: "bench_p521_intrinsic", input: in_p5, expect: Some(0), native: Some(t) });

	// ── ML-DSA-65 (fips204 — matches intrinsic 110) ────────────────────
	let (ml_pk, ml_sk) = {
		use fips204::ml_dsa_65;
		use fips204::traits::{KeyGen, SerDes, Signer};
		let (pk, sk) = ml_dsa_65::KG::try_keygen().expect("mldsa keygen");
		let sig = sk.try_sign(&msg, &[]).expect("mldsa sign");
		(pk.into_bytes(), sig)
	};
	let t = {
		use fips204::ml_dsa_65;
		use fips204::traits::{SerDes, Verifier};
		native_of("ml-dsa-65 verify", &mut || {
			let pk = ml_dsa_65::PublicKey::try_from_bytes(ml_pk).expect("pk");
			assert!(pk.verify(std::hint::black_box(&msg), &ml_sk, &[]));
		})
	};
	let mut in_ml = Vec::new();
	in_ml.extend_from_slice(&ml_pk);
	in_ml.extend_from_slice(&ml_sk);
	in_ml.extend_from_slice(&msg);
	workloads.push(Workload { name: "bench_mldsa_soft", input: in_ml.clone(), expect: Some(0), native: Some(t) });
	workloads.push(Workload { name: "bench_mldsa_intrinsic", input: in_ml, expect: Some(0), native: Some(t) });

	// ── SLH-DSA-SHA2-128s (finality vote scheme; no intrinsic) ─────────
	let slh_sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::slh_keygen_internal(
		&[0x42u8; 16],
		&[0x43u8; 16],
		&[0x44u8; 16],
	);
	let slh_vk = slh_sk.as_ref().clone();
	let slh_sig = slh_sk.try_sign_with_context(&msg, &[], None).expect("slh sign");
	let slh_vk_bytes = slh_vk.to_bytes();
	let slh_sig_bytes = slh_sig.to_bytes();
	assert_eq!(slh_sig_bytes.len(), 7856, "SLH-DSA-SHA2-128s signature size");
	let t = native_of("slh-dsa-128s verify", &mut || {
		let vk = slh_dsa::VerifyingKey::<slh_dsa::Sha2_128s>::try_from(&slh_vk_bytes[..])
			.expect("vk");
		let sig =
			slh_dsa::Signature::<slh_dsa::Sha2_128s>::try_from(&slh_sig_bytes[..]).expect("sig");
		vk.try_verify_with_context(std::hint::black_box(&msg), &[], &sig).expect("verify");
	});
	let mut in_slh = Vec::new();
	in_slh.extend_from_slice(&slh_vk_bytes);
	in_slh.extend_from_slice(&slh_sig_bytes);
	in_slh.extend_from_slice(&msg);
	workloads.push(Workload { name: "bench_slhdsa_soft", input: in_slh.clone(), expect: Some(0), native: Some(t) });
	workloads.push(Workload { name: "bench_slhdsa_intrinsic", input: in_slh, expect: Some(0), native: Some(t) });

	// ── BLS12-381 single pairing (ring-VRF/Groth16 preview) ────────────
	let g1 = (ark_bls12_381::G1Affine::generator() * ark_bls12_381::Fr::from(5u64))
		.into_affine();
	let g2 = (ark_bls12_381::G2Affine::generator() * ark_bls12_381::Fr::from(7u64))
		.into_affine();
	let expected_pairing: u64 = {
		let out = ark_bls12_381::Bls12_381::pairing(g1, g2);
		let mut buf = Vec::new();
		out.0.serialize_uncompressed(&mut buf).expect("serialize");
		u64::from_le_bytes(buf[..8].try_into().expect("len"))
	};
	let t = native_of("bls12-381 pairing", &mut || {
		let out = ark_bls12_381::Bls12_381::pairing(
			std::hint::black_box(g1),
			std::hint::black_box(g2),
		);
		let _ = std::hint::black_box(out);
	});
	let mut in_bls = Vec::new();
	{
		let mut buf = Vec::new();
		g1.serialize_uncompressed(&mut buf).expect("g1");
		assert_eq!(buf.len(), 96);
		in_bls.extend_from_slice(&buf);
		let mut buf = Vec::new();
		g2.serialize_uncompressed(&mut buf).expect("g2");
		assert_eq!(buf.len(), 192);
		in_bls.extend_from_slice(&buf);
	}
	workloads.push(Workload {
		name: "bench_bls_pairing_soft",
		input: in_bls,
		expect: Some(expected_pairing),
		native: Some(t),
	});

	// ── BLS12-381 pairing-check, 2 pairs (matches intrinsic 114) ───────
	// e(5·G1, 7·G2) · e(-5·G1, 7·G2) = e(0·G1, 7·G2) = identity.
	let mut in_blsck = Vec::new();
	{
		use ark_serialize::CanonicalSerialize as _;
		let g2_7 = (ark_bls12_381::G2Affine::generator() * ark_bls12_381::Fr::from(7u64))
			.into_affine();
		for k in [5i64, -5i64] {
			let g1_k = (ark_bls12_381::G1Affine::generator() * ark_bls12_381::Fr::from(k))
				.into_affine();
			let mut buf = Vec::new();
			g1_k.serialize_uncompressed(&mut buf).expect("g1");
			in_blsck.extend_from_slice(&buf);
			let mut buf = Vec::new();
			g2_7.serialize_uncompressed(&mut buf).expect("g2");
			in_blsck.extend_from_slice(&buf);
		}
	}
	let t = {
		use ark_ff::One;
		native_of("bls12-381 pairing_check(2)", &mut || {
			use ark_serialize::CanonicalDeserialize;
			// Mirror the intrinsic: checked deserialize + multi-pairing.
			let g1s: Vec<_> = (0..2)
				.map(|i| {
					ark_bls12_381::G1Affine::deserialize_uncompressed(
						std::hint::black_box(&in_blsck[i * 288..i * 288 + 96]),
					)
					.expect("g1")
				})
				.collect();
			let g2s: Vec<_> = (0..2)
				.map(|i| {
					ark_bls12_381::G2Affine::deserialize_uncompressed(
						std::hint::black_box(&in_blsck[i * 288 + 96..i * 288 + 288]),
					)
					.expect("g2")
				})
				.collect();
			assert!(ark_bls12_381::Bls12_381::multi_pairing(g1s, g2s).0.is_one());
		})
	};
	workloads.push(Workload {
		name: "bench_bls_pairing_check_soft",
		input: in_blsck.clone(),
		expect: Some(0),
		native: Some(t),
	});
	workloads.push(Workload {
		name: "bench_bls_pairing_check_intrinsic",
		input: in_blsck,
		expect: Some(0),
		native: Some(t),
	});

	// ── RVM interpreter, executor-mirrored config ──────────────────────
	let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
	config.set_allow_experimental(true);
	config.set_backend(Some(BackendKind::Interpreter));
	let engine = Engine::new(&config).expect("engine");

	let blob = rostro_executor_fixture_cipher_bench::binary_unwrap();
	let module =
		Module::new(&engine, &ModuleConfig::new(), blob.to_vec().into()).expect("module compile");

	let mut linker = polkavm::Linker::<(), String>::new();
	register_substrate_host_functions::<(), HostFns>(&mut linker).expect("register host fns");
	// Intrinsic imports are intercepted inline by the interpreter's
	// FAST_OP_ECALLI arms; the stubs only satisfy instantiation's import
	// resolution (keeping the missing-host-function check strict for
	// everything else).
	for name in [
		"rostro_mldsa65_verify",
		"rostro_p521_verify_prehash",
		"rostro_ed25519_verify",
		"rostro_secp256k1_recover",
		"rostro_slhdsa128s_verify",
		"rostro_bls381_pairing_check",
	] {
		linker
			.define_untyped(name, move |_caller: polkavm::Caller<()>| -> Result<(), String> {
				Err(format!("unreachable: {name} is dispatched inline by the interpreter"))
			})
			.expect("define intrinsic stub");
	}
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
	// Call-overhead calibration first.
	let noop_pc = find_pc("bench_noop");
	let (noop, _) = time_it(
		&mut || {
			instance.reset_memory().expect("reset_memory");
			instance.set_gas(i64::MAX / 2);
			sp_externalities::set_and_run_with_externalities(&mut ext, || {
				instance
					.call_typed::<(u32, u32)>(&mut (), noop_pc, (heap_base, 0))
					.expect("noop call");
			});
			assert_eq!(instance.reg(Reg::A0), 0);
		},
		2_000,
	);
	println!("{:30} {}", "bench_noop", fmt(noop));

	let mut results: Vec<(&str, Duration, Option<Duration>)> = Vec::new();
	for w in &workloads {
		let pc = find_pc(w.name);
		let len: u32 = w.input.len().try_into().expect("input fits u32");
		let mut run = || {
			instance.reset_memory().expect("reset_memory");
			instance.set_gas(i64::MAX / 2);
			instance.sbrk(len).expect("sbrk");
			instance.write_memory(heap_base, &w.input).expect("write input");
			sp_externalities::set_and_run_with_externalities(&mut ext, || {
				instance
					.call_typed::<(u32, u32)>(&mut (), pc, (heap_base, len))
					.unwrap_or_else(|e| panic!("guest call {}: {e:?}", w.name));
			});
			let a0 = instance.reg(Reg::A0);
			if let Some(want) = w.expect {
				assert_eq!(a0, want, "{} returned {a0}", w.name);
			} else {
				assert_ne!(a0, 0, "{} must do real work", w.name);
			}
		};
		let (t, n) = time_it(&mut run, 2_000);
		println!("{:30} {}  ({n} iters)", w.name, fmt(t));
		results.push((w.name, t, w.native));
	}

	// ── Summary matrix ─────────────────────────────────────────────────
	let get = |name: &str| {
		results
			.iter()
			.find(|(n, _, _)| *n == name)
			.unwrap_or_else(|| panic!("bench ran: {name}"))
			.clone()
	};
	println!("\n== summary (noop overhead subtracted; ratio = RVM/native) ==");
	println!(
		"{:22} {:>12} {:>12} {:>12} {:>9} {:>9}",
		"cipher", "native", "soft (interp)", "intrinsic", "soft x", "intr x"
	);
	let row = |cipher: &str, soft: &str, intr: Option<&str>| {
		let (_, t_soft, native) = get(soft);
		let native = native.expect("native baseline recorded");
		let t_soft = t_soft.saturating_sub(noop);
		let (t_intr, intr_ratio) = match intr {
			Some(name) => {
				let (_, t, _) = get(name);
				let t = t.saturating_sub(noop);
				(fmt(t), format!("{:.2}x", t.as_secs_f64() / native.as_secs_f64()))
			},
			None => ("—".into(), "—".into()),
		};
		println!(
			"{:22} {:>12} {:>12} {:>12} {:>8.0}x {:>9}",
			cipher,
			fmt(native),
			fmt(t_soft),
			t_intr,
			t_soft.as_secs_f64() / native.as_secs_f64(),
			intr_ratio
		);
	};
	row("ed25519", "bench_ed25519_soft", Some("bench_ed25519_intrinsic"));
	row("sr25519", "bench_sr25519_soft", None);
	row("secp256k1 recover", "bench_ecrecover_soft", Some("bench_ecrecover_intrinsic"));
	row("p521", "bench_p521_soft", Some("bench_p521_intrinsic"));
	row("ml-dsa-65", "bench_mldsa_soft", Some("bench_mldsa_intrinsic"));
	row("slh-dsa-128s", "bench_slhdsa_soft", Some("bench_slhdsa_intrinsic"));
	row("bls12-381 pairing", "bench_bls_pairing_soft", None);
	row(
		"bls pairing_check(2)",
		"bench_bls_pairing_check_soft",
		Some("bench_bls_pairing_check_intrinsic"),
	);
}
