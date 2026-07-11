// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Shared plumbing for the facade fixture's two harness bins: case
//! construction (inputs + natively computed expected values + native
//! baseline closures) and the executor-mirrored VM setup.

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::CanonicalSerialize;
use polkavm::{BackendKind, Config, Engine, Module, ModuleConfig, Reg};
use rostro_executor::register_substrate_host_functions;
use rostro_guest_crypto::verify;
use rostro_guest_crypto::hooks;

pub type HostFns = (
	sp_io::storage::HostFunctions,
	sp_io::hashing::HostFunctions,
	sp_io::crypto::HostFunctions,
	sp_io::misc::HostFunctions,
	sp_io::allocator::HostFunctions,
);

pub fn ser<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
	let mut buf = Vec::new();
	t.serialize_uncompressed(&mut buf).expect("serialize");
	buf
}

pub struct Case {
	pub name: &'static str,
	pub input: Vec<u8>,
	/// Native baseline: the same operation through the facade's native
	/// backend (used by the bench bin; the correctness bin ignores it).
	pub native: Box<dyn FnMut()>,
	/// Per-case override of the bench guard ratio (None = the default).
	pub guard_max: Option<f64>,
}

pub fn build_cases() -> Vec<Case> {
	let mut cases = Vec::new();
	type BlsFr = ark_bls12_381::Fr;
	type BanderFr = ark_ed_on_bls12_381_bandersnatch::Fr;

	// ── ft_pairing: expected via the facade's native hooks path ────────
	{
		let g1 = (hooks::BlsG1Affine::generator() * BlsFr::from(5)).into_affine();
		let g2 = (hooks::BlsG2Affine::generator() * BlsFr::from(7)).into_affine();
		let expected = hooks::Bls12_381::pairing(g1, g2);
		let mut input = ser(&g1);
		input.extend_from_slice(&ser(&g2));
		input.extend_from_slice(&ser(&expected.0));
		let native = Box::new(move || {
			std::hint::black_box(hooks::Bls12_381::pairing(g1, g2));
		});
		cases.push(Case { name: "ft_pairing", input, native, guard_max: None });
	}

	// ── ft_multi_pairing with n = 10 > MAX_BLS_PAIRS: chunking path ────
	{
		let n = 10usize;
		assert!(n > rostro_guest_crypto::MAX_BLS_PAIRS);
		let g1s: Vec<_> = (1..=n)
			.map(|k| (hooks::BlsG1Affine::generator() * BlsFr::from(k as u64)).into_affine())
			.collect();
		let g2s: Vec<_> = (1..=n)
			.map(|k| (hooks::BlsG2Affine::generator() * BlsFr::from(2 * k as u64)).into_affine())
			.collect();
		let expected = hooks::Bls12_381::multi_pairing(g1s.clone(), g2s.clone());
		let mut input = (n as u32).to_le_bytes().to_vec();
		for (g1, g2) in g1s.iter().zip(&g2s) {
			input.extend_from_slice(&ser(g1));
			input.extend_from_slice(&ser(g2));
		}
		input.extend_from_slice(&ser(&expected.0));
		let native = Box::new(move || {
			std::hint::black_box(hooks::Bls12_381::multi_pairing(g1s.clone(), g2s.clone()));
		});
		cases.push(Case { name: "ft_multi_pairing", input, native, guard_max: None });
	}

	// ── MSM cases (n = 5), expected via the facade's native msm ────────
	macro_rules! msm_case {
		($name:literal, $affine:ty, $proj:ty, $fr:ty, $n:expr, $guard:expr) => {{
			let n: usize = $n;
			let bases: Vec<$affine> = (1..=n)
				.map(|k| (<$affine>::generator() * <$fr>::from(k as u64)).into_affine())
				.collect();
			let scalars: Vec<$fr> = (1..=n).map(|k| <$fr>::from(3 * k as u64 + 1)).collect();
			let expected = <$proj>::msm(&bases, &scalars).unwrap().into_affine();
			let mut input = (n as u32).to_le_bytes().to_vec();
			for b in &bases {
				input.extend_from_slice(&ser(b));
			}
			for s in &scalars {
				input.extend_from_slice(&ser(s));
			}
			input.extend_from_slice(&ser(&expected));
			let native = Box::new(move || {
				std::hint::black_box(<$proj>::msm(&bases, &scalars).unwrap());
			});
			cases.push(Case { name: $name, input, native, guard_max: $guard });
		}};
	}
	msm_case!("ft_msm_g1", hooks::BlsG1Affine, hooks::BlsG1Projective, BlsFr, 5, None);
	// Same export at ring-scale n. The wire ABI charges a CONSTANT ~30 µs of
	// interpreted Montgomery↔bytes conversion per point while Pippenger's
	// native per-point cost FALLS with n, so a pure MSM measured
	// bytes-to-bytes diverges from native as n grows (~24x at n=256) — that
	// is conversion cost, not compute. A true interpreted fallback measures
	// 100-150x at this n; the 60x guard splits the two regimes. Killing the
	// conversion needs a raw Montgomery-limb ABI (memcpy marshalling) — a
	// candidate follow-up, see the doc.
	msm_case!("ft_msm_g1", hooks::BlsG1Affine, hooks::BlsG1Projective, BlsFr, 256, Some(60.0));
	msm_case!("ft_msm_g2", hooks::BlsG2Affine, hooks::BlsG2Projective, BlsFr, 5, None);
	msm_case!("ft_te_msm", hooks::EdwardsAffine, hooks::EdwardsProjective, BanderFr, 5, None);
	msm_case!("ft_sw_msm", hooks::SWAffine, hooks::SWProjective, BanderFr, 5, None);

	// ── mul_projective cases, expected via the facade's native path ────
	// G1 stays within ark's 4-limb GLV bound; the others take a 5-limb
	// scalar (the wide-integer path).
	macro_rules! mul_case {
		($name:literal, $affine:ty, $limbs:expr) => {{
			let limbs: &[u64] = $limbs;
			let base = (<$affine>::generator().mul_bigint([9u64])).into_affine();
			let expected = base.mul_bigint(limbs).into_affine();
			let mut input = (limbs.len() as u32).to_le_bytes().to_vec();
			for l in limbs {
				input.extend_from_slice(&l.to_le_bytes());
			}
			input.extend_from_slice(&ser(&base));
			input.extend_from_slice(&ser(&expected));
			let limbs = limbs.to_vec();
			let native = Box::new(move || {
				std::hint::black_box(base.mul_bigint(&limbs[..]));
			});
			cases.push(Case { name: $name, input, native, guard_max: None });
		}};
	}
	mul_case!("ft_mul_g1", hooks::BlsG1Affine, &[0xdead_beef, 42, 7, 1]);
	mul_case!("ft_mul_g2", hooks::BlsG2Affine, &[7, 0, 0, 0, 1]);
	mul_case!("ft_mul_te", hooks::EdwardsAffine, &[7, 0, 0, 0, 1]);
	mul_case!("ft_mul_sw", hooks::SWAffine, &[7, 0, 0, 0, 1]);

	// ── verify facade cases ────────────────────────────────────────────
	{
		// RFC 6979 §A.2.5 (P-256 + SHA-256, "sample") — same anchor as the
		// intrinsic KAT and the facade's native differential test.
		let hex = |s: &str| -> Vec<u8> {
			(0..s.len() / 2)
				.map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
				.collect()
		};
		let mut input = vec![0x03u8];
		input.extend_from_slice(&hex(
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
		));
		input.extend_from_slice(&hex(
			"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
		));
		input.extend_from_slice(&hex(
			"AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
		));
		let native = {
			let input = input.clone();
			Box::new(move || {
				let vk: &[u8; 33] = input[..33].try_into().unwrap();
				let sig: &[u8; 64] = input[33..97].try_into().unwrap();
				assert!(verify::p256_verify_prehash(vk, sig, &input[97..]));
			})
		};
		cases.push(Case { name: "ft_p256", input, native, guard_max: None });
	}
	{
		use p521::ecdsa::signature::hazmat::PrehashSigner;
		let sk = p521::ecdsa::SigningKey::from_slice(&[1u8; 66]).expect("key");
		let vk = p521::ecdsa::VerifyingKey::from(&sk);
		let digest = [0x42u8; 64];
		let sig: p521::ecdsa::Signature = sk.sign_prehash(&digest).expect("sign");
		let mut input = vk.to_encoded_point(false).as_bytes().to_vec();
		input.extend_from_slice(&sig.to_bytes());
		input.extend_from_slice(&digest);
		assert_eq!(input.len(), 133 + 132 + 64);
		let native = {
			let input = input.clone();
			Box::new(move || {
				let vk: &[u8; 133] = input[..133].try_into().unwrap();
				let sig: &[u8; 132] = input[133..265].try_into().unwrap();
				assert!(verify::p521_verify_prehash(vk, sig, &input[265..]));
			})
		};
		cases.push(Case { name: "ft_p521", input, native, guard_max: None });
	}
	{
		use fips204::ml_dsa_65;
		use fips204::traits::{SerDes, Signer};
		let (pk, sk) = ml_dsa_65::try_keygen().expect("keygen");
		let msg = b"rostro facade guest differential";
		let sig = sk.try_sign(msg, &[]).expect("sign");
		let mut input = pk.into_bytes().to_vec();
		input.extend_from_slice(&sig);
		input.extend_from_slice(msg);
		let native = {
			let input = input.clone();
			Box::new(move || {
				let pk: &[u8; 1952] = input[..1952].try_into().unwrap();
				let sig: &[u8; 3309] = input[1952..5261].try_into().unwrap();
				assert!(verify::mldsa65_verify(pk, &input[5261..], sig, &[]));
			})
		};
		cases.push(Case { name: "ft_mldsa", input, native, guard_max: None });
	}
	{
		let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::slh_keygen_internal(
			&[0x01u8; 16],
			&[0x02u8; 16],
			&[0x03u8; 16],
		);
		let msg = b"rostro facade guest differential";
		let sig = sk.try_sign_with_context(msg, &[], None).expect("sign");
		let mut input = sk.as_ref().to_bytes().to_vec();
		input.extend_from_slice(&sig.to_bytes());
		input.extend_from_slice(msg);
		let native = {
			let input = input.clone();
			Box::new(move || {
				let pk: &[u8; 32] = input[..32].try_into().unwrap();
				let sig: &[u8; 7856] = input[32..7888].try_into().unwrap();
				assert!(verify::slhdsa128s_verify(pk, &input[7888..], sig, &[]));
			})
		};
		cases.push(Case { name: "ft_slhdsa", input, native, guard_max: None });
	}
	{
		use k256::ecdsa::SigningKey;
		let sk = SigningKey::from_slice(&[9u8; 32]).expect("key");
		let msg_hash = [0x55u8; 32];
		let (sig, recid) = sk.sign_prehash_recoverable(&msg_hash).expect("sign");
		let mut input = msg_hash.to_vec();
		input.extend_from_slice(&sig.to_bytes());
		input.push(recid.to_byte());
		input.extend_from_slice(&sk.verifying_key().to_encoded_point(false).as_bytes()[1..]);
		let native = {
			let input = input.clone();
			Box::new(move || {
				let hash: &[u8; 32] = input[..32].try_into().unwrap();
				let sig: &[u8; 65] = input[32..97].try_into().unwrap();
				assert!(verify::secp256k1_recover(hash, sig).is_some());
			})
		};
		cases.push(Case { name: "ft_recover", input, native, guard_max: None });
	}
	{
		// Bilinearity pair set through the checked standalone verifier.
		let g1 = (hooks::BlsG1Affine::generator() * BlsFr::from(2)).into_affine();
		let g1_neg = (hooks::BlsG1Affine::generator() * -BlsFr::from(2)).into_affine();
		let g2 = hooks::BlsG2Affine::generator();
		let mut input = ser(&g1);
		input.extend_from_slice(&ser(&g2));
		input.extend_from_slice(&ser(&g1_neg));
		input.extend_from_slice(&ser(&g2));
		let native = {
			let input = input.clone();
			Box::new(move || {
				assert!(verify::bls381_pairing_check(&input));
			})
		};
		cases.push(Case { name: "ft_pairing_check", input, native, guard_max: None });
	}
	{
		use sp_core::Pair;
		let msg = b"rostro facade sp_io in-guest";
		let pair = sp_core::ed25519::Pair::from_seed(&[1u8; 32]);
		let mut input = pair.public().0.to_vec();
		input.extend_from_slice(&pair.sign(msg).0);
		input.extend_from_slice(msg);
		let native = {
			let input = input.clone();
			Box::new(move || {
				let pk: &[u8; 32] = input[..32].try_into().unwrap();
				let sig: &[u8; 64] = input[32..96].try_into().unwrap();
				assert!(verify::ed25519_verify(sig, &input[96..], pk));
			})
		};
		cases.push(Case { name: "ft_ed25519", input, native, guard_max: None });

		let pair = sp_core::sr25519::Pair::from_seed(&[2u8; 32]);
		let mut input = pair.public().0.to_vec();
		input.extend_from_slice(&pair.sign(msg).0);
		input.extend_from_slice(msg);
		let native = {
			let input = input.clone();
			Box::new(move || {
				let pk: &[u8; 32] = input[..32].try_into().unwrap();
				let sig: &[u8; 64] = input[32..96].try_into().unwrap();
				assert!(verify::sr25519_verify(sig, &input[96..], pk));
			})
		};
		cases.push(Case { name: "ft_sr25519", input, native, guard_max: None });

		let pair = sp_core::ecdsa::Pair::from_seed(&[3u8; 32]);
		let hash = [0x11u8; 32];
		let mut input = pair.public().0.to_vec();
		input.extend_from_slice(&pair.sign_prehashed(&hash).0);
		input.extend_from_slice(&hash);
		let native = {
			let input = input.clone();
			Box::new(move || {
				let pk: &[u8; 33] = input[..33].try_into().unwrap();
				let sig: &[u8; 65] = input[33..98].try_into().unwrap();
				let hash: &[u8; 32] = input[98..].try_into().unwrap();
				assert!(verify::ecdsa_verify_prehashed(sig, hash, pk));
			})
		};
		cases.push(Case { name: "ft_ecdsa", input, native, guard_max: None });
	}

	cases
}


/// Executor-mirrored VM setup shared by both bins: interpreter backend,
/// substrate host functions, the executor's reserved-range intrinsic-stub
/// registration (its canonical symbol list is integration-checked here).
pub struct Vm {
	pub module: Module,
	pub instance: polkavm::Instance<(), String>,
	pub heap_base: u32,
}

pub fn setup_vm() -> Vm {
	let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
	config.set_allow_experimental(true);
	config.set_backend(Some(BackendKind::Interpreter));
	let engine = Engine::new(&config).expect("engine");
	let blob = rostro_executor_fixture_facade_test::binary_unwrap();
	let module =
		Module::new(&engine, &ModuleConfig::new(), blob.to_vec().into()).expect("module compile");
	let mut linker = polkavm::Linker::<(), String>::new();
	register_substrate_host_functions::<(), HostFns>(&mut linker).expect("register host fns");
	rostro_executor::register_rostro_intrinsic_stubs::<()>(&mut linker)
		.expect("register intrinsic stubs");
	let instance_pre = linker.instantiate_pre(&module).expect("instantiate_pre");
	let instance = instance_pre.instantiate().expect("instantiate");
	let heap_base = module.memory_map().heap_base();
	Vm { module, instance, heap_base }
}

/// Run one guest case; returns the A0 status.
pub fn run_case(vm: &mut Vm, ext: &mut sp_state_machine::BasicExternalities, case: &Case) -> u64 {
	let pc = vm
		.module
		.exports()
		.find(|e| e.symbol().as_bytes() == case.name.as_bytes())
		.unwrap_or_else(|| panic!("export not found: {}", case.name))
		.program_counter();
	vm.instance.reset_memory().expect("reset_memory");
	vm.instance.set_gas(i64::MAX / 2);
	// Grow the heap past the input so guest allocations don't overlap it.
	vm.instance.sbrk(case.input.len() as u32).expect("sbrk");
	vm.instance.write_memory(vm.heap_base, &case.input).expect("write input");
	sp_externalities::set_and_run_with_externalities(ext, || {
		vm.instance
			.call_typed::<(u32, u32)>(&mut (), pc, (vm.heap_base, case.input.len() as u32))
			.unwrap_or_else(|e| panic!("{}: trap: {e:?}", case.name));
	});
	vm.instance.reg(Reg::A0)
}
