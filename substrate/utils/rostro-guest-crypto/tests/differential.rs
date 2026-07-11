// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Native differential battery: facade == raw reference crate, per cipher;
//! and hooked arkworks == plain arkworks, per group operation (the
//! byte-equality consensus gate for the ring-VRF curve switch — W3's
//! acceptance criterion stands on these).
//!
//! The facade-guest == facade-native leg runs in the executor fixture
//! (`substrate/utils/rostro-executor/tests/fixtures/facade-test`), where the
//! guest side really executes the ecalli intrinsics.

use rostro_guest_crypto::{hooks, verify, RostroCurveHooks};

fn hex(s: &str) -> Vec<u8> {
	(0..s.len() / 2)
		.map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
		.collect()
}

// ── verify facade vs reference crates ───────────────────────────────────

#[test]
fn p256_matches_rfc6979_vector() {
	// RFC 6979 §A.2.5 (P-256 + SHA-256, message "sample") — the same anchor
	// the intrinsic KAT pins.
	let mut vk = [0u8; 33];
	vk[0] = 0x03;
	vk[1..].copy_from_slice(&hex(
		"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
	));
	let sig: [u8; 64] = hex(
		"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
	)
	.try_into()
	.unwrap();
	let digest = hex("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF");
	assert!(verify::p256_verify_prehash(&vk, &sig, &digest));
	let mut bad = sig;
	bad[0] ^= 1;
	assert!(!verify::p256_verify_prehash(&vk, &bad, &digest));
}

#[test]
fn p521_matches_reference_sign() {
	use p521::ecdsa::signature::hazmat::PrehashSigner;
	// P-521 scalars are 521 bits: 66 bytes with a 0x01 top byte stays below
	// the group order (0x07 would overflow it).
	let sk = p521::ecdsa::SigningKey::from_slice(&[1u8; 66]).expect("key");
	// `SigningKey::verifying_key` is cfg-gated on a "verifying" feature p521
	// doesn't define (upstream template artifact); the From impl is gated
	// correctly.
	let vk = p521::ecdsa::VerifyingKey::from(&sk);
	let vk_bytes: [u8; 133] = vk.to_encoded_point(false).as_bytes().try_into().unwrap();
	let digest = [0x42u8; 64];
	let sig: p521::ecdsa::Signature = sk.sign_prehash(&digest).expect("sign");
	let sig_bytes: [u8; 132] = sig.to_bytes().as_slice().try_into().unwrap();
	assert!(verify::p521_verify_prehash(&vk_bytes, &sig_bytes, &digest));
	let mut bad = digest;
	bad[0] ^= 1;
	assert!(!verify::p521_verify_prehash(&vk_bytes, &sig_bytes, &bad));
}

#[test]
fn mldsa65_matches_reference_sign() {
	use fips204::ml_dsa_65;
	use fips204::traits::{SerDes, Signer};
	let (pk, sk) = ml_dsa_65::try_keygen().expect("keygen");
	let msg = b"rostro facade differential";
	let sig = sk.try_sign(msg, b"ctx").expect("sign");
	let pk_bytes = pk.into_bytes();
	assert!(verify::mldsa65_verify(&pk_bytes, msg, &sig, b"ctx"));
	assert!(!verify::mldsa65_verify(&pk_bytes, msg, &sig, b"wrong-ctx"));
	let mut bad = sig;
	bad[0] ^= 1;
	assert!(!verify::mldsa65_verify(&pk_bytes, msg, &bad, b"ctx"));
}

#[test]
fn slhdsa128s_matches_reference_sign() {
	// Deterministic keygen from fixed FIPS 205 seeds + deterministic sign —
	// the same construction the intrinsic KAT uses.
	let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::slh_keygen_internal(
		&[0x01u8; 16],
		&[0x02u8; 16],
		&[0x03u8; 16],
	);
	let vk_bytes: [u8; 32] = sk.as_ref().to_bytes().as_slice().try_into().unwrap();
	let msg = b"rostro facade differential";
	let sig = sk.try_sign_with_context(msg, &[], None).expect("sign");
	let sig_bytes: [u8; 7856] = sig.to_bytes().as_slice().try_into().unwrap();
	assert!(verify::slhdsa128s_verify(&vk_bytes, msg, &sig_bytes, &[]));
	assert!(!verify::slhdsa128s_verify(&vk_bytes, b"tampered", &sig_bytes, &[]));
}

#[test]
fn secp256k1_recover_roundtrip_and_strictness() {
	use k256::ecdsa::SigningKey;
	let sk = SigningKey::from_slice(&[9u8; 32]).expect("key");
	let msg_hash = [0x55u8; 32];
	let (sig, recid) = sk.sign_prehash_recoverable(&msg_hash).expect("sign");
	let mut sig65 = [0u8; 65];
	sig65[..64].copy_from_slice(&sig.to_bytes());
	sig65[64] = recid.to_byte();
	let recovered = verify::secp256k1_recover(&msg_hash, &sig65).expect("recover");
	let expected = sk.verifying_key().to_encoded_point(false);
	assert_eq!(&recovered[..], &expected.as_bytes()[1..]);
	// recovery id ≥ 2 rejected (Ethereum strict).
	let mut bad = sig65;
	bad[64] = 2;
	assert!(verify::secp256k1_recover(&msg_hash, &bad).is_none());
}

#[test]
fn bls381_pairing_check_bilinearity_and_caps() {
	use ark_ec::{AffineRepr, CurveGroup};
	use ark_serialize::CanonicalSerialize;
	let ser = |k: i64| {
		let g1 = (ark_bls12_381::G1Affine::generator() * ark_bls12_381::Fr::from(k)).into_affine();
		let g2 = ark_bls12_381::G2Affine::generator();
		let mut buf = Vec::new();
		g1.serialize_uncompressed(&mut buf).unwrap();
		g2.serialize_uncompressed(&mut buf).unwrap();
		buf
	};
	let mut pairs = ser(2);
	pairs.extend_from_slice(&ser(-2));
	assert!(verify::bls381_pairing_check(&pairs));
	let mut bad = pairs.clone();
	bad[3] ^= 1;
	assert!(!verify::bls381_pairing_check(&bad));
	// Over-cap and misaligned inputs fail closed.
	assert!(!verify::bls381_pairing_check(&pairs[..100]));
	let over: Vec<u8> = core::iter::repeat_n(pairs.clone(), 5).flatten().collect();
	assert!(!verify::bls381_pairing_check(&over)); // 10 pairs > MAX_BLS_PAIRS
}

#[test]
fn sp_io_delegations_roundtrip() {
	use sp_core::Pair;
	let pair = sp_core::ed25519::Pair::from_seed(&[1u8; 32]);
	let msg = b"facade sp_io delegation";
	let sig = pair.sign(msg);
	assert!(verify::ed25519_verify(&sig.0, msg, &pair.public().0));
	assert!(!verify::ed25519_verify(&sig.0, b"other", &pair.public().0));

	let pair = sp_core::sr25519::Pair::from_seed(&[2u8; 32]);
	let sig = pair.sign(msg);
	assert!(verify::sr25519_verify(&sig.0, msg, &pair.public().0));
	assert!(!verify::sr25519_verify(&sig.0, b"other", &pair.public().0));

	let pair = sp_core::ecdsa::Pair::from_seed(&[3u8; 32]);
	let hash = [0x11u8; 32];
	let sig = pair.sign_prehashed(&hash);
	assert!(verify::ecdsa_verify_prehashed(&sig.0, &hash, &pair.public().0));
	assert!(!verify::ecdsa_verify_prehashed(&sig.0, &[0x12u8; 32], &pair.public().0));
}

// ── hooked arkworks == plain arkworks (the consensus byte-equality gate) ──

fn ser<T: ark_serialize::CanonicalSerialize>(t: &T) -> Vec<u8> {
	let mut buf = Vec::new();
	t.serialize_uncompressed(&mut buf).expect("serialize");
	buf
}

#[test]
fn hooked_pairing_equals_plain() {
	use ark_ec::pairing::Pairing;
	use ark_ec::{AffineRepr, CurveGroup};
	// Exercises multi_miller_loop + final_exponentiation through the full
	// ext plumbing.
	let a_h = (hooks::BlsG1Affine::generator() * ark_bls12_381::Fr::from(5)).into_affine();
	let b_h = (hooks::BlsG2Affine::generator() * ark_bls12_381::Fr::from(7)).into_affine();
	let hooked = hooks::Bls12_381::pairing(a_h, b_h);
	let a_p = (ark_bls12_381::G1Affine::generator() * ark_bls12_381::Fr::from(5)).into_affine();
	let b_p = (ark_bls12_381::G2Affine::generator() * ark_bls12_381::Fr::from(7)).into_affine();
	let plain = ark_bls12_381::Bls12_381::pairing(a_p, b_p);
	assert_eq!(ser(&hooked.0), ser(&plain.0));
}

#[test]
fn hooked_msm_equals_plain() {
	use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
	let scalars: Vec<ark_bls12_381::Fr> =
		(1..=16).map(|k| ark_bls12_381::Fr::from(k * 3 + 1)).collect();

	let bases_h: Vec<hooks::BlsG1Affine> = (1..=16)
		.map(|k| (hooks::BlsG1Affine::generator() * ark_bls12_381::Fr::from(k)).into_affine())
		.collect();
	let hooked = hooks::BlsG1Projective::msm_unchecked(&bases_h, &scalars).into_affine();
	let bases_p: Vec<ark_bls12_381::G1Affine> = (1..=16)
		.map(|k| (ark_bls12_381::G1Affine::generator() * ark_bls12_381::Fr::from(k)).into_affine())
		.collect();
	let plain = ark_bls12_381::G1Projective::msm_unchecked(&bases_p, &scalars).into_affine();
	assert_eq!(ser(&hooked), ser(&plain));

	let bases_h: Vec<hooks::BlsG2Affine> = (1..=16)
		.map(|k| (hooks::BlsG2Affine::generator() * ark_bls12_381::Fr::from(k)).into_affine())
		.collect();
	let hooked = hooks::BlsG2Projective::msm_unchecked(&bases_h, &scalars).into_affine();
	let bases_p: Vec<ark_bls12_381::G2Affine> = (1..=16)
		.map(|k| (ark_bls12_381::G2Affine::generator() * ark_bls12_381::Fr::from(k)).into_affine())
		.collect();
	let plain = ark_bls12_381::G2Projective::msm_unchecked(&bases_p, &scalars).into_affine();
	assert_eq!(ser(&hooked), ser(&plain));
}

#[test]
fn hooked_mul_projective_equals_plain() {
	use ark_ec::{AffineRepr, CurveGroup};
	let limbs: [u64; 4] = [0xdead_beef, 42, 7, 1];
	let hooked = hooks::BlsG1Affine::generator().mul_bigint(limbs).into_affine();
	let plain = ark_bls12_381::G1Affine::generator().mul_bigint(limbs).into_affine();
	assert_eq!(ser(&hooked), ser(&plain));
	let hooked = hooks::BlsG2Affine::generator().mul_bigint(limbs).into_affine();
	let plain = ark_bls12_381::G2Affine::generator().mul_bigint(limbs).into_affine();
	assert_eq!(ser(&hooked), ser(&plain));
}

#[test]
fn hooked_bandersnatch_equals_plain() {
	use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
	type PlainTe = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
	type PlainSw = ark_ed_on_bls12_381_bandersnatch::SWAffine;
	type Fr = ark_ed_on_bls12_381_bandersnatch::Fr;
	let scalars: Vec<Fr> = (1..=16).map(|k| Fr::from(k * 5 + 2)).collect();

	let bases_h: Vec<hooks::EdwardsAffine> =
		(1..=16).map(|k| (hooks::EdwardsAffine::generator() * Fr::from(k)).into_affine()).collect();
	let hooked = hooks::EdwardsProjective::msm_unchecked(&bases_h, &scalars).into_affine();
	let bases_p: Vec<PlainTe> =
		(1..=16).map(|k| (PlainTe::generator() * Fr::from(k)).into_affine()).collect();
	let plain = ark_ed_on_bls12_381_bandersnatch::EdwardsProjective::msm_unchecked(
		&bases_p, &scalars,
	)
	.into_affine();
	assert_eq!(ser(&hooked), ser(&plain));

	let bases_h: Vec<hooks::SWAffine> =
		(1..=16).map(|k| (hooks::SWAffine::generator() * Fr::from(k)).into_affine()).collect();
	let hooked = hooks::SWProjective::msm_unchecked(&bases_h, &scalars).into_affine();
	let bases_p: Vec<PlainSw> =
		(1..=16).map(|k| (PlainSw::generator() * Fr::from(k)).into_affine()).collect();
	let plain =
		ark_ed_on_bls12_381_bandersnatch::SWProjective::msm_unchecked(&bases_p, &scalars)
			.into_affine();
	assert_eq!(ser(&hooked), ser(&plain));

	// mul_projective through mul_bigint, both representations — a 5-limb
	// scalar exercises the wide-integer path (double-and-add on these
	// curves; no GLV).
	let limbs: [u64; 5] = [7, 0, 0, 0, 1];
	let hooked = hooks::EdwardsAffine::generator().mul_bigint(limbs).into_affine();
	let plain = PlainTe::generator().mul_bigint(limbs).into_affine();
	assert_eq!(ser(&hooked), ser(&plain));
	let hooked = hooks::SWAffine::generator().mul_bigint(limbs).into_affine();
	let plain = PlainSw::generator().mul_bigint(limbs).into_affine();
	assert_eq!(ser(&hooked), ser(&plain));
}

#[test]
fn hashing_delegation_known_vector() {
	// SHA-256("abc") — FIPS 180 vector, pins the sp_io delegation.
	let expected = hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	assert_eq!(&rostro_guest_crypto::hashing::sha2_256(b"abc")[..], &expected[..]);
}

// Type-level: RostroCurveHooks satisfies both hooks traits (what W3's
// vendored ark-vrf will bind against).
#[allow(dead_code)]
fn assert_hooks_bounds<
	H: ark_bls12_381_ext::CurveHooks + ark_ed_on_bls12_381_bandersnatch_ext::CurveHooks,
>() {
}
#[allow(dead_code)]
fn assert_rostro_hooks() {
	assert_hooks_bounds::<RostroCurveHooks>();
}
