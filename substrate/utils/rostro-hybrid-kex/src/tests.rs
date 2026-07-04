// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! NIST ACVP known-answer tests for the vendored `ml-kem` crate, plus
//! pinned vectors for the hybrid combine. The crates.io ml-kem tarball
//! excludes upstream's KAT files, so this module is the only KAT
//! coverage the vendored code gets — a failure here after a re-vendor
//! means upstream changed behavior: investigate, never update vectors.

use super::*;
use crate::kat_mlkem768::{DECAP_768, ENCAP_768, KEYGEN_768};

fn h(s: &str) -> Vec<u8> {
	hex::decode(s).expect("fixture hex is valid")
}

#[allow(deprecated)] // from_expanded: ACVP vectors carry expanded dk form
fn dk_from_expanded(dk_hex: &str) -> MlKemDecapKey {
	let bytes = h(dk_hex);
	let arr = ml_kem::ml_kem_768::ExpandedDecapsulationKey::try_from(bytes.as_slice())
		.expect("fixture dk length is 2400");
	DecapsulationKey768::from_expanded(&arr).expect("NIST fixture dk is valid")
}

#[test]
fn acvp_keygen_768() {
	for v in KEYGEN_768 {
		let mut seed = [0u8; MLKEM768_SEED_BYTES];
		seed[..32].copy_from_slice(&h(v.d));
		seed[32..].copy_from_slice(&h(v.z));
		let (dk, ek_bytes) = mlkem_keypair_from_seed(&seed);
		assert_eq!(ek_bytes.as_slice(), h(v.ek).as_slice(), "ek mismatch tcId={}", v.tc_id);
		// Seed-derived and expanded-form keys must agree (PartialEq
		// compares the key material, not the initialization path).
		assert_eq!(dk, dk_from_expanded(v.dk), "dk mismatch tcId={}", v.tc_id);
	}
}

#[test]
fn acvp_encap_768() {
	for v in ENCAP_768 {
		let ek: [u8; MLKEM768_EK_BYTES] = h(v.ek).try_into().expect("fixture ek length");
		let m: [u8; 32] = h(v.m).try_into().expect("fixture m length");
		let (ct, ss) = mlkem_encapsulate(&ek, &m).expect("NIST fixture ek is valid");
		assert_eq!(ct.as_slice(), h(v.c).as_slice(), "ciphertext mismatch tcId={}", v.tc_id);
		assert_eq!(ss.as_slice(), h(v.k).as_slice(), "shared key mismatch tcId={}", v.tc_id);
		// Valid-path decapsulation: the matching dk recovers the same key.
		let dk = dk_from_expanded(v.dk);
		let ct_arr: [u8; MLKEM768_CT_BYTES] = ct;
		assert_eq!(
			mlkem_decapsulate(&dk, &ct_arr).expect("valid ct decapsulates").as_slice(),
			h(v.k).as_slice(),
			"decap of KAT ciphertext mismatch tcId={}",
			v.tc_id
		);
	}
}

#[test]
fn acvp_decap_768_implicit_rejection() {
	// All three vectors are 'modified ciphertext' cases: FIPS 203
	// implicit rejection must return the exact deterministic garbage
	// key NIST expects, not an error and not a different garbage.
	for v in DECAP_768 {
		assert_eq!(v.reason, "modified ciphertext");
		let dk = dk_from_expanded(v.dk);
		let ct: [u8; MLKEM768_CT_BYTES] = h(v.c).try_into().expect("fixture ct length");
		let ss = mlkem_decapsulate(&dk, &ct).expect("implicit rejection is not an error");
		assert_eq!(ss.as_slice(), h(v.k).as_slice(), "implicit-rejection key mismatch tcId={}", v.tc_id);
	}
}

#[test]
fn hybrid_combine_pinned_vector() {
	// Pinned at construction time (2026-07-03). If this fails, the wire
	// protocol changed: bump HYBRID_KDF_INFO to v2 and the handshake
	// protocol version — never adjust the vector.
	let mlkem_ss: [u8; 32] = core::array::from_fn(|i| i as u8);
	let x25519_ss: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);
	assert_eq!(
		hybrid_shared_secret(&mlkem_ss, &x25519_ss).as_slice(),
		h("0c50a2bff4ba1ccda2d944f459af5d7d61ca5a291c8d9d032fc397bfe14ed20a").as_slice(),
	);
}

#[test]
fn hybrid_handshake_end_to_end() {
	// Full initiator/responder flow over both components, as the
	// validator-channel handshake wrapper will drive it.
	use x25519_dalek::{PublicKey, StaticSecret};

	// Responder: long-lived-ish handshake material.
	let r_mlkem_seed = [0x42u8; MLKEM768_SEED_BYTES];
	let (r_dk, r_ek_bytes) = mlkem_keypair_from_seed(&r_mlkem_seed);
	let r_x = StaticSecret::from([0x24u8; 32]);
	let r_x_pub = PublicKey::from(&r_x);

	// Initiator: encapsulates to the responder's ek, does X25519.
	let i_x = StaticSecret::from([0x33u8; 32]);
	let i_x_pub = PublicKey::from(&i_x);
	let m = [0x55u8; 32]; // fresh CSPRNG in production
	let (ct, i_mlkem_ss) = mlkem_encapsulate(&r_ek_bytes, &m).expect("valid ek");
	let i_hybrid = hybrid_shared_secret(&i_mlkem_ss, i_x.diffie_hellman(&r_x_pub).as_bytes());

	// Responder: decapsulates the ciphertext, does X25519.
	let r_mlkem_ss = mlkem_decapsulate(&r_dk, &ct).expect("valid ct");
	let r_hybrid = hybrid_shared_secret(&r_mlkem_ss, r_x.diffie_hellman(&i_x_pub).as_bytes());

	assert_eq!(i_hybrid, r_hybrid);

	// A mangled ciphertext must not error (implicit rejection) but must
	// yield a different secret, failing the handshake at the AEAD.
	let mut bad_ct = ct;
	bad_ct[0] ^= 1;
	let garbage = mlkem_decapsulate(&r_dk, &bad_ct).expect("implicit rejection");
	assert_ne!(garbage, r_mlkem_ss);
}
