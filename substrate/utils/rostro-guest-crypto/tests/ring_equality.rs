// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! W3 consensus gate (docs/RVM-VERIFY-INTRINSICS.md §6): ring artifacts and
//! VRF outputs from the VENDORED ark-vrf (hooked curves, RostroCurveHooks)
//! must equal PLAIN upstream ark-vrf byte-for-byte. Any divergence between
//! the hooked and plain constructions is a consensus split.
//!
//! The upstream reference is registry ark-vrf 0.1.0 (cargo cannot hold two
//! same-version sources of one package; the 0.1.0 → 0.1.1 delta is
//! docs/formatting only — verified at vendoring time). The vendored crate's
//! own `vectors_process` tests additionally pin the hooked stack to the
//! upstream-published test vectors.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_vrf::suites::bandersnatch as hooked;
use ark_vrf_upstream::suites::bandersnatch as plain;

const RING_SIZE: usize = 16;
const SRS_SEED: [u8; 32] = [7u8; 32];

fn ser<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
	let mut buf = Vec::new();
	t.serialize_compressed(&mut buf).expect("serialize");
	buf
}

#[test]
fn vrf_input_output_and_ietf_proof_equal() {
	let h_secret = hooked::Secret::from_seed(b"w3-gate");
	let p_secret = plain::Secret::from_seed(b"w3-gate");
	assert_eq!(ser(&h_secret.public().0), ser(&p_secret.public().0), "public key");

	// Input::new runs data_to_point — this pins the vendored Elligator2
	// plain-map + coordinate-copy deviation.
	let h_input = hooked::Input::new(b"w3 gate input").expect("input");
	let p_input = plain::Input::new(b"w3 gate input").expect("input");
	assert_eq!(ser(&h_input.0), ser(&p_input.0), "hash-to-curve input point");

	let h_output = h_secret.output(h_input);
	let p_output = p_secret.output(p_input);
	assert_eq!(ser(&h_output.0), ser(&p_output.0), "VRF output point");
	assert_eq!(h_output.hash()[..32], p_output.hash()[..32], "VRF output hash");

	// IETF proof: deterministic nonce (RFC 9381 §5.4.2.2) → byte-comparable.
	let h_proof = {
		use ark_vrf::ietf::Prover;
		h_secret.prove(h_input, h_output, b"gate ad")
	};
	let p_proof = {
		use ark_vrf_upstream::ietf::Prover;
		p_secret.prove(p_input, p_output, b"gate ad")
	};
	assert_eq!(ser(&h_proof), ser(&p_proof), "IETF proof");
}

#[test]
fn ring_artifacts_equal_and_proofs_interop() {
	// Same URS seed → same trusted-setup powers; the URS construction
	// itself runs group operations, so this also gates the hooks inside
	// parameter generation.
	let h_params = hooked::RingProofParams::from_seed(RING_SIZE, SRS_SEED);
	let p_params = plain::RingProofParams::from_seed(RING_SIZE, SRS_SEED);
	assert_eq!(ser(&h_params), ser(&p_params), "ring proof params (URS + piop)");

	let h_pks: Vec<_> = (0..RING_SIZE as u64)
		.map(|i| hooked::Secret::from_seed(&i.to_le_bytes()).public().0)
		.collect();
	let p_pks: Vec<_> = (0..RING_SIZE as u64)
		.map(|i| plain::Secret::from_seed(&i.to_le_bytes()).public().0)
		.collect();

	// THE consensus artifact: pallet-sassafras' update_ring_verifier builds
	// exactly this from the next session's authority keys.
	let h_vk = h_params.verifier_key(&h_pks);
	let p_vk = p_params.verifier_key(&p_pks);
	assert_eq!(ser(&h_vk), ser(&p_vk), "ring verifier key");
	assert_eq!(
		ser(&h_vk.commitment()),
		ser(&p_vk.commitment()),
		"ring commitment (on-chain form)"
	);

	// Wire interop: a ring proof produced by the hooked stack must verify
	// under the plain stack (and vice versa). Ring proofs are blinded, so
	// bytes are compared only across the serialize/deserialize boundary,
	// not across stacks.
	let idx = 3usize;
	let h_secret = hooked::Secret::from_seed(&(idx as u64).to_le_bytes());
	let h_input = hooked::Input::new(b"ring gate input").expect("input");
	let h_output = h_secret.output(h_input);
	let h_proof = {
		use ark_vrf::ring::Prover;
		let prover = h_params.prover(h_params.prover_key(&h_pks), idx);
		h_secret.prove(h_input, h_output, b"ring ad", &prover)
	};
	{
		use ark_vrf_upstream::ring::Verifier;
		let proof = plain::RingProof::deserialize_compressed(&ser(&h_proof)[..])
			.expect("hooked ring proof deserializes as plain");
		let input = plain::Input::new(b"ring gate input").expect("input");
		let output = plain::Output::from(
			ark_vrf_upstream::AffinePoint::<plain::BandersnatchSha512Ell2>::deserialize_compressed(
				&ser(&h_output.0)[..],
			)
			.expect("output point"),
		);
		let verifier = p_params.verifier(p_vk);
		plain::Public::verify(input, output, b"ring ad", &proof, &verifier)
			.expect("hooked ring proof verifies under the plain stack");
	}

	// And the reverse direction.
	let p_secret = plain::Secret::from_seed(&(idx as u64).to_le_bytes());
	let p_input = plain::Input::new(b"ring gate input").expect("input");
	let p_output = p_secret.output(p_input);
	let p_proof = {
		use ark_vrf_upstream::ring::Prover;
		let prover = p_params.prover(p_params.prover_key(&p_pks), idx);
		p_secret.prove(p_input, p_output, b"ring ad", &prover)
	};
	{
		use ark_vrf::ring::Verifier;
		let proof = hooked::RingProof::deserialize_compressed(&ser(&p_proof)[..])
			.expect("plain ring proof deserializes as hooked");
		let input = hooked::Input::new(b"ring gate input").expect("input");
		let output = hooked::Output::from(
			ark_vrf::AffinePoint::<hooked::BandersnatchSha512Ell2>::deserialize_compressed(
				&ser(&p_output.0)[..],
			)
			.expect("output point"),
		);
		let verifier = h_params.verifier(h_vk);
		hooked::Public::verify(input, output, b"ring ad", &proof, &verifier)
			.expect("plain ring proof verifies under the hooked stack");
	}
}
