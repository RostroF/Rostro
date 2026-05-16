// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Round-trip self-consistency tests for the IETF↔arkworks BLS12-381
//! point codec.
//!
//! The property we're proving: encode-then-decode (and decode-then-
//! encode) is the identity function for every valid input. If this
//! holds for arbitrary random points AND for the explicitly-handled
//! infinity case, the encoder and decoder agree on the format.
//!
//! That alone doesn't prove the format matches Ethereum's transcript
//! byte-for-byte — that's a follow-up commit grounding-out against
//! published BLS12-381 test vectors and (later) a real transcript.
//! What it does prove is internal consistency, which is the
//! load-bearing property for everything downstream of the codec
//! (PcsParams construction, RingProofParams, chain-spec hash).

use ark_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rostro_kzg_srs::{
	build_pcs_params, build_ring_proof_params_from_pcs, decode_ietf_g1, decode_ietf_g2,
	encode_ietf_g1, encode_ietf_g2, ring_proof_params_sha256, Error, G1_COMPRESSED_LEN,
	G2_COMPRESSED_LEN, RING_SIZE,
};

// ─── Codec round-trip ─────────────────────────────────────────────────────

#[test]
fn g1_round_trip_random_points() {
	let mut rng = ChaCha20Rng::from_seed([0xA1; 32]);
	for i in 0..50 {
		let p = G1Projective::rand(&mut rng).into_affine();
		let bytes = encode_ietf_g1(&p);
		let p2 = decode_ietf_g1(&bytes)
			.unwrap_or_else(|e| panic!("iter {i}: decode failed: {e:?}"));
		assert_eq!(p, p2, "iter {i}: round-trip diverged");
	}
}

#[test]
fn g2_round_trip_random_points() {
	let mut rng = ChaCha20Rng::from_seed([0xA2; 32]);
	for i in 0..50 {
		let p = G2Projective::rand(&mut rng).into_affine();
		let bytes = encode_ietf_g2(&p);
		let p2 = decode_ietf_g2(&bytes)
			.unwrap_or_else(|e| panic!("iter {i}: decode failed: {e:?}"));
		assert_eq!(p, p2, "iter {i}: round-trip diverged");
	}
}

#[test]
fn g1_round_trip_infinity() {
	let inf = G1Affine::zero();
	let bytes = encode_ietf_g1(&inf);
	// Compression + infinity, all other bits zero.
	assert_eq!(bytes[0], 0xC0);
	assert!(bytes[1..].iter().all(|&b| b == 0));
	let inf2 = decode_ietf_g1(&bytes).unwrap();
	assert_eq!(inf, inf2);
}

#[test]
fn g2_round_trip_infinity() {
	let inf = G2Affine::zero();
	let bytes = encode_ietf_g2(&inf);
	assert_eq!(bytes[0], 0xC0);
	assert!(bytes[1..].iter().all(|&b| b == 0));
	let inf2 = decode_ietf_g2(&bytes).unwrap();
	assert_eq!(inf, inf2);
}

#[test]
fn g1_round_trip_generator() {
	let g = G1Projective::generator().into_affine();
	let bytes = encode_ietf_g1(&g);
	let g2 = decode_ietf_g1(&bytes).unwrap();
	assert_eq!(g, g2);
}

#[test]
fn g2_round_trip_generator() {
	let g = G2Projective::generator().into_affine();
	let bytes = encode_ietf_g2(&g);
	let g2 = decode_ietf_g2(&bytes).unwrap();
	assert_eq!(g, g2);
}

// ─── Decoder rejects malformed inputs ────────────────────────────────────

#[test]
fn g1_decoder_rejects_uncompressed_flag() {
	// Encode a real point, then strip the compression flag.
	let mut rng = ChaCha20Rng::from_seed([1; 32]);
	let p = G1Projective::rand(&mut rng).into_affine();
	let mut bytes = encode_ietf_g1(&p);
	bytes[0] &= !0x80;
	let err = decode_ietf_g1(&bytes).unwrap_err();
	assert!(matches!(err, Error::NotCompressed));
}

#[test]
fn g1_decoder_rejects_malformed_infinity() {
	let mut bytes = [0u8; G1_COMPRESSED_LEN];
	bytes[0] = 0xC0; // compression + infinity
	bytes[5] = 0xFF; // junk in trailing bytes — not allowed
	let err = decode_ietf_g1(&bytes).unwrap_err();
	assert!(matches!(err, Error::MalformedInfinity));
}

#[test]
fn g2_decoder_rejects_malformed_infinity() {
	let mut bytes = [0u8; G2_COMPRESSED_LEN];
	bytes[0] = 0xC0;
	bytes[60] = 0x01;
	let err = decode_ietf_g2(&bytes).unwrap_err();
	assert!(matches!(err, Error::MalformedInfinity));
}

// ─── Synthetic transcript end-to-end ───────────────────────────────────────

/// Synthesize what an Ethereum-style transcript would look like (random
/// G1/G2 powers serialized in IETF format), then run the full pipeline:
/// IETF bytes → arkworks points → PcsParams → RingProofParams → SHA-256.
///
/// If this passes, R3's chainspec generation can swap the synthetic
/// generation for real Ethereum bytes and the rest of the pipeline is
/// unchanged.
#[test]
fn end_to_end_synthetic_transcript_pipeline() {
	let mut rng = ChaCha20Rng::from_seed([0xE7; 32]);

	// Sassafras at RING_SIZE=512 needs pcs_domain_size(512) = 3073 G1
	// powers (3 * piop_domain_size + 1, where piop_domain_size = 1024 =
	// (512 + 4 + 252).next_power_of_two() for bandersnatch's 252-bit
	// scalar field). Comfortably inside Ethereum's 4096-power EIP-4844
	// ceremony output.
	let n_g1 = 3073;
	let n_g2 = 65;

	// Step 1: synthesize IETF-formatted transcript bytes.
	let g1_transcript: Vec<[u8; G1_COMPRESSED_LEN]> = (0..n_g1)
		.map(|_| {
			let p = G1Projective::rand(&mut rng).into_affine();
			encode_ietf_g1(&p)
		})
		.collect();
	let g2_transcript: Vec<[u8; G2_COMPRESSED_LEN]> = (0..n_g2)
		.map(|_| {
			let p = G2Projective::rand(&mut rng).into_affine();
			encode_ietf_g2(&p)
		})
		.collect();

	// Step 2: parse the IETF bytes back into arkworks points.
	let g1_points: Vec<G1Affine> =
		g1_transcript.iter().map(|b| decode_ietf_g1(b).expect("g1 decode")).collect();
	let g2_points: Vec<G2Affine> =
		g2_transcript.iter().map(|b| decode_ietf_g2(b).expect("g2 decode")).collect();

	// Step 3: build PcsParams (sufficiency check happens here).
	let pcs_params = build_pcs_params(g1_points, g2_points, RING_SIZE).expect("pcs params");

	// Step 4: build RingProofParams. THIS is the function that R3
	// chainspec generation calls with real Ethereum bytes.
	let ring_params =
		build_ring_proof_params_from_pcs(RING_SIZE, pcs_params).expect("ring proof params");

	// Step 5: derive the chainspec hash. Stable across runs given the
	// same input → same hash.
	let hash1 = ring_proof_params_sha256(&ring_params);

	// Determinism check: rebuild from the *same* transcript bytes,
	// confirm identical hash.
	let g1_points2: Vec<G1Affine> =
		g1_transcript.iter().map(|b| decode_ietf_g1(b).unwrap()).collect();
	let g2_points2: Vec<G2Affine> =
		g2_transcript.iter().map(|b| decode_ietf_g2(b).unwrap()).collect();
	let pcs2 = build_pcs_params(g1_points2, g2_points2, RING_SIZE).unwrap();
	let ring_params2 = build_ring_proof_params_from_pcs(RING_SIZE, pcs2).unwrap();
	let hash2 = ring_proof_params_sha256(&ring_params2);

	assert_eq!(
		hash1, hash2,
		"identical transcript bytes must produce identical chainspec hash"
	);
}

#[test]
fn pcs_params_rejects_insufficient_g1() {
	let g1_points: Vec<G1Affine> = (0..10).map(|_| G1Affine::zero()).collect();
	let g2_points: Vec<G2Affine> = vec![G2Affine::zero(); 2];
	let err = build_pcs_params(g1_points, g2_points, RING_SIZE).unwrap_err();
	assert!(matches!(err, Error::InsufficientG1Powers { .. }));
}

#[test]
fn pcs_params_rejects_insufficient_g2() {
	// Need ≥ pcs_domain_size(512) = 3073 G1 to clear that check first.
	let g1_points: Vec<G1Affine> = (0..3073).map(|_| G1Affine::zero()).collect();
	let g2_points: Vec<G2Affine> = vec![G2Affine::zero(); 1]; // need 2
	let err = build_pcs_params(g1_points, g2_points, RING_SIZE).unwrap_err();
	assert!(matches!(err, Error::InsufficientG2Powers(1)));
}
