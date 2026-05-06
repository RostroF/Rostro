// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Ground-truth tests against the IETF/RFC-9380 BLS12-381 spec and the
//! actual EIP-4844 trusted-setup transcript shipped by
//! `ethereum/c-kzg-4844`.
//!
//! ## Why both layers
//!
//! The `round_trip.rs` test file proves codec self-consistency:
//! encode-then-decode is identity. That's load-bearing but it does not
//! prove our codec agrees with the spec — encoder and decoder could
//! both be wrong in a self-consistent way (e.g. swapped y-sign
//! convention).
//!
//! This file closes that gap two ways:
//!
//! 1. **Generator point check**: the BLS12-381 G1/G2 generator points
//!    have published canonical IETF compressed encodings (ZCash spec /
//!    EIP-2537). We recompute the encoding through our codec and
//!    require byte-equality with the published constant. If our codec
//!    deviated from spec on the y-sign convention, this fails.
//!
//! 2. **Real transcript check**: every G1 and G2 point in Ethereum's
//!    actual EIP-4844 trusted-setup file gets parsed through our
//!    codec, re-encoded through our codec, and the re-encoded bytes
//!    are required to be byte-identical to the input bytes from
//!    Ethereum's transcript. ~8200 points across both Lagrange and
//!    monomial sections. If even one bit differs anywhere, the assert
//!    fires.
//!
//! Either layer alone might miss something. Together they bracket the
//! codec's correctness firmly.
//!
//! ## Fixture provenance
//!
//! `tests/fixtures/eip4844_trusted_setup.txt` is the trusted-setup
//! file from `ethereum/c-kzg-4844`, fetched from
//! `https://raw.githubusercontent.com/ethereum/c-kzg-4844/main/src/trusted_setup.txt`.
//! SHA-256 documented in the test below; if upstream rotates the file,
//! that hash should be updated alongside the fixture refresh.

use ark_bls12_381::{G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use rostro_kzg_srs::{
	build_pcs_params, build_ring_proof_params_from_pcs, decode_ietf_g1, decode_ietf_g2,
	encode_ietf_g1, encode_ietf_g2, ring_proof_params_sha256,
	transcript::{parse_eip4844_setup, verify_byte_identical_round_trip},
	G1_COMPRESSED_LEN, G2_COMPRESSED_LEN, RING_SIZE,
};
use sha2::{Digest, Sha256};

// ─── Spec-published constants ─────────────────────────────────────────────

/// BLS12-381 G1 generator in IETF compressed encoding. Canonical value
/// from ZCash BLS12-381 specification + EIP-2537. The leading 0x97
/// decomposes as: 0b1001_0111 = compression flag (1) | infinity flag
/// (0) | y-sign flag (0) | high 5 bits of x-coordinate (0b10111 =
/// 0x17). Y-sign 0 means y < -y in the canonical ordering, which
/// matches the spec's choice.
const G1_GENERATOR_IETF_HEX: &str =
	"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

/// BLS12-381 G2 generator in IETF compressed encoding. 96 bytes; first
/// 48 bytes encode c1 of x (with flags in the top byte), second 48
/// bytes encode c0 of x. Canonical value from ZCash spec + EIP-2537.
const G2_GENERATOR_IETF_HEX: &str = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

/// SHA-256 of the EIP-4844 trusted-setup file as fetched from
/// ethereum/c-kzg-4844 main branch on 2026-05-05. If the fixture is
/// refreshed from upstream, recompute and update.
const EIP4844_FIXTURE_SHA256: &str =
	"d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7";

/// Pinned chainspec hash for the EIP-4844 trusted setup truncated to
/// RING_SIZE=512 (3073 G1 monomial powers, 2 G2 monomial powers),
/// passed through `RingProofParams::from_pcs_params` and SHA-256'd
/// over arkworks' canonical uncompressed encoding.
///
/// This is the hash that R3 chainspec generation will write into
/// `UrsSource::EthereumKzgCeremony2023.srs_hash`. Pinning it here as a
/// regression check: if our codec, parser, or any arkworks-version
/// upgrade affects the bit-level output, this assertion trips.
const PINNED_CHAINSPEC_HASH: &str =
	"6fd78bb063a66012b84aa8f7a560915b05b3f30c19c342bd59e4334285f98263";

// ─── Generator-point ground truth ─────────────────────────────────────────

#[test]
fn g1_generator_matches_ietf_spec() {
	let expected = hex_to_array_48(G1_GENERATOR_IETF_HEX);
	let g = G1Projective::generator().into_affine();
	let our_bytes = encode_ietf_g1(&g);
	assert_eq!(
		our_bytes, expected,
		"G1 generator IETF encoding must match the canonical ZCash/EIP-2537 spec value"
	);

	// And the reverse: spec bytes round-trip through our decoder back
	// to the actual generator.
	let decoded = decode_ietf_g1(&expected).expect("spec G1 generator should decode");
	assert_eq!(decoded, g, "decoded spec G1 generator must equal arkworks generator");
}

#[test]
fn g2_generator_matches_ietf_spec() {
	let expected = hex_to_array_96(G2_GENERATOR_IETF_HEX);
	let g = G2Projective::generator().into_affine();
	let our_bytes = encode_ietf_g2(&g);
	assert_eq!(
		our_bytes, expected,
		"G2 generator IETF encoding must match the canonical ZCash/EIP-2537 spec value"
	);

	let decoded = decode_ietf_g2(&expected).expect("spec G2 generator should decode");
	assert_eq!(decoded, g, "decoded spec G2 generator must equal arkworks generator");
}

// ─── EIP-4844 trusted-setup ground truth ──────────────────────────────────

const FIXTURE: &str =
	include_str!("../tests/fixtures/eip4844_trusted_setup.txt");

#[test]
fn fixture_sha256_matches_documented_value() {
	let actual = hex::encode(Sha256::digest(FIXTURE.as_bytes()));
	assert_eq!(
		actual.as_str(),
		EIP4844_FIXTURE_SHA256,
		"trusted-setup fixture SHA-256 mismatch — fixture has been modified or replaced"
	);
}

#[test]
fn eip4844_transcript_round_trips_byte_identical() {
	let verified = verify_byte_identical_round_trip(FIXTURE)
		.expect("EIP-4844 transcript must parse + round-trip cleanly");

	// 4096 G1 Lagrange + 65 G2 monomial + 4096 G1 monomial = 8257 points.
	assert_eq!(
		verified, 8257,
		"expected 8257 round-trip-verified points (4096 + 65 + 4096); got {verified}"
	);
}

#[test]
fn eip4844_transcript_builds_pcs_params_and_ring_context() {
	let setup = parse_eip4844_setup(FIXTURE).expect("transcript parses");

	assert_eq!(setup.powers_in_g1_monomial.len(), 4096);
	assert_eq!(setup.powers_in_g2_monomial.len(), 65);

	// Truncate to what RING_SIZE=512 needs: 3073 G1, 2 G2.
	let mut g1 = setup.powers_in_g1_monomial;
	g1.truncate(3073);
	let mut g2 = setup.powers_in_g2_monomial;
	g2.truncate(2);

	let pcs = build_pcs_params(g1, g2, RING_SIZE).expect("PcsParams build");
	let ring = build_ring_proof_params_from_pcs(RING_SIZE, pcs)
		.expect("RingProofParams build from real EIP-4844 transcript");

	let hash = ring_proof_params_sha256(&ring);
	let hash_hex = hex::encode(hash);

	// Pinned regression: this is the hash R3 chainspec generation will
	// embed in `UrsSource::EthereumKzgCeremony2023.srs_hash`. Any
	// codec / parser / arkworks-version change that affects bit-level
	// output trips this assertion.
	assert_eq!(
		hash_hex.as_str(),
		PINNED_CHAINSPEC_HASH,
		"EIP-4844 chainspec hash drifted — investigate before merging"
	);

	// Determinism: rebuild from the *same* fixture bytes, must match.
	let setup2 = parse_eip4844_setup(FIXTURE).unwrap();
	let mut g1_2 = setup2.powers_in_g1_monomial;
	g1_2.truncate(3073);
	let mut g2_2 = setup2.powers_in_g2_monomial;
	g2_2.truncate(2);
	let pcs2 = build_pcs_params(g1_2, g2_2, RING_SIZE).unwrap();
	let ring2 = build_ring_proof_params_from_pcs(RING_SIZE, pcs2).unwrap();
	assert_eq!(hash, ring_proof_params_sha256(&ring2), "chainspec hash must be deterministic");
}

#[test]
fn eip4844_g1_monomial_first_entry_is_generator() {
	// Sanity check: the first monomial G1 power g^τ^0 = g must be the
	// curve generator. This is true for any KZG ceremony that didn't
	// tamper with the seed.
	let setup = parse_eip4844_setup(FIXTURE).expect("transcript parses");
	let g = G1Projective::generator().into_affine();
	assert_eq!(
		setup.powers_in_g1_monomial[0], g,
		"first monomial G1 power must be the BLS12-381 generator"
	);
}

#[test]
fn eip4844_g2_monomial_first_entry_is_generator() {
	let setup = parse_eip4844_setup(FIXTURE).expect("transcript parses");
	let g = G2Projective::generator().into_affine();
	assert_eq!(
		setup.powers_in_g2_monomial[0], g,
		"first monomial G2 power must be the BLS12-381 G2 generator"
	);
}

// ─── Hex helpers ──────────────────────────────────────────────────────────

fn hex_to_array_48(s: &str) -> [u8; G1_COMPRESSED_LEN] {
	assert_eq!(s.len(), 96);
	let mut out = [0u8; G1_COMPRESSED_LEN];
	for i in 0..G1_COMPRESSED_LEN {
		out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
	}
	out
}

fn hex_to_array_96(s: &str) -> [u8; G2_COMPRESSED_LEN] {
	assert_eq!(s.len(), 192);
	let mut out = [0u8; G2_COMPRESSED_LEN];
	for i in 0..G2_COMPRESSED_LEN {
		out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
	}
	out
}
