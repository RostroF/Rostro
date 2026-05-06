// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-kzg-srs
//!
//! Phase Ring R1.5 verification spike: prove that a KZG SRS — Ethereum's
//! published EIP-4844 ceremony output, or a synthetic equivalent —
//! converts cleanly into the bandersnatch ring context that
//! `pallet-sassafras` consumes.
//!
//! ## Why custom tooling
//!
//! Ethereum's transcript serializes BLS12-381 G1/G2 points using the
//! IETF/CFRG compressed encoding ([RFC 9380] / [EIP-2537]). arkworks
//! uses its own canonical compressed encoding. Both are 48 bytes for G1
//! / 96 bytes for G2, and both encode the same x-coordinate, but the
//! flag-bit layouts differ. We could try to find an existing crate
//! that bridges them, or we can write the bridge ourselves and
//! self-prove it by **round-trip**:
//!
//! - `arkworks G1Affine → encode_ietf_g1 → bytes → decode_ietf_g1 →
//!   arkworks G1Affine` should be the identity for every valid point.
//!
//! If round-trip is identity for arbitrary random points (and for the
//! point at infinity), the encoder and decoder are mutually correct.
//! That doesn't *prove* the format matches the IETF spec on its own —
//! that's grounded out by checking against published BLS12-381 test
//! vectors (next commit) — but it proves the bridge is internally
//! consistent, which is the load-bearing property for the rest of R1.5.
//!
//! ## What this commit lands
//!
//! - IETF compressed encoding for G1 + G2 with explicit handling of
//!   compression / infinity / y-sign flags
//! - Round-trip self-consistency tests (random points + infinity)
//! - End-to-end pipeline test: synthetic IETF bytes → parse → PcsParams
//!   → RingProofParams → SHA-256 chainspec hash, exercised at the
//!   actual production size (`pcs_domain_size(1024) = 6145` G1 powers).
//! - Sufficiency error variants (`InsufficientG1Powers`,
//!   `InsufficientG2Powers`) so chainspec generation can fail loudly
//!   rather than silently truncating.
//!
//! ## R1.5 empirical finding + the RING_SIZE=512 decision
//!
//! The ark-vrf formula `pcs_domain_size(R) = 3 * piop_domain_size(R) +
//! 1` with `piop_domain_size(R) = (R + 4 + 252).next_power_of_two()`
//! (252 = bandersnatch scalar bit size) gives the URS-power cliff:
//!
//! | RING_SIZE | G1 powers needed | Validator ceiling | Ethereum SRS (4096) fits? |
//! |-----------|------------------|-------------------|---------------------------|
//! |       256 |             1537 |         up to 256 | ✓                         |
//! |   **512** |         **3073** |     **up to 512** | **✓** (R5/v1 choice)      |
//! |       768 |             4097 |         up to 768 | ✗ by one power            |
//! |      1024 |             6145 |        up to 1024 | ✗                         |
//!
//! Rostro v1 sets RING_SIZE = 512 — Ethereum's ceremony fits with
//! headroom, the validator ceiling is ample for any plausible early-
//! network NPoS validator count, and if Rostro outgrows it the
//! scale-up path is a runtime upgrade with a fresh ceremony at higher
//! degree (which by then will likely have published options we don't
//! have today).
//!
//! Rationale + the upgrade path are documented at the constant's
//! source (`sp_consensus_sassafras::vrf::RING_SIZE`). This crate's
//! pipeline is parametric in [`RING_SIZE`] — bumping the constant
//! upstream propagates here automatically, no code changes in this
//! crate when the v2 ceremony lands.
//!
//! [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380
//! [EIP-2537]: https://eips.ethereum.org/EIPS/eip-2537

#![warn(missing_docs)]

pub mod transcript;

use ark_bls12_381::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use ark_vrf::{
	ring::{pcs_domain_size, PcsParams, RingProofParams},
	suites::bandersnatch::BandersnatchSha512Ell2,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Sassafras's fixed ring size, re-exported from the canonical
/// definition in `sp_consensus_sassafras`. v1 is **512**; rationale and
/// scale-up path documented at the constant's source.
pub use sp_consensus_sassafras::vrf::RING_SIZE;

/// Compressed G1 point length on BLS12-381 (IETF and arkworks both 48).
pub const G1_COMPRESSED_LEN: usize = 48;
/// Compressed G2 point length on BLS12-381 (IETF and arkworks both 96).
pub const G2_COMPRESSED_LEN: usize = 96;

/// IETF compression flag — set when bytes encode a compressed point.
const FLAG_COMPRESSION: u8 = 0x80;
/// IETF infinity flag — set when point is the identity (only with compression).
const FLAG_INFINITY: u8 = 0x40;
/// IETF y-sign flag — set when y > -y in the canonical (non-Montgomery) ordering.
const FLAG_Y_SIGN: u8 = 0x20;
/// Mask for the three flag bits — clearing these recovers the x-coordinate top byte.
const FLAG_MASK: u8 = FLAG_COMPRESSION | FLAG_INFINITY | FLAG_Y_SIGN;

/// The bandersnatch suite Sassafras uses. Re-exported so consumers
/// don't have to depend on `ark-vrf` directly.
pub type BandersnatchSuite = BandersnatchSha512Ell2;

/// PCS params (`URS<Bls12_381>`) consumed by `RingProofParams::from_pcs_params`.
pub type BandersnatchPcsParams = PcsParams<BandersnatchSuite>;

/// Ring proof params (the full bandersnatch ring context).
pub type BandersnatchRingProofParams = RingProofParams<BandersnatchSuite>;

/// Errors the spike can surface.
#[derive(Debug, Error)]
pub enum Error {
	/// Insufficient G1 powers for the requested ring size.
	#[error("KZG transcript provides {provided} G1 powers; need at least {required} for ring size {ring_size}")]
	InsufficientG1Powers {
		/// Requested ring size.
		ring_size: usize,
		/// Required G1 powers count for this ring size.
		required: usize,
		/// Actually provided count.
		provided: usize,
	},
	/// Insufficient G2 powers (need at least 2 for KZG verification).
	#[error("KZG transcript provides {0} G2 powers; need at least 2")]
	InsufficientG2Powers(usize),
	/// Compression flag missing — uncompressed encoding not accepted.
	#[error("compression flag not set; uncompressed BLS12-381 encoding is not accepted")]
	NotCompressed,
	/// Infinity point with non-zero remaining bytes.
	#[error("infinity flag set but trailing bytes are non-zero")]
	MalformedInfinity,
	/// x-coordinate doesn't fit in field (≥ p).
	#[error("x-coordinate is not a valid field element (≥ p)")]
	XOutOfRange,
	/// y² has no square root in the field — point is not on the curve.
	#[error("y² has no square root: x is not on the curve")]
	NotOnCurve,
	/// Resulting point is on curve but not in the prime-order subgroup.
	#[error("point is on the curve but not in the prime-order subgroup")]
	NotInSubgroup,
	/// Underlying `RingProofParams::from_pcs_params` failed.
	#[error("ring proof params construction failed: PcsParams was not large enough or malformed")]
	RingProofParamsConstruction,
}

// ─── IETF G1 codec ─────────────────────────────────────────────────────────

/// Encode an arkworks `G1Affine` to its 48-byte IETF compressed form.
///
/// Layout:
/// - byte 0 high bits: compression (1) ‖ infinity ‖ y-sign
/// - bytes 0..48: 381-bit x-coordinate big-endian, with the top 3 bits
///   used as flags
pub fn encode_ietf_g1(point: &G1Affine) -> [u8; G1_COMPRESSED_LEN] {
	let mut out = [0u8; G1_COMPRESSED_LEN];
	if point.is_zero() {
		out[0] = FLAG_COMPRESSION | FLAG_INFINITY;
		return out;
	}
	let (x, y) = point.xy().expect("non-infinity has xy; qed");
	let x_bytes = fq_to_be_bytes_48(&x);
	out.copy_from_slice(&x_bytes);
	out[0] |= FLAG_COMPRESSION;
	if y_is_lex_larger_fq(&y) {
		out[0] |= FLAG_Y_SIGN;
	}
	out
}

/// Decode a 48-byte IETF-compressed point into `G1Affine`. Validates
/// compression flag, x-coord range, on-curve, and prime-order subgroup.
pub fn decode_ietf_g1(bytes: &[u8; G1_COMPRESSED_LEN]) -> Result<G1Affine, Error> {
	let flags = bytes[0] & FLAG_MASK;
	if flags & FLAG_COMPRESSION == 0 {
		return Err(Error::NotCompressed);
	}
	if flags & FLAG_INFINITY != 0 {
		if bytes[0] != (FLAG_COMPRESSION | FLAG_INFINITY) || bytes[1..].iter().any(|&b| b != 0) {
			return Err(Error::MalformedInfinity);
		}
		return Ok(G1Affine::zero());
	}
	let y_sign = flags & FLAG_Y_SIGN != 0;

	let mut x_bytes = *bytes;
	x_bytes[0] &= !FLAG_MASK;
	let x = fq_from_be_bytes_strict(&x_bytes)?;

	// y² = x³ + 4
	let y_sq = x.square() * x + Fq::from(4u32);
	let y = y_sq.sqrt().ok_or(Error::NotOnCurve)?;
	let y_chosen = if y_sign == y_is_lex_larger_fq(&y) { y } else { -y };

	let point = G1Affine::new_unchecked(x, y_chosen);
	if !point.is_on_curve() {
		return Err(Error::NotOnCurve);
	}
	if !point.is_in_correct_subgroup_assuming_on_curve() {
		return Err(Error::NotInSubgroup);
	}
	Ok(point)
}

// ─── IETF G2 codec ─────────────────────────────────────────────────────────

/// Encode an arkworks `G2Affine` to its 96-byte IETF compressed form.
///
/// G2 layout: bytes 0..48 = c1 (imaginary part of x), bytes 48..96 = c0
/// (real part). Flags occupy the top 3 bits of byte 0 (i.e. the top of
/// c1's encoding).
pub fn encode_ietf_g2(point: &G2Affine) -> [u8; G2_COMPRESSED_LEN] {
	let mut out = [0u8; G2_COMPRESSED_LEN];
	if point.is_zero() {
		out[0] = FLAG_COMPRESSION | FLAG_INFINITY;
		return out;
	}
	let (x, y) = point.xy().expect("non-infinity has xy; qed");
	let c1_bytes = fq_to_be_bytes_48(&x.c1);
	let c0_bytes = fq_to_be_bytes_48(&x.c0);
	out[..48].copy_from_slice(&c1_bytes);
	out[48..].copy_from_slice(&c0_bytes);
	out[0] |= FLAG_COMPRESSION;
	if y_is_lex_larger_fq2(&y) {
		out[0] |= FLAG_Y_SIGN;
	}
	out
}

/// Decode a 96-byte IETF-compressed point into `G2Affine`.
pub fn decode_ietf_g2(bytes: &[u8; G2_COMPRESSED_LEN]) -> Result<G2Affine, Error> {
	let flags = bytes[0] & FLAG_MASK;
	if flags & FLAG_COMPRESSION == 0 {
		return Err(Error::NotCompressed);
	}
	if flags & FLAG_INFINITY != 0 {
		if bytes[0] != (FLAG_COMPRESSION | FLAG_INFINITY) || bytes[1..].iter().any(|&b| b != 0) {
			return Err(Error::MalformedInfinity);
		}
		return Ok(G2Affine::zero());
	}
	let y_sign = flags & FLAG_Y_SIGN != 0;

	let mut c1_bytes = [0u8; 48];
	c1_bytes.copy_from_slice(&bytes[..48]);
	c1_bytes[0] &= !FLAG_MASK;
	let c1 = fq_from_be_bytes_strict(&c1_bytes)?;

	let mut c0_bytes = [0u8; 48];
	c0_bytes.copy_from_slice(&bytes[48..]);
	let c0 = fq_from_be_bytes_strict(&c0_bytes)?;

	let x = Fq2::new(c0, c1);

	// y² = x³ + 4(1+u). In Fq2: 4(1+u) = (4, 4).
	let y_sq = x.square() * x + Fq2::new(Fq::from(4u32), Fq::from(4u32));
	let y = y_sq.sqrt().ok_or(Error::NotOnCurve)?;
	let y_chosen = if y_sign == y_is_lex_larger_fq2(&y) { y } else { -y };

	let point = G2Affine::new_unchecked(x, y_chosen);
	if !point.is_on_curve() {
		return Err(Error::NotOnCurve);
	}
	if !point.is_in_correct_subgroup_assuming_on_curve() {
		return Err(Error::NotInSubgroup);
	}
	Ok(point)
}

// ─── Field-element helpers ─────────────────────────────────────────────────

/// Big-endian 48-byte encoding of an Fq element in canonical (non-Montgomery)
/// form.
fn fq_to_be_bytes_48(x: &Fq) -> [u8; 48] {
	let mut bytes = x.into_bigint().to_bytes_be();
	// `to_bytes_be` returns the minimum byte representation; left-pad to 48.
	while bytes.len() < 48 {
		bytes.insert(0, 0);
	}
	bytes.truncate(48);
	let mut out = [0u8; 48];
	out.copy_from_slice(&bytes);
	out
}

/// Strict big-endian decode of an Fq element. Rejects values ≥ p
/// (canonical-form requirement matching IETF spec).
///
/// BLS12-381's Fq is a 381-bit prime, represented in arkworks as a
/// `BigInt<6>` (six u64 limbs in little-endian limb order). We read the
/// 48 input bytes as a big-endian integer, repack as little-endian
/// u64 limbs, and validate against `Fq::MODULUS`.
fn fq_from_be_bytes_strict(bytes: &[u8; 48]) -> Result<Fq, Error> {
	let mut limbs = [0u64; 6];
	for (limb_idx, limb) in limbs.iter_mut().enumerate() {
		// Limb 0 is the least significant; it lives in the *last* 8
		// bytes of the big-endian buffer.
		let lo = 48 - 8 * (limb_idx + 1);
		let hi = lo + 8;
		let mut limb_bytes = [0u8; 8];
		limb_bytes.copy_from_slice(&bytes[lo..hi]);
		*limb = u64::from_be_bytes(limb_bytes);
	}
	let bi = BigInt::<6>::new(limbs);
	if bi >= Fq::MODULUS {
		return Err(Error::XOutOfRange);
	}
	Fq::from_bigint(bi).ok_or(Error::XOutOfRange)
}

/// y > -y in canonical (non-Montgomery) ordering on Fq.
fn y_is_lex_larger_fq(y: &Fq) -> bool {
	y.into_bigint() > (-*y).into_bigint()
}

/// y > -y in lex ordering on Fq2 = c0 + c1·u, comparing (c1, c0)
/// lexicographically. (RFC 9380's convention: the high-degree coefficient
/// is the more-significant component for sign comparison.)
fn y_is_lex_larger_fq2(y: &Fq2) -> bool {
	let neg = -*y;
	match y.c1.into_bigint().cmp(&neg.c1.into_bigint()) {
		core::cmp::Ordering::Greater => true,
		core::cmp::Ordering::Less => false,
		core::cmp::Ordering::Equal => y.c0.into_bigint() > neg.c0.into_bigint(),
	}
}

// ─── PcsParams construction ────────────────────────────────────────────────

/// Build a `BandersnatchPcsParams` from sequences of (already-decoded)
/// G1 and G2 powers. Performs the sufficiency check.
pub fn build_pcs_params(
	powers_in_g1: Vec<G1Affine>,
	powers_in_g2: Vec<G2Affine>,
	ring_size: usize,
) -> Result<BandersnatchPcsParams, Error> {
	let required = pcs_domain_size::<BandersnatchSuite>(ring_size);
	if powers_in_g1.len() < required {
		return Err(Error::InsufficientG1Powers {
			ring_size,
			required,
			provided: powers_in_g1.len(),
		});
	}
	if powers_in_g2.len() < 2 {
		return Err(Error::InsufficientG2Powers(powers_in_g2.len()));
	}
	Ok(BandersnatchPcsParams { powers_in_g1, powers_in_g2 })
}

/// Build a `BandersnatchRingProofParams` from `BandersnatchPcsParams`.
/// The full production-shape constructor.
pub fn build_ring_proof_params_from_pcs(
	ring_size: usize,
	pcs_params: BandersnatchPcsParams,
) -> Result<BandersnatchRingProofParams, Error> {
	BandersnatchRingProofParams::from_pcs_params(ring_size, pcs_params)
		.map_err(|_| Error::RingProofParamsConstruction)
}

/// Convenience: deterministic-from-seed RingProofParams. Mirrors the
/// path `RingContext::new_testing()` uses internally (`ChaCha20Rng` ->
/// random PCS setup). Used as a control case in tests.
pub fn build_ring_proof_params_from_seed(
	ring_size: usize,
	seed: [u8; 32],
) -> BandersnatchRingProofParams {
	BandersnatchRingProofParams::from_seed(ring_size, seed)
}

// ─── Stable hash for chain-spec metadata ──────────────────────────────────

/// SHA-256 of arkworks' canonical uncompressed encoding of the
/// `RingProofParams`. This is the hash that goes into chain-spec
/// metadata as `UrsSource::EthereumKzgCeremony2023::srs_hash`, allowing
/// third parties to re-derive the URS and verify it byte-for-byte.
pub fn ring_proof_params_sha256(params: &BandersnatchRingProofParams) -> [u8; 32] {
	use ark_vrf::reexports::ark_serialize::{CanonicalSerialize, Compress};
	let mut buf = Vec::with_capacity(params.serialized_size(Compress::No));
	params
		.serialize_uncompressed(&mut buf)
		.expect("canonical serialization is infallible for valid RingProofParams; qed");
	let digest = Sha256::digest(&buf);
	let mut out = [0u8; 32];
	out.copy_from_slice(&digest);
	out
}
