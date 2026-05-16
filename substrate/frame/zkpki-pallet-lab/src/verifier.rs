//! Groth16 verification kernel for the mime_wrap circuit.
//!
//! no_std-shaped. Pure arkworks types (no file I/O, no ark-circom, no
//! wasmer). This module is what lands in the final pallet byte-for-byte.
//!
//! Public inputs for the mime_wrap circuit are 600 Fr elements arranged
//! as bit decompositions of four compact fields:
//!   * `commitment_c`  — 32 bytes → 256 bits
//!   * `ec_key_pub`    — 32 bytes → 256 bits
//!   * `bucket`        — u64 → 64 bits, big-endian
//!   * `user_otp`      — 24 bits of a u32 → 24 bits, big-endian
//! (total 600 bits)
//!
//! Bit order within each byte is MSB-first, matching circomlib's Sha256
//! convention used in the Stage 1 circuit.

use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use sp_std::vec::Vec;

/// Error variants returned from the verify path. Each is distinct so
/// the pallet can emit precise [`Error`](crate::pallet::Error) values
/// to callers.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The proof bytes don't decode as a compressed Groth16 proof.
    ProofMalformed,
    /// The stored VK bytes don't decode as a compressed Groth16 VK.
    VerifyingKeyMalformed,
    /// Proof decoded cleanly but pairing check failed — either the
    /// proof is cryptographically invalid, or the public inputs don't
    /// match what the proof attests to.
    PairingFailed,
    /// The user_otp value exceeds 24 bits (0x00FF_FFFF). Caller should
    /// mask off the upper 8 bits client-side; we surface this instead
    /// of silently truncating so a malformed caller isn't accidentally
    /// verified against a different OTP than they thought.
    OtpOutOfRange,
}

/// Verify a mime_wrap Groth16 proof given the compact public-input
/// components. Reconstructs the 600-element Fr bit vector internally.
///
/// `commitment_c` and `ec_key_pub` are each 32 bytes. `bucket` is a
/// u64 interpreted big-endian. `user_otp` is the low-24-bits of a u32
/// (BE); the top 8 bits must be zero.
pub fn verify_mime_wrap(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    commitment_c: &[u8; 32],
    ec_key_pub: &[u8; 32],
    bucket: u64,
    user_otp: u32,
) -> Result<bool, VerifyError> {
    if user_otp & 0xFF00_0000 != 0 {
        return Err(VerifyError::OtpOutOfRange);
    }
    let public_inputs = build_public_inputs(commitment_c, ec_key_pub, bucket, user_otp);

    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|_| VerifyError::VerifyingKeyMalformed)?;
    let pvk = prepare_verifying_key(&vk);

    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|_| VerifyError::ProofMalformed)?;

    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .map_err(|_| VerifyError::PairingFailed)
}

/// Build the 600-element Fr public-input vector from compact fields.
/// Split out so tests can inspect the vector directly and compare to
/// what the circuit consumes during witness generation.
///
/// Ordering must match the Circom circuit's `public [...]` declaration
/// order: commitmentC (256), ecKeyPub (256), bucket (64), userOtp (24).
pub fn build_public_inputs(
    commitment_c: &[u8; 32],
    ec_key_pub: &[u8; 32],
    bucket: u64,
    user_otp: u32,
) -> Vec<Fr> {
    let mut out: Vec<Fr> = Vec::with_capacity(600);
    push_bytes_bits_be(&mut out, commitment_c);
    push_bytes_bits_be(&mut out, ec_key_pub);
    push_bytes_bits_be(&mut out, &bucket.to_be_bytes());
    push_u24_bits_be(&mut out, user_otp);
    out
}

fn push_bytes_bits_be(out: &mut Vec<Fr>, bytes: &[u8]) {
    for &byte in bytes {
        for shift in (0..8).rev() {
            out.push(bit_fr((byte >> shift) & 1));
        }
    }
}

fn push_u24_bits_be(out: &mut Vec<Fr>, value: u32) {
    // Lowest 24 bits of `value`, emitted MSB-first (matches the
    // `bytesToBitsBE(c2hash).slice(-24)` pattern used in the Stage 1
    // JavaScript fixture generator).
    for shift in (0..24).rev() {
        out.push(bit_fr(((value >> shift) & 1) as u8));
    }
}

fn bit_fr(b: u8) -> Fr {
    if b == 0 {
        Fr::zero()
    } else {
        // From<u64> for Fr is infallible for 0/1.
        Fr::from(1u64)
    }
}
