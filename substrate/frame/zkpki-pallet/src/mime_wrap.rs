//! Groth16 verification kernel for the mime-wrap circuit.
//!
//! Ported from the Stage 4 standalone `zkpki-mime-wrap` pallet
//! (`paseo-node/pallets/zkpki-mime-wrap/src/verifier.rs`) — production
//! home now lives here as part of the integrated zk-pki-pallet's
//! Android-tier PoP path.
//!
//! no_std-shaped. Pure arkworks types (no file I/O, no ark-circom, no
//! wasmer). The kernel runs verbatim in the runtime via the
//! `verify_mime_wrap` entry point, called from
//! `verify_pop_assertion`'s MimeWrap dispatch arm.
//!
//! Public inputs for the mime-wrap circuit are 600 Fr elements arranged
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
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use sp_std::vec::Vec;

/// Fixed 26-byte DER SPKI prefix that wraps a 65-byte SEC1
/// uncompressed P-256 point into a 91-byte SubjectPublicKeyInfo
/// structure, matching what dotwave's StrongBox ceremony returns
/// from Android Keystore.
///
/// Bytes break down as:
///   30 59                           SEQUENCE (89 bytes follow)
///     30 13                         SEQUENCE — AlgorithmIdentifier
///       06 07 2a 86 48 ce 3d 02 01  OID 1.2.840.10045.2.1 (id-ecPublicKey)
///       06 08 2a 86 48 ce 3d 03 01 07
///                                   OID 1.2.840.10045.3.1.7 (P-256)
///     03 42                         BIT STRING (66 bytes follow)
///       00                          unused-bits indicator
///       (then 65 SEC1 bytes follow)
const P256_DER_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Wrap a 65-byte SEC1 uncompressed P-256 public key into the
/// 91-byte DER SPKI form used by dotwave's `derive_ec_key_pub_from_der`.
///
/// Returns `None` if `sec1` isn't exactly 65 bytes (the SEC1
/// uncompressed point form starts with `0x04` followed by 32-byte
/// X then 32-byte Y).
///
/// Used by `mint_cert`'s mime-wrap path to re-derive the
/// `ec_key_pub` value the client claims, for the Paseo-phase
/// equality tripwire (see the `MimeWrapEcKeyPubMismatch` error and
/// the `ZK-PKI ec_key_pub Binding` design memo).
pub fn sec1_to_der_spki_p256(sec1: &[u8]) -> Option<Vec<u8>> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return None;
    }
    let mut out = Vec::with_capacity(91);
    out.extend_from_slice(&P256_DER_SPKI_PREFIX);
    out.extend_from_slice(sec1);
    Some(out)
}

/// Re-derive the 32-byte `ec_key_pub` value the dotwave prover
/// computes locally as `SHA256(91-byte DER SPKI)`.
///
/// Returns `None` if the SEC1 input is malformed (handled by
/// `sec1_to_der_spki_p256`).
pub fn derive_ec_key_pub_p256(sec1: &[u8]) -> Option<[u8; 32]> {
    sec1_to_der_spki_p256(sec1).map(|der| sp_io::hashing::sha2_256(&der))
}

/// Error variants returned from the verify path. Each is distinct so
/// the caller (`verify_pop_assertion`) can map to a specific
/// pallet `Error<T>` variant.
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

/// Verify a mime-wrap Groth16 proof given the compact public-input
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 26-byte SPKI prefix wrapping a 65-byte SEC1 P-256 point —
    /// must match what dotwave's Android Keystore returns
    /// (`derive_ec_key_pub_from_der`). Pin the prefix bytes so a
    /// silent canonicalization drift fails this test loudly.
    #[test]
    fn p256_der_spki_prefix_is_stable() {
        // Apply to an arbitrary 65-byte SEC1 placeholder and check
        // length + the prefix bytes match. The prefix is the
        // standard X.509 AlgorithmIdentifier for ECDSA-P256 plus
        // the SubjectPublicKeyInfo BIT STRING wrapper.
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        let der = sec1_to_der_spki_p256(&sec1).expect("65-byte 0x04-prefixed SEC1");
        assert_eq!(der.len(), 91);
        assert_eq!(&der[..26], &P256_DER_SPKI_PREFIX);
        assert_eq!(&der[26..], &sec1);
    }

    #[test]
    fn sec1_canonicalizer_rejects_wrong_length() {
        assert!(sec1_to_der_spki_p256(&[0u8; 64]).is_none());
        assert!(sec1_to_der_spki_p256(&[0u8; 66]).is_none());
        assert!(sec1_to_der_spki_p256(&[]).is_none());
    }

    #[test]
    fn sec1_canonicalizer_rejects_compressed_form() {
        // Compressed P-256 SEC1 starts with 0x02 or 0x03; only the
        // uncompressed 0x04 form is the 65-byte canonical input.
        let mut compressed = [0u8; 65];
        compressed[0] = 0x02;
        assert!(sec1_to_der_spki_p256(&compressed).is_none());
    }

    /// Real-fixture verifier test against the proof captured from
    /// the S20 during the Stage 4c.3 end-to-end run on 2026-04-24.
    /// These exact bytes verified successfully on paseo-node via
    /// polkadot-js → `zkPkiMimeWrap.verifyAndRecord`; this test
    /// proves the production-home verifier (folded into pki/pallet)
    /// produces the same Ok(true) result against the same VK +
    /// public inputs.
    ///
    /// If this test ever fails, either the verifier kernel was
    /// changed in a semantically-breaking way or the dotwave
    /// trusted-setup deterministic seed was changed (which would
    /// invalidate the VK). Both cases need an explicit decision.
    #[test]
    fn verifies_captured_s20_proof_bytes() {
        let proof = hex_decode_panic(concat!(
            "7431233dfbf5eed5caf340a9937b33739048bc74fc2b176222222892b7f500a2",
            "2205eb1656d01a582a9ee86ed114a262755909bdb84057d04e77300e5dd8f311",
            "1be519eb4f2a30bd0ea753096ac440af33ae089dcd3a9fd605b9a91b23a20224",
            "bc5ad29f7410fd43b2a71f5a1c13891038d169e9c3e960ec135ccb86e544eb0a",
        ));
        let vk = hex_decode_panic(concat!(
            // 19,464-byte mime-wrap VK from dotwave's deterministic
            // setup (POC_SETUP_SEED). Pinned here so the test is
            // self-contained — no chain state required.
            include_str!("test_fixtures/mime_wrap_vk.hex"),
        ));
        let commitment_c: [u8; 32] = hex32(
            "1f9934256f270bd33ceeddfeb986d72b7cc8e8468b03e802a103e188158a30be",
        );
        let ec_key_pub: [u8; 32] = hex32(
            "6b835a99c80f9c3de19da492d6a1c3760e36c80fc3fdc24287681e1d83c53d43",
        );
        let bucket: u64 = 59_236_852;
        let user_otp: u32 = 12_467_619;

        let result = verify_mime_wrap(
            &proof,
            &vk,
            &commitment_c,
            &ec_key_pub,
            bucket,
            user_otp,
        );
        assert_eq!(
            result,
            Ok(true),
            "captured S20 proof must verify against captured VK + public inputs",
        );
    }

    /// Tampering any single public-input field flips the pairing
    /// check to `Ok(false)` (or `PairingFailed`). This proves the
    /// verifier is binding to all four public-input components, not
    /// silently ignoring any.
    #[test]
    fn rejects_tampered_public_inputs() {
        let proof = hex_decode_panic(concat!(
            "7431233dfbf5eed5caf340a9937b33739048bc74fc2b176222222892b7f500a2",
            "2205eb1656d01a582a9ee86ed114a262755909bdb84057d04e77300e5dd8f311",
            "1be519eb4f2a30bd0ea753096ac440af33ae089dcd3a9fd605b9a91b23a20224",
            "bc5ad29f7410fd43b2a71f5a1c13891038d169e9c3e960ec135ccb86e544eb0a",
        ));
        let vk = hex_decode_panic(include_str!("test_fixtures/mime_wrap_vk.hex"));
        let commitment_c: [u8; 32] = hex32(
            "1f9934256f270bd33ceeddfeb986d72b7cc8e8468b03e802a103e188158a30be",
        );
        let ec_key_pub: [u8; 32] = hex32(
            "6b835a99c80f9c3de19da492d6a1c3760e36c80fc3fdc24287681e1d83c53d43",
        );

        // Flip a bit in commitment_c.
        let mut bad_commitment = commitment_c;
        bad_commitment[0] ^= 0x01;
        let r = verify_mime_wrap(
            &proof, &vk, &bad_commitment, &ec_key_pub, 59_236_852, 12_467_619,
        );
        assert!(matches!(r, Ok(false) | Err(VerifyError::PairingFailed)));

        // Flip a bit in ec_key_pub.
        let mut bad_pub = ec_key_pub;
        bad_pub[0] ^= 0x01;
        let r = verify_mime_wrap(
            &proof, &vk, &commitment_c, &bad_pub, 59_236_852, 12_467_619,
        );
        assert!(matches!(r, Ok(false) | Err(VerifyError::PairingFailed)));

        // Different bucket.
        let r = verify_mime_wrap(
            &proof, &vk, &commitment_c, &ec_key_pub, 59_236_853, 12_467_619,
        );
        assert!(matches!(r, Ok(false) | Err(VerifyError::PairingFailed)));

        // Different user_otp.
        let r = verify_mime_wrap(
            &proof, &vk, &commitment_c, &ec_key_pub, 59_236_852, 12_467_620,
        );
        assert!(matches!(r, Ok(false) | Err(VerifyError::PairingFailed)));
    }

    #[test]
    fn rejects_otp_out_of_range() {
        // user_otp top 8 bits non-zero. The verifier surfaces this
        // explicitly rather than silently truncating.
        let r = verify_mime_wrap(
            &[0u8; 128],
            &[0u8; 1],
            &[0u8; 32],
            &[0u8; 32],
            0,
            0xFF000000,
        );
        assert_eq!(r, Err(VerifyError::OtpOutOfRange));
    }

    // ── helpers ──

    fn hex_decode_panic(s: &str) -> Vec<u8> {
        let s = s.trim().trim_start_matches("0x").trim();
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = hex_nibble(bytes[i]);
            let lo = hex_nibble(bytes[i + 1]);
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("non-hex byte in fixture: 0x{:02x}", b),
        }
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex_decode_panic(s);
        assert_eq!(v.len(), 32, "expected 32-byte hex string");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }
}
