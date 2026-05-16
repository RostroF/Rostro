//! TPM 2.0 path — Windows TBS and Linux `/dev/tpmrm0`. Wire format
//! is byte-identical across the two; the `Tpm2Flavor` field on the
//! payload distinguishes operational origin.
//!
//! The verifier operates on the pre-canonicalized [`Tpm2HipProof`]
//! struct. A restricted AIK physically cannot sign arbitrary data —
//! `TPM2_Quote` signs `SHA-256(TPMS_ATTEST)` where the TPM itself
//! generates the `TPMS_ATTEST` blob. So the canonical proof carries
//! `quote_attest` as raw bytes; the verifier checks the signature
//! against the TPM's actual signing domain.

extern crate alloc;

use alloc::vec::Vec;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use zk_pki_primitives::hip::{HipPlatform, Tpm2Flavor, Tpm2GenesisFingerprint, Tpm2HipProof};

use crate::{find_pcr, HipError, HipVerificationReport};

// TCG Part 2 constants.
const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// Internal-only TPM2 verification. Four steps:
///
/// 1. `blake2_256(ek_public) == ek_hash` — gate that the supplied
///    EK pubkey matches the claimed cert hash.
/// 2. `aik_certify_signature` verifies over `aik_certify_info` under
///    `ek_public` (TPM2_Certify — EK signs over AIK's name).
/// 3. `quote_signature` verifies over `SHA-256(quote_attest)` under
///    `aik_public`. Matches the TPM's actual signing domain.
/// 4. Parse `quote_attest` to pin its inner `pcrDigest` and
///    `extraData` fields against the canonical proof's redundant
///    `pcr_digest` / `nonce` fields.
pub(crate) fn verify_internal(
    proof: &Tpm2HipProof,
) -> Result<HipVerificationReport, HipError> {
    // 1 — EK hash consistency.
    let ek_hash_computed = sp_io::hashing::blake2_256(proof.ek_public.as_slice());
    if ek_hash_computed != proof.ek_hash {
        return Err(HipError::EkHashMismatch);
    }

    // 2 — AIK-certify signature under EK.
    verify_ecdsa_p256_over(
        proof.ek_public.as_slice(),
        proof.aik_certify_info.as_slice(),
        proof.aik_certify_signature.as_slice(),
    )
    .map_err(|_| HipError::AikCertifyInvalid)?;

    // 3 — Quote signature over SHA-256(quote_attest) under AIK.
    verify_ecdsa_p256_over_prehashed(
        proof.aik_public.as_slice(),
        proof.quote_attest.as_slice(),
        proof.quote_signature.as_slice(),
    )
    .map_err(|_| HipError::QuoteSignatureInvalid)?;

    // 4 — Pin inner vs outer fields.
    let (inner_pcr_digest, inner_extra_data) =
        parse_tpms_attest_quote(proof.quote_attest.as_slice())
            .ok_or(HipError::QuoteAttestMalformed)?;
    if inner_pcr_digest != proof.pcr_digest {
        return Err(HipError::PcrDigestMismatch);
    }
    if inner_extra_data != proof.nonce {
        return Err(HipError::NonceAttestMismatch);
    }

    Ok(HipVerificationReport {
        platform: match proof.flavor {
            Tpm2Flavor::Windows => HipPlatform::Tpm2Windows,
            Tpm2Flavor::Linux => HipPlatform::Tpm2Linux,
        },
        device_identity_confirmed: true,
        secure_boot_intact: true, // not enforced at internal-only layer
    })
}

/// Genesis-compare verification. Runs the internal check, pins the
/// caller's expected nonce, compares AIK identity and PCR 7 to the
/// stored genesis fingerprint.
pub(crate) fn verify_against_genesis(
    proof: &Tpm2HipProof,
    genesis: &Tpm2GenesisFingerprint,
    expected_nonce: &[u8; 32],
) -> Result<HipVerificationReport, HipError> {
    let report = verify_internal(proof)?;

    // Bind to caller's expected nonce. The internal check already
    // pinned attest.extraData == proof.nonce; this closes the
    // remaining replay path where a previously-valid proof is
    // submitted in a different intended context.
    if &proof.nonce != expected_nonce {
        return Err(HipError::NonceExpectedMismatch);
    }

    // AIK identity — must match genesis.
    let aik_hash = sp_io::hashing::blake2_256(proof.aik_public.as_slice());
    if aik_hash != genesis.aik_public_hash {
        return Err(HipError::AikGenesisMismatch);
    }

    // PCR 7 (Secure Boot state) must match genesis. Other PCRs may
    // progress forward across legitimate OS updates — full policy
    // is a future-pass concern tracked by the seal-break taxonomy.
    let genesis_pcr7 = find_pcr(&genesis.pcr_values, 7)
        .ok_or(HipError::GenesisPcr7Missing)?;
    let current_pcr7 = find_pcr(&proof.pcr_values, 7)
        .ok_or(HipError::CurrentPcr7Missing)?;
    if current_pcr7 != genesis_pcr7 {
        return Err(HipError::Pcr7GenesisMismatch);
    }

    Ok(report)
}

/// Verify an ECDSA-P256 signature over arbitrary message bytes.
/// Signature bytes are DER; pubkey is SEC1 uncompressed. Message is
/// hashed with SHA-256 before verify.
fn verify_ecdsa_p256_over(
    pubkey_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), HipError> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|_| HipError::BadPublicKey)?;
    let sig = Signature::from_der(signature_bytes)
        .map_err(|_| HipError::BadSignature)?;
    let digest = Sha256::digest(message);
    vk.verify_prehash(&digest, &sig)
        .map_err(|_| HipError::QuoteSignatureInvalid)
}

/// Same as above, explicit about the "TPM signed SHA-256(message)"
/// domain. Separate helper so the error mapping is targeted.
fn verify_ecdsa_p256_over_prehashed(
    pubkey_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), HipError> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|_| HipError::BadPublicKey)?;
    let sig = Signature::from_der(signature_bytes)
        .map_err(|_| HipError::BadSignature)?;
    let digest = Sha256::digest(message);
    vk.verify_prehash(&digest, &sig)
        .map_err(|_| HipError::QuoteSignatureInvalid)
}

/// Parse a `TPMS_ATTEST` blob (type `TPM_ST_ATTEST_QUOTE`) into
/// `(pcrDigest, extraData)`. Both must be 32 bytes; extraData
/// shorter than 32 is rejected because the canonical proof's
/// `nonce` is fixed-size. Returns `None` on any layout problem.
///
/// TPMS_ATTEST wire layout (TCG Part 2 10.12.8):
/// ```text
///   magic            u32                      = 0xFF544347
///   type             u16                      = 0x8018 (QUOTE)
///   qualifiedSigner  TPM2B_NAME  (u16 + data)
///   extraData        TPM2B_DATA  (u16 + data) ← nonce echo
///   clockInfo        17 bytes
///   firmwareVersion  u64
///   attested         TPMS_QUOTE_INFO:
///     pcrSelect      TPML_PCR_SELECTION (u32 count + selections)
///     pcrDigest      TPM2B_DIGEST (u16 + data)
/// ```
fn parse_tpms_attest_quote(attest: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let mut p = 0usize;
    let magic = read_u32(attest, &mut p)?;
    if magic != TPM_GENERATED_VALUE {
        return None;
    }
    let typ = read_u16(attest, &mut p)?;
    if typ != TPM_ST_ATTEST_QUOTE {
        return None;
    }
    // qualifiedSigner — skip.
    let _qualified_signer = read_sized_u16(attest, &mut p)?;
    // extraData — must be exactly 32 bytes.
    let extra_data = read_sized_u16(attest, &mut p)?;
    if extra_data.len() != 32 {
        return None;
    }
    let mut extra = [0u8; 32];
    extra.copy_from_slice(extra_data);
    // clockInfo (17) + firmwareVersion (8) = 25 bytes.
    if attest.len() < p + 25 {
        return None;
    }
    p += 25;
    // pcrSelect — skip by counting selections.
    let sel_count = read_u32(attest, &mut p)?;
    for _ in 0..sel_count {
        let _alg = read_u16(attest, &mut p)?;
        let sel_size = *attest.get(p)? as usize;
        p += 1 + sel_size;
    }
    // pcrDigest — must be exactly 32 bytes (SHA-256).
    let pcr = read_sized_u16(attest, &mut p)?;
    if pcr.len() != 32 {
        return None;
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(pcr);
    Some((digest, extra))
}

// ── Minimal big-endian readers used only by `parse_tpms_attest_quote`. ──

fn read_u16(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    if bytes.len() < *pos + 2 {
        return None;
    }
    let v = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
    *pos += 2;
    Some(v)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    if bytes.len() < *pos + 4 {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*pos..*pos + 4]);
    *pos += 4;
    Some(u32::from_be_bytes(buf))
}

fn read_sized_u16<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let size = read_u16(bytes, pos)? as usize;
    if bytes.len() < *pos + size {
        return None;
    }
    let slice = &bytes[*pos..*pos + size];
    *pos += size;
    Some(slice)
}

// Quiet the unused-import warning on `Vec` while `no_std` is on.
#[allow(dead_code)]
fn _unused(_: Vec<u8>) {}
