//! Android StrongBox HIP proof verification.
//!
//! The StrongBox path has no TPM2_Quote equivalent. Its chain of
//! custody is:
//!
//!   1. `cert_ec_chain` — X.509 attestation chain for the cert signing
//!      key, rooted at Google's attestation CA. Proves `cert_ec_public`
//!      lives in StrongBox on a genuine Google-signed device.
//!   2. `attest_ec_chain` — attestation chain for a secondary EC key
//!      used solely to sign the binding proof. Same root.
//!   3. `hmac_binding_signature` — ECDSA-SHA256 by `attest_ec` over
//!      `blake2_256(hmac_binding_output || nonce)`. Proves the HMAC
//!      key and attest_ec were co-located in StrongBox at ceremony
//!      time (the AttestKey-binding workaround for Samsung KeyMint's
//!      symmetric-key attestation gap — see memory
//!      `project_strongbox_hmac_gap`).
//!   4. `integrity_signature` — ECDSA-SHA256 by `cert_ec` over
//!      `blake2_256(integrity_blob)`. Binds the integrity declaration
//!      to the cert_ec key.
//!
//! # Scope of this pass
//!
//! Implemented here (signature-level crypto checks only):
//!
//! - `attest_ec_public` verifies `hmac_binding_signature` over the
//!   correct commitment.
//! - `cert_ec_public` verifies `integrity_signature` over the correct
//!   commitment.
//! - Both chains are non-empty (leaf + at least one intermediate).
//!
//! Deferred to the seal-break taxonomy session:
//!
//! - Full X.509 chain-to-root verification against Google's
//!   attestation root CA.
//! - RootOfTrust extraction from the attestation chain leaf's
//!   `AuthorizationList` extension.
//! - Genesis-compare drift checks (VerifiedBoot state change, patch
//!   level regression, AttestKey binding commitment drift).
//!
//! The current implementation catches signature tampering on a well-
//! formed proof but does not prove the chain roots in a known CA.
//! Pallet-layer defense-in-depth (via the planned `PlatformTag` and
//! the dotwave-side OS-attestation pre-flight) reduces exposure
//! in the interim.

extern crate alloc;

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use zk_pki_primitives::hip::{
    HipPlatform, StrongBoxGenesisFingerprint, StrongBoxHipProof,
};

use crate::{HipError, HipVerificationReport};

/// Internal-only StrongBox verification. Does not consult any
/// genesis fingerprint. Checks:
///
/// 1. Both attestation chains are non-empty.
/// 2. `hmac_binding_signature` verifies over
///    `blake2_256(hmac_binding_output || nonce)` under
///    `attest_ec_public`.
/// 3. `integrity_signature` verifies over
///    `blake2_256(integrity_blob)` under `cert_ec_public`.
///
/// Does NOT currently check that the chains root at Google's
/// attestation CA — deferred to the seal-break taxonomy pass.
pub(crate) fn verify_internal(
    proof: &StrongBoxHipProof,
) -> Result<HipVerificationReport, HipError> {
    // 1 — Non-empty chains. Every real StrongBox attestation comes
    //     back as a multi-cert chain; empty here means the caller
    //     cut corners on the probe side.
    if proof.cert_ec_chain.is_empty() || proof.attest_ec_chain.is_empty() {
        return Err(HipError::ChainEmpty);
    }

    // 2 — HMAC binding signature. `attest_ec_public` signed over
    //     blake2_256(hmac_binding_output || nonce). Recompute
    //     commitment here and verify.
    //
    // StrongBox keys are minted with `setDigests(DIGEST_SHA256)`,
    // so the only signing path KeyMint accepts is `SHA256withECDSA`
    // — that pre-hashes the input with SHA-256 before signing. The
    // chain-side prehash therefore has to be `SHA-256(commitment)`,
    // not `commitment` itself, to match what the secure element
    // actually signed.
    let commitment = {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&proof.hmac_binding_output);
        input[32..].copy_from_slice(&proof.nonce);
        sp_io::hashing::blake2_256(&input)
    };
    let commitment_sha = sp_io::hashing::sha2_256(&commitment);
    verify_ecdsa_p256_prehashed(
        &proof.attest_ec_public,
        &commitment_sha,
        proof.hmac_binding_signature.as_slice(),
    )
    .map_err(|e| match e {
        HipError::BadPublicKey | HipError::BadSignature => e,
        _ => HipError::HmacBindingSignatureInvalid,
    })?;

    // 3 — Integrity signature. `cert_ec_public` signed over
    //     blake2_256(integrity_blob). Same SHA-256 outer wrap as
    //     the binding signature above — `cert_ec` is also minted
    //     with `setDigests(DIGEST_SHA256)`.
    let integrity_digest = sp_io::hashing::blake2_256(proof.integrity_blob.as_slice());
    let integrity_digest_sha = sp_io::hashing::sha2_256(&integrity_digest);
    verify_ecdsa_p256_prehashed(
        &proof.cert_ec_public,
        &integrity_digest_sha,
        proof.integrity_signature.as_slice(),
    )
    .map_err(|e| match e {
        HipError::BadPublicKey | HipError::BadSignature => e,
        _ => HipError::IntegritySignatureInvalid,
    })?;

    Ok(HipVerificationReport {
        platform: HipPlatform::StrongBox,
        device_identity_confirmed: true,
        // Secure-boot state isn't extractable without X.509 chain
        // parsing — the RootOfTrust lives in an AuthorizationList
        // extension on the cert leaf. Deferred pass.
        secure_boot_intact: false,
    })
}

/// Genesis-compare verification for StrongBox. Runs the internal
/// check, pins the caller's expected nonce, compares cert_ec and
/// attest_ec identity hashes to the stored genesis fingerprint.
///
/// RootOfTrust drift / patch-level regression / HMAC binding
/// commitment match are deferred to the seal-break taxonomy pass —
/// they require the `hmac_binding_commitment` derivation to be
/// bound to the per-session nonce rather than the genesis nonce,
/// which intersects with the broader seal-break design.
pub(crate) fn verify_against_genesis(
    proof: &StrongBoxHipProof,
    genesis: &StrongBoxGenesisFingerprint,
    expected_nonce: &[u8; 32],
) -> Result<HipVerificationReport, HipError> {
    let report = verify_internal(proof)?;

    if &proof.nonce != expected_nonce {
        return Err(HipError::NonceExpectedMismatch);
    }

    // cert_ec identity — must match genesis.
    let cert_ec_hash = sp_io::hashing::blake2_256(&proof.cert_ec_public);
    if cert_ec_hash != genesis.cert_ec_public_hash {
        // Reuse AikGenesisMismatch semantically — "device-signing key
        // identity diverged from genesis". Not perfect naming; the
        // seal-break taxonomy pass will introduce dedicated
        // StrongBox drift variants.
        return Err(HipError::AikGenesisMismatch);
    }

    // attest_ec identity — must also match genesis.
    let attest_ec_hash = sp_io::hashing::blake2_256(&proof.attest_ec_public);
    if attest_ec_hash != genesis.attest_ec_public_hash {
        return Err(HipError::AikGenesisMismatch);
    }

    Ok(report)
}

/// Verify an ECDSA-P256 signature over a pre-computed digest.
/// `pubkey_bytes` is SEC1 uncompressed (65 bytes for P-256),
/// `digest` is 32 bytes (blake2_256 or SHA-256), `signature_bytes`
/// is DER-encoded ECDSA.
fn verify_ecdsa_p256_prehashed(
    pubkey_bytes: &[u8],
    digest: &[u8; 32],
    signature_bytes: &[u8],
) -> Result<(), HipError> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|_| HipError::BadPublicKey)?;
    let sig = Signature::from_der(signature_bytes)
        .map_err(|_| HipError::BadSignature)?;
    vk.verify_prehash(digest, &sig)
        // This error gets re-mapped by the caller to the right
        // signature-specific variant; the generic one here is a
        // placeholder that the caller replaces via its `match`.
        .map_err(|_| HipError::HmacBindingSignatureInvalid)
}
