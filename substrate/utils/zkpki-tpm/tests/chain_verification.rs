//! Chain signature verification and root pinning tests.
//!
//! Positive case: the real SM-G986U attestation chain signs cleanly end to
//! end and the root matches Google's pinned Hardware Attestation Root CA.
//!
//! Negative cases: every class of tampering must be rejected — broken
//! signature, wrong root, truncated chain, non-self-signed root.

#[path = "fixtures/sm_g986u_attestation.rs"]
mod fixture;

use zk_pki_tpm::{
    verify_chain, verify_chain_with_pin, verify_chain_with_pin_and_intermediates, ChainError,
    GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH,
};

fn real_chain() -> Vec<Vec<u8>> {
    vec![
        fixture::leaf_der(),
        fixture::int1_der(),
        fixture::int2_der(),
        fixture::root_der(),
    ]
}

#[test]
fn real_chain_verifies_end_to_end() {
    let chain = real_chain();
    verify_chain(&chain).expect("real SM-G986U chain must verify cleanly");
}

#[test]
fn empty_chain_rejected() {
    let chain: Vec<Vec<u8>> = Vec::new();
    assert_eq!(verify_chain(&chain), Err(ChainError::EmptyChain));
}

#[test]
fn truncated_chain_rejected_due_to_missing_root() {
    // Only leaf + int1 — no root present. int1 is signed by int2 (P-384
    // ECDSA), but we're treating int1 as its own "root" and self-verifying
    // with int1's P-256 key. The p256 DER parser rejects the signature
    // because the r/s integers are sized for P-384 (48 bytes each), not
    // P-256 (32 bytes each), which surfaces as SignatureEncodingFailure.
    // Other rejection paths (pin mismatch, verify failure) are also
    // acceptable — we only care that a truncated chain never verifies.
    let chain = vec![fixture::leaf_der(), fixture::int1_der()];
    let result = verify_chain(&chain);
    assert!(result.is_err(), "truncated chain must not verify");
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            ChainError::SignatureVerifyFailed
                | ChainError::SignatureEncodingFailure
                | ChainError::RootPinMismatch
                | ChainError::ParentAlgorithmMismatch
                | ChainError::UnsupportedSignatureAlgorithm
                | ChainError::BadPublicKey
        ),
        "got {:?}",
        err
    );
}

#[test]
fn wrong_root_pin_rejected() {
    // Same valid chain, but pin to a different SPKI hash. Must be rejected
    // with the specific RootPinMismatch variant.
    let chain = real_chain();
    let bogus_pin = [0xaa; 32];
    assert_eq!(
        verify_chain_with_pin(&chain, &bogus_pin),
        Err(ChainError::RootPinMismatch)
    );
}

#[test]
fn tampered_leaf_signature_rejected() {
    // Flip a byte inside the leaf cert's signature. The signature over TBS
    // bytes will no longer verify against int1's P-256 pubkey.
    let mut chain = real_chain();
    let leaf = &mut chain[0];
    // Flip a byte near the end — within the ECDSA signature bit string.
    let last = leaf.len() - 10;
    leaf[last] ^= 0xff;

    let result = verify_chain(&chain);
    assert!(result.is_err(), "tampered leaf signature must not verify");
    // Tamper can land on a TBS byte or a signature byte; accept either.
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            ChainError::SignatureVerifyFailed
                | ChainError::MalformedCertificate
                | ChainError::SignatureEncodingFailure
        ),
        "got {:?}",
        err
    );
}

#[test]
fn garbage_bytes_rejected() {
    let chain = vec![vec![0xff; 128], fixture::int1_der(), fixture::int2_der(), fixture::root_der()];
    assert_eq!(
        verify_chain(&chain),
        Err(ChainError::MalformedCertificate)
    );
}

// -------- RSA path sanity tests --------
//
// The Google Hardware Attestation Root CA signs with RSA-PKCS1-v1_5 over
// SHA-256. Two places in the real chain exercise RSA: the root's own
// self-signature, and int2's signature (issued by root). The tests below
// tamper bytes inside those specific signature regions — the only way
// rejection happens is if the RSA verifier actually ran and produced a
// cryptographic mismatch. Previously these paths could have silently
// passed due to a dispatch bug; these tests catch that class of failure.

#[test]
fn tampered_root_self_signature_rejected_via_rsa_path() {
    // Root cert layout: 1380 bytes total, last 513 bytes are the RSA
    // signature bit string content. Flipping a byte well inside the sig
    // region cannot affect SPKI (pin still matches) or TBS (self-sign is
    // still over the correct TBS) — only the signature value is broken.
    let mut chain = real_chain();
    let root = &mut chain[3];
    let offset = root.len() - 64;
    root[offset] ^= 0xff;

    // verify_chain runs the self-sign check first, before pin or pairwise.
    // Expect SignatureVerifyFailed — which is only reachable through the
    // RSA verifier for sha256WithRSAEncryption.
    assert_eq!(verify_chain(&chain), Err(ChainError::SignatureVerifyFailed));
}

#[test]
fn tampered_int2_signature_rejected_via_rsa_path() {
    // int2 is signed by root's RSA key. int2 is 987 bytes; last ~516 bytes
    // are the RSA signature. Flipping a byte inside that region breaks
    // int2 → root verification (RSA) without affecting int1 → int2 (ECDSA
    // over int2's subject pubkey, which sits earlier in the cert).
    let mut chain = real_chain();
    let int2 = &mut chain[2];
    let offset = int2.len() - 64;
    int2[offset] ^= 0xff;

    // Root self-sign passes (root unchanged), pin passes (root unchanged).
    // Failure must come from the pairwise walk on int2 → root, which is
    // the RSA verifier.
    assert_eq!(verify_chain(&chain), Err(ChainError::SignatureVerifyFailed));
}

// -------- Manufacturer intermediate gate --------
//
// Google's Hardware Attestation Root CA is universal across Android
// Keystore chains — pinning the root alone cannot distinguish legitimate
// secure-element hardware from a different Google-signed path. The
// manufacturer intermediate gate requires at least one cert between leaf
// and root (exclusive) to match a known vendor intermediate SPKI.

#[test]
fn unknown_manufacturer_intermediate_rejected() {
    // Real chain, correct Google root pin, but a manufacturer intermediate
    // set that deliberately does not contain the Samsung S3K250AF hash.
    // The gate must fire with UnknownManufacturer, proving the check ran
    // against the supplied set rather than silently passing.
    let chain = real_chain();
    let bogus_intermediates: &[[u8; 32]] = &[[0xaa; 32]];
    assert_eq!(
        verify_chain_with_pin_and_intermediates(
            &chain,
            &GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH,
            bogus_intermediates,
        ),
        Err(ChainError::UnknownManufacturer),
    );
}
