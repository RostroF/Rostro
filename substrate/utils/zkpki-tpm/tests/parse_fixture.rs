//! Integration test that runs the real attestation chain captured from a
//! Samsung Galaxy S20+ 5G (SM-G986U) through the parser and asserts the
//! fields we care about.
//!
//! Fixture source: dotwave's ZK-PKI Ceremony Smoke Test on 2026-04-16. The
//! ceremony passed — StrongBox on Snapdragon 865 cooperated, produced a
//! valid Android Keystore attestation chain. This test ensures the parser
//! keeps agreeing with that reality.

#[path = "fixtures/sm_g986u_attestation.rs"]
mod fixture;

use codec::Encode;
use zk_pki_tpm::{parse_attestation, SecurityLevel, VerifiedBootState};
use zk_pki_primitives::crypto::KeyAlgorithm;

fn build_chain() -> Vec<u8> {
    let chain: Vec<Vec<u8>> = vec![
        fixture::leaf_der(),
        fixture::int1_der(),
        fixture::int2_der(),
        fixture::root_der(),
    ];
    chain.encode()
}

#[test]
fn parses_real_strongbox_attestation() {
    let bytes = build_chain();
    let parsed = parse_attestation(&bytes)
        .expect("parser returned None — attestation should decode cleanly");

    // The leaf cert's SubjectPublicKeyInfo is a SEC1-encoded P-256 point.
    assert_eq!(parsed.pubkey.algorithm, KeyAlgorithm::EcdsaP256);

    // KeyDescription says both levels are StrongBox — the full FIDO2
    // hardware-authenticator guarantee the design requires.
    assert_eq!(
        parsed.attestation_security_level,
        SecurityLevel::StrongBox
    );
    assert_eq!(parsed.keymint_security_level, SecurityLevel::StrongBox);
    assert!(parsed.is_hardware);

    // The challenge baked into the StrongBox key at generation time
    // must round-trip byte-identical.
    assert_eq!(
        parsed.attestation_challenge.as_slice(),
        &fixture::EXPECTED_CHALLENGE
    );

    // Root cert bytes should equal the last cert in the chain.
    assert_eq!(parsed.root_cert_der, fixture::root_der());

    // RootOfTrust: the SM-G986U fixture was captured on a factory-stock
    // device with a locked bootloader and verified boot. A rooted device
    // would report false/Unverified here, failing PoP eligibility.
    assert_eq!(parsed.device_locked, true);
    assert_eq!(parsed.verified_boot_state, VerifiedBootState::Verified);
    assert!(parsed.is_pop_eligible,
        "SM-G986U fixture must be PoP-eligible (StrongBox + locked + verified)");
}

#[test]
fn rejects_empty_chain() {
    let empty: Vec<Vec<u8>> = Vec::new();
    let bytes = empty.encode();
    assert!(parse_attestation(&bytes).is_none());
}

#[test]
fn rejects_garbage_bytes() {
    let garbage = vec![0xff; 128];
    assert!(parse_attestation(&garbage).is_none());
}

#[test]
fn rejects_chain_with_broken_leaf() {
    // Real chain but leaf replaced with non-DER bytes.
    let chain: Vec<Vec<u8>> = vec![
        vec![0x00, 0x01, 0x02, 0x03],
        fixture::int1_der(),
        fixture::int2_der(),
        fixture::root_der(),
    ];
    assert!(parse_attestation(&chain.encode()).is_none());
}
