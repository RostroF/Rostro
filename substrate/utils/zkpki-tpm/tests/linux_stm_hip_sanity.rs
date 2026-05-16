//! Sanity tests for the captured Linux STM dTPM HIP proof.
//!
//! Mirrors `windows_amd_hip_sanity.rs` — confirms the real-hardware
//! bytes decode as a `CanonicalHipProof::Tpm2` with Linux flavor,
//! the critical fields round-trip through SCALE, and the
//! `zk-pki-hip` verifier accepts the bytes when `self` is used as
//! the genesis fingerprint.
//!
//! Canary for the Tpm2Linux dispatch path: the verifier treats
//! Windows and Linux flavors identically (same wire format), but
//! the `flavor` field must propagate correctly through decode and
//! the `HipPlatform::from_proof` projection.

#[path = "fixtures/linux_stm_hip_proof.rs"]
mod fixture;

use codec::Decode;
use zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION;
use zk_pki_primitives::hip::{
    CanonicalHipProof, GenesisHardwareFingerprint, HipPlatform, Tpm2Flavor,
    Tpm2GenesisFingerprint,
};

fn decode_proof() -> CanonicalHipProof {
    let bytes = fixture::canonical_hip_proof_bytes();
    CanonicalHipProof::decode(&mut &bytes[..])
        .expect("CanonicalHipProof should decode from real hardware bytes")
}

fn as_tpm2(proof: &CanonicalHipProof) -> &zk_pki_primitives::hip::Tpm2HipProof {
    match proof {
        CanonicalHipProof::Tpm2(p) => p,
        _ => panic!("expected Tpm2 variant for Linux fixture"),
    }
}

#[test]
fn hip_proof_bytes_not_empty() {
    let bytes = fixture::canonical_hip_proof_bytes();
    assert!(!bytes.is_empty());
}

#[test]
fn hip_proof_decodes_from_scale() {
    let proof = decode_proof();
    let tpm2 = as_tpm2(&proof);
    assert!(matches!(tpm2.flavor, Tpm2Flavor::Linux));
    assert!(matches!(
        HipPlatform::from_proof(&proof),
        HipPlatform::Tpm2Linux,
    ));
}

#[test]
fn hip_proof_nonce_matches_capture() {
    let proof = decode_proof();
    assert_eq!(as_tpm2(&proof).nonce, fixture::genesis_nonce());
}

#[test]
fn hip_proof_pcr_values_present() {
    let proof = decode_proof();
    let tpm2 = as_tpm2(&proof);
    // Capture selects PCRs 0, 1, 4, 7, 11.
    assert_eq!(tpm2.pcr_values.len(), 5);
    let pcr7 = tpm2.pcr_values.iter().find(|p| p.index == 7);
    assert!(pcr7.is_some(), "PCR 7 (Secure Boot anchor) must be present");
}

#[test]
fn hip_proof_aik_public_present() {
    let proof = decode_proof();
    let tpm2 = as_tpm2(&proof);
    assert!(!tpm2.aik_public.is_empty());
    // P-256 SEC1 uncompressed is 65 bytes (0x04 || x || y).
    assert_eq!(tpm2.aik_public.len(), 65);
    assert_eq!(tpm2.aik_public[0], 0x04);
}

#[test]
fn hip_proof_verifies_internal_on_linux_platform() {
    sp_io::TestExternalities::default().execute_with(|| {
        let proof = decode_proof();
        let report = zk_pki_hip::verify_hip_proof_internal(&proof)
            .expect("Linux TPM2 proof should pass internal verification");
        assert!(matches!(report.platform, HipPlatform::Tpm2Linux));
        assert!(report.device_identity_confirmed);
    });
}

#[test]
fn hip_proof_verifies_against_self_as_genesis() {
    sp_io::TestExternalities::default().execute_with(|| {
        let proof = decode_proof();
        let tpm2 = as_tpm2(&proof);

        let genesis = GenesisHardwareFingerprint::Tpm2(Tpm2GenesisFingerprint {
            flavor: Tpm2Flavor::Linux,
            ek_hash: tpm2.ek_hash,
            aik_public_hash: sp_io::hashing::blake2_256(tpm2.aik_public.as_slice()),
            pcr_values: tpm2.pcr_values.clone(),
            schema_version: CURRENT_SCHEMA_VERSION,
        });

        let expected_nonce = tpm2.nonce;
        let result =
            zk_pki_hip::verify_hip_proof_against_genesis(&proof, &genesis, &expected_nonce);
        assert!(
            result.is_ok(),
            "real-hardware Linux HIP proof should verify against its own genesis: {:?}",
            result.err(),
        );
    });
}
