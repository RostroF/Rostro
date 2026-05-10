//! Sanity tests for the captured Windows AMD fTPM HIP proof.
//!
//! Confirms the real-hardware bytes decode as a `CanonicalHipProof`,
//! the critical fields round-trip correctly through SCALE, and the
//! `zk-pki-hip` verifier accepts the bytes when `self` is used as
//! the genesis fingerprint (end-to-end crypto check against real
//! AMD fTPM hardware — the signing-domain-mismatch catch that
//! motivated adding `quote_attest` to the canonical struct).

#[path = "fixtures/windows_amd_hip_proof.rs"]
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
        _ => panic!("expected Tpm2 variant for Windows fixture"),
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
    // Windows AMD fixture must decode as the Tpm2 variant with
    // Windows flavor. HipPlatform projection confirms the surface
    // contract relying parties see.
    assert!(matches!(proof, CanonicalHipProof::Tpm2(_)));
    let tpm2 = as_tpm2(&proof);
    assert!(matches!(tpm2.flavor, Tpm2Flavor::Windows));
    assert!(matches!(
        HipPlatform::from_proof(&proof),
        HipPlatform::Tpm2Windows,
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
    assert!(!as_tpm2(&proof).pcr_values.is_empty());
}

#[test]
fn hip_proof_aik_public_present() {
    let proof = decode_proof();
    assert!(!as_tpm2(&proof).aik_public.is_empty());
}

#[test]
fn hip_proof_verifies_against_self_as_genesis() {
    // Build a Tpm2 genesis fingerprint from this proof's own values
    // and run it through the full verifier. Proves the crypto path
    // (EK-hash consistency, AIK-certify signature under EK, quote
    // signature under AIK, PCR7 + AIK identity matching genesis)
    // executes correctly on real AMD fTPM hardware bytes.
    sp_io::TestExternalities::default().execute_with(|| {
        let proof = decode_proof();
        let tpm2 = as_tpm2(&proof);

        let genesis = GenesisHardwareFingerprint::Tpm2(Tpm2GenesisFingerprint {
            flavor: Tpm2Flavor::Windows,
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
            "real-hardware HIP proof should verify against its own genesis: {:?}",
            result.err(),
        );
    });
}
