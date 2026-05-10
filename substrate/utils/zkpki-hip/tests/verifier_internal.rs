//! Verifier unit tests using synthesized `CanonicalHipProof` structs.
//!
//! These tests do not touch real TPM hardware — they construct
//! proofs with RustCrypto `p256` keypairs, sign the synthetic
//! elements, and confirm `zk_pki_hip::verify_hip_proof_internal`
//! accepts or rejects them as designed. Real-hardware coverage
//! lives in the fixture-driven `zk-pki-tpm` tests.

use frame_support::{traits::ConstU32, BoundedVec};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use zk_pki_hip::{verify_hip_proof_internal, HipError};
use zk_pki_primitives::hip::{
    CanonicalHipProof, HipPlatform, PcrValue, Tpm2Flavor, Tpm2HipProof,
};

fn sign_p256(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: Signature = sk.sign(msg);
    sig.to_der().as_bytes().to_vec()
}

fn pub_bytes(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

/// Build a minimal TPMS_ATTEST (type = TPM_ST_ATTEST_QUOTE) blob.
fn synth_tpms_attest_quote(nonce: &[u8; 32], pcr_digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xFF54_4347u32.to_be_bytes()); // magic
    out.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
    out.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner: empty name
    out.extend_from_slice(&32u16.to_be_bytes()); // extraData size
    out.extend_from_slice(nonce);
    out.extend_from_slice(&[0u8; 17]); // clockInfo: zeros
    out.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
    out.extend_from_slice(&0u32.to_be_bytes()); // pcrSelect count = 0
    out.extend_from_slice(&32u16.to_be_bytes()); // pcrDigest size
    out.extend_from_slice(pcr_digest);
    out
}

/// Build a valid synthesized Tpm2 proof. Fixed scalars → deterministic.
fn valid_tpm2_proof() -> Tpm2HipProof {
    let ek = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let aik = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    let ek_pub = pub_bytes(&ek);
    let aik_pub = pub_bytes(&aik);

    let aik_certify_info = b"aik-certify-info".to_vec();
    let aik_certify_sig = sign_p256(&ek, &aik_certify_info);

    let pcr_digest = [0xAAu8; 32];
    let nonce = [0x01u8; 32];

    let quote_attest = synth_tpms_attest_quote(&nonce, &pcr_digest);
    let quote_sig = sign_p256(&aik, &quote_attest);

    let pcr_values: BoundedVec<PcrValue, ConstU32<16>> = BoundedVec::try_from(vec![
        PcrValue { index: 0, value: [0u8; 32] },
        PcrValue { index: 7, value: [0x77u8; 32] },
    ])
    .unwrap();

    let ek_hash = sp_io::hashing::blake2_256(&ek_pub);

    Tpm2HipProof {
        flavor: Tpm2Flavor::Windows,
        ek_hash,
        ek_public: BoundedVec::try_from(ek_pub).unwrap(),
        aik_public: BoundedVec::try_from(aik_pub).unwrap(),
        aik_certify_info: BoundedVec::try_from(aik_certify_info).unwrap(),
        aik_certify_signature: BoundedVec::try_from(aik_certify_sig).unwrap(),
        pcr_values,
        pcr_digest,
        quote_attest: BoundedVec::try_from(quote_attest).unwrap(),
        quote_signature: BoundedVec::try_from(quote_sig).unwrap(),
        nonce,
    }
}

fn wrap(p: Tpm2HipProof) -> CanonicalHipProof {
    CanonicalHipProof::Tpm2(p)
}

#[test]
fn synth_valid_proof_verifies() {
    sp_io::TestExternalities::default().execute_with(|| {
        let proof = wrap(valid_tpm2_proof());
        let report = verify_hip_proof_internal(&proof).expect("synth proof verifies");
        assert!(matches!(report.platform, HipPlatform::Tpm2Windows));
        assert!(report.device_identity_confirmed);
    });
}

#[test]
fn linux_flavor_also_verifies() {
    // Same wire format as Windows; the flavor field shouldn't affect
    // the cryptographic checks. Only the platform projection in the
    // returned report changes.
    sp_io::TestExternalities::default().execute_with(|| {
        let mut inner = valid_tpm2_proof();
        inner.flavor = Tpm2Flavor::Linux;
        // The aik_certify_signature is over the original `aik_certify_info`
        // bytes signed by EK — flavor is not part of the signed payload,
        // so the sig still verifies. Same for quote_signature.
        let report = verify_hip_proof_internal(&wrap(inner)).expect("Linux flavor verifies");
        assert!(matches!(report.platform, HipPlatform::Tpm2Linux));
    });
}

#[test]
fn ek_hash_mismatch_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut inner = valid_tpm2_proof();
        inner.ek_hash = [0x99u8; 32]; // bogus
        assert_eq!(
            verify_hip_proof_internal(&wrap(inner)).unwrap_err(),
            HipError::EkHashMismatch,
        );
    });
}

#[test]
fn tampered_aik_certify_signature_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut inner = valid_tpm2_proof();
        let mut sig_bytes = inner.aik_certify_signature.to_vec();
        sig_bytes[5] ^= 0x01;
        inner.aik_certify_signature = BoundedVec::try_from(sig_bytes).unwrap();
        let err = verify_hip_proof_internal(&wrap(inner)).unwrap_err();
        assert!(
            matches!(err, HipError::AikCertifyInvalid | HipError::BadSignature),
            "unexpected error variant: {:?}",
            err,
        );
    });
}

#[test]
fn tampered_quote_signature_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut inner = valid_tpm2_proof();
        let mut sig_bytes = inner.quote_signature.to_vec();
        sig_bytes[5] ^= 0x01;
        inner.quote_signature = BoundedVec::try_from(sig_bytes).unwrap();
        let err = verify_hip_proof_internal(&wrap(inner)).unwrap_err();
        assert!(
            matches!(err, HipError::QuoteSignatureInvalid | HipError::BadSignature),
            "unexpected error variant: {:?}",
            err,
        );
    });
}

#[test]
fn tampered_pcr_digest_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut inner = valid_tpm2_proof();
        inner.pcr_digest[0] ^= 0x01;
        assert_eq!(
            verify_hip_proof_internal(&wrap(inner)).unwrap_err(),
            HipError::PcrDigestMismatch,
        );
    });
}

#[test]
fn tampered_nonce_rejected() {
    sp_io::TestExternalities::default().execute_with(|| {
        let mut inner = valid_tpm2_proof();
        inner.nonce[0] ^= 0x01;
        assert_eq!(
            verify_hip_proof_internal(&wrap(inner)).unwrap_err(),
            HipError::NonceAttestMismatch,
        );
    });
}

#[test]
fn genesis_path_aik_hash_mismatch_rejected() {
    use zk_pki_primitives::hip::{
        GenesisHardwareFingerprint, Tpm2GenesisFingerprint,
    };

    sp_io::TestExternalities::default().execute_with(|| {
        let inner = valid_tpm2_proof();
        let wrong_aik_hash = [0xBBu8; 32];
        let genesis = GenesisHardwareFingerprint::Tpm2(Tpm2GenesisFingerprint {
            flavor: Tpm2Flavor::Windows,
            ek_hash: inner.ek_hash,
            aik_public_hash: wrong_aik_hash,
            pcr_values: inner.pcr_values.clone(),
            schema_version: zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION,
        });
        let nonce = inner.nonce;
        assert_eq!(
            zk_pki_hip::verify_hip_proof_against_genesis(&wrap(inner), &genesis, &nonce)
                .unwrap_err(),
            HipError::AikGenesisMismatch,
        );
    });
}

#[test]
fn genesis_path_pcr7_mismatch_rejected() {
    use zk_pki_primitives::hip::{
        GenesisHardwareFingerprint, Tpm2GenesisFingerprint,
    };

    sp_io::TestExternalities::default().execute_with(|| {
        let inner = valid_tpm2_proof();
        let aik_hash = sp_io::hashing::blake2_256(inner.aik_public.as_slice());
        let genesis_pcrs: BoundedVec<PcrValue, ConstU32<16>> = BoundedVec::try_from(vec![
            PcrValue { index: 7, value: [0x00u8; 32] },
        ])
        .unwrap();
        let genesis = GenesisHardwareFingerprint::Tpm2(Tpm2GenesisFingerprint {
            flavor: Tpm2Flavor::Windows,
            ek_hash: inner.ek_hash,
            aik_public_hash: aik_hash,
            pcr_values: genesis_pcrs,
            schema_version: zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION,
        });
        let nonce = inner.nonce;
        assert_eq!(
            zk_pki_hip::verify_hip_proof_against_genesis(&wrap(inner), &genesis, &nonce)
                .unwrap_err(),
            HipError::Pcr7GenesisMismatch,
        );
    });
}

#[test]
fn genesis_path_valid_against_matching_fingerprint() {
    use zk_pki_primitives::hip::{
        GenesisHardwareFingerprint, Tpm2GenesisFingerprint,
    };

    sp_io::TestExternalities::default().execute_with(|| {
        let inner = valid_tpm2_proof();
        let aik_hash = sp_io::hashing::blake2_256(inner.aik_public.as_slice());
        let genesis = GenesisHardwareFingerprint::Tpm2(Tpm2GenesisFingerprint {
            flavor: Tpm2Flavor::Windows,
            ek_hash: inner.ek_hash,
            aik_public_hash: aik_hash,
            pcr_values: inner.pcr_values.clone(),
            schema_version: zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION,
        });
        let expected_nonce = inner.nonce;
        let report =
            zk_pki_hip::verify_hip_proof_against_genesis(&wrap(inner), &genesis, &expected_nonce)
                .expect("matching genesis verifies");
        assert!(report.device_identity_confirmed);
    });
}

#[test]
fn platform_mismatch_between_proof_and_fingerprint_rejected() {
    // A Tpm2 proof against a StrongBox fingerprint (or vice versa)
    // should refuse with PlatformMismatch — the verifier must not
    // dispatch cross-variant.
    use zk_pki_primitives::hip::{
        GenesisHardwareFingerprint, StrongBoxGenesisFingerprint,
    };

    sp_io::TestExternalities::default().execute_with(|| {
        let inner = valid_tpm2_proof();
        let genesis = GenesisHardwareFingerprint::StrongBox(StrongBoxGenesisFingerprint {
            cert_ec_public_hash: [0u8; 32],
            attest_ec_public_hash: [0u8; 32],
            hmac_binding_commitment: [0u8; 32],
            root_of_trust: None,
            os_patch_level: None,
            boot_patch_level: None,
            vendor_patch_level: None,
            schema_version: zk_pki_primitives::cert::CURRENT_SCHEMA_VERSION,
        });
        let nonce = inner.nonce;
        assert_eq!(
            zk_pki_hip::verify_hip_proof_against_genesis(&wrap(inner), &genesis, &nonce)
                .unwrap_err(),
            HipError::PlatformMismatch,
        );
    });
}
