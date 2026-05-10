//! End-to-end tests for `verify_binding_proof` (TODO-3 payload orchestration).
//!
//! # Two-tier test strategy
//!
//! ## Negative tests — real SM-G986U hardware bytes
//!
//! Every rejection test below uses the real
//! [`sm_g986u_binding_proof.rs`](fixtures/sm_g986u_binding_proof.rs) capture:
//! real cert_ec chain, real attest_ec chain, real HMAC output, real
//! binding signature, real challenge. They mutate **one** field per test
//! and assert the specific rejection variant that gate should fire. These
//! are real-hardware validation of Gates 1–6 inside the orchestration.
//!
//! They never reach step 7 (integrity attestation) because a prior gate
//! always short-circuits, so the fact that we don't possess the real
//! cert_ec private key (it's in StrongBox on the device) does not matter
//! — the integrity fields can be any bytes and the tests still pass
//! cleanly.
//!
//! ## Positive test — synthesized end-to-end
//!
//! `valid_payload_v3_verifies` is **fully synthesized**. We generate
//! fresh P-256 keypairs, build minimal Android Keystore-shaped cert
//! chains via `rcgen`, hand-encode the KeyDescription extension, and
//! exercise the orchestration with a test-specific root pin + test
//! manufacturer intermediate via
//! [`verify_binding_proof_with_pins`]. This proves the composition
//! logic is correct given a valid input.
//!
//! It does **not** exercise the real Google root pin or the real Samsung
//! S3K250AF intermediate pin — those are exercised by the chain-
//! verification tests in `chain_verification.rs`. The two tiers together
//! cover: real-bytes validation of the production pin path (there),
//! logic validation of the orchestration (here).
//!
//! **Replace-when:** when TODO-4 wires the Dotwave Kotlin ceremony to
//! emit an integrity-attestation blob + signature at ceremony time, a
//! real capture from the SM-G986U can replace the synthesized positive
//! test. The negative tests are unaffected — they continue to use real
//! bytes.

#[path = "fixtures/sm_g986u_binding_proof.rs"]
mod fixture;

use codec::Encode;
use der::{Decode, Encode as DerEncode};
use frame_support::BoundedVec;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use x509_cert::Certificate as X509Certificate;

use zk_pki_integrity::{
    IntegrityAttestation, DOTWAVE_PACKAGE_NAME, DOTWAVE_SIGNING_CERT_HASH,
};
use zk_pki_primitives::tpm::AttestationType;
use zk_pki_tpm::{
    verify_binding_proof, verify_binding_proof_with_pins, AttestationPayloadV3,
    BindingProofError, ChainError, VerifiedBootState,
    GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH, KNOWN_MANUFACTURER_INTERMEDIATES,
};

// ═══════════════════════════════════════════════════════════════════════
// Negative tests — real SM-G986U hardware bytes
// ═══════════════════════════════════════════════════════════════════════
//
// The real cert_ec and attest_ec leaves sign / certify real StrongBox
// private keys we do not possess, so step 7 (integrity) would always
// fail signature verification. Every negative test below short-circuits
// before step 7, so the integrity fields can be arbitrary bytes.
// `garbage_integrity()` returns empty vecs — their only role is to
// populate the struct.

/// Well-formed integrity blob + placeholder signature for negative
/// tests that use `real_payload()`. Values mirror the OLD fixture's
/// cert_ec chain `attestationApplicationId` so the step-3.5 cross-
/// check passes cleanly and doesn't shadow the test's intended
/// failure point (challenge mismatch / tampered binding sig / etc.).
///
/// Signature bytes are placeholder — no negative test here reaches
/// step 7 (integrity sig verify). A test that *does* expect step 7 to
/// fail either overrides `integrity_blob` with malformed bytes (→
/// decode failure) or overrides `integrity_signature` (→ sig failure);
/// either path returns `IntegrityFailed(_)` which is what those tests
/// assert against.
fn integrity_matching_old_fixture() -> (Vec<u8>, Vec<u8>) {
    // SHA-256 of the dev-build APK signing cert that produced the
    // captured `sm_g986u_binding_proof` fixture. Identical byte value
    // to what the fixture's cert_ec leaf has embedded in its
    // `attestationApplicationId` extension — so chain-vs-blob
    // comparison at step 3.5 matches.
    const OLD_FIXTURE_SIGNING_CERT_HASH: [u8; 32] = [
        0xf8, 0x8c, 0xbc, 0xa4, 0x59, 0x07, 0x34, 0xcb,
        0x0c, 0x0c, 0x42, 0xed, 0xc5, 0xe1, 0x4c, 0xc1,
        0xfe, 0xaf, 0xd8, 0x16, 0x9d, 0x41, 0x04, 0x73,
        0xf3, 0xdf, 0x53, 0x68, 0x12, 0xf3, 0x45, 0x72,
    ];
    let att = IntegrityAttestation {
        package_name: BoundedVec::try_from(b"com.dotwave.dotwave".to_vec())
            .expect("fits in ConstU32<256>"),
        signing_cert_hash: OLD_FIXTURE_SIGNING_CERT_HASH,
        block_number: 0,
        no_debugger: true,
        keystore_integrity: true,
    };
    (att.encode(), vec![0u8; 72])
}

fn real_payload() -> AttestationPayloadV3 {
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&fixture::hmac_binding_output());
    let (integrity_blob, integrity_signature) = integrity_matching_old_fixture();
    AttestationPayloadV3 {
        cert_ec_chain: fixture::cert_ec_chain(),
        attest_ec_chain: fixture::attest_ec_chain(),
        hmac_binding_output: hmac,
        binding_signature: fixture::binding_signature(),
        integrity_blob,
        integrity_signature,
    }
}

fn real_challenge() -> Vec<u8> {
    fixture::challenge()
}

#[test]
fn root_mismatch_rejected() {
    // RootMismatch fires only when both chains independently clear
    // Gate 1 but their root cert bytes still differ. With the real
    // SM-G986U fixture both chains share a byte-identical root, and no
    // single-byte mutation yields a chain whose root still passes Gate 1
    // (tampering breaks either sig or pin first). So this one negative
    // test is synthesized.
    //
    // Trick: build two shared CAs using the **same** root keypair but
    // **different** serial numbers. Same keypair → same SPKI → both
    // roots hash to the same pin. Different serial → different DER
    // bytes → RootMismatch fires. This proves the byte-equality check
    // is load-bearing even when the roots share a public key.
    let common_root_key = synth::p256_sk([7u8; 32]);
    let shared_a = synth::build_shared_ca_with_root_key(common_root_key.clone(), 1);
    let shared_b = synth::build_shared_ca_with_root_key(common_root_key, 2);
    assert_eq!(
        shared_a.root_spki_hash(),
        shared_b.root_spki_hash(),
        "same root keypair → same SPKI",
    );
    assert_ne!(
        shared_a.root_der(),
        shared_b.root_der(),
        "different serial → different root cert bytes",
    );

    let challenge = [0xabu8; 32];
    let hmac_output = [0u8; 32];
    let cert_ec_sk = synth::p256_sk([10u8; 32]);
    let attest_ec_sk = synth::p256_sk([11u8; 32]);

    let cert_ec_leaf_der = synth::leaf(
        &shared_a,
        &cert_ec_sk,
        synth::key_description_der(&challenge),
    );
    let attest_ec_leaf_der = synth::leaf(
        &shared_b,
        &attest_ec_sk,
        synth::key_description_der(&challenge),
    );

    let mut cert_ec_chain = vec![cert_ec_leaf_der];
    cert_ec_chain.extend(shared_a.chain_tail());
    let mut attest_ec_chain = vec![attest_ec_leaf_der];
    attest_ec_chain.extend(shared_b.chain_tail());

    let (integrity_blob, integrity_signature) =
        synth::valid_integrity(&cert_ec_sk, 1_000, 1_500, 1_200);
    let binding_signature =
        synth::sign_binding_commitment(&attest_ec_sk, &hmac_output, &challenge);

    let payload = AttestationPayloadV3 {
        cert_ec_chain,
        attest_ec_chain,
        hmac_binding_output: hmac_output,
        binding_signature,
        integrity_blob,
        integrity_signature,
    };

    // Pin on shared SPKI; allow both chains' intermediates (different
    // intermediates because each shared CA builds its own).
    let intermediates: Vec<[u8; 32]> =
        vec![shared_a.int_spki_hash(), shared_b.int_spki_hash()];

    let err = verify_binding_proof_with_pins(
        &payload,
        &shared_a.root_spki_hash(),
        &intermediates,
        &challenge,
        1_000,
        1_500,
    )
    .expect_err("different root cert bytes must be caught");
    assert_eq!(err, BindingProofError::RootMismatch);
}

#[test]
fn challenge_mismatch_rejected() {
    let payload = real_payload();
    // Mutate the expected_challenge input so both chains' embedded
    // challenges differ from it. Real challenge is 32 bytes; any other
    // 32 bytes trigger the mismatch.
    let wrong = [0x00u8; 32];
    let err = verify_binding_proof(&payload, &wrong, 1, 1_000_000)
        .expect_err("wrong expected_challenge must be rejected");
    assert_eq!(err, BindingProofError::ChallengeMismatch);
}

#[test]
fn binding_signature_invalid_rejected() {
    let mut payload = real_payload();
    // Flip a byte deep inside the binding sig's DER integer bodies so
    // ECDSA math fails but DER framing still parses. The ceremony
    // produced a 72-byte DER; byte ~50 lands in one of the integers.
    let idx = payload.binding_signature.len() - 5;
    payload.binding_signature[idx] ^= 0xff;

    let err = verify_binding_proof(
        &payload,
        &real_challenge(),
        1,
        1_000_000,
    )
    .expect_err("tampered binding signature must be rejected");
    assert_eq!(err, BindingProofError::BindingSignatureInvalid);
}

#[test]
fn integrity_check_failed_rejected() {
    // All prior gates must clear for this test to reach step 7, so we
    // keep real cert_ec, real attest_ec, real HMAC, real binding sig,
    // real challenge — and feed an integrity blob that will fail
    // verification. The real cert_ec pubkey's private half is not ours,
    // so any signature we produce over any blob won't verify. Passing
    // random bytes as the blob causes SCALE decode to fail. Either path
    // lands in `IntegrityFailed(_)`.
    let mut payload = real_payload();
    payload.integrity_blob = vec![0xffu8; 64];
    payload.integrity_signature = vec![0xffu8; 72];

    let err = verify_binding_proof(
        &payload,
        &real_challenge(),
        1,
        1_000_000,
    )
    .expect_err("bad integrity blob must be rejected");
    assert!(
        matches!(err, BindingProofError::IntegrityFailed(_)),
        "got {:?}",
        err
    );
}

#[test]
fn cert_ec_chain_invalid_rejected() {
    let mut payload = real_payload();
    // Flip a byte in the cert_ec leaf signature — chain sig verification
    // fails at leaf→int. Surfaces as CertEcChainInvalid.
    let last = payload.cert_ec_chain[0].len() - 10;
    payload.cert_ec_chain[0][last] ^= 0xff;

    let err = verify_binding_proof(
        &payload,
        &real_challenge(),
        1,
        1_000_000,
    )
    .expect_err("tampered cert_ec chain must be rejected");
    assert!(
        matches!(err, BindingProofError::CertEcChainInvalid(_)),
        "got {:?}",
        err
    );
}

#[test]
fn attest_ec_chain_invalid_rejected() {
    let mut payload = real_payload();
    let last = payload.attest_ec_chain[0].len() - 10;
    payload.attest_ec_chain[0][last] ^= 0xff;

    let err = verify_binding_proof(
        &payload,
        &real_challenge(),
        1,
        1_000_000,
    )
    .expect_err("tampered attest_ec chain must be rejected");
    assert!(
        matches!(err, BindingProofError::AttestEcChainInvalid(_)),
        "got {:?}",
        err
    );
}

// ═══════════════════════════════════════════════════════════════════════
// AAID cross-check negatives — synthesized
// ═══════════════════════════════════════════════════════════════════════
//
// The AAID cross-check at step 3.5 compares the chain's
// `attestationApplicationId` against the integrity blob's declared
// fields. To exercise the rejection paths we synthesize a cert_ec chain
// that carries an AAID with the "wrong" values (different from what the
// blob declares) and feed it through `verify_binding_proof_with_pins`.
//
// The integrity blob is built via `synth::valid_integrity`, which uses
// `DOTWAVE_PACKAGE_NAME` / `DOTWAVE_SIGNING_CERT_HASH` from
// `zk-pki-integrity`. So "wrong" means "not equal to the constant".

#[test]
fn package_name_mismatch_rejected() {
    let challenge = [0x9au8; 32];
    let hmac_output = [0x42u8; 32];

    let shared = synth::build_shared_ca();
    let cert_ec_sk = synth::p256_sk([3u8; 32]);
    let attest_ec_sk = synth::p256_sk([4u8; 32]);

    // cert_ec leaf declares an AAID with the WRONG package name. The
    // blob will declare DOTWAVE_PACKAGE_NAME; cross-check fires.
    let cert_ec_leaf_der = synth::leaf(
        &shared,
        &cert_ec_sk,
        synth::key_description_der_with_aaid(
            &challenge,
            b"com.wrong.pkg",
            &DOTWAVE_SIGNING_CERT_HASH,
        ),
    );
    // attest_ec doesn't need AAID for this test — cross-check examines
    // cert_ec primary and only compares attest_ec if BOTH carry AAID.
    let attest_ec_leaf_der = synth::leaf(
        &shared,
        &attest_ec_sk,
        synth::key_description_der(&challenge),
    );

    let tail = shared.chain_tail();
    let mut cert_ec_chain = vec![cert_ec_leaf_der];
    cert_ec_chain.extend(tail.clone());
    let mut attest_ec_chain = vec![attest_ec_leaf_der];
    attest_ec_chain.extend(tail);

    let binding_signature =
        synth::sign_binding_commitment(&attest_ec_sk, &hmac_output, &challenge);
    let (integrity_blob, integrity_signature) =
        synth::valid_integrity(&cert_ec_sk, 1_000, 1_500, 1_200);

    let payload = AttestationPayloadV3 {
        cert_ec_chain,
        attest_ec_chain,
        hmac_binding_output: hmac_output,
        binding_signature,
        integrity_blob,
        integrity_signature,
    };

    let intermediates: [[u8; 32]; 1] = [shared.int_spki_hash()];
    let err = verify_binding_proof_with_pins(
        &payload,
        &shared.root_spki_hash(),
        &intermediates,
        &challenge,
        1_000,
        1_500,
    )
    .expect_err("chain AAID package_name mismatch must be rejected");
    assert_eq!(err, BindingProofError::PackageNameCrossCheckFailed);
}

#[test]
fn signing_cert_mismatch_rejected() {
    let challenge = [0x9au8; 32];
    let hmac_output = [0x42u8; 32];

    let shared = synth::build_shared_ca();
    let cert_ec_sk = synth::p256_sk([3u8; 32]);
    let attest_ec_sk = synth::p256_sk([4u8; 32]);

    // cert_ec AAID has the right package_name but the WRONG signing
    // cert hash. Cross-check passes the package_name branch, then
    // fails on the hash branch.
    let wrong_hash = [0xabu8; 32];
    let cert_ec_leaf_der = synth::leaf(
        &shared,
        &cert_ec_sk,
        synth::key_description_der_with_aaid(
            &challenge,
            DOTWAVE_PACKAGE_NAME,
            &wrong_hash,
        ),
    );
    let attest_ec_leaf_der = synth::leaf(
        &shared,
        &attest_ec_sk,
        synth::key_description_der(&challenge),
    );

    let tail = shared.chain_tail();
    let mut cert_ec_chain = vec![cert_ec_leaf_der];
    cert_ec_chain.extend(tail.clone());
    let mut attest_ec_chain = vec![attest_ec_leaf_der];
    attest_ec_chain.extend(tail);

    let binding_signature =
        synth::sign_binding_commitment(&attest_ec_sk, &hmac_output, &challenge);
    let (integrity_blob, integrity_signature) =
        synth::valid_integrity(&cert_ec_sk, 1_000, 1_500, 1_200);

    let payload = AttestationPayloadV3 {
        cert_ec_chain,
        attest_ec_chain,
        hmac_binding_output: hmac_output,
        binding_signature,
        integrity_blob,
        integrity_signature,
    };

    let intermediates: [[u8; 32]; 1] = [shared.int_spki_hash()];
    let err = verify_binding_proof_with_pins(
        &payload,
        &shared.root_spki_hash(),
        &intermediates,
        &challenge,
        1_000,
        1_500,
    )
    .expect_err("chain AAID signing_cert_hash mismatch must be rejected");
    assert_eq!(err, BindingProofError::SigningCertCrossCheckFailed);
}

// ═══════════════════════════════════════════════════════════════════════
// Positive test — synthesized end-to-end
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn valid_payload_v3_verifies() {
    // Fully synthesized: test-generated keypairs, test-built cert chains,
    // test-synthesized integrity blob. Uses verify_binding_proof_with_pins
    // to thread test-specific root + manufacturer pin through. Proves
    // composition logic is correct.
    //
    // Replace-when TODO-4: when Dotwave Kotlin ceremony captures a real
    // integrity blob from the SM-G986U, this test can be replaced with
    // real fixture bytes and call the production verify_binding_proof.
    let challenge = [0x9au8; 32];
    let hmac_output = [0x42u8; 32];

    let shared = synth::build_shared_ca();

    let cert_ec_sk = synth::p256_sk([3u8; 32]);
    let attest_ec_sk = synth::p256_sk([4u8; 32]);

    let cert_ec_leaf_der = synth::leaf(
        &shared,
        &cert_ec_sk,
        synth::key_description_der(&challenge),
    );
    let attest_ec_leaf_der = synth::leaf(
        &shared,
        &attest_ec_sk,
        synth::key_description_der(&challenge),
    );

    // Cache the shared tail once — serializing twice may produce
    // byte-different outputs (timestamp or signature-randomness
    // sensitivity in the underlying X.509 builder), which would fail
    // the RootMismatch check on a logically-valid payload.
    let tail = shared.chain_tail();
    let mut cert_ec_chain = vec![cert_ec_leaf_der];
    cert_ec_chain.extend(tail.clone());
    let mut attest_ec_chain = vec![attest_ec_leaf_der];
    attest_ec_chain.extend(tail);

    let binding_signature =
        synth::sign_binding_commitment(&attest_ec_sk, &hmac_output, &challenge);

    let (integrity_blob, integrity_signature) =
        synth::valid_integrity(&cert_ec_sk, 1_000, 1_500, 1_200);

    let payload = AttestationPayloadV3 {
        cert_ec_chain,
        attest_ec_chain,
        hmac_binding_output: hmac_output,
        binding_signature,
        integrity_blob,
        integrity_signature,
    };

    let intermediates: [[u8; 32]; 1] = [shared.int_spki_hash()];
    let verified = verify_binding_proof_with_pins(
        &payload,
        &shared.root_spki_hash(),
        &intermediates,
        &challenge,
        1_000,
        1_500,
    )
    .expect("synthesized valid payload must verify");

    assert_eq!(verified.attestation_type, AttestationType::Tpm);
    assert!(verified.device_locked);
    assert_eq!(verified.verified_boot_state, VerifiedBootState::Verified);
    assert!(verified.manufacturer_verified);
}

// Sanity: verify the production pin constants are wired through from the
// crate root exactly as the synthesized positive test reads them. Cheap
// compile-time check that re-exports didn't drift.
#[test]
fn production_constants_are_visible() {
    let _: [u8; 32] = GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH;
    let _: &[[u8; 32]] = KNOWN_MANUFACTURER_INTERMEDIATES;
    let _: ChainError = ChainError::EmptyChain;
}

// ═══════════════════════════════════════════════════════════════════════
// Synthesis helpers — test-only cert chain and blob construction
// ═══════════════════════════════════════════════════════════════════════

mod synth {
    use super::*;

    /// Root + intermediate pair signing a shared chain.
    pub struct SharedCa {
        pub root: Certificate,
        pub intermediate: Certificate,
    }

    impl SharedCa {
        pub fn root_der(&self) -> Vec<u8> {
            self.root.serialize_der().expect("root cert serializes")
        }

        pub fn int_der(&self) -> Vec<u8> {
            self.intermediate
                .serialize_der_with_signer(&self.root)
                .expect("int signed by root")
        }

        /// The two certs below the leaf: intermediate + root.
        pub fn chain_tail(&self) -> Vec<Vec<u8>> {
            vec![self.int_der(), self.root_der()]
        }

        pub fn root_spki_hash(&self) -> [u8; 32] {
            spki_blake2b_256(&self.root_der())
        }

        pub fn int_spki_hash(&self) -> [u8; 32] {
            spki_blake2b_256(&self.int_der())
        }
    }

    pub fn build_shared_ca() -> SharedCa {
        build_shared_ca_with_root_key(p256_sk([1u8; 32]), 1)
    }

    /// Build a shared CA (root + intermediate) using a caller-supplied
    /// root keypair. `root_serial` differentiates otherwise-identical
    /// roots for the root-mismatch test.
    pub fn build_shared_ca_with_root_key(
        root_sk: SigningKey,
        root_serial: u64,
    ) -> SharedCa {
        let root_kp = p256_to_rcgen_kp(&root_sk);
        let mut root_params = CertificateParams::new(vec!["test-root".to_string()]);
        root_params.alg = &PKCS_ECDSA_P256_SHA256;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_pair = Some(root_kp);
        root_params.serial_number = Some(rcgen::SerialNumber::from(root_serial));
        let root = Certificate::from_params(root_params).expect("root cert builds");

        let int_sk = p256_sk([2u8; 32]);
        let int_kp = p256_to_rcgen_kp(&int_sk);
        let mut int_params = CertificateParams::new(vec!["test-intermediate".to_string()]);
        int_params.alg = &PKCS_ECDSA_P256_SHA256;
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_params.key_pair = Some(int_kp);
        let intermediate =
            Certificate::from_params(int_params).expect("int cert builds");

        SharedCa { root, intermediate }
    }

    /// Build a leaf cert signed by `shared.intermediate`, carrying the
    /// given KeyDescription extension payload.
    pub fn leaf(shared: &SharedCa, leaf_sk: &SigningKey, key_desc: Vec<u8>) -> Vec<u8> {
        let leaf_kp = p256_to_rcgen_kp(leaf_sk);
        let mut leaf_params = CertificateParams::new(vec!["test-leaf".to_string()]);
        leaf_params.alg = &PKCS_ECDSA_P256_SHA256;
        leaf_params.key_pair = Some(leaf_kp);
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                key_desc,
            ));
        let leaf_cert = Certificate::from_params(leaf_params).expect("leaf cert builds");
        leaf_cert
            .serialize_der_with_signer(&shared.intermediate)
            .expect("leaf signed by int")
    }

    /// Deterministic P-256 keypair — avoids pulling an RNG into dev-deps
    /// and keeps test signatures reproducible.
    pub fn p256_sk(scalar: [u8; 32]) -> SigningKey {
        SigningKey::from_slice(&scalar).expect("valid P-256 scalar")
    }

    fn p256_to_rcgen_kp(sk: &SigningKey) -> KeyPair {
        let pkcs8 = build_p256_pkcs8_der(sk);
        KeyPair::from_der(&pkcs8).expect("rcgen accepts pkcs8")
    }

    /// Hand-roll a PKCS#8 PrivateKeyInfo DER for a P-256 ECDSA signing
    /// key. Avoids pulling the `pkcs8` feature into p256 just so test
    /// code can hand rcgen a keypair. Format: PKCS#8 outer SEQUENCE
    /// wrapping `{ version, AlgorithmIdentifier(ecPublicKey/prime256v1),
    /// OCTET STRING(ECPrivateKey) }`.
    fn build_p256_pkcs8_der(sk: &SigningKey) -> Vec<u8> {
        // ecPublicKey: 1.2.840.10045.2.1
        const OID_EC_PUBLIC_KEY: &[u8] =
            &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        // prime256v1 / secp256r1: 1.2.840.10045.3.1.7
        const OID_PRIME256V1: &[u8] =
            &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

        let scalar = sk.to_bytes();
        let scalar_bytes: &[u8] = scalar.as_ref();
        let vk = sk.verifying_key();
        let encoded = vk.to_encoded_point(false);
        let pubkey_sec1 = encoded.as_bytes();

        // AlgorithmIdentifier SEQUENCE { ecPublicKey OID, prime256v1 OID }
        let mut algo = Vec::new();
        algo.extend(der_tlv(0x06, OID_EC_PUBLIC_KEY));
        algo.extend(der_tlv(0x06, OID_PRIME256V1));
        let algo_seq = der_sequence(&algo);

        // ECPrivateKey SEQUENCE { version 1, OCTET STRING scalar,
        //                         [1] EXPLICIT BIT STRING pubkey }
        let mut ec_priv = Vec::new();
        ec_priv.extend(der_tlv(0x02, &[1])); // INTEGER 1
        ec_priv.extend(der_tlv(0x04, scalar_bytes)); // OCTET STRING
        let mut bit_string_content = Vec::with_capacity(1 + pubkey_sec1.len());
        bit_string_content.push(0); // unused bits = 0
        bit_string_content.extend_from_slice(pubkey_sec1);
        let bit_str = der_tlv(0x03, &bit_string_content);
        // [1] EXPLICIT tag: 0xA1 (context-specific, constructed, #1)
        ec_priv.extend(der_tlv(0xA1, &bit_str));
        let ec_priv_seq = der_sequence(&ec_priv);
        let ec_priv_octet = der_tlv(0x04, &ec_priv_seq);

        // PKCS#8 PrivateKeyInfo
        let mut pkcs8 = Vec::new();
        pkcs8.extend(der_tlv(0x02, &[0])); // version INTEGER 0
        pkcs8.extend(algo_seq);
        pkcs8.extend(ec_priv_octet);
        der_sequence(&pkcs8)
    }

    /// Parse a DER cert and compute the Blake2b-256 of its
    /// SubjectPublicKeyInfo — matches the hash formula used by
    /// `verify_chain_with_pin_and_intermediates`.
    fn spki_blake2b_256(cert_der: &[u8]) -> [u8; 32] {
        let cert = X509Certificate::from_der(cert_der).expect("valid DER");
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("spki re-encodes");
        sp_core::hashing::blake2_256(&spki_der)
    }

    /// Sign `blake2_256(hmac_output || challenge)` with `attest_sk`.
    pub fn sign_binding_commitment(
        attest_sk: &SigningKey,
        hmac_output: &[u8; 32],
        challenge: &[u8; 32],
    ) -> Vec<u8> {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(hmac_output);
        input.extend_from_slice(challenge);
        let commitment = sp_core::hashing::blake2_256(&input);
        let sig: Signature = attest_sk.sign(&commitment);
        sig.to_der().as_bytes().to_vec()
    }

    /// Build a SCALE-encoded valid IntegrityAttestation blob and sign its
    /// blake2b-256 hash with `cert_ec_sk`. The block number lies inside
    /// the offer window.
    pub fn valid_integrity(
        cert_ec_sk: &SigningKey,
        created_at: u64,
        expiry: u64,
        block: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        assert!(block >= created_at && block <= expiry);
        let att = IntegrityAttestation {
            package_name: BoundedVec::try_from(DOTWAVE_PACKAGE_NAME.to_vec())
                .expect("fits in ConstU32<256>"),
            signing_cert_hash: DOTWAVE_SIGNING_CERT_HASH,
            block_number: block,
            no_debugger: true,
            keystore_integrity: true,
        };
        let blob = att.encode();
        let digest = sp_core::hashing::blake2_256(&blob);
        let sig: Signature = cert_ec_sk.sign(&digest);
        (blob, sig.to_der().as_bytes().to_vec())
    }

    /// Minimal Android Keystore KeyDescription DER — just enough for
    /// the parser in `parse.rs` to extract challenge, StrongBox
    /// security levels, and RootOfTrust (deviceLocked=true,
    /// verifiedBootState=Verified). The parser walks by position, so
    /// we emit exactly the sequence it expects.
    pub fn key_description_der(challenge: &[u8; 32]) -> Vec<u8> {
        let mut inner = Vec::new();
        // attestationVersion INTEGER — any value the parser skips.
        inner.extend(der_integer_u8(3));
        // attestationSecurityLevel ENUMERATED = 2 (StrongBox).
        inner.extend(der_enumerated(2));
        // keyMintVersion INTEGER — skipped.
        inner.extend(der_integer_u8(3));
        // keyMintSecurityLevel ENUMERATED = 2 (StrongBox).
        inner.extend(der_enumerated(2));
        // attestationChallenge OCTET STRING.
        inner.extend(der_octet_string(challenge));
        // uniqueId OCTET STRING — empty; parser skips.
        inner.extend(der_octet_string(&[]));
        // softwareEnforced AuthorizationList — empty SEQUENCE.
        inner.extend(der_sequence(&[]));
        // hardwareEnforced AuthorizationList containing [704] RootOfTrust.
        let mut rot = Vec::new();
        // verifiedBootKey OCTET STRING — opaque 32 bytes.
        rot.extend(der_octet_string(&[0u8; 32]));
        // deviceLocked BOOLEAN = true (0xFF per DER).
        rot.extend(der_boolean(true));
        // verifiedBootState ENUMERATED = 0 (Verified).
        rot.extend(der_enumerated(0));
        // verifiedBootHash OCTET STRING.
        rot.extend(der_octet_string(&[0u8; 32]));
        let rot_seq = der_sequence(&rot);
        let rot_explicit_704 = der_explicit_704(&rot_seq);
        let hw_enforced = der_sequence(&rot_explicit_704);
        inner.extend(hw_enforced);
        der_sequence(&inner)
    }

    /// Like [`key_description_der`] but also includes an
    /// `attestationApplicationId` block inside **softwareEnforced**
    /// (where the real Keystore daemon writes it, since the TEE
    /// cannot verify package identity). Used by the AAID cross-check
    /// negative tests — the caller sets `package_name` or
    /// `signing_cert_hash` to a value that disagrees with the
    /// integrity blob, confirming the step-3.5 check fires.
    pub fn key_description_der_with_aaid(
        challenge: &[u8; 32],
        package_name: &[u8],
        signing_cert_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend(der_integer_u8(3));
        inner.extend(der_enumerated(2));
        inner.extend(der_integer_u8(3));
        inner.extend(der_enumerated(2));
        inner.extend(der_octet_string(challenge));
        inner.extend(der_octet_string(&[]));

        // softwareEnforced — [709] EXPLICIT OCTET STRING wrapping
        //   SEQUENCE { SET OF (SEQUENCE { OCTET STRING, INTEGER }),
        //              SET OF OCTET STRING }
        let pkg_info_inner = {
            let mut v = Vec::new();
            v.extend(der_octet_string(package_name));
            v.extend(der_integer_u8(1));
            v
        };
        let pkg_info_seq = der_sequence(&pkg_info_inner);
        let pkg_info_set = der_set(&pkg_info_seq);
        let digest_set = der_set(&der_octet_string(signing_cert_hash));
        let aaid_inner_seq = {
            let mut v = Vec::new();
            v.extend(pkg_info_set);
            v.extend(digest_set);
            der_sequence(&v)
        };
        let aaid_octet = der_octet_string(&aaid_inner_seq);
        let aaid_explicit_709 = der_explicit_709(&aaid_octet);
        let sw_enforced = der_sequence(&aaid_explicit_709);
        inner.extend(sw_enforced);

        // hardwareEnforced — [704] EXPLICIT SEQUENCE (rootOfTrust).
        let mut rot = Vec::new();
        rot.extend(der_octet_string(&[0u8; 32]));
        rot.extend(der_boolean(true));
        rot.extend(der_enumerated(0));
        rot.extend(der_octet_string(&[0u8; 32]));
        let rot_seq = der_sequence(&rot);
        let rot_explicit_704 = der_explicit_704(&rot_seq);
        let hw_enforced = der_sequence(&rot_explicit_704);
        inner.extend(hw_enforced);

        der_sequence(&inner)
    }

    // ─── DER encoders ──────────────────────────────────────────────
    //
    // Hand-rolled to avoid pulling a DER-builder crate just for these
    // tests. Only encodes what KeyDescription needs: small INTEGERs,
    // OCTET STRINGs, BOOLEAN, ENUMERATED, SEQUENCE, and the long-form
    // context-specific tag [704] EXPLICIT.

    fn encode_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else {
            let bytes = len.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&b| b != 0)
                .expect("len != 0 implies some non-zero byte");
            let nonzero = &bytes[start..];
            let mut out = vec![0x80 | nonzero.len() as u8];
            out.extend_from_slice(nonzero);
            out
        }
    }

    fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + body.len());
        out.push(tag);
        out.extend(encode_len(body.len()));
        out.extend_from_slice(body);
        out
    }

    fn der_integer_u8(v: u8) -> Vec<u8> {
        // DER INTEGER, always encoded as unsigned with high bit safe:
        // for v in 0..=0x7F, content is one byte; for 0x80..=0xFF
        // prepend 0x00 to keep unsigned.
        if v & 0x80 != 0 {
            der_tlv(0x02, &[0, v])
        } else {
            der_tlv(0x02, &[v])
        }
    }

    fn der_enumerated(v: u8) -> Vec<u8> {
        der_tlv(0x0A, &[v])
    }

    fn der_octet_string(body: &[u8]) -> Vec<u8> {
        der_tlv(0x04, body)
    }

    fn der_boolean(v: bool) -> Vec<u8> {
        der_tlv(0x01, &[if v { 0xFF } else { 0x00 }])
    }

    fn der_sequence(body: &[u8]) -> Vec<u8> {
        der_tlv(0x30, body)
    }

    fn der_set(body: &[u8]) -> Vec<u8> {
        // 0x31 = SET (universal class, constructed, tag 17).
        der_tlv(0x31, body)
    }

    /// `[704] EXPLICIT inner` — class=context-specific, constructed.
    /// 704 = 5 * 128 + 64, base-128 encoded as 0x85 0x40 (continuation
    /// bit set on the high digit, clear on the low). Short-form 0x1F
    /// signals long-form tag number follows.
    fn der_explicit_704(inner: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + 4 + inner.len());
        out.push(0xBF); // 10_1_11111 = ctx-spec, constructed, long-form
        out.push(0x85); // continuation, high digit = 5
        out.push(0x40); // terminator, low digit = 64
        out.extend(encode_len(inner.len()));
        out.extend_from_slice(inner);
        out
    }

    /// `[709] EXPLICIT inner` — same encoding pattern as 704.
    /// 709 = 5 * 128 + 69 → base-128 `0x85 0x45`.
    fn der_explicit_709(inner: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + 4 + inner.len());
        out.push(0xBF);
        out.push(0x85);
        out.push(0x45); // terminator, low digit = 69
        out.extend(encode_len(inner.len()));
        out.extend_from_slice(inner);
        out
    }
}
