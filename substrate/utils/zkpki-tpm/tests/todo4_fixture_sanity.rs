//! Sanity tests for the TODO-4 real-hardware ceremony fixture.
//!
//! Runs each gate of the `verify_binding_proof` pipeline separately
//! against the SM-G986U capture so a failure pinpoints exactly which
//! step regressed. Kept separate from `payload_v3.rs` — that file owns
//! the synthesized-chain positive test and the Gate 1–6 negative cases,
//! while this file exists to prove the real bytes from hardware are
//! self-consistent and ready for pallet integration.

#[path = "fixtures/sm_g986u_todo4_ceremony.rs"]
mod fixture;

use codec::Decode;
use zk_pki_integrity::{IntegrityAttestation, DOTWAVE_PACKAGE_NAME};
use zk_pki_tpm::{
    parse_chain_without_verify, verify_chain, verify_binding_proof, AttestationPayloadV3,
    BindingProofError,
};

#[test]
fn cert_ec_chain_verifies_end_to_end() {
    let chain = fixture::cert_ec_chain();
    verify_chain(&chain).expect("cert_ec chain must verify against production pins");
}

#[test]
fn attest_ec_chain_verifies_end_to_end() {
    let chain = fixture::attest_ec_chain();
    verify_chain(&chain).expect("attest_ec chain must verify against production pins");
}

#[test]
fn both_chains_share_byte_identical_root() {
    let cert_root = fixture::cert_ec_chain().last().cloned().unwrap();
    let attest_root = fixture::attest_ec_chain().last().cloned().unwrap();
    assert_eq!(
        cert_root, attest_root,
        "shared hardware → shared provisioned root cert",
    );
}

#[test]
fn challenge_echo_matches_input_challenge() {
    assert_eq!(
        fixture::challenge(),
        fixture::challenge_echo(),
        "Kotlin ceremony must echo back the same 32 bytes it baked into \
         setAttestationChallenge() on both EC keys",
    );
}

#[test]
fn both_leaves_embed_the_same_challenge() {
    let cert_ec = parse_chain_without_verify(&fixture::cert_ec_chain())
        .expect("cert_ec leaf parses");
    let attest_ec = parse_chain_without_verify(&fixture::attest_ec_chain())
        .expect("attest_ec leaf parses");
    assert_eq!(cert_ec.attestation_challenge, fixture::challenge());
    assert_eq!(attest_ec.attestation_challenge, fixture::challenge());
}

#[test]
fn package_name_cross_check_passes_on_real_fixture() {
    // Extract attestationApplicationId.package_name from the fresh
    // SM-G986U cert_ec leaf and assert it equals the production
    // Dotwave identifier. Proves the parser's tag-709 extraction is
    // wired correctly and that the three-way agreement (chain ↔ blob ↔
    // constant) holds on real hardware bytes with the corrected
    // applicationId.
    let cert_ec = parse_chain_without_verify(&fixture::cert_ec_chain())
        .expect("cert_ec leaf parses");
    let chain_pkg = cert_ec
        .package_name
        .as_ref()
        .expect("tag [709] present on SM-G986U attestation chain");
    assert_eq!(
        chain_pkg.as_slice(),
        b"com.dotwave.app",
        "chain attestationApplicationId.package_name must equal the \
         production applicationId after the gradle rename",
    );

    // Both chains should carry the same AAID — they were generated
    // back-to-back in the same ceremony under the same applicationId.
    let attest_ec = parse_chain_without_verify(&fixture::attest_ec_chain()).unwrap();
    assert_eq!(
        attest_ec.package_name.as_ref().unwrap().as_slice(),
        chain_pkg.as_slice(),
        "cert_ec and attest_ec chains must agree on AAID package_name",
    );
}

#[test]
fn signing_cert_hash_extracted_from_fixture() {
    // Parser extracts the SHA-256 of the APK signing cert from the
    // AAID's signature_digests set. Byte-for-byte assertion against
    // the known dev-build hash (mirrored in the fixture's
    // `DEV_APK_SIGNING_CERT_HASH` constant and inside the integrity
    // blob) confirms the three sources agree.
    let cert_ec = parse_chain_without_verify(&fixture::cert_ec_chain()).unwrap();
    let chain_hash = cert_ec
        .signing_cert_hash
        .expect("signature_digests set present on SM-G986U chain");
    assert_eq!(
        chain_hash, fixture::DEV_APK_SIGNING_CERT_HASH,
        "chain AAID signature_digest must equal the fixture's \
         ground-truth dev APK signing cert hash",
    );
}

#[test]
fn both_leaves_are_strongbox_and_verified_boot() {
    let cert_ec = parse_chain_without_verify(&fixture::cert_ec_chain()).unwrap();
    let attest_ec = parse_chain_without_verify(&fixture::attest_ec_chain()).unwrap();
    assert!(cert_ec.is_pop_eligible, "cert_ec must be PoP-eligible");
    assert!(attest_ec.is_pop_eligible, "attest_ec must be PoP-eligible");
    assert!(cert_ec.device_locked);
    assert!(attest_ec.device_locked);
}

#[test]
fn binding_signature_verifies_over_commitment() {
    // Reproduce step 5 of verify_binding_proof without running the rest.
    let attest_ec = parse_chain_without_verify(&fixture::attest_ec_chain()).unwrap();
    let hmac_output = fixture::hmac_binding_output();
    let challenge = fixture::challenge();
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(&hmac_output);
    input.extend_from_slice(&challenge);
    let commitment = sp_core::hashing::blake2_256(&input);
    assert!(
        attest_ec.pubkey.verify_signature(&commitment, &fixture::binding_signature()),
        "attest_ec leaf pubkey must verify the binding signature over \
         blake2_256(hmac_output || challenge)",
    );
}

#[test]
fn integrity_blob_decodes_to_expected_fields() {
    let bytes = fixture::integrity_blob();
    let att = IntegrityAttestation::decode(&mut &bytes[..])
        .expect("SCALE decode of real integrity blob");
    assert_eq!(
        att.package_name.as_slice(),
        DOTWAVE_PACKAGE_NAME,
        "blob's package_name must equal the zk-pki-integrity constant",
    );
    assert_eq!(
        att.signing_cert_hash, fixture::DEV_APK_SIGNING_CERT_HASH,
        "blob's signing_cert_hash must equal the captured dev-build cert hash",
    );
    assert_eq!(att.block_number, 0, "block_number placeholder is 0");
    assert!(att.no_debugger, "ceremony ran without debugger");
    assert!(
        att.keystore_integrity,
        "Keystore daemon signer was visible"
    );
}

#[test]
fn integrity_signature_verifies_under_cert_ec_pubkey() {
    // The integrity blob is signed by zkpki_cert_ec, which is the same
    // key certified by the cert_ec attestation chain. Verify without
    // invoking full verify_integrity_attestation — that check would
    // currently fail at `InvalidSigningCert` because the placeholder
    // constant is still [0u8; 32] (see doc comment in the fixture).
    let cert_ec = parse_chain_without_verify(&fixture::cert_ec_chain()).unwrap();
    let digest = sp_core::hashing::blake2_256(&fixture::integrity_blob());
    assert!(
        cert_ec.pubkey.verify_signature(&digest, &fixture::integrity_signature()),
        "cert_ec pubkey must verify the integrity signature over \
         blake2_256(integrity_blob)",
    );
}

#[test]
fn full_verify_binding_proof_fires_integrity_gate_as_expected() {
    // End-to-end call. Current state: the real SM-G986U capture passes
    // ALL gates except the signing cert hash check — chain verification
    // (both chains), root pin, manufacturer intermediate, same-root,
    // same-challenge, binding signature verify, integrity blob decode,
    // and integrity signature verify all pass on real bytes.
    //
    // The one expected rejection is
    // `IntegrityFailed(InvalidSigningCert)` — `DOTWAVE_SIGNING_CERT_HASH`
    // in `zk-pki-integrity` is deliberately left at the `[0u8; 32]`
    // placeholder. Updating it to the current dev-build hash would
    // create a constant that works on one machine and silently fails
    // everywhere else; gating behind `schema_version` is ceremony for a
    // problem that resolves itself when the real production APK signing
    // key exists.
    //
    // **Action before mainnet: update `DOTWAVE_SIGNING_CERT_HASH` in
    // `zk-pki-integrity` to the SHA-256 of the production Dotwave APK
    // signing certificate.** That is the right place for this reminder
    // — the test asserts the exact failure mode so a silent regression
    // (e.g., someone setting the constant to a plausible-looking dev
    // value) shows up as this test failing to match
    // `InvalidSigningCert`.
    let payload = AttestationPayloadV3 {
        cert_ec_chain: fixture::cert_ec_chain(),
        attest_ec_chain: fixture::attest_ec_chain(),
        hmac_binding_output: {
            let mut h = [0u8; 32];
            h.copy_from_slice(&fixture::hmac_binding_output());
            h
        },
        binding_signature: fixture::binding_signature(),
        integrity_blob: fixture::integrity_blob(),
        integrity_signature: fixture::integrity_signature(),
    };
    let result = verify_binding_proof(&payload, &fixture::challenge(), 0, u64::MAX);
    match result {
        Err(BindingProofError::IntegrityFailed(inner)) => {
            // Pinpoint: must be the InvalidSigningCert variant, proving
            // every prior gate passed and the only remaining blocker is
            // the placeholder constant.
            assert!(
                format!("{:?}", inner).contains("InvalidSigningCert"),
                "unexpected integrity sub-error: {:?}",
                inner,
            );
        }
        Ok(_) => panic!(
            "verify_binding_proof unexpectedly passed — did \
             DOTWAVE_SIGNING_CERT_HASH get updated? If so this test needs \
             updating too."
        ),
        Err(other) => panic!(
            "expected IntegrityFailed(InvalidSigningCert); got {:?}",
            other,
        ),
    }
}
