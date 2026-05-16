//! Sanity checks on the TODO-3 binding-proof fixture. The full pallet-side
//! payload parser and binding-proof verifier come in the next step; this
//! test just confirms the captured bytes decode cleanly and behave as
//! expected under the primitives already shipped (chain verification, pin
//! check, challenge extraction).

#[path = "fixtures/sm_g986u_binding_proof.rs"]
mod fixture;

use codec::Encode;
use zk_pki_tpm::{parse_attestation, verify_chain};

#[test]
fn cert_ec_chain_verifies_and_extracts_expected_fields() {
    let chain = fixture::cert_ec_chain();
    verify_chain(&chain).expect("cert_ec chain must verify end-to-end");

    // Run the existing single-chain parser over cert_ec — confirms
    // KeyDescription decode still works against this fresh fixture.
    let bytes = chain.encode();
    let parsed = parse_attestation(&bytes).expect("cert_ec parses");

    assert_eq!(
        parsed.attestation_challenge.as_slice(),
        fixture::challenge().as_slice(),
        "cert_ec leaf's KeyDescription must embed the ceremony challenge"
    );
    assert!(parsed.is_pop_eligible,
        "SM-G986U is locked + verified-booted — PoP eligible");
}

#[test]
fn attest_ec_chain_verifies_and_shares_challenge() {
    let chain = fixture::attest_ec_chain();
    verify_chain(&chain).expect("attest_ec chain must verify end-to-end");

    let bytes = chain.encode();
    let parsed = parse_attestation(&bytes).expect("attest_ec parses");

    assert_eq!(
        parsed.attestation_challenge.as_slice(),
        fixture::challenge().as_slice(),
        "attest_ec leaf must carry the same ceremony challenge — the \
         'same ceremony' binding across both chains depends on this"
    );
    assert!(parsed.is_pop_eligible);
}

#[test]
fn both_chains_share_the_same_root_cert() {
    // The intermediates and root cert are provisioned at manufacture time
    // and are identical across every attestation request on the device.
    // The TODO-3 parser will rely on this — same-root byte comparison is
    // one axis of "same hardware" proof.
    assert_eq!(
        fixture::cert_ec_chain().last().unwrap(),
        fixture::attest_ec_chain().last().unwrap(),
    );
}

#[test]
fn captured_sizes_match_android_keystore_expectations() {
    assert_eq!(fixture::challenge().len(), 32);
    assert_eq!(fixture::cert_ec_leaf().len(), 670);
    assert_eq!(fixture::cert_ec_int1().len(), 565);
    assert_eq!(fixture::cert_ec_int2().len(), 987);
    assert_eq!(fixture::cert_ec_root().len(), 1380);
    assert_eq!(fixture::attest_ec_leaf().len(), 670);
    // HMAC-SHA256 output is always 32 bytes.
    assert_eq!(fixture::hmac_binding_output().len(), 32);
    // P-256 ECDSA signatures in DER encoding are ~70–72 bytes depending on
    // r/s leading-zero padding. The captured one is 72.
    assert_eq!(fixture::binding_signature().len(), 72);
}

#[test]
fn expected_commitment_is_blake2b_of_hmac_output_and_challenge() {
    let hmac_out = fixture::hmac_binding_output();
    let challenge = fixture::challenge();
    let mut input = Vec::with_capacity(hmac_out.len() + challenge.len());
    input.extend_from_slice(&hmac_out);
    input.extend_from_slice(&challenge);
    let computed = sp_core::hashing::blake2_256(&input);
    assert_eq!(
        computed, fixture::EXPECTED_COMMITMENT,
        "commitment recorded in fixture must match \
         sp_core::hashing::blake2_256(hmac_output || challenge)"
    );
}
