//! Basic-shape and SPKI-hash assertions on the captured AMD fTPM fixture.
//! The live chain verifier itself is Google-Android-specific (RSA root,
//! P-384 intermediates, etc.); this suite is just confirming the bytes
//! parse and the intermediate's SPKI hashes to the value we wrote into
//! `chain.rs::AMD_FTPM_PRG_RN_INTERMEDIATE_HASH`.

#[path = "fixtures/amd_ftpm_chain.rs"]
mod fixture;

use der::{Decode, Encode};
use x509_cert::Certificate;
use zk_pki_tpm::chain::AMD_FTPM_PRG_RN_INTERMEDIATE_HASH;

#[test]
fn amd_ek_cert_parses() {
    let cert = fixture::amd_ek_cert();
    assert!(!cert.is_empty());
    assert_eq!(cert[0], 0x30, "DER SEQUENCE tag");
    let _ = Certificate::from_der(&cert).expect("EK cert must parse as X.509");
}

#[test]
fn amd_chain_has_three_certs() {
    let chain = fixture::amd_ftpm_chain();
    assert_eq!(chain.len(), 3);
}

#[test]
fn amd_intermediate_is_ca() {
    let intermediate = fixture::amd_intermediate_cert();
    assert!(!intermediate.is_empty());
    assert_eq!(intermediate[0], 0x30);
    let cert = Certificate::from_der(&intermediate)
        .expect("intermediate cert must parse");
    // Subject CN=PRG-RN.
    let subject = cert.tbs_certificate.subject.to_string();
    assert!(
        subject.contains("PRG-RN"),
        "subject should contain PRG-RN, got: {subject}",
    );
}

#[test]
fn amd_root_is_self_signed() {
    let root = fixture::amd_root_cert();
    assert!(!root.is_empty());
    assert_eq!(root[0], 0x30);
    let cert = Certificate::from_der(&root).expect("root cert must parse");
    // Subject and issuer both CN=AMDTPM → self-signed.
    let subject = cert.tbs_certificate.subject.to_string();
    let issuer = cert.tbs_certificate.issuer.to_string();
    assert!(subject.contains("AMDTPM"), "subject: {subject}");
    assert!(issuer.contains("AMDTPM"), "issuer: {issuer}");
    assert_eq!(subject, issuer, "root must be self-signed");
}

#[test]
fn amd_intermediate_spki_hash_matches_constant() {
    let intermediate = fixture::amd_intermediate_cert();
    let cert = Certificate::from_der(&intermediate)
        .expect("intermediate cert must parse");
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("SPKI must re-encode");
    let spki_hash = sp_io::hashing::blake2_256(&spki_der);
    assert_eq!(
        spki_hash, AMD_FTPM_PRG_RN_INTERMEDIATE_HASH,
        "AMD intermediate SPKI hash must match the KNOWN_MANUFACTURER_INTERMEDIATES entry",
    );
}
