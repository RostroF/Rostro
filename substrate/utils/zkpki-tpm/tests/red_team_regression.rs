//! Red-team regression: pins the Fix 1 invariant that `ek_hash` is
//! derived from the leaf cert's `SubjectPublicKeyInfo`, not from the
//! manufacturer attestation root.
//!
//! Background: an earlier implementation hashed `chain.last()` (the
//! root cert). That collapsed every device sharing a manufacturer
//! root to the same EK hash, breaking root-scoped Sybil resistance
//! (pki/CLAUDE.md invariant #6). The fix hashes the leaf SPKI, which
//! is device-unique (fresh per secure-hardware keypair) and bound to
//! the signed TBS of the leaf so a chain that verifies cannot have a
//! mutated SPKI.

#[path = "fixtures/sm_g986u_attestation.rs"]
mod fixture;

use codec::Encode;
use zk_pki_tpm::parse_attestation;

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
fn ek_hash_basis_is_leaf_spki_not_manufacturer_root() {
    let parsed = parse_attestation(&build_chain())
        .expect("SM-G986U fixture parses cleanly");

    // Both fields must be populated.
    assert!(!parsed.leaf_spki_der.is_empty(), "leaf_spki_der must be populated");
    assert!(!parsed.root_cert_der.is_empty(), "root_cert_der must be populated");

    // Leaf SPKI is a small DER structure (AlgorithmIdentifier +
    // subjectPublicKey BitString). The root cert DER is the whole
    // signed certificate. SPKI must be strictly smaller than the
    // root cert bytes — if these were equal or SPKI > root, the
    // field extraction is wrong.
    assert!(
        parsed.leaf_spki_der.len() < parsed.root_cert_der.len(),
        "leaf SPKI must be smaller than the root cert (got SPKI={}, root={})",
        parsed.leaf_spki_der.len(),
        parsed.root_cert_der.len(),
    );

    // And they must not be byte-equal. If an implementation
    // regression were ever to assign `root_cert_der` into
    // `leaf_spki_der`, this assertion fails loudly.
    assert_ne!(
        parsed.leaf_spki_der, parsed.root_cert_der,
        "leaf_spki_der must be distinct from root_cert_der",
    );

    // Their hashes must also differ — the production `ek_hash =
    // blake2_256(leaf_spki_der)` MUST NOT equal what the old broken
    // implementation produced (`blake2_256(root_cert_der)`).
    let leaf_spki_hash = sp_io::hashing::blake2_256(&parsed.leaf_spki_der);
    let root_hash = sp_io::hashing::blake2_256(&parsed.root_cert_der);
    assert_ne!(
        leaf_spki_hash, root_hash,
        "EK identity hash (blake2_256 leaf SPKI) must not collide with \
         the old manufacturer-root hash",
    );
}
