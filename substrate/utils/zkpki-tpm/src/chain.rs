//! Certificate chain signature verification and root pinning.
//!
//! This module walks an Android Keystore attestation cert chain from leaf to
//! root, verifies each adjacent pair's signature cryptographically, and pins
//! the root's SubjectPublicKeyInfo to Google's Hardware Attestation Root CA.
//!
//! Without this module, [`crate::parse::parse_attestation`] would trust the
//! KeyDescription extension inside a cert the attacker could have made up.
//! With it, the KeyDescription is only trusted once the cert carrying it has
//! been verified to terminate at a Google-signed root.
//!
//! Supported signature algorithms (observed in real chains from Android 13 /
//! Snapdragon 865 StrongBox):
//!
//! | Cert pair in SM-G986U chain         | Algorithm                |
//! |-------------------------------------|--------------------------|
//! | leaf (P-256) signed by int1 (P-256) | ECDSA with SHA-256       |
//! | int1 (P-256) signed by int2 (P-384) | ECDSA with SHA-256       |
//! | int2 (P-384) signed by root (RSA)   | RSA-PKCS1-v1_5 SHA-256   |
//! | root self-signed (RSA 4096)         | RSA-PKCS1-v1_5 SHA-256   |

extern crate alloc;

use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use rsa::{pkcs1::DecodeRsaPublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

/// Extract the raw DER bytes of the TBSCertificate (including its tag and
/// length) from the original cert DER. Signature verification must use these
/// exact bytes — re-encoding the parsed `TbsCertificate` via
/// `Encode::to_der()` produces canonically-correct DER but is not guaranteed
/// to be byte-identical to the original, which breaks signature checks
/// because the signer signed the original bytes.
fn extract_tbs_raw(cert_der: &[u8]) -> Option<&[u8]> {
    if cert_der.len() < 2 || cert_der[0] != 0x30 {
        return None;
    }
    let (outer_len_nbytes, _) = parse_der_length(&cert_der[1..])?;
    let tbs_start = 1 + outer_len_nbytes;
    if cert_der.len() < tbs_start + 2 || cert_der[tbs_start] != 0x30 {
        return None;
    }
    let (tbs_len_nbytes, tbs_len) = parse_der_length(&cert_der[tbs_start + 1..])?;
    let tbs_end = tbs_start + 1 + tbs_len_nbytes + tbs_len;
    if cert_der.len() < tbs_end {
        return None;
    }
    Some(&cert_der[tbs_start..tbs_end])
}

/// Decode a DER length. Returns (bytes consumed, length value).
/// Supports short form (< 128) and long form up to 4 length bytes.
fn parse_der_length(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let first = bytes[0];
    if first & 0x80 == 0 {
        return Some((1, first as usize));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || bytes.len() < 1 + n {
        return None;
    }
    let mut len: usize = 0;
    for i in 0..n {
        len = (len << 8) | (bytes[1 + i] as usize);
    }
    Some((1 + n, len))
}

/// Signature algorithm OIDs encountered in Android Keystore attestation chains.
const ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// Public key algorithm OIDs.
const EC_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Named curve OIDs used inside ecPublicKey `parameters`.
const SECP_256_R1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP_384_R1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Blake2b-256 of the DER-encoded SubjectPublicKeyInfo belonging to Google's
/// Hardware Attestation Root CA (issuer serial `f92009e853b6b045`).
///
/// Extracted from the real SM-G986U attestation chain captured on 2026-04-16
/// via `/tmp/extract_root_pin.py` — ground truth, not a spec or blog value.
/// Any attestation chain whose root SPKI does not hash to this value is
/// rejected, regardless of how plausible the chain otherwise looks.
///
/// This is the trust-anchor pin. It proves the chain is Google-signed but
/// not which hardware manufacturer produced the secure element — Google's
/// root is universal across Android Keystore attestation. Manufacturer
/// identity is checked separately via [`KNOWN_MANUFACTURER_INTERMEDIATES`].
pub const GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH: [u8; 32] = [
    0x27, 0x5c, 0x6e, 0xf3, 0xfe, 0xfc, 0xeb, 0x62,
    0x1c, 0x2b, 0x5a, 0x99, 0x29, 0x7c, 0x8c, 0xca,
    0xae, 0x7b, 0x1c, 0x18, 0xd4, 0xd8, 0xe1, 0xc9,
    0xf6, 0xd8, 0xeb, 0xfb, 0xe8, 0x26, 0xa6, 0xc5,
];

/// Blake2b-256 of the DER-encoded SubjectPublicKeyInfo belonging to the
/// Samsung S3K250AF StrongBox manufacturer intermediate certificate
/// (subject serialNumber `dcafc938d18986a5`, P-384, signed directly by
/// Google's Hardware Attestation Root CA).
///
/// Extracted from the SM-G986U attestation chain (cert at index 2, between
/// the device-specific batch intermediate and the Google root) via
/// `/tmp/extract_intermediates.py`. In Android Keystore attestation, Google
/// signs one intermediate like this per secure-element manufacturer / SoC
/// family — every device shipping the Samsung S3K250AF StrongBox chip
/// inherits this same intermediate. Matching on its SPKI proves the
/// attesting device contains legitimate Samsung secure-element hardware,
/// not just a generic Google-signed chain built by some other path.
pub const SAMSUNG_S3K250AF_INTERMEDIATE_HASH: [u8; 32] = [
    0x97, 0x25, 0x56, 0x39, 0x9b, 0x78, 0x81, 0xa3,
    0xa0, 0x41, 0xed, 0x82, 0x2b, 0x2e, 0xb5, 0xab,
    0x5c, 0xfe, 0x3d, 0x4c, 0xf5, 0x95, 0xd5, 0xc5,
    0x32, 0xc7, 0xa7, 0x99, 0xe6, 0xd1, 0x37, 0x7b,
];

/// Blake2b-256 of the DER-encoded SubjectPublicKeyInfo belonging to the
/// AMD fTPM PRG-RN intermediate CA (subject `CN=PRG-RN,
/// O=Advanced Micro Devices`, P-256, signed by `CN=AMDTPM` root).
///
/// Captured from Lucy (Anthony's AMD Ryzen laptop) on 2026-04-17.
/// Extracted via `/tmp/extract_amd_spki.py` and cross-verified by
/// Python `cryptography` lib — both methods agree on the SPKI bytes
/// and the Blake2b-256 output. Fixture is at
/// `tpm/tests/fixtures/amd_ftpm_chain.rs`; the
/// `amd_intermediate_spki_hash_matches_constant` test keeps this
/// constant pinned to what the fixture produces at verification time.
///
/// Note: AMD fTPM chains are not Android Keystore attestation chains,
/// so they do NOT pass through `verify_chain` — that path pins to
/// Google's root. This intermediate's hash is listed in
/// [`KNOWN_MANUFACTURER_INTERMEDIATES`] so that future TPM-vendor
/// attestation flows (where the manufacturer gate applies but the
/// Google-root pin is replaced) can recognize AMD fTPM hardware.
pub const AMD_FTPM_PRG_RN_INTERMEDIATE_HASH: [u8; 32] = [
    0xbb, 0xe1, 0x79, 0x30, 0xb1, 0x4b, 0xf5, 0x00,
    0x0b, 0xc7, 0x65, 0x6f, 0x97, 0xb0, 0x32, 0xdd,
    0x3e, 0xf3, 0x53, 0xa2, 0xf8, 0xe9, 0x47, 0x5c,
    0x98, 0x14, 0xbc, 0x41, 0x36, 0xc5, 0xe3, 0x23,
];

/// STMicroelectronics TPM ECC384 Intermediate CA 01.
/// Captured: Dell Latitude hardware at OOBE, April 2026.
/// AIA: http://secure.globalsign.com/stmtpmecc384int01.crt
/// Thumbprint: E5E87D5FF99AD6D6CF2518C300C2346326CB3B52
/// Covers: STM33HTPHAHD4 TPM, ECC P-384 keys.
///
/// TODO: add DER fixture at
///       `pki/tpm/tests/fixtures/stm_intermediates/stmtpmecc384int01.der`
///       and wire `stm_ecc384_int01_spki_hash_matches_constant` test
///       (mirror the `amd_intermediate_spki_hash_matches_constant`
///       pattern in `amd_ftpm_chain_sanity.rs`). DER bytes on
///       Anthony's flash drive pending fixture pass.
pub const STM_ECC384_INT01_INTERMEDIATE_HASH: [u8; 32] = [
    0xec, 0x5a, 0xe4, 0x62, 0xb5, 0x3a, 0x4b, 0x40,
    0xf3, 0x6c, 0x49, 0xf5, 0x34, 0xd8, 0x0e, 0xb1,
    0xcb, 0x44, 0xd9, 0xe3, 0x0d, 0xe2, 0x38, 0x11,
    0x5d, 0x16, 0xc5, 0xf4, 0xf4, 0xfd, 0x33, 0xb2,
];

/// STMicroelectronics TPM ECC Intermediate CA 02.
/// Captured: Dell Latitude hardware at OOBE, April 2026.
/// AIA: http://secure.globalsign.com/stmtpmeccint02.crt
/// Thumbprint: 4BE0B50031A24AB1DE162010276BE8ACFAE5F64B
/// Covers: STM33HTPHAHD4 TPM, ECC P-256 keys.
///
/// TODO: add DER fixture at
///       `pki/tpm/tests/fixtures/stm_intermediates/stmtpmeccint02.der`
///       and wire `stm_ecc_int02_spki_hash_matches_constant` test
///       (mirror the `amd_intermediate_spki_hash_matches_constant`
///       pattern in `amd_ftpm_chain_sanity.rs`). DER bytes on
///       Anthony's flash drive pending fixture pass.
pub const STM_ECC_INT02_INTERMEDIATE_HASH: [u8; 32] = [
    0x32, 0xd0, 0x56, 0x94, 0xc3, 0xc7, 0x71, 0xf0,
    0x48, 0xa4, 0x26, 0x29, 0x6b, 0xb1, 0xd4, 0xa4,
    0x77, 0x49, 0xa3, 0x1b, 0xa7, 0x01, 0x15, 0xa0,
    0x28, 0x20, 0xac, 0xd8, 0x4e, 0xbe, 0x62, 0xe7,
];

/// STMicroelectronics TPM EK Intermediate CA 06.
/// Captured: Dell Latitude hardware at OOBE, April 2026.
/// AIA: http://secure.globalsign.com/stmtpmekint06.crt
/// Thumbprint: A446DA11C302000F9E147B3053A7C3F8BF75F78F
/// Covers: STM33HTPHAHD4 TPM, RSA-2048 keys.
///
/// TODO: add DER fixture at
///       `pki/tpm/tests/fixtures/stm_intermediates/stmtpmekint06.der`
///       and wire `stm_ek_int06_spki_hash_matches_constant` test
///       (mirror the `amd_intermediate_spki_hash_matches_constant`
///       pattern in `amd_ftpm_chain_sanity.rs`). DER bytes on
///       Anthony's flash drive pending fixture pass.
pub const STM_EK_INT06_INTERMEDIATE_HASH: [u8; 32] = [
    0xf4, 0x1e, 0x4d, 0xfa, 0x4c, 0x4c, 0x8f, 0xe8,
    0x2c, 0x04, 0x19, 0x55, 0x5c, 0x0f, 0x7d, 0x2c,
    0xd5, 0xc0, 0x12, 0x62, 0x44, 0xf0, 0x61, 0x70,
    0xaa, 0xaa, 0x9e, 0x31, 0x14, 0xa3, 0x4c, 0x72,
];

/// SPKI hashes of known-legitimate StrongBox manufacturer intermediate
/// certificates. An attestation chain must contain at least one cert
/// (between leaf and root, exclusive) whose SPKI hashes to an entry in
/// this list — otherwise the chain is rejected with
/// [`ChainError::UnknownManufacturer`].
///
/// The Google root pin is necessary but not sufficient: every legitimate
/// Android Keystore attestation chain terminates at the same Google root,
/// so pinning the root alone cannot distinguish real secure-element
/// hardware from a theoretical rogue OEM that Google nonetheless signed.
/// The manufacturer intermediate gate is the layer that proves the
/// attesting device contains hardware from a known, tested, legitimate
/// secure-element vendor.
///
/// When the ink! EK trust chain registry contract ships, this constant is
/// replaced by a contract query. The pallet logic stays the same —
/// `schema_version` handles the migration.
pub const KNOWN_MANUFACTURER_INTERMEDIATES: &[[u8; 32]] = &[
    SAMSUNG_S3K250AF_INTERMEDIATE_HASH,
    AMD_FTPM_PRG_RN_INTERMEDIATE_HASH,
    STM_ECC384_INT01_INTERMEDIATE_HASH,
    STM_ECC_INT02_INTERMEDIATE_HASH,
    STM_EK_INT06_INTERMEDIATE_HASH,
    // GOOGLE_TITAN_M2_INTERMEDIATE_HASH — add when tested on Pixel
    // QUALCOMM_SPU_INTERMEDIATE_HASH    — add when tested
];

/// Chain verification error cases. Each failure mode is a distinct enum
/// variant so negative-case tests can assert the exact reason a chain was
/// rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    EmptyChain,
    ChainTooLong,
    MalformedCertificate,
    UnsupportedSignatureAlgorithm,
    UnsupportedCurve,
    ParentAlgorithmMismatch,
    TbsEncodingFailure,
    SignatureEncodingFailure,
    SpkiEncodingFailure,
    BadPublicKey,
    SignatureVerifyFailed,
    RootNotSelfSigned,
    RootPinMismatch,
    UnknownManufacturer,
}

/// Maximum chain length we accept, to bound work. Real Android chains are
/// typically 3–4 certs; anything much larger is suspicious.
const MAX_CHAIN_LEN: usize = 10;

/// Verify a cert chain and pin the root to Google's Hardware Attestation
/// Root CA. This is the production entry point.
pub fn verify_chain(chain: &[Vec<u8>]) -> Result<(), ChainError> {
    verify_chain_with_pin(chain, &GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH)
}

/// Verify a cert chain and pin the root to the supplied SPKI hash. Uses
/// the default [`KNOWN_MANUFACTURER_INTERMEDIATES`] set for the manufacturer
/// gate. Exposed so negative-case tests can inject a non-matching pin and
/// confirm rejection without needing a second forged chain.
pub fn verify_chain_with_pin(
    chain: &[Vec<u8>],
    pin: &[u8; 32],
) -> Result<(), ChainError> {
    verify_chain_with_pin_and_intermediates(chain, pin, KNOWN_MANUFACTURER_INTERMEDIATES)
}

/// Verify a cert chain, pin the root to the supplied SPKI hash, and require
/// at least one cert between leaf and root (exclusive) to match the supplied
/// manufacturer intermediate set. Exposed so negative-case tests can inject
/// an empty or non-matching manufacturer set and confirm the
/// [`ChainError::UnknownManufacturer`] rejection path fires.
pub fn verify_chain_with_pin_and_intermediates(
    chain: &[Vec<u8>],
    pin: &[u8; 32],
    known_intermediates: &[[u8; 32]],
) -> Result<(), ChainError> {
    if chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }
    if chain.len() > MAX_CHAIN_LEN {
        return Err(ChainError::ChainTooLong);
    }

    let mut parsed: Vec<Certificate> = Vec::with_capacity(chain.len());
    for der in chain.iter() {
        parsed.push(
            Certificate::from_der(der).map_err(|_| ChainError::MalformedCertificate)?,
        );
    }

    let root_idx = parsed.len() - 1;
    let root_der = &chain[root_idx];
    let root = &parsed[root_idx];

    // Enforce root self-signature first. If this fails, the chain's anchor
    // is dead regardless of what the pin says.
    verify_cert_sig(root_der, root, root)?;

    // Root SPKI pin check. Re-encode the parsed SPKI and Blake2b-256 it.
    // Re-encoding SPKI is safe here because we only hash it; we don't need
    // byte-exact equality with the original signer's bytes.
    let root_spki_der = root
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| ChainError::SpkiEncodingFailure)?;
    let root_spki_hash = sp_io::hashing::blake2_256(&root_spki_der);
    if &root_spki_hash != pin {
        return Err(ChainError::RootPinMismatch);
    }

    // Walk leaf → root pairwise.
    for i in 0..parsed.len().saturating_sub(1) {
        verify_cert_sig(&chain[i], &parsed[i], &parsed[i + 1])?;
    }

    // Manufacturer intermediate gate. At least one cert strictly between
    // leaf and root must have an SPKI matching a known StrongBox
    // manufacturer intermediate. The Google root is universal across
    // Android, so this gate is what proves the attesting device contains
    // legitimate secure-element hardware from a known vendor (e.g. Samsung
    // S3K250AF) rather than an arbitrary Google-signed leaf.
    //
    // Chains shorter than 3 have no intermediates and cannot carry this
    // proof — they are rejected as UnknownManufacturer. In practice real
    // Android Keystore attestation chains are always 3–4 deep, so this
    // only excludes pathological inputs.
    let intermediate_slice: &[Certificate] = parsed
        .get(1..parsed.len().saturating_sub(1))
        .unwrap_or(&[]);
    let mut manufacturer_matched = false;
    for cert in intermediate_slice {
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| ChainError::SpkiEncodingFailure)?;
        let spki_hash = sp_io::hashing::blake2_256(&spki_der);
        if known_intermediates.iter().any(|m| m == &spki_hash) {
            manufacturer_matched = true;
            break;
        }
    }
    if !manufacturer_matched {
        return Err(ChainError::UnknownManufacturer);
    }

    Ok(())
}

/// Verify that `child`'s signature was produced by `parent`'s public key
/// over `child`'s TBS bytes. `child_der` is the original DER encoding of
/// the child cert — we extract the raw TBS bytes from it rather than
/// re-encoding the parsed `TbsCertificate`, to guarantee byte-exact match
/// with what the issuer signed.
fn verify_cert_sig(
    child_der: &[u8],
    child: &Certificate,
    parent: &Certificate,
) -> Result<(), ChainError> {
    let tbs_bytes = extract_tbs_raw(child_der).ok_or(ChainError::TbsEncodingFailure)?;

    let sig_bytes = child
        .signature
        .as_bytes()
        .ok_or(ChainError::SignatureEncodingFailure)?;

    let sig_alg = &child.signature_algorithm.oid;
    let parent_spki = &parent.tbs_certificate.subject_public_key_info;

    if *sig_alg == ECDSA_WITH_SHA256 {
        verify_ecdsa_sha256(tbs_bytes, sig_bytes, parent_spki)
    } else if *sig_alg == SHA256_WITH_RSA {
        verify_rsa_pkcs1_sha256(tbs_bytes, sig_bytes, parent_spki)
    } else {
        Err(ChainError::UnsupportedSignatureAlgorithm)
    }
}

fn verify_ecdsa_sha256(
    tbs: &[u8],
    sig: &[u8],
    parent_spki: &SubjectPublicKeyInfoOwned,
) -> Result<(), ChainError> {
    if parent_spki.algorithm.oid != EC_PUBLIC_KEY {
        return Err(ChainError::ParentAlgorithmMismatch);
    }

    // Named-curve ecPublicKey stores the curve OID directly as the
    // algorithm's parameters.
    let params = parent_spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(ChainError::BadPublicKey)?;
    let curve_oid: ObjectIdentifier = params
        .decode_as()
        .map_err(|_| ChainError::BadPublicKey)?;

    let pubkey_bytes = parent_spki.subject_public_key.raw_bytes();

    // Pre-compute the SHA-256 hash of TBS. Both P-256 and P-384 ECDSA
    // signatures on Android Keystore attestation chains use SHA-256,
    // independent of the curve. Using `verify_prehash` makes the hash
    // choice explicit rather than relying on each curve crate's default
    // DigestPrimitive (which is SHA-256 for P-256 but SHA-384 for P-384 —
    // a silent mismatch that causes verification to fail).
    let digest = Sha256::digest(tbs);

    if curve_oid == SECP_256_R1 {
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
            .map_err(|_| ChainError::BadPublicKey)?;
        let sig = Signature::from_der(sig)
            .map_err(|_| ChainError::SignatureEncodingFailure)?;
        vk.verify_prehash(&digest, &sig)
            .map_err(|_| ChainError::SignatureVerifyFailed)
    } else if curve_oid == SECP_384_R1 {
        use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
            .map_err(|_| ChainError::BadPublicKey)?;
        let sig = Signature::from_der(sig)
            .map_err(|_| ChainError::SignatureEncodingFailure)?;
        vk.verify_prehash(&digest, &sig)
            .map_err(|_| ChainError::SignatureVerifyFailed)
    } else {
        Err(ChainError::UnsupportedCurve)
    }
}

fn verify_rsa_pkcs1_sha256(
    tbs: &[u8],
    sig: &[u8],
    parent_spki: &SubjectPublicKeyInfoOwned,
) -> Result<(), ChainError> {
    if parent_spki.algorithm.oid != RSA_ENCRYPTION {
        return Err(ChainError::ParentAlgorithmMismatch);
    }

    // The BIT STRING wraps a PKCS#1 RSAPublicKey SEQUENCE.
    let pubkey_bytes = parent_spki.subject_public_key.raw_bytes();
    let public_key =
        RsaPublicKey::from_pkcs1_der(pubkey_bytes).map_err(|_| ChainError::BadPublicKey)?;

    let digest = Sha256::digest(tbs);
    let scheme = Pkcs1v15Sign::new::<Sha256>();

    public_key
        .verify(scheme, &digest[..], sig)
        .map_err(|_| ChainError::SignatureVerifyFailed)
}
