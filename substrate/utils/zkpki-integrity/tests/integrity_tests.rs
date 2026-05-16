//! Integration tests for `zk-pki-integrity`.
//!
//! Each test fabricates a P-256 keypair, builds an [`IntegrityAttestation`],
//! SCALE-encodes it, signs the blake2b-256 hash of the encoded bytes with
//! the private key, and feeds the result through
//! [`verify_integrity_attestation`]. The positive case must verify; each
//! negative case mutates exactly one field (or the signature) and asserts
//! the specific [`IntegrityError`] variant that gate should fire.

use codec::Encode;
use frame_support::BoundedVec;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

use zk_pki_integrity::{
    verify_integrity_attestation, IntegrityAttestation, IntegrityError, DOTWAVE_PACKAGE_NAME,
    DOTWAVE_SIGNING_CERT_HASH,
};
use zk_pki_primitives::crypto::DevicePublicKey;

/// Offer window used across tests. Ceremony block 1_200 lies inside;
/// 999 is before; 1_501 is after.
const OFFER_CREATED_AT: u64 = 1_000;
const OFFER_EXPIRY: u64 = 1_500;

struct TestKeypair {
    sk: SigningKey,
    device_pubkey: DevicePublicKey,
}

/// Deterministic P-256 keypair. Using a fixed scalar avoids pulling an
/// RNG into dev-dependencies; RFC 6979 nonce derivation inside p256's
/// `Signer::sign` means signatures are deterministic too, which keeps
/// test output stable.
fn test_keypair() -> TestKeypair {
    let secret_scalar = [7u8; 32];
    let sk = SigningKey::from_slice(&secret_scalar).expect("valid P-256 scalar");
    let vk: VerifyingKey = *sk.verifying_key();
    let encoded = vk.to_encoded_point(false);
    let device_pubkey =
        DevicePublicKey::new_p256(encoded.as_bytes()).expect("valid SEC1 encoding");
    TestKeypair { sk, device_pubkey }
}

fn default_attestation(block_number: u64) -> IntegrityAttestation {
    IntegrityAttestation {
        package_name: BoundedVec::try_from(DOTWAVE_PACKAGE_NAME.to_vec())
            .expect("fits in ConstU32<256>"),
        signing_cert_hash: DOTWAVE_SIGNING_CERT_HASH,
        block_number,
        no_debugger: true,
        keystore_integrity: true,
    }
}

/// Sign `blake2_256(blob)` with `sk`. Matches what the Kotlin ceremony
/// will do: blake2b-256 of the SCALE-encoded blob, then ECDSA-P256-SHA256
/// over that 32-byte digest (SHA-256 applied internally by p256's
/// `Signer::sign`).
fn sign_blob(sk: &SigningKey, blob: &[u8]) -> Vec<u8> {
    let digest = sp_io::hashing::blake2_256(blob);
    let sig: Signature = sk.sign(&digest);
    sig.to_der().as_bytes().to_vec()
}

#[test]
fn valid_attestation_verifies() {
    let kp = test_keypair();
    let att = default_attestation(1_200);
    let blob = att.encode();
    let sig = sign_blob(&kp.sk, &blob);

    let result = verify_integrity_attestation(
        &blob,
        &sig,
        &kp.device_pubkey,
        OFFER_CREATED_AT,
        OFFER_EXPIRY,
    )
    .expect("valid attestation must verify");
    assert_eq!(result.block_number, 1_200);
    assert!(result.no_debugger);
    assert!(result.keystore_integrity);
}

#[test]
fn invalid_signature_rejected() {
    let kp = test_keypair();
    let att = default_attestation(1_200);
    let blob = att.encode();
    let mut sig = sign_blob(&kp.sk, &blob);
    // Flip a byte inside the DER-encoded signature. ECDSA verification
    // must fail — either the byte lands in the integer value and the
    // math rejects, or it lands in the DER structure and parsing rejects.
    // Either path surfaces as SignatureInvalid via verify_signature's
    // DER-then-raw fallback that rejects both.
    let last = sig.len() - 1;
    sig[last] ^= 0xff;

    assert_eq!(
        verify_integrity_attestation(
            &blob,
            &sig,
            &kp.device_pubkey,
            OFFER_CREATED_AT,
            OFFER_EXPIRY,
        ),
        Err(IntegrityError::SignatureInvalid),
    );
}

#[test]
fn wrong_package_name_rejected() {
    let kp = test_keypair();
    let mut att = default_attestation(1_200);
    att.package_name =
        BoundedVec::try_from(b"com.notdotwave.app".to_vec()).expect("fits in ConstU32<256>");
    let blob = att.encode();
    let sig = sign_blob(&kp.sk, &blob);

    assert_eq!(
        verify_integrity_attestation(
            &blob,
            &sig,
            &kp.device_pubkey,
            OFFER_CREATED_AT,
            OFFER_EXPIRY,
        ),
        Err(IntegrityError::InvalidPackageName),
    );
}

#[test]
fn wrong_signing_cert_rejected() {
    // During beta, `DOTWAVE_SIGNING_CERT_HASH` is `[0u8; 32]` and the
    // Kotlin ceremony emits zeros too, so the equality check on the
    // happy path passes. This test exercises the rejection path by
    // emitting a non-zero blob hash against the zero constant. Once the
    // constant is grounded in the real APK signing cert hash at launch,
    // the test still exercises the rejection path — any mismatch fails,
    // regardless of which side holds which value.
    let kp = test_keypair();
    let mut att = default_attestation(1_200);
    att.signing_cert_hash = [0xabu8; 32];
    let blob = att.encode();
    let sig = sign_blob(&kp.sk, &blob);

    assert_eq!(
        verify_integrity_attestation(
            &blob,
            &sig,
            &kp.device_pubkey,
            OFFER_CREATED_AT,
            OFFER_EXPIRY,
        ),
        Err(IntegrityError::InvalidSigningCert),
    );
}

#[test]
fn ceremony_before_offer_window_rejected() {
    let kp = test_keypair();
    let att = default_attestation(OFFER_CREATED_AT - 1);
    let blob = att.encode();
    let sig = sign_blob(&kp.sk, &blob);

    assert_eq!(
        verify_integrity_attestation(
            &blob,
            &sig,
            &kp.device_pubkey,
            OFFER_CREATED_AT,
            OFFER_EXPIRY,
        ),
        Err(IntegrityError::CeremonyOutsideOfferWindow),
    );
}

#[test]
fn ceremony_after_offer_window_rejected() {
    let kp = test_keypair();
    let att = default_attestation(OFFER_EXPIRY + 1);
    let blob = att.encode();
    let sig = sign_blob(&kp.sk, &blob);

    assert_eq!(
        verify_integrity_attestation(
            &blob,
            &sig,
            &kp.device_pubkey,
            OFFER_CREATED_AT,
            OFFER_EXPIRY,
        ),
        Err(IntegrityError::CeremonyOutsideOfferWindow),
    );
}

#[test]
fn debugger_detected_rejected() {
    let kp = test_keypair();
    let mut att = default_attestation(1_200);
    att.no_debugger = false;
    let blob = att.encode();
    let sig = sign_blob(&kp.sk, &blob);

    assert_eq!(
        verify_integrity_attestation(
            &blob,
            &sig,
            &kp.device_pubkey,
            OFFER_CREATED_AT,
            OFFER_EXPIRY,
        ),
        Err(IntegrityError::DebuggerDetected),
    );
}

#[test]
fn keystore_integrity_failed_rejected() {
    let kp = test_keypair();
    let mut att = default_attestation(1_200);
    att.keystore_integrity = false;
    let blob = att.encode();
    let sig = sign_blob(&kp.sk, &blob);

    assert_eq!(
        verify_integrity_attestation(
            &blob,
            &sig,
            &kp.device_pubkey,
            OFFER_CREATED_AT,
            OFFER_EXPIRY,
        ),
        Err(IntegrityError::KeystoreIntegrityFailed),
    );
}
