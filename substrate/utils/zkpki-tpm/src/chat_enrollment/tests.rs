use super::*;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

/// An attest_ec keypair plus the [`DevicePublicKey`] the verifier sees.
fn keypair(scalar: [u8; 32]) -> (SigningKey, DevicePublicKey) {
    let sk = SigningKey::from_slice(&scalar).expect("valid P-256 scalar");
    let sec1 = sk.verifying_key().to_encoded_point(false);
    let pk = DevicePublicKey::new_p256(sec1.as_bytes()).expect("valid SEC1 pubkey");
    (sk, pk)
}

/// Produce an id-binding signature exactly as the phone would: ECDSA over
/// `blake2_256(ID_BINDING_CONTEXT || id_commitment || challenge)`.
fn sign(sk: &SigningKey, id_commitment: &[u8; 32], challenge: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(ID_BINDING_CONTEXT);
    input.extend_from_slice(id_commitment);
    input.extend_from_slice(challenge);
    let msg = sp_io::hashing::blake2_256(&input);
    let sig: Signature = sk.sign(&msg);
    sig.to_der().as_bytes().to_vec()
}

#[test]
fn valid_enrollment_verifies() {
    let (sk, pk) = keypair([7u8; 32]);
    let id_commitment = [9u8; 32];
    let challenge = [3u8; 32];
    let enrollment = ChatEnrollment {
        id_commitment,
        id_binding_signature: sign(&sk, &id_commitment, &challenge),
    };
    assert_eq!(verify_chat_enrollment(&enrollment, &pk, &challenge), Ok(()));
}

#[test]
fn wrong_key_rejected() {
    let (sk, _) = keypair([7u8; 32]);
    let (_, other_pk) = keypair([8u8; 32]);
    let id_commitment = [9u8; 32];
    let challenge = [3u8; 32];
    let enrollment = ChatEnrollment {
        id_commitment,
        id_binding_signature: sign(&sk, &id_commitment, &challenge),
    };
    assert_eq!(
        verify_chat_enrollment(&enrollment, &other_pk, &challenge),
        Err(ChatEnrollmentError::BindingSignatureInvalid),
    );
}

#[test]
fn tampered_commitment_rejected() {
    let (sk, pk) = keypair([7u8; 32]);
    let id_commitment = [9u8; 32];
    let challenge = [3u8; 32];
    let mut enrollment = ChatEnrollment {
        id_commitment,
        id_binding_signature: sign(&sk, &id_commitment, &challenge),
    };
    // Flip a bit of the commitment after signing: the signature no longer
    // covers the submitted value.
    enrollment.id_commitment[0] ^= 1;
    assert_eq!(
        verify_chat_enrollment(&enrollment, &pk, &challenge),
        Err(ChatEnrollmentError::BindingSignatureInvalid),
    );
}

#[test]
fn wrong_challenge_rejected() {
    // A binding signed for one offer cannot be replayed against another.
    let (sk, pk) = keypair([7u8; 32]);
    let id_commitment = [9u8; 32];
    let enrollment = ChatEnrollment {
        id_commitment,
        id_binding_signature: sign(&sk, &id_commitment, &[3u8; 32]),
    };
    assert_eq!(
        verify_chat_enrollment(&enrollment, &pk, &[4u8; 32]),
        Err(ChatEnrollmentError::BindingSignatureInvalid),
    );
}
