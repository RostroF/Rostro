// SPDX-License-Identifier: Apache-2.0

//! `WatchdogSigner` — owns an Ed25519 key in process RAM and produces
//! per-kind domain-separated signatures.
//!
//! v0.1 holds the key in plain RAM (ed25519-dalek's `SigningKey` zeroizes
//! on drop via its `zeroize` feature). v0.3+ replaces this with a
//! TPM-sealed key per the `watchdog-tpm-seal` memory; the public API
//! stays the same.

use crate::sign_kind::{SignKind, SignKindError, DOMAIN_PREFIX};
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use rand_core::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

pub const SIGNATURE_LEN: usize = 64;
pub const PUBKEY_LEN: usize = PUBLIC_KEY_LENGTH;

pub struct WatchdogSigner {
    key: SigningKey,
}

impl core::fmt::Debug for WatchdogSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WatchdogSigner").field("pubkey", &self.key.verifying_key().to_bytes()).finish_non_exhaustive()
    }
}

impl WatchdogSigner {
    /// Generate a fresh Ed25519 key from the OS RNG.
    pub fn generate() -> Self {
        Self { key: SigningKey::generate(&mut OsRng) }
    }

    /// Construct from a 32-byte secret seed. All-zero seed is rejected as
    /// a sentinel per the project's input-validation discipline.
    pub fn from_secret_bytes(bytes: [u8; SECRET_KEY_LENGTH]) -> Result<Self, SignerError> {
        if bytes.iter().all(|&b| b == 0) {
            return Err(SignerError::SentinelKey);
        }
        Ok(Self { key: SigningKey::from_bytes(&bytes) })
    }

    pub fn public_key(&self) -> [u8; PUBKEY_LEN] {
        self.key.verifying_key().to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign `payload` under `kind`. The signed bytes are
    /// `DOMAIN_PREFIX || kind.domain_tag() || 0x00 || payload`, so a
    /// signature produced under one kind structurally cannot be replayed
    /// under another.
    pub fn sign_kind(
        &self,
        kind: SignKind,
        payload: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], SignerError> {
        kind.validate_payload(payload)?;
        let tag = kind.domain_tag();
        let mut to_sign =
            Zeroizing::new(Vec::with_capacity(DOMAIN_PREFIX.len() + tag.len() + 1 + payload.len()));
        to_sign.extend_from_slice(DOMAIN_PREFIX);
        to_sign.extend_from_slice(tag);
        to_sign.push(0u8);
        to_sign.extend_from_slice(payload);
        let sig: Signature = self.key.sign(&to_sign);
        Ok(sig.to_bytes())
    }
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("sign kind: {0}")]
    Kind(#[from] SignKindError),
    #[error("rejected all-zero sentinel secret key")]
    SentinelKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn rebuild_signed_bytes(kind: SignKind, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(DOMAIN_PREFIX);
        v.extend_from_slice(kind.domain_tag());
        v.push(0);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = WatchdogSigner::generate();
        let b = WatchdogSigner::generate();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let signer = WatchdogSigner::generate();
        let payload = b"libp2p noise handshake input";
        let sig_bytes = signer.sign_kind(SignKind::NoiseHandshake, payload).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        let to_verify = rebuild_signed_bytes(SignKind::NoiseHandshake, payload);
        signer.verifying_key().verify(&to_verify, &sig).unwrap();
    }

    #[test]
    fn cross_kind_signature_does_not_verify() {
        let signer = WatchdogSigner::generate();
        let payload = b"some payload";
        let sig_bytes = signer.sign_kind(SignKind::NoiseHandshake, payload).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        let to_verify = rebuild_signed_bytes(SignKind::CanonicalAttest, payload);
        assert!(signer.verifying_key().verify(&to_verify, &sig).is_err());
    }

    #[test]
    fn empty_payload_rejected_at_signer() {
        let signer = WatchdogSigner::generate();
        let err = signer.sign_kind(SignKind::NoiseHandshake, &[]).unwrap_err();
        assert!(matches!(err, SignerError::Kind(SignKindError::EmptyPayload(_))));
    }

    #[test]
    fn deterministic_signature_from_seed() {
        let seed = [42u8; SECRET_KEY_LENGTH];
        let a = WatchdogSigner::from_secret_bytes(seed).unwrap();
        let b = WatchdogSigner::from_secret_bytes(seed).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        let payload = b"abc";
        assert_eq!(
            a.sign_kind(SignKind::NoiseHandshake, payload).unwrap(),
            b.sign_kind(SignKind::NoiseHandshake, payload).unwrap(),
        );
    }

    #[test]
    fn all_zero_seed_rejected() {
        let err = WatchdogSigner::from_secret_bytes([0u8; SECRET_KEY_LENGTH]).unwrap_err();
        assert!(matches!(err, SignerError::SentinelKey));
    }
}
