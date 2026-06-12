// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-chat-content-seal — inner content-layer encryption
//!
//! Phase 3 of the dotwave-chat crypto plan (hardware-bound content).
//! Seals the message content to the **recipient's static silicon
//! content key** — P-256 (Android StrongBox) or P-384 (TPM 2.0) —
//! so that reassembled messages sit **encrypted at rest** on the
//! recipient's device and decrypt only through the chip that holds
//! the private scalar.
//!
//! Layer position (see `rostro-chat-primitives::envelope`): the
//! encoded [`ContentSealed`] **is** the `inner_ciphertext` carried by
//! `UnsealedInner`. The sender signs over it (background-verifiable),
//! sealed-sender wraps it (outer layer), the stripe layer shreds it.
//! On receive the app unwraps the outer layer in the background,
//! verifies the sender, and stores the still-encrypted
//! [`ContentSealed`]; only an explicit read — biometric → in-silicon
//! ECDH — produces plaintext, transiently.
//!
//! ## Construction
//!
//! The recipient's curve is whatever their silicon natively offers
//! (the RNS chat-identity record advertises it); the sender is always
//! software on this layer:
//!
//! ```text
//! 1. Parse recipient content key (curve-tagged SEC1).
//! 2. Generate fresh ephemeral keypair ON THE RECIPIENT'S CURVE.
//! 3. shared = ECDH(eph_sk, recipient_content_pk)   // x-coordinate
//! 4. prk = HKDF-Extract(salt = eph_pk_sec1 || recipient_pk_sec1, ikm = shared)
//! 5. aead_key = HKDF-Expand(prk, CONTENT_SEAL_KEY_INFO, 32)
//! 6. nonce    = HKDF-Expand(prk, CONTENT_SEAL_NONCE_INFO, 12)
//! 7. ciphertext = ChaCha20-Poly1305(aead_key, nonce, AAD = empty, plaintext)
//! ```
//!
//! Wire output: [`ContentSealed`] `{ curve, ephemeral_pub_sec1,
//! ciphertext }` (SCALE).
//!
//! ## The silicon seam
//!
//! Decryption needs exactly ONE private-key operation: the ECDH in
//! step 3 with the recipient's static scalar. [`unseal_with`] takes
//! that operation as a [`ContentEcdh`] implementation, so:
//!
//! - **real hardware**: StrongBox / TPM performs the key agreement
//!   in-chip (biometric-gated by the platform keystore); the private
//!   key NEVER leaves the element; HKDF + AEAD run in app code on
//!   the 32/48-byte shared secret.
//! - **dev box / tests**: [`SoftwareContentKey`] holds the scalar in
//!   memory and is the stand-in provider.
//!
//! [`unseal_software`] is the convenience wrapper over the software
//! provider.
//!
//! ## What this does NOT do
//!
//! - **Sender authentication** — the `UnsealedInner` signature
//!   (verified in the background, before content decrypt) owns that.
//! - **Forward secrecy across the recipient key** — the content key
//!   is static; per-message ephemerals protect the *sender* side
//!   only. Forward secrecy is Phase 5 (Double Ratchet) layered
//!   above; this layer's job is the at-rest + in-silicon property.
//! - **Replay defense** — `MessageId` dedup at the application
//!   layer, exactly as for the outer layer.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use codec::{Decode, Encode};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF-Expand info string for the AEAD key. Bumping breaks every
/// previously-sealed message.
pub const CONTENT_SEAL_KEY_INFO: &[u8] = b"rostro/chat-content-seal/key/v1";

/// HKDF-Expand info string for the AEAD nonce.
pub const CONTENT_SEAL_NONCE_INFO: &[u8] = b"rostro/chat-content-seal/nonce/v1";

/// Curve of a content key. Driven by what the recipient's silicon
/// natively offers — StrongBox has no P-384/521 or Curve25519; TPMs
/// offer stronger NIST curves. PQ lands as a new variant (v1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum ContentCurve {
	/// NIST P-256 (secp256r1) — Android StrongBox, Apple SE.
	P256,
	/// NIST P-384 (secp384r1) — TPM 2.0 laptops/desktops.
	P384,
}

/// A recipient content public key as published in the RNS
/// chat-identity record: curve tag + SEC1 bytes (compressed or
/// uncompressed both accepted).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ContentPublicKey {
	pub curve: ContentCurve,
	pub sec1: Vec<u8>,
}

/// On-the-wire sealed content. The SCALE encoding of this struct is
/// what goes into `UnsealedInner.inner_ciphertext` — and what sits
/// encrypted at rest in the recipient's app store until read.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ContentSealed {
	/// Curve both keys (recipient static + sender ephemeral) live on.
	pub curve: ContentCurve,
	/// Sender's per-message ephemeral public key, SEC1 compressed.
	pub ephemeral_pub_sec1: Vec<u8>,
	/// AEAD ciphertext over the caller's plaintext.
	pub ciphertext: Vec<u8>,
}

/// Errors from sealing/unsealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentSealError {
	/// Recipient (or ephemeral) public key bytes are not a valid
	/// point on the declared curve.
	InvalidPublicKey,
	/// Private scalar bytes are not a valid non-zero scalar for the
	/// declared curve.
	InvalidSecretKey,
	/// The ECDH provider's curve doesn't match the sealed blob's.
	CurveMismatch,
	/// AEAD authentication failed: tampering, wrong recipient key,
	/// or domain confusion.
	AeadAuthFailed,
	/// The silicon/provider refused or failed the ECDH operation
	/// (e.g. biometric not presented, keystore error). Carries the
	/// provider's message.
	EcdhProvider(String),
}

/// The ONE private-key operation content decryption needs: ECDH of
/// the recipient's static content scalar against the sender's
/// ephemeral public key. On real hardware this runs **inside**
/// StrongBox / the TPM (platform-keystore key agreement, biometric
/// gated) and returns only the shared secret; the scalar never
/// leaves the element.
pub trait ContentEcdh {
	/// The curve this provider's key lives on.
	fn curve(&self) -> ContentCurve;

	/// ECDH(static scalar, `ephemeral_pub_sec1`) → shared-secret
	/// bytes (the x-coordinate: 32 bytes on P-256, 48 on P-384).
	fn ecdh(&self, ephemeral_pub_sec1: &[u8]) -> Result<Vec<u8>, ContentSealError>;
}

/// Software content key — the dev-box / test stand-in for the
/// silicon provider, and the reference implementation hardware
/// providers must agree with byte-for-byte.
pub struct SoftwareContentKey {
	curve: ContentCurve,
	scalar: Vec<u8>,
}

impl SoftwareContentKey {
	/// Build from a raw scalar (32 bytes for P-256, 48 for P-384).
	/// Validates the scalar is in range for the curve.
	pub fn from_scalar(curve: ContentCurve, scalar: &[u8]) -> Result<Self, ContentSealError> {
		// Round-trip through the curve's SecretKey to validate.
		match curve {
			ContentCurve::P256 => {
				p256::SecretKey::from_slice(scalar)
					.map_err(|_| ContentSealError::InvalidSecretKey)?;
			}
			ContentCurve::P384 => {
				p384::SecretKey::from_slice(scalar)
					.map_err(|_| ContentSealError::InvalidSecretKey)?;
			}
		}
		Ok(Self { curve, scalar: scalar.to_vec() })
	}

	/// The public half, as published in the RNS record (SEC1
	/// compressed).
	pub fn public_key(&self) -> ContentPublicKey {
		let sec1 = match self.curve {
			ContentCurve::P256 => {
				let sk = p256::SecretKey::from_slice(&self.scalar)
					.expect("validated in from_scalar");
				sk.public_key().to_sec1_bytes().to_vec()
			}
			ContentCurve::P384 => {
				let sk = p384::SecretKey::from_slice(&self.scalar)
					.expect("validated in from_scalar");
				sk.public_key().to_sec1_bytes().to_vec()
			}
		};
		ContentPublicKey { curve: self.curve, sec1 }
	}
}

impl Drop for SoftwareContentKey {
	fn drop(&mut self) {
		self.scalar.zeroize();
	}
}

impl ContentEcdh for SoftwareContentKey {
	fn curve(&self) -> ContentCurve {
		self.curve
	}

	fn ecdh(&self, ephemeral_pub_sec1: &[u8]) -> Result<Vec<u8>, ContentSealError> {
		match self.curve {
			ContentCurve::P256 => {
				let sk = p256::SecretKey::from_slice(&self.scalar)
					.map_err(|_| ContentSealError::InvalidSecretKey)?;
				let pk = p256::PublicKey::from_sec1_bytes(ephemeral_pub_sec1)
					.map_err(|_| ContentSealError::InvalidPublicKey)?;
				let shared = p256::ecdh::diffie_hellman(
					sk.to_nonzero_scalar(),
					pk.as_affine(),
				);
				Ok(shared.raw_secret_bytes().to_vec())
			}
			ContentCurve::P384 => {
				let sk = p384::SecretKey::from_slice(&self.scalar)
					.map_err(|_| ContentSealError::InvalidSecretKey)?;
				let pk = p384::PublicKey::from_sec1_bytes(ephemeral_pub_sec1)
					.map_err(|_| ContentSealError::InvalidPublicKey)?;
				let shared = p384::ecdh::diffie_hellman(
					sk.to_nonzero_scalar(),
					pk.as_affine(),
				);
				Ok(shared.raw_secret_bytes().to_vec())
			}
		}
	}
}

/// Seal `plaintext` to the recipient's published content key using a
/// fresh per-message ephemeral keypair on the recipient's curve.
/// Sender side is always software — cross-platform messaging works
/// because the RECIPIENT's silicon picks the curve and the sender
/// just follows the record's tag.
pub fn seal<R>(
	recipient: &ContentPublicKey,
	plaintext: &[u8],
	rng: &mut R,
) -> Result<ContentSealed, ContentSealError>
where
	R: rand_core::RngCore + rand_core::CryptoRng,
{
	let (ephemeral_pub_sec1, shared) = match recipient.curve {
		ContentCurve::P256 => {
			let recipient_pk = p256::PublicKey::from_sec1_bytes(&recipient.sec1)
				.map_err(|_| ContentSealError::InvalidPublicKey)?;
			let eph = p256::ecdh::EphemeralSecret::random(rng);
			let eph_pub = p256::EncodedPoint::from(eph.public_key()).compress();
			let shared = eph.diffie_hellman(&recipient_pk);
			(eph_pub.as_bytes().to_vec(), shared.raw_secret_bytes().to_vec())
		}
		ContentCurve::P384 => {
			let recipient_pk = p384::PublicKey::from_sec1_bytes(&recipient.sec1)
				.map_err(|_| ContentSealError::InvalidPublicKey)?;
			let eph = p384::ecdh::EphemeralSecret::random(rng);
			let eph_pub = p384::EncodedPoint::from(eph.public_key()).compress();
			let shared = eph.diffie_hellman(&recipient_pk);
			(eph_pub.as_bytes().to_vec(), shared.raw_secret_bytes().to_vec())
		}
	};

	let (aead_key, nonce) =
		derive_aead_key_and_nonce(&shared, &ephemeral_pub_sec1, &recipient.sec1);
	let mut zs = shared;
	zs.zeroize();

	let cipher = ChaCha20Poly1305::new((&aead_key).into());
	let ciphertext = cipher
		.encrypt((&nonce).into(), plaintext)
		.expect("ChaCha20-Poly1305 encryption is infallible for valid inputs");

	let mut zk = aead_key;
	zk.zeroize();
	let mut zn = nonce;
	zn.zeroize();

	Ok(ContentSealed {
		curve: recipient.curve,
		ephemeral_pub_sec1,
		ciphertext,
	})
}

/// Unseal via a [`ContentEcdh`] provider (silicon on real hardware,
/// [`SoftwareContentKey`] on the dev box). `recipient_pub_sec1` must
/// be the EXACT bytes published in the RNS record — it is bound into
/// the KDF salt, so a blob sealed to a different key (or a record
/// the sender saw differently) fails authentication rather than
/// decrypting.
pub fn unseal_with(
	provider: &dyn ContentEcdh,
	recipient_pub_sec1: &[u8],
	sealed: &ContentSealed,
) -> Result<Vec<u8>, ContentSealError> {
	if provider.curve() != sealed.curve {
		return Err(ContentSealError::CurveMismatch);
	}
	let shared = provider.ecdh(&sealed.ephemeral_pub_sec1)?;

	let (aead_key, nonce) =
		derive_aead_key_and_nonce(&shared, &sealed.ephemeral_pub_sec1, recipient_pub_sec1);
	let mut zs = shared;
	zs.zeroize();

	let cipher = ChaCha20Poly1305::new((&aead_key).into());
	let plaintext = cipher
		.decrypt((&nonce).into(), sealed.ciphertext.as_slice())
		.map_err(|_| ContentSealError::AeadAuthFailed)?;

	let mut zk = aead_key;
	zk.zeroize();
	let mut zn = nonce;
	zn.zeroize();

	Ok(plaintext)
}

/// Convenience: unseal with a software scalar (dev box / tests).
pub fn unseal_software(
	curve: ContentCurve,
	scalar: &[u8],
	sealed: &ContentSealed,
) -> Result<Vec<u8>, ContentSealError> {
	let key = SoftwareContentKey::from_scalar(curve, scalar)?;
	let pub_sec1 = key.public_key().sec1;
	unseal_with(&key, &pub_sec1, sealed)
}

/// HKDF-Extract over `salt = ephemeral_pub_sec1 || recipient_pub_sec1`,
/// then HKDF-Expand for the AEAD key (32) and nonce (12). Mirrors the
/// sealed-sender derivation shape; distinct info constants keep the
/// two layers domain-separated even if key material ever collided.
fn derive_aead_key_and_nonce(
	shared: &[u8],
	ephemeral_pub_sec1: &[u8],
	recipient_pub_sec1: &[u8],
) -> ([u8; 32], [u8; 12]) {
	let mut salt = Vec::with_capacity(ephemeral_pub_sec1.len() + recipient_pub_sec1.len());
	salt.extend_from_slice(ephemeral_pub_sec1);
	salt.extend_from_slice(recipient_pub_sec1);
	let hk = Hkdf::<Sha256>::new(Some(&salt), shared);

	let mut key = [0u8; 32];
	hk.expand(CONTENT_SEAL_KEY_INFO, &mut key)
		.expect("32 bytes within HKDF output limit");

	let mut nonce = [0u8; 12];
	hk.expand(CONTENT_SEAL_NONCE_INFO, &mut nonce)
		.expect("12 bytes within HKDF output limit");

	(key, nonce)
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

	fn rng() -> ChaCha20Rng {
		ChaCha20Rng::seed_from_u64(42)
	}

	fn p256_key(byte: u8) -> SoftwareContentKey {
		SoftwareContentKey::from_scalar(ContentCurve::P256, &[byte; 32]).unwrap()
	}

	fn p384_key(byte: u8) -> SoftwareContentKey {
		SoftwareContentKey::from_scalar(ContentCurve::P384, &[byte; 48]).unwrap()
	}

	#[test]
	fn p256_roundtrip() {
		let bob = p256_key(0x11);
		let bob_pub = bob.public_key();
		let sealed = seal(&bob_pub, b"strongbox-bound hello", &mut rng()).unwrap();
		let plain = unseal_with(&bob, &bob_pub.sec1, &sealed).unwrap();
		assert_eq!(plain, b"strongbox-bound hello");
	}

	#[test]
	fn p384_roundtrip() {
		let bob = p384_key(0x22);
		let bob_pub = bob.public_key();
		let sealed = seal(&bob_pub, b"tpm-bound hello", &mut rng()).unwrap();
		let plain = unseal_with(&bob, &bob_pub.sec1, &sealed).unwrap();
		assert_eq!(plain, b"tpm-bound hello");
	}

	/// Cross-platform by construction: the SENDER follows the
	/// recipient's advertised curve. Phone (P-256 holder) → laptop
	/// (P-384 holder) and back.
	#[test]
	fn cross_curve_both_directions() {
		let phone = p256_key(0x33);
		let laptop = p384_key(0x44);

		// phone → laptop: sealed on P-384 (laptop's curve).
		let to_laptop = seal(&laptop.public_key(), b"phone->laptop", &mut rng()).unwrap();
		assert_eq!(to_laptop.curve, ContentCurve::P384);
		assert_eq!(
			unseal_with(&laptop, &laptop.public_key().sec1, &to_laptop).unwrap(),
			b"phone->laptop"
		);

		// laptop → phone: sealed on P-256 (phone's curve).
		let to_phone = seal(&phone.public_key(), b"laptop->phone", &mut rng()).unwrap();
		assert_eq!(to_phone.curve, ContentCurve::P256);
		assert_eq!(
			unseal_with(&phone, &phone.public_key().sec1, &to_phone).unwrap(),
			b"laptop->phone"
		);
	}

	#[test]
	fn tampered_ciphertext_rejected() {
		let bob = p256_key(0x11);
		let bob_pub = bob.public_key();
		let mut sealed = seal(&bob_pub, b"payload", &mut rng()).unwrap();
		sealed.ciphertext[0] ^= 1;
		assert_eq!(
			unseal_with(&bob, &bob_pub.sec1, &sealed),
			Err(ContentSealError::AeadAuthFailed)
		);
	}

	#[test]
	fn wrong_recipient_rejected() {
		let bob = p256_key(0x11);
		let mallory = p256_key(0x55);
		let sealed = seal(&bob.public_key(), b"for bob only", &mut rng()).unwrap();
		assert_eq!(
			unseal_with(&mallory, &mallory.public_key().sec1, &sealed),
			Err(ContentSealError::AeadAuthFailed)
		);
	}

	#[test]
	fn curve_mismatch_rejected() {
		let bob_p384 = p384_key(0x22);
		let sealed_p256 = seal(&p256_key(0x11).public_key(), b"x", &mut rng()).unwrap();
		assert_eq!(
			unseal_with(&bob_p384, &bob_p384.public_key().sec1, &sealed_p256),
			Err(ContentSealError::CurveMismatch)
		);
	}

	/// The wire blob never contains the plaintext — the at-rest
	/// property the whole layer exists for.
	#[test]
	fn sealed_blob_does_not_leak_plaintext() {
		let bob = p256_key(0x11);
		let body = b"finding-you-is-death plaintext";
		let sealed = seal(&bob.public_key(), body, &mut rng()).unwrap();
		let encoded = sealed.encode();
		assert!(
			!encoded
				.windows(body.len())
				.any(|w| w == body.as_slice()),
			"sealed encoding leaks plaintext"
		);
	}

	/// SCALE round-trip — what travels in `inner_ciphertext` and
	/// sits in the app store decodes back exactly.
	#[test]
	fn scale_roundtrip() {
		let bob = p256_key(0x11);
		let sealed = seal(&bob.public_key(), b"persist me", &mut rng()).unwrap();
		let decoded = ContentSealed::decode(&mut &sealed.encode()[..]).unwrap();
		assert_eq!(decoded, sealed);
	}
}
