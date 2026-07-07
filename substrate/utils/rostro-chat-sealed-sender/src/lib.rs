// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-chat-sealed-sender — outer-layer Sealed Sender encryption
//!
//! Phase A2 of the MLS-chat plan. Per-message ephemeral X25519 ECDH
//! against the recipient's identity key + HKDF-SHA256 key/nonce
//! derivation + ChaCha20-Poly1305 AEAD. Mirrors Signal's Sealed
//! Sender pattern: anyone observing the wire sees only an opaque
//! ciphertext + a random ephemeral pubkey; the sender's identity
//! (which lives inside the `UnsealedInner` structure defined by
//! the `rostro-chat-primitives` crate) is hidden until the
//! recipient decrypts.
//!
//! ## Construction
//!
//! For each message:
//!
//! ```text
//! 1. Generate fresh ephemeral X25519 keypair (eph_sk, eph_pk).
//! 2. shared = X25519(eph_sk, recipient_identity_pk).
//! 3. prk = HKDF-Extract(salt = eph_pk || recipient_identity_pk, ikm = shared).
//! 4. aead_key = HKDF-Expand(prk, info = SEALED_SENDER_KEY_INFO, 32).
//! 5. nonce    = HKDF-Expand(prk, info = SEALED_SENDER_NONCE_INFO, 12).
//! 6. ciphertext = ChaCha20-Poly1305(aead_key, nonce, AAD = empty, plaintext).
//! ```
//!
//! Wire output: `(eph_pk, ciphertext)`.
//!
//! Recipient mirrors:
//!
//! ```text
//! 1. shared = X25519(recipient_identity_sk, eph_pk).
//! 2. Same prk, aead_key, nonce derivation.
//! 3. plaintext = ChaCha20-Poly1305-decrypt(...).
//! ```
//!
//! ## What this gives
//!
//! - **Sender anonymity on the wire**: outsiders see only
//!   `(random eph_pk, opaque ciphertext)`. Sender's identity key is
//!   never on the wire; it's inside the encrypted blob.
//! - **Forward secrecy per-message**: the ephemeral key is destroyed
//!   immediately after encryption. Compromise of the recipient's
//!   identity secret tomorrow doesn't decrypt a message sent today
//!   IF the ephemeral was zeroized (a property we maintain in
//!   [`seal`]).
//! - **Recipient binding**: `recipient_identity_pk` is folded into
//!   the HKDF salt, so a ciphertext sealed for Alice cannot be
//!   re-routed to and accepted by Bob — Bob's KDF derives a
//!   different key.
//!
//! ## What this does NOT do
//!
//! - **Replay defense**: an attacker can re-deliver an unmodified
//!   sealed message to the recipient. Defense lives at the
//!   application layer: the recipient deduplicates by
//!   `MessageId` (the inner signature binds to a specific
//!   `MessageId`, so accepted replays land as duplicates and can
//!   be discarded).
//! - **Sender authentication**: the inner `UnsealedInner.signature`
//!   handles that. This crate only delivers the inner bytes from
//!   sender to recipient confidentially.
//! - **Replay across recipients**: prevented by recipient-pk
//!   binding (above).
//! - **Identity-key conversion**: caller supplies the recipient's
//!   X25519 identity pubkey directly. If the on-chain identity is
//!   Ed25519, callers apply the Edwards-to-Montgomery conversion
//!   before passing it here.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use codec::{Decode, Encode};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::Zeroize;

/// HKDF-Expand info string for the AEAD key. Bumping breaks every
/// previously-sealed message.
pub const SEALED_SENDER_KEY_INFO: &[u8] = b"rostro/chat-sealed-sender/key/v1";

/// HKDF-Expand info string for the AEAD nonce.
pub const SEALED_SENDER_NONCE_INFO: &[u8] = b"rostro/chat-sealed-sender/nonce/v1";

/// On-the-wire sealed output. SCALE-encodable; the recipient
/// reconstructs from this exactly.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SealedOutput {
	/// Sender's per-message ephemeral X25519 public key.
	pub ephemeral_pub: [u8; 32],
	/// AEAD ciphertext over the caller's plaintext.
	pub ciphertext: Vec<u8>,
}

/// Errors from [`unseal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsealError {
	/// AEAD authentication failed. Could indicate:
	///
	/// - Tampered ciphertext or ephemeral pubkey
	/// - Wrong recipient identity secret (sealed for a different recipient)
	/// - Crypto-layer downgrade or domain confusion (different
	///   SEALED_SENDER_*_INFO at sender vs. recipient)
	AeadAuthFailed,
}

/// Seal `plaintext` to `recipient_identity_pub` using a fresh
/// per-message ephemeral X25519 keypair generated from `rng`.
///
/// Returns a [`SealedOutput`] carrying the ephemeral pubkey and the
/// AEAD ciphertext. The ephemeral secret is dropped (and zeroized
/// via `x25519_dalek::StaticSecret`'s `Drop` impl) before the
/// function returns; only the public half is on the wire.
pub fn seal<R>(
	recipient_identity_pub: &[u8; 32],
	plaintext: &[u8],
	rng: &mut R,
) -> SealedOutput
where
	R: rand_core::RngCore + rand_core::CryptoRng,
{
	let ephemeral_secret = X25519SecretKey::random_from_rng(rng);
	let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
	let recipient_pub = X25519PublicKey::from(*recipient_identity_pub);
	let shared = ephemeral_secret.diffie_hellman(&recipient_pub);

	let (aead_key, nonce) = derive_aead_key_and_nonce(
		shared.as_bytes(),
		ephemeral_pub.as_bytes(),
		recipient_identity_pub,
	);

	let cipher = ChaCha20Poly1305::new((&aead_key).into());
	let ciphertext = cipher
		.encrypt((&nonce).into(), plaintext)
		.expect("ChaCha20-Poly1305 encryption is infallible for valid inputs");

	// Best-effort zeroize of the derived key material before drop.
	let mut zk = aead_key;
	zk.zeroize();
	let mut zn = nonce;
	zn.zeroize();

	SealedOutput {
		ephemeral_pub: *ephemeral_pub.as_bytes(),
		ciphertext,
	}
}

/// Unseal a [`SealedOutput`] using the recipient's X25519 identity
/// secret. Returns the original plaintext on success; any tampering
/// or wrong-recipient attempt surfaces as
/// [`UnsealError::AeadAuthFailed`].
pub fn unseal(
	recipient_identity_secret_bytes: &[u8; 32],
	sealed: &SealedOutput,
) -> Result<Vec<u8>, UnsealError> {
	let recipient_secret = X25519SecretKey::from(*recipient_identity_secret_bytes);
	let recipient_pub = X25519PublicKey::from(&recipient_secret);
	let ephemeral_pub = X25519PublicKey::from(sealed.ephemeral_pub);
	let shared = recipient_secret.diffie_hellman(&ephemeral_pub);

	let (aead_key, nonce) = derive_aead_key_and_nonce(
		shared.as_bytes(),
		&sealed.ephemeral_pub,
		recipient_pub.as_bytes(),
	);

	let cipher = ChaCha20Poly1305::new((&aead_key).into());
	let plaintext = cipher
		.decrypt((&nonce).into(), sealed.ciphertext.as_slice())
		.map_err(|_| UnsealError::AeadAuthFailed)?;

	// Zeroize derived key/nonce after use (best-effort; rust drop
	// rules limit what we can guarantee).
	let mut zk = aead_key;
	zk.zeroize();
	let mut zn = nonce;
	zn.zeroize();

	Ok(plaintext)
}

// ── hybrid (X25519 + ML-KEM-768) sealed sender ──────────────────────
//
// The PQ upgrade of [`seal`]/[`unseal`] for the pairwise envelope path
// (docs/PQ-CHAT.md). Peel order makes this seal the quantum shield for
// everything inside it: relays only ever hold the outer blob, so once
// the outer seal is hybrid, archived network traffic at Q-day stops
// here — sender identity, DR headers, and the P-256 content blob are
// all shielded even though individually quantum-broken.
//
// Construction: the X25519 ephemeral DH is unchanged; the sender
// additionally encapsulates against the recipient's published SEAL
// key (the ML-KEM-768 ek from the RNS `SEAL` record, identity-signed
// — callers MUST verify that signature before sealing). The two
// secrets combine via rostro-hybrid-kex's `hybrid_shared_secret`
// (TLS X25519MLKEM768 ordering) so the derivation cannot drift from
// the validator channel, and the combined secret feeds the same
// HKDF/AEAD pipeline under bumped `hybrid-key/v1` info strings. The
// KEM ciphertext rides as AEAD AAD: tampering it fails authentication
// directly, on top of FIPS 203 implicit rejection.
//
// Confidentiality holds while EITHER X25519 or ML-KEM holds — the
// same hedge as every hybrid in the stack. The classical [`seal`]
// stays for the onion-layer path until pq-node-identity Stage 2
// hybridizes node identities; the two forms are distinct types under
// distinct KDF domains, so they cannot be confused.

/// HKDF-Expand info string for the hybrid AEAD key.
pub const SEALED_SENDER_HYBRID_KEY_INFO: &[u8] = b"rostro/chat-sealed-sender/hybrid-key/v1";

/// HKDF-Expand info string for the hybrid AEAD nonce.
pub const SEALED_SENDER_HYBRID_NONCE_INFO: &[u8] = b"rostro/chat-sealed-sender/hybrid-nonce/v1";

/// On-the-wire hybrid sealed output: the classical ephemeral, the
/// ML-KEM-768 ciphertext, and the AEAD ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct HybridSealedOutput {
	/// Sender's per-message ephemeral X25519 public key.
	pub ephemeral_pub: [u8; 32],
	/// ML-KEM-768 ciphertext encapsulated against the recipient's
	/// SEAL key. Also bound into the AEAD as AAD.
	pub pq_ct: [u8; rostro_hybrid_kex::MLKEM768_CT_BYTES],
	/// AEAD ciphertext over the caller's plaintext.
	pub ciphertext: Vec<u8>,
}

/// Errors from [`hybrid_seal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridSealError {
	/// The recipient's SEAL encapsulation key failed ML-KEM decoding.
	/// (A *verified* SEAL record can still carry a structurally
	/// invalid ek — signature checks bytes, not lattice validity.)
	InvalidSealKey,
}

/// Hybrid-seal `plaintext` to a recipient identified by its X25519
/// identity key (classical leg) AND its published SEAL encapsulation
/// key (PQ leg). Callers MUST have verified the SEAL record's identity
/// signature (`rostro-chat-dr::verify_seal_ek`) before calling.
pub fn hybrid_seal<R>(
	recipient_identity_pub: &[u8; 32],
	recipient_seal_ek: &[u8; rostro_hybrid_kex::MLKEM768_EK_BYTES],
	plaintext: &[u8],
	rng: &mut R,
) -> Result<HybridSealedOutput, HybridSealError>
where
	R: rand_core::RngCore + rand_core::CryptoRng,
{
	let ephemeral_secret = X25519SecretKey::random_from_rng(&mut *rng);
	let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
	let recipient_pub = X25519PublicKey::from(*recipient_identity_pub);
	let shared_x = ephemeral_secret.diffie_hellman(&recipient_pub);

	let mut m = [0u8; 32];
	rng.fill_bytes(&mut m);
	let (pq_ct, pq_ss) = rostro_hybrid_kex::mlkem_encapsulate(recipient_seal_ek, &m)
		.map_err(|_| HybridSealError::InvalidSealKey)?;
	m.zeroize();

	let mut combined =
		rostro_hybrid_kex::hybrid_shared_secret(&pq_ss, shared_x.as_bytes());
	let mut zss = pq_ss;
	zss.zeroize();

	let (aead_key, nonce) = derive_hybrid_aead_key_and_nonce(
		&combined,
		ephemeral_pub.as_bytes(),
		recipient_identity_pub,
	);
	combined.zeroize();

	let cipher = ChaCha20Poly1305::new((&aead_key).into());
	let ciphertext = cipher
		.encrypt(
			(&nonce).into(),
			chacha20poly1305::aead::Payload { msg: plaintext, aad: &pq_ct },
		)
		.expect("ChaCha20-Poly1305 encryption is infallible for valid inputs");

	let mut zk = aead_key;
	zk.zeroize();
	let mut zn = nonce;
	zn.zeroize();

	Ok(HybridSealedOutput { ephemeral_pub: *ephemeral_pub.as_bytes(), pq_ct, ciphertext })
}

/// Unseal a [`HybridSealedOutput`] with the recipient's X25519
/// identity secret AND its SEAL decapsulation key. A tampered
/// `pq_ct` implicit-rejects to a garbage secret (FIPS 203) and is
/// additionally AAD-bound, so all tampering surfaces uniformly as
/// [`UnsealError::AeadAuthFailed`] — no decapsulation oracle.
pub fn hybrid_unseal(
	recipient_identity_secret_bytes: &[u8; 32],
	seal_decap: &rostro_hybrid_kex::MlKemDecapKey,
	sealed: &HybridSealedOutput,
) -> Result<Vec<u8>, UnsealError> {
	let recipient_secret = X25519SecretKey::from(*recipient_identity_secret_bytes);
	let recipient_pub = X25519PublicKey::from(&recipient_secret);
	let ephemeral_pub = X25519PublicKey::from(sealed.ephemeral_pub);
	let shared_x = recipient_secret.diffie_hellman(&ephemeral_pub);

	let pq_ss = rostro_hybrid_kex::mlkem_decapsulate(seal_decap, &sealed.pq_ct)
		.map_err(|_| UnsealError::AeadAuthFailed)?;

	let mut combined = rostro_hybrid_kex::hybrid_shared_secret(&pq_ss, shared_x.as_bytes());
	let mut zss = pq_ss;
	zss.zeroize();

	let (aead_key, nonce) = derive_hybrid_aead_key_and_nonce(
		&combined,
		&sealed.ephemeral_pub,
		recipient_pub.as_bytes(),
	);
	combined.zeroize();

	let cipher = ChaCha20Poly1305::new((&aead_key).into());
	let plaintext = cipher
		.decrypt(
			(&nonce).into(),
			chacha20poly1305::aead::Payload {
				msg: sealed.ciphertext.as_slice(),
				aad: &sealed.pq_ct,
			},
		)
		.map_err(|_| UnsealError::AeadAuthFailed)?;

	let mut zk = aead_key;
	zk.zeroize();
	let mut zn = nonce;
	zn.zeroize();

	Ok(plaintext)
}

/// Hybrid twin of [`derive_aead_key_and_nonce`]: same salt layout
/// (`ephemeral_pub || recipient_pub`), the COMBINED hybrid secret as
/// ikm, and the `hybrid-key/v1` info strings. A classical seal and a
/// hybrid seal of identical key material can never derive the same
/// AEAD key.
fn derive_hybrid_aead_key_and_nonce(
	combined: &[u8; 32],
	ephemeral_pub: &[u8; 32],
	recipient_pub: &[u8; 32],
) -> ([u8; 32], [u8; 12]) {
	let mut salt = [0u8; 64];
	salt[..32].copy_from_slice(ephemeral_pub);
	salt[32..].copy_from_slice(recipient_pub);
	let hk = Hkdf::<Sha256>::new(Some(&salt), combined);

	let mut key = [0u8; 32];
	hk.expand(SEALED_SENDER_HYBRID_KEY_INFO, &mut key)
		.expect("32 bytes within HKDF output limit");

	let mut nonce = [0u8; 12];
	hk.expand(SEALED_SENDER_HYBRID_NONCE_INFO, &mut nonce)
		.expect("12 bytes within HKDF output limit");

	(key, nonce)
}

/// HKDF-Extract over `salt = ephemeral_pub || recipient_pub`, then
/// HKDF-Expand twice for the AEAD key (32 bytes) and nonce (12
/// bytes). Output ordering and labels are domain-separated by
/// [`SEALED_SENDER_KEY_INFO`] / [`SEALED_SENDER_NONCE_INFO`] so a
/// future protocol change can bump the constants without breaking
/// the algorithm.
fn derive_aead_key_and_nonce(
	shared: &[u8],
	ephemeral_pub: &[u8; 32],
	recipient_pub: &[u8; 32],
) -> ([u8; 32], [u8; 12]) {
	let mut salt = [0u8; 64];
	salt[..32].copy_from_slice(ephemeral_pub);
	salt[32..].copy_from_slice(recipient_pub);
	let hk = Hkdf::<Sha256>::new(Some(&salt), shared);

	let mut key = [0u8; 32];
	hk.expand(SEALED_SENDER_KEY_INFO, &mut key)
		.expect("32 bytes within HKDF output limit");

	let mut nonce = [0u8; 12];
	hk.expand(SEALED_SENDER_NONCE_INFO, &mut nonce)
		.expect("12 bytes within HKDF output limit");

	(key, nonce)
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_chacha::ChaCha20Rng;
	use rand_core::SeedableRng;

	fn test_rng(seed: u8) -> ChaCha20Rng {
		ChaCha20Rng::from_seed([seed; 32])
	}

	fn fresh_recipient_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
		let mut rng = test_rng(seed);
		let sk = X25519SecretKey::random_from_rng(&mut rng);
		let pk = X25519PublicKey::from(&sk);
		(sk.to_bytes(), *pk.as_bytes())
	}

	// ── roundtrip ─────────────────────────────────────────────────

	#[test]
	fn seal_unseal_roundtrip() {
		let mut rng = test_rng(0x01);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x02);
		let plaintext = b"hello sealed sender";
		let sealed = seal(&recip_pk, plaintext, &mut rng);
		let recovered = unseal(&recip_sk, &sealed).unwrap();
		assert_eq!(recovered, plaintext);
	}

	#[test]
	fn empty_plaintext_roundtrip() {
		let mut rng = test_rng(0x03);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x04);
		let sealed = seal(&recip_pk, b"", &mut rng);
		let recovered = unseal(&recip_sk, &sealed).unwrap();
		assert_eq!(recovered, b"");
	}

	#[test]
	fn larger_plaintext_roundtrip() {
		let mut rng = test_rng(0x05);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x06);
		// 4 KiB — typical chat message size budget.
		let plaintext: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
		let sealed = seal(&recip_pk, &plaintext, &mut rng);
		let recovered = unseal(&recip_sk, &sealed).unwrap();
		assert_eq!(recovered, plaintext);
	}

	// ── randomness in each seal ───────────────────────────────────

	#[test]
	fn two_seals_of_same_plaintext_produce_different_ciphertexts() {
		let mut rng = test_rng(0x07);
		let (_recip_sk, recip_pk) = fresh_recipient_keypair(0x08);
		let plaintext = b"deterministic plaintext";
		let s1 = seal(&recip_pk, plaintext, &mut rng);
		let s2 = seal(&recip_pk, plaintext, &mut rng);
		// Ephemeral keypair differs per call, so both the public
		// key on the wire AND the derived AEAD key differ.
		assert_ne!(s1.ephemeral_pub, s2.ephemeral_pub);
		assert_ne!(s1.ciphertext, s2.ciphertext);
	}

	// ── tamper resistance ─────────────────────────────────────────

	#[test]
	fn tampered_ciphertext_fails_aead() {
		let mut rng = test_rng(0x09);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x0A);
		let mut sealed = seal(&recip_pk, b"sensitive payload", &mut rng);
		sealed.ciphertext[0] ^= 0xFF;
		assert_eq!(unseal(&recip_sk, &sealed), Err(UnsealError::AeadAuthFailed));
	}

	#[test]
	fn tampered_ephemeral_pub_fails() {
		// Changing eph_pub changes the HKDF salt AND the X25519 DH
		// output the recipient computes, so the recipient's derived
		// AEAD key won't match the sender's. AEAD auth fails.
		let mut rng = test_rng(0x0B);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x0C);
		let mut sealed = seal(&recip_pk, b"important", &mut rng);
		sealed.ephemeral_pub[15] ^= 0xFF;
		assert_eq!(unseal(&recip_sk, &sealed), Err(UnsealError::AeadAuthFailed));
	}

	// ── recipient binding (cannot redirect ciphertext to a different recipient) ──

	#[test]
	fn ciphertext_sealed_for_alice_does_not_unseal_for_bob() {
		let mut rng = test_rng(0x0D);
		let (alice_sk, alice_pk) = fresh_recipient_keypair(0x0E);
		let (bob_sk, bob_pk) = fresh_recipient_keypair(0x0F);
		assert_ne!(alice_pk, bob_pk);

		let sealed_for_alice = seal(&alice_pk, b"for alice only", &mut rng);

		// Alice can open.
		assert!(unseal(&alice_sk, &sealed_for_alice).is_ok());
		// Bob cannot — wrong identity secret derives a different
		// AEAD key (and even if it derived the right shared
		// secret, the recipient_pub component of the HKDF salt
		// differs, so the key still wouldn't match).
		assert_eq!(
			unseal(&bob_sk, &sealed_for_alice),
			Err(UnsealError::AeadAuthFailed),
		);
	}

	// ── SCALE roundtrip ───────────────────────────────────────────

	#[test]
	fn sealed_output_scale_roundtrip() {
		let mut rng = test_rng(0x10);
		let (_recip_sk, recip_pk) = fresh_recipient_keypair(0x11);
		let sealed = seal(&recip_pk, b"scale me", &mut rng);
		let encoded = sealed.encode();
		let decoded = SealedOutput::decode(&mut &encoded[..]).unwrap();
		assert_eq!(sealed, decoded);
	}

	#[test]
	fn sealed_output_wire_size_overhead_is_bounded() {
		// Pin the wire-format overhead: 32-byte ephemeral_pub +
		// a SCALE-encoded `Vec<u8>` (compact length prefix + bytes
		// + 16-byte AEAD tag).
		let mut rng = test_rng(0x12);
		let (_recip_sk, recip_pk) = fresh_recipient_keypair(0x13);
		let plaintext = b"x"; // 1 byte
		let sealed = seal(&recip_pk, plaintext, &mut rng);
		let encoded = sealed.encode();
		// 32 (eph_pub) + 1 (SCALE compact length 0x04..0x40 → 1 byte)
		// + 1 (plaintext) + 16 (poly1305 tag) = 50 bytes.
		assert_eq!(encoded.len(), 50);
	}

	// ── KDF properties ────────────────────────────────────────────

	#[test]
	fn kdf_is_deterministic_for_same_inputs() {
		let shared = [0x11u8; 32];
		let eph = [0x22u8; 32];
		let recip = [0x33u8; 32];
		let (k1, n1) = derive_aead_key_and_nonce(&shared, &eph, &recip);
		let (k2, n2) = derive_aead_key_and_nonce(&shared, &eph, &recip);
		assert_eq!(k1, k2);
		assert_eq!(n1, n2);
	}

	#[test]
	fn kdf_diverges_on_different_recipient_pub() {
		let shared = [0x11u8; 32];
		let eph = [0x22u8; 32];
		let recip_a = [0x33u8; 32];
		let recip_b = [0x44u8; 32];
		let (k_a, _) = derive_aead_key_and_nonce(&shared, &eph, &recip_a);
		let (k_b, _) = derive_aead_key_and_nonce(&shared, &eph, &recip_b);
		assert_ne!(k_a, k_b, "different recipient pubkeys must derive different keys");
	}

	#[test]
	fn kdf_diverges_on_different_ephemeral_pub() {
		let shared = [0x11u8; 32];
		let eph_a = [0x22u8; 32];
		let eph_b = [0x55u8; 32];
		let recip = [0x33u8; 32];
		let (k_a, _) = derive_aead_key_and_nonce(&shared, &eph_a, &recip);
		let (k_b, _) = derive_aead_key_and_nonce(&shared, &eph_b, &recip);
		assert_ne!(k_a, k_b);
	}

	#[test]
	fn kdf_key_and_nonce_are_distinct() {
		// Sanity: HKDF info strings are different, so the 32-byte
		// key extracted from one info string MUST differ from the
		// 12-byte nonce extracted from the other. (We check the
		// first 12 bytes of the key against the nonce since those
		// are the comparable widths.)
		let shared = [0x11u8; 32];
		let eph = [0x22u8; 32];
		let recip = [0x33u8; 32];
		let (key, nonce) = derive_aead_key_and_nonce(&shared, &eph, &recip);
		assert_ne!(&key[..12], &nonce[..]);
	}

	// ── cross-context isolation ───────────────────────────────────

	#[test]
	fn ciphertext_under_v1_info_does_not_decrypt_under_alt_info() {
		// Hand-roll a "v2" KDF that uses a DIFFERENT info string
		// and prove that ciphertext sealed with v1 cannot be
		// decrypted under v2 even with the same X25519 key
		// material — domain separation flows through HKDF info.
		let mut rng = test_rng(0x14);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x15);
		let plaintext = b"v1 sealed";
		let sealed = seal(&recip_pk, plaintext, &mut rng);

		// Recover what an honest v1 recipient would compute.
		let v1_recovered = unseal(&recip_sk, &sealed).unwrap();
		assert_eq!(v1_recovered, plaintext);

		// Now simulate an "alt-info" recipient: derive an AEAD key
		// using a fake-future info string.
		const ALT_KEY_INFO: &[u8] = b"rostro/chat-sealed-sender/key/v999";
		const ALT_NONCE_INFO: &[u8] = b"rostro/chat-sealed-sender/nonce/v999";
		let recip_secret = X25519SecretKey::from(recip_sk);
		let eph_pub_obj = X25519PublicKey::from(sealed.ephemeral_pub);
		let shared = recip_secret.diffie_hellman(&eph_pub_obj);
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(&sealed.ephemeral_pub);
		salt[32..].copy_from_slice(&recip_pk);
		let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
		let mut alt_key = [0u8; 32];
		let mut alt_nonce = [0u8; 12];
		hk.expand(ALT_KEY_INFO, &mut alt_key).unwrap();
		hk.expand(ALT_NONCE_INFO, &mut alt_nonce).unwrap();

		let alt_cipher = ChaCha20Poly1305::new((&alt_key).into());
		let outcome = alt_cipher.decrypt(
			(&alt_nonce).into(),
			sealed.ciphertext.as_slice(),
		);
		assert!(
			outcome.is_err(),
			"a v1-sealed ciphertext must not decrypt under a v999 KDF info",
		);
	}

	// ── public domain constant pins ───────────────────────────────

	#[test]
	fn domain_constants_have_expected_values() {
		assert_eq!(
			SEALED_SENDER_KEY_INFO,
			b"rostro/chat-sealed-sender/key/v1",
		);
		assert_eq!(
			SEALED_SENDER_NONCE_INFO,
			b"rostro/chat-sealed-sender/nonce/v1",
		);
		assert_eq!(
			SEALED_SENDER_HYBRID_KEY_INFO,
			b"rostro/chat-sealed-sender/hybrid-key/v1",
		);
		assert_eq!(
			SEALED_SENDER_HYBRID_NONCE_INFO,
			b"rostro/chat-sealed-sender/hybrid-nonce/v1",
		);
	}

	// ── hybrid (X25519 + ML-KEM-768) seal ─────────────────────────

	fn fresh_seal_keypair(
		seed: u8,
	) -> (rostro_hybrid_kex::MlKemDecapKey, [u8; rostro_hybrid_kex::MLKEM768_EK_BYTES]) {
		rostro_hybrid_kex::mlkem_keypair_from_seed(&[seed; 64])
	}

	#[test]
	fn hybrid_seal_unseal_roundtrip() {
		let mut rng = test_rng(0x20);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x21);
		let (seal_dk, seal_ek) = fresh_seal_keypair(0x22);
		let plaintext = b"hello hybrid sealed sender";
		let sealed = hybrid_seal(&recip_pk, &seal_ek, plaintext, &mut rng).unwrap();
		let recovered = hybrid_unseal(&recip_sk, &seal_dk, &sealed).unwrap();
		assert_eq!(recovered, plaintext);
	}

	#[test]
	fn hybrid_larger_plaintext_roundtrip() {
		let mut rng = test_rng(0x23);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x24);
		let (seal_dk, seal_ek) = fresh_seal_keypair(0x25);
		// 4 KiB — the FIXED_DROP_SIZE onion budget.
		let plaintext: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
		let sealed = hybrid_seal(&recip_pk, &seal_ek, &plaintext, &mut rng).unwrap();
		let recovered = hybrid_unseal(&recip_sk, &seal_dk, &sealed).unwrap();
		assert_eq!(recovered, plaintext);
	}

	#[test]
	fn hybrid_two_seals_differ() {
		let mut rng = test_rng(0x26);
		let (_recip_sk, recip_pk) = fresh_recipient_keypair(0x27);
		let (_seal_dk, seal_ek) = fresh_seal_keypair(0x28);
		let s1 = hybrid_seal(&recip_pk, &seal_ek, b"same", &mut rng).unwrap();
		let s2 = hybrid_seal(&recip_pk, &seal_ek, b"same", &mut rng).unwrap();
		assert_ne!(s1.ephemeral_pub, s2.ephemeral_pub);
		assert_ne!(s1.pq_ct, s2.pq_ct);
		assert_ne!(s1.ciphertext, s2.ciphertext);
	}

	#[test]
	fn hybrid_tampered_ciphertext_fails() {
		let mut rng = test_rng(0x29);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x2A);
		let (seal_dk, seal_ek) = fresh_seal_keypair(0x2B);
		let mut sealed = hybrid_seal(&recip_pk, &seal_ek, b"payload", &mut rng).unwrap();
		sealed.ciphertext[0] ^= 0xFF;
		assert_eq!(
			hybrid_unseal(&recip_sk, &seal_dk, &sealed),
			Err(UnsealError::AeadAuthFailed),
		);
	}

	#[test]
	fn hybrid_tampered_ephemeral_fails() {
		let mut rng = test_rng(0x2C);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x2D);
		let (seal_dk, seal_ek) = fresh_seal_keypair(0x2E);
		let mut sealed = hybrid_seal(&recip_pk, &seal_ek, b"payload", &mut rng).unwrap();
		sealed.ephemeral_pub[15] ^= 0xFF;
		assert_eq!(
			hybrid_unseal(&recip_sk, &seal_dk, &sealed),
			Err(UnsealError::AeadAuthFailed),
		);
	}

	#[test]
	fn hybrid_tampered_pq_ct_fails() {
		// Two independent defenses: FIPS 203 implicit rejection diverges
		// the KEM secret, AND pq_ct is AEAD AAD. Either alone fails auth.
		let mut rng = test_rng(0x2F);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x30);
		let (seal_dk, seal_ek) = fresh_seal_keypair(0x31);
		let mut sealed = hybrid_seal(&recip_pk, &seal_ek, b"payload", &mut rng).unwrap();
		sealed.pq_ct[100] ^= 0xFF;
		assert_eq!(
			hybrid_unseal(&recip_sk, &seal_dk, &sealed),
			Err(UnsealError::AeadAuthFailed),
		);
	}

	#[test]
	fn hybrid_kem_leg_actually_contributes() {
		// Correct X25519 identity secret, WRONG seal decap key: the
		// classical leg alone must not unseal.
		let mut rng = test_rng(0x32);
		let (recip_sk, recip_pk) = fresh_recipient_keypair(0x33);
		let (_seal_dk, seal_ek) = fresh_seal_keypair(0x34);
		let (wrong_dk, _) = fresh_seal_keypair(0x35);
		let sealed = hybrid_seal(&recip_pk, &seal_ek, b"both legs", &mut rng).unwrap();
		assert_eq!(
			hybrid_unseal(&recip_sk, &wrong_dk, &sealed),
			Err(UnsealError::AeadAuthFailed),
		);
	}

	#[test]
	fn hybrid_classical_leg_actually_contributes() {
		// Correct seal decap key, WRONG X25519 identity secret: the PQ
		// leg alone must not unseal.
		let mut rng = test_rng(0x36);
		let (_recip_sk, recip_pk) = fresh_recipient_keypair(0x37);
		let (wrong_sk, _) = fresh_recipient_keypair(0x38);
		let (seal_dk, seal_ek) = fresh_seal_keypair(0x39);
		let sealed = hybrid_seal(&recip_pk, &seal_ek, b"both legs", &mut rng).unwrap();
		assert_eq!(
			hybrid_unseal(&wrong_sk, &seal_dk, &sealed),
			Err(UnsealError::AeadAuthFailed),
		);
	}

	#[test]
	fn hybrid_invalid_seal_ek_is_hard_error() {
		// A structurally invalid ek (coefficients out of range) must be
		// a loud error, not a silent garbage seal — the sender is about
		// to trust this key with the whole envelope.
		let mut rng = test_rng(0x3A);
		let (_recip_sk, recip_pk) = fresh_recipient_keypair(0x3B);
		let bad_ek = [0xFFu8; rostro_hybrid_kex::MLKEM768_EK_BYTES];
		assert_eq!(
			hybrid_seal(&recip_pk, &bad_ek, b"x", &mut rng),
			Err(HybridSealError::InvalidSealKey),
		);
	}

	#[test]
	fn hybrid_sealed_output_scale_roundtrip_and_size() {
		let mut rng = test_rng(0x3C);
		let (_recip_sk, recip_pk) = fresh_recipient_keypair(0x3D);
		let (_seal_dk, seal_ek) = fresh_seal_keypair(0x3E);
		let sealed = hybrid_seal(&recip_pk, &seal_ek, b"x", &mut rng).unwrap();
		let encoded = sealed.encode();
		let decoded = HybridSealedOutput::decode(&mut &encoded[..]).unwrap();
		assert_eq!(sealed, decoded);
		// 32 (eph) + 1088 (pq_ct) + 1 (compact len) + 1 (plaintext)
		// + 16 (poly1305 tag) = 1138: the hybrid tax over classical is
		// exactly the pq_ct.
		assert_eq!(encoded.len(), 1138);
	}

	#[test]
	fn hybrid_and_classical_kdf_domains_are_isolated() {
		// Same 32-byte secret, same salt inputs: the classical and
		// hybrid derivations must never produce the same AEAD key.
		let secret = [0x11u8; 32];
		let eph = [0x22u8; 32];
		let recip = [0x33u8; 32];
		let (k_classical, n_classical) = derive_aead_key_and_nonce(&secret, &eph, &recip);
		let (k_hybrid, n_hybrid) = derive_hybrid_aead_key_and_nonce(&secret, &eph, &recip);
		assert_ne!(k_classical, k_hybrid);
		assert_ne!(n_classical, n_hybrid);
	}
}
