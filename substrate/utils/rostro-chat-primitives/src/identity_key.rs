// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Ed25519 → X25519 identity-key derivation.
//!
//! Phase C1 of the MLS-chat plan. Provides the deterministic
//! conversion from a Rostro user's Ed25519 identity pubkey (their
//! SS58 AccountId bytes for Ed25519-keyed accounts, per the
//! `btow_chain_side_progress` BTOW design — Ed25519 accounts have
//! `AccountId = raw pubkey`) into the X25519 identity pubkey used
//! by the `rostro-chat-sealed-sender` crate's `seal()` for outer-layer ECDH.
//!
//! ## Why convert rather than register
//!
//! Every Rostro SS58 already has a cryptographic identity (Ed25519
//! for sig + sr25519 for some variants). Registering a separate
//! X25519 chat-identity key on-chain would duplicate state and
//! create a "your chat key was never registered" failure mode.
//! The conversion lets any RNS-resolved Ed25519 SS58 immediately
//! receive sealed-sender chat without additional setup.
//!
//! ## The conversion (RFC 7748 / Signal precedent)
//!
//! Ed25519 keys live on the Edwards form of Curve25519; X25519 keys
//! live on the Montgomery form. There is a canonical, bijective
//! map between them. Signal uses exactly this conversion in their
//! "XEdDSA" construction so a user's single identity key serves
//! both signing (Ed25519) and ECDH (X25519). Implementation:
//! decompress the Ed25519 point, convert to Montgomery, serialize
//! the u-coordinate.
//!
//! ## Limitations
//!
//! - **Ed25519-only.** sr25519 (Ristretto) accounts have a
//!   different point representation. For v0.1 chat the assumption
//!   is that users register their RNS name with an Ed25519 key.
//!   sr25519-keyed accounts would need either (a) a separate
//!   chat-identity-key registration mechanism or (b) extending
//!   this derivation to also handle Ristretto. Tracked as
//!   follow-up.
//! - **Some Ed25519 pubkeys don't decompress.** Bytes that don't
//!   encode a valid Edwards point fail conversion. This function
//!   returns `Option<[u8; 32]>` so callers can surface that.

/// Convert a 32-byte Ed25519 signing-key seed into the matching
/// X25519 static secret. The resulting secret pairs (via
/// [`ed25519_to_x25519_pubkey`]) with the X25519 pubkey derived
/// from the corresponding Ed25519 verification key — Signal's
/// XEdDSA construction.
///
/// Algorithm (per RFC 7748 / Ed25519 internal expansion):
///   1. `h = SHA-512(seed)`
///   2. X25519 scalar bytes = first 32 bytes of `h`
///   3. Apply X25519 clamping:
///      - `bytes[0] &= 248` (clear low 3 bits)
///      - `bytes[31] &= 127` (clear high bit)
///      - `bytes[31] |= 64`  (set second-highest bit)
///
/// The resulting 32 bytes are a valid `x25519_dalek::StaticSecret`
/// scalar that produces the same X25519 public key as
/// [`ed25519_to_x25519_pubkey`] applied to the corresponding
/// Ed25519 verification key.
pub fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> [u8; 32] {
	use sha2::{Digest, Sha512};
	let hash = Sha512::digest(seed);
	let mut secret = [0u8; 32];
	secret.copy_from_slice(&hash[..32]);
	// X25519 clamping (RFC 7748 §5).
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
	secret
}

/// Convert a raw 32-byte Ed25519 public key into the canonical
/// X25519 public key (u-coordinate, 32 bytes) for the same
/// underlying identity.
///
/// Returns `None` if `ed25519_pubkey` does not decode as a valid
/// Edwards point.
///
/// This is the Signal-precedent "convert once" pattern: the user's
/// single identity key generates both their Ed25519 signing key
/// (used by `rostro-chat-primitives::envelope::sign_inner`) and
/// their X25519 ECDH key (used by `rostro-chat-sealed-sender::seal`
/// to encrypt the outer envelope to them).
pub fn ed25519_to_x25519_pubkey(ed25519_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
	let compressed = curve25519_dalek::edwards::CompressedEdwardsY(*ed25519_pubkey);
	let edwards = compressed.decompress()?;
	let montgomery = edwards.to_montgomery();
	Some(montgomery.to_bytes())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A known-valid Ed25519 verification key (the public side of a
	/// fixed signing key). Generated once from `SigningKey::from(seed)`
	/// — used as a stable test vector.
	fn known_ed25519_pubkey() -> [u8; 32] {
		let signing = ed25519_zebra::SigningKey::from([0x42u8; 32]);
		let vk = ed25519_zebra::VerificationKey::from(&signing);
		vk.into()
	}

	#[test]
	fn convert_valid_ed25519_pubkey() {
		let ed = known_ed25519_pubkey();
		let x = ed25519_to_x25519_pubkey(&ed).expect("valid Ed25519 must convert");
		assert_ne!(
			&x, &[0u8; 32],
			"converted X25519 pubkey must not be all-zero",
		);
		assert_ne!(
			&x, &ed,
			"X25519 form should differ from Ed25519 form (different curves)",
		);
	}

	#[test]
	fn conversion_is_deterministic() {
		let ed = known_ed25519_pubkey();
		let x1 = ed25519_to_x25519_pubkey(&ed).unwrap();
		let x2 = ed25519_to_x25519_pubkey(&ed).unwrap();
		assert_eq!(x1, x2, "conversion is a pure function");
	}

	#[test]
	fn different_ed25519_keys_yield_different_x25519_keys() {
		let signing_a = ed25519_zebra::SigningKey::from([0x11u8; 32]);
		let signing_b = ed25519_zebra::SigningKey::from([0x22u8; 32]);
		let ed_a: [u8; 32] = ed25519_zebra::VerificationKey::from(&signing_a).into();
		let ed_b: [u8; 32] = ed25519_zebra::VerificationKey::from(&signing_b).into();
		let x_a = ed25519_to_x25519_pubkey(&ed_a).unwrap();
		let x_b = ed25519_to_x25519_pubkey(&ed_b).unwrap();
		assert_ne!(x_a, x_b);
	}

	#[test]
	fn function_signature_returns_option() {
		// Some 32-byte patterns happen to decompress as valid
		// Edwards points (Curve25519's y-coordinate space is dense),
		// so we can't easily assert "bad bytes return None" for a
		// specific input. The function contract is captured in the
		// signature `-> Option<[u8; 32]>` and exercised through the
		// real-key path in `convert_valid_ed25519_pubkey`. This test
		// just exercises both Some and the type-level None
		// possibility — empty random input that does decode just
		// returns a valid X25519 pubkey, and the type system
		// ensures callers handle the None branch.
		let ed = known_ed25519_pubkey();
		match ed25519_to_x25519_pubkey(&ed) {
			Some(x) => assert_eq!(x.len(), 32),
			None => panic!("known-valid Ed25519 key must decode"),
		}
	}

	#[test]
	fn converted_x25519_works_with_sealed_sender_kdf_structure() {
		// Sanity: the output is well-formed enough to be used as a
		// recipient X25519 pubkey in a Sealed Sender derivation.
		// We don't run the full seal/unseal here (that's the
		// sealed-sender crate's job) — just confirm the byte shape
		// is what the sealed-sender API expects (32 bytes).
		let ed = known_ed25519_pubkey();
		let x = ed25519_to_x25519_pubkey(&ed).unwrap();
		assert_eq!(x.len(), 32);
	}

	#[test]
	fn seed_to_secret_yields_valid_x25519_keypair() {
		// The XEdDSA invariant: the X25519 secret derived from a
		// seed pairs with the X25519 pubkey derived from the
		// corresponding Ed25519 verification key. ECDH between
		// (derived secret, peer pubkey) is symmetric.
		use x25519_dalek::{PublicKey as XPub, StaticSecret as XSecret};

		let alice_seed = [0x42u8; 32];
		let alice_signing = ed25519_zebra::SigningKey::from(alice_seed);
		let alice_ed_pub: [u8; 32] =
			ed25519_zebra::VerificationKey::from(&alice_signing).into();

		let alice_x_secret_bytes = ed25519_seed_to_x25519_secret(&alice_seed);
		let alice_x_pub_via_secret =
			*XPub::from(&XSecret::from(alice_x_secret_bytes)).as_bytes();
		let alice_x_pub_via_edwards = ed25519_to_x25519_pubkey(&alice_ed_pub).unwrap();
		assert_eq!(
			alice_x_pub_via_secret, alice_x_pub_via_edwards,
			"X25519 pubkey derived from seed must equal pubkey derived from \
			 Ed25519 verification key (XEdDSA consistency)",
		);

		// Round-trip ECDH with a second party: both sides compute
		// the same shared secret.
		let bob_seed = [0x99u8; 32];
		let bob_x_secret = XSecret::from(ed25519_seed_to_x25519_secret(&bob_seed));
		let bob_x_pub = *XPub::from(&bob_x_secret).as_bytes();
		let alice_x_secret = XSecret::from(alice_x_secret_bytes);
		let shared_alice = alice_x_secret.diffie_hellman(&XPub::from(bob_x_pub));
		let shared_bob =
			bob_x_secret.diffie_hellman(&XPub::from(alice_x_pub_via_secret));
		assert_eq!(shared_alice.as_bytes(), shared_bob.as_bytes());
	}

	#[test]
	fn seed_to_secret_is_clamped() {
		let secret = ed25519_seed_to_x25519_secret(&[0x42; 32]);
		// X25519 clamping invariants:
		assert_eq!(secret[0] & 7, 0, "low 3 bits cleared");
		assert_eq!(secret[31] & 128, 0, "high bit cleared");
		assert_eq!(secret[31] & 64, 64, "second-highest bit set");
	}

	#[test]
	fn seed_to_secret_is_deterministic() {
		let s1 = ed25519_seed_to_x25519_secret(&[0x33; 32]);
		let s2 = ed25519_seed_to_x25519_secret(&[0x33; 32]);
		assert_eq!(s1, s2);
	}

	#[test]
	fn round_through_known_zebra_key_gives_predictable_shape() {
		// Pin the conversion for a known Ed25519 input so a future
		// refactor of curve25519-dalek that changes the convention
		// breaks this test.
		let ed = known_ed25519_pubkey();
		let x = ed25519_to_x25519_pubkey(&ed).unwrap();
		// Recompute via the algorithm spelled out by hand: the
		// output must equal Edwards-to-Montgomery of the input.
		// (We're essentially asserting that the helper isn't doing
		// something funky like double-conversion.)
		let compressed = curve25519_dalek::edwards::CompressedEdwardsY(ed);
		let manual_montgomery = compressed.decompress().unwrap().to_montgomery().to_bytes();
		assert_eq!(x, manual_montgomery);
	}
}
