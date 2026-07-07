// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Sealed Sender envelope types.
//!
//! Mirrors Signal's Sealed Sender pattern: the **outer envelope**
//! reveals only routing-essential fields (the envelope kind and an
//! opaque outer ciphertext blob). The **sender's identity** — their
//! pubkey and their signature over the inner payload — lives only
//! inside the [`UnsealedInner`] structure, which is encrypted by the
//! upper layer (Sealed Sender outer-layer ECDH + AEAD) before the
//! outer envelope is constructed. Anyone observing the wire sees
//! only [`SealedEnvelope`]; the sender's identity is invisible until
//! the recipient decrypts.
//!
//! ## Layering
//!
//! 1. **Plaintext** message.
//! 2. Upper layer (MLS for groups, Double Ratchet for pairwise)
//!    encrypts plaintext → `inner_ciphertext`.
//! 3. Sender signs `(message_id, inner_ciphertext)` under a
//!    domain-separated preimage. The signature + sender pubkey +
//!    `inner_ciphertext` together form [`UnsealedInner`].
//! 4. Sealed Sender outer-layer (separate from this crate's
//!    responsibility) encrypts the encoded [`UnsealedInner`] under
//!    an ephemeral-static ECDH derived key to produce
//!    `outer_ciphertext`.
//! 5. [`SealedEnvelope`] wraps `outer_ciphertext` along with the
//!    [`EnvelopeKind`] tag, ephemeral pubkey, and message id.
//! 6. The encoded [`SealedEnvelope`] is the input to the chunk
//!    layer; tagged chunks fan out to relays.
//!
//! At the recipient side, the flow is reversed: assemble shares →
//! combine → decode [`SealedEnvelope`] → outer-decrypt to
//! [`UnsealedInner`] → [`crate::verify::verify_sender`] to
//! authenticate → upper-layer-decrypt `inner_ciphertext` to
//! plaintext.
//!
//! ## What this crate does NOT do
//!
//! This crate defines the wire types and the signature preimage
//! layout only. It does NOT perform any encryption: `outer_ciphertext`
//! is treated as opaque bytes that the caller produces and consumes
//! at the Sealed Sender outer layer. Sealed Sender's ECDH + AEAD
//! plug in at the boundary. Same with the upper layer's `inner_ciphertext`
//! (MLS or DR ciphertext is opaque bytes here).
//!
//! Test invariant the wire format pins (see tests): the encoded
//! [`SealedEnvelope`] does NOT contain the sender's plaintext pubkey
//! bytes — `UnsealedInner` (which carries the pubkey) is meant to
//! sit *inside* `outer_ciphertext` after Sealed Sender encryption.

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::descriptor::{GroupId, MessageId};

/// Domain-separation tag for the sender-signature preimage. Bumped
/// (e.g. `/v2`) if the preimage layout ever changes incompatibly,
/// guaranteeing that a v1 signature cannot replay against a v2
/// verifier.
pub const SENDER_PREIMAGE_DOMAIN: &[u8] = b"rostro/chat/sender-sig/v1";

/// Tag distinguishing pairwise DMs from group messages on the
/// recipient side. Invisible to relays (the entire
/// [`SealedEnvelope`] is chunked across relays, so relays see
/// only noise shares).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum EnvelopeKind {
	/// One-to-one DM. Outer-layer Sealed Sender uses
	/// ephemeral-X25519 ECDH against the recipient's identity key.
	Pairwise,
	/// Group message addressed to `GroupId`. Outer layer uses the
	/// MLS group's current epoch key.
	Group(GroupId),
}

/// Outer-layer wire envelope. After the chunk split, pieces of the
/// SCALE-encoded form of this struct travel over the network; only
/// the recipient who assembles all N shares reconstructs the
/// envelope.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SealedEnvelope {
	/// Pairwise/group tag for recipient's decrypt path.
	pub kind: EnvelopeKind,
	/// Opaque outer ciphertext. Upper-layer Sealed Sender produces
	/// these bytes by encrypting an encoded [`UnsealedInner`] under
	/// an ephemeral-static ECDH derived key. This crate treats it
	/// as opaque.
	pub outer_ciphertext: Vec<u8>,
	/// Sender's ephemeral X25519 public key for outer-layer ECDH.
	/// For [`EnvelopeKind::Group`] messages where the outer key
	/// derives from MLS group state, this is the zero sentinel
	/// `[0u8; 32]` (the receiver knows from `kind` that the
	/// ephemeral key is unused).
	pub ephemeral_pubkey: [u8; 32],
	/// Stable message id. Echoed in the share descriptors so the
	/// recipient can correlate (DHT descriptor → assembled envelope)
	/// and so the sender's signature binds to a per-message identity
	/// rather than to a session.
	pub message_id: MessageId,
}

/// Post-outer-decrypt view. The recipient produces this by decrypting
/// [`SealedEnvelope::outer_ciphertext`]. The sender's pubkey +
/// signature live here (never in the outer envelope), so observers
/// of the wire never see them.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct UnsealedInner {
	/// Sender's Ed25519 public key. Verified against the upper-
	/// layer session state by [`crate::verify::verify_sender`].
	pub sender_pubkey: [u8; 32],
	/// Ed25519 signature over `build_sender_preimage(message_id,
	/// inner_ciphertext)`.
	pub sender_signature: [u8; 64],
	/// Upper-layer (MLS or DR) ciphertext. Opaque to this crate;
	/// recipient passes it to the upper layer for decrypt.
	pub inner_ciphertext: Vec<u8>,
}

/// Build the canonical preimage bytes that a sender signs over.
/// Layout:
///
/// ```text
/// SENDER_PREIMAGE_DOMAIN || message_id || inner_ciphertext
/// ```
///
/// Length: `SENDER_PREIMAGE_DOMAIN.len() + 32 + inner_ciphertext.len()`.
///
/// The signature binds the sender's identity to **this specific
/// message_id** and **this specific inner ciphertext** — replaying a
/// signature against a different message or different ciphertext
/// fails verification.
pub fn build_sender_preimage(
	message_id: &MessageId,
	inner_ciphertext: &[u8],
) -> Vec<u8> {
	let mut buf = Vec::with_capacity(SENDER_PREIMAGE_DOMAIN.len() + 32 + inner_ciphertext.len());
	buf.extend_from_slice(SENDER_PREIMAGE_DOMAIN);
	buf.extend_from_slice(&message_id.0);
	buf.extend_from_slice(inner_ciphertext);
	buf
}

/// Sign an inner ciphertext under the given Ed25519 signing key and
/// return a constructed [`UnsealedInner`]. Pure constructor — no
/// I/O, no randomness in the signing operation itself (Ed25519
/// signatures are deterministic).
///
/// Std-gated because [`ed25519_zebra::SigningKey`] construction
/// pulls in `getrandom` for key generation; the verify path stays
/// no_std-compatible for any future no_std consumer.
#[cfg(feature = "std")]
pub fn sign_inner(
	inner_ciphertext: Vec<u8>,
	message_id: &MessageId,
	signing_key: &ed25519_zebra::SigningKey,
) -> UnsealedInner {
	let preimage = build_sender_preimage(message_id, &inner_ciphertext);
	let sig: ed25519_zebra::Signature = signing_key.sign(&preimage);
	let vk: ed25519_zebra::VerificationKey =
		ed25519_zebra::VerificationKey::from(signing_key);
	UnsealedInner {
		sender_pubkey: vk.into(),
		sender_signature: sig.into(),
		inner_ciphertext,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::descriptor::GroupId;

	#[test]
	fn envelope_kind_pairwise_scale_roundtrip() {
		let k = EnvelopeKind::Pairwise;
		let bytes = k.encode();
		assert_eq!(EnvelopeKind::decode(&mut &bytes[..]).unwrap(), k);
	}

	#[test]
	fn envelope_kind_group_scale_roundtrip() {
		let k = EnvelopeKind::Group(GroupId([0x42; 32]));
		let bytes = k.encode();
		assert_eq!(EnvelopeKind::decode(&mut &bytes[..]).unwrap(), k);
	}

	#[test]
	fn sealed_envelope_pairwise_scale_roundtrip() {
		let e = SealedEnvelope {
			kind: EnvelopeKind::Pairwise,
			outer_ciphertext: alloc::vec![0xAB; 64],
			ephemeral_pubkey: [0xCD; 32],
			message_id: MessageId([0xEF; 32]),
		};
		let bytes = e.encode();
		assert_eq!(SealedEnvelope::decode(&mut &bytes[..]).unwrap(), e);
	}

	#[test]
	fn sealed_envelope_group_scale_roundtrip() {
		let e = SealedEnvelope {
			kind: EnvelopeKind::Group(GroupId([0x11; 32])),
			outer_ciphertext: alloc::vec![0x22; 128],
			// Group envelopes use the zero sentinel for ephemeral_pubkey.
			ephemeral_pubkey: [0u8; 32],
			message_id: MessageId([0x33; 32]),
		};
		let bytes = e.encode();
		assert_eq!(SealedEnvelope::decode(&mut &bytes[..]).unwrap(), e);
	}

	#[test]
	fn unsealed_inner_scale_roundtrip() {
		let u = UnsealedInner {
			sender_pubkey: [0xAA; 32],
			sender_signature: [0xBB; 64],
			inner_ciphertext: alloc::vec![0xCC; 50],
		};
		let bytes = u.encode();
		assert_eq!(UnsealedInner::decode(&mut &bytes[..]).unwrap(), u);
	}

	// ── preimage layout stability ─────────────────────────────────

	#[test]
	fn preimage_layout_is_stable() {
		// Pin the preimage byte layout against accidental refactors.
		// A change here breaks every previously-signed message.
		let p = build_sender_preimage(&MessageId([0xAA; 32]), &[0xBB, 0xBB, 0xBB]);
		assert_eq!(p.len(), SENDER_PREIMAGE_DOMAIN.len() + 32 + 3);
		assert_eq!(&p[..SENDER_PREIMAGE_DOMAIN.len()], SENDER_PREIMAGE_DOMAIN);
		let body_off = SENDER_PREIMAGE_DOMAIN.len();
		assert_eq!(&p[body_off..body_off + 32], &[0xAA; 32]);
		assert_eq!(&p[body_off + 32..body_off + 35], &[0xBB; 3]);
	}

	#[test]
	fn preimage_includes_message_id() {
		// Different message_ids produce different preimages even
		// with identical inner ciphertext — binds signature to
		// per-message identity.
		let inner = alloc::vec![0xCC; 8];
		let p1 = build_sender_preimage(&MessageId([0x01; 32]), &inner);
		let p2 = build_sender_preimage(&MessageId([0x02; 32]), &inner);
		assert_ne!(p1, p2);
	}

	#[test]
	fn preimage_includes_inner_ciphertext() {
		// Different inner ciphertexts produce different preimages
		// even with identical message_id — binds signature to the
		// specific payload.
		let mid = MessageId([0x05; 32]);
		let p1 = build_sender_preimage(&mid, b"hello");
		let p2 = build_sender_preimage(&mid, b"world");
		assert_ne!(p1, p2);
	}

	// ── wire format invariants ────────────────────────────────────

	#[test]
	fn outer_envelope_does_not_leak_sender_pubkey() {
		// Wire contract: SealedEnvelope's encoded form must not
		// contain a plaintext sender_pubkey. The sender_pubkey
		// lives in UnsealedInner, which is meant to be wrapped
		// inside outer_ciphertext after Sealed Sender encryption.
		//
		// We simulate the encryption by filling outer_ciphertext
		// with a benign pattern; verify the encoded outer doesn't
		// contain the (distinctive) sender_pubkey bytes.
		let sender_pubkey_bytes = [0x77u8; 32]; // distinctive marker

		// Sanity: confirm UnsealedInner DOES contain the marker
		// when encoded directly (this is the "before encryption"
		// view that must not appear on the wire).
		let inner = UnsealedInner {
			sender_pubkey: sender_pubkey_bytes,
			sender_signature: [0x88; 64],
			inner_ciphertext: alloc::vec![0x99; 16],
		};
		let inner_encoded = inner.encode();
		assert!(
			inner_encoded.windows(32).any(|w| w == sender_pubkey_bytes),
			"sanity: UnsealedInner SHOULD contain sender_pubkey when encoded raw",
		);

		// Outer envelope built with a placeholder ciphertext that
		// does NOT contain the sender_pubkey pattern. In real use,
		// outer_ciphertext is AEAD(inner_encoded) under the Sealed
		// Sender outer key; the pubkey is no longer in plaintext.
		let outer_placeholder_ciphertext = alloc::vec![0xAB; 100];
		let env = SealedEnvelope {
			kind: EnvelopeKind::Pairwise,
			outer_ciphertext: outer_placeholder_ciphertext,
			ephemeral_pubkey: [0xEE; 32],
			message_id: MessageId([0xFF; 32]),
		};
		let outer_encoded = env.encode();

		assert!(
			!outer_encoded.windows(32).any(|w| w == sender_pubkey_bytes),
			"SealedEnvelope wire form must NOT contain the sender_pubkey \
			 bytes when outer_ciphertext is properly encrypted",
		);
	}

	#[test]
	fn outer_envelope_does_not_leak_sender_signature() {
		// Same wire-contract check for the sender signature.
		let sig_bytes = [0x66u8; 64]; // distinctive marker

		let inner = UnsealedInner {
			sender_pubkey: [0x77; 32],
			sender_signature: sig_bytes,
			inner_ciphertext: alloc::vec![],
		};
		let inner_encoded = inner.encode();
		assert!(
			inner_encoded.windows(64).any(|w| w == sig_bytes),
			"sanity: UnsealedInner SHOULD contain sender_signature when encoded raw",
		);

		let env = SealedEnvelope {
			kind: EnvelopeKind::Pairwise,
			outer_ciphertext: alloc::vec![0x11; 80],
			ephemeral_pubkey: [0x22; 32],
			message_id: MessageId([0x33; 32]),
		};
		let outer_encoded = env.encode();
		assert!(
			!outer_encoded.windows(64).any(|w| w == sig_bytes),
			"SealedEnvelope wire form must NOT contain the sender_signature",
		);
	}

	// ── sign + verify roundtrip (under std) ───────────────────────

	#[cfg(feature = "std")]
	#[test]
	fn sign_inner_produces_verifiable_signature() {
		use ed25519_zebra::SigningKey;
		let signing_key = SigningKey::from([0x42u8; 32]);
		let mid = MessageId([0xAB; 32]);
		let ciphertext = alloc::vec![1, 2, 3, 4, 5];

		let unsealed = sign_inner(ciphertext.clone(), &mid, &signing_key);

		// Pubkey matches the signing key.
		let expected_vk: ed25519_zebra::VerificationKey =
			ed25519_zebra::VerificationKey::from(&signing_key);
		let expected_pk: [u8; 32] = expected_vk.into();
		assert_eq!(unsealed.sender_pubkey, expected_pk);

		// Inner ciphertext is carried unchanged.
		assert_eq!(unsealed.inner_ciphertext, ciphertext);

		// Signature verifies against the preimage.
		let preimage = build_sender_preimage(&mid, &ciphertext);
		let vk =
			ed25519_zebra::VerificationKey::try_from(unsealed.sender_pubkey).unwrap();
		let sig = ed25519_zebra::Signature::from(unsealed.sender_signature);
		assert!(vk.verify(&sig, &preimage).is_ok());
	}

	#[cfg(feature = "std")]
	#[test]
	fn sign_inner_is_deterministic() {
		// Ed25519 sigs are deterministic; two calls with the same
		// (key, mid, inner) produce identical UnsealedInner.
		use ed25519_zebra::SigningKey;
		let key = SigningKey::from([0x42u8; 32]);
		let mid = MessageId([0xAB; 32]);
		let ciphertext = alloc::vec![1, 2, 3];

		let u1 = sign_inner(ciphertext.clone(), &mid, &key);
		let u2 = sign_inner(ciphertext, &mid, &key);
		assert_eq!(u1, u2);
	}
}
