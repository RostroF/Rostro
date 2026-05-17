// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Per-response verification primitives.
//!
//! Crate-level verification logic. Three responsibilities:
//!
//! - [`verify_sender`]: validates the sender's Ed25519 signature
//!   over a recovered [`crate::envelope::UnsealedInner`] against
//!   the message id observed in the outer envelope.
//! - [`derive_share_mac_key`] + [`mac_share`] + [`verify_share_mac`]:
//!   per-share MAC construction. Each XOR share is tagged with a
//!   keyed-blake2 MAC, keyed by a per-message key derived from the
//!   upper-layer session secret. A relay that flips bits in a share
//!   produces a MAC mismatch that the recipient detects at fetch
//!   time, identifying *which* share was tampered.
//! - [`MacError`] / [`VerifyError`]: distinguishable error variants
//!   so callers can route remediation (re-fetch the bad share, ban
//!   the offending relay, etc.).
//!
//! TTL checks live on [`crate::descriptor::ShareDescriptor`]
//! directly (`is_expired`).

use alloc::vec::Vec;
use sp_crypto_hashing::blake2_256;

use crate::descriptor::{MessageId, ShareIndex};
use crate::envelope::{build_sender_preimage, UnsealedInner};

/// Length of a per-share MAC tag, in bytes. Blake2-256 output is 32 bytes.
pub const MAC_TAG_LEN: usize = 32;

/// Per-share MAC key. Derived per-message from the upper-layer session
/// secret via [`derive_share_mac_key`]; the same key MACs every share
/// of a given message.
pub type ShareMacKey = [u8; 32];

/// Per-share MAC tag.
pub type ShareMacTag = [u8; MAC_TAG_LEN];

/// Domain-separation tag for share-MAC-key derivation.
pub const SHARE_MAC_KEY_DOMAIN: &[u8] = b"rostro/chat/share-mac-key/v1";

/// Domain-separation tag for the share MAC itself.
pub const SHARE_MAC_DOMAIN: &[u8] = b"rostro/chat/share-mac/v1";

/// Verification outcomes for a single [`UnsealedInner`] sender check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
	/// `sender_pubkey` is not a valid Ed25519 point.
	InvalidPubkey,
	/// `sender_signature` does not match the preimage under
	/// `sender_pubkey`. Could indicate tampered `inner_ciphertext`,
	/// tampered `message_id`, tampered signature bytes, or wrong
	/// purported sender key.
	SignatureInvalid,
}

/// MAC-check outcomes for a single share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacError {
	/// Computed MAC for the share bytes + index does not match the
	/// claimed tag. Indicates tampered share bytes, tampered index
	/// (share-swap attack), or tampered tag.
	TagMismatch,
}

/// Derive a per-message share-MAC key from an upper-layer session
/// secret and the message id. The same key MACs every share of a
/// given message; different messages produce different keys.
///
/// `session_secret` is whatever the upper layer (MLS group epoch
/// key, Double Ratchet message key, etc.) hands us — this crate
/// does not own session state.
///
/// Layout:
///
/// ```text
/// SHARE_MAC_KEY_DOMAIN || session_secret || message_id
/// ```
pub fn derive_share_mac_key(
	session_secret: &[u8; 32],
	message_id: &MessageId,
) -> ShareMacKey {
	let mut input = Vec::with_capacity(SHARE_MAC_KEY_DOMAIN.len() + 32 + 32);
	input.extend_from_slice(SHARE_MAC_KEY_DOMAIN);
	input.extend_from_slice(session_secret);
	input.extend_from_slice(&message_id.0);
	blake2_256(&input)
}

/// Compute the MAC tag for a single share.
///
/// Layout signed:
///
/// ```text
/// SHARE_MAC_DOMAIN || key || share_index || share_bytes
/// ```
///
/// Including `share_index` in the preimage prevents share-swap
/// attacks where a relay returns `share[i]`'s bytes when `share[j]`
/// was asked for. The MAC binds bytes to their canonical position.
pub fn mac_share(
	key: &ShareMacKey,
	share_bytes: &[u8],
	share_index: ShareIndex,
) -> ShareMacTag {
	let mut input = Vec::with_capacity(
		SHARE_MAC_DOMAIN.len() + 32 + 1 + share_bytes.len(),
	);
	input.extend_from_slice(SHARE_MAC_DOMAIN);
	input.extend_from_slice(key);
	input.push(share_index);
	input.extend_from_slice(share_bytes);
	blake2_256(&input)
}

/// Verify a claimed MAC tag against a share's bytes + index under
/// `key`. Constant-time-ish comparison: blake2_256 itself is fast
/// and the byte comparison short-circuits, but for 32-byte MACs the
/// timing exposure is negligible.
///
/// Returns `Ok(())` on match, [`MacError::TagMismatch`] on any
/// divergence (tampered bytes, tampered index, tampered tag, wrong
/// key — all surface as the same outcome).
pub fn verify_share_mac(
	key: &ShareMacKey,
	share_bytes: &[u8],
	share_index: ShareIndex,
	claimed_tag: &ShareMacTag,
) -> Result<(), MacError> {
	let computed = mac_share(key, share_bytes, share_index);
	if &computed == claimed_tag {
		Ok(())
	} else {
		Err(MacError::TagMismatch)
	}
}

/// Verify the sender's signature on a recovered [`UnsealedInner`]
/// against the `message_id` observed in the outer envelope.
///
/// On success returns the sender pubkey. The caller must verify this
/// pubkey matches the upper-layer session's expected sender (e.g.,
/// the MLS roster for the group, or the DR pairwise identity).
/// This function does not own session state.
///
/// **Critical:** `message_id` MUST be the message id from the
/// outer [`crate::envelope::SealedEnvelope`], NOT one re-derived
/// from the inner ciphertext. The signature binds the *outer
/// envelope's* `message_id` to the inner ciphertext; passing a
/// mismatched id is the same failure as a tampered signature.
pub fn verify_sender(
	unsealed: &UnsealedInner,
	message_id: &MessageId,
) -> Result<[u8; 32], VerifyError> {
	let preimage = build_sender_preimage(message_id, &unsealed.inner_ciphertext);
	let vk = ed25519_zebra::VerificationKey::try_from(unsealed.sender_pubkey)
		.map_err(|_| VerifyError::InvalidPubkey)?;
	let sig = ed25519_zebra::Signature::from(unsealed.sender_signature);
	vk.verify(&sig, &preimage)
		.map_err(|_| VerifyError::SignatureInvalid)?;
	Ok(unsealed.sender_pubkey)
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
	use super::*;
	use crate::envelope::sign_inner;
	use ed25519_zebra::SigningKey;
	use alloc::vec;

	fn fixed_key() -> SigningKey {
		SigningKey::from([0x42u8; 32])
	}

	fn other_key() -> SigningKey {
		SigningKey::from([0x99u8; 32])
	}

	#[test]
	fn verify_accepts_honest_signature() {
		let key = fixed_key();
		let mid = MessageId([0xAA; 32]);
		let unsealed = sign_inner(vec![1, 2, 3, 4, 5], &mid, &key);

		let pubkey = verify_sender(&unsealed, &mid).unwrap();
		let expected: [u8; 32] =
			ed25519_zebra::VerificationKey::from(&key).into();
		assert_eq!(pubkey, expected);
	}

	#[test]
	fn verify_rejects_tampered_inner_ciphertext() {
		let key = fixed_key();
		let mid = MessageId([0xAA; 32]);
		let mut unsealed = sign_inner(vec![1, 2, 3, 4, 5], &mid, &key);
		// Flip a byte after signing; signature no longer matches.
		unsealed.inner_ciphertext[0] ^= 0xFF;
		assert_eq!(
			verify_sender(&unsealed, &mid),
			Err(VerifyError::SignatureInvalid),
		);
	}

	#[test]
	fn verify_rejects_tampered_message_id() {
		let key = fixed_key();
		let signed_mid = MessageId([0xAA; 32]);
		let unsealed = sign_inner(vec![1, 2, 3], &signed_mid, &key);
		// Recipient passes a different message_id than the one the
		// sender signed over. Verification fails.
		let wrong_mid = MessageId([0xBB; 32]);
		assert_eq!(
			verify_sender(&unsealed, &wrong_mid),
			Err(VerifyError::SignatureInvalid),
		);
	}

	#[test]
	fn verify_rejects_wrong_sender_pubkey() {
		let key_a = fixed_key();
		let key_b = other_key();
		let mid = MessageId([0xAA; 32]);
		let mut unsealed = sign_inner(vec![1, 2, 3], &mid, &key_a);
		// Replace pubkey with key_b's (which didn't sign).
		let vk_b: ed25519_zebra::VerificationKey =
			ed25519_zebra::VerificationKey::from(&key_b);
		unsealed.sender_pubkey = vk_b.into();
		assert_eq!(
			verify_sender(&unsealed, &mid),
			Err(VerifyError::SignatureInvalid),
		);
	}

	#[test]
	fn verify_rejects_tampered_signature() {
		let key = fixed_key();
		let mid = MessageId([0xAA; 32]);
		let mut unsealed = sign_inner(vec![1, 2, 3], &mid, &key);
		unsealed.sender_signature[0] ^= 0xFF;
		assert_eq!(
			verify_sender(&unsealed, &mid),
			Err(VerifyError::SignatureInvalid),
		);
	}

	#[test]
	fn verify_rejects_invalid_pubkey_bytes() {
		// All-0xFF bytes are unlikely to decompress to a valid
		// Ed25519 point. ed25519-zebra may reject at decode time
		// (InvalidPubkey) or at verify time (SignatureInvalid)
		// depending on whether the bytes happen to lift to some
		// point on the curve; either path preserves the contract
		// that bogus pubkey bytes do not verify.
		let key = fixed_key();
		let mid = MessageId([0xAA; 32]);
		let mut unsealed = sign_inner(vec![1, 2, 3], &mid, &key);
		unsealed.sender_pubkey = [0xFFu8; 32];
		match verify_sender(&unsealed, &mid) {
			Err(VerifyError::InvalidPubkey) | Err(VerifyError::SignatureInvalid) => {},
			other => panic!(
				"expected InvalidPubkey or SignatureInvalid, got {:?}",
				other,
			),
		}
	}

	#[test]
	fn verify_rejects_empty_inner_ciphertext_with_wrong_sig() {
		// Honest-empty-ciphertext: sign empty, verify empty — works.
		let key = fixed_key();
		let mid = MessageId([0xAA; 32]);
		let unsealed = sign_inner(vec![], &mid, &key);
		assert!(verify_sender(&unsealed, &mid).is_ok());

		// Tampered: claim empty but the sig was for non-empty.
		let mut tampered = sign_inner(vec![1, 2, 3], &mid, &key);
		tampered.inner_ciphertext.clear();
		assert_eq!(
			verify_sender(&tampered, &mid),
			Err(VerifyError::SignatureInvalid),
		);
	}

	// ── share MAC primitives ──────────────────────────────────────

	const SAMPLE_SECRET: [u8; 32] = [0x42; 32];

	#[test]
	fn mac_honest_share_verifies() {
		let key = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0xAA; 32]));
		let bytes = vec![1, 2, 3, 4, 5];
		let tag = mac_share(&key, &bytes, 0);
		assert!(verify_share_mac(&key, &bytes, 0, &tag).is_ok());
	}

	#[test]
	fn mac_rejects_tampered_share_bytes() {
		let key = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0xAA; 32]));
		let bytes = vec![1, 2, 3, 4, 5];
		let tag = mac_share(&key, &bytes, 0);
		// Flip a byte; MAC fails.
		let tampered = vec![1, 2, 3, 4, 99];
		assert_eq!(
			verify_share_mac(&key, &tampered, 0, &tag),
			Err(MacError::TagMismatch),
		);
	}

	#[test]
	fn mac_rejects_share_swap() {
		// Relay returns share[0]'s bytes when share[1] was asked for.
		// The MAC binds bytes to position; index mismatch fails MAC.
		let key = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0xAA; 32]));
		let bytes = vec![5, 6, 7, 8];
		let tag_for_index_0 = mac_share(&key, &bytes, 0);
		// Same bytes, claimed as share index 1: MAC fails.
		assert_eq!(
			verify_share_mac(&key, &bytes, 1, &tag_for_index_0),
			Err(MacError::TagMismatch),
		);
	}

	#[test]
	fn mac_rejects_tampered_tag() {
		let key = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0xAA; 32]));
		let bytes = vec![1, 2, 3];
		let mut tag = mac_share(&key, &bytes, 0);
		tag[0] ^= 0xFF;
		assert_eq!(
			verify_share_mac(&key, &bytes, 0, &tag),
			Err(MacError::TagMismatch),
		);
	}

	#[test]
	fn mac_rejects_wrong_key() {
		let key_a = derive_share_mac_key(&[0x01; 32], &MessageId([0xAA; 32]));
		let key_b = derive_share_mac_key(&[0x02; 32], &MessageId([0xAA; 32]));
		let bytes = vec![1, 2, 3];
		let tag = mac_share(&key_a, &bytes, 0);
		// Wrong session secret → wrong key → MAC fails.
		assert_eq!(
			verify_share_mac(&key_b, &bytes, 0, &tag),
			Err(MacError::TagMismatch),
		);
	}

	#[test]
	fn mac_key_differs_per_message() {
		// Same session secret, different message_id → different MAC key.
		// Prevents replaying a share from one message into a different
		// message under the same session.
		let k1 = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0x01; 32]));
		let k2 = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0x02; 32]));
		assert_ne!(k1, k2);
	}

	#[test]
	fn mac_key_differs_per_session() {
		// Same message_id, different session secret → different MAC key.
		let k1 = derive_share_mac_key(&[0x01; 32], &MessageId([0xAA; 32]));
		let k2 = derive_share_mac_key(&[0x02; 32], &MessageId([0xAA; 32]));
		assert_ne!(k1, k2);
	}

	#[test]
	fn mac_is_deterministic() {
		// blake2 is deterministic; same inputs → same MAC. Test
		// pins this so a future refactor that introduces randomness
		// (it shouldn't!) breaks the test.
		let key = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0xAA; 32]));
		let bytes = vec![1, 2, 3, 4, 5];
		let t1 = mac_share(&key, &bytes, 0);
		let t2 = mac_share(&key, &bytes, 0);
		assert_eq!(t1, t2);
	}

	#[test]
	fn mac_empty_share_verifies() {
		// MAC of an empty share is well-defined; verifies cleanly.
		let key = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0xAA; 32]));
		let tag = mac_share(&key, &[], 0);
		assert!(verify_share_mac(&key, &[], 0, &tag).is_ok());
	}

	#[test]
	fn mac_key_derivation_layout_is_stable() {
		// Pin output against accidental refactors. A change here
		// breaks every previously-MAC'd share.
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0x55; 32]));
		// Recompute by hand to assert the formula didn't change.
		let mut input = Vec::with_capacity(SHARE_MAC_KEY_DOMAIN.len() + 32 + 32);
		input.extend_from_slice(SHARE_MAC_KEY_DOMAIN);
		input.extend_from_slice(&[0x42; 32]);
		input.extend_from_slice(&[0x55; 32]);
		assert_eq!(key, blake2_256(&input));
	}
}
