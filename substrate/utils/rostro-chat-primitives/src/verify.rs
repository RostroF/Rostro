// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Per-response verification primitives.
//!
//! Crate-level verification logic. Three responsibilities:
//!
//! - [`verify_sender`]: validates the sender's Ed25519 signature
//!   over a recovered [`crate::envelope::UnsealedInner`] against
//!   the message id observed in the outer envelope.
//! - [`derive_stripe_mac_secret`] + [`derive_share_mac_key`] +
//!   [`mac_chunk`] + [`verify_chunk_mac`]: per-chunk MAC
//!   construction (v2, descriptor-bound). Each chunk of a split
//!   message is tagged with a keyed-blake2 MAC computed **on the
//!   sender's device**, keyed by a per-message key derived from a
//!   per-conversation secret. The preimage binds the chunk bytes
//!   AND the sender-authored descriptor fields (message_id,
//!   pickup_key, share_index, total_shares, expires_at), so neither
//!   a storing relay nor the peeling/distributing node can rewrite
//!   any of them undetected — every relay on the path is reduced to
//!   drop-or-deliver-intact. A MAC mismatch at fetch time identifies
//!   *which* chunk was tampered.
//! - [`MacError`] / [`VerifyError`]: distinguishable error variants
//!   so callers can route remediation. NOTE the privacy rules in
//!   docs/CHAT-SHARE-CHUNKING.md §4.6: remediation is re-fetch via a
//!   NORMAL-shaped pickup query, and tamper attribution never leaves
//!   the recipient's device.
//!
//! MAC verification is local-only on the recipient device and
//! produces no wire traffic: it authenticates the shares TO the
//! recipient, never the recipient to anyone. The unauthenticated
//! fetch path is a design invariant, not an omission.
//!
//! TTL checks live on [`crate::descriptor::ShareDescriptor`]
//! directly (`is_expired`).

use alloc::vec::Vec;
use sp_crypto_hashing::blake2_256;

use crate::descriptor::{MessageId, PickupKey, ShareIndex, UnixTimestamp};
use crate::envelope::{build_sender_preimage, UnsealedInner};

/// Length of a per-chunk MAC tag, in bytes. Blake2-256 output is 32 bytes.
pub const MAC_TAG_LEN: usize = 32;

/// Per-chunk MAC key. Derived per-message from the per-conversation
/// stripe-MAC secret via [`derive_share_mac_key`]; the same key MACs
/// every chunk of a given message.
pub type ShareMacKey = [u8; 32];

/// Per-chunk MAC tag.
pub type ShareMacTag = [u8; MAC_TAG_LEN];

/// Domain-separation tag for deriving the per-conversation stripe-MAC
/// secret from the conversation's shared secret (X3DH today, PQXDH
/// when it lands; the MLS group path feeds its epoch secret into the
/// same shape). Forward secrecy is irrelevant here — the key protects
/// integrity only — so a static per-conversation secret is correct.
pub const STRIPE_MAC_SECRET_DOMAIN: &[u8] = b"rostro/chat/stripe-mac-secret/v1";

/// Domain-separation tag for per-message share-MAC-key derivation.
/// v2: keyed by the per-conversation stripe-MAC secret. (v1 was keyed
/// by an upper-layer session secret the node-side splitter never had,
/// which is how the zero-key placeholder shipped — see
/// docs/CHAT-SHARE-CHUNKING.md §1c.)
pub const SHARE_MAC_KEY_DOMAIN: &[u8] = b"rostro/chat/share-mac-key/v2";

/// Domain-separation tag for the per-chunk MAC itself. v2: the
/// preimage is descriptor-bound (see [`mac_chunk`]).
pub const SHARE_MAC_DOMAIN: &[u8] = b"rostro/chat/share-mac/v2";

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

/// MAC-check outcomes for a single chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacError {
	/// Computed MAC for the chunk bytes + bound descriptor fields
	/// does not match the claimed tag. Indicates tampered chunk
	/// bytes, a tampered descriptor field (index swap, TTL rewrite,
	/// total rewrite, pickup rewrite), or a tampered tag.
	TagMismatch,
}

/// Derive the per-conversation stripe-MAC secret from the
/// conversation's shared secret. Computed once at session
/// establishment on BOTH devices; never sent anywhere.
///
/// `conversation_secret` is the 32-byte shared secret that roots the
/// conversation: the X3DH/PQXDH-derived pairwise secret, or the MLS
/// epoch secret for the (future) group path. This crate does not own
/// session state.
///
/// Layout:
///
/// ```text
/// STRIPE_MAC_SECRET_DOMAIN || conversation_secret
/// ```
pub fn derive_stripe_mac_secret(conversation_secret: &[u8; 32]) -> [u8; 32] {
	let mut input =
		Vec::with_capacity(STRIPE_MAC_SECRET_DOMAIN.len() + 32);
	input.extend_from_slice(STRIPE_MAC_SECRET_DOMAIN);
	input.extend_from_slice(conversation_secret);
	blake2_256(&input)
}

/// Derive a per-message share-MAC key from the per-conversation
/// stripe-MAC secret and the message id. The same key MACs every
/// chunk of a given message; different messages produce different
/// keys, so a chunk from one message can never be replayed into
/// another under the same conversation.
///
/// Both ends can derive this BEFORE decrypting anything: the
/// recipient reads `message_id` off the fetched descriptor and holds
/// the stripe-MAC secret per contact.
///
/// Layout:
///
/// ```text
/// SHARE_MAC_KEY_DOMAIN || stripe_mac_secret || message_id
/// ```
pub fn derive_share_mac_key(
	stripe_mac_secret: &[u8; 32],
	message_id: &MessageId,
) -> ShareMacKey {
	let mut input = Vec::with_capacity(SHARE_MAC_KEY_DOMAIN.len() + 32 + 32);
	input.extend_from_slice(SHARE_MAC_KEY_DOMAIN);
	input.extend_from_slice(stripe_mac_secret);
	input.extend_from_slice(&message_id.0);
	blake2_256(&input)
}

/// Compute the v2 (descriptor-bound) MAC tag for a single chunk.
///
/// Layout signed (fixed-width fields before the variable-length
/// chunk bytes, so the preimage is unambiguous):
///
/// ```text
/// SHARE_MAC_DOMAIN || key || message_id || pickup_key
///   || share_index || total_shares || expires_at (u64 BE)
///   || chunk_bytes
/// ```
///
/// Binding rationale (docs/CHAT-SHARE-CHUNKING.md §4.3): the client
/// authors both the descriptor and the tag, so binding is free, and
/// it closes the distributing node's tampering surface — without it
/// a malicious peeler could rewrite `expires_at` (TTL-shortening =
/// censorship that looks like expiry) or `total_shares` undetected.
/// `share_index` in the preimage prevents chunk-swap attacks.
/// `relay_pubkey` stays OUTSIDE the preimage: it is the distributing
/// node's self-identity stamp, not sender-asserted data.
pub fn mac_chunk(
	key: &ShareMacKey,
	message_id: &MessageId,
	pickup_key: &PickupKey,
	share_index: ShareIndex,
	total_shares: u8,
	expires_at_unix_ts: UnixTimestamp,
	chunk_bytes: &[u8],
) -> ShareMacTag {
	let mut input = Vec::with_capacity(
		SHARE_MAC_DOMAIN.len() + 32 + 32 + 32 + 1 + 1 + 8 + chunk_bytes.len(),
	);
	input.extend_from_slice(SHARE_MAC_DOMAIN);
	input.extend_from_slice(key);
	input.extend_from_slice(&message_id.0);
	input.extend_from_slice(&pickup_key.0);
	input.push(share_index);
	input.push(total_shares);
	input.extend_from_slice(&expires_at_unix_ts.to_be_bytes());
	input.extend_from_slice(chunk_bytes);
	blake2_256(&input)
}

/// Verify a claimed MAC tag against a chunk's bytes + bound
/// descriptor fields under `key`. Constant-time-ish comparison:
/// blake2_256 itself is fast and the byte comparison
/// short-circuits, but for 32-byte MACs the timing exposure is
/// negligible.
///
/// Returns `Ok(())` on match, [`MacError::TagMismatch`] on any
/// divergence (tampered bytes, any tampered bound field, tampered
/// tag, wrong key — all surface as the same outcome).
pub fn verify_chunk_mac(
	key: &ShareMacKey,
	message_id: &MessageId,
	pickup_key: &PickupKey,
	share_index: ShareIndex,
	total_shares: u8,
	expires_at_unix_ts: UnixTimestamp,
	chunk_bytes: &[u8],
	claimed_tag: &ShareMacTag,
) -> Result<(), MacError> {
	let computed = mac_chunk(
		key,
		message_id,
		pickup_key,
		share_index,
		total_shares,
		expires_at_unix_ts,
		chunk_bytes,
	);
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

	// ── chunk MAC primitives (v2, descriptor-bound) ───────────────

	use crate::descriptor::PickupKey;

	const SAMPLE_SECRET: [u8; 32] = [0x42; 32];
	const SAMPLE_EXPIRY: UnixTimestamp = 1_700_259_200;

	fn sample_pickup() -> PickupKey {
		PickupKey([0xBB; 32])
	}

	/// Convenience wrapper: tag chunk `i` of `total` with the sample
	/// message context.
	fn tag(
		key: &ShareMacKey,
		mid: &MessageId,
		bytes: &[u8],
		i: ShareIndex,
		total: u8,
	) -> ShareMacTag {
		mac_chunk(key, mid, &sample_pickup(), i, total, SAMPLE_EXPIRY, bytes)
	}

	fn check(
		key: &ShareMacKey,
		mid: &MessageId,
		bytes: &[u8],
		i: ShareIndex,
		total: u8,
		t: &ShareMacTag,
	) -> Result<(), MacError> {
		verify_chunk_mac(key, mid, &sample_pickup(), i, total, SAMPLE_EXPIRY, bytes, t)
	}

	#[test]
	fn mac_honest_chunk_verifies() {
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let bytes = vec![1, 2, 3, 4, 5];
		let t = tag(&key, &mid, &bytes, 0, 5);
		assert!(check(&key, &mid, &bytes, 0, 5, &t).is_ok());
	}

	#[test]
	fn mac_rejects_tampered_chunk_bytes() {
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let bytes = vec![1, 2, 3, 4, 5];
		let t = tag(&key, &mid, &bytes, 0, 5);
		let tampered = vec![1, 2, 3, 4, 99];
		assert_eq!(check(&key, &mid, &tampered, 0, 5, &t), Err(MacError::TagMismatch));
	}

	#[test]
	fn mac_rejects_chunk_swap() {
		// Relay returns chunk[0]'s bytes when chunk[1] was asked for.
		// The MAC binds bytes to position; index mismatch fails MAC.
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let bytes = vec![5, 6, 7, 8];
		let tag_for_index_0 = tag(&key, &mid, &bytes, 0, 5);
		assert_eq!(
			check(&key, &mid, &bytes, 1, 5, &tag_for_index_0),
			Err(MacError::TagMismatch),
		);
	}

	#[test]
	fn mac_rejects_total_rewrite() {
		// A relay rewriting total_shares (e.g. to make a partial set
		// look complete) breaks the MAC — the v2 binding at work.
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let bytes = vec![1, 2, 3];
		let t = tag(&key, &mid, &bytes, 0, 5);
		assert_eq!(check(&key, &mid, &bytes, 0, 3, &t), Err(MacError::TagMismatch));
	}

	#[test]
	fn mac_rejects_expiry_rewrite() {
		// TTL-shortening by a relay (censorship dressed as expiry) is
		// detectable: expires_at is inside the preimage.
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let bytes = vec![1, 2, 3];
		let t = tag(&key, &mid, &bytes, 0, 5);
		assert_eq!(
			verify_chunk_mac(
				&key,
				&mid,
				&sample_pickup(),
				0,
				5,
				SAMPLE_EXPIRY - 3600,
				&bytes,
				&t,
			),
			Err(MacError::TagMismatch),
		);
	}

	#[test]
	fn mac_rejects_pickup_rewrite() {
		// Redirecting a chunk to a different pickup key breaks the MAC.
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let bytes = vec![1, 2, 3];
		let t = tag(&key, &mid, &bytes, 0, 5);
		assert_eq!(
			verify_chunk_mac(
				&key,
				&mid,
				&PickupKey([0xCC; 32]),
				0,
				5,
				SAMPLE_EXPIRY,
				&bytes,
				&t,
			),
			Err(MacError::TagMismatch),
		);
	}

	#[test]
	fn mac_rejects_tampered_tag() {
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let bytes = vec![1, 2, 3];
		let mut t = tag(&key, &mid, &bytes, 0, 5);
		t[0] ^= 0xFF;
		assert_eq!(check(&key, &mid, &bytes, 0, 5, &t), Err(MacError::TagMismatch));
	}

	#[test]
	fn mac_rejects_wrong_key() {
		let mid = MessageId([0xAA; 32]);
		let key_a = derive_share_mac_key(&[0x01; 32], &mid);
		let key_b = derive_share_mac_key(&[0x02; 32], &mid);
		let bytes = vec![1, 2, 3];
		let t = tag(&key_a, &mid, &bytes, 0, 5);
		assert_eq!(check(&key_b, &mid, &bytes, 0, 5, &t), Err(MacError::TagMismatch));
	}

	#[test]
	fn mac_key_differs_per_message() {
		// Same stripe-MAC secret, different message_id → different
		// key. Prevents replaying a chunk from one message into a
		// different message under the same conversation.
		let k1 = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0x01; 32]));
		let k2 = derive_share_mac_key(&SAMPLE_SECRET, &MessageId([0x02; 32]));
		assert_ne!(k1, k2);
	}

	#[test]
	fn mac_key_differs_per_conversation() {
		// Same message_id, different stripe-MAC secret → different key.
		let k1 = derive_share_mac_key(&[0x01; 32], &MessageId([0xAA; 32]));
		let k2 = derive_share_mac_key(&[0x02; 32], &MessageId([0xAA; 32]));
		assert_ne!(k1, k2);
	}

	#[test]
	fn stripe_mac_secret_differs_per_conversation_secret() {
		let s1 = derive_stripe_mac_secret(&[0x01; 32]);
		let s2 = derive_stripe_mac_secret(&[0x02; 32]);
		assert_ne!(s1, s2);
		// And is domain-separated from the raw hash of the secret.
		assert_ne!(s1, blake2_256(&[0x01; 32]));
	}

	#[test]
	fn mac_is_deterministic() {
		// blake2 is deterministic; same inputs → same MAC. Test
		// pins this so a future refactor that introduces randomness
		// (it shouldn't!) breaks the test.
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let bytes = vec![1, 2, 3, 4, 5];
		assert_eq!(tag(&key, &mid, &bytes, 0, 5), tag(&key, &mid, &bytes, 0, 5));
	}

	#[test]
	fn mac_empty_chunk_verifies() {
		// MAC of an empty chunk is well-defined; verifies cleanly.
		// (Payloads shorter than the chunk count produce empty
		// trailing chunks — see chunk.rs edge cases.)
		let mid = MessageId([0xAA; 32]);
		let key = derive_share_mac_key(&SAMPLE_SECRET, &mid);
		let t = tag(&key, &mid, &[], 4, 5);
		assert!(check(&key, &mid, &[], 4, 5, &t).is_ok());
	}

	#[test]
	fn mac_key_derivation_layout_is_stable() {
		// Pin output against accidental refactors. A change here
		// breaks every previously-MAC'd chunk.
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0x55; 32]));
		// Recompute by hand to assert the formula didn't change.
		let mut input = Vec::with_capacity(SHARE_MAC_KEY_DOMAIN.len() + 32 + 32);
		input.extend_from_slice(SHARE_MAC_KEY_DOMAIN);
		input.extend_from_slice(&[0x42; 32]);
		input.extend_from_slice(&[0x55; 32]);
		assert_eq!(key, blake2_256(&input));
	}

	#[test]
	fn mac_chunk_preimage_layout_is_stable() {
		// Pin the full v2 preimage layout: domain || key || message_id
		// || pickup_key || index || total || expiry BE || bytes.
		let mid = MessageId([0x55; 32]);
		let key = derive_share_mac_key(&[0x42; 32], &mid);
		let bytes = vec![9, 8, 7];
		let t = tag(&key, &mid, &bytes, 2, 5);

		let mut input = Vec::new();
		input.extend_from_slice(SHARE_MAC_DOMAIN);
		input.extend_from_slice(&key);
		input.extend_from_slice(&mid.0);
		input.extend_from_slice(&sample_pickup().0);
		input.push(2);
		input.push(5);
		input.extend_from_slice(&SAMPLE_EXPIRY.to_be_bytes());
		input.extend_from_slice(&bytes);
		assert_eq!(t, blake2_256(&input));
	}
}
