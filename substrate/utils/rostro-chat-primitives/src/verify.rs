// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Per-response verification primitives.
//!
//! Crate-level verification logic. Three responsibilities:
//!
//! - [`verify_sender`]: validates the sender's Ed25519 signature
//!   over a recovered [`crate::envelope::UnsealedInner`] against
//!   the message id observed in the outer envelope.
//! - [`checksum_chunk`] + [`verify_chunk_checksum`]: per-chunk
//!   descriptor-bound **integrity checksum** (a keyless blake2 hash).
//!   Each chunk of a split message carries a checksum computed on the
//!   sender's device over the chunk bytes AND the sender-authored
//!   descriptor fields (message_id, pickup_key, share_index,
//!   total_shares, expires_at). It exists to catch and LOCALIZE
//!   accidental corruption — bit rot in a relay's RAM, a truncated
//!   transfer, a mislabelled index — and tells the recipient *which*
//!   chunk was mangled.
//!
//!   **This is a checksum, not a MAC.** It is keyless, so anyone
//!   (including any relay) can recompute a valid checksum over
//!   substituted bytes. It therefore provides NO protection against
//!   an adversarial relay and is not a security boundary. Content
//!   authenticity is owned entirely by the envelope's sealed-sender
//!   AEAD + the sender's Ed25519 signature ([`verify_sender`]): a
//!   tampered chunk can only ever cause a decrypt/verify failure
//!   (denial), never accepted-forged content. See
//!   docs/CHAT-SHARE-CHUNKING.md §4.3 for why a real (relay-
//!   unforgeable) keyed MAC was deferred to the rotation-minted
//!   keying path, and why availability lives in the bucket-
//!   subscription replication scheme, not in client-side recovery.
//! - [`ChecksumError`] / [`VerifyError`]: distinguishable error
//!   variants so callers can localize a corrupt chunk.
//!
//! TTL checks live on [`crate::descriptor::ShareDescriptor`]
//! directly (`is_expired`).

use alloc::vec::Vec;
use sp_crypto_hashing::blake2_256;

use crate::descriptor::{MessageId, PickupKey, ShareIndex, UnixTimestamp};
use crate::envelope::{build_sender_preimage, UnsealedInner};

/// Length of a per-chunk checksum, in bytes. Blake2-256 output is 32 bytes.
pub const CHUNK_CHECKSUM_LEN: usize = 32;

/// Per-chunk integrity checksum (a keyless blake2 hash — NOT a MAC;
/// see the module docs). Corruption detection + localization only.
pub type ChunkChecksum = [u8; CHUNK_CHECKSUM_LEN];

/// Domain-separation tag for the per-chunk checksum. Descriptor-bound
/// (see [`checksum_chunk`]).
pub const CHUNK_CHECKSUM_DOMAIN: &[u8] = b"rostro/chat/chunk-checksum/v1";

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

/// Checksum-check outcome for a single chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumError {
	/// Computed checksum for the chunk bytes + bound descriptor
	/// fields does not match the claimed checksum. Indicates
	/// corrupted chunk bytes or a corrupted descriptor field (wrong
	/// index, rewritten TTL/total, wrong pickup) — accidental or
	/// adversarial. Either way the chunk is unusable; the recipient
	/// falls back to a fresh poll (availability is the bucket-
	/// subscription scheme's job, not this function's).
	Mismatch,
}

/// Compute the descriptor-bound integrity checksum for a single
/// chunk. Keyless (see module docs) — this is corruption detection,
/// not authentication.
///
/// Layout hashed (fixed-width fields before the variable-length
/// chunk bytes, so the preimage is unambiguous):
///
/// ```text
/// CHUNK_CHECKSUM_DOMAIN || message_id || pickup_key
///   || share_index || total_shares || expires_at (u64 BE)
///   || chunk_bytes
/// ```
///
/// Binding the descriptor fields (not just bytes+index) means a
/// checksum mismatch also catches accidental corruption of the
/// index, total, expiry, or pickup — the sender authors both the
/// descriptor and the checksum for free. `relay_pubkey` stays
/// OUTSIDE the preimage: it is the distributing node's self-identity
/// stamp, filled in per-relay, not sender-authored.
pub fn checksum_chunk(
	message_id: &MessageId,
	pickup_key: &PickupKey,
	share_index: ShareIndex,
	total_shares: u8,
	expires_at_unix_ts: UnixTimestamp,
	chunk_bytes: &[u8],
) -> ChunkChecksum {
	let mut input = Vec::with_capacity(
		CHUNK_CHECKSUM_DOMAIN.len() + 32 + 32 + 1 + 1 + 8 + chunk_bytes.len(),
	);
	input.extend_from_slice(CHUNK_CHECKSUM_DOMAIN);
	input.extend_from_slice(&message_id.0);
	input.extend_from_slice(&pickup_key.0);
	input.push(share_index);
	input.push(total_shares);
	input.extend_from_slice(&expires_at_unix_ts.to_be_bytes());
	input.extend_from_slice(chunk_bytes);
	blake2_256(&input)
}

/// Verify a claimed checksum against a chunk's bytes + bound
/// descriptor fields.
///
/// Returns `Ok(())` on match, [`ChecksumError::Mismatch`] on any
/// divergence. A pass means "not corrupted in transit/storage," NOT
/// "authentic" — authenticity is the AEAD's job ([`verify_sender`]
/// and the sealed-sender unseal downstream).
pub fn verify_chunk_checksum(
	message_id: &MessageId,
	pickup_key: &PickupKey,
	share_index: ShareIndex,
	total_shares: u8,
	expires_at_unix_ts: UnixTimestamp,
	chunk_bytes: &[u8],
	claimed: &ChunkChecksum,
) -> Result<(), ChecksumError> {
	let computed = checksum_chunk(
		message_id,
		pickup_key,
		share_index,
		total_shares,
		expires_at_unix_ts,
		chunk_bytes,
	);
	if &computed == claimed {
		Ok(())
	} else {
		Err(ChecksumError::Mismatch)
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

	// ── chunk checksum primitives (keyless, descriptor-bound) ─────

	use crate::descriptor::PickupKey;

	const SAMPLE_EXPIRY: UnixTimestamp = 1_700_259_200;

	fn sample_pickup() -> PickupKey {
		PickupKey([0xBB; 32])
	}

	/// Convenience wrapper: checksum chunk `i` of `total` with the
	/// sample message context.
	fn ck(mid: &MessageId, bytes: &[u8], i: ShareIndex, total: u8) -> ChunkChecksum {
		checksum_chunk(mid, &sample_pickup(), i, total, SAMPLE_EXPIRY, bytes)
	}

	fn check(
		mid: &MessageId,
		bytes: &[u8],
		i: ShareIndex,
		total: u8,
		c: &ChunkChecksum,
	) -> Result<(), ChecksumError> {
		verify_chunk_checksum(mid, &sample_pickup(), i, total, SAMPLE_EXPIRY, bytes, c)
	}

	#[test]
	fn checksum_honest_chunk_verifies() {
		let mid = MessageId([0xAA; 32]);
		let bytes = vec![1, 2, 3, 4, 5];
		let c = ck(&mid, &bytes, 0, 5);
		assert!(check(&mid, &bytes, 0, 5, &c).is_ok());
	}

	#[test]
	fn checksum_catches_corrupted_bytes() {
		let mid = MessageId([0xAA; 32]);
		let bytes = vec![1, 2, 3, 4, 5];
		let c = ck(&mid, &bytes, 0, 5);
		let corrupted = vec![1, 2, 3, 4, 99];
		assert_eq!(check(&mid, &corrupted, 0, 5, &c), Err(ChecksumError::Mismatch));
	}

	#[test]
	fn checksum_catches_index_corruption() {
		// A chunk delivered under the wrong index fails — the index is
		// in the preimage.
		let mid = MessageId([0xAA; 32]);
		let bytes = vec![5, 6, 7, 8];
		let c0 = ck(&mid, &bytes, 0, 5);
		assert_eq!(check(&mid, &bytes, 1, 5, &c0), Err(ChecksumError::Mismatch));
	}

	#[test]
	fn checksum_catches_total_corruption() {
		let mid = MessageId([0xAA; 32]);
		let bytes = vec![1, 2, 3];
		let c = ck(&mid, &bytes, 0, 5);
		assert_eq!(check(&mid, &bytes, 0, 3, &c), Err(ChecksumError::Mismatch));
	}

	#[test]
	fn checksum_catches_expiry_corruption() {
		let mid = MessageId([0xAA; 32]);
		let bytes = vec![1, 2, 3];
		let c = ck(&mid, &bytes, 0, 5);
		assert_eq!(
			verify_chunk_checksum(
				&mid,
				&sample_pickup(),
				0,
				5,
				SAMPLE_EXPIRY - 3600,
				&bytes,
				&c,
			),
			Err(ChecksumError::Mismatch),
		);
	}

	#[test]
	fn checksum_catches_pickup_corruption() {
		let mid = MessageId([0xAA; 32]);
		let bytes = vec![1, 2, 3];
		let c = ck(&mid, &bytes, 0, 5);
		assert_eq!(
			verify_chunk_checksum(
				&mid,
				&PickupKey([0xCC; 32]),
				0,
				5,
				SAMPLE_EXPIRY,
				&bytes,
				&c,
			),
			Err(ChecksumError::Mismatch),
		);
	}

	#[test]
	fn checksum_catches_corrupted_checksum_field() {
		let mid = MessageId([0xAA; 32]);
		let bytes = vec![1, 2, 3];
		let mut c = ck(&mid, &bytes, 0, 5);
		c[0] ^= 0xFF;
		assert_eq!(check(&mid, &bytes, 0, 5, &c), Err(ChecksumError::Mismatch));
	}

	#[test]
	fn checksum_differs_per_message() {
		// Different message_id → different checksum for identical bytes,
		// so a chunk can't be silently reused across messages.
		let bytes = vec![1, 2, 3];
		let c1 = ck(&MessageId([0x01; 32]), &bytes, 0, 5);
		let c2 = ck(&MessageId([0x02; 32]), &bytes, 0, 5);
		assert_ne!(c1, c2);
	}

	#[test]
	fn checksum_is_deterministic() {
		let mid = MessageId([0xAA; 32]);
		let bytes = vec![1, 2, 3, 4, 5];
		assert_eq!(ck(&mid, &bytes, 0, 5), ck(&mid, &bytes, 0, 5));
	}

	#[test]
	fn checksum_empty_chunk_verifies() {
		// Empty trailing chunks (payload shorter than N) checksum cleanly.
		let mid = MessageId([0xAA; 32]);
		let c = ck(&mid, &[], 4, 5);
		assert!(check(&mid, &[], 4, 5, &c).is_ok());
	}

	#[test]
	fn checksum_preimage_layout_is_stable() {
		// Pin the keyless preimage: domain || message_id || pickup_key
		// || index || total || expiry BE || bytes.
		let mid = MessageId([0x55; 32]);
		let bytes = vec![9, 8, 7];
		let c = ck(&mid, &bytes, 2, 5);

		let mut input = Vec::new();
		input.extend_from_slice(CHUNK_CHECKSUM_DOMAIN);
		input.extend_from_slice(&mid.0);
		input.extend_from_slice(&sample_pickup().0);
		input.push(2);
		input.push(5);
		input.extend_from_slice(&SAMPLE_EXPIRY.to_be_bytes());
		input.extend_from_slice(&bytes);
		assert_eq!(c, blake2_256(&input));
	}
}
