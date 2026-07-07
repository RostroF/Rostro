// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! End-to-end integration test for the rostro-chat-primitives crate.
//!
//! Exercises the full sender-device → wire → recipient-device flow
//! that this crate's primitives compose into. No real encryption
//! (this crate defines wire types, not crypto layers); the test uses
//! raw bytes in place of Sealed Sender outer-AEAD and MLS/DR
//! inner-AEAD to demonstrate that the primitives glue together
//! correctly.
//!
//! Real production usage layers in:
//!   - MLS or Double Ratchet for `inner_ciphertext` AEAD
//!   - Sealed Sender outer ECDH+AEAD for `outer_ciphertext`
//!   - the onion path + libp2p transport for batch delivery
//!
//! The flow under test is the chunk cutover shape
//! (docs/CHAT-SHARE-CHUNKING.md): the SENDER DEVICE splits + MACs
//! (`prepare_batch`), a distributing node validates shape only
//! (`validate_prepared_batch` — it holds no MAC key), and the
//! RECIPIENT DEVICE verifies + reassembles
//! (`combine_chunks_verified`).

use codec::{Decode, Encode};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rostro_chat_primitives::{
	chunk::{
		combine_chunks_verified, prepare_batch, validate_prepared_batch,
		ChunkCombineError, PreparedBatch, TaggedChunk,
	},
	descriptor::{
		GroupId, MessageId, PickupKey, RelayPubkey, ShareDescriptor, CHAT_TTL_SECONDS,
	},
	envelope::{sign_inner, SealedEnvelope, UnsealedInner, PAIRWISE_PQ_CT_BYTES},
	verify::verify_sender,
};

const CHUNK_COUNT: usize = 5;
const NOW_TS: u64 = 1_700_000_000;

/// Recipient-side view of a batch: the `TaggedChunk` refs a client
/// builds from fetched shares (descriptor fields AS FETCHED).
fn tagged_refs(batch: &PreparedBatch) -> Vec<TaggedChunk<'_>> {
	batch
		.shares
		.iter()
		.map(|s| TaggedChunk {
			share_index: s.share_index,
			total_shares: s.total_shares,
			expires_at_unix_ts: s.expires_at_unix_ts,
			bytes: &s.chunk_bytes,
			checksum: &s.checksum,
		})
		.collect()
}

/// Full sender → wire → recipient roundtrip for a pairwise DM.
///
/// In real use, `outer_ciphertext` would be Sealed Sender's AEAD output
/// over the encoded `UnsealedInner`. Here we just inline the encoded
/// `UnsealedInner` as the outer ciphertext — sender encrypts is a no-op,
/// recipient decrypts is `UnsealedInner::decode`. The structure of the
/// flow is identical.
#[test]
fn pairwise_dm_full_stack_roundtrip() {
	// ── Sender device ─────────────────────────────────────────────

	let mut rng = ChaCha20Rng::from_seed([0xABu8; 32]);

	// Sender's identity (Ed25519).
	let signing_key = ed25519_zebra::SigningKey::from([0x11u8; 32]);

	// Recipient's identity (just need the pubkey for pickup-key derivation).
	let recipient_pubkey: [u8; 32] = ed25519_zebra::VerificationKey::from(
		&ed25519_zebra::SigningKey::from([0x22u8; 32]),
	)
	.into();

	// The original plaintext message the sender wants to deliver.
	let plaintext: &[u8] = b"hello from rostro chat layer";

	// Step 1: in production, MLS/DR would AEAD-encrypt the plaintext
	// into inner_ciphertext. Here we just pass the plaintext as the
	// "encrypted" inner ciphertext for test purposes.
	let inner_ciphertext = plaintext.to_vec();

	// Step 2: sender generates a fresh per-message id.
	let message_id = MessageId::generate(&mut rng);

	// Step 3: sender signs (message_id, inner_ciphertext) → UnsealedInner.
	let unsealed = sign_inner(inner_ciphertext.clone(), &message_id, &signing_key);

	// Step 4: encode UnsealedInner. In production, Sealed Sender's
	// outer AEAD encrypts this; here we'll use the encoded bytes
	// directly as outer_ciphertext.
	let unsealed_encoded = unsealed.encode();

	// Step 5: build the outer SealedEnvelope.
	let envelope = SealedEnvelope::Pairwise {
		ephemeral_pubkey: [0xEE; 32], // would be a real X25519 epk in production
		pq_ct: [0x5A; PAIRWISE_PQ_CT_BYTES], // would be a real ML-KEM ct in production
		outer_ciphertext: unsealed_encoded,
		message_id,
	};
	let envelope_encoded = envelope.encode();

	// Step 6: chunk + checksum on the sender's device — the whole
	// prepare-side pipeline in one call.
	let pickup_key = PickupKey::for_pairwise(&recipient_pubkey);
	let expires_at = NOW_TS + CHAT_TTL_SECONDS;
	let batch = prepare_batch(
		&envelope_encoded,
		CHUNK_COUNT,
		message_id,
		pickup_key,
		expires_at,
	)
	.unwrap();
	assert_eq!(batch.shares.len(), CHUNK_COUNT);

	// The batch is the wire artifact (onion drop / RPC payload): the
	// chunks SUM to the envelope size — no N× expansion.
	let chunk_total: usize = batch.shares.iter().map(|s| s.chunk_bytes.len()).sum();
	assert_eq!(chunk_total, envelope_encoded.len());
	let wire = batch.encode();
	let batch_at_node = PreparedBatch::decode(&mut &wire[..]).unwrap();
	assert_eq!(batch_at_node, batch);

	// ── Distributing node (pure routing, no key) ──────────────────

	// Shape validation at the handoff, then descriptor assembly: the
	// node stamps its own relay_pubkey around the client's fields.
	let total = validate_prepared_batch(&batch_at_node, NOW_TS).unwrap();
	assert_eq!(total as usize, CHUNK_COUNT);
	let descriptors: Vec<ShareDescriptor> = batch_at_node
		.shares
		.iter()
		.map(|s| ShareDescriptor {
			relay_pubkey: RelayPubkey([0x44; 32]), // the distributing node's key
			message_id: batch_at_node.message_id,
			share_index: s.share_index,
			total_shares: s.total_shares,
			pickup_key: batch_at_node.pickup_key,
			expires_at_unix_ts: s.expires_at_unix_ts,
		})
		.collect();

	// Descriptors SCALE-roundtrip (they travel to storing relays).
	for d in &descriptors {
		let bytes = d.encode();
		assert_eq!(ShareDescriptor::decode(&mut &bytes[..]).unwrap(), *d);
	}

	// ── Recipient device ──────────────────────────────────────────

	// Verify checksums + concatenate (keyless — the recipient needs
	// nothing but the fetched descriptors + its own eventual AEAD key).
	let recovered_envelope_bytes = combine_chunks_verified(
		&message_id,
		&pickup_key,
		&tagged_refs(&batch_at_node),
	)
	.expect("verified reassembly of honest chunks must succeed");
	assert_eq!(recovered_envelope_bytes, envelope_encoded);

	// Recipient decodes the SealedEnvelope.
	let recovered_envelope =
		SealedEnvelope::decode(&mut &recovered_envelope_bytes[..]).unwrap();
	assert_eq!(recovered_envelope, envelope);

	// Recipient confirms the envelope variant is pairwise (would
	// route to hybrid-unseal + DR-decrypt rather than MLS-decrypt).
	assert!(matches!(recovered_envelope, SealedEnvelope::Pairwise { .. }));

	// Recipient decrypts outer_ciphertext. In production this is the
	// hybrid sealed-sender unseal; here it's just SCALE decode.
	let recovered_unsealed =
		UnsealedInner::decode(&mut recovered_envelope.outer_ciphertext()).unwrap();

	// Recipient verifies the sender signature against the outer's
	// message_id (NOT a freshly-derived one).
	let verified_pubkey = verify_sender(&recovered_unsealed, recovered_envelope.message_id())
		.expect("honest sender signature must verify");

	// Verified pubkey matches the sender's actual pubkey.
	let expected_sender_pubkey: [u8; 32] =
		ed25519_zebra::VerificationKey::from(&signing_key).into();
	assert_eq!(verified_pubkey, expected_sender_pubkey);

	// Recipient decrypts inner_ciphertext. In production this is
	// DR/MLS AEAD decrypt; here it's the no-op identity.
	let recovered_plaintext = recovered_unsealed.inner_ciphertext;
	assert_eq!(recovered_plaintext, plaintext);
}

/// Same flow for a group message — verifies that the EnvelopeKind::Group
/// path round-trips and PickupKey derivation differs from pairwise.
#[test]
fn group_message_full_stack_roundtrip() {
	let mut rng = ChaCha20Rng::from_seed([0xCDu8; 32]);
	let signing_key = ed25519_zebra::SigningKey::from([0x77u8; 32]);
	let group_id = GroupId::generate(&mut rng);
	let plaintext: &[u8] = b"group message: shipping at block 9000";

	let message_id = MessageId::generate(&mut rng);
	let unsealed = sign_inner(plaintext.to_vec(), &message_id, &signing_key);
	let envelope = SealedEnvelope::Group {
		group_id,
		outer_ciphertext: unsealed.encode(),
		message_id,
	};
	let envelope_encoded = envelope.encode();

	// Pickup key for the group differs from any pairwise pickup key.
	let group_pickup = PickupKey::for_group(&group_id);
	let pairwise_pickup_with_same_bytes = PickupKey::for_pairwise(&group_id.0);
	assert_ne!(
		group_pickup, pairwise_pickup_with_same_bytes,
		"domain separation must keep pairwise and group pickup keys distinct",
	);

	let batch = prepare_batch(
		&envelope_encoded,
		CHUNK_COUNT,
		message_id,
		group_pickup,
		NOW_TS + CHAT_TTL_SECONDS,
	)
	.unwrap();

	// Recipient roundtrip.
	let recovered = combine_chunks_verified(
		&message_id,
		&group_pickup,
		&tagged_refs(&batch),
	)
	.unwrap();
	let recovered_envelope = SealedEnvelope::decode(&mut &recovered[..]).unwrap();
	assert!(matches!(recovered_envelope, SealedEnvelope::Group { group_id: g, .. } if g == group_id));
	let recovered_unsealed =
		UnsealedInner::decode(&mut recovered_envelope.outer_ciphertext()).unwrap();
	verify_sender(&recovered_unsealed, recovered_envelope.message_id()).unwrap();
	assert_eq!(recovered_unsealed.inner_ciphertext, plaintext);
}

/// Corrupt chunk is identified by position so the recipient can
/// re-fetch from another replica (via a NORMAL-shaped pickup query —
/// see docs/CHAT-SHARE-CHUNKING.md §4.6) and keep the attribution
/// on-device.
#[test]
fn tampered_chunk_is_localized() {
	let mut rng = ChaCha20Rng::from_seed([0xEFu8; 32]);
	let signing_key = ed25519_zebra::SigningKey::from([0x44u8; 32]);
	let plaintext = b"corruption detection at the relay layer";

	let message_id = MessageId::generate(&mut rng);
	let unsealed = sign_inner(plaintext.to_vec(), &message_id, &signing_key);
	let envelope = SealedEnvelope::Pairwise {
		ephemeral_pubkey: [0; 32],
		pq_ct: [0; PAIRWISE_PQ_CT_BYTES],
		outer_ciphertext: unsealed.encode(),
		message_id,
	};
	let pickup = PickupKey::for_pairwise(&[0x10; 32]);
	let mut batch = prepare_batch(
		&envelope.encode(),
		CHUNK_COUNT,
		message_id,
		pickup,
		NOW_TS + CHAT_TTL_SECONDS,
	)
	.unwrap();

	// Simulate bit rot / corruption of chunk 2's bytes.
	batch.shares[2].chunk_bytes[0] ^= 0xFF;

	match combine_chunks_verified(&message_id, &pickup, &tagged_refs(&batch)) {
		Err(ChunkCombineError::CorruptChunk { slice_index, share_index }) => {
			assert_eq!(slice_index, 2);
			assert_eq!(share_index, 2);
		},
		other => panic!("expected CorruptChunk at index 2, got {other:?}"),
	}
}
