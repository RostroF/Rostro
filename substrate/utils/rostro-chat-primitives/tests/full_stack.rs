// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! End-to-end integration test for the rostro-chat-primitives crate.
//!
//! Exercises the full sender → wire → recipient flow that this
//! crate's primitives compose into. No real encryption (this crate
//! defines wire types, not crypto layers); the test uses raw bytes
//! in place of Sealed Sender outer-AEAD and MLS/DR inner-AEAD to
//! demonstrate that the primitives glue together correctly.
//!
//! Real production usage layers in:
//!   - MLS or Double Ratchet for `inner_ciphertext` AEAD
//!   - Sealed Sender outer ECDH+AEAD for `outer_ciphertext`
//!   - libp2p transport for share delivery + DHT publication
//!
//! Those layers are out of this crate's scope; the integration test
//! demonstrates that the wire types and verification primitives
//! correctly carry data between sender and recipient given those
//! upper-layer crypto operations.

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rostro_chat_primitives::{
	descriptor::{MessageId, ShareDescriptor, ShareIndex, CHAT_TTL_SECONDS},
	descriptor::{GroupId, PickupKey, RelayPubkey},
	envelope::{sign_inner, EnvelopeKind, SealedEnvelope, UnsealedInner},
	stripe::{combine_xor_authenticated, split_xor},
	verify::{derive_share_mac_key, mac_share, verify_sender, ShareMacTag},
};
use codec::{Decode, Encode};

const SHARE_COUNT: usize = 5;

/// Full sender → wire → recipient roundtrip for a pairwise DM.
///
/// In real use, `outer_ciphertext` would be Sealed Sender's AEAD output
/// over the encoded `UnsealedInner`. Here we just inline the encoded
/// `UnsealedInner` as the outer ciphertext — sender encrypts is a no-op,
/// recipient decrypts is `UnsealedInner::decode`. The structure of the
/// flow is identical.
#[test]
fn pairwise_dm_full_stack_roundtrip() {
	// ── Sender side ───────────────────────────────────────────────

	let mut rng = ChaCha20Rng::from_seed([0xABu8; 32]);

	// Sender's identity (libp2p Ed25519 node key).
	let signing_key = ed25519_zebra::SigningKey::from([0x11u8; 32]);

	// Recipient's identity (just need the pubkey for pickup-key derivation).
	let recipient_pubkey: [u8; 32] = ed25519_zebra::VerificationKey::from(
		&ed25519_zebra::SigningKey::from([0x22u8; 32]),
	)
	.into();

	// Shared symmetric secret between sender and recipient (in real
	// use, derived from the DR pairwise session). For test purposes
	// we just pick a fixed value both sides know.
	let session_secret: [u8; 32] = [0x33; 32];

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
	let envelope = SealedEnvelope {
		kind: EnvelopeKind::Pairwise,
		outer_ciphertext: unsealed_encoded,
		ephemeral_pubkey: [0xEE; 32], // would be a real X25519 epk in production
		message_id,
	};
	let envelope_encoded = envelope.encode();

	// Step 6: stripe-split the encoded envelope into N shares.
	let share_bytes = split_xor(&envelope_encoded, SHARE_COUNT, &mut rng).unwrap();
	assert_eq!(share_bytes.len(), SHARE_COUNT);

	// Step 7: derive the per-message MAC key + tag each share.
	let mac_key = derive_share_mac_key(&session_secret, &message_id);
	let share_tags: Vec<ShareMacTag> = share_bytes
		.iter()
		.enumerate()
		.map(|(i, s)| mac_share(&mac_key, s, i as ShareIndex))
		.collect();

	// Step 8: build descriptors that would go to the DHT. (We don't
	// exercise the DHT in this test; just verify the descriptor shape
	// round-trips through SCALE.)
	let pickup_key = PickupKey::for_pairwise(&recipient_pubkey);
	let descriptors: Vec<ShareDescriptor> = (0..SHARE_COUNT)
		.map(|i| ShareDescriptor {
			relay_pubkey: RelayPubkey([0x44; 32]), // would be the per-share relay's key
			message_id,
			share_index: i as ShareIndex,
			total_shares: SHARE_COUNT as u8,
			pickup_key,
			expires_at_unix_ts: 1_700_000_000 + CHAT_TTL_SECONDS,
		})
		.collect();

	// Descriptors SCALE-roundtrip.
	for d in &descriptors {
		let bytes = d.encode();
		assert_eq!(ShareDescriptor::decode(&mut &bytes[..]).unwrap(), *d);
	}

	// ── Wire (no-op in test; in production: libp2p + DHT) ─────────

	// ── Recipient side ────────────────────────────────────────────

	// Recipient assembles (share_index, share_bytes, tag) triples
	// after fetching from each relay.
	let triples: Vec<(ShareIndex, &[u8], &ShareMacTag)> = share_bytes
		.iter()
		.zip(share_tags.iter())
		.enumerate()
		.map(|(i, (b, t))| (i as ShareIndex, b.as_slice(), t))
		.collect();

	// Recipient verifies MACs + XOR-combines.
	let recovered_envelope_bytes = combine_xor_authenticated(&mac_key, &triples)
		.expect("auth-combine of honest shares must succeed");
	assert_eq!(recovered_envelope_bytes, envelope_encoded);

	// Recipient decodes the SealedEnvelope.
	let recovered_envelope =
		SealedEnvelope::decode(&mut &recovered_envelope_bytes[..]).unwrap();
	assert_eq!(recovered_envelope, envelope);

	// Recipient confirms the envelope kind is pairwise (would route
	// to DR-decrypt rather than MLS-decrypt).
	assert_eq!(recovered_envelope.kind, EnvelopeKind::Pairwise);

	// Recipient decrypts outer_ciphertext. In production this is
	// Sealed Sender outer AEAD decrypt; here it's just SCALE decode.
	let recovered_unsealed =
		UnsealedInner::decode(&mut &recovered_envelope.outer_ciphertext[..]).unwrap();

	// Recipient verifies the sender signature against the outer's
	// message_id (NOT a freshly-derived one).
	let verified_pubkey = verify_sender(&recovered_unsealed, &recovered_envelope.message_id)
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
	let session_secret: [u8; 32] = [0x55; 32];
	let group_id = GroupId::generate(&mut rng);
	let plaintext: &[u8] = b"group message: shipping at block 9000";

	let message_id = MessageId::generate(&mut rng);
	let unsealed = sign_inner(plaintext.to_vec(), &message_id, &signing_key);
	let envelope = SealedEnvelope {
		kind: EnvelopeKind::Group(group_id),
		outer_ciphertext: unsealed.encode(),
		ephemeral_pubkey: [0u8; 32], // group sentinel
		message_id,
	};
	let envelope_encoded = envelope.encode();

	let share_bytes = split_xor(&envelope_encoded, SHARE_COUNT, &mut rng).unwrap();
	let mac_key = derive_share_mac_key(&session_secret, &message_id);
	let share_tags: Vec<ShareMacTag> = share_bytes
		.iter()
		.enumerate()
		.map(|(i, s)| mac_share(&mac_key, s, i as ShareIndex))
		.collect();

	// Pickup key for the group differs from any pairwise pickup key.
	let group_pickup = PickupKey::for_group(&group_id);
	let pairwise_pickup_with_same_bytes = PickupKey::for_pairwise(&group_id.0);
	assert_ne!(
		group_pickup, pairwise_pickup_with_same_bytes,
		"domain separation must keep pairwise and group pickup keys distinct",
	);

	// Recipient roundtrip.
	let triples: Vec<(ShareIndex, &[u8], &ShareMacTag)> = share_bytes
		.iter()
		.zip(share_tags.iter())
		.enumerate()
		.map(|(i, (b, t))| (i as ShareIndex, b.as_slice(), t))
		.collect();
	let recovered = combine_xor_authenticated(&mac_key, &triples).unwrap();
	let recovered_envelope = SealedEnvelope::decode(&mut &recovered[..]).unwrap();
	assert_eq!(recovered_envelope.kind, EnvelopeKind::Group(group_id));
	let recovered_unsealed =
		UnsealedInner::decode(&mut &recovered_envelope.outer_ciphertext[..]).unwrap();
	verify_sender(&recovered_unsealed, &recovered_envelope.message_id).unwrap();
	assert_eq!(recovered_unsealed.inner_ciphertext, plaintext);
}

/// Tampered share is identified by position so the recipient can
/// re-fetch *just that share* from a different relay.
#[test]
fn tampered_share_is_localized() {
	let mut rng = ChaCha20Rng::from_seed([0xEFu8; 32]);
	let signing_key = ed25519_zebra::SigningKey::from([0x44u8; 32]);
	let session_secret: [u8; 32] = [0x66; 32];
	let plaintext = b"tamper detection at the relay layer";

	let message_id = MessageId::generate(&mut rng);
	let unsealed = sign_inner(plaintext.to_vec(), &message_id, &signing_key);
	let envelope = SealedEnvelope {
		kind: EnvelopeKind::Pairwise,
		outer_ciphertext: unsealed.encode(),
		ephemeral_pubkey: [0; 32],
		message_id,
	};
	let envelope_encoded = envelope.encode();

	let share_bytes = split_xor(&envelope_encoded, SHARE_COUNT, &mut rng).unwrap();
	let mac_key = derive_share_mac_key(&session_secret, &message_id);
	let mut share_tags: Vec<ShareMacTag> = share_bytes
		.iter()
		.enumerate()
		.map(|(i, s)| mac_share(&mac_key, s, i as ShareIndex))
		.collect();

	// Simulate a malicious relay corrupting share at index 2's tag.
	share_tags[2][0] ^= 0xFF;

	let triples: Vec<(ShareIndex, &[u8], &ShareMacTag)> = share_bytes
		.iter()
		.zip(share_tags.iter())
		.enumerate()
		.map(|(i, (b, t))| (i as ShareIndex, b.as_slice(), t))
		.collect();

	match combine_xor_authenticated(&mac_key, &triples) {
		Err(rostro_chat_primitives::stripe::AuthCombineError::TamperedShare {
			slice_index,
			share_index,
		}) => {
			assert_eq!(slice_index, 2);
			assert_eq!(share_index, 2);
		},
		other => panic!("expected TamperedShare at index 2, got {:?}", other),
	}
}
