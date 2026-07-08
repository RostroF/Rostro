// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Full crypto-stack end-to-end integration test for the Rostro
//! chat layer.
//!
//! Exercises all four crypto crates composed together — the path a
//! real chat message takes, minus libp2p transport (which lives in
//! Phase B):
//!
//! **Pairwise flow** (DR + Sealed Sender + envelope + chunk + checksum):
//!
//! ```text
//! plaintext
//!   → DR Session::encrypt              (rostro-chat-dr)
//!   → DR WireMessage (inner_ciphertext)
//!   → sign_inner → UnsealedInner       (rostro-chat-primitives)
//!   → SCALE encode UnsealedInner
//!   → seal under recipient's X25519 id (rostro-chat-sealed-sender)
//!   → SealedEnvelope::Pairwise         (rostro-chat-primitives)
//!   → SCALE encode SealedEnvelope
//!   → prepare_batch (chunk + checksum) (rostro-chat-primitives)
//!   → N tagged chunks over the wire
//! (recipient reverses all of the above)
//! ```
//!
//! **Group flow** (MLS + envelope + chunk + checksum, no Sealed Sender
//! outer):
//!
//! ```text
//! plaintext
//!   → MLS Group::encrypt_application_message  (rostro-chat-mls)
//!   → MLS wire bytes (outer_ciphertext directly)
//!   → SealedEnvelope::Group { group_id, .. }
//!   → SCALE encode + prepare_batch (chunk + checksum)
//!   → N tagged chunks over the wire
//! ```
//!
//! Group messages skip the Sealed Sender outer wrap because MLS
//! already provides (a) group-key confidentiality and (b) sender
//! authentication via the leaf node signature inside the MLS
//! message. The MLS header leaks sender identity to observers
//! who can decode MLS framing, which is an accepted trade for
//! v0.1.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rostro_chat_dr::{
	handshake_shared_secret, Session as DrSession, WireMessage as DrWireMessage,
};
use rostro_chat_mls::Member;
use rostro_chat_primitives::{
	chunk::{
		combine_chunks_verified, prepare_batch, ChunkCombineError, PreparedBatch,
		TaggedChunk,
	},
	descriptor::{GroupId, MessageId, PickupKey, CHAT_TTL_SECONDS},
	envelope::{sign_inner, SealedEnvelope, UnsealedInner},
	verify::verify_sender,
};
use rostro_chat_sealed_sender::{hybrid_seal, hybrid_unseal, HybridSealedOutput};

use codec::{Decode, Encode};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

const CHUNK_COUNT: usize = 5;
const NOW_TS: u64 = 1_700_000_000;

/// Build a fresh DR session pair (Alice initiator, Bob responder)
/// from a deterministic seed. Mirrors the X3DH-lite handshake.
fn fresh_dr_pair(seed_a: u64, seed_b: u64) -> (DrSession, DrSession) {
	let mut rng_a = ChaCha20Rng::seed_from_u64(seed_a);
	let mut rng_b = ChaCha20Rng::seed_from_u64(seed_b);
	let alice_sk = X25519SecretKey::random_from_rng(&mut rng_a);
	let bob_sk = X25519SecretKey::random_from_rng(&mut rng_b);
	let alice_pk = X25519PublicKey::from(&alice_sk);
	let bob_pk = X25519PublicKey::from(&bob_sk);
	let shared_a = handshake_shared_secret(&alice_sk, &bob_pk);
	let shared_b = handshake_shared_secret(&bob_sk, &alice_pk);
	let alice_session = DrSession::from_handshake_initiator(shared_a, alice_sk, bob_pk);
	let bob_session = DrSession::from_handshake_responder(shared_b, bob_sk, alice_pk);
	(alice_session, bob_session)
}

/// Fresh X25519 identity keypair (for Sealed Sender ECDH at the
/// outer layer). In production these are derived once per SS58
/// account, persisted in the local keystore.
fn fresh_x25519_identity(seed: u64) -> ([u8; 32], [u8; 32]) {
	let mut rng = ChaCha20Rng::seed_from_u64(seed);
	let sk = X25519SecretKey::random_from_rng(&mut rng);
	let pk = X25519PublicKey::from(&sk);
	(sk.to_bytes(), *pk.as_bytes())
}

/// Encode + chunk-split + MAC a SealedEnvelope on the "sender's
/// device" — the prepare-side pipeline of the chunk cutover
/// (docs/CHAT-SHARE-CHUNKING.md). Returns (encoded_envelope_bytes,
/// batch) so the test can inspect both sides of the wire.
fn fresh_seal_keypair(
	seed: u8,
) -> (rostro_hybrid_kex::MlKemDecapKey, [u8; rostro_hybrid_kex::MLKEM768_EK_BYTES]) {
	rostro_hybrid_kex::mlkem_keypair_from_seed(&[seed; 64])
}

fn chunk_and_checksum(
	envelope: &SealedEnvelope,
	pickup_key: PickupKey,
) -> (Vec<u8>, PreparedBatch) {
	let encoded = envelope.encode();
	let batch = prepare_batch(
		&encoded,
		CHUNK_COUNT,
		*envelope.message_id(),
		pickup_key,
		NOW_TS + CHAT_TTL_SECONDS,
	)
	.unwrap();
	// The chunk invariant that motivated the cutover: pieces SUM to
	// the envelope size instead of N× it.
	let total: usize = batch.shares.iter().map(|s| s.chunk_bytes.len()).sum();
	assert_eq!(total, encoded.len());
	(encoded, batch)
}

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

#[test]
fn pairwise_full_crypto_stack_roundtrip() {
	// ── Setup ─────────────────────────────────────────────────────

	let mut rng = ChaCha20Rng::seed_from_u64(0xAB);

	// Alice's signing identity (Ed25519, maps to SS58).
	let alice_signing = ed25519_zebra::SigningKey::from([0x11u8; 32]);
	let _alice_signing_pub: [u8; 32] =
		ed25519_zebra::VerificationKey::from(&alice_signing).into();

	// Bob's X25519 identity (for Sealed Sender outer ECDH).
	let (bob_x_sk, bob_x_pk) = fresh_x25519_identity(0x22);
	let (bob_seal_dk, bob_seal_ek) = fresh_seal_keypair(0x23);

	// DR session pair — established via an X3DH-lite handshake.
	let (mut alice_dr, mut bob_dr) = fresh_dr_pair(0x33, 0x44);



	let plaintext = b"hello over the full crypto stack";

	// ── Sender flow ───────────────────────────────────────────────

	// 1. DR-encrypt the plaintext.
	let dr_msg: DrWireMessage = alice_dr.encrypt(plaintext);
	let inner_ciphertext = dr_msg.encode();

	// 2. Wrap in UnsealedInner with sender's Ed25519 signature.
	let message_id = MessageId::generate(&mut rng);
	let unsealed = sign_inner(inner_ciphertext, &message_id, &alice_signing);

	// 3. Encode UnsealedInner → bytes that Sealed Sender will encrypt.
	let unsealed_encoded = unsealed.encode();

	// 4. Hybrid-Sealed-Sender-seal to Bob's X25519 identity pubkey
	//    + his ML-KEM-768 SEAL key (docs/PQ-CHAT.md).
	let ss: HybridSealedOutput =
		hybrid_seal(&bob_x_pk, &bob_seal_ek, &unsealed_encoded, &mut rng).unwrap();

	// 5. Build the outer SealedEnvelope.
	let envelope = SealedEnvelope::Pairwise {
		ephemeral_pubkey: ss.ephemeral_pub,
		pq_ct: ss.pq_ct,
		outer_ciphertext: ss.ciphertext,
		message_id,
	};

	// 6. Chunk-split + checksum each piece on the sender's device.
	let pickup_key = PickupKey::for_pairwise(&bob_x_pk);
	let (_envelope_encoded, batch) = chunk_and_checksum(&envelope, pickup_key);

	// ── Recipient flow ────────────────────────────────────────────

	// 1. Verified reassembly (check every chunk's checksum, then
	//    concatenate in index order).
	let refs = tagged_refs(&batch);
	let recovered_envelope_bytes =
		combine_chunks_verified(&message_id, &pickup_key, &refs).unwrap();

	// 2. Decode SealedEnvelope.
	let recovered_envelope =
		SealedEnvelope::decode(&mut &recovered_envelope_bytes[..]).unwrap();
	let SealedEnvelope::Pairwise {
		ephemeral_pubkey: rec_eph,
		pq_ct: rec_pq_ct,
		outer_ciphertext: rec_outer,
		message_id: rec_mid,
	} = recovered_envelope
	else {
		panic!("expected a Pairwise envelope");
	};

	// 3. Hybrid-Sealed-Sender-unseal with Bob's X25519 identity
	//    secret + SEAL decapsulation key.
	let ss_recovered = HybridSealedOutput {
		ephemeral_pub: rec_eph,
		pq_ct: rec_pq_ct,
		ciphertext: rec_outer,
	};
	let unsealed_bytes = hybrid_unseal(&bob_x_sk, &bob_seal_dk, &ss_recovered).unwrap();

	// 4. Decode UnsealedInner.
	let recovered_unsealed =
		UnsealedInner::decode(&mut &unsealed_bytes[..]).unwrap();

	// 5. Verify the sender signature against the outer envelope's
	//    message_id.
	let verified_sender_pubkey =
		verify_sender(&recovered_unsealed, &rec_mid).unwrap();
	let expected_sender_pubkey: [u8; 32] =
		ed25519_zebra::VerificationKey::from(&alice_signing).into();
	assert_eq!(verified_sender_pubkey, expected_sender_pubkey);

	// 6. DR-decode + decrypt inner ciphertext.
	let dr_wire_recovered =
		DrWireMessage::decode(&mut &recovered_unsealed.inner_ciphertext[..]).unwrap();
	let recovered_plaintext = bob_dr.decrypt(&dr_wire_recovered).unwrap();
	assert_eq!(recovered_plaintext, plaintext);
}

#[test]
fn group_full_crypto_stack_roundtrip() {
	// ── Setup ─────────────────────────────────────────────────────

	let mut rng = ChaCha20Rng::seed_from_u64(0xCD);

	let alice = Member::new().unwrap();
	let bob = Member::new().unwrap();
	let charlie = Member::new().unwrap();

	let gid = GroupId([0x66; 32]);
	let mut alice_group = alice.create_group(&gid).unwrap();

	// Add bob.
	let bob_kp = bob.key_package().unwrap();
	let (_c, welcome_b, rt_b) = alice_group.add_member(&alice, bob_kp).unwrap();
	let mut bob_group = bob
		.process_welcome(welcome_to_in(welcome_b), rt_b)
		.unwrap();

	// Add charlie.
	let charlie_kp = charlie.key_package().unwrap();
	let (commit_c, welcome_c, rt_c) = alice_group.add_member(&alice, charlie_kp).unwrap();
	// Bob catches up to the new epoch.
	let commit_bytes = mls_to_bytes(&commit_c);
	let _ = bob_group.decrypt_or_process(&bob, &commit_bytes);
	let mut charlie_group = charlie
		.process_welcome(welcome_to_in(welcome_c), rt_c)
		.unwrap();

	let plaintext = b"group hello via full stack";



	// ── Sender flow ───────────────────────────────────────────────

	// 1. MLS-encrypt at the current epoch. Result IS the outer
	//    ciphertext (no Sealed Sender wrap for groups in v0.1).
	let mls_wire = alice_group
		.encrypt_application_message(&alice, plaintext)
		.unwrap();

	// 2. Build SealedEnvelope::Group (no ephemeral, no KEM ct — the
	//    group outer key comes from MLS epoch state).
	let message_id = MessageId::generate(&mut rng);
	let envelope = SealedEnvelope::Group {
		group_id: gid,
		outer_ciphertext: mls_wire,
		message_id,
	};

	// 3. Chunk-split + checksum.
	let pickup_key = PickupKey::for_group(&gid);
	let (_, batch) = chunk_and_checksum(&envelope, pickup_key);

	// ── Recipient flow (Bob) ──────────────────────────────────────

	let refs = tagged_refs(&batch);
	let bob_recovered =
		combine_chunks_verified(&message_id, &pickup_key, &refs).unwrap();
	let bob_envelope = SealedEnvelope::decode(&mut &bob_recovered[..]).unwrap();
	assert!(matches!(bob_envelope, SealedEnvelope::Group { group_id: g, .. } if g == gid));
	let bob_plaintext = bob_group
		.decrypt_or_process(&bob, bob_envelope.outer_ciphertext())
		.unwrap();
	assert_eq!(bob_plaintext, plaintext);

	// ── Recipient flow (Charlie) ──────────────────────────────────

	let charlie_recovered =
		combine_chunks_verified(&message_id, &pickup_key, &refs).unwrap();
	let charlie_envelope =
		SealedEnvelope::decode(&mut &charlie_recovered[..]).unwrap();
	let charlie_plaintext = charlie_group
		.decrypt_or_process(&charlie, charlie_envelope.outer_ciphertext())
		.unwrap();
	assert_eq!(charlie_plaintext, plaintext);
}

#[test]
fn group_removed_member_cannot_decrypt_via_full_stack() {
	let mut rng = ChaCha20Rng::seed_from_u64(0xEF);

	let alice = Member::new().unwrap();
	let bob = Member::new().unwrap();
	let charlie = Member::new().unwrap();

	let gid = GroupId([0x88; 32]);
	let mut alice_group = alice.create_group(&gid).unwrap();

	// Add bob.
	let bob_kp = bob.key_package().unwrap();
	let (_c, welcome_b, rt_b) = alice_group.add_member(&alice, bob_kp).unwrap();
	let mut bob_group = bob
		.process_welcome(welcome_to_in(welcome_b), rt_b)
		.unwrap();

	// Add charlie.
	let charlie_kp = charlie.key_package().unwrap();
	let (commit_c, welcome_c, rt_c) = alice_group.add_member(&alice, charlie_kp).unwrap();
	let _ = bob_group.decrypt_or_process(&bob, &mls_to_bytes(&commit_c));
	let mut charlie_group = charlie
		.process_welcome(welcome_to_in(welcome_c), rt_c)
		.unwrap();

	// Alice removes Charlie.
	let charlie_id = charlie.identity();
	let commit_rm = alice_group.remove_member(&alice, &charlie_id).unwrap();
	let _ = bob_group.decrypt_or_process(&bob, &mls_to_bytes(&commit_rm));

	// Alice sends post-remove via the full stack.
	let plaintext = b"members only - post-remove";
	let mls_wire = alice_group
		.encrypt_application_message(&alice, plaintext)
		.unwrap();
	let message_id = MessageId::generate(&mut rng);
	let envelope = SealedEnvelope::Group {
		group_id: gid,
		outer_ciphertext: mls_wire,
		message_id,
	};
	let pickup_key = PickupKey::for_group(&gid);
	let (_, batch) = chunk_and_checksum(&envelope, pickup_key);
	let refs = tagged_refs(&batch);

	// Bob (still a member) decrypts.
	let bob_recovered =
		combine_chunks_verified(&message_id, &pickup_key, &refs).unwrap();
	let bob_envelope = SealedEnvelope::decode(&mut &bob_recovered[..]).unwrap();
	assert_eq!(
		bob_group
			.decrypt_or_process(&bob, bob_envelope.outer_ciphertext())
			.unwrap(),
		plaintext,
	);

	// Charlie (removed) attempts the same flow. The chunk layer
	// succeeds (chunks + keyless checksums are public) — but the MLS
	// decryption fails because Charlie's MLS state is at the
	// pre-remove epoch. What matters: at the MLS layer, Charlie can
	// NOT decrypt the post-remove message.
	let charlie_recovered =
		combine_chunks_verified(&message_id, &pickup_key, &refs).unwrap();
	let charlie_envelope =
		SealedEnvelope::decode(&mut &charlie_recovered[..]).unwrap();
	assert!(
		charlie_group
			.decrypt_or_process(&charlie, charlie_envelope.outer_ciphertext())
			.is_err(),
		"removed member must not be able to decrypt a post-remove message",
	);
}

#[test]
fn corrupt_chunk_localized_in_full_stack() {
	let mut rng = ChaCha20Rng::seed_from_u64(0x12);
	let alice_signing = ed25519_zebra::SigningKey::from([0x44u8; 32]);
	let (_bob_x_sk, bob_x_pk) = fresh_x25519_identity(0x55);
	let (_bob_seal_dk, bob_seal_ek) = fresh_seal_keypair(0x56);
	let (mut alice_dr, _bob_dr) = fresh_dr_pair(0x66, 0x77);

	let plaintext = b"corruption detection at the chunk layer";
	let dr_msg = alice_dr.encrypt(plaintext);
	let inner_ciphertext = dr_msg.encode();
	let message_id = MessageId::generate(&mut rng);
	let unsealed = sign_inner(inner_ciphertext, &message_id, &alice_signing);
	let ss = hybrid_seal(&bob_x_pk, &bob_seal_ek, &unsealed.encode(), &mut rng).unwrap();
	let envelope = SealedEnvelope::Pairwise {
		ephemeral_pubkey: ss.ephemeral_pub,
		pq_ct: ss.pq_ct,
		outer_ciphertext: ss.ciphertext,
		message_id,
	};
	let pickup_key = PickupKey::for_pairwise(&bob_x_pk);
	let (_, mut batch) = chunk_and_checksum(&envelope, pickup_key);

	// Corrupt chunk at slice index 3.
	batch.shares[3].chunk_bytes[0] ^= 0xFF;

	let refs = tagged_refs(&batch);
	match combine_chunks_verified(&message_id, &pickup_key, &refs) {
		Err(ChunkCombineError::CorruptChunk { slice_index, share_index }) => {
			assert_eq!(slice_index, 3);
			assert_eq!(share_index, 3);
		},
		other => panic!("expected CorruptChunk at slice_index 3, got {:?}", other),
	}
}

// ── helpers ──────────────────────────────────────────────────────

fn mls_to_bytes(out: &openmls::framing::MlsMessageOut) -> Vec<u8> {
	use tls_codec::Serialize as _;
	out.tls_serialize_detached().unwrap()
}

fn welcome_to_in(welcome: openmls::framing::MlsMessageOut) -> openmls::prelude::Welcome {
	use openmls::framing::{MlsMessageBodyIn, MlsMessageIn};
	use tls_codec::{Deserialize as _, Serialize as _};
	let bytes = welcome.tls_serialize_detached().unwrap();
	let mut slice = bytes.as_slice();
	let in_msg = MlsMessageIn::tls_deserialize(&mut slice).unwrap();
	match in_msg.extract() {
		MlsMessageBodyIn::Welcome(w) => w,
		other => panic!("expected Welcome, got {:?}", other),
	}
}
