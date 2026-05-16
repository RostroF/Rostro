// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Behavioral tests for the Double Ratchet session.
//!
//! Covers:
//! - simple round-trip in both directions
//! - back-and-forth that exercises DH ratchet rotation each turn
//! - out-of-order delivery within a single sending chain
//! - cross-chain skipped-key handling (out-of-order across a DH step)
//! - tampered-header rejection
//! - `MAX_SKIP` overflow rejection
//!
//! Determinism is achieved with `StdRng::seed_from_u64`. The crate's
//! RNG dependency is `rand_core`; tests pull `rand` for ergonomics.

use crate::ratchet::{Header, MAX_SKIP};
use crate::session::{Error, Session};

use rand::{rngs::StdRng, SeedableRng};
use x25519_dalek::{PublicKey, StaticSecret};

/// Build a fresh (alice, bob) session pair with deterministic RNGs.
/// The shared secret and Bob's keypair would normally come from X3DH.
fn pair() -> (Session, Session, StdRng) {
	// One RNG for Bob's initial keypair, separate ones for each
	// session so DH ratchet generation is independently reproducible.
	let mut bob_init_rng = StdRng::seed_from_u64(0xB0B);
	let bob_dhs = StaticSecret::random_from_rng(&mut bob_init_rng);
	let bob_pub: [u8; 32] = *PublicKey::from(&bob_dhs).as_bytes();
	let shared_secret = [42u8; 32];

	let mut alice_rng = StdRng::seed_from_u64(0xA11CE);
	let alice = Session::initialize_alice(&mut alice_rng, shared_secret, bob_pub);
	let bob = Session::initialize_bob(shared_secret, bob_dhs);

	// Caller drives DH-ratchet RNG via this; one shared rng is fine
	// since we only need pseudorandomness, not crypto strength here.
	let drive_rng = StdRng::seed_from_u64(0xD41E);
	(alice, bob, drive_rng)
}

#[test]
fn alice_to_bob_round_trip() {
	let (mut alice, mut bob, mut rng) = pair();
	let msg = alice.encrypt(b"hello bob", b"v1").expect("encrypt");
	let pt = bob
		.decrypt(&mut rng, &msg.header, &msg.ciphertext, b"v1")
		.expect("decrypt");
	assert_eq!(pt, b"hello bob");
}

#[test]
fn bob_cannot_encrypt_until_first_inbound() {
	let (mut _alice, mut bob, mut _rng) = pair();
	let err = bob.encrypt(b"too early", b"v1").unwrap_err();
	matches!(err, Error::NotReady(_));
}

#[test]
fn back_and_forth_exercises_dh_ratchet() {
	let (mut alice, mut bob, mut rng) = pair();

	// 5 rounds of A→B then B→A. Each direction's first message after
	// receiving rotates DHs, exercising the DH ratchet path.
	for round in 0..5u32 {
		let m1 = alice
			.encrypt(format!("a{}", round).as_bytes(), b"v1")
			.unwrap();
		let pt1 = bob
			.decrypt(&mut rng, &m1.header, &m1.ciphertext, b"v1")
			.unwrap();
		assert_eq!(pt1, format!("a{}", round).as_bytes());

		let m2 = bob
			.encrypt(format!("b{}", round).as_bytes(), b"v1")
			.unwrap();
		let pt2 = alice
			.decrypt(&mut rng, &m2.header, &m2.ciphertext, b"v1")
			.unwrap();
		assert_eq!(pt2, format!("b{}", round).as_bytes());
	}
}

#[test]
fn out_of_order_within_one_chain() {
	let (mut alice, mut bob, mut rng) = pair();

	// Alice sends 4 messages without ever receiving a reply — they all
	// share a single sending chain.
	let m0 = alice.encrypt(b"a0", b"v1").unwrap();
	let m1 = alice.encrypt(b"a1", b"v1").unwrap();
	let m2 = alice.encrypt(b"a2", b"v1").unwrap();
	let m3 = alice.encrypt(b"a3", b"v1").unwrap();

	// Deliver out of order: 2, 0, 3, 1.
	let pt2 = bob
		.decrypt(&mut rng, &m2.header, &m2.ciphertext, b"v1")
		.unwrap();
	assert_eq!(pt2, b"a2");
	let pt0 = bob
		.decrypt(&mut rng, &m0.header, &m0.ciphertext, b"v1")
		.unwrap();
	assert_eq!(pt0, b"a0");
	let pt3 = bob
		.decrypt(&mut rng, &m3.header, &m3.ciphertext, b"v1")
		.unwrap();
	assert_eq!(pt3, b"a3");
	let pt1 = bob
		.decrypt(&mut rng, &m1.header, &m1.ciphertext, b"v1")
		.unwrap();
	assert_eq!(pt1, b"a1");
}

#[test]
fn skipped_key_survives_dh_ratchet() {
	let (mut alice, mut bob, mut rng) = pair();

	// Alice sends two on chain-1.
	let a0 = alice.encrypt(b"a0", b"v1").unwrap();
	let a1 = alice.encrypt(b"a1", b"v1").unwrap();

	// Bob sees a0, replies, Alice receives reply (Alice DH-rotates).
	bob.decrypt(&mut rng, &a0.header, &a0.ciphertext, b"v1")
		.unwrap();
	let b0 = bob.encrypt(b"b0", b"v1").unwrap();
	alice
		.decrypt(&mut rng, &b0.header, &b0.ciphertext, b"v1")
		.unwrap();

	// Alice sends a2 on her new chain.
	let a2 = alice.encrypt(b"a2", b"v1").unwrap();

	// Bob sees a2 first — DH ratchet, header.pn = 2 means skip a1's
	// key on the old chain.
	let pt2 = bob
		.decrypt(&mut rng, &a2.header, &a2.ciphertext, b"v1")
		.unwrap();
	assert_eq!(pt2, b"a2");

	// Late delivery of a1 — skipped cache hit.
	let pt1 = bob
		.decrypt(&mut rng, &a1.header, &a1.ciphertext, b"v1")
		.unwrap();
	assert_eq!(pt1, b"a1");
}

#[test]
fn tampered_header_rejected() {
	let (mut alice, mut bob, mut rng) = pair();
	let m = alice.encrypt(b"hello", b"v1").unwrap();

	let mut bad = m.header;
	bad.n = bad.n.wrapping_add(1); // anything off-by-one breaks AD

	let err = bob
		.decrypt(&mut rng, &bad, &m.ciphertext, b"v1")
		.unwrap_err();
	assert!(matches!(err, Error::AeadFailed));
}

#[test]
fn tampered_ciphertext_rejected() {
	let (mut alice, mut bob, mut rng) = pair();
	let m = alice.encrypt(b"hello", b"v1").unwrap();
	let mut bad_ct = m.ciphertext.clone();
	bad_ct[0] ^= 0x01;

	let err = bob
		.decrypt(&mut rng, &m.header, &bad_ct, b"v1")
		.unwrap_err();
	assert!(matches!(err, Error::AeadFailed));
}

#[test]
fn max_skip_overflow_rejected() {
	let (mut alice, mut bob, mut rng) = pair();

	// Alice sends one message Bob will receive, anchoring the chain.
	let a0 = alice.encrypt(b"a0", b"v1").unwrap();
	bob.decrypt(&mut rng, &a0.header, &a0.ciphertext, b"v1")
		.unwrap();

	// Bob's nr is 1 after decrypting a0. He'll trip the per-chain
	// bound when a message arrives with n - nr > MAX_SKIP, i.e. n
	// strictly greater than MAX_SKIP + 1. Alice's Ns is 1, so we need
	// to send MAX_SKIP + 2 more messages so the last one has
	// n = MAX_SKIP + 2.
	let mut last = None;
	for _ in 0..=(MAX_SKIP + 1) {
		last = Some(alice.encrypt(b"x", b"v1").unwrap());
	}
	let last = last.unwrap();
	let err = bob
		.decrypt(&mut rng, &last.header, &last.ciphertext, b"v1")
		.unwrap_err();
	assert!(matches!(err, Error::TooManySkipped));
}

#[test]
fn header_serialize_round_trip() {
	let h = Header { dh_pubkey: [9u8; 32], pn: 7, n: 42 };
	let bytes = h.to_bytes();
	let parsed = Header::from_bytes(&bytes).unwrap();
	assert_eq!(parsed, h);
	assert!(Header::from_bytes(&bytes[..39]).is_none());
}
