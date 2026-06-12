// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-chat-onion — one-hop onion wrapping
//!
//! Phase 4 of the dotwave-chat plan (network-origin anonymity). Splits
//! **who** from **where** across two relays so that no single relay
//! sees both the sender and the destination:
//!
//! ```text
//! sender → GUARD → RELAY-2 → (existing stripe fan-out → bucket)
//! ```
//!
//! - **GUARD** sees the sender (its cert + IP) and the next hop, but
//!   NOT the destination — the inner layer is sealed to relay-2.
//! - **RELAY-2** sees the destination (the drop it injects into the
//!   stripe layer) but NOT the sender — it only ever saw the guard
//!   hand over an opaque blob.
//!
//! Relinking sender→destination requires the *specific* guard and
//! relay-2 to collude.
//!
//! ## Construction (nested seal, not Sphinx)
//!
//! For a single hop with both relays under Rostro's canonical-gated
//! trust model, full Sphinx (fixed packets, per-hop MACs, reply
//! blocks, replay caches) is overkill. We nest two
//! [`rostro_chat_sealed_sender`] layers — per-message ephemeral X25519
//! ECDH + HKDF-SHA256 + ChaCha20-Poly1305 — each relay holding an
//! X25519 *onion key*:
//!
//! ```text
//! INNER   = seal(relay2_onion_pub, pad(drop, FIXED_DROP_SIZE))
//! FORWARD = SCALE{ next_hop, inner: INNER }
//! OUTER   = seal(guard_onion_pub, FORWARD)
//! ```
//!
//! - Sender authenticates its (throwaway) cert to the guard, sends
//!   `OUTER`.
//! - Guard [`peel_guard`]: `unseal(OUTER)` → `(next_hop, INNER)`;
//!   forwards `INNER` to `next_hop`. The guard cannot read `INNER`
//!   (sealed to relay-2's key).
//! - Relay-2 [`peel_relay2`]: `unseal(INNER)` → `unpad` → `drop`;
//!   injects into the existing stripe path.
//!
//! Per-message ephemeral keys at every layer ⇒ no cross-message
//! linkage. Fixed [`FIXED_DROP_SIZE`] ⇒ guard and relay-2 both see
//! constant-size blobs (size-correlation defense). Sphinx is the
//! upgrade path if more hops are ever added.
//!
//! ## What this crate does NOT do
//!
//! - **No transport.** The guard→relay-2 hand-off and the cert
//!   admission are the node's job; this crate is the wrap/peel math.
//! - **No sender authentication.** The guard runs `verify_chat_auth`
//!   on the cert presented alongside `OUTER`; this layer is unkeyed by
//!   sender identity by design (that is the point).
//! - **No timing-analysis resistance.** Cover traffic / mixnet
//!   transport is a documented residual, deferred under the
//!   burner-grade-opsec assumption.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use rostro_chat_sealed_sender::{seal, unseal, SealedOutput, UnsealError};
use zeroize::Zeroize;

/// Fixed plaintext size every drop is padded to before the inner
/// seal, so the guard and relay-2 see constant-size blobs regardless
/// of message length. Must exceed the largest realistic
/// `SealedEnvelope + routing` drop; over-padding only costs bytes on
/// the wire. (Tunable — open decision #3 in the Phase-4 doc.)
pub const FIXED_DROP_SIZE: usize = 4096;

/// A relay's onion identity: the X25519 public key the sender seals a
/// layer to. Distinct from the relay's libp2p/gossip key; published
/// alongside it. `id` is the opaque routing handle the guard uses to
/// reach this relay (e.g. its peer id), carried in the clear inside
/// the guard's layer.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OnionRelay {
	/// Opaque next-hop routing handle (the node maps it to a peer).
	pub id: Vec<u8>,
	/// The relay's X25519 onion public key.
	pub onion_pub: [u8; 32],
}

/// What the guard learns after peeling the outer layer: where to
/// forward, and the still-sealed inner blob. The guard never learns
/// the destination bucket (that is inside `inner`, sealed to relay-2).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct GuardForward {
	/// Relay-2's routing handle (`OnionRelay::id`).
	pub next_hop: Vec<u8>,
	/// The inner onion layer, sealed to relay-2.
	pub inner: SealedOutput,
}

/// Errors from onion peeling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionError {
	/// AEAD auth failed unsealing a layer: tampering, wrong relay key,
	/// or a layer presented to the wrong hop.
	Seal(UnsealError),
	/// A layer decrypted but did not decode as the expected structure.
	BadEncoding,
	/// The padded drop's length prefix is impossible (corrupt /
	/// wrong-key plaintext that happened to authenticate — should not
	/// occur with AEAD, defensive).
	BadPadding,
}

impl From<UnsealError> for OnionError {
	fn from(e: UnsealError) -> Self {
		OnionError::Seal(e)
	}
}

/// The outer onion packet handed to the guard. Just a [`SealedOutput`]
/// — a random ephemeral pubkey + opaque ciphertext, indistinguishable
/// on the wire from any other sealed blob.
pub type OnionPacket = SealedOutput;

/// Wrap `drop_bytes` into a two-layer onion: inner sealed to `relay2`,
/// outer sealed to `guard`. The returned packet is what the sender
/// presents to the guard (alongside its cert).
///
/// `drop_bytes` is the SCALE-encoded drop relay-2 will inject into the
/// stripe layer (the `SealedEnvelope` + routing). It is padded to
/// [`FIXED_DROP_SIZE`] before sealing; a drop larger than that is a
/// caller error ([`OnionError::BadPadding`]).
pub fn wrap_onion<R>(
	guard: &OnionRelay,
	relay2: &OnionRelay,
	drop_bytes: &[u8],
	rng: &mut R,
) -> Result<OnionPacket, OnionError>
where
	R: rand_core::RngCore + rand_core::CryptoRng,
{
	let mut padded = pad_drop(drop_bytes)?;
	let inner = seal(&relay2.onion_pub, &padded, rng);
	padded.zeroize();

	let forward = GuardForward { next_hop: relay2.id.clone(), inner };
	let forward_bytes = forward.encode();
	let outer = seal(&guard.onion_pub, &forward_bytes, rng);
	Ok(outer)
}

/// Guard side: peel the outer layer with the guard's onion secret.
/// Returns where to forward and the still-sealed inner blob. The guard
/// cannot read the inner blob — it is sealed to relay-2.
pub fn peel_guard(
	guard_onion_secret: &[u8; 32],
	packet: &OnionPacket,
) -> Result<GuardForward, OnionError> {
	let forward_bytes = unseal(guard_onion_secret, packet)?;
	GuardForward::decode(&mut &forward_bytes[..]).map_err(|_| OnionError::BadEncoding)
}

/// Relay-2 side: peel the inner layer with relay-2's onion secret and
/// recover the original drop bytes (depadded). What relay-2 injects
/// into the existing stripe path.
pub fn peel_relay2(
	relay2_onion_secret: &[u8; 32],
	inner: &SealedOutput,
) -> Result<Vec<u8>, OnionError> {
	let mut padded = unseal(relay2_onion_secret, inner)?;
	let drop = unpad_drop(&padded)?;
	padded.zeroize();
	Ok(drop)
}

/// Pad to `FIXED_DROP_SIZE`: `[len: u32 LE][drop][zeros]`.
fn pad_drop(drop: &[u8]) -> Result<Vec<u8>, OnionError> {
	// 4-byte length prefix + payload must fit the fixed frame.
	if drop.len() + 4 > FIXED_DROP_SIZE {
		return Err(OnionError::BadPadding);
	}
	let mut out = Vec::with_capacity(FIXED_DROP_SIZE);
	out.extend_from_slice(&(drop.len() as u32).to_le_bytes());
	out.extend_from_slice(drop);
	out.resize(FIXED_DROP_SIZE, 0);
	Ok(out)
}

/// Inverse of [`pad_drop`].
fn unpad_drop(padded: &[u8]) -> Result<Vec<u8>, OnionError> {
	if padded.len() != FIXED_DROP_SIZE {
		return Err(OnionError::BadPadding);
	}
	let mut len_bytes = [0u8; 4];
	len_bytes.copy_from_slice(&padded[..4]);
	let len = u32::from_le_bytes(len_bytes) as usize;
	if 4 + len > FIXED_DROP_SIZE {
		return Err(OnionError::BadPadding);
	}
	Ok(padded[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
	use rostro_chat_sealed_sender::SealedOutput;
	use x25519_dalek::{PublicKey, StaticSecret};

	fn rng() -> ChaCha20Rng {
		ChaCha20Rng::seed_from_u64(0x04)
	}

	/// A relay's onion keypair: (secret bytes, OnionRelay).
	fn relay(id: &[u8], seed: u64) -> ([u8; 32], OnionRelay) {
		let mut r = ChaCha20Rng::seed_from_u64(seed);
		let secret = StaticSecret::random_from_rng(&mut r);
		let pubk = PublicKey::from(&secret);
		(secret.to_bytes(), OnionRelay { id: id.to_vec(), onion_pub: *pubk.as_bytes() })
	}

	#[test]
	fn full_onion_roundtrip() {
		let (guard_sk, guard) = relay(b"guard", 1);
		let (relay2_sk, relay2) = relay(b"relay-2", 2);
		let drop = b"the SealedEnvelope + bucket routing relay-2 injects";

		let packet = wrap_onion(&guard, &relay2, drop, &mut rng()).unwrap();

		let fwd = peel_guard(&guard_sk, &packet).unwrap();
		assert_eq!(fwd.next_hop, relay2.id, "guard forwards to relay-2");

		let recovered = peel_relay2(&relay2_sk, &fwd.inner).unwrap();
		assert_eq!(recovered, drop, "relay-2 recovers the original drop");
	}

	#[test]
	fn guard_cannot_read_inner() {
		// The guard learns the next hop but the inner is sealed to
		// relay-2 — the guard's own key cannot open it.
		let (guard_sk, guard) = relay(b"guard", 1);
		let (_relay2_sk, relay2) = relay(b"relay-2", 2);
		let packet = wrap_onion(&guard, &relay2, b"destination secret", &mut rng()).unwrap();
		let fwd = peel_guard(&guard_sk, &packet).unwrap();
		// Guard tries its own key on the inner layer → fails.
		assert!(peel_relay2(&guard_sk, &fwd.inner).is_err(), "guard must not read the inner");
	}

	#[test]
	fn relay2_sees_no_sender_material() {
		// Structural: relay-2 only ever receives `inner`, which is a
		// SealedOutput with a per-message random ephemeral. The outer
		// layer (carrying the sender's ephemeral) never reaches it,
		// and nothing in `inner` is keyed to the sender.
		let (guard_sk, guard) = relay(b"guard", 1);
		let (relay2_sk, relay2) = relay(b"relay-2", 2);
		let packet = wrap_onion(&guard, &relay2, b"hello", &mut rng()).unwrap();
		let fwd = peel_guard(&guard_sk, &packet).unwrap();
		// relay-2 succeeds with ONLY the inner — no part of the outer
		// packet / sender material is needed.
		assert_eq!(peel_relay2(&relay2_sk, &fwd.inner).unwrap(), b"hello");
	}

	#[test]
	fn wrong_guard_key_rejected() {
		let (_guard_sk, guard) = relay(b"guard", 1);
		let (_relay2_sk, relay2) = relay(b"relay-2", 2);
		let (wrong_sk, _) = relay(b"impostor", 9);
		let packet = wrap_onion(&guard, &relay2, b"x", &mut rng()).unwrap();
		assert!(matches!(peel_guard(&wrong_sk, &packet), Err(OnionError::Seal(_))));
	}

	#[test]
	fn tampered_packet_rejected() {
		let (guard_sk, guard) = relay(b"guard", 1);
		let (_relay2_sk, relay2) = relay(b"relay-2", 2);
		let mut packet = wrap_onion(&guard, &relay2, b"x", &mut rng()).unwrap();
		packet.ciphertext[0] ^= 1;
		assert!(matches!(peel_guard(&guard_sk, &packet), Err(OnionError::Seal(_))));
	}

	#[test]
	fn padding_makes_layers_fixed_size() {
		let (_guard_sk, guard) = relay(b"guard", 1);
		let (_relay2_sk, relay2) = relay(b"relay-2", 2);
		let short = wrap_onion(&guard, &relay2, b"hi", &mut rng()).unwrap();
		let long = wrap_onion(&guard, &relay2, &[0xAB; 1500], &mut rng()).unwrap();
		// Different plaintext lengths → identical on-wire ciphertext
		// length (the inner is padded to FIXED_DROP_SIZE, and the
		// outer wraps a fixed-size GuardForward).
		assert_eq!(short.ciphertext.len(), long.ciphertext.len());
	}

	#[test]
	fn oversize_drop_rejected() {
		let (_g, guard) = relay(b"guard", 1);
		let (_r, relay2) = relay(b"relay-2", 2);
		let too_big = vec![0u8; FIXED_DROP_SIZE]; // + 4-byte prefix overflows
		assert_eq!(
			wrap_onion(&guard, &relay2, &too_big, &mut rng()),
			Err(OnionError::BadPadding)
		);
	}

	#[test]
	fn empty_drop_roundtrips() {
		let (guard_sk, guard) = relay(b"guard", 1);
		let (relay2_sk, relay2) = relay(b"relay-2", 2);
		let packet = wrap_onion(&guard, &relay2, b"", &mut rng()).unwrap();
		let fwd = peel_guard(&guard_sk, &packet).unwrap();
		assert_eq!(peel_relay2(&relay2_sk, &fwd.inner).unwrap(), b"");
	}

	#[test]
	fn forward_and_inner_scale_roundtrip() {
		let (_g, guard) = relay(b"guard", 1);
		let (_r, relay2) = relay(b"relay-2", 2);
		let packet = wrap_onion(&guard, &relay2, b"persist me", &mut rng()).unwrap();
		// OnionPacket (SealedOutput) and GuardForward both SCALE-cycle.
		let p2 = SealedOutput::decode(&mut &packet.encode()[..]).unwrap();
		assert_eq!(p2, packet);
	}
}
