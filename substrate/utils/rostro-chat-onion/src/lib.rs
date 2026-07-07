// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-chat-onion — onion wrapping addressed to node identities
//!
//! Phase 4 of the dotwave-chat plan (network-origin anonymity). Splits
//! **who** from **where** across relays so that no single relay sees
//! both the sender and the destination:
//!
//! ```text
//! sender → GUARD → RELAY-2 → (existing chunk fan-out → bucket)
//! ```
//!
//! - **GUARD** sees the sender (its cert + IP) and the next hop, but
//!   NOT the destination — the inner layer is sealed to relay-2.
//! - **RELAY-2** sees the destination (the drop it fans out to the
//!   chunk layer) but NOT the sender — it only ever saw the guard hand
//!   over an opaque blob.
//!
//! Relinking sender→destination requires the *specific* relays on the
//! path to collude.
//!
//! ## Addressed to node identities (design choice A)
//!
//! Each layer is sealed to a relay's [`NodeIdentity`] (its ed25519 node
//! key, per `docs/NODE-IDENTITY.md`) via the XEdDSA-derived X25519 seal
//! key. The sender learns relay identities + keys by reading canonical
//! state (the validator-attribute registration), so a malicious guard
//! cannot substitute a key it controls.
//!
//! ## One uniform hop operation
//!
//! Every layer, when peeled, yields an [`OnionHop`]:
//!
//! - [`OnionHop::Forward`] — "I'm an intermediate hop; forward `inner`
//!   to `next_hop`." (The guard, for the one-hop case.)
//! - [`OnionHop::Deliver`] — "I'm the last hop; inject `drop` into the
//!   existing recipient path." (Relay-2.)
//!
//! So a node doesn't need to know whether it's acting as guard or
//! relay-2: it [`process_hop`]s with its own [`NodeSecret`] and acts on
//! the returned variant. This generalises to N hops for free — each
//! [`OnionHop::Forward`] wraps another until a [`OnionHop::Deliver`].
//!
//! ## Construction
//!
//! ```text
//! INNER = seal(relay2,  Deliver{ pad(drop) })
//! OUTER = seal(guard,   Forward{ next_hop: relay2, inner: INNER })
//! ```
//!
//! Per-message ephemeral keys at every layer ⇒ no cross-message
//! linkage. The drop is padded to [`FIXED_DROP_SIZE`] at the `Deliver`
//! layer ⇒ every message nests to the same size regardless of length.
//!
//! ## What this crate does NOT do
//!
//! - **No transport.** The hand-off between relays and the cert
//!   admission are the node's job; this is the wrap/peel math.
//! - **No timing-analysis resistance.** Cover traffic is a documented
//!   residual, deferred under the burner-grade-opsec assumption.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use rostro_chat_sealed_sender::{seal, unseal, SealedOutput, UnsealError};
use rostro_node_identity::{NodeIdentity, NodeSecret};
use zeroize::Zeroize;

/// Fixed plaintext size every drop is padded to at the `Deliver`
/// layer, so all messages nest to a constant size regardless of length.
/// Must exceed the largest realistic drop (a `PreparedBatch`: the
/// chunks sum to the envelope size, plus ~42 bytes/chunk of descriptor
/// + tag framing); over-padding only costs bytes. (Open decision #3 in
/// the Phase-4 doc.)
pub const FIXED_DROP_SIZE: usize = 4096;

/// An opaque onion packet: a [`SealedOutput`] (random ephemeral pubkey
/// + AEAD ciphertext), indistinguishable on the wire from any other
/// sealed blob. This is what the sender hands the guard, and what each
/// relay forwards to the next.
pub type OnionPacket = SealedOutput;

// NOTE: the chat application's `Deliver` drop encoding is
// `rostro_chat_primitives::chunk::PreparedBatch` (SCALE), carrying the
// pickup key + message id + the sender-prepared, MAC-tagged chunks.
// This crate deliberately does NOT define (or depend on) that type:
// the onion treats the drop as opaque bytes, and the drop's shape is
// the chat layer's contract. (The pre-chunk-cutover
// `OnionDeliverPayload` wrapper lived here; deleted with the cutover,
// docs/CHAT-SHARE-CHUNKING.md.)

/// The result of peeling one layer — what a relay does next.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum OnionHop {
	/// Intermediate hop: forward `inner` to the node whose ed25519
	/// identity is `next_hop` (a raw ed25519 pubkey; the node layer
	/// maps it to a peer to reach).
	Forward { next_hop: [u8; 32], inner: OnionPacket },
	/// Last hop: hand `drop` (the depadded, opaque drop bytes — the
	/// chat layer's `PreparedBatch` encoding) to the recipient path.
	Deliver { drop: Vec<u8> },
}

/// Errors from building or processing an onion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionError {
	/// A relay's node identity has an ed25519 pubkey that is not a valid
	/// Edwards point, so no seal key can be derived for it.
	UnaddressableRelay,
	/// AEAD auth failed peeling a layer: tampering, wrong relay key, or
	/// a layer presented to the wrong hop.
	Seal(UnsealError),
	/// A layer decrypted but did not decode as an [`OnionHop`].
	BadEncoding,
	/// The `Deliver` drop is larger than [`FIXED_DROP_SIZE`] permits, or
	/// the padding length prefix is impossible.
	BadPadding,
	/// `wrap_onion` was called with an empty relay path.
	EmptyPath,
}

impl From<UnsealError> for OnionError {
	fn from(e: UnsealError) -> Self {
		OnionError::Seal(e)
	}
}

/// Wrap `drop_bytes` into a nested onion for `path` (the ordered relay
/// identities, e.g. `[guard, relay2]`). The returned packet is sealed
/// to `path[0]` — what the sender presents to the first relay.
///
/// The innermost layer is a [`OnionHop::Deliver`] sealed to the last
/// relay; each preceding relay gets a [`OnionHop::Forward`] pointing at
/// the relay whose layer it wraps.
pub fn wrap_onion<R>(
	path: &[NodeIdentity],
	drop_bytes: &[u8],
	rng: &mut R,
) -> Result<OnionPacket, OnionError>
where
	R: rand_core::RngCore + rand_core::CryptoRng,
{
	let (&last, prefix) = path.split_last().ok_or(OnionError::EmptyPath)?;

	// Innermost: Deliver{ padded drop } sealed to the last relay.
	let mut padded = pad_drop(drop_bytes)?;
	let mut packet = seal_to(&last, &OnionHop::Deliver { drop: padded.clone() }.encode(), rng)?;
	padded.zeroize();

	// Wrap outward: each preceding relay forwards to the one inside it.
	let mut next_hop = last.ed25519_pubkey();
	for relay in prefix.iter().rev() {
		let hop = OnionHop::Forward { next_hop, inner: packet };
		packet = seal_to(relay, &hop.encode(), rng)?;
		next_hop = relay.ed25519_pubkey();
	}
	Ok(packet)
}

/// Process one hop: peel the layer sealed to this node and return what
/// to do next. The node acts on the variant — [`OnionHop::Forward`]:
/// send `inner` to `next_hop`; [`OnionHop::Deliver`]: inject `drop`.
///
/// State-free and uniform: the same call works whether this node is the
/// guard, an intermediate, or the last relay.
pub fn process_hop(
	node_secret: &NodeSecret,
	packet: &OnionPacket,
) -> Result<OnionHop, OnionError> {
	let plaintext = unseal(&node_secret.seal_secret(), packet)?;
	let mut hop = OnionHop::decode(&mut &plaintext[..]).map_err(|_| OnionError::BadEncoding)?;
	// Depad a Deliver's drop before handing it back.
	if let OnionHop::Deliver { drop } = &mut hop {
		*drop = unpad_drop(drop)?;
	}
	Ok(hop)
}

/// Seal `bytes` to a relay's node identity (its XEdDSA-derived X25519
/// seal key).
fn seal_to<R>(
	relay: &NodeIdentity,
	bytes: &[u8],
	rng: &mut R,
) -> Result<OnionPacket, OnionError>
where
	R: rand_core::RngCore + rand_core::CryptoRng,
{
	let seal_pub = relay.seal_pubkey().ok_or(OnionError::UnaddressableRelay)?;
	Ok(seal(&seal_pub, bytes, rng))
}

/// Pad to `FIXED_DROP_SIZE`: `[len: u32 LE][drop][zeros]`.
fn pad_drop(drop: &[u8]) -> Result<Vec<u8>, OnionError> {
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

	fn rng() -> ChaCha20Rng {
		ChaCha20Rng::seed_from_u64(0x04)
	}

	fn node(seed_byte: u8) -> NodeSecret {
		NodeSecret::from_seed([seed_byte; 32])
	}

	#[test]
	fn two_hop_path_forwards_then_delivers() {
		let guard = node(1);
		let relay2 = node(2);
		let path = [guard.identity(), relay2.identity()];
		let drop = b"the SealedEnvelope + bucket routing relay-2 injects";

		let packet = wrap_onion(&path, drop, &mut rng()).unwrap();

		// Guard peels → Forward to relay-2.
		match process_hop(&guard, &packet).unwrap() {
			OnionHop::Forward { next_hop, inner } => {
				assert_eq!(next_hop, relay2.identity().ed25519_pubkey(), "forwards to relay-2");
				// Relay-2 peels the inner → Deliver the drop.
				match process_hop(&relay2, &inner).unwrap() {
					OnionHop::Deliver { drop: recovered } => assert_eq!(recovered, drop),
					OnionHop::Forward { .. } => panic!("relay-2 should deliver, not forward"),
				}
			}
			OnionHop::Deliver { .. } => panic!("guard should forward, not deliver"),
		}
	}

	#[test]
	fn guard_cannot_read_the_delivered_drop() {
		// The guard only ever obtains the Forward layer; the inner is
		// sealed to relay-2, so the guard's own key cannot open it.
		let guard = node(1);
		let relay2 = node(2);
		let path = [guard.identity(), relay2.identity()];
		let packet = wrap_onion(&path, b"destination secret", &mut rng()).unwrap();
		let inner = match process_hop(&guard, &packet).unwrap() {
			OnionHop::Forward { inner, .. } => inner,
			_ => panic!(),
		};
		// Guard tries its own secret on the inner → fails.
		assert!(matches!(process_hop(&guard, &inner), Err(OnionError::Seal(_))));
	}

	#[test]
	fn single_hop_path_delivers_directly() {
		let only = node(5);
		let packet = wrap_onion(&[only.identity()], b"direct", &mut rng()).unwrap();
		match process_hop(&only, &packet).unwrap() {
			OnionHop::Deliver { drop } => assert_eq!(drop, b"direct"),
			_ => panic!("single-relay path delivers"),
		}
	}

	#[test]
	fn three_hop_path_chains() {
		let a = node(10);
		let b = node(11);
		let c = node(12);
		let path = [a.identity(), b.identity(), c.identity()];
		let packet = wrap_onion(&path, b"deep", &mut rng()).unwrap();

		let p2 = match process_hop(&a, &packet).unwrap() {
			OnionHop::Forward { next_hop, inner } => {
				assert_eq!(next_hop, b.identity().ed25519_pubkey());
				inner
			}
			_ => panic!(),
		};
		let p3 = match process_hop(&b, &p2).unwrap() {
			OnionHop::Forward { next_hop, inner } => {
				assert_eq!(next_hop, c.identity().ed25519_pubkey());
				inner
			}
			_ => panic!(),
		};
		match process_hop(&c, &p3).unwrap() {
			OnionHop::Deliver { drop } => assert_eq!(drop, b"deep"),
			_ => panic!(),
		}
	}

	#[test]
	fn wrong_node_rejected() {
		let guard = node(1);
		let relay2 = node(2);
		let impostor = node(9);
		let packet =
			wrap_onion(&[guard.identity(), relay2.identity()], b"x", &mut rng()).unwrap();
		assert!(matches!(process_hop(&impostor, &packet), Err(OnionError::Seal(_))));
	}

	#[test]
	fn tampered_packet_rejected() {
		let guard = node(1);
		let relay2 = node(2);
		let mut packet =
			wrap_onion(&[guard.identity(), relay2.identity()], b"x", &mut rng()).unwrap();
		packet.ciphertext[0] ^= 1;
		assert!(matches!(process_hop(&guard, &packet), Err(OnionError::Seal(_))));
	}

	#[test]
	fn padding_makes_packets_fixed_size() {
		let path = [node(1).identity(), node(2).identity()];
		let short = wrap_onion(&path, b"hi", &mut rng()).unwrap();
		let long = wrap_onion(&path, &[0xAB; 1500], &mut rng()).unwrap();
		// Different drop lengths → identical on-wire ciphertext length
		// (padded at the Deliver layer; nesting overhead is fixed).
		assert_eq!(short.ciphertext.len(), long.ciphertext.len());
	}

	#[test]
	fn oversize_drop_rejected() {
		let path = [node(1).identity(), node(2).identity()];
		let too_big = alloc::vec![0u8; FIXED_DROP_SIZE]; // + 4-byte prefix overflows
		assert_eq!(wrap_onion(&path, &too_big, &mut rng()), Err(OnionError::BadPadding));
	}

	#[test]
	fn empty_path_rejected() {
		assert_eq!(wrap_onion(&[], b"x", &mut rng()), Err(OnionError::EmptyPath));
	}

	#[test]
	fn empty_drop_roundtrips() {
		let guard = node(1);
		let relay2 = node(2);
		let packet =
			wrap_onion(&[guard.identity(), relay2.identity()], b"", &mut rng()).unwrap();
		let inner = match process_hop(&guard, &packet).unwrap() {
			OnionHop::Forward { inner, .. } => inner,
			_ => panic!(),
		};
		match process_hop(&relay2, &inner).unwrap() {
			OnionHop::Deliver { drop } => assert_eq!(drop, b""),
			_ => panic!(),
		}
	}
}
