// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-node-identity — a node's identity is its ed25519 key
//!
//! Design **choice A** (see `docs/NODE-IDENTITY.md`): a node does not
//! get a separate identity/onion key. Its identity **is** its libp2p
//! ed25519 node key — the public half embedded in its peer id. That one
//! key serves all four faces the quarantine gate + chat onion need:
//!
//! | Face | Mechanism |
//! |---|---|
//! | Gate resolution | the owner registers this pubkey (peer id) under their canonical name; the gate reverse-looks-up the connecting peer id |
//! | Proof of possession | free — the libp2p Noise handshake already proved the node holds this key |
//! | Non-repudiation | [`NodeSecret::sign`] / [`NodeIdentity::verify`] |
//! | Addressability | [`NodeIdentity::seal_pubkey`] / [`NodeSecret::seal_secret`] — XEdDSA convert-once to X25519 for ECDH sealing |
//!
//! The conversion is the **XEdDSA** "convert once" pattern (Signal):
//! ed25519 lives on the Edwards form of Curve25519, X25519 on the
//! Montgomery form, and the map is canonical and bijective. This crate
//! reimplements the standard conversion (RFC 7748 §5 clamp for the
//! secret, Edwards→Montgomery for the public) rather than depending on
//! the chat layer, so foundational consumers (the validator gate) don't
//! pull in chat crates — and a dev-only cross-check test pins the output
//! byte-identical to `rostro-chat-primitives::identity_key`.
//!
//! ## Boundary
//!
//! This crate works on **raw ed25519 pubkey bytes** (`[u8; 32]`).
//! Peer-id encode/decode stays at the node, where libp2p already lives;
//! a libp2p ed25519 peer id embeds exactly these 32 bytes.

#![cfg_attr(not(feature = "std"), no_std)]

use zeroize::Zeroize;

/// A node's public identity: its ed25519 verification key (the 32 bytes
/// a libp2p ed25519 peer id embeds, and what the owner registers under
/// their canonical name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeIdentity {
	ed25519_pub: [u8; 32],
}

impl NodeIdentity {
	/// Wrap the node's raw ed25519 public key.
	pub fn from_ed25519_pubkey(ed25519_pub: [u8; 32]) -> Self {
		Self { ed25519_pub }
	}

	/// The raw ed25519 public key (≡ the bytes a libp2p ed25519 peer id
	/// embeds; the value registered in the validator attribute).
	pub fn ed25519_pubkey(&self) -> [u8; 32] {
		self.ed25519_pub
	}

	/// The X25519 public key to **seal to** when addressing an onion
	/// layer (or any sealed-sender ciphertext) to this node. `None` if
	/// the ed25519 bytes don't decode as a valid Edwards point.
	pub fn seal_pubkey(&self) -> Option<[u8; 32]> {
		ed25519_pub_to_x25519(&self.ed25519_pub)
	}

	/// Verify a node signature over `msg` for non-repudiation.
	pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> bool {
		let vk = match ed25519_zebra::VerificationKey::try_from(self.ed25519_pub) {
			Ok(vk) => vk,
			Err(_) => return false,
		};
		let sig = ed25519_zebra::Signature::from(*signature);
		vk.verify(&sig, msg).is_ok()
	}
}

/// A node's secret half: the ed25519 node-key seed. Zeroized on drop.
/// On a running node this is the libp2p node key's secret; in tests it
/// is any 32-byte seed.
pub struct NodeSecret {
	seed: [u8; 32],
}

impl NodeSecret {
	/// Wrap the node's ed25519 seed (the libp2p node-key secret).
	pub fn from_seed(seed: [u8; 32]) -> Self {
		Self { seed }
	}

	/// The public identity derived from this secret.
	pub fn identity(&self) -> NodeIdentity {
		let signing = ed25519_zebra::SigningKey::from(self.seed);
		let vk: [u8; 32] = ed25519_zebra::VerificationKey::from(&signing).into();
		NodeIdentity::from_ed25519_pubkey(vk)
	}

	/// Sign `msg` with the node key (non-repudiation).
	pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
		let signing = ed25519_zebra::SigningKey::from(self.seed);
		let sig: ed25519_zebra::Signature = signing.sign(msg);
		sig.into()
	}

	/// The X25519 secret to **unseal** onion layers (sealed-sender
	/// ciphertexts) addressed to this node's identity. Pairs with
	/// [`NodeIdentity::seal_pubkey`] by the XEdDSA invariant.
	pub fn seal_secret(&self) -> [u8; 32] {
		ed25519_seed_to_x25519_secret(&self.seed)
	}
}

impl Drop for NodeSecret {
	fn drop(&mut self) {
		self.seed.zeroize();
	}
}

/// Edwards→Montgomery: ed25519 public key → X25519 public key.
/// `None` if the bytes are not a valid Edwards point.
fn ed25519_pub_to_x25519(ed25519_pub: &[u8; 32]) -> Option<[u8; 32]> {
	let compressed = curve25519_dalek::edwards::CompressedEdwardsY(*ed25519_pub);
	let edwards = compressed.decompress()?;
	Some(edwards.to_montgomery().to_bytes())
}

/// Ed25519 seed → X25519 static secret (RFC 7748 §5 clamp of the first
/// 32 bytes of SHA-512(seed)). Pairs with [`ed25519_pub_to_x25519`].
fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> [u8; 32] {
	use sha2::{Digest, Sha512};
	let hash = Sha512::digest(seed);
	let mut secret = [0u8; 32];
	secret.copy_from_slice(&hash[..32]);
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
	secret
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_chacha::rand_core::SeedableRng;
	use rostro_chat_sealed_sender::{seal, unseal, SealedOutput};
	use x25519_dalek::{PublicKey as XPub, StaticSecret as XSecret};

	fn node(seed_byte: u8) -> NodeSecret {
		NodeSecret::from_seed([seed_byte; 32])
	}

	#[test]
	fn identity_round_trips_from_secret() {
		let n = node(0x11);
		let id = n.identity();
		// The identity's ed25519 pubkey is the node key's vk.
		let signing = ed25519_zebra::SigningKey::from([0x11u8; 32]);
		let vk: [u8; 32] = ed25519_zebra::VerificationKey::from(&signing).into();
		assert_eq!(id.ed25519_pubkey(), vk);
	}

	#[test]
	fn sign_verify_non_repudiation() {
		let n = node(0x22);
		let id = n.identity();
		let msg = b"bucket-introduction response: peer P in bucket 47";
		let sig = n.sign(msg);
		assert!(id.verify(msg, &sig), "node's own signature verifies");
		// Tampered message fails.
		assert!(!id.verify(b"a different claim", &sig));
		// A different node's identity does not verify this signature.
		assert!(!node(0x23).identity().verify(msg, &sig));
	}

	#[test]
	fn seal_pubkey_and_secret_pair() {
		// XEdDSA invariant: the X25519 pubkey from the identity and the
		// X25519 secret from the node secret form one keypair.
		let n = node(0x33);
		let pub_from_id = n.identity().seal_pubkey().expect("valid point");
		let pub_from_secret = *XPub::from(&XSecret::from(n.seal_secret())).as_bytes();
		assert_eq!(pub_from_id, pub_from_secret);
	}

	#[test]
	fn node_receives_onion_layer_sealed_to_its_identity() {
		// The end-to-end property the onion needs: a sender who only
		// knows the node's REGISTERED ed25519 pubkey can seal to it, and
		// the node unseals with the secret derived from its node key.
		let n = node(0x44);
		let registered_pubkey = n.identity().ed25519_pubkey(); // what the client reads from canonical state
		let seal_to = NodeIdentity::from_ed25519_pubkey(registered_pubkey)
			.seal_pubkey()
			.expect("valid point");

		let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
		let sealed: SealedOutput = seal(&seal_to, b"inner onion blob", &mut rng);

		let recovered = unseal(&n.seal_secret(), &sealed).expect("node unseals");
		assert_eq!(recovered, b"inner onion blob");
	}

	#[test]
	fn wrong_node_cannot_unseal() {
		let recipient = node(0x44);
		let seal_to = recipient.identity().seal_pubkey().unwrap();
		let mut rng = rand_chacha::ChaCha20Rng::from_seed([8u8; 32]);
		let sealed = seal(&seal_to, b"secret", &mut rng);
		// A different node's seal secret must not open it.
		assert!(unseal(&node(0x45).seal_secret(), &sealed).is_err());
	}

	#[test]
	fn conversion_byte_identical_to_chat_primitives() {
		// Pin: this crate's conversion must match the chat layer's
		// exactly, or seals would silently fail to interoperate.
		use rostro_chat_primitives::identity_key::{
			ed25519_seed_to_x25519_secret as chat_secret,
			ed25519_to_x25519_pubkey as chat_pubkey,
		};
		for b in [0x01u8, 0x42, 0x99, 0xFE] {
			let seed = [b; 32];
			let n = NodeSecret::from_seed(seed);
			assert_eq!(
				n.seal_secret(),
				chat_secret(&seed),
				"secret conversion diverged from chat-primitives",
			);
			let ed = n.identity().ed25519_pubkey();
			assert_eq!(
				n.identity().seal_pubkey(),
				chat_pubkey(&ed),
				"pubkey conversion diverged from chat-primitives",
			);
		}
	}
}
