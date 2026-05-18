// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! JSON-RPC surface for the chat layer.
//!
//! Phase C2a/C2b of the MLS-chat plan. Adds the `chat_*` JSON-RPC
//! namespace exposed by every gemini-node.
//!
//! ## v0.1 chat-identity assumption (single-user-per-node)
//!
//! This module uses the running node's **libp2p Ed25519
//! node-identity key** as if it were the user's chat identity.
//! That works cleanly when each demo node is run by one user
//! (charlie's node, dave's node — one user each) but is
//! structurally wrong for production: a real user's chain
//! identity (SS58) can be Sr25519 (Polkadot wallet), secp256k1
//! (Ethereum/EVM wallet), or Ed25519 (Solana wallet) per the BTOW
//! multi-scheme design — none of which is the same as the libp2p
//! node-identity Ed25519 key. Chat identity is intentionally
//! Ed25519-only (X25519 conversion via XEdDSA needs an Edwards
//! key) and must be registered separately from the chain
//! identity. See the `chat-identity-separate-from-chain` memory
//! for the architectural detail.
//!
//! Follow-up step plumbs in a dedicated chat-identity keystore
//! entry + RNS chat-pubkey record so multi-scheme chain identities
//! work cleanly. v0.1 demo accepts the single-user-per-node
//! limitation.
//!
//! The methods here run on the same JSON-RPC server the node uses
//! for system/transaction-payment RPC. CLI clients (subxt, curl,
//! a small dedicated binary) talk to the node via this surface
//! instead of poking at libp2p directly.
//!
//! ## Methods
//!
//! - `chat_myIdentity` — returns this node's libp2p Ed25519 pubkey
//!   plus its derived X25519 pubkey (the one Sealed Sender
//!   senders encrypt to). The demo scripts use this to learn each
//!   non-validator's identity for routing.
//! - `chat_myPickupKey` — returns this node's pickup key (the
//!   domain-separated DHT lookup key under which sealed-sender
//!   messages addressed to this node land). Recipients query
//!   relays with this key to retrieve waiting shares.
//! - `chat_localStoreLen` — returns the number of share entries
//!   currently held in this node's `EphemeralShareStore`. Useful
//!   diagnostic for "is there anything waiting for me?".

use jsonrpsee::{
	core::RpcResult,
	proc_macros::rpc,
	types::error::ErrorObject,
};
use std::collections::HashMap;
use std::sync::Arc;

use codec::Decode;
use rostro_chat_ephemeral_store::EphemeralShareStore;
use rostro_chat_primitives::{
	descriptor::{MessageId, PickupKey},
	envelope::{EnvelopeKind, SealedEnvelope, UnsealedInner},
	identity_key::{ed25519_seed_to_x25519_secret, ed25519_to_x25519_pubkey},
	store_protocol::ShareStore as _,
	stripe::combine_xor,
	verify::verify_sender,
};
use rostro_chat_sealed_sender::{unseal as ss_unseal, SealedOutput};

/// JSON-RPC response shape for `chat_myIdentity`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatIdentity {
	/// Hex-encoded Ed25519 libp2p node-identity pubkey (32 bytes).
	pub ed25519_pubkey_hex: String,
	/// Hex-encoded X25519 chat-identity pubkey derived from the
	/// Ed25519 pubkey via Edwards-to-Montgomery conversion.
	/// `None` if the Ed25519 bytes don't decode as a valid Edwards
	/// point (rare in practice).
	pub x25519_pubkey_hex: Option<String>,
}

/// JSON-RPC response shape for `chat_myPickupKey`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatPickupKey {
	/// Hex-encoded 32-byte pickup key. Recipients query the DHT
	/// (or known relays directly) with this to retrieve their
	/// waiting shares.
	pub hex: String,
}

/// One successfully-decrypted chat message returned by `chat_fetch`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatFetchedMessage {
	/// Hex-encoded `MessageId` (32 bytes). Stable per message so
	/// clients can deduplicate across repeated `chat_fetch` calls.
	pub message_id_hex: String,
	/// Hex-encoded verified sender Ed25519 pubkey (32 bytes).
	pub sender_pubkey_hex: String,
	/// Plaintext bytes, hex-encoded. Always present; for human
	/// messages the bytes are typically UTF-8.
	pub plaintext_hex: String,
	/// Plaintext interpreted as UTF-8, if the bytes parse cleanly.
	/// `None` if the inner ciphertext is binary.
	pub plaintext_utf8: Option<String>,
}

/// JSON-RPC trait for the chat-diagnostic surface.
#[rpc(client, server)]
pub trait ChatRpcApi {
	/// Return this node's chat identity (Ed25519 + derived X25519).
	#[method(name = "chat_myIdentity")]
	fn my_identity(&self) -> RpcResult<ChatIdentity>;

	/// Return this node's pickup key — recipients query relays
	/// with this 32-byte value to retrieve their waiting shares.
	#[method(name = "chat_myPickupKey")]
	fn my_pickup_key(&self) -> RpcResult<ChatPickupKey>;

	/// Return the number of share entries currently held in this
	/// node's local share store. Diagnostic.
	#[method(name = "chat_localStoreLen")]
	fn local_store_len(&self) -> RpcResult<u64>;

	/// Return all chat messages currently decryptable for this
	/// node — i.e. shares stored under this node's pickup key that
	/// form a complete N-of-N stripe set and unseal successfully
	/// under this node's X25519 identity secret.
	///
	/// Idempotent: successive calls return the same messages until
	/// the underlying shares expire from the relay's store (block-
	/// anchored TTL). Clients deduplicate by `message_id_hex`.
	///
	/// v0.1 limitations:
	///   * Reads from the LOCAL store only — does not yet fetch
	///     from remote relays over `/rostro/chat-fetch/1`. For
	///     local-node-as-relay demos this is sufficient.
	///   * Skips per-share MAC verification (no per-message
	///     session key derivation yet); relies on the
	///     sealed-sender AEAD to authenticate the full envelope.
	///   * Pairwise messages only — group (MLS) messages decrypt
	///     differently and land in a follow-up.
	#[method(name = "chat_fetch")]
	fn fetch(&self) -> RpcResult<Vec<ChatFetchedMessage>>;
}

/// Concrete implementation backed by an Ed25519 identity pubkey +
/// seed + an `Arc<EphemeralShareStore>`. The implementation is
/// `Send + Sync` so jsonrpsee can serve concurrent requests.
///
/// The seed is held in process memory for the lifetime of the
/// node. v0.1 doesn't zeroize after each use — same exposure
/// surface as the libp2p node-identity key, which is also in
/// process memory throughout the run.
pub struct ChatRpc {
	identity_pubkey_ed25519: [u8; 32],
	identity_seed_ed25519: [u8; 32],
	share_store: Arc<EphemeralShareStore>,
}

impl ChatRpc {
	/// Construct from the running node's libp2p Ed25519 identity
	/// pubkey + seed + the shared share-store.
	pub fn new(
		identity_pubkey_ed25519: [u8; 32],
		identity_seed_ed25519: [u8; 32],
		share_store: Arc<EphemeralShareStore>,
	) -> Self {
		Self { identity_pubkey_ed25519, identity_seed_ed25519, share_store }
	}
}

impl ChatRpcApiServer for ChatRpc {
	fn my_identity(&self) -> RpcResult<ChatIdentity> {
		let ed25519_hex = hex::encode(self.identity_pubkey_ed25519);
		let x25519_hex = ed25519_to_x25519_pubkey(&self.identity_pubkey_ed25519)
			.map(hex::encode);
		Ok(ChatIdentity { ed25519_pubkey_hex: ed25519_hex, x25519_pubkey_hex: x25519_hex })
	}

	fn my_pickup_key(&self) -> RpcResult<ChatPickupKey> {
		// Pickup key is computed from THIS node's X25519 identity
		// pubkey (the same one senders Sealed-Sender-encrypt to).
		// Pairwise pickup-key domain — group messages will surface
		// via a separate group_pickup_key method when MLS groups
		// are wired into the RPC.
		let x25519 = ed25519_to_x25519_pubkey(&self.identity_pubkey_ed25519).ok_or_else(
			|| {
				ErrorObject::owned::<()>(
					-32001,
					"node's Ed25519 identity pubkey doesn't decode as a valid \
					 Edwards point — cannot derive X25519 or pickup key",
					None,
				)
			},
		)?;
		let pickup = PickupKey::for_pairwise(&x25519);
		Ok(ChatPickupKey { hex: hex::encode(pickup.0) })
	}

	fn local_store_len(&self) -> RpcResult<u64> {
		Ok(self.share_store.len() as u64)
	}

	fn fetch(&self) -> RpcResult<Vec<ChatFetchedMessage>> {
		// Derive our pickup key from our X25519 identity pubkey
		// (pairwise domain) and our X25519 identity secret from
		// our Ed25519 seed (XEdDSA).
		let my_x25519_pubkey =
			ed25519_to_x25519_pubkey(&self.identity_pubkey_ed25519).ok_or_else(|| {
				ErrorObject::owned::<()>(
					-32001,
					"node's Ed25519 identity pubkey doesn't decode as a valid \
					 Edwards point — cannot derive X25519 or pickup key",
					None,
				)
			})?;
		let my_pickup = PickupKey::for_pairwise(&my_x25519_pubkey);
		let my_x25519_secret_bytes =
			ed25519_seed_to_x25519_secret(&self.identity_seed_ed25519);

		// Pull every share stored under our pickup key from the
		// local share-store.
		let matched = self.share_store.get_by_pickup_key(&my_pickup);

		// Group by message_id so we can reconstruct complete
		// N-of-N stripe sets per message. The tuple-elements we
		// care about: (share_index, share_bytes, total_shares).
		type Group = Vec<(u8, Vec<u8>, u8)>;
		let mut by_message: HashMap<MessageId, Group> = HashMap::new();
		for (desc, bytes, _mac) in matched {
			by_message.entry(desc.message_id).or_default().push((
				desc.share_index,
				bytes,
				desc.total_shares,
			));
		}

		let mut out: Vec<ChatFetchedMessage> = Vec::new();
		for (message_id, mut shares) in by_message {
			// Skip incomplete sets — we'll surface them on a
			// later fetch when the missing shares arrive.
			let total_shares = match shares.first().map(|(_, _, t)| *t) {
				Some(t) => t,
				None => continue,
			};
			if !shares.iter().all(|(_, _, t)| *t == total_shares) {
				// Inconsistent total_shares across descriptors —
				// drop the message (bogus / spoofed).
				continue;
			}
			if shares.len() != total_shares as usize {
				continue;
			}
			// Sort by share_index for determinism (XOR is
			// order-independent but sorted output is easier to
			// reason about in tests).
			shares.sort_by_key(|(idx, _, _)| *idx);

			let share_byte_refs: Vec<&[u8]> =
				shares.iter().map(|(_, b, _)| b.as_slice()).collect();
			let envelope_bytes = match combine_xor(&share_byte_refs) {
				Ok(b) => b,
				Err(_) => continue, // size mismatch / no shares
			};

			let envelope = match SealedEnvelope::decode(&mut &envelope_bytes[..]) {
				Ok(e) => e,
				Err(_) => continue, // garbled
			};

			// v0.1: pairwise messages only. Group (MLS) decryption
			// is its own path and lands in a follow-up.
			if !matches!(envelope.kind, EnvelopeKind::Pairwise) {
				continue;
			}

			// Sealed-sender-unseal the outer ciphertext using our
			// X25519 identity secret + the envelope's ephemeral
			// pubkey.
			let sealed = SealedOutput {
				ephemeral_pub: envelope.ephemeral_pubkey,
				ciphertext: envelope.outer_ciphertext,
			};
			let unsealed_bytes = match ss_unseal(&my_x25519_secret_bytes, &sealed) {
				Ok(b) => b,
				Err(_) => continue, // not for us / tampered
			};

			let unsealed = match UnsealedInner::decode(&mut &unsealed_bytes[..]) {
				Ok(u) => u,
				Err(_) => continue, // malformed inner
			};

			// Verify the sender's signature against the outer
			// envelope's message_id.
			let verified_sender = match verify_sender(&unsealed, &envelope.message_id) {
				Ok(p) => p,
				Err(_) => continue, // bad signature
			};

			// v0.1 inner ciphertext IS the plaintext (no DR
			// pairwise wrapper yet — that's v1 hardening). The
			// bytes the sender placed in `UnsealedInner.inner_ciphertext`
			// are the human plaintext.
			let plaintext_bytes = unsealed.inner_ciphertext;
			let plaintext_utf8 = std::str::from_utf8(&plaintext_bytes)
				.ok()
				.map(|s| s.to_string());

			out.push(ChatFetchedMessage {
				message_id_hex: hex::encode(message_id.0),
				sender_pubkey_hex: hex::encode(verified_sender),
				plaintext_hex: hex::encode(&plaintext_bytes),
				plaintext_utf8,
			});
		}
		// Stable ordering for determinism.
		out.sort_by(|a, b| a.message_id_hex.cmp(&b.message_id_hex));
		Ok(out)
	}
}
