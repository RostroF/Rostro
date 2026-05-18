// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! JSON-RPC surface for the chat layer.
//!
//! Phase C2a of the MLS-chat plan. Adds the `chat_*` JSON-RPC
//! namespace exposed by every gemini-node. v0.1 surface is purely
//! diagnostic — enough for the demo scripts to introspect a
//! running node's chat identity + pickup key without the full
//! send/fetch logic, which lands in C2b/c.
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
use std::sync::Arc;

use rostro_chat_ephemeral_store::EphemeralShareStore;
use rostro_chat_primitives::{
	descriptor::PickupKey,
	identity_key::ed25519_to_x25519_pubkey,
	store_protocol::ShareStore as _,
};

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
}

/// Concrete implementation backed by an Ed25519 identity pubkey
/// snapshot + an `Arc<EphemeralShareStore>`. The implementation is
/// `Send + Sync` so jsonrpsee can serve concurrent requests.
pub struct ChatRpc {
	identity_pubkey_ed25519: [u8; 32],
	share_store: Arc<EphemeralShareStore>,
}

impl ChatRpc {
	/// Construct from the running node's libp2p Ed25519 identity
	/// pubkey + the shared share-store.
	pub fn new(
		identity_pubkey_ed25519: [u8; 32],
		share_store: Arc<EphemeralShareStore>,
	) -> Self {
		Self { identity_pubkey_ed25519, share_store }
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
}
