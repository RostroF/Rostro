// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! JSON-RPC surface for the chat layer.
//!
//! Phase C2 (refactored). The gemini-node is a **routing/storage
//! relay** for the chat layer — it never holds user chat-identity
//! secrets and never sees user plaintext. End-user mobile apps
//! (or test-harness CLIs) do all the chat-crypto on-device:
//!
//! - Build + sign + sealed-sender-encrypt the envelope locally
//! - Stripe-split it locally (the node does the stripe so the
//!   client RPC stays a single call — this is the only "trust the
//!   sender's own node" step in the design)
//! - Hand the encoded SealedEnvelope to the node via `chat_send_envelope`
//! - On the recipient side, query the node via `chat_fetch_shares`,
//!   reconstruct + unseal + verify ALL on-device
//!
//! The node sees:
//!   - The OUTER envelope's public fields (kind, ephemeral_pubkey,
//!     message_id) — required for routing + recipient pickup-key
//!     derivation
//!   - Opaque `outer_ciphertext` bytes (Sealed Sender AEAD output)
//!   - Pickup keys (hashes — bind to recipient pubkey but don't
//!     reveal who actually owns them)
//!
//! The node never sees:
//!   - User chat-identity Ed25519 signing keys (those stay
//!     on-device)
//!   - User chat-identity X25519 secrets (those stay on-device)
//!   - Plaintext message bodies
//!   - The inner `UnsealedInner` structure (encrypted inside the
//!     outer envelope)
//!
//! This matches the Signal architecture principle: "the server can
//! route encrypted messages but can't read them" — even if the
//! gemini-node is compromised, the attacker sees only ciphertext
//! and routing metadata.
//!
//! ## Methods
//!
//! - `chat_nodeInfo` — diagnostic; returns this node's libp2p
//!   PeerId + Ed25519 pubkey. Demo scripts use the PeerId to
//!   target a specific node as a relay.
//! - `chat_localStoreLen` — diagnostic; number of share entries
//!   the node currently holds.
//! - `chat_send_envelope(recipient_chat_pubkey_hex, envelope_hex, total_shares)`
//!   — accept a pre-built SealedEnvelope (encrypted on the
//!   sender's device), XOR-stripe it into `total_shares` shares,
//!   MAC each share, deposit to the local share store keyed by
//!   the recipient's derived pickup_key.
//! - `chat_fetch_shares(pickup_key_hex, relay_peer_id_hex?)` —
//!   return raw ciphertext shares matching the given pickup_key.
//!   When `relay_peer_id_hex` is set, ALSO query that remote
//!   node via `/rostro/chat-fetch/1` and merge results.

use jsonrpsee::{
	core::RpcResult,
	proc_macros::rpc,
	types::error::ErrorObject,
};
use std::sync::Arc;

use codec::{Decode, Encode};
use rand_core::{OsRng, RngCore};
use rc_network::{service::traits::NetworkService, types::ProtocolName, IfDisconnected, PeerId};
use rostro_chat_ephemeral_store::EphemeralShareStore;
use rostro_chat_primitives::{
	descriptor::{
		BlockNumber, MessageId, PickupKey, RelayPubkey, ShareDescriptor, ShareIndex,
	},
	envelope::{EnvelopeKind, SealedEnvelope},
	fetch_protocol::{FetchRequest, FetchResponse},
	identity_key::ed25519_to_x25519_pubkey,
	store_protocol::ShareStore as _,
	stripe::{split_xor, MAX_SHARES},
	verify::mac_share,
};

use crate::chat_fetch_protocol::CHAT_FETCH_PROTOCOL_NAME;

/// Default number of XOR-stripe shares per send. Clients can override.
pub const DEFAULT_TOTAL_SHARES: usize = 5;

/// JSON-RPC response for `chat_nodeInfo`. Diagnostic — tells demo
/// scripts where this node lives for routing.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatNodeInfo {
	/// Hex-encoded Ed25519 libp2p node-identity pubkey (32 bytes).
	/// PeerId derives from this; same bytes show up as the
	/// `relay_pubkey` field of share descriptors this node mints.
	pub node_pubkey_ed25519_hex: String,
}

/// JSON-RPC response for `chat_send_envelope`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatSendResult {
	/// Hex-encoded MessageId extracted from the SealedEnvelope the
	/// client supplied. Returned so clients can correlate
	/// successful sends with their own outgoing-message logs.
	pub message_id_hex: String,
	/// Number of shares the node split the envelope into.
	pub share_count: u32,
	/// Recipient's domain-separated pickup key (hex). Useful for
	/// scripts verifying that fetch uses the same key.
	pub recipient_pickup_key_hex: String,
}

/// JSON-RPC response: a single share descriptor flattened to
/// hex-encoded fields.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatShareDescriptorRpc {
	pub relay_pubkey_hex: String,
	pub message_id_hex: String,
	pub share_index: u8,
	pub total_shares: u8,
	pub pickup_key_hex: String,
	pub expires_at_block: u32,
}

/// JSON-RPC response: one stored share returned by `chat_fetch_shares`.
/// The client uses these to reconstruct messages locally:
///
/// 1. Group by `descriptor.message_id_hex`
/// 2. When all `total_shares` are present, XOR-combine `share_bytes_hex`
/// 3. SCALE-decode the result as `SealedEnvelope`
/// 4. Sealed-sender-unseal with the recipient's X25519 secret
/// 5. SCALE-decode `UnsealedInner` and verify the sender signature
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatFetchedShareRaw {
	pub descriptor: ChatShareDescriptorRpc,
	pub share_bytes_hex: String,
	pub mac_tag_hex: String,
}

/// JSON-RPC trait for the chat surface.
#[rpc(client, server)]
pub trait ChatRpcApi {
	/// Diagnostic: return this node's identity for routing
	/// purposes.
	#[method(name = "chat_nodeInfo")]
	fn node_info(&self) -> RpcResult<ChatNodeInfo>;

	/// Diagnostic: number of share entries currently held in
	/// this node's local share store.
	#[method(name = "chat_localStoreLen")]
	fn local_store_len(&self) -> RpcResult<u64>;

	/// Accept a pre-built, pre-sealed SealedEnvelope from a client,
	/// XOR-stripe-split it into `total_shares` shares, MAC each
	/// share, deposit to the local share store keyed by the
	/// recipient's derived pickup key.
	///
	/// Parameters:
	///   * `recipient_chat_pubkey_hex` — recipient's 32-byte
	///     Ed25519 chat-identity pubkey, hex-encoded. Used to
	///     derive the pickup key for share-store indexing.
	///   * `envelope_hex` — SCALE-encoded `SealedEnvelope` bytes,
	///     hex-encoded. The client built + signed + sealed this
	///     on-device; the node treats `outer_ciphertext` as opaque.
	///   * `total_shares` — number of XOR-stripe shares. Range
	///     [2, MAX_SHARES]. Defaults to [`DEFAULT_TOTAL_SHARES`]
	///     when 0 is passed.
	#[method(name = "chat_send_envelope")]
	fn send_envelope(
		&self,
		recipient_chat_pubkey_hex: String,
		envelope_hex: String,
		total_shares: u8,
	) -> RpcResult<ChatSendResult>;

	/// Return raw share descriptors + ciphertext bytes for shares
	/// stored under the given pickup key. The client reconstructs
	/// + decrypts on-device.
	///
	/// Parameters:
	///   * `pickup_key_hex` — recipient's 32-byte domain-separated
	///     pickup key (hex). The recipient computes this locally:
	///     `PickupKey::for_pairwise(&recipient_x25519_pubkey)`.
	///   * `relay_peer_id_hex` — optional libp2p PeerId of a remote
	///     relay to also query via outbound `/rostro/chat-fetch/1`.
	///     When set, the node merges the remote response with its
	///     local view.
	#[method(name = "chat_fetch_shares")]
	fn fetch_shares<'life0, 'async_trait>(
		&'life0 self,
		pickup_key_hex: String,
		relay_peer_id_hex: Option<String>,
	) -> core::pin::Pin<
		Box<
			dyn core::future::Future<Output = RpcResult<Vec<ChatFetchedShareRaw>>>
				+ core::marker::Send
				+ 'async_trait,
		>,
	>
	where
		'life0: 'async_trait,
		Self: 'async_trait;
}

/// Concrete implementation. Holds only the node's PUBLIC libp2p
/// identity pubkey (for routing diagnostics + share descriptors
/// the node mints as a relay) + handles to the share store and the
/// networking service. Does NOT hold any user chat-identity
/// secret — those live on user devices.
pub struct ChatRpc {
	node_pubkey_ed25519: [u8; 32],
	share_store: Arc<EphemeralShareStore>,
	network: Arc<dyn NetworkService>,
}

impl ChatRpc {
	pub fn new(
		node_pubkey_ed25519: [u8; 32],
		share_store: Arc<EphemeralShareStore>,
		network: Arc<dyn NetworkService>,
	) -> Self {
		Self { node_pubkey_ed25519, share_store, network }
	}
}

impl ChatRpcApiServer for ChatRpc {
	fn node_info(&self) -> RpcResult<ChatNodeInfo> {
		Ok(ChatNodeInfo {
			node_pubkey_ed25519_hex: hex::encode(self.node_pubkey_ed25519),
		})
	}

	fn local_store_len(&self) -> RpcResult<u64> {
		Ok(self.share_store.len() as u64)
	}

	fn send_envelope(
		&self,
		recipient_chat_pubkey_hex: String,
		envelope_hex: String,
		total_shares: u8,
	) -> RpcResult<ChatSendResult> {
		// Decode + sanity-check inputs.
		let recipient_ed25519 = decode_hex32(&recipient_chat_pubkey_hex)
			.map_err(|e| invalid_param("recipient_chat_pubkey_hex", &e))?;
		let recipient_x25519 =
			ed25519_to_x25519_pubkey(&recipient_ed25519).ok_or_else(|| {
				ErrorObject::owned::<()>(
					-32602,
					"recipient_chat_pubkey_hex doesn't decode as a valid \
					 Edwards point — cannot derive pickup key",
					None,
				)
			})?;
		let recipient_pickup = PickupKey::for_pairwise(&recipient_x25519);

		let envelope_bytes = hex::decode(envelope_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("envelope_hex", &format!("invalid hex: {e}")))?;
		let envelope = SealedEnvelope::decode(&mut &envelope_bytes[..]).map_err(|e| {
			invalid_param("envelope_hex", &format!("SCALE-decode failed: {e}"))
		})?;

		// v0.1 ships pairwise only; group flows take a different path.
		if !matches!(envelope.kind, EnvelopeKind::Pairwise) {
			return Err(invalid_param(
				"envelope_hex",
				"only Pairwise envelopes are supported in v0.1",
			));
		}

		let n_shares = if total_shares == 0 {
			DEFAULT_TOTAL_SHARES
		} else {
			let n = total_shares as usize;
			if n < 2 || n > MAX_SHARES {
				return Err(invalid_param(
					"total_shares",
					&format!("must be 0 (default) or in [2, {MAX_SHARES}]"),
				));
			}
			n
		};

		// Stripe-split the encoded envelope.
		let encoded = envelope.encode();
		let message_id = envelope.message_id;
		let mut rng = OsRng;
		let shares = split_xor(&encoded, n_shares, &mut rng).map_err(|e| {
			ErrorObject::owned::<()>(-32000, format!("split_xor failed: {e:?}"), None)
		})?;

		// MAC each share with the v0.1 zero key (per-message
		// session-secret derivation lands with the DR pairwise
		// wrapper — this is the same placeholder chat_send used).
		let mac_key = [0u8; 32];
		let total_u8 = n_shares as u8;
		for (i, share_bytes) in shares.into_iter().enumerate() {
			let share_index = i as ShareIndex;
			let mac_tag = mac_share(&mac_key, &share_bytes, share_index);
			let descriptor = ShareDescriptor {
				relay_pubkey: RelayPubkey(self.node_pubkey_ed25519),
				message_id,
				share_index,
				total_shares: total_u8,
				pickup_key: recipient_pickup,
				// v0.1: no TTL (u32::MAX). Block-anchored TTL is a
				// follow-up.
				expires_at_block: BlockNumber::MAX,
			};
			self.share_store
				.insert(descriptor, share_bytes, mac_tag)
				.map_err(|e| {
					ErrorObject::owned::<()>(
						-32000,
						format!("local share-store insert failed: {e:?}"),
						None,
					)
				})?;
		}

		Ok(ChatSendResult {
			message_id_hex: hex::encode(message_id.0),
			share_count: n_shares as u32,
			recipient_pickup_key_hex: hex::encode(recipient_pickup.0),
		})
	}

	fn fetch_shares<'life0, 'async_trait>(
		&'life0 self,
		pickup_key_hex: String,
		relay_peer_id_hex: Option<String>,
	) -> core::pin::Pin<
		Box<
			dyn core::future::Future<Output = RpcResult<Vec<ChatFetchedShareRaw>>>
				+ core::marker::Send
				+ 'async_trait,
		>,
	>
	where
		'life0: 'async_trait,
		Self: 'async_trait,
	{
		let share_store = self.share_store.clone();
		let network = self.network.clone();
		Box::pin(async move {
			let pickup_bytes = decode_hex32(&pickup_key_hex)
				.map_err(|e| invalid_param("pickup_key_hex", &e))?;
			let pickup = PickupKey(pickup_bytes);

			// Local store first.
			let mut matched = share_store.get_by_pickup_key(&pickup);

			// Remote relay (optional).
			if let Some(hex_peer) = relay_peer_id_hex {
				let peer = parse_peer_id(&hex_peer)
					.map_err(|e| invalid_param("relay_peer_id_hex", &e))?;
				let request = FetchRequest { pickup_key: pickup };
				let request_bytes = request.encode();
				match network
					.request(
						peer,
						ProtocolName::from(CHAT_FETCH_PROTOCOL_NAME),
						request_bytes,
						None,
						IfDisconnected::TryConnect,
					)
					.await
				{
					Ok((resp_bytes, _)) => {
						if let Ok(resp) = FetchResponse::decode(&mut &resp_bytes[..]) {
							for fs in resp.shares {
								matched.push((
									fs.descriptor,
									fs.share_bytes,
									fs.mac_tag,
								));
							}
						} else {
							log::warn!(
								target: "rostro-chat-rpc",
								"chat_fetch_shares: relay {peer} returned malformed \
								 FetchResponse — local view only",
							);
						}
					},
					Err(e) => {
						log::warn!(
							target: "rostro-chat-rpc",
							"chat_fetch_shares: relay {peer} request failed: {e:?} \
							 — falling back to local view",
						);
					},
				}
			}

			// Dedupe (message_id, share_index) pairs that show up
			// both locally and remotely.
			let mut seen: std::collections::HashSet<(MessageId, u8)> =
				std::collections::HashSet::new();
			let mut out: Vec<ChatFetchedShareRaw> = Vec::new();
			for (descriptor, share_bytes, mac_tag) in matched {
				let key = (descriptor.message_id, descriptor.share_index);
				if !seen.insert(key) {
					continue;
				}
				out.push(ChatFetchedShareRaw {
					descriptor: ChatShareDescriptorRpc {
						relay_pubkey_hex: hex::encode(descriptor.relay_pubkey.0),
						message_id_hex: hex::encode(descriptor.message_id.0),
						share_index: descriptor.share_index,
						total_shares: descriptor.total_shares,
						pickup_key_hex: hex::encode(descriptor.pickup_key.0),
						expires_at_block: descriptor.expires_at_block,
					},
					share_bytes_hex: hex::encode(&share_bytes),
					mac_tag_hex: hex::encode(mac_tag),
				});
			}
			// Stable ordering for determinism.
			out.sort_by(|a, b| {
				(a.descriptor.message_id_hex.as_str(), a.descriptor.share_index).cmp(&(
					b.descriptor.message_id_hex.as_str(),
					b.descriptor.share_index,
				))
			});
			Ok(out)
		})
	}
}

/// Decode a 64-character hex string (optionally `0x`-prefixed) into
/// 32 raw bytes.
fn decode_hex32(hex_str: &str) -> Result<[u8; 32], String> {
	let s = hex_str.trim_start_matches("0x");
	let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
	if bytes.len() != 32 {
		return Err(format!("expected 32 bytes, got {}", bytes.len()));
	}
	let mut out = [0u8; 32];
	out.copy_from_slice(&bytes);
	Ok(out)
}

/// Parse a libp2p `PeerId` from its multibase string form
/// (`12D3KooW...`).
fn parse_peer_id(s: &str) -> Result<PeerId, String> {
	use std::str::FromStr;
	PeerId::from_str(s).map_err(|e| format!("invalid PeerId '{s}': {e}"))
}

fn invalid_param(name: &str, why: &str) -> ErrorObject<'static> {
	ErrorObject::owned::<()>(-32602, format!("{name}: {why}"), None)
}

// Suppress unused warning on RngCore when total_shares branch
// uses split_xor path only; OsRng is imported for the RNG itself.
const _: fn() = || {
	let mut r = OsRng;
	let mut buf = [0u8; 4];
	r.fill_bytes(&mut buf);
};
