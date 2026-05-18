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

use codec::{Decode, Encode};
use rand_core::{OsRng, RngCore};
use rc_network::{service::traits::NetworkService, types::ProtocolName, IfDisconnected, PeerId};
use rostro_chat_ephemeral_store::EphemeralShareStore;
use rostro_chat_primitives::{
	descriptor::{
		BlockNumber, MessageId, PickupKey, RelayPubkey, ShareDescriptor, ShareIndex,
	},
	envelope::{sign_inner, EnvelopeKind, SealedEnvelope, UnsealedInner},
	fetch_protocol::{FetchRequest, FetchResponse},
	identity_key::{ed25519_seed_to_x25519_secret, ed25519_to_x25519_pubkey},
	store_protocol::ShareStore as _,
	stripe::{combine_xor, split_xor},
	verify::{mac_share, verify_sender, ShareMacTag},
};
use rostro_chat_sealed_sender::{seal as ss_seal, unseal as ss_unseal, SealedOutput};

use crate::chat_fetch_protocol::CHAT_FETCH_PROTOCOL_NAME;

/// Number of XOR-stripe shares emitted per chat_send. v0.1 fixes
/// this; future versions may take it as a parameter for tuning
/// the confidentiality/availability trade-off.
pub const SEND_TOTAL_SHARES: usize = 5;

/// Decode a 64-character hex string into 32 raw bytes.
fn decode_hex32(hex: &str) -> Result<[u8; 32], String> {
	let bytes = hex::decode(hex).map_err(|e| format!("invalid hex: {e}"))?;
	if bytes.len() != 32 {
		return Err(format!("expected 32 bytes, got {}", bytes.len()));
	}
	let mut out = [0u8; 32];
	out.copy_from_slice(&bytes);
	Ok(out)
}

/// Parse a libp2p `PeerId` from a multibase string (the standard
/// `12D3KooW...` form) — same encoding `PeerId::to_string()`
/// produces.
fn parse_peer_id(s: &str) -> Result<PeerId, String> {
	use std::str::FromStr;
	PeerId::from_str(s).map_err(|e| format!("invalid PeerId '{s}': {e}"))
}

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

/// JSON-RPC response shape for `chat_send`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatSendResult {
	/// Hex-encoded `MessageId` (32 random bytes) generated for this
	/// send. The recipient's `chat_fetch` returns the same value so
	/// clients can correlate.
	pub message_id_hex: String,
	/// Number of XOR-stripe shares the sender split the envelope
	/// into. v0.1 fixes this at [`SEND_TOTAL_SHARES`].
	pub share_count: u32,
	/// Recipient's domain-separated pickup key (hex). Useful for
	/// demo scripts that want to verify the recipient queries
	/// under the right key.
	pub recipient_pickup_key_hex: String,
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

	/// Send a chat message addressed to a single recipient.
	///
	/// `recipient_chat_pubkey_hex` is the recipient's 32-byte Ed25519
	/// chat identity pubkey, hex-encoded (64 chars). For v0.1
	/// demos with single-user-per-node topology, this is the
	/// recipient's libp2p Ed25519 node-identity key (per the
	/// chat-identity-separate-from-chain memo, real users will
	/// register a dedicated chat identity once that path is wired).
	///
	/// `message` is the plaintext to send. v0.1 ships the bytes
	/// verbatim inside `UnsealedInner.inner_ciphertext` — no DR
	/// pairwise wrapper yet, just sealed-sender-protected
	/// transport. Recipients see the same UTF-8 string back.
	///
	/// v0.1 deposit policy: the resulting XOR-stripe shares are
	/// stored in THIS node's local share store, keyed by the
	/// recipient's pickup key. The recipient's gemini-node fetches
	/// them via `/rostro/chat-fetch/1` (inbound libp2p protocol,
	/// already wired in Phase B6). Multi-node sender→remote-relay
	/// ship lands in C2d.
	#[method(name = "chat_send")]
	fn send(
		&self,
		recipient_chat_pubkey_hex: String,
		message: String,
	) -> RpcResult<ChatSendResult>;

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
	///   * Skips per-share MAC verification (no per-message
	///     session key derivation yet); relies on the
	///     sealed-sender AEAD to authenticate the full envelope.
	///   * Pairwise messages only — group (MLS) messages decrypt
	///     differently and land in a follow-up.
	///
	/// `relay_peer_id_hex` is optional. When `None`, the method
	/// reads only from this node's local share store (same
	/// behavior as Phase C2b). When `Some(peer_id)`, the method
	/// ALSO queries the named remote relay via the outbound
	/// `/rostro/chat-fetch/1` libp2p request and merges the
	/// returned shares with the local view before decrypting.
	/// Use this to fetch messages from a sender's node in the
	/// 2+3 demo topology.
	#[method(name = "chat_fetch")]
	async fn fetch(
		&self,
		relay_peer_id_hex: Option<String>,
	) -> RpcResult<Vec<ChatFetchedMessage>>;
}

/// Concrete implementation backed by an Ed25519 identity pubkey +
/// seed + an `Arc<EphemeralShareStore>` + an `Arc<dyn NetworkService>`
/// for outbound remote-relay fetches. The implementation is
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
	network: Arc<dyn NetworkService>,
}

impl ChatRpc {
	/// Construct from the running node's libp2p Ed25519 identity
	/// pubkey + seed + the shared share-store + the network handle.
	pub fn new(
		identity_pubkey_ed25519: [u8; 32],
		identity_seed_ed25519: [u8; 32],
		share_store: Arc<EphemeralShareStore>,
		network: Arc<dyn NetworkService>,
	) -> Self {
		Self { identity_pubkey_ed25519, identity_seed_ed25519, share_store, network }
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

	fn send(
		&self,
		recipient_chat_pubkey_hex: String,
		message: String,
	) -> RpcResult<ChatSendResult> {
		// ── decode + sanity-check inputs ──────────────────────────
		let recipient_ed25519: [u8; 32] = decode_hex32(&recipient_chat_pubkey_hex)
			.map_err(|e| {
				ErrorObject::owned::<()>(
					-32602,
					format!("recipient_chat_pubkey_hex: {e}"),
					None,
				)
			})?;
		let recipient_x25519 =
			ed25519_to_x25519_pubkey(&recipient_ed25519).ok_or_else(|| {
				ErrorObject::owned::<()>(
					-32602,
					"recipient_chat_pubkey_hex doesn't decode as a valid Edwards \
					 point — cannot derive X25519 for sealed-sender ECDH",
					None,
				)
			})?;
		let recipient_pickup = PickupKey::for_pairwise(&recipient_x25519);

		if self.identity_seed_ed25519 == [0u8; 32] {
			return Err(ErrorObject::owned::<()>(
				-32001,
				"node has no persistent chat identity (libp2p node key was \
				 fresh-per-run). Set --node-key or --node-key-file.",
				None,
			));
		}
		let signing_key =
			ed25519_zebra::SigningKey::from(self.identity_seed_ed25519);

		// ── build the inner-layer payload ─────────────────────────
		// v0.1 = plaintext bytes verbatim. A future DR pairwise
		// wrapper would replace this with a DR WireMessage.
		let inner_ciphertext = message.into_bytes();

		// Fresh per-send MessageId. 256-bit random — no collision
		// check needed at this width.
		let message_id = {
			let mut bytes = [0u8; 32];
			OsRng.fill_bytes(&mut bytes);
			MessageId(bytes)
		};

		let unsealed = sign_inner(inner_ciphertext, &message_id, &signing_key);
		let unsealed_encoded = unsealed.encode();

		// ── sealed-sender outer layer ─────────────────────────────
		let mut send_rng = OsRng;
		let sealed = ss_seal(&recipient_x25519, &unsealed_encoded, &mut send_rng);

		// ── outer envelope ────────────────────────────────────────
		let envelope = SealedEnvelope {
			kind: EnvelopeKind::Pairwise,
			outer_ciphertext: sealed.ciphertext,
			ephemeral_pubkey: sealed.ephemeral_pub,
			message_id,
		};
		let envelope_encoded = envelope.encode();

		// ── XOR-stripe + per-share MAC + descriptors ──────────────
		let shares = split_xor(&envelope_encoded, SEND_TOTAL_SHARES, &mut send_rng)
			.map_err(|e| {
				ErrorObject::owned::<()>(
					-32000,
					format!("split_xor failed: {e:?}"),
					None,
				)
			})?;

		// v0.1 uses a zero MAC key (per-message session-secret
		// derivation lands with the DR wrapper). The MAC is
		// computed-but-not-verified at fetch time — recipients
		// rely on the sealed-sender AEAD to authenticate the full
		// envelope.
		let mac_key = [0u8; 32];

		let total_shares_u8 = SEND_TOTAL_SHARES as u8;
		for (i, share_bytes) in shares.into_iter().enumerate() {
			let share_index = i as ShareIndex;
			let mac_tag = mac_share(&mac_key, &share_bytes, share_index);
			let descriptor = ShareDescriptor {
				relay_pubkey: RelayPubkey(self.identity_pubkey_ed25519),
				message_id,
				share_index,
				total_shares: total_shares_u8,
				pickup_key: recipient_pickup,
				// Effectively no-expire for v0.1 demo: u32::MAX
				// blocks. The TTL-sweep wiring + a HeaderBackend
				// handle for current_block landings as a follow-up.
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
			share_count: SEND_TOTAL_SHARES as u32,
			recipient_pickup_key_hex: hex::encode(recipient_pickup.0),
		})
	}

	fn fetch<'life0, 'async_trait>(
		&'life0 self,
		relay_peer_id_hex: Option<String>,
	) -> core::pin::Pin<
		std::boxed::Box<
			dyn core::future::Future<Output = RpcResult<Vec<ChatFetchedMessage>>>
				+ core::marker::Send
				+ 'async_trait,
		>,
	>
	where
		'life0: 'async_trait,
		Self: 'async_trait,
	{
		let identity_pubkey_ed25519 = self.identity_pubkey_ed25519;
		let identity_seed_ed25519 = self.identity_seed_ed25519;
		let share_store = self.share_store.clone();
		let network = self.network.clone();
		std::boxed::Box::pin(async move {
		// Derive our pickup key from our X25519 identity pubkey
		// (pairwise domain) and our X25519 identity secret from
		// our Ed25519 seed (XEdDSA).
		let my_x25519_pubkey =
			ed25519_to_x25519_pubkey(&identity_pubkey_ed25519).ok_or_else(|| {
				ErrorObject::owned::<()>(
					-32001,
					"node's Ed25519 identity pubkey doesn't decode as a valid \
					 Edwards point — cannot derive X25519 or pickup key",
					None,
				)
			})?;
		let my_pickup = PickupKey::for_pairwise(&my_x25519_pubkey);
		let my_x25519_secret_bytes =
			ed25519_seed_to_x25519_secret(&identity_seed_ed25519);

		// Collect (descriptor, bytes, mac) triples from local
		// store first.
		let mut matched: Vec<(ShareDescriptor, Vec<u8>, ShareMacTag)> =
			share_store.get_by_pickup_key(&my_pickup);

		// If a remote relay was specified, fan out to it and merge
		// its returned shares with the local view.
		if let Some(hex_peer) = relay_peer_id_hex {
			let peer = parse_peer_id(&hex_peer).map_err(|e| {
				ErrorObject::owned::<()>(
					-32602,
					format!("relay_peer_id_hex: {e}"),
					None,
				)
			})?;
			let request = FetchRequest { pickup_key: my_pickup };
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
							matched.push((fs.descriptor, fs.share_bytes, fs.mac_tag));
						}
					} else {
						log::warn!(
							target: "rostro-chat-rpc",
							"chat_fetch: remote relay {peer} returned malformed \
							 FetchResponse — local view only",
						);
					}
				},
				Err(e) => {
					log::warn!(
						target: "rostro-chat-rpc",
						"chat_fetch: remote relay {peer} request failed: {e:?} \
						 — falling back to local view",
					);
				},
			}
		}

		// Group by message_id so we can reconstruct complete
		// N-of-N stripe sets per message. Dedupe (message_id,
		// share_index) pairs in case the same share is present in
		// both the local view and the remote response.
		type Group = Vec<(u8, Vec<u8>, u8)>;
		let mut by_message: HashMap<MessageId, Group> = HashMap::new();
		let mut seen: std::collections::HashSet<(MessageId, u8)> =
			std::collections::HashSet::new();
		for (desc, bytes, _mac) in matched {
			let key = (desc.message_id, desc.share_index);
			if !seen.insert(key) {
				continue;
			}
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
		})
	}
}
