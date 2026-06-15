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

use async_trait::async_trait;
use jsonrpsee::{
	core::RpcResult,
	proc_macros::rpc,
	types::error::ErrorObject,
};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use codec::{Decode, Encode};
use ed25519_zebra::{Signature as Ed25519Signature, VerificationKey as Ed25519VerificationKey};
use gemini_runtime::{opaque::Block, AccountId};
use rand_core::{OsRng, RngCore};
use rc_network::{service::traits::NetworkService, types::ProtocolName, IfDisconnected, PeerId};
use rostro_chat_ephemeral_store::EphemeralShareStore;
use rostro_chat_primitives::{
	bucket::bucket_for_pickup_key,
	descriptor::{
		MessageId, PickupKey, RelayPubkey, ShareDescriptor, ShareIndex, UnixTimestamp,
		CHAT_TTL_SECONDS,
	},
	envelope::{EnvelopeKind, SealedEnvelope},
	fetch_protocol::{FetchRequest, FetchResponse},
	identity_key::ed25519_to_x25519_pubkey,
	store_protocol::{ShareStore as _, StoreRejection, StoreRequest, StoreResponse},
	stripe::{split_xor, MAX_SHARES},
	verify::mac_share,
};
use rostro_chat_onion::{process_hop, OnionDeliverPayload, OnionHop, OnionPacket};
use rostro_node_identity::NodeSecret;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::blake2_256;
use sp_runtime::SaturatedConversion;
use zk_pki_hip::{verify_hip_proof_against_genesis, verify_hip_proof_internal};
use zk_pki_primitives::hip::CanonicalHipProof;
use zk_pki_primitives::runtime_api::{CertState as RpcCertState, ZkPkiApi};

use crate::chat_bucket_cache::BucketCache;
use crate::chat_onion_forward_protocol::{
	onion_forward_digest, OnionForwardRequest, OnionForwardResponse,
	CHAT_ONION_FORWARD_PROTOCOL_NAME, RELAY_UNAVAILABLE_CODE,
};
use crate::chat_stripe_protocol::CHAT_STRIPE_PROTOCOL_NAME;

/// Local-clock helper. Returns the host's current Unix timestamp in
/// seconds. Used to stamp `expires_at_unix_ts` on outbound share
/// descriptors and to drive store-side TTL sweeps. Falls back to 0
/// only if the system clock is set before 1970 (which fails the
/// expiry-bounds checks downstream — caller will see rejections,
/// which is the right operational signal).
fn now_unix_seconds() -> UnixTimestamp {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Domain-separation tag for the chat-auth challenge signed by the
/// caller's HW-attested device key. The signed message is:
///
///     blake2_256(CHAT_AUTH_DOMAIN || envelope_bytes || timestamp_be_bytes)
///
/// Binding both `envelope_bytes` and `timestamp_be_bytes` prevents
/// (a) replay of the signature with a different envelope and
/// (b) replay of the signature later (subject to the
/// `CHAT_AUTH_TIMESTAMP_WINDOW_SECS` skew check at the receiver).
pub const CHAT_AUTH_DOMAIN: &[u8] = b"rostro/chat/auth/v1";

/// Maximum allowed skew between the client-provided
/// `auth_timestamp_secs` and the node's local clock. Outside this
/// window the auth is rejected. 600 seconds accommodates ordinary
/// NTP drift + transport latency without leaving room for stale
/// replays.
pub const CHAT_AUTH_TIMESTAMP_WINDOW_SECS: u64 = 600;

// ── Chat-auth session handshake (node-local HIP session) ────────────
//
// One biometric+HIP handshake establishes a node-local, time-bounded
// session; drops within it ride a cheap software session key (Tier 4).
// See docs/DOTWAVE-CHAT-AUTH-CEREMONY.md.

/// Domain tag for the session-handshake nonce. Distinct from
/// `CHAT_AUTH_DOMAIN` (the per-drop signature domain) so a signature
/// from one context can never be replayed in the other.
pub const CHAT_SESSION_NONCE_DOMAIN: &[u8] = b"rostro/chat/session-nonce/v1";

/// Domain tag for a per-drop session-key signature. Within a live session
/// the client's software session key signs `blake2_256(this ‖ drop_bytes)`;
/// the node verifies against the session's stored `session_pubkey`. Cheap —
/// no secure-element crossing, no HIP (the handshake already proved those).
/// Distinct domain from the handshake nonce and the cert-auth digest.
pub const CHAT_SESSION_DROP_DOMAIN: &[u8] = b"rostro/chat/session-drop/v1";

/// Maximum age, in blocks, of the handshake's anchor block. The HIP
/// proof's nonce is derived from a recent block hash; an anchor older
/// than this is rejected so a captured proof can't be replayed
/// indefinitely. ~10 blocks ≈ 60 s at 6 s/block.
pub const CHAT_SESSION_ANCHOR_WINDOW_BLOCKS: u32 = 10;

/// Session lifetime W — the device-health half-life. 4 days. Enforced on
/// the node's MONOTONIC clock as a HARD cap: activity does NOT extend it;
/// at expiry the client must re-handshake (a fresh biometric+HIP).
pub const CHAT_SESSION_TTL_SECS: u64 = 4 * 24 * 60 * 60; // 345_600

/// Backstop cap on concurrent in-RAM sessions (eviction = soonest-to-expire).
const MAX_SESSIONS: usize = 100_000;

/// Derive the block-anchored handshake nonce the client bakes into its
/// HIP attestation challenge. Binds the proof to a recent block
/// (freshness), the cert (`cert_thumbprint`), THIS guard node
/// (`guard_node_id` — no cross-node replay), and the client's
/// `session_pubkey` (authorizing exactly that session key — an attacker
/// can't swap in their own key without invalidating the nonce, and can't
/// regenerate the proof without the biometric-gated HW key). Node and
/// client compute it identically from public inputs; it is never stored.
fn derive_session_nonce(
	anchor_block_hash: &[u8; 32],
	cert_thumbprint: &[u8; 32],
	guard_node_id: &[u8; 32],
	session_pubkey: &[u8; 32],
) -> [u8; 32] {
	let mut buf = Vec::with_capacity(CHAT_SESSION_NONCE_DOMAIN.len() + 32 * 4);
	buf.extend_from_slice(CHAT_SESSION_NONCE_DOMAIN);
	buf.extend_from_slice(anchor_block_hash);
	buf.extend_from_slice(cert_thumbprint);
	buf.extend_from_slice(guard_node_id);
	buf.extend_from_slice(session_pubkey);
	blake2_256(&buf)
}

/// A node-local authenticated chat session. Admits drops from
/// `bound_account` signed by `session_pubkey` until `expires_at`
/// (monotonic). Hard cap — not extended by activity.
#[derive(Clone)]
struct ChatSession {
	bound_account: AccountId,
	session_pubkey: [u8; 32],
	expires_at: Instant,
}

/// In-RAM session store keyed by cert thumbprint. Ephemeral — a node
/// restart drops all sessions (clients re-handshake). Bounded by
/// [`MAX_SESSIONS`] with soonest-to-expire eviction.
#[derive(Default)]
struct SessionStore {
	by_thumbprint: HashMap<[u8; 32], ChatSession>,
}

impl SessionStore {
	/// Record (or refresh) a session, sweeping expired entries first and
	/// evicting the soonest-to-expire if at capacity.
	fn insert(&mut self, thumbprint: [u8; 32], session: ChatSession, now: Instant) {
		self.by_thumbprint.retain(|_, s| s.expires_at > now);
		if self.by_thumbprint.len() >= MAX_SESSIONS
			&& !self.by_thumbprint.contains_key(&thumbprint)
		{
			if let Some((&victim, _)) =
				self.by_thumbprint.iter().min_by_key(|(_, s)| s.expires_at)
			{
				self.by_thumbprint.remove(&victim);
			}
		}
		self.by_thumbprint.insert(thumbprint, session);
	}

	/// Fetch a live (non-expired) session for `thumbprint`, or `None`.
	/// The Tier-4 per-drop admission path (`verify_session_drop`).
	fn get_live(&self, thumbprint: &[u8; 32], now: Instant) -> Option<ChatSession> {
		self.by_thumbprint
			.get(thumbprint)
			.filter(|s| s.expires_at > now)
			.cloned()
	}
}

use crate::chat_fetch_protocol::CHAT_FETCH_PROTOCOL_NAME;

/// Default number of XOR-stripe shares per send. Clients can override.
pub const DEFAULT_TOTAL_SHARES: usize = 5;

/// Replication factor for push gossip: each shard is pushed to up
/// to this many bucket-subscribed peers. If fewer than
/// `REPLICATION_FACTOR` peers subscribe to the message's bucket,
/// push goes to whoever's available (degraded redundancy logged).
/// If zero peers subscribe, the send is rejected
/// (old-tenant-mail behavior — there's nowhere to deliver).
pub const REPLICATION_FACTOR: usize = 5;

/// Maximum number of bucket peers to query when `chat_fetch_shares`
/// hits a local-store miss and needs to fall back to the network.
/// Each query is an outbound `/rostro/chat-fetch/1` request to a
/// peer subscribed to the message's pickup-key bucket. The first
/// few peers are typically enough to assemble (one bucket peer
/// usually holds the full replicated set after a push).
pub const MAX_FALLBACK_FETCH_PEERS: usize = 3;

/// JSON-RPC response for `chat_nodeInfo`. Diagnostic — tells demo
/// scripts where this node lives for routing.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatNodeInfo {
	/// Hex-encoded Ed25519 libp2p node-identity pubkey (32 bytes).
	/// PeerId derives from this; same bytes show up as the
	/// `relay_pubkey` field of share descriptors this node mints.
	pub node_pubkey_ed25519_hex: String,
}

/// JSON-RPC response for `chat_mySubscription`. Lets operators +
/// scenario scripts read the local node's current bucket
/// subscription bitmap + version.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatMySubscription {
	/// 64-character hex string of the 32-byte bitmap.
	pub bitmap_hex: String,
	/// Number of buckets currently subscribed to (popcount of
	/// bitmap).
	pub bucket_count: u32,
	/// Monotonic version counter. Bumps on every local subscription
	/// change (rebalance, operator override). Peers cache by
	/// version to reject older replays.
	pub version: u32,
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
	pub expires_at_unix_ts: u64,
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

/// JSON-RPC response for `chat_authenticate` — the session handshake.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatAuthenticateResult {
	/// Hex of the 32-byte account the cert is bound to (the authenticated
	/// identity). The client compares it against its own account's raw bytes.
	pub bound_account_hex: String,
	/// Wall-clock Unix seconds at which the session expires, for the client
	/// to schedule a proactive re-handshake. The node ENFORCES on its own
	/// monotonic clock; this is the client-facing estimate.
	pub expiry_unix_secs: u64,
	/// Session lifetime W in seconds (device-health half-life).
	pub session_ttl_secs: u64,
}

/// JSON-RPC trait for the chat surface.
#[rpc(client, server)]
pub trait ChatRpcApi {
	/// Diagnostic: return this node's identity for routing
	/// purposes.
	#[method(name = "chat_nodeInfo")]
	fn node_info(&self) -> RpcResult<ChatNodeInfo>;

	/// Diagnostic: return this node's current bucket subscription
	/// state. Used by scenario scripts to verify rebalance behavior
	/// and by operators to inspect what the node carries.
	#[method(name = "chat_mySubscription")]
	fn my_subscription(&self) -> RpcResult<ChatMySubscription>;

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
	///   * `auth_cert_thumbprint_hex` — caller's zkpki cert
	///     thumbprint (32 bytes, hex). Identifies the cert whose
	///     HW-attested device key signed `auth_sig_hex`.
	///   * `auth_timestamp_secs` — caller's local Unix-seconds
	///     timestamp at signing. Must be within
	///     [`CHAT_AUTH_TIMESTAMP_WINDOW_SECS`] of the node's clock.
	///   * `auth_sig_hex` — signature over
	///     `blake2_256(CHAT_AUTH_DOMAIN || envelope_bytes ||
	///     auth_timestamp_be_bytes)` produced by the cert's
	///     hardware-attested device key.
	///
	/// All three auth-* parameters are required together. The node
	/// looks up the cert via the zkpki runtime API, requires
	/// `cert_state == Active`, verifies the signature against the
	/// cert's stored `device_pubkey`, and uses `cert.bound_account`
	/// as the authenticated requestor identity for any downstream
	/// rate-limiting / abuse-tracking. Any auth failure rejects
	/// the request.
	///
	/// The three auth-* parameters remain `Option<String>` for wire
	/// compatibility, but absence is REJECTED (Phase 2 cert-gated
	/// send): there is no unauthenticated path. Every drop must carry
	/// a valid signature under an Active zkpki cert.
	#[method(name = "chat_send_envelope")]
	async fn send_envelope(
		&self,
		recipient_chat_pubkey_hex: String,
		envelope_hex: String,
		total_shares: u8,
		auth_cert_thumbprint_hex: Option<String>,
		auth_timestamp_secs: Option<u64>,
		auth_sig_hex: Option<String>,
	) -> RpcResult<ChatSendResult>;

	/// Submit an **onion-wrapped** send (Phase 4, network-origin
	/// anonymity). The node peels the one layer addressed to it — using
	/// its own node key in the isolated peeler, never in the secret-free
	/// routing layer — and then either:
	///   * `Deliver` → injects the recipient-sealed envelope into the
	///     normal stripe-and-distribute path (this node is the last hop;
	///     the sender is already gone), or
	///   * `Forward` → hands the inner blob to the next hop (slice 2).
	///
	/// Cert-auth (Phase 2) is verified over the onion packet bytes — the
	/// sender signs the packet it presents to this guard.
	///
	/// Parameters:
	///   * `onion_packet_hex` — the SCALE-encoded `OnionPacket` sealed to
	///     this node's identity (hex).
	///   * `total_shares` — stripe count for the eventual distribution.
	///   * `auth_*` — full per-drop cert auth (the renewal/fallback path).
	///   * `session_cert_thumbprint_hex` + `session_sig_hex` — the cheap
	///     session path: within a live session (established via
	///     `chat_authenticate`), the drop is admitted by an Ed25519
	///     session-key signature over the onion packet, with no
	///     secure-element crossing. Preferred when present; the node falls
	///     back to full cert auth otherwise. (Trailing `Option`s keep this
	///     wire-compatible with pre-session callers.)
	#[method(name = "chat_send_onion")]
	async fn send_onion(
		&self,
		onion_packet_hex: String,
		total_shares: u8,
		auth_cert_thumbprint_hex: Option<String>,
		auth_timestamp_secs: Option<u64>,
		auth_sig_hex: Option<String>,
		session_cert_thumbprint_hex: Option<String>,
		session_sig_hex: Option<String>,
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
	async fn fetch_shares(
		&self,
		pickup_key_hex: String,
		relay_peer_id_hex: Option<String>,
	) -> RpcResult<Vec<ChatFetchedShareRaw>>;

	/// Establish a node-local authenticated session (the chat-auth
	/// ceremony). The client proves, in one biometric-gated crossing, that
	/// it holds an Active HW-attested cert on a healthy device, and
	/// authorizes a cheap software session key for subsequent drops — so the
	/// secure element is NOT touched per message.
	///
	/// Parameters:
	///   * `cert_thumbprint_hex` — the caller's zkpki cert (32 bytes, hex).
	///   * `hip_proof_hex` — SCALE-encoded `CanonicalHipProof` (StrongBox /
	///     TPM2), with the session nonce baked into its attestation
	///     challenge.
	///   * `anchor_block_number` — the recent block the nonce is anchored to.
	///   * `session_pubkey_hex` — the client's software session Ed25519
	///     pubkey (32 bytes, hex) to authorize for this session.
	///
	/// The node derives the expected nonce
	/// (`H(domain ‖ anchor_block_hash ‖ thumbprint ‖ guard_node_id ‖
	/// session_pubkey)`), checks the anchor block is recent, requires the
	/// cert `Active`, verifies the HIP against the cert's enrolled
	/// `genesis_fingerprint` (drift detection; internal-consistency-only
	/// fallback for dev-stub certs with no genesis), and on success records
	/// the session for W = [`CHAT_SESSION_TTL_SECS`] on its monotonic clock.
	#[method(name = "chat_authenticate")]
	async fn authenticate(
		&self,
		cert_thumbprint_hex: String,
		hip_proof_hex: String,
		anchor_block_number: u64,
		session_pubkey_hex: String,
	) -> RpcResult<ChatAuthenticateResult>;
}

/// Concrete implementation. Holds only the node's PUBLIC libp2p
/// identity pubkey (for routing diagnostics + share descriptors
/// the node mints as a relay) + handles to the share store, the
/// networking service, the chain client (for the zkpki
/// runtime-API auth lookup), and the bucket cache (for push-gossip
/// peer selection). Does NOT hold any user chat-identity
/// secret — those live on user devices.
pub struct ChatRpc<C> {
	node_pubkey_ed25519: [u8; 32],
	/// This node's OWN onion peel context, present iff a persistent
	/// libp2p key is configured. Holds the node-key identity (for the
	/// isolated peeler) plus the routing handles the `Deliver` path
	/// needs. Not a user secret; never touches gossipsub. Same shape the
	/// (slice-2) `/rostro/chat-onion-forward/1` handler uses on relay-2.
	onion_ctx: Option<OnionPeelCtx>,
	share_store: Arc<EphemeralShareStore>,
	network: Arc<dyn NetworkService>,
	client: Arc<C>,
	bucket_cache: BucketCache,
	/// Optional: present iff this node has a chat-gossip
	/// `LocalSubscriptionState` (= has a persistent libp2p
	/// identity key). `chat_mySubscription` returns an empty
	/// snapshot when None.
	local_subscription:
		Option<crate::chat_gossip_protocol::LocalSubscriptionState>,
	/// Node-local authenticated chat sessions (the chat-auth ceremony).
	/// In-RAM, ephemeral; keyed by cert thumbprint. A node restart drops
	/// all sessions and clients re-handshake.
	sessions: Arc<Mutex<SessionStore>>,
	_block: PhantomData<Block>,
}

impl<C> ChatRpc<C>
where
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: ZkPkiApi<Block, AccountId>,
{
	pub fn new(
		node_pubkey_ed25519: [u8; 32],
		node_seed: Option<[u8; 32]>,
		share_store: Arc<EphemeralShareStore>,
		network: Arc<dyn NetworkService>,
		client: Arc<C>,
		bucket_cache: BucketCache,
		local_subscription: Option<
			crate::chat_gossip_protocol::LocalSubscriptionState,
		>,
	) -> Self {
		let onion_ctx = node_seed.map(|seed| {
			OnionPeelCtx::new(
				seed,
				node_pubkey_ed25519,
				bucket_cache.clone(),
				network.clone(),
			)
		});
		Self {
			node_pubkey_ed25519,
			onion_ctx,
			share_store,
			network,
			client,
			bucket_cache,
			local_subscription,
			sessions: Arc::new(Mutex::new(SessionStore::default())),
			_block: PhantomData,
		}
	}

	/// Verify a caller's chat-auth credentials against the zkpki
	/// runtime API. Returns the authenticated `AccountId` on
	/// success or a structured error on any failure.
	fn verify_chat_auth(
		&self,
		envelope_bytes: &[u8],
		thumbprint_hex: &str,
		timestamp_secs: u64,
		sig_hex: &str,
	) -> Result<AccountId, ErrorObject<'static>> {
		// 1. Timestamp window check (rejects stale replays).
		let now = now_unix_seconds();
		let skew = if now > timestamp_secs {
			now - timestamp_secs
		} else {
			timestamp_secs - now
		};
		if skew > CHAT_AUTH_TIMESTAMP_WINDOW_SECS {
			return Err(ErrorObject::owned::<()>(
				-32000,
				format!(
					"chat-auth timestamp out of window: skew {skew}s > \
					 {CHAT_AUTH_TIMESTAMP_WINDOW_SECS}s",
				),
				None,
			));
		}

		// 2. Decode thumbprint + signature hex.
		let thumbprint = decode_hex32(thumbprint_hex)
			.map_err(|e| invalid_param("auth_cert_thumbprint_hex", &e))?;
		let sig_bytes = hex::decode(sig_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("auth_sig_hex", &format!("invalid hex: {e}")))?;

		// 3. Runtime API lookup: cert authentication info.
		let best = self.client.info().best_hash;
		let info = self
			.client
			.runtime_api()
			.cert_authentication(best, thumbprint)
			.map_err(|e| {
				ErrorObject::owned::<()>(
					-32000,
					format!("zkpki runtime API call failed: {e:?}"),
					None,
				)
			})?
			.ok_or_else(|| {
				ErrorObject::owned::<()>(
					-32000,
					"chat-auth cert not found (purged or never existed)",
					None,
				)
			})?;

		// 4. Cert must be Active.
		if !matches!(info.cert_state, RpcCertState::Active) {
			return Err(ErrorObject::owned::<()>(
				-32000,
				format!(
					"chat-auth cert is not Active (state: {:?})",
					info.cert_state,
				),
				None,
			));
		}

		// 5. Reconstruct the signed message + verify against the
		//    cert's HW-attested device pubkey.
		let mut to_sign = Vec::with_capacity(
			CHAT_AUTH_DOMAIN.len() + envelope_bytes.len() + 8,
		);
		to_sign.extend_from_slice(CHAT_AUTH_DOMAIN);
		to_sign.extend_from_slice(envelope_bytes);
		to_sign.extend_from_slice(&timestamp_secs.to_be_bytes());
		let digest = blake2_256(&to_sign);
		if !info.device_pubkey.verify_signature(&digest, &sig_bytes) {
			return Err(ErrorObject::owned::<()>(
				-32000,
				"chat-auth signature verification failed",
				None,
			));
		}

		Ok(info.bound_account)
	}

	/// The chat-auth session handshake (the ceremony). Verifies a fresh
	/// HW-attested HIP proof bound to a block-anchored, guard- and
	/// session-key-bound nonce, requires the cert Active, and records a
	/// node-local session valid for W. Sync (all runtime-API calls are
	/// blocking); the async trait method just wraps it.
	fn do_authenticate(
		&self,
		cert_thumbprint_hex: &str,
		hip_proof_hex: &str,
		anchor_block_number: u64,
		session_pubkey_hex: &str,
	) -> Result<ChatAuthenticateResult, ErrorObject<'static>> {
		// 1. Decode inputs.
		let thumbprint = decode_hex32(cert_thumbprint_hex)
			.map_err(|e| invalid_param("cert_thumbprint_hex", &e))?;
		let session_pubkey = decode_hex32(session_pubkey_hex)
			.map_err(|e| invalid_param("session_pubkey_hex", &e))?;
		let hip_bytes = hex::decode(hip_proof_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("hip_proof_hex", &format!("invalid hex: {e}")))?;
		let proof = CanonicalHipProof::decode(&mut &hip_bytes[..]).map_err(|e| {
			invalid_param("hip_proof_hex", &format!("decode CanonicalHipProof: {e}"))
		})?;

		// 2. Anchor block must be recent in OUR own chain view.
		let info = self.client.info();
		let best_number: u32 = info.best_number.saturated_into::<u32>();
		let anchor: u32 = u32::try_from(anchor_block_number)
			.map_err(|_| invalid_param("anchor_block_number", "exceeds u32 block range"))?;
		if anchor > best_number {
			return Err(auth_err("anchor block is in the future"));
		}
		if best_number - anchor > CHAT_SESSION_ANCHOR_WINDOW_BLOCKS {
			return Err(auth_err(&format!(
				"anchor block too old: {} behind best > window {}",
				best_number - anchor,
				CHAT_SESSION_ANCHOR_WINDOW_BLOCKS,
			)));
		}
		let anchor_hash = self
			.client
			.hash(anchor)
			.map_err(|e| auth_err(&format!("anchor block hash lookup failed: {e}")))?
			.ok_or_else(|| auth_err("anchor block not found"))?;
		let anchor_hash32: [u8; 32] = anchor_hash
			.as_ref()
			.try_into()
			.map_err(|_| auth_err("anchor block hash is not 32 bytes"))?;

		// 3. The nonce the HIP proof must be bound to (block + cert + this
		//    guard + the session key being authorized).
		let expected_nonce = derive_session_nonce(
			&anchor_hash32,
			&thumbprint,
			&self.node_pubkey_ed25519,
			&session_pubkey,
		);

		// 4. Cert must exist + be Active.
		let best = info.best_hash;
		let cert = self
			.client
			.runtime_api()
			.cert_authentication(best, thumbprint)
			.map_err(|e| auth_err(&format!("zkpki runtime API failed: {e:?}")))?
			.ok_or_else(|| auth_err("cert not found (purged or never existed)"))?;
		if !matches!(cert.cert_state, RpcCertState::Active) {
			return Err(auth_err(&format!(
				"cert is not Active (state: {:?})",
				cert.cert_state
			)));
		}

		// 5. HIP: drift detection vs the cert's enrolled genesis if present
		//    (production mime-wrap / TPM2 cert); internal-consistency-only
		//    fallback for a dev-stub cert with no genesis (the nonce is NOT
		//    bound in that path — dev degradation, never production).
		let genesis = self
			.client
			.runtime_api()
			.cert_hip_genesis(best, thumbprint)
			.map_err(|e| auth_err(&format!("zkpki runtime API failed: {e:?}")))?;
		let report = match &genesis {
			Some(g) => verify_hip_proof_against_genesis(&proof, g, &expected_nonce)
				.map_err(|e| auth_err(&format!("HIP drift verification failed: {e:?}")))?,
			None => verify_hip_proof_internal(&proof)
				.map_err(|e| auth_err(&format!("HIP internal verification failed: {e:?}")))?,
		};
		if !report.secure_boot_intact {
			return Err(auth_err("device secure-boot state not intact"));
		}

		// 6. Record the session — monotonic-clock hard cap (W).
		let now = Instant::now();
		let session = ChatSession {
			bound_account: cert.bound_account.clone(),
			session_pubkey,
			expires_at: now + Duration::from_secs(CHAT_SESSION_TTL_SECS),
		};
		self.sessions
			.lock()
			.map_err(|_| auth_err("session store lock poisoned"))?
			.insert(thumbprint, session, now);

		Ok(ChatAuthenticateResult {
			bound_account_hex: hex::encode(cert.bound_account),
			expiry_unix_secs: now_unix_seconds().saturating_add(CHAT_SESSION_TTL_SECS),
			session_ttl_secs: CHAT_SESSION_TTL_SECS,
		})
	}

	/// Admit a drop via a LIVE session's cheap session-key signature instead
	/// of full per-drop cert auth. Looks up the session by cert thumbprint,
	/// verifies the Ed25519 session-key signature over
	/// `blake2_256(CHAT_SESSION_DROP_DOMAIN ‖ drop_bytes)` against the
	/// session's authorized `session_pubkey`, and returns the bound account.
	/// No secure-element crossing, no HIP — the handshake already proved
	/// device health + human presence for the session's lifetime. Errors if
	/// there is no live session (client must re-handshake) or the signature
	/// fails.
	fn verify_session_drop(
		&self,
		drop_bytes: &[u8],
		thumbprint_hex: &str,
		session_sig_hex: &str,
	) -> Result<AccountId, ErrorObject<'static>> {
		let thumbprint = decode_hex32(thumbprint_hex)
			.map_err(|e| invalid_param("session_cert_thumbprint_hex", &e))?;
		let sig_bytes = hex::decode(session_sig_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("session_sig_hex", &format!("invalid hex: {e}")))?;
		let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
			invalid_param("session_sig_hex", "expected a 64-byte Ed25519 signature")
		})?;

		let session = self
			.sessions
			.lock()
			.map_err(|_| auth_err("session store lock poisoned"))?
			.get_live(&thumbprint, Instant::now())
			.ok_or_else(|| {
				auth_err("no live session for this cert — re-handshake (chat_authenticate)")
			})?;

		let mut to_sign =
			Vec::with_capacity(CHAT_SESSION_DROP_DOMAIN.len() + drop_bytes.len());
		to_sign.extend_from_slice(CHAT_SESSION_DROP_DOMAIN);
		to_sign.extend_from_slice(drop_bytes);
		let digest = blake2_256(&to_sign);

		let vk = Ed25519VerificationKey::try_from(session.session_pubkey)
			.map_err(|_| auth_err("stored session pubkey is not a valid Ed25519 key"))?;
		let sig = Ed25519Signature::from(sig_arr);
		vk.verify(&sig, &digest)
			.map_err(|_| auth_err("session-key signature verification failed"))?;

		Ok(session.bound_account)
	}
}

/// Which hop is peeling, and therefore which `OnionHop` outcome is legal.
/// The peel logic is byte-identical on every hop; only the *legal result*
/// differs, so this is the one knob that distinguishes guard from relay-2.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PeelMode {
	/// The guard's `chat_send_onion` RPC entry. The onion MUST peel to
	/// `Forward`: a `Deliver` here would make the cert-authed entry node the
	/// FINAL hop, so it would see the sender (cert + IP) AND the recipient
	/// bucket at once — collapsing the very sender↔recipient split the onion
	/// exists to enforce. A `Deliver` at the guard is therefore rejected; the
	/// path must be ≥2 hops (guard forwards, relay-2 delivers).
	GuardEntry,
	/// The final relay (relay-2), reached via `/rostro/chat-onion-forward/2`.
	/// The onion MUST peel to `Deliver`: a further `Forward` would be hop ≥3,
	/// rejected as the 2-hop cap (loop / amplification defense).
	FinalRelay,
}

/// Onion peel-and-dispatch context — this node's OWN node key plus the
/// routing handles the `Deliver` path needs. Deliberately NON-generic and
/// free of any user secret: it holds only `node_secret` (this node's own
/// key, for the single peel step), `node_pubkey_ed25519`, the `bucket_cache`
/// and the `network` handle. Shared by the guard's `chat_send_onion` RPC
/// entry and (slice 2) the `/rostro/chat-onion-forward/1` handler, so the
/// peeler is byte-identical on every hop. Auth is the CALLER's concern.
pub(crate) struct OnionPeelCtx {
	node_secret: NodeSecret,
	node_pubkey_ed25519: [u8; 32],
	bucket_cache: BucketCache,
	network: Arc<dyn NetworkService>,
}

impl OnionPeelCtx {
	pub(crate) fn new(
		seed: [u8; 32],
		node_pubkey_ed25519: [u8; 32],
		bucket_cache: BucketCache,
		network: Arc<dyn NetworkService>,
	) -> Self {
		Self {
			node_secret: NodeSecret::from_seed(seed),
			node_pubkey_ed25519,
			bucket_cache,
			network,
		}
	}

	/// Peel this node's layer — the ONE key-using step — and act on the
	/// result. `Deliver` → inject the recipient MESSAGE into the stripe
	/// path; `Forward` → (slice 2) send the inner onion DIRECTLY to
	/// `next_hop`, never through stripe. Caller-agnostic: the guard RPC
	/// does cert-auth before calling this; the relay-2 forward handler
	/// gates on canonical-peer status. Holds no user secret.
	pub(crate) async fn peel_and_dispatch(
		&self,
		packet: &OnionPacket,
		total_shares: u8,
		mode: PeelMode,
	) -> RpcResult<ChatSendResult> {
		let hop = process_hop(&self.node_secret, packet).map_err(|e| {
			ErrorObject::owned::<()>(-32000, format!("onion peel failed: {e:?}"), None)
		})?;

		match hop {
			OnionHop::Deliver { drop } => {
				// 1c: a guard must never be the final hop. A `Deliver` peeled at
				// the cert-authed RPC entry means a 1-hop onion — the entry node
				// would learn the sender (cert + IP) AND the recipient bucket,
				// collapsing the sender↔recipient split. Reject; require ≥2 hops.
				if mode == PeelMode::GuardEntry {
					return Err(ErrorObject::owned::<()>(
						-32000,
						"onion delivered at the guard entry: a 1-hop onion exposes \
						 sender and recipient to one node; the path must be at least \
						 two hops (guard forwards, relay-2 delivers)",
						None,
					));
				}
				// Last hop: inject the recipient-sealed envelope into the
				// normal stripe-and-distribute path (the sender is gone).
				let payload = OnionDeliverPayload::decode(&mut &drop[..]).map_err(|e| {
					ErrorObject::owned::<()>(
						-32000,
						format!("onion deliver payload decode: {e}"),
						None,
					)
				})?;
				let recipient_x25519 =
					ed25519_to_x25519_pubkey(&payload.recipient_chat_pubkey).ok_or_else(|| {
						ErrorObject::owned::<()>(
							-32000,
							"onion deliver recipient pubkey is not a valid Edwards point",
							None,
						)
					})?;
				let recipient_pickup = PickupKey::for_pairwise(&recipient_x25519);
				let envelope =
					SealedEnvelope::decode(&mut &payload.envelope_bytes[..]).map_err(|e| {
						ErrorObject::owned::<()>(
							-32000,
							format!("onion deliver envelope decode: {e}"),
							None,
						)
					})?;
				self.stripe_and_distribute(envelope, recipient_pickup, total_shares).await
			}
			OnionHop::Forward { next_hop, inner } => {
				// Direct node-to-node hop. INVARIANT: the onion is
				// transport, never a message — `inner` (an `OnionPacket`)
				// is forwarded DIRECTLY to `next_hop` over
				// /rostro/chat-onion-forward/1 and must NEVER be decoded
				// into a `SealedEnvelope`, addressed to a bucket, or passed
				// to `stripe_and_distribute`. Sharding an onion to forward
				// it is the precise failure the peeler/messaging split
				// prevents. See docs/DOTWAVE-CHAT-METADATA-ANONYMITY.md.
				if mode == PeelMode::FinalRelay {
					// A forwarded onion that peels to a further Forward
					// would be hop ≥3 — refused (2-hop cap; loop defense).
					return Err(ErrorObject::owned::<()>(
						-32000,
						"onion exceeds the 2-hop limit: a forwarded onion must \
						 deliver, not forward again",
						None,
					));
				}
				let peer = PeerId::from_ed25519(&next_hop).ok_or_else(|| {
					ErrorObject::owned::<()>(
						-32000,
						"onion forward next_hop is not a valid ed25519 public key",
						None,
					)
				})?;
				// 1b: liveness. Only forward to a relay that is a LIVE chat-fabric
				// member — present in our chat-gossip bucket cache (added on
				// stream-open, dropped on disconnect). If the app picked a stale or
				// offline relay-2, fail FAST with a distinct code so the app
				// re-rolls, rather than hanging out the 120s forward timeout.
				if self.bucket_cache.get(&peer).is_none() {
					return Err(ErrorObject::owned::<()>(
						RELAY_UNAVAILABLE_CODE,
						format!(
							"relay unavailable: chosen relay-2 ({peer}) is not a live \
							 chat relay; pick another relay-2 and retry"
						),
						None,
					));
				}
				// 1a: forward-leg accountability. Sign (total_shares ‖ inner) with
				// THIS guard's node key. relay-2 recovers our identity from the
				// authenticated connection and verifies this before peeling; a
				// bad/absent signature is a reputation-docked rejection there. The
				// signature is the guard's OWN node key — never sender material.
				let packet_bytes = inner.encode();
				let guard_sig = self
					.node_secret
					.sign(&onion_forward_digest(total_shares, &packet_bytes));
				let request = OnionForwardRequest { total_shares, packet_bytes, guard_sig };
				let (resp_bytes, _) = self
					.network
					.request(
						peer,
						ProtocolName::from(CHAT_ONION_FORWARD_PROTOCOL_NAME),
						request.encode(),
						None,
						IfDisconnected::TryConnect,
					)
					.await
					.map_err(|e| {
						ErrorObject::owned::<()>(
							-32000,
							format!("onion forward to relay-2 ({peer}) failed: {e:?}"),
							None,
						)
					})?;
				match OnionForwardResponse::decode(&mut &resp_bytes[..]) {
					Ok(OnionForwardResponse::Delivered {
						message_id_hex,
						share_count,
						recipient_pickup_key_hex,
					}) => Ok(ChatSendResult {
						message_id_hex,
						share_count,
						recipient_pickup_key_hex,
					}),
					Ok(OnionForwardResponse::Rejected { code, message }) => {
						Err(ErrorObject::owned::<()>(code, message, None))
					}
					Err(e) => Err(ErrorObject::owned::<()>(
						-32000,
						format!("onion forward response decode failed: {e}"),
						None,
					)),
				}
			}
		}
	}

	/// Shared distribution core: stripe-split a recipient-sealed
	/// envelope and push the shards to the recipient bucket's peers over
	/// `/rostro/chat-stripe/1`. Pure routing — holds no secret.
	///
	/// Used by the onion peeler's `Deliver` path (relay-2 re-inserts a
	/// peeled envelope into the normal distribution; the sender is
	/// already gone). `send_envelope` inlines the same logic today; the
	/// two converge on this helper once the onion path is fabric-proven.
	///
	/// INVARIANT — MESSAGE-ONLY, never an onion. Callers must pass a
	/// fully-peeled **recipient message** (the `SealedEnvelope` carried by
	/// an `OnionHop::Deliver` drop, or a direct `send_envelope`). An onion
	/// in flight (an `OnionPacket`, e.g. an `OnionHop::Forward { inner }`)
	/// must **never** reach this path: onions are forwarded directly
	/// node-to-node, never sharded/bucketed. Sharding an onion to move it
	/// between hops — peel → shard → forward → peel → shard again — is the
	/// exact failure this separation prevents. The `OnionPacket` vs
	/// `SealedEnvelope` type split enforces it; this note guards against a
	/// future caller decoding an onion into an envelope to slip it through.
	/// See docs/DOTWAVE-CHAT-METADATA-ANONYMITY.md, "Resolved structure".
	async fn stripe_and_distribute(
		&self,
		envelope: SealedEnvelope,
		recipient_pickup: PickupKey,
		total_shares: u8,
	) -> RpcResult<ChatSendResult> {
		if !matches!(envelope.kind, EnvelopeKind::Pairwise) {
			return Err(invalid_param(
				"envelope",
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

		let encoded = envelope.encode();
		let message_id = envelope.message_id;
		let mut rng = OsRng;
		let shares = split_xor(&encoded, n_shares, &mut rng).map_err(|e| {
			ErrorObject::owned::<()>(-32000, format!("split_xor failed: {e:?}"), None)
		})?;

		let bucket = bucket_for_pickup_key(&recipient_pickup);
		let mut bucket_peers = self.bucket_cache.peers_for_bucket(bucket);
		if bucket_peers.is_empty() {
			return Err(ErrorObject::owned::<()>(
				-32000,
				format!(
					"no bucket peers available for bucket {bucket} — try a \
					 different RPC node, or wait for peers to advertise their \
					 bucket subscriptions on /rostro/chat-gossip/1",
				),
				None,
			));
		}

		// Shuffle so each shard goes to up to REPLICATION_FACTOR random
		// bucket peers (non-deterministic — predictable selection would
		// let an observer game which peers receive which shards).
		use rand_core::RngCore;
		let peer_n = bucket_peers.len();
		for i in (1..peer_n).rev() {
			let j = (rng.next_u64() as usize) % (i + 1);
			bucket_peers.swap(i, j);
		}
		let n_replicas = REPLICATION_FACTOR.min(bucket_peers.len());
		let selected_peers: Vec<rc_network::PeerId> =
			bucket_peers.into_iter().take(n_replicas).collect();

		let mac_key = [0u8; 32];
		let total_u8 = n_shares as u8;
		let expires_at = now_unix_seconds().saturating_add(CHAT_TTL_SECONDS);

		let mut stored_total: usize = 0;
		let mut rejected_total: usize = 0;
		let mut transport_failed_total: usize = 0;

		for (i, share_bytes) in shares.into_iter().enumerate() {
			let share_index = i as ShareIndex;
			let mac_tag = mac_share(&mac_key, &share_bytes, share_index);
			let descriptor = ShareDescriptor {
				relay_pubkey: RelayPubkey(self.node_pubkey_ed25519),
				message_id,
				share_index,
				total_shares: total_u8,
				pickup_key: recipient_pickup,
				expires_at_unix_ts: expires_at,
			};
			let store_req =
				StoreRequest { descriptor, share_bytes: share_bytes.clone(), mac_tag };
			let request_bytes = store_req.encode();

			for peer in &selected_peers {
				match self
					.network
					.request(
						*peer,
						ProtocolName::from(CHAT_STRIPE_PROTOCOL_NAME),
						request_bytes.clone(),
						None,
						IfDisconnected::TryConnect,
					)
					.await
				{
					Ok((resp_bytes, _)) => match StoreResponse::decode(&mut &resp_bytes[..]) {
						Ok(StoreResponse::Stored) => stored_total += 1,
						Ok(StoreResponse::Rejected(reason)) => {
							rejected_total += 1;
							// DuplicateShare on a retry is fine — count as Stored.
							if matches!(reason, StoreRejection::DuplicateShare) {
								stored_total += 1;
								rejected_total -= 1;
							}
						}
						Err(_) => transport_failed_total += 1,
					},
					Err(_) => transport_failed_total += 1,
				}
			}
		}

		log::info!(
			target: "rostro-chat-rpc",
			"chat distribute: shards={n_shares} stored={stored_total} \
			 rejected={rejected_total} transport_failed={transport_failed_total} \
			 message_id={}",
			hex::encode(message_id.0),
		);

		if stored_total < n_shares {
			return Err(ErrorObject::owned::<()>(
				-32000,
				format!(
					"only {stored_total} of {n_shares} shards landed (need {n_shares} \
					 for recipient assembly); {rejected_total} rejected, \
					 {transport_failed_total} transport-failed",
				),
				None,
			));
		}

		Ok(ChatSendResult {
			message_id_hex: hex::encode(message_id.0),
			share_count: n_shares as u32,
			recipient_pickup_key_hex: hex::encode(recipient_pickup.0),
		})
	}
}

#[async_trait]
impl<C> ChatRpcApiServer for ChatRpc<C>
where
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: ZkPkiApi<Block, AccountId>,
{
	fn node_info(&self) -> RpcResult<ChatNodeInfo> {
		Ok(ChatNodeInfo {
			node_pubkey_ed25519_hex: hex::encode(self.node_pubkey_ed25519),
		})
	}

	fn local_store_len(&self) -> RpcResult<u64> {
		Ok(self.share_store.len() as u64)
	}

	fn my_subscription(&self) -> RpcResult<ChatMySubscription> {
		match &self.local_subscription {
			Some(state) => {
				let bitmap = state.current_bitmap();
				Ok(ChatMySubscription {
					bitmap_hex: hex::encode(bitmap.0),
					bucket_count: bitmap.count(),
					version: state.current_version(),
				})
			}
			None => Ok(ChatMySubscription {
				bitmap_hex: String::new(),
				bucket_count: 0,
				version: 0,
			}),
		}
	}

	async fn send_envelope(
		&self,
		recipient_chat_pubkey_hex: String,
		envelope_hex: String,
		total_shares: u8,
		auth_cert_thumbprint_hex: Option<String>,
		auth_timestamp_secs: Option<u64>,
		auth_sig_hex: Option<String>,
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

		// Chat-auth verification (Phase 2: cert-gated send). All
		// three auth-* parameters are required; there is no
		// unauthenticated path.
		match (auth_cert_thumbprint_hex, auth_timestamp_secs, auth_sig_hex) {
			(Some(tp), Some(ts), Some(sig)) => {
				let authed = self.verify_chat_auth(&envelope_bytes, &tp, ts, &sig)?;
				log::debug!(
					target: "rostro-chat-rpc",
					"chat_send_envelope authenticated as account {:?}",
					authed,
				);
			}
			_ => {
				return Err(invalid_param(
					"auth_*",
					"chat_send_envelope requires cert auth: all three of \
					 auth_cert_thumbprint_hex, auth_timestamp_secs, \
					 auth_sig_hex must be present, signed by an Active \
					 zkpki cert's device key",
				));
			}
		}

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

		// Pick bucket peers for the message's bucket. Reject the
		// send if zero peers subscribe (old-tenant-mail behavior
		// per design discussion — there's nowhere to deliver).
		let bucket = bucket_for_pickup_key(&recipient_pickup);
		let mut bucket_peers = self.bucket_cache.peers_for_bucket(bucket);
		if bucket_peers.is_empty() {
			return Err(ErrorObject::owned::<()>(
				-32000,
				format!(
					"no bucket peers available for bucket {bucket} — try a \
					 different RPC node, or wait for peers to advertise \
					 their bucket subscriptions on /rostro/chat-gossip/1",
				),
				None,
			));
		}

		// Shuffle for replication picks (each shard goes to up to
		// REPLICATION_FACTOR random bucket peers). OsRng for
		// non-deterministic selection — predictable selection
		// would let an observer game which peers receive which
		// shards.
		use rand_core::RngCore;
		fn shuffle_in_place(v: &mut Vec<rc_network::PeerId>, rng: &mut OsRng) {
			let n = v.len();
			for i in (1..n).rev() {
				let j = (rng.next_u64() as usize) % (i + 1);
				v.swap(i, j);
			}
		}
		shuffle_in_place(&mut bucket_peers, &mut rng);
		let n_replicas = REPLICATION_FACTOR.min(bucket_peers.len());
		let selected_peers: Vec<rc_network::PeerId> =
			bucket_peers.into_iter().take(n_replicas).collect();

		// MAC each share with the v0.1 zero key (per-message
		// session-secret derivation lands with the DR pairwise
		// wrapper — placeholder, same as the prior demo).
		let mac_key = [0u8; 32];
		let total_u8 = n_shares as u8;
		let expires_at = now_unix_seconds().saturating_add(CHAT_TTL_SECONDS);

		// Push each shard to every selected peer. Outbound
		// /rostro/chat-stripe/1 request-response. Aggregate
		// success counts so we can surface degraded redundancy.
		let mut stored_total: usize = 0;
		let mut rejected_total: usize = 0;
		let mut transport_failed_total: usize = 0;

		for (i, share_bytes) in shares.into_iter().enumerate() {
			let share_index = i as ShareIndex;
			let mac_tag = mac_share(&mac_key, &share_bytes, share_index);
			let descriptor = ShareDescriptor {
				relay_pubkey: RelayPubkey(self.node_pubkey_ed25519),
				message_id,
				share_index,
				total_shares: total_u8,
				pickup_key: recipient_pickup,
				expires_at_unix_ts: expires_at,
			};
			let store_req = StoreRequest {
				descriptor,
				share_bytes: share_bytes.clone(),
				mac_tag,
			};
			let request_bytes = store_req.encode();

			for peer in &selected_peers {
				match self
					.network
					.request(
						*peer,
						ProtocolName::from(CHAT_STRIPE_PROTOCOL_NAME),
						request_bytes.clone(),
						None,
						IfDisconnected::TryConnect,
					)
					.await
				{
					Ok((resp_bytes, _)) => {
						match StoreResponse::decode(&mut &resp_bytes[..]) {
							Ok(StoreResponse::Stored) => {
								stored_total += 1;
							}
							Ok(StoreResponse::Rejected(reason)) => {
								rejected_total += 1;
								log::debug!(
									target: "rostro-chat-rpc",
									"push shard {} of message {} to {} \
									 rejected: {:?}",
									share_index,
									hex::encode(&message_id.0[..4]),
									peer,
									reason,
								);
								// DuplicateShare on a retry is fine — count
								// it as Stored so we don't over-flag.
								if matches!(reason, StoreRejection::DuplicateShare) {
									stored_total += 1;
									rejected_total -= 1;
								}
							}
							Err(_) => {
								transport_failed_total += 1;
								log::debug!(
									target: "rostro-chat-rpc",
									"push to {}: undecodable StoreResponse",
									peer,
								);
							}
						}
					}
					Err(e) => {
						transport_failed_total += 1;
						log::debug!(
							target: "rostro-chat-rpc",
							"push shard {} of message {} to {} \
							 transport failed: {:?}",
							share_index,
							hex::encode(&message_id.0[..4]),
							peer,
							e,
						);
					}
				}
			}
		}

		// Aggregate. n_shares × n_replicas requests issued; the
		// minimum we need for "send succeeded" is that each shard
		// landed somewhere — at least n_shares total Stored
		// responses. If we got fewer, the send is degraded;
		// callers see a structured warning in the response shape.
		let total_attempts = n_shares * n_replicas;
		log::info!(
			target: "rostro-chat-rpc",
			"chat_send_envelope: shards={} replicas={} attempts={} stored={} rejected={} transport_failed={} \
			 message_id={}",
			n_shares,
			n_replicas,
			total_attempts,
			stored_total,
			rejected_total,
			transport_failed_total,
			hex::encode(message_id.0),
		);

		if stored_total < n_shares {
			return Err(ErrorObject::owned::<()>(
				-32000,
				format!(
					"chat_send_envelope: only {stored_total} of {n_shares} shards \
					 landed (need at least {n_shares} for recipient assembly); \
					 {rejected_total} rejected, {transport_failed_total} \
					 transport-failed",
				),
				None,
			));
		}

		Ok(ChatSendResult {
			message_id_hex: hex::encode(message_id.0),
			share_count: n_shares as u32,
			recipient_pickup_key_hex: hex::encode(recipient_pickup.0),
		})
	}

	async fn send_onion(
		&self,
		onion_packet_hex: String,
		total_shares: u8,
		auth_cert_thumbprint_hex: Option<String>,
		auth_timestamp_secs: Option<u64>,
		auth_sig_hex: Option<String>,
		session_cert_thumbprint_hex: Option<String>,
		session_sig_hex: Option<String>,
	) -> RpcResult<ChatSendResult> {
		// The peeler needs this node's own key (isolated in OnionPeelCtx,
		// outside the secret-free routing layer).
		let ctx = self.onion_ctx.as_ref().ok_or_else(|| {
			ErrorObject::owned::<()>(
				-32000,
				"this node has no persistent identity; onion relaying is disabled \
				 (set --node-key / --node-key-file)",
				None,
			)
		})?;

		let packet_bytes = hex::decode(onion_packet_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("onion_packet_hex", &format!("invalid hex: {e}")))?;
		let packet = OnionPacket::decode(&mut &packet_bytes[..]).map_err(|e| {
			invalid_param("onion_packet_hex", &format!("SCALE-decode failed: {e}"))
		})?;

		// Auth over the onion packet bytes — the guard authenticates the
		// sender at the RPC entry. Prefer a LIVE session (cheap session-key
		// signature, no secure-element crossing); fall back to full per-drop
		// cert auth (the handshake/renewal path). The peel + dispatch below is
		// auth-agnostic: the slice-2 relay-2 forward handler gates on
		// canonical-peer status instead, never re-authing the sender.
		match (session_cert_thumbprint_hex, session_sig_hex) {
			(Some(tp), Some(sig)) => {
				let authed = self.verify_session_drop(&packet_bytes, &tp, &sig)?;
				log::debug!(
					target: "rostro-chat-rpc",
					"chat_send_onion authenticated via session as account {:?}",
					authed,
				);
			}
			_ => match (auth_cert_thumbprint_hex, auth_timestamp_secs, auth_sig_hex) {
				(Some(tp), Some(ts), Some(sig)) => {
					let authed = self.verify_chat_auth(&packet_bytes, &tp, ts, &sig)?;
					log::debug!(
						target: "rostro-chat-rpc",
						"chat_send_onion authenticated via cert auth as account {:?}",
						authed,
					);
				}
				_ => {
					return Err(invalid_param(
						"auth",
						"chat_send_onion requires either a live session \
						 (session_cert_thumbprint_hex + session_sig_hex) or full cert \
						 auth (auth_cert_thumbprint_hex + auth_timestamp_secs + \
						 auth_sig_hex, signed by an Active zkpki cert's device key)",
					));
				}
			},
		}

		// Peel + dispatch via the shared context — the SAME code path the
		// /rostro/chat-onion-forward/2 handler runs on relay-2.
		// `PeelMode::GuardEntry`: the guard MUST forward to relay-2; a `Deliver`
		// peeled here (a 1-hop onion) is rejected, since the guard must never be
		// the final hop and see sender+recipient together (1c).
		ctx.peel_and_dispatch(&packet, total_shares, PeelMode::GuardEntry).await
	}

	async fn fetch_shares(
		&self,
		pickup_key_hex: String,
		relay_peer_id_hex: Option<String>,
	) -> RpcResult<Vec<ChatFetchedShareRaw>> {
		let pickup_bytes = decode_hex32(&pickup_key_hex)
			.map_err(|e| invalid_param("pickup_key_hex", &e))?;
		let pickup = PickupKey(pickup_bytes);

		// Local store first.
		let mut matched = self.share_store.get_by_pickup_key(&pickup);

		// Explicit relay (optional). When the caller names a specific
		// peer (via `relay_peer_id_hex`), query that peer in addition
		// to the local view. This is the demo-script path; the
		// production path doesn't need it — the bucket-peer
		// auto-fallback below handles the "I hit an RPC node that
		// doesn't have my shards" case structurally.
		if let Some(hex_peer) = relay_peer_id_hex {
			let peer = parse_peer_id(&hex_peer)
				.map_err(|e| invalid_param("relay_peer_id_hex", &e))?;
			let request = FetchRequest { pickup_key: pickup };
			let request_bytes = request.encode();
			match self
				.network
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

		// Bucket-peer auto-fallback. If after the local store + any
		// explicit-peer lookup we still don't have shards for this
		// pickup key, query bucket peers from the BucketCache. This
		// makes the "hit any RPC node" property hold for fetch:
		// recipients don't have to know which RPC node received the
		// push — any node will resolve via fallback when it doesn't
		// have the shards locally.
		//
		// Why "still empty" not "always": when the local store has
		// shards, the recipient's gateway IS a bucket peer and push
		// reached it; no fallback needed. When local is empty, the
		// gateway either (a) doesn't subscribe to the bucket or (b)
		// subscribes but didn't receive the push (e.g., entry node
		// that pushed elsewhere). Either way, a small set of
		// bucket-peer queries assembles what's needed.
		if matched.is_empty() {
			use rostro_chat_primitives::bucket::bucket_for_pickup_key;

			let bucket = bucket_for_pickup_key(&pickup);
			let mut bucket_peers = self.bucket_cache.peers_for_bucket(bucket);

			// Shuffle so we don't always query the same N peers for
			// the same bucket (load-spreading + privacy: prevents an
			// observer from correlating "alice's gateway always asks
			// bob for bucket 42").
			use rand_core::RngCore;
			let mut rng = OsRng;
			let n = bucket_peers.len();
			for i in (1..n).rev() {
				let j = (rng.next_u64() as usize) % (i + 1);
				bucket_peers.swap(i, j);
			}

			let to_query: Vec<PeerId> = bucket_peers
				.into_iter()
				.take(MAX_FALLBACK_FETCH_PEERS)
				.collect();

			if !to_query.is_empty() {
				log::debug!(
					target: "rostro-chat-rpc",
					"chat_fetch_shares: local miss for bucket {bucket}; \
					 querying {} bucket peer(s) via fallback",
					to_query.len(),
				);
			}

			let fetch_req = FetchRequest { pickup_key: pickup };
			let fetch_req_bytes = fetch_req.encode();

			for peer in to_query {
				match self
					.network
					.request(
						peer,
						ProtocolName::from(CHAT_FETCH_PROTOCOL_NAME),
						fetch_req_bytes.clone(),
						None,
						IfDisconnected::TryConnect,
					)
					.await
				{
					Ok((resp_bytes, _)) => {
						match FetchResponse::decode(&mut &resp_bytes[..]) {
							Ok(resp) => {
								let n = resp.shares.len();
								for fs in resp.shares {
									matched.push((fs.descriptor, fs.share_bytes, fs.mac_tag));
								}
								if n > 0 {
									log::debug!(
										target: "rostro-chat-rpc",
										"fallback: peer {peer} returned {} shares",
										n,
									);
								}
							}
							Err(e) => {
								log::debug!(
									target: "rostro-chat-rpc",
									"fallback: peer {peer} returned undecodable \
									 FetchResponse: {e:?}",
								);
							}
						}
					}
					Err(e) => {
						log::debug!(
							target: "rostro-chat-rpc",
							"fallback: peer {peer} request failed: {e:?}",
						);
					}
				}
			}
		}

		// Dedupe (message_id, share_index) pairs that show up both
		// locally and remotely.
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
					expires_at_unix_ts: descriptor.expires_at_unix_ts,
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
	}

	async fn authenticate(
		&self,
		cert_thumbprint_hex: String,
		hip_proof_hex: String,
		anchor_block_number: u64,
		session_pubkey_hex: String,
	) -> RpcResult<ChatAuthenticateResult> {
		self.do_authenticate(
			&cert_thumbprint_hex,
			&hip_proof_hex,
			anchor_block_number,
			&session_pubkey_hex,
		)
		.map_err(Into::into)
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

/// Application-level auth/handshake rejection (cert/HIP/nonce/session).
fn auth_err(why: &str) -> ErrorObject<'static> {
	ErrorObject::owned::<()>(-32000, why.to_string(), None)
}

// Suppress unused warning on RngCore when total_shares branch
// uses split_xor path only; OsRng is imported for the RNG itself.
const _: fn() = || {
	let mut r = OsRng;
	let mut buf = [0u8; 4];
	r.fill_bytes(&mut buf);
};
