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
//! - Chunk + checksum the encoded SealedEnvelope on-device and hand
//!   the prepared batch to the node via `chat_send_prepared` (the
//!   node splits nothing and holds no key — it is pure routing)
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
//! - `chat_send_prepared(batch_hex, auth_*)` — accept a
//!   client-prepared chunk batch (split + checksummed on the sender's
//!   device; see docs/CHAT-SHARE-CHUNKING.md) and fan each chunk
//!   out to its own replica set of bucket peers. The node is pure
//!   routing: it validates shape, stamps its identity into the
//!   descriptors, and holds no key.
//! - `chat_fetch_shares(pickup_key_hex, relay_peer_id_hex?)` —
//!   return raw ciphertext chunks matching the given pickup_key.
//!   Aggregates across bucket peers whenever the local view is
//!   missing chunks (with per-chunk replica sets no single relay
//!   is expected to hold a whole message).

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
use gemini_runtime::{opaque::Block, AccountId, Balance};
use rand_core::{OsRng, RngCore};
use rc_network::{service::traits::NetworkService, types::ProtocolName, IfDisconnected, PeerId};
use rostro_chat_ephemeral_store::EphemeralShareStore;
use rostro_chat_membership_auth::{
	deserialize_vk, verify_handshake_proof, AcceptedSession, Bn254, ChainView, HandshakeError,
	HandshakeRequest, HandshakeSessions, VerifyingKey,
};
use rostro_chat_primitives::{
	bucket::bucket_for_pickup_key,
	chunk::{validate_prepared_batch, PreparedBatch},
	descriptor::{
		MessageId, PickupKey, RelayPubkey, ShareDescriptor, ShareIndex, UnixTimestamp,
	},
	fetch_protocol::{FetchRequest, FetchResponse},
	store_protocol::{ShareStore as _, StoreRejection, StoreRequest, StoreResponse},
	verify::ChunkChecksum,
};
use rostro_chat_onion::{process_hop, OnionHop, OnionPacket};
use rostro_node_identity::NodeSecret;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::blake2_256;
use sp_runtime::traits::Block as BlockT;
use sp_runtime::SaturatedConversion;
use zk_pki_hip::{verify_hip_proof_against_genesis, verify_hip_proof_internal};
use zk_pki_primitives::hip::CanonicalHipProof;
use rns_runtime_api::PnsStorageApi;
use zk_pki_primitives::runtime_api::{CertState as RpcCertState, ZkPkiApi};

use crate::chat_spend_protocol::VerifierError;

use crate::chat_bucket_cache::BucketCache;
use crate::chat_onion_forward_protocol::{
	onion_forward_digest, OnionForwardRequest, OnionForwardResponse,
	CHAT_ONION_FORWARD_PROTOCOL_NAME, RELAY_UNAVAILABLE_CODE,
};
use crate::chat_chunk_protocol::CHAT_CHUNK_PROTOCOL_NAME;

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
///     blake2_256(CHAT_AUTH_DOMAIN || payload_bytes || timestamp_be_bytes)
///
/// where `payload_bytes` is the prepared-batch bytes (direct send)
/// or the onion packet bytes (onion send). Binding both the payload
/// and `timestamp_be_bytes` prevents
/// (a) replay of the signature with a different payload and
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

/// Replication factor for push gossip: each CHUNK is pushed to up
/// to this many bucket-subscribed peers, and different chunks go to
/// DISJOINT peer sets when the bucket has enough peers
/// (docs/CHAT-SHARE-CHUNKING.md §4.4). Per-message relay cost is
/// ~message_size × CHUNK_REPLICATION; message loss probability is
/// ~N·p^R for per-relay unavailability p. If fewer peers subscribe
/// than a chunk's set needs, push goes to whoever's available
/// (degraded redundancy; overlap accepted on small networks). If
/// zero peers subscribe, the send is rejected (old-tenant-mail
/// behavior — there's nowhere to deliver).
pub const CHUNK_REPLICATION: usize = 3;

/// Maximum number of bucket peers to query when `chat_fetch_shares`
/// needs to aggregate from the network. Each query is an outbound
/// `/rostro/chat-fetch/1` request to a peer subscribed to the
/// pickup-key bucket. With per-chunk DISJOINT replica sets, chunks
/// of one message live on up to `total × CHUNK_REPLICATION` peers,
/// so aggregation stops early once every matched message is
/// complete rather than always burning the full budget.
pub const MAX_FALLBACK_FETCH_PEERS: usize = 8;

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

/// JSON-RPC response for `chat_send_prepared` / `chat_send_onion`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatSendResult {
	/// Hex-encoded MessageId from the client-prepared batch.
	/// Returned so clients can correlate successful sends with
	/// their own outgoing-message logs.
	pub message_id_hex: String,
	/// Number of chunks the batch carried (each landed on at least
	/// one replica).
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

/// JSON-RPC response: one stored chunk returned by `chat_fetch_shares`.
/// The client uses these to reconstruct messages locally:
///
/// 1. Group by `descriptor.message_id_hex`
/// 2. When all `total_shares` are present, verify each chunk's checksum
///    and concatenate in index order (`combine_chunks_verified`)
/// 3. SCALE-decode the result as `SealedEnvelope`
/// 4. Sealed-sender-unseal with the recipient's X25519 secret
/// 5. SCALE-decode `UnsealedInner` and verify the sender signature
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatFetchedShareRaw {
	pub descriptor: ChatShareDescriptorRpc,
	pub share_bytes_hex: String,
	pub checksum_hex: String,
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

/// JSON-RPC response for `chat_authenticateMembership` — the anonymous
/// membership handshake. The guard learns only the session key, the rate tag,
/// and the epoch; never the cert.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatMembershipAuthResult {
	/// Echo of the session public key the session is keyed by (hex).
	pub session_pubkey_hex: String,
	/// Epoch the session is valid through.
	pub expires_epoch: u64,
	/// The node's current epoch at acceptance.
	pub current_epoch: u64,
	/// The witnessed spend record, SCALE-encoded (hex) — the PORTABLE
	/// admission ticket (CHAT-SESSION-TICKET.md): present it to any other
	/// guard via `chat_presentSessionTicket` to enter there without a new
	/// handshake (and without a second spend, which would be refused).
	pub ticket_hex: String,
}

/// A proof's `anchor_block` must be within this many blocks of the node's best
/// block to count as recent (~1 day at the chat epoch length).
const MEMBERSHIP_ANCHOR_WINDOW_BLOCKS: u64 = 14_400;

/// [`ChainView`] over the zkpki runtime API at a fixed best block, so the
/// membership-auth verifier can validate a proof's public inputs. `pub(crate)`
/// so the recorder (chat_spend_protocol) can re-verify a witnessed proof.
pub(crate) struct RuntimeChainView<'a, C> {
	pub(crate) client: &'a C,
	pub(crate) best: <Block as BlockT>::Hash,
	pub(crate) best_number: u64,
}

impl<'a, C> ChainView for RuntimeChainView<'a, C>
where
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
	C::Api: ZkPkiApi<Block, AccountId>,
{
	fn membership_root_recent(&self, root: &[u8; 32]) -> bool {
		self.client
			.runtime_api()
			.membership_root_recent(self.best, *root)
			.unwrap_or(false)
	}
	fn freshness_root_recent(&self, root: &[u8; 32]) -> bool {
		self.client
			.runtime_api()
			.freshness_root_recent(self.best, *root)
			.unwrap_or(false)
	}
	fn current_epoch(&self) -> u64 {
		self.client
			.runtime_api()
			.membership_epoch(self.best)
			.unwrap_or(0) as u64
	}
	fn anchor_recent(&self, anchor_block: u64) -> bool {
		anchor_block <= self.best_number
			&& self.best_number.saturating_sub(anchor_block)
				<= MEMBERSHIP_ANCHOR_WINDOW_BLOCKS
	}
	fn scope(&self) -> u64 {
		self.client
			.runtime_api()
			.membership_scope(self.best)
			.unwrap_or(0)
	}
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

	/// Accept a client-prepared chunk batch (the chunk cutover,
	/// docs/CHAT-SHARE-CHUNKING.md): the SENDER DEVICE split the
	/// sealed envelope into chunks, checksummed each one, authored
	/// the descriptor fields, and derived the pickup key. This node
	/// is pure routing — it validates shape (it holds no key), stamps
	/// its own identity into the descriptors, and pushes each chunk
	/// to that chunk's own replica set of bucket peers.
	///
	/// Parameters:
	///   * `batch_hex` — SCALE-encoded
	///     `rostro_chat_primitives::chunk::PreparedBatch` bytes,
	///     hex-encoded. Carries pickup_key + message_id + the
	///     tagged chunks.
	///   * `auth_cert_thumbprint_hex` — caller's zkpki cert
	///     thumbprint (32 bytes, hex). Identifies the cert whose
	///     HW-attested device key signed `auth_sig_hex`.
	///   * `auth_timestamp_secs` — caller's local Unix-seconds
	///     timestamp at signing. Must be within
	///     [`CHAT_AUTH_TIMESTAMP_WINDOW_SECS`] of the node's clock.
	///   * `auth_sig_hex` — signature over
	///     `blake2_256(CHAT_AUTH_DOMAIN || batch_bytes ||
	///     auth_timestamp_be_bytes)` produced by the cert's
	///     hardware-attested device key — i.e. over the EXACT bytes
	///     passed as `batch_hex`.
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
	#[method(name = "chat_send_prepared")]
	async fn send_prepared(
		&self,
		batch_hex: String,
		auth_cert_thumbprint_hex: Option<String>,
		auth_timestamp_secs: Option<u64>,
		auth_sig_hex: Option<String>,
	) -> RpcResult<ChatSendResult>;

	/// Submit an **onion-wrapped** send (Phase 4, network-origin
	/// anonymity). The node peels the one layer addressed to it — using
	/// its own node key in the isolated peeler, never in the secret-free
	/// routing layer — and then either:
	///   * `Deliver` → fans the client-prepared chunk batch out to the
	///     bucket peers (this node is the last hop; the sender is
	///     already gone), or
	///   * `Forward` → hands the inner blob to the next hop (slice 2).
	///
	/// Cert-auth (Phase 2) is verified over the onion packet bytes — the
	/// sender signs the packet it presents to this guard.
	///
	/// Parameters:
	///   * `onion_packet_hex` — the SCALE-encoded `OnionPacket` sealed to
	///     this node's identity (hex). The innermost `Deliver` drop is a
	///     SCALE-encoded `PreparedBatch` (chunk counts ride inside it).
	///   * `auth_*` — full per-drop cert auth (the renewal/fallback path).
	///   * `session_cert_thumbprint_hex` + `session_sig_hex` — the cheap
	///     session path: within a live session, the drop is admitted by an
	///     Ed25519 session-key signature over the onion packet, with no
	///     secure-element crossing. The 32-byte lookup key is the cert
	///     thumbprint for an identified session (`chat_authenticate`) or
	///     the authorized session pubkey for an anonymous membership
	///     session (`chat_authenticateMembership`) — both stores are
	///     consulted. Preferred when present; the node falls back to full
	///     cert auth otherwise. (Trailing `Option`s keep this
	///     wire-compatible with pre-session callers.)
	#[method(name = "chat_send_onion")]
	async fn send_onion(
		&self,
		onion_packet_hex: String,
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

	/// The anonymous-membership handshake (Phase 2). The caller proves, in
	/// zero knowledge, possession of a valid, non-expired, HIP-fresh cert in
	/// the membership set, without revealing which one. The node verifies the
	/// Groth16 proof against the pinned verifying key and recent chain roots,
	/// spends the per-epoch nullifier, and records a session keyed by
	/// `session_pubkey`. Returns an error if membership auth is not activated
	/// on this node.
	#[method(name = "chat_authenticateMembership")]
	async fn authenticate_membership(
		&self,
		proof_hex: String,
		membership_root_hex: String,
		freshness_root_hex: String,
		nullifier_hex: String,
		current_epoch: u64,
		anchor_block: u64,
		session_pubkey_hex: String,
	) -> RpcResult<ChatMembershipAuthResult>;

	/// Present a witnessed session ticket (the `ticket_hex` returned by
	/// `chat_authenticateMembership`) to install its session at THIS guard
	/// without a new handshake — the portable-ticket path
	/// (CHAT-SESSION-TICKET.md 2.2 / D2). The guard validates the record
	/// against the current guard set + quarantine and, on success, inserts
	/// it into the spend store (feeding gossip) and caches the session.
	/// Idempotent: re-presenting a live ticket is a no-op success. Returns
	/// the epoch the session is valid through.
	#[method(name = "chat_presentSessionTicket")]
	async fn present_session_ticket(&self, ticket_hex: String) -> RpcResult<u64>;
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
	/// Pinned Groth16 verifying key for the anonymous-membership handshake.
	/// `None` is the activation gate: until the trusted-setup ceremony's vk is
	/// configured (a mainnet posture), the membership endpoint returns "not
	/// activated". Testnet runs with `None`.
	membership_vk: Option<VerifyingKey<Bn254>>,
	/// Node-local anonymous-membership sessions (keyed by session pubkey). The
	/// cert is never stored. The spend is now witnessed by the committee, not the
	/// local set, so admission writes here via `note_session`.
	membership_sessions: Arc<Mutex<HandshakeSessions>>,
	/// This node's ed25519 identity, for signing as the verifier in the witnessed
	/// spend. `None` (no persistent libp2p key) disables membership admission.
	node_secret: Option<NodeSecret>,
	/// Shared per-epoch witnessed-spend store. The verifier writes admitted spends
	/// here; `/rostro/chat-spend/1` reconciliation spreads them network-wide.
	spend_store: crate::chat_spend_protocol::SharedSpendStore,
	/// Shared per-epoch quarantine set. The verifier skips quarantined committee
	/// members so it only builds admissible records.
	quarantine: crate::chat_spend_protocol::SharedQuarantineSet,
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
		membership_vk_bytes: Option<Vec<u8>>,
		spend_store: crate::chat_spend_protocol::SharedSpendStore,
		quarantine: crate::chat_spend_protocol::SharedQuarantineSet,
	) -> Self {
		// Pin the anonymous-membership verifying key, flipping the activation
		// gate on. `None` (or undecodable bytes) leaves the endpoint returning
		// "not activated" — the correct posture until a vk is pinned. Mainnet
		// bakes a ceremony vk into the binary; the dev/testnet path loads one
		// from `--chat-membership-vk`.
		let membership_vk = match membership_vk_bytes {
			Some(bytes) => match deserialize_vk(&bytes) {
				Some(vk) => {
					#[cfg(feature = "chat-diagnostics")]
					log::info!(
						target: "rostro-chat",
						"anonymous-membership auth ACTIVATED (pinned vk, {} bytes)",
						bytes.len(),
					);
					Some(vk)
				}
				None => {
					log::error!(
						target: "rostro-chat",
						"chat-membership vk failed to decode; membership auth stays OFF",
					);
					None
				}
			},
			None => None,
		};
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
			membership_vk,
			membership_sessions: Arc::new(Mutex::new(HandshakeSessions::new())),
			node_secret: node_seed.map(NodeSecret::from_seed),
			spend_store,
			quarantine,
			_block: PhantomData,
		}
	}

	/// Verify a caller's chat-auth credentials against the zkpki
	/// runtime API. `payload_bytes` is whatever the caller signed
	/// (the prepared-batch bytes for `chat_send_prepared`, the onion
	/// packet bytes for `chat_send_onion`). Returns the
	/// authenticated `AccountId` on success or a structured error on
	/// any failure.
	fn verify_chat_auth(
		&self,
		payload_bytes: &[u8],
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
			CHAT_AUTH_DOMAIN.len() + payload_bytes.len() + 8,
		);
		to_sign.extend_from_slice(CHAT_AUTH_DOMAIN);
		to_sign.extend_from_slice(payload_bytes);
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
	/// Anonymous-membership handshake (Phase 2). Verifies a Groth16 proof
	/// against the pinned vk and recent chain roots, spends the nullifier, and
	/// records a session. Sync; the async trait method wraps it.
	/// Verify a membership handshake's proof against chain state, with no spend,
	/// returning the validated request. The witnessed spend (committee network
	/// round-trip) and session issuance happen in the async
	/// `authenticate_membership`, which calls this first.
	fn verify_membership_proof(
		&self,
		proof_hex: &str,
		membership_root_hex: &str,
		freshness_root_hex: &str,
		nullifier_hex: &str,
		current_epoch: u64,
		anchor_block: u64,
		session_pubkey_hex: &str,
	) -> Result<HandshakeRequest, ErrorObject<'static>> {
		// Activation gate: inactive until a production verifying key is pinned.
		let vk = self.membership_vk.as_ref().ok_or_else(|| {
			ErrorObject::owned::<()>(
				-32001,
				"chat membership auth not activated on this node",
				None,
			)
		})?;

		// Decode inputs.
		let proof = hex::decode(proof_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("proof_hex", &format!("invalid hex: {e}")))?;
		let membership_root = decode_hex32(membership_root_hex)
			.map_err(|e| invalid_param("membership_root_hex", &e))?;
		let freshness_root = decode_hex32(freshness_root_hex)
			.map_err(|e| invalid_param("freshness_root_hex", &e))?;
		let nullifier = decode_hex32(nullifier_hex)
			.map_err(|e| invalid_param("nullifier_hex", &e))?;
		let session_pubkey = hex::decode(session_pubkey_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("session_pubkey_hex", &format!("invalid hex: {e}")))?;

		let req = HandshakeRequest {
			proof,
			membership_root,
			freshness_root,
			nullifier,
			current_epoch,
			anchor_block,
			session_pubkey,
		};

		// ChainView over the best block.
		let info = self.client.info();
		let chain = RuntimeChainView {
			client: self.client.as_ref(),
			best: info.best_hash,
			best_number: info.best_number.saturated_into::<u64>(),
		};

		// Verify the proof + chain checks only — NO local nullifier spend. The
		// spend is witnessed by the committee in the async caller.
		verify_handshake_proof(vk, &req, &self.node_pubkey_ed25519, &chain).map_err(|e| match e {
			// Hard cutover at the epoch boundary: a proof for a lapsed epoch is
			// rejected with an actionable error so the client rebuilds for the
			// current epoch. No grace window; the boundary stays clean.
			HandshakeError::EpochMismatch => ErrorObject::owned::<()>(
				-32005,
				"epoch rolled; rebuild the membership proof for the current epoch",
				None,
			),
			other => ErrorObject::owned::<()>(
				-32000,
				format!("membership handshake rejected: {other:?}"),
				None,
			),
		})?;
		Ok(req)
	}

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

impl<C> ChatRpc<C>
where
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: ZkPkiApi<Block, AccountId>,
	C::Api: PnsStorageApi<Block, u64, Balance, AccountId>,
{
	/// Membership-session counterpart of [`Self::verify_session_drop`]:
	/// admit a drop signed by a session key the ANONYMOUS handshake
	/// (`chat_authenticateMembership`) authorized. Same Ed25519 check over
	/// `blake2_256(CHAT_SESSION_DROP_DOMAIN ‖ drop_bytes)`, but the lookup
	/// key is the session pubkey itself (there is no cert thumbprint — the
	/// session is anonymous by construction, so nothing is returned on
	/// success) and liveness is epoch-gated rather than wall-clock-gated.
	///
	/// Portable-ticket admission (CHAT-SESSION-TICKET.md 2.2): on a
	/// session-cache miss, the witnessed spend record itself is the
	/// admission ticket — look the session key up in the spend store
	/// (fed by gossip and by `chat_presentSessionTicket`), re-validate it
	/// against the CURRENT guard set + quarantine, and cache the session.
	/// A guard that never saw the handshake admits the same session.
	fn verify_membership_session_drop(
		&self,
		drop_bytes: &[u8],
		session_pubkey_hex: &str,
		session_sig_hex: &str,
	) -> Result<(), ErrorObject<'static>> {
		let session_pubkey = decode_hex32(session_pubkey_hex)
			.map_err(|e| invalid_param("session_cert_thumbprint_hex", &e))?;
		let sig_bytes = hex::decode(session_sig_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("session_sig_hex", &format!("invalid hex: {e}")))?;
		let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
			invalid_param("session_sig_hex", "expected a 64-byte Ed25519 signature")
		})?;

		let info = self.client.info();
		let chain = RuntimeChainView {
			client: self.client.as_ref(),
			best: info.best_hash,
			best_number: info.best_number.saturated_into::<u64>(),
		};
		let current_epoch = chain.current_epoch();

		let cached = {
			let sessions = self
				.membership_sessions
				.lock()
				.map_err(|_| auth_err("membership session lock poisoned"))?;
			sessions
				.live(&session_pubkey, current_epoch)
				.map(|s| s.session_pubkey.clone())
		};
		let stored_pubkey = match cached {
			Some(p) => p,
			None => self.admit_session_ticket(&session_pubkey, current_epoch)?,
		};

		let mut to_sign =
			Vec::with_capacity(CHAT_SESSION_DROP_DOMAIN.len() + drop_bytes.len());
		to_sign.extend_from_slice(CHAT_SESSION_DROP_DOMAIN);
		to_sign.extend_from_slice(drop_bytes);
		let digest = blake2_256(&to_sign);

		let vk = Ed25519VerificationKey::try_from(stored_pubkey.as_slice())
			.map_err(|_| auth_err("stored session pubkey is not a valid Ed25519 key"))?;
		let sig = Ed25519Signature::from(sig_arr);
		vk.verify(&sig, &digest)
			.map_err(|_| auth_err("session-key signature verification failed"))?;
		Ok(())
	}

	/// The spend-store half of portable-ticket admission: find the witnessed
	/// record authorizing `session_pubkey`, validate it against the current
	/// guard set (t-of-k signatures, committee membership) and the quarantine
	/// set, and on success cache an [`AcceptedSession`] so subsequent drops
	/// take the cheap path. Returns the authorized session pubkey.
	fn admit_session_ticket(
		&self,
		session_pubkey: &[u8; 32],
		current_epoch: u64,
	) -> Result<Vec<u8>, ErrorObject<'static>> {
		let record = self
			.spend_store
			.lock()
			.get_by_session(session_pubkey)
			.cloned()
			.ok_or_else(|| {
				auth_err(
					"no live session and no witnessed ticket for this key — \
					 re-handshake (chat_authenticateMembership) or present the \
					 ticket (chat_presentSessionTicket)",
				)
			})?;
		self.install_session_ticket(record, Some(current_epoch))
	}

	/// Validate a witnessed record against the CURRENT guard set + quarantine
	/// and, on success, insert it into the spend store (so it also gossips)
	/// and cache the session. `expected_epoch` pins the record to the caller's
	/// epoch when known (the drop path); `None` uses the chain's current epoch
	/// (the present-ticket path). Returns the authorized session pubkey.
	fn install_session_ticket(
		&self,
		record: rostro_chat_membership_auth::spend::SpendRecord,
		expected_epoch: Option<u64>,
	) -> Result<Vec<u8>, ErrorObject<'static>> {
		use crate::chat_spend_protocol::{NodeSigVerify, COMMITTEE_K, COMMITTEE_T};
		use rostro_chat_membership_auth::spend::verify_record;

		let (chain_epoch, head) = crate::spend_committee::epoch_and_head(&self.client)
			.map_err(|e| auth_err(&format!("epoch/head unavailable: {e}")))?;
		let want = expected_epoch.unwrap_or(chain_epoch);
		if record.epoch != want {
			return Err(auth_err("session ticket is from a different epoch — re-handshake"));
		}
		let guard_set = crate::spend_committee::fetch_guard_set(&self.client, head)
			.map_err(|e| auth_err(&format!("guard set unavailable: {e}")))?;
		verify_record(&record, &guard_set, COMMITTEE_K, COMMITTEE_T, &NodeSigVerify)
			.map_err(|e| auth_err(&format!("session ticket failed verification: {e:?}")))?;
		if !self.quarantine.lock().admits(&record, COMMITTEE_T) {
			return Err(auth_err("session ticket's signers are quarantined"));
		}

		let session_pubkey = record.session_pubkey.clone();
		let session = AcceptedSession {
			session_pubkey: session_pubkey.clone(),
			nullifier: record.nullifier,
			expires_epoch: record.epoch,
		};
		// Insert into the spend store too: a presented ticket then reaches
		// other guards by the same anti-entropy gossip a handshake would.
		let _ = self.spend_store.lock().insert(record);
		self.membership_sessions
			.lock()
			.map_err(|_| auth_err("membership session lock poisoned"))?
			.note_session(session);
		#[cfg(feature = "chat-diagnostics")]
		log::debug!(
			target: "rostro-chat-rpc",
			"membership session installed via witnessed ticket (epoch {})",
			want,
		);
		Ok(session_pubkey)
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
	/// result. `Deliver` → fan the client-prepared chunk batch out to
	/// bucket peers; `Forward` → (slice 2) send the inner onion DIRECTLY
	/// to `next_hop`, never through the chunk path. Caller-agnostic: the
	/// guard RPC does cert-auth before calling this; the relay-2 forward
	/// handler gates on canonical-peer status. Holds no user secret.
	pub(crate) async fn peel_and_dispatch(
		&self,
		packet: &OnionPacket,
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
				// Last hop: fan the client-prepared chunk batch out to the
				// bucket peers (the sender is gone). The drop bytes ARE a
				// SCALE-encoded `PreparedBatch` — split + checksummed on the
				// sender's device; this node holds no key.
				let batch = PreparedBatch::decode(&mut &drop[..]).map_err(|e| {
					ErrorObject::owned::<()>(
						-32000,
						format!("onion deliver batch decode: {e}"),
						None,
					)
				})?;
				// The sender pre-derived the pickup key (for_pairwise for a
				// normal DM, for_deaddrop for a dead drop) inside the batch.
				// The relay is dumb infra: it routes by these opaque bytes
				// and cannot tell the two apart. No key validation,
				// conversion, or hashing here.
				distribute_prepared(
					self.node_pubkey_ed25519,
					&self.bucket_cache,
					&self.network,
					batch,
				)
				.await
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
				// 1a: forward-leg accountability. Sign the inner packet with
				// THIS guard's node key. relay-2 recovers our identity from the
				// authenticated connection and verifies this before peeling; a
				// bad/absent signature is a reputation-docked rejection there. The
				// signature is the guard's OWN node key — never sender material.
				let packet_bytes = inner.encode();
				let guard_sig =
					self.node_secret.sign(&onion_forward_digest(&packet_bytes));
				let request = OnionForwardRequest { packet_bytes, guard_sig };
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
}

/// Shared distribution core: fan a client-prepared chunk batch out to
/// the recipient bucket's peers over `/rostro/chat-chunk/1`. Pure
/// routing — this node validates SHAPE only (it holds no key, by
/// design), stamps its own identity into the descriptors, and pushes
/// each chunk to that chunk's OWN replica set. One implementation for
/// both entries (the onion peeler's `Deliver` arm on relay-2 and the
/// direct `chat_send_prepared` RPC), so the two can never drift.
///
/// INVARIANT — MESSAGE-ONLY, never an onion. Callers must pass a
/// fully-peeled **recipient batch** (the `PreparedBatch` carried by an
/// `OnionHop::Deliver` drop, or a direct `chat_send_prepared`). An
/// onion in flight (an `OnionPacket`, e.g. an `OnionHop::Forward {
/// inner }`) must **never** reach this path: onions are forwarded
/// directly node-to-node, never chunked/bucketed. Chunking an onion to
/// move it between hops — peel → chunk → forward → peel → chunk again
/// — is the exact failure this separation prevents. The `OnionPacket`
/// vs `PreparedBatch` type split enforces it; this note guards against
/// a future caller decoding an onion into a batch to slip it through.
/// See docs/DOTWAVE-CHAT-METADATA-ANONYMITY.md, "Resolved structure".
///
/// ## Per-chunk disjoint replica sets
///
/// The shuffled bucket-peer list is partitioned so chunk `i`'s
/// replicas are `peers[(i·R + j) % peer_count]` for `j in 0..R`
/// (R = [`CHUNK_REPLICATION`]): fully disjoint when the bucket has
/// ≥ total×R peers, minimal round-robin overlap when it doesn't
/// (degraded on small networks — the envelope AEAD still protects
/// content; docs/CHAT-SHARE-CHUNKING.md §4.4). Within one chunk's set
/// the peers are always distinct. This is the fix for the deployed
/// stripe bug where EVERY share went to the SAME peer set, handing
/// each replica the whole message.
async fn distribute_prepared(
	node_pubkey_ed25519: [u8; 32],
	bucket_cache: &BucketCache,
	network: &Arc<dyn NetworkService>,
	batch: PreparedBatch,
) -> RpcResult<ChatSendResult> {
	// Shape + expiry validation at the handoff (reject known-invalid
	// input before any fan-out). Checksums are NOT checked — that is
	// the recipient's local corruption check, not the node's job.
	let total = validate_prepared_batch(&batch, now_unix_seconds()).map_err(|e| {
		invalid_param("batch", &format!("prepared batch rejected: {e:?}"))
	})?;
	let n_chunks = total as usize;

	// Pick bucket peers for the batch's bucket. Reject the send if
	// zero peers subscribe (old-tenant-mail behavior — there's
	// nowhere to deliver).
	let bucket = bucket_for_pickup_key(&batch.pickup_key);
	let mut bucket_peers = bucket_cache.peers_for_bucket(bucket);
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

	// Shuffle with OsRng — predictable selection would let an observer
	// game which peers receive which chunks — then partition into
	// per-chunk replica sets by index arithmetic over the shuffle.
	let mut rng = OsRng;
	let peer_n = bucket_peers.len();
	for i in (1..peer_n).rev() {
		let j = (rng.next_u64() as usize) % (i + 1);
		bucket_peers.swap(i, j);
	}
	let n_replicas = CHUNK_REPLICATION.min(peer_n);

	let mut stored_total: usize = 0;
	let mut rejected_total: usize = 0;
	let mut transport_failed_total: usize = 0;
	// A message is deliverable iff EVERY chunk landed somewhere; count
	// chunks with ≥1 Stored rather than raw store successes (the old
	// stripe criterion would accept chunk 0 stored five times while
	// chunk 3 landed nowhere).
	let mut chunks_landed: usize = 0;

	for (ci, share) in batch.shares.iter().enumerate() {
		let descriptor = ShareDescriptor {
			relay_pubkey: RelayPubkey(node_pubkey_ed25519),
			message_id: batch.message_id,
			share_index: share.share_index,
			total_shares: share.total_shares,
			pickup_key: batch.pickup_key,
			expires_at_unix_ts: share.expires_at_unix_ts,
		};
		let store_req = StoreRequest {
			descriptor,
			share_bytes: share.chunk_bytes.clone(),
			checksum: share.checksum,
		};
		let request_bytes = store_req.encode();

		let mut this_chunk_stored: usize = 0;
		for j in 0..n_replicas {
			// Consecutive residues mod peer_n: distinct within the
			// set (n_replicas ≤ peer_n), disjoint across chunks when
			// peer_n ≥ n_chunks × n_replicas.
			let peer = bucket_peers[(ci * n_replicas + j) % peer_n];
			match network
				.request(
					peer,
					ProtocolName::from(CHAT_CHUNK_PROTOCOL_NAME),
					request_bytes.clone(),
					None,
					IfDisconnected::TryConnect,
				)
				.await
			{
				Ok((resp_bytes, _)) => match StoreResponse::decode(&mut &resp_bytes[..]) {
					Ok(StoreResponse::Stored) => {
						stored_total += 1;
						this_chunk_stored += 1;
					}
					Ok(StoreResponse::Rejected(StoreRejection::DuplicateShare)) => {
						// Duplicate on a retry is fine — the chunk is there.
						stored_total += 1;
						this_chunk_stored += 1;
					}
					Ok(StoreResponse::Rejected(reason)) => {
						rejected_total += 1;
						// No message_id: a chunk-placement rejection must
						// not link the chunk to its message on a persisted
						// log line (GUARD-PRIVACY-AUDIT G2). share_index +
						// peer + reason are operational.
						log::debug!(
							target: "rostro-chat-rpc",
							"push chunk {} to {} rejected: {:?}",
							share.share_index,
							peer,
							reason,
						);
					}
					Err(_) => {
						transport_failed_total += 1;
						log::debug!(
							target: "rostro-chat-rpc",
							"push to {}: undecodable StoreResponse",
							peer,
						);
					}
				},
				Err(e) => {
					transport_failed_total += 1;
					// No message_id (GUARD-PRIVACY-AUDIT G2).
					log::debug!(
						target: "rostro-chat-rpc",
						"push chunk {} to {} transport failed: {:?}",
						share.share_index,
						peer,
						e,
					);
				}
			}
		}
		if this_chunk_stored > 0 {
			chunks_landed += 1;
		}
	}

	// No message_id: even the lab build must not link a distribute
	// outcome to its message (GUARD-PRIVACY-AUDIT G3). Aggregate
	// chunk counts are operational.
	#[cfg(feature = "chat-diagnostics")]
	log::info!(
		target: "rostro-chat-rpc",
		"chat distribute: chunks={n_chunks} landed={chunks_landed} \
		 stored={stored_total} rejected={rejected_total} \
		 transport_failed={transport_failed_total}",
	);

	if chunks_landed < n_chunks {
		return Err(ErrorObject::owned::<()>(
			-32000,
			format!(
				"only {chunks_landed} of {n_chunks} chunks landed on at least \
				 one replica (every chunk is required for recipient assembly); \
				 {stored_total} stores succeeded, {rejected_total} rejected, \
				 {transport_failed_total} transport-failed",
			),
			None,
		));
	}

	Ok(ChatSendResult {
		message_id_hex: hex::encode(batch.message_id.0),
		share_count: n_chunks as u32,
		recipient_pickup_key_hex: hex::encode(batch.pickup_key.0),
	})
}

#[async_trait]
impl<C> ChatRpcApiServer for ChatRpc<C>
where
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: ZkPkiApi<Block, AccountId>,
	C::Api: PnsStorageApi<Block, u64, Balance, AccountId>,
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

	async fn send_prepared(
		&self,
		batch_hex: String,
		auth_cert_thumbprint_hex: Option<String>,
		auth_timestamp_secs: Option<u64>,
		auth_sig_hex: Option<String>,
	) -> RpcResult<ChatSendResult> {
		let batch_bytes = hex::decode(batch_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("batch_hex", &format!("invalid hex: {e}")))?;

		// Chat-auth verification (Phase 2: cert-gated send) over the
		// EXACT batch bytes. All three auth-* parameters are required;
		// there is no unauthenticated path.
		match (auth_cert_thumbprint_hex, auth_timestamp_secs, auth_sig_hex) {
			(Some(tp), Some(ts), Some(sig)) => {
				// The `?` is the auth gate; the account it returns must
				// not persist on a log line (GUARD-PRIVACY-AUDIT G3).
				self.verify_chat_auth(&batch_bytes, &tp, ts, &sig)?;
				#[cfg(feature = "chat-diagnostics")]
				log::debug!(
					target: "rostro-chat-rpc",
					"chat_send_prepared authenticated via cert session",
				);
			}
			_ => {
				return Err(invalid_param(
					"auth_*",
					"chat_send_prepared requires cert auth: all three of \
					 auth_cert_thumbprint_hex, auth_timestamp_secs, \
					 auth_sig_hex must be present, signed by an Active \
					 zkpki cert's device key",
				));
			}
		}

		let batch = PreparedBatch::decode(&mut &batch_bytes[..]).map_err(|e| {
			invalid_param("batch_hex", &format!("SCALE-decode failed: {e}"))
		})?;

		distribute_prepared(
			self.node_pubkey_ed25519,
			&self.bucket_cache,
			&self.network,
			batch,
		)
		.await
	}

	async fn send_onion(
		&self,
		onion_packet_hex: String,
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
				// One session-auth surface, two stores: the identified
				// cert-session store (keyed by cert thumbprint) and the
				// anonymous membership-session store (keyed by the session
				// pubkey `chat_authenticateMembership` authorized). Try the
				// cert store first; on ANY miss fall through to membership —
				// the same 32-byte param carries whichever key the client's
				// handshake produced, and the signature check is identical.
				match self.verify_session_drop(&packet_bytes, &tp, &sig) {
					Ok(_) => {
						// Account dropped from the log (GUARD-PRIVACY-AUDIT G3).
						#[cfg(feature = "chat-diagnostics")]
						log::debug!(
							target: "rostro-chat-rpc",
							"chat_send_onion authenticated via cert session",
						);
					}
					Err(_) => {
						self.verify_membership_session_drop(&packet_bytes, &tp, &sig)?;
						#[cfg(feature = "chat-diagnostics")]
						log::debug!(
							target: "rostro-chat-rpc",
							"chat_send_onion authenticated via anonymous membership session",
						);
					}
				}
			}
			_ => match (auth_cert_thumbprint_hex, auth_timestamp_secs, auth_sig_hex) {
				(Some(tp), Some(ts), Some(sig)) => {
					// The `?` is the auth gate; account dropped from the log
					// (GUARD-PRIVACY-AUDIT G3).
					self.verify_chat_auth(&packet_bytes, &tp, ts, &sig)?;
					#[cfg(feature = "chat-diagnostics")]
					log::debug!(
						target: "rostro-chat-rpc",
						"chat_send_onion authenticated via cert auth",
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
		ctx.peel_and_dispatch(&packet, PeelMode::GuardEntry).await
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
							matched.push((fs.descriptor, fs.share_bytes, fs.checksum));
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

		// Bucket-peer aggregation. If after the local store + any
		// explicit-peer lookup the view is empty OR any message is
		// missing chunks, query bucket peers from the BucketCache and
		// merge. This makes the "hit any RPC node" property hold for
		// fetch — and it is REQUIRED under per-chunk disjoint replica
		// sets: chunks of one message deliberately land on different
		// relays, so a single store (including our own) holding a
		// complete message is the exception, not the rule.
		//
		// Why "incomplete" and not "always": once every matched
		// message has all its chunks there is nothing left to gather,
		// and the loop below also stops early on completeness for the
		// same reason.
		if matched.is_empty() || matched_set_incomplete(&matched) {
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

			// bucket is a coarse pickup locator; this fetch event stays
			// out of the canonical binary (GUARD-PRIVACY-AUDIT G3).
			#[cfg(feature = "chat-diagnostics")]
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
				// Stop as soon as every matched message is complete —
				// don't burn the whole peer budget on nothing.
				if !matched.is_empty() && !matched_set_incomplete(&matched) {
					break;
				}
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
								// Share-hit count is a delivery event; keep it
								// out of the canonical binary (G3).
								#[cfg(feature = "chat-diagnostics")]
								let n = resp.shares.len();
								for fs in resp.shares {
									matched.push((fs.descriptor, fs.share_bytes, fs.checksum));
								}
								#[cfg(feature = "chat-diagnostics")]
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
		for (descriptor, share_bytes, checksum) in matched {
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
				checksum_hex: hex::encode(checksum),
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

	async fn authenticate_membership(
		&self,
		proof_hex: String,
		membership_root_hex: String,
		freshness_root_hex: String,
		nullifier_hex: String,
		current_epoch: u64,
		anchor_block: u64,
		session_pubkey_hex: String,
	) -> RpcResult<ChatMembershipAuthResult> {
		// 1. Verify the proof against chain state. No local nullifier spend.
		let req = self.verify_membership_proof(
			&proof_hex,
			&membership_root_hex,
			&freshness_root_hex,
			&nullifier_hex,
			current_epoch,
			anchor_block,
			&session_pubkey_hex,
		)?;

		// 2. The verifier signs as its node identity; without a persistent libp2p
		//    key it cannot participate in the witnessed spend.
		let node_secret = self.node_secret.as_ref().ok_or_else(|| {
			ErrorObject::owned::<()>(
				-32002,
				"membership auth requires a persistent node identity (set --node-key)",
				None,
			)
		})?;

		// 3. Witnessed spend: the committee collects t counter-signatures. The
		//    committee is a single serialisation point per nullifier, so a member
		//    round-robining across guards cannot assemble a second quorum.
		let record = crate::chat_spend_protocol::run_verifier(
			&self.network,
			&self.client,
			node_secret,
			self.node_pubkey_ed25519,
			&self.spend_store,
			&self.quarantine,
			&req,
		)
		.await
		.map_err(|e| match e {
			VerifierError::AlreadySpent => {
				ErrorObject::owned::<()>(-32003, "nullifier already spent this epoch", None)
			}
			VerifierError::Committee(s) => {
				ErrorObject::owned::<()>(-32000, format!("witness committee unavailable: {s}"), None)
			}
			VerifierError::InsufficientWitnesses { got, need } => ErrorObject::owned::<()>(
				-32004,
				format!("insufficient committee witnesses: {got}/{need}"),
				None,
			),
		})?;

		// 4. Issue the session, keyed by session pubkey, for cheap per-drop auth.
		//    No local spend recorded here: the committee enforced single-use.
		let session = AcceptedSession {
			session_pubkey: req.session_pubkey.clone(),
			nullifier: req.nullifier,
			expires_epoch: req.current_epoch,
		};
		{
			let mut sessions = self.membership_sessions.lock().map_err(|_| {
				ErrorObject::owned::<()>(-32000, "membership session lock poisoned", None)
			})?;
			sessions.note_session(session.clone());
		}

		Ok(ChatMembershipAuthResult {
			session_pubkey_hex: format!("0x{}", hex::encode(&session.session_pubkey)),
			expires_epoch: session.expires_epoch,
			current_epoch,
			ticket_hex: format!("0x{}", hex::encode(record.encode())),
		})
	}

	async fn present_session_ticket(&self, ticket_hex: String) -> RpcResult<u64> {
		let bytes = hex::decode(ticket_hex.trim_start_matches("0x"))
			.map_err(|e| invalid_param("ticket_hex", &format!("invalid hex: {e}")))?;
		let record = rostro_chat_membership_auth::spend::SpendRecord::decode(&mut &bytes[..])
			.map_err(|e| invalid_param("ticket_hex", &format!("SCALE-decode failed: {e}")))?;
		let epoch = record.epoch;
		// None => validate against the chain's CURRENT epoch, so a ticket from
		// a past epoch is refused (the record.epoch == current_epoch check in
		// install_session_ticket does this); on success `epoch` is that epoch.
		self.install_session_ticket(record, None)?;
		Ok(epoch)
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

/// `true` if any message in the matched share set is still missing
/// chunks (fewer distinct `share_index` values than its
/// `total_shares` claims). With per-chunk DISJOINT replica sets a
/// single relay holding SOME chunks of a message is the NORMAL case,
/// so fetch aggregation triggers on incompleteness, not only on an
/// empty local view. Duplicates across sources are absorbed by the
/// index set.
fn matched_set_incomplete(matched: &[(ShareDescriptor, Vec<u8>, ChunkChecksum)]) -> bool {
	use std::collections::HashSet;
	let mut per_message: HashMap<MessageId, (u8, HashSet<ShareIndex>)> = HashMap::new();
	for (d, _, _) in matched {
		let entry = per_message
			.entry(d.message_id)
			.or_insert_with(|| (d.total_shares, HashSet::new()));
		entry.1.insert(d.share_index);
	}
	per_message
		.values()
		.any(|(total, have)| have.len() < *total as usize)
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
