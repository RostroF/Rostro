// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase Z4 — libp2p binding for the validator-only encrypted gossip
//! channel.
//!
//! Two protocols on sc-network:
//!
//! * **`/rostro/validator-channel-handshake/1`** (request/response):
//!   exchanges [`HandshakePayload`]s. Each side signs its X25519
//!   ephemeral with its GRANDPA Ed25519 session key from the local
//!   keystore. The receiver verifies the signature AND looks up the
//!   claimed pubkey in the on-chain active-validator set via
//!   [`crate::active_authority_set`]. Both checks must pass before a
//!   [`Session`] is established.
//!
//! * **`/rostro/validator-channel/1`** (notification): carries
//!   encrypted [`WireMessage`]s once a Session is established.
//!   Heartbeats demonstrate the channel works; future GRANDPA
//!   integration replaces / wraps this content.
//!
//! ## Initiation rule
//!
//! Race conditions are sidestepped by a strict **lower-PeerId
//! initiates** rule: when peer X connects, only the side whose own
//! PeerId compares lexicographically less than X's PeerId opens the
//! handshake. The other side waits for the inbound. Result: exactly
//! one handshake exchange per peer pair per connection.
//!
//! ## Single-owner task pattern
//!
//! The notification service is owned by exactly one task
//! ([`run_notification_task`]) that handles both inbound decrypt
//! and outbound heartbeat send in a single `tokio::select!`. This
//! sidesteps the `&mut self` async-await constraint on
//! [`NotificationService::next_event`] without resorting to
//! `Mutex<Box<dyn NotificationService>>` (which would either block
//! across awaits or fail Send bounds).
//!
//! ## What's deferred to Z5
//!
//! Authority-set rotation. v0 assumes the active set is stable for
//! the duration of the lab run; rotation handling is its own
//! workstream.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use codec::{Decode, Encode};
use futures::StreamExt;
use parking_lot::Mutex;
use rand_core::OsRng;
use rc_network::{
	config::{NonReservedPeerMode, SetConfig},
	peer_store::PeerStoreProvider,
	request_responses::{IncomingRequest, OutgoingResponse},
	service::traits::{
		NetworkRequest, NetworkStateInfo, NotificationEvent, NotificationService,
		ValidationResult,
	},
	service::NotificationMetrics,
	types::ProtocolName,
	IfDisconnected, NetworkBackend, PeerId,
};
use rostro_validator_channel::{
	handshake_preimage, handshake_shared_secret, verify_handshake, HandshakeError,
	HandshakePayload, Session, WireMessage,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_grandpa::{GrandpaApi, KEY_TYPE as GRANDPA_KEY_TYPE};
use sp_core::ed25519 as sp_ed25519;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use crate::active_authority_set::is_active_authority;

/// libp2p request-response protocol for the handshake exchange.
pub const HANDSHAKE_PROTOCOL_NAME: &str = "/rostro/validator-channel-handshake/1";

/// libp2p notification protocol for encrypted message exchange after
/// a handshake has established a Session.
pub const NOTIFICATION_PROTOCOL_NAME: &str = "/rostro/validator-channel/1";

const INBOUND_QUEUE_CAPACITY: usize = 64;
const MAX_HANDSHAKE_REQUEST_SIZE: u64 = 512;
const MAX_HANDSHAKE_RESPONSE_SIZE: u64 = 512;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const HEARTBEAT_INTERVAL_SECS: u64 = 10;
const MAX_NOTIFICATION_SIZE: u64 = 1024 * 1024;

/// On-the-wire handshake reply. Either accepts (returning the
/// responder's own [`HandshakePayload`]) or explicitly rejects (giving
/// the initiator a clear signal not to retry until the active set
/// rotates).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum HandshakeReply {
	Accept(HandshakePayload),
	Reject,
}

/// Shared per-peer Session map. Populated when a handshake succeeds;
/// drained on disconnect.
pub type SharedSessions = Arc<Mutex<HashMap<PeerId, Session>>>;

/// In-flight ephemeral X25519 secrets for handshakes we've
/// initiated. Removed when the response arrives (success or
/// failure).
type PendingEphemerals = Arc<Mutex<HashMap<PeerId, X25519SecretKey>>>;

/// Our own GRANDPA Ed25519 pubkey (if we're a validator). `None` for
/// non-validators — the handshake task only runs when this is Some.
#[derive(Clone)]
pub struct LocalAuthorityKey {
	pub pubkey: [u8; 32],
}

impl LocalAuthorityKey {
	/// Probe the keystore for a local GRANDPA pubkey. Returns the
	/// first one found, or `None` if we're not configured as a
	/// validator (no GRANDPA key in the keystore).
	pub fn from_keystore(keystore: &KeystorePtr) -> Option<Self> {
		let keys = keystore.ed25519_public_keys(GRANDPA_KEY_TYPE);
		keys.first().map(|pk| {
			let bytes: [u8; 32] = AsRef::<[u8]>::as_ref(pk)
				.try_into()
				.expect("Ed25519 pubkey is 32 bytes");
			LocalAuthorityKey { pubkey: bytes }
		})
	}
}

// ───── Handshake server protocol ───────────────────────────────────────

pub fn build_handshake_server<N, C, Block>(
	client: Arc<C>,
	keystore: KeystorePtr,
	local_authority: LocalAuthorityKey,
	sessions: SharedSessions,
) -> (N::RequestResponseProtocolConfig, impl std::future::Future<Output = ()>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: GrandpaApi<Block>,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);
	let config = N::request_response_config(
		ProtocolName::from(HANDSHAKE_PROTOCOL_NAME),
		Vec::new(),
		MAX_HANDSHAKE_REQUEST_SIZE,
		MAX_HANDSHAKE_RESPONSE_SIZE,
		Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
		Some(tx),
	);
	let handler = run_handshake_server(client, keystore, local_authority, sessions, rx);
	(config, handler)
}

async fn run_handshake_server<C, Block>(
	client: Arc<C>,
	keystore: KeystorePtr,
	local_authority: LocalAuthorityKey,
	sessions: SharedSessions,
	mut rx: async_channel::Receiver<IncomingRequest>,
) where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: GrandpaApi<Block>,
{
	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		let reply = handle_handshake_inbound::<C, Block>(
			&client,
			&keystore,
			&local_authority,
			&sessions,
			peer,
			&payload,
		);
		let _ = pending_response.send(OutgoingResponse {
			result: Ok(reply.encode()),
			reputation_changes: Vec::new(),
			sent_feedback: None,
		});
	}
}

fn handle_handshake_inbound<C, Block>(
	client: &Arc<C>,
	keystore: &KeystorePtr,
	local_authority: &LocalAuthorityKey,
	sessions: &SharedSessions,
	peer: PeerId,
	payload: &[u8],
) -> HandshakeReply
where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: GrandpaApi<Block>,
{
	let req = match HandshakePayload::decode(&mut &payload[..]) {
		Ok(r) => r,
		Err(_) => {
			log::debug!(
				target: "rostro-validator-channel",
				"undecodable handshake from {}; rejecting",
				peer,
			);
			return HandshakeReply::Reject;
		},
	};

	match is_active_authority(client, &req.claimed_pubkey) {
		Ok(true) => {},
		Ok(false) => {
			log::debug!(
				target: "rostro-validator-channel",
				"peer {} claimed pubkey 0x{} not in active validator set; rejecting",
				peer,
				hex_prefix(&req.claimed_pubkey, 8),
			);
			return HandshakeReply::Reject;
		},
		Err(e) => {
			log::warn!(
				target: "rostro-validator-channel",
				"active-set lookup failed during handshake from {}: {}",
				peer,
				e,
			);
			return HandshakeReply::Reject;
		},
	}

	if let Err(HandshakeError::SignatureInvalid | HandshakeError::InvalidPubkey) =
		verify_handshake(&req)
	{
		log::warn!(
			target: "rostro-validator-channel",
			"handshake signature verification failed from {}; rejecting",
			peer,
		);
		return HandshakeReply::Reject;
	}

	let our_eph_secret = X25519SecretKey::random_from_rng(OsRng);
	let our_eph_pub = X25519PublicKey::from(&our_eph_secret);
	let our_preimage = handshake_preimage(&local_authority.pubkey, our_eph_pub.as_bytes());
	let sp_pubkey = sp_ed25519::Public::from(local_authority.pubkey);
	let signature = match keystore.ed25519_sign(GRANDPA_KEY_TYPE, &sp_pubkey, &our_preimage) {
		Ok(Some(sig)) => sig,
		Ok(None) => {
			log::warn!(
				target: "rostro-validator-channel",
				"keystore has no signing key for our claimed authority pubkey; cannot \
				 respond to handshake from {}",
				peer,
			);
			return HandshakeReply::Reject;
		},
		Err(e) => {
			log::warn!(
				target: "rostro-validator-channel",
				"keystore signing failed during handshake from {}: {:?}",
				peer,
				e,
			);
			return HandshakeReply::Reject;
		},
	};

	let our_payload = HandshakePayload {
		claimed_pubkey: local_authority.pubkey,
		ephemeral_x25519: *our_eph_pub.as_bytes(),
		signature: signature.0,
	};

	let peer_eph_pub = X25519PublicKey::from(req.ephemeral_x25519);
	let shared = handshake_shared_secret(&our_eph_secret, &peer_eph_pub);
	let session = Session::from_handshake_responder(shared, our_eph_secret, peer_eph_pub);
	sessions.lock().insert(peer, session);
	log::info!(
		target: "rostro-validator-channel",
		"established responder session with peer {} (pubkey 0x{}…)",
		peer,
		hex_prefix(&req.claimed_pubkey, 8),
	);

	HandshakeReply::Accept(our_payload)
}

// ───── Notification protocol config ────────────────────────────────────

/// Build the notification protocol config + handle. Caller (service.rs)
/// provides the metrics + peerstore from the network builder context.
pub fn build_notification_protocol<N, Block>(
	metrics: NotificationMetrics,
	peer_store: Arc<dyn PeerStoreProvider>,
) -> (N::NotificationProtocolConfig, Box<dyn NotificationService>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
{
	N::notification_config(
		ProtocolName::from(NOTIFICATION_PROTOCOL_NAME),
		Vec::new(),
		MAX_NOTIFICATION_SIZE,
		None, // no handshake; OOB via the request-response protocol above
		SetConfig {
			in_peers: 64,
			out_peers: 64,
			reserved_nodes: Vec::new(),
			non_reserved_mode: NonReservedPeerMode::Accept,
		},
		metrics,
		peer_store,
	)
}

// ───── Outbound handshake helper (used by run_notification_task) ──────

async fn handle_handshake_outbound<N>(
	network: Arc<N>,
	peer: PeerId,
	request_bytes: Vec<u8>,
	pending: PendingEphemerals,
	sessions: SharedSessions,
) where
	N: NetworkRequest + ?Sized,
{
	let result = network
		.request(
			peer,
			ProtocolName::from(HANDSHAKE_PROTOCOL_NAME),
			request_bytes,
			None,
			IfDisconnected::ImmediateError,
		)
		.await;
	let (response_bytes, _) = match result {
		Ok(r) => r,
		Err(e) => {
			log::debug!(
				target: "rostro-validator-channel",
				"handshake request to {} failed: {:?}",
				peer,
				e,
			);
			pending.lock().remove(&peer);
			return;
		},
	};

	let reply = match HandshakeReply::decode(&mut &response_bytes[..]) {
		Ok(r) => r,
		Err(_) => {
			log::warn!(
				target: "rostro-validator-channel",
				"undecodable handshake reply from {}",
				peer,
			);
			pending.lock().remove(&peer);
			return;
		},
	};

	let peer_payload = match reply {
		HandshakeReply::Accept(p) => p,
		HandshakeReply::Reject => {
			log::debug!(
				target: "rostro-validator-channel",
				"peer {} rejected our handshake (not in active set or sig check failed)",
				peer,
			);
			pending.lock().remove(&peer);
			return;
		},
	};

	if verify_handshake(&peer_payload).is_err() {
		log::warn!(
			target: "rostro-validator-channel",
			"responder {} signature verification failed; aborting",
			peer,
		);
		pending.lock().remove(&peer);
		return;
	}

	let our_eph_secret = match pending.lock().remove(&peer) {
		Some(s) => s,
		None => return,
	};
	let peer_eph_pub = X25519PublicKey::from(peer_payload.ephemeral_x25519);
	let shared = handshake_shared_secret(&our_eph_secret, &peer_eph_pub);
	let session = Session::from_handshake_initiator(shared, our_eph_secret, peer_eph_pub);
	sessions.lock().insert(peer, session);
	log::info!(
		target: "rostro-validator-channel",
		"established initiator session with peer {} (pubkey 0x{}…)",
		peer,
		hex_prefix(&peer_payload.claimed_pubkey, 8),
	);
}

// ───── Notification task (single owner of the NotificationService) ─────

/// Single task owning the NotificationService. Handles four things
/// in one `tokio::select!` loop:
///
/// 1. **Handshake initiation** on
///    [`NotificationEvent::NotificationStreamOpened`] — when the
///    peer-set machinery opens a notification substream with a peer,
///    if the lower-PeerId-initiates rule says we go first, we send
///    a handshake via the request/response protocol. On success,
///    register an initiator [`Session`] in the shared map.
/// 2. **Inbound decrypt** on
///    [`NotificationEvent::NotificationReceived`]: decrypt the
///    [`WireMessage`] with the peer's `Session` and log the
///    plaintext.
/// 3. **Inbound substream validation** on
///    [`NotificationEvent::ValidateInboundSubstream`]: accept any
///    inbound substream. The cryptographic auth happens at the
///    request/response handshake layer, not at substream-open.
/// 4. **Heartbeat send** on a periodic timer: encrypt a small
///    "I'm alive at t=…" message with each established session and
///    push via `send_sync_notification`.
///
/// This module was previously split into a separate
/// `run_handshake_asker` (subscribed to
/// [`NetworkEventStream::event_stream`]) plus a notification task.
/// That design didn't work because Substrate's
/// `NetworkService::event_stream` no longer emits
/// `NotificationStreamOpened` events for individual notification
/// protocols — those events now come **only** via the per-protocol
/// `NotificationService::next_event` channel. Consolidating both
/// concerns into one task that owns the NotificationService is
/// the correct pattern under the current sc-network API.
pub async fn run_notification_task<N>(
	mut notification_service: Box<dyn NotificationService>,
	network: Arc<N>,
	keystore: KeystorePtr,
	local_authority: LocalAuthorityKey,
	sessions: SharedSessions,
	our_pubkey: [u8; 32],
) where
	N: NetworkRequest + NetworkStateInfo + Send + Sync + 'static + ?Sized,
{
	let local_peer_id = network.local_peer_id();
	let pending: PendingEphemerals = Arc::new(Mutex::new(HashMap::new()));

	let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
	// `interval.tick()` returns immediately on first call; skip it.
	interval.tick().await;

	loop {
		tokio::select! {
			event = notification_service.next_event() => {
				match event {
					Some(NotificationEvent::NotificationStreamOpened { peer, .. }) => {
						// New peer-set substream for our protocol. Use this as
						// our trigger to run the X3DH-lite handshake.
						if sessions.lock().contains_key(&peer) {
							continue;
						}
						if pending.lock().contains_key(&peer) {
							continue;
						}
						if !should_initiate(&local_peer_id, &peer) {
							log::debug!(
								target: "rostro-validator-channel",
								"peer {} has lower PeerId; they initiate the handshake",
								peer,
							);
							continue;
						}

						let our_eph_secret = X25519SecretKey::random_from_rng(OsRng);
						let our_eph_pub = X25519PublicKey::from(&our_eph_secret);
						let preimage =
							handshake_preimage(&local_authority.pubkey, our_eph_pub.as_bytes());
						let sp_pubkey = sp_ed25519::Public::from(local_authority.pubkey);
						let signature = match keystore.ed25519_sign(
							GRANDPA_KEY_TYPE,
							&sp_pubkey,
							&preimage,
						) {
							Ok(Some(s)) => s,
							_ => {
								log::warn!(
									target: "rostro-validator-channel",
									"could not sign our handshake (missing key?); skipping {}",
									peer,
								);
								continue;
							},
						};
						let our_payload = HandshakePayload {
							claimed_pubkey: local_authority.pubkey,
							ephemeral_x25519: *our_eph_pub.as_bytes(),
							signature: signature.0,
						};
						pending.lock().insert(peer, our_eph_secret);

						let net = network.clone();
						let pending_for_task = pending.clone();
						let sessions_for_task = sessions.clone();
						let request_bytes = our_payload.encode();
						tokio::spawn(async move {
							handle_handshake_outbound(
								net,
								peer,
								request_bytes,
								pending_for_task,
								sessions_for_task,
							)
							.await;
						});
					},
					Some(NotificationEvent::NotificationStreamClosed { peer }) => {
						sessions.lock().remove(&peer);
						pending.lock().remove(&peer);
					},
					Some(NotificationEvent::NotificationReceived { peer, notification }) => {
						let wire = match WireMessage::decode(&mut &notification[..]) {
							Ok(m) => m,
							Err(_) => {
								log::debug!(
									target: "rostro-validator-channel",
									"undecodable wire message from {}",
									peer,
								);
								continue;
							},
						};
						let plaintext = {
							let mut s = sessions.lock();
							let sess = match s.get_mut(&peer) {
								Some(s) => s,
								None => {
									log::debug!(
										target: "rostro-validator-channel",
										"wire message from {} with no session; dropping",
										peer,
									);
									continue;
								},
							};
							match sess.decrypt(&wire) {
								Ok(p) => p,
								Err(e) => {
									log::warn!(
										target: "rostro-validator-channel",
										"decryption from {} failed: {:?}",
										peer,
										e,
									);
									continue;
								},
							}
						};
						log::info!(
							target: "rostro-validator-channel",
							"decrypted message from {}: {}",
							peer,
							String::from_utf8_lossy(&plaintext),
						);
					},
					Some(NotificationEvent::ValidateInboundSubstream { peer, result_tx, .. }) => {
						// Accept any inbound — auth happens OOB via
						// the request-response handshake.
						let _ = result_tx.send(ValidationResult::Accept);
						log::trace!(
							target: "rostro-validator-channel",
							"accepted inbound notification substream from {}",
							peer,
						);
					},
					Some(_) => {},
					None => {
						log::warn!(
							target: "rostro-validator-channel",
							"notification service stream ended",
						);
						return;
					},
				}
			},
			_ = interval.tick() => {
				let now = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.map(|d| d.as_secs())
					.unwrap_or(0);
				let payload = format!(
					"hb from 0x{}… at t={}",
					hex_prefix(&our_pubkey, 8),
					now,
				);

				// Collect peer + encrypted bytes under one lock pass
				// to avoid holding the mutex across the send loop.
				let to_send: Vec<(PeerId, Vec<u8>)> = {
					let mut s = sessions.lock();
					s.iter_mut()
						.map(|(peer, sess)| {
							let wire = sess.encrypt(payload.as_bytes());
							(*peer, wire.encode())
						})
						.collect()
				};

				for (peer, bytes) in to_send {
					notification_service.send_sync_notification(&peer, bytes);
					log::trace!(
						target: "rostro-validator-channel",
						"sent encrypted heartbeat to {}",
						peer,
					);
				}
			},
		}
	}
}

// ───── Helpers ─────────────────────────────────────────────────────────

/// Lower-PeerId-initiates. Both sides agree on a single initiator
/// per pair so we don't get duplicate handshake exchanges.
fn should_initiate(local: &PeerId, remote: &PeerId) -> bool {
	local.to_bytes() < remote.to_bytes()
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
	let n = n.min(bytes.len());
	let mut s = String::with_capacity(n * 2);
	for b in &bytes[..n] {
		s.push(nibble(b >> 4));
		s.push(nibble(b & 0x0f));
	}
	s
}

fn nibble(n: u8) -> char {
	match n {
		0..=9 => (b'0' + n) as char,
		_ => (b'a' + n - 10) as char,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hex_prefix_truncates_to_requested_length() {
		assert_eq!(hex_prefix(&[0xAB, 0xCD, 0xEF], 2), "abcd");
		assert_eq!(hex_prefix(&[0xAB, 0xCD], 0), "");
	}

	#[test]
	fn hex_prefix_handles_short_input() {
		assert_eq!(hex_prefix(&[0xAB], 8), "ab");
	}

	#[test]
	fn handshake_reply_scale_roundtrip() {
		let accept = HandshakeReply::Accept(HandshakePayload {
			claimed_pubkey: [0x11; 32],
			ephemeral_x25519: [0x22; 32],
			signature: [0x33; 64],
		});
		let reject = HandshakeReply::Reject;
		assert_eq!(
			HandshakeReply::decode(&mut &accept.encode()[..]).unwrap(),
			accept,
		);
		assert_eq!(
			HandshakeReply::decode(&mut &reject.encode()[..]).unwrap(),
			reject,
		);
	}

	// PeerId byte-comparison for initiation rule. We can't easily
	// build "real" PeerIds in unit tests (they're derived from
	// libp2p Identity keys), but the documented invariant is:
	// `local.to_bytes() < remote.to_bytes()` ⇒ local initiates.
	// Compile-test only; real behavior is verified in Z6 scenarios.
}
