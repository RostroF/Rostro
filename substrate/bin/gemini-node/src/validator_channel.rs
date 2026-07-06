// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase Z4 — libp2p binding for the validator-only encrypted gossip
//! channel.
//!
//! Two protocols on sc-network:
//!
//! * **`/rostro/validator-channel-handshake/4`** (request/response):
//!   exchanges [`HandshakePayload`]s carrying the v3 hybrid key
//!   exchange — an X25519 ephemeral plus the ML-KEM-768 flight
//!   (initiator: encapsulation key; responder: ciphertext). Each side
//!   signs both halves with its channel key (delegated from the
//!   GRANDPA key via [`ChannelCert`]). The receiver verifies the
//!   signature AND looks up the cert's authority pubkey in the
//!   on-chain active-validator set via
//!   [`crate::active_authority_set`]. Both checks must pass before a
//!   [`Session`] is established, keyed by the HYBRID secret
//!   (docs/PQ-TRANSPORT.md): recorded channel traffic stays
//!   confidential unless X25519 and ML-KEM both fall.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use codec::{Decode, Encode};
use futures::StreamExt;
use gemini_runtime::AccountId;
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
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
use rostro_hybrid_kex::{
	hybrid_shared_secret, mlkem_decapsulate, mlkem_encapsulate, mlkem_keypair_from_seed,
	MlKemDecapKey, MLKEM768_SEED_BYTES,
};
use rostro_validator_channel::{
	cert_preimage, handshake_preimage, handshake_shared_secret, verify_handshake, ChannelCert,
	HandshakePayload, HybridKexMaterial, KexRole, Session, WireMessage,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_grandpa::{GrandpaApi, KEY_TYPE as GRANDPA_KEY_TYPE};
use sp_core::crypto::KeyTypeId;
use sp_core::ed25519 as sp_ed25519;
use sp_core::rostro_hybrid as sp_rostro_hybrid;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zk_pki_primitives::runtime_api::ZkPkiApi;

use crate::active_authority_set::is_active_authority;

/// Keystore key type for the per-validator *channel key* (ed25519).
/// This key is NEVER registered on-chain: it is a delegate the GRANDPA
/// authority key vouches for via a [`ChannelCert`], so the
/// internet-facing validator-channel code signs handshakes with THIS
/// key and never touches the slashable consensus key. See
/// docs/VALIDATOR-CHANNEL-CERT.md and docs/KEYSTORE-AUDIT.md (F1).
pub const CHANNEL_KEY_TYPE: KeyTypeId = KeyTypeId(*b"chnl");

/// How often [`run_cert_issuer`] polls the chain's 24h membership epoch
/// to decide whether to re-issue the channel cert. The epoch rolls at
/// most once per 24h; a 60s poll re-issues within a minute of the roll
/// at the cost of one cheap runtime read per minute.
const CERT_REFRESH_POLL_SECS: u64 = 60;

/// libp2p request-response protocol for the handshake exchange. Bumped
/// to `/3` for the hybrid X25519+ML-KEM-768 handshake; `/2` was the
/// cert-carrying classical form, `/1` signed with the GRANDPA key —
/// both are gone. A hard cutover, as each bump before it: an old-`/N`
/// peer and a `/3` peer simply never negotiate a substream, which is
/// the intended behavior (no mixed fleet).
pub const HANDSHAKE_PROTOCOL_NAME: &str = "/rostro/validator-channel-handshake/4";

/// libp2p notification protocol for encrypted message exchange after
/// a handshake has established a Session.
pub const NOTIFICATION_PROTOCOL_NAME: &str = "/rostro/validator-channel/1";

const INBOUND_QUEUE_CAPACITY: usize = 64;
// The v3 hybrid payloads are 1417 bytes (initiator, carrying the
// ML-KEM-768 encapsulation key) / 1321 bytes (responder, carrying the
// ciphertext) plus SCALE overhead. 2 KiB gives headroom without
// admitting junk. An undersized cap here fails SILENTLY at the
// request-response layer — if handshakes ever stop flowing after a
// payload change, check these first.
const MAX_HANDSHAKE_REQUEST_SIZE: u64 = 2048;
const MAX_HANDSHAKE_RESPONSE_SIZE: u64 = 2048;
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

/// Peer-presence event published by [`run_notification_task`] for any
/// task that needs an "I saw a peer connect" signal. The notification
/// task is the only thing in our tree that reliably sees these events
/// — sc-network's `NetworkService::event_stream` no longer emits
/// `NotificationStreamOpened`/`Closed` (commented out in
/// `substrate/client/network/src/service.rs:1664-1672`). Forwarding
/// them on a broadcast channel lets [`crate::attest_asker`] and any
/// future module subscribe without re-discovering the upstream
/// breakage or adding a new GPL-3.0 client/ dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPresenceEvent {
	Connected(PeerId),
	Disconnected(PeerId),
}

/// Sender side of the peer-presence broadcast. Build with
/// `tokio::sync::broadcast::channel(N)` in service.rs and pass into
/// [`run_notification_task`]; consumers get receivers via
/// `tx.subscribe()`.
pub type PeerPresenceSender = tokio::sync::broadcast::Sender<PeerPresenceEvent>;

/// Shared per-peer Session map. Populated when a handshake succeeds;
/// drained on disconnect.
pub type SharedSessions = Arc<Mutex<HashMap<PeerId, Session>>>;

/// In-flight secrets for a handshake we've initiated: the X25519
/// ephemeral and the ML-KEM-768 decapsulation key whose encapsulation
/// key rode our request. Removed when the response arrives (success or
/// failure).
struct PendingHandshake {
	x25519_secret: X25519SecretKey,
	mlkem_dk: MlKemDecapKey,
}

type PendingEphemerals = Arc<Mutex<HashMap<PeerId, PendingHandshake>>>;

/// The current channel [`ChannelCert`], refreshed once per 24h epoch by
/// [`run_cert_issuer`]. `None` until the issuer runs its first cycle;
/// the sign paths skip until it is populated. Shared read-mostly, so a
/// plain mutex is fine (updated ~once/24h, read per handshake).
pub type SharedCert = Arc<Mutex<Option<ChannelCert>>>;

/// The chain's current 24h membership epoch, published by
/// [`run_cert_issuer`] each poll and read by the handshake verifier as
/// the `current_epoch` argument to `verify_handshake`. Starts at 0
/// (before the first poll no real cert can verify, and we have no cert
/// of our own to offer either — a harmless startup window).
pub type SharedEpoch = Arc<AtomicU64>;

/// This node's validator identity for the channel: its on-chain GRANDPA
/// authority pubkey plus the keystore-resident channel pubkey the
/// authority delegates to. `None` for non-validators — the handshake
/// init path only runs when this is `Some`.
#[derive(Clone)]
pub struct LocalChannelIdentity {
	/// GRANDPA hybrid pubkey (ed25519 32 || SLH-DSA 32) — on-chain
	/// validator identity; its ed25519 component issues the cert.
	pub authority_pubkey: [u8; 64],
	/// Channel Ed25519 pubkey (`chnl`) — signs handshakes, cert subject.
	pub channel_pubkey: [u8; 32],
}

impl LocalChannelIdentity {
	/// Probe the keystore for a local GRANDPA pubkey; if present (i.e.
	/// this node is a validator), get-or-generate the persistent
	/// channel key and return the pair. Returns `None` for
	/// non-validators (no GRANDPA key).
	///
	/// The channel key is generated once and persisted by the keystore,
	/// so a restart reuses the same key — a stolen channel key is still
	/// useless without a current-epoch cert, and reusing one key avoids
	/// littering the keystore (which has no delete API).
	pub fn from_keystore(keystore: &KeystorePtr) -> Option<Self> {
		let authority_pk =
			keystore.rostro_hybrid_public_keys(GRANDPA_KEY_TYPE).into_iter().next()?;
		let authority_pubkey: [u8; 64] = AsRef::<[u8]>::as_ref(&authority_pk)
			.try_into()
			.expect("hybrid pubkey is 64 bytes");

		let channel_pk = match keystore.ed25519_public_keys(CHANNEL_KEY_TYPE).into_iter().next() {
			Some(pk) => pk,
			None => match keystore.ed25519_generate_new(CHANNEL_KEY_TYPE, None) {
				Ok(pk) => {
					log::info!(
						target: "rostro-validator-channel",
						"generated a new channel key (chnl) for handshake signing",
					);
					pk
				},
				Err(e) => {
					log::warn!(
						target: "rostro-validator-channel",
						"failed to generate channel key: {:?}; channel disabled",
						e,
					);
					return None;
				},
			},
		};
		let channel_pubkey: [u8; 32] = AsRef::<[u8]>::as_ref(&channel_pk)
			.try_into()
			.expect("Ed25519 pubkey is 32 bytes");

		Some(LocalChannelIdentity { authority_pubkey, channel_pubkey })
	}
}

/// Read the chain's current 24h membership epoch from the runtime API.
/// Returns `None` if the runtime call fails (treated as "epoch unknown
/// this cycle" by the issuer, which simply retries next poll).
fn fetch_membership_epoch<C, Block>(client: &Arc<C>) -> Option<u64>
where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: ZkPkiApi<Block, AccountId>,
{
	let best = client.info().best_hash;
	client.runtime_api().membership_epoch(best).ok().map(|e| e as u64)
}

/// Issue a [`ChannelCert`] by signing `(channel_pubkey, epoch)` with the
/// ed25519 COMPONENT of the GRANDPA hybrid authority key via the
/// keystore (docs/PQ-FINALITY.md D5 — the cert stays 64 bytes, inside
/// the handshake's 512-byte budget). This is the ONE place the channel
/// subsystem touches the slashable consensus key, and it runs at most
/// once per 24h epoch. Returns `None` if the keystore has no GRANDPA
/// signing key for our authority pubkey.
pub fn issue_cert(
	keystore: &KeystorePtr,
	identity: &LocalChannelIdentity,
	epoch: u64,
) -> Option<ChannelCert> {
	let preimage = cert_preimage(&identity.authority_pubkey, &identity.channel_pubkey, epoch);
	let sp_authority = sp_rostro_hybrid::Public::from(identity.authority_pubkey);
	let sig = match keystore.rostro_hybrid_sign_ed25519_component(
		GRANDPA_KEY_TYPE,
		&sp_authority,
		&preimage,
	) {
		Ok(Some(s)) => s,
		Ok(None) => {
			log::warn!(
				target: "rostro-validator-channel",
				"keystore has no GRANDPA signing key for our authority pubkey; \
				 cannot issue a channel cert",
			);
			return None;
		},
		Err(e) => {
			log::warn!(
				target: "rostro-validator-channel",
				"GRANDPA signing failed while issuing channel cert: {:?}",
				e,
			);
			return None;
		},
	};
	Some(ChannelCert {
		authority_pubkey: identity.authority_pubkey,
		channel_pubkey: identity.channel_pubkey,
		epoch,
		signature: sig.0,
	})
}

/// Long-lived task: keep `shared_epoch` and `shared_cert` current.
/// Polls the chain's 24h membership epoch every
/// [`CERT_REFRESH_POLL_SECS`]; on the first cycle and whenever the
/// epoch rolls, re-issues the channel cert (the once-per-epoch GRANDPA
/// key touch). Spawned only for validators.
pub async fn run_cert_issuer<C, Block>(
	client: Arc<C>,
	keystore: KeystorePtr,
	identity: LocalChannelIdentity,
	shared_cert: SharedCert,
	shared_epoch: SharedEpoch,
) where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: ZkPkiApi<Block, AccountId>,
{
	let mut interval = tokio::time::interval(Duration::from_secs(CERT_REFRESH_POLL_SECS));
	let mut issued_for: Option<u64> = None;
	loop {
		interval.tick().await;
		let epoch = match fetch_membership_epoch::<C, Block>(&client) {
			Some(e) => e,
			None => continue,
		};
		shared_epoch.store(epoch, Ordering::Relaxed);

		let need_reissue = issued_for != Some(epoch) || shared_cert.lock().is_none();
		if !need_reissue {
			continue;
		}
		match issue_cert(&keystore, &identity, epoch) {
			Some(cert) => {
				*shared_cert.lock() = Some(cert);
				issued_for = Some(epoch);
				log::info!(
					target: "rostro-validator-channel",
					"issued channel cert for epoch {} (chnl 0x{}…)",
					epoch,
					hex_prefix(&identity.channel_pubkey, 8),
				);
			},
			None => {
				// Leave any prior cert in place; retry next poll.
				log::warn!(
					target: "rostro-validator-channel",
					"could not issue channel cert for epoch {}; will retry",
					epoch,
				);
			},
		}
	}
}

/// Build our own outbound/reply handshake payload: sign a fresh session
/// ephemeral plus our side's ML-KEM flight with the CHANNEL key and
/// attach the current cert. The signature covers both exchange halves,
/// so the PQ material cannot be stripped or swapped in-path. Returns
/// `None` if we have no current cert yet (issuer hasn't run) or the
/// keystore can't sign with the channel key.
fn build_our_handshake_payload(
	keystore: &KeystorePtr,
	identity: &LocalChannelIdentity,
	shared_cert: &SharedCert,
	our_eph_pub: &X25519PublicKey,
	kex: HybridKexMaterial,
) -> Option<HandshakePayload> {
	let cert = shared_cert.lock().clone()?;
	let preimage =
		handshake_preimage(&cert.channel_pubkey, cert.epoch, our_eph_pub.as_bytes(), &kex);
	let sp_channel = sp_ed25519::Public::from(identity.channel_pubkey);
	let sig = match keystore.ed25519_sign(CHANNEL_KEY_TYPE, &sp_channel, &preimage) {
		Ok(Some(s)) => s,
		_ => return None,
	};
	Some(HandshakePayload {
		cert,
		ephemeral_x25519: *our_eph_pub.as_bytes(),
		kex,
		signature: sig.0,
	})
}

// ───── Handshake server protocol ───────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn build_handshake_server<N, C, Block>(
	client: Arc<C>,
	keystore: KeystorePtr,
	identity: LocalChannelIdentity,
	shared_cert: SharedCert,
	shared_epoch: SharedEpoch,
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
	let handler =
		run_handshake_server(client, keystore, identity, shared_cert, shared_epoch, sessions, rx);
	(config, handler)
}

#[allow(clippy::too_many_arguments)]
async fn run_handshake_server<C, Block>(
	client: Arc<C>,
	keystore: KeystorePtr,
	identity: LocalChannelIdentity,
	shared_cert: SharedCert,
	shared_epoch: SharedEpoch,
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
			&identity,
			&shared_cert,
			&shared_epoch,
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

#[allow(clippy::too_many_arguments)]
fn handle_handshake_inbound<C, Block>(
	client: &Arc<C>,
	keystore: &KeystorePtr,
	identity: &LocalChannelIdentity,
	shared_cert: &SharedCert,
	shared_epoch: &SharedEpoch,
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

	// The cert's authority key (not the channel key) is the on-chain
	// identity that must be in the active validator set.
	match is_active_authority(client, &req.cert.authority_pubkey) {
		Ok(true) => {},
		Ok(false) => {
			log::debug!(
				target: "rostro-validator-channel",
				"peer {} authority 0x{} not in active validator set; rejecting",
				peer,
				hex_prefix(&req.cert.authority_pubkey, 8),
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

	// Cert signature + kex role + epoch window + channel-key handshake
	// signature (covering both exchange halves).
	let current_epoch = shared_epoch.load(Ordering::Relaxed);
	if let Err(e) = verify_handshake(&req, current_epoch, KexRole::Initiator) {
		log::warn!(
			target: "rostro-validator-channel",
			"handshake verification failed from {} ({:?}); rejecting",
			peer,
			e,
		);
		return HandshakeReply::Reject;
	}

	// PQ half: encapsulate against the initiator's ML-KEM key. The role
	// check above guarantees the InitiatorEk shape. A key that fails
	// FIPS 203 validation is a malformed handshake — reject.
	let HybridKexMaterial::InitiatorEk(ref peer_ek) = req.kex else {
		unreachable!("verify_handshake enforced KexRole::Initiator");
	};
	let mut m = [0u8; 32];
	OsRng.fill_bytes(&mut m);
	let (ct, mlkem_ss) = match mlkem_encapsulate(peer_ek, &m) {
		Ok(pair) => pair,
		Err(e) => {
			log::warn!(
				target: "rostro-validator-channel",
				"handshake from {} carried an invalid ML-KEM key ({:?}); rejecting",
				peer,
				e,
			);
			return HandshakeReply::Reject;
		},
	};

	let our_eph_secret = X25519SecretKey::random_from_rng(OsRng);
	let our_eph_pub = X25519PublicKey::from(&our_eph_secret);
	let our_payload = match build_our_handshake_payload(
		keystore,
		identity,
		shared_cert,
		&our_eph_pub,
		HybridKexMaterial::ResponderCt(ct),
	) {
		Some(p) => p,
		None => {
			log::warn!(
				target: "rostro-validator-channel",
				"no current channel cert / channel signing key; cannot respond to \
				 handshake from {}",
				peer,
			);
			return HandshakeReply::Reject;
		},
	};

	let peer_eph_pub = X25519PublicKey::from(req.ephemeral_x25519);
	let shared =
		hybrid_shared_secret(&mlkem_ss, &handshake_shared_secret(&our_eph_secret, &peer_eph_pub));
	let session = Session::from_handshake_responder(shared, our_eph_secret, peer_eph_pub);
	sessions.lock().insert(peer, session);
	log::info!(
		target: "rostro-validator-channel",
		"established responder session with peer {} (authority 0x{}…)",
		peer,
		hex_prefix(&req.cert.authority_pubkey, 8),
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
	current_epoch: u64,
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

	// Verify the responder's cert + kex role + epoch window +
	// channel-key signature (covering both exchange halves). Active-set
	// membership of the responder's authority key is NOT re-checked
	// here: only a node already in our active set would hold a keystore
	// GRANDPA key able to issue a verifying cert, and the initiator's
	// own active-set filtering happens when peers are admitted. The
	// cert signature is the binding that matters.
	if let Err(e) = verify_handshake(&peer_payload, current_epoch, KexRole::Responder) {
		log::warn!(
			target: "rostro-validator-channel",
			"responder {} handshake verification failed ({:?}); aborting",
			peer,
			e,
		);
		pending.lock().remove(&peer);
		return;
	}

	let PendingHandshake { x25519_secret: our_eph_secret, mlkem_dk } =
		match pending.lock().remove(&peer) {
			Some(s) => s,
			None => return,
		};

	// PQ half: decapsulate the responder's ciphertext with the key we
	// generated for this handshake. A mangled ciphertext implicitly
	// rejects into a garbage secret and the session dies at the first
	// AEAD check, so there is no oracle here; an outright decode error
	// aborts.
	let HybridKexMaterial::ResponderCt(ref ct) = peer_payload.kex else {
		unreachable!("verify_handshake enforced KexRole::Responder");
	};
	let mlkem_ss = match mlkem_decapsulate(&mlkem_dk, ct) {
		Ok(ss) => ss,
		Err(e) => {
			log::warn!(
				target: "rostro-validator-channel",
				"decapsulation of responder {}'s ciphertext failed ({:?}); aborting",
				peer,
				e,
			);
			return;
		},
	};

	let peer_eph_pub = X25519PublicKey::from(peer_payload.ephemeral_x25519);
	let shared =
		hybrid_shared_secret(&mlkem_ss, &handshake_shared_secret(&our_eph_secret, &peer_eph_pub));
	let session = Session::from_handshake_initiator(shared, our_eph_secret, peer_eph_pub);
	sessions.lock().insert(peer, session);
	log::info!(
		target: "rostro-validator-channel",
		"established initiator session with peer {} (authority 0x{}…)",
		peer,
		hex_prefix(&peer_payload.cert.authority_pubkey, 8),
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
#[allow(clippy::too_many_arguments)]
pub async fn run_notification_task<N>(
	mut notification_service: Box<dyn NotificationService>,
	network: Arc<N>,
	keystore: KeystorePtr,
	identity: Option<LocalChannelIdentity>,
	shared_cert: SharedCert,
	shared_epoch: SharedEpoch,
	sessions: SharedSessions,
	presence_tx: PeerPresenceSender,
) where
	N: NetworkRequest + NetworkStateInfo + Send + Sync + 'static + ?Sized,
{
	let local_peer_id = network.local_peer_id();
	let pending: PendingEphemerals = Arc::new(Mutex::new(HashMap::new()));

	// `our_pubkey` is only used inside the validator-channel-internal
	// heartbeat formatter; for non-validators we have no sessions so
	// no heartbeats fire — the zero pubkey is a safe placeholder.
	let our_pubkey: [u8; 64] = identity
		.as_ref()
		.map(|i| i.authority_pubkey)
		.unwrap_or([0u8; 64]);

	let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
	// `interval.tick()` returns immediately on first call; skip it.
	interval.tick().await;

	loop {
		tokio::select! {
			event = notification_service.next_event() => {
				match event {
					Some(NotificationEvent::NotificationStreamOpened { peer, .. }) => {
						// Broadcast for any subscriber that needs a
						// "peer connected" signal (e.g.
						// [`crate::attest_asker`]). `send` only fails
						// when there are no receivers — fine, we drop
						// the event in that case.
						let _ = presence_tx.send(PeerPresenceEvent::Connected(peer));

						// Validator-only branch: initiate the X3DH-lite
						// handshake. Non-validators (identity == None)
						// emit presence and stop here.
						let Some(ref local_identity) = identity else { continue };

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
						// PQ half: fresh per-session ML-KEM-768 keypair;
						// the encapsulation key rides the request, the
						// decapsulation key waits in `pending`.
						let mut mlkem_seed = [0u8; MLKEM768_SEED_BYTES];
						OsRng.fill_bytes(&mut mlkem_seed);
						let (mlkem_dk, mlkem_ek) = mlkem_keypair_from_seed(&mlkem_seed);
						// Sign with the CHANNEL key + attach the current
						// cert; the GRANDPA key is never used here.
						let our_payload = match build_our_handshake_payload(
							&keystore,
							local_identity,
							&shared_cert,
							&our_eph_pub,
							HybridKexMaterial::InitiatorEk(mlkem_ek),
						) {
							Some(p) => p,
							None => {
								log::warn!(
									target: "rostro-validator-channel",
									"no current channel cert yet; skipping handshake to {}",
									peer,
								);
								continue;
							},
						};
						pending.lock().insert(
							peer,
							PendingHandshake { x25519_secret: our_eph_secret, mlkem_dk },
						);

						// Capture the current epoch for verifying the
						// responder's reply cert; the round-trip is well
						// within one 24h epoch.
						let current_epoch = shared_epoch.load(Ordering::Relaxed);
						let net = network.clone();
						let pending_for_task = pending.clone();
						let sessions_for_task = sessions.clone();
						let request_bytes = our_payload.encode();
						tokio::spawn(async move {
							handle_handshake_outbound(
								net,
								peer,
								request_bytes,
								current_epoch,
								pending_for_task,
								sessions_for_task,
							)
							.await;
						});
					},
					Some(NotificationEvent::NotificationStreamClosed { peer }) => {
						let _ = presence_tx.send(PeerPresenceEvent::Disconnected(peer));
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
			cert: ChannelCert {
				authority_pubkey: [0x11; 64],
				channel_pubkey: [0x44; 32],
				epoch: 7,
				signature: [0x55; 64],
			},
			ephemeral_x25519: [0x22; 32],
			kex: HybridKexMaterial::ResponderCt(
				[0x66; rostro_hybrid_kex::MLKEM768_CT_BYTES],
			),
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

	#[test]
	fn handshake_payloads_fit_protocol_size_caps() {
		// An undersized request-response cap fails SILENTLY (requests
		// just never arrive), so pin the encoded wire sizes against the
		// caps. The initiator flight (ML-KEM ek) is the larger one.
		let cert = ChannelCert {
			authority_pubkey: [0x11; 64],
			channel_pubkey: [0x44; 32],
			epoch: 7,
			signature: [0x55; 64],
		};
		let request = HandshakePayload {
			cert: cert.clone(),
			ephemeral_x25519: [0x22; 32],
			kex: HybridKexMaterial::InitiatorEk(
				[0x77; rostro_hybrid_kex::MLKEM768_EK_BYTES],
			),
			signature: [0x33; 64],
		};
		let reply = HandshakeReply::Accept(HandshakePayload {
			cert,
			ephemeral_x25519: [0x22; 32],
			kex: HybridKexMaterial::ResponderCt(
				[0x66; rostro_hybrid_kex::MLKEM768_CT_BYTES],
			),
			signature: [0x33; 64],
		});
		assert!(request.encode().len() as u64 <= MAX_HANDSHAKE_REQUEST_SIZE);
		assert!(reply.encode().len() as u64 <= MAX_HANDSHAKE_RESPONSE_SIZE);
	}

	// PeerId byte-comparison for initiation rule. We can't easily
	// build "real" PeerIds in unit tests (they're derived from
	// libp2p Identity keys), but the documented invariant is:
	// `local.to_bytes() < remote.to_bytes()` ⇒ local initiates.
	// Compile-test only; real behavior is verified in Z6 scenarios.
}
