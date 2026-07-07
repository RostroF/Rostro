// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `/rostro/chat-gossip/1` — libp2p notification protocol for
//! propagating [`BucketSubscription`] advertisements between
//! chat-gossip-channel peers.
//!
//! ## What the protocol carries
//!
//! One wire-message variant, [`GossipWire::Advertisement`], wrapping
//! a signed [`BucketSubscription`]. Peers exchange these to populate
//! their [`BucketCache`]. Future variants (rotation notices,
//! anti-entropy digest requests) extend this enum without protocol-
//! version bumps because SCALE encoding tolerates trailing variants
//! added with care.
//!
//! ## Event flow
//!
//! - `NotificationStreamOpened(peer)` → send our current
//!   advertisement to that peer (gives them our subscription).
//! - `NotificationReceived(peer, bytes)` → decode + verify + cache.
//! - `NotificationStreamClosed(peer)` → drop their entry from the
//!   cache.
//! - `ValidateInboundSubstream(peer, _)` → accept all (admission is
//!   handled separately by [`crate::chat_admission`] at the
//!   chat-chunk / chat-fetch layer).
//!
//! ## Local subscription change broadcast
//!
//! When the local node's subscription changes (operator-driven or
//! weekly-rebalance-driven, lands in A.1), [`broadcast_subscription`]
//! sends the new advertisement to every currently-connected peer.
//! This is the only place outbound notifications fire after the
//! initial peer-connect advertisement.
//!
//! ## No heartbeat timer
//!
//! Per design discussion: refrigerators not subway stations.
//! Subscription advertisements are event-driven (on connect + on
//! local change), not periodic. Peer liveness is detected via
//! libp2p's `NotificationStreamClosed` event, not via heartbeat
//! timeout. This keeps the chat-gossip channel quiet most of the
//! time.

use std::sync::Arc;
use std::time::Duration;

use codec::{Decode, Encode};
use ed25519_zebra::{SigningKey, VerificationKey};
use parking_lot::RwLock;
use rc_network::{
	config::{NonReservedPeerMode, SetConfig},
	peer_store::PeerStoreProvider,
	service::{
		traits::{NotificationEvent, NotificationService, ValidationResult},
		NotificationMetrics,
	},
	types::ProtocolName,
	NetworkBackend,
};
use sp_runtime::traits::Block as BlockT;

use rostro_chat_primitives::bucket::{BucketBitmap, BucketSubscription};

use crate::chat_bucket_cache::BucketCache;

/// libp2p notification protocol name. Versioned suffix bumped if
/// the wire format ever changes incompatibly.
pub const CHAT_GOSSIP_PROTOCOL_NAME: &str = "/rostro/chat-gossip/1";

/// Maximum size of a single inbound notification (bytes). A
/// [`BucketSubscription`] is fixed-size at ~140 bytes; 512 leaves
/// headroom for the enum-discriminant overhead and future variant
/// fields without admitting anything large enough to OOM.
const MAX_NOTIFICATION_SIZE: u64 = 512;

/// libp2p notification substream open/close timeout. Notification
/// protocols are persistent — once open, they stay open until the
/// peer disconnects. The timeout only matters at substream setup.
const SUBSTREAM_OPEN_TIMEOUT_SECS: u64 = 10;

/// Wire-format envelope for messages on `/rostro/chat-gossip/1`.
/// Outer enum dispatches on the discriminant; the current single
/// variant carries a signed advertisement.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum GossipWire {
	Advertisement(BucketSubscription),
}

/// Local node's bucket subscription state. Holds the signing key
/// (libp2p node-identity Ed25519) plus the current bitmap + version
/// counter. Cheap to clone — internal state is `Arc<RwLock<...>>`.
///
/// Mutating the bitmap via [`LocalSubscriptionState::set_bitmap`]
/// bumps the version, ready for the next outbound advertisement.
#[derive(Clone)]
pub struct LocalSubscriptionState {
	inner: Arc<LocalSubscriptionStateInner>,
}

struct LocalSubscriptionStateInner {
	signing_key: SigningKey,
	node_pubkey: [u8; 32],
	bitmap: RwLock<BucketBitmap>,
	version: RwLock<u32>,
}

impl LocalSubscriptionState {
	/// Construct from a libp2p node-identity signing key + initial
	/// bitmap. The first `version` is derived from `now_unix_s` so
	/// reboots don't replay an older version against peers' caches
	/// (each process restart sees `now > prior_now`, so the version
	/// advances forward across the reboot boundary).
	pub fn new(
		signing_key: SigningKey,
		initial_bitmap: BucketBitmap,
		now_unix_s: u64,
	) -> Self {
		let vk = VerificationKey::from(&signing_key);
		let node_pubkey: [u8; 32] = vk.into();
		// u32 holds ~136 years of seconds — wraparound concerns
		// well after this protocol is irrelevant.
		let initial_version = now_unix_s as u32;
		Self {
			inner: Arc::new(LocalSubscriptionStateInner {
				signing_key,
				node_pubkey,
				bitmap: RwLock::new(initial_bitmap),
				version: RwLock::new(initial_version),
			}),
		}
	}

	/// Local node's libp2p Ed25519 identity pubkey. Mirrors what
	/// the libp2p PeerId is derived from.
	pub fn node_pubkey(&self) -> [u8; 32] {
		self.inner.node_pubkey
	}

	/// Build a signed advertisement for the current bitmap + version.
	/// `now_unix_s` is folded into the signed payload (replay-window
	/// enforcement at the receiver).
	pub fn build_advertisement(&self, now_unix_s: u64) -> BucketSubscription {
		let bitmap = *self.inner.bitmap.read();
		let version = *self.inner.version.read();
		BucketSubscription::build_signed(
			self.inner.node_pubkey,
			version,
			bitmap,
			now_unix_s,
			|payload| self.inner.signing_key.sign(payload).into(),
		)
	}

	/// Replace the current bitmap; bumps `version` by 1. Intended
	/// to be called by the weekly-rebalance task (Commit A.1) or
	/// by an operator-driven runtime control endpoint.
	pub fn set_bitmap(&self, new_bitmap: BucketBitmap) {
		let mut bitmap = self.inner.bitmap.write();
		let mut version = self.inner.version.write();
		*bitmap = new_bitmap;
		*version = version.saturating_add(1);
	}

	/// Read the current bitmap. For tests / diagnostics; the
	/// outbound path uses [`Self::build_advertisement`] directly.
	pub fn current_bitmap(&self) -> BucketBitmap {
		*self.inner.bitmap.read()
	}

	/// Read the current version counter. For tests / diagnostics.
	pub fn current_version(&self) -> u32 {
		*self.inner.version.read()
	}
}

/// Local-clock helper (matches the convention used elsewhere in
/// chat-side modules).
fn now_unix_seconds() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Build the libp2p notification protocol config + service handle.
/// Caller (service.rs) registers the config via
/// `FullNetworkConfiguration::add_notification_protocol` and passes
/// the service handle to [`run_chat_gossip_task`].
pub fn build_chat_gossip_protocol<N, Block>(
	metrics: NotificationMetrics,
	peer_store: Arc<dyn PeerStoreProvider>,
) -> (N::NotificationProtocolConfig, Box<dyn NotificationService>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
{
	N::notification_config(
		ProtocolName::from(CHAT_GOSSIP_PROTOCOL_NAME),
		Vec::new(),
		MAX_NOTIFICATION_SIZE,
		// No handshake; first event after stream open is the
		// outbound advertisement we send to them.
		None,
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

/// Main loop. Pulls notification events off the service, handles
/// stream-opened (send our advertisement), notification-received
/// (decode + cache.try_insert), stream-closed (drop their cache
/// entry). Runs forever; spawn on the task manager.
///
/// `rebalance_signal_rx` receives `()` whenever the rebalance
/// task applies a new bitmap to `local_state`. The gossip task
/// re-broadcasts the updated subscription to every cached peer
/// so they update their `BucketCache` entry for us with the
/// bumped-version advertisement.
pub async fn run_chat_gossip_task(
	mut notification_service: Box<dyn NotificationService>,
	cache: BucketCache,
	local_state: LocalSubscriptionState,
	mut rebalance_signal_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
) {
	loop {
		tokio::select! {
			event = notification_service.next_event() => {
				let Some(event) = event else {
					log::warn!(
						target: "rostro-chat-gossip",
						"chat-gossip notification service stream ended",
					);
					return;
				};
				match event {
					NotificationEvent::ValidateInboundSubstream { peer: _, result_tx, .. } => {
						let _ = result_tx.send(ValidationResult::Accept);
					},
					NotificationEvent::NotificationStreamOpened { peer, .. } => {
						let now = now_unix_seconds();
						let ad = local_state.build_advertisement(now);
						let wire = GossipWire::Advertisement(ad).encode();
						if let Err(e) = notification_service.send_async_notification(&peer, wire).await {
							log::debug!(
								target: "rostro-chat-gossip",
								"failed to send advertisement to {}: {:?}",
								peer,
								e,
							);
						} else {
							log::trace!(
								target: "rostro-chat-gossip",
								"sent advertisement (v{}) to newly-opened stream with {}",
								local_state.current_version(),
								peer,
							);
						}
					},
					NotificationEvent::NotificationReceived { peer, notification } => {
						let wire = match GossipWire::decode(&mut &notification[..]) {
							Ok(w) => w,
							Err(_) => {
								log::debug!(
									target: "rostro-chat-gossip",
									"undecodable gossip-wire message from {}",
									peer,
								);
								continue;
							},
						};
						let GossipWire::Advertisement(ad) = wire;
						let now = now_unix_seconds();
						match cache.try_insert(peer, ad, now) {
							Ok(()) => {
								log::trace!(
									target: "rostro-chat-gossip",
									"cached advertisement from {}",
									peer,
								);
							},
							Err(e) => {
								log::debug!(
									target: "rostro-chat-gossip",
									"rejected advertisement from {}: {:?}",
									peer,
									e,
								);
							},
						}
					},
					NotificationEvent::NotificationStreamClosed { peer } => {
						cache.drop_peer(&peer);
						log::trace!(
							target: "rostro-chat-gossip",
							"peer {} disconnected; dropped from bucket cache",
							peer,
						);
					},
				}
			}
			Some(_) = rebalance_signal_rx.recv() => {
				// Rebalance task updated our bitmap + bumped version.
				// Broadcast the new advertisement to every cached peer
				// so they refresh their copy of our subscription
				// (which drives chat-chunk routing decisions on
				// THEIR end).
				let peers: Vec<rc_network::PeerId> = cache
					.all_peers()
					.into_iter()
					.map(|(p, _)| p)
					.collect();
				let n_peers = peers.len();
				let now = now_unix_seconds();
				let ad = local_state.build_advertisement(now);
				let wire = GossipWire::Advertisement(ad).encode();
				let mut sent = 0usize;
				for peer in peers {
					if notification_service
						.send_async_notification(&peer, wire.clone())
						.await
						.is_ok()
					{
						sent += 1;
					}
				}
				log::info!(
					target: "rostro-chat-gossip",
					"rebalance: broadcast subscription v{} to {}/{} peers",
					local_state.current_version(),
					sent,
					n_peers,
				);
			}
		}
	}
}

/// Broadcast the local node's current subscription to every
/// connected `/rostro/chat-gossip/1` peer. Called by the
/// rebalance task (A.1) after [`LocalSubscriptionState::set_bitmap`]
/// updates the bitmap+version.
///
/// Implementation note: libp2p's notification_service.send_*
/// requires individual peer enumeration. We iterate over the
/// caller-supplied peer list (typically `cache.peers_for_bucket(*)`
/// merged across the local subscription set, or simply
/// `cache_connected_peers()` for a full broadcast).
pub async fn broadcast_subscription(
	notification_service: &mut Box<dyn NotificationService>,
	local_state: &LocalSubscriptionState,
	peers: &[rc_network::PeerId],
) {
	let now = now_unix_seconds();
	let ad = local_state.build_advertisement(now);
	let wire = GossipWire::Advertisement(ad).encode();
	for peer in peers {
		if let Err(e) = notification_service
			.send_async_notification(peer, wire.clone())
			.await
		{
			log::debug!(
				target: "rostro-chat-gossip",
				"broadcast: failed to send to {}: {:?}",
				peer,
				e,
			);
		}
	}
}

/// Unused at protocol-build-time but kept for parity with other
/// chat-side modules that expose their substream open timeout.
#[allow(dead_code)]
pub const SUBSTREAM_OPEN_TIMEOUT: Duration =
	Duration::from_secs(SUBSTREAM_OPEN_TIMEOUT_SECS);

#[cfg(test)]
mod tests {
	use super::*;
	use rostro_chat_primitives::bucket::BucketBitmap;

	#[test]
	fn local_state_constructs_with_valid_pubkey() {
		let sk = SigningKey::from([0x11u8; 32]);
		let now = 1_700_000_000;
		let state = LocalSubscriptionState::new(sk, BucketBitmap::all(), now);
		// Pubkey is derivable from the signing key.
		let vk_expected: [u8; 32] = VerificationKey::from(&SigningKey::from([0x11u8; 32])).into();
		assert_eq!(state.node_pubkey(), vk_expected);
		assert_eq!(state.current_bitmap(), BucketBitmap::all());
		assert_eq!(state.current_version(), now as u32);
	}

	#[test]
	fn set_bitmap_bumps_version() {
		let sk = SigningKey::from([0x22u8; 32]);
		let state = LocalSubscriptionState::new(sk, BucketBitmap::all(), 1_700_000_000);
		let v0 = state.current_version();
		let mut new_bitmap = BucketBitmap::empty();
		new_bitmap.insert(42);
		state.set_bitmap(new_bitmap);
		assert_eq!(state.current_version(), v0 + 1);
		assert_eq!(state.current_bitmap(), new_bitmap);
	}

	#[test]
	fn advertisement_roundtrips_through_wire() {
		let sk = SigningKey::from([0x33u8; 32]);
		let state = LocalSubscriptionState::new(sk, BucketBitmap::all(), 1_700_000_000);
		let ad = state.build_advertisement(1_700_000_100);
		let wire = GossipWire::Advertisement(ad.clone());
		let bytes = wire.encode();
		let decoded = GossipWire::decode(&mut &bytes[..]).unwrap();
		let GossipWire::Advertisement(decoded_ad) = decoded;
		assert_eq!(decoded_ad, ad);
		// Signature verifies after wire roundtrip.
		assert!(decoded_ad.verify_signature().is_ok());
	}

	#[test]
	fn version_advances_across_multiple_set_bitmap_calls() {
		let sk = SigningKey::from([0x44u8; 32]);
		let state = LocalSubscriptionState::new(sk, BucketBitmap::empty(), 1_700_000_000);
		let v0 = state.current_version();
		for _ in 0..5 {
			state.set_bitmap(BucketBitmap::all());
		}
		assert_eq!(state.current_version(), v0 + 5);
	}

	#[test]
	fn ad_built_after_set_bitmap_uses_new_state() {
		let sk = SigningKey::from([0x55u8; 32]);
		let state = LocalSubscriptionState::new(sk, BucketBitmap::empty(), 1_700_000_000);
		let mut bitmap = BucketBitmap::empty();
		bitmap.insert(7);
		bitmap.insert(99);
		state.set_bitmap(bitmap);

		let ad = state.build_advertisement(1_700_000_500);
		assert!(ad.bitmap.contains(7));
		assert!(ad.bitmap.contains(99));
		assert!(!ad.bitmap.contains(8));
		assert!(ad.verify_signature().is_ok());
		assert_eq!(ad.version, state.current_version());
	}

	#[test]
	fn clone_shares_subscription_state() {
		let sk = SigningKey::from([0x66u8; 32]);
		let state_a = LocalSubscriptionState::new(sk, BucketBitmap::empty(), 1_700_000_000);
		let state_b = state_a.clone();
		state_a.set_bitmap(BucketBitmap::all());
		assert_eq!(state_b.current_bitmap(), BucketBitmap::all());
		assert_eq!(state_b.current_version(), state_a.current_version());
	}
}
