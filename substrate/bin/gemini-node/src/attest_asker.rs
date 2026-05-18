// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase 7 v2 Piece 3c/3d — connect-time canonical-files attest asker.
//!
//! Long-running task that:
//!
//! 1. Subscribes to the [`rc_network::Event`] stream.
//! 2. On every newly-seen peer (deduplicated via the drift ledger),
//!    issues an [`AttestationRequest`] over
//!    `/rostro/canonical-attest/1` with a fresh random nonce.
//! 3. Receives the response, runs
//!    [`rostro_canonical_fetch::attest::verify`] against the local
//!    on-chain `CanonicalFilesApi::canonical_root()`.
//! 4. Routes the outcome:
//!    - **Match** → mark peer `Passed` in the drift ledger; normal
//!      traffic allowed.
//!    - **RootMismatch / NonceMismatch / decode failure** → mark
//!      peer `Failed`, report a fatal reputation change (drops them
//!      below the ban threshold so libp2p won't reconnect for a
//!      cooldown period), and call `disconnect_peer` for immediate
//!      effect.
//!
//! ## Pessimistic disconnect (v0)
//!
//! [`rostro_canonical_fetch::attest::drift_action`] supports
//! role-based routing (SlashValidator vs AwaitPeerHeal vs
//! Disconnect). v0 takes the conservative path: on any non-Match
//! outcome we ban + disconnect, regardless of peer role. The
//! role-based routing matures once Phase 6.9 hardware attestation
//! makes role claims unforgeable; until then, over-ejecting is
//! safer than under-ejecting.
//!
//! ## Strict pre-attest packet drop is DEFERRED
//!
//! Per [`canonical_files_gate_grief_defense`] memory: the strict
//! "drop everything except attest from pre-attest peers" requirement
//! lands in the future channel-split workstream (see
//! [`gossip_channels_split`]). Validator-only privileged gossip will
//! be inaccessible to non-validators by construction; the general
//! channel will gate at the channel boundary in that work. For v0
//! the rate-limit + ban-on-Mismatch combo is the defense.

use std::collections::HashSet;
use std::sync::Arc;

use codec::{Decode, Encode};
use parking_lot::Mutex;
use rand::RngCore;
use rc_network::{
	service::traits::{NetworkPeers, NetworkRequest},
	types::ProtocolName,
	IfDisconnected, PeerId, ReputationChange,
};
use rostro_canonical_fetch::attest::{
	drift_action, verify, AttestationOutcome, AttestationRequest, AttestationResponse,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use tokio::sync::broadcast;

use pallet_rostro_canonical_files::CanonicalFilesApi;

use crate::attest_protocol::ATTEST_PROTOCOL_NAME;
use crate::connect_gate::{DriftLedger, PeerGateState};
use crate::validator_channel::PeerPresenceEvent;

/// Shared per-peer drift ledger. Wrapped because both the asker (this
/// file) and any future strict-drop filter need read access; only the
/// asker mutates.
pub type SharedDriftLedger = Arc<Mutex<DriftLedger<PeerId>>>;

/// Reputation change applied to peers that fail attest. `new_fatal`
/// drops the peer below sc-network's `BANNED_THRESHOLD`, putting them
/// on a per-peer-store cooldown so libp2p won't keep reconnecting.
fn fatal_rep_change() -> ReputationChange {
	ReputationChange::new_fatal("canonical-files attest mismatch")
}

/// Long-running task entry point. Consumes peer-connect events from
/// the validator-channel notification task's broadcast
/// [`PeerPresenceEvent`] channel — `NetworkService::event_stream` no
/// longer delivers `NotificationStreamOpened` (Substrate commented
/// it out at `substrate/client/network/src/service.rs:1664-1672`),
/// so we route through the only NotificationService in our tree
/// that does see those events.
pub async fn run_attest_asker<C, N, Block>(
	network: Arc<N>,
	client: Arc<C>,
	drift_ledger: SharedDriftLedger,
	mut presence_rx: broadcast::Receiver<PeerPresenceEvent>,
) where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: CanonicalFilesApi<Block>,
	N: NetworkRequest + NetworkPeers + Send + Sync + 'static + ?Sized,
{
	let mut attested_peers: HashSet<PeerId> = HashSet::new();

	log::info!(
		target: "rostro-attest-asker",
		"canonical-files connect-time asker started; subscribing to peer-presence events",
	);

	loop {
		match presence_rx.recv().await {
			Ok(PeerPresenceEvent::Connected(peer)) => {
				if attested_peers.contains(&peer) {
					continue;
				}
				attested_peers.insert(peer);
				drift_ledger.lock().set(peer, PeerGateState::Pending);

				// Run attest serially in the event loop. Each attest
				// is a single request/response roundtrip with a 5s
				// timeout; light load. If this becomes a hot path
				// switch to `task_manager.spawn_handle` for per-peer
				// concurrency.
				attest_one_peer(&network, &client, &drift_ledger, peer).await;
			},
			Ok(PeerPresenceEvent::Disconnected(peer)) => {
				attested_peers.remove(&peer);
				drift_ledger.lock().forget(&peer);
			},
			Err(broadcast::error::RecvError::Lagged(n)) => {
				log::warn!(
					target: "rostro-attest-asker",
					"presence channel lagged: {} events dropped",
					n,
				);
			},
			Err(broadcast::error::RecvError::Closed) => {
				log::warn!(
					target: "rostro-attest-asker",
					"presence channel closed; asker exiting",
				);
				return;
			},
		}
	}
}

async fn attest_one_peer<C, N, Block>(
	network: &Arc<N>,
	client: &Arc<C>,
	drift_ledger: &SharedDriftLedger,
	peer: PeerId,
) where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: CanonicalFilesApi<Block>,
	N: NetworkRequest + NetworkPeers + ?Sized,
{
	let mut nonce = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut nonce);
	let request = AttestationRequest { nonce };
	let payload = request.encode();

	let response_bytes = match network
		.request(
			peer,
			ProtocolName::from(ATTEST_PROTOCOL_NAME),
			payload,
			None,
			IfDisconnected::ImmediateError,
		)
		.await
	{
		Ok((bytes, _)) => bytes,
		Err(e) => {
			// Couldn't reach peer. Not definitively Failed — they
			// might not yet have the attest protocol open. Leave
			// in Pending so the next NotificationStreamOpened
			// won't re-trigger (already in the dedupe set); if
			// they disconnect and reconnect, dedupe clears and
			// we'll retry.
			log::debug!(
				target: "rostro-attest-asker",
				"attest request to {} failed (will retry on reconnect): {:?}",
				peer,
				e,
			);
			return;
		},
	};

	let response = match AttestationResponse::decode(&mut &response_bytes[..]) {
		Ok(r) => r,
		Err(e) => {
			log::warn!(
				target: "rostro-attest-asker",
				"undecodable attest response from {} ({}); banning",
				peer,
				e,
			);
			drift_ledger.lock().set(peer, PeerGateState::Failed);
			ban_peer(network, peer);
			return;
		},
	};

	let best = client.info().best_hash;
	let chain_canonical_root = match client.runtime_api().canonical_root(best) {
		Ok(r) => r,
		Err(e) => {
			// Our own runtime call failed. Don't punish the peer
			// for our problem; leave them Pending and log.
			log::warn!(
				target: "rostro-attest-asker",
				"CanonicalFilesApi::canonical_root failed: {:?}",
				e,
			);
			return;
		},
	};

	let outcome = verify(&request, &response, chain_canonical_root);
	match outcome {
		AttestationOutcome::Match => {
			drift_ledger.lock().set(peer, PeerGateState::Passed);
			log::info!(
				target: "rostro-attest-asker",
				"peer {} passed canonical-files attest",
				peer,
			);
		},
		AttestationOutcome::RootMismatch { peer_claimed, chain_canonical } => {
			// v0 stub: drift_action's role-based routing
			// (SlashValidator vs AwaitPeerHeal vs Disconnect) needs
			// an authoritative on-chain view of the peer's role.
			// Until 6.9 hardware attestation makes that
			// unforgeable, we pessimistically ban+disconnect
			// regardless of role. Logging records the routing the
			// future code WILL take.
			let advised = drift_action(response.claimed_role);
			let _ = (advised, peer_claimed, chain_canonical); // surface in logs
			log::warn!(
				target: "rostro-attest-asker",
				"peer {} canonical-files RootMismatch (peer_claimed=0x{}, \
				 chain_canonical=0x{}, advised={:?}); ban+disconnect (v0 pessimistic)",
				peer,
				hex_lower(&peer_claimed),
				hex_lower(&chain_canonical),
				advised,
			);
			drift_ledger.lock().set(peer, PeerGateState::Failed);
			ban_peer(network, peer);
		},
		AttestationOutcome::NonceMismatch { sent, echoed } => {
			log::warn!(
				target: "rostro-attest-asker",
				"peer {} attest NonceMismatch (sent=0x{}, echoed=0x{}); ban+disconnect",
				peer,
				hex_lower(&sent),
				hex_lower(&echoed),
			);
			drift_ledger.lock().set(peer, PeerGateState::Failed);
			ban_peer(network, peer);
		},
	}
}

/// Ban + disconnect. The `report_peer` call drops the peer below
/// libp2p's BANNED_THRESHOLD reputation; `disconnect_peer` triggers
/// the close. Belt + suspenders so a single mechanism can't
/// accidentally leave the peer connected.
fn ban_peer<N>(network: &Arc<N>, peer: PeerId)
where
	N: NetworkPeers + ?Sized,
{
	network.report_peer(peer, fatal_rep_change());
	network.disconnect_peer(peer, ProtocolName::from(ATTEST_PROTOCOL_NAME));
}

fn hex_lower(bytes: &[u8; 32]) -> String {
	let mut s = String::with_capacity(64);
	for b in bytes.iter() {
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
