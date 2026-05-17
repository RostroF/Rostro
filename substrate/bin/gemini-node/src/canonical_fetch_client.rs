// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Libp2p client side of `/rostro/canonical-fetch-attested/1`.
//!
//! Phase 7 v2 follow-up: closes the gap noted in `phase_7_v2_outcome`
//! memory — the server-side handler was wired and signing replies
//! since 2026-05-16, but nothing in our tree initiated requests.
//! All heal-on-boot flowed through `LocalDirectoryFetchTransport`
//! (`--canonical-files-dir`), which means heal only worked when an
//! operator had pre-stocked the canonical bytes locally.
//!
//! This module adds the broadcast client + K-of-N signed-attestation
//! aggregation so a drifted node can ask reachable peers for
//! canonical bytes and accept only when K distinct signers agree.
//!
//! ## Threat model (per `canonical_heal_protocol_design`)
//!
//! A drifted node broadcasts a [`SignedFetchRequest`] (canonical-hash
//! + fresh nonce) to N reachable peers. Each peer that has matching
//! bytes signs a [`SignedFetchResponse`] under its libp2p node-
//! identity key. The client:
//!
//! 1. Verifies each response individually (bytes hash, nonce echo,
//!    signature) via
//!    [`rostro_canonical_fetch::signed_fetch::verify_signed_response`].
//! 2. Aggregates verified responses via
//!    [`rostro_canonical_fetch::signed_fetch::select_freshest_canonical`]:
//!    groups by exact bytes, counts **distinct** signer pubkeys,
//!    requires `k_threshold` distinct signers agreeing on the same
//!    payload. On tie (e.g., a mid-upgrade where two payloads each
//!    meet K), pick the one whose responses anchor to the higher
//!    block number — the network's more current view.
//!
//! ## Why we don't trust a single peer
//!
//! A hostile single peer can fabricate any bytes whose blake2_256
//! hash happens to match the requested canonical hash — impossible
//! in practice (hash collision) — OR more realistically, can return
//! stale bytes from a previous canonical-files revision while the
//! chain has moved on. The K-distinct-signer requirement raises the
//! cost of either attack from "one Sybil PeerId" to "K independent
//! validator-grade identities," matching the
//! [[canonical_heal_protocol_design]] memo's intent.
//!
//! ## What's NOT in this module (yet)
//!
//! - **Boot-time integration into `verify_at_boot`'s heal path.**
//!   `HealFetcher` is a sync trait; bridging to async libp2p
//!   requires `tokio::runtime::Handle::block_on` and careful
//!   thread-context handling. Land that integration when the
//!   first real consumer needs it (mid-run drift detection or
//!   network-only-heal scenarios). v0 ships the primitive.
//! - **Peer-list curation.** Caller supplies the peer list. The
//!   most common production path will be "everyone currently
//!   connected on the canonical-fetch protocol's substream," but
//!   that's a wire-up policy decision left to the caller.

use std::sync::Arc;
use std::time::Duration;

use codec::{Decode, Encode};
use rand::RngCore;
use rc_network::{
	service::traits::NetworkRequest, types::ProtocolName, IfDisconnected, PeerId,
};
use rostro_canonical_fetch::signed_fetch::{
	select_freshest_canonical, verify_signed_response, AggregateError, SignedFetchReply,
	SignedFetchRequest, SignedFetchResponse,
};
use tokio::sync::mpsc;

use crate::canonical_fetch_protocol::CANONICAL_FETCH_PROTOCOL_NAME;

/// Outcome of [`broadcast_fetch_and_aggregate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
	/// No peers supplied. Caller responsibility — we don't auto-
	/// discover peers because policy varies.
	NoPeers,
	/// Aggregation failed: fewer than K distinct signers agreed on
	/// any single payload. `got` is the best per-payload agreement
	/// we observed.
	InsufficientAttestations { got: usize, needed: usize },
}

impl From<AggregateError> for BroadcastError {
	fn from(e: AggregateError) -> Self {
		match e {
			AggregateError::InsufficientAttestations { got, needed } => {
				BroadcastError::InsufficientAttestations { got, needed }
			},
		}
	}
}

/// Broadcast a [`SignedFetchRequest`] for `expected_hash` to each
/// PeerId in `peers`, collect signed responses with `timeout`,
/// verify each one, and aggregate via
/// [`select_freshest_canonical`]. Returns the canonical bytes if
/// K distinct signers agreed on the same payload.
///
/// Concurrency: all requests fan out in parallel via
/// `tokio::spawn`. The collect loop drains responses on an unbounded
/// channel as they arrive; first to reach the K threshold wins.
/// Slow peers are timed out at the deadline, NOT individually —
/// the loop just stops collecting once the deadline passes.
pub async fn broadcast_fetch_and_aggregate<N>(
	network: Arc<N>,
	peers: Vec<PeerId>,
	expected_hash: [u8; 32],
	k_threshold: usize,
	timeout: Duration,
) -> Result<Vec<u8>, BroadcastError>
where
	N: NetworkRequest + Send + Sync + 'static + ?Sized,
{
	if peers.is_empty() {
		return Err(BroadcastError::NoPeers);
	}

	let mut nonce = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut nonce);
	let request = SignedFetchRequest { canonical_hash: expected_hash, nonce };
	let request_bytes = request.encode();
	let n_peers = peers.len();

	// Fan out: spawn N tasks, each sends one request. Channel
	// collects responses (Ok or Err — peer-level errors get the
	// Err so the collect loop doesn't wait on dead peers).
	let (tx, mut rx) = mpsc::channel::<Option<SignedFetchResponse>>(n_peers);
	for peer in peers {
		let net = network.clone();
		let req = request_bytes.clone();
		let tx = tx.clone();
		tokio::spawn(async move {
			let result = net
				.request(
					peer,
					ProtocolName::from(CANONICAL_FETCH_PROTOCOL_NAME),
					req,
					None,
					IfDisconnected::ImmediateError,
				)
				.await;
			let response_bytes = match result {
				Ok((bytes, _)) => bytes,
				Err(e) => {
					log::debug!(
						target: "rostro-canonical-fetch-client",
						"fetch from {} failed: {:?}",
						peer,
						e,
					);
					let _ = tx.send(None).await;
					return;
				},
			};
			let reply = match SignedFetchReply::decode(&mut &response_bytes[..]) {
				Ok(r) => r,
				Err(_) => {
					let _ = tx.send(None).await;
					return;
				},
			};
			let signed = match reply {
				SignedFetchReply::Signed(s) => s,
				SignedFetchReply::NotAvailable => {
					let _ = tx.send(None).await;
					return;
				},
			};
			let _ = tx.send(Some(signed)).await;
		});
	}
	// Drop the original sender so rx.recv() returns None when all
	// spawned tasks finish.
	drop(tx);

	// Collect verified responses up to `timeout` total. Verifies
	// inline so invalid/tampered responses don't take up a slot.
	let mut verified: Vec<SignedFetchResponse> = Vec::with_capacity(n_peers);
	let mut received: usize = 0;
	let deadline = tokio::time::Instant::now() + timeout;
	loop {
		if received >= n_peers {
			break;
		}
		let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
		if remaining.is_zero() {
			break;
		}
		match tokio::time::timeout(remaining, rx.recv()).await {
			Ok(Some(Some(resp))) => {
				received += 1;
				match verify_signed_response(&expected_hash, &nonce, &resp) {
					Ok(_) => verified.push(resp),
					Err(e) => log::debug!(
						target: "rostro-canonical-fetch-client",
						"discarded unverified response: {:?}",
						e,
					),
				}
			},
			Ok(Some(None)) => {
				received += 1;
			},
			Ok(None) => break,
			Err(_) => break, // deadline reached
		}
	}

	log::info!(
		target: "rostro-canonical-fetch-client",
		"broadcast collected {} verified responses ({} attempts); aggregating with K={}",
		verified.len(),
		received,
		k_threshold,
	);

	select_freshest_canonical(&verified, k_threshold).map_err(Into::into)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn from_aggregate_error_preserves_counts() {
		let err: BroadcastError = AggregateError::InsufficientAttestations {
			got: 2,
			needed: 5,
		}
		.into();
		match err {
			BroadcastError::InsufficientAttestations { got, needed } => {
				assert_eq!(got, 2);
				assert_eq!(needed, 5);
			},
			other => panic!("expected InsufficientAttestations, got {:?}", other),
		}
	}
}
