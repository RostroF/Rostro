// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase 7b step 5b: server-side handler for the canonical-root
//! attestation protocol.
//!
//! Registers `/rostro/canonical-attest/1` as a request-response
//! protocol on `sc-network`. When a peer sends an
//! [`AttestationRequest`], we read the local on-chain
//! `CanonicalFilesApi::canonical_root()` value and reply with an
//! [`AttestationResponse`] echoing the nonce and reporting our
//! locally-computed canonical root.
//!
//! ## Why server-only at this milestone
//!
//! The protocol primitives (Phase 7b step 5a, in
//! `rostro-canonical-fetch::attest`) are bidirectional. This module
//! wires up only the *responder* half of the request/response. Any
//! peer that supports the client half can probe a Rostro node and
//! detect drift. Mutual peer-on-connect attestation (the asker
//! half) lands in a follow-up milestone — without Phase 6.9
//! hardware-rooted measurement the client-side gating mostly
//! catches honest drift, which Phase 7a's boot-time self-check
//! already catches on the drifted peer's own node. Hardware
//! attestation is what makes mutual attestation truly load-bearing
//! against sophisticated adversaries.
//!
//! ## What the handler does
//!
//! 1. Decode the request payload as [`AttestationRequest`] (SCALE).
//!    A malformed payload returns `Err(())` to the peer (no
//!    reputation change — could be a non-Rostro peer probing).
//! 2. Read `CanonicalFilesApi::canonical_root()` at the latest
//!    block.
//! 3. Determine our own role hint: `Validator` if the local config
//!    says we're an authority, `NonValidator` otherwise.
//! 4. Build an [`AttestationResponse`] echoing the request nonce,
//!    reporting our root + role hint. Encode + send.
//!
//! ## What the handler is NOT
//!
//! - Not authenticated. The response is a self-report; without
//!   Phase 6.9 hardware attestation there is no cryptographic
//!   proof of file possession behind the claim.
//! - Not rate-limited beyond the inbound-queue capacity. Capacity
//!   is sized so a saturating peer queues responses but doesn't
//!   crash the node.

use std::sync::Arc;

use codec::{Decode, Encode};
use futures::StreamExt;
use rc_network::{
	request_responses::{IncomingRequest, OutgoingResponse},
	types::ProtocolName,
	NetworkBackend,
};
use rostro_canonical_fetch::attest::{
	AttestationRequest, AttestationResponse, PeerRole,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use pallet_rostro_canonical_files::CanonicalFilesApi;

/// Inbound-queue capacity. The protocol spec recommends `T / d`
/// where `T` = request_timeout and `d` = expected handle latency.
/// At our 5s timeout and ~1ms handle latency (one runtime API
/// call), 64 queued in-flight requests is comfortably within the
/// recommendation and matches what Substrate's other
/// request/response handlers use.
const INBOUND_QUEUE_CAPACITY: usize = 64;

/// Maximum request payload size. An [`AttestationRequest`] is
/// fixed-shape (32-byte nonce) so 64 bytes leaves comfortable
/// SCALE-overhead headroom without inviting amplification abuse.
const MAX_REQUEST_SIZE: u64 = 64;

/// Maximum response payload size. An [`AttestationResponse`] is
/// fixed-shape (32B nonce + 32B root + small enum tag) — well under
/// 256 bytes including SCALE overhead.
const MAX_RESPONSE_SIZE: u64 = 256;

/// Request timeout. Generous; the responder only does one runtime
/// API read.
const REQUEST_TIMEOUT_SECS: u64 = 5;

/// Wire-protocol name, fixed across all Rostro chains. The chain
/// the handler answers for is established by the
/// `CanonicalFilesApi::canonical_root()` query — both peers
/// reading the same chain by definition agree on it.
pub const ATTEST_PROTOCOL_NAME: &str = "/rostro/canonical-attest/1";

/// Build the protocol config and a future that drives the
/// server-side handler. The caller adds the returned config to
/// `FullNetworkConfiguration` via `add_request_response_protocol`
/// and spawns the future on the task manager.
///
/// Generic over the [`NetworkBackend`] type so the returned config
/// is the right concrete `N::RequestResponseProtocolConfig` for
/// whichever backend (libp2p / litep2p) the node is running.
pub fn build_attest_protocol<N, C, Block>(
	client: Arc<C>,
	is_authority: bool,
) -> (N::RequestResponseProtocolConfig, impl std::future::Future<Output = ()>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: CanonicalFilesApi<Block>,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);

	let config = N::request_response_config(
		ProtocolName::from(ATTEST_PROTOCOL_NAME),
		Vec::new(),
		MAX_REQUEST_SIZE,
		MAX_RESPONSE_SIZE,
		std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
		Some(tx),
	);

	let handler = run_handler(client, is_authority, rx);

	(config, handler)
}

async fn run_handler<C, Block>(
	client: Arc<C>,
	is_authority: bool,
	mut rx: async_channel::Receiver<IncomingRequest>,
) where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: CanonicalFilesApi<Block>,
{
	let our_role = if is_authority { PeerRole::Validator } else { PeerRole::NonValidator };

	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		let result = handle_one(&client, our_role, &payload);
		match &result {
			Ok(_) => {
				log::trace!(
					target: "rostro-attest",
					"served canonical-root attestation to {}",
					peer,
				);
			},
			Err(e) => {
				log::debug!(
					target: "rostro-attest",
					"declined attestation request from {}: {}",
					peer,
					e,
				);
			},
		}
		// Drop the oneshot if pending_response can't be filled;
		// dropping is the protocol's "decline without reputation
		// change" signal per `request_responses.rs:228-233`.
		let _ = pending_response.send(OutgoingResponse {
			result: result.map_err(|_| ()),
			reputation_changes: Vec::new(),
			sent_feedback: None,
		});
	}
}

fn handle_one<C, Block>(
	client: &Arc<C>,
	our_role: PeerRole,
	payload: &[u8],
) -> Result<Vec<u8>, &'static str>
where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
	C::Api: CanonicalFilesApi<Block>,
{
	let req = AttestationRequest::decode(&mut &payload[..])
		.map_err(|_| "decode AttestationRequest")?;

	let best = client.info().best_hash;
	let claimed_root = client
		.runtime_api()
		.canonical_root(best)
		.map_err(|_| "CanonicalFilesApi::canonical_root runtime call")?;

	let resp = AttestationResponse {
		nonce: req.nonce,
		claimed_root,
		claimed_role: our_role,
	};
	Ok(resp.encode())
}
