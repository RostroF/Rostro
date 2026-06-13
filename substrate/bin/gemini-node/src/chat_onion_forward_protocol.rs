// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rc-network` adapter for `/rostro/chat-onion-forward/1` — the
//! node-to-node hop that carries a metadata-anonymity onion from the
//! guard to relay-2 (Phase 4, slice 2).
//!
//! ## What this is (and is NOT)
//!
//! An onion is **transport, not a message**. It is passed DIRECTLY from
//! one node to the next, peeled one layer per hop, and only the FINAL
//! peeled message ever enters the bucket/stripe messaging layer. This
//! protocol is that direct hop: the guard, after peeling its own layer,
//! sends the still-sealed `inner` packet here; relay-2 receives it,
//! peels its layer, and (because it is the last hop) injects the
//! recipient **message** into the normal stripe-and-distribute path.
//!
//! The onion is **never** sharded to forward it — that is the precise
//! failure the peeler/messaging split exists to prevent. See
//! docs/DOTWAVE-CHAT-METADATA-ANONYMITY.md, "Resolved structure".
//!
//! ## Trust model
//!
//! Cert-auth of the original sender happens ONCE, at the guard's RPC
//! entry (`chat_send_onion`). Relay-2 does NOT re-auth the sender (it
//! never sees the sender). Instead it admits a forward only from a
//! **canonical-gated peer relay** (`DriftLedger::is_passed`) that is not
//! an active validator (`is_chat_admitted`, the channel-split invariant).
//! Trust chain: `client →(cert)→ guard →(canonical-gated peer)→ relay-2`.
//!
//! ## 2-hop cap
//!
//! relay-2 peels with `allow_forward = false`: a packet that peels to a
//! further `Forward` is rejected. v1 is strictly two hops; this caps the
//! chain and removes relay-to-relay loops/amplification as an abuse
//! vector. N-hop (Sphinx territory) is a documented future.

use std::sync::Arc;

use codec::{Decode, Encode};
use futures::StreamExt;
use rc_network::{
	request_responses::{IncomingRequest, OutgoingResponse},
	types::ProtocolName,
	NetworkBackend,
};
use rostro_chat_onion::OnionPacket;
use sp_runtime::traits::Block as BlockT;

use crate::attest_asker::SharedDriftLedger;
use crate::chat_admission::is_chat_admitted;
use crate::chat_rpc::OnionPeelCtx;
use crate::validator_channel::SharedSessions;

/// libp2p protocol name. Versioned suffix bumped on an incompatible
/// wire change. Distinct from the other `/rostro/chat-*` protocols.
pub const CHAT_ONION_FORWARD_PROTOCOL_NAME: &str = "/rostro/chat-onion-forward/1";

/// Inbound queue capacity. Matches the other chat handlers.
const INBOUND_QUEUE_CAPACITY: usize = 64;

/// Maximum request payload. An onion's inner packet wraps a single
/// padded drop (`rostro_chat_onion::FIXED_DROP_SIZE`) plus per-layer
/// sealing overhead — a few KiB. 64 KiB leaves generous headroom.
const MAX_REQUEST_SIZE: u64 = 64 * 1024;

/// Maximum response payload. An [`OnionForwardResponse`] is two short
/// hex strings or a rejection message; 4 KiB covers error text.
const MAX_RESPONSE_SIZE: u64 = 4 * 1024;

/// Request timeout. Relay-2 peels AND runs the full stripe fan-out
/// synchronously before responding, so this is necessarily larger than
/// a single stripe request. (Synchronous result propagation is a v1
/// choice — it returns the real delivery outcome to the guard, at the
/// cost of holding the forward request open during relay-2's fan-out.)
const REQUEST_TIMEOUT_SECS: u64 = 120;

/// The forward request: the still-sealed inner onion packet plus the
/// share count to use when relay-2 reaches the final `Deliver`. The
/// packet is SCALE-encoded `OnionPacket` bytes; relay-2 decodes and
/// peels it. The request carries NO sender material — the guard's outer
/// layer (with the sender's ephemeral) never reaches relay-2.
#[derive(Encode, Decode)]
pub struct OnionForwardRequest {
	/// Share count to use at the final `Deliver` (0 = node default).
	pub total_shares: u8,
	/// SCALE-encoded inner `OnionPacket` (sealed to relay-2).
	pub packet_bytes: Vec<u8>,
}

/// The forward response: the delivery outcome relay-2 produced, relayed
/// back so the guard can return a meaningful result to the sender. The
/// guard cannot construct these itself — message id and pickup key are
/// only known after relay-2 peels the inner layer.
#[derive(Encode, Decode)]
pub enum OnionForwardResponse {
	/// relay-2 peeled to `Deliver` and the message was striped.
	Delivered {
		message_id_hex: String,
		share_count: u32,
		recipient_pickup_key_hex: String,
	},
	/// relay-2 refused or failed (gate, decode, peel, or stripe).
	/// `code`/`message` mirror the underlying jsonrpsee error so the
	/// guard can relay it transparently to the sender.
	Rejected { code: i32, message: String },
}

/// Build the protocol config + return the inbound `rx`. The config must
/// be registered into `net_config` BEFORE `build_network`; the handler
/// future (which needs the post-`build_network` `NetworkService` handle
/// for the outbound stripe fan-out) is spawned separately via
/// [`run_onion_forward_handler`].
pub fn build_chat_onion_forward_config<N, Block>(
) -> (N::RequestResponseProtocolConfig, async_channel::Receiver<IncomingRequest>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);
	let config = N::request_response_config(
		ProtocolName::from(CHAT_ONION_FORWARD_PROTOCOL_NAME),
		Vec::new(),
		MAX_REQUEST_SIZE,
		MAX_RESPONSE_SIZE,
		std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
		Some(tx),
	);
	(config, rx)
}

/// Inbound-forward loop. For each request: gate the sending peer (must
/// be a canonical-gated relay and not an active validator), decode the
/// inner packet, then peel-and-dispatch it with `allow_forward = false`
/// (relay-2 must DELIVER — the 2-hop cap). The peeler injects the
/// recipient message into the existing stripe path; the delivery outcome
/// is relayed back to the guard.
pub async fn run_onion_forward_handler(
	peel_ctx: Arc<OnionPeelCtx>,
	sessions: SharedSessions,
	drift_ledger: SharedDriftLedger,
	mut rx: async_channel::Receiver<IncomingRequest>,
) {
	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		// Gate: only canonical-gated peer relays may forward onions to
		// us, and never active validators (channel-split). The original
		// sender is NOT re-authed here — relay-2 never sees the sender.
		let admitted = is_chat_admitted(&sessions, &peer);
		let canonical_relay = drift_ledger.lock().is_passed(&peer);
		if !admitted || !canonical_relay {
			log::debug!(
				target: "rostro-chat-onion-fwd",
				"rejecting onion-forward from {peer} (not_validator={admitted}, \
				 canonical_relay={canonical_relay})",
			);
			let _ = pending_response.send(OutgoingResponse {
				result: Err(()),
				reputation_changes: Vec::new(),
				sent_feedback: None,
			});
			continue;
		}

		let response = handle_forward(&peel_ctx, &payload).await;
		let _ = pending_response.send(OutgoingResponse {
			result: Ok(response.encode()),
			reputation_changes: Vec::new(),
			sent_feedback: None,
		});
	}
}

/// Decode + peel + deliver one forwarded onion. Always DELIVER
/// (`allow_forward = false`): a forwarded packet that peels to a further
/// `Forward` is rejected (2-hop cap). Returns the wire response.
async fn handle_forward(peel_ctx: &OnionPeelCtx, payload: &[u8]) -> OnionForwardResponse {
	let req = match OnionForwardRequest::decode(&mut &payload[..]) {
		Ok(req) => req,
		Err(e) => {
			return OnionForwardResponse::Rejected {
				code: -32000,
				message: format!("onion-forward request decode failed: {e}"),
			}
		}
	};
	let packet = match OnionPacket::decode(&mut &req.packet_bytes[..]) {
		Ok(packet) => packet,
		Err(e) => {
			return OnionForwardResponse::Rejected {
				code: -32000,
				message: format!("forwarded onion packet decode failed: {e}"),
			}
		}
	};
	// allow_forward = false: relay-2 must deliver, never re-forward.
	match peel_ctx.peel_and_dispatch(&packet, req.total_shares, false).await {
		Ok(r) => OnionForwardResponse::Delivered {
			message_id_hex: r.message_id_hex,
			share_count: r.share_count,
			recipient_pickup_key_hex: r.recipient_pickup_key_hex,
		},
		Err(e) => OnionForwardResponse::Rejected { code: e.code(), message: e.message().to_string() },
	}
}
