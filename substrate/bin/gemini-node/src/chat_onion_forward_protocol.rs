// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rc-network` adapter for `/rostro/chat-onion-forward/3` — the
//! node-to-node hop that carries a metadata-anonymity onion from the
//! guard to relay-2 (Phase 4, slice 2).
//!
//! ## What this is (and is NOT)
//!
//! An onion is **transport, not a message**. It is passed DIRECTLY from
//! one node to the next, peeled one layer per hop, and only the FINAL
//! peeled message ever enters the bucket/chunk messaging layer. This
//! protocol is that direct hop: the guard, after peeling its own layer,
//! sends the still-sealed `inner` packet here; relay-2 receives it,
//! peels its layer, and (because it is the last hop) fans the
//! recipient's prepared chunk batch out to the bucket peers.
//!
//! The onion is **never** sharded to forward it — that is the precise
//! failure the peeler/messaging split exists to prevent. See
//! docs/DOTWAVE-CHAT-METADATA-ANONYMITY.md, "Resolved structure".
//!
//! ## Trust model
//!
//! Cert-auth of the original *sender* happens ONCE, at the guard's RPC
//! entry (`chat_send_onion`). Relay-2 does NOT re-auth the sender (it
//! never sees the sender). It admits a forward only from a **canonical-gated
//! peer relay** (`DriftLedger::is_passed`) that is not an active validator
//! (`is_chat_admitted`, the channel-split invariant), AND it verifies a
//! **guard attestation** (`guard_sig`, 1a): the forwarding node signs the
//! packet with its node key, relay-2 recovers that key from the authenticated
//! connection and checks it before peeling. This does not (and cannot, without
//! breaking sender anonymity) *prevent* a malicious canonical node from
//! injecting — but it makes every forward **attributable to a node identity**
//! and reputation-ejectable, which is the accountability a volunteer fabric
//! runs on. Trust chain: `client →(cert)→ guard →(canonical peer + signed
//! attestation)→ relay-2`.
//!
//! ## 2-hop cap
//!
//! relay-2 peels with `PeelMode::FinalRelay`: a packet that peels to a
//! further `Forward` is rejected. v1 is strictly two hops; this caps the
//! chain and removes relay-to-relay loops/amplification as an abuse
//! vector. N-hop (Sphinx territory) is a documented future.

use std::sync::Arc;

use codec::{Decode, Encode};
use futures::StreamExt;
use rc_network::{
	request_responses::{IncomingRequest, OutgoingResponse},
	types::ProtocolName,
	NetworkBackend, ReputationChange,
};
use rostro_chat_onion::OnionPacket;
use rostro_node_identity::NodeIdentity;
use sp_core::blake2_256;
use sp_runtime::traits::Block as BlockT;

use crate::attest_asker::SharedDriftLedger;
use crate::chat_admission::is_chat_admitted;
use crate::chat_rpc::{OnionPeelCtx, PeelMode};
use crate::validator_channel::SharedSessions;

/// libp2p protocol name. Versioned suffix bumped on an incompatible
/// wire change. Distinct from the other `/rostro/chat-*` protocols.
/// Bumped to `/2` when the guard attestation (`guard_sig`) was added to
/// [`OnionForwardRequest`]; bumped to `/3` at the chunk cutover
/// (docs/CHAT-SHARE-CHUNKING.md), when `total_shares` left the request
/// (chunk counts ride inside the sender-prepared batch) — hard
/// cutovers, no coexistence.
pub const CHAT_ONION_FORWARD_PROTOCOL_NAME: &str = "/rostro/chat-onion-forward/3";

/// JSON-RPC error code `chat_send_onion` returns when the sender's chosen
/// relay-2 is not a live chat-fabric member (1b liveness pre-check). Distinct
/// from the generic `-32000` so the mobile app can match on it and re-roll to
/// another relay-2 instead of surfacing a hard failure. Within the JSON-RPC
/// implementation-defined server-error band (-32000..=-32099).
pub const RELAY_UNAVAILABLE_CODE: i32 = -32050;

/// Domain separator for the guard's forward-leg attestation signature, bound
/// into the signed digest so a guard's onion-forward signature can never be
/// confused with one it produced for any other purpose. `/v2`: the chunk
/// cutover removed `total_shares` from the digest (chunk counts ride inside
/// the sender-prepared batch, MAC-bound end-to-end).
pub const ONION_FWD_DOMAIN: &[u8] = b"rostro/chat/onion-forward/v2";

/// The digest the guard signs and relay-2 verifies for forward-leg
/// accountability (1a): `blake2_256(ONION_FWD_DOMAIN ‖ packet_bytes)`.
/// One shared helper so the two sides can never drift.
pub fn onion_forward_digest(packet_bytes: &[u8]) -> [u8; 32] {
	let mut buf = Vec::with_capacity(ONION_FWD_DOMAIN.len() + packet_bytes.len());
	buf.extend_from_slice(ONION_FWD_DOMAIN);
	buf.extend_from_slice(packet_bytes);
	blake2_256(&buf)
}

/// Reputation penalty for a peer that forwards an onion which fails the guard
/// attestation or is undecodable — a misbehaving guard. Heavy but non-fatal:
/// standard peer scoring bans a peer that repeats this, while a single anomaly
/// (e.g. across a restart) does not insta-ban an honest relay. A failed *peel*
/// after a VALID attestation is NOT penalised — the guard cannot inspect the
/// relay-2-sealed inner layer, so a bad inner is the sender's construction.
fn bad_forward_rep() -> ReputationChange {
	ReputationChange::new(-(1 << 16), "bad chat onion-forward")
}

/// Inbound queue capacity. Matches the other chat handlers.
const INBOUND_QUEUE_CAPACITY: usize = 64;

/// Maximum request payload. An onion's inner packet wraps a single
/// padded drop (`rostro_chat_onion::FIXED_DROP_SIZE`) plus per-layer
/// sealing overhead — a few KiB. 64 KiB leaves generous headroom.
const MAX_REQUEST_SIZE: u64 = 64 * 1024;

/// Maximum response payload. An [`OnionForwardResponse`] is two short
/// hex strings or a rejection message; 4 KiB covers error text.
const MAX_RESPONSE_SIZE: u64 = 4 * 1024;

/// Request timeout. Relay-2 peels AND runs the full chunk fan-out
/// synchronously before responding, so this is necessarily larger than
/// a single store request. (Synchronous result propagation is a v1
/// choice — it returns the real delivery outcome to the guard, at the
/// cost of holding the forward request open during relay-2's fan-out.)
const REQUEST_TIMEOUT_SECS: u64 = 120;

/// The forward request: the still-sealed inner onion packet. The
/// packet is SCALE-encoded `OnionPacket` bytes; relay-2 decodes and
/// peels it (the innermost `Deliver` drop is a sender-prepared chunk
/// batch, chunk counts included). The request carries NO sender
/// material — the guard's outer layer (with the sender's ephemeral)
/// never reaches relay-2.
#[derive(Encode, Decode)]
pub struct OnionForwardRequest {
	/// SCALE-encoded inner `OnionPacket` (sealed to relay-2).
	pub packet_bytes: Vec<u8>,
	/// The forwarding guard's ed25519 signature over
	/// `onion_forward_digest(packet_bytes)` (1a). relay-2
	/// recovers the guard's pubkey from the AUTHENTICATED sending peer and
	/// verifies this BEFORE peeling, making every forwarded onion attributable
	/// to a specific node identity (reputation-ejectable on abuse). This is the
	/// guard's OWN node key — never sender material; the sender's ephemeral
	/// (the outer layer) never reaches relay-2.
	pub guard_sig: [u8; 64],
}

/// The forward response: the delivery outcome relay-2 produced, relayed
/// back so the guard can return a meaningful result to the sender. The
/// guard cannot construct these itself — message id and pickup key are
/// only known after relay-2 peels the inner layer.
#[derive(Encode, Decode)]
pub enum OnionForwardResponse {
	/// relay-2 peeled to `Deliver` and the chunks were distributed.
	Delivered {
		message_id_hex: String,
		share_count: u32,
		recipient_pickup_key_hex: String,
	},
	/// relay-2 refused or failed (gate, decode, peel, or distribute).
	/// `code`/`message` mirror the underlying jsonrpsee error so the
	/// guard can relay it transparently to the sender.
	Rejected { code: i32, message: String },
}

/// Build the protocol config + return the inbound `rx`. The config must
/// be registered into `net_config` BEFORE `build_network`; the handler
/// future (which needs the post-`build_network` `NetworkService` handle
/// for the outbound chunk fan-out) is spawned separately via
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
/// be a canonical-gated relay and not an active validator), verify the
/// guard attestation (1a), decode the inner packet, then peel-and-dispatch
/// it with `PeelMode::FinalRelay` (relay-2 must DELIVER — the 2-hop cap).
/// The peeler fans the recipient batch out to the bucket peers; the
/// delivery outcome — and any reputation penalty for a misbehaving
/// guard — is relayed back via the response.
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

		// Recover the forwarding guard's node identity from the AUTHENTICATED
		// connection (the libp2p Noise handshake already proved the peer holds
		// this key). `None` for a non-ed25519 peer id, which then fails the
		// attestation check below.
		let guard_id = peer.into_ed25519().map(NodeIdentity::from_ed25519_pubkey);

		let (response, reputation_changes) =
			handle_forward(&peel_ctx, guard_id.as_ref(), &payload).await;
		let _ = pending_response.send(OutgoingResponse {
			result: Ok(response.encode()),
			reputation_changes,
			sent_feedback: None,
		});
	}
}

/// Verify the guard attestation, then decode + peel + deliver one forwarded
/// onion. Always DELIVER (`PeelMode::FinalRelay`): a forwarded packet that
/// peels to a further `Forward` is rejected (2-hop cap). Returns the wire
/// response plus any reputation change to apply to the forwarding peer.
async fn handle_forward(
	peel_ctx: &OnionPeelCtx,
	guard_id: Option<&NodeIdentity>,
	payload: &[u8],
) -> (OnionForwardResponse, Vec<ReputationChange>) {
	let req = match OnionForwardRequest::decode(&mut &payload[..]) {
		Ok(req) => req,
		Err(e) => {
			return (
				OnionForwardResponse::Rejected {
					code: -32000,
					message: format!("onion-forward request decode failed: {e}"),
				},
				vec![bad_forward_rep()],
			)
		}
	};

	// 1a: verify the guard's forward-leg attestation BEFORE peeling. A guard
	// that signs nothing, signs the wrong bytes, or is not an ed25519 peer is a
	// misbehaving forwarder — reject and reputation-dock the (authenticated)
	// peer. The signature binds the exact inner packet to the signing node,
	// so every accepted forward is attributable and ejectable.
	let digest = onion_forward_digest(&req.packet_bytes);
	let attested = guard_id.map_or(false, |id| id.verify(&digest, &req.guard_sig));
	if !attested {
		return (
			OnionForwardResponse::Rejected {
				code: -32000,
				message: "onion-forward guard attestation invalid".to_string(),
			},
			vec![bad_forward_rep()],
		);
	}

	let packet = match OnionPacket::decode(&mut &req.packet_bytes[..]) {
		Ok(packet) => packet,
		Err(e) => {
			return (
				OnionForwardResponse::Rejected {
					code: -32000,
					message: format!("forwarded onion packet decode failed: {e}"),
				},
				vec![bad_forward_rep()],
			)
		}
	};

	// PeelMode::FinalRelay: relay-2 must deliver, never re-forward (2-hop cap).
	// A peel/deliver error here is NOT reputation-penalised — the inner layer is
	// sealed to relay-2, so the guard could not have inspected it; a bad inner
	// is the sender's construction, not the forwarding guard's fault.
	match peel_ctx.peel_and_dispatch(&packet, PeelMode::FinalRelay).await {
		Ok(r) => (
			OnionForwardResponse::Delivered {
				message_id_hex: r.message_id_hex,
				share_count: r.share_count,
				recipient_pickup_key_hex: r.recipient_pickup_key_hex,
			},
			Vec::new(),
		),
		Err(e) => (
			OnionForwardResponse::Rejected { code: e.code(), message: e.message().to_string() },
			Vec::new(),
		),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rostro_node_identity::NodeSecret;

	#[test]
	fn guard_attestation_roundtrips_and_binds_content() {
		// Pins the 1a accountability primitive: the guard signs the digest,
		// relay-2 recovers the guard identity from the authenticated peer and
		// verifies. A valid forward is attributable to the signing node, and any
		// tamper of the signed fields breaks verification.
		let guard = NodeSecret::from_seed([0x42; 32]);
		let id = guard.identity();
		let packet_bytes = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

		let sig = guard.sign(&onion_forward_digest(&packet_bytes));

		// Honest forward verifies.
		assert!(id.verify(&onion_forward_digest(&packet_bytes), &sig));

		// Tampering the inner packet breaks attribution.
		let mut tampered = packet_bytes.clone();
		tampered[0] ^= 0xFF;
		assert!(!id.verify(&onion_forward_digest(&tampered), &sig));

		// A DIFFERENT node cannot pass this signature off as its own — the
		// forward is bound to the signing identity (ejectable attribution), and
		// `guard_id = None` (non-ed25519 peer) likewise fails by construction.
		let other = NodeSecret::from_seed([0x43; 32]);
		assert!(!other.identity().verify(&onion_forward_digest(&packet_bytes), &sig));
	}

	#[test]
	fn digest_is_domain_separated() {
		// The signed digest is domain-separated, so a guard's onion-forward
		// signature can't be replayed as a signature over raw bytes.
		let packet_bytes = vec![9u8; 16];
		let d = onion_forward_digest(&packet_bytes);
		assert_ne!(d, blake2_256(&packet_bytes));
	}
}
