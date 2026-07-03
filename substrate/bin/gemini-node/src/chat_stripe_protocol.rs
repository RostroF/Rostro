// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rc-network` adapter for `/rostro/chat-stripe/1`.
//!
//! Phase B6 of the MLS-chat plan — sender → relay binding. Pulls
//! `IncomingRequest`s off the rc-network channel, dispatches to
//! [`rostro_chat_primitives::store_protocol::process_store_request_bytes`]
//! (Apache-2.0 byte-shim that handles SCALE decode + validation +
//! ShareStore::insert + SCALE encode), sends the encoded
//! `StoreResponse` back via `OutgoingResponse`.
//!
//! All protocol logic lives in the Apache-2.0 utility crate; this
//! file is pure plumbing.
//!
//! ## Channel admission
//!
//! Inbound requests from peers that have a live validator-channel
//! session are rejected — the channel-split invariant says
//! validators don't carry chat traffic. The check consults
//! [`crate::chat_admission::is_chat_admitted`] against the
//! `SharedSessions` map populated by the validator-channel
//! handshake. Rejected requests receive `OutgoingResponse {
//! result: Err(()) }`; the rejection is also logged.

use std::sync::Arc;

use futures::StreamExt;
use rc_network::{
	request_responses::{IncomingRequest, OutgoingResponse},
	types::ProtocolName,
	NetworkBackend,
};
use rostro_chat_primitives::store_protocol::{process_store_request_bytes, ShareStore};
use sp_runtime::traits::Block as BlockT;

use crate::chat_admission::is_chat_admitted;
use crate::validator_channel::SharedSessions;

/// Local-clock helper. Returns the host's current Unix timestamp in
/// seconds, used to bound `expires_at_unix_ts` on inbound share
/// descriptors. No chain involvement — local-clock TTL means a
/// chat-gossip relay doesn't need to follow blocks.
fn now_unix_seconds() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// libp2p protocol name. Versioned suffix bumped if the wire
/// format changes incompatibly. Distinct from
/// `/rostro/validator-channel/*` and `/rostro/canonical-fetch-*`.
pub const CHAT_STRIPE_PROTOCOL_NAME: &str = "/rostro/chat-stripe/1";

/// Inbound queue capacity. Matches the existing canonical-fetch
/// + attest handler conventions.
const INBOUND_QUEUE_CAPACITY: usize = 64;

/// Maximum request payload size. A share body can be up to
/// [`rostro_chat_primitives::store_protocol::MAX_SHARE_BYTES`]
/// (4 MiB); SCALE-encoding plus descriptor + MAC tag adds at most
/// a few hundred bytes.
const MAX_REQUEST_SIZE: u64 =
	rostro_chat_primitives::store_protocol::MAX_SHARE_BYTES as u64 + 1024;

/// Maximum response payload size. A `StoreResponse` is a few
/// bytes; 64 bytes leaves headroom for future fields.
const MAX_RESPONSE_SIZE: u64 = 64;

/// Request timeout. Generous because a 4 MiB share over a slow
/// link can take a while.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Build the protocol config + handler future. The caller registers
/// the config via `FullNetworkConfiguration::add_request_response_protocol`
/// and spawns the future on the task manager.
///
/// `validator_sessions` is the same `SharedSessions` map owned by
/// the validator-channel handshake server; the handler consults it
/// to enforce the channel-split invariant (validators rejected from
/// chat substreams).
pub fn build_chat_stripe_protocol<N, S, Block>(
	store: Arc<S>,
	validator_sessions: SharedSessions,
) -> (N::RequestResponseProtocolConfig, impl std::future::Future<Output = ()>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
	S: ShareStore + Send + Sync + 'static,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);

	let config = N::request_response_config(
		ProtocolName::from(CHAT_STRIPE_PROTOCOL_NAME),
		Vec::new(),
		MAX_REQUEST_SIZE,
		MAX_RESPONSE_SIZE,
		std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
		Some(tx),
	);

	(config, run_handler::<S>(store, validator_sessions, rx))
}

/// Inbound-request loop. Pulls `IncomingRequest`s from rc-network,
/// gates each on the channel-split admission check, dispatches
/// admitted requests to the Apache-2.0 byte-shim. No protocol
/// logic lives here.
async fn run_handler<S>(
	store: Arc<S>,
	validator_sessions: SharedSessions,
	mut rx: async_channel::Receiver<IncomingRequest>,
) where
	S: ShareStore + Send + Sync + 'static,
{
	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		// Admission: reject peers known to be active validators.
		if !is_chat_admitted(&validator_sessions, &peer) {
			log::debug!(
				target: "rostro-chat-stripe",
				"rejecting store request from {} — peer holds a validator-channel \
				 session (channel-split invariant)",
				peer,
			);
			let _ = pending_response.send(OutgoingResponse {
				result: Err(()),
				reputation_changes: Vec::new(),
				sent_feedback: None,
			});
			continue;
		}

		let now_ts = now_unix_seconds();
		let (response_bytes, decoded_ok) =
			process_store_request_bytes(store.as_ref(), now_ts, &payload);
		if decoded_ok {
			// Drop-stored success + depositing peer: not in the canonical
			// binary (GUARD-PRIVACY-AUDIT G3).
			#[cfg(feature = "chat-diagnostics")]
			log::trace!(
				target: "rostro-chat-stripe",
				"processed store request from {}",
				peer,
			);
		} else {
			log::debug!(
				target: "rostro-chat-stripe",
				"malformed store request from {}",
				peer,
			);
		}
		let _ = pending_response.send(OutgoingResponse {
			result: Ok(response_bytes),
			reputation_changes: Vec::new(),
			sent_feedback: None,
		});
	}
}
