// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rc-network` adapter for `/rostro/chat-fetch/1`.
//!
//! Phase B6 of the MLS-chat plan — recipient → relay binding.
//! Pulls `IncomingRequest`s off the rc-network channel, dispatches
//! to
//! [`rostro_chat_primitives::fetch_protocol::process_fetch_request_bytes`]
//! (Apache-2.0 byte-shim that handles SCALE decode +
//! ShareStore::get_by_pickup_key + truncate-to-cap + SCALE encode),
//! sends the encoded `FetchResponse` back via `OutgoingResponse`.
//!
//! All protocol logic lives in the Apache-2.0 utility crate; this
//! file is pure plumbing. Unlike the store side, the fetch handler
//! does NOT need the chain client (no TTL check at fetch time —
//! the store's sweep already evicted expired entries).
//!
//! ## Channel admission
//!
//! TODO(B6b): same admission note as `chat_stripe_protocol.rs` —
//! refuse to serve fetches to peers in the active validator set
//! once the RoleResolver integration lands.

#![allow(dead_code)]

use std::sync::Arc;

use futures::StreamExt;
use rc_network::{
	request_responses::{IncomingRequest, OutgoingResponse},
	types::ProtocolName,
	NetworkBackend,
};
use rostro_chat_primitives::fetch_protocol::process_fetch_request_bytes;
use rostro_chat_primitives::store_protocol::ShareStore;
use sp_runtime::traits::Block as BlockT;

/// libp2p protocol name. Distinct from `/rostro/chat-stripe/1`,
/// `/rostro/validator-channel/*`, and `/rostro/canonical-fetch-*`.
pub const CHAT_FETCH_PROTOCOL_NAME: &str = "/rostro/chat-fetch/1";

/// Inbound queue capacity.
const INBOUND_QUEUE_CAPACITY: usize = 64;

/// Maximum request payload size. A `FetchRequest` is just a 32-byte
/// pickup_key; 128 bytes is overkill headroom for SCALE overhead +
/// any future field additions.
const MAX_REQUEST_SIZE: u64 = 128;

/// Maximum response payload size. A `FetchResponse` with up to
/// [`rostro_chat_primitives::fetch_protocol::MAX_FETCH_RESPONSE_SHARES`]
/// (32) shares, each carrying up to
/// [`rostro_chat_primitives::store_protocol::MAX_SHARE_BYTES`]
/// (4 MiB) of bytes plus a ~100-byte descriptor + 32-byte MAC tag.
/// 32 × 4 MiB = 128 MiB worst case + SCALE / descriptor / MAC
/// overhead.
const MAX_RESPONSE_SIZE: u64 = 32 * rostro_chat_primitives::store_protocol::MAX_SHARE_BYTES
	as u64
	+ 16 * 1024;

/// Request timeout. Generous to accommodate large fetch responses
/// over slow links.
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// Build the protocol config + handler future. Caller registers the
/// config + spawns the future on the task manager.
pub fn build_chat_fetch_protocol<N, S, Block>(
	store: Arc<S>,
) -> (N::RequestResponseProtocolConfig, impl std::future::Future<Output = ()>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
	S: ShareStore + Send + Sync + 'static,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);

	let config = N::request_response_config(
		ProtocolName::from(CHAT_FETCH_PROTOCOL_NAME),
		Vec::new(),
		MAX_REQUEST_SIZE,
		MAX_RESPONSE_SIZE,
		std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
		Some(tx),
	);

	(config, run_handler::<S, Block>(store, rx))
}

/// Inbound-request loop. Pulls `IncomingRequest`s, dispatches to
/// the Apache-2.0 byte-shim, sends back the encoded `FetchResponse`.
async fn run_handler<S, Block>(
	store: Arc<S>,
	mut rx: async_channel::Receiver<IncomingRequest>,
) where
	Block: BlockT,
	S: ShareStore + Send + Sync + 'static,
{
	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		let (response_bytes, decoded_ok) =
			process_fetch_request_bytes(store.as_ref(), &payload);
		if decoded_ok {
			log::trace!(
				target: "rostro-chat-fetch",
				"processed fetch request from {}",
				peer,
			);
		} else {
			log::debug!(
				target: "rostro-chat-fetch",
				"malformed fetch request from {}",
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
