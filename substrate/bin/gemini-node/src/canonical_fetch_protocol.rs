// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase 7 v2 step 2c: server-side handler for the signed
//! canonical-fetch protocol `/rostro/canonical-fetch-attested/1`.
//!
//! Mirrors [`crate::attest_protocol`] in shape, with three additions:
//!
//! 1. **Bytes** as the payload (not a root attestation), looked up
//!    in a [`rostro_canonical_fetch::CanonicalFileSource`].
//! 2. **Ed25519 signatures** over the response, using the node's
//!    libp2p identity key. The asker re-verifies via
//!    [`rostro_canonical_fetch::signed_fetch::verify_signed_response`].
//! 3. **Chain anchor** (block_number, block_hash) embedded in the
//!    signature preimage, so the asker can reason about how current
//!    the attestation is and disambiguate forks.
//!
//! ## What's deferred
//!
//! The client-side broadcast + K-signature aggregation lives at
//! Piece 3 (asker-side wiring), where it composes with the
//! connect-time gate and the heal flow.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codec::{Decode, Encode};
use futures::StreamExt;
use rc_network::{
	request_responses::{IncomingRequest, OutgoingResponse},
	types::ProtocolName,
	NetworkBackend,
};
use rostro_canonical_fetch::{
	signed_fetch::{handle_signed_request, SignedFetchRequest},
	CanonicalFileSource, MAX_RESPONSE_BYTES,
};
use sp_blockchain::HeaderBackend;
use sp_runtime::{traits::Block as BlockT, SaturatedConversion};

/// libp2p protocol name. Versioned suffix — bumped if the wire format
/// ever changes incompatibly.
pub const CANONICAL_FETCH_PROTOCOL_NAME: &str = "/rostro/canonical-fetch-attested/1";

/// Inbound queue capacity. Matches [`crate::attest_protocol`] and
/// Substrate's other request/response handlers.
const INBOUND_QUEUE_CAPACITY: usize = 64;

/// Maximum request payload size. A [`SignedFetchRequest`] is fixed
/// shape (32-byte hash + 32-byte nonce); 128 bytes leaves comfortable
/// SCALE-overhead headroom.
const MAX_REQUEST_SIZE: u64 = 128;

/// Maximum response payload size. Sized to the underlying
/// [`MAX_RESPONSE_BYTES`] cap plus generous overhead for the
/// SCALE-encoded signature + metadata fields (~256 bytes).
const MAX_RESPONSE_SIZE: u64 = MAX_RESPONSE_BYTES as u64 + 1024;

/// Request timeout. Generous because a heal-fetch may need to pull
/// multi-megabyte canonical bytes across the network.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Build the protocol config + handler future. The caller registers
/// the config via `FullNetworkConfiguration::add_request_response_protocol`
/// and spawns the future on the task manager. Generic over
/// [`NetworkBackend`] so the config types are right for whichever
/// backend (libp2p / litep2p) the node is running.
pub fn build_canonical_fetch_protocol<N, C, S, Block>(
	client: Arc<C>,
	source: Arc<S>,
	signing_key: ed25519_zebra::SigningKey,
) -> (N::RequestResponseProtocolConfig, impl std::future::Future<Output = ()>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
	Block::Hash: AsRef<[u8]>,
	C: HeaderBackend<Block> + Send + Sync + 'static,
	S: CanonicalFileSource + Send + Sync + 'static,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);

	let config = N::request_response_config(
		ProtocolName::from(CANONICAL_FETCH_PROTOCOL_NAME),
		Vec::new(),
		MAX_REQUEST_SIZE,
		MAX_RESPONSE_SIZE,
		Duration::from_secs(REQUEST_TIMEOUT_SECS),
		Some(tx),
	);

	let handler = run_handler::<C, S, Block>(client, source, signing_key, rx);
	(config, handler)
}

async fn run_handler<C, S, Block>(
	client: Arc<C>,
	source: Arc<S>,
	signing_key: ed25519_zebra::SigningKey,
	mut rx: async_channel::Receiver<IncomingRequest>,
) where
	Block: BlockT,
	Block::Hash: AsRef<[u8]>,
	C: HeaderBackend<Block> + Send + Sync + 'static,
	S: CanonicalFileSource + Send + Sync + 'static,
{
	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		let result = handle_one::<C, S, Block>(&client, &source, &signing_key, &payload);
		match &result {
			Ok(_) => {
				log::trace!(
					target: "rostro-canonical-fetch",
					"served signed canonical-fetch reply to {}",
					peer,
				);
			},
			Err(e) => {
				log::debug!(
					target: "rostro-canonical-fetch",
					"declined fetch request from {}: {}",
					peer,
					e,
				);
			},
		}
		// Dropping pending_response is the protocol's "decline
		// without reputation change" signal — used here because we
		// don't penalize peers for sending malformed bytes (could be
		// a non-Rostro peer probing).
		let _ = pending_response.send(OutgoingResponse {
			result: result.map_err(|_| ()),
			reputation_changes: Vec::new(),
			sent_feedback: None,
		});
	}
}

fn handle_one<C, S, Block>(
	client: &Arc<C>,
	source: &Arc<S>,
	signing_key: &ed25519_zebra::SigningKey,
	payload: &[u8],
) -> Result<Vec<u8>, &'static str>
where
	Block: BlockT,
	Block::Hash: AsRef<[u8]>,
	C: HeaderBackend<Block>,
	S: CanonicalFileSource,
{
	let req = SignedFetchRequest::decode(&mut &payload[..])
		.map_err(|_| "decode SignedFetchRequest")?;

	let info = client.info();
	// Saturating conversion: NumberFor<Block> for this chain is u32
	// already, so this is identity. The constraint exists so a future
	// migration to u64 block numbers doesn't silently truncate.
	let block_number: u32 = info.best_number.saturated_into::<u32>();
	let raw_hash = info.best_hash.as_ref();
	if raw_hash.len() < 32 {
		return Err("best_hash narrower than 32 bytes");
	}
	let mut block_hash = [0u8; 32];
	block_hash.copy_from_slice(&raw_hash[..32]);

	let timestamp_unix_secs = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);

	let reply = handle_signed_request(
		source.as_ref(),
		&req,
		block_number,
		block_hash,
		timestamp_unix_secs,
		signing_key,
	);
	Ok(reply.encode())
}

/// Load the libp2p node-identity Ed25519 key for re-use as the
/// canonical-fetch attestation signing key.
///
/// Mirrors `sc-network`'s on-disk format:
/// - 32 raw bytes, OR
/// - 64-character hex string
///
/// Errors if the key is configured as `Secret::New` (fresh-per-run)
/// because canonical-fetch attestations need a persistent identity:
/// peers correlate "who signed" with "who I'm peered to," and a
/// per-run identity defeats that correlation.
pub fn load_node_identity_signing_key(
	node_key: &rc_network::config::NodeKeyConfig,
) -> Result<ed25519_zebra::SigningKey, String> {
	use rc_network::config::{NodeKeyConfig, Secret};
	let bytes: [u8; 32] = match node_key {
		NodeKeyConfig::Ed25519(Secret::Input(sk)) => {
			let raw: &[u8] = sk.as_ref();
			raw.try_into()
				.map_err(|_| format!("node-identity key length {} != 32", raw.len()))?
		},
		NodeKeyConfig::Ed25519(Secret::File(path)) => {
			let file_bytes = std::fs::read(path).map_err(|e| {
				format!(
					"reading node-identity key file {}: {e}",
					path.display(),
				)
			})?;
			parse_node_key_bytes(&file_bytes)?
		},
		NodeKeyConfig::Ed25519(Secret::New) => {
			return Err(
				"canonical-fetch attestation requires a persistent libp2p \
				 node-identity key; got `Secret::New` (fresh-per-run). \
				 Pass --node-key <hex>, --node-key-file <path>, or rely on \
				 the default <base-path>/network/secret_ed25519 file."
					.to_string(),
			);
		},
	};
	Ok(ed25519_zebra::SigningKey::from(bytes))
}

/// Parse a libp2p node-identity-key file. Two acceptable formats —
/// the same sc-network's `into_keypair` accepts — so this function
/// works against keys written by sc-network itself.
fn parse_node_key_bytes(bytes: &[u8]) -> Result<[u8; 32], String> {
	// 64-char hex string. sc-network's writer emits the file in this
	// form.
	if bytes.len() == 64 {
		if let Ok(s) = std::str::from_utf8(bytes) {
			if let Ok(decoded) = array_bytes::hex2bytes(s) {
				if decoded.len() == 32 {
					return decoded
						.try_into()
						.map_err(|_| "hex decode length != 32".to_string());
				}
			}
		}
	}
	// 32 raw bytes. sc-network's reader accepts this for backward
	// compat.
	if bytes.len() == 32 {
		return bytes.try_into().map_err(|_| "raw key length != 32".to_string());
	}
	Err(format!(
		"node-identity key file has {} bytes; expected 32 raw bytes or 64-char hex string",
		bytes.len(),
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_accepts_32_raw_bytes() {
		let raw = [0x42u8; 32];
		let parsed = parse_node_key_bytes(&raw).unwrap();
		assert_eq!(parsed, raw);
	}

	#[test]
	fn parse_accepts_64_hex_chars() {
		// 32 bytes of 0xAB as hex.
		let hex = "ab".repeat(32);
		let parsed = parse_node_key_bytes(hex.as_bytes()).unwrap();
		assert_eq!(parsed, [0xABu8; 32]);
	}

	#[test]
	fn parse_rejects_wrong_length() {
		assert!(parse_node_key_bytes(&[0u8; 31]).is_err());
		assert!(parse_node_key_bytes(&[0u8; 33]).is_err());
		assert!(parse_node_key_bytes(b"too short hex").is_err());
	}

	#[test]
	fn parse_rejects_non_hex_in_64_byte_input() {
		let bad_hex = "zz".repeat(32);
		assert!(parse_node_key_bytes(bad_hex.as_bytes()).is_err());
	}

	#[test]
	fn load_rejects_secret_new() {
		use rc_network::config::{NodeKeyConfig, Secret};
		let cfg = NodeKeyConfig::Ed25519(Secret::New);
		let err = load_node_identity_signing_key(&cfg).unwrap_err();
		assert!(err.contains("persistent"));
	}
}
