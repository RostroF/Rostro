// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Thin substrate-RPC client built on jsonrpsee.
//!
//! We don't use subxt here — the test harness submits malformed and
//! adversarial payloads, and subxt's type-safety would fight us. Raw
//! JSON-RPC + manual SCALE construction gives us full control.

use anyhow::{Context, Result};
use jsonrpsee::{
	core::client::ClientT,
	rpc_params,
	ws_client::{WsClient, WsClientBuilder},
};
use serde::Deserialize;

/// Open a WebSocket JSON-RPC client to a substrate node.
pub async fn connect(ws_url: &str) -> Result<WsClient> {
	WsClientBuilder::default()
		.build(ws_url)
		.await
		.with_context(|| format!("connecting to {ws_url}"))
}

/// `system_chain` — sanity check we're talking to the right thing.
pub async fn system_chain(client: &WsClient) -> Result<String> {
	let s: String = client.request("system_chain", rpc_params![]).await?;
	Ok(s)
}

/// `chain_getHeader` (no params = latest).
pub async fn chain_get_header(client: &WsClient) -> Result<HeaderJson> {
	let h: HeaderJson = client.request("chain_getHeader", rpc_params![]).await?;
	Ok(h)
}

/// `chain_getFinalizedHead` → block hash.
pub async fn chain_get_finalized_head(client: &WsClient) -> Result<String> {
	let h: String = client.request("chain_getFinalizedHead", rpc_params![]).await?;
	Ok(h)
}

/// `system_health` returns peers / sync status.
pub async fn system_health(client: &WsClient) -> Result<HealthJson> {
	let h: HealthJson = client.request("system_health", rpc_params![]).await?;
	Ok(h)
}

/// `state_call` — execute a runtime API method, returning the SCALE-encoded
/// result. `method` is e.g. `"SassafrasApi_slot_ticket"`. `params_hex` is
/// the SCALE-encoded args as a 0x-prefixed hex string.
pub async fn state_call(
	client: &WsClient,
	method: &str,
	params_hex: &str,
) -> Result<String> {
	let r: String = client
		.request("state_call", rpc_params![method, params_hex])
		.await?;
	Ok(r)
}

/// `author_submitExtrinsic` — submit a hex-encoded extrinsic. Returns
/// the extrinsic hash on success.
pub async fn author_submit_extrinsic(
	client: &WsClient,
	extrinsic_hex: &str,
) -> Result<String> {
	let r: String = client
		.request("author_submitExtrinsic", rpc_params![extrinsic_hex])
		.await?;
	Ok(r)
}

/// `author_pendingExtrinsics` — list of hex-encoded extrinsics in the
/// node's local mempool.
pub async fn author_pending_extrinsics(client: &WsClient) -> Result<Vec<String>> {
	let r: Vec<String> = client
		.request("author_pendingExtrinsics", rpc_params![])
		.await?;
	Ok(r)
}

#[derive(Debug, Deserialize)]
pub struct HeaderJson {
	pub number: String, // hex like "0x42"
	#[serde(rename = "stateRoot")]
	pub state_root: String,
	#[serde(rename = "parentHash")]
	pub parent_hash: String,
}

impl HeaderJson {
	pub fn number_decimal(&self) -> u64 {
		u64::from_str_radix(self.number.trim_start_matches("0x"), 16).unwrap_or(0)
	}
}

#[derive(Debug, Deserialize)]
pub struct HealthJson {
	pub peers: u64,
	#[serde(rename = "isSyncing")]
	pub is_syncing: bool,
	#[serde(rename = "shouldHavePeers")]
	pub should_have_peers: bool,
}
