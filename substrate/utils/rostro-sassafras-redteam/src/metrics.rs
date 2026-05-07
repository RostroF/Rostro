// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Block-production-rate sampler.
//!
//! Polls `chain_getHeader` at a fixed cadence, records (timestamp,
//! block_number) pairs, computes blocks/min, finalization gap.

use anyhow::Result;
use std::time::{Duration, Instant};

use crate::client;

/// One sample of chain liveness.
#[derive(Debug, Clone)]
pub struct LivenessSample {
	pub at: Instant,
	pub best_number: u64,
	pub finalized_number: u64,
	pub peers: u64,
}

/// Sample once.
pub async fn sample(client: &jsonrpsee::ws_client::WsClient) -> Result<LivenessSample> {
	let head = client::chain_get_header(client).await?;
	let finalized_hash = client::chain_get_finalized_head(client).await?;
	// Get the finalized header by hash; fall back to 0 if call fails.
	let finalized_number =
		match client_get_header_by_hash(client, &finalized_hash).await {
			Ok(h) => h.number_decimal(),
			Err(_) => 0,
		};
	let health = client::system_health(client).await?;

	Ok(LivenessSample {
		at: Instant::now(),
		best_number: head.number_decimal(),
		finalized_number,
		peers: health.peers,
	})
}

async fn client_get_header_by_hash(
	c: &jsonrpsee::ws_client::WsClient,
	hash: &str,
) -> Result<client::HeaderJson> {
	use jsonrpsee::core::client::ClientT;
	use jsonrpsee::rpc_params;
	let h: client::HeaderJson = c.request("chain_getHeader", rpc_params![hash]).await?;
	Ok(h)
}

/// Run a sampling window, return summary stats.
pub async fn observe_window(
	client: &jsonrpsee::ws_client::WsClient,
	duration: Duration,
	tick: Duration,
) -> Result<WindowStats> {
	let mut samples: Vec<LivenessSample> = Vec::new();
	let start = Instant::now();
	while start.elapsed() < duration {
		if let Ok(s) = sample(client).await {
			samples.push(s);
		}
		tokio::time::sleep(tick).await;
	}

	if samples.is_empty() {
		anyhow::bail!("no samples taken in observation window");
	}
	let first = &samples[0];
	let last = &samples[samples.len() - 1];
	let elapsed_secs = last.at.duration_since(first.at).as_secs_f64().max(0.001);
	let blocks_added = last.best_number.saturating_sub(first.best_number);
	let finalized_added = last.finalized_number.saturating_sub(first.finalized_number);

	Ok(WindowStats {
		samples_taken: samples.len(),
		blocks_added,
		finalized_added,
		blocks_per_minute: (blocks_added as f64) * 60.0 / elapsed_secs,
		finalization_gap_at_end: last.best_number.saturating_sub(last.finalized_number),
		peers_at_end: last.peers,
		first_best: first.best_number,
		last_best: last.best_number,
		first_finalized: first.finalized_number,
		last_finalized: last.finalized_number,
	})
}

#[derive(Debug)]
pub struct WindowStats {
	pub samples_taken: usize,
	pub blocks_added: u64,
	pub finalized_added: u64,
	pub blocks_per_minute: f64,
	pub finalization_gap_at_end: u64,
	pub peers_at_end: u64,
	pub first_best: u64,
	pub last_best: u64,
	pub first_finalized: u64,
	pub last_finalized: u64,
}

impl std::fmt::Display for WindowStats {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"samples={}, best #{}→#{} (+{}), finalized #{}→#{} (+{}), peers={}, gap={}, blocks/min={:.1}",
			self.samples_taken,
			self.first_best,
			self.last_best,
			self.blocks_added,
			self.first_finalized,
			self.last_finalized,
			self.finalized_added,
			self.peers_at_end,
			self.finalization_gap_at_end,
			self.blocks_per_minute,
		)
	}
}
