// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Sassafras adversarial test harness — Phase 4 of the Fagan inspection.
//!
//! Each subcommand exercises one or more findings from the
//! threat-landscape catalog (see commit message for table). Output
//! captures before/after metrics so reachability vs. theoretical
//! finding can be distinguished cleanly.

#![warn(missing_docs)]

mod client;
mod metrics;
mod attacks;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "rostro-sassafras-redteam", about = "Sassafras attack harness", long_about = None)]
struct Cli {
	#[command(subcommand)]
	cmd: Cmd,
}

#[derive(Debug, clap::Subcommand)]
enum Cmd {
	/// Connect + dump basic chain state to confirm reachability.
	ChainInfo {
		/// WebSocket URL of a target gemini-node (e.g. ws://127.0.0.1:9934).
		#[arg(long, default_value = "ws://127.0.0.1:9934")]
		ws: String,
	},
	/// F-6: spam `state_call SassafrasApi::slot_ticket` to force runtime
	/// `sort_segments(u32::MAX, ...)` calls — the documented free-RPC
	/// DoS vector. Measures block-production rate before / during /
	/// after.
	AttackRpcSort {
		#[arg(long, default_value = "ws://127.0.0.1:9934")]
		ws: String,
		/// Number of concurrent RPC clients pounding the node.
		#[arg(long, default_value = "8")]
		concurrency: usize,
		/// Duration of the attack in seconds.
		#[arg(long, default_value = "60")]
		duration_secs: u64,
		/// Slot range to query (slot ids 0..N each loop iteration).
		#[arg(long, default_value = "1200")]
		slot_range: u64,
	},
	/// F-25: submit a `submit_tickets` extrinsic from External source
	/// to confirm the pallet's validate_unsigned rejects it. We expect
	/// rejection — but we want evidence the gate works.
	AttackExternalTickets {
		#[arg(long, default_value = "ws://127.0.0.1:9934")]
		ws: String,
		/// Number of envelope bytes (junk; we don't bother with valid
		/// ring proofs because the validate_unsigned source check
		/// fires before any verification). Roughly a TicketEnvelope
		/// is ~800 bytes.
		#[arg(long, default_value = "800")]
		junk_bytes: usize,
	},
	/// Observe block-production cadence for a duration. Used as
	/// baseline measurement before / after attacks. Reports
	/// blocks/min, finalization gap, peer count.
	Monitor {
		#[arg(long, default_value = "ws://127.0.0.1:9934")]
		ws: String,
		#[arg(long, default_value = "60")]
		duration_secs: u64,
	},
	/// Test that `chain_subscribeNewHeads` works through the shield.
	/// Subscribes, waits for at least 2 head notifications, then exits.
	/// Reports success/failure. Used to verify wallets can still talk
	/// to the shielded node.
	SubscribeTest {
		#[arg(long, default_value = "ws://127.0.0.1:9934")]
		ws: String,
		#[arg(long, default_value = "30")]
		timeout_secs: u64,
	},
	/// F-NEW-2: bandwidth amplification via `SassafrasApi_ring_context`.
	/// Each call returns ~580KB (the KZG SRS). Single storage-read on
	/// the server, but the response is huge and unauthenticated. Sizes
	/// the outbound throughput an attacker can sustain.
	AttackBandwidthAmp {
		#[arg(long, default_value = "ws://127.0.0.1:9934")]
		ws: String,
		#[arg(long, default_value = "8")]
		concurrency: usize,
		#[arg(long, default_value = "30")]
		duration_secs: u64,
	},
	/// F-7: flood the `SassafrasApi_submit_tickets_unsigned_extrinsic`
	/// runtime API with empty + garbage payloads. Sizes whether the
	/// ring-proof verification path is reachable from outside, and
	/// confirms whether this API panics on garbage like the extrinsic
	/// submit path does.
	AttackTicketsApi {
		#[arg(long, default_value = "ws://127.0.0.1:9934")]
		ws: String,
		#[arg(long, default_value = "8")]
		concurrency: usize,
		#[arg(long, default_value = "30")]
		duration_secs: u64,
		/// "empty" = SCALE encoding of empty Vec<TicketEnvelope> (0x00).
		/// "garbage" = random-but-vec-prefixed junk that resembles N envelopes.
		#[arg(long, default_value = "empty")]
		mode: String,
	},
	/// F-25-sub: flood `author_submitExtrinsic` with random junk bytes.
	/// First-round F-25 showed that malformed bytes panic the runtime
	/// inside `TaggedTransactionQueue::validate_transaction` (wasm
	/// `unreachable` trap) instead of returning InvalidTransaction
	/// cleanly. Each panic spends real CPU running the validation
	/// runtime API. This subcommand sizes whether that panic-on-junk is
	/// a free-CPU DoS at scale: many concurrent submits, no auth, no
	/// fee, observe block-production rate before/during/after.
	FloodJunkExtrinsics {
		#[arg(long, default_value = "ws://127.0.0.1:9934")]
		ws: String,
		#[arg(long, default_value = "8")]
		concurrency: usize,
		#[arg(long, default_value = "30")]
		duration_secs: u64,
		#[arg(long, default_value = "256")]
		junk_bytes: usize,
	},
}

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
			.unwrap_or_else(|_| "info".into()))
		.init();

	let cli = Cli::parse();
	match cli.cmd {
		Cmd::ChainInfo { ws } => attacks::chain_info(&ws).await,
		Cmd::AttackRpcSort { ws, concurrency, duration_secs, slot_range } =>
			attacks::attack_rpc_sort(&ws, concurrency, duration_secs, slot_range).await,
		Cmd::AttackExternalTickets { ws, junk_bytes } =>
			attacks::attack_external_tickets(&ws, junk_bytes).await,
		Cmd::Monitor { ws, duration_secs } =>
			attacks::monitor(&ws, duration_secs).await,
		Cmd::FloodJunkExtrinsics { ws, concurrency, duration_secs, junk_bytes } =>
			attacks::flood_junk_extrinsics(&ws, concurrency, duration_secs, junk_bytes).await,
		Cmd::AttackTicketsApi { ws, concurrency, duration_secs, mode } =>
			attacks::attack_tickets_api(&ws, concurrency, duration_secs, &mode).await,
		Cmd::AttackBandwidthAmp { ws, concurrency, duration_secs } =>
			attacks::attack_bandwidth_amp(&ws, concurrency, duration_secs).await,
		Cmd::SubscribeTest { ws, timeout_secs } =>
			attacks::subscribe_test(&ws, timeout_secs).await,
	}
}
