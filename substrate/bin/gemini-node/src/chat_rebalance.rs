// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Weekly bucket-subscription rebalance.
//!
//! Operators decide *how many* buckets a node should carry
//! (capacity, via the `CHAT_BUCKET_TARGET_COUNT` env var); the
//! network decides *which* buckets via the presence-aggregated
//! [`crate::chat_bucket_cache::BucketCache`]. This module runs the
//! actual rebalance event:
//!
//! 1. Periodic tick (every 60 s) checks: "is it past my
//!    deterministic rebalance time for this ISO week, and did I
//!    not already rebalance this week?"
//! 2. When the answer is yes, reads the cache's full distribution
//!    and computes the target bitmap via
//!    [`rostro_chat_primitives::bucket::compute_target_subscription`].
//! 3. Drops local-store entries for departing buckets — those
//!    other bucket peers (or anti-entropy) own now.
//! 4. Updates [`LocalSubscriptionState`] (bumps version) and
//!    signals the chat-gossip task to re-advertise.
//!
//! ## Per-node deterministic random timing
//!
//! [`compute_rebalance_time`] derives a per-(node_pubkey, week)
//! offset within the Tuesday 06:00-18:00 UTC window. Different
//! nodes rebalance at different minutes within the window; no
//! coordination required; an attacker can compute one node's
//! rebalance time but can't synchronize the network.
//!
//! ## v0.1 default is a no-op
//!
//! When `target_count >= BUCKET_COUNT`, the periodic task short-
//! circuits — no rebalance to do. Default for v0.1 demo / early
//! network. Operators dialing capacity down (mainnet-scale) are
//! the only ones who'll see the rebalance machinery run.
//!
//! ## Force-now test mode
//!
//! `CHAT_REBALANCE_AT_STARTUP=1` triggers a single rebalance
//! immediately after the initial gossip-settle window. Useful
//! for scenario tests that can't wait for Tuesday UTC; never set
//! in production. The normal weekly schedule resumes after.

use std::sync::Arc;
use std::time::Duration;

use rostro_chat_primitives::bucket::{
	compute_rebalance_time, compute_target_subscription, current_rebalance_week,
	BucketBitmap, BUCKET_COUNT,
};
use rostro_chat_primitives::store_protocol::ShareStore;
use tokio::sync::mpsc;

use crate::chat_bucket_cache::BucketCache;
use crate::chat_gossip_protocol::LocalSubscriptionState;

/// How often the periodic task checks "is it time to rebalance?"
/// 60 seconds — cheap, no I/O on most ticks, ~720 checks per day.
/// The actual rebalance event fires at most once per ISO week per
/// node, so the tick interval is just resolution on the trigger
/// instant.
pub const REBALANCE_TICK_INTERVAL_SECS: u64 = 60;

/// Window after task startup before the first force-now rebalance
/// (if `CHAT_REBALANCE_AT_STARTUP` is set). Lets the gossip layer
/// populate the bucket cache before we read the distribution from
/// it — otherwise we'd compute against an empty cache and pick
/// purely-hash-tie-broken buckets, missing the network-driven
/// balance.
pub const FORCE_NOW_SETTLE_SECS: u64 = 15;

/// Outcome of one rebalance attempt — used by the periodic task
/// to log + by tests to verify behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebalanceOutcome {
	/// `target_count >= BUCKET_COUNT` — nothing to do.
	NoOpDefault,
	/// Already ran this ISO week for this node.
	AlreadyDoneThisWeek,
	/// Not yet at this node's rebalance instant for the current
	/// week.
	NotYetTime,
	/// Bucket cache was empty — no peer distribution to read. The
	/// first node in a new network sees this until peers arrive.
	NoCacheYet,
	/// Computed bitmap matches the current one — no change needed.
	BitmapUnchanged,
	/// Rebalance fired: updated bitmap, dropped `dropped` entries
	/// from departing buckets. `departing` and `arriving` count
	/// the bucket-set changes for logging.
	Applied { departing: u32, arriving: u32, dropped: usize },
}

/// Pure single-shot rebalance evaluation. Decides what action (if
/// any) to take for the given inputs, performs the in-store drop
/// + state update if the action is `Applied`, and returns the
/// outcome.
///
/// Separated from the timing loop so it's unit-testable + the
/// force-now path can reuse it.
pub fn try_rebalance<S>(
	local_state: &LocalSubscriptionState,
	bucket_cache: &BucketCache,
	store: &Arc<S>,
	target_count: u16,
) -> RebalanceOutcome
where
	S: ShareStore + Send + Sync + 'static,
{
	if target_count >= BUCKET_COUNT {
		return RebalanceOutcome::NoOpDefault;
	}

	let distribution = bucket_cache.full_distribution();
	let total_subscribers: usize = distribution.iter().sum();
	if total_subscribers == 0 {
		return RebalanceOutcome::NoCacheYet;
	}

	let new_bitmap = compute_target_subscription(
		&distribution,
		target_count,
		&local_state.node_pubkey(),
	);
	let old_bitmap = local_state.current_bitmap();
	if new_bitmap == old_bitmap {
		return RebalanceOutcome::BitmapUnchanged;
	}

	// Compute departing / arriving for the in-store drop and logs.
	let departing: Vec<u8> = old_bitmap
		.iter_set()
		.filter(|b| !new_bitmap.contains(*b))
		.collect();
	let arriving_count: u32 = new_bitmap
		.iter_set()
		.filter(|b| !old_bitmap.contains(*b))
		.count() as u32;
	let dropped = store.drop_entries_in_buckets(&departing);

	local_state.set_bitmap(new_bitmap);

	RebalanceOutcome::Applied {
		departing: departing.len() as u32,
		arriving: arriving_count,
		dropped,
	}
}

/// Read `CHAT_BUCKET_TARGET_COUNT` from the environment. Returns
/// `BUCKET_COUNT` (no-op) if unset or unparseable. Out-of-range
/// values clamp to `[0, BUCKET_COUNT]`. Logs a warning on parse
/// failure.
pub fn read_target_count_from_env() -> u16 {
	match std::env::var("CHAT_BUCKET_TARGET_COUNT") {
		Ok(s) => match s.parse::<u16>() {
			Ok(n) => n.min(BUCKET_COUNT),
			Err(e) => {
				log::warn!(
					target: "rostro-chat-rebalance",
					"CHAT_BUCKET_TARGET_COUNT={s:?} unparseable: {e}; defaulting to {}",
					BUCKET_COUNT,
				);
				BUCKET_COUNT
			}
		},
		Err(_) => BUCKET_COUNT,
	}
}

/// Local-clock helper.
fn now_unix_seconds() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Periodic rebalance task. Run forever; spawn on the task
/// manager. Sends `()` on `signal_tx` after a successful
/// `RebalanceOutcome::Applied` so the chat-gossip task knows to
/// re-advertise.
pub async fn run_rebalance_task<S>(
	local_state: LocalSubscriptionState,
	bucket_cache: BucketCache,
	store: Arc<S>,
	target_count: u16,
	signal_tx: mpsc::UnboundedSender<()>,
) where
	S: ShareStore + Send + Sync + 'static,
{
	if target_count >= BUCKET_COUNT {
		log::info!(
			target: "rostro-chat-rebalance",
			"target_count={target_count} >= BUCKET_COUNT={BUCKET_COUNT}; \
			 rebalance task starting in no-op mode",
		);
	} else {
		log::info!(
			target: "rostro-chat-rebalance",
			"rebalance task starting; target_count={target_count}, \
			 tick={REBALANCE_TICK_INTERVAL_SECS}s",
		);
	}

	let force_now = std::env::var("CHAT_REBALANCE_AT_STARTUP")
		.map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
		.unwrap_or(false);
	if force_now {
		log::info!(
			target: "rostro-chat-rebalance",
			"CHAT_REBALANCE_AT_STARTUP set — will force rebalance after \
			 {FORCE_NOW_SETTLE_SECS}s settle",
		);
		tokio::time::sleep(Duration::from_secs(FORCE_NOW_SETTLE_SECS)).await;
		let outcome = try_rebalance(&local_state, &bucket_cache, &store, target_count);
		log::info!(
			target: "rostro-chat-rebalance",
			"force-now rebalance outcome: {:?}",
			outcome,
		);
		if matches!(outcome, RebalanceOutcome::Applied { .. }) {
			let _ = signal_tx.send(());
		}
	}

	let mut ticker = tokio::time::interval(Duration::from_secs(REBALANCE_TICK_INTERVAL_SECS));
	ticker.tick().await; // immediate first tick — skip
	let mut last_rebalanced_week: Option<u32> = None;

	loop {
		ticker.tick().await;

		if target_count >= BUCKET_COUNT {
			continue;
		}

		let now = now_unix_seconds();
		let week = current_rebalance_week(now);

		if last_rebalanced_week == Some(week) {
			continue;
		}

		let rebalance_at = compute_rebalance_time(&local_state.node_pubkey(), week);
		if now < rebalance_at {
			continue;
		}

		let outcome = try_rebalance(&local_state, &bucket_cache, &store, target_count);
		log::info!(
			target: "rostro-chat-rebalance",
			"weekly rebalance outcome for week {week}: {:?}",
			outcome,
		);

		// Always mark the week as done, even on no-op outcomes,
		// so we don't re-check on every tick for the rest of the
		// week. NotYetTime can't reach here because we gated on
		// `now < rebalance_at` above.
		last_rebalanced_week = Some(week);

		if matches!(outcome, RebalanceOutcome::Applied { .. }) {
			let _ = signal_tx.send(());
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn read_env_unset_returns_default() {
		// Clear any local override before reading.
		std::env::remove_var("CHAT_BUCKET_TARGET_COUNT");
		assert_eq!(read_target_count_from_env(), BUCKET_COUNT);
	}

	#[test]
	fn read_env_valid_value_returned() {
		std::env::set_var("CHAT_BUCKET_TARGET_COUNT", "32");
		assert_eq!(read_target_count_from_env(), 32);
		std::env::remove_var("CHAT_BUCKET_TARGET_COUNT");
	}

	#[test]
	fn read_env_clamps_above_bucket_count() {
		std::env::set_var("CHAT_BUCKET_TARGET_COUNT", "5000");
		assert_eq!(read_target_count_from_env(), BUCKET_COUNT);
		std::env::remove_var("CHAT_BUCKET_TARGET_COUNT");
	}

	#[test]
	fn read_env_unparseable_falls_back_to_default() {
		std::env::set_var("CHAT_BUCKET_TARGET_COUNT", "not-a-number");
		assert_eq!(read_target_count_from_env(), BUCKET_COUNT);
		std::env::remove_var("CHAT_BUCKET_TARGET_COUNT");
	}

	#[test]
	fn rebalance_outcome_variants_have_distinct_debug() {
		// Sanity: outcome printing in production logs needs to be
		// distinguishable across variants.
		let a = format!("{:?}", RebalanceOutcome::NoOpDefault);
		let b = format!("{:?}", RebalanceOutcome::AlreadyDoneThisWeek);
		let c = format!("{:?}", RebalanceOutcome::NoCacheYet);
		let d = format!("{:?}", RebalanceOutcome::BitmapUnchanged);
		let e = format!(
			"{:?}",
			RebalanceOutcome::Applied { departing: 5, arriving: 5, dropped: 12 },
		);
		assert_ne!(a, b);
		assert_ne!(b, c);
		assert_ne!(c, d);
		assert_ne!(d, e);
	}
}
