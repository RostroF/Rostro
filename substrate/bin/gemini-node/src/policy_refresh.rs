// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Substrate-side glue for Phase 6.1c: bridges the on-chain
//! `pallet-rostro-rpc-method-policy` registry to the native
//! `rostro-rpc-shield`'s in-memory [`PolicyCache`].
//!
//! Shape: thin async task. Reads `RpcMethodPolicyApi::all_policies(at)`
//! at intervals, decodes the result, converts the pallet's `MethodPolicy`
//! enum to the shield library's `MethodPolicy` (same shape, different
//! crate), and pushes the snapshot into the cache via
//! `PolicyCache::set_policies`.
//!
//! Lives in gemini-node (binary) rather than substrate/client/rpc-servers
//! to avoid pulling pallet deps into substrate's GPL tree. Substrate-side
//! code in `client/rpc-servers/src/middleware/rostro_shield.rs` exposes
//! `RostroShieldLayer::shield()` so this file can reach the cache.

use std::sync::Arc;
use std::time::Duration;

use rc_rpc_server::middleware::RostroShieldLayer;
use rc_service::SpawnTaskHandle;
use rostro_rpc_shield::statecall::MethodPolicy as ShieldPolicy;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use pallet_rostro_rpc_method_policy::{
	MethodPolicy as PalletPolicy, RpcMethodPolicyApi,
};

/// Refresh interval. Short enough that policy updates from a runtime
/// upgrade propagate to the shield within roughly a minute, long enough
/// that the runtime API call doesn't become a continuous background
/// load. Tunable via `ShieldConfig` in a future iteration.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Convert the pallet's policy enum to the shield's. Same shape, but
/// they're independent crates so a manual mapping is needed. Codec
/// indices on the pallet side are documented as load-bearing — if a
/// new variant is added there, this match will fail to compile until
/// the corresponding shield variant is added too. That's the desired
/// failure mode.
fn convert(p: PalletPolicy) -> ShieldPolicy {
	match p {
		PalletPolicy::PublicSafe => ShieldPolicy::PublicSafe,
		PalletPolicy::PublicGated => ShieldPolicy::PublicGated,
		PalletPolicy::LocalOnly => ShieldPolicy::LocalOnly,
		PalletPolicy::Deny => ShieldPolicy::Deny,
	}
}

/// Spawn the periodic refresh task. No-op if the operator didn't
/// activate the shield (`ROSTRO_RPC_SHIELD` unset). When active, the
/// task does an initial fetch immediately, then sleeps for
/// `REFRESH_INTERVAL` between refreshes.
pub fn spawn<Client, Block>(
	maybe_layer: &Option<RostroShieldLayer>,
	client: Arc<Client>,
	task_handle: &SpawnTaskHandle,
) where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: RpcMethodPolicyApi<Block>,
{
	let Some(layer) = maybe_layer else {
		// Shield is disabled — nothing to refresh.
		return;
	};
	let cache = layer.shield().policy_cache();

	task_handle.spawn(
		"shield-policy-refresh",
		Some("rostro-shield"),
		async move {
			loop {
				match fetch(&*client) {
					Ok(snapshot) => {
						let converted: Vec<(Vec<u8>, ShieldPolicy)> = snapshot
							.into_iter()
							.map(|(name, p)| (name, convert(p)))
							.collect();
						let n = converted.len();
						cache.set_policies(converted);
						log::debug!(
							target: "rostro-shield",
							"refreshed RPC method policy cache: {n} entries",
						);
					}
					Err(err) => {
						// Runtime API errors are typically transient
						// (chain not yet synced, brief storage glitch).
						// Don't crash; the cache keeps its last-good
						// snapshot, or falls back to the hard-coded
						// allowlist if it has never bootstrapped.
						log::warn!(
							target: "rostro-shield",
							"RPC method policy refresh failed: {err}; \
							 cache unchanged, will retry in {:?}",
							REFRESH_INTERVAL,
						);
					}
				}
				tokio::time::sleep(REFRESH_INTERVAL).await;
			}
		},
	);
}

/// Single fetch of the policy table. Synchronous runtime API call;
/// returns the pallet's encoding of the snapshot.
fn fetch<Client, Block>(
	client: &Client,
) -> Result<Vec<(Vec<u8>, PalletPolicy)>, String>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
	Client::Api: RpcMethodPolicyApi<Block>,
{
	let best = client.info().best_hash;
	let api = client.runtime_api();
	api.all_policies(best).map_err(|e| format!("runtime API error: {e:?}"))
}
