// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! chat-spend-witness — node-side guard-set read + committee selection.
//!
//! Reads the enrolled guard set from RNS (`PnsStorageApi::guard_set`) at the
//! finalized head and selects the witnessed-spend committee over it via the pure
//! [`committee`] function. The guard set is current RNS membership, NOT an
//! epoch-locked snapshot: verifier and recorders agree because they read the same
//! finalized state, and the set changes only via RNS enrol/expire (slow,
//! consensus-agreed). Guard churn (connect/disconnect) is liveness, absorbed by
//! the `t`-of-`k` collection, and never affects membership.
//!
//! The committee math lives in `rostro-chat-membership-auth` (Apache, fully
//! tested without a runtime client). This module is the thin runtime-API glue.

use std::sync::Arc;

use gemini_runtime::{opaque::Block, AccountId, Balance};
use rns_runtime_api::PnsStorageApi;
use rostro_chat_membership_auth::spend::{committee, NodeId};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use zk_pki_primitives::runtime_api::ZkPkiApi;

/// Read the enrolled guard set (RNS `NODE` records) at block `at`.
pub fn fetch_guard_set<Client>(
	client: &Arc<Client>,
	at: <Block as BlockT>::Hash,
) -> Result<Vec<NodeId>, String>
where
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: PnsStorageApi<Block, u64, Balance, AccountId>,
{
	let keys = client
		.runtime_api()
		.guard_set(at)
		.map_err(|e| format!("PnsStorageApi::guard_set runtime call: {e:?}"))?;
	Ok(keys.into_iter().map(|k| k.to_vec()).collect())
}

/// The current membership epoch and the block to read the guard set at: the
/// finalized head. Reading at the finalized head, rather than the epoch-start
/// block (up to a full epoch old and pruned on non-archive nodes), keeps the
/// guard set always available. The set may drift within an epoch as guards
/// enrol/leave, but the verifier and recorders agree as long as both have
/// finalised the same head, which holds outside brief finality lag.
pub fn epoch_and_head<Client>(
	client: &Arc<Client>,
) -> Result<(u64, <Block as BlockT>::Hash), String>
where
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: ZkPkiApi<Block, AccountId>,
{
	let info = client.info();
	let epoch = client
		.runtime_api()
		.membership_epoch(info.best_hash)
		.map_err(|e| format!("ZkPkiApi::membership_epoch runtime call: {e:?}"))? as u64;
	Ok((epoch, info.finalized_hash))
}

/// Select the witnessed-spend committee for `nullifier` over the current guard set
/// (read at the finalized head), excluding `verifier`. Delegates to the pure
/// [`committee`] selection, so its result matches the committee any other node
/// computes from the same finalized set.
pub fn committee_at_epoch<Client>(
	client: &Arc<Client>,
	nullifier: &[u8; 32],
	k: usize,
	verifier: &[u8],
) -> Result<Vec<NodeId>, String>
where
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: PnsStorageApi<Block, u64, Balance, AccountId> + ZkPkiApi<Block, AccountId>,
{
	let (epoch, head) = epoch_and_head(client)?;
	let set = fetch_guard_set(client, head)?;
	Ok(committee(nullifier, epoch, &set, k, verifier))
}
