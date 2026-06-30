// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! chat-spend-witness Phase 2b — node-side guard-set read + committee selection.
//!
//! Reads the enrolled guard set from RNS (`PnsStorageApi::guard_set`) at the
//! membership-epoch anchor block and selects the witnessed-spend committee over
//! it via the pure [`committee`] function. Reading at the epoch anchor (the block
//! at the start of the current membership epoch) gives every node the same
//! per-epoch snapshot, so verifier and recorders agree on the committee for a
//! given nullifier.
//!
//! The committee math lives in `rostro-chat-membership-auth` (Apache, fully
//! tested without a runtime client). This module is the thin runtime-API glue;
//! the verifier/recorder protocol that calls it lands in Phase 4.

use std::sync::Arc;

use gemini_runtime::{opaque::Block, AccountId, Balance};
use rns_runtime_api::PnsStorageApi;
use rostro_chat_membership_auth::spend::{committee, NodeId};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::{Block as BlockT, UniqueSaturatedInto};
use zk_pki_primitives::runtime_api::ZkPkiApi;

/// Membership-epoch length in blocks. MUST match zkpki's `EPOCH_LENGTH_BLOCKS`
/// (the runtime computes `current_epoch = block_number / EPOCH_LENGTH_BLOCKS`).
/// Held node-side so the guard set is read at the same epoch-start block on every
/// node. Trust-but-verify: this mirrors an on-chain constant and should be
/// reconciled against the runtime; a drift would desync committees, not corrupt
/// state.
const MEMBERSHIP_EPOCH_LENGTH_BLOCKS: u64 = 14_400;

/// Read the enrolled guard set (RNS `NODE` records) at block `at`.
#[allow(dead_code)] // wired into the verifier/recorder path in Phase 4
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

/// The current membership epoch and the hash of its anchor block (the block at
/// height `epoch * EPOCH_LENGTH_BLOCKS`). Falls back to the best hash if that
/// height is not yet resolvable (early chain), which only matters before the
/// first epoch boundary.
#[allow(dead_code)] // wired into the verifier/recorder path in Phase 4
pub fn epoch_anchor<Client>(
	client: &Arc<Client>,
) -> Result<(u64, <Block as BlockT>::Hash), String>
where
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: ZkPkiApi<Block, AccountId>,
{
	let best = client.info().best_hash;
	let epoch = client
		.runtime_api()
		.membership_epoch(best)
		.map_err(|e| format!("ZkPkiApi::membership_epoch runtime call: {e:?}"))? as u64;
	let anchor_height = epoch.saturating_mul(MEMBERSHIP_EPOCH_LENGTH_BLOCKS);
	let number = anchor_height.unique_saturated_into();
	let hash = client
		.hash(number)
		.map_err(|e| format!("anchor block hash lookup: {e:?}"))?
		.unwrap_or(best);
	Ok((epoch, hash))
}

/// Select the witnessed-spend committee for `nullifier` over the guard set at the
/// current epoch anchor, excluding `verifier`. This is the node entry point; it
/// delegates to the pure [`committee`] selection, so its result matches the
/// committee any other node computes from the same epoch-anchored set.
#[allow(dead_code)] // wired into the verifier/recorder path in Phase 4
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
	let (epoch, at) = epoch_anchor(client)?;
	let set = fetch_guard_set(client, at)?;
	Ok(committee(nullifier, epoch, &set, k, verifier))
}
