// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Retired-key reaper: the destruction half of the consensus-key double
//! ratchet (docs/CONSENSUS-KEY-LIFECYCLE.md §2, docs/PQ-FINALITY.md P3).
//!
//! Forced rotation only kills classical long-range attacks if retired
//! secrets stop existing. This task makes deletion an *automatic node
//! behavior* instead of an operator chore: it polls the chain's lineage
//! records and removes the keystore file of any local GRANDPA hybrid key
//! the chain says is permanently retired.
//!
//! Safety rules, in order of importance:
//!
//! 1. **Chain-authoritative**: a key is destroyed only when
//!    [`KeyLineageApi::is_retired_grandpa_key`] says it has a permanent
//!    retirement record. A live authority-set poll cannot distinguish a
//!    queued-not-yet-active key from a retired one; the lineage record
//!    can. Destroying a queued key would brick the upcoming rotation.
//! 2. **Finalized state only**: the query runs at the *finalized* head,
//!    never the best block. Destruction is irreversible; a re-org must
//!    not be able to have opinions about it.
//! 3. **Successor must exist**: nothing is deleted unless at least one
//!    OTHER local GRANDPA key is present and NOT retired. A
//!    deadline-disabled validator keeps its (only) key — healing via
//!    fresh `set_keys` is the recovery path, and this task must never
//!    make recovery harder.
//!
//! The F3 sealing integration point is [`RetiredKeySealHook`]: when
//! TPM-sealed keystores land (KEYSTORE-AUDIT F3), advancing the sealing
//! monotonic counter happens in `before_destroy`, making regression to
//! the destroyed key physically impossible rather than merely deleted.

use std::{path::PathBuf, sync::Arc, time::Duration};

use pallet_rostro_key_lineage::KeyLineageApi;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_grandpa::KEY_TYPE as GRANDPA_KEY_TYPE;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;

/// Poll cadence. Retirement happens at most once per session (4h in
/// production, faster in lab-fast); a 60s poll destroys within a minute
/// of finalized retirement for one cheap runtime read per minute.
const REAP_POLL_SECS: u64 = 60;

/// F3 seam: invoked immediately before a retired key's file is removed.
/// The TPM-sealing integration advances its monotonic counter here so
/// the sealed blob becomes undecryptable even if the file removal is
/// somehow undone (backup, snapshot, copy).
pub trait RetiredKeySealHook: Send + Sync {
	/// `public` is the full 64-byte hybrid public key being destroyed.
	fn before_destroy(&self, public: &[u8]);
}

/// Default hook until F3 lands: destruction is file removal only, and
/// says so honestly in the log.
pub struct NoSealHook;

impl RetiredKeySealHook for NoSealHook {
	fn before_destroy(&self, public: &[u8]) {
		log::info!(
			target: "rostro-key-reaper",
			"destroying retired GRANDPA key 0x{}… (file removal only; TPM seal-counter \
			 integration is a mainnet item — KEYSTORE-AUDIT F3)",
			hex_prefix(public, 8),
		);
	}
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
	bytes.iter().take(n).map(|b| format!("{b:02x}")).collect()
}

/// The keystore file for a key, exactly as `LocalKeystore` lays it out:
/// `<path>/<hex(key_type)><hex(public)>`.
fn key_file(keystore_path: &PathBuf, public: &[u8]) -> PathBuf {
	let mut name = hex::encode(GRANDPA_KEY_TYPE.0);
	name.push_str(&hex::encode(public));
	keystore_path.join(name)
}

/// Long-lived task: destroy local GRANDPA keys the finalized chain has
/// permanently retired. `keystore_path` is `None` for in-memory
/// keystores (dev), where there is nothing on disk to destroy.
pub async fn run_retired_key_reaper<Block, C>(
	client: Arc<C>,
	keystore: KeystorePtr,
	keystore_path: Option<PathBuf>,
	hook: Arc<dyn RetiredKeySealHook>,
) where
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: KeyLineageApi<Block>,
{
	let Some(keystore_path) = keystore_path else {
		log::info!(
			target: "rostro-key-reaper",
			"in-memory keystore: retired-key reaper idle (nothing on disk to destroy)",
		);
		return;
	};

	loop {
		tokio::time::sleep(Duration::from_secs(REAP_POLL_SECS)).await;

		let locals = keystore.rostro_hybrid_public_keys(GRANDPA_KEY_TYPE);
		if locals.len() < 2 {
			// Zero keys: not a validator. One key: even if the chain
			// retired it, keep it — healing needs the operator to mint a
			// successor first (safety rule 3).
			continue;
		}

		// Rule 2: finalized head only.
		let finalized = client.info().finalized_hash;
		let api = client.runtime_api();

		let mut retired = Vec::new();
		let mut live_successors = 0usize;
		for key in &locals {
			match api.is_retired_grandpa_key(finalized, key.clone().into()) {
				Ok(true) => retired.push(key.clone()),
				Ok(false) => live_successors += 1,
				Err(e) => {
					log::warn!(
						target: "rostro-key-reaper",
						"lineage query failed at finalized head; skipping this cycle: {e:?}",
					);
					retired.clear();
					break;
				},
			}
		}

		// Rule 3: at least one non-retired local key must remain.
		if live_successors == 0 {
			continue;
		}

		for key in retired {
			let public: &[u8] = key.as_ref();
			let path = key_file(&keystore_path, public);
			if !path.exists() {
				continue;
			}
			hook.before_destroy(public);
			match std::fs::remove_file(&path) {
				Ok(()) => log::info!(
					target: "rostro-key-reaper",
					"retired GRANDPA key 0x{}… destroyed (lineage-retired at finalized head, \
					 {live_successors} live successor(s) present)",
					hex_prefix(public, 8),
				),
				Err(e) => log::warn!(
					target: "rostro-key-reaper",
					"failed to remove retired key file {}: {e}",
					path.display(),
				),
			}
		}
	}
}
