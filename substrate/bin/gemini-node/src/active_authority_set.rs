// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase Z2 — active-validator-set lookup helper.
//!
//! Wraps the `GrandpaApi::grandpa_authorities()` runtime call so the
//! validator-channel handshake (Phase Z3) and the GRANDPA router
//! shim (Phase Z4) can answer "is this peer's session-signing
//! pubkey in the current active validator set?"
//!
//! The active set in v0 is the GRANDPA authority set. Sassafras has
//! its own authorities list (bandersnatch keys for slot VRF) but
//! those aren't appropriate for general session-signing; GRANDPA's
//! Ed25519 keys serve the dual purpose of finality signing AND
//! validator-channel handshake authentication.
//!
//! ## Why no caching in v0
//!
//! Authority sets change only at era boundaries (every several
//! hundred blocks). The runtime call is cheap — single state read.
//! Caching would help under high churn but adds invalidation
//! complexity; defer until profiling shows the call is a hotspot.

use std::sync::Arc;

use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_grandpa::{AuthorityId, GrandpaApi};
use sp_runtime::traits::Block as BlockT;

/// Fetch the current GRANDPA authority pubkeys at the latest known
/// block. Returns each authority's 32-byte Ed25519 pubkey.
///
/// Errors from the runtime call surface as a human-readable string;
/// the caller decides whether to fail-stop or fall back.
pub fn fetch_active_authorities<Block, Client>(
	client: &Arc<Client>,
) -> Result<Vec<[u8; 32]>, String>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: GrandpaApi<Block>,
{
	let best = client.info().best_hash;
	let list = client
		.runtime_api()
		.grandpa_authorities(best)
		.map_err(|e| format!("GrandpaApi::grandpa_authorities runtime call: {e:?}"))?;
	Ok(list.into_iter().map(|(id, _weight)| authority_id_to_bytes(&id)).collect())
}

/// Convenience predicate: is `pubkey` in the current active set?
/// `pubkey` is the candidate peer's claimed Ed25519 session pubkey;
/// the handshake verifies a signed challenge against this key
/// AFTER membership is confirmed.
pub fn is_active_authority<Block, Client>(
	client: &Arc<Client>,
	pubkey: &[u8; 32],
) -> Result<bool, String>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: GrandpaApi<Block>,
{
	let set = fetch_active_authorities(client)?;
	Ok(set.iter().any(|k| k == pubkey))
}

/// Convert a GRANDPA `AuthorityId` (Ed25519 newtype) to its raw
/// 32-byte representation. The conversion is direct — Ed25519 keys
/// are 32 bytes wide and the newtype is `#[repr(transparent)]`-ish.
fn authority_id_to_bytes(id: &AuthorityId) -> [u8; 32] {
	let raw = AsRef::<[u8]>::as_ref(id);
	debug_assert_eq!(
		raw.len(),
		32,
		"Ed25519 AuthorityId must be 32 bytes; got {}",
		raw.len(),
	);
	let mut out = [0u8; 32];
	let n = core::cmp::min(raw.len(), 32);
	out[..n].copy_from_slice(&raw[..n]);
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_consensus_grandpa::AuthorityId;
	use sp_core::crypto::Pair;

	#[test]
	fn authority_id_to_bytes_recovers_raw_pubkey() {
		// Generate a deterministic Ed25519 keypair, wrap as
		// AuthorityId, verify our extraction round-trips.
		let pair = sp_core::ed25519::Pair::from_seed(&[0xA5u8; 32]);
		let pubkey = pair.public();
		let id = AuthorityId::from(pubkey);
		let extracted = authority_id_to_bytes(&id);
		let direct: [u8; 32] = AsRef::<[u8]>::as_ref(&pubkey)
			.try_into()
			.expect("Ed25519 public is exactly 32 bytes");
		assert_eq!(extracted, direct);
	}

	#[test]
	fn authority_id_to_bytes_distinguishes_keys() {
		let pair_a = sp_core::ed25519::Pair::from_seed(&[0x11u8; 32]);
		let pair_b = sp_core::ed25519::Pair::from_seed(&[0x22u8; 32]);
		let id_a = AuthorityId::from(pair_a.public());
		let id_b = AuthorityId::from(pair_b.public());
		assert_ne!(authority_id_to_bytes(&id_a), authority_id_to_bytes(&id_b));
	}
}
