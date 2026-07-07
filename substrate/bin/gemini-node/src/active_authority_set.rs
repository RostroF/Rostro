// SPDX-License-Identifier: Apache-2.0
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
//! hybrid ed25519+SLH-DSA keys serve the dual purpose of finality
//! signing AND validator-channel cert issuance.
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
/// block. Returns each authority's 64-byte hybrid pubkey
/// (ed25519 32 || SLH-DSA 32).
///
/// Errors from the runtime call surface as a human-readable string;
/// the caller decides whether to fail-stop or fall back.
pub fn fetch_active_authorities<Block, Client>(
	client: &Arc<Client>,
) -> Result<Vec<[u8; 64]>, String>
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
/// `pubkey` is the candidate peer's claimed hybrid session pubkey;
/// the handshake verifies a signed challenge against this key
/// AFTER membership is confirmed.
pub fn is_active_authority<Block, Client>(
	client: &Arc<Client>,
	pubkey: &[u8; 64],
) -> Result<bool, String>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: GrandpaApi<Block>,
{
	let set = fetch_active_authorities(client)?;
	Ok(set.iter().any(|k| k == pubkey))
}

/// Convert a GRANDPA `AuthorityId` (hybrid newtype) to its raw
/// 64-byte representation (ed25519 component || SLH-DSA component).
///
/// ALL 64 bytes must be copied: the P2 hybrid cutover briefly kept the
/// 32-byte-era copy loop here, which zero-padded the SLH-DSA half and
/// made [`is_active_authority`] reject every real hybrid authority key
/// (the membership check compared zero-tailed entries against full
/// 64-byte cert ids). The tests below pin the full-width roundtrip.
fn authority_id_to_bytes(id: &AuthorityId) -> [u8; 64] {
	AsRef::<[u8]>::as_ref(id)
		.try_into()
		.expect("hybrid AuthorityId is a fixed 64-byte newtype; qed")
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_consensus_grandpa::AuthorityId;
	use sp_core::crypto::Pair;

	#[test]
	fn authority_id_to_bytes_recovers_raw_pubkey() {
		// Generate a deterministic hybrid keypair, wrap as
		// AuthorityId, verify our extraction round-trips ALL 64 bytes
		// (a zero-padded SLH-DSA half here silently kills every
		// validator-channel handshake at the membership check).
		let pair = sp_core::rostro_hybrid::Pair::from_seed(&[0xA5u8; 32]);
		let pubkey = pair.public();
		let id = AuthorityId::from(pubkey);
		let extracted = authority_id_to_bytes(&id);
		let direct: [u8; 64] = AsRef::<[u8]>::as_ref(&pubkey)
			.try_into()
			.expect("hybrid public is exactly 64 bytes");
		assert_eq!(extracted, direct);
		assert_ne!(&extracted[32..], &[0u8; 32], "SLH-DSA component must survive");
	}

	#[test]
	fn authority_id_to_bytes_distinguishes_keys() {
		let pair_a = sp_core::rostro_hybrid::Pair::from_seed(&[0x11u8; 32]);
		let pair_b = sp_core::rostro_hybrid::Pair::from_seed(&[0x22u8; 32]);
		let id_a = AuthorityId::from(pair_a.public());
		let id_b = AuthorityId::from(pair_b.public());
		assert_ne!(authority_id_to_bytes(&id_a), authority_id_to_bytes(&id_b));
	}

	#[test]
	fn authority_id_to_bytes_distinguishes_same_ed25519_different_slh() {
		// Two ids sharing an ed25519 component but differing in the
		// SLH-DSA half must NOT collapse to the same bytes — this is
		// exactly the aliasing the zero-padding bug created.
		let pair = sp_core::rostro_hybrid::Pair::from_seed(&[0x33u8; 32]);
		let real: [u8; 64] = AsRef::<[u8]>::as_ref(&pair.public())
			.try_into()
			.expect("hybrid public is exactly 64 bytes");
		let mut forged = real;
		forged[32..].copy_from_slice(&[0u8; 32]);
		let id_real = AuthorityId::from(sp_core::rostro_hybrid::Public::from_raw(real));
		let id_forged = AuthorityId::from(sp_core::rostro_hybrid::Public::from_raw(forged));
		assert_ne!(authority_id_to_bytes(&id_real), authority_id_to_bytes(&id_forged));
	}
}
