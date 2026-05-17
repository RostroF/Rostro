// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Chain specs for gemini.
//!
//! Two named specs at v0.1.0:
//!
//! - **`dev`**: single-authority Sassafras testbed (Alice). For
//!   single-process development.
//! - **`local`**: two-authority Sassafras testbed (Alice + Bob). The
//!   twin-node bringup target — run two `gemini-node` instances on
//!   the same machine, watch them peer, exchange the
//!   construct-dummy-ring-context-derived authority set, and finalize
//!   via GRANDPA.
//!
//! ## URS
//!
//! Genesis populates `pallet_sassafras::RingContext` with
//! `RingProofParams::from_seed(R, [0; 32])` via the
//! `construct-dummy-ring-context` feature flag on the runtime crate.
//! NOT cryptographically secure — testbed only. R3 follow-up replaces
//! with the EIP-4844-derived URS via
//! `rostro_kzg_srs::build_ring_context_bytes_for_genesis`.

use gemini_runtime::{
	AccountId, GrandpaId, SassafrasId, Signature, ROSTO, WASM_BINARY,
};
use rc_service::ChainType;
use serde_json::{json, Value};
use sp_consensus_grandpa::AuthorityId as GrandpaAuthorityId;
use sp_consensus_sassafras::EpochConfiguration;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};

/// A specialized [`ChainSpec`] for the gemini runtime.
pub type ChainSpec = rc_service::GenericChainSpec;

type AccountPublic = <Signature as Verify>::Signer;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

/// Generate an account ID from seed (Sr25519-derived). For balance/sudo;
/// validator authority keys flow through `authority_keys_from_seed`.
pub fn get_account_id_from_seed(seed: &str) -> AccountId {
	let pubkey = get_from_seed::<sr25519::Public>(seed);
	AccountPublic::from(pubkey).into_account()
}

/// Generate a Sassafras (bandersnatch) + GRANDPA (ed25519) authority
/// pair from a seed string.
pub fn authority_keys_from_seed(s: &str) -> (SassafrasId, GrandpaId) {
	(get_from_seed::<SassafrasId>(s), get_from_seed::<GrandpaAuthorityId>(s))
}

fn dev_endowed_accounts() -> Vec<AccountId> {
	["Alice", "Bob", "Charlie", "Dave", "Eve", "Ferdie"]
		.iter()
		.map(|s| get_account_id_from_seed(s))
		.collect()
}

// ─── `dev` chain spec ──────────────────────────────────────────────────────

/// Single-authority gemini for single-process development.
pub fn development_config() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "gemini wasm not available".to_string())?,
		None,
	)
	.with_name("Gemini Development")
	.with_id("gemini-dev")
	.with_chain_type(ChainType::Development)
	.with_genesis_config_patch(testnet_genesis(
		vec![authority_keys_from_seed("Alice")],
		get_account_id_from_seed("Alice"),
		dev_endowed_accounts(),
	))
	.with_properties(properties())
	.build())
}

// ─── `local` chain spec — twin lab ─────────────────────────────────────────

/// Two-authority gemini for the twin-node bringup. Run two
/// `gemini-node` instances on the same machine with this spec; pass
/// `--bootnodes` on the second to point at the first's libp2p addr.
pub fn local_config() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "gemini wasm not available".to_string())?,
		None,
	)
	.with_name("Gemini Local")
	.with_id("gemini-local")
	.with_chain_type(ChainType::Local)
	.with_genesis_config_patch(testnet_genesis(
		vec![
			authority_keys_from_seed("Alice"),
			authority_keys_from_seed("Bob"),
		],
		get_account_id_from_seed("Alice"),
		dev_endowed_accounts(),
	))
	.with_properties(properties())
	.build())
}

// ─── `star` chain spec — Phase Star 5-node bringup ────────────────────────

/// Five-authority gemini for the Phase Star milestone. Alice + Bob +
/// Charlie + Dave + Eve as Sassafras + GRANDPA validators. Used by
/// `scripts/run-star.sh` to stand up the namesake star topology:
/// Alice is the bootnode, the other four leaves dial her. All five
/// produce Sassafras blocks and finalize via GRANDPA.
pub fn star_config() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "gemini wasm not available".to_string())?,
		None,
	)
	.with_name("Gemini Star")
	.with_id("gemini-star")
	.with_chain_type(ChainType::Local)
	.with_genesis_config_patch(testnet_genesis(
		vec![
			authority_keys_from_seed("Alice"),
			authority_keys_from_seed("Bob"),
			authority_keys_from_seed("Charlie"),
			authority_keys_from_seed("Dave"),
			authority_keys_from_seed("Eve"),
		],
		get_account_id_from_seed("Alice"),
		dev_endowed_accounts(),
	))
	.with_properties(properties())
	.build())
}

fn properties() -> rc_service::Properties {
	let mut p = rc_service::Properties::new();
	p.insert("tokenSymbol".into(), "ROS".into());
	p.insert("tokenDecimals".into(), 12.into());
	p.insert("ss58Format".into(), 42.into());
	p
}

/// Read the canonical-files initialFiles vec from the
/// `ROSTRO_CANONICAL_GEMINI_NODE_HASH` env var, if set.
///
/// Lab-only convenience for `scripts/run-star.sh`. The script
/// computes the blake2_256 of the gemini-node binary, exports the
/// hex digest in this env var, and starts the star. Genesis then
/// includes a `("gemini-node", <hash>)` entry so the verifier's
/// boot check runs against a real value on every node.
///
/// Returns an empty vec when the env var is absent or malformed —
/// the genesis check then no-ops (logs "skipping"), preserving the
/// production default. Malformed values (wrong length, non-hex)
/// emit no error here because chain spec construction can't surface
/// one; operators see the env var go unused at boot when the
/// verifier logs "skipping."
fn read_initial_canonical_files() -> Vec<(Vec<u8>, [u8; 32])> {
	let Ok(hex) = std::env::var("ROSTRO_CANONICAL_GEMINI_NODE_HASH") else {
		return Vec::new();
	};
	let trimmed = hex.trim_start_matches("0x");
	if trimmed.len() != 64 {
		return Vec::new();
	}
	let mut bytes = [0u8; 32];
	for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
		let s = std::str::from_utf8(chunk).ok().unwrap_or("");
		let b = u8::from_str_radix(s, 16).ok().unwrap_or(0xFF);
		bytes[i] = b;
	}
	vec![(b"gemini-node".to_vec(), bytes)]
}

/// Genesis storage patch.
///
/// `pallet_sassafras::GenesisConfig` only carries authorities +
/// epoch_config. The ring context (URS) gets populated by the
/// `construct-dummy-ring-context` feature gate at genesis-build time
/// — so we don't pass URS bytes here in v1.
fn testnet_genesis(
	initial_authorities: Vec<(SassafrasId, GrandpaId)>,
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
) -> Value {
	const ENDOWMENT: u128 = 1_000_000 * ROSTO;

	json!({
		"balances": {
			"balances": endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, ENDOWMENT))
				.collect::<Vec<_>>(),
		},
		"sassafras": {
			"authorities": initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
			"epochConfig": EpochConfiguration {
				redundancy_factor: 2,
				attempts_number: 32,
			},
		},
		"grandpa": {
			"authorities": initial_authorities
				.iter()
				.map(|x| (x.1.clone(), 1u64))
				.collect::<Vec<_>>(),
		},
		"sudo": {
			"key": Some(root_key),
		},
		// Phase 7a smoke / dev convenience: empty initial canonical-files
		// set BY DEFAULT. The verifier finds no entry for "gemini-node",
		// logs "skipping", and continues. The foundation populates real
		// hashes post-genesis via SRT extrinsic.
		//
		// Lab override: the `ROSTRO_CANONICAL_GEMINI_NODE_HASH` env var
		// (32-byte hex, 64 chars) seeds the gemini-node binary's
		// canonical hash at genesis. Set by `scripts/run-star.sh` so
		// the 5-node star boots with a real check active. Production
		// chain specs leave this unset; SRT publishes post-genesis.
		"canonicalFiles": {
			"initialFiles": read_initial_canonical_files(),
		},
		// RNS reserved-list seed. SEED_RESERVED is the curated list
		// from `pallet-rns-registrar/src/genesis_reserved.rs` —
		// network family labels, DNS infra, RFC 2142 mailboxes,
		// operational subdomains. Each label gets hashed against the
		// runtime's BaseNode at genesis-build time and inserted into
		// `ReservedList`. SRT can extend or shrink post-genesis via
		// `add_reserved` / `remove_reserved` extrinsics.
		"rnsRegistrar": {
			"reservedNames": pallet_rns_registrar::genesis_reserved::SEED_RESERVED
				.iter()
				.map(|l| l.to_vec())
				.collect::<Vec<Vec<u8>>>(),
		},
	})
}
