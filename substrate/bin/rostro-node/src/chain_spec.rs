// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Chain specifications for Rostro.

use rc_service::ChainType;
use rns_types::{Record, RST_BASENODE};
use rostro_runtime::{AccountId, AuraId, GrandpaId, Signature, ROSTO, WASM_BINARY};
use sp_consensus_grandpa::AuthorityId as GrandpaAuthorityId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};
use serde_json::{json, Value};

/// A specialized [`ChainSpec`] for the Rostro solochain runtime.
pub type ChainSpec = rc_service::GenericChainSpec;

type AccountPublic = <Signature as Verify>::Signer;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaAuthorityId>(s))
}

/// Build the development chain spec.
///
/// Pre-funds Alice/Bob/Charlie/Dave/Eve/Ferdie with 1M ROS, names Alice as
/// sudo + initial Aura authority + initial GRANDPA authority. Single-block
/// finality for fast dev iteration.
pub fn development_config() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
		None,
	)
	.with_name("Rostro Development")
	.with_id("rostro-dev")
	.with_chain_type(ChainType::Development)
	.with_genesis_config_patch(testnet_genesis(
		// Initial PoA authorities
		vec![authority_keys_from_seed("Alice")],
		// Sudo
		get_account_id_from_seed::<sr25519::Public>("Alice"),
		// Pre-funded
		vec![
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			get_account_id_from_seed::<sr25519::Public>("Bob"),
			get_account_id_from_seed::<sr25519::Public>("Charlie"),
			get_account_id_from_seed::<sr25519::Public>("Dave"),
			get_account_id_from_seed::<sr25519::Public>("Eve"),
			get_account_id_from_seed::<sr25519::Public>("Ferdie"),
		],
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

/// Configure initial storage state for FRAME modules — returned as a JSON
/// patch over the runtime's default `GenesisConfig`.
fn testnet_genesis(
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
) -> Value {
	const ENDOWMENT: u128 = 1_000_000 * ROSTO;

	// RNS pricing: registration fee per label length (1..=10+ chars, length 11 = "10 or more")
	let base_prices: [u128; 11] = [
		1000 * ROSTO, // 1 char
		100 * ROSTO,  // 2 chars
		45 * ROSTO,   // 3 chars
		25 * ROSTO,   // 4 chars
		10 * ROSTO,   // 5 chars
		ROSTO / 2,    // 6 chars
		ROSTO / 2,    // 7 chars
		ROSTO / 2,    // 8 chars
		ROSTO / 2,    // 9 chars
		ROSTO / 2,    // 10 chars
		ROSTO / 2,    // 11+ chars
	];

	// Seed reserved labels — vendored from pallet_rns_registrar::genesis_reserved::SEED_RESERVED.
	// Inlined here as a JSON-serializable Vec<Vec<u8>> rather than imported, since the
	// runtime crate isn't a chain-spec dep target. Sync with that file pre-mainnet.
	let reserved_labels: Vec<Vec<u8>> = pallet_rns_registrar::genesis_reserved::SEED_RESERVED
		.iter()
		.map(|s| s.to_vec())
		.collect();

	json!({
		"balances": {
			"balances": endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, ENDOWMENT))
				.collect::<Vec<_>>(),
		},
		"aura": {
			"authorities": initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
		},
		"grandpa": {
			"authorities": initial_authorities
				.iter()
				.map(|x| (x.1.clone(), 1u64))
				.collect::<Vec<_>>(),
		},
		"sudo": {
			"key": Some(root_key.clone()),
		},

		// ─── RNS genesis ────────────────────────────────────────────────────
		// Mint the basenode NFT (class 0) to root. This anchors the entire
		// `.rst` namespace under root's ownership at chain birth.
		"rnsNft": {
			"tokens": vec![(
				root_key.clone(),
				Vec::<u8>::new(),
				(),
				vec![(
					root_key.clone(),
					Vec::<u8>::new(),
					Record::default(),
					RST_BASENODE,
				)],
			)],
		},
		"rnsPriceOracle": {
			"basePrices": base_prices,
			"rentPrices": base_prices,
			"initRate": ROSTO,
		},
		"rnsRegistrar": {
			"infos": Vec::<(rns_types::DomainHash, ())>::new(),
			"reservedList": Vec::<rns_types::DomainHash>::new(),
			"reservedNames": reserved_labels,
		},
		"rnsRegistry": {
			"origin": Vec::<(rns_types::DomainHash, rns_types::DomainTracing)>::new(),
			"official": Some(root_key),
		},
	})
}
