// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Chain specifications for Rostro.
//!
//! Three named specs at v0.1.0 (Phase Gemini):
//!
//! - **`dev`** (alias `rostro-dev`): single Aura authority (Alice). Single-
//!   node local development, fast iteration. Sudo = Alice.
//! - **`gemini`**: two Aura authorities (Alice + Bob). The twin lab — verify
//!   multi-node peering / authority rotation / GRANDPA finalization on a
//!   single laptop before deploying to disposable cloud instances.
//! - **`rostro`**: three Aura authorities (Alice + Bob + Charlie) plus a
//!   DNS-form bootnode multiaddr placeholder for `bootnode.rostro.org`. The
//!   production-ish template; finalize the bootnode peer-id and authority
//!   keys before mainnet.
//!
//! ## Network security posture (v0.1.0)
//!
//! - **Transport cipher**: ChaCha20-Poly1305. `libp2p-noise` (v0.46) hardcodes
//!   `Noise_XX_25519_ChaChaPoly_SHA256` as its only handshake protocol — AES-GCM
//!   was dropped upstream, so no configuration knob is required. Verified at
//!   `~/.cargo/registry/src/.../libp2p-noise-0.46.x/src/protocol.rs` line 37.
//! - **Forward secrecy**: per-session via Noise XX's X25519 ephemeral DH.
//!   Compromising a node's static long-term key does not retroactively
//!   compromise past sessions; each connection derives a fresh shared secret.
//! - **Per-message FS at the gossip layer (Signal Double Ratchet)**: explicitly
//!   deferred to v0.2.0. v0.1.0 ships per-session forward secrecy only.
//!   See `~/.claude/projects/-home-coder-Rostro/memory/phase_gemini.md`.

use rc_service::ChainType;
use rns_types::{Record, RST_BASENODE};
use rostro_runtime::{AccountId, AuraId, GrandpaId, Signature, ROSTO, WASM_BINARY};
use sp_consensus_grandpa::AuthorityId as GrandpaAuthorityId;
use sp_core::{ed25519, sr25519, Pair, Public};
use sp_runtime::{traits::{IdentifyAccount, Verify}, MultiSigner};
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

/// Derive a Rostro-style AccountId from a seed: `blake2_256(ed25519_pubkey)`.
/// This routes through `MultiSigner::RostroEd25519`, which is the runtime's
/// canonical extrinsic-signing scheme. AccountId is decoupled from the
/// public key so signature schemes can migrate (e.g. to Falcon) later
/// without changing user-facing addresses.
pub fn rostro_account_from_seed(seed: &str) -> AccountId {
	let pubkey = get_from_seed::<ed25519::Public>(seed);
	MultiSigner::RostroEd25519(pubkey).into_account()
}

/// Generate an Aura+GRANDPA authority key pair from a seed string.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaAuthorityId>(s))
}

/// Standard pre-funded set used across local specs (dev/gemini): the six
/// well-known Substrate dev seeds, with Rostro's hash-based AccountId
/// derivation.
fn dev_endowed_accounts() -> Vec<AccountId> {
	["Alice", "Bob", "Charlie", "Dave", "Eve", "Ferdie"]
		.iter()
		.map(|s| rostro_account_from_seed(s))
		.collect()
}

// ─── `dev` chain spec ──────────────────────────────────────────────────────

/// Build the development chain spec — single authority (Alice), single-node.
pub fn development_config() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
		None,
	)
	.with_name("Rostro Development")
	.with_id("rostro-dev")
	.with_chain_type(ChainType::Development)
	.with_genesis_config_patch(testnet_genesis(
		vec![authority_keys_from_seed("Alice")],
		rostro_account_from_seed("Alice"),
		dev_endowed_accounts(),
	))
	.with_properties(properties())
	.build())
}

// ─── `gemini` chain spec — twin lab ────────────────────────────────────────

/// Build the Gemini chain spec — two authorities (Alice + Bob) for the twin
/// lab. Run two `rostro-node` processes on the same machine with this spec
/// and watch them peer, rotate authority, and finalize via GRANDPA.
///
/// Bootnodes are intentionally empty here; pass `--bootnodes` on the second
/// node's CLI pointing at the first node's libp2p address.
pub fn gemini_config() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Gemini wasm not available".to_string())?,
		None,
	)
	.with_name("Rostro Gemini")
	.with_id("rostro-gemini")
	.with_chain_type(ChainType::Local)
	.with_genesis_config_patch(testnet_genesis(
		vec![authority_keys_from_seed("Alice"), authority_keys_from_seed("Bob")],
		rostro_account_from_seed("Alice"),
		dev_endowed_accounts(),
	))
	.with_properties(properties())
	.build())
}

// ─── `rostro` chain spec — production-ish template ─────────────────────────

/// Build the Rostro chain spec — production-ish template with three
/// authorities (Alice + Bob + Charlie at v0.1.0) and a DNS-form bootnode
/// multiaddr.
///
/// **Pre-mainnet TODO**:
/// - Replace dev seeds with real authority keys (Aura Sr25519 + GRANDPA Ed25519).
/// - Generate a stable libp2p node-key for the Hetzner anchor and replace
///   `<HETZNER_PEER_ID>` below with the resulting `12D3KooW...` peer id.
/// - Confirm the `bootnode.rostro.org` DNS A record points at the Hetzner
///   instance's public IP.
pub fn rostro_config() -> Result<ChainSpec, String> {
	let mut spec = ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Rostro wasm not available".to_string())?,
		None,
	)
	.with_name("Rostro")
	.with_id("rostro")
	.with_chain_type(ChainType::Live)
	.with_genesis_config_patch(testnet_genesis(
		vec![
			authority_keys_from_seed("Alice"),
			authority_keys_from_seed("Bob"),
			authority_keys_from_seed("Charlie"),
		],
		rostro_account_from_seed("Alice"),
		dev_endowed_accounts(),
	))
	.with_properties(properties())
	.build();

	// The bootnode multiaddr is left as a TODO until the Hetzner anchor's
	// node-key is generated; uncomment + fill once provisioned.
	//
	// spec.add_boot_node(
	//     "/dns4/bootnode.rostro.org/tcp/30333/p2p/12D3KooW<HETZNER_PEER_ID>"
	//         .parse()
	//         .expect("hardcoded multiaddr is valid; qed"),
	// );
	let _ = &mut spec; // keep the binding mutable-ready for the TODO

	Ok(spec)
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
