// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Live integration test for the rostro-client storage + runtime-API
//! read path. Requires a running gemini-node:
//!
//!     cargo test --release -p rostro-client --test live_storage \
//!         -- --ignored --nocapture
//!
//! Exercises:
//! - `fetch_storage` against `System.Account` (StorageMap with
//!   Blake2_128Concat) and `RnsPriceOracle.BasePrice` (StorageValue).
//! - `call_runtime_api` against `PnsStorageApi_account_dashboard` and
//!   `PnsStorageApi_resolve_name`.
//!
//! The shapes assertions deliberately match by composite/primitive
//! structure (`scale_value::ValueDef`), not by typed deserialization,
//! because that is what dotwave does at the consumer layer.

use codec::Encode;
use rostro_client::RostroClient;
use scale_value::{Composite, Primitive, ValueDef};
use sp_core::{crypto::Pair, sr25519};

const NODE_URL: &str = "ws://127.0.0.1:9944";

#[tokio::test]
#[ignore]
async fn fetch_storage_system_account_for_alice_decodes() {
	let client = RostroClient::connect(NODE_URL).await.expect("node reachable");
	let metadata = client.metadata().await.expect("metadata fetch");

	let alice = sr25519::Pair::from_string("//Alice", None).unwrap().public();
	let account_bytes: [u8; 32] = alice.0;
	let scale_encoded_account = account_bytes.encode();

	let result = client
		.fetch_storage(&metadata, "System", "Account", &[&scale_encoded_account])
		.await
		.expect("fetch_storage succeeds");

	let value = result.expect("Alice has a System.Account entry on --dev");

	let ValueDef::Composite(Composite::Named(fields)) = &value.value else {
		panic!("System.Account decoded shape is not a named composite: {:?}", value);
	};
	assert!(
		fields.iter().any(|(n, _)| n == "data"),
		"System.Account missing 'data' field; got {:?}",
		fields.iter().map(|(n, _)| n).collect::<Vec<_>>()
	);
}

#[tokio::test]
#[ignore]
async fn fetch_storage_rns_price_oracle_base_price_decodes() {
	let client = RostroClient::connect(NODE_URL).await.expect("node reachable");
	let metadata = client.metadata().await.expect("metadata fetch");

	let result = client
		.fetch_storage(&metadata, "RnsPriceOracle", "BasePrice", &[])
		.await
		.expect("fetch_storage succeeds");

	let value = result.expect("BasePrice is initialized at genesis");

	let ValueDef::Composite(Composite::Unnamed(arr)) = &value.value else {
		panic!("RnsPriceOracle.BasePrice expected unnamed composite (array): {:?}", value);
	};
	assert_eq!(arr.len(), 11, "BasePrice should be a [u128; 11], got len {}", arr.len());
	for (i, v) in arr.iter().enumerate() {
		assert!(
			matches!(v.value, ValueDef::Primitive(Primitive::U128(_))),
			"BasePrice[{}] not a u128: {:?}",
			i,
			v
		);
	}
}

#[tokio::test]
#[ignore]
async fn call_runtime_api_account_dashboard_for_alice_returns_empty() {
	let client = RostroClient::connect(NODE_URL).await.expect("node reachable");
	let metadata = client.metadata().await.expect("metadata fetch");

	let alice = sr25519::Pair::from_string("//Alice", None).unwrap().public();
	let alice_bytes: [u8; 32] = alice.0;
	let args = alice_bytes.encode();

	let value = client
		.call_runtime_api(&metadata, "PnsStorageApi", "account_dashboard", &args)
		.await
		.expect("runtime API call succeeds");

	let ValueDef::Composite(Composite::Named(fields)) = &value.value else {
		panic!("AccountDashboard expected named composite: {:?}", value);
	};

	let primary_name = fields
		.iter()
		.find(|(n, _)| n == "primary_name")
		.map(|(_, v)| &v.value)
		.expect("primary_name field present");
	let ValueDef::Variant(var) = primary_name else {
		panic!("primary_name not a variant: {:?}", primary_name);
	};
	assert_eq!(
		var.name, "None",
		"Alice should have no primary name on a fresh chain (got {})",
		var.name
	);
}

#[tokio::test]
#[ignore]
async fn call_runtime_api_resolve_name_for_unregistered_returns_none() {
	let client = RostroClient::connect(NODE_URL).await.expect("node reachable");
	let metadata = client.metadata().await.expect("metadata fetch");

	let name = b"alice".to_vec();
	let args = name.encode();

	let value = client
		.call_runtime_api(&metadata, "PnsStorageApi", "resolve_name", &args)
		.await
		.expect("runtime API call succeeds");

	let ValueDef::Variant(var) = &value.value else {
		panic!("resolve_name expected to return Option (variant), got {:?}", value);
	};
	assert_eq!(var.name, "None", "alice should be unregistered on a fresh chain");
}
