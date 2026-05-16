// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! WebSocket JSON-RPC client wrapper.
//!
//! Thin layer over `jsonrpsee-ws-client`. Exposes only the three methods the
//! recognizer needs: fetch metadata, enumerate the fingerprint map's keys,
//! fetch each storage value. Anything more is out of v0 scope.

use crate::{
	recognize as run_recognize,
	storage::{
		decode_role_from_storage_key, well_known_fingerprints_prefix, PALLET_NAME, STORAGE_NAME,
	},
	storage_query::{
		build_storage_key, decode_runtime_api_return, decode_storage_value, StorageQueryError,
	},
	Recognizer,
};
use rostro_canonicalize::CanonicalizeError;
use codec::Decode;
use frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed};
use jsonrpsee::{core::client::ClientT, rpc_params, ws_client::WsClientBuilder};
use scale_info::PortableRegistry;

/// Errors the RPC client can produce.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
	#[error("connect failed: {0}")]
	Connect(String),
	#[error("rpc call failed: {0}")]
	Call(String),
	#[error("unexpected response shape: {0}")]
	Shape(String),
	#[error("hex decode failed: {0}")]
	Hex(String),
	#[error("metadata decode failed: {0}")]
	MetadataDecode(String),
	#[error("metadata version unsupported: expected V14, V15, or V16, got V{0}")]
	UnsupportedMetadataVersion(u8),
	#[error("metadata missing well-known role marker on chain")]
	NoWellKnownFingerprints,
	#[error("canonicalize: {0:?}")]
	Canonicalize(CanonicalizeError),
	#[error("storage query: {0}")]
	StorageQuery(#[from] StorageQueryError),
}

/// Async chain client. Holds an open WebSocket session.
pub struct RostroClient {
	ws: jsonrpsee::ws_client::WsClient,
}

impl RostroClient {
	/// Connect to a node's JSON-RPC endpoint (typically `ws://127.0.0.1:9944`).
	pub async fn connect(url: &str) -> Result<Self, RpcError> {
		let ws = WsClientBuilder::default()
			.build(url)
			.await
			.map_err(|e| RpcError::Connect(e.to_string()))?;
		Ok(Self { ws })
	}

	/// Fetch the chain's runtime metadata at V15. V15 is required because
	/// the storage + runtime-API decode paths in `storage_query` introspect
	/// V15-shaped types (`apis: Vec<RuntimeApiMetadata>` is V15+ only).
	/// `state_getMetadata` returns whatever the runtime declares as
	/// default (often V14); we explicitly call `Metadata_metadata_at_version(15)`
	/// to force V15.
	pub async fn metadata(&self) -> Result<RuntimeMetadata, RpcError> {
		use codec::Encode;
		let args = 15u32.encode();
		let raw = self.state_call("Metadata_metadata_at_version", &args).await?;
		let opaque: Option<Vec<u8>> = Decode::decode(&mut &raw[..])
			.map_err(|e| RpcError::MetadataDecode(e.to_string()))?;
		let opaque = opaque.ok_or_else(|| {
			RpcError::MetadataDecode("runtime does not expose metadata at V15".into())
		})?;
		let prefixed = RuntimeMetadataPrefixed::decode(&mut &opaque[..])
			.map_err(|e| RpcError::MetadataDecode(e.to_string()))?;
		Ok(prefixed.1)
	}

	/// Read every entry of `WellKnownTypeFingerprints` storage. Returns a
	/// list of `(role_marker_bytes, fingerprint)` pairs in storage order.
	pub async fn well_known_fingerprints(&self) -> Result<Vec<(Vec<u8>, [u8; 32])>, RpcError> {
		let prefix = well_known_fingerprints_prefix();
		let prefix_hex = format!("0x{}", hex_encode(&prefix));

		// Page size 256 — substrate's RPC enforces a 1000-entry hard cap on
		// `state_getKeysPaged`, and the on-chain `MAX_ADDITIONAL_FINGERPRINTS`
		// cap is 64 plus the v0 seed (7) → at most 71 entries today. A
		// single page suffices. If that bound rises, this becomes a paged
		// loop using the last returned key as the next start_key.
		let keys_hex: Vec<String> = self
			.ws
			.request(
				"state_getKeysPaged",
				rpc_params![prefix_hex.clone(), 256u32, prefix_hex],
			)
			.await
			.map_err(|e| RpcError::Call(e.to_string()))?;

		let mut out = Vec::with_capacity(keys_hex.len());
		for k_hex in keys_hex {
			let key_bytes = decode_hex(&k_hex)?;
			let role = decode_role_from_storage_key(&key_bytes)
				.ok_or_else(|| RpcError::Shape("non-conforming storage key".into()))?;

			let value_hex: Option<String> = self
				.ws
				.request("state_getStorage", rpc_params![format!("0x{}", hex_encode(&key_bytes))])
				.await
				.map_err(|e| RpcError::Call(e.to_string()))?;
			let value_hex = value_hex
				.ok_or_else(|| RpcError::Shape("storage key returned by getKeysPaged but value missing".into()))?;
			let value_bytes = decode_hex(&value_hex)?;
			if value_bytes.len() != 32 {
				return Err(RpcError::Shape(format!(
					"fingerprint value must be 32 bytes, got {}",
					value_bytes.len()
				)));
			}
			let mut fp = [0u8; 32];
			fp.copy_from_slice(&value_bytes);
			out.push((role, fp));
		}
		Ok(out)
	}

	/// Fetch metadata + on-chain fingerprints, run the recognizer, return
	/// the resulting recognition map. The single high-level entry point a
	/// downstream consumer needs.
	pub async fn recognize(&self) -> Result<Recognizer, RpcError> {
		let metadata = self.metadata().await?;
		let registry = portable_registry_from(&metadata)?;
		let fingerprints = self.well_known_fingerprints().await?;
		if fingerprints.is_empty() {
			return Err(RpcError::NoWellKnownFingerprints);
		}
		Ok(run_recognize(&registry, &fingerprints))
	}

	/// Fetch a raw storage value at the latest block. Returns `None` if
	/// the entry is absent.
	pub async fn state_get_storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RpcError> {
		let key_hex = format!("0x{}", hex_encode(key));
		let value_hex: Option<String> = self
			.ws
			.request("state_getStorage", rpc_params![key_hex])
			.await
			.map_err(|e| RpcError::Call(e.to_string()))?;
		match value_hex {
			Some(s) => Ok(Some(decode_hex(&s)?)),
			None => Ok(None),
		}
	}

	/// Invoke a runtime API method via `state_call` at the latest block.
	/// `method` is the substrate-conventional `"TraitName_method_name"`,
	/// e.g. `"PnsStorageApi_resolve_name"`. `args` is the SCALE-encoded
	/// concatenation of the inputs.
	pub async fn state_call(&self, method: &str, args: &[u8]) -> Result<Vec<u8>, RpcError> {
		let args_hex = format!("0x{}", hex_encode(args));
		let result_hex: String = self
			.ws
			.request("state_call", rpc_params![method, args_hex])
			.await
			.map_err(|e| RpcError::Call(e.to_string()))?;
		decode_hex(&result_hex)
	}

	/// Fetch a typed storage entry at the latest block, decoded as a
	/// `scale_value::Value` against the metadata. `keys` holds one
	/// SCALE-encoded byte slice per hasher (empty for `StorageValue`).
	/// Returns `Ok(None)` for `Optional`-modifier entries that are absent.
	pub async fn fetch_storage(
		&self,
		metadata: &RuntimeMetadata,
		pallet: &str,
		item: &str,
		keys: &[&[u8]],
	) -> Result<Option<scale_value::Value<()>>, RpcError> {
		let key = build_storage_key(metadata, pallet, item, keys)?;
		let raw = match self.state_get_storage(&key).await? {
			Some(b) => b,
			None => return Ok(None),
		};
		let value = decode_storage_value(metadata, pallet, item, &raw)?;
		Ok(Some(value))
	}

	/// Invoke a runtime API method and decode its return value against
	/// the runtime API's declared output type. `args` is the
	/// SCALE-encoded concatenation of the method's inputs.
	pub async fn call_runtime_api(
		&self,
		metadata: &RuntimeMetadata,
		trait_name: &str,
		method: &str,
		args: &[u8],
	) -> Result<scale_value::Value<()>, RpcError> {
		let method_name = format!("{trait_name}_{method}");
		let raw = self.state_call(&method_name, args).await?;
		let value = decode_runtime_api_return(metadata, trait_name, method, &raw)?;
		Ok(value)
	}

	/// Generic JSON-RPC escape hatch — for methods this client doesn't
	/// wrap (e.g. `system_accountNextIndex` for best-block nonce reads
	/// during extrinsic submission).
	pub async fn request<R: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: jsonrpsee::core::params::ArrayParams,
	) -> Result<R, RpcError> {
		self.ws.request(method, params).await.map_err(|e| RpcError::Call(e.to_string()))
	}
}

/// Extract the `PortableRegistry` from a strongly-typed `RuntimeMetadata`
/// for the metadata versions that carry one.
fn portable_registry_from(m: &RuntimeMetadata) -> Result<PortableRegistry, RpcError> {
	match m {
		RuntimeMetadata::V14(v14) => Ok(v14.types.clone()),
		RuntimeMetadata::V15(v15) => Ok(v15.types.clone()),
		RuntimeMetadata::V16(v16) => Ok(v16.types.clone()),
		other => Err(RpcError::UnsupportedMetadataVersion(metadata_version_byte(other))),
	}
}

fn metadata_version_byte(m: &RuntimeMetadata) -> u8 {
	use RuntimeMetadata::*;
	match m {
		V0(_) => 0,
		V1(_) => 1,
		V2(_) => 2,
		V3(_) => 3,
		V4(_) => 4,
		V5(_) => 5,
		V6(_) => 6,
		V7(_) => 7,
		V8(_) => 8,
		V9(_) => 9,
		V10(_) => 10,
		V11(_) => 11,
		V12(_) => 12,
		V13(_) => 13,
		V14(_) => 14,
		V15(_) => 15,
		V16(_) => 16,
	}
}

fn decode_hex(s: &str) -> Result<Vec<u8>, RpcError> {
	let trimmed = s.strip_prefix("0x").unwrap_or(s);
	if trimmed.len() % 2 != 0 {
		return Err(RpcError::Hex("odd length".into()));
	}
	let mut out = Vec::with_capacity(trimmed.len() / 2);
	let bytes = trimmed.as_bytes();
	for chunk in bytes.chunks(2) {
		out.push(
			(decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?,
		);
	}
	Ok(out)
}

fn decode_hex_nibble(b: u8) -> Result<u8, RpcError> {
	match b {
		b'0'..=b'9' => Ok(b - b'0'),
		b'a'..=b'f' => Ok(b - b'a' + 10),
		b'A'..=b'F' => Ok(b - b'A' + 10),
		_ => Err(RpcError::Hex(format!("invalid char 0x{:02x}", b))),
	}
}

fn hex_encode(bytes: &[u8]) -> String {
	let mut out = String::with_capacity(bytes.len() * 2);
	for b in bytes {
		out.push(nibble_char(b >> 4));
		out.push(nibble_char(b & 0x0f));
	}
	out
}

fn nibble_char(n: u8) -> char {
	match n {
		0..=9 => (b'0' + n) as char,
		_ => (b'a' + n - 10) as char,
	}
}

// Suppress dead-code lint when `ClientT` is brought in only for `request`.
#[allow(unused_imports)]
use ClientT as _;

// `STORAGE_NAME` and `PALLET_NAME` are imported as constants the storage
// module exposes; documented as part of the public surface a downstream
// consumer can reference.
#[allow(unused_imports)]
use {PALLET_NAME as _, STORAGE_NAME as _};
