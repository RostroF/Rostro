// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Generic storage-read primitives: key construction over arbitrary
//! `StorageHasher` configurations and SCALE decoding against the
//! runtime's `PortableRegistry`.
//!
//! Pure logic — no I/O. The RPC client (`rpc.rs`) drives this for live
//! reads against a node.
//!
//! ## Storage key layout
//!
//! For a `Plain` entry: `twox_128(pallet) || twox_128(item)` (32 bytes).
//!
//! For a `Map` entry with N hashers: 32-byte prefix followed by one
//! hashed segment per key part:
//!
//! - `Blake2_128` → `blake2_128(scale_encoded_key)` (16 bytes)
//! - `Blake2_128Concat` → `blake2_128(scale_encoded_key) || scale_encoded_key`
//! - `Blake2_256` → `blake2_256(scale_encoded_key)`
//! - `Twox128` → `twox_128(scale_encoded_key)`
//! - `Twox256` → `twox_256(scale_encoded_key)`
//! - `Twox64Concat` → `twox_64(scale_encoded_key) || scale_encoded_key`
//! - `Identity` → `scale_encoded_key`
//!
//! Callers pass SCALE-encoded key bytes. Encoding from a typed value is
//! the caller's responsibility for now — the recognized roles
//! (Account/Hash/Balance/etc.) all have stable SCALE encodings.

use frame_metadata::{
	v15::{PalletMetadata, RuntimeMetadataV15, StorageEntryMetadata, StorageEntryType, StorageHasher},
	RuntimeMetadata,
};
use scale_info::PortableRegistry;
use sp_core::hashing::{blake2_128, blake2_256, twox_128, twox_256, twox_64};

#[derive(Debug, thiserror::Error)]
pub enum StorageQueryError {
	#[error("metadata version unsupported: only V14, V15, V16 expose PortableRegistry")]
	UnsupportedMetadataVersion,
	#[error("pallet '{0}' not found in metadata")]
	PalletNotFound(String),
	#[error("storage item '{pallet}.{item}' not found")]
	ItemNotFound { pallet: String, item: String },
	#[error("'{pallet}.{item}' is a Plain entry, not a Map; pass an empty key list")]
	UnexpectedKeysForPlain { pallet: String, item: String },
	#[error("'{pallet}.{item}' is a Map with {expected} key(s); got {got}")]
	KeyArityMismatch { pallet: String, item: String, expected: usize, got: usize },
	#[error("decode against PortableRegistry failed: {0}")]
	Decode(String),
}

/// Build the full SCALE-prefixed storage key for `(pallet, item, keys)`.
///
/// `keys` must hold one SCALE-encoded byte slice per hasher in the
/// metadata for that entry. For a `Plain` entry, pass `&[]`.
pub fn build_storage_key(
	metadata: &RuntimeMetadata,
	pallet: &str,
	item: &str,
	keys: &[&[u8]],
) -> Result<Vec<u8>, StorageQueryError> {
	let v15 = unwrap_v15(metadata)?;
	let entry = find_storage_entry(v15, pallet, item)?;

	let mut out = Vec::with_capacity(32 + keys.iter().map(|k| k.len() + 16).sum::<usize>());
	out.extend_from_slice(&twox_128(pallet.as_bytes()));
	out.extend_from_slice(&twox_128(item.as_bytes()));

	match &entry.ty {
		StorageEntryType::Plain(_) => {
			if !keys.is_empty() {
				return Err(StorageQueryError::UnexpectedKeysForPlain {
					pallet: pallet.into(),
					item: item.into(),
				});
			}
		},
		StorageEntryType::Map { hashers, .. } => {
			if hashers.len() != keys.len() {
				return Err(StorageQueryError::KeyArityMismatch {
					pallet: pallet.into(),
					item: item.into(),
					expected: hashers.len(),
					got: keys.len(),
				});
			}
			for (hasher, key) in hashers.iter().zip(keys.iter()) {
				append_hashed_segment(&mut out, hasher, key);
			}
		},
	}
	Ok(out)
}

/// Decode a raw storage value against the `(pallet, item)`'s declared
/// value type, into a path-stripped `scale_value::Value`. Returns an
/// untyped `Value<()>` because consumers walking it (e.g. dotwave)
/// match by composite/primitive structure rather than type id.
pub fn decode_storage_value(
	metadata: &RuntimeMetadata,
	pallet: &str,
	item: &str,
	raw: &[u8],
) -> Result<scale_value::Value<()>, StorageQueryError> {
	let v15 = unwrap_v15(metadata)?;
	let entry = find_storage_entry(v15, pallet, item)?;
	let type_id = match &entry.ty {
		StorageEntryType::Plain(t) => t.id,
		StorageEntryType::Map { value, .. } => value.id,
	};
	decode_value_with_type(raw, type_id, &v15.types)
}

/// Decode raw bytes as a runtime API method's declared return type.
pub fn decode_runtime_api_return(
	metadata: &RuntimeMetadata,
	trait_name: &str,
	method: &str,
	raw: &[u8],
) -> Result<scale_value::Value<()>, StorageQueryError> {
	let v15 = unwrap_v15(metadata)?;
	let api = v15
		.apis
		.iter()
		.find(|a| a.name == trait_name)
		.ok_or_else(|| StorageQueryError::PalletNotFound(trait_name.into()))?;
	let m = api.methods.iter().find(|m| m.name == method).ok_or_else(|| {
		StorageQueryError::ItemNotFound { pallet: trait_name.into(), item: method.into() }
	})?;
	decode_value_with_type(raw, m.output.id, &v15.types)
}

fn decode_value_with_type(
	raw: &[u8],
	type_id: u32,
	registry: &PortableRegistry,
) -> Result<scale_value::Value<()>, StorageQueryError> {
	let mut cursor = raw;
	let value = scale_value::scale::decode_as_type(&mut cursor, type_id, registry)
		.map_err(|e| StorageQueryError::Decode(e.to_string()))?;
	Ok(value.remove_context())
}

fn unwrap_v15(metadata: &RuntimeMetadata) -> Result<&RuntimeMetadataV15, StorageQueryError> {
	match metadata {
		RuntimeMetadata::V15(v15) => Ok(v15),
		_ => Err(StorageQueryError::UnsupportedMetadataVersion),
	}
}

fn find_storage_entry<'a>(
	v15: &'a RuntimeMetadataV15,
	pallet: &str,
	item: &str,
) -> Result<&'a StorageEntryMetadata<scale_info::form::PortableForm>, StorageQueryError> {
	let p: &PalletMetadata<_> = v15
		.pallets
		.iter()
		.find(|p| p.name == pallet)
		.ok_or_else(|| StorageQueryError::PalletNotFound(pallet.into()))?;
	let storage = p.storage.as_ref().ok_or_else(|| StorageQueryError::ItemNotFound {
		pallet: pallet.into(),
		item: item.into(),
	})?;
	storage.entries.iter().find(|e| e.name == item).ok_or_else(|| StorageQueryError::ItemNotFound {
		pallet: pallet.into(),
		item: item.into(),
	})
}

fn append_hashed_segment(out: &mut Vec<u8>, hasher: &StorageHasher, encoded_key: &[u8]) {
	match hasher {
		StorageHasher::Blake2_128 => out.extend_from_slice(&blake2_128(encoded_key)),
		StorageHasher::Blake2_128Concat => {
			out.extend_from_slice(&blake2_128(encoded_key));
			out.extend_from_slice(encoded_key);
		},
		StorageHasher::Blake2_256 => out.extend_from_slice(&blake2_256(encoded_key)),
		StorageHasher::Twox128 => out.extend_from_slice(&twox_128(encoded_key)),
		StorageHasher::Twox256 => out.extend_from_slice(&twox_256(encoded_key)),
		StorageHasher::Twox64Concat => {
			out.extend_from_slice(&twox_64(encoded_key));
			out.extend_from_slice(encoded_key);
		},
		StorageHasher::Identity => out.extend_from_slice(encoded_key),
	}
}
