// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for rostro-client.
//!
//! Two layers:
//! - canonicalize parity: each well-known role's canonical_def derived from
//!   the real upstream type matches the build-time-generated constant
//! - recognizer end-to-end: synthetic registries verify recognition logic
//!   for happy path, hint-mismatch (forgery), and inferred (no path hint).

use crate::{
	canonical_def, fingerprint, recognize, well_known_canonical_defs as defs, Recognition,
	WellKnownRole, FINGERPRINT_VERSION,
};
use codec::{Decode, Encode};
use scale_info::{PortableRegistry, Registry, TypeInfo};
use sp_core::{crypto::AccountId32, H256};
use sp_runtime::{generic::Era, MultiAddress};
use sp_weights::Weight;

fn portable<T: TypeInfo + 'static>() -> (PortableRegistry, u32) {
	let mut registry = Registry::new();
	let symbol = registry.register_type(&scale_info::MetaType::new::<T>());
	let id = symbol.id;
	let portable: PortableRegistry = registry.into();
	(portable, id)
}

// ─── canonical_def parity: real upstream types must canonicalize to the
//      build-time-generated constants ──────────────────────────────────────

#[test]
fn upstream_account_id_32_matches_generated_def() {
	let (reg, id) = portable::<AccountId32>();
	assert_eq!(canonical_def(id, &reg).unwrap().as_bytes(), defs::ACCOUNT_ID_32);
}

#[test]
fn upstream_h256_matches_generated_def() {
	let (reg, id) = portable::<H256>();
	assert_eq!(canonical_def(id, &reg).unwrap().as_bytes(), defs::HASH_32);
}

#[test]
fn upstream_era_matches_generated_def() {
	let (reg, id) = portable::<Era>();
	assert_eq!(canonical_def(id, &reg).unwrap().as_bytes(), defs::ERA);
}

#[test]
fn upstream_multiaddress_matches_generated_def() {
	let (reg, id) = portable::<MultiAddress<AccountId32, ()>>();
	assert_eq!(canonical_def(id, &reg).unwrap().as_bytes(), defs::MULTIADDRESS);
}

#[test]
fn upstream_weight_matches_generated_def() {
	let (reg, id) = portable::<Weight>();
	assert_eq!(canonical_def(id, &reg).unwrap().as_bytes(), defs::WEIGHT);
}

#[test]
fn upstream_u128_matches_generated_def() {
	let (reg, id) = portable::<u128>();
	assert_eq!(canonical_def(id, &reg).unwrap().as_bytes(), defs::BALANCE_U128);
}

#[test]
fn upstream_u32_matches_generated_def() {
	let (reg, id) = portable::<u32>();
	assert_eq!(canonical_def(id, &reg).unwrap().as_bytes(), defs::BLOCK_NUMBER_U32);
}

// ─── fingerprint distinctness ──────────────────────────────────────────────

#[test]
fn v1_fingerprints_are_distinct_across_roles() {
	let mut seen = std::collections::HashSet::new();
	for role in WellKnownRole::ALL.iter() {
		let fp = fingerprint(role.canonical_def(), role.marker(), FINGERPRINT_VERSION);
		assert!(
			seen.insert(fp),
			"role {:?} fingerprint collides with another v1 role",
			role,
		);
	}
}

// ─── recognition end-to-end against synthetic registries ───────────────────

fn synthetic_v1_on_chain_map() -> Vec<(Vec<u8>, [u8; 32])> {
	WellKnownRole::ALL
		.iter()
		.map(|r| {
			(
				r.marker().to_vec(),
				fingerprint(r.canonical_def(), r.marker(), FINGERPRINT_VERSION),
			)
		})
		.collect()
}

#[test]
fn recognizes_account_id_32_as_account() {
	let (reg, id) = portable::<AccountId32>();
	let r = recognize(&reg, &synthetic_v1_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Account));
}

#[test]
fn recognizes_h256_as_hash() {
	let (reg, id) = portable::<H256>();
	let r = recognize(&reg, &synthetic_v1_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Hash));
}

#[test]
fn recognizes_era_via_path_hint() {
	let (reg, id) = portable::<Era>();
	let r = recognize(&reg, &synthetic_v1_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Era));
}

#[test]
fn recognizes_multiaddress_via_path_hint() {
	let (reg, id) = portable::<MultiAddress<AccountId32, ()>>();
	let r = recognize(&reg, &synthetic_v1_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::MultiAddress));
}

#[test]
fn recognizes_weight_via_path_hint() {
	let (reg, id) = portable::<Weight>();
	let r = recognize(&reg, &synthetic_v1_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Weight));
}

// ─── forgery detection ─────────────────────────────────────────────────────

mod forged {
	use codec::{Decode, Encode};
	use scale_info::TypeInfo;

	#[derive(Encode, Decode, TypeInfo)]
	#[allow(dead_code)]
	pub struct AccountId32(pub u128);
}

#[test]
fn forged_account_path_pointing_at_wrong_shape_caught_as_hint_mismatch() {
	// `forged::AccountId32(u128)` — path says Account, body is u128. The
	// hint triggers (last path segment is "AccountId32") but the canonical
	// def is "u128", which does not match the Account role's "[u8;32]" —
	// the recognizer detects the forgery and emits `HintMismatch`.
	let (reg, id) = portable::<forged::AccountId32>();
	let r = recognize(&reg, &synthetic_v1_on_chain_map());
	assert_eq!(
		r.recognize_type(id),
		Recognition::HintMismatch { hinted: WellKnownRole::Account }
	);
}

// ─── inference for no-path-hint primitives ─────────────────────────────────

#[derive(Encode, Decode, TypeInfo)]
#[allow(dead_code)]
struct UnknownNewtype(u128);

#[test]
fn unknown_newtype_with_balance_shape_inferred_not_verified() {
	let (reg, id) = portable::<UnknownNewtype>();
	let r = recognize(&reg, &synthetic_v1_on_chain_map());
	match r.recognize_type(id) {
		Recognition::Inferred { roles } => {
			assert!(roles.contains(&WellKnownRole::Balance));
		},
		other => panic!("expected Inferred, got {:?}", other),
	}
}
