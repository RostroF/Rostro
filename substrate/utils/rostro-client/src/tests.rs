// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for rostro-client v0.

use crate::{
	canonical_def, fingerprint, recognize, Recognition, WellKnownRole, FINGERPRINT_VERSION,
};
use codec::{Decode, Encode};
use scale_info::{PortableRegistry, Registry, TypeInfo};

/// Build a single-type registry. Returns the portable registry plus the
/// portable-form type id of the registered type.
fn portable<T: TypeInfo + 'static>() -> (PortableRegistry, u32) {
	let mut registry = Registry::new();
	let symbol = registry.register_type(&scale_info::MetaType::new::<T>());
	let id = symbol.id;
	let portable: PortableRegistry = registry.into();
	(portable, id)
}

// ─── synthetic types matching the v0 well-known roles ──────────────────────

#[derive(Encode, Decode, TypeInfo)]
#[allow(dead_code)]
pub struct AccountId32(pub [u8; 32]);

#[derive(Encode, Decode, TypeInfo)]
#[allow(dead_code)]
pub struct H256(pub [u8; 32]);

/// Mirror of `sp_weights::Weight` — both fields carry `#[codec(compact)]`,
/// which is what makes the metadata representation use `Compact<u64>` and
/// what the pallet's canonical_def must therefore declare. Hand-writing
/// `u64` instead of `Compact<u64>` was the bug the live integration test
/// caught on 2026-05-04.
#[derive(Encode, Decode, TypeInfo)]
#[allow(dead_code)]
pub struct Weight {
	#[codec(compact)]
	pub ref_time: u64,
	#[codec(compact)]
	pub proof_size: u64,
}

#[derive(Encode, Decode, TypeInfo)]
#[allow(dead_code)]
pub struct UnknownNewtype(pub u128);

mod forged {
	use codec::{Decode, Encode};
	use scale_info::TypeInfo;

	#[derive(Encode, Decode, TypeInfo)]
	#[allow(dead_code)]
	pub struct AccountId32(pub u128);
}

// ─── canonical_def parity with the pallet ──────────────────────────────────

#[test]
fn account_id_32_canonicalizes_to_pallet_def() {
	let (reg, id) = portable::<AccountId32>();
	assert_eq!(canonical_def(id, &reg).unwrap(), "[u8;32]");
}

#[test]
fn h256_canonicalizes_to_pallet_def() {
	let (reg, id) = portable::<H256>();
	assert_eq!(canonical_def(id, &reg).unwrap(), "[u8;32]");
}

#[test]
fn weight_canonicalizes_to_pallet_def() {
	let (reg, id) = portable::<Weight>();
	assert_eq!(
		canonical_def(id, &reg).unwrap(),
		"struct{proof_size:Compact<u64>,ref_time:Compact<u64>}"
	);
}

#[test]
fn u128_canonicalizes_to_pallet_def() {
	let (reg, id) = portable::<u128>();
	assert_eq!(canonical_def(id, &reg).unwrap(), "u128");
}

#[test]
fn u32_canonicalizes_to_pallet_def() {
	let (reg, id) = portable::<u32>();
	assert_eq!(canonical_def(id, &reg).unwrap(), "u32");
}

// ─── fingerprint self-consistency ──────────────────────────────────────────
//
// The ground-truth oracle for "client fingerprints match the on-chain map"
// is `tests/live_recognizer.rs` — it talks to a real --dev node. This unit
// test confirms a weaker but still useful property: each role's fingerprint
// is deterministic and the seven (or however many) v0 roles produce
// distinct fingerprints, so a metadata type that shape-matches one role
// can never accidentally hash-match another.

#[test]
fn v0_fingerprints_are_distinct_across_roles() {
	let mut seen = std::collections::HashSet::new();
	for role in WellKnownRole::ALL.iter() {
		let fp = fingerprint(role.canonical_def(), role.marker(), FINGERPRINT_VERSION);
		assert!(
			seen.insert(fp),
			"role {:?} fingerprint collides with another v0 role",
			role,
		);
	}
}

// ─── recognition end-to-end against synthetic registry ─────────────────────

fn synthetic_v0_on_chain_map() -> Vec<(Vec<u8>, [u8; 32])> {
	WellKnownRole::ALL
		.iter()
		.map(|r| (r.marker().to_vec(), fingerprint(r.canonical_def(), r.marker(), FINGERPRINT_VERSION)))
		.collect()
}

#[test]
fn recognizes_account_id_32_as_account() {
	let (reg, id) = portable::<AccountId32>();
	let r = recognize(&reg, &synthetic_v0_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Account));
}

#[test]
fn recognizes_h256_as_hash() {
	let (reg, id) = portable::<H256>();
	let r = recognize(&reg, &synthetic_v0_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Hash));
}

#[test]
fn recognizes_weight_via_path_hint() {
	let (reg, id) = portable::<Weight>();
	let r = recognize(&reg, &synthetic_v0_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Weight));
}

#[test]
fn unknown_newtype_with_pallet_shape_inferred_not_verified() {
	// `UnknownNewtype(u128)` newtype-unwraps to `u128`. No path hint
	// applies, but the structural shape matches Balance. Surfaces as
	// `Inferred` — without a path, we cannot commit to a single role.
	let (reg, id) = portable::<UnknownNewtype>();
	let r = recognize(&reg, &synthetic_v0_on_chain_map());
	match r.recognize_type(id) {
		Recognition::Inferred { roles } => {
			assert!(roles.contains(&WellKnownRole::Balance));
		},
		other => panic!("expected Inferred, got {:?}", other),
	}
}

#[test]
fn forged_account_path_pointing_at_wrong_shape_caught_as_hint_mismatch() {
	// `forged::AccountId32(u128)` — path says Account, body is u128. The
	// hint triggers (last path segment is "AccountId32") but the canonical
	// def is "u128", which does not match the Account role's "[u8;32]" —
	// the recognizer detects the forgery and emits `HintMismatch`.
	let (reg, id) = portable::<forged::AccountId32>();
	let r = recognize(&reg, &synthetic_v0_on_chain_map());
	assert_eq!(
		r.recognize_type(id),
		Recognition::HintMismatch { hinted: WellKnownRole::Account }
	);
}
