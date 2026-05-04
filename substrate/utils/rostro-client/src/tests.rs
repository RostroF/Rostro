// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for rostro-client v0.

use crate::{
	canonical_def, fingerprint, recognize, Recognition, WellKnownRole, FINGERPRINT_VERSION,
};
use codec::{Decode, Encode};
use scale_info::{PortableRegistry, Registry, TypeInfo};

// ─── helpers ───────────────────────────────────────────────────────────────

/// Compile-time hex string → `[u8; 32]` literal.
macro_rules! hex32 {
	($s:literal) => {{
		const BYTES: [u8; 32] = {
			let s = $s.as_bytes();
			let mut out = [0u8; 32];
			let mut i = 0;
			while i < 32 {
				out[i] = (hex_nibble(s[i * 2]) << 4) | hex_nibble(s[i * 2 + 1]);
				i += 1;
			}
			out
		};
		BYTES
	}};
}

const fn hex_nibble(b: u8) -> u8 {
	match b {
		b'0'..=b'9' => b - b'0',
		b'a'..=b'f' => b - b'a' + 10,
		b'A'..=b'F' => b - b'A' + 10,
		_ => 0,
	}
}

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

#[derive(Encode, Decode, TypeInfo)]
#[allow(dead_code)]
pub enum Era {
	Immortal,
	Mortal { period: u64, phase: u64 },
}

#[derive(Encode, Decode, TypeInfo)]
#[allow(dead_code)]
pub enum MultiAddress {
	Id([u8; 32]),
	Index(codec::Compact<()>),
	Raw(Vec<u8>),
	Address32([u8; 32]),
	Address20([u8; 20]),
}

#[derive(Encode, Decode, TypeInfo)]
#[allow(dead_code)]
pub struct Weight {
	pub ref_time: u64,
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
fn era_canonicalizes_to_pallet_def() {
	let (reg, id) = portable::<Era>();
	assert_eq!(
		canonical_def(id, &reg).unwrap(),
		"enum{Immortal,Mortal{period:u64,phase:u64}}"
	);
}

#[test]
fn multiaddress_canonicalizes_to_pallet_def() {
	let (reg, id) = portable::<MultiAddress>();
	assert_eq!(
		canonical_def(id, &reg).unwrap(),
		"enum{Address20([u8;20]),Address32([u8;32]),Id([u8;32]),Index(Compact<()>),Raw(Vec<u8>)}"
	);
}

#[test]
fn weight_canonicalizes_to_pallet_def() {
	let (reg, id) = portable::<Weight>();
	assert_eq!(
		canonical_def(id, &reg).unwrap(),
		"struct{proof_size:u64,ref_time:u64}"
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

// ─── fingerprint parity with the pallet (oracle = live --dev verify) ───────

/// All seven v0 fingerprints, observed live on the running --dev node
/// during Phase 2 v0 verification. The reference oracle for the recognizer.
const V0_FINGERPRINTS: &[(&[u8], [u8; 32])] = &[
	(b"account",      hex32!("1f3e1e7491299377134b3faa6a159e678b270e2ef783dcd0cfca9e46e2debe12")),
	(b"hash",         hex32!("d274d8a698e1e87977ba24ecb6bdf0b028bd59b3466c11543350d815035c4760")),
	(b"era",          hex32!("e8730f843f86fc834a9e7871057730857e5bcfdd11a12cc0d14f0d260e373c9a")),
	(b"multiaddress", hex32!("585713f8ec9d9e349671fb5093be06674f34c6f18e3e3f15f8408ac69cab7f3f")),
	(b"weight",       hex32!("da0cb7c7b60e55fdbbf8ffeb1ce7b3e0f26e68ba6a0a799110a4bf326a0b593f")),
	(b"balance",      hex32!("8e9454711c397fa2f04337ad5bde5df62dfb1d25c4057c9539244fe49dd45312")),
	(b"block-number", hex32!("86a1106049ebe1385d9c7e3a4fcb28083f6b7a6646cfe21f0c6027fdfbb42bfe")),
];

#[test]
fn client_fingerprints_match_on_chain_v0() {
	for role in WellKnownRole::ALL.iter() {
		let computed = fingerprint(role.canonical_def(), role.marker(), FINGERPRINT_VERSION);
		let expected = V0_FINGERPRINTS
			.iter()
			.find(|(r, _)| *r == role.marker())
			.map(|(_, fp)| *fp)
			.expect("role present in oracle");
		assert_eq!(
			computed, expected,
			"client fingerprint must equal on-chain fingerprint for role {:?}",
			role
		);
	}
}

// ─── recognition end-to-end ────────────────────────────────────────────────

fn v0_on_chain_map() -> Vec<(Vec<u8>, [u8; 32])> {
	V0_FINGERPRINTS.iter().map(|(r, fp)| (r.to_vec(), *fp)).collect()
}

#[test]
fn recognizes_account_id_32_as_account() {
	let (reg, id) = portable::<AccountId32>();
	let r = recognize(&reg, &v0_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Account));
}

#[test]
fn recognizes_h256_as_hash() {
	let (reg, id) = portable::<H256>();
	let r = recognize(&reg, &v0_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Hash));
}

#[test]
fn recognizes_era_via_path_hint() {
	let (reg, id) = portable::<Era>();
	let r = recognize(&reg, &v0_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Era));
}

#[test]
fn recognizes_weight_via_path_hint() {
	let (reg, id) = portable::<Weight>();
	let r = recognize(&reg, &v0_on_chain_map());
	assert_eq!(r.recognize_type(id), Recognition::Verified(WellKnownRole::Weight));
}

#[test]
fn unknown_newtype_with_pallet_shape_inferred_not_verified() {
	// `UnknownNewtype(u128)` newtype-unwraps to `u128`. No path hint
	// applies, but the structural shape matches Balance. Surfaces as
	// `Inferred` — without a path, we cannot commit to a single role.
	let (reg, id) = portable::<UnknownNewtype>();
	let r = recognize(&reg, &v0_on_chain_map());
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
	let r = recognize(&reg, &v0_on_chain_map());
	assert_eq!(
		r.recognize_type(id),
		Recognition::HintMismatch { hinted: WellKnownRole::Account }
	);
}
