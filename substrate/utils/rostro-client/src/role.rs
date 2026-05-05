// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! The seven v1 well-known roles, with their role markers and canonical_def
//! strings sourced from `rostro_canonicalize`'s build-time-derived constants.
//! Pallet and client share the same source of truth — identical bytes flow
//! into both ends of the fingerprint hash.

use rostro_canonicalize::{well_known_canonical_defs as defs, well_known_roles as roles};

/// Well-known canonical roles seeded into the on-chain fingerprint registry
/// at genesis. v1 covers all seven roles; canonical_defs are auto-derived
/// from real `scale_info::TypeInfo` at build time.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WellKnownRole {
	Account,
	Hash,
	Era,
	MultiAddress,
	Weight,
	Balance,
	BlockNumber,
}

impl WellKnownRole {
	/// All v1 well-known roles. Order is stable but not load-bearing — the
	/// fingerprint binds the role marker into the hash.
	pub const ALL: [Self; 7] = [
		Self::Account,
		Self::Hash,
		Self::Era,
		Self::MultiAddress,
		Self::Weight,
		Self::Balance,
		Self::BlockNumber,
	];

	/// Role marker bytes — the literal byte string the pallet hashes.
	pub const fn marker(self) -> &'static [u8] {
		match self {
			Self::Account => roles::ACCOUNT_ID_32,
			Self::Hash => roles::HASH_32,
			Self::Era => roles::ERA,
			Self::MultiAddress => roles::MULTIADDRESS,
			Self::Weight => roles::WEIGHT,
			Self::Balance => roles::BALANCE_U128,
			Self::BlockNumber => roles::BLOCK_NUMBER_U32,
		}
	}

	/// Canonical structural definition — derived at build time from real
	/// `scale_info::TypeInfo`. Both pallet and client read these from the
	/// same `rostro-canonicalize` build artifact, so they cannot drift.
	pub const fn canonical_def(self) -> &'static [u8] {
		match self {
			Self::Account => defs::ACCOUNT_ID_32,
			Self::Hash => defs::HASH_32,
			Self::Era => defs::ERA,
			Self::MultiAddress => defs::MULTIADDRESS,
			Self::Weight => defs::WEIGHT,
			Self::Balance => defs::BALANCE_U128,
			Self::BlockNumber => defs::BLOCK_NUMBER_U32,
		}
	}

	/// Heuristic: given a type's `path` from metadata, guess which role it
	/// might be. The guess is then verified by fingerprint comparison —
	/// this function is the *hint*, not the decision.
	pub fn hint_from_path(path: &[String]) -> Option<Self> {
		let last = path.last().map(String::as_str)?;
		match last {
			"AccountId32" | "AccountId" => Some(Self::Account),
			"H256" | "Hash" => Some(Self::Hash),
			"Era" => Some(Self::Era),
			"MultiAddress" => Some(Self::MultiAddress),
			"Weight" => Some(Self::Weight),
			// Balance and BlockNumber are usually type aliases (not in
			// metadata as named types) — they appear inline as u128 / u32
			// at the use site. Recognition for them goes through the
			// shape-only `Inferred` path.
			_ => None,
		}
	}
}
