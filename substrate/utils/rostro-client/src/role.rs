// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! The seven v0 well-known roles, with their role markers and canonical_def
//! strings. Mirrors `pallet-rostro-type-registry`'s `roles` and
//! `canonical_defs` modules byte-for-byte.

/// Well-known canonical roles seeded into the on-chain fingerprint registry
/// at genesis. v0 covers the shape-clean roles whose `scale_info::TypeInfo`
/// produces a deterministic structural string. Era and MultiAddress are
/// deferred to v1 — Substrate's custom `TypeInfo` impls for those produce
/// large, encoding-quirky representations that hand-written canonical_defs
/// could not safely mirror.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WellKnownRole {
	Account,
	Hash,
	Weight,
	Balance,
	BlockNumber,
}

impl WellKnownRole {
	/// All v0 well-known roles. Order is stable but not load-bearing — the
	/// fingerprint binds the role marker into the hash.
	pub const ALL: [Self; 5] = [
		Self::Account,
		Self::Hash,
		Self::Weight,
		Self::Balance,
		Self::BlockNumber,
	];

	/// Role marker bytes — the literal byte string the pallet hashes.
	pub const fn marker(self) -> &'static [u8] {
		match self {
			Self::Account => b"account",
			Self::Hash => b"hash",
			Self::Weight => b"weight",
			Self::Balance => b"balance",
			Self::BlockNumber => b"block-number",
		}
	}

	/// Canonical structural definition — the byte string the pallet hashes
	/// alongside the role marker. Must mirror byte-for-byte what the pallet
	/// stores; the recognizer recomputes against this constant.
	pub const fn canonical_def(self) -> &'static [u8] {
		match self {
			Self::Account => b"[u8;32]",
			Self::Hash => b"[u8;32]",
			// Substrate's Weight has `#[codec(compact)]` on both fields,
			// so the metadata representation uses `Compact<u64>` not `u64`.
			Self::Weight => b"struct{proof_size:Compact<u64>,ref_time:Compact<u64>}",
			Self::Balance => b"u128",
			Self::BlockNumber => b"u32",
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
			"Weight" => Some(Self::Weight),
			// Balance and BlockNumber are usually type aliases (not in
			// metadata as named types) — they appear inline as u128 / u32
			// at the use site. The recognizer also probes shape-matching
			// roles for primitive-typed fields when no path hint applies.
			_ => None,
		}
	}
}
