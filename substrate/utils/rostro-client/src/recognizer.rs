// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Recognizer: ties canonicalization, fingerprinting, and the on-chain
//! fingerprint map together. Produces a `Recognition` that maps metadata
//! type ids to verified well-known roles.

use crate::{canonical_def, fingerprint, FINGERPRINT_VERSION, WellKnownRole};
use scale_info::PortableRegistry;
use std::collections::{BTreeMap, BTreeSet};

/// Outcome of recognizing a single metadata type against the on-chain
/// fingerprint map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recognition {
	/// Type's path-hint was verified by fingerprint match — semantically
	/// this type IS the named role.
	Verified(WellKnownRole),
	/// Type's path hinted at a role, but the fingerprint did not match the
	/// on-chain entry. Forged or migrated metadata; do not trust the path
	/// claim. Generic SCALE decoding only.
	HintMismatch { hinted: WellKnownRole },
	/// No path-hint applied. Fingerprint may still match by structural
	/// shape against any role; the `inferred` set carries the candidates.
	Inferred { roles: Vec<WellKnownRole> },
	/// Neither path nor structural shape match any well-known role.
	Unknown,
}

/// Result of recognizing every type in a `PortableRegistry` against the
/// supplied on-chain fingerprint map.
#[derive(Clone, Debug, Default)]
pub struct Recognizer {
	/// `metadata::TypeId → Recognition`. Sparse — types that don't shape-
	/// match any role are absent from the map (queried as `Unknown`).
	pub by_type: BTreeMap<u32, Recognition>,
}

impl Recognizer {
	/// Lookup the recognition outcome for a given metadata type id.
	pub fn recognize_type(&self, type_id: u32) -> Recognition {
		self.by_type.get(&type_id).cloned().unwrap_or(Recognition::Unknown)
	}

	/// Return all metadata type ids verified as the supplied role.
	pub fn type_ids_for_role(&self, role: WellKnownRole) -> Vec<u32> {
		self.by_type
			.iter()
			.filter_map(|(id, r)| match r {
				Recognition::Verified(rv) if *rv == role => Some(*id),
				_ => None,
			})
			.collect()
	}
}

/// Walk every type in the registry, attempt role recognition, and produce a
/// `Recognizer`.
///
/// The on-chain fingerprint map is supplied as a slice of
/// `(role_marker, fingerprint)` pairs — the same shape clients fetch from
/// `WellKnownTypeFingerprints` storage.
pub fn recognize(
	registry: &PortableRegistry,
	on_chain: &[(Vec<u8>, [u8; 32])],
) -> Recognizer {
	let mut by_type = BTreeMap::new();

	for ty in registry.types.iter() {
		let id = ty.id;
		let path: Vec<String> =
			ty.ty.path.segments.iter().map(|s| s.to_string()).collect();
		let hinted = WellKnownRole::hint_from_path(&path);

		// Compute the type's structural canonical_def. Errors short-circuit
		// to `Unknown` — we don't want adversarial metadata to disrupt the
		// recognition of well-formed entries.
		let def = match canonical_def(id, registry) {
			Ok(d) => d,
			Err(_) => continue,
		};

		// Path-hint path: verify the hinted role's fingerprint against the
		// on-chain entry.
		if let Some(role) = hinted {
			if def.as_bytes() == role.canonical_def() {
				let fp = fingerprint(def.as_bytes(), role.marker(), FINGERPRINT_VERSION);
				if find_fingerprint(on_chain, role.marker()) == Some(fp) {
					by_type.insert(id, Recognition::Verified(role));
					continue;
				}
			}
			// Hint did not verify — record the mismatch and fall through.
			by_type.insert(id, Recognition::HintMismatch { hinted: role });
			continue;
		}

		// No path hint. Probe every well-known role: a fingerprint match
		// here is a structural-shape suggestion, not a verification (the
		// type may legitimately be a non-canonical use of the same shape).
		// We surface candidates as `Inferred`.
		let mut candidates: BTreeSet<WellKnownRole> = BTreeSet::new();
		for role in WellKnownRole::ALL.iter() {
			if def.as_bytes() == role.canonical_def() {
				let fp = fingerprint(def.as_bytes(), role.marker(), FINGERPRINT_VERSION);
				if find_fingerprint(on_chain, role.marker()) == Some(fp) {
					candidates.insert(*role);
				}
			}
		}
		if !candidates.is_empty() {
			by_type.insert(
				id,
				Recognition::Inferred {
					roles: candidates.into_iter().collect(),
				},
			);
		}
	}

	Recognizer { by_type }
}

fn find_fingerprint(map: &[(Vec<u8>, [u8; 32])], role: &[u8]) -> Option<[u8; 32]> {
	map.iter().find_map(|(r, fp)| if r.as_slice() == role { Some(*fp) } else { None })
}

// `WellKnownRole` requires `Ord` for the `BTreeSet` above. Implement it as
// a stable enum ordering — semantics are not load-bearing.
impl Ord for WellKnownRole {
	fn cmp(&self, other: &Self) -> core::cmp::Ordering {
		(*self as u8).cmp(&(*other as u8))
	}
}
impl PartialOrd for WellKnownRole {
	fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
		Some(self.cmp(other))
	}
}
