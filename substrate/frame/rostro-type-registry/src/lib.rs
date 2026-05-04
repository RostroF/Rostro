// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro Type Registry
//!
//! On-chain anchor for canonical type fingerprints. Implements the recognizer
//! architecture decided 2026-05-03: the runtime tells clients "this fingerprint
//! is the canonical AccountId32 for me." Forged metadata that claims a
//! different fingerprint for the same role can't pass.
//!
//! ## Fingerprint format
//!
//! `fingerprint = blake2_256(canonical_def_bytes ‖ b':' ‖ role_marker ‖ b':' ‖ version_u32_le)`
//!
//! The `canonical_def_bytes` is a deterministic, whitespace-free string
//! representation of the type's structural definition. Examples:
//!
//! | Role         | canonical_def                                                                                            |
//! |--------------|----------------------------------------------------------------------------------------------------------|
//! | account      | `[u8;32]`                                                                                                |
//! | hash         | `[u8;32]`                                                                                                |
//! | era          | `enum{Immortal,Mortal{period:u64,phase:u64}}`                                                            |
//! | multiaddress | `enum{Address20([u8;20]),Address32([u8;32]),Id([u8;32]),Index(Compact<()>),Raw(Vec<u8>)}`                |
//! | weight       | `struct{proof_size:u64,ref_time:u64}`                                                                    |
//! | balance      | `u128`                                                                                                   |
//! | block-number | `u32`                                                                                                    |
//!
//! Note: enum variants and struct fields are alphabetized. AccountId32 and Hash
//! share the same `canonical_def` (both `[u8;32]`) but their fingerprints differ
//! because the role marker is part of the input.
//!
//! ## What this v0 ships
//!
//! - `WellKnownTypeFingerprints` storage map: role marker → fingerprint hash
//! - `fingerprint()` helper for off-chain recomputation parity
//! - Genesis builder seeds canonical entries for 7 well-known roles
//!
//! ## What's deferred
//!
//! - Per-type fingerprints in metadata-ir (clients still recompute externally for now)
//! - `construct_runtime!` macro extensions to auto-emit role → metadata-type-id mappings
//! - `frame-executive` runtime-upgrade gate that rejects fingerprint mismatches
//! - Client-side recognizer (lands with `rostro-client` Tier-2 work)
//!
//! See `~/.claude/projects/-home-coder-Rostro/memory/recognizer_architecture_decision.md`
//! for the full design + adversarial ranking.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

use alloc::vec::Vec;
use frame_support::pallet_prelude::*;

/// Canonical role markers seeded at genesis. Treat these as protocol constants.
pub mod roles {
	pub const ACCOUNT: &[u8] = b"account";
	pub const HASH: &[u8] = b"hash";
	pub const ERA: &[u8] = b"era";
	pub const MULTIADDRESS: &[u8] = b"multiaddress";
	pub const WEIGHT: &[u8] = b"weight";
	pub const BALANCE: &[u8] = b"balance";
	pub const BLOCK_NUMBER: &[u8] = b"block-number";
}

/// Canonical structural definitions for the v0 well-known roles.
/// Alphabetized fields/variants, no whitespace.
pub mod canonical_defs {
	pub const ACCOUNT_ID_32: &[u8] = b"[u8;32]";
	pub const HASH_32: &[u8] = b"[u8;32]";
	pub const ERA: &[u8] = b"enum{Immortal,Mortal{period:u64,phase:u64}}";
	pub const MULTIADDRESS: &[u8] =
		b"enum{Address20([u8;20]),Address32([u8;32]),Id([u8;32]),Index(Compact<()>),Raw(Vec<u8>)}";
	pub const WEIGHT: &[u8] = b"struct{proof_size:u64,ref_time:u64}";
	pub const BALANCE_U128: &[u8] = b"u128";
	pub const BLOCK_NUMBER_U32: &[u8] = b"u32";
}

/// Fingerprint version. Bump when the canonical_def format changes (e.g. if we
/// extend to cover generics differently). v0 ships at 1.
pub const FINGERPRINT_VERSION: u32 = 1;

/// Maximum role marker length in bytes. Roles are short ASCII strings.
pub const MAX_ROLE_LEN: u32 = 32;

/// Compute a canonical type fingerprint.
///
/// `blake2_256(canonical_def_bytes ‖ b':' ‖ role ‖ b':' ‖ version.to_le_bytes())`
///
/// Constructed identically off-chain by `rostro-client` for verification
/// against the on-chain `WellKnownTypeFingerprints` map.
pub fn fingerprint(canonical_def: &[u8], role: &[u8], version: u32) -> [u8; 32] {
	let mut buf = Vec::with_capacity(canonical_def.len() + role.len() + 6);
	buf.extend_from_slice(canonical_def);
	buf.push(b':');
	buf.extend_from_slice(role);
	buf.push(b':');
	buf.extend_from_slice(&version.to_le_bytes());
	sp_io::hashing::blake2_256(&buf)
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Origin permitted to mutate fingerprints post-genesis. In production
		/// this resolves to the Security Response Team (`pallet-rostro-security-
		/// response-team`, deferred to prelaunch). Stub at `EnsureRoot` until
		/// the SRT pallet lands.
		// TODO(srt): retarget at `pallet-rostro-security-response-team`
		type SecurityResponseTeamOrigin: EnsureOrigin<Self::RuntimeOrigin>;
	}

	/// On-chain map of role marker → canonical type fingerprint.
	///
	/// Source of truth for `rostro-client`'s recognizer. A type whose computed
	/// fingerprint matches an entry here is canonically that role; any other
	/// claim is unauthenticated and falls back to generic SCALE decoding.
	#[pallet::storage]
	pub type WellKnownTypeFingerprints<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		BoundedVec<u8, ConstU32<MAX_ROLE_LEN>>,
		[u8; 32],
		OptionQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A canonical role fingerprint was registered or updated.
		FingerprintRegistered { role: Vec<u8>, fingerprint: [u8; 32] },
		/// A canonical role fingerprint was removed.
		FingerprintRemoved { role: Vec<u8> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Role marker exceeds `MAX_ROLE_LEN`.
		RoleTooLong,
		/// No fingerprint registered for the supplied role.
		RoleNotFound,
	}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		/// Additional `(role, fingerprint)` pairs to seed beyond the v0 default
		/// set. Most chains leave this empty — the v0 set covers the well-known
		/// Substrate roles and is unconditionally seeded.
		pub additional_fingerprints: Vec<(Vec<u8>, [u8; 32])>,
		#[serde(skip)]
		pub _config: core::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			// v0 default seed: the seven canonical Substrate-flavored roles.
			let v0_seed: [(&[u8], &[u8]); 7] = [
				(roles::ACCOUNT, canonical_defs::ACCOUNT_ID_32),
				(roles::HASH, canonical_defs::HASH_32),
				(roles::ERA, canonical_defs::ERA),
				(roles::MULTIADDRESS, canonical_defs::MULTIADDRESS),
				(roles::WEIGHT, canonical_defs::WEIGHT),
				(roles::BALANCE, canonical_defs::BALANCE_U128),
				(roles::BLOCK_NUMBER, canonical_defs::BLOCK_NUMBER_U32),
			];

			for (role, def) in v0_seed.iter() {
				let fp = super::fingerprint(def, role, FINGERPRINT_VERSION);
				let key: BoundedVec<u8, ConstU32<MAX_ROLE_LEN>> =
					BoundedVec::try_from(role.to_vec())
						.expect("v0 seed roles fit in MAX_ROLE_LEN; qed");
				WellKnownTypeFingerprints::<T>::insert(&key, fp);
			}

			// Genesis-supplied additions (chain-spec extension).
			for (role, fp) in self.additional_fingerprints.iter() {
				let key: BoundedVec<u8, ConstU32<MAX_ROLE_LEN>> =
					BoundedVec::try_from(role.clone()).expect("chain spec role fits; qed");
				WellKnownTypeFingerprints::<T>::insert(&key, fp);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register or replace the fingerprint for a role. SRT-gated.
		///
		/// Use case: governance-approved migration where a canonical type
		/// changes shape (e.g. Weight v1 → v2). The fingerprint is recomputed
		/// off-chain from the new canonical_def + role + bumped version, then
		/// installed via this call.
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(10_000, 0))]
		pub fn register_fingerprint(
			origin: OriginFor<T>,
			role: Vec<u8>,
			fingerprint: [u8; 32],
		) -> DispatchResult {
			T::SecurityResponseTeamOrigin::ensure_origin(origin)?;
			let key: BoundedVec<u8, ConstU32<MAX_ROLE_LEN>> =
				BoundedVec::try_from(role.clone()).map_err(|_| Error::<T>::RoleTooLong)?;
			WellKnownTypeFingerprints::<T>::insert(&key, fingerprint);
			Self::deposit_event(Event::FingerprintRegistered { role, fingerprint });
			Ok(())
		}

		/// Remove a role's fingerprint. SRT-gated.
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(10_000, 0))]
		pub fn remove_fingerprint(origin: OriginFor<T>, role: Vec<u8>) -> DispatchResult {
			T::SecurityResponseTeamOrigin::ensure_origin(origin)?;
			let key: BoundedVec<u8, ConstU32<MAX_ROLE_LEN>> =
				BoundedVec::try_from(role.clone()).map_err(|_| Error::<T>::RoleTooLong)?;
			ensure!(
				WellKnownTypeFingerprints::<T>::take(&key).is_some(),
				Error::<T>::RoleNotFound
			);
			Self::deposit_event(Event::FingerprintRemoved { role });
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The fingerprint of an account-shaped 32-byte type must NOT collide with
	/// the fingerprint of a hash-shaped 32-byte type, even though both have
	/// identical structural definitions. This is the core anti-shape-collision
	/// property of the recognizer architecture.
	#[test]
	fn account_and_hash_fingerprints_diverge() {
		let acc = fingerprint(canonical_defs::ACCOUNT_ID_32, roles::ACCOUNT, FINGERPRINT_VERSION);
		let hash = fingerprint(canonical_defs::HASH_32, roles::HASH, FINGERPRINT_VERSION);
		assert_ne!(acc, hash, "shape-equivalent types must fingerprint to different roles");
	}

	#[test]
	fn fingerprint_is_deterministic() {
		let a = fingerprint(b"u128", b"balance", 1);
		let b = fingerprint(b"u128", b"balance", 1);
		assert_eq!(a, b);
	}

	#[test]
	fn version_bump_changes_fingerprint() {
		let v1 = fingerprint(b"u128", b"balance", 1);
		let v2 = fingerprint(b"u128", b"balance", 2);
		assert_ne!(v1, v2, "version bump must produce distinct fingerprint");
	}
}
