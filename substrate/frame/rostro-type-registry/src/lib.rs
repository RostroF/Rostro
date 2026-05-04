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

/// The seven well-known v0 roles paired with their canonical structural
/// definitions. Source of truth for both genesis seeding and the runtime-upgrade
/// gate; keeping them in one place ensures the two invariants can never drift.
pub const V0_WELL_KNOWN_ROLES: [(&[u8], &[u8]); 7] = [
	(roles::ACCOUNT, canonical_defs::ACCOUNT_ID_32),
	(roles::HASH, canonical_defs::HASH_32),
	(roles::ERA, canonical_defs::ERA),
	(roles::MULTIADDRESS, canonical_defs::MULTIADDRESS),
	(roles::WEIGHT, canonical_defs::WEIGHT),
	(roles::BALANCE, canonical_defs::BALANCE_U128),
	(roles::BLOCK_NUMBER, canonical_defs::BLOCK_NUMBER_U32),
];

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
		/// Role marker is empty. Roles are protocol identifiers and the empty
		/// string is semantically meaningless; rejected as a known-invalid
		/// sentinel.
		EmptyRole,
		/// Fingerprint is the all-zero 32-byte sentinel. blake2_256 of any
		/// real canonical_def input does not produce this; accepting it would
		/// install a value that recomputation can never match, permanently
		/// bricking the role's gate.
		ZeroFingerprint,
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
			for (role, def) in super::V0_WELL_KNOWN_ROLES.iter() {
				let fp = super::fingerprint(def, role, FINGERPRINT_VERSION);
				let key: BoundedVec<u8, ConstU32<MAX_ROLE_LEN>> =
					BoundedVec::try_from(role.to_vec())
						.expect("v0 seed roles fit in MAX_ROLE_LEN; qed");
				WellKnownTypeFingerprints::<T>::insert(&key, fp);
			}

			// Genesis-supplied additions (chain-spec extension). Same
			// known-invalid-sentinel rejections as the SRT-gated extrinsic;
			// chain-spec input is not a trusted boundary.
			for (role, fp) in self.additional_fingerprints.iter() {
				assert!(!role.is_empty(), "chain spec must not supply empty role");
				assert!(
					fp != &[0u8; 32],
					"chain spec must not supply all-zero fingerprint for role {:?}",
					role
				);
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
			ensure!(!role.is_empty(), Error::<T>::EmptyRole);
			ensure!(fingerprint != [0u8; 32], Error::<T>::ZeroFingerprint);
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
			ensure!(!role.is_empty(), Error::<T>::EmptyRole);
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

/// Runtime-upgrade-time guards. Wire `EnforceWellKnownFingerprints` into
/// `frame_system::Config::SingleBlockMigrations` to make every runtime upgrade
/// fail closed if the new binary's compile-time canonical types diverge from
/// the fingerprints already anchored on chain.
pub mod migrations {
	use super::*;
	use frame_support::{
		traits::OnRuntimeUpgrade,
		weights::Weight,
	};

	/// Result of comparing one role's recomputed fingerprint against the
	/// on-chain entry. `Match` and `Healed` are non-fatal; `Mismatch` is the
	/// signal a runtime upgrade should reject.
	#[derive(Debug, PartialEq, Eq)]
	pub enum RoleCheck {
		/// On-chain entry exists and equals the recomputed fingerprint.
		Match,
		/// On-chain entry was missing (pallet just added via upgrade) and was
		/// seeded with the recomputed fingerprint.
		Healed,
		/// On-chain entry exists but disagrees with the recomputed fingerprint.
		/// The upgrade must be rejected.
		Mismatch { stored: [u8; 32], expected: [u8; 32] },
	}

	/// Pure decision function: given a role's stored fingerprint (or absence)
	/// and the recomputed expected value, decide what action to take. Extracted
	/// from the storage-backed migration so it can be unit-tested without a
	/// mock runtime.
	pub fn classify_role(stored: Option<[u8; 32]>, expected: [u8; 32]) -> RoleCheck {
		match stored {
			None => RoleCheck::Healed,
			Some(s) if s == expected => RoleCheck::Match,
			Some(s) => RoleCheck::Mismatch { stored: s, expected },
		}
	}

	/// Runtime-upgrade gate. Iterates every v0 well-known role, recomputes its
	/// fingerprint from the *current binary's* canonical_def, and compares to
	/// the on-chain entry:
	/// - missing → seeded (handles the migration-onto-existing-chain case)
	/// - matching → no-op
	/// - mismatching → panic, which fails the block carrying the upgrade
	///
	/// Legitimate canonical-type version bumps land by ordering an SRT-gated
	/// `register_fingerprint` migration *before* this gate in the migration
	/// tuple, so the on-chain entry is updated to the new value before the
	/// comparison runs.
	pub struct EnforceWellKnownFingerprints<T>(core::marker::PhantomData<T>);

	impl<T: Config> OnRuntimeUpgrade for EnforceWellKnownFingerprints<T> {
		fn on_runtime_upgrade() -> Weight {
			let mut reads = 0u64;
			let mut writes = 0u64;

			for (role, def) in V0_WELL_KNOWN_ROLES.iter() {
				let expected = fingerprint(def, role, FINGERPRINT_VERSION);
				let key: BoundedVec<u8, ConstU32<MAX_ROLE_LEN>> =
					BoundedVec::try_from(role.to_vec())
						.expect("v0 well-known role fits in MAX_ROLE_LEN; qed");

				let stored = pallet::WellKnownTypeFingerprints::<T>::get(&key);
				reads += 1;

				match classify_role(stored, expected) {
					RoleCheck::Match => {},
					RoleCheck::Healed => {
						pallet::WellKnownTypeFingerprints::<T>::insert(&key, expected);
						writes += 1;
					},
					RoleCheck::Mismatch { stored, expected } => {
						log::error!(
							target: "runtime::rostro-type-registry",
							"well-known role {:?} fingerprint mismatch — stored=0x{} expected=0x{}",
							role,
							hex_fmt(&stored),
							hex_fmt(&expected),
						);
						panic!(
							"rostro-type-registry: well-known role fingerprint mismatch — \
							 runtime upgrade rejected"
						);
					},
				}
			}

			T::DbWeight::get().reads_writes(reads, writes)
		}
	}

	fn hex_fmt(bytes: &[u8; 32]) -> alloc::string::String {
		use alloc::string::String;
		let mut out = String::with_capacity(64);
		for b in bytes.iter() {
			out.push(nibble(b >> 4));
			out.push(nibble(b & 0x0f));
		}
		out
	}

	const fn nibble(n: u8) -> char {
		match n {
			0..=9 => (b'0' + n) as char,
			_ => (b'a' + n - 10) as char,
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

	mod gate {
		use super::super::migrations::{classify_role, RoleCheck};

		const A: [u8; 32] = [0xAA; 32];
		const B: [u8; 32] = [0xBB; 32];

		#[test]
		fn match_when_stored_equals_expected() {
			assert_eq!(classify_role(Some(A), A), RoleCheck::Match);
		}

		#[test]
		fn heals_when_storage_missing() {
			assert_eq!(classify_role(None, A), RoleCheck::Healed);
		}

		#[test]
		fn mismatch_signals_rejection() {
			assert_eq!(
				classify_role(Some(A), B),
				RoleCheck::Mismatch { stored: A, expected: B },
			);
		}

		#[test]
		fn v0_seed_recomputes_to_distinct_values() {
			use super::super::{fingerprint, FINGERPRINT_VERSION, V0_WELL_KNOWN_ROLES};
			let mut seen = std::collections::HashSet::new();
			for (role, def) in V0_WELL_KNOWN_ROLES.iter() {
				let fp = fingerprint(def, role, FINGERPRINT_VERSION);
				assert!(seen.insert(fp), "v0 fingerprints must be globally distinct");
			}
		}
	}

	mod validation {
		use crate as pallet_rostro_type_registry;
		use crate::pallet::Error;
		use frame_support::{assert_noop, assert_ok, derive_impl};
		use frame_system::EnsureRoot;
		use sp_core::H256;
		use sp_runtime::{
			traits::{BlakeTwo256, IdentityLookup},
			BuildStorage,
		};

		type AccountId = u64;
		type Block = frame_system::mocking::MockBlock<Test>;

		frame_support::construct_runtime!(
			pub enum Test {
				System: frame_system,
				TypeRegistry: pallet_rostro_type_registry,
			}
		);

		#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
		impl frame_system::Config for Test {
			type Block = Block;
			type AccountId = AccountId;
			type Lookup = IdentityLookup<Self::AccountId>;
			type Hash = H256;
			type Hashing = BlakeTwo256;
			type AccountData = ();
		}

		impl pallet_rostro_type_registry::Config for Test {
			type SecurityResponseTeamOrigin = EnsureRoot<AccountId>;
		}

		fn new_test_ext() -> sp_io::TestExternalities {
			let t = frame_system::GenesisConfig::<Test>::default()
				.build_storage()
				.unwrap();
			let mut ext = sp_io::TestExternalities::new(t);
			ext.execute_with(|| System::set_block_number(1));
			ext
		}

		#[test]
		fn register_rejects_empty_role() {
			new_test_ext().execute_with(|| {
				assert_noop!(
					TypeRegistry::register_fingerprint(
						frame_system::RawOrigin::Root.into(),
						alloc::vec![],
						[0xAB; 32],
					),
					Error::<Test>::EmptyRole,
				);
			});
		}

		#[test]
		fn register_rejects_zero_fingerprint() {
			new_test_ext().execute_with(|| {
				assert_noop!(
					TypeRegistry::register_fingerprint(
						frame_system::RawOrigin::Root.into(),
						b"new-role".to_vec(),
						[0u8; 32],
					),
					Error::<Test>::ZeroFingerprint,
				);
			});
		}

		#[test]
		fn register_rejects_role_too_long() {
			new_test_ext().execute_with(|| {
				let too_long = alloc::vec![b'x'; (super::super::MAX_ROLE_LEN as usize) + 1];
				assert_noop!(
					TypeRegistry::register_fingerprint(
						frame_system::RawOrigin::Root.into(),
						too_long,
						[0xAB; 32],
					),
					Error::<Test>::RoleTooLong,
				);
			});
		}

		#[test]
		fn register_accepts_valid_input() {
			new_test_ext().execute_with(|| {
				assert_ok!(TypeRegistry::register_fingerprint(
					frame_system::RawOrigin::Root.into(),
					b"new-role".to_vec(),
					[0xAB; 32],
				));
			});
		}

		#[test]
		fn remove_rejects_empty_role() {
			new_test_ext().execute_with(|| {
				assert_noop!(
					TypeRegistry::remove_fingerprint(
						frame_system::RawOrigin::Root.into(),
						alloc::vec![],
					),
					Error::<Test>::EmptyRole,
				);
			});
		}
	}
}
