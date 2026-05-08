// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro Canonical Files
//!
//! On-chain registry of canonical foundation-file hashes. Native nodes verify
//! their own foundation files at boot against the entries here; mismatches
//! fail-stop. The chain refuses to participate in a network whose nodes are
//! running modified foundation code.
//!
//! ## Strip-mall enforcement boundary
//!
//! Per the Rostro architecture commitment ("modify your shop, not the
//! foundation"), this pallet enforces the *foundation* files only:
//!
//! - The canonical node binary (when hardware attestation is online; until
//!   then operator-side self-check, which catches honest mistakes but not
//!   adversarial modification)
//! - The canonical foundation runtime WASM blob
//! - Foundation library artifacts shipped alongside the binary
//!
//! Operator-added pallets / extensions are out of scope here. They have
//! their own state-isolation defenses (per-pallet write-authorization,
//! tracked separately).
//!
//! ## Why a flat StorageMap rather than the Merkle tree directly
//!
//! The Merkle tree is the verifier's local construction, not the on-chain
//! representation. Storing per-leaf entries (path → hash) gives:
//!
//! - O(1) per-file lookup at boot (the verifier doesn't need the tree to
//!   answer "is this single file canonical?")
//! - Trivial per-file revocation via SRT (replace one entry, no rebalancing)
//! - Cleaner SRT update extrinsic semantics (set_file vs replace-the-whole-tree)
//!
//! The verifier composes its own Merkle tree from the leaves, hashes its
//! local file tree, and on root mismatch walks down to find the divergent
//! file. The tree shape is implementation detail of the verifier; the
//! pallet just owns the canonical leaves.
//!
//! ## Mirrors the rpc-method-policy / type-registry pattern
//!
//! Same shape as `pallet-rostro-rpc-method-policy` and
//! `pallet-rostro-type-registry`: storage map, SRT-gated extrinsics for
//! mutation, genesis seed for v0 entries (empty initially — the foundation
//! adds canonical hashes via the post-genesis SRT extrinsic as releases
//! land), runtime API exposing per-file lookup + the bulk iterator.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

use alloc::vec::Vec;
use frame_support::pallet_prelude::*;

/// Maximum length in bytes for a canonical file path.
///
/// Foundation file paths are short, well-known strings (e.g.
/// "gemini-node", "gemini-runtime.wasm"). Cap generously at 256 to
/// leave room for nested paths in future iterations
/// ("foundation/runtime/v3.wasm") without forcing a parameter-bump
/// migration.
pub const MAX_FILE_PATH_LEN: u32 = 256;

/// Minimum file path length. Empty paths are obviously invalid;
/// single-char paths are too sparse to be self-describing. 3 is the
/// floor below which a path can't be a meaningful identifier.
pub const MIN_FILE_PATH_LEN: u32 = 3;

/// Maximum number of `(path, hash)` pairs a chain spec may supply via
/// `GenesisConfig::initial_files`. Capped to prevent a hostile fork
/// chain spec from DoS'ing genesis import. The legitimate v0 set is
/// expected to be well under 32.
pub const MAX_INITIAL_FILES: usize = 256;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Origin permitted to mutate canonical-file entries
		/// post-genesis. In production this resolves to the Security
		/// Response Team (`pallet-rostro-security-response-team`,
		/// deferred to prelaunch). Stub at `EnsureRoot` until the
		/// SRT pallet lands.
		// TODO(srt): retarget at `pallet-rostro-security-response-team`
		type SecurityResponseTeamOrigin: EnsureOrigin<Self::RuntimeOrigin>;
	}

	/// On-chain map of canonical foundation-file path → blake2_256 hash.
	///
	/// Source of truth for the native verifier's boot self-check. A
	/// file present here MUST hash to the registered value; mismatch
	/// is fail-stop. A file absent here is operator-supplied and
	/// not verified by the foundation gate.
	#[pallet::storage]
	pub type CanonicalFiles<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		BoundedVec<u8, ConstU32<MAX_FILE_PATH_LEN>>,
		[u8; 32],
		OptionQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A canonical file's hash was registered or updated.
		FileRegistered { path: Vec<u8>, hash: [u8; 32] },
		/// A canonical file entry was removed (operator's local copy
		/// of that file is now operator-responsibility, not foundation-
		/// verified).
		FileRemoved { path: Vec<u8> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// File path exceeds `MAX_FILE_PATH_LEN`.
		PathTooLong,
		/// File path shorter than `MIN_FILE_PATH_LEN`. Single- and
		/// two-byte paths are too terse to be self-describing.
		PathTooShort,
		/// File path contains a NUL byte. Paths are ASCII / UTF-8
		/// strings; embedded NULs are malformed at best, parse-confusion
		/// attempts at worst.
		PathContainsNul,
		/// Hash is the all-zero 32-byte sentinel. blake2_256 of any
		/// nonempty input does not produce zero; accepting it would
		/// install a value the verifier can never legitimately match,
		/// permanently bricking the file's gate.
		ZeroHash,
		/// No entry registered for the supplied path.
		FileNotFound,
	}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		/// Initial `(path, hash)` pairs to seed at genesis. Most
		/// chains will leave this empty: foundation file hashes get
		/// added post-genesis via the SRT extrinsic as the foundation
		/// publishes signed releases. A non-empty seed is for testing
		/// or for forks that bake their own canonical set in.
		pub initial_files: Vec<(Vec<u8>, [u8; 32])>,
		#[serde(skip)]
		pub _config: core::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			assert!(
				self.initial_files.len() <= MAX_INITIAL_FILES,
				"initial_files exceeds MAX_INITIAL_FILES ({})",
				MAX_INITIAL_FILES
			);

			for (path, hash) in self.initial_files.iter() {
				assert!(
					path.len() >= MIN_FILE_PATH_LEN as usize,
					"chain spec file path {:?} shorter than MIN_FILE_PATH_LEN ({})",
					path,
					MIN_FILE_PATH_LEN
				);
				assert!(
					path.len() <= MAX_FILE_PATH_LEN as usize,
					"chain spec file path {:?} exceeds MAX_FILE_PATH_LEN ({})",
					path,
					MAX_FILE_PATH_LEN
				);
				assert!(
					!path.contains(&0u8),
					"chain spec file path {:?} contains NUL",
					path
				);
				assert!(
					hash != &[0u8; 32],
					"chain spec must not supply zero-hash for file {:?}",
					path
				);
				let key: BoundedVec<u8, ConstU32<MAX_FILE_PATH_LEN>> =
					BoundedVec::try_from(path.clone())
						.expect("path length already checked; qed");
				CanonicalFiles::<T>::insert(&key, hash);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register or replace the canonical hash for a file. SRT-gated.
		///
		/// Use case: foundation publishes a signed binary release;
		/// SRT extrinsic registers the new build's hash. Existing
		/// nodes upgrade to the new binary (manually or via the
		/// installer) and pass the boot self-check against the new
		/// canonical hash.
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(10_000, 0))]
		pub fn register_file(
			origin: OriginFor<T>,
			path: Vec<u8>,
			hash: [u8; 32],
		) -> DispatchResult {
			T::SecurityResponseTeamOrigin::ensure_origin(origin)?;
			ensure!(path.len() >= MIN_FILE_PATH_LEN as usize, Error::<T>::PathTooShort);
			ensure!(!path.contains(&0u8), Error::<T>::PathContainsNul);
			ensure!(hash != [0u8; 32], Error::<T>::ZeroHash);
			let key: BoundedVec<u8, ConstU32<MAX_FILE_PATH_LEN>> =
				BoundedVec::try_from(path.clone()).map_err(|_| Error::<T>::PathTooLong)?;
			CanonicalFiles::<T>::insert(&key, hash);
			Self::deposit_event(Event::FileRegistered { path, hash });
			Ok(())
		}

		/// Remove a canonical file entry. SRT-gated.
		///
		/// Use case: a foundation file is retired (e.g., a deprecated
		/// helper crate gets removed in the next release); the SRT
		/// removes its entry so future verifiers don't enforce a
		/// hash for a file that no longer exists.
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(10_000, 0))]
		pub fn remove_file(origin: OriginFor<T>, path: Vec<u8>) -> DispatchResult {
			T::SecurityResponseTeamOrigin::ensure_origin(origin)?;
			ensure!(path.len() >= MIN_FILE_PATH_LEN as usize, Error::<T>::PathTooShort);
			ensure!(!path.contains(&0u8), Error::<T>::PathContainsNul);
			let key: BoundedVec<u8, ConstU32<MAX_FILE_PATH_LEN>> =
				BoundedVec::try_from(path.clone()).map_err(|_| Error::<T>::PathTooLong)?;
			ensure!(
				CanonicalFiles::<T>::take(&key).is_some(),
				Error::<T>::FileNotFound
			);
			Self::deposit_event(Event::FileRemoved { path });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Read the canonical hash for `path`. Returns `None` if
		/// the path isn't registered or if the supplied path exceeds
		/// `MAX_FILE_PATH_LEN`.
		pub fn hash_for(path: &[u8]) -> Option<[u8; 32]> {
			let key: BoundedVec<u8, ConstU32<MAX_FILE_PATH_LEN>> =
				BoundedVec::try_from(path.to_vec()).ok()?;
			CanonicalFiles::<T>::get(&key)
		}

		/// Iterator over all canonical file entries. Used by the
		/// native verifier to bootstrap its local Merkle-tree
		/// reconstruction.
		pub fn all_files() -> Vec<(Vec<u8>, [u8; 32])> {
			CanonicalFiles::<T>::iter()
				.map(|(k, v)| (k.into_inner(), v))
				.collect()
		}
	}
}

/// Runtime API exposed for the native node-side verifier to query
/// canonical-file hashes from the host side. Called via
/// `client.runtime_api().{hash_for, all_files}(at)` — host-side, no
/// JSON-RPC trip. Also reachable from outside via `state_call`,
/// classified PublicGated by `pallet-rostro-rpc-method-policy`'s v0
/// seed (added to V0_WELL_KNOWN_POLICIES alongside the existing
/// runtime API entries).
sp_api::decl_runtime_apis! {
	pub trait CanonicalFilesApi {
		/// Look up the canonical hash for a single file path.
		/// Returns `None` if the file isn't registered.
		fn hash_for(path: Vec<u8>) -> Option<[u8; 32]>;

		/// Iterate the full canonical-file table. Bounded by storage
		/// entry count; intended for the verifier's startup
		/// bootstrap of its local Merkle tree.
		fn all_files() -> Vec<(Vec<u8>, [u8; 32])>;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate as pallet_rostro_canonical_files;
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
			CanonicalFiles: pallet_rostro_canonical_files,
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

	impl pallet_rostro_canonical_files::Config for Test {
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

	fn key(s: &[u8]) -> BoundedVec<u8, ConstU32<MAX_FILE_PATH_LEN>> {
		BoundedVec::try_from(s.to_vec()).unwrap()
	}

	#[test]
	fn register_rejects_too_short_path() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				CanonicalFiles::register_file(
					frame_system::RawOrigin::Root.into(),
					b"ab".to_vec(),
					[0xAB; 32],
				),
				Error::<Test>::PathTooShort,
			);
		});
	}

	#[test]
	fn register_rejects_path_with_nul() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				CanonicalFiles::register_file(
					frame_system::RawOrigin::Root.into(),
					b"foo\0bar".to_vec(),
					[0xAB; 32],
				),
				Error::<Test>::PathContainsNul,
			);
		});
	}

	#[test]
	fn register_rejects_zero_hash() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				CanonicalFiles::register_file(
					frame_system::RawOrigin::Root.into(),
					b"gemini-node".to_vec(),
					[0u8; 32],
				),
				Error::<Test>::ZeroHash,
			);
		});
	}

	#[test]
	fn register_rejects_path_too_long() {
		new_test_ext().execute_with(|| {
			let too_long = alloc::vec![b'x'; (MAX_FILE_PATH_LEN as usize) + 1];
			assert_noop!(
				CanonicalFiles::register_file(
					frame_system::RawOrigin::Root.into(),
					too_long,
					[0xAB; 32],
				),
				Error::<Test>::PathTooLong,
			);
		});
	}

	#[test]
	fn register_then_lookup_roundtrips() {
		new_test_ext().execute_with(|| {
			let path = b"gemini-node".to_vec();
			let hash = [0xAB; 32];
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				path.clone(),
				hash,
			));
			assert_eq!(crate::pallet::Pallet::<Test>::hash_for(&path), Some(hash));
		});
	}

	#[test]
	fn register_overwrites_existing() {
		// SRT replacing an existing entry (e.g., new release) is
		// the legitimate update path. Verify it works without
		// requiring an explicit remove first.
		new_test_ext().execute_with(|| {
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-node".to_vec(),
				[0x01; 32],
			));
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-node".to_vec(),
				[0x02; 32],
			));
			assert_eq!(
				crate::pallet::Pallet::<Test>::hash_for(b"gemini-node"),
				Some([0x02; 32]),
			);
		});
	}

	#[test]
	fn remove_clears_entry() {
		new_test_ext().execute_with(|| {
			let path = b"gemini-node".to_vec();
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				path.clone(),
				[0xAB; 32],
			));
			assert_ok!(CanonicalFiles::remove_file(
				frame_system::RawOrigin::Root.into(),
				path.clone(),
			));
			assert_eq!(crate::pallet::Pallet::<Test>::hash_for(&path), None);
		});
	}

	#[test]
	fn remove_rejects_not_found() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				CanonicalFiles::remove_file(
					frame_system::RawOrigin::Root.into(),
					b"never-registered".to_vec(),
				),
				Error::<Test>::FileNotFound,
			);
		});
	}

	#[test]
	fn all_files_returns_all_entries() {
		new_test_ext().execute_with(|| {
			let entries = [
				(b"gemini-node".to_vec(), [0x01; 32]),
				(b"gemini-runtime.wasm".to_vec(), [0x02; 32]),
				(b"chain-spec.json".to_vec(), [0x03; 32]),
			];
			for (p, h) in entries.iter() {
				assert_ok!(CanonicalFiles::register_file(
					frame_system::RawOrigin::Root.into(),
					p.clone(),
					*h,
				));
			}
			let mut got = crate::pallet::Pallet::<Test>::all_files();
			got.sort_by(|a, b| a.0.cmp(&b.0));
			let mut expected: Vec<_> = entries.to_vec();
			expected.sort_by(|a, b| a.0.cmp(&b.0));
			assert_eq!(got, expected);
		});
	}

	#[test]
	fn genesis_seeds_initial_files() {
		let initial = alloc::vec![
			(b"gemini-node".to_vec(), [0x01; 32]),
			(b"gemini-runtime.wasm".to_vec(), [0x02; 32]),
		];
		let genesis = crate::pallet::GenesisConfig::<Test> {
			initial_files: initial.clone(),
			_config: core::marker::PhantomData,
		};
		let mut t = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap();
		genesis.assimilate_storage(&mut t).unwrap();
		let mut ext = sp_io::TestExternalities::new(t);
		ext.execute_with(|| {
			for (p, h) in initial.iter() {
				assert_eq!(
					crate::pallet::CanonicalFiles::<Test>::get(&key(p)),
					Some(*h),
				);
			}
		});
	}

	#[test]
	#[should_panic(expected = "shorter than MIN_FILE_PATH_LEN")]
	fn genesis_panics_on_too_short_path() {
		let genesis = crate::pallet::GenesisConfig::<Test> {
			initial_files: alloc::vec![(b"ab".to_vec(), [0x01; 32])],
			_config: core::marker::PhantomData,
		};
		let mut t = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap();
		genesis.assimilate_storage(&mut t).unwrap();
		let _ext = sp_io::TestExternalities::new(t);
	}

	#[test]
	#[should_panic(expected = "must not supply zero-hash")]
	fn genesis_panics_on_zero_hash() {
		let genesis = crate::pallet::GenesisConfig::<Test> {
			initial_files: alloc::vec![(b"gemini-node".to_vec(), [0u8; 32])],
			_config: core::marker::PhantomData,
		};
		let mut t = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap();
		genesis.assimilate_storage(&mut t).unwrap();
		let _ext = sp_io::TestExternalities::new(t);
	}

	#[test]
	fn hash_for_returns_none_when_path_too_long() {
		// Defensive: oversized path can't be a valid key, so the
		// helper returns None rather than erroring. The verifier
		// treats absent entries as "not foundation-canonical, operator
		// responsibility" — so an oversized lookup naturally falls
		// through.
		new_test_ext().execute_with(|| {
			let too_long = alloc::vec![b'x'; (MAX_FILE_PATH_LEN as usize) + 1];
			assert_eq!(crate::pallet::Pallet::<Test>::hash_for(&too_long), None);
		});
	}
}
