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

	/// The current `rostro_release` ed25519 pubkey — the SRT-controlled
	/// signing identity for Foundation release manifests. Watchdog
	/// recovery (piece B.1) verifies the SRT-signed manifest on the
	/// canonical-cache against a compile-time-baked copy of this
	/// pubkey; the on-chain value is the **verification reference**
	/// the watchdog reconciles its baked copy against periodically
	/// (piece B.1-bis). Divergence between baked and on-chain is a
	/// real signal — see [[feedback_trust_but_verify_baked_plus_onchain]].
	///
	/// `None` = pubkey not yet set (genesis without
	/// `initial_release_pubkey`). Once set, rotation goes through
	/// `set_release_pubkey` (SRT-gated). Stored bytes are the raw
	/// 32-byte ed25519 public key, NOT an SSH-format-wrapped
	/// representation.
	#[pallet::storage]
	pub type ReleasePubkey<T: Config> = StorageValue<_, [u8; 32], OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A canonical file's hash was registered or updated.
		FileRegistered { path: Vec<u8>, hash: [u8; 32] },
		/// A canonical file entry was removed (operator's local copy
		/// of that file is now operator-responsibility, not foundation-
		/// verified).
		FileRemoved { path: Vec<u8> },
		/// The `rostro_release` ed25519 pubkey was set or rotated.
		/// Watchdog reconciliation threads pick this up on their next
		/// poll and compare against their compile-time-baked copy.
		ReleasePubkeyUpdated { pubkey: [u8; 32] },
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
		/// Initial `rostro_release` ed25519 pubkey to seed at genesis.
		/// `None` = pubkey will be set post-genesis via SRT extrinsic.
		/// `Some(pubkey)` = bakes the lab/release pubkey into genesis
		/// state so the chain-side reconciliation reference is present
		/// from block 0. The zero-pubkey `[0u8; 32]` is rejected at
		/// build (same threat-model rationale as `register_file`'s
		/// `ZeroHash` rejection — the all-zero ed25519 point isn't a
		/// legitimate pubkey).
		pub initial_release_pubkey: Option<[u8; 32]>,
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

			if let Some(pubkey) = self.initial_release_pubkey {
				assert!(
					pubkey != [0u8; 32],
					"initial_release_pubkey must not be the all-zero sentinel"
				);
				ReleasePubkey::<T>::put(pubkey);
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

		/// Set or rotate the `rostro_release` ed25519 pubkey. SRT-gated.
		///
		/// Use case: Foundation rotates its release-signing key (routine
		/// schedule, compromise response, or quorum change in the SRT
		/// itself). Watchdog reconciliation threads pick up the new
		/// value on their next poll and compare against their compile-
		/// time-baked copy; divergence is a real signal — either the
		/// node's binary is stale or the chain saw a key rotation the
		/// node hasn't caught up to yet.
		///
		/// Rejects the all-zero sentinel for the same threat-model reason
		/// `register_file` rejects all-zero hashes: an attacker-controlled
		/// "set pubkey to zero" would brick recovery against any genuine
		/// signed manifest going forward.
		#[pallet::call_index(2)]
		#[pallet::weight(Weight::from_parts(10_000, 0))]
		pub fn set_release_pubkey(
			origin: OriginFor<T>,
			pubkey: [u8; 32],
		) -> DispatchResult {
			T::SecurityResponseTeamOrigin::ensure_origin(origin)?;
			ensure!(pubkey != [0u8; 32], Error::<T>::ZeroHash);
			ReleasePubkey::<T>::put(pubkey);
			Self::deposit_event(Event::ReleasePubkeyUpdated { pubkey });
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

		/// Read the current `rostro_release` ed25519 pubkey, or `None`
		/// if not yet set. The watchdog's reconciliation thread polls
		/// this and compares to its compile-time-baked copy.
		pub fn release_pubkey() -> Option<[u8; 32]> {
			ReleasePubkey::<T>::get()
		}

		/// Compute the canonical Merkle root over all registered
		/// `(path, hash)` entries.
		///
		/// Used by the Phase 7b network-edge attestation flow: peers
		/// compare their locally-computed root against this on-chain
		/// canonical root in O(1) before drilling into per-file
		/// diffs. A divergent root tells you *something* in your
		/// foundation fileset is wrong; the leaf walk
		/// (`hash_for` / `all_files`) localizes *which* file.
		///
		/// Empty registry returns `[0u8; 32]`.
		///
		/// Construction (see free fns `leaf_hash` / `node_hash`):
		///
		/// - Leaves are SCALE-encoded `(path, hash)` tuples, blake2_256
		///   hashed under a `LEAF_TAG` byte.
		/// - Internal nodes blake2_256 their two children under a
		///   `NODE_TAG` byte.
		/// - Domain separation between leaves and nodes prevents any
		///   leaf from being structurally indistinguishable from an
		///   internal node (closes the second-preimage class flagged
		///   on naive Merkle constructions).
		/// - Leaves are sorted lexicographically by path before
		///   tree-building, so the root is purely a function of the
		///   stored set, not insertion order.
		/// - Odd-sized layers duplicate the last child. This is safe
		///   here because the leaf set comes from on-chain storage
		///   iteration; no attacker can append a phantom (n+1)-th
		///   leaf to claim a different root.
		pub fn canonical_root() -> [u8; 32] {
			let mut entries: Vec<(Vec<u8>, [u8; 32])> = CanonicalFiles::<T>::iter()
				.map(|(k, v)| (k.into_inner(), v))
				.collect();
			entries.sort_by(|a, b| a.0.cmp(&b.0));
			merkle_root_of(&entries)
		}
	}
}

/// Domain-separation tag for leaf hashes in [`merkle_root_of`].
const LEAF_TAG: u8 = 0x00;

/// Domain-separation tag for internal-node hashes in [`merkle_root_of`].
const NODE_TAG: u8 = 0x01;

/// Hash a single `(path, hash)` leaf. SCALE-encodes the pair (so the
/// length-prefix on `path` is part of the hash and a path of bytes
/// `b"foo" || b"bar"` cannot collide with two paths `b"foo"` and
/// `b"bar"`), then prefixes the encoded payload with [`LEAF_TAG`].
pub fn leaf_hash(path: &[u8], file_hash: &[u8; 32]) -> [u8; 32] {
	use codec::Encode;
	let payload = (path, file_hash).encode();
	let mut buf = alloc::vec::Vec::with_capacity(1 + payload.len());
	buf.push(LEAF_TAG);
	buf.extend_from_slice(&payload);
	sp_io::hashing::blake2_256(&buf)
}

/// Hash a pair of children into their parent. Fixed 65-byte buffer
/// (1 tag + 32 left + 32 right), no allocation.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	let mut buf = [0u8; 65];
	buf[0] = NODE_TAG;
	buf[1..33].copy_from_slice(left);
	buf[33..65].copy_from_slice(right);
	sp_io::hashing::blake2_256(&buf)
}

/// Compute the Merkle root over an already-sorted slice of
/// `(path, hash)` entries. Exposed at module level so the native
/// verifier can call the same function over its locally-computed
/// fileset and compare against `Pallet::canonical_root()` without
/// pulling in `frame-system`.
///
/// Empty input returns `[0u8; 32]`.
pub fn merkle_root_of(entries: &[(alloc::vec::Vec<u8>, [u8; 32])]) -> [u8; 32] {
	if entries.is_empty() {
		return [0u8; 32];
	}
	let mut layer: alloc::vec::Vec<[u8; 32]> = entries
		.iter()
		.map(|(p, h)| leaf_hash(p, h))
		.collect();
	while layer.len() > 1 {
		if layer.len() % 2 == 1 {
			let last = *layer.last().expect("len() > 1 above; qed");
			layer.push(last);
		}
		layer = layer
			.chunks(2)
			.map(|pair| node_hash(&pair[0], &pair[1]))
			.collect();
	}
	layer[0]
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

		/// The canonical Merkle root over all registered
		/// `(path, hash)` entries. Phase 7b uses this for fast
		/// peer-to-peer drift detection: peers compare local root
		/// against canonical root in O(1) before walking the
		/// per-file diff.
		fn canonical_root() -> [u8; 32];

		/// The current `rostro_release` ed25519 pubkey, or `None` if
		/// not yet set. Watchdog reconciliation (piece B.1-bis) calls
		/// this via RPC to localhost gemini-node periodically and
		/// compares the result against its compile-time-baked pubkey.
		/// Divergence is the signal that the node's binary is stale,
		/// the release pipeline was compromised, or a routine key
		/// rotation happened.
		fn release_pubkey() -> Option<[u8; 32]>;
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
			initial_release_pubkey: None,
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
			initial_release_pubkey: None,
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
			initial_release_pubkey: None,
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

	// ─── canonical_root / Merkle construction ─────────────────────────────

	#[test]
	fn canonical_root_empty_registry_is_zero() {
		new_test_ext().execute_with(|| {
			assert_eq!(crate::pallet::Pallet::<Test>::canonical_root(), [0u8; 32]);
		});
	}

	#[test]
	fn canonical_root_single_entry_equals_leaf_hash() {
		new_test_ext().execute_with(|| {
			let path = b"gemini-node".to_vec();
			let hash = [0xAB; 32];
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				path.clone(),
				hash,
			));
			let root = crate::pallet::Pallet::<Test>::canonical_root();
			let expected = crate::leaf_hash(&path, &hash);
			assert_eq!(root, expected);
		});
	}

	#[test]
	fn canonical_root_two_entries_is_node_of_sorted_leaves() {
		new_test_ext().execute_with(|| {
			// Register out of order; root must reflect lexicographic
			// (path) ordering, not insertion order.
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"zzz".to_vec(),
				[0x02; 32],
			));
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"aaa".to_vec(),
				[0x01; 32],
			));
			let root = crate::pallet::Pallet::<Test>::canonical_root();
			let leaf_a = crate::leaf_hash(b"aaa", &[0x01; 32]);
			let leaf_z = crate::leaf_hash(b"zzz", &[0x02; 32]);
			let expected = crate::node_hash(&leaf_a, &leaf_z);
			assert_eq!(root, expected);
		});
	}

	#[test]
	fn canonical_root_three_entries_duplicates_last_for_odd_layer() {
		new_test_ext().execute_with(|| {
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"aaa".to_vec(),
				[0x01; 32],
			));
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"bbb".to_vec(),
				[0x02; 32],
			));
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"ccc".to_vec(),
				[0x03; 32],
			));
			let root = crate::pallet::Pallet::<Test>::canonical_root();
			let leaf_a = crate::leaf_hash(b"aaa", &[0x01; 32]);
			let leaf_b = crate::leaf_hash(b"bbb", &[0x02; 32]);
			let leaf_c = crate::leaf_hash(b"ccc", &[0x03; 32]);
			// Layer 1: [ ab, cc ] (last duplicated).
			let ab = crate::node_hash(&leaf_a, &leaf_b);
			let cc = crate::node_hash(&leaf_c, &leaf_c);
			let expected = crate::node_hash(&ab, &cc);
			assert_eq!(root, expected);
		});
	}

	#[test]
	fn canonical_root_is_insertion_order_independent() {
		// Registering the same set in two different orders must
		// produce the same root.
		let entries: alloc::vec::Vec<(alloc::vec::Vec<u8>, [u8; 32])> = alloc::vec![
			(b"alpha".to_vec(), [0x01; 32]),
			(b"beta".to_vec(), [0x02; 32]),
			(b"gamma".to_vec(), [0x03; 32]),
			(b"delta".to_vec(), [0x04; 32]),
		];

		let root_forward = new_test_ext().execute_with(|| {
			for (p, h) in entries.iter() {
				assert_ok!(CanonicalFiles::register_file(
					frame_system::RawOrigin::Root.into(),
					p.clone(),
					*h,
				));
			}
			crate::pallet::Pallet::<Test>::canonical_root()
		});

		let root_reverse = new_test_ext().execute_with(|| {
			for (p, h) in entries.iter().rev() {
				assert_ok!(CanonicalFiles::register_file(
					frame_system::RawOrigin::Root.into(),
					p.clone(),
					*h,
				));
			}
			crate::pallet::Pallet::<Test>::canonical_root()
		});

		assert_eq!(root_forward, root_reverse);
	}

	#[test]
	fn canonical_root_changes_when_one_byte_of_one_hash_changes() {
		// Tampering invariant: any change to any leaf must change the
		// root.
		let baseline = new_test_ext().execute_with(|| {
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-node".to_vec(),
				[0xAA; 32],
			));
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-runtime.wasm".to_vec(),
				[0xBB; 32],
			));
			crate::pallet::Pallet::<Test>::canonical_root()
		});
		let tampered = new_test_ext().execute_with(|| {
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-node".to_vec(),
				[0xAA; 32],
			));
			let mut bb = [0xBB; 32];
			bb[31] ^= 0x01; // flip one bit
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-runtime.wasm".to_vec(),
				bb,
			));
			crate::pallet::Pallet::<Test>::canonical_root()
		});
		assert_ne!(baseline, tampered);
	}

	#[test]
	fn canonical_root_changes_when_two_paths_swap_hashes() {
		// Hash-swap defense: A's hash registered against B's path,
		// and vice versa, must produce a different root than the
		// correct binding. This is the property that makes
		// `(path, hash)` leaves rather than `hash`-only leaves
		// meaningful.
		let correct = new_test_ext().execute_with(|| {
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-node".to_vec(),
				[0xAA; 32],
			));
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-runtime.wasm".to_vec(),
				[0xBB; 32],
			));
			crate::pallet::Pallet::<Test>::canonical_root()
		});
		let swapped = new_test_ext().execute_with(|| {
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-node".to_vec(),
				[0xBB; 32],
			));
			assert_ok!(CanonicalFiles::register_file(
				frame_system::RawOrigin::Root.into(),
				b"gemini-runtime.wasm".to_vec(),
				[0xAA; 32],
			));
			crate::pallet::Pallet::<Test>::canonical_root()
		});
		assert_ne!(correct, swapped);
	}

	#[test]
	fn merkle_root_of_matches_canonical_root() {
		// The free function `merkle_root_of` is what the native
		// verifier will call against its locally-computed entry list.
		// It must agree bit-for-bit with the on-chain
		// `canonical_root()` over the same input set.
		let entries: alloc::vec::Vec<(alloc::vec::Vec<u8>, [u8; 32])> = alloc::vec![
			(b"alpha".to_vec(), [0x01; 32]),
			(b"beta".to_vec(), [0x02; 32]),
			(b"gamma".to_vec(), [0x03; 32]),
		];
		let on_chain = new_test_ext().execute_with(|| {
			for (p, h) in entries.iter() {
				assert_ok!(CanonicalFiles::register_file(
					frame_system::RawOrigin::Root.into(),
					p.clone(),
					*h,
				));
			}
			crate::pallet::Pallet::<Test>::canonical_root()
		});

		let mut sorted = entries.clone();
		sorted.sort_by(|a, b| a.0.cmp(&b.0));
		let standalone = crate::merkle_root_of(&sorted);

		assert_eq!(on_chain, standalone);
	}

	#[test]
	fn leaf_hash_is_distinct_from_node_hash_for_same_payload_bytes() {
		// Domain separation invariant: a 65-byte payload that
		// happens to match the node-tag layout must not produce the
		// same hash as a leaf encoding with the same trailing
		// bytes. Sanity-checks that LEAF_TAG ≠ NODE_TAG actually
		// matters.
		let bytes32 = [0x77u8; 32];
		let leaf_with_payload_that_looks_like_node = crate::leaf_hash(
			&[0u8; 32], // 32 bytes path
			&bytes32,
		);
		let node = crate::node_hash(&[0u8; 32], &bytes32);
		assert_ne!(leaf_with_payload_that_looks_like_node, node);
	}

	// ─── ReleasePubkey (piece B.1-bis) ────────────────────────────────

	#[test]
	fn release_pubkey_defaults_to_none() {
		new_test_ext().execute_with(|| {
			assert_eq!(crate::pallet::Pallet::<Test>::release_pubkey(), None);
		});
	}

	#[test]
	fn set_release_pubkey_round_trips() {
		new_test_ext().execute_with(|| {
			let pubkey = [0x42u8; 32];
			assert_ok!(CanonicalFiles::set_release_pubkey(
				frame_system::RawOrigin::Root.into(),
				pubkey,
			));
			assert_eq!(crate::pallet::Pallet::<Test>::release_pubkey(), Some(pubkey));
		});
	}

	#[test]
	fn set_release_pubkey_overwrites() {
		new_test_ext().execute_with(|| {
			assert_ok!(CanonicalFiles::set_release_pubkey(
				frame_system::RawOrigin::Root.into(),
				[0x01u8; 32],
			));
			assert_ok!(CanonicalFiles::set_release_pubkey(
				frame_system::RawOrigin::Root.into(),
				[0x02u8; 32],
			));
			assert_eq!(crate::pallet::Pallet::<Test>::release_pubkey(), Some([0x02u8; 32]));
		});
	}

	#[test]
	fn set_release_pubkey_rejects_zero() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				CanonicalFiles::set_release_pubkey(
					frame_system::RawOrigin::Root.into(),
					[0u8; 32],
				),
				Error::<Test>::ZeroHash,
			);
		});
	}

	#[test]
	fn set_release_pubkey_requires_srt_origin() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				CanonicalFiles::set_release_pubkey(
					frame_system::RawOrigin::Signed(1).into(),
					[0xAB; 32],
				),
				sp_runtime::DispatchError::BadOrigin,
			);
		});
	}

	#[test]
	fn genesis_seeds_release_pubkey_when_set() {
		// The Test impl's `new_test_ext` doesn't yet wire
		// initial_release_pubkey, so we exercise the build path
		// directly: assemble a GenesisConfig with Some(pubkey) and
		// invoke `BuildGenesisConfig::build`.
		use crate::pallet::GenesisConfig;
		use frame_support::traits::BuildGenesisConfig;
		let mut ext = sp_io::TestExternalities::default();
		ext.execute_with(|| {
			let pubkey = [0xCD; 32];
			let gc: GenesisConfig<Test> = GenesisConfig {
				initial_files: alloc::vec![],
				initial_release_pubkey: Some(pubkey),
				_config: core::marker::PhantomData,
			};
			gc.build();
			assert_eq!(crate::pallet::Pallet::<Test>::release_pubkey(), Some(pubkey));
		});
	}

	#[test]
	#[should_panic(expected = "initial_release_pubkey must not be the all-zero sentinel")]
	fn genesis_rejects_zero_release_pubkey() {
		use crate::pallet::GenesisConfig;
		use frame_support::traits::BuildGenesisConfig;
		let mut ext = sp_io::TestExternalities::default();
		ext.execute_with(|| {
			let gc: GenesisConfig<Test> = GenesisConfig {
				initial_files: alloc::vec![],
				initial_release_pubkey: Some([0u8; 32]),
				_config: core::marker::PhantomData,
			};
			gc.build();
		});
	}

	#[test]
	fn release_pubkey_event_emitted_on_set() {
		new_test_ext().execute_with(|| {
			frame_system::Pallet::<Test>::set_block_number(1);
			let pubkey = [0x99; 32];
			assert_ok!(CanonicalFiles::set_release_pubkey(
				frame_system::RawOrigin::Root.into(),
				pubkey,
			));
			let events: alloc::vec::Vec<_> = frame_system::Pallet::<Test>::events()
				.into_iter()
				.filter_map(|r| match r.event {
					RuntimeEvent::CanonicalFiles(e) => Some(e),
					_ => None,
				})
				.collect();
			assert!(events.iter().any(|e| matches!(e, Event::ReleasePubkeyUpdated { pubkey: p } if *p == pubkey)));
		});
	}
}
