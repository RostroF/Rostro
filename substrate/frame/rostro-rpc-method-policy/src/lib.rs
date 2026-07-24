// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro RPC Method Policy
//!
//! On-chain registry of access policies for RPC methods. Native node code
//! (specifically `rostro-rpc-shield`'s middleware) queries this registry to
//! decide whether to admit, gate, or refuse each incoming JSON-RPC call.
//!
//! ## Why on-chain
//!
//! The shield's allowlist used to be hard-coded into the native binary. That
//! created a coordination problem: WASM runtime upgrades (which can
//! add/change runtime API methods) and native binary upgrades (which carry
//! the allowlist) are on different cadences. A WASM upgrade that adds a new
//! runtime API method would default to Deny on every existing-fleet node
//! until each operator rolled out an updated binary. Operationally
//! burdensome and a UX break.
//!
//! By moving the policy on-chain:
//! - WASM upgrade carries its own policy update (alongside the new runtime API)
//! - Native binary reads from chain at startup and on era / `set_code` events
//! - Runtime upgrades stay coordinated with their access-policy changes
//!
//! Same pattern as `pallet-rostro-type-registry` (recognizer fingerprints).
//!
//! ## Policy classes
//!
//! Each registered method maps to one of:
//! - `PublicSafe` — anyone, no per-method gate, only generic source rate limit
//! - `PublicGated` — anyone, but the per-method rate-limit bucket applies
//! - `LocalOnly` — only loopback callers (operator-side CLI / management)
//! - `Deny` — never admitted from any source. Reserved for known panic/amplifier methods.
//!
//! Methods absent from the registry default to **Deny** in the native shield
//! (explicit allowlist). New runtime API methods MUST be added to the
//! registry — either at genesis seed or via a governance-approved migration
//! — before they're publicly callable.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use scale_info::TypeInfo;

/// Maximum length in bytes for a registered method name.
///
/// The longest substrate runtime API method name in current use is around
/// 60 characters (`SassafrasApi_submit_report_equivocation_unsigned_extrinsic`).
/// We cap generously at 128 to leave room for future longer trait+method
/// pairings without forcing a parameter-bump migration.
pub const MAX_METHOD_NAME_LEN: u32 = 128;

/// Minimum method name length. Substrate's shortest are 8+ chars
/// (`Core_*`, `Babe_*`); 4 is a hard floor that rejects single-character
/// or empty-trait sentinels without limiting legitimate names.
pub const MIN_METHOD_NAME_LEN: u32 = 4;

/// Maximum number of `(method_name, policy)` pairs a chain spec may supply
/// via `GenesisConfig::additional_policies`. Capped to prevent a hostile
/// fork chain spec from DoS'ing genesis import. The current shield's
/// hard-coded allowlist is around 25 entries; legitimate seed extensions
/// are short.
pub const MAX_ADDITIONAL_POLICIES: usize = 256;

/// Access policy for a registered RPC method.
///
/// Kept in lockstep with the `MethodPolicy` enum in
/// `rostro-rpc-shield::statecall`. A future cleanup will deduplicate by
/// having the shield import the on-chain enum, but for v0 the two are kept
/// identical by convention; the values are SCALE-encoded as small u8
/// discriminants and the variants are explicitly numbered to make the
/// wire format stable across versions.
#[derive(
	Debug,
	Clone,
	Copy,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum MethodPolicy {
	/// Anyone may call. Subject only to the per-/24 source rate limit.
	#[codec(index = 0)]
	PublicSafe,
	/// Publicly callable but charged against a tighter per-method bucket
	/// for back-pressure.
	#[codec(index = 1)]
	PublicGated,
	/// Loopback callers only. Used for validator-internal management
	/// operations like `generate_key_ownership_proof`. Returns
	/// `StateCallLocalOnly` deny when called from non-loopback.
	#[codec(index = 2)]
	LocalOnly,
	/// Never admitted. Reserved for known panic-on-call runtime APIs
	/// (`*_submit_*_unsigned_extrinsic`) and known bandwidth amplifiers
	/// (`SassafrasApi_ring_context`) that have no legitimate external
	/// caller.
	#[codec(index = 3)]
	Deny,
}

/// Compute the v0 well-known method-policy seed list. This is the
/// authoritative initial classification consumed at genesis. Mirrors the
/// hard-coded allowlist in `rostro-rpc-shield::statecall::StateCallPolicy`
/// at the time this pallet was added.
///
/// Future migrations (new runtime API methods added in a runtime upgrade)
/// land via SRT-gated `set_method_policy` extrinsic calls bundled into the
/// upgrade migration tuple.
pub const V0_WELL_KNOWN_POLICIES: &[(&[u8], MethodPolicy)] = &[
	// ─── Deny (panic vectors + amplifiers) ───────────────────────────
	(b"SassafrasApi_ring_context", MethodPolicy::Deny),
	(b"SassafrasApi_submit_tickets_unsigned_extrinsic", MethodPolicy::Deny),
	(b"SassafrasApi_submit_report_equivocation_unsigned_extrinsic", MethodPolicy::Deny),
	(b"GrandpaApi_submit_report_equivocation_unsigned_extrinsic", MethodPolicy::Deny),
	// ─── LocalOnly (validator-internal) ─────────────────────────────
	(b"SassafrasApi_generate_key_ownership_proof", MethodPolicy::LocalOnly),
	(b"GrandpaApi_generate_key_ownership_proof", MethodPolicy::LocalOnly),
	(b"SessionKeys_generate_session_keys", MethodPolicy::LocalOnly),
	(b"SessionKeys_decode_session_keys", MethodPolicy::LocalOnly),
	// ─── PublicSafe (cheap reads) ────────────────────────────────────
	(b"Core_version", MethodPolicy::PublicSafe),
	(b"Core_initialize_block", MethodPolicy::PublicSafe),
	(b"Metadata_metadata_versions", MethodPolicy::PublicSafe),
	(b"AccountNonceApi_account_nonce", MethodPolicy::PublicSafe),
	(b"GrandpaApi_grandpa_authorities", MethodPolicy::PublicSafe),
	(b"GrandpaApi_current_set_id", MethodPolicy::PublicSafe),
	(b"SassafrasApi_current_epoch", MethodPolicy::PublicSafe),
	(b"SassafrasApi_next_epoch", MethodPolicy::PublicSafe),
	(b"TransactionPaymentApi_query_info", MethodPolicy::PublicSafe),
	(b"TransactionPaymentApi_query_fee_details", MethodPolicy::PublicSafe),
	(b"TransactionPaymentApi_query_weight_to_fee", MethodPolicy::PublicSafe),
	(b"TransactionPaymentApi_query_length_to_fee", MethodPolicy::PublicSafe),
	(b"GenesisBuilder_get_preset", MethodPolicy::PublicSafe),
	(b"GenesisBuilder_preset_names", MethodPolicy::PublicSafe),
	// ─── PublicGated (callable but expensive) ─────────────────────────
	(b"SassafrasApi_slot_ticket", MethodPolicy::PublicGated),
	(b"SassafrasApi_slot_ticket_id", MethodPolicy::PublicGated),
	(b"Metadata_metadata", MethodPolicy::PublicGated),
	(b"Metadata_metadata_at_version", MethodPolicy::PublicGated),
	(b"BlockBuilder_apply_extrinsic", MethodPolicy::PublicGated),
	(b"BlockBuilder_finalize_block", MethodPolicy::PublicGated),
	(b"BlockBuilder_inherent_extrinsics", MethodPolicy::PublicGated),
	(b"BlockBuilder_check_inherents", MethodPolicy::PublicGated),
	(b"TaggedTransactionQueue_validate_transaction", MethodPolicy::PublicGated),
	(b"GenesisBuilder_build_state", MethodPolicy::PublicGated),
	// ─── This pallet's own runtime API ────────────────────────────────
	// Self-anchoring: the policy registry must classify itself, since the
	// shield will reach for these methods to bootstrap. Both gated rather
	// than safe so a hostile peer can't mass-poll the full table at
	// arbitrary rate even though entries are individually small.
	(b"RpcMethodPolicyApi_policy_for", MethodPolicy::PublicGated),
	(b"RpcMethodPolicyApi_all_policies", MethodPolicy::PublicGated),
	// ─── Canonical-files registry (Phase 7a) ──────────────────────────
	// Same gating rationale as the policy registry: PublicGated so a
	// hostile caller can't mass-poll, but reachable by legitimate
	// verifiers + tooling.
	(b"CanonicalFilesApi_hash_for", MethodPolicy::PublicGated),
	(b"CanonicalFilesApi_all_files", MethodPolicy::PublicGated),
	(b"CanonicalFilesApi_canonical_root", MethodPolicy::PublicGated),
	// ─── RNS — identity primitive ────────────────────────────────────
	// Snorkel and external clients reach name records via these
	// runtime APIs over state_call. PublicGated so the shield rate-
	// limits and tracks repeat callers but doesn't deny — RNS data
	// is public-by-design; the gating is about request-volume hygiene.
	(b"PnsStorageApi_get_info", MethodPolicy::PublicGated),
	(b"PnsStorageApi_lookup", MethodPolicy::PublicGated),
	(b"PnsStorageApi_resolve_name", MethodPolicy::PublicGated),
	(b"PnsStorageApi_get_listing", MethodPolicy::PublicGated),
	(b"PnsStorageApi_lookup_by_name", MethodPolicy::PublicGated),

	// zk-pki cert / EK / chain-validity queries. Same PublicGated
	// posture as RNS: cert state is public-by-design (it's the
	// hardware-attestation registry), shield rate-limits volume.
	(b"ZkPkiApi_cert_status", MethodPolicy::PublicGated),
	(b"ZkPkiApi_certs_by_issuer", MethodPolicy::PublicGated),
	(b"ZkPkiApi_certs_by_user", MethodPolicy::PublicGated),
	(b"ZkPkiApi_certs_by_root", MethodPolicy::PublicGated),
	(b"ZkPkiApi_entity_status", MethodPolicy::PublicGated),
	(b"ZkPkiApi_ek_lookup", MethodPolicy::PublicGated),
	(b"ZkPkiApi_chain_valid_at", MethodPolicy::PublicGated),
	(b"ZkPkiApi_certs_by_device_key", MethodPolicy::PublicGated),
];

/// Runtime API exposed for the `rostro-rpc-shield` middleware to query
/// the on-chain policy registry from the host side. The shield calls
/// these via `client.runtime_api().{policy_for,all_policies}(at)` —
/// that's an in-process call into the WASM runtime, not a JSON-RPC
/// trip. They are also reachable from outside via `state_call`, gated
/// PublicGated by V0_WELL_KNOWN_POLICIES above.
sp_api::decl_runtime_apis! {
	pub trait RpcMethodPolicyApi {
		/// Look up the policy for a single method name. Returns `None`
		/// if the method isn't registered (caller should default-Deny).
		fn policy_for(method: Vec<u8>) -> Option<MethodPolicy>;

		/// Iterate the full policy table. Bounded by the storage map's
		/// entry count; intended for the shield's startup bootstrap.
		fn all_policies() -> Vec<(Vec<u8>, MethodPolicy)>;
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Re-assert the well-known policy set on every runtime upgrade.
		/// The compiled [`V0_WELL_KNOWN_POLICIES`] list is authoritative
		/// for the native shield's allowlist. Genesis seeds it, but a
		/// method added to the list in a later runtime would otherwise
		/// never reach an already-running chain's registry — and the
		/// shield default-denies unregistered methods, so the new API
		/// would be silently unreachable after `set_code` (the exact gap
		/// that stranded `ZkPkiApi_cert_by_device_key` at spec 109).
		/// Idempotent upsert keeps the registry in lockstep with the
		/// binary — the mechanism `set_method_policy`'s doc promises,
		/// applied to the whole set so no future addition is forgotten.
		/// Cheap: O(list) writes, once per upgrade.
		fn on_runtime_upgrade() -> Weight {
			let mut writes = 0u64;
			for (name, policy) in super::V0_WELL_KNOWN_POLICIES.iter() {
				if let Ok(key) =
					BoundedVec::<u8, ConstU32<MAX_METHOD_NAME_LEN>>::try_from(name.to_vec())
				{
					RpcMethodPolicy::<T>::insert(&key, policy);
					writes = writes.saturating_add(1);
				}
			}
			T::DbWeight::get().writes(writes)
		}
	}

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Origin permitted to mutate policies post-genesis. In production
		/// this resolves to the Security Response Team
		/// (`pallet-rostro-security-response-team`, deferred to prelaunch).
		/// Stub at `EnsureRoot` until the SRT pallet lands.
		// TODO(srt): retarget at `pallet-rostro-security-response-team`
		type SecurityResponseTeamOrigin: EnsureOrigin<Self::RuntimeOrigin>;
	}

	/// On-chain map of method name → access policy.
	///
	/// Source of truth for `rostro-rpc-shield`. A method present here gets
	/// the registered policy; a method absent here defaults to Deny in the
	/// native shield (explicit allowlist).
	#[pallet::storage]
	pub type RpcMethodPolicy<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		BoundedVec<u8, ConstU32<MAX_METHOD_NAME_LEN>>,
		MethodPolicy,
		OptionQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A method's access policy was registered or updated.
		PolicySet { method: Vec<u8>, policy: MethodPolicy },
		/// A method's access policy was removed (falls back to Deny in the
		/// native shield).
		PolicyRemoved { method: Vec<u8> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Method name exceeds `MAX_METHOD_NAME_LEN`.
		MethodNameTooLong,
		/// Method name shorter than `MIN_METHOD_NAME_LEN`. The minimum
		/// rejects single-character or empty-trait sentinels that cannot
		/// be substrate-runtime-API-shaped.
		MethodNameTooShort,
		/// Method name contains a NUL byte. Substrate runtime API names are
		/// ASCII-only `Trait_method` strings; a NUL inside one is malformed
		/// at best and a parse-confusion attempt at worst.
		MethodNameContainsNul,
		/// No policy registered for the supplied method.
		MethodNotFound,
	}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		/// Additional `(method_name, policy)` pairs to seed beyond the v0
		/// well-known set. Most chains leave this empty; the v0 set covers
		/// the substrate + Sassafras + GRANDPA runtime APIs known at this
		/// pallet's introduction. Genesis-supplied additions run FIRST,
		/// then the v0 seed runs LAST and is therefore authoritative — a
		/// chain spec cannot override well-known policy classifications.
		pub additional_policies: Vec<(Vec<u8>, MethodPolicy)>,
		#[serde(skip)]
		pub _config: core::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			assert!(
				self.additional_policies.len() <= MAX_ADDITIONAL_POLICIES,
				"additional_policies exceeds MAX_ADDITIONAL_POLICIES ({})",
				MAX_ADDITIONAL_POLICIES
			);

			for (name, policy) in self.additional_policies.iter() {
				assert!(
					name.len() >= MIN_METHOD_NAME_LEN as usize,
					"chain spec method name {:?} shorter than MIN_METHOD_NAME_LEN ({})",
					name,
					MIN_METHOD_NAME_LEN
				);
				assert!(
					!name.contains(&0u8),
					"chain spec method name {:?} contains NUL byte",
					name
				);
				let key: BoundedVec<u8, ConstU32<MAX_METHOD_NAME_LEN>> =
					BoundedVec::try_from(name.clone())
						.expect("chain spec method name fits; qed");
				RpcMethodPolicy::<T>::insert(&key, policy);
			}

			// v0 seed last — authoritative; overwrites any chain-spec entry
			// that tried to claim a well-known method. Deny-tier methods
			// especially cannot be relaxed by a malicious fork's chain spec.
			for (name, policy) in super::V0_WELL_KNOWN_POLICIES.iter() {
				let key: BoundedVec<u8, ConstU32<MAX_METHOD_NAME_LEN>> =
					BoundedVec::try_from(name.to_vec())
						.expect("v0 seed method names fit in MAX_METHOD_NAME_LEN; qed");
				RpcMethodPolicy::<T>::insert(&key, policy);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register or replace the access policy for an RPC method. SRT-gated.
		///
		/// Use case: a runtime upgrade adds a new runtime API method. The
		/// upgrade migration tuple includes a `set_method_policy(name,
		/// classification)` call so the native shield's allowlist updates
		/// in lockstep with the WASM behaviour.
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(10_000, 0))]
		pub fn set_method_policy(
			origin: OriginFor<T>,
			method: Vec<u8>,
			policy: MethodPolicy,
		) -> DispatchResult {
			T::SecurityResponseTeamOrigin::ensure_origin(origin)?;
			ensure!(method.len() >= MIN_METHOD_NAME_LEN as usize, Error::<T>::MethodNameTooShort);
			ensure!(!method.contains(&0u8), Error::<T>::MethodNameContainsNul);
			let key: BoundedVec<u8, ConstU32<MAX_METHOD_NAME_LEN>> =
				BoundedVec::try_from(method.clone())
					.map_err(|_| Error::<T>::MethodNameTooLong)?;
			RpcMethodPolicy::<T>::insert(&key, policy);
			Self::deposit_event(Event::PolicySet { method, policy });
			Ok(())
		}

		/// Remove a method's policy entry. SRT-gated.
		///
		/// After removal the method falls through to the native shield's
		/// default (Deny). Use this to retire a runtime API method that's
		/// being removed in a runtime upgrade.
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(10_000, 0))]
		pub fn remove_method_policy(
			origin: OriginFor<T>,
			method: Vec<u8>,
		) -> DispatchResult {
			T::SecurityResponseTeamOrigin::ensure_origin(origin)?;
			ensure!(method.len() >= MIN_METHOD_NAME_LEN as usize, Error::<T>::MethodNameTooShort);
			ensure!(!method.contains(&0u8), Error::<T>::MethodNameContainsNul);
			let key: BoundedVec<u8, ConstU32<MAX_METHOD_NAME_LEN>> =
				BoundedVec::try_from(method.clone())
					.map_err(|_| Error::<T>::MethodNameTooLong)?;
			ensure!(
				RpcMethodPolicy::<T>::take(&key).is_some(),
				Error::<T>::MethodNotFound
			);
			Self::deposit_event(Event::PolicyRemoved { method });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Read the policy for `method`. Used by the runtime API impl
		/// (and indirectly by the native `rostro-rpc-shield`).
		///
		/// Returns `None` if the method isn't registered or if the
		/// supplied name exceeds `MAX_METHOD_NAME_LEN` (oversized names
		/// can't be a key, so they trivially aren't registered).
		pub fn policy_for(method: &[u8]) -> Option<MethodPolicy> {
			let key: BoundedVec<u8, ConstU32<MAX_METHOD_NAME_LEN>> =
				BoundedVec::try_from(method.to_vec()).ok()?;
			RpcMethodPolicy::<T>::get(&key)
		}

		/// Materialize the full policy table. Used by the native shield
		/// at startup to bootstrap its in-memory cache. The result is
		/// bounded by the storage map's entry count.
		pub fn all_policies() -> Vec<(Vec<u8>, MethodPolicy)> {
			RpcMethodPolicy::<T>::iter()
				.map(|(k, v)| (k.into_inner(), v))
				.collect()
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate as pallet_rostro_rpc_method_policy;
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
			Policy: pallet_rostro_rpc_method_policy,
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

	impl pallet_rostro_rpc_method_policy::Config for Test {
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

	fn key(s: &[u8]) -> BoundedVec<u8, ConstU32<MAX_METHOD_NAME_LEN>> {
		BoundedVec::try_from(s.to_vec()).unwrap()
	}

	#[test]
	fn set_rejects_too_short() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				Policy::set_method_policy(
					frame_system::RawOrigin::Root.into(),
					b"abc".to_vec(),
					MethodPolicy::PublicSafe,
				),
				Error::<Test>::MethodNameTooShort,
			);
		});
	}

	#[test]
	fn set_rejects_nul_byte() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				Policy::set_method_policy(
					frame_system::RawOrigin::Root.into(),
					b"foo\0bar".to_vec(),
					MethodPolicy::PublicSafe,
				),
				Error::<Test>::MethodNameContainsNul,
			);
		});
	}

	#[test]
	fn set_rejects_too_long() {
		new_test_ext().execute_with(|| {
			let too_long = alloc::vec![b'x'; (MAX_METHOD_NAME_LEN as usize) + 1];
			assert_noop!(
				Policy::set_method_policy(
					frame_system::RawOrigin::Root.into(),
					too_long,
					MethodPolicy::PublicSafe,
				),
				Error::<Test>::MethodNameTooLong,
			);
		});
	}

	#[test]
	fn set_then_get_roundtrips() {
		new_test_ext().execute_with(|| {
			assert_ok!(Policy::set_method_policy(
				frame_system::RawOrigin::Root.into(),
				b"new_TraitApi_method".to_vec(),
				MethodPolicy::PublicGated,
			));
			assert_eq!(
				crate::pallet::RpcMethodPolicy::<Test>::get(&key(b"new_TraitApi_method")),
				Some(MethodPolicy::PublicGated),
			);
		});
	}

	#[test]
	fn remove_clears_entry() {
		new_test_ext().execute_with(|| {
			assert_ok!(Policy::set_method_policy(
				frame_system::RawOrigin::Root.into(),
				b"new_TraitApi_method".to_vec(),
				MethodPolicy::PublicSafe,
			));
			assert_ok!(Policy::remove_method_policy(
				frame_system::RawOrigin::Root.into(),
				b"new_TraitApi_method".to_vec(),
			));
			assert!(
				crate::pallet::RpcMethodPolicy::<Test>::get(&key(b"new_TraitApi_method"))
					.is_none()
			);
		});
	}

	#[test]
	fn remove_rejects_not_found() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				Policy::remove_method_policy(
					frame_system::RawOrigin::Root.into(),
					b"never_seen_method".to_vec(),
				),
				Error::<Test>::MethodNotFound,
			);
		});
	}

	#[test]
	fn genesis_seeds_v0_set() {
		// v0 seed runs in BuildGenesisConfig and should populate every
		// well-known method.
		let genesis = crate::pallet::GenesisConfig::<Test> {
			additional_policies: alloc::vec![],
			_config: core::marker::PhantomData,
		};
		let mut t = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap();
		genesis.assimilate_storage(&mut t).unwrap();
		let mut ext = sp_io::TestExternalities::new(t);
		ext.execute_with(|| {
			for (name, expected) in V0_WELL_KNOWN_POLICIES.iter() {
				let stored = crate::pallet::RpcMethodPolicy::<Test>::get(&key(name));
				assert_eq!(stored, Some(*expected), "v0 seed missing/wrong for {:?}", name);
			}
		});
	}

	#[test]
	fn genesis_additional_cannot_relax_v0_deny() {
		// A hostile chain spec tries to flip a Deny-tier method (ring_context)
		// to PublicSafe via additional_policies. The v0 seed runs LAST and
		// MUST overwrite. Verifies the same authoritative-seeding property
		// the type-registry pallet has.
		let bogus_relaxation = alloc::vec![(
			b"SassafrasApi_ring_context".to_vec(),
			MethodPolicy::PublicSafe,
		)];
		let genesis = crate::pallet::GenesisConfig::<Test> {
			additional_policies: bogus_relaxation,
			_config: core::marker::PhantomData,
		};
		let mut t = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap();
		genesis.assimilate_storage(&mut t).unwrap();
		let mut ext = sp_io::TestExternalities::new(t);
		ext.execute_with(|| {
			let stored = crate::pallet::RpcMethodPolicy::<Test>::get(
				&key(b"SassafrasApi_ring_context")
			);
			assert_eq!(
				stored,
				Some(MethodPolicy::Deny),
				"v0 seed must overwrite chain-spec-supplied relaxation",
			);
		});
	}

	#[test]
	#[should_panic(expected = "shorter than MIN_METHOD_NAME_LEN")]
	fn genesis_panics_on_too_short_additional() {
		let genesis = crate::pallet::GenesisConfig::<Test> {
			additional_policies: alloc::vec![(b"abc".to_vec(), MethodPolicy::PublicSafe)],
			_config: core::marker::PhantomData,
		};
		let mut t = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap();
		genesis.assimilate_storage(&mut t).unwrap();
		let mut ext = sp_io::TestExternalities::new(t);
		ext.execute_with(|| {});
	}

	#[test]
	fn v0_seed_classifies_known_panic_vectors_as_deny() {
		// Spot-check the load-bearing claim that the four panic-vector /
		// amplifier methods are denied at genesis.
		new_test_ext().execute_with(|| {
			// Use BuildGenesisConfig path
			let genesis = crate::pallet::GenesisConfig::<Test> {
				additional_policies: alloc::vec![],
				_config: core::marker::PhantomData,
			};
			let mut t = frame_system::GenesisConfig::<Test>::default()
				.build_storage()
				.unwrap();
			genesis.assimilate_storage(&mut t).unwrap();
			let mut ext = sp_io::TestExternalities::new(t);
			ext.execute_with(|| {
				for name in [
					b"SassafrasApi_ring_context".as_slice(),
					b"SassafrasApi_submit_tickets_unsigned_extrinsic",
					b"SassafrasApi_submit_report_equivocation_unsigned_extrinsic",
					b"GrandpaApi_submit_report_equivocation_unsigned_extrinsic",
				] {
					let stored = crate::pallet::RpcMethodPolicy::<Test>::get(&key(name));
					assert_eq!(stored, Some(MethodPolicy::Deny), "{:?} must be Deny", name);
				}
			});
		});
	}
}
