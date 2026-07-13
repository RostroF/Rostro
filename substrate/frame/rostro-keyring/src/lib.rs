// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro account keyring
//!
//! A Rostro account is a persistent identity with a mutable, revocable
//! set of signing keys (docs/KEYRING.md, implementing the Stage B
//! overlay of docs/PQ-SIGNATURES.md). This pallet holds the on-chain
//! map `AccountId32 → { authorized (scheme, pubkey) }` and the verify
//! routine the runtime's extrinsic `Checkable` path consults.
//!
//! ## Semantics
//!
//! - **No entry** (almost every account, forever): verification is the
//!   stateless derived-key default — `RostroSignature::verify` against
//!   the address. Zero new state, BYO-wallet flow unchanged.
//! - **Entry exists**: a signature is valid if it verifies on the
//!   derived path (unless derived authority is rescinded) OR against
//!   any enrolled key via `RostroSignature::verify_against`.
//! - **Derived authority is a flag, not a list entry.** sr25519 and
//!   ed25519 share the raw-pubkey address namespace, so "the derived
//!   key" is not one `(scheme, pubkey)` pair; rescinding it must kill
//!   both derived paths at once. `derived_rescinded` does exactly that
//!   — the Q-day classical-retirement lever, per account.
//! - **At least one authority always remains**: `rescind_key` refuses
//!   to empty the key list while derived authority is rescinded, and
//!   `rescind_derived` requires a non-empty list. An entry whose list
//!   empties while derived authority is active is deleted outright —
//!   the account returns to the stateless default.
//! - **Proof of possession at enroll**: the candidate key must sign
//!   [`enroll_challenge`] (domain tag ‖ genesis hash ‖ account). You
//!   cannot enroll a key you don't hold — griefing today, a rogue-key
//!   hazard once the `Both` policy exists.
//!
//! The founding use case: a 25519 root (mnemonic, later Ledger) mints
//! the account, then a P-256 device key (StrongBox/TPM) is enrolled as
//! the everyday convenience signer. The same machinery is the PQ
//! migration ramp (enroll ML-DSA beside classical, later rescind
//! classical) and the lost-device recovery path (sign with another
//! enrolled key, rescind the lost one) — one abstraction, on purpose.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{traits::Get, BoundedVec};
use rostro_multi_key::{RostroSignature, RostroSigner};
use scale_info::TypeInfo;
use sp_core::crypto::AccountId32;
use sp_runtime::traits::Verify;

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// Domain-separation tag for the enroll proof-of-possession challenge.
pub const ENROLL_DOMAIN_TAG: &[u8; 24] = b"rostro:keyring:enroll:v1";

/// The enroll proof-of-possession challenge: the candidate key signs
/// `SCALE((ENROLL_DOMAIN_TAG, genesis_hash, account))`. The genesis hash
/// blocks cross-chain replay, the account blocks cross-account replay;
/// same-account replay is inert because the enclosing extrinsic needs
/// the account's own live authority plus its nonce. Exported so the
/// wallet builds byte-identical challenge material.
pub fn enroll_challenge<H: Encode>(genesis_hash: &H, who: &AccountId32) -> Vec<u8> {
	(ENROLL_DOMAIN_TAG, genesis_hash, who).encode()
}

/// Per-entry signing policy. Wire-frozen from day one (append-only enum
/// discipline), but only `Either` is constructible today: there is no
/// `set_policy` call, and verification implements only `Either`. `Both`
/// needs a dual-signature envelope that doesn't exist yet; `PqOnly`
/// needs a PQ scheme. Both arrive with the ML-DSA phase
/// (docs/PQ-SIGNATURES.md).
#[derive(
	Clone, Copy, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	Debug, Default,
)]
pub enum Policy {
	/// Any single authorized key may sign.
	#[default]
	Either,
	/// Reserved: classical + PQ signature both required.
	Both,
	/// Reserved: classical keys refused.
	PqOnly,
}

/// One account's keyring. Exists only for accounts that opted in.
#[derive(
	Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Debug,
)]
#[scale_info(skip_type_params(M))]
pub struct KeyringEntry<M: Get<u32>> {
	/// Enrolled keys, each proven-possessed at enroll time. No duplicates.
	pub keys: BoundedVec<RostroSigner, M>,
	/// Signing policy — always `Either` today (see [`Policy`]).
	pub policy: Policy,
	/// When set, the address-derived key(s) no longer authorize spends;
	/// only enrolled keys do. Settable only while `keys` is non-empty.
	pub derived_rescinded: bool,
}

impl<M: Get<u32>> Default for KeyringEntry<M> {
	fn default() -> Self {
		Self { keys: BoundedVec::new(), policy: Policy::Either, derived_rescinded: false }
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// `AccountId` is pinned to `AccountId32`: this pallet's whole subject
	/// is the relationship between AccountId32 address derivation and
	/// explicit key authority, and `RostroSignature::verify` speaks
	/// `AccountId32` natively.
	#[pallet::config]
	pub trait Config: frame_system::Config<AccountId = AccountId32> {
		/// The overarching event type.
		#[allow(deprecated)]
		type RuntimeEvent: From<Event<Self>>
			+ IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Maximum enrolled keys per account.
		#[pallet::constant]
		type MaxKeys: Get<u32>;
	}

	/// The keyring overlay: accounts with an entry here have opted in to
	/// explicit key authority. Consulted once per signed extrinsic in the
	/// runtime's `Checkable` path — same cost class as the nonce check.
	#[pallet::storage]
	pub type Keyring<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, KeyringEntry<T::MaxKeys>, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A key was enrolled with valid proof of possession.
		KeyEnrolled { who: T::AccountId, key: RostroSigner },
		/// An enrolled key was rescinded.
		KeyRescinded { who: T::AccountId, key: RostroSigner },
		/// The address-derived key(s) no longer authorize this account.
		DerivedRescinded { who: T::AccountId },
		/// The address-derived key(s) authorize this account again.
		DerivedRestored { who: T::AccountId },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The key is already enrolled for this account.
		AlreadyEnrolled,
		/// The key is not enrolled for this account.
		KeyNotEnrolled,
		/// The account's keyring is full (`MaxKeys`).
		TooManyKeys,
		/// The proof-of-possession signature does not verify for the
		/// candidate key over this account's enroll challenge.
		BadProofOfPossession,
		/// The operation would leave the account with no signing
		/// authority at all. Refused: a keyless account is a bricked
		/// account, not a hard cutover.
		LastAuthority,
		/// The account has no keyring entry.
		NoKeyringEntry,
		/// Derived authority is already rescinded.
		DerivedAlreadyRescinded,
		/// Derived authority is not rescinded.
		DerivedNotRescinded,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Enroll `key` as an authorized signer for the calling account.
		/// `pop` is the proof of possession: `key`'s signature over this
		/// account's [`enroll_challenge`]. The call itself is authorized by
		/// the account's existing authority (derived or enrolled) like any
		/// signed extrinsic — enrollment while classical signatures are
		/// trustworthy is the security-critical event of the whole PQ
		/// migration (docs/PQ-SIGNATURES.md, "the enrollment invariant").
		#[pallet::call_index(0)]
		#[pallet::weight(
			Weight::from_parts(100_000_000, 0)
				.saturating_add(T::DbWeight::get().reads_writes(2, 1))
		)]
		pub fn enroll_key(
			origin: OriginFor<T>,
			key: RostroSigner,
			pop: RostroSignature,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let challenge = Self::enroll_challenge_for(&who);
			ensure!(pop.verify_against(&challenge, &key), Error::<T>::BadProofOfPossession);

			let mut entry = Keyring::<T>::get(&who).unwrap_or_default();
			ensure!(!entry.keys.contains(&key), Error::<T>::AlreadyEnrolled);
			entry.keys.try_push(key.clone()).map_err(|_| Error::<T>::TooManyKeys)?;
			Keyring::<T>::insert(&who, entry);

			Self::deposit_event(Event::KeyEnrolled { who, key });
			Ok(())
		}

		/// Rescind an enrolled key. Refused if it is the last authority
		/// (derived rescinded and one key left). If the list empties while
		/// derived authority is active, the entry is deleted and the
		/// account returns to the stateless derived default.
		#[pallet::call_index(1)]
		#[pallet::weight(
			Weight::from_parts(10_000, 0)
				.saturating_add(T::DbWeight::get().reads_writes(1, 1))
		)]
		pub fn rescind_key(origin: OriginFor<T>, key: RostroSigner) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let mut entry = Keyring::<T>::get(&who).ok_or(Error::<T>::NoKeyringEntry)?;
			let pos = entry
				.keys
				.iter()
				.position(|k| k == &key)
				.ok_or(Error::<T>::KeyNotEnrolled)?;
			ensure!(
				!(entry.derived_rescinded && entry.keys.len() == 1),
				Error::<T>::LastAuthority
			);
			entry.keys.remove(pos);
			if entry.keys.is_empty() {
				// derived_rescinded is false here (guard above), so the
				// account is back to exactly the no-entry default.
				Keyring::<T>::remove(&who);
			} else {
				Keyring::<T>::insert(&who, entry);
			}

			Self::deposit_event(Event::KeyRescinded { who, key });
			Ok(())
		}

		/// Rescind the address-derived key(s): from this point only
		/// enrolled keys authorize the account. Requires at least one
		/// enrolled key. This is the per-account classical-retirement
		/// lever — at Q-day, an account that has enrolled a PQ key and
		/// called this is done migrating.
		#[pallet::call_index(2)]
		#[pallet::weight(
			Weight::from_parts(10_000, 0)
				.saturating_add(T::DbWeight::get().reads_writes(1, 1))
		)]
		pub fn rescind_derived(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let mut entry = Keyring::<T>::get(&who).ok_or(Error::<T>::NoKeyringEntry)?;
			ensure!(!entry.derived_rescinded, Error::<T>::DerivedAlreadyRescinded);
			// Entries never persist with an empty list, but the invariant
			// is load-bearing enough to check, not assume.
			ensure!(!entry.keys.is_empty(), Error::<T>::LastAuthority);
			entry.derived_rescinded = true;
			Keyring::<T>::insert(&who, entry);

			Self::deposit_event(Event::DerivedRescinded { who });
			Ok(())
		}

		/// Restore derived authority (undo [`Call::rescind_derived`]).
		/// Authorized by any currently enrolled key, like every call here.
		#[pallet::call_index(3)]
		#[pallet::weight(
			Weight::from_parts(10_000, 0)
				.saturating_add(T::DbWeight::get().reads_writes(1, 1))
		)]
		pub fn restore_derived(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let mut entry = Keyring::<T>::get(&who).ok_or(Error::<T>::NoKeyringEntry)?;
			ensure!(entry.derived_rescinded, Error::<T>::DerivedNotRescinded);
			entry.derived_rescinded = false;
			Keyring::<T>::insert(&who, entry);

			Self::deposit_event(Event::DerivedRestored { who });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// The enroll challenge for `who` on this chain.
		pub fn enroll_challenge_for(who: &T::AccountId) -> Vec<u8> {
			let genesis = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
			enroll_challenge(&genesis, who)
		}

		/// The keyring-aware signature check, called from the runtime's
		/// extrinsic `Checkable` path (via the `KeyringSignature` wrapper's
		/// `Verify` impl). One storage read; the no-entry fast path is the
		/// stateless derived-key default, byte-for-byte today's behaviour.
		pub fn verify_extrinsic_signature(
			sig: &RostroSignature,
			payload: &[u8],
			who: &T::AccountId,
		) -> bool {
			match Keyring::<T>::get(who) {
				None => sig.verify(payload, who),
				Some(entry) => {
					// Policy::Either is the only constructible policy today;
					// Both/PqOnly gain arms when they become constructible.
					(!entry.derived_rescinded && sig.verify(payload, who))
						|| entry.keys.iter().any(|k| sig.verify_against(payload, k))
				},
			}
		}
	}
}
