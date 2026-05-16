// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro operator-state pallet
//!
//! On-chain storage for operator-private application objects (NFTs,
//! tickets, custom records minted under an RNS namespace by a
//! Rostro merchant operator). The pallet enforces three invariants
//! that make multi-operator coexistence safe on shared chain state:
//!
//! 1. **Cross-namespace write isolation.** Operator B cannot
//!    intentionally or accidentally mutate operator A's objects.
//!    Storage is keyed by `(DomainHash, AccountId, ObjectType,
//!    ObjectId)`; B's writes physically cannot address A's storage
//!    subtree because B's `AccountId` differs.
//! 2. **RNS-rooted current authority.** Every namespace-mutating
//!    extrinsic checks both that (a) the signer is the *current*
//!    RNS registrant of the name AND (b) the signer matches the
//!    `AccountId` baked into the storage key. Both checks must
//!    pass, so re-registration of an RNS name by a different
//!    account never grants access to the previous registrant's
//!    objects.
//! 3. **State-rent backed cleanup economy.** Every minted object
//!    locks an operator-paid deposit. When the namespace's RNS
//!    registrant changes (or lapses entirely), any account can
//!    call the permissionless `cleanup` extrinsic to delete the
//!    object and collect the deposit residue. Snorkels are the
//!    practical dominant callers but the pallet does not gate the
//!    extrinsic on any role.
//!
//! ## Object lifecycle
//!
//! - **Mint**: namespace owner (current RNS registrant) calls
//!   [`mint_object`] with an initial owner (typically the customer),
//!   a payload blob, and a deposit at or above
//!   `T::MinObjectDeposit`. The deposit is reserved on the
//!   namespace owner's account.
//! - **Mutate**: namespace owner updates an object's blob via
//!   [`mutate_object_blob`]. Object's `current_owner` is unaffected.
//! - **Transfer**: the object's *current* owner (not the namespace
//!   owner) reassigns ownership via [`transfer_object`]. This is
//!   how a customer hands off their NFT to another customer; the
//!   namespace owner has no veto.
//! - **Burn**: namespace owner deletes an object via [`burn_object`],
//!   which un-reserves and refunds the deposit to the namespace
//!   owner.
//! - **Cleanup**: anyone calls [`cleanup`] on an object whose
//!   namespace is no longer registered to the same `AccountId`.
//!   The deposit residue is paid to the caller (minus their gas).
//!
//! ## Pattern B fee model (Phase 1)
//!
//! Operators routinely call extrinsics with the customer as the
//! `owner` field, paying both the deposit and the tx fee
//! themselves — promo airdrops, comp replacements, gift NFTs.
//! Pattern C (customer-signed action with operator-sponsored fee)
//! lives at the runtime fee-payment layer and is its own
//! workstream; the operator-state pallet does not need to know
//! about it.
//!
//! ## Out of scope
//!
//! - **Bilateral non-repudiation receipts.** Customer↔operator
//!   trade evidence (both parties' signatures attesting to a
//!   trade) is its own pallet; operator-state objects are the
//!   *result* of trades, not the receipts of them.
//! - **The operator-runtime sidecar.** This pallet sits independently;
//!   the sidecar is one of its consumers but the pallet is
//!   independently testable and useful (any application can mint
//!   under it via signed extrinsics).
//! - **Foundation-canonical state** (canonical-files registry,
//!   RpcMethodPolicy, etc.). Foundation state lives in dedicated
//!   pallets with SRT-gated mutation; operator-state is for
//!   third-party application state on top.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ReservableCurrency},
};
use frame_system::pallet_prelude::BlockNumberFor;
use rns_types::DomainHash;
use scale_info::TypeInfo;

/// Maximum byte length of an operator-supplied `object_type`
/// discriminator (e.g. "ticket-v2", "nft", "receipt"). 64 bytes is
/// generous — operator can pick whatever convention fits, but a
/// single short string per object class is the expected use.
pub const MAX_OBJECT_TYPE_LEN: u32 = 64;

/// Maximum byte length of an operator-supplied `object_id` within
/// a type. 64 bytes leaves room for SS58-style references, UUID
/// strings, hashes-as-hex, etc., without inviting bloat.
pub const MAX_OBJECT_ID_LEN: u32 = 64;

/// Hard cap on the bytes of the object payload blob. 4 KiB. Larger
/// payloads should be stored off-chain (IPFS, web2 backend, or
/// sidecar's local DB) with a content hash held on chain.
pub const MAX_BLOB_SIZE: u32 = 4 * 1024;

/// Convenience type alias for the configured currency's balance.
pub type BalanceOf<T> = <<T as Config>::Currency as Currency<
	<T as frame_system::Config>::AccountId,
>>::Balance;

/// Bounded form of an `object_type` key.
pub type BoundedObjectType = BoundedVec<u8, ConstU32<MAX_OBJECT_TYPE_LEN>>;

/// Bounded form of an `object_id` key.
pub type BoundedObjectId = BoundedVec<u8, ConstU32<MAX_OBJECT_ID_LEN>>;

/// Bounded form of an object payload blob.
pub type BoundedBlob = BoundedVec<u8, ConstU32<MAX_BLOB_SIZE>>;

/// On-chain object record. The `(DomainHash, AccountId, ObjectType,
/// ObjectId)` 4-tuple keys this in storage; the AccountId in the
/// key is the *minting* operator's account, frozen at mint time
/// and never rewritten — it's the unfakeable second value that
/// keeps a re-registrant of the same name from inheriting these
/// objects.
#[derive(
	Encode, Decode, MaxEncodedLen, TypeInfo, DebugNoBound, CloneNoBound, PartialEqNoBound, EqNoBound,
)]
#[scale_info(skip_type_params(T))]
pub struct Object<T: Config> {
	/// Account currently authorized to transfer this specific
	/// object. Set at mint time (typically the customer for
	/// customer-facing NFTs, the operator for internal records).
	/// Updates when [`Pallet::transfer_object`] is called.
	pub current_owner: T::AccountId,

	/// Application-defined payload. Opaque to the chain — the
	/// operator's local-WASM sidecar interprets it.
	pub blob: BoundedBlob,

	/// Reserved deposit on the namespace owner's account. Refunded
	/// on `burn_object`; paid to caller on `cleanup`.
	pub deposit: BalanceOf<T>,

	/// Block at which this object was originally minted. Useful for
	/// auditing and for off-chain indexers; not consulted by any
	/// extrinsic.
	pub mint_block: BlockNumberFor<T>,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;
	use pallet_rns_registrar::traits::NameRegistry;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Reservable currency used for object deposits. Mint
		/// reserves; burn unreserves; cleanup repatriates the
		/// reserve to the cleanup caller.
		type Currency: ReservableCurrency<Self::AccountId>;

		/// Plug-in to the RNS pallet for the authoritative
		/// "current owner of this name" lookup. The pallet does
		/// not embed any RNS internals — it just consults this
		/// trait at write time.
		type RnsRegistry: NameRegistry<AccountId = Self::AccountId>;

		/// Floor on the per-object deposit. Governance-tunable.
		/// Sized so that `cleanup` is comfortably profitable
		/// against typical gas costs after the namespace lapses.
		#[pallet::constant]
		type MinObjectDeposit: Get<BalanceOf<Self>>;
	}

	/// Operator state, keyed by
	/// `(rns_namespace, mint_account, object_type, object_id)`.
	///
	/// The `Identity` hasher on `DomainHash` is safe — `DomainHash`
	/// is already a 32-byte hash output, so re-hashing buys
	/// nothing and `Identity` lets us iterate cheaply by namespace
	/// when needed (e.g., a future helper for "all objects in
	/// namespace X"). Account, object_type, and object_id keys use
	/// `Blake2_128Concat` — concat hashers preserve the original
	/// key bytes for partial-prefix iteration and avoid prefix
	/// collisions.
	#[pallet::storage]
	pub type OperatorState<T: Config> = StorageNMap<
		_,
		(
			NMapKey<Identity, DomainHash>,
			NMapKey<Blake2_128Concat, T::AccountId>,
			NMapKey<Blake2_128Concat, BoundedObjectType>,
			NMapKey<Blake2_128Concat, BoundedObjectId>,
		),
		Object<T>,
		OptionQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new object was minted into operator state.
		ObjectMinted {
			namespace: DomainHash,
			operator: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
			owner: T::AccountId,
			deposit: BalanceOf<T>,
		},
		/// An object's blob payload was replaced by the namespace
		/// owner. The object's owner / deposit / mint block are
		/// unchanged.
		ObjectMutated {
			namespace: DomainHash,
			operator: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
		},
		/// Ownership of an object was transferred.
		ObjectTransferred {
			namespace: DomainHash,
			operator: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
			from: T::AccountId,
			to: T::AccountId,
		},
		/// An object was burned by the namespace owner; deposit
		/// refunded to the operator.
		ObjectBurned {
			namespace: DomainHash,
			operator: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
			deposit_refunded: BalanceOf<T>,
		},
		/// An object was cleaned up by a permissionless caller
		/// after the namespace registration lapsed or transferred
		/// to a different account. The deposit was paid to the
		/// caller.
		ObjectCleanedUp {
			namespace: DomainHash,
			operator: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
			caller: T::AccountId,
			deposit_paid: BalanceOf<T>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// `object_type` exceeds [`MAX_OBJECT_TYPE_LEN`].
		ObjectTypeTooLong,
		/// `object_type` was empty; meaningful types must be at
		/// least one byte.
		ObjectTypeEmpty,
		/// `object_id` exceeds [`MAX_OBJECT_ID_LEN`].
		ObjectIdTooLong,
		/// `object_id` was empty; meaningful ids must be at
		/// least one byte.
		ObjectIdEmpty,
		/// Payload blob exceeds [`MAX_BLOB_SIZE`].
		BlobTooLarge,
		/// Caller tried to mint with a deposit below
		/// `T::MinObjectDeposit`.
		DepositTooSmall,
		/// Caller is not the current RNS registrant of the
		/// namespace they're trying to mutate. Either the name has
		/// lapsed, the name is registered to someone else, or the
		/// caller signed under a different account.
		NamespaceNotOwnedBySigner,
		/// The storage key's mint-time AccountId differs from the
		/// signer. Even if the signer holds the current RNS
		/// registration, they cannot mutate objects minted by a
		/// different account under the same name.
		MintAccountMismatch,
		/// The signer is not the current owner of the object —
		/// only the current owner can transfer.
		NotObjectOwner,
		/// No object exists at the supplied `(namespace, mint_account,
		/// object_type, object_id)` key.
		ObjectNotFound,
		/// Cleanup was called on an object whose namespace is still
		/// registered to the same mint-time AccountId. The object
		/// is alive; cleanup is rejected.
		NotEligibleForCleanup,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Mint a new object under the caller's RNS namespace.
		///
		/// The caller must be the current RNS registrant of
		/// `namespace`. The mint reserves `deposit` on the
		/// caller's account; that deposit funds the eventual
		/// cleanup incentive (or is refunded on graceful burn).
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(20_000, 0))]
		pub fn mint_object(
			origin: OriginFor<T>,
			namespace: DomainHash,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
			owner: T::AccountId,
			blob: Vec<u8>,
			deposit: BalanceOf<T>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::ensure_namespace_owner(&who, namespace)?;

			let object_type = Self::bounded_type(object_type)?;
			let object_id = Self::bounded_id(object_id)?;
			let blob = Self::bounded_blob(blob)?;
			ensure!(deposit >= T::MinObjectDeposit::get(), Error::<T>::DepositTooSmall);

			T::Currency::reserve(&who, deposit)?;

			let object = Object::<T> {
				current_owner: owner.clone(),
				blob,
				deposit,
				mint_block: <frame_system::Pallet<T>>::block_number(),
			};
			OperatorState::<T>::insert(
				(namespace, who.clone(), object_type.clone(), object_id.clone()),
				object,
			);

			Self::deposit_event(Event::ObjectMinted {
				namespace,
				operator: who,
				object_type: object_type.into_inner(),
				object_id: object_id.into_inner(),
				owner,
				deposit,
			});
			Ok(())
		}

		/// Replace the payload blob of an existing object. Only
		/// the namespace owner (current RNS registrant + same
		/// AccountId that minted) can mutate. Object's owner
		/// field, deposit, and mint block are unaffected.
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(15_000, 0))]
		pub fn mutate_object_blob(
			origin: OriginFor<T>,
			namespace: DomainHash,
			mint_account: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
			new_blob: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::ensure_namespace_owner(&who, namespace)?;
			ensure!(who == mint_account, Error::<T>::MintAccountMismatch);

			let object_type = Self::bounded_type(object_type)?;
			let object_id = Self::bounded_id(object_id)?;
			let new_blob = Self::bounded_blob(new_blob)?;
			let key = (namespace, who.clone(), object_type.clone(), object_id.clone());

			OperatorState::<T>::try_mutate(&key, |maybe| -> DispatchResult {
				let obj = maybe.as_mut().ok_or(Error::<T>::ObjectNotFound)?;
				obj.blob = new_blob;
				Ok(())
			})?;

			Self::deposit_event(Event::ObjectMutated {
				namespace,
				operator: who,
				object_type: object_type.into_inner(),
				object_id: object_id.into_inner(),
			});
			Ok(())
		}

		/// Transfer ownership of an object to a new account. Only
		/// the *current owner* of the object can transfer — the
		/// namespace owner has no veto. This is how a customer
		/// hands their NFT to another account.
		#[pallet::call_index(2)]
		#[pallet::weight(Weight::from_parts(15_000, 0))]
		pub fn transfer_object(
			origin: OriginFor<T>,
			namespace: DomainHash,
			mint_account: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
			new_owner: T::AccountId,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let object_type = Self::bounded_type(object_type)?;
			let object_id = Self::bounded_id(object_id)?;
			let key = (namespace, mint_account.clone(), object_type.clone(), object_id.clone());

			let from = OperatorState::<T>::try_mutate(&key, |maybe| -> Result<T::AccountId, DispatchError> {
				let obj = maybe.as_mut().ok_or(Error::<T>::ObjectNotFound)?;
				ensure!(obj.current_owner == who, Error::<T>::NotObjectOwner);
				let prev = core::mem::replace(&mut obj.current_owner, new_owner.clone());
				Ok(prev)
			})?;

			Self::deposit_event(Event::ObjectTransferred {
				namespace,
				operator: mint_account,
				object_type: object_type.into_inner(),
				object_id: object_id.into_inner(),
				from,
				to: new_owner,
			});
			Ok(())
		}

		/// Burn an object. Only the namespace owner (current RNS
		/// registrant + same AccountId that minted) can burn; the
		/// reserved deposit is unreserved back to the namespace
		/// owner.
		#[pallet::call_index(3)]
		#[pallet::weight(Weight::from_parts(20_000, 0))]
		pub fn burn_object(
			origin: OriginFor<T>,
			namespace: DomainHash,
			mint_account: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::ensure_namespace_owner(&who, namespace)?;
			ensure!(who == mint_account, Error::<T>::MintAccountMismatch);

			let object_type = Self::bounded_type(object_type)?;
			let object_id = Self::bounded_id(object_id)?;
			let key = (namespace, who.clone(), object_type.clone(), object_id.clone());

			let object = OperatorState::<T>::take(&key).ok_or(Error::<T>::ObjectNotFound)?;
			let _ = T::Currency::unreserve(&who, object.deposit);

			Self::deposit_event(Event::ObjectBurned {
				namespace,
				operator: who,
				object_type: object_type.into_inner(),
				object_id: object_id.into_inner(),
				deposit_refunded: object.deposit,
			});
			Ok(())
		}

		/// Permissionless cleanup of an orphaned object. Anyone
		/// can call. Eligibility: the namespace's current RNS
		/// registrant is `None` OR is a different account than the
		/// `mint_account` baked into the storage key. On success,
		/// the deposit residue is repatriated from the mint
		/// account's reserve to the caller's free balance.
		#[pallet::call_index(4)]
		#[pallet::weight(Weight::from_parts(25_000, 0))]
		pub fn cleanup(
			origin: OriginFor<T>,
			namespace: DomainHash,
			mint_account: T::AccountId,
			object_type: Vec<u8>,
			object_id: Vec<u8>,
		) -> DispatchResult {
			let caller = ensure_signed(origin)?;
			let object_type = Self::bounded_type(object_type)?;
			let object_id = Self::bounded_id(object_id)?;
			let key = (namespace, mint_account.clone(), object_type.clone(), object_id.clone());

			let current = T::RnsRegistry::owner_of(namespace);
			let eligible = match current {
				None => true,
				Some(addr) => addr != mint_account,
			};
			ensure!(eligible, Error::<T>::NotEligibleForCleanup);

			let object = OperatorState::<T>::take(&key).ok_or(Error::<T>::ObjectNotFound)?;
			let _ = T::Currency::repatriate_reserved(
				&mint_account,
				&caller,
				object.deposit,
				frame_support::traits::BalanceStatus::Free,
			);

			Self::deposit_event(Event::ObjectCleanedUp {
				namespace,
				operator: mint_account,
				object_type: object_type.into_inner(),
				object_id: object_id.into_inner(),
				caller,
				deposit_paid: object.deposit,
			});
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Verify `who` is the current RNS registrant of `namespace`.
		fn ensure_namespace_owner(
			who: &T::AccountId,
			namespace: DomainHash,
		) -> DispatchResult {
			let current = T::RnsRegistry::owner_of(namespace)
				.ok_or(Error::<T>::NamespaceNotOwnedBySigner)?;
			ensure!(&current == who, Error::<T>::NamespaceNotOwnedBySigner);
			Ok(())
		}

		fn bounded_type(input: Vec<u8>) -> Result<BoundedObjectType, DispatchError> {
			ensure!(!input.is_empty(), Error::<T>::ObjectTypeEmpty);
			BoundedObjectType::try_from(input).map_err(|_| Error::<T>::ObjectTypeTooLong.into())
		}

		fn bounded_id(input: Vec<u8>) -> Result<BoundedObjectId, DispatchError> {
			ensure!(!input.is_empty(), Error::<T>::ObjectIdEmpty);
			BoundedObjectId::try_from(input).map_err(|_| Error::<T>::ObjectIdTooLong.into())
		}

		fn bounded_blob(input: Vec<u8>) -> Result<BoundedBlob, DispatchError> {
			BoundedBlob::try_from(input).map_err(|_| Error::<T>::BlobTooLarge.into())
		}

		/// Read an object by its full key. Returns `None` if no
		/// object is stored there.
		pub fn get_object(
			namespace: DomainHash,
			mint_account: &T::AccountId,
			object_type: &[u8],
			object_id: &[u8],
		) -> Option<Object<T>> {
			let object_type = BoundedObjectType::try_from(object_type.to_vec()).ok()?;
			let object_id = BoundedObjectId::try_from(object_id.to_vec()).ok()?;
			OperatorState::<T>::get((namespace, mint_account.clone(), object_type, object_id))
		}
	}
}

#[cfg(test)]
mod tests;
