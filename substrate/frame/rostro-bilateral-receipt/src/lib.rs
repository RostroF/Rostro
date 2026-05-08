// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro bilateral receipt pallet
//!
//! On-chain non-repudiation for customer↔operator economic
//! interactions. Both parties co-sign a [`ReceiptPayload`]; the
//! pallet verifies both signatures, performs the balance transfer
//! atomically, optionally triggers an operator-state mint via the
//! configured [`AtomicMintHook`], and records the receipt under
//! the SCALE-encoded payload's blake2_256 hash so neither party
//! can later deny what was agreed.
//!
//! ## Why bilateral
//!
//! Standard balance transfers carry only the sender's signature.
//! That's enough to prove "Alice paid Bob" but says nothing about
//! what Bob promised in exchange. The bilateral receipt records
//! Bob's countersignature on the same payload — Alice's payment +
//! the trade reference + the fee responsibility — so future
//! disputes have a single signed object naming both parties'
//! commitments. Neither side can lie about the trade that
//! happened.
//!
//! ## Anyone can relay
//!
//! `submit_trade` accepts any signed origin as the relayer. The
//! relayer is not paying out (the customer is) and not receiving
//! (the operator is); they're just submitting two pre-signed
//! signatures to chain. This lets:
//!
//! - Customers pre-sign before a trade and have the operator
//!   finalize on submission.
//! - Operators pre-sign promo terms and have customers finalize
//!   when they redeem.
//! - Light clients submit on either party's behalf without
//!   running a full node.
//!
//! Per-customer monotonic nonces close the replay window.
//!
//! ## Atomic operator-state mint
//!
//! Many trades are "I paid X, I got back this NFT." `submit_trade`
//! takes an optional [`MintAlong`] parameter; when present, the
//! pallet's [`Config::AtomicMintHook`] runs after the balance
//! transfer succeeds. The runtime wires this to
//! `pallet-rostro-operator-state::mint_object`. The operator's
//! signature on the bundle covers the mint parameters too — by
//! signing, the operator authorizes both the receipt of payment
//! AND the named mint.
//!
//! ## Signature scheme
//!
//! Generic over signature scheme via the standard FRAME
//! `Verify`/`IdentifyAccount` pattern. Runtime configures
//! `Signature = MultiSignature` and `AccountPublic = MultiSigner`,
//! which gives operators the option of Ed25519, Sr25519, or
//! ECDSA — useful as Phase 6.9 hardware attestation lands and
//! some hardware classes are ECDSA-only.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use frame_system::pallet_prelude::BlockNumberFor;
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::traits::{IdentifyAccount, Member, Verify};

/// Maximum byte length of an arbitrary off-chain trade reference
/// (order ID, terms hash, IPFS CID, freeform memo). 256 bytes is
/// generous; longer descriptions go off-chain with a hash here.
pub const MAX_TRADE_REF_LEN: u32 = 256;

/// Convenience type alias for the configured currency's balance.
pub type BalanceOf<T> = <<T as Config>::Currency as Currency<
	<T as frame_system::Config>::AccountId,
>>::Balance;

/// Bounded form of a trade reference.
pub type BoundedTradeRef = BoundedVec<u8, ConstU32<MAX_TRADE_REF_LEN>>;

/// Who absorbs the chain transaction fee. Recorded on the receipt
/// for audit; the actual fee withdrawal is decided by the
/// runtime's signed-extension stack.
#[derive(
	Debug, Clone, PartialEq, Eq,
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub enum FeePayerKind {
	/// Customer pays the relayer's tx fee for `submit_trade`.
	Customer,
	/// Operator covers the tx fee. Used for promos / comps.
	Operator,
}

/// What the parties co-sign. The blake2_256 of `(payload,
/// mint_along)`'s SCALE encoding is the receipt's primary storage
/// key; this lets the same `ReceiptPayload` be reused with or
/// without a `mint_along` and still produce distinct receipts.
#[derive(
	Debug, Clone, PartialEq, Eq,
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct ReceiptPayload<AccountId, Balance> {
	/// The customer (paying party).
	pub customer: AccountId,
	/// The operator (receiving party).
	pub operator: AccountId,
	/// Amount transferred from customer to operator on receipt
	/// acceptance.
	pub amount: Balance,
	/// Off-chain trade reference (order ID, terms hash, etc.).
	pub trade_ref: BoundedTradeRef,
	/// Who absorbs the relayer's tx fee.
	pub fee_payer: FeePayerKind,
	/// Per-customer monotonic nonce. Each customer's nonces must
	/// strictly increase; replays are rejected.
	pub nonce: u64,
}

/// Optional atomic mint that runs after a successful trade.
/// Operator's signature on the receipt covers these parameters
/// too (the bundle is what's signed), so signing the receipt
/// authorizes both the payment receipt AND the mint.
#[derive(
	Debug, Clone, PartialEq, Eq,
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct MintAlong<AccountId, Balance> {
	/// RNS namespace (DomainHash) under which to mint.
	pub namespace: H256,
	/// Operator-defined object type (`ticket-v1`, `nft`, etc.).
	pub object_type: BoundedVec<u8, ConstU32<64>>,
	/// Operator-defined object id within the type.
	pub object_id: BoundedVec<u8, ConstU32<64>>,
	/// Account that becomes the object's `current_owner`.
	pub owner: AccountId,
	/// Operator-defined payload blob.
	pub blob: BoundedVec<u8, ConstU32<4096>>,
	/// Deposit reserved on the operator's account by the mint.
	pub deposit: Balance,
}

/// Stored receipt record. Carries the original payload + the block
/// at which the receipt landed.
#[derive(
	Encode, Decode, MaxEncodedLen, TypeInfo, frame_support::CloneNoBound,
	frame_support::PartialEqNoBound, frame_support::EqNoBound, frame_support::DebugNoBound,
)]
#[scale_info(skip_type_params(T))]
pub struct RecordedReceipt<T: Config> {
	pub payload: ReceiptPayload<T::AccountId, BalanceOf<T>>,
	pub block: BlockNumberFor<T>,
}

/// Plug-in for the optional atomic mint after a successful trade.
/// The runtime wires this to `pallet-rostro-operator-state::Pallet`
/// (or another mint sink). Tests provide a no-op or recording
/// mock.
pub trait AtomicMintHook<AccountId, Balance> {
	/// Execute a mint with the given parameters. Called only
	/// after both signatures verify and the balance transfer
	/// succeeds.
	fn mint(
		operator: &AccountId,
		namespace: H256,
		object_type: Vec<u8>,
		object_id: Vec<u8>,
		owner: AccountId,
		blob: Vec<u8>,
		deposit: Balance,
	) -> DispatchResult;
}

/// Default impl that fails if invoked. Use this in runtimes that
/// don't expose an `operator-state` mint sink — `mint_along` calls
/// will fail loud rather than silently dropping the mint.
pub struct NoMintHook;
impl<AccountId, Balance> AtomicMintHook<AccountId, Balance> for NoMintHook {
	fn mint(
		_: &AccountId,
		_: H256,
		_: Vec<u8>,
		_: Vec<u8>,
		_: AccountId,
		_: Vec<u8>,
		_: Balance,
	) -> DispatchResult {
		Err(DispatchError::Other("AtomicMintHook not configured for this runtime"))
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Currency used for the trade transfer.
		type Currency: Currency<Self::AccountId>;

		/// Signature scheme. The runtime configures this to
		/// `MultiSignature` so customers and operators can use
		/// any of Ed25519 / Sr25519 / ECDSA.
		type Signature: Verify<Signer = Self::AccountPublic>
			+ Member
			+ Encode
			+ Decode
			+ TypeInfo
			+ MaxEncodedLen;

		/// Public-key type associated with [`Self::Signature`].
		/// `IdentifyAccount<AccountId = Self::AccountId>` lets us
		/// verify a signature directly against an `AccountId`.
		type AccountPublic: IdentifyAccount<AccountId = Self::AccountId>;

		/// Plug-in that executes the optional atomic mint when
		/// `mint_along` is supplied.
		type AtomicMintHook: AtomicMintHook<Self::AccountId, BalanceOf<Self>>;
	}

	/// Receipts indexed by blake2_256 of the SCALE-encoded
	/// `(payload, mint_along)` bundle.
	#[pallet::storage]
	pub type Receipts<T: Config> =
		StorageMap<_, Identity, H256, RecordedReceipt<T>, OptionQuery>;

	/// Per-customer last-seen nonce. Submitted nonces must
	/// strictly exceed this value; `None` means the customer has
	/// never submitted a receipt before (any positive nonce is
	/// accepted as the first).
	#[pallet::storage]
	pub type LastNonce<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, u64, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A bilateral trade was recorded on chain.
		TradeRecorded {
			receipt_hash: H256,
			customer: T::AccountId,
			operator: T::AccountId,
			amount: BalanceOf<T>,
			minted: bool,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Customer's signature didn't verify against the bundle.
		InvalidCustomerSignature,
		/// Operator's signature didn't verify against the bundle.
		InvalidOperatorSignature,
		/// Customer == operator. Trades require two distinct parties.
		SelfTrade,
		/// Submitted nonce <= the customer's last-seen nonce.
		ReplayedOrStaleNonce,
		/// Receipt with this hash was already recorded. Race-window
		/// defense (two relayers submitting the same payload).
		ReceiptAlreadyRecorded,
		/// Balance transfer from customer to operator failed
		/// (insufficient funds, frozen account, etc.).
		TransferFailed,
		/// Atomic mint hook returned an error.
		MintHookFailed,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Submit a bilateral receipt. The submitter (relayer)
		/// need not be either party. On success the balance
		/// transfer is performed and the receipt recorded; if
		/// `mint_along` is supplied, the configured
		/// `AtomicMintHook` runs after the transfer.
		///
		/// Both signatures are required; either's invalidity
		/// rejects the entire call. Nonce is per-customer and
		/// must strictly increase.
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(50_000, 0))]
		pub fn submit_trade(
			origin: OriginFor<T>,
			payload: ReceiptPayload<T::AccountId, BalanceOf<T>>,
			customer_signature: T::Signature,
			operator_signature: T::Signature,
			mint_along: Option<MintAlong<T::AccountId, BalanceOf<T>>>,
		) -> DispatchResult {
			let _relayer = ensure_signed(origin)?;

			ensure!(payload.customer != payload.operator, Error::<T>::SelfTrade);

			let last = LastNonce::<T>::get(&payload.customer).unwrap_or(0);
			ensure!(payload.nonce > last, Error::<T>::ReplayedOrStaleNonce);

			// Canonical signed bundle: payload + optional mint
			// params. Tupling these means the operator's
			// signature covers the mint authorization too — no
			// separate authorization step.
			let sign_bundle = (payload.clone(), mint_along.clone()).encode();

			ensure!(
				customer_signature.verify(&sign_bundle[..], &payload.customer),
				Error::<T>::InvalidCustomerSignature,
			);
			ensure!(
				operator_signature.verify(&sign_bundle[..], &payload.operator),
				Error::<T>::InvalidOperatorSignature,
			);

			let receipt_hash = H256::from(sp_io::hashing::blake2_256(&sign_bundle));
			ensure!(
				!Receipts::<T>::contains_key(receipt_hash),
				Error::<T>::ReceiptAlreadyRecorded,
			);

			T::Currency::transfer(
				&payload.customer,
				&payload.operator,
				payload.amount,
				ExistenceRequirement::KeepAlive,
			)
			.map_err(|_| Error::<T>::TransferFailed)?;

			let recorded = RecordedReceipt::<T> {
				payload: payload.clone(),
				block: <frame_system::Pallet<T>>::block_number(),
			};
			Receipts::<T>::insert(receipt_hash, recorded);
			LastNonce::<T>::insert(&payload.customer, payload.nonce);

			let minted = if let Some(m) = mint_along {
				T::AtomicMintHook::mint(
					&payload.operator,
					m.namespace,
					m.object_type.into_inner(),
					m.object_id.into_inner(),
					m.owner,
					m.blob.into_inner(),
					m.deposit,
				)
				.map_err(|_| Error::<T>::MintHookFailed)?;
				true
			} else {
				false
			};

			Self::deposit_event(Event::TradeRecorded {
				receipt_hash,
				customer: payload.customer,
				operator: payload.operator,
				amount: payload.amount,
				minted,
			});
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Look up a recorded receipt by its hash.
		pub fn receipt_of(hash: H256) -> Option<RecordedReceipt<T>> {
			Receipts::<T>::get(hash)
		}

		/// Look up a customer's last-recorded nonce. `None` if the
		/// customer hasn't submitted any receipts yet.
		pub fn last_nonce_of(account: &T::AccountId) -> Option<u64> {
			LastNonce::<T>::get(account)
		}
	}
}

#[cfg(test)]
mod tests;
