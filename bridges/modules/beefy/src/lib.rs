// Copyright 2021 Parity Technologies (UK) Ltd.
// This file is part of Parity Bridges Common.

// Parity Bridges Common is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Bridges Common is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Bridges Common.  If not, see <http://www.gnu.org/licenses/>.

//! BEEFY bridge pallet.
//!
//! This pallet is an on-chain BEEFY light client for Substrate-based chains that are using the
//! following pallets bundle: `pallet-mmr`, `pallet-beefy` and `pallet-beefy-mmr`.
//!
//! The pallet is able to verify MMR leaf proofs and BEEFY commitments, so it has access
//! to the following data of the bridged chain:
//!
//! - header hashes
//! - changes of BEEFY authorities
//! - extra data of MMR leafs
//!
//! Given the header hash, other pallets are able to verify header-based proofs
//! (e.g. storage proofs, transaction inclusion proofs, etc.).

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use bp_beefy::{ChainWithBeefy, InitializationData};
use sp_std::{boxed::Box, prelude::*};

// Re-export in crate namespace for `construct_runtime!`
pub use pallet::*;

mod utils;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod mock_chain;

/// The target that will be used when publishing logs related to this pallet.
pub const LOG_TARGET: &str = "runtime::bridge-beefy";

/// Configured bridged chain.
pub type BridgedChain<T, I> = <T as Config<I>>::BridgedChain;
/// Block number, used by configured bridged chain.
pub type BridgedBlockNumber<T, I> = bp_runtime::BlockNumberOf<BridgedChain<T, I>>;
/// Block hash, used by configured bridged chain.
pub type BridgedBlockHash<T, I> = bp_runtime::HashOf<BridgedChain<T, I>>;

/// Pallet initialization data.
pub type InitializationDataOf<T, I> =
	InitializationData<BridgedBlockNumber<T, I>, bp_beefy::MmrHashOf<BridgedChain<T, I>>>;
/// BEEFY validator id, used by configured bridged chain.
pub type BridgedBeefyAuthorityId<T, I> = bp_beefy::BeefyAuthorityIdOf<BridgedChain<T, I>>;
/// BEEFY validator set, used by configured bridged chain.
pub type BridgedBeefyAuthoritySet<T, I> = bp_beefy::BeefyAuthoritySetOf<BridgedChain<T, I>>;
/// BEEFY authority set, used by configured bridged chain.
pub type BridgedBeefyAuthoritySetInfo<T, I> = bp_beefy::BeefyAuthoritySetInfoOf<BridgedChain<T, I>>;
/// BEEFY signed commitment, used by configured bridged chain.
pub type BridgedBeefySignedCommitment<T, I> = bp_beefy::BeefySignedCommitmentOf<BridgedChain<T, I>>;
/// MMR hashing algorithm, used by configured bridged chain.
pub type BridgedMmrHashing<T, I> = bp_beefy::MmrHashingOf<BridgedChain<T, I>>;
/// MMR hashing output type of `BridgedMmrHashing<T, I>`.
pub type BridgedMmrHash<T, I> = bp_beefy::MmrHashOf<BridgedChain<T, I>>;
/// The type of the MMR leaf extra data used by the configured bridged chain.
pub type BridgedBeefyMmrLeafExtra<T, I> = bp_beefy::BeefyMmrLeafExtraOf<BridgedChain<T, I>>;
/// BEEFY MMR proof type used by the pallet
pub type BridgedMmrProof<T, I> = bp_beefy::MmrProofOf<BridgedChain<T, I>>;
/// MMR leaf type, used by configured bridged chain.
pub type BridgedBeefyMmrLeaf<T, I> = bp_beefy::BeefyMmrLeafOf<BridgedChain<T, I>>;
/// Imported commitment data, stored by the pallet.
pub type ImportedCommitment<T, I> = bp_beefy::ImportedCommitment<
	BridgedBlockNumber<T, I>,
	BridgedBlockHash<T, I>,
	BridgedMmrHash<T, I>,
>;

/// Some high level info about the imported commitments.
#[derive(codec::Encode, codec::Decode, scale_info::TypeInfo)]
pub struct ImportedCommitmentsInfoData<BlockNumber> {
	/// Best known block number, provided in a BEEFY commitment. However this is not
	/// the best proven block. The best proven block is this block's parent.
	best_block_number: BlockNumber,
	/// The head of the `ImportedBlockNumbers` ring buffer.
	next_block_number_index: u32,
}

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use super::*;
	use bp_runtime::{BasicOperatingMode, OwnedBridgeModule};
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::config]
	pub trait Config<I: 'static = ()>: frame_system::Config {
		/// The upper bound on the number of requests allowed by the pallet.
		///
		/// A request refers to an action which writes a header to storage.
		///
		/// Once this bound is reached the pallet will reject all commitments
		/// until the request count has decreased.
		#[pallet::constant]
		type MaxRequests: Get<u32>;

		/// Maximal number of imported commitments to keep in the storage.
		///
		/// The setting is there to prevent growing the on-chain state indefinitely. Note
		/// the setting does not relate to block numbers - we will simply keep as much items
		/// in the storage, so it doesn't guarantee any fixed timeframe for imported commitments.
		#[pallet::constant]
		type CommitmentsToKeep: Get<u32>;

		/// The chain we are bridging to here.
		type BridgedChain: ChainWithBeefy;
	}

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T, I = ()>(PhantomData<(T, I)>);

	#[pallet::hooks]
	impl<T: Config<I>, I: 'static> Hooks<BlockNumberFor<T>> for Pallet<T, I> {
		fn on_initialize(_n: BlockNumberFor<T>) -> frame_support::weights::Weight {
			<RequestCount<T, I>>::mutate(|count| *count = count.saturating_sub(1));

			Weight::from_parts(0, 0)
				.saturating_add(T::DbWeight::get().reads(1))
				.saturating_add(T::DbWeight::get().writes(1))
		}
	}

	impl<T: Config<I>, I: 'static> OwnedBridgeModule<T> for Pallet<T, I> {
		const LOG_TARGET: &'static str = LOG_TARGET;
		type OwnerStorage = PalletOwner<T, I>;
		type OperatingMode = BasicOperatingMode;
		type OperatingModeStorage = PalletOperatingMode<T, I>;
	}

	#[pallet::call]
	impl<T: Config<I>, I: 'static> Pallet<T, I>
	where
		BridgedMmrHashing<T, I>: 'static + Send + Sync,
	{
		/// Initialize pallet with BEEFY authority set and best known finalized block number.
		#[pallet::call_index(0)]
		#[pallet::weight((T::DbWeight::get().reads_writes(2, 3), DispatchClass::Operational))]
		pub fn initialize(
			origin: OriginFor<T>,
			init_data: InitializationDataOf<T, I>,
		) -> DispatchResult {
			Self::ensure_owner_or_root(origin)?;

			let is_initialized = <ImportedCommitmentsInfo<T, I>>::exists();
			ensure!(!is_initialized, <Error<T, I>>::AlreadyInitialized);

			tracing::info!(target: LOG_TARGET, ?init_data, "Initializing bridge BEEFY pallet");
			Ok(initialize::<T, I>(init_data)?)
		}

		/// Change `PalletOwner`.
		///
		/// May only be called either by root, or by `PalletOwner`.
		#[pallet::call_index(1)]
		#[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
		pub fn set_owner(origin: OriginFor<T>, new_owner: Option<T::AccountId>) -> DispatchResult {
			<Self as OwnedBridgeModule<_>>::set_owner(origin, new_owner)
		}

		/// Halt or resume all pallet operations.
		///
		/// May only be called either by root, or by `PalletOwner`.
		#[pallet::call_index(2)]
		#[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
		pub fn set_operating_mode(
			origin: OriginFor<T>,
			operating_mode: BasicOperatingMode,
		) -> DispatchResult {
			<Self as OwnedBridgeModule<_>>::set_operating_mode(origin, operating_mode)
		}

		/// Submit a commitment generated by BEEFY authority set.
		///
		/// It will use the underlying storage pallet to fetch information about the current
		/// authority set and best finalized block number in order to verify that the commitment
		/// is valid.
		///
		/// If successful in verification, it will update the underlying storage with the data
		/// provided in the newly submitted commitment.
		#[pallet::call_index(3)]
		// The weight scales linearly with the three attacker-controlled vectors:
		// `validator_set.validators` (one ECDSA verify and one merkle leaf hash per
		// validator), `commitment.signatures` (one ECDSA verify per `Some` slot, bounded
		// above by `validator_set.len()`), and `mmr_proof.items` (one MMR hash per item).
		// Without this, `submit_commitment` was `#[pallet::weight(0)]` — i.e. free DoS
		// even on the failure path, since `validate_transaction` runs the full crypto
		// before charging the caller. We charge a conservative per-element constant
		// modeled on the BEEFY commitment-import path of `pallet-beefy-mmr`. The constant
		// is intentionally pessimistic; replace with a proper `WeightInfo` benchmark in
		// follow-up work (see TODO below).
		//
		// TODO: write a proper benchmark and switch to `T::WeightInfo::submit_commitment`.
		#[pallet::weight(Pallet::<T, I>::submit_commitment_weight(
			validator_set.len() as u32,
			commitment.signatures.len() as u32,
			mmr_proof.items.len() as u32,
		))]
		pub fn submit_commitment(
			origin: OriginFor<T>,
			commitment: BridgedBeefySignedCommitment<T, I>,
			validator_set: BridgedBeefyAuthoritySet<T, I>,
			mmr_leaf: Box<BridgedBeefyMmrLeaf<T, I>>,
			mmr_proof: BridgedMmrProof<T, I>,
		) -> DispatchResult
		where
			BridgedBeefySignedCommitment<T, I>: Clone,
		{
			Self::ensure_not_halted().map_err(Error::<T, I>::BridgeModule)?;
			ensure_signed(origin)?;

			ensure!(Self::request_count() < T::MaxRequests::get(), <Error<T, I>>::TooManyRequests);

			// Ensure that the commitment is for a better block.
			let commitments_info =
				ImportedCommitmentsInfo::<T, I>::get().ok_or(Error::<T, I>::NotInitialized)?;
			ensure!(
				commitment.commitment.block_number > commitments_info.best_block_number,
				Error::<T, I>::OldCommitment
			);

			// Verify commitment and mmr leaf.
			let current_authority_set_info = CurrentAuthoritySetInfo::<T, I>::get();
			let mmr_root = utils::verify_commitment::<T, I>(
				&commitment,
				&current_authority_set_info,
				&validator_set,
			)?;
			utils::verify_beefy_mmr_leaf::<T, I>(&mmr_leaf, mmr_proof, mmr_root)?;

			// Bind the proven leaf to the commitment's block number.
			//
			// `verify_beefy_mmr_leaf` only proves that `mmr_leaf` is *some* leaf inside
			// the MMR whose root the commitment authenticates. It does NOT prove that the
			// leaf is the leaf for `commitment.block_number`. Without this check an
			// attacker can pair a genuine commitment for block `N` with a genuine proof
			// for an unrelated historical leaf `M` and have the bridge write
			// `ImportedCommitments[N].parent_number_and_hash` to the parent of block `M`.
			// Downstream consumers reading that field as "the parent of the BEEFY-finalized
			// block at height N" then read a stale (but signed-looking) header hash.
			//
			// This is structurally Hyperbridge bug class #2 (Verichains writeup, April
			// 2026): a valid proof attached to a different request body. Per the BEEFY MMR
			// leaf semantics in `pallet-beefy-mmr`, a leaf produced when authoring block
			// `B` carries `parent_number_and_hash = (B - 1, parent_hash)`. The commitment
			// for block `B` therefore must satisfy
			// `mmr_leaf.parent_number_and_hash.0 + 1 == commitment.block_number`.
			let leaf_parent_number = mmr_leaf.parent_number_and_hash.0;
			let expected_commitment_block =
				sp_runtime::traits::CheckedAdd::checked_add(
					&leaf_parent_number,
					&sp_runtime::traits::One::one(),
				)
				.ok_or(Error::<T, I>::MmrLeafNotForCommitmentBlock)?;
			ensure!(
				expected_commitment_block == commitment.commitment.block_number,
				Error::<T, I>::MmrLeafNotForCommitmentBlock,
			);

			// Bind the proven leaf to the commitment's signing authority set.
			//
			// The v2 leaf added `current_validator_set_id` to record which BEEFY set was
			// active when the leaf was authored. The commitment is signed by some specific
			// authority set whose id is in `commitment.commitment.validator_set_id`. The
			// two values MUST match — if they don't, the leaf was authored under set X but
			// the signatures we're verifying come from set Y, so the bridge would be
			// trusting data that the signing set has no authority over.
			//
			// Without this check, the new `current_validator_set_id` field is dead weight:
			// it's in the leaf but no verifier consults it. The block-number binding above
			// pins WHICH BLOCK the leaf is for; this check pins WHICH SET signed it.
			ensure!(
				mmr_leaf.current_validator_set_id == commitment.commitment.validator_set_id,
				Error::<T, I>::MmrLeafSetIdMismatch,
			);

			// Refuse to rotate to an empty next-set.
			//
			// `signatures_required(0) == 0` (see `utils::signatures_required`), so an
			// empty `beefy_next_authority_set` becoming the current set would mean every
			// future commitment passes signature verification with zero signatures —
			// equivalent to letting the bridge be re-initialized by anyone holding any MMR
			// proof. The companion guard exists in `initialize`; we mirror it here on the
			// rotation path.
			ensure!(
				mmr_leaf.beefy_next_authority_set.len > 0,
				Error::<T, I>::EmptyNextAuthoritySet,
			);

			// Update request count.
			RequestCount::<T, I>::mutate(|count| *count += 1);
			// Update authority set if needed.
			if mmr_leaf.beefy_next_authority_set.id > current_authority_set_info.id {
				CurrentAuthoritySetInfo::<T, I>::put(mmr_leaf.beefy_next_authority_set);
			}

			// Import commitment.
			let block_number_index = commitments_info.next_block_number_index;
			let to_prune = ImportedBlockNumbers::<T, I>::try_get(block_number_index);
			ImportedCommitments::<T, I>::insert(
				commitment.commitment.block_number,
				ImportedCommitment::<T, I> {
					parent_number_and_hash: mmr_leaf.parent_number_and_hash,
					mmr_root,
				},
			);
			ImportedBlockNumbers::<T, I>::insert(
				block_number_index,
				commitment.commitment.block_number,
			);
			ImportedCommitmentsInfo::<T, I>::put(ImportedCommitmentsInfoData {
				best_block_number: commitment.commitment.block_number,
				next_block_number_index: (block_number_index + 1) % T::CommitmentsToKeep::get(),
			});
			if let Ok(old_block_number) = to_prune {
				tracing::debug!(
					target: LOG_TARGET,
					?old_block_number,
					"Pruning commitment for old block."
				);
				ImportedCommitments::<T, I>::remove(old_block_number);
			}

			tracing::info!(
				target: LOG_TARGET,
				block=?commitment.commitment.block_number,
				"Successfully imported commitment for block",
			);

			Ok(())
		}
	}

	/// The current number of requests which have written to storage.
	///
	/// If the `RequestCount` hits `MaxRequests`, no more calls will be allowed to the pallet until
	/// the request capacity is increased.
	///
	/// The `RequestCount` is decreased by one at the beginning of every block. This is to ensure
	/// that the pallet can always make progress.
	#[pallet::storage]
	pub type RequestCount<T: Config<I>, I: 'static = ()> = StorageValue<_, u32, ValueQuery>;

	/// High level info about the imported commitments.
	///
	/// Contains the following info:
	/// - best known block number of the bridged chain, finalized by BEEFY
	/// - the head of the `ImportedBlockNumbers` ring buffer
	#[pallet::storage]
	pub type ImportedCommitmentsInfo<T: Config<I>, I: 'static = ()> =
		StorageValue<_, ImportedCommitmentsInfoData<BridgedBlockNumber<T, I>>>;

	/// A ring buffer containing the block numbers of the commitments that we have imported,
	/// ordered by the insertion time.
	#[pallet::storage]
	pub(super) type ImportedBlockNumbers<T: Config<I>, I: 'static = ()> =
		StorageMap<_, Identity, u32, BridgedBlockNumber<T, I>>;

	/// All the commitments that we have imported and haven't been pruned yet.
	#[pallet::storage]
	pub type ImportedCommitments<T: Config<I>, I: 'static = ()> =
		StorageMap<_, Blake2_128Concat, BridgedBlockNumber<T, I>, ImportedCommitment<T, I>>;

	/// The current BEEFY authority set at the bridged chain.
	#[pallet::storage]
	pub type CurrentAuthoritySetInfo<T: Config<I>, I: 'static = ()> =
		StorageValue<_, BridgedBeefyAuthoritySetInfo<T, I>, ValueQuery>;

	/// Optional pallet owner.
	///
	/// Pallet owner has the right to halt all pallet operations and then resume it. If it is
	/// `None`, then there are no direct ways to halt/resume pallet operations, but other
	/// runtime methods may still be used to do that (i.e. `democracy::referendum` to update halt
	/// flag directly or calling `set_operating_mode`).
	#[pallet::storage]
	pub type PalletOwner<T: Config<I>, I: 'static = ()> =
		StorageValue<_, T::AccountId, OptionQuery>;

	/// The current operating mode of the pallet.
	///
	/// Depending on the mode either all, or no transactions will be allowed.
	#[pallet::storage]
	pub type PalletOperatingMode<T: Config<I>, I: 'static = ()> =
		StorageValue<_, BasicOperatingMode, ValueQuery>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config<I>, I: 'static = ()> {
		/// Optional module owner account.
		pub owner: Option<T::AccountId>,
		/// Optional module initialization data.
		pub init_data: Option<InitializationDataOf<T, I>>,
	}

	#[pallet::genesis_build]
	impl<T: Config<I>, I: 'static> BuildGenesisConfig for GenesisConfig<T, I> {
		fn build(&self) {
			if let Some(ref owner) = self.owner {
				<PalletOwner<T, I>>::put(owner);
			}

			if let Some(init_data) = self.init_data.clone() {
				initialize::<T, I>(init_data)
					.expect("invalid initialization data of BEEFY bridge pallet");
			} else {
				// Since the bridge hasn't been initialized we shouldn't allow anyone to perform
				// transactions.
				<PalletOperatingMode<T, I>>::put(BasicOperatingMode::Halted);
			}
		}
	}

	#[pallet::error]
	pub enum Error<T, I = ()> {
		/// The pallet has not been initialized yet.
		NotInitialized,
		/// The pallet has already been initialized.
		AlreadyInitialized,
		/// Invalid initial authority set.
		InvalidInitialAuthoritySet,
		/// There are too many requests for the current window to handle.
		TooManyRequests,
		/// The imported commitment is older than the best commitment known to the pallet.
		OldCommitment,
		/// The commitment is signed by unknown validator set.
		InvalidCommitmentValidatorSetId,
		/// The id of the provided validator set is invalid.
		InvalidValidatorSetId,
		/// The number of signatures in the commitment is invalid.
		InvalidCommitmentSignaturesLen,
		/// The number of validator ids provided is invalid.
		InvalidValidatorSetLen,
		/// There aren't enough correct signatures in the commitment to finalize the block.
		NotEnoughCorrectSignatures,
		/// MMR root is missing from the commitment.
		MmrRootMissingFromCommitment,
		/// The commitment payload is not in canonical form.
		///
		/// `Payload` requires identifiers to be sorted strictly ascending (no duplicates).
		/// `Decode` does not enforce this, so a malicious encoder can ship a payload where
		/// `get_raw` (binary search) and `get_all_raw` (linear scan) resolve duplicate ids
		/// to different entries — a port-induced bug class where two reasonable verifier
		/// implementations of the same payload disagree on which value is canonical.
		/// The bridge rejects non-canonical payloads at extraction time so all downstream
		/// reads are unambiguous.
		NonCanonicalCommitmentPayload,
		/// MMR proof verification has failed.
		MmrProofVerificationFailed,
		/// The MMR leaf does not correspond to the block number of the commitment.
		///
		/// The proof verifies that `mmr_leaf` is *some* leaf in the MMR rooted at the
		/// commitment payload. It does not on its own prove that the leaf is the leaf
		/// for `commitment.block_number`. This error fires when the bridge detects that
		/// `mmr_leaf.parent_number_and_hash.0 + 1 != commitment.block_number`, which
		/// would otherwise let an attacker pair a real commitment for block `N` with a
		/// real proof for an unrelated historical leaf and have the bridge store the
		/// wrong `(parent_number_and_hash)` under key `N`. This is the analogue of
		/// Hyperbridge's missing-binding bug #2 (April 2026 incident).
		MmrLeafNotForCommitmentBlock,
		/// The MMR leaf's `current_validator_set_id` does not match the commitment's
		/// `validator_set_id`.
		///
		/// In the v2 leaf, `current_validator_set_id` records the BEEFY authority set
		/// that was active when the leaf was authored. The commitment is signed by some
		/// specific authority set whose id is in `commitment.validator_set_id`. If those
		/// two values disagree, either the commitment is signed by the wrong set for this
		/// block, or the leaf is from a different set. Both are equivalent to fix #2's
		/// "leaf not for this commitment" failure mode but caught against a different
		/// invariant — required because the parent-block-number check alone does not
		/// constrain *which set's signatures* must have authenticated the leaf's data.
		MmrLeafSetIdMismatch,
		/// The MMR leaf's `beefy_next_authority_set.len` is zero.
		///
		/// `signatures_required(0) == 0`, so adopting an empty next-set as the new current
		/// set would mean every subsequent commitment passes signature verification with
		/// zero signatures. Reject the leaf and refuse to rotate.
		EmptyNextAuthoritySet,
		/// The validators are not matching the merkle tree root of the authority set.
		InvalidValidatorSetRoot,
		/// Error generated by the `OwnedBridgeModule` trait.
		BridgeModule(bp_runtime::OwnedBridgeModuleError),
	}

	/// Initialize pallet with given parameters.
	pub(super) fn initialize<T: Config<I>, I: 'static>(
		init_data: InitializationDataOf<T, I>,
	) -> Result<(), Error<T, I>> {
		if init_data.authority_set.len == 0 {
			return Err(Error::<T, I>::InvalidInitialAuthoritySet);
		}
		CurrentAuthoritySetInfo::<T, I>::put(init_data.authority_set);

		<PalletOperatingMode<T, I>>::put(init_data.operating_mode);
		ImportedCommitmentsInfo::<T, I>::put(ImportedCommitmentsInfoData {
			best_block_number: init_data.best_block_number,
			next_block_number_index: 0,
		});

		Ok(())
	}

	impl<T: Config<I>, I: 'static> Pallet<T, I> {
		/// The current number of requests which have written to storage.
		pub fn request_count() -> u32 {
			RequestCount::<T, I>::get()
		}

		/// Conservative weight estimate for `submit_commitment` that scales linearly with
		/// the three attacker-controlled vectors (validator set size, number of signature
		/// slots, and MMR proof item count).
		///
		/// The per-element constants are intentionally pessimistic — they are an interim
		/// measure to remove the `weight(0)` DoS surface. They should be replaced by
		/// proper FRAME benchmarks (`T::WeightInfo::submit_commitment(...)`) in follow-up
		/// work; this function exists so that `submit_commitment` already charges
		/// proportionally to its inputs even before benchmarks land.
		///
		/// Picked to be in the same order of magnitude as
		/// `pallet_beefy_mmr::WeightInfo::n_leafs_proof_is_optimal` and the per-validator
		/// signature-verify cost of comparable BEEFY-related dispatchables.
		pub fn submit_commitment_weight(
			validators_len: u32,
			signatures_len: u32,
			proof_items_len: u32,
		) -> frame_support::weights::Weight {
			use frame_support::weights::Weight;

			// Fixed overhead: storage reads/writes (RequestCount, ImportedCommitments etc.).
			let base = T::DbWeight::get().reads_writes(4, 4);
			// Per-validator: one ECDSA recover + one keccak/merkle leaf hash.
			// Pessimistic: ~250 us per validator.
			let per_validator = Weight::from_parts(250_000_000, 0);
			// Per-signature slot: at most one ECDSA verify on the call boundary.
			let per_signature = Weight::from_parts(100_000_000, 0);
			// Per-MMR-item: one keccak combine.
			let per_proof_item = Weight::from_parts(20_000_000, 0);

			base.saturating_add(per_validator.saturating_mul(validators_len.into()))
				.saturating_add(per_signature.saturating_mul(signatures_len.into()))
				.saturating_add(per_proof_item.saturating_mul(proof_items_len.into()))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bp_runtime::{BasicOperatingMode, OwnedBridgeModuleError};
	use bp_test_utils::generate_owned_bridge_module_tests;
	use frame_support::{assert_noop, assert_ok, traits::Get};
	use mock::*;
	use mock_chain::*;
	use sp_consensus_beefy::mmr::BeefyAuthoritySet;
	use sp_runtime::DispatchError;

	fn next_block() {
		use frame_support::traits::OnInitialize;

		let current_number = frame_system::Pallet::<TestRuntime>::block_number();
		frame_system::Pallet::<TestRuntime>::set_block_number(current_number + 1);
		let _ = Pallet::<TestRuntime>::on_initialize(current_number);
	}

	fn import_header_chain(headers: Vec<HeaderAndCommitment>) {
		for header in headers {
			if header.commitment.is_some() {
				assert_ok!(import_commitment(header));
			}
		}
	}

	#[test]
	fn fails_to_initialize_if_already_initialized() {
		run_test_with_initialize(32, || {
			assert_noop!(
				Pallet::<TestRuntime>::initialize(
					RuntimeOrigin::root(),
					InitializationData {
						operating_mode: BasicOperatingMode::Normal,
						best_block_number: 0,
						authority_set: BeefyAuthoritySet {
							id: 0,
							len: 1,
							keyset_commitment: [0u8; 32].into()
						}
					}
				),
				Error::<TestRuntime, ()>::AlreadyInitialized,
			);
		});
	}

	#[test]
	fn fails_to_initialize_if_authority_set_is_empty() {
		run_test(|| {
			assert_noop!(
				Pallet::<TestRuntime>::initialize(
					RuntimeOrigin::root(),
					InitializationData {
						operating_mode: BasicOperatingMode::Normal,
						best_block_number: 0,
						authority_set: BeefyAuthoritySet {
							id: 0,
							len: 0,
							keyset_commitment: [0u8; 32].into()
						}
					}
				),
				Error::<TestRuntime, ()>::InvalidInitialAuthoritySet,
			);
		});
	}

	#[test]
	fn fails_to_import_commitment_if_halted() {
		run_test_with_initialize(1, || {
			assert_ok!(Pallet::<TestRuntime>::set_operating_mode(
				RuntimeOrigin::root(),
				BasicOperatingMode::Halted
			));
			assert_noop!(
				import_commitment(ChainBuilder::new(1).append_finalized_header().to_header()),
				Error::<TestRuntime, ()>::BridgeModule(OwnedBridgeModuleError::Halted),
			);
		})
	}

	#[test]
	fn fails_to_import_commitment_if_too_many_requests() {
		run_test_with_initialize(1, || {
			let max_requests = <<TestRuntime as Config>::MaxRequests as Get<u32>>::get() as u64;
			let mut chain = ChainBuilder::new(1);
			for _ in 0..max_requests + 2 {
				chain = chain.append_finalized_header();
			}

			// import `max_request` headers
			for i in 0..max_requests {
				assert_ok!(import_commitment(chain.header(i + 1)));
			}

			// try to import next header: it fails because we are no longer accepting commitments
			assert_noop!(
				import_commitment(chain.header(max_requests + 1)),
				Error::<TestRuntime, ()>::TooManyRequests,
			);

			// when next block is "started", we allow import of next header
			next_block();
			assert_ok!(import_commitment(chain.header(max_requests + 1)));

			// but we can't import two headers until next block and so on
			assert_noop!(
				import_commitment(chain.header(max_requests + 2)),
				Error::<TestRuntime, ()>::TooManyRequests,
			);
		})
	}

	#[test]
	fn fails_to_import_commitment_if_not_initialized() {
		run_test(|| {
			assert_noop!(
				import_commitment(ChainBuilder::new(1).append_finalized_header().to_header()),
				Error::<TestRuntime, ()>::NotInitialized,
			);
		})
	}

	#[test]
	fn submit_commitment_works_with_long_chain_with_handoffs() {
		run_test_with_initialize(3, || {
			let chain = ChainBuilder::new(3)
				.append_finalized_header()
				.append_default_headers(16) // 2..17
				.append_finalized_header() // 18
				.append_default_headers(16) // 19..34
				.append_handoff_header(9) // 35
				.append_default_headers(8) // 36..43
				.append_finalized_header() // 44
				.append_default_headers(8) // 45..52
				.append_handoff_header(17) // 53
				.append_default_headers(4) // 54..57
				.append_finalized_header() // 58
				.append_default_headers(4); // 59..63
			import_header_chain(chain.to_chain());

			assert_eq!(
				ImportedCommitmentsInfo::<TestRuntime>::get().unwrap().best_block_number,
				58
			);
			assert_eq!(CurrentAuthoritySetInfo::<TestRuntime>::get().id, 2);
			assert_eq!(CurrentAuthoritySetInfo::<TestRuntime>::get().len, 17);

			let imported_commitment = ImportedCommitments::<TestRuntime>::get(58).unwrap();
			assert_eq!(
				imported_commitment,
				bp_beefy::ImportedCommitment {
					parent_number_and_hash: (57, chain.header(57).header.hash()),
					mmr_root: chain.header(58).mmr_root,
				},
			);
		})
	}

	#[test]
	fn commitment_pruning_works() {
		run_test_with_initialize(3, || {
			let commitments_to_keep = <TestRuntime as Config<()>>::CommitmentsToKeep::get();
			let commitments_to_import: Vec<HeaderAndCommitment> = ChainBuilder::new(3)
				.append_finalized_headers(commitments_to_keep as usize + 2)
				.to_chain();

			// import exactly `CommitmentsToKeep` commitments
			for index in 0..commitments_to_keep {
				next_block();
				import_commitment(commitments_to_import[index as usize].clone())
					.expect("must succeed");
				assert_eq!(
					ImportedCommitmentsInfo::<TestRuntime>::get().unwrap().next_block_number_index,
					(index + 1) % commitments_to_keep
				);
			}

			// ensure that all commitments are in the storage
			assert_eq!(
				ImportedCommitmentsInfo::<TestRuntime>::get().unwrap().best_block_number,
				commitments_to_keep as TestBridgedBlockNumber
			);
			assert_eq!(
				ImportedCommitmentsInfo::<TestRuntime>::get().unwrap().next_block_number_index,
				0
			);
			for index in 0..commitments_to_keep {
				assert!(ImportedCommitments::<TestRuntime>::get(
					index as TestBridgedBlockNumber + 1
				)
				.is_some());
				assert_eq!(
					ImportedBlockNumbers::<TestRuntime>::get(index),
					Some(Into::into(index + 1)),
				);
			}

			// import next commitment
			next_block();
			import_commitment(commitments_to_import[commitments_to_keep as usize].clone())
				.expect("must succeed");
			assert_eq!(
				ImportedCommitmentsInfo::<TestRuntime>::get().unwrap().next_block_number_index,
				1
			);
			assert!(ImportedCommitments::<TestRuntime>::get(
				commitments_to_keep as TestBridgedBlockNumber + 1
			)
			.is_some());
			assert_eq!(
				ImportedBlockNumbers::<TestRuntime>::get(0),
				Some(Into::into(commitments_to_keep + 1)),
			);
			// the side effect of the import is that the commitment#1 is pruned
			assert!(ImportedCommitments::<TestRuntime>::get(1).is_none());

			// import next commitment
			next_block();
			import_commitment(commitments_to_import[commitments_to_keep as usize + 1].clone())
				.expect("must succeed");
			assert_eq!(
				ImportedCommitmentsInfo::<TestRuntime>::get().unwrap().next_block_number_index,
				2
			);
			assert!(ImportedCommitments::<TestRuntime>::get(
				commitments_to_keep as TestBridgedBlockNumber + 2
			)
			.is_some());
			assert_eq!(
				ImportedBlockNumbers::<TestRuntime>::get(1),
				Some(Into::into(commitments_to_keep + 2)),
			);
			// the side effect of the import is that the commitment#2 is pruned
			assert!(ImportedCommitments::<TestRuntime>::get(1).is_none());
			assert!(ImportedCommitments::<TestRuntime>::get(2).is_none());
		});
	}

	generate_owned_bridge_module_tests!(BasicOperatingMode::Normal, BasicOperatingMode::Halted);

	// Regression test for the missing-binding finding (Hyperbridge bug class #2).
	//
	// Without the leaf-to-commitment-block binding (`leaf.parent_number_and_hash.0 + 1
	// == commitment.block_number`), an attacker can pair a real signed commitment for
	// block `N+1` with a real proof for the leaf at block `N` (or any other historical
	// block). The proof verifies (it is a real proof against a real MMR root in the
	// real commitment payload), and the bridge would write an `ImportedCommitments`
	// entry whose `parent_number_and_hash` does not actually correspond to the parent of
	// block `N+1`. This regression test demonstrates that the binding rejects exactly
	// that mismatch.
	#[test]
	fn submit_commitment_rejects_leaf_not_for_commitment_block() {
		// Build a header for block 1 (its leaf has parent_number_and_hash = (0, ..)).
		// Re-sign the commitment with a tampered `block_number = 2`. The MMR proof
		// itself stays consistent (we did not touch the leaf or the proof). Without the
		// binding check the bridge would have accepted this and stored the wrong
		// `parent_number_and_hash` under key 2.
		run_test_with_initialize(1, || {
			let validators = validator_pairs(0, 1);
			let mut header =
				ChainBuilder::new(1).append_finalized_header().to_header();
			header.customize_commitment(
				|commitment| {
					commitment.block_number = 2;
				},
				&validators,
				1,
			);
			assert_noop!(
				import_commitment(header),
				Error::<TestRuntime, ()>::MmrLeafNotForCommitmentBlock,
			);
		});
	}
}
