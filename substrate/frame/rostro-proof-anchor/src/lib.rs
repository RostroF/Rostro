// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro Proof Anchor
//!
//! Inherent extrinsic that rides the per-window execution proof into the
//! block header as a `DigestItem::Consensus(*b"rstr", proof_bytes)`. Block
//! authors pull the latest proof bytes node-side via
//! `RostroProofInherentDataProvider` (defined in `rostro-node`); the
//! inherent's call body runs in apply_extrinsic and deposits the digest log.
//!
//! ## Why an inherent + pallet (consensus-agnostic)
//!
//! Aura today, Sassafras tomorrow, anything-else after — the consensus
//! engine doesn't need to know about the proof. The runtime emits the
//! digest, the consensus engine just feeds the runtime. This is the same
//! pattern Substrate uses for `pallet-timestamp` and similar infrastructure
//! pallets that need an inherent at every block.
//!
//! ## Inherent flow
//!
//! 1. Trace observer (node-side) generates a STARK proof for an 8-block
//!    window and stores the encoded bytes in an `Arc<Mutex<Option<Vec<u8>>>>`.
//! 2. `RostroProofInherentDataProvider::provide_inherent_data` reads (and
//!    consumes — `take()`) the latest proof bytes when the proposer asks
//!    for inherent data on a slot.
//! 3. `create_inherent` here builds a `Call::anchor_proof { proof }` if
//!    inherent data was provided.
//! 4. The runtime executes the inherent during `apply_extrinsic`, validates
//!    the proof bytes, and calls `frame_system::deposit_log` to attach the
//!    digest item to the block being built.
//! 5. Other validators import the block, see the digest item, and may
//!    verify it advisory off-chain.
//!
//! ## What this pallet doesn't do (yet)
//!
//! - **No on-chain verification**. The proof bytes are deposited as-is.
//!   Verification happens off-chain. A future runtime upgrade flips
//!   enforcement on by adding a host function for FRI verify and rejecting
//!   blocks whose anchored proofs don't verify.
//! - **No proof-of-presence requirement**. Not every block carries a proof
//!   — windows are 8 blocks long and the trace observer may lag. Blocks
//!   without an anchored proof are valid.
//! - **No replay protection**. The same proof can be anchored in multiple
//!   blocks if the inherent data provider keeps yielding it. We `take()` to
//!   consume once, but if a proof is regenerated it can be re-anchored.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;
use alloc::vec::Vec;

use sp_inherents::InherentIdentifier;
use sp_runtime::ConsensusEngineId;

/// Inherent identifier used by `RostroProofInherentDataProvider` to put
/// proof bytes into the inherent data and by this pallet to retrieve them.
pub const ROSTRO_PROOF_INHERENT_ID: InherentIdentifier = *b"rstrprof";

/// Consensus engine ID used in the digest item that anchors the proof
/// to the block header.
pub const ROSTRO_PROOF_ENGINE_ID: ConsensusEngineId = *b"rstr";

/// Minimum acceptable proof size. Real Plonky3 STARK proofs in our v0
/// configuration are ~2.9 KB; the floor here rejects obviously-malformed
/// input. Tunable as the proof system evolves.
pub const MIN_PROOF_LEN: u32 = 256;

/// Maximum acceptable proof size. v0 proofs are ~2.9 KB, but we leave
/// headroom for future AIR variations that produce larger artifacts.
pub const MAX_PROOF_LEN: u32 = 16 * 1024;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_inherents::{InherentData, IsFatalError};
	use sp_runtime::DigestItem;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::error]
	pub enum Error<T> {
		/// Proof bytes are empty. Known-invalid sentinel.
		EmptyProof,
		/// Proof shorter than `MIN_PROOF_LEN`. Real STARK proofs are
		/// kilobytes; this floor catches obvious garbage.
		ProofTooShort,
		/// Proof longer than `MAX_PROOF_LEN`. Defensive cap; real proofs
		/// from our v0 AIR are well under this.
		ProofTooLong,
		/// Proof bytes are all zero. Known-invalid sentinel — a real proof
		/// is high-entropy by construction.
		ZeroProof,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Anchor a per-window execution proof into the block header as a
		/// `DigestItem::Consensus(ROSTRO_PROOF_ENGINE_ID, proof)`.
		///
		/// Called via inherent only — `ensure_none(origin)` rejects signed
		/// or root origins. The proof bytes are validated for shape
		/// (size + zero-sentinel) but NOT cryptographically verified
		/// on-chain at v0; verification is advisory off-chain. Future
		/// runtime upgrade flips enforcement on.
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(10_000_000, 0))]
		pub fn anchor_proof(origin: OriginFor<T>, proof: Vec<u8>) -> DispatchResult {
			ensure_none(origin)?;
			ensure!(!proof.is_empty(), Error::<T>::EmptyProof);
			ensure!(proof.len() >= MIN_PROOF_LEN as usize, Error::<T>::ProofTooShort);
			ensure!(proof.len() <= MAX_PROOF_LEN as usize, Error::<T>::ProofTooLong);
			ensure!(proof.iter().any(|b| *b != 0), Error::<T>::ZeroProof);

			frame_system::Pallet::<T>::deposit_log(DigestItem::Consensus(
				ROSTRO_PROOF_ENGINE_ID,
				proof,
			));
			Ok(())
		}
	}

	#[pallet::inherent]
	impl<T: Config> ProvideInherent for Pallet<T> {
		type Call = Call<T>;
		type Error = InherentError;
		const INHERENT_IDENTIFIER: InherentIdentifier = ROSTRO_PROOF_INHERENT_ID;

		fn create_inherent(data: &InherentData) -> Option<Self::Call> {
			let proof: Option<Vec<u8>> =
				data.get_data(&ROSTRO_PROOF_INHERENT_ID).ok().flatten();
			let proof = proof?;
			// Size-validate at inherent-creation time so we never propose a
			// block whose own inherent will fail in apply_extrinsic.
			if proof.is_empty()
				|| proof.len() < MIN_PROOF_LEN as usize
				|| proof.len() > MAX_PROOF_LEN as usize
				|| proof.iter().all(|b| *b == 0)
			{
				return None;
			}
			Some(Call::anchor_proof { proof })
		}

		fn is_inherent(call: &Self::Call) -> bool {
			matches!(call, Call::anchor_proof { .. })
		}

		fn check_inherent(_call: &Self::Call, _data: &InherentData) -> Result<(), Self::Error> {
			// At v0 we don't fail blocks for proof-data mismatches — the
			// proof is advisory. A future hardening pass enforces equality
			// between the proposer's inherent data and what each importer
			// would expect.
			Ok(())
		}

		fn is_inherent_required(_data: &InherentData) -> Result<Option<Self::Error>, Self::Error> {
			// Anchoring is optional per block. Proofs lag the chain by up
			// to one window; not every slot has a fresh proof to anchor.
			Ok(None)
		}
	}

	/// Inherent-side errors. v0 doesn't actually use any (anchoring is
	/// optional), but the trait requires a type that implements
	/// `IsFatalError`.
	#[derive(Encode, Decode, core::fmt::Debug)]
	pub enum InherentError {
		/// Reserved for future hardening.
		Reserved,
	}

	impl IsFatalError for InherentError {
		fn is_fatal_error(&self) -> bool {
			false
		}
	}
}
