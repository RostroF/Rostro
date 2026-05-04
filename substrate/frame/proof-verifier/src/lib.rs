// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Proof Verifier Pallet
//!
//! Generic on-chain verifier for Plonky3 / FRI-based STARK proofs.
//!
//! Three downstream workloads consume this pallet:
//! - **Execution proofs**: validators verify that a block's state transition
//!   was computed correctly without re-executing it (~10-50ms verify vs
//!   seconds of re-execution).
//! - **Light-client checkpoints (BEEFY-equivalent)**: aggregate K-of-N
//!   validator signatures into a single STARK proof that mobile light
//!   clients verify in 50-300ms.
//! - **Validator-side hip-check**: hardware-attestation continuity proven
//!   in Plonky3 instead of Groth16/BN254 (validator hardware can run FRI
//!   provers; mobile cannot).
//!
//! The pallet is verifier-only. Proof generation happens off-chain (in
//! validator daemons or operator services). Each circuit family registers
//! its verifying-key hash on-chain via [`Call::register_verifier`] (admin
//! or governance origin); subsequent proofs reference that key by hash.
//!
//! Configuration commitments per `crypto_stack_v1.md`:
//! - **Field**: Goldilocks (`p3-goldilocks`, 64-bit prime, well-established)
//! - **Extension**: `BinomialExtensionField<Goldilocks, 2>` (~128-bit security)
//! - **In-circuit hash**: Poseidon2 (FRI-friendly, circuit-efficient)
//! - **Out-of-circuit hash**: Keccak (NIST SHA-3 standardized, transparent)
//! - **Proof system**: uni-stark + TwoAdicFriPcs
//! - **PQ posture**: hash-based, transparent setup, no curve assumption,
//!   post-quantum-secure by construction.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
	use codec::{Decode, Encode, MaxEncodedLen};
	use frame_support::{
		pallet_prelude::*,
		BoundedVec,
	};
	use frame_system::pallet_prelude::*;
	use sp_runtime::traits::Hash as HashT;
	use scale_info::TypeInfo;

	/// Identifier for a registered verifying key. Computed as the Blake2b-256
	/// hash of the SCALE-encoded verifying key bytes.
	pub type VerifierKeyHash = [u8; 32];

	/// Maximum size in bytes of a single verifying key blob the pallet will
	/// accept. Plonky3 verifying keys for typical Rostro circuits are under
	/// 1 KB; we set a generous cap here that can be lowered post-launch
	/// based on actual circuit measurements.
	pub const MAX_VERIFYING_KEY_LEN: u32 = 64 * 1024;

	/// Maximum size in bytes of a proof the pallet will verify in one
	/// extrinsic. Plonky3 STARK proofs are typically 50-200 KB; we allow up
	/// to 512 KB to leave headroom for larger circuits.
	pub const MAX_PROOF_LEN: u32 = 512 * 1024;

	/// Maximum size in bytes of public-input bytes for a single proof.
	pub const MAX_PUBLIC_INPUTS_LEN: u32 = 64 * 1024;

	/// Information about a registered verifying key.
	#[derive(
		Clone, Debug, Eq, PartialEq, Encode, Decode, MaxEncodedLen, TypeInfo,
	)]
	pub struct VerifierInfo<AccountId, BlockNumber> {
		/// The account that registered this verifier (for governance
		/// audit). `None` if registered via a non-account origin such as
		/// root or a governance collective.
		pub registrar: Option<AccountId>,
		/// Block at which the verifier was registered.
		pub registered_at: BlockNumber,
		/// SCALE-encoded verifying key bytes. Bounded to
		/// [`MAX_VERIFYING_KEY_LEN`].
		pub verifying_key: BoundedVec<u8, ConstU32<MAX_VERIFYING_KEY_LEN>>,
		/// Free-form circuit family identifier (e.g.,
		/// `b"execution-proof-v1"`, `b"hip-check-validator"`). Used by
		/// downstream pallets to dispatch on circuit type.
		pub circuit_family: BoundedVec<u8, ConstU32<64>>,
	}

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Origin permitted to register and deregister verifying keys.
		/// Typically root or a governance origin.
		type RegistrarOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Weight information for the pallet's extrinsics.
		type WeightInfo: WeightInfo;
	}

	/// Trait for benchmarked weights.
	pub trait WeightInfo {
		fn register_verifier() -> Weight;
		fn deregister_verifier() -> Weight;
		fn verify_proof() -> Weight;
	}

	/// Stub weights for development. Real weights generated via
	/// `frame-benchmarking` in a follow-up commit.
	impl WeightInfo for () {
		fn register_verifier() -> Weight {
			Weight::from_parts(10_000_000, 0)
		}
		fn deregister_verifier() -> Weight {
			Weight::from_parts(10_000_000, 0)
		}
		fn verify_proof() -> Weight {
			// Stub. Real verify cost is ~10-50ms wall-clock on validator
			// hardware per crypto_stack_v1.md target. Will be benchmarked
			// against actual circuits before mainnet.
			Weight::from_parts(50_000_000_000, 0)
		}
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Storage map: verifying-key hash → VerifierInfo.
	#[pallet::storage]
	#[pallet::getter(fn verifier)]
	pub type Verifiers<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		VerifierKeyHash,
		VerifierInfo<T::AccountId, BlockNumberFor<T>>,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A verifying key was registered.
		VerifierRegistered {
			key_hash: VerifierKeyHash,
			circuit_family: BoundedVec<u8, ConstU32<64>>,
			registrar: Option<T::AccountId>,
		},
		/// A verifying key was deregistered.
		VerifierDeregistered { key_hash: VerifierKeyHash },
		/// A proof was successfully verified.
		ProofVerified {
			key_hash: VerifierKeyHash,
			submitter: T::AccountId,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The supplied verifying-key hash is not registered.
		VerifierNotRegistered,
		/// The supplied verifying-key hash is already registered.
		VerifierAlreadyRegistered,
		/// The verifying key exceeds [`MAX_VERIFYING_KEY_LEN`] bytes.
		VerifyingKeyTooLarge,
		/// The verifying key is empty. Empty bytes hash to a deterministic
		/// constant; accepting this would create a registered "verifier"
		/// that proves nothing.
		EmptyVerifyingKey,
		/// The verifying key bytes are all zero. Known-invalid sentinel —
		/// no real circuit's verifying key is the zero blob.
		ZeroVerifyingKey,
		/// The proof exceeds [`MAX_PROOF_LEN`] bytes.
		ProofTooLarge,
		/// The proof bytes are empty. A real STARK proof is non-empty.
		EmptyProof,
		/// The public inputs exceed [`MAX_PUBLIC_INPUTS_LEN`] bytes.
		PublicInputsTooLarge,
		/// The circuit-family identifier exceeds 64 bytes.
		CircuitFamilyTooLarge,
		/// The circuit-family identifier is empty. Circuit family is a
		/// dispatch key for downstream pallets; the empty string routes
		/// nowhere.
		EmptyCircuitFamily,
		/// The supplied verifier-key hash is the all-zero sentinel. Rejected
		/// at the boundary even though storage lookup would also fail —
		/// types prove shape, not semantics.
		ZeroKeyHash,
		/// The proof failed verification.
		InvalidProof,
		/// Verification could not be performed (deserialization or runtime
		/// error before the cryptographic check).
		VerifierError,
		/// Real Plonky3 verification is not yet implemented; the extrinsic
		/// fails closed. Returning `Ok(())` from a stub verifier was a
		/// security gap caught in the 2026-05-04 red-team; do not relax
		/// this until `p3_uni_stark::verify` is wired in.
		VerifierNotImplemented,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register a new verifying key, indexed by its Blake2b-256 hash.
		///
		/// Called by [`Config::RegistrarOrigin`] (typically root or a
		/// governance origin) when a new circuit family is added to the
		/// chain. Subsequent [`Self::verify_proof`] calls reference this
		/// key by hash.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::register_verifier())]
		pub fn register_verifier(
			origin: OriginFor<T>,
			verifying_key: BoundedVec<u8, ConstU32<MAX_VERIFYING_KEY_LEN>>,
			circuit_family: BoundedVec<u8, ConstU32<64>>,
		) -> DispatchResult {
			T::RegistrarOrigin::ensure_origin(origin.clone())?;
			ensure!(!verifying_key.is_empty(), Error::<T>::EmptyVerifyingKey);
			ensure!(
				verifying_key.iter().any(|b| *b != 0),
				Error::<T>::ZeroVerifyingKey
			);
			ensure!(!circuit_family.is_empty(), Error::<T>::EmptyCircuitFamily);
			// Try to extract a signing account if the origin happens to
			// also be signed; otherwise `None` (root or non-account
			// governance origin).
			let registrar = ensure_signed(origin).ok();

			let key_hash = T::Hashing::hash(&verifying_key)
				.as_ref()
				.try_into()
				.map_err(|_| Error::<T>::VerifierError)?;

			ensure!(
				!Verifiers::<T>::contains_key(key_hash),
				Error::<T>::VerifierAlreadyRegistered
			);

			let now = frame_system::Pallet::<T>::block_number();
			Verifiers::<T>::insert(
				key_hash,
				VerifierInfo {
					registrar: registrar.clone(),
					registered_at: now,
					verifying_key,
					circuit_family: circuit_family.clone(),
				},
			);

			Self::deposit_event(Event::VerifierRegistered {
				key_hash,
				circuit_family,
				registrar,
			});
			Ok(())
		}

		/// Deregister a verifying key. Called by
		/// [`Config::RegistrarOrigin`] when a circuit family is retired.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::deregister_verifier())]
		pub fn deregister_verifier(
			origin: OriginFor<T>,
			key_hash: VerifierKeyHash,
		) -> DispatchResult {
			T::RegistrarOrigin::ensure_origin(origin)?;
			ensure!(key_hash != [0u8; 32], Error::<T>::ZeroKeyHash);
			ensure!(
				Verifiers::<T>::contains_key(key_hash),
				Error::<T>::VerifierNotRegistered
			);
			Verifiers::<T>::remove(key_hash);
			Self::deposit_event(Event::VerifierDeregistered { key_hash });
			Ok(())
		}

		/// Verify a Plonky3 STARK proof against a registered verifying key.
		///
		/// **Until Plonky3 verification lands, this extrinsic fails closed**:
		/// every call returns `Error::VerifierNotImplemented` after passing
		/// the input-validation and storage-lookup checks. Returning `Ok(())`
		/// from a stub verifier was identified as a critical security gap
		/// during the 2026-05-04 white-box red-team — any downstream pallet
		/// that began trusting the dispatch result or the `ProofVerified`
		/// event would be silently bypassable. Fail-closed avoids that
		/// trap; the path remains live so wiring work can continue without
		/// landing a soundness regression in the meantime.
		///
		/// When the real verifier lands it dispatches on `info.circuit_family`
		/// to invoke the correct `p3_uni_stark::verify` call with the right
		/// `StarkConfig` and AIR.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::verify_proof())]
		pub fn verify_proof(
			origin: OriginFor<T>,
			key_hash: VerifierKeyHash,
			proof: BoundedVec<u8, ConstU32<MAX_PROOF_LEN>>,
			_public_inputs: BoundedVec<u8, ConstU32<MAX_PUBLIC_INPUTS_LEN>>,
		) -> DispatchResult {
			let _submitter = ensure_signed(origin)?;
			ensure!(key_hash != [0u8; 32], Error::<T>::ZeroKeyHash);
			ensure!(!proof.is_empty(), Error::<T>::EmptyProof);
			// `_public_inputs` may legitimately be empty for circuits with no
			// public inputs; do not validate.

			let _info = Verifiers::<T>::get(key_hash)
				.ok_or(Error::<T>::VerifierNotRegistered)?;

			// TODO(stage3-plonky3-base): real Plonky3 verification.
			Err(Error::<T>::VerifierNotImplemented.into())
		}
	}
}

