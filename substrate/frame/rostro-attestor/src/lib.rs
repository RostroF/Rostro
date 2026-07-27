//! # Rostro Attestor Quorum
//!
//! A subset of validators (the Attestor Quorum) signs the on-chain
//! `RootOfRoots` checkpoint with a **secp256k1** key so a foreign Ethereum
//! contract can verify it with `ecrecover`. Signatures land as **unsigned
//! transactions** (`validate_unsigned`, external source allowed) so the normal
//! mempool aggregates the quorum — no gossip stack. When a height collects a
//! quorum, its checkpoint is promoted to [`LatestCheckpoint`] and served.
//!
//! This crate is the runtime half. The node-side signer (an `offchain_worker`
//! that reads the root, signs, and submits `attest`) is wired separately. See
//! `docs/ATTESTOR-QUORUM.md`.
//!
//! ## Cross-chain byte-identity
//! `sp_io`'s recover is malleability-tolerant, Ethereum's `ecrecover` is not, so
//! every attestation is required to be **low-s** and `v ∈ {27,28}` — the exact
//! bytes the Solidity verifier accepts.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// A 20-byte Ethereum address (the attestor identity on both chains).
pub type EthAddress = [u8; 20];
/// A 65-byte recoverable ECDSA signature `r ‖ s ‖ v`.
pub type Signature = [u8; 65];

/// The current checkpoint value (the `RootOfRoots`) the quorum signs. Wired to
/// the ZkPki pallet in the runtime; a test value in the mock.
pub trait CheckpointProvider {
    fn root() -> [u8; 32];
}

/// The current attestor set (Ethereum addresses) and quorum threshold. Wired to
/// the validator set in the runtime; a fixed set in the mock.
pub trait AttestorRegistry {
    fn attestors() -> alloc::vec::Vec<EthAddress>;
    fn threshold() -> u32;
    fn is_attestor(addr: &EthAddress) -> bool {
        Self::attestors().iter().any(|a| a == addr)
    }
}

/// secp256k1 half-order `n/2`, big-endian. A signature with `s > n/2` is the
/// malleable high-s form Ethereum rejects (EIP-2); we reject it too.
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// `true` iff the 32-byte big-endian `s` is `<= n/2` (canonical low-s).
fn is_low_s(s: &[u8]) -> bool {
    if s.len() != 32 {
        return false;
    }
    for (a, b) in s.iter().zip(SECP256K1_HALF_ORDER.iter()) {
        if a < b {
            return true;
        }
        if a > b {
            return false;
        }
    }
    true // exactly n/2 is acceptable
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::vec::Vec;
    use codec::{Decode, Encode, MaxEncodedLen};
    use frame_support::{pallet_prelude::*, BoundedVec};
    use frame_system::pallet_prelude::*;
    use scale_info::TypeInfo;
    use sp_runtime::traits::UniqueSaturatedInto;

    /// A finalized checkpoint: the signed `RootOfRoots` at `height` plus the
    /// quorum of signatures. This is what a foreign verifier consumes.
    #[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[cfg_attr(feature = "std", derive(Debug))]
    #[scale_info(skip_type_params(T))]
    pub struct Checkpoint<T: Config> {
        pub root: [u8; 32],
        pub height: u64,
        pub sigs: BoundedVec<Signature, T::MaxAttestors>,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Supplies the current `RootOfRoots` (the value being signed).
        type Checkpoint: CheckpointProvider;
        /// Supplies the current attestor set + quorum threshold.
        type Attestors: AttestorRegistry;
        /// Upper bound on the attestor set (chain-wide validator cap).
        #[pallet::constant]
        type MaxAttestors: Get<u32>;
        /// How many recent heights of `(height → root)` to retain for validating
        /// attestations, and how long pending signatures may accumulate.
        #[pallet::constant]
        type RecentWindow: Get<u32>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Recorded `RootOfRoots` at each recent height, so an attestation for a past
    /// height is checked against the root the chain actually had then.
    #[pallet::storage]
    pub type RecentRoots<T: Config> = StorageMap<_, Twox64Concat, u64, [u8; 32], OptionQuery>;

    /// Signatures accumulating for a height, until they reach the quorum.
    #[pallet::storage]
    pub type PendingSigs<T: Config> = StorageMap<
        _,
        Twox64Concat,
        u64,
        BoundedVec<(EthAddress, Signature), T::MaxAttestors>,
        ValueQuery,
    >;

    /// The most recent height that reached a quorum — the served checkpoint.
    #[pallet::storage]
    pub type LatestCheckpoint<T: Config> = StorageValue<_, Checkpoint<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A height reached the quorum; `signers` distinct attestors signed it.
        CheckpointFinalized { height: u64, root: [u8; 32], signers: u32 },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The attested root does not match the root the chain had at `height`.
        RootMismatch,
        /// `v` is not the Ethereum form 27/28.
        BadRecoveryId,
        /// `s` is above `n/2` (non-canonical high-s; Ethereum would reject it).
        HighS,
        /// The signature failed to recover a public key.
        BadSignature,
        /// The recovered signer is not in the current attestor set.
        NotAnAttestor,
        /// This attestor already signed this height.
        DuplicateSigner,
        /// The height's signature set is already full.
        TooManySigs,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(n: BlockNumberFor<T>) {
            // Record the checkpoint root for this height so later-landing
            // attestations for it can be validated, then prune the window.
            let h: u64 = n.unique_saturated_into();
            RecentRoots::<T>::insert(h, T::Checkpoint::root());
            let window = T::RecentWindow::get() as u64;
            if h >= window {
                let old = h - window;
                RecentRoots::<T>::remove(old);
                PendingSigs::<T>::remove(old);
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Land one attestor's signature over `(height, root)`. Unsigned: the
        /// signature IS the authorization. Reaching the quorum finalizes the
        /// checkpoint.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(30_000_000, 0))]
        pub fn attest(
            origin: OriginFor<T>,
            height: u64,
            root: [u8; 32],
            sig: Signature,
        ) -> DispatchResult {
            ensure_none(origin)?;
            let addr = Self::verify_attestation(height, root, &sig)?;

            let count = PendingSigs::<T>::try_mutate(
                height,
                |v| -> Result<u32, DispatchError> {
                    ensure!(
                        !v.iter().any(|(a, _)| a == &addr),
                        Error::<T>::DuplicateSigner
                    );
                    v.try_push((addr, sig)).map_err(|_| Error::<T>::TooManySigs)?;
                    Ok(v.len() as u32)
                },
            )?;

            if count >= T::Attestors::threshold() {
                Self::finalize(height, root, count);
            }
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// The signed commitment: `keccak256(root ‖ height_be8)`.
        pub fn commitment(height: u64, root: &[u8; 32]) -> [u8; 32] {
            let mut buf = [0u8; 40];
            buf[..32].copy_from_slice(root);
            buf[32..].copy_from_slice(&height.to_be_bytes());
            sp_io::hashing::keccak_256(&buf)
        }

        /// Verify one attestation and return the recovered attestor address.
        /// Shared by `attest` and `validate_unsigned` so both agree exactly.
        pub fn verify_attestation(
            height: u64,
            root: [u8; 32],
            sig: &Signature,
        ) -> Result<EthAddress, Error<T>> {
            // 1. The attested root must be the one the chain had at that height.
            ensure!(
                RecentRoots::<T>::get(height) == Some(root),
                Error::<T>::RootMismatch
            );
            // 2. Ethereum-canonical form: v ∈ {27,28}, low-s.
            let v = sig[64];
            ensure!(v == 27 || v == 28, Error::<T>::BadRecoveryId);
            ensure!(is_low_s(&sig[32..64]), Error::<T>::HighS);
            // 3. Recover the public key (sp_io normalizes v ≥ 27 for us).
            let digest = Self::commitment(height, &root);
            let pubkey = sp_io::crypto::secp256k1_ecdsa_recover(sig, &digest)
                .map_err(|_| Error::<T>::BadSignature)?;
            // 4. Ethereum address = keccak256(pubkey)[12..].
            let addr = Self::eth_address(&pubkey);
            // 5. Must be a current attestor.
            ensure!(T::Attestors::is_attestor(&addr), Error::<T>::NotAnAttestor);
            Ok(addr)
        }

        /// `keccak256(uncompressed_pubkey_64)[12..]` — the 20-byte eth address.
        fn eth_address(pubkey: &[u8; 64]) -> EthAddress {
            let h = sp_io::hashing::keccak_256(pubkey);
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&h[12..]);
            addr
        }

        /// Promote a quorum-reaching height to the served checkpoint.
        fn finalize(height: u64, root: [u8; 32], signers: u32) {
            let sigs: BoundedVec<Signature, T::MaxAttestors> = BoundedVec::truncate_from(
                PendingSigs::<T>::get(height).into_iter().map(|(_, s)| s).collect::<Vec<_>>(),
            );
            LatestCheckpoint::<T>::put(Checkpoint { root, height, sigs });
            PendingSigs::<T>::remove(height);
            Self::deposit_event(Event::CheckpointFinalized { height, root, signers });
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            let Call::attest { height, root, sig } = call else {
                return InvalidTransaction::Call.into();
            };
            // Full crypto + membership check gates pool admission, so invalid or
            // non-attestor signatures never enter the mempool (spam-bounded).
            let addr = Self::verify_attestation(*height, *root, sig)
                .map_err(|_| InvalidTransaction::BadProof)?;
            ValidTransaction::with_tag_prefix("RostroAttestor")
                .priority(100)
                // One valid attestation per (height, attestor): the mempool
                // dedups, so external gossip of duplicates is dropped for free.
                .and_provides((*height, addr))
                .longevity(T::RecentWindow::get() as u64)
                // Allow external source: the mempool aggregates the quorum.
                .propagate(true)
                .build()
        }
    }
}
