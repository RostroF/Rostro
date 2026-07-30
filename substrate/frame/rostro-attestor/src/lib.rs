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

/// The attestor session key. A **secp256k1** app-key (own key type `atte`) that
/// joins the runtime's `SessionKeys` so it rotates with the validator's other
/// keys and is vetted through the same `set_keys` path. It is the key the node's
/// offchain signer uses; the pallet caches the active set's derived Ethereum
/// addresses each session (see [`OneSessionHandler`] impl below).
pub mod app {
    use sp_application_crypto::{app_crypto, ecdsa, KeyTypeId};
    /// Key type identifier for the attestor signing key.
    pub const ATTESTOR: KeyTypeId = KeyTypeId(*b"atte");
    app_crypto!(ecdsa, ATTESTOR);
}
/// The attestor authority public key (secp256k1 app-public).
pub type AuthorityId = app::Public;

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
    use frame_support::{
        crypto::ecdsa::ECDSAExt, pallet_prelude::*, traits::OneSessionHandler, BoundedVec,
        WeakBoundedVec,
    };
    use frame_system::{
        offchain::{CreateBare, SubmitTransaction},
        pallet_prelude::*,
    };
    use scale_info::TypeInfo;
    use sp_application_crypto::RuntimeAppPublic;
    use sp_runtime::{traits::UniqueSaturatedInto, BoundToRuntimeAppPublic};

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
    // `CreateBare` lets the offchain signer submit the unsigned `attest` extrinsic
    // (the mempool then aggregates the quorum — no gossip stack).
    pub trait Config: frame_system::Config + CreateBare<Call<Self>> {
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

    /// The current session's attestor set as Ethereum addresses, derived once per
    /// session from the validators' `ATTESTOR` session keys (see the
    /// [`OneSessionHandler`] impl). This is what the runtime's [`AttestorRegistry`]
    /// binding reads. Bounded by `MaxAttestors` (the chain-wide validator cap).
    #[pallet::storage]
    pub type SessionAttestors<T: Config> =
        StorageValue<_, WeakBoundedVec<EthAddress, T::MaxAttestors>, ValueQuery>;

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

        /// Offchain signer (im-online shape). On each block, a validator holding
        /// an in-set `ATTESTOR` key signs this height's checkpoint and submits an
        /// unsigned `attest`. Self-gating: a node with no in-set attestor key in
        /// its keystore does nothing.
        fn offchain_worker(now: BlockNumberFor<T>) {
            if sp_io::offchain::is_validator() {
                Self::offchain_attest(now);
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
        /// The current served checkpoint (root, height, quorum signatures), or
        /// `None` if no height has reached quorum yet. Projected to a plain,
        /// version-stable struct by the runtime API (`ZkPkiApi::signed_checkpoint`).
        pub fn latest_checkpoint() -> Option<Checkpoint<T>> {
            LatestCheckpoint::<T>::get()
        }

        /// The current session's attestor set as Ethereum addresses — a foreign
        /// contract pins this list; the node uses it to track rotation.
        pub fn attestor_addresses() -> Vec<EthAddress> {
            SessionAttestors::<T>::get().into_inner()
        }

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

        /// Promote a quorum-reaching height to the served checkpoint. Monotonic: a
        /// stale or replayed quorum for a height at or below the currently served
        /// checkpoint is discarded, never regressing `LatestCheckpoint`. This closes
        /// the checkpoint-regression race (a straggler quorum for an older height) and
        /// backstops the pool-level guard in `validate_unsigned` for any on-chain or
        /// non-eclipsing consumer.
        fn finalize(height: u64, root: [u8; 32], signers: u32) {
            if let Some(existing) = LatestCheckpoint::<T>::get() {
                if height <= existing.height {
                    PendingSigs::<T>::remove(height);
                    return;
                }
            }
            let sigs: BoundedVec<Signature, T::MaxAttestors> = BoundedVec::truncate_from(
                PendingSigs::<T>::get(height).into_iter().map(|(_, s)| s).collect::<Vec<_>>(),
            );
            LatestCheckpoint::<T>::put(Checkpoint { root, height, sigs });
            PendingSigs::<T>::remove(height);
            Self::deposit_event(Event::CheckpointFinalized { height, root, signers });
        }
    }

    impl<T: Config> Pallet<T> {
        /// Derive Ethereum addresses for a session's attestor keys and cache them
        /// as the current attestor set. A key that fails to decode or decompress
        /// is skipped (a well-formed `ATTESTOR` session key never does).
        fn cache_session_attestors(keys: impl Iterator<Item = AuthorityId>) {
            let addrs: Vec<EthAddress> = keys.filter_map(|k| Self::key_to_eth(&k)).collect();
            let bounded = WeakBoundedVec::<_, T::MaxAttestors>::force_from(
                addrs,
                Some("RostroAttestor: attestor keys exceed MaxAttestors; excess dropped."),
            );
            SessionAttestors::<T>::put(bounded);
        }

        /// `AuthorityId` (compressed secp256k1) → 20-byte Ethereum address, via
        /// `k256` decompression + keccak. Runtime-safe (see `ECDSAExt`).
        fn key_to_eth(key: &AuthorityId) -> Option<EthAddress> {
            use sp_core::crypto::ByteArray;
            let raw = ByteArray::to_raw_vec(key);
            sp_core::ecdsa::Public::from_slice(&raw).ok()?.to_eth_address().ok()
        }

        /// Sign this height's checkpoint with each local `ATTESTOR` key that is in
        /// the current attestor set, and submit an unsigned `attest` per key.
        fn offchain_attest(now: BlockNumberFor<T>) {
            let height: u64 = now.unique_saturated_into();
            // Bind to exactly the root `validate_unsigned` will check for `height`.
            let Some(root) = RecentRoots::<T>::get(height) else { return };
            if !Self::should_attest(height, &root) {
                return;
            }
            let set = SessionAttestors::<T>::get();
            let digest = Self::commitment(height, &root);
            for auth in AuthorityId::all() {
                // Only our keys that are in the current attestor set sign.
                let Some(addr) = Self::key_to_eth(&auth) else { continue };
                if !set.contains(&addr) {
                    continue;
                }
                // Sign the keccak digest directly (NOT RuntimeAppPublic::sign,
                // which blake2-prehashes) so the recovered signer is the eth key.
                use sp_core::crypto::ByteArray;
                let raw = ByteArray::to_raw_vec(&auth);
                let Ok(core_pub) = sp_core::ecdsa::Public::from_slice(&raw) else { continue };
                let Some(sig) =
                    sp_io::crypto::ecdsa_sign_prehashed(app::ATTESTOR, &core_pub, &digest)
                else {
                    continue;
                };
                // Ethereum form: v ∈ {27,28} (the host returns 0/1); k256 already
                // yields low-s, so the bytes satisfy the pallet's canonical check.
                let mut bytes: [u8; 65] = sig.0;
                bytes[64] = bytes[64].saturating_add(27);
                let xt = T::create_bare(Call::attest { height, root, sig: bytes }.into());
                let _ = SubmitTransaction::<T, Call<T>>::submit_transaction(xt);
            }
        }

        /// Attest on a changed root, or on a heartbeat every `RecentWindow/2`
        /// blocks so a stable root still refreshes the served checkpoint (and a
        /// validator that missed the change-block still contributes its sig).
        fn should_attest(height: u64, root: &[u8; 32]) -> bool {
            let hb = (T::RecentWindow::get() as u64) / 2;
            if hb != 0 && height % hb == 0 {
                return true;
            }
            match RecentRoots::<T>::get(height.saturating_sub(1)) {
                Some(prev) => &prev != root,
                None => true,
            }
        }
    }

    impl<T: Config> BoundToRuntimeAppPublic for Pallet<T> {
        type Public = AuthorityId;
    }

    /// Caches each session's validator attestor keys (as Ethereum addresses) so
    /// the [`AttestorRegistry`] binding always reflects the active validator set.
    /// The `ATTESTOR` key rides `SessionKeys`, so this fires on every rotation.
    impl<T: Config> OneSessionHandler<T::AccountId> for Pallet<T> {
        type Key = AuthorityId;

        fn on_genesis_session<'a, I: 'a>(validators: I)
        where
            I: Iterator<Item = (&'a T::AccountId, AuthorityId)>,
        {
            Self::cache_session_attestors(validators.map(|(_, k)| k));
        }

        fn on_new_session<'a, I: 'a>(_changed: bool, validators: I, _queued: I)
        where
            I: Iterator<Item = (&'a T::AccountId, AuthorityId)>,
        {
            Self::cache_session_attestors(validators.map(|(_, k)| k));
        }

        fn on_disabled(_validator_index: u32) {
            // A validator disabled mid-session simply may not sign; the ⌈2/3⌉
            // quorum already tolerates absent signers, and the set refreshes at
            // the next session boundary.
        }
    }

    /// The runtime binds `Config::Attestors` to the pallet itself: the attestor
    /// set is the current session's validators (via their `ATTESTOR` keys), with
    /// a ⌈2/3⌉ quorum. `v0` = all active validators; a designated subset is a
    /// later refinement via the key-lineage template.
    impl<T: Config> AttestorRegistry for Pallet<T> {
        fn attestors() -> Vec<EthAddress> {
            SessionAttestors::<T>::get().into_inner()
        }
        fn threshold() -> u32 {
            let n = SessionAttestors::<T>::get().len() as u32;
            if n == 0 {
                // Never auto-finalize on an empty attestor set: ⌈2·0/3⌉ = 0 would make
                // `count >= threshold` vacuously true. No sig can land on an empty set
                // (recovery fails membership), but floor at 1 so the invariant is local.
                return 1;
            }
            // ⌈2n/3⌉
            (2 * n + 2) / 3
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
            // Monotonic gate: reject attestations for a height at or below the served
            // checkpoint. After `finalize` prunes `PendingSigs`, the `DuplicateSigner`
            // memory for that height is gone, so byte-for-byte captured `attest` txs
            // would otherwise re-enter the pool and re-finalize an old height over a
            // newer checkpoint — permissionless, no attestor key (R4). This closes it
            // at pool admission; `finalize` backstops on-chain.
            let latest_height = LatestCheckpoint::<T>::get().map(|c| c.height).unwrap_or_default();
            if *height <= latest_height {
                return InvalidTransaction::Stale.into();
            }
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
