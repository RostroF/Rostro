//! # zkpki-pallet-lab
//!
//! Stage 4a PoC — a standalone FRAME pallet that verifies mime_wrap
//! Groth16 proofs and tracks consumed (bucket, nonce) pairs for
//! replay prevention.
//!
//! Scope: two extrinsics, three storage items, three errors, two
//! events. No attestation-chain verification in this lab (that lives
//! in a separate pallet / HIP pipeline). No weight benchmarking yet
//! (stubs present; real weights come in Stage 4b via
//! `frame-benchmarking`).
//!
//! Design:
//!
//! * `register_commitment(ec_key_pub, commitment_c)` — ceremony-time.
//!   Stores the commitment `C = SHA256(ec_key_pub || seed)` on-chain
//!   under `ec_key_pub` as the storage key. One entry per user
//!   identity. Overwriting is not permitted (re-enrollment requires a
//!   separate "release" flow — not in 4a scope).
//!
//! * `verify_and_record(ec_key_pub, bucket, nonce, user_otp, proof)`
//!   — sign-time. Looks up the stored commitment, reconstructs the
//!   600-element public-input vector, verifies the Groth16 proof,
//!   records the (bucket, nonce) as consumed, and emits an event.
//!   Rejects replays, stale commitments, malformed proofs, and
//!   proofs that don't pass the pairing check.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod verifier;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use pallet::*;

// ────────────────────────────────────────────────────────────────────
// WORKAROUND: wasmer-vm (via ark-circom, pulled in as a dev-dep for the
// integration tests) references `__rust_probestack` in its generated
// code. Rust 1.82+ removed this symbol from compiler-builtins on
// x86_64-unknown-linux-gnu, so linking the test binary fails with
// `undefined symbol: __rust_probestack`. The Substrate runtime build
// path (wasm32-unknown-unknown) doesn't see wasmer at all, so this
// workaround has zero effect on the eventual Rostro deployment.
//
// Stub is empty — safe because `__rust_probestack` is only called when
// a Rust stack frame exceeds PAGE_SIZE (4KB), and our test paths stay
// well under that bound.
#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
#[unsafe(no_mangle)]
pub extern "C" fn __rust_probestack() {}
// ────────────────────────────────────────────────────────────────────

#[frame_support::pallet]
pub mod pallet {
    use crate::verifier::{VerifyError, verify_mime_wrap};
    use frame_support::{pallet_prelude::*, traits::Get};
    use frame_system::pallet_prelude::*;

    /// Fixed-size Groth16 proof size on BN254 (compressed form).
    /// Proof layout is (G1, G2, G1) = 32 + 64 + 32 = 128 bytes.
    pub const PROOF_BYTES_LEN: u32 = 128;

    /// Maximum bytes for the stored verifying key. Our mime_wrap VK is
    /// ~19 KB compressed (one IC point per public input, 601 of them,
    /// plus alpha/beta/gamma/delta). The bound is a few hundred bytes
    /// of slack for forward-compatibility with larger circuits.
    pub const MAX_VK_BYTES: u32 = 32_768;

    /// Bounded byte buffer for the Groth16 proof. Tight bound because
    /// compressed BN254 proofs are always exactly 128 bytes; the
    /// `BoundedVec` enforces this at decode time so a malformed extrinsic
    /// is rejected before any crypto work happens.
    pub type ProofBytes = BoundedVec<u8, ConstU32<PROOF_BYTES_LEN>>;

    /// Bounded byte buffer for the verifying key.
    pub type VkBytes = BoundedVec<u8, ConstU32<MAX_VK_BYTES>>;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Runtime event type.
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum number of (bucket, nonce) pairs retained for replay
        /// prevention before the oldest are pruned. Per-sign cost is
        /// one storage insert; this bound keeps the table from growing
        /// unboundedly if pruning lags. For Stage 4a the pruner is a
        /// stub; Stage 4b will wire it into `on_idle` or similar.
        type MaxConsumedNonces: Get<u32>;
    }

    // ────────── Storage ──────────

    /// Per-identity commitment registered at ceremony time.
    /// Key: the P-256 compressed-or-hashed ec_key_pub (32 bytes).
    /// Value: commitment_c (32 bytes, SHA256 output).
    #[pallet::storage]
    pub type Commitments<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], [u8; 32], OptionQuery>;

    /// Tracks consumed (bucket, nonce) pairs to prevent replay of the
    /// same signed extrinsic within the same OTP window. Key is
    /// `(bucket: u64, nonce: [u8; 32])`.
    #[pallet::storage]
    pub type ConsumedNonces<T: Config> =
        StorageMap<_, Blake2_128Concat, (u64, [u8; 32]), (), OptionQuery>;

    /// Compressed Groth16 verifying key for the mime_wrap circuit.
    /// Set once via `set_verifying_key` (root-only; the production
    /// design will gate this behind governance).
    #[pallet::storage]
    pub type MimeWrapVk<T: Config> = StorageValue<_, VkBytes, OptionQuery>;

    // ────────── Events ──────────

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new ceremony-time commitment was registered.
        CommitmentRegistered {
            who: T::AccountId,
            ec_key_pub: [u8; 32],
            commitment_c: [u8; 32],
        },
        /// A sign-time proof verified and the (bucket, nonce) was
        /// recorded as consumed.
        ProofVerified {
            who: T::AccountId,
            ec_key_pub: [u8; 32],
            bucket: u64,
        },
        /// The verifying key for the mime_wrap circuit was
        /// (re-)installed.
        VerifyingKeySet,
    }

    // ────────── Errors ──────────

    #[pallet::error]
    pub enum Error<T> {
        /// No verifying key has been set — the pallet cannot verify
        /// any proofs until the VK is installed.
        VerifyingKeyNotSet,
        /// The stored verifying key bytes don't decode as a valid VK.
        VerifyingKeyMalformed,
        /// `verify_and_record` was called but no commitment is
        /// registered for this `ec_key_pub`.
        CommitmentNotRegistered,
        /// A commitment already exists for this `ec_key_pub`. Re-
        /// enrollment requires explicit release first (not in 4a).
        CommitmentAlreadyRegistered,
        /// The (bucket, nonce) pair has already been consumed — this
        /// is a replay attempt.
        ReplayRejected,
        /// The proof bytes are not a well-formed compressed Groth16
        /// BN254 proof.
        ProofMalformed,
        /// The pairing check failed — proof is cryptographically
        /// invalid or the public inputs don't match what the proof
        /// attests to.
        ProofInvalid,
        /// `user_otp` has bits set above the 24-bit window.
        OtpOutOfRange,
    }

    // ────────── Extrinsics ──────────

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Ceremony-time: register the commitment `C = SHA256(ec_key_pub || seed)`
        /// for this user identity. Rejected if a commitment already
        /// exists for `ec_key_pub`. Weight is a stub (storage insert
        /// plus event); real weight comes in Stage 4b.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn register_commitment(
            origin: OriginFor<T>,
            ec_key_pub: [u8; 32],
            commitment_c: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                !Commitments::<T>::contains_key(ec_key_pub),
                Error::<T>::CommitmentAlreadyRegistered
            );
            Commitments::<T>::insert(ec_key_pub, commitment_c);
            Self::deposit_event(Event::CommitmentRegistered {
                who,
                ec_key_pub,
                commitment_c,
            });
            Ok(())
        }

        /// Sign-time: verify a proof, mark the (bucket, nonce) as
        /// consumed, emit an event. All work must complete inside the
        /// weight budget — the Stage 3 lab measured 1.2ms per verify,
        /// so Stage 4b will size the weight constant accordingly.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(1_200_000_000, 0))]
        pub fn verify_and_record(
            origin: OriginFor<T>,
            ec_key_pub: [u8; 32],
            bucket: u64,
            nonce: [u8; 32],
            user_otp: u32,
            proof: ProofBytes,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Replay check first — cheapest rejection path.
            ensure!(
                !ConsumedNonces::<T>::contains_key((bucket, nonce)),
                Error::<T>::ReplayRejected
            );

            // Look up the registered commitment for this identity.
            let commitment_c = Commitments::<T>::get(ec_key_pub)
                .ok_or(Error::<T>::CommitmentNotRegistered)?;

            // Load the VK bytes. Stored as BoundedVec; the underlying
            // Vec<u8> is what ark-serialize expects.
            let vk_bounded = MimeWrapVk::<T>::get().ok_or(Error::<T>::VerifyingKeyNotSet)?;
            let vk_bytes: &[u8] = vk_bounded.as_slice();

            // Verify.
            let ok = verify_mime_wrap(
                proof.as_slice(),
                vk_bytes,
                &commitment_c,
                &ec_key_pub,
                bucket,
                user_otp,
            )
            .map_err(|e| match e {
                VerifyError::ProofMalformed => Error::<T>::ProofMalformed,
                VerifyError::VerifyingKeyMalformed => Error::<T>::VerifyingKeyMalformed,
                VerifyError::PairingFailed => Error::<T>::ProofInvalid,
                VerifyError::OtpOutOfRange => Error::<T>::OtpOutOfRange,
            })?;
            ensure!(ok, Error::<T>::ProofInvalid);

            // Record the (bucket, nonce) as consumed.
            ConsumedNonces::<T>::insert((bucket, nonce), ());

            Self::deposit_event(Event::ProofVerified {
                who,
                ec_key_pub,
                bucket,
            });
            Ok(())
        }

        /// Install or replace the mime_wrap verifying key. Root-only
        /// for 4a; production design routes this through a governance
        /// origin. Stored bytes must be the compressed-serialized
        /// form of `ark_groth16::VerifyingKey<Bn254>`.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn set_verifying_key(origin: OriginFor<T>, vk: VkBytes) -> DispatchResult {
            frame_system::ensure_root(origin)?;
            MimeWrapVk::<T>::put(vk);
            Self::deposit_event(Event::VerifyingKeySet);
            Ok(())
        }
    }
}
