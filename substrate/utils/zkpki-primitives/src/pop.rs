//! PoP-asserted action primitives.
//!
//! A [`PopAssertion`] is a hardware-bound identity assertion attached
//! to a pallet extrinsic. It proves the caller controls a specific
//! hardware-anchored cert keypair AND that the attesting hardware is
//! still intact since genesis — completely independent of the
//! Substrate keypair that pays fees and sequences the transaction.
//!
//! The two-key separation is load-bearing:
//! - The Substrate keypair proves fee payment + replay protection at
//!   the transaction layer.
//! - The PopAssertion proves hardware-anchored identity at the
//!   extrinsic layer.
//!
//! If the two keypairs were collapsed, a compromised wallet key would
//! imply a compromised identity. Keeping them separate means a stolen
//! seed phrase can drain funds but cannot impersonate the holder's
//! cert-backed identity — the attacker needs physical control of the
//! hardware-bound keypair.
//!
//! # Two PoP mechanisms
//!
//! [`PopAssertion`] is an enum because the cryptographic shape of the
//! identity proof differs by platform tier:
//!
//! - [`PopAssertion::HipSigned`] — P-256 ECDSA over `derive_pop_nonce`
//!   plus a [`CanonicalHipProof`]. Used by TPM2 hardware (the
//!   `CanonicalHipProof::Tpm2` variant). The signature half rides on
//!   the cert's `cert_ec_pubkey`.
//!
//! - [`PopAssertion::MimeWrap`] — Groth16 proof over a
//!   `(commitment_c, ec_key_pub, bucket, user_otp)` tuple plus a
//!   [`CanonicalHipProof`]. Used by Android StrongBox hardware (the
//!   `CanonicalHipProof::StrongBox` variant) where the AttestKey-bound
//!   HMAC isn't strong enough to carry HipSigned safely on its own.
//!
//! Both variants carry the HIP proof — hardware integrity is
//! universal. What differs is the identity-proof half. Platform gating
//! is enforced at `mint_cert` (the cert's
//! [`crate::template::PopMechanism`] is matched against the
//! attestation chain platform) and again at `verify_pop_assertion`
//! (the cert's pinned `pop_mechanism` is matched against the
//! variant submitted), so a TPM2 cert cannot be used with a MimeWrap
//! assertion and vice versa.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::ConstU32, BoundedVec};
use scale_info::TypeInfo;

use crate::hip::CanonicalHipProof;

/// Compressed BN254 Groth16 proof size, in bytes. Layout is (G1, G2,
/// G1) = 32 + 64 + 32. Used as the `BoundedVec` ceiling on
/// `PopAssertion::MimeWrap.proof`.
pub const MIME_WRAP_PROOF_LEN: u32 = 128;

/// Hardware-bound identity assertion attached to a pallet extrinsic.
/// See module docs.
#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug,
)]
pub enum PopAssertion {
    /// TPM2 path. ECDSA signature over `blake2_256(call_data ||
    /// derive_pop_nonce(...))` produced by the cert's
    /// hardware-bound `cert_ec_pubkey`.
    HipSigned {
        /// Thumbprint of the cert being asserted.
        cert_thumbprint: [u8; 32],
        /// ECDSA P-256 signature (DER or raw r||s) over
        /// `blake2_256(call_data || nonce)`. Bounded to 72 bytes
        /// (max DER-ECDSA-P256 size).
        cert_ec_signature: BoundedVec<u8, ConstU32<72>>,
        /// Hardware integrity proof — proves the attesting hardware
        /// is still in the same boot state it was at genesis.
        hip_proof: CanonicalHipProof,
    },

    /// Android StrongBox path. Groth16 proof over the mime-wrap
    /// circuit's public-input tuple `(commitment_c, ec_key_pub,
    /// bucket, user_otp)`. The pallet rebuilds the public-input
    /// vector internally from the cert's stored commitment and the
    /// `bucket` / `user_otp` carried here.
    MimeWrap {
        /// Thumbprint of the cert being asserted.
        cert_thumbprint: [u8; 32],
        /// 30-second time bucket the proof was generated for. Bound
        /// to TOTP ticking; reused with `nonce` as the replay-map
        /// key.
        bucket: u64,
        /// Per-call random nonce. The pallet rejects a second
        /// presentation of the same `(bucket, nonce)` pair via
        /// `ConsumedMimeWrapNonces`.
        nonce: [u8; 32],
        /// Low-24-bits of the OTP value the circuit consumed. Top
        /// 8 bits MUST be zero — the verifier surfaces
        /// `MimeWrapOtpOutOfRange` rather than truncating silently.
        user_otp: u32,
        /// Compressed BN254 Groth16 proof. Always 128 bytes when
        /// well-formed.
        proof: BoundedVec<u8, ConstU32<MIME_WRAP_PROOF_LEN>>,
        /// Hardware integrity proof — universal across both
        /// variants. Hardware integrity is independent of which
        /// identity-proof mechanism the cert uses.
        hip_proof: CanonicalHipProof,
    },
}

impl PopAssertion {
    /// Thumbprint of the cert this assertion is for. Lifted to a
    /// helper so call sites don't need to match the enum just to
    /// extract the thumbprint.
    pub fn cert_thumbprint(&self) -> &[u8; 32] {
        match self {
            PopAssertion::HipSigned { cert_thumbprint, .. } => cert_thumbprint,
            PopAssertion::MimeWrap { cert_thumbprint, .. } => cert_thumbprint,
        }
    }

    /// Hardware integrity proof attached to this assertion. Universal
    /// across both variants — hardware integrity verification runs
    /// regardless of which identity-proof mechanism the cert uses.
    pub fn hip_proof(&self) -> &CanonicalHipProof {
        match self {
            PopAssertion::HipSigned { hip_proof, .. } => hip_proof,
            PopAssertion::MimeWrap { hip_proof, .. } => hip_proof,
        }
    }
}

/// Derive the PopAssertion nonce.
///
/// `parent_hash` is the hash of the parent (most-recently-finalised)
/// block — available to both the client before submission and the
/// pallet during execution via `frame_system::Pallet::<T>::parent_hash()`.
/// That plus the cert thumbprint plus the call's own argument bytes
/// gives a nonce that is:
/// - **Knowable** to the client before signing (parent hash is
///   already sealed by the time the client crafts the transaction).
/// - **Unique** per cert per call per block (the cert thumbprint
///   prevents collision between different certs executing the same
///   call in the same block).
/// - **Not-pre-predictable** by an attacker ahead of time (can't
///   forge a valid signature before the parent block exists).
/// - **Verifiable** by the pallet by calling `parent_hash()` at
///   verification time — the same value the client committed to.
///
/// Only consumed by the [`PopAssertion::HipSigned`] path. The
/// MimeWrap path's freshness comes from `(bucket, nonce)` plus the
/// replay-map insert; the client doesn't sign over a derived nonce
/// because the proof's public inputs already commit to the bucket.
///
/// Client-side derivation and pallet-side derivation MUST agree
/// byte-for-byte, including SCALE-encoding of the tuple.
pub fn derive_pop_nonce(
    parent_hash: &[u8; 32],
    cert_thumbprint: &[u8; 32],
    call_data: &[u8],
) -> [u8; 32] {
    sp_io::hashing::blake2_256(
        &(parent_hash, cert_thumbprint, call_data).encode(),
    )
}

/// Marker trait for extrinsic call structs (or the extrinsics
/// themselves) that require a `PopAssertion`. Implementors must call
/// the pallet's `verify_pop_assertion` helper before any state
/// changes. The assertion is independent of the Substrate keypair —
/// it proves hardware-bound identity, not fee payment.
///
/// No concrete implementations yet — this is the framework marker for
/// the future relying-party extrinsics that follow the
/// `self_discard_cert` standard path pattern.
pub trait PopGated {
    /// Return the `PopAssertion` carried on this call.
    fn pop_assertion(&self) -> &PopAssertion;
}
