// Copyright 2026 The ZK-PKI Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ZK-PKI Integrity Attestation.
//!
//! A signed blob the Dotwave Kotlin ceremony emits alongside the Android
//! Keystore attestation chains. The chain attestations prove the key was
//! generated inside genuine StrongBox hardware; this blob proves the
//! ceremony that generated it ran inside the genuine Dotwave app, within
//! the offer window, with no debugger attached and an unmodified Android
//! Keystore daemon.
//!
//! Without this gate the pallet cannot distinguish a legitimate Dotwave
//! ceremony from a custom app that knows the ceremony design and mimics
//! every StrongBox flag correctly. The signature over the blob binds the
//! declaration to the EC cert keypair that the chain attestation already
//! certifies — no new trust anchor is introduced.
//!
//! ## Cross-check with the chain's attestationApplicationId
//!
//! The `softwareEnforced.attestationApplicationId` field inside the EC
//! cert's attestation chain is written by the Android Keystore daemon at
//! key-generation time; Dotwave cannot forge it. The blob carries the same
//! package_name + signing_cert_hash fields independently. The pallet (at
//! TODO 4 wiring time) must cross-check the two — an attacker cannot fake
//! one without the other matching.
//!
//! ## What this crate does NOT do
//!
//! - It does not talk to Google Play Integrity API. That's an optional
//!   reputation signal, handled off-chain, not a hard gate.
//! - It does not verify the Android Keystore cert chain or EK trust chain.
//!   That lives in `zk-pki-tpm`.
//! - It does not run device-side detection (debugger / Keystore integrity).
//!   The Kotlin ceremony does that and records the results as `bool` fields
//!   here. The pallet trusts the blob only because the signature binds it
//!   to the chain-attested EC key.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{traits::ConstU32, BoundedVec};
use scale_info::TypeInfo;

use zk_pki_primitives::crypto::DevicePublicKey;

/// Reverse-DNS package name of the genuine Dotwave Android app. The blob
/// must carry this exact value or the manufacturer gate rejects it.
///
/// Kept as a byte slice (not `&str`) because `BoundedVec<u8, _>::as_slice()`
/// returns bytes — no UTF-8 round-tripping required to compare.
pub const DOTWAVE_PACKAGE_NAME: &[u8] = b"com.dotwave.app";

/// SHA-256 of the Dotwave Android APK signing certificate.
///
/// **Placeholder.** Until the production APK signing key is minted and
/// this constant is replaced with the real hash, every equality check
/// against this value passes — the Kotlin ceremony emits the same zero
/// hash so both sides match and the gate is effectively a no-op for
/// signing-cert identity. This is intentional for the Paseo beta: the
/// structural check is wired end-to-end and exercised by tests, but the
/// constant is not yet grounded in a real cert.
///
/// **Before mainnet:** replace this with the real SHA-256 of the Dotwave
/// APK signing cert. Governance can rotate it via the same mechanism
/// that updates `GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH` in
/// `zk-pki-tpm` — constant edit + `schema_version` bump.
pub const DOTWAVE_SIGNING_CERT_HASH: [u8; 32] = [0u8; 32];

/// Max bytes for `package_name`. 256 is well over the Android package-name
/// cap (~150 chars) and matches the bound in the TODO 3 spec.
pub type MaxPackageNameLen = ConstU32<256>;

/// Signed device-integrity declaration that accompanies the Android
/// Keystore attestation chains.
///
/// Serialised via SCALE (never raw byte concatenation — raw concat has
/// ambiguous field boundaries, which is a preimage-collision footgun).
/// The Kotlin ceremony SCALE-encodes this struct, blake2b-256 hashes the
/// encoded bytes, and signs that hash with the EC cert keypair (the same
/// key the chain attestation already certifies). The pallet re-runs the
/// same encoding + hash + verify on receipt.
#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug,
)]
pub struct IntegrityAttestation {
    /// Reverse-DNS package name of the app that ran the ceremony. Cross-
    /// checked against the EC attestation chain's `attestationApplicationId`
    /// at pallet wiring time.
    pub package_name: BoundedVec<u8, MaxPackageNameLen>,
    /// SHA-256 of the APK signing cert. Matched against
    /// [`DOTWAVE_SIGNING_CERT_HASH`].
    pub signing_cert_hash: [u8; 32],
    /// Block height at the moment the ceremony ran. Must fall within the
    /// issuer's offer window.
    pub block_number: u64,
    /// True when `Debug.isDebuggerConnected()` and `/proc/self/status`
    /// `TracerPid` both indicated no debugger at ceremony time.
    pub no_debugger: bool,
    /// True when the Android Keystore daemon's binary identity matched
    /// the unmodified system version at ceremony time.
    pub keystore_integrity: bool,
}

/// Rejection reasons from [`verify_integrity_attestation`]. Each variant
/// is a distinct check so negative-case tests can assert the exact gate
/// that fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityError {
    /// Blob bytes did not SCALE-decode into [`IntegrityAttestation`].
    DecodeFailed,
    /// Signature did not verify against the supplied EC public key.
    SignatureInvalid,
    /// `package_name` did not match [`DOTWAVE_PACKAGE_NAME`].
    InvalidPackageName,
    /// `signing_cert_hash` did not match [`DOTWAVE_SIGNING_CERT_HASH`].
    ///
    /// During beta this variant is unreachable in practice — the constant
    /// is a zero hash and the ceremony emits zero hashes too, so the
    /// equality passes. It becomes meaningful once the constant is
    /// replaced with the real APK signing cert hash.
    InvalidSigningCert,
    /// `block_number` fell before the offer window opened or after it
    /// closed.
    CeremonyOutsideOfferWindow,
    /// `no_debugger` was false — a debugger was attached at ceremony time.
    DebuggerDetected,
    /// `keystore_integrity` was false — the Android Keystore daemon did
    /// not match the unmodified system binary at ceremony time.
    KeystoreIntegrityFailed,
}

/// Verify an integrity attestation blob against the EC cert public key
/// that already signed the chain attestation.
///
/// Steps run in fixed order; the first failing check short-circuits with
/// the matching [`IntegrityError`] so failure modes stay distinguishable:
///
/// 1. SCALE-decode `blob` into [`IntegrityAttestation`].
/// 2. Verify the ECDSA P-256 signature over `blake2_256(blob)` using
///    `cert_ec_pubkey`. The EC key validates its own accompanying blob
///    using the same curve as its chain attestation.
/// 3. `package_name` must equal [`DOTWAVE_PACKAGE_NAME`].
/// 4. `signing_cert_hash` must equal [`DOTWAVE_SIGNING_CERT_HASH`].
/// 5. `block_number` must fall in `[offer_created_at_block, offer_expiry_block]`
///    inclusive — ceremony must have run inside the offer window.
/// 6. `no_debugger` must be true.
/// 7. `keystore_integrity` must be true.
///
/// Cross-checking the blob's `package_name` / `signing_cert_hash` against
/// the EC attestation chain's `attestationApplicationId` happens at the
/// pallet boundary (TODO 4), not here — this crate only has the blob, not
/// the chain.
pub fn verify_integrity_attestation(
    blob: &[u8],
    signature: &[u8],
    cert_ec_pubkey: &DevicePublicKey,
    offer_created_at_block: u64,
    offer_expiry_block: u64,
) -> Result<IntegrityAttestation, IntegrityError> {
    let mut cursor: &[u8] = blob;
    let attestation = IntegrityAttestation::decode(&mut cursor)
        .map_err(|_| IntegrityError::DecodeFailed)?;

    let digest = sp_io::hashing::blake2_256(blob);
    if !cert_ec_pubkey.verify_signature(&digest, signature) {
        return Err(IntegrityError::SignatureInvalid);
    }

    if attestation.package_name.as_slice() != DOTWAVE_PACKAGE_NAME {
        return Err(IntegrityError::InvalidPackageName);
    }

    if attestation.signing_cert_hash != DOTWAVE_SIGNING_CERT_HASH {
        return Err(IntegrityError::InvalidSigningCert);
    }

    if attestation.block_number < offer_created_at_block
        || attestation.block_number > offer_expiry_block
    {
        return Err(IntegrityError::CeremonyOutsideOfferWindow);
    }

    if !attestation.no_debugger {
        return Err(IntegrityError::DebuggerDetected);
    }

    if !attestation.keystore_integrity {
        return Err(IntegrityError::KeystoreIntegrityFailed);
    }

    Ok(attestation)
}

// Keep `Vec` reachable through this crate root for downstream callers
// that want the same encoded-bytes type without importing `alloc`.
#[doc(hidden)]
pub type EncodedBytes = Vec<u8>;
