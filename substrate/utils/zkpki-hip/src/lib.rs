//! Hardware Integrity Proof verifier.
//!
//! Verifies [`CanonicalHipProof`] (from `zk-pki-primitives::hip`)
//! structs produced by platform-specific probes / ceremonies. The
//! probe handles wire-format parsing (TPMS_ATTEST, StrongBox
//! attestation bytes, etc.) in userspace where `std` is available;
//! this crate operates purely on the canonical enum and runs in
//! `no_std`.
//!
//! # Platform coverage
//!
//! - **`CanonicalHipProof::Tpm2`** — full verification path (EK hash
//!   consistency, AIK↔EK binding via TPM2_Certify, quote signature
//!   over SHA-256(TPMS_ATTEST) by AIK, inner-vs-outer pcrDigest /
//!   nonce pinning). Works for both `Tpm2Flavor::Windows` (TBS) and
//!   `Tpm2Flavor::Linux` (`/dev/tpmrm0`) — identical wire format.
//!
//! - **`CanonicalHipProof::StrongBox`** — signature-level verifier
//!   (cert_ec↔attest_ec binding via the binding proof, integrity
//!   signature under cert_ec, SPKI consistency between the declared
//!   SEC1 pubkeys). Full X.509 chain-to-root verification + RootOfTrust
//!   extraction is deferred to the seal-break taxonomy pass.
//!
//! # Entry points
//!
//! - [`verify_hip_proof_internal`] — internal consistency only. Used
//!   at `mint_cert` to record the genesis fingerprint; no prior
//!   fingerprint to compare against.
//!
//! - [`verify_hip_proof_against_genesis`] — ongoing verification.
//!   Runs the internal checks and additionally compares the proof
//!   to a stored [`GenesisHardwareFingerprint`]. TPM2 variant
//!   compares AIK identity + PCR7; StrongBox genesis-compare is
//!   currently a partial implementation (see `android::
//!   verify_against_genesis` for the exact checks performed).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod tpm2;
pub mod android;

use zk_pki_primitives::hip::{
    CanonicalHipProof, GenesisHardwareFingerprint, HipPlatform, PcrValue,
};

/// Error cases for HIP verification. Each failure mode is a distinct
/// variant so callers (and tests) can assert the exact reason a
/// proof was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HipError {
    // ── Platform-agnostic / dispatch ──────────────────────────────
    /// Platform variant on the proof doesn't have a verifier wired
    /// yet. Not a security failure — scope boundary.
    PlatformNotImplemented,
    /// The `CanonicalHipProof` variant and the
    /// `GenesisHardwareFingerprint` variant disagree (e.g., a TPM2
    /// proof submitted against a StrongBox genesis fingerprint).
    /// Always a bug or active spoof attempt — legitimate flows never
    /// mix variants.
    PlatformMismatch,

    // ── TPM2 path ─────────────────────────────────────────────────
    /// `blake2_256(ek_public) != ek_hash` — proof's claimed EK hash
    /// doesn't match the supplied EK pubkey.
    EkHashMismatch,
    /// AIK-certify signature verification failed. Either the AIK
    /// wasn't created under this EK's hierarchy or the bytes were
    /// tampered.
    AikCertifyInvalid,
    /// Quote signature over `SHA-256(quote_attest)` by the AIK
    /// failed — attest bytes or signature tampered.
    QuoteSignatureInvalid,
    /// `quote_attest` did not parse as a well-formed TPMS_ATTEST
    /// quote structure (bad magic, wrong type, truncated fields).
    QuoteAttestMalformed,
    /// Inner `pcrDigest` parsed from `quote_attest` does not match
    /// the redundant `pcr_digest` field. Tamper or probe bug.
    PcrDigestMismatch,
    /// Inner `extraData` parsed from `quote_attest` does not match
    /// the redundant `nonce` field. The caller's nonce wasn't what
    /// the TPM quoted against.
    NonceAttestMismatch,
    /// Caller-supplied `expected_nonce` does not match the proof's
    /// `nonce`. Catches stale-proof replay where the proof was valid
    /// for a previous request but doesn't bind to this one.
    NonceExpectedMismatch,
    /// The AIK in this proof doesn't match the one recorded at
    /// genesis. Device identity diverged.
    AikGenesisMismatch,
    /// PCR 7 (Secure Boot state) in this proof differs from the
    /// value recorded at genesis. Most common cause: user disabled
    /// Secure Boot or reinstalled a non-signed OS.
    Pcr7GenesisMismatch,
    /// Genesis fingerprint is missing PCR 7.
    GenesisPcr7Missing,
    /// The current proof doesn't include PCR 7.
    CurrentPcr7Missing,

    // ── StrongBox path ────────────────────────────────────────────
    /// `hmac_binding_signature` did not verify over
    /// `blake2_256(hmac_binding_output || nonce)` under the proof's
    /// `attest_ec_public`. Breaks the attest_ec ↔ HMAC co-location
    /// proof.
    HmacBindingSignatureInvalid,
    /// `integrity_signature` did not verify over
    /// `blake2_256(integrity_blob)` under the proof's
    /// `cert_ec_public`. The integrity declaration cannot be trusted
    /// as coming from this cert_ec key.
    IntegritySignatureInvalid,
    /// `cert_ec_chain` or `attest_ec_chain` is empty. Every StrongBox
    /// proof must carry at least the leaf + one intermediate.
    ChainEmpty,
    /// `cert_ec_public` doesn't match the cert_ec attestation chain
    /// leaf's declared SEC1 pubkey (post-SPKI-strip). Would indicate
    /// the caller tampered with the pubkey field without updating
    /// the chain, or vice-versa.
    CertEcPubkeyChainMismatch,

    // ── Generic key / signature parse failures ────────────────────
    /// EC public key bytes were malformed or not a valid curve point.
    BadPublicKey,
    /// Signature bytes not valid DER.
    BadSignature,
}

/// Successful-verification report. Surfaces the structured facts
/// that gated extrinsics / relying parties act on.
#[derive(Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct HipVerificationReport {
    pub platform: HipPlatform,
    pub device_identity_confirmed: bool,
    pub secure_boot_intact: bool,
}

/// Internal-only consistency check. Used at genesis (`mint_cert`)
/// where there's no prior fingerprint to compare against — confirms
/// the proof structure is cryptographically sound.
pub fn verify_hip_proof_internal(
    proof: &CanonicalHipProof,
) -> Result<HipVerificationReport, HipError> {
    match proof {
        CanonicalHipProof::Tpm2(p) => tpm2::verify_internal(p),
        CanonicalHipProof::StrongBox(p) => android::verify_internal(p),
    }
}

/// Ongoing verification — runs the internal checks AND compares
/// against the stored genesis fingerprint. Proof and fingerprint
/// must share the same platform variant; mismatch yields
/// `PlatformMismatch`.
///
/// For self-as-genesis / internal-consistency tests, pass
/// `&proof.nonce()` as `expected_nonce` (the check reduces to a
/// tautology and doesn't exclude any valid proof).
pub fn verify_hip_proof_against_genesis(
    proof: &CanonicalHipProof,
    genesis: &GenesisHardwareFingerprint,
    expected_nonce: &[u8; 32],
) -> Result<HipVerificationReport, HipError> {
    match (proof, genesis) {
        (CanonicalHipProof::Tpm2(p), GenesisHardwareFingerprint::Tpm2(g)) => {
            tpm2::verify_against_genesis(p, g, expected_nonce)
        }
        (CanonicalHipProof::StrongBox(p), GenesisHardwareFingerprint::StrongBox(g)) => {
            android::verify_against_genesis(p, g, expected_nonce)
        }
        _ => Err(HipError::PlatformMismatch),
    }
}

/// Look up a PCR value by index in a `BoundedVec<PcrValue, _>`.
/// Used by the TPM2 genesis-compare path to find PCR 7 in both the
/// proof and the genesis fingerprint.
pub(crate) fn find_pcr<B>(
    pcrs: &frame_support::BoundedVec<PcrValue, B>,
    index: u8,
) -> Option<[u8; 32]>
where
    B: frame_support::traits::Get<u32>,
{
    pcrs.iter().find(|p| p.index == index).map(|p| p.value)
}
