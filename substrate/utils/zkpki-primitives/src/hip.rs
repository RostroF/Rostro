//! Hardware Integrity Proof (HIP) primitives.
//!
//! A `CanonicalHipProof` is the pallet's pre-canonicalized, platform-
//! flavored representation of a hardware integrity assertion. Platform-
//! specific wire formats (TPM2 `TPMS_ATTEST`, Android StrongBox
//! attestation chains, etc.) are parsed off-chain by the probe/
//! ceremony and reduced to this enum before being sent on-chain. The
//! pallet verifier in `zk-pki-hip` operates purely on this enum — no
//! TPM2 wire-format parsing lives in `no_std`, and all Android X.509
//! chain verification happens in the std-available `zk-pki-tpm` crate.
//!
//! ## Shape
//!
//! ```text
//!                     CanonicalHipProof
//!                           │
//!            ┌──────────────┴──────────────┐
//!            ▼                             ▼
//!     Tpm2(Tpm2HipProof)          StrongBox(StrongBoxHipProof)
//!            │                             │
//!     flavor: Tpm2Flavor              cert_ec_chain
//!     ek_hash, ek_public              attest_ec_chain
//!     aik_public, aik_certify_*       hmac_binding_output + signature
//!     pcr_values, pcr_digest          integrity_blob + signature
//!     quote_attest, quote_signature   nonce
//!     nonce
//! ```
//!
//! TPM2 Windows and TPM2 Linux share the TCG wire format byte-for-byte;
//! the `Tpm2Flavor` field carries the operational-origin distinction
//! without duplicating 12 fields across two enum variants.
//!
//! StrongBox has no TPM2_Quote equivalent — its proof is a fresh
//! attestation chain (X.509 from the Keystore daemon, rooted at
//! Google's attestation CA) plus a binding proof that the HMAC key
//! was co-located in StrongBox at ceremony time. See the project
//! memory `project_strongbox_hmac_gap` for the design rationale.
//!
//! ## Two types of HIP usage
//!
//! 1. **Genesis recording** — at `mint_cert`, PoP cert holders submit
//!    a `CanonicalHipProof`. The pallet derives a
//!    `GenesisHardwareFingerprint` (also enum-flavored) and pins it
//!    to the cold record. Verification at genesis is internal
//!    consistency only (signatures, nonce); there is no prior
//!    fingerprint to compare against.
//!
//! 2. **Ongoing attestation** — relying parties / gated extrinsics
//!    submit a fresh `CanonicalHipProof` compared against the stored
//!    `GenesisHardwareFingerprint`. TPM2 genesis-compare is wired;
//!    StrongBox genesis-compare (RootOfTrust drift, patch-level
//!    regression) lands in the follow-up session alongside the
//!    seal-break taxonomy.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::ConstU32, BoundedVec};
use scale_info::TypeInfo;

// ═══════════════════════════════════════════════════════════════════════════
// Platform projection (for RPC/telemetry/PlatformTag)
// ═══════════════════════════════════════════════════════════════════════════

/// Flat projection of "which platform produced the proof". Derived
/// from a `CanonicalHipProof` via [`HipPlatform::from_proof`] — the
/// wire-format source of truth is the enum variant itself, this is
/// just a convenience for callers (RPC responses, telemetry, future
/// PlatformTag work) that need a flat `enum` without having to
/// pattern-match on the payload struct.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub enum HipPlatform {
    /// Windows TPM 2.0 via TBS (TPM Base Services).
    Tpm2Windows,
    /// Linux TPM 2.0 via `/dev/tpmrm0` (kernel resource manager).
    Tpm2Linux,
    /// Android StrongBox attestation.
    StrongBox,
}

impl HipPlatform {
    /// Flatten a `CanonicalHipProof` to its platform projection.
    pub fn from_proof(proof: &CanonicalHipProof) -> Self {
        match proof {
            CanonicalHipProof::Tpm2(p) => match p.flavor {
                Tpm2Flavor::Windows => Self::Tpm2Windows,
                Tpm2Flavor::Linux => Self::Tpm2Linux,
            },
            CanonicalHipProof::StrongBox(_) => Self::StrongBox,
        }
    }

    /// Flatten a `GenesisHardwareFingerprint` to its platform
    /// projection. Matches [`Self::from_proof`] so a stored
    /// fingerprint and an incoming proof project to the same tag.
    pub fn from_fingerprint(fp: &GenesisHardwareFingerprint) -> Self {
        match fp {
            GenesisHardwareFingerprint::Tpm2(g) => match g.flavor {
                Tpm2Flavor::Windows => Self::Tpm2Windows,
                Tpm2Flavor::Linux => Self::Tpm2Linux,
            },
            GenesisHardwareFingerprint::StrongBox(_) => Self::StrongBox,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TPM2 (Windows + Linux share this)
// ═══════════════════════════════════════════════════════════════════════════

/// TPM2 flavor — Windows (TBS) vs Linux (`/dev/tpmrm0`). The wire
/// format is identical between them; the flavor is preserved so
/// telemetry and future PlatformTag work can distinguish operational
/// origin without duplicating 12 fields across separate variants.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub enum Tpm2Flavor {
    Windows,
    Linux,
}

/// A single PCR (Platform Configuration Register) value. The `index`
/// is the PCR slot number; `value` is the SHA-256 digest of what's
/// extended into that slot.
///
/// PCRs of interest for HIP:
/// - PCR 0 — firmware / BIOS
/// - PCR 1 — host platform configuration
/// - PCR 4 — boot manager / MBR / GPT
/// - PCR 7 — Secure Boot state (the critical one)
/// - PCR 11 — BitLocker volume encryption (Windows-specific)
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct PcrValue {
    pub index: u8,
    pub value: [u8; 32],
}

/// TPM2-specific HIP proof payload.
///
/// Verification steps (in `zk-pki-hip::tpm2`):
/// 1. `blake2_256(ek_public) == ek_hash` — self-consistency gate.
/// 2. `aik_certify_signature` verifies over `aik_certify_info` under
///    `ek_public` — proves AIK was certified by the EK (TPM2_Certify).
/// 3. `quote_signature` verifies over `SHA-256(quote_attest)` under
///    `aik_public` — matches the TPM's actual signing domain
///    (TPM2_Quote signs `SHA-256(TPMS_ATTEST)`, not a caller-
///    synthesized commitment).
/// 4. Parse `quote_attest` and pin its inner `pcrDigest` / `extraData`
///    fields against the redundant-by-design `pcr_digest` / `nonce`
///    fields on this struct.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct Tpm2HipProof {
    pub flavor: Tpm2Flavor,
    /// `blake2_256(leaf_spki_der)` — hash of the leaf EK cert's
    /// SubjectPublicKeyInfo. Device-unique and bound to the signed
    /// TBS of the leaf, so a verified chain cannot have a mutated
    /// SPKI. This is the device identity anchor used by the root-
    /// scoped EK deduplication registry.
    pub ek_hash: [u8; 32],
    /// EK public key bytes (SEC1 uncompressed for ECC). Needed to
    /// verify the AIK-certify signature; redundant-by-design with
    /// `ek_hash` (verifier checks the two agree).
    pub ek_public: BoundedVec<u8, ConstU32<128>>,
    /// AIK public key bytes (SEC1 uncompressed for ECC).
    pub aik_public: BoundedVec<u8, ConstU32<128>>,
    /// TPMS_ATTEST-derived bytes describing the certified AIK.
    /// Produced by `TPM2_Certify` on the EK hierarchy.
    pub aik_certify_info: BoundedVec<u8, ConstU32<512>>,
    /// Signature over `aik_certify_info` by the EK. Proves the AIK
    /// was created under the EK hierarchy.
    pub aik_certify_signature: BoundedVec<u8, ConstU32<256>>,
    /// PCR values included in the quote. Probe lists only those the
    /// pallet cares about; genesis pins them for subsequent compares.
    pub pcr_values: BoundedVec<PcrValue, ConstU32<16>>,
    /// SHA-256 digest of the selected PCRs, as produced by the TPM
    /// internally for the quote. Redundant-by-design with the
    /// `pcrDigest` field inside `quote_attest`; verifier pins them.
    pub pcr_digest: [u8; 32],
    /// Raw `TPMS_ATTEST` blob returned by `TPM2_Quote`. This is what
    /// the TPM actually signed — a restricted AIK cannot sign
    /// arbitrary data, only TPM-internal structures.
    pub quote_attest: BoundedVec<u8, ConstU32<512>>,
    /// ECDSA-SHA256 signature by the AIK over `quote_attest`.
    pub quote_signature: BoundedVec<u8, ConstU32<256>>,
    /// Nonce injected by the caller to bind the quote to a specific
    /// request. Echoed back from the TPM in `TPMS_ATTEST.extraData`;
    /// verifier pins the two against each other.
    pub nonce: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// Android StrongBox
// ═══════════════════════════════════════════════════════════════════════════

/// Android Verified Boot state, as reported in
/// `hardwareEnforced.RootOfTrust.verifiedBootState` on the Keystore
/// attestation chain.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub enum VerifiedBootState {
    /// All boot components verified — locked bootloader, factory image.
    Green,
    /// User-signed boot (custom OS with user-installed verification
    /// certs).
    Yellow,
    /// Unlocked bootloader.
    Orange,
    /// Failed verification.
    Red,
}

/// StrongBox HIP proof payload. Produced by the dotwave ceremony on
/// Android 12+ with Android Keystore's StrongBox backend.
///
/// Verification steps (in `zk-pki-hip::android`):
/// 1. `cert_ec_chain` verifies to Google's attestation root CA; the
///    leaf's SPKI matches `cert_ec_public` (after SPKI → SEC1 strip).
/// 2. `attest_ec_chain` verifies to Google's attestation root CA.
/// 3. `hmac_binding_signature` verifies over
///    `blake2_256(hmac_binding_output || nonce)` under the attest_ec
///    leaf's pubkey — proves attest_ec and the HMAC key were co-located
///    in StrongBox at ceremony time (the AttestKey-binding workaround
///    for Samsung KeyMint's symmetric-key attestation gap; see memory
///    `project_strongbox_hmac_gap`).
/// 4. `integrity_signature` verifies over `blake2_256(integrity_blob)`
///    under `cert_ec_public` — binds the integrity attestation to
///    the cert_ec key without a separate trust anchor.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct StrongBoxHipProof {
    /// SEC1 uncompressed P-256 public key (65 bytes: 0x04 || x || y)
    /// for the `zkpki_cert_ec` key. The Android ceremony emits this
    /// as DER-encoded SPKI (91 bytes) by default; the canonicalize
    /// step strips the SPKI envelope to this fixed-size SEC1 form.
    /// See memory `project_strongbox_pubkey_is_der_spki`.
    pub cert_ec_public: [u8; 65],
    /// SEC1 uncompressed P-256 public key for the `zkpki_attest_ec`
    /// key — the secondary EC key that signs the binding proof.
    /// Carried explicitly (derivable from the `attest_ec_chain` leaf
    /// but re-parsing DER on-chain is avoided) so the verifier can
    /// check `hmac_binding_signature` without X.509 machinery.
    pub attest_ec_public: [u8; 65],
    /// Attestation chain for the `zkpki_cert_ec` key, DER-encoded X.509
    /// certs, leaf-first. Rooted at Google's attestation CA.
    /// Full chain-to-root verification (+ RootOfTrust extraction) is
    /// a follow-up pass; the initial verifier does signature checks
    /// only and treats the chain as provenance metadata.
    pub cert_ec_chain: BoundedVec<BoundedVec<u8, ConstU32<2048>>, ConstU32<8>>,
    /// Attestation chain for the `zkpki_attest_ec` key. Same root as
    /// `cert_ec_chain`, different leaf.
    pub attest_ec_chain: BoundedVec<BoundedVec<u8, ConstU32<2048>>, ConstU32<8>>,
    /// `HMAC-SHA256(hmac_key, binding_proof_context)` — computed inside
    /// StrongBox at ceremony time. The HMAC key itself is not attested
    /// (Samsung KeyMint gap) but the ceremony binds it to the attested
    /// `attest_ec_key` via `hmac_binding_signature`.
    pub hmac_binding_output: [u8; 32],
    /// ECDSA-SHA256 signature by the `attest_ec_key` over
    /// `blake2_256(hmac_binding_output || nonce)`. Proves both keys
    /// were resident in StrongBox within the same execution context.
    pub hmac_binding_signature: BoundedVec<u8, ConstU32<256>>,
    /// The versioned context string the HMAC was computed over.
    /// Typically `b"zkpki-binding-proof-v1"`. Versioned so the proof
    /// construction can bump without breaking existing certs.
    pub binding_proof_context: BoundedVec<u8, ConstU32<64>>,
    /// SCALE-encoded `zk_pki_integrity::IntegrityAttestation` — the
    /// Gate-2 integrity declaration. Contains declared package name,
    /// APK signing cert SHA-256, ceremony block number, debugger
    /// check, Keystore daemon integrity check.
    pub integrity_blob: BoundedVec<u8, ConstU32<512>>,
    /// ECDSA-SHA256 signature by `cert_ec` over
    /// `blake2_256(integrity_blob)`. Binds the integrity declaration
    /// to the cert_ec key — no separate trust anchor required.
    pub integrity_signature: BoundedVec<u8, ConstU32<256>>,
    /// Caller-supplied 32-byte nonce. Baked into both EC keys'
    /// attestation extensions at ceremony time (`setAttestationChallenge`)
    /// and referenced in the binding-proof commitment.
    pub nonce: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// Top-level proof + fingerprint enums
// ═══════════════════════════════════════════════════════════════════════════

/// Pre-canonicalized HIP proof — platform-flavored enum. Dispatched
/// in the verifier by variant; each platform's internal consistency
/// check lives in its own module in `zk-pki-hip`.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub enum CanonicalHipProof {
    Tpm2(Tpm2HipProof),
    StrongBox(StrongBoxHipProof),
}

/// TPM2 genesis fingerprint — stored on `CertRecordCold` at mint time.
/// Ongoing proofs compare against this snapshot of device state.
///
/// Only PCR 7 (Secure Boot state) is an exact-match invariant in the
/// current verifier. Other PCRs may legitimately progress forward
/// across OS updates; broader comparison policy is a future-pass
/// concern tracked by the seal-break taxonomy work.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct Tpm2GenesisFingerprint {
    pub flavor: Tpm2Flavor,
    /// `blake2_256(leaf_spki_der)` — device identity.
    pub ek_hash: [u8; 32],
    /// `blake2_256(aik_public)` — AIK identity. Ongoing proofs must
    /// use the same AIK (TPM2_Certify at genesis establishes AIK's
    /// EK-hierarchy membership).
    pub aik_public_hash: [u8; 32],
    /// PCR values at genesis — ground truth for boot-state compares.
    pub pcr_values: BoundedVec<PcrValue, ConstU32<16>>,
    pub schema_version: crate::cert::SchemaVersion,
}

/// Android Verified Boot RootOfTrust snapshot — the `hardwareEnforced`
/// fields pinned at genesis for ongoing comparison. Extracted from
/// the attestation chain's `AuthorizationList` at mint time.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct RootOfTrustSnapshot {
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_key: [u8; 32],
    pub verified_boot_hash: [u8; 32],
    pub device_locked: bool,
}

/// StrongBox genesis fingerprint — device identity anchors + ongoing-
/// compare invariants.
///
/// Genesis-compare verification (RootOfTrust drift, patch-level
/// regression, AttestKey binding check) lands with the seal-break
/// taxonomy in a follow-up session. For the current pass only the
/// fields are defined and SCALE-encodable; the verifier's
/// genesis-compare branch for StrongBox returns partial evidence.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub struct StrongBoxGenesisFingerprint {
    /// `blake2_256(cert_ec_public)` — cert-key device identity.
    pub cert_ec_public_hash: [u8; 32],
    /// `blake2_256(attest_ec_public)` — binding-proof signer identity.
    pub attest_ec_public_hash: [u8; 32],
    /// `blake2_256(hmac_binding_output || nonce)` at genesis. The
    /// AttestKey-binding artifact; interim defense while upstream
    /// HMAC attestation is not yet landed.
    pub hmac_binding_commitment: [u8; 32],
    /// Verified Boot fields pinned at genesis. `None` in the current
    /// pass because X.509 chain parsing isn't wired yet — the mint
    /// path can't extract real values, and `None` is the honest
    /// sentinel for "not yet extracted" (vs storing zero/Green
    /// placeholders that would lie about device state).
    ///
    /// Follow-up pass (seal-break taxonomy + chain parser): these
    /// fields flip to required `T`. Testnet state is disposable until
    /// mainnet (see memory `project_testnet_state_disposable`), so
    /// no migration path is needed — wipe + redeploy at refactor time.
    pub root_of_trust: Option<RootOfTrustSnapshot>,
    pub os_patch_level: Option<u32>,
    pub boot_patch_level: Option<u32>,
    pub vendor_patch_level: Option<u32>,
    pub schema_version: crate::cert::SchemaVersion,
}

/// Genesis hardware fingerprint — platform-flavored. Stored on
/// `CertRecordCold` at `mint_cert` time as the ground-truth snapshot
/// of device state for ongoing HIP verification.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
pub enum GenesisHardwareFingerprint {
    Tpm2(Tpm2GenesisFingerprint),
    StrongBox(StrongBoxGenesisFingerprint),
}
