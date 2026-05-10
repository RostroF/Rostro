use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{traits::ConstU32, BoundedVec};
use scale_info::TypeInfo;

use crate::eku::Eku;

/// Maximum number of EKUs attachable to a single template.
pub const MAX_TEMPLATE_EKUS: u32 = 16;

/// Maximum byte length of a cert template name. Bounded so the
/// `(issuer, name)` storage key stays bounded.
pub const MAX_TEMPLATE_NAME_LEN: u32 = 64;

/// Maximum byte length of a template's optional metadata schema.
/// Covers a JSON-Schema-ish descriptor — whatever the issuer wants
/// to pin to the template class so relying parties can interpret
/// minted-cert metadata consistently.
pub const MAX_TEMPLATE_METADATA_SCHEMA_LEN: u32 = 1024;

/// PoP (Proof of Personhood) requirement on a cert template.
///
/// An issuer declares at template-creation time whether certs minted
/// under this template class MUST carry a physical-TPM attestation
/// (`AttestationType::Tpm`) or whether the issuer explicitly waives
/// PoP and will accept any attestation type.
///
/// The distinction is a trust-policy choice owned by the issuer. The
/// pallet enforces it at `mint_cert` so the template's declared
/// policy is honored end-to-end, not just advisory.
#[derive(
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    Clone,
    PartialEq,
    Eq,
    MaxEncodedLen,
    Debug,
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum PopRequirement {
    /// `AttestationType::Tpm` mandatory — mints fail otherwise.
    Required,
    /// Issuer waives PoP — any attestation type accepted.
    NotRequired,
}

/// Cryptographic mechanism used to assert PoP at sign time.
///
/// Distinct from [`PopRequirement`]: that one says *whether* PoP is
/// required at all; this one says *how* the holder proves possession
/// when PoP is required. The two-tier split exists because the
/// Android StrongBox HMAC binding is too weak to carry the standard
/// HipSigned (P-256 ECDSA over a derived nonce) approach safely on
/// its own — see the `StrongBox HMAC Gap` design note. The mime-wrap
/// Groth16 proof was introduced as the Android-only alternative.
///
/// **Platform gating is enforced at `mint_cert`**: a template with
/// `pop_mechanism == Some(MimeWrap)` may only be used to mint certs
/// whose attestation chain places them on Android (StrongBox);
/// `Some(HipSigned)` may only be used on TPM2 hardware. Mismatched
/// mints fail rather than producing a cert that would later be
/// unusable.
#[derive(
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    Clone,
    Copy,
    PartialEq,
    Eq,
    MaxEncodedLen,
    Debug,
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum PopMechanism {
    /// P-256 ECDSA signature over `derive_pop_nonce` plus a HIP
    /// proof. Standard path. Permitted on TPM2 attestation chains
    /// (`CanonicalHipProof::Tpm2`); rejected on StrongBox at mint
    /// time because the StrongBox HMAC binding is the very weakness
    /// MimeWrap was designed to work around.
    HipSigned,
    /// Groth16 proof over the mime-wrap circuit's public inputs plus
    /// a HIP proof. Android StrongBox path. Rejected on TPM2 at mint
    /// time as a category error — TPM2 has a real attestation chain
    /// and gains nothing from the ZK detour.
    MimeWrap,
}

/// On-chain template record. Immutable after creation except for
/// `is_active`, `issued_count`, and (implicitly) the deposit held.
/// Identified uniquely by `(issuer, name)`.
#[derive(Encode, Decode, TypeInfo, Clone, PartialEq, Eq, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug))]
#[scale_info(skip_type_params(AccountId, BlockNumber, Balance))]
pub struct CertTemplate<AccountId, BlockNumber, Balance> {
    pub issuer: AccountId,
    pub name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
    pub created_at_block: BlockNumber,
    pub pop_requirement: PopRequirement,
    /// Cryptographic mechanism for PoP at sign time. `Some(...)`
    /// only when `pop_requirement == Required`; `None` when PoP is
    /// waived. The pallet enforces this consistency at template
    /// creation, and enforces the platform gate (HipSigned ↔ Tpm2 /
    /// MimeWrap ↔ StrongBox) at `mint_cert`.
    pub pop_mechanism: Option<PopMechanism>,
    pub max_ttl_blocks: u64,
    pub min_ttl_blocks: u64,
    pub max_certs: Option<u32>,
    /// Monotonic lifetime counter — incremented at mint, never
    /// decremented. Used for reputation / audit. The discard-safety
    /// counter lives separately on-chain as `TemplateActiveCertCount`.
    pub issued_count: u32,
    pub deposit: Balance,
    pub metadata_schema:
        Option<BoundedVec<u8, ConstU32<MAX_TEMPLATE_METADATA_SCHEMA_LEN>>>,
    pub is_active: bool,
    /// EKUs attached to certs minted under this template. Immutable
    /// after template creation — copied verbatim onto
    /// `CertRecordHot.ekus` at mint time.
    pub ekus: BoundedVec<Eku, ConstU32<MAX_TEMPLATE_EKUS>>,
}
