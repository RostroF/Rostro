//! Extended Key Usage (EKU) variants for ZK-PKI certificates.
//!
//! Standard X.509 EKUs map 1:1 to real OID values in [`crate::oids`] —
//! ClientAuth, ServerAuth, CodeSigning, EmailProtection. Relying
//! parties that already trust the ZK-PKI issuer in their own trust
//! store can use these for TLS/SMIME/codesign without protocol
//! involvement; the pallet does not assert cross-ecosystem trust.
//!
//! ZK-PKI-specific EKUs (ProofOfPersonhood, BlockchainSigning, etc.)
//! use OIDs under the ZK-PKI PEN arc. The PEN is pending IANA
//! assignment — request filed 2026-04-18, expected within 7 days. The
//! enum variants are final; only the OID string constants in
//! [`crate::oids`] need updating once the PEN lands.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Extended Key Usage variants.
///
/// Encoded on-chain as the enum discriminant. Human-readable OID
/// form lives in [`crate::oids`] for off-chain tooling (cert export,
/// TLS integration, etc.).
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
pub enum Eku {
    // ── Standard X.509 EKUs — OIDs final ──────────────────────────
    /// `serverAuth` (1.3.6.1.5.5.7.3.1). Valid only when relying
    /// party independently trusts the ZK-PKI issuer.
    ServerAuth,
    /// `clientAuth` (1.3.6.1.5.5.7.3.2).
    ClientAuth,
    /// `codeSigning` (1.3.6.1.5.5.7.3.3).
    CodeSigning,
    /// `emailProtection` (1.3.6.1.5.5.7.3.4).
    EmailProtection,

    // ── ZK-PKI EKUs — OIDs pending IANA PEN ───────────────────────
    /// Certifies the subject completed a physical-TPM ceremony.
    /// Templates carrying this EKU must have
    /// `PopRequirement::Required`; roots/issuers carrying it as a
    /// capability must themselves hold a `Tpm` attestation.
    ProofOfPersonhood,
    /// Signing authority for on-chain blockchain transactions.
    BlockchainSigning,
    /// Generic identity assertion — relying parties pick their own semantics.
    IdentityAssertion,
    /// Marks the subject as an issuer in the ZK-PKI hierarchy.
    IssuerCert,
    /// Marks the subject as a root CA in the ZK-PKI hierarchy.
    RootCert,
    /// Authority to issue via ink! smart contracts.
    SmartContractIssuer,
}

impl Eku {
    /// EKUs that propagate through the trust hierarchy — an issuer
    /// cannot grant what their own cert does not have as a
    /// capability. Standard EKUs (ClientAuth / ServerAuth / etc.) are
    /// freely assignable and return `false` here; the relying-party
    /// trust decision for those is out of band.
    pub fn requires_issuer_capability(&self) -> bool {
        matches!(
            self,
            Eku::ProofOfPersonhood
                | Eku::SmartContractIssuer
                | Eku::IssuerCert
                | Eku::RootCert
        )
    }

    /// `true` iff this EKU on a template forces
    /// `pop_requirement == Required`. Only `ProofOfPersonhood`
    /// implies PoP in v1.
    pub fn implies_pop_required(&self) -> bool {
        matches!(self, Eku::ProofOfPersonhood)
    }

    /// EKUs that may appear in a root's `capability_ekus` set.
    pub fn valid_for_root(&self) -> bool {
        matches!(
            self,
            Eku::RootCert | Eku::ProofOfPersonhood | Eku::SmartContractIssuer
        )
    }

    /// EKUs that may appear in an issuer's `capability_ekus` set.
    pub fn valid_for_issuer(&self) -> bool {
        matches!(
            self,
            Eku::IssuerCert | Eku::ProofOfPersonhood | Eku::SmartContractIssuer
        )
    }
}
