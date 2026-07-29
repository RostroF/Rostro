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
    /// Chat membership: the cert may authenticate to chat guards.
    ///
    /// The declared form of the membership-tree leaf: `mint_cert`
    /// accepts a `chat_enrollment` only under a template carrying
    /// this EKU, and stamps it onto the cert record only when the
    /// enrollment actually inserted a leaf — so possession of this
    /// EKU on a cert is equivalent to a live leaf in the membership
    /// tree. Chartering flows through the normal capability chain
    /// (root → issuer → template); the holder's silicon is checked
    /// at mint (§5.5), not via the root's own attestation.
    ///
    /// Appended after `SmartContractIssuer` — variant indexes are
    /// live in SCALE-encoded chain state; append-only.
    ChatAuth,
    /// Witness membership: the cert holds a presentable anonymous
    /// membership credential (non-chat) — the "approved-to-transact"
    /// form used for RWA and other relying-party flows.
    ///
    /// The declared form of a witness-cert leaf: `mint_witness_cert`
    /// accepts an enrollment only under a template carrying this EKU,
    /// and inserts the leaf into a per-issuer keccak tree under a
    /// distinct domain scope (`WITNESS_SCOPE = 2`, not chat's
    /// `MEMBERSHIP_SCOPE = 1`) so a presentation cannot cross the
    /// chat/witness domain boundary; per-issuer separation is by tree
    /// (root), not scope. The presentation is additionally bound to a
    /// relying-party action via the circuit's `challenge`. Unlike
    /// `ChatAuth`, the on-chain cert carries no
    /// resolvable issuer↔holder edge (the witness path suppresses the
    /// user/issuer secondary indexes); the leaf is the only footprint.
    /// Chartering flows through the normal capability chain
    /// (root → issuer → template); the holder's silicon is checked at
    /// mint (§5.5), not via the root's own attestation.
    ///
    /// Appended after `ChatAuth` — variant indexes are live in
    /// SCALE-encoded chain state; append-only.
    WitnessAuth,
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
                | Eku::ChatAuth
                | Eku::WitnessAuth
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
            Eku::RootCert
                | Eku::ProofOfPersonhood
                | Eku::SmartContractIssuer
                | Eku::ChatAuth
                | Eku::WitnessAuth
        )
    }

    /// EKUs that may appear in an issuer's `capability_ekus` set.
    pub fn valid_for_issuer(&self) -> bool {
        matches!(
            self,
            Eku::IssuerCert
                | Eku::ProofOfPersonhood
                | Eku::SmartContractIssuer
                | Eku::ChatAuth
                | Eku::WitnessAuth
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;

    /// SCALE variant indexes are live in chain state (templates, cert
    /// records, capability sets) — this pin fails loudly if anyone
    /// reorders or inserts instead of appending.
    #[test]
    fn eku_variant_indexes_are_pinned() {
        let pins: [(Eku, u8); 12] = [
            (Eku::ServerAuth, 0),
            (Eku::ClientAuth, 1),
            (Eku::CodeSigning, 2),
            (Eku::EmailProtection, 3),
            (Eku::ProofOfPersonhood, 4),
            (Eku::BlockchainSigning, 5),
            (Eku::IdentityAssertion, 6),
            (Eku::IssuerCert, 7),
            (Eku::RootCert, 8),
            (Eku::SmartContractIssuer, 9),
            (Eku::ChatAuth, 10),
            (Eku::WitnessAuth, 11),
        ];
        for (eku, index) in pins {
            assert_eq!(eku.encode(), vec![index], "{eku:?} index drifted");
        }
    }

    #[test]
    fn chat_auth_capability_plumbing() {
        assert!(Eku::ChatAuth.requires_issuer_capability());
        assert!(Eku::ChatAuth.valid_for_root());
        assert!(Eku::ChatAuth.valid_for_issuer());
        // ChatAuth must NOT force a PoP template: the §5.5 silicon gate
        // on the enrollment itself is the hardware check, so PoP-free
        // templates may carry ChatAuth (e.g. lab desktop mints).
        assert!(!Eku::ChatAuth.implies_pop_required());
    }

    #[test]
    fn witness_auth_capability_plumbing() {
        // WitnessAuth is a full sibling of ChatAuth in the charter chain:
        // an issuer can only grant it if its own cert carries it, and it
        // is delegable at root and issuer tiers.
        assert!(Eku::WitnessAuth.requires_issuer_capability());
        assert!(Eku::WitnessAuth.valid_for_root());
        assert!(Eku::WitnessAuth.valid_for_issuer());
        // Same silicon-gate reasoning as ChatAuth: the §5.5 hardware
        // check is on the enrollment, not forced via the template.
        assert!(!Eku::WitnessAuth.implies_pop_required());
    }
}
