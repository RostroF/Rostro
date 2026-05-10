use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Attestation type determines PoP eligibility.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub enum AttestationType {
    /// Physical TPM or secure enclave — eligible for Proof of Personhood.
    Tpm,
    /// vKMS / software TPM — machine/org identity only, NOT PoP eligible.
    Packed,
    /// Self-attested — lowest trust tier.
    None,
}

impl AttestationType {
    pub fn is_pop_eligible(&self) -> bool {
        matches!(self, AttestationType::Tpm)
    }
}
