#![cfg_attr(not(feature = "std"), no_std)]

pub mod chain;
pub mod parse;
mod verify;

pub use chain::{
    verify_chain, verify_chain_with_pin, verify_chain_with_pin_and_intermediates, ChainError,
    GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH, KNOWN_MANUFACTURER_INTERMEDIATES,
    SAMSUNG_S3K250AF_INTERMEDIATE_HASH,
};
pub use parse::{
    parse_attestation, parse_chain_without_verify, ParsedAttestation, SecurityLevel,
    VerifiedBootState,
};
pub use verify::{
    verify_binding_proof, verify_binding_proof_with_pins, AttestationPayloadV3,
    BindingProofError, BindingProofVerifier, ProductionBindingProofVerifier,
    TpmAttestationVerifier, VerifiedAttestation,
};

#[cfg(feature = "test-utils")]
pub use verify::test_mock_verifier;
