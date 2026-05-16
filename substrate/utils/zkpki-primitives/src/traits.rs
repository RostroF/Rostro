use codec::Encode;
use crate::crypto::DevicePublicKey;
use crate::ek::EkHash;
use crate::tpm::AttestationType;

/// Validates a TPM/FIDO2 attestation blob.
///
/// `challenge` is mandatory per FIDO2 spec — provides freshness binding
/// to prevent attestation replay. The pallet generates it as
/// `blake2_256(account ++ block_number)` and passes it through.
pub trait AttestationVerifier {
    type Error;

    /// Verify the attestation blob and extract the EK hash.
    ///
    /// `expected_pubkey`: the device public key the caller submitted (any supported algorithm).
    /// `challenge`: freshness nonce — the verifier checks the attestation's
    /// clientDataHash includes this value.
    fn verify(
        attestation: &[u8],
        expected_pubkey: &DevicePublicKey,
        challenge: &[u8],
    ) -> Result<(EkHash, AttestationType), Self::Error>;
}

/// Stub verifier for Paseo testnet. Accepts all attestations.
/// Returns hash of the pubkey as EK (not zeros — defensive against
/// code paths that use EK hash without checking is_pop_eligible()).
/// Returns `AttestationType::None` — no PoP eligibility, no EK dedup.
pub struct NoopAttestationVerifier;

impl AttestationVerifier for NoopAttestationVerifier {
    type Error = sp_runtime::DispatchError;

    fn verify(
        _attestation: &[u8],
        expected_pubkey: &DevicePublicKey,
        _challenge: &[u8],
    ) -> Result<(EkHash, AttestationType), Self::Error> {
        // Hash the full DevicePublicKey encoding (includes algorithm + bytes).
        let ek_hash = sp_io::hashing::blake2_256(&expected_pubkey.encode());
        Ok((ek_hash, AttestationType::None))
    }
}

/// Test-only verifier that returns `AttestationType::Tpm` with a
/// per-call-unique EK hash derived from `(pubkey, challenge)`.
/// Different challenges produce different EK hashes, so the EK
/// dedup gate on `register_root` / `issue_issuer_cert` stays
/// satisfied across multiple calls in the same test. Exists to
/// exercise PoP-capability happy-path code in the pallet — not for
/// production use.
pub struct TpmTestAttestationVerifier;

impl AttestationVerifier for TpmTestAttestationVerifier {
    type Error = sp_runtime::DispatchError;

    fn verify(
        _attestation: &[u8],
        expected_pubkey: &DevicePublicKey,
        challenge: &[u8],
    ) -> Result<(EkHash, AttestationType), Self::Error> {
        let ek_hash =
            sp_io::hashing::blake2_256(&(expected_pubkey.encode(), challenge).encode());
        Ok((ek_hash, AttestationType::Tpm))
    }
}
