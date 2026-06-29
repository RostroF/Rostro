//! Chat membership enrollment: binding an `id_commitment` to the device's
//! attested key at mint.
//!
//! This is deliberately separate from device attestation ([`crate::verify`]).
//! The attestation payload proves the cert's genuineness; chat enrollment
//! is an overlay that proves a hardware-derived membership commitment was
//! asserted by the *same* genuine, intact silicon. Keeping it in its own
//! module (and its own extrinsic field) means the attestation payload keeps
//! its single purpose, and a cert can exist with or without a chat leaf.
//!
//! See DOTWAVE-CHAT-ANON-MEMBERSHIP-AUTH section 4.3 and DECISIONS D2.

extern crate alloc;
use alloc::vec::Vec;

use codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
use zk_pki_primitives::crypto::DevicePublicKey;

/// Domain-separation context for the id-commitment binding signature.
/// Mixed in ahead of the commitment and challenge so a signature produced
/// for this purpose can never be replayed as any other attest_ec signature
/// (the integrity blob, the co-residency binding, a future use).
pub const ID_BINDING_CONTEXT: &[u8] = b"rostro-chat-id-binding-v1";

/// A holder's chat-membership enrollment, submitted alongside mint.
///
/// `id_commitment` is `Poseidon(s)` (canonical little-endian bytes), where
/// `s` is the hardware-derived membership secret; the phone never reveals
/// `s`. `id_binding_signature` is produced by the device's attested
/// `attest_ec` key over
/// `blake2_256(ID_BINDING_CONTEXT || id_commitment || challenge)`. Because
/// `attest_ec` is the key the attestation already proved genuine,
/// non-exportable, and same-RootOfTrust as the cert, the commitment
/// inherits that hardware binding.
///
/// `id_commitment` is *not* range-checked here. The pallet validates it is
/// a canonical BN254 field element at the point it becomes a leaf
/// (validate-at-handoff), where it already depends on the Poseidon crate.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct ChatEnrollment {
    pub id_commitment: [u8; 32],
    pub id_binding_signature: Vec<u8>,
}

/// Rejection reasons for [`verify_chat_enrollment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatEnrollmentError {
    /// `id_binding_signature` did not verify under `attest_ec` over
    /// `blake2_256(ID_BINDING_CONTEXT || id_commitment || challenge)`.
    BindingSignatureInvalid,
}

/// Verify that `enrollment.id_commitment` was signed by the attested
/// `attest_ec` key for this `challenge`.
///
/// The caller must pass the `attest_ec_pubkey` from a *verified*
/// attestation ([`crate::VerifiedAttestation::attest_ec_pubkey`]) and the
/// same `challenge` (the offer nonce) it verified that attestation
/// against. The binding then inherits genuineness and same-RootOfTrust
/// from that prior check: this function only adds "and the same silicon
/// asserts this commitment, for this offer."
pub fn verify_chat_enrollment(
    enrollment: &ChatEnrollment,
    attest_ec_pubkey: &DevicePublicKey,
    challenge: &[u8],
) -> Result<(), ChatEnrollmentError> {
    let mut input = Vec::with_capacity(ID_BINDING_CONTEXT.len() + 32 + challenge.len());
    input.extend_from_slice(ID_BINDING_CONTEXT);
    input.extend_from_slice(&enrollment.id_commitment);
    input.extend_from_slice(challenge);
    let msg = sp_io::hashing::blake2_256(&input);

    if !attest_ec_pubkey.verify_signature(&msg, &enrollment.id_binding_signature) {
        return Err(ChatEnrollmentError::BindingSignatureInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
