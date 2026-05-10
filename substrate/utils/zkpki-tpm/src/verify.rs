//! Production attestation verifiers.
//!
//! Two entry points live here:
//!
//! - [`TpmAttestationVerifier`] — the original single-chain verifier used
//!   by early wiring. Verifies one Android Keystore attestation chain,
//!   extracts the EK hash, and returns an [`AttestationType`].
//!
//! - [`verify_binding_proof`] — the TODO-3 orchestration layer. Takes an
//!   [`AttestationPayloadV3`] (two chains + HMAC binding output + binding
//!   signature + integrity-attestation blob + integrity signature) and
//!   runs the full verification pipeline end-to-end: Gate 1 (chain
//!   verification, Google root pin, manufacturer intermediate pin),
//!   same-challenge + same-root cross-chain binding, operational binding
//!   signature over `blake2_256(hmac_output || challenge)`, and Gate 2
//!   (integrity attestation via `zk_pki_integrity`). Returns
//!   [`VerifiedAttestation`] on success — everything the pallet's
//!   `mint_cert` extrinsic needs to decide PoP eligibility and write the
//!   EK registry entry.

extern crate alloc;

use alloc::vec::Vec;

use codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
use zk_pki_integrity::{
    verify_integrity_attestation, IntegrityAttestation, IntegrityError,
};
use zk_pki_primitives::{
    crypto::DevicePublicKey,
    ek::EkHash,
    tpm::AttestationType,
    traits::AttestationVerifier,
};

use crate::chain::{
    verify_chain_with_pin_and_intermediates, ChainError,
    GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH, KNOWN_MANUFACTURER_INTERMEDIATES,
};
use crate::parse::{self, VerifiedBootState};

/// Production Android Keystore attestation verifier.
pub struct TpmAttestationVerifier;

impl AttestationVerifier for TpmAttestationVerifier {
    type Error = sp_runtime::DispatchError;

    fn verify(
        attestation: &[u8],
        expected_pubkey: &DevicePublicKey,
        challenge: &[u8],
    ) -> Result<(EkHash, AttestationType), Self::Error> {
        let parsed = parse::parse_attestation(attestation)
            .ok_or(sp_runtime::DispatchError::Other("MalformedAttestation"))?;

        if &parsed.pubkey != expected_pubkey {
            return Err(sp_runtime::DispatchError::Other("PubkeyMismatch"));
        }

        if parsed.attestation_challenge.as_slice() != challenge {
            return Err(sp_runtime::DispatchError::Other("ChallengeMismatch"));
        }

        // EK identity = blake2_256 of the leaf cert's SubjectPublicKeyInfo.
        // The SPKI is device-unique (fresh per StrongBox keypair) and
        // lives inside the signed TBS — a chain that verifies cannot
        // have an altered SPKI. Hashing the manufacturer root (which is
        // shared across every device on that manufacturer) would
        // collapse every device to one EK per root, breaking Sybil
        // resistance under invariant #6.
        let ek_hash = sp_io::hashing::blake2_256(&parsed.leaf_spki_der);

        // PoP eligibility requires StrongBox on both security levels AND a
        // locked bootloader AND a verified boot state. Rejecting anything
        // less closes the rooted-phone-farm attack: a farm of rooted devices
        // can automate the ceremony, produce valid keys and signatures, and
        // still fail here because the RootOfTrust data comes from secure
        // hardware, not userspace.
        let att_type = if parsed.is_pop_eligible {
            AttestationType::Tpm
        } else {
            AttestationType::Packed
        };

        Ok((ek_hash, att_type))
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TODO-3 v3 attestation payload — orchestration layer composing Gate 1
// (chain + manufacturer intermediate) + binding proof + Gate 2 (integrity).
// ═══════════════════════════════════════════════════════════════════════

/// Full TODO-3 mint-time attestation payload.
///
/// The Dotwave Kotlin ceremony produces this shape; the pallet's
/// `mint_cert` extrinsic receives it SCALE-encoded, hands it to
/// [`verify_binding_proof`], and on success uses the returned
/// [`VerifiedAttestation`] to write the cert lookup entry and EK registry.
///
/// ## Fields
///
/// - `cert_ec_chain` / `attest_ec_chain` — Android Keystore attestation
///   chains, leaf first, Google Hardware Attestation Root CA last. The two
///   chains share the same intermediates and root (provisioned at device
///   manufacture, shared across all keys attested on the hardware); only
///   the leaves differ. `cert_ec` certifies `zkpki_cert_ec` (the user's
///   on-chain cert signing key); `attest_ec` certifies `zkpki_attest_ec`
///   (the dedicated binding-proof key).
///
/// - `hmac_binding_output` — the 32-byte HMAC-SHA256 output over the fixed
///   context string `"zkpki-binding-proof-v1"`, computed inside StrongBox
///   using the user's HMAC key. On Samsung Knox the HMAC key has no
///   attestation chain; its presence in the same StrongBox as
///   `zkpki_attest_ec` is proven cryptographically by the binding
///   signature below, not by a cert.
///
/// - `binding_signature` — DER-encoded ECDSA-P-256 signature produced by
///   `zkpki_attest_ec` over the commitment
///   `blake2b_256(hmac_binding_output || attestation_challenge)`. Proves
///   the binding key and the HMAC key live in the same StrongBox.
///
/// - `integrity_blob` — SCALE-encoded
///   [`zk_pki_integrity::IntegrityAttestation`] — the device-integrity
///   declaration (package name, APK signing cert hash, ceremony block
///   number, debugger + Keystore integrity bits).
///
/// - `integrity_signature` — DER-encoded ECDSA-P-256 signature produced by
///   `zkpki_cert_ec` over `blake2_256(integrity_blob)`.
///
/// SCALE-encodable (`Encode + Decode + TypeInfo`) so the pallet can
/// accept it directly as an extrinsic parameter. The inner `Vec<u8>`s
/// are unbounded at the type level; Substrate's extrinsic size limit
/// (default ~4 MB) is the real upper bound, and the wire payload for a
/// typical Android Keystore two-chain attestation sits comfortably
/// under 50 KB. Pallets that want a tighter ceiling can wrap the whole
/// payload in a `BoundedVec<u8, _>` at the call boundary and decode
/// after length-checking.
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct AttestationPayloadV3 {
    pub cert_ec_chain: Vec<Vec<u8>>,
    pub attest_ec_chain: Vec<Vec<u8>>,
    pub hmac_binding_output: [u8; 32],
    pub binding_signature: Vec<u8>,
    pub integrity_blob: Vec<u8>,
    pub integrity_signature: Vec<u8>,
}

/// Fields the caller needs after [`verify_binding_proof`] succeeds.
///
/// The pallet uses `cert_ec_pubkey` as the on-chain signing key bound to
/// the newly minted cert; `ek_hash` is the key for the EK deduplication
/// registry; `attestation_type` drives PoP eligibility; `device_locked`
/// and `verified_boot_state` are surfaced to relying parties as raw
/// RootOfTrust fields; `manufacturer_verified` records that the cert_ec
/// chain's intermediate matched a known-good StrongBox manufacturer pin.
///
/// `Debug` is gated on `std` because the embedded `AttestationType`
/// derives `Debug` only under `std`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct VerifiedAttestation {
    pub cert_ec_pubkey: DevicePublicKey,
    pub ek_hash: [u8; 32],
    pub attestation_type: AttestationType,
    pub device_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub manufacturer_verified: bool,
    /// `attestationApplicationId`'s first `package_name` extracted from
    /// the cert_ec chain, or `None` if the chain's KeyDescription did
    /// not carry tag [709]. When `Some`, its value was cross-checked
    /// against the integrity blob's `package_name` inside
    /// [`verify_binding_proof`].
    pub package_name: Option<Vec<u8>>,
    /// `attestationApplicationId`'s first `signature_digest` (SHA-256
    /// of the APK signing cert) extracted from the cert_ec chain, or
    /// `None` if absent. When `Some`, its value was cross-checked
    /// against the integrity blob's `signing_cert_hash` inside
    /// [`verify_binding_proof`].
    pub signing_cert_hash: Option<[u8; 32]>,
}

/// Distinguishable rejection reasons for [`verify_binding_proof`]. Each
/// variant corresponds to a specific gate in the pipeline so negative
/// tests and runtime diagnostics can tell exactly which check fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingProofError {
    /// `cert_ec_chain` failed signature verification, root pin, or
    /// manufacturer intermediate pin. Also returned if the chain parses
    /// cryptographically but the leaf has no valid KeyDescription
    /// extension — surfaced as `ChainError::MalformedCertificate`.
    CertEcChainInvalid(ChainError),
    /// Same as [`Self::CertEcChainInvalid`] but for `attest_ec_chain`.
    AttestEcChainInvalid(ChainError),
    /// The two chains do not terminate at byte-identical root
    /// certificates. Real Android hardware provisions one root at
    /// manufacture time and every attestation chain on that device shares
    /// it — a mismatch means the chains came from different hardware.
    RootMismatch,
    /// The attestation challenge recorded in one or both chains'
    /// KeyDescription extension does not equal the challenge the pallet
    /// passed in. Either chain's challenge diverging from the expected
    /// value means the chains were not produced for *this* offer.
    ChallengeMismatch,
    /// Reserved. Commitment input construction is deterministic given the
    /// other fields; this variant is never currently returned but is
    /// listed as a protocol-level rejection reason for future use (e.g.
    /// if the caller supplies a pre-computed commitment).
    CommitmentInvalid,
    /// The binding signature did not verify under `attest_ec_leaf`'s
    /// public key over the commitment
    /// `blake2_256(hmac_binding_output || challenge)`.
    BindingSignatureInvalid,
    /// The integrity-attestation blob failed its own
    /// [`zk_pki_integrity::verify_integrity_attestation`] check. Carries
    /// the exact sub-error (decode failure, signature invalid, wrong
    /// package, offer-window mismatch, debugger detected, etc.).
    IntegrityFailed(IntegrityError),
    /// The cert_ec chain's `attestationApplicationId.package_name`
    /// disagreed with the integrity blob's declared `package_name`, or
    /// the two chains' AAID package names disagreed with each other.
    /// The Keystore daemon writes the chain's AAID at key-generation
    /// time, so a mismatch means the blob was produced by a different
    /// app than the one whose cert_ec key we're certifying.
    PackageNameCrossCheckFailed,
    /// The cert_ec chain's `attestationApplicationId.signing_cert_hash`
    /// disagreed with the integrity blob's `signing_cert_hash`. Same
    /// security argument as [`Self::PackageNameCrossCheckFailed`] —
    /// chain AAID is Keystore-written, blob is app-written; a mismatch
    /// proves the two weren't produced by the same signed APK.
    SigningCertCrossCheckFailed,
}

/// Verify a TODO-3 attestation payload end-to-end using the production
/// Google root pin and the default [`KNOWN_MANUFACTURER_INTERMEDIATES`]
/// set.
pub fn verify_binding_proof(
    payload: &AttestationPayloadV3,
    expected_challenge: &[u8],
    offer_created_at_block: u64,
    offer_expiry_block: u64,
) -> Result<VerifiedAttestation, BindingProofError> {
    verify_binding_proof_with_pins(
        payload,
        &GOOGLE_HARDWARE_ATTESTATION_ROOT_SPKI_HASH,
        KNOWN_MANUFACTURER_INTERMEDIATES,
        expected_challenge,
        offer_created_at_block,
        offer_expiry_block,
    )
}

/// Same as [`verify_binding_proof`] but takes the root pin and
/// manufacturer intermediate set as parameters.
///
/// Exposed so synthesized-keypair tests can build their own test chains
/// and thread a test-specific pin + intermediate hash through the
/// verifier without forging against the production constants. Production
/// callers should always use [`verify_binding_proof`].
pub fn verify_binding_proof_with_pins(
    payload: &AttestationPayloadV3,
    pin: &[u8; 32],
    known_intermediates: &[[u8; 32]],
    expected_challenge: &[u8],
    offer_created_at_block: u64,
    offer_expiry_block: u64,
) -> Result<VerifiedAttestation, BindingProofError> {
    // 1. cert_ec chain: signatures + Google root pin + manufacturer pin.
    verify_chain_with_pin_and_intermediates(
        &payload.cert_ec_chain,
        pin,
        known_intermediates,
    )
    .map_err(BindingProofError::CertEcChainInvalid)?;

    // 2. attest_ec chain: same suite of checks.
    verify_chain_with_pin_and_intermediates(
        &payload.attest_ec_chain,
        pin,
        known_intermediates,
    )
    .map_err(BindingProofError::AttestEcChainInvalid)?;

    // 3. Same-root byte equality. Both chains verified cleanly above, so
    // both have a last() element. The byte-comparison holds on real
    // Android hardware because the root is provisioned once and reused
    // across every attestation on the device.
    let cert_root = payload
        .cert_ec_chain
        .last()
        .ok_or(BindingProofError::CertEcChainInvalid(ChainError::EmptyChain))?;
    let attest_root = payload
        .attest_ec_chain
        .last()
        .ok_or(BindingProofError::AttestEcChainInvalid(ChainError::EmptyChain))?;
    if cert_root != attest_root {
        return Err(BindingProofError::RootMismatch);
    }

    // Extract leaf fields from each chain. Uses the no-reverify path
    // because the chains already verified in steps 1 and 2.
    let cert_ec_parsed = parse::parse_chain_without_verify(&payload.cert_ec_chain)
        .ok_or(BindingProofError::CertEcChainInvalid(
            ChainError::MalformedCertificate,
        ))?;
    let attest_ec_parsed = parse::parse_chain_without_verify(&payload.attest_ec_chain)
        .ok_or(BindingProofError::AttestEcChainInvalid(
            ChainError::MalformedCertificate,
        ))?;

    // 3.5. Cross-check the cert_ec chain's `attestationApplicationId`
    // against the integrity blob. The chain's AAID is written by the
    // Android Keystore daemon at key-generation time (the app cannot
    // forge it); the blob's matching fields are written by the app.
    // Requiring them to agree here is what proves the blob came from
    // the **same** signed APK that Keystore saw generating the keys —
    // an attacker who controls the blob cannot also rewrite the
    // Keystore-produced chain.
    //
    // The chain↔blob agreement here, combined with the blob↔constant
    // checks inside `verify_integrity_attestation` at step 7, forms
    // the three-way agreement (chain == blob == constant) that the
    // Gate 2 design relies on.
    //
    // Decoding the blob here is fail-fast — if the caller passed
    // malformed bytes we bail now rather than waiting until step 7.
    // The same decode happens again inside
    // `verify_integrity_attestation`; the redundancy is ~50ns and
    // keeps the two call paths independently auditable.
    let blob = IntegrityAttestation::decode(&mut &payload.integrity_blob[..])
        .map_err(|_| BindingProofError::IntegrityFailed(IntegrityError::DecodeFailed))?;

    if let Some(chain_pkg) = cert_ec_parsed.package_name.as_ref() {
        if chain_pkg.as_slice() != blob.package_name.as_slice() {
            return Err(BindingProofError::PackageNameCrossCheckFailed);
        }
        // If the attest_ec chain also carries AAID, the two chains
        // must agree — they were generated back-to-back in the same
        // ceremony under the same applicationId, so a divergence means
        // mix-and-match across devices or apps.
        if let Some(attest_pkg) = attest_ec_parsed.package_name.as_ref() {
            if chain_pkg != attest_pkg {
                return Err(BindingProofError::PackageNameCrossCheckFailed);
            }
        }
    }

    if let Some(chain_hash) = cert_ec_parsed.signing_cert_hash.as_ref() {
        if chain_hash != &blob.signing_cert_hash {
            return Err(BindingProofError::SigningCertCrossCheckFailed);
        }
    }

    // 4. Same-challenge cross-chain. Each chain's KeyDescription embeds
    // the attestation challenge that was passed to `setAttestationChallenge`
    // at key generation time. Both chains generated in the same ceremony
    // carry the same challenge, and it must equal what the pallet
    // expects (the offer nonce). Any divergence means replay, swap, or
    // mix-and-match.
    if cert_ec_parsed.attestation_challenge.as_slice() != expected_challenge
        || attest_ec_parsed.attestation_challenge.as_slice() != expected_challenge
    {
        return Err(BindingProofError::ChallengeMismatch);
    }

    // 5. Commitment = blake2_256(hmac_binding_output || expected_challenge).
    // Mixing the challenge into the commitment binds the HMAC operation
    // to the specific offer — a recorded HMAC output cannot be reused
    // across offers because the challenge varies per offer.
    let mut commitment_input = Vec::with_capacity(32 + expected_challenge.len());
    commitment_input.extend_from_slice(&payload.hmac_binding_output);
    commitment_input.extend_from_slice(expected_challenge);
    let commitment = sp_io::hashing::blake2_256(&commitment_input);

    // 6. Binding signature: attest_ec leaf pubkey verifies binding_signature
    // over the commitment. DevicePublicKey::verify_signature internally
    // applies ECDSA-SHA256 (the standard p256 scheme) and attempts DER
    // first, raw (r||s) second — covering either encoding the ceremony
    // might emit.
    if !attest_ec_parsed
        .pubkey
        .verify_signature(&commitment, &payload.binding_signature)
    {
        return Err(BindingProofError::BindingSignatureInvalid);
    }

    // 7. Integrity attestation (Gate 2). The blob is signed by the same
    // key that cert_ec certifies — no new trust anchor, just a second
    // use of the already-chain-attested cert_ec key.
    verify_integrity_attestation(
        &payload.integrity_blob,
        &payload.integrity_signature,
        &cert_ec_parsed.pubkey,
        offer_created_at_block,
        offer_expiry_block,
    )
    .map_err(BindingProofError::IntegrityFailed)?;

    // Assemble the verified result.
    // EK identity is the leaf SPKI hash (device-unique). See the same
    // rationale on `TpmAttestationVerifier::verify`.
    let ek_hash = sp_io::hashing::blake2_256(&cert_ec_parsed.leaf_spki_der);
    let attestation_type = if cert_ec_parsed.is_pop_eligible {
        AttestationType::Tpm
    } else {
        AttestationType::Packed
    };

    Ok(VerifiedAttestation {
        cert_ec_pubkey: cert_ec_parsed.pubkey,
        ek_hash,
        attestation_type,
        device_locked: cert_ec_parsed.device_locked,
        verified_boot_state: cert_ec_parsed.verified_boot_state,
        // We reached this point only because Gate 1 passed — so at least
        // one intermediate matched `known_intermediates`. Record that
        // fact in the returned struct so the pallet can surface it.
        manufacturer_verified: true,
        // Surface the cross-checked AAID fields so pallet callers can
        // write them into storage / log them / present them to relying
        // parties without re-parsing the chain.
        package_name: cert_ec_parsed.package_name,
        signing_cert_hash: cert_ec_parsed.signing_cert_hash,
    })
}

// ═══════════════════════════════════════════════════════════════════════
// BindingProofVerifier trait — pluggable verification for pallet config
// ═══════════════════════════════════════════════════════════════════════

/// Associated-type-free verifier trait the pallet is configured with.
/// Lets the runtime pick between the production
/// [`ProductionBindingProofVerifier`] (real Google + Samsung pins) and
/// test-only implementations that inject synth pins or skip crypto
/// entirely for integration tests.
///
/// Mirrors the [`zk_pki_primitives::traits::AttestationVerifier`]
/// pattern the pallet already uses for `register_root` /
/// `issue_issuer_cert`, but with the TODO-3 payload shape and error
/// type.
pub trait BindingProofVerifier {
    fn verify(
        payload: &AttestationPayloadV3,
        expected_challenge: &[u8],
        offer_created_at_block: u64,
        offer_expiry_block: u64,
    ) -> Result<VerifiedAttestation, BindingProofError>;
}

/// Production verifier. Pins against Google's Hardware Attestation Root
/// CA and the [`KNOWN_MANUFACTURER_INTERMEDIATES`] set; uses the
/// real constants from `zk-pki-integrity` for Gate 2.
///
/// This is the only verifier that should be wired into a mainnet
/// runtime. Testnet and integration-test runtimes can wire
/// `test_mock_verifier::NoopBindingProofVerifier` instead.
pub struct ProductionBindingProofVerifier;

impl BindingProofVerifier for ProductionBindingProofVerifier {
    fn verify(
        payload: &AttestationPayloadV3,
        expected_challenge: &[u8],
        offer_created_at_block: u64,
        offer_expiry_block: u64,
    ) -> Result<VerifiedAttestation, BindingProofError> {
        verify_binding_proof(
            payload,
            expected_challenge,
            offer_created_at_block,
            offer_expiry_block,
        )
    }
}

/// Test-only verifier that returns a caller-controlled verdict.
/// Gated behind the `test-utils` feature so production builds can't
/// accidentally depend on it.
///
/// **Do not wire into a production runtime** — this bypasses every
/// security check.
///
/// # How pallet tests control the mock
///
/// The real `verify_binding_proof` decodes `payload.integrity_blob`
/// as a SCALE-encoded `IntegrityAttestation`. The mock here hijacks
/// that field: it decodes `payload.integrity_blob` as a
/// [`MockVerdict`] instead. Tests build payloads where the
/// integrity_blob carries the verdict they want the mock to return:
///
/// ```ignore
/// use codec::Encode;
/// let payload = AttestationPayloadV3 {
///     // everything else can be dummy bytes — the mock ignores them
///     integrity_blob: MockVerdict::Tpm {
///         ek_hash: [0x42; 32],
///         pubkey_bytes: fake_p256_pubkey().to_vec(),
///     }.encode(),
///     ..dummy_payload()
/// };
/// ```
///
/// This keeps tests explicit (each test's crafted verdict is visible
/// in the payload construction) and avoids thread-local sugar /
/// runtime-feature gates on the pallet side.
#[cfg(feature = "test-utils")]
pub mod test_mock_verifier {
    use super::*;
    use codec::{Decode, Encode};
    use zk_pki_primitives::{crypto::DevicePublicKey, tpm::AttestationType};

    /// A verdict the test runtime wants the mock to return. SCALE-
    /// encoded by the test into `payload.integrity_blob`; the mock
    /// decodes and returns accordingly.
    #[derive(Clone, Encode, Decode)]
    pub enum MockVerdict {
        /// Return `Ok` with `AttestationType::Tpm`, the given EK hash,
        /// and a `DevicePublicKey` parsed from the given SEC1 bytes.
        /// Device is reported as locked + verifiedBoot=Verified,
        /// manufacturer_verified=true.
        Tpm { ek_hash: [u8; 32], pubkey_bytes: Vec<u8> },
        /// Return `Ok` with `AttestationType::Packed` and the given
        /// pubkey. `ek_hash` is hard-set to `[0u8; 32]` (the pallet's
        /// EK-dedup path checks `attestation_type.is_pop_eligible()`
        /// first, so the zero hash is never written to the registry).
        Packed { pubkey_bytes: Vec<u8> },
        /// Return `Ok` with `AttestationType::None` — no hardware
        /// attestation at all. Used by fee-system tests to exercise
        /// the `MintFeeNone` tier; not PoP-eligible, no EK dedup.
        None { pubkey_bytes: Vec<u8> },
        /// Return `Err(BindingProofError::BindingSignatureInvalid)`.
        /// Pallet surfaces this as `Error::AttestationInvalid`.
        Fail,
    }

    /// Mock implementation of [`BindingProofVerifier`] controlled by
    /// the `integrity_blob` field of each payload.
    pub struct NoopBindingProofVerifier;

    impl BindingProofVerifier for NoopBindingProofVerifier {
        fn verify(
            payload: &AttestationPayloadV3,
            _expected_challenge: &[u8],
            _offer_created_at_block: u64,
            _offer_expiry_block: u64,
        ) -> Result<VerifiedAttestation, BindingProofError> {
            let verdict = MockVerdict::decode(&mut &payload.integrity_blob[..]).map_err(|_| {
                BindingProofError::IntegrityFailed(IntegrityError::DecodeFailed)
            })?;
            match verdict {
                MockVerdict::Fail => Err(BindingProofError::BindingSignatureInvalid),
                MockVerdict::Tpm { ek_hash, pubkey_bytes } => {
                    let pubkey = DevicePublicKey::new_p256(&pubkey_bytes).map_err(|_| {
                        BindingProofError::CertEcChainInvalid(
                            crate::chain::ChainError::BadPublicKey,
                        )
                    })?;
                    Ok(VerifiedAttestation {
                        cert_ec_pubkey: pubkey,
                        ek_hash,
                        attestation_type: AttestationType::Tpm,
                        device_locked: true,
                        verified_boot_state: crate::parse::VerifiedBootState::Verified,
                        manufacturer_verified: true,
                        package_name: None,
                        signing_cert_hash: None,
                    })
                }
                MockVerdict::Packed { pubkey_bytes } => {
                    let pubkey = DevicePublicKey::new_p256(&pubkey_bytes).map_err(|_| {
                        BindingProofError::CertEcChainInvalid(
                            crate::chain::ChainError::BadPublicKey,
                        )
                    })?;
                    Ok(VerifiedAttestation {
                        cert_ec_pubkey: pubkey,
                        ek_hash: [0u8; 32],
                        attestation_type: AttestationType::Packed,
                        device_locked: false,
                        verified_boot_state: crate::parse::VerifiedBootState::Unverified,
                        manufacturer_verified: false,
                        package_name: None,
                        signing_cert_hash: None,
                    })
                }
                MockVerdict::None { pubkey_bytes } => {
                    let pubkey = DevicePublicKey::new_p256(&pubkey_bytes).map_err(|_| {
                        BindingProofError::CertEcChainInvalid(
                            crate::chain::ChainError::BadPublicKey,
                        )
                    })?;
                    Ok(VerifiedAttestation {
                        cert_ec_pubkey: pubkey,
                        ek_hash: [0u8; 32],
                        attestation_type: AttestationType::None,
                        device_locked: false,
                        verified_boot_state: crate::parse::VerifiedBootState::Unverified,
                        manufacturer_verified: false,
                        package_name: None,
                        signing_cert_hash: None,
                    })
                }
            }
        }
    }
}
