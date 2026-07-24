//! Presentation-protocol signing domains — the registry for every context in
//! which a zkpki device key signs something *off-chain* for an external
//! verifier (EAP-TLS session tokens, per-call tokens, OIDC assertions, …).
//!
//! # Invariant
//!
//! A presentation domain MUST NEVER collide with any preimage a device key
//! signs on-chain (extrinsic signing via the keyring's EcdsaP256 variant, PoP
//! assertions, HIP nonces) or with any other `rostro/…` domain in the
//! workspace. The same StrongBox/TPM key can simultaneously be a keyring
//! account authority and a presentation signer; domain separation is the only
//! thing preventing a presentation signature from being lifted into an
//! extrinsic (or vice versa). Every constant here therefore uses the house
//! `rostro/presentation/<profile>/v<N>` prefix, which no on-chain signing
//! path uses.
//!
//! New profiles append new constants; existing constants never change bytes.
//! A breaking change to a profile's preimage layout mints `/v<N+1>` alongside
//! the old constant.

/// Generic short-lived presentation token: a device-key signature over
/// `(audience, context, nonce, issued_at, expires_at)`. The token-bound
/// profile for verifiers that do not hold a live channel to the device.
pub const PRESENTATION_TOKEN_DOMAIN_V1: &[u8] = b"rostro/presentation/token/v1";

/// Telephony per-call token: a device-key signature over
/// `(destination, presented_cli, call_id, issued_at)`. Rides SIP signaling
/// so terminating-side verifiers can check attestation without a channel to
/// the caller's device.
pub const PRESENTATION_CALL_TOKEN_DOMAIN_V1: &[u8] = b"rostro/presentation/call-token/v1";

/// Reserved for the channel-bound profile if a profile-specific exporter
/// binding is ever needed beyond what TLS 1.3 CertificateVerify provides.
/// Unused today; declared so the name is burned in the registry.
///
/// `#[doc(hidden)]` and deliberately NOT a `pub` signing constant: the
/// preimage layout for a channel-binding token is undesigned, so nothing
/// should be able to sign with `channel-binding/v1` and freeze its bytes
/// to an accidental format. Promote to a documented `pub const` only when
/// the profile's field layout is actually specified.
#[doc(hidden)]
#[allow(dead_code)]
pub(crate) const _RESERVED_PRESENTATION_CHANNEL_BINDING_DOMAIN_V1: &[u8] =
    b"rostro/presentation/channel-binding/v1";
