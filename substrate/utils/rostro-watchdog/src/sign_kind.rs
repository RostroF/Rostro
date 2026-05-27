// SPDX-License-Identifier: Apache-2.0

//! Typed sign-kind whitelist.
//!
//! Every `Sign` request carries a kind discriminant; the watchdog does
//! shape validation per kind and prepends a domain-separator before
//! hashing. There is no "sign arbitrary bytes" op — a compromised node
//! cannot ask the watchdog to sign attacker-chosen data because the kinds
//! are an explicit, code-reviewed whitelist.
//!
//! Adding a new kind requires an explicit watchdog code change.
//! Validator session keys (BABE/Sassafras/GRANDPA) are a v0.2 surface and
//! deliberately have no kinds defined here.

use thiserror::Error;

/// Domain prefix prepended to every signed payload. Versioned so a future
/// protocol revision rotates the prefix and old signatures don't verify
/// under the new scheme even with the same key.
pub const DOMAIN_PREFIX: &[u8] = b"rostro-watchdog/v1/";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignKind {
    /// libp2p Noise-XX handshake input.
    NoiseHandshake = 0x01,
    /// Canonical-files `AttestationResponse`. The node already has the
    /// codec; watchdog re-validates shape on parse when wired.
    CanonicalAttest = 0x02,
    /// Libp2p signed peer record (DHT publication / address advertisement).
    PeerRecord = 0x03,
}

impl SignKind {
    pub fn from_u8(v: u8) -> Result<Self, SignKindError> {
        match v {
            0x01 => Ok(SignKind::NoiseHandshake),
            0x02 => Ok(SignKind::CanonicalAttest),
            0x03 => Ok(SignKind::PeerRecord),
            other => Err(SignKindError::Unknown(other)),
        }
    }

    /// Per-kind shape check. v0.1 enforces size bounds only; full
    /// structural validation (Noise prologue parse, AttestationResponse
    /// codec, etc.) is added when each consumer wires in.
    pub fn validate_payload(self, payload: &[u8]) -> Result<(), SignKindError> {
        let max = match self {
            SignKind::NoiseHandshake => 256,
            SignKind::CanonicalAttest => 4096,
            SignKind::PeerRecord => 1024,
        };
        if payload.is_empty() {
            return Err(SignKindError::EmptyPayload(self));
        }
        if payload.len() > max {
            return Err(SignKindError::PayloadTooLarge { kind: self, len: payload.len(), max });
        }
        Ok(())
    }

    /// Per-kind domain tag. Distinct tags prevent cross-kind signature
    /// replay: a signature produced under `NoiseHandshake` cannot be
    /// re-asserted as a `CanonicalAttest` signature even on the same
    /// payload bytes.
    pub fn domain_tag(self) -> &'static [u8] {
        match self {
            SignKind::NoiseHandshake => b"noise-xx",
            SignKind::CanonicalAttest => b"canon-attest",
            SignKind::PeerRecord => b"peer-record",
        }
    }
}

#[derive(Debug, Error)]
pub enum SignKindError {
    #[error("unknown sign kind 0x{0:02x}")]
    Unknown(u8),
    #[error("empty payload for kind {0:?}")]
    EmptyPayload(SignKind),
    #[error("payload for kind {kind:?} is {len} bytes, max {max}")]
    PayloadTooLarge { kind: SignKind, len: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_round_trips_u8() {
        for kind in [SignKind::NoiseHandshake, SignKind::CanonicalAttest, SignKind::PeerRecord] {
            assert_eq!(SignKind::from_u8(kind as u8).unwrap(), kind);
        }
    }

    #[test]
    fn unknown_byte_rejected() {
        assert!(matches!(SignKind::from_u8(0xFF), Err(SignKindError::Unknown(0xFF))));
    }

    #[test]
    fn domain_tags_are_distinct() {
        let tags = [
            SignKind::NoiseHandshake.domain_tag(),
            SignKind::CanonicalAttest.domain_tag(),
            SignKind::PeerRecord.domain_tag(),
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "domain tags must be distinct");
            }
        }
    }

    #[test]
    fn empty_payload_rejected() {
        assert!(matches!(
            SignKind::NoiseHandshake.validate_payload(&[]),
            Err(SignKindError::EmptyPayload(_))
        ));
    }

    #[test]
    fn oversized_payload_rejected() {
        let big = vec![0u8; 257];
        assert!(matches!(
            SignKind::NoiseHandshake.validate_payload(&big),
            Err(SignKindError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn normal_payload_accepted() {
        let ok = vec![0u8; 32];
        assert!(SignKind::NoiseHandshake.validate_payload(&ok).is_ok());
    }
}
