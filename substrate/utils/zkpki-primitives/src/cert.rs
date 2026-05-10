use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Schema version — first field in canonical serialization to enable migration detection.
/// The pallet refuses to mint any cert below `CURRENT_SCHEMA_VERSION` (invariant #8).
pub type SchemaVersion = u16;
/// Schema v3: PoP certs carry an explicit `pop_mechanism` field on
/// the Hot record + an optional `commitment_c` in the
/// `MimeWrapCommitments` map (Cold-tier separate map). See
/// `zk_pki_primitives::pop` and `zk_pki_primitives::template`.
/// Bumped 2026-04-25.
///
/// Schema v2 (2026-04-18): PoP certs carry a
/// `GenesisHardwareFingerprint` on the Cold record.
pub const CURRENT_SCHEMA_VERSION: SchemaVersion = 3;

/// Blake2b-256 thumbprint (32 bytes). Computed on-chain at mint time over SCALE-encoded
/// canonical fields via sp_core::blake2_256.
pub type Thumbprint = [u8; 32];

/// Canonical field order for thumbprint computation (the entire struct is SCALE-encoded
/// as a unit — each field gets its SCALE length prefix, preventing preimage collisions).
///
/// Order: schema_version, root, issuer, user, user_pubkey, registration_block, expiry, metadata.
///
/// Generic over `AccountId`, `BlockNumber`, and `Metadata`.
/// The device public key type is algorithm-agnostic — P-256, P-521, or ML-DSA
/// depending on what the client's hardware supports.
/// `BlockNumber` matches the runtime's block number type — no fixed `u64` conversion boundary.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct CertCanonical<AccountId, BlockNumber, Metadata> {
    pub schema_version: SchemaVersion,
    pub root: AccountId,
    pub issuer: AccountId,
    pub user: AccountId,
    pub user_pubkey: crate::crypto::DevicePublicKey,
    /// Block at which this cert was registered/minted. Included in canonical serialization
    /// to guarantee unique thumbprints even when key, TTL, and addresses are reused
    /// (e.g., root re-registration after clean deregistration). Publicly observable,
    /// independently verifiable, consistent with the non-repudiation story.
    pub registration_block: BlockNumber,
    /// Absolute block number for TTL / expiry. Never stored as a duration.
    /// Uses the runtime's native block number type — X.509 NotAfter equivalent.
    pub expiry: BlockNumber,
    pub metadata: Metadata,
}

/// Cert state — replaces the boolean `is_active` field.
/// Validity is derived from this state, `expiry_block` vs current block,
/// and parent entity state. Single source of truth.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub enum CertState {
    /// Cert is active and operational.
    Active,
    /// Cert is suspended by issuer. Holder has a 30-day grace
    /// period to self-discard; otherwise the cert becomes reapable
    /// via `cleanup()` after the grace period elapses.
    Suspended,
}

impl CertState {
    pub fn is_active(&self) -> bool {
        matches!(self, CertState::Active)
    }

    pub fn is_suspended(&self) -> bool {
        matches!(self, CertState::Suspended)
    }
}
