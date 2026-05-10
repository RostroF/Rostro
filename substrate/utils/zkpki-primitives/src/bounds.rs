//! Bounded collection size constants used across the workspace.
//! Centralised here so pallet storage, extrinsics, and RPC types all agree.

/// Max byte length of a raw TPM attestation blob.
pub const MAX_ATTESTATION_LEN: u32 = 4096;

/// Max byte length of issuer-defined cert metadata (immutable at mint).
pub const MAX_METADATA_LEN: u32 = 1024;

/// Max byte length of a suspension reason string.
pub const MAX_SUSPENSION_REASON_LEN: u32 = 256;

/// Max byte length of a device public key (accommodates ML-DSA-87 at ~2,592 bytes).
pub const MAX_DEVICE_PUBKEY_LEN: u32 = 3072;

/// Hard pallet ceiling for issuers per root. Runtime constant `MaxIssuersPerRoot`
/// can be set lower but never higher than this.
pub const ABSOLUTE_MAX_ISSUERS_PER_ROOT: u32 = 100;

/// Max entries processable in a single `purge_expired` call.
pub const MAX_PURGE_BATCH_SIZE: u32 = 20;

/// Number of expired entries grabbed by piggyback cleanup during `mint_cert`.
pub const PIGGYBACK_CLEANUP_COUNT: u32 = 5;
