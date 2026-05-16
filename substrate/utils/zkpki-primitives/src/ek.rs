//! Endorsement Key hash primitive — used as the on-chain deduplication key.
//! One active PoP cert per EK hash is enforced by the pallet.

/// Hash of the TPM Endorsement Key (Blake2b-256 of the raw EK).
/// One active PoP cert per EK hash is the deduplication invariant.
pub type EkHash = [u8; 32];
