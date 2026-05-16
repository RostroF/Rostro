//! Runtime API trait + response types for ZK-PKI RPC queries.
//!
//! The types here are the **external-facing** RPC contract — they
//! intentionally differ from the on-chain storage types in
//! [`crate::cert`] and [`crate::issuer`]:
//!
//! - [`CertState`] flattens the on-chain state (just Active/Suspended)
//!   plus expiry-by-block-comparison into a single enum relying
//!   parties can switch on directly (Active/Suspended/Expired/Purged).
//! - [`EntityState`] drops the `BlockNumber` generic + the
//!   Retired/Deactivated variants that are internal renewal machinery;
//!   RPC consumers see just the three states they need for a
//!   trust decision (Active/Challenge/Compromised).
//! - [`OcspStatus`] / [`RevocationReason`] project the internal
//!   state into the vocabulary of X.509/OCSP so existing PKI tooling
//!   can consume the response without a new mental model.
//!
//! Block numbers are exposed as `u64` at the API boundary even when
//! the runtime uses `u32` internally — keeps the response schema
//! stable across runtimes with different `BlockNumber` types.

use codec::{Codec, Decode, Encode, MaxEncodedLen};
use frame_support::{traits::ConstU32, BoundedVec};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

use crate::eku::Eku;
use crate::template::{PopRequirement, MAX_TEMPLATE_EKUS, MAX_TEMPLATE_NAME_LEN};
use crate::tpm::AttestationType;

// ──────────────────────────────────────────────────────────────────────
// Enums — RPC projection of on-chain states
// ──────────────────────────────────────────────────────────────────────

/// X.509/OCSP-compatible top-level status. Relying parties that
/// already speak OCSP can consume the response without translation.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub enum OcspStatus {
    /// Cert is present, active, and within its validity window.
    Good,
    /// Cert is suspended, invalidated, or expired.
    Revoked,
    /// No record of this thumbprint on-chain. Equivalent to OCSP
    /// `unknown`; the pallet returns `None` from `cert_status`
    /// rather than `Unknown` here, so in practice this variant is
    /// reserved for future bridge/cross-chain responses.
    Unknown,
}

/// RFC 5280 revocation reason categories, narrowed to the set the
/// pallet can distinguish. `Expired` is included even though RFC 5280
/// lists it under "certificateHold" semantics — relying parties want
/// to distinguish expiry from active suspension.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub enum RevocationReason {
    /// Issuer set `is_active = false`. Holder has a 30-day grace
    /// period to self-discard and recover deposit; after that the
    /// cert becomes reapable via `cleanup()` by any caller.
    Suspended,
    /// Issuer removed the lookup entry (ZK-PKI `invalidate_cert`).
    Invalidated,
    /// Cert's absolute block expiry has passed.
    Expired,
}

/// RPC-level cert state. Flatter than the on-chain
/// [`crate::cert::CertState`] because relying parties want one enum
/// to switch on rather than a storage-state + block-arithmetic combo.
///
/// `Purged` is logically reachable but never returned by `cert_status`
/// — the pallet returns `Option::None` for purged / never-existed
/// thumbprints. The variant exists for clients that cache state
/// across a purge boundary and want to model the transition
/// explicitly.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub enum CertState {
    Active,
    Suspended,
    Expired,
    Purged,
}

/// RPC-level entity state — trust-decision-ready. The on-chain
/// [`crate::issuer::EntityState`] carries Retired / Deactivated
/// variants that matter for renewal bookkeeping but not for a
/// consuming application; this enum collapses them.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub enum EntityState {
    Active,
    Challenge,
    Compromised,
}

/// Distinguish a root from an issuer in [`EntityStatusResponse`].
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub enum EntityType {
    Root,
    Issuer,
}

// ──────────────────────────────────────────────────────────────────────
// Response types
// ──────────────────────────────────────────────────────────────────────

/// Full OCSP-compatible + ZK-PKI cert status response. Two-layer
/// design: the first six fields mirror an OCSP response almost
/// verbatim; the remaining fields are ZK-PKI extensions that carry
/// the rest of the trust context relying parties want.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub struct CertStatusResponse<AccountId> {
    // ── Layer 1 — X.509/OCSP compatible ──────────────────────────
    pub status: OcspStatus,
    /// Block number the response is "as-of" — i.e., current block.
    pub this_update: u64,
    /// Block number by which a relying party should re-query. Computed
    /// as `this_update + T::TtlCheckInterval::get()`; the pallet
    /// surfaces the interval so different runtimes can tune it.
    pub next_update: u64,
    /// Block the cert was revoked (suspended / invalidated). `None`
    /// for active certs.
    pub revocation_time: Option<u64>,
    pub revocation_reason: Option<RevocationReason>,

    // ── Layer 2 — ZK-PKI extensions ──────────────────────────────
    pub thumbprint: [u8; 32],
    pub cert_state: CertState,
    pub expiry_block: u64,
    pub mint_block: u64,
    pub issuer: AccountId,
    pub issuer_status: EntityState,
    pub issuer_compromised_at_block: Option<u64>,
    pub root: AccountId,
    pub root_status: EntityState,
    pub root_compromised_at_block: Option<u64>,
    pub attestation_type: AttestationType,
    pub manufacturer_verified: bool,
    pub ek_hash: Option<[u8; 32]>,
    /// Template class this cert was minted under. Empty vector when
    /// the minting issuer's template has since been discarded —
    /// callers should check `template_pop_requirement` to distinguish
    /// "no template ever" (can't happen for certs minted after
    /// templates landed) from "template was discarded after mint".
    pub template_name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
    /// PoP policy declared by the template at the time this cert was
    /// minted. `None` iff the template no longer exists (issuer
    /// discarded it after the cert was minted). Relying parties that
    /// need PoP signal should fall back to
    /// `attestation_type == AttestationType::Tpm` in that case.
    pub template_pop_requirement: Option<PopRequirement>,
    /// EKUs attached to this cert at mint time (copied verbatim from
    /// the template). Empty for root / issuer certs — those carry
    /// capability EKUs on their entity record, not on the cert.
    pub ekus: BoundedVec<Eku, ConstU32<MAX_TEMPLATE_EKUS>>,
}

/// Compact cert record for list-style queries (certs_by_*). Full
/// trust context isn't included — callers that need the compromise
/// state of every parent should call `cert_status` on the thumbprint.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub struct CertSummary {
    pub thumbprint: [u8; 32],
    pub cert_state: CertState,
    pub expiry_block: u64,
    pub mint_block: u64,
    pub attestation_type: AttestationType,
    pub manufacturer_verified: bool,
}

/// Entity (root or issuer) status for reputation-aware callers.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub struct EntityStatusResponse<AccountId> {
    pub address: AccountId,
    pub entity_type: EntityType,
    pub state: EntityState,
    pub compromised_at_block: Option<u64>,
    /// Total cert volume issued by this entity (ever). For roots,
    /// this counts issuer certs; for issuers, end-user certs.
    pub cert_volume: u32,
    /// Basis points (1/10000) of certs this entity has
    /// invalidated/suspended. Reputation input — low is good,
    /// high is bad.
    pub invalidation_rate: u32,
}

// ──────────────────────────────────────────────────────────────────────
// Runtime API trait
// ──────────────────────────────────────────────────────────────────────

sp_api::decl_runtime_apis! {
    /// Queries against on-chain ZK-PKI state. Pure storage reads — no
    /// off-chain computation, no event replay.
    pub trait ZkPkiApi<AccountId>
    where
        AccountId: Codec,
    {
        /// Full cert status for a thumbprint. Returns `None` if the
        /// thumbprint has no lookup entry (never existed or purged).
        fn cert_status(thumbprint: [u8; 32]) -> Option<CertStatusResponse<AccountId>>;

        /// Compact summaries of every cert `issuer` has issued that
        /// still has a lookup entry.
        fn certs_by_issuer(issuer: AccountId) -> Vec<CertSummary>;

        /// Compact summaries of every cert held by `user`.
        fn certs_by_user(user: AccountId) -> Vec<CertSummary>;

        /// Compact summaries of every cert anchored under `root`.
        fn certs_by_root(root: AccountId) -> Vec<CertSummary>;

        /// Entity-level status. `address` must be a registered root or
        /// issuer; returns `None` otherwise.
        fn entity_status(address: AccountId) -> Option<EntityStatusResponse<AccountId>>;

        /// Look up the active PoP thumbprint for a device (EK hash)
        /// under a specific root's trust hierarchy. Root-scoped — a
        /// device may hold active PoP certs under multiple roots
        /// concurrently; callers must specify which trust domain
        /// they're querying.
        fn ek_lookup(root: AccountId, ek_hash: [u8; 32]) -> Option<[u8; 32]>;

        /// Was the cert valid at a specific historical block?
        /// `true` iff the cert was minted by `block_number`, hadn't
        /// expired at that block, and neither the issuer nor root was
        /// compromised on or before that block.
        fn chain_valid_at(thumbprint: [u8; 32], block_number: u64) -> bool;
    }
}
