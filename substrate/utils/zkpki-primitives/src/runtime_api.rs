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

use crate::crypto::DevicePublicKey;
use crate::eku::Eku;
use crate::hip::GenesisHardwareFingerprint;
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

/// Minimum cert info needed to authenticate an off-chain
/// challenge-response signed by the cert's hardware-attested device
/// key. Returned by [`ZkPkiApi::cert_authentication`].
///
/// Off-chain consumers (notably the chat-channel JSON-RPC entry
/// point at [gemini-node]) use this to:
///
/// 1. Check the cert is in `Active` state (`cert_state`).
/// 2. Verify the cert hasn't expired (`expiry_block`).
/// 3. Verify a signed challenge against `device_pubkey`.
/// 4. Use `bound_account` as the authenticated requestor SS58
///    after all three of the above pass.
///
/// This response intentionally omits the trust-chain context the
/// `CertStatusResponse` carries (root, issuer, attestation type,
/// EKUs, etc.). Callers that need that should still use
/// `cert_status`; this method is the narrow "auth-me" surface
/// where minimizing exposed metadata matters.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub struct CertAuthInfo<AccountId> {
    /// SS58 the cert is bound to. Becomes the authenticated
    /// identity for the requestor after signature verification.
    pub bound_account: AccountId,
    /// HW-attested device public key. The off-chain consumer
    /// verifies the challenge signature against this key.
    pub device_pubkey: DevicePublicKey,
    /// Current cert state. Off-chain consumers should accept only
    /// `Active`; `Suspended`, `Expired`, `Purged` all mean the
    /// holder shouldn't be acting as this identity right now.
    pub cert_state: CertState,
    /// Block at which the cert expires. Surfaced as `u64` for the
    /// usual stable-across-runtime-block-number-types reason.
    pub expiry_block: u64,
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

/// The public side of a cert's anonymous-membership witness: everything the
/// phone prover needs to assemble a [`MembershipCircuit`] *except* the secret
/// `s` (which never leaves the device's secure element). The caller already
/// knows the current roots/epoch/scope via the other API methods; this bundles
/// the per-cert, position-dependent data: the leaf index and the two depth-32
/// authentication paths (sibling at each level, bottom-up, canonical LE field
/// bytes), plus the leaf-value scalars the circuit checks as private witness.
///
/// PRIVACY: looking this up by thumbprint reveals to the *serving* node which
/// cert the caller holds. Anonymity vs the chat **guard** is preserved (the
/// guard only ever sees the Groth16 proof); anonymity vs the path-serving node
/// is not, and is a Phase-2 concern (fetch over onion, or from a tree snapshot
/// the device walks locally). For the smoke test / testnet collection posture
/// this linkage is acceptable.
#[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug, serde::Serialize, serde::Deserialize))]
pub struct MembershipWitnessData {
    /// The cert's leaf index in both the membership and freshness trees.
    pub leaf_position: u64,
    /// Block at which the cert expires (the circuit's `expiry_block` witness).
    pub expiry_block: u64,
    /// The cert's current HIP-freshness deadline in epochs (the freshness
    /// leaf value; circuit's `fresh_until_epoch` witness).
    pub fresh_until_epoch: u32,
    /// Depth-32 membership-tree authentication path, bottom-up, LE field bytes.
    pub membership_path: Vec<[u8; 32]>,
    /// Depth-32 freshness-tree authentication path, bottom-up, LE field bytes.
    pub freshness_path: Vec<[u8; 32]>,
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

        /// Minimum cert info needed to authenticate an off-chain
        /// challenge-response. Returns `None` if the thumbprint has
        /// no lookup entry.
        ///
        /// Use case: the gemini-node chat layer's JSON-RPC entry
        /// point verifies an end-user's HW-attested signature over
        /// a challenge before accepting `chat_send_envelope`. It
        /// needs the cert's `device_pubkey` to verify and the
        /// cert's `bound_account` as the authenticated identity.
        /// `cert_status` doesn't expose either; this method does.
        fn cert_authentication(
            thumbprint: [u8; 32],
        ) -> Option<CertAuthInfo<AccountId>>;

        /// The cert's enrolled hardware fingerprint (HIP genesis), or
        /// `None` if the cert carries no HIP (a non-PoP / dev-stub cert
        /// minted without a `hip_proof_at_genesis`).
        ///
        /// Use case: the chat-auth session handshake. The node verifies a
        /// fresh `CanonicalHipProof` from the client against this enrolled
        /// baseline via `verify_hip_proof_against_genesis` — device-state
        /// drift detection ("is this still the enrolled-good device?").
        /// Pure storage read of `CertLookupCold(thumbprint).genesis_fingerprint`;
        /// the cold record is already fetched by `cert_authentication`, so
        /// this adds no extra read for callers that need both.
        fn cert_hip_genesis(
            thumbprint: [u8; 32],
        ) -> Option<GenesisHardwareFingerprint>;

        // ── Chat anonymous-membership handshake ──────────────────────────
        // The chat guard verifies a Groth16 membership proof off-chain; it
        // needs the current/recent commitment roots, the epoch, and the scope
        // to validate the proof's public inputs (see rostro-chat-membership-auth).

        /// Current membership-tree root (canonical field-element bytes).
        fn membership_root() -> [u8; 32];
        /// Is `root` the current membership root or within the recent-root ring?
        fn membership_root_recent(root: [u8; 32]) -> bool;
        /// Current freshness-tree root.
        fn freshness_root() -> [u8; 32];
        /// Is `root` the current freshness root or within its recent-root ring?
        fn freshness_root_recent(root: [u8; 32]) -> bool;
        /// Current epoch (block number / epoch length).
        fn membership_epoch() -> u32;
        /// The anonymity-set scope constant committed in every membership leaf.
        fn membership_scope() -> u64;

        /// The public side of `thumbprint`'s membership witness: leaf index,
        /// expiry, freshness deadline, and the two depth-32 authentication
        /// paths. `None` if the thumbprint has no cert or the cert was minted
        /// without chat enrollment (no `leaf_position`). See
        /// [`MembershipWitnessData`] for the privacy caveat on this lookup.
        fn membership_witness(thumbprint: [u8; 32]) -> Option<MembershipWitnessData>;
    }
}
